//! Recover mnemonic notes from pool history.
//!
//! Shield deposits are FrameTx frames (or `executeBatch` calls), so the shield
//! selector is not the transaction prefix and the note value is not `tx.value`.
//! A partial unshield spends that deposit and appends a change note at the next
//! derivation index. The change value is `inputs - publicAmount - fee` from
//! `settle`. A spent index still counts as used, so a later note is not hidden
//! by an empty gap at the front of the scan.

use std::collections::{HashMap, HashSet};

use alloy::{
    primitives::{B256, U256 as AlloyU256},
    sol_types::SolCall,
};
use anyhow::Result;
use kohaku_minimal_shield::{
    Note,
    abis::{FrameAccount, Multicall3, ShieldedPool},
};
use ruint::aliases::U256 as Ruint;

use crate::wallet::{self, NoteSecrets};

const INDEX_GAP: u32 = 32;
const SCAN_CAP: u32 = 512;
const TX_TYPE: u8 = 0x06;

#[derive(Clone, Copy)]
pub struct LeafInfo {
    pub index: u32,
    pub epoch: u64,
}

pub struct ShieldSeen {
    pub inner: Ruint,
    pub value: Ruint,
}

pub struct SettleSeen {
    pub nf1: Ruint,
    pub nf2: Ruint,
    pub out1: Ruint,
    pub out2: Ruint,
    pub public_amount: Ruint,
    pub fee: Ruint,
    pub epoch: u64,
    pub block: u64,
    pub tx_index: u64,
    pub log_index: u64,
}

pub enum PoolAction {
    Shield {
        inner: Ruint,
        value: Ruint,
    },
    Settle {
        nf1: Ruint,
        nf2: Ruint,
        out1: Ruint,
        out2: Ruint,
        public_amount: Ruint,
        fee: Ruint,
        epoch: u64,
    },
}

pub struct RecoveredNote {
    pub note: Note,
    pub index: u32,
    pub spent: bool,
}

struct Owned {
    note: Note,
    index: u32,
    leaf: u32,
    leaf_epoch: u64,
    spent: bool,
}

struct SecretsCache<'a> {
    mnemonic: &'a str,
    chain_id: u64,
    pool: alloy::primitives::Address,
    secrets: HashMap<u32, NoteSecrets>,
}

impl<'a> SecretsCache<'a> {
    fn note(&mut self, index: u32, value: Ruint) -> Result<Note> {
        if let Some(secrets) = self.secrets.get(&index).copied() {
            return Ok(wallet::note_from_secrets(
                secrets,
                value,
                self.chain_id,
                self.pool,
            ));
        }
        let secrets = wallet::note_secrets(self.mnemonic, index, self.chain_id, self.pool)?;
        self.secrets.insert(index, secrets);
        Ok(wallet::note_from_secrets(
            secrets,
            value,
            self.chain_id,
            self.pool,
        ))
    }
}

/// Pull shield and settle calls out of a raw FrameTx (`0x06 || rlp`) or bare calldata.
pub fn actions_from_raw(raw: &[u8], tx_value: Ruint) -> Vec<PoolAction> {
    if raw.first() == Some(&TX_TYPE) {
        return actions_from_envelope(&raw[1..]).unwrap_or_default();
    }
    if raw.first().is_some_and(|b| *b >= 0xc0) {
        if let Some(actions) = actions_from_envelope(raw) {
            return actions;
        }
    }
    let mut out = Vec::new();
    walk_calldata(raw, tx_value, &mut out, 0);
    out
}

/// This devnet returns type `0x06` transactions as JSON `frames`, with an empty `input`
/// and no `eth_getRawTransactionByHash`.
pub fn actions_from_tx_json(tx: &serde_json::Value) -> Vec<PoolAction> {
    let Some(frames) = tx.get("frames").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for frame in frames {
        let data = frame
            .get("data")
            .or_else(|| frame.get("input"))
            .and_then(|v| v.as_str())
            .and_then(decode_hex)
            .unwrap_or_default();
        let value = frame
            .get("value")
            .and_then(|v| v.as_str())
            .and_then(parse_quantity)
            .unwrap_or(Ruint::ZERO);
        walk_calldata(&data, value, &mut out, 0);
    }
    out
}

pub fn recover_notes(
    mnemonic: &str,
    chain_id: u64,
    pool: alloy::primitives::Address,
    leaves: &HashMap<Ruint, LeafInfo>,
    shields: &[ShieldSeen],
    settles: &[SettleSeen],
    spent: &HashSet<Ruint>,
    max_epoch: u64,
) -> Result<Vec<RecoveredNote>> {
    let mut cache = SecretsCache {
        mnemonic,
        chain_id,
        pool,
        secrets: HashMap::new(),
    };
    let mut owned: Vec<Owned> = Vec::new();
    let mut used_shields = vec![false; shields.len()];
    let mut settle_order: Vec<usize> = (0..settles.len()).collect();
    settle_order.sort_by_key(|&i| (settles[i].block, settles[i].tx_index, settles[i].log_index));
    let mut settle_done = vec![false; settles.len()];

    for _ in 0..64 {
        let before = owned.len();
        scan_shields(&mut cache, &mut owned, shields, &mut used_shields, leaves)?;
        apply_settles(
            &mut cache,
            &mut owned,
            settles,
            &settle_order,
            &mut settle_done,
            leaves,
        )?;
        if owned.len() == before {
            break;
        }
    }
    for note in &mut owned {
        if note.spent {
            continue;
        }
        if burned(note, spent, max_epoch) {
            note.spent = true;
        }
    }
    Ok(owned
        .into_iter()
        .map(|n| RecoveredNote {
            note: n.note,
            index: n.index,
            spent: n.spent,
        })
        .collect())
}

fn scan_shields(
    cache: &mut SecretsCache<'_>,
    owned: &mut Vec<Owned>,
    shields: &[ShieldSeen],
    used_shields: &mut [bool],
    leaves: &HashMap<Ruint, LeafInfo>,
) -> Result<()> {
    let mut gap = 0u32;
    let mut index = 0u32;
    while index <= SCAN_CAP {
        if owned.iter().any(|n| n.index == index) {
            gap = 0;
            index += 1;
            continue;
        }
        if let Some((note, leaf)) = match_shield(cache, index, shields, used_shields, leaves)? {
            owned.push(Owned {
                note,
                index,
                leaf: leaf.index,
                leaf_epoch: leaf.epoch,
                spent: false,
            });
            gap = 0;
            index += 1;
            continue;
        }
        gap += 1;
        if gap >= INDEX_GAP {
            break;
        }
        index += 1;
    }
    Ok(())
}

fn match_shield(
    cache: &mut SecretsCache<'_>,
    index: u32,
    shields: &[ShieldSeen],
    used_shields: &mut [bool],
    leaves: &HashMap<Ruint, LeafInfo>,
) -> Result<Option<(Note, LeafInfo)>> {
    let inner = cache.note(index, Ruint::ZERO)?.inner();
    for (i, shield) in shields.iter().enumerate() {
        if used_shields[i] || shield.inner != inner {
            continue;
        }
        let note = cache.note(index, shield.value)?;
        if let Some(leaf) = leaves.get(&note.commitment()) {
            used_shields[i] = true;
            return Ok(Some((note, *leaf)));
        }
    }
    Ok(None)
}

fn apply_settles(
    cache: &mut SecretsCache<'_>,
    owned: &mut Vec<Owned>,
    settles: &[SettleSeen],
    order: &[usize],
    done: &mut [bool],
    leaves: &HashMap<Ruint, LeafInfo>,
) -> Result<()> {
    for &si in order {
        if done[si] {
            continue;
        }
        let settle = &settles[si];
        let inputs: Vec<usize> = owned
            .iter()
            .enumerate()
            .filter(|(_, n)| !n.spent && is_input(n, settle))
            .map(|(i, _)| i)
            .collect();
        if inputs.is_empty() {
            continue;
        }
        let Some(sum) = inputs
            .iter()
            .try_fold(Ruint::ZERO, |acc, i| acc.checked_add(owned[*i].note.value))
        else {
            continue;
        };
        let Some(change_value) = sum
            .checked_sub(settle.public_amount)
            .and_then(|v| v.checked_sub(settle.fee))
        else {
            continue;
        };
        if change_value.is_zero() {
            for i in inputs {
                owned[i].spent = true;
            }
            done[si] = true;
            continue;
        }
        let Some((index, note, leaf)) = locate_change(cache, owned, change_value, settle, leaves)?
        else {
            continue;
        };
        for i in inputs {
            owned[i].spent = true;
        }
        owned.push(Owned {
            note,
            index,
            leaf: leaf.index,
            leaf_epoch: leaf.epoch,
            spent: false,
        });
        done[si] = true;
    }
    Ok(())
}

fn locate_change(
    cache: &mut SecretsCache<'_>,
    owned: &[Owned],
    value: Ruint,
    settle: &SettleSeen,
    leaves: &HashMap<Ruint, LeafInfo>,
) -> Result<Option<(u32, Note, LeafInfo)>> {
    for index in 0..=SCAN_CAP {
        if owned.iter().any(|n| n.index == index) {
            continue;
        }
        let note = cache.note(index, value)?;
        let cm = note.commitment();
        if cm != settle.out1 && cm != settle.out2 {
            continue;
        }
        if let Some(leaf) = leaves.get(&cm) {
            return Ok(Some((index, note, *leaf)));
        }
    }
    Ok(None)
}

fn is_input(note: &Owned, settle: &SettleSeen) -> bool {
    let nf = note.note.nullifier(
        note.note.domain(settle.epoch),
        Ruint::from(u64::from(note.leaf)),
    );
    nf == settle.nf1 || nf == settle.nf2
}

fn burned(note: &Owned, spent: &HashSet<Ruint>, max_epoch: u64) -> bool {
    let end = max_epoch.max(note.leaf_epoch);
    let leaf = Ruint::from(u64::from(note.leaf));
    (note.leaf_epoch..=end)
        .any(|epoch| spent.contains(&note.note.nullifier(note.note.domain(epoch), leaf)))
}

fn actions_from_envelope(raw: &[u8]) -> Option<Vec<PoolAction>> {
    let mut i = 0;
    let item = read_item(raw, &mut i)?;
    if i != raw.len() {
        return None;
    }
    let Item::List(body) = item else {
        return None;
    };
    let fields = read_sequence(body)?;
    if fields.len() < 5 {
        return None;
    }
    let Item::List(frames_body) = fields[4] else {
        return None;
    };
    let frames = read_sequence(frames_body)?;
    let mut out = Vec::new();
    for frame in frames {
        let Item::List(frame_body) = frame else {
            return None;
        };
        let parts = read_sequence(frame_body)?;
        if parts.len() < 6 {
            return None;
        }
        let Item::Bytes(value_bytes) = parts[4] else {
            return None;
        };
        let Item::Bytes(data) = parts[5] else {
            return None;
        };
        let value = int_from_be(value_bytes)?;
        walk_calldata(data, value, &mut out, 0);
    }
    Some(out)
}

fn walk_calldata(data: &[u8], value: Ruint, out: &mut Vec<PoolAction>, depth: u8) {
    if depth > 4 || data.len() < 4 {
        return;
    }
    if data[..4] == ShieldedPool::shieldCall::SELECTOR {
        if let Ok(call) = ShieldedPool::shieldCall::abi_decode(data) {
            out.push(PoolAction::Shield {
                inner: ruint_from_b256(call.inner),
                value,
            });
        }
        return;
    }
    if data[..4] == ShieldedPool::settleCall::SELECTOR {
        if let Ok(call) = ShieldedPool::settleCall::abi_decode(data) {
            let s = call.s;
            out.push(PoolAction::Settle {
                nf1: ruint_from_b256(s.nf1),
                nf2: ruint_from_b256(s.nf2),
                out1: ruint_from_b256(s.outCm1),
                out2: ruint_from_b256(s.outCm2),
                public_amount: ruint_from_alloy(s.publicAmount),
                fee: ruint_from_alloy(s.fee),
                epoch: s.epoch,
            });
        }
        return;
    }
    if data[..4] == FrameAccount::executeBatchCall::SELECTOR {
        if let Ok(call) = FrameAccount::executeBatchCall::abi_decode(data) {
            for inner in call.calls {
                walk_calldata(&inner.data, ruint_from_alloy(inner.value), out, depth + 1);
            }
        }
        return;
    }
    if data[..4] == Multicall3::aggregate3Call::SELECTOR {
        if let Ok(call) = Multicall3::aggregate3Call::abi_decode(data) {
            for inner in call.calls {
                walk_calldata(&inner.callData, value, out, depth + 1);
            }
        }
    }
}

fn ruint_from_b256(v: B256) -> Ruint {
    Ruint::from_be_bytes(v.0)
}

fn ruint_from_alloy(v: AlloyU256) -> Ruint {
    Ruint::from_be_bytes::<32>(v.to_be_bytes::<32>())
}

enum Item<'a> {
    Bytes(&'a [u8]),
    List(&'a [u8]),
}

fn read_sequence(body: &[u8]) -> Option<Vec<Item<'_>>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < body.len() {
        out.push(read_item(body, &mut i)?);
    }
    Some(out)
}

fn read_item<'a>(buf: &'a [u8], i: &mut usize) -> Option<Item<'a>> {
    let start = *i;
    let b = *buf.get(*i)?;
    *i += 1;
    if b < 0x80 {
        return Some(Item::Bytes(&buf[start..*i]));
    }
    if b < 0xb8 {
        return take_bytes(buf, i, (b - 0x80) as usize);
    }
    if b < 0xc0 {
        let n = (b - 0xb7) as usize;
        let len = read_long_len(buf, i, n)?;
        return take_bytes(buf, i, len);
    }
    if b < 0xf8 {
        return take_list(buf, i, (b - 0xc0) as usize);
    }
    let n = (b - 0xf7) as usize;
    let len = read_long_len(buf, i, n)?;
    take_list(buf, i, len)
}

fn take_bytes<'a>(buf: &'a [u8], i: &mut usize, len: usize) -> Option<Item<'a>> {
    let from = *i;
    *i = i.checked_add(len)?;
    if *i > buf.len() {
        return None;
    }
    Some(Item::Bytes(&buf[from..*i]))
}

fn take_list<'a>(buf: &'a [u8], i: &mut usize, len: usize) -> Option<Item<'a>> {
    let from = *i;
    *i = i.checked_add(len)?;
    if *i > buf.len() {
        return None;
    }
    Some(Item::List(&buf[from..*i]))
}

fn read_long_len(buf: &[u8], i: &mut usize, n: usize) -> Option<usize> {
    if n == 0 || n > 8 || buf.len().saturating_sub(*i) < n {
        return None;
    }
    let mut x = 0usize;
    for _ in 0..n {
        x = x.checked_shl(8)?.checked_add(usize::from(buf[*i]))?;
        *i += 1;
    }
    if x < 56 {
        return None;
    }
    Some(x)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return None;
    }
    hex::decode(s).ok()
}

fn parse_quantity(s: &str) -> Option<Ruint> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Some(Ruint::ZERO);
    }
    Ruint::from_str_radix(s, 16).ok()
}

fn int_from_be(bytes: &[u8]) -> Option<Ruint> {
    if bytes.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(bytes);
    Some(Ruint::from_be_bytes(out))
}

#[cfg(test)]
mod tests {
    use super::{
        LeafInfo, PoolAction, SettleSeen, ShieldSeen, actions_from_raw, actions_from_tx_json,
        recover_notes,
    };
    use crate::{txbuild, wallet};
    use alloy::{
        primitives::{Address, Bytes, U256, address},
        sol_types::SolCall,
    };
    use kohaku_frametx_kit::{FRAME_MODE_SENDER, Frame, FrameSig, FrameTx};
    use kohaku_minimal_shield::{
        Note,
        abis::{FrameAccount, ShieldedPool},
    };
    use ruint::aliases::U256 as Ruint;
    use std::collections::{HashMap, HashSet};

    const PHRASE: &str = "test test test test test test test test test test test junk";

    fn r(n: u64) -> Ruint {
        Ruint::from(n)
    }

    fn pool() -> Address {
        address!("0xcb83980f3cc99e258295814375b0a94fe0ac0e86")
    }

    fn note(index: u32, value: u64) -> Note {
        wallet::note_at(PHRASE, index, r(value), 8141, pool()).unwrap()
    }

    fn leaf(cm: Ruint, index: u32, epoch: u64, leaves: &mut HashMap<Ruint, LeafInfo>) {
        leaves.insert(cm, LeafInfo { index, epoch });
    }

    fn frame(value: U256, data: Bytes) -> FrameTx {
        FrameTx {
            chain_id: 8141,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: 0,
            sender: Address::repeat_byte(1),
            frames: vec![Frame {
                mode: FRAME_MODE_SENDER,
                flags: 0,
                target: Some(pool()),
                execution_gas: 1,
                state_gas: 1,
                value,
                data,
            }],
            signatures: vec![FrameSig::secp256k1(Address::repeat_byte(2))],
            max_priority_fee: U256::from(1u64),
            max_fee: U256::from(2u64),
            max_blob_fee: U256::ZERO,
            blob_hashes: vec![],
        }
    }

    #[test]
    fn frame_shield_is_not_the_transaction_prefix() {
        let deposit = note(0, 1_000);
        let inner = deposit.inner().to_be_bytes::<32>();
        let tx = frame(U256::from(1_000u64), txbuild::shield_calldata(inner));
        let raw = tx.raw();
        assert_ne!(&raw[..4], ShieldedPool::shieldCall::SELECTOR.as_slice());
        let actions = actions_from_raw(&raw, Ruint::ZERO);
        let PoolAction::Shield { inner, value } = &actions[0] else {
            panic!("expected shield");
        };
        assert_eq!(*inner, deposit.inner());
        assert_eq!(*value, r(1_000));
    }

    #[test]
    fn execute_batch_shield_uses_the_call_value() {
        let deposit = note(0, 1_000);
        let batch = FrameAccount::executeBatchCall {
            calls: vec![FrameAccount::Call {
                target: pool(),
                value: U256::from(1_000u64),
                data: txbuild::shield_calldata(deposit.inner().to_be_bytes::<32>()),
            }],
            signature: Bytes::new(),
        };
        let tx = frame(U256::ZERO, Bytes::from(batch.abi_encode()));
        let actions = actions_from_raw(&tx.raw(), r(999));
        let PoolAction::Shield { inner, value } = &actions[0] else {
            panic!("expected shield");
        };
        assert_eq!(*inner, deposit.inner());
        assert_eq!(*value, r(1_000));
    }

    #[test]
    fn rpc_json_frames_decode_settle_when_input_is_empty() {
        let tx = serde_json::json!({
            "type": "0x6",
            "input": "0x",
            "frames": [{
                "mode": "0x2",
                "value": "0x0",
                "data": "0x921fcac7197f08fbc42490f532466379ada1f83be2307ba42a932cd9981e7fb6aa2d5359000000000000000000000000000000000000000000000000000000000004f62f000000000000000000000000000000000000000000000000000000000000000010fd35b358869f1e10483910240fc5488777de42911ffc614553d64b3cbb5845053fc4a2fbd082769a5c26b6e44ff6c597dc351bd31010ed14306a7f700c51a20302711052d4b337b692a3f3897880c1921737b7270a5ebf50481f3c4ef8efc400e9367dff9fbaf2afdfb5285f7a450308f8ebe7abc5ddc17b53001ffe620d7b2fd476622c67c880b3049a76c7337192362834c9d6dfb55c5060bb96c98932bb000000000000000000000000000000000000000000000000033f55c29d710000000000000000000000000000000000000000000000000000000e7a17bd8ef5a80000000000000000000000005c9a93b44ce45a03d29b93026cbafa2e8492a707000000000000000000000000600db63bc366c317ad0592906f2a6c5c75ffa7a7"
            }]
        });
        let mut actions = actions_from_tx_json(&tx);
        let PoolAction::Settle {
            public_amount,
            fee,
            out1,
            epoch,
            ..
        } = actions.remove(0)
        else {
            panic!("expected settle from json frames");
        };
        assert_eq!(public_amount, r(234_000_000_000_000_000));
        assert_eq!(fee, Ruint::from(4_074_892_057_048_488u64));
        assert_eq!(epoch, 0);
        assert_eq!(
            hex::encode(out1.to_be_bytes::<32>()),
            "00e9367dff9fbaf2afdfb5285f7a450308f8ebe7abc5ddc17b53001ffe620d7b"
        );
    }

    #[test]
    fn settle_frame_exposes_public_amount_and_fee() {
        let spend = ShieldedPool::Spend {
            root: alloy::primitives::B256::ZERO,
            rootSlot: 1,
            epoch: 4,
            domain: alloy::primitives::B256::repeat_byte(2),
            nf1: alloy::primitives::B256::repeat_byte(3),
            nf2: alloy::primitives::B256::repeat_byte(4),
            outCm1: alloy::primitives::B256::repeat_byte(5),
            outCm2: alloy::primitives::B256::repeat_byte(6),
            publicAmount: U256::from(400_000u64),
            fee: U256::from(50_000u64),
            recipient: Address::repeat_byte(7),
            authorizer: Address::repeat_byte(8),
        };
        let tx = frame(
            U256::ZERO,
            Bytes::from(ShieldedPool::settleCall { s: spend }.abi_encode()),
        );
        let actions = actions_from_raw(&tx.raw(), Ruint::ZERO);
        let PoolAction::Settle {
            public_amount,
            fee,
            epoch,
            ..
        } = &actions[0]
        else {
            panic!("expected settle");
        };
        assert_eq!(*public_amount, r(400_000));
        assert_eq!(*fee, r(50_000));
        assert_eq!(*epoch, 4);
    }

    #[test]
    fn spent_deposit_does_not_hide_the_change_note() {
        let deposit = note(0, 1_000);
        let change = note(1, 550);
        let epoch = 3u64;
        let nf = deposit.nullifier(deposit.domain(epoch), r(7));
        let mut leaves = HashMap::new();
        leaf(deposit.commitment(), 7, 1, &mut leaves);
        leaf(change.commitment(), 8, epoch, &mut leaves);
        let shields = vec![ShieldSeen {
            inner: deposit.inner(),
            value: r(1_000),
        }];
        let settles = vec![SettleSeen {
            nf1: nf,
            nf2: r(99),
            out1: change.commitment(),
            out2: r(1),
            public_amount: r(400),
            fee: r(50),
            epoch,
            block: 2,
            tx_index: 0,
            log_index: 1,
        }];
        let spent = HashSet::from([nf]);
        let found = recover_notes(
            PHRASE,
            8141,
            pool(),
            &leaves,
            &shields,
            &settles,
            &spent,
            epoch,
        )
        .unwrap();
        let live: Vec<_> = found.iter().filter(|n| !n.spent).collect();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].index, 1);
        assert_eq!(live[0].note.value, r(550));
        assert!(found.iter().any(|n| n.index == 0 && n.spent));
    }

    #[test]
    fn spent_first_shield_still_reaches_the_next_shield() {
        let first = note(0, 100);
        let second = note(1, 250);
        let epoch = 1u64;
        let nf = first.nullifier(first.domain(epoch), r(4));
        let mut leaves = HashMap::new();
        leaf(first.commitment(), 4, 0, &mut leaves);
        leaf(second.commitment(), 5, 0, &mut leaves);
        let shields = vec![
            ShieldSeen {
                inner: first.inner(),
                value: r(100),
            },
            ShieldSeen {
                inner: second.inner(),
                value: r(250),
            },
        ];
        let settles = vec![SettleSeen {
            nf1: nf,
            nf2: r(50),
            out1: r(2),
            out2: r(3),
            public_amount: r(90),
            fee: r(10),
            epoch,
            block: 1,
            tx_index: 0,
            log_index: 0,
        }];
        let found = recover_notes(
            PHRASE,
            8141,
            pool(),
            &leaves,
            &shields,
            &settles,
            &HashSet::from([nf]),
            epoch,
        )
        .unwrap();
        let live: Vec<_> = found.iter().filter(|n| !n.spent).collect();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].index, 1);
        assert_eq!(live[0].note.value, r(250));
    }

    #[test]
    fn merge_then_partial_unshield_keeps_the_final_change() {
        let left = note(0, 100);
        let right = note(1, 40);
        let merged = note(2, 130);
        let change = note(3, 80);
        let mut leaves = HashMap::new();
        leaf(left.commitment(), 1, 0, &mut leaves);
        leaf(right.commitment(), 2, 0, &mut leaves);
        leaf(merged.commitment(), 3, 1, &mut leaves);
        leaf(change.commitment(), 4, 2, &mut leaves);
        let nf_left = left.nullifier(left.domain(1), r(1));
        let nf_right = right.nullifier(right.domain(1), r(2));
        let nf_merged = merged.nullifier(merged.domain(2), r(3));
        let shields = vec![
            ShieldSeen {
                inner: left.inner(),
                value: r(100),
            },
            ShieldSeen {
                inner: right.inner(),
                value: r(40),
            },
        ];
        let settles = vec![
            SettleSeen {
                nf1: nf_left,
                nf2: nf_right,
                out1: merged.commitment(),
                out2: r(9),
                public_amount: Ruint::ZERO,
                fee: r(10),
                epoch: 1,
                block: 5,
                tx_index: 0,
                log_index: 0,
            },
            SettleSeen {
                nf1: nf_merged,
                nf2: r(8),
                out1: change.commitment(),
                out2: r(7),
                public_amount: r(40),
                fee: r(10),
                epoch: 2,
                block: 6,
                tx_index: 0,
                log_index: 0,
            },
        ];
        let found = recover_notes(
            PHRASE,
            8141,
            pool(),
            &leaves,
            &shields,
            &settles,
            &HashSet::from([nf_left, nf_right, nf_merged]),
            2,
        )
        .unwrap();
        let live: Vec<_> = found.iter().filter(|n| !n.spent).collect();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].index, 3);
        assert_eq!(live[0].note.value, r(80));
        assert_eq!(found.iter().filter(|n| n.spent).count(), 3);
    }

    #[tokio::test]
    #[ignore]
    async fn devnet_phrase_recovers_the_unshield_change() {
        let phrase = std::env::var("DEVNET_MNEMONIC").expect("set DEVNET_MNEMONIC");
        let rpc = std::env::var("HEGOTA_RPC_URL")
            .unwrap_or_else(|_| "https://rpc1.privacy.ethrex.xyz".into());
        let pool_addr = pool();
        let deposit_value = Ruint::from(1_234_000_000_000_000_000u64);
        let deposit = wallet::note_at(&phrase, 0, deposit_value, 8141, pool_addr).unwrap();
        let client = reqwest::Client::builder().build().unwrap();
        let sig = "0x1c9386c619e61f45f16a19541b370266f8eb6fd22d241ff010e03cc31ea82368";
        let change_cm = "0x00e9367dff9fbaf2afdfb5285f7a450308f8ebe7abc5ddc17b53001ffe620d7b";
        let deposit_logs = rpc_call(
            &client,
            &rpc,
            "eth_getLogs",
            serde_json::json!([{
                "fromBlock": "0x2302a",
                "address": format!("{pool_addr:#x}"),
                "topics": [sig, word(deposit.commitment())]
            }]),
        )
        .await;
        let change_logs = rpc_call(
            &client,
            &rpc,
            "eth_getLogs",
            serde_json::json!([{
                "fromBlock": "0x2302a",
                "address": format!("{pool_addr:#x}"),
                "topics": [sig, change_cm]
            }]),
        )
        .await;
        let deposit_logs = deposit_logs.as_array().expect("deposit logs");
        let change_logs = change_logs.as_array().expect("change logs");
        assert_eq!(
            deposit_logs.len(),
            1,
            "index 0 shield of 1.234 ETH is not in the pool"
        );
        assert_eq!(
            change_logs.len(),
            1,
            "known change commitment is not in the pool"
        );
        let mut leaves = HashMap::new();
        let mut shields = Vec::new();
        let mut settles = Vec::new();
        for log in deposit_logs.iter().chain(change_logs.iter()) {
            let (cm, index, epoch) = leaf_meta(log);
            leaves.insert(cm, LeafInfo { index, epoch });
            let hash = log["transactionHash"].as_str().unwrap();
            let tx = rpc_call(
                &client,
                &rpc,
                "eth_getTransactionByHash",
                serde_json::json!([hash]),
            )
            .await;
            let block = as_u64(super::parse_quantity(log["blockNumber"].as_str().unwrap()).unwrap());
            for action in actions_from_tx_json(&tx) {
                match action {
                    PoolAction::Shield { inner, value } => {
                        shields.push(ShieldSeen { inner, value });
                    }
                    PoolAction::Settle {
                        nf1,
                        nf2,
                        out1,
                        out2,
                        public_amount,
                        fee,
                        epoch,
                    } => settles.push(SettleSeen {
                        nf1,
                        nf2,
                        out1,
                        out2,
                        public_amount,
                        fee,
                        epoch,
                        block,
                        tx_index: 0,
                        log_index: as_u64(
                            super::parse_quantity(log["logIndex"].as_str().unwrap()).unwrap(),
                        ),
                    }),
                }
            }
        }
        assert!(!shields.is_empty(), "shield frame was not decoded");
        assert!(!settles.is_empty(), "settle frame was not decoded");
        let found = recover_notes(
            &phrase,
            8141,
            pool_addr,
            &leaves,
            &shields,
            &settles,
            &HashSet::new(),
            0,
        )
        .unwrap();
        let live: Vec<_> = found.iter().filter(|n| !n.spent).collect();
        assert_eq!(
            live.len(),
            1,
            "indexes {:?}",
            found.iter().map(|n| (n.index, n.spent)).collect::<Vec<_>>()
        );
        assert_eq!(live[0].index, 1);
        assert_eq!(
            hex::encode(live[0].note.commitment().to_be_bytes::<32>()),
            change_cm.trim_start_matches("0x")
        );
    }

    async fn rpc_call(
        client: &reqwest::Client,
        url: &str,
        method: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let text = client
            .post(url)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        parsed.get("result").cloned().unwrap_or(parsed)
    }

    fn word(v: Ruint) -> String {
        format!("0x{}", hex::encode(v.to_be_bytes::<32>()))
    }

    fn as_u64(v: Ruint) -> u64 {
        let bytes = v.to_be_bytes::<32>();
        u64::from_be_bytes(bytes[24..32].try_into().unwrap())
    }

    fn leaf_meta(log: &serde_json::Value) -> (Ruint, u32, u64) {
        let topics = log["topics"].as_array().unwrap();
        let cm = super::parse_quantity(topics[1].as_str().unwrap()).unwrap();
        let epoch = as_u64(super::parse_quantity(topics[2].as_str().unwrap()).unwrap());
        let data = super::decode_hex(log["data"].as_str().unwrap()).unwrap();
        let index = u32::from_be_bytes(data[28..32].try_into().unwrap());
        (cm, index, epoch)
    }
}
