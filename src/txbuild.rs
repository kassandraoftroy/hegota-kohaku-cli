//! Frame transactions for EOAs (SENDER frames) and deployed FrameAccounts
//! (VERIFY `approveSender`, then `executeBatch` with no inner signature).

use alloy::{
    primitives::{Address, Bytes, U256},
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use anyhow::Result;
use kohaku_frametx_kit::{
    APPROVE_EXECUTION_AND_PAYMENT, ATOMIC_BATCH_FLAG, FRAME_MODE_SENDER, FRAME_MODE_VERIFY, Frame,
    FrameSig, FrameTx, SETTLE_FRAME_GAS, SETTLE_FRAME_STATE_GAS, SHIELD_VERIFY_GAS,
};
use kohaku_minimal_shield::{
    Call,
    abis::{FrameAccount, ShieldedPool},
};

pub const SIMPLE_EXEC: u64 = 120_000;
pub const SIMPLE_STATE: u64 = 250_000;
pub const CALL_EXEC: u64 = 500_000;
pub const CALL_STATE: u64 = 400_000;
pub const APPROVE_EXEC: u64 = 200_000;
pub const APPROVE_STATE: u64 = 100_000;

#[derive(Clone)]
pub struct OutCall {
    pub target: Address,
    pub value: U256,
    pub data: Bytes,
    pub execution_gas: u64,
    pub state_gas: u64,
}

impl OutCall {
    pub fn simple(target: Address, value: U256) -> Self {
        Self {
            target,
            value,
            data: Bytes::new(),
            execution_gas: SIMPLE_EXEC,
            state_gas: SIMPLE_STATE,
        }
    }

    pub fn contract(target: Address, value: U256, data: Bytes) -> Self {
        Self {
            target,
            value,
            data,
            execution_gas: CALL_EXEC,
            state_gas: CALL_STATE,
        }
    }
}

/// EOA default-code VERIFY plus one SENDER frame per call. Two or more calls
/// are one atomic batch.
pub fn eoa_frames(
    signer: &PrivateKeySigner,
    calls: &[OutCall],
    nonce: u64,
    chain_id: u64,
    tip: U256,
    max_fee: U256,
) -> Result<FrameTx> {
    let sender = signer.address();
    let mut frames = vec![Frame {
        mode: FRAME_MODE_VERIFY,
        flags: APPROVE_EXECUTION_AND_PAYMENT,
        target: Some(sender),
        execution_gas: SHIELD_VERIFY_GAS,
        state_gas: 0,
        value: U256::ZERO,
        data: Bytes::new(),
    }];
    let last = calls.len().saturating_sub(1);
    for (i, call) in calls.iter().enumerate() {
        let flags = if calls.len() > 1 && i != last {
            ATOMIC_BATCH_FLAG
        } else {
            0
        };
        frames.push(Frame {
            mode: FRAME_MODE_SENDER,
            flags,
            target: Some(call.target),
            execution_gas: call.execution_gas,
            state_gas: call.state_gas,
            value: call.value,
            data: call.data.clone(),
        });
    }
    let mut tx = base(sender, frames, nonce, chain_id, tip, max_fee, sender);
    tx.sign_secp256k1(0, signer)?;
    tx.check_resource_limits()?;
    Ok(tx)
}

/// Smart account pays gas. Owner signs the frame tx; `executeBatch` sees
/// `msg.sender == address(this)` and skips the inner ECDSA.
pub fn account_frames(
    account: Address,
    owner: &PrivateKeySigner,
    calls: &[Call],
    nonce: u64,
    chain_id: u64,
    tip: U256,
    max_fee: U256,
    execution_gas: u64,
    state_gas: u64,
) -> Result<FrameTx> {
    let exec = FrameAccount::executeBatchCall {
        calls: calls
            .iter()
            .map(|c| kohaku_minimal_shield::abis::FrameAccount::Call {
                target: c.target,
                value: c.value,
                data: c.data.clone(),
            })
            .collect(),
        signature: Bytes::new(),
    }
    .abi_encode();
    let frames = vec![
        Frame {
            mode: FRAME_MODE_VERIFY,
            flags: APPROVE_EXECUTION_AND_PAYMENT,
            target: Some(account),
            execution_gas: APPROVE_EXEC,
            state_gas: APPROVE_STATE,
            value: U256::ZERO,
            data: Bytes::from(FrameAccount::approveSenderCall {}.abi_encode()),
        },
        Frame {
            mode: FRAME_MODE_SENDER,
            flags: 0,
            target: Some(account),
            execution_gas,
            state_gas,
            value: U256::ZERO,
            data: Bytes::from(exec),
        },
    ];
    let mut tx = base(
        account,
        frames,
        nonce,
        chain_id,
        tip,
        max_fee,
        owner.address(),
    );
    tx.sign_secp256k1(0, owner)?;
    tx.check_resource_limits()?;
    Ok(tx)
}

pub fn shield_calldata(inner: [u8; 32]) -> Bytes {
    Bytes::from(
        ShieldedPool::shieldCall {
            inner: inner.into(),
        }
        .abi_encode(),
    )
}

pub fn publish_calldata(epoch: u64) -> Bytes {
    Bytes::from(ShieldedPool::publishEpochRootCall { epoch }.abi_encode())
}

/// Append `publishEpochRoot` as the last SENDER frame. The previous SENDER
/// carries the atomic-batch flag so the publication lands with the call that
/// changed the root. Spend tails cannot use this: they have one DEFAULT frame.
pub fn append_pool_publish(tx: &mut FrameTx, pool: Address, epoch: u64) {
    if let Some(frame) = tx
        .frames
        .iter_mut()
        .rev()
        .find(|frame| frame.mode == FRAME_MODE_SENDER)
    {
        frame.flags |= ATOMIC_BATCH_FLAG;
    }
    tx.frames.push(Frame {
        mode: FRAME_MODE_SENDER,
        flags: 0,
        target: Some(pool),
        execution_gas: SETTLE_FRAME_GAS,
        state_gas: SETTLE_FRAME_STATE_GAS,
        value: U256::ZERO,
        data: publish_calldata(epoch),
    });
}

fn base(
    sender: Address,
    frames: Vec<Frame>,
    nonce: u64,
    chain_id: u64,
    tip: U256,
    max_fee: U256,
    sig_signer: Address,
) -> FrameTx {
    FrameTx {
        chain_id,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: nonce,
        sender,
        frames,
        signatures: vec![FrameSig::secp256k1(sig_signer)],
        max_priority_fee: tip,
        max_fee,
        max_blob_fee: U256::ZERO,
        blob_hashes: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::{OutCall, account_frames, append_pool_publish, eoa_frames};
    use alloy::{
        primitives::{Address, U256},
        signers::local::PrivateKeySigner,
    };
    use kohaku_frametx_kit::ATOMIC_BATCH_FLAG;
    use kohaku_minimal_shield::Call;

    fn n(v: u64) -> U256 {
        U256::try_from(v).expect("u64 fits")
    }

    #[test]
    fn eoa_multicall_sets_atomic_flag_on_all_but_last() {
        let signer = PrivateKeySigner::random();
        let calls = vec![
            OutCall::simple(Address::repeat_byte(1), n(1)),
            OutCall::simple(Address::repeat_byte(2), n(2)),
        ];
        let mut tx = eoa_frames(&signer, &calls, 0, 8141, n(1), n(2)).unwrap();
        assert_eq!(tx.sender, signer.address());
        assert_eq!(tx.frames[1].flags, ATOMIC_BATCH_FLAG);
        assert_eq!(tx.frames[2].flags, 0);
        let pool = Address::repeat_byte(4);
        append_pool_publish(&mut tx, pool, 3);
        assert_eq!(tx.frames[2].flags, ATOMIC_BATCH_FLAG);
        assert_eq!(tx.frames[3].flags, 0);
        assert_eq!(tx.frames[3].target, Some(pool));
        assert_eq!(tx.signatures[0].signer, signer.address());
    }

    #[test]
    fn account_sender_is_the_account_and_owner_signs() {
        let owner = PrivateKeySigner::random();
        let account = Address::repeat_byte(9);
        let calls = vec![Call {
            target: Address::repeat_byte(3),
            value: n(5),
            data: Default::default(),
        }];
        let tx = account_frames(account, &owner, &calls, 1, 8141, n(1), n(2), 1000, 1000).unwrap();
        assert_eq!(tx.sender, account);
        assert_ne!(tx.signatures[0].signer, account);
        assert_eq!(tx.signatures[0].signer, owner.address());
        assert_eq!(tx.frames.len(), 2);
        assert!(!tx.frames[0].data.is_empty());
        assert!(!tx.frames[1].data.is_empty());
    }
}
