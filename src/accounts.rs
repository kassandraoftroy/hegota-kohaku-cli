//! Public EOAs and FrameAccount owners.

use std::future::Future;

use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use anyhow::{Result, bail};
use kohaku_minimal_shield::{abis::FrameAccountFactory, frame_account_salt};

use crate::{
    chain::Network,
    wallet::{Secrets, SeedAccounts, eoa_path, signer_at, smart_owner_path},
};

const SCAN_BATCH: u32 = 5;
const SCAN_LIMIT: u32 = 1000;

/// Indexes kept after a gap scan: `0..=last_used`, or nothing when the first batch is unused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexScan {
    pub indexes: Vec<u32>,
    pub next: u32,
}

#[derive(Debug, Clone)]
pub struct Eoa {
    pub index: u32,
    pub signer: PrivateKeySigner,
    pub balance: U256,
}

#[derive(Debug, Clone)]
pub struct Smart {
    pub index: u32,
    pub owner: PrivateKeySigner,
    pub account: Address,
    pub deployed: bool,
    pub balance: U256,
}

pub fn eoa_signer(secrets: &Secrets, index: u32) -> Result<PrivateKeySigner> {
    signer_at(&secrets.mnemonic, &eoa_path(index))
}

pub fn smart_owner(secrets: &Secrets, index: u32) -> Result<PrivateKeySigner> {
    signer_at(&secrets.mnemonic, &smart_owner_path(index))
}

pub async fn predict_account(
    provider: &impl Provider,
    factory: Address,
    owner: Address,
) -> Result<Address> {
    let salt = frame_account_salt(owner);
    let addr = FrameAccountFactory::new(factory, provider)
        .getAddress(owner, salt)
        .call()
        .await?;
    Ok(addr)
}

pub async fn load_eoas(
    provider: &impl Provider,
    secrets: &Secrets,
    mut on_rpc: impl FnMut(),
) -> Result<Vec<Eoa>> {
    let mut out = Vec::new();
    for index in &secrets.public_indexes {
        let signer = eoa_signer(secrets, *index)?;
        let balance = provider.get_balance(signer.address()).await?;
        on_rpc();
        out.push(Eoa {
            index: *index,
            signer,
            balance,
        });
    }
    Ok(out)
}

pub async fn load_smart(
    provider: &impl Provider,
    net: &Network,
    secrets: &Secrets,
    mut on_rpc: impl FnMut(),
) -> Result<Vec<Smart>> {
    if net.acct_factory.is_zero() {
        return Ok(Vec::new());
    }
    let mut seen = secrets.smart_indexes.clone();
    seen.sort_unstable();
    seen.dedup();
    let mut out = Vec::new();
    let mut j = 0u32;
    let limit = seen.iter().copied().max().unwrap_or(0).saturating_add(8);
    loop {
        if j > limit && !seen.contains(&j) {
            break;
        }
        let owner = smart_owner(secrets, j)?;
        let account = predict_account(provider, net.acct_factory, owner.address()).await?;
        on_rpc();
        let code = provider.get_code_at(account).await?;
        on_rpc();
        let deployed = !code.is_empty();
        if deployed || seen.contains(&j) {
            let balance = provider.get_balance(account).await?;
            on_rpc();
            out.push(Smart {
                index: j,
                owner,
                account,
                deployed,
                balance,
            });
            j += 1;
            continue;
        }
        if j > seen.iter().copied().max().unwrap_or(0) {
            break;
        }
        j += 1;
    }
    Ok(out)
}

/// Lowest `j` whose FrameAccount has no code.
pub async fn next_free_smart(
    provider: &impl Provider,
    net: &Network,
    secrets: &Secrets,
) -> Result<Smart> {
    let factory = crate::chain::require_factory(net)?;
    for j in 0..10_000u32 {
        let owner = smart_owner(secrets, j)?;
        let account = predict_account(provider, factory, owner.address()).await?;
        let code = provider.get_code_at(account).await?;
        if code.is_empty() {
            let balance = provider.get_balance(account).await?;
            return Ok(Smart {
                index: j,
                owner,
                account,
                deployed: false,
                balance,
            });
        }
    }
    anyhow::bail!("no free smart-account index")
}

/// Non-zero nonce, contract code, or an ETH balance means the address has been used.
pub async fn address_was_used(provider: &impl Provider, address: Address) -> Result<bool> {
    if provider.get_transaction_count(address).await? != 0 {
        return Ok(true);
    }
    if !provider.get_code_at(address).await?.is_empty() {
        return Ok(true);
    }
    Ok(!provider.get_balance(address).await?.is_zero())
}

/// Scan the first 5 indexes, then the next 5, until a batch is entirely unused.
pub async fn scan_index_batches<F, Fut>(mut used: F) -> Result<IndexScan>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let mut last_used = None;
    let mut start = 0u32;
    loop {
        if start >= SCAN_LIMIT {
            bail!("account scan stopped at index {SCAN_LIMIT}");
        }
        let mut batch_used = false;
        let end = start.saturating_add(SCAN_BATCH).min(SCAN_LIMIT);
        for index in start..end {
            if used(index).await? {
                last_used = Some(index);
                batch_used = true;
            }
        }
        if !batch_used {
            break;
        }
        start = end;
    }
    let indexes = match last_used {
        Some(last) => (0..=last).collect(),
        None => Vec::new(),
    };
    let next = last_used.map_or(0, |index| index.saturating_add(1));
    Ok(IndexScan { indexes, next })
}

/// Import scan. Public EOAs are the derived addresses. Frame accounts are the
/// CREATE2 addresses of the owner keys, not the owner addresses themselves.
pub async fn scan_imported(
    provider: &impl Provider,
    net: &Network,
    mnemonic: &str,
) -> Result<(SeedAccounts, bool)> {
    let public = scan_index_batches(|index| async move {
        let signer = signer_at(mnemonic, &eoa_path(index))?;
        address_was_used(provider, signer.address()).await
    })
    .await?;
    let smart_scanned = !net.acct_factory.is_zero();
    let smart = if smart_scanned {
        scan_index_batches(|index| async move {
            let owner = signer_at(mnemonic, &smart_owner_path(index))?;
            let account = predict_account(provider, net.acct_factory, owner.address()).await?;
            address_was_used(provider, account).await
        })
        .await?
    } else {
        IndexScan {
            indexes: Vec::new(),
            next: 0,
        }
    };
    Ok((
        SeedAccounts {
            public_indexes: public.indexes,
            next_public: public.next,
            smart_indexes: smart.indexes,
        },
        smart_scanned,
    ))
}

#[cfg(test)]
mod tests {
    use super::scan_index_batches;

    #[tokio::test]
    async fn unused_first_batch_stores_nothing() {
        let mut calls = 0u32;
        let scan = scan_index_batches(|_| {
            calls += 1;
            async { Ok(false) }
        })
        .await
        .unwrap();
        assert_eq!(calls, 5);
        assert!(scan.indexes.is_empty());
        assert_eq!(scan.next, 0);
    }

    #[tokio::test]
    async fn used_at_two_stores_through_that_index() {
        let mut calls = 0u32;
        let scan = scan_index_batches(|index| {
            calls += 1;
            async move { Ok(index == 2) }
        })
        .await
        .unwrap();
        // First batch 0..5 used; second batch 5..10 empty → stop.
        assert_eq!(calls, 10);
        assert_eq!(scan.indexes, (0..=2).collect::<Vec<_>>());
        assert_eq!(scan.next, 3);
    }

    #[tokio::test]
    async fn used_at_zero_and_seven_scans_three_batches() {
        let mut calls = 0u32;
        let scan = scan_index_batches(|index| {
            calls += 1;
            async move { Ok(index == 0 || index == 7) }
        })
        .await
        .unwrap();
        // Batches 0..5 and 5..10 used; 10..15 empty → stop.
        assert_eq!(calls, 15);
        assert_eq!(scan.indexes, (0..=7).collect::<Vec<_>>());
        assert_eq!(scan.next, 8);
    }
}
