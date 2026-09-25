//! Public EOAs and FrameAccount owners.

use std::future::Future;

use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Result, bail};
use kohaku_minimal_shield::{abis::FrameAccountFactory, frame_account_salt};

use crate::{
    chain::{self, Network, Token},
    wallet::{Secrets, SeedAccounts, eoa_path, signer_at, smart_owner_path},
};

const SCAN_BATCH: u32 = 5;
const SCAN_LIMIT: u32 = 1000;

sol! {
    #[sol(rpc)]
    interface Erc20Balance {
        function balanceOf(address account) external view returns (uint256);
    }
}

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

/// Non-zero ERC-20 holding discovered during an isolated session.
#[derive(Debug, Clone)]
pub struct TokenAmount {
    pub symbol: String,
    pub amount: U256,
    pub decimals: u8,
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

async fn fetch_tokens(
    provider: &impl Provider,
    tokens: &[Token],
    account: Address,
) -> Result<(Vec<TokenAmount>, u64)> {
    let mut held = Vec::new();
    let mut rpcs = 0u64;
    for token in tokens {
        let amount = Erc20Balance::new(token.address, provider)
            .balanceOf(account)
            .call()
            .await?;
        rpcs += 1;
        if !amount.is_zero() {
            held.push(TokenAmount {
                symbol: token.symbol.clone(),
                amount,
                decimals: token.decimals,
            });
        }
    }
    Ok((held, rpcs))
}

/// Load EOAs; each index uses its own Tor isolation session.
/// When `tokens` is non-empty, `balanceOf` calls share that session.
pub async fn load_eoas(
    url: reqwest::Url,
    without_tor: bool,
    secrets: &Secrets,
    tokens: &[Token],
    mut on_rpc: impl FnMut(),
) -> Result<(Vec<Eoa>, Vec<Vec<TokenAmount>>)> {
    let mut out = Vec::new();
    let mut token_lists = Vec::new();
    for index in &secrets.public_indexes {
        let index = *index;
        let mnemonic = secrets.mnemonic.clone();
        let tokens = tokens.to_vec();
        let (eoa, held, rpcs) =
            chain::with_isolated_provider(url.clone(), without_tor, |provider| async move {
                let signer = signer_at(&mnemonic, &eoa_path(index))?;
                let balance = provider.get_balance(signer.address()).await?;
                let mut rpcs = 1u64;
                let (held, token_rpcs) =
                    fetch_tokens(&provider, &tokens, signer.address()).await?;
                rpcs += token_rpcs;
                Ok((
                    Eoa {
                        index,
                        signer,
                        balance,
                    },
                    held,
                    rpcs,
                ))
            })
            .await?;
        for _ in 0..rpcs {
            on_rpc();
        }
        out.push(eoa);
        token_lists.push(held);
    }
    Ok((out, token_lists))
}

/// Load smart accounts; each index `j` uses its own Tor isolation session.
/// Kept slots also fetch `tokens` on that same session.
pub async fn load_smart(
    url: reqwest::Url,
    without_tor: bool,
    net: &Network,
    secrets: &Secrets,
    tokens: &[Token],
    mut on_rpc: impl FnMut(),
) -> Result<(Vec<Smart>, Vec<Vec<TokenAmount>>)> {
    if net.acct_factory.is_zero() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut seen = secrets.smart_indexes.clone();
    seen.sort_unstable();
    seen.dedup();
    let mut out = Vec::new();
    let mut token_lists = Vec::new();
    let mut j = 0u32;
    let limit = seen.iter().copied().max().unwrap_or(0).saturating_add(8);
    let factory = net.acct_factory;
    let mnemonic = secrets.mnemonic.clone();
    loop {
        if j > limit && !seen.contains(&j) {
            break;
        }
        let seen = seen.clone();
        let mnemonic = mnemonic.clone();
        let tokens = tokens.to_vec();
        let (smart, held, rpcs, stop) =
            chain::with_isolated_provider(url.clone(), without_tor, |provider| async move {
                let owner = signer_at(&mnemonic, &smart_owner_path(j))?;
                let account = predict_account(&provider, factory, owner.address()).await?;
                let mut rpcs = 1u64;
                let code = provider.get_code_at(account).await?;
                rpcs += 1;
                let deployed = !code.is_empty();
                if deployed || seen.contains(&j) {
                    let balance = provider.get_balance(account).await?;
                    rpcs += 1;
                    let (held, token_rpcs) = fetch_tokens(&provider, &tokens, account).await?;
                    rpcs += token_rpcs;
                    return Ok((
                        Some(Smart {
                            index: j,
                            owner,
                            account,
                            deployed,
                            balance,
                        }),
                        held,
                        rpcs,
                        false,
                    ));
                }
                let stop = j > seen.iter().copied().max().unwrap_or(0);
                Ok((None, Vec::new(), rpcs, stop))
            })
            .await?;
        for _ in 0..rpcs {
            on_rpc();
        }
        if let Some(smart) = smart {
            out.push(smart);
            token_lists.push(held);
            j += 1;
            continue;
        }
        if stop {
            break;
        }
        j += 1;
    }
    Ok((out, token_lists))
}

/// Lowest `j` whose FrameAccount has no code. Each probe uses its own isolation session.
pub async fn next_free_smart(
    url: reqwest::Url,
    without_tor: bool,
    net: &Network,
    secrets: &Secrets,
) -> Result<Smart> {
    let factory = crate::chain::require_factory(net)?;
    let mnemonic = secrets.mnemonic.clone();
    for j in 0..10_000u32 {
        let mnemonic = mnemonic.clone();
        let smart = chain::with_isolated_provider(url.clone(), without_tor, |provider| async move {
            let owner = signer_at(&mnemonic, &smart_owner_path(j))?;
            let account = predict_account(&provider, factory, owner.address()).await?;
            let code = provider.get_code_at(account).await?;
            if !code.is_empty() {
                return Ok(None);
            }
            let balance = provider.get_balance(account).await?;
            Ok(Some(Smart {
                index: j,
                owner,
                account,
                deployed: false,
                balance,
            }))
        })
        .await?;
        if let Some(smart) = smart {
            return Ok(smart);
        }
    }
    anyhow::bail!("no free smart-account index")
}

/// One smart account on a single isolation session.
pub async fn load_one_smart(
    url: reqwest::Url,
    without_tor: bool,
    net: &Network,
    secrets: &Secrets,
    j: u32,
) -> Result<Smart> {
    let factory = crate::chain::require_factory(net)?;
    let mnemonic = secrets.mnemonic.clone();
    chain::with_isolated_provider(url, without_tor, |provider| async move {
        let owner = signer_at(&mnemonic, &smart_owner_path(j))?;
        let account = predict_account(&provider, factory, owner.address()).await?;
        let code = provider.get_code_at(account).await?;
        let balance = provider.get_balance(account).await?;
        Ok(Smart {
            index: j,
            owner,
            account,
            deployed: !code.is_empty(),
            balance,
        })
    })
    .await
}

/// Non-zero nonce, contract code, or an ETH balance means the address has been used.
///
/// Issues one JSON-RPC batch (`eth_getTransactionCount` + `eth_getCode` +
/// `eth_getBalance`) so a Tor round-trip checks all three at once.
pub async fn address_was_used(provider: &impl Provider, address: Address) -> Result<bool> {
    use alloy::rpc::client::BatchRequest;
    let mut batch = BatchRequest::new(provider.client());
    let nonce_w = batch
        .add_call("eth_getTransactionCount", &(address, "latest"))
        .map_err(|e| anyhow::anyhow!("batch nonce: {e}"))?;
    let code_w = batch
        .add_call("eth_getCode", &(address, "latest"))
        .map_err(|e| anyhow::anyhow!("batch code: {e}"))?;
    let bal_w = batch
        .add_call("eth_getBalance", &(address, "latest"))
        .map_err(|e| anyhow::anyhow!("batch balance: {e}"))?;
    batch
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("batch send: {e}"))?;
    let nonce: U256 = nonce_w
        .await
        .map_err(|e| anyhow::anyhow!("nonce response: {e}"))?;
    let code: alloy::primitives::Bytes = code_w
        .await
        .map_err(|e| anyhow::anyhow!("code response: {e}"))?;
    let balance: U256 = bal_w
        .await
        .map_err(|e| anyhow::anyhow!("balance response: {e}"))?;
    Ok(!nonce.is_zero() || !code.is_empty() || !balance.is_zero())
}

/// Scan the first 5 indexes, then the next 5, until a batch is entirely unused.
///
/// `on_index(done, total)` is called after each index probe. `total` is the end
/// of the current scan batch (grows as more batches are needed).
pub async fn scan_index_batches<F, Fut>(
    mut used: F,
    mut on_index: impl FnMut(u64, u64),
) -> Result<IndexScan>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    let mut last_used = None;
    let mut start = 0u32;
    let mut done = 0u64;
    loop {
        if start >= SCAN_LIMIT {
            bail!("account scan stopped at index {SCAN_LIMIT}");
        }
        let mut batch_used = false;
        let end = start.saturating_add(SCAN_BATCH).min(SCAN_LIMIT);
        let total = u64::from(end);
        if done == 0 {
            on_index(0, total.max(1));
        }
        for index in start..end {
            if used(index).await? {
                last_used = Some(index);
                batch_used = true;
            }
            done += 1;
            on_index(done, total.max(done));
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
/// Each index uses its own Tor isolation session; used-checks are JSON-RPC batched.
///
/// `on_progress(done, total)` tracks indexes probed across public then smart scans.
pub async fn scan_imported(
    url: reqwest::Url,
    without_tor: bool,
    net: &Network,
    mnemonic: &str,
    mut on_progress: impl FnMut(u64, u64),
) -> Result<(SeedAccounts, bool)> {
    use std::cell::Cell;

    let mnemonic_owned = mnemonic.to_string();
    let smart_later = !net.acct_factory.is_zero();
    let done = Cell::new(0u64);
    let total = Cell::new({
        let mut t = u64::from(SCAN_BATCH);
        if smart_later {
            t = t.saturating_add(u64::from(SCAN_BATCH));
        }
        t
    });
    on_progress(0, total.get().max(1));

    let mut report = |d: u64, t: u64| {
        done.set(d);
        if t > total.get() {
            total.set(t);
        }
        if d > total.get() {
            total.set(d);
        }
        on_progress(done.get(), total.get().max(1));
    };

    let public = {
        let url = url.clone();
        let mnemonic_owned = mnemonic_owned.clone();
        scan_index_batches(
            |index| {
                let url = url.clone();
                let mnemonic = mnemonic_owned.clone();
                async move {
                    chain::with_isolated_provider(url, without_tor, |provider| async move {
                        let signer = signer_at(&mnemonic, &eoa_path(index))?;
                        address_was_used(&provider, signer.address()).await
                    })
                    .await
                }
            },
            |batch_done, batch_total| {
                let mut t = batch_total;
                if smart_later {
                    t = t.saturating_add(u64::from(SCAN_BATCH));
                }
                report(batch_done, t);
            },
        )
        .await?
    };
    let public_done = done.get();
    let smart_scanned = smart_later;
    let smart = if smart_scanned {
        let factory = net.acct_factory;
        let mnemonic_owned = mnemonic.to_string();
        let url = url.clone();
        scan_index_batches(
            |index| {
                let url = url.clone();
                let mnemonic = mnemonic_owned.clone();
                async move {
                    chain::with_isolated_provider(url, without_tor, |provider| async move {
                        let owner = signer_at(&mnemonic, &smart_owner_path(index))?;
                        let account = predict_account(&provider, factory, owner.address()).await?;
                        address_was_used(&provider, account).await
                    })
                    .await
                }
            },
            |batch_done, batch_total| {
                report(
                    public_done.saturating_add(batch_done),
                    public_done.saturating_add(batch_total),
                );
            },
        )
        .await?
    } else {
        IndexScan {
            indexes: Vec::new(),
            next: 0,
        }
    };
    let finished = done.get().max(1);
    on_progress(finished, finished);
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
        let scan = scan_index_batches(
            |_| {
                calls += 1;
                async { Ok(false) }
            },
            |_, _| {},
        )
        .await
        .unwrap();
        assert_eq!(calls, 5);
        assert!(scan.indexes.is_empty());
        assert_eq!(scan.next, 0);
    }

    #[tokio::test]
    async fn used_at_two_stores_through_that_index() {
        let mut calls = 0u32;
        let scan = scan_index_batches(
            |index| {
                calls += 1;
                async move { Ok(index == 2) }
            },
            |_, _| {},
        )
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
        let scan = scan_index_batches(
            |index| {
                calls += 1;
                async move { Ok(index == 0 || index == 7) }
            },
            |_, _| {},
        )
        .await
        .unwrap();
        // Batches 0..5 and 5..10 used; 10..15 empty → stop.
        assert_eq!(calls, 15);
        assert_eq!(scan.indexes, (0..=7).collect::<Vec<_>>());
        assert_eq!(scan.next, 8);
    }
}
