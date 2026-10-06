//! Network profile and RPC helpers. The only HTTP endpoint is the Ethereum RPC.

use std::{future::Future, path::PathBuf};

use alloy::{
    primitives::{Address, Bytes},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::client::RpcClient,
};
use anyhow::{Context, Result, bail};
use kohaku_frametx_kit::FrameTxClient;
use kohaku_minimal_shield::Pool;
use kohaku_tor_rpc::TorRpc;
use serde::Deserialize;
use tokio::sync::OnceCell;

#[derive(Debug, Clone)]
pub struct Network {
    pub name: String,
    pub chain_id: u64,
    pub pool: Address,
    pub acct_factory: Address,
    pub multicall3: Address,
    pub deployed_block: u64,
    pub max_fee_gwei: Option<u64>,
    pub frame_account_creation_code: Vec<u8>,
    pub tokens: Vec<Token>,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub symbol: String,
    pub address: Address,
    pub decimals: u8,
}

#[derive(Deserialize)]
struct NetworkFile {
    name: String,
    chain_id: u64,
    pool: String,
    acct_factory: String,
    multicall3: String,
    deployed_block: u64,
    #[serde(default)]
    max_fee_gwei: Option<u64>,
    #[serde(default)]
    frame_account_creation_code: Option<String>,
    #[serde(default)]
    tokens: Vec<TokenFile>,
}

#[derive(Deserialize)]
struct TokenFile {
    symbol: String,
    address: String,
    decimals: u8,
}

pub fn load_network(name: &str) -> Result<Network> {
    let raw = match name {
        "devnet" => include_str!("../networks/devnet.toml"),
        "testnet" => include_str!("../networks/testnet.toml"),
        "mainnet" => include_str!("../networks/mainnet.toml"),
        other => bail!("unknown network {other} (devnet, testnet, or mainnet)"),
    };
    let file: NetworkFile = toml::from_str(raw)?;
    let mut net = Network {
        name: file.name,
        chain_id: file.chain_id,
        pool: parse_addr(&file.pool)?,
        acct_factory: parse_addr(&file.acct_factory)?,
        multicall3: parse_addr(&file.multicall3)?,
        deployed_block: file.deployed_block,
        max_fee_gwei: file.max_fee_gwei,
        frame_account_creation_code: parse_bytes_opt(file.frame_account_creation_code.as_deref())?,
        tokens: file
            .tokens
            .iter()
            .map(|t| {
                Ok(Token {
                    symbol: t.symbol.clone(),
                    address: parse_addr(&t.address)?,
                    decimals: t.decimals,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    if let Ok(v) = std::env::var("HEGOTA_POOL") {
        net.pool = parse_addr(&v)?;
    }
    if let Ok(v) = std::env::var("HEGOTA_FACTORY") {
        net.acct_factory = parse_addr(&v)?;
    }
    if let Ok(v) = std::env::var("HEGOTA_MULTICALL3") {
        net.multicall3 = parse_addr(&v)?;
    }
    if let Ok(v) = std::env::var("HEGOTA_DEPLOYED_BLOCK") {
        net.deployed_block = v.parse().context("HEGOTA_DEPLOYED_BLOCK")?;
    }
    if let Ok(v) = std::env::var("HEGOTA_MAX_FEE_GWEI") {
        net.max_fee_gwei = Some(v.parse().context("HEGOTA_MAX_FEE_GWEI")?);
    }
    if let Ok(v) = std::env::var("HEGOTA_FRAME_ACCOUNT_CREATION_CODE") {
        net.frame_account_creation_code = parse_bytes(&v)?;
    }
    Ok(net)
}

pub fn require_factory(net: &Network) -> Result<Address> {
    if net.acct_factory.is_zero() {
        bail!(
            "FrameAccount factory is not set. Redeploy it with `just deploy-factory` and set \
             `acct_factory` in the network profile or HEGOTA_FACTORY. The previous factory's accounts \
             cannot approve themselves."
        );
    }
    Ok(net.acct_factory)
}

pub fn require_creation_code(net: &Network) -> Result<&[u8]> {
    if net.frame_account_creation_code.is_empty() {
        bail!(
            "frame_account_creation_code is missing from the network profile. Pin the FrameAccount \
             creation bytecode (not runtime code) so addresses can be predicted offline."
        );
    }
    Ok(&net.frame_account_creation_code)
}

/// EIP-1559 max-fee cap from the network profile (`max_fee_gwei`), if set.
pub fn max_fee_cap(net: &Network) -> Option<alloy::primitives::U256> {
    net.max_fee_gwei.map(|gwei| {
        alloy::primitives::U256::from(gwei) * alloy::primitives::U256::from(1_000_000_000u64)
    })
}

pub fn pool_of(net: &Network) -> Pool {
    Pool {
        chain_id: net.chain_id,
        address: net.pool,
        factory: net.acct_factory,
        deployed_block: net.deployed_block,
    }
}

pub fn rpc_url(flag: Option<String>) -> Result<reqwest::Url> {
    let raw = flag
        .or_else(|| std::env::var("HEGOTA_RPC_URL").ok())
        .context("pass --rpc-url or set HEGOTA_RPC_URL")?;
    raw.parse().context("rpc url")
}

/// FrameTx client: Tor-isolated when Tor is on, clearnet otherwise. Fails closed if Tor is required.
pub async fn frame_client(url: &reqwest::Url, without_tor_flag: bool) -> Result<FrameTxClient> {
    if without_tor(without_tor_flag) {
        Ok(FrameTxClient::new(url.clone()))
    } else {
        let client = tor_session()
            .await
            .context("Tor is required for FrameTx; pass --without-tor or set DISABLE_TOR=1 to use clearnet")?
            .isolated_rpc_client(url.clone())
            .context("Tor RPC client for FrameTx")?;
        Ok(FrameTxClient::from_rpc_client(client))
    }
}

static TOR: OnceCell<TorRpc> = OnceCell::const_new();

pub async fn tor_session() -> Result<&'static TorRpc> {
    TOR.get_or_try_init(TorRpc::connect).await
}

pub fn without_tor(flag: bool) -> bool {
    flag || std::env::var("DISABLE_TOR").ok().as_deref() == Some("1")
}

/// Interactive runs print a warning when Tor is off.
pub fn warn_if_tor_disabled(flag: bool, non_interactive: bool) {
    if !non_interactive && without_tor(flag) {
        eprintln!("warning: tor is disabled");
    }
}

/// Shared-circuit provider for pool sync / long-lived reads.
pub async fn http_provider(url: reqwest::Url, without_tor_flag: bool) -> Result<impl Provider + Clone> {
    let client = if without_tor(without_tor_flag) {
        RpcClient::new_http(url)
    } else {
        tor_session().await?.shared_rpc_client(url)?
    };
    Ok(ProviderBuilder::new().connect_client(client))
}

/// Run `f` on a short-lived provider that uses one Tor isolation session (or clearnet).
pub async fn with_isolated_provider<F, Fut, T>(
    url: reqwest::Url,
    without_tor_flag: bool,
    f: F,
) -> Result<T>
where
    F: FnOnce(RootProvider) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let client = if without_tor(without_tor_flag) {
        RpcClient::new_http(url)
    } else {
        tor_session().await?.isolated_rpc_client(url)?
    };
    f(RootProvider::new(client)).await
}

/// Abort when the RPC chain id or pool bytecode does not match the network profile.
pub async fn ensure_rpc_matches_network(
    provider: &impl Provider,
    net: &Network,
) -> Result<()> {
    let chain = provider.get_chain_id().await?;
    if chain != net.chain_id {
        bail!(
            "RPC chain id {chain} does not match network profile {} (chain {}). Check --rpc-url / HEGOTA_RPC_URL.",
            net.name,
            net.chain_id
        );
    }
    if !net.pool.is_zero() {
        let code = provider.get_code_at(net.pool).await?;
        if code.is_empty() {
            bail!(
                "no contract code at pool {:#x} on chain {}. Check the network profile or RPC.",
                net.pool,
                net.chain_id
            );
        }
    }
    Ok(())
}

pub fn indexer_path(data_dir: &std::path::Path, wallet: &str, network: &str) -> PathBuf {
    data_dir
        .join(wallet)
        .join(format!("indexer-{network}.redb"))
}

fn parse_addr(s: &str) -> Result<Address> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Address::ZERO);
    }
    s.parse().with_context(|| format!("address {s}"))
}

fn parse_bytes_opt(s: Option<&str>) -> Result<Vec<u8>> {
    match s {
        None | Some("") => Ok(Vec::new()),
        Some(raw) => parse_bytes(raw),
    }
}

fn parse_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    if s.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s).with_context(|| "frame_account_creation_code hex")
}

#[allow(dead_code)]
pub fn creation_code_bytes(net: &Network) -> Bytes {
    Bytes::from(net.frame_account_creation_code.clone())
}
