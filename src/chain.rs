//! Network profile and RPC helpers. The only HTTP endpoint is the Ethereum RPC.

use std::path::PathBuf;

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
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

pub fn frame_client(url: &reqwest::Url) -> FrameTxClient {
    FrameTxClient::new(url.clone())
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

pub async fn http_provider(url: reqwest::Url, without_tor_flag: bool) -> Result<impl Provider + Clone> {
    let client = if without_tor(without_tor_flag) {
        RpcClient::new_http(url)
    } else {
        tor_session().await?.rpc_client(url)?
    };
    Ok(ProviderBuilder::new().connect_client(client))
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
