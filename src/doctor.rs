//! Offline network-profile sanity check (`kohaku-hegota doctor`).

use alloy::primitives::Address;
use anyhow::{Result, bail};
use kohaku_minimal_shield::predict_frame_account;
use serde_json::{Value, json};

use crate::chain::{self, Network};

/// Known live CREATE2 vector for the pinned devnet factory + creation code.
pub const SELFCHECK_OWNER: &str = "0x77ce0b7bab0a63a59b27c84fe7a5dc6ca3ec556e";
pub const SELFCHECK_ACCOUNT: &str = "0x9b6c14e6bb1d0ac5616caf5adf0449e426217f4b";

/// Offline check: CREATE2 pin, fee cap presence, Tor mode. No RPC required.
pub fn run(net: &Network, without_tor_flag: bool) -> Result<Value> {
    let owner: Address = SELFCHECK_OWNER.parse()?;
    let expected: Address = SELFCHECK_ACCOUNT.parse()?;
    let creation = chain::require_creation_code(net)?;
    let predicted = predict_frame_account(net.acct_factory, owner, creation);
    let create2_ok = predicted == expected;
    let tor_disabled = chain::without_tor(without_tor_flag);
    let max_fee_gwei = net.max_fee_gwei;
    let body = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "network": net.name,
        "chain_id": net.chain_id,
        "factory": format!("{:#x}", net.acct_factory),
        "pool": format!("{:#x}", net.pool),
        "creation_code_bytes": creation.len(),
        "create2": {
            "owner": SELFCHECK_OWNER,
            "predicted": format!("{predicted:#x}"),
            "expected": SELFCHECK_ACCOUNT,
            "ok": create2_ok,
        },
        "max_fee_gwei": max_fee_gwei,
        "max_fee_cap_set": max_fee_gwei.is_some(),
        "tor": if tor_disabled { "clearnet" } else { "enabled" },
    });
    if !create2_ok {
        bail!(
            "CREATE2 pin mismatch: predicted {predicted:#x} != expected {expected:#x}. \
             Update frame_account_creation_code in the network profile."
        );
    }
    if max_fee_gwei.is_none() {
        bail!(
            "max_fee_gwei is unset on network {}; fee floods are uncapped",
            net.name
        );
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::load_network;

    #[test]
    fn doctor_devnet_pin_matches_known_vector() {
        let net = load_network("devnet").unwrap();
        let body = run(&net, true).unwrap();
        assert_eq!(body["create2"]["ok"], true);
        assert_eq!(body["max_fee_cap_set"], true);
    }
}
