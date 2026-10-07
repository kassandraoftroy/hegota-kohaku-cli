# Changelog

## 0.0.2

- Tor-backed `FrameTxClient` (isolated circuit) when Tor is on; fail closed otherwise
- Pin `frame_account_creation_code` + offline CREATE2 predict with RPC mismatch bail
- Strict CREATE2 for fund destinations (`transfer --to aN`, unshield tails / `--next`)
- `max_fee_gwei` fee cap; show fee / human amounts in confirmations
- Sync cache only through `latest-32`; always RPC-fetch the reorg window
- Harden `EVENT_CACHE_ENDPOINT` install validation (opt-in URL only)
- Keep pending notes after broadcast; confirm when commitment appears; `rescan` + `claim`
- Sign with profile `chain_id`; `ensure_rpc_matches_network` before sync, transfer, hydrate
- Dry-run no longer simulates/signs before confirm; no silent atomic split-resend
- Non-interactive `create-wallet` omits mnemonic from JSON
- Document `https://rpc1.privacy.ethrex.xyz` and optional event-cache URL
- `doctor` offline profile check (CREATE2 pin, fee cap)

## 0.0.1

- Initial Hegota wallet CLI
