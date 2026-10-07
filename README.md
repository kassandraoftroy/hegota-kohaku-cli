# hegota-kohaku-cli

CLI wallet for Hegota (FrameTx + minimal shielded pool). Mirrors kohaku-cli flows against hegota EIPs.

## Setup

You need [kohaku-rs](https://github.com/ethereum/kohaku-rs) on branch `experiments/minimal-shield-frames` as a path dependency (see `Cargo.toml`).

```bash
cargo build --release
export PATH="$PWD/target/release:$PATH"
export HEGOTA_RPC_URL="https://rpc1.privacy.ethrex.xyz"
```

Devnet chain id is **8141**. Tor is used by default for RPC; pass `--without-tor` or set `DISABLE_TOR=1` only if you must.

Optional first-sync speed-up (opt-in; never defaulted by the binary):

```bash
export EVENT_CACHE_ENDPOINT="https://artifacts.0000000000.org/hegota/devnet/pool-sync.bin"
```

Fund EOAs from the public faucet / whoever distributes devnet ETH for this network.

## Demo

```bash
kohaku-hegota create-wallet dev
kohaku-hegota balances --verbose
# fund EOA 0, then:
kohaku-hegota shield --from 0 --amount-formatted 0.01
kohaku-hegota unshield --next --amount-formatted 0.005
kohaku-hegota claim --from 0   # if you have withdrawal credit
kohaku-hegota rescan           # recover notes from mnemonic + chain
```

Dry-runs are the default in `--non-interactive` mode unless `--broadcast` is set. Confirmations show human ETH amounts and fee estimates.

## What's new in 0.0.2

- Tor for FrameTx (isolated circuit per send) when Tor is enabled
- Offline CREATE2 FrameAccount prediction + pinned creation bytecode
- Sync cache reorg margin (32 blocks) and stricter event-cache validation
- Pending notes kept after broadcast; confirmed on sync; `rescan` / `claim`
- Fee cap (`max_fee_gwei`), fee shown in confirm, profile chain id for signing
- Stricter receipts; safer dry-run (no pre-confirm signed txs / silent split-resend)

```bash
kohaku-hegota doctor   # offline CREATE2 pin, fee cap, and Tor mode
```
