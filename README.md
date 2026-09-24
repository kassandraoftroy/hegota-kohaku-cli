# hegota-kohaku-cli

a cli that mirors the functionality of kohaku-cli but works with hegota EIPs and a new ETH mixer that integrates the hegota EIPs

## setup

you need the kohaku-rs repo at this branch https://github.com/ethereum/kohaku-rs/tree/experiments/minimal-shield-frames

make sure to correctly point to your path of kohaku-rs repo in Cargo.toml (these lines)

```
kohaku-frametx-kit = { path = "../kohaku-rs/crates/frametx-kit" }
kohaku-kv-store = { path = "../kohaku-rs/crates/kv-store" }
kohaku-minimal-shield = { path = "../kohaku-rs/crates/minimal-shield" }
```


now from this repo root run

```
cargo build --release
```

set env vars:

```
export PATH="$PWD/target/release:$PATH"
export HEGOTA_RPC_URL="<hegota devnet rpc>"
```

you need a devnet RPC url.

now you can run all the `kohaku-hegota` commands and demo the wallet.

## demo

```
kohaku-hegota create-wallet dev
```

creates your wallet


```
kohaku-hegota balances --verbose
```

sync wallet see empty balances. (slow only first time) 

copy EOA zero to fund it. now fund EOA 0 with some devnet ETH.

```
kohaku-hegota shield
```

shield some eth

```
kohaku-hegota balances --verbose
```

see result

```
kohaku-hegota unshield --next
```

unshield some eth to your own fresh EOA

```
kohaku-hegota unshield --next --tail-calls 0xRecipient::{amount of ETH to forward in wei}
```

unshield some eth to your own fresh smart account which then forwards ETH to 0xRecipient.

```
kohaku-hegota balances --verbose
```

see wallet result now