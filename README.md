# hegota-kohaku-cli

a cli that mirors the functionality of kohaku-cli but works with hegota EIPs and a new ETH mixer that integrates the hegota privacy EIPs and frame txs for private txs with no brpadacster/relayer

# run

you need the kohaku-rs repo at this branch https://github.com/ethereum/kohaku-rs/tree/experiments/minimal-shield-frames

you also need minimal-shielded-pool repo here: https://github.com/soispoke/minimal-shielded-pool

now we assume you have these three repos in the same dir:

./kohaku-rs
./minimal-shielded-pool
./hegota-kohaku-cli

from kohaku-rs repo root run:

```
cargo run --manifest-path crates/Cargo.toml \
  -p kohaku-minimal-shield-circuit --bin convert-msp-artifacts -- \
  ../minimal-shielded-pool/build/spend_final.zkey \
  ../minimal-shielded-pool/build/spend_js/spend.wasm \
  crates/minimal-shield/.hegota-data/circuit
```

now from hegota-kohaku-cli repo root run

```
cargo build --release
```

set env vars:

```
export PATH="$PWD/target/release:$PATH"
export HEGOTA_RPC_URL="<hegota devnet rpc>"
export CIRCUIT_ARTIFACTS="<artifacts path>"
```



you'll find artifacts path here `<path>/kohaku-rs/crates/minimal-shield/.hegota-data/circuit`

you need a devnet RPC url.

now you can run all the `kohaku-hegota` commands and demo the wallet.


kohaku-hegota create-wallet dev

kohaku-hegota balances --verbose

{fund EOA 0}

kohaku-hegota shield

kohaku-hegota balances --verbose

kohaku-hegota unshield --next

kohaku-hegota unshield --next --tail-calls 0xRecipient::{amount of ETH to forward in wei}

kohaku-hegota balances --verbose