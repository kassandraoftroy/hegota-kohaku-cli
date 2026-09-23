# Current approveSender factory: 0x445f97B761c3F99f0e2F9e6f4ADAfcc98486f5fC
# A new deployment changes CREATE2 addresses. Paste that address into
# networks/devnet.toml `factory` (or export HEGOTA_FACTORY).
deploy-factory:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${HEGOTA_RPC_URL:?set HEGOTA_RPC_URL}"
    : "${HEGOTA_DEPLOYER_PK:?set HEGOTA_DEPLOYER_PK}"
    cd ../frame-privacy-acct
    forge create src/FrameAccountFactory.sol:FrameAccountFactory \
        --rpc-url "$HEGOTA_RPC_URL" \
        --private-key "$HEGOTA_DEPLOYER_PK" \
        --broadcast \
        --gas-price 3000000000 \
        --priority-gas-price 1000000000 \
        --gas-limit 12000000
