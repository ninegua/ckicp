# ckICP Main Canister
ckICP Main canister on the Internet Computer.

# Architecture
The ICP part consists of 2 canisters: a *minter* canister, and an *eth_state* canister.

## Minter Canister
This canister is responsible for issuing minting signatures using tECDSA, and transferring ICP when it gets
notifications about burned ckICP from the *eth_state* canister.

## ETH State Sync Canister
This canister is responsible for syncing states from Ethereum, and notifying the minter.

# License
MIT
