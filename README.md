# ckICP Main Canister
ckICP Main canister on the Internet Computer.

# Architecture
The ICP part consists of 2 canisters: a *minter* canister, and an *eth_state* canister.

## Minter Canister
This canister is responsible for issuing minting signatures using tECDSA, and transferring 
ICP when it gets notifications about burned ckICP from the *eth_state* canister.

```
mint_ckicp:
    1. ICRC2 transfer
    2. generate tecdsa signature
release_icp:
    1. check caller is eth_state canister
    2. record event uid
    3. transfer ICP
```

## ETH State Sync Canister
This canister is responsible for syncing states from Ethereum, and notifying the minter.

```
timer:
    call sync_events every x minutes
sync_events:
    look for BurnToIcp and BurnToIcpAccountId events
    call release_icp of minter canister
```

## ICP -> ckICP User Flow
1. User has an ETH wallet with some ETH in it, and an ICP wallet with some ICP in it.
2. Call `mint_ckicp` of the ckICP minter canister.
3. Wait to get signature (if the call fails, calculate `MsgId` deterministically, then use `MsgId` to query for signature).
4. Use the signature to call `selfMint` of the ckICP ETH contract.
5. Get ckICP in return.

## ckICP -> ICP User Flow
1. User has ckICP in an ETH wallet, and an ICP wallet (can be empty).
2. Call `burn` or `burnToAccountId` of the ckICP ETH contract.
3. Wait to get ICP in the ICP wallet.

# License
MIT
