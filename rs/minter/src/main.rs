#![allow(clippy::unwrap_used)]
#![allow(unused_imports)]

use ckicp_minter::crypto::EcdsaSignature;
use ckicp_minter::memory::*;
use ckicp_minter::tecdsa::{ManagementCanister, SignWithECDSAReply};
use ckicp_minter::utils::*;

use candid::{candid_method, CandidType, Decode, Encode, Nat, Principal};
use ic_canister_log::{declare_log_buffer, export};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::{
    BoundedStorable, DefaultMemoryImpl, StableBTreeMap, StableCell, StableVec, Storable,
};

use rustic::access_control::*;
use rustic::inter_canister::*;
use rustic::reentrancy_guard::*;
use rustic::types::*;
use rustic::utils::*;
use rustic_macros::modifiers;

use serde_bytes::ByteBuf;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

use std::borrow::Cow;
use std::cell::RefCell;
use std::convert::From;
use std::time::Duration;

use k256::{
    ecdsa::VerifyingKey,
    elliptic_curve::{
        generic_array::{typenum::Unsigned, GenericArray},
        Curve,
    },
    PublicKey, Secp256k1,
};

use icrc_ledger_types::icrc1;
use icrc_ledger_types::icrc2;

type Amount = u64;
type MsgId = u128;

#[derive(CandidType, candid::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum EthRpcError {
    NoPermission,
    TooFewCycles(String),
    ServiceUrlParseError,
    ServiceUrlHostMissing,
    ServiceUrlHostNotAllowed(String),
    ProviderNotFound,
    HttpRequestError { code: u32, message: String },
}

#[derive(CandidType, candid::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReturnError {
    GenericError,
    InputError,
    Unauthorized,
    Expired,
    InterCanisterCallError(String),
    TecdsaSignatureError,
    EventSeen,
    TransferError(String),
    EthRpcError(EthRpcError),
    JsonParseError(String),
    EventLogError(LogError),
}

#[init]
#[candid_method(init)]
pub fn init() {
    rustic::rustic_init();
}

#[post_upgrade]
pub fn post_upgrade() {
    rustic::rustic_post_upgrade(false, false, false);

    // post upgrade code for your canister
}

#[query]
#[candid_method(query)]
pub fn get_ckicp_config() -> CkicpConfig {
    CKICP_CONFIG.with(|ckicp_config| {
        let ckicp_config = ckicp_config.borrow();
        ckicp_config.get().0.clone().unwrap()
    })
}

#[query]
#[candid_method(query)]
pub fn get_ckicp_state() -> CkicpState {
    CKICP_STATE.with(|ckicp_state| {
        let ckicp_state = ckicp_state.borrow();
        ckicp_state.get().0.clone().unwrap_or_default()
    })
}

#[query]
#[candid_method(query)]
pub fn get_nonce() -> u32 {
    let caller = ic_cdk::caller();
    let caller_subaccount = subaccount_from_principal(&caller);
    NONCE_MAP.with(|nonce_map| {
        let nonce_map = nonce_map.borrow();
        nonce_map.get(&caller_subaccount).unwrap_or(0)
    })
}

/// Nonce starts at 1 and is incremented for each call to mint_ckicp
/// MsgId is deterministically computed as xor_nibbles(keccak256(caller, nonce))
/// and does not need to be returned.
/// ICP is transferred using ICRC-2 approved transfer
#[update]
#[candid_method(update)]
pub async fn mint_ckicp(
    from_subaccount: icrc1::account::Subaccount,
    amount: Amount,
    target_eth_wallet: [u8; 20],
) -> Result<EcdsaSignature, ReturnError> {
    let _guard = ReentrancyGuard::new();
    let caller = canister_caller();
    let caller_subaccount = subaccount_from_principal(&caller);
    let nonce = NONCE_MAP.with(|nonce_map| {
        let mut nonce_map = nonce_map.borrow_mut();
        let nonce = nonce_map.get(&caller_subaccount).unwrap_or(0) + 1;
        nonce_map.insert(caller_subaccount, nonce);
        nonce
    });
    let msg_id = calc_msgid(&caller_subaccount, nonce);
    let config: CkicpConfig = get_ckicp_config();
    let now = canister_time();
    let expiry = now / 1_000_000_000 + config.expiry_seconds;

    fn update_status(msg_id: MsgId, amount: Amount, expiry: u64, state: MintState) {
        STATUS_MAP.with(|sm| {
            let mut sm = sm.borrow_mut();
            sm.insert(
                msg_id,
                MintStatus {
                    amount,
                    expiry,
                    state,
                },
            );
        });
    }

    update_status(msg_id, amount, expiry, MintState::Init);
    // ICRC-2 transfer
    let tx_args = icrc2::transfer_from::TransferFromArgs {
        spender_subaccount: None,
        from: icrc1::account::Account {
            owner: caller,
            subaccount: Some(from_subaccount),
        },
        to: icrc1::account::Account {
            owner: config.ckicp_canister_id,
            subaccount: None,
        },
        amount: Nat::from(amount),
        fee: None,
        memo: Some(icrc1::transfer::Memo::from(msg_id.to_be_bytes().to_vec())),
        created_at_time: Some(now),
    };
    let tx_result: Result<Nat, icrc2::transfer_from::TransferFromError> = canister_call(
        config.ledger_canister_id,
        "icrc2_transfer_from",
        tx_args,
        candid::encode_one,
        |r| candid::decode_one(r),
    )
    .await
    .map_err(|err| ReturnError::InterCanisterCallError(format!("{:?}", err)))?;

    match tx_result {
        Ok(_) => {
            update_status(msg_id, amount, expiry, MintState::FundReceived);
        }
        Err(err) => return Err(ReturnError::TransferError(format!("{:?}", err))),
    }

    // Generate tECDSA signature
    // payload is (amount, to, msgId, expiry, chainId, ckicp_eth_address), 32 bytes each
    let amount_to_transfer = amount - config.ckicp_fee;
    let mut payload_to_sign: [u8; 192] = [0; 192];
    payload_to_sign[0..32].copy_from_slice(&amount_to_transfer.to_be_bytes());
    payload_to_sign[32..64].copy_from_slice(&target_eth_wallet);
    payload_to_sign[64..96].copy_from_slice(&msg_id.to_be_bytes());
    payload_to_sign[96..128].copy_from_slice(&expiry.to_be_bytes());
    payload_to_sign[128..160].copy_from_slice(&config.target_chain_ids[0].to_be_bytes());
    payload_to_sign[160..192].copy_from_slice(&config.ckicp_eth_address);

    let mut hasher = Sha256::new();
    hasher.update(payload_to_sign);
    let hashed = hasher.finalize();

    let _signature: Vec<u8> = {
        let (res,): (SignWithECDSAReply,) = ManagementCanister::sign(hashed.to_vec())
            .await
            .map_err(|_| ReturnError::TecdsaSignatureError)?;
        res.signature
    };

    // TODO: Calculate `v`

    // TODO: Add signature to map for future queries
    // SIGNATURE_MAP.with(|sm| {
    //     let mut sm = sm.borrow_mut();
    //     sm.insert(
    //         msg_id,
    //         EcdsaSignature {
    //             r: signature[0..32],
    //             s: signature[32..64],
    //             v: signature[64],
    //         },
    //     );
    // });

    update_status(msg_id, amount, expiry, MintState::Signed);

    // Return tECDSA signature
    unimplemented!();
}

async fn eth_rpc_call(
    json_rpc_payload: Value,
    cycles: u128,
) -> Result<Result<Vec<u8>, EthRpcError>, ReturnError> {
    let config: CkicpConfig = get_ckicp_config();
    let rpc_result: Result<Vec<u8>, EthRpcError> = canister_call_with_payment(
        config.eth_rpc_canister_id,
        "json_rpc_request",
        (
            json_rpc_payload.to_string(),
            config.eth_rpc_service_url.clone(),
            config.max_response_bytes,
        ),
        candid::encode_args,
        |r| candid::decode_one(r),
        cycles,
    )
    .await
    .map_err(|err| ReturnError::InterCanisterCallError(format!("{:?}", err)))?;
    Ok(rpc_result)
}

/// Look up ethereum event log of the given block for Burn events.
/// Process those that have not yet been processed.
///
/// (TODO): How to avoid DoS attack?
#[update]
#[candid_method(update)]
#[modifiers("only_owner")]
pub async fn process_block(block_hash: String) -> Result<String, ReturnError> {
    // get log events from block with the given block_hash
    // NOTE: if log exceeds pre-allocated space, we need manual intervention.
    let config: CkicpConfig = get_ckicp_config();
    let json_rpc_payload = json!({
        "jsonrpc":"2.0",
        "method":"eth_getLogs",
        "params":[{
            "address": config.ckicp_eth_erc20_address,
            "blockHash": block_hash,
        }],
    });

    let logs: Value = match eth_rpc_call(json_rpc_payload, config.cycle_cost_of_eth_getlogs).await?
    {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|err| ReturnError::JsonParseError(err.to_string()))?,
        Err(err) => return Err(ReturnError::EthRpcError(err)),
    };
    process_logs(logs).await
}

/// Given some event logs, process burn events in them.
async fn process_logs(logs: Value) -> Result<String, ReturnError> {
    let entries = read_event_logs(&logs).map_err(ReturnError::EventLogError)?;
    let mut transferred = Vec::new();
    for entry in entries {
        match parse_burn_event(&entry) {
            Ok(burn) => {
                if let Err(err) = release_icp(burn.clone(), entry.event_id).await {
                    // TODO: shall we log this error?
                    transferred.push(format!("error {:?}", err));
                } else {
                    transferred.push(format!("transferred {} {:?}", burn, entry.event_id));
                }
            }
            Err(err) => {
                // Skip this error (which is usually due to different event types)
                // TODO: shall we log this error?
            }
        }
    }

    Ok(transferred.join("\n"))
}

/// Sync event logs of the ckICP ERC-20 contract via RPC.
/// This is meant to be called from a timer.
#[update]
#[candid_method(update)]
#[modifiers("only_owner")]
pub async fn sync_event_logs() -> Result<String, ReturnError> {
    let _guard = ReentrancyGuard::new();
    // get log events from block with the given block_hash
    // NOTE: if log exceeds pre-allocated space, we need manual intervention.
    let config: CkicpConfig = get_ckicp_config();
    let mut state: CkicpState = get_ckicp_state();
    match state.next_blocks.pop_front() {
        Some(next_block) => {
            // get logs between last_block and next_block.
            let json_rpc_payload = json!({
                "jsonrpc":"2.0",
                "method":"eth_getLogs",
                "params":[{
                    "address": config.ckicp_eth_erc20_address,
                    "fromBlock": format!("{:#x}", state.last_block + 1),
                    "toBlock": format!("{:#x}", next_block),
                }],
            });
            let logs: Value =
                match eth_rpc_call(json_rpc_payload, config.cycle_cost_of_eth_getlogs).await? {
                    Ok(bytes) => serde_json::from_slice(&bytes)
                        .map_err(|err| ReturnError::JsonParseError(err.to_string()))?,
                    Err(err) => return Err(ReturnError::EthRpcError(err)),
                };
            // TODO: process_logs may throw errors that requires futher processing: range is too big,
            // or number of returned bytes exceed limit. This can handled by halving the range and re-try.
            let result = process_logs(logs).await?;
            CKICP_STATE.with(|ckicp_state| {
                let mut ckicp_state = ckicp_state.borrow_mut();
                let mut state = ckicp_state.get().0.clone();
                state.as_mut().map(|s| {
                    if let Some(last_block) = s.next_blocks.pop_front() {
                        s.last_block = last_block;
                    }
                });
                ckicp_state.set(Cbor(state)).unwrap();
            });
            Ok(result)
        }
        None => {
            // get latest block number, and push to state.next_block_starts array.
            let json_rpc_payload = json!({
                "jsonrpc":"2.0",
                "method":"eth_blockNumber",
                "params":[]
            });
            let result: Value =
                match eth_rpc_call(json_rpc_payload, config.cycle_cost_of_eth_blocknumber).await? {
                    Ok(bytes) => serde_json::from_slice(&bytes)
                        .map_err(|err| ReturnError::JsonParseError(err.to_string()))?,
                    Err(err) => {
                        // TODO: log error and skip (because this will be called again)
                        return Err(ReturnError::JsonParseError(format!("{:?}", err)));
                    }
                };
            let block_number = match result
                .as_object()
                .and_then(|x| x.get("result"))
                .and_then(|x| x.as_str())
                .and_then(|x| hex::decode(&x[2..]).ok())
                .map(|x| {
                    let mut bytes = [0; 8];
                    let len = x.len().min(8);
                    bytes[(8 - len)..].copy_from_slice(&x[(x.len() - len)..]);
                    u64::from_be_bytes(bytes)
                }) {
                Some(block_number) => block_number,
                None => {
                    return Err(ReturnError::JsonParseError(
                        "cannot parse result as a block number".to_string(),
                    ));
                }
            };
            CKICP_STATE.with(|ckicp_state| {
                let mut ckicp_state = ckicp_state.borrow_mut();
                let mut state = ckicp_state.get().0.clone();
                state.as_mut().map(|s| match s.next_blocks.pop_back() {
                    None => s.next_blocks.push_back(block_number),
                    Some(x) if x < block_number => s.next_blocks.push_back(x),
                    _ => (),
                });
                ckicp_state.set(Cbor(state)).unwrap();
            });
            Ok(String::new())
        }
    }
}

/// The event_id needs to uniquely identify each burn event on Ethereum.
/// This allows the ETH State Sync canister to be stateless.
pub async fn release_icp(event: BurnEvent, event_id: EventId) -> Result<(), ReturnError> {
    let config: CkicpConfig = get_ckicp_config();

    // FIXME: should differentiate between event_seen and event_processed
    let event_seen = EVENT_ID_MAP.with(|event_id_map| {
        let mut event_id_map = event_id_map.borrow_mut();
        if event_id_map.contains_key(&event_id.into()) {
            return true;
        } else {
            event_id_map.insert(event_id.into(), 1);
            return false;
        }
    });

    if event_seen {
        return Err(ReturnError::EventSeen);
    }

    match event {
        BurnEvent::BurnToIcp(account, amount) => {
            if amount <= config.ckicp_fee {
                return Err(ReturnError::TransferError(format!(
                    "Amount must be greater than fee {}",
                    config.ckicp_fee
                )));
            }
            let amount = Nat::from(amount - config.ckicp_fee);
            let tx_args = icrc1::transfer::TransferArg {
                from_subaccount: None,
                to: account,
                amount,
                fee: None,
                memo: None,
                created_at_time: None,
            };
            let tx_result: Result<Nat, icrc1::transfer::TransferError> = canister_call(
                config.ledger_canister_id,
                "icrc1_transfer",
                tx_args,
                candid::encode_one,
                |r| candid::decode_one(r),
            )
            .await
            .map_err(|err| ReturnError::InterCanisterCallError(format!("{:?}", err)))?;
            match tx_result {
                Ok(_) => Ok(()),
                Err(err) => Err(ReturnError::TransferError(format!("{:?}", err))),
            }
        }
        BurnEvent::BurnToIcpAccountId(account_id, amount) => {
            if amount <= config.ckicp_fee {
                return Err(ReturnError::TransferError(format!(
                    "Amount must be greater than fee {}",
                    config.ckicp_fee
                )));
            }
            let amount = ic_ledger_types::Tokens::from_e8s(amount - config.ckicp_fee);
            let tx_args = ic_ledger_types::TransferArgs {
                from_subaccount: None,
                to: account_id,
                amount,
                fee: ic_ledger_types::Tokens::from_e8s(config.ckicp_fee),
                memo: ic_ledger_types::Memo(0),
                created_at_time: None,
            };
            let tx_result: Result<u64, ic_ledger_types::TransferError> = canister_call(
                config.ledger_canister_id,
                "transfer",
                tx_args,
                candid::encode_one,
                |r| candid::decode_one(r),
            )
            .await
            .map_err(|err| ReturnError::InterCanisterCallError(format!("{:?}", err)))?;
            match tx_result {
                Ok(_) => Ok(()),
                Err(err) => Err(ReturnError::TransferError(format!("{:?}", err))),
            }
        }
    }
}

#[query]
#[candid_method(query)]
pub fn get_signature(msg_id: MsgId) -> Option<EcdsaSignature> {
    SIGNATURE_MAP.with(|sm| {
        let sm = sm.borrow();
        sm.get(&msg_id)
    })
}

#[update]
#[candid_method(update)]
#[modifiers("only_owner")]
pub fn set_ckicp_config(config: CkicpConfig) {
    CKICP_CONFIG.with(|ckicp_config| {
        let mut ckicp_config = ckicp_config.borrow_mut();
        ckicp_config.set(Cbor(Some(config))).unwrap();
    })
}

#[update]
#[candid_method(update)]
#[modifiers("only_owner")]
pub async fn update_ckicp_state() {
    let config: CkicpConfig = get_ckicp_config();
    let mut state: CkicpState = get_ckicp_state();
    // TODO: Update tecdsa signer key and calculate signer ETH address
    state.last_block = config.starting_block_number;

    CKICP_STATE.with(|ckicp_state| {
        let mut ckicp_state = ckicp_state.borrow_mut();
        ckicp_state.set(Cbor(Some(state))).unwrap();
    })
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    candid::export_service!();
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}
