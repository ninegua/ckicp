use candid::{candid_method, CandidType, Decode, Encode, Nat, Principal};
use ic_canister_log::{declare_log_buffer, export};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::stable::{StableReader, StableWriter};
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::memory_manager::MemoryId;
use ic_stable_structures::{
    BoundedStorable, DefaultMemoryImpl, StableBTreeMap, StableCell, StableVec, Storable,
};

use rustic::access_control::*;
use rustic::default_memory_map::*;
use rustic::function;
use rustic::inter_canister::*;
use rustic::reentrancy_guard::*;
use rustic::types::*;
use rustic::utils::*;

use serde_bytes::ByteBuf;
use std::borrow::Cow;
use std::cell::RefCell;
use std::convert::From;
use std::time;

use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg, TransferError};

type Amount = u64;

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct CkicpConfig {
    ckicp_canister_id: Principal,
    ckicp_eth_address: [u8; 32],
    ckicp_fee: Amount,
}

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct CkicpMetadata {
    tecdsa_pubkey: String,
    tecdsa_address: [u8; 20],
}

#[derive(CandidType, candid::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReturnError {
    GenericError,
    InputError,
    Unauthorized,
    Expired,
    InterCanisterCallError,
}
