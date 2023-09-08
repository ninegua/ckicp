use candid::{CandidType, Principal, Encode, Decode};
use ic_stable_structures::memory_manager::MemoryId;
use ic_stable_structures::DefaultMemoryImpl;
use std::cell::RefCell;
use std::borrow::Cow;
use ic_stable_structures::{StableCell, StableVec, Storable, BoundedStorable, StableBTreeMap};
use rustic::default_memory_map::MEMORY_MANAGER;
use rustic::types::{RM, VM, Cbor};

use crate::crypto::EcdsaSignature;


type Amount = u64;
type MsgId = u128;

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct CkicpConfig {
    pub ckicp_canister_id: Principal,
    pub ledger_canister_id: Principal,
    pub ckicp_eth_address: [u8; 20],
    pub ckicp_fee: Amount,
}

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct CkicpState {
    pub tecdsa_pubkey: String,
    pub tecdsa_signer_address: [u8; 20],
    pub total_icp_locked: Amount,
}

#[derive(CandidType, serde::Serialize, serde::Deserialize, Default, Clone, Debug, PartialEq, Eq)]
pub enum MintState {
    #[default]
    Init,
    FundReceived,
    Signed,
    Confirmed,
    Expired,
}

impl Storable for MintState {
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        match bytes[0] {
            0 => MintState::Init,
            1 => MintState::FundReceived,
            2 => MintState::Signed,
            3 => MintState::Confirmed,
            4 => MintState::Expired,
            _ => panic!("invalid mint state"),
        }
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(vec![match self {
            MintState::Init => 0,
            MintState::FundReceived => 1,
            MintState::Signed => 2,
            MintState::Confirmed => 3,
            MintState::Expired => 4,
        }])
    }
}

impl BoundedStorable for MintState {
    const MAX_SIZE: u32 = 1;
    const IS_FIXED_SIZE: bool = true;
}

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct MintStatus {
    pub msg_id: MsgId,
    pub amount: Amount,
    pub expiry: u64, // seconds since UNIX epoch
    pub state: MintState,
}

impl Storable for MintStatus {
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }

    fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }
}

impl BoundedStorable for MintStatus {
    const MAX_SIZE: u32 = 60;
    const IS_FIXED_SIZE: bool = false;
}

const CKICP_CONFIG_SIZE: u64 = 1;
const CKICP_STATE_SIZE: u64 = 1;

const CKICP_CONFIG_PAGE_START: u64 = rustic::default_memory_map::USER_PAGE_START;
const CKICP_CONFIG_PAGE_END: u64 = CKICP_CONFIG_PAGE_START + CKICP_CONFIG_SIZE;
const CKICP_STATE_PAGE_START: u64 = CKICP_CONFIG_PAGE_END;
const CKICP_STATE_PAGE_END: u64 = CKICP_STATE_PAGE_START + CKICP_STATE_SIZE;

const NONCE_MAP_MEM_ID: MemoryId = MemoryId::new(0);
const STATUS_MAP_MEM_ID: MemoryId = MemoryId::new(1);
const SIGNATURE_MAP_MEM_ID: MemoryId = MemoryId::new(2);

thread_local! {

    pub static CKICP_CONFIG: RefCell<StableCell<Cbor<Option<CkicpConfig>>, RM>> =
        RefCell::new(StableCell::init(
            RM::new(DefaultMemoryImpl::default(), CKICP_CONFIG_PAGE_START..CKICP_CONFIG_PAGE_END),
            Cbor::default(),
        ).expect("failed to initialize")
    );

    pub static CKICP_STATE: RefCell<StableCell<Cbor<Option<CkicpState>>, RM>> =
        RefCell::new(StableCell::init(
            RM::new(DefaultMemoryImpl::default(), CKICP_STATE_PAGE_START..CKICP_STATE_PAGE_END),
            Cbor::default(),
        ).expect("failed to initialize")
    );

    // map caller -> nonce
    pub static NONCE_MAP: RefCell<StableBTreeMap<[u8;32], u32, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(StableBTreeMap::init(mm.borrow().get(NONCE_MAP_MEM_ID)))
    });

    // map msgid -> status
    pub static STATUS_MAP: RefCell<StableBTreeMap<MsgId, MintStatus, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(StableBTreeMap::init(mm.borrow().get(STATUS_MAP_MEM_ID)))
    });

    // map msgid -> signature
    pub static SIGNATURE_MAP: RefCell<StableBTreeMap<MsgId, EcdsaSignature, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(StableBTreeMap::init(mm.borrow().get(SIGNATURE_MAP_MEM_ID)))
    });
}


