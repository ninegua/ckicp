use candid::{CandidType, Principal};
use ic_stable_structures::memory_manager::MemoryId;
use ic_stable_structures::DefaultMemoryImpl;
use std::cell::RefCell;
use ic_stable_structures::{StableCell, StableVec, Storable, BoundedStorable, StableBTreeMap};
use rustic::default_memory_map::MEMORY_MANAGER;
use rustic::types::{RM, VM, Cbor};
use crate::crypto::EcdsaSignature;

type Amount = u64;

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct CkicpConfig {
    ckicp_canister_id: Principal,
    ckicp_eth_address: [u8; 20],
    ckicp_fee: Amount,
}

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct CkicpState {
    tecdsa_pubkey: String,
    tecdsa_signer_address: [u8; 20],
    total_icp_locked: Amount,
}



const CKICP_CONFIG_SIZE: u64 = 1;
const CKICP_STATE_SIZE: u64 = 1;

const CKICP_CONFIG_PAGE_START: u64 = rustic::default_memory_map::USER_PAGE_START;
const CKICP_CONFIG_PAGE_END: u64 = CKICP_CONFIG_PAGE_START + CKICP_CONFIG_SIZE;
const CKICP_STATE_PAGE_START: u64 = CKICP_CONFIG_PAGE_END;
const CKICP_STATE_PAGE_END: u64 = CKICP_STATE_PAGE_START + CKICP_STATE_SIZE;

const MSGID_MAP_MEM_ID: MemoryId = MemoryId::new(0);
const SIGNATURE_MAP_MEM_ID: MemoryId = MemoryId::new(1);

thread_local! {

    static CKICP_CONFIG: RefCell<StableCell<Cbor<Option<CkicpConfig>>, RM>> =
        RefCell::new(StableCell::init(
            RM::new(DefaultMemoryImpl::default(), CKICP_CONFIG_PAGE_START..CKICP_CONFIG_PAGE_END),
            Cbor::default(),
        ).expect("failed to initialize")
    );

    static CKICP_STATE: RefCell<StableCell<Cbor<Option<CkicpState>>, RM>> =
        RefCell::new(StableCell::init(
            RM::new(DefaultMemoryImpl::default(), CKICP_STATE_PAGE_START..CKICP_STATE_PAGE_END),
            Cbor::default(),
        ).expect("failed to initialize")
    );

    // map (caller, nonce) -> msgid
    static MSGID_MAP: RefCell<StableBTreeMap<([u8;32], u32), u32, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(StableBTreeMap::init(mm.borrow().get(MSGID_MAP_MEM_ID)))
    });

    // map msgid -> signature
    static SIGNATURE_MAP: RefCell<StableBTreeMap<u32, EcdsaSignature, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(StableBTreeMap::init(mm.borrow().get(SIGNATURE_MAP_MEM_ID)))
    });
}

pub(crate) fn memory_init() {
    
}

