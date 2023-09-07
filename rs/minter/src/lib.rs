
#![allow(clippy::unwrap_used)]
#![allow(unused_imports)]

use candid::{candid_method, CandidType, Decode, Encode, Nat, Principal};
use ic_canister_log::{declare_log_buffer, export};
use ic_cdk::api::call::CallResult;
use ic_cdk_macros::{init, post_upgrade, pre_upgrade, query, update};
use ic_stable_structures::memory_manager::MemoryId;
use ic_stable_structures::{
    BoundedStorable, DefaultMemoryImpl, StableBTreeMap, StableCell, StableVec, Storable,
};
use ic_cdk::api::management_canister::ecdsa::EcdsaPublicKeyResponse;

use rustic::access_control::*;
use rustic::default_memory_map::*;
use rustic::inter_canister::*;
use rustic::reentrancy_guard::*;
use rustic::types::*;
use rustic::utils::*;

use serde_bytes::ByteBuf;
use zeroize::ZeroizeOnDrop;

use std::borrow::Cow;
use std::cell::RefCell;
use std::convert::From;
use std::time::Duration;

use k256::{
    elliptic_curve::{
        generic_array::{typenum::Unsigned, GenericArray},
        Curve,
    },
    Secp256k1,
    PublicKey,
    ecdsa::VerifyingKey,
};

use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use icrc_ledger_types::icrc1::transfer::{Memo, TransferArg, TransferError};

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

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize)]
pub struct EcdsaSignature {
    r: [u8; 32],
    s: [u8; 32],
    v: u8,
}

impl Storable for EcdsaSignature {
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        let mut bytes = bytes.into_owned();
        let v = bytes.split_off(64);
        let s = bytes.split_off(32);
        Self {
            r: bytes.try_into().unwrap(),
            s: s.try_into().unwrap(),
            v: v[0],
        }
    }

    fn to_bytes(&self) -> Cow<[u8]> {
        let mut bytes = Vec::with_capacity(65);
        bytes.extend_from_slice(&self.r);
        bytes.extend_from_slice(&self.s);
        bytes.push(self.v);
        bytes.into()
    }
}

impl BoundedStorable for EcdsaSignature {
    const MAX_SIZE: u32 = 100;
    const IS_FIXED_SIZE: bool = true;
}


#[derive(CandidType, candid::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReturnError {
    GenericError,
    InputError,
    Unauthorized,
    Expired,
    InterCanisterCallError,
}

const CKICP_CONFIG_SIZE: u64 = 1;
const CKICP_STATE_SIZE: u64 = 1;

const CKICP_CONFIG_PAGE_START: u64 = USER_PAGE_START;
const CKICP_CONFIG_PAGE_END: u64 = CKICP_CONFIG_PAGE_START + CKICP_CONFIG_SIZE;
const CKICP_STATE_PAGE_START: u64 = CKICP_CONFIG_PAGE_END;
const CKICP_STATE_PAGE_END: u64 = CKICP_STATE_PAGE_START + CKICP_STATE_SIZE;

const SIGNATURE_MAP_MEM_ID: MemoryId = MemoryId::new(0);

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

    // map (caller, nonce) -> signature
    static SIGNATURE_MAP: RefCell<StableBTreeMap<([u8;32], u32), EcdsaSignature, VM>> =
        MEMORY_MANAGER.with(|mm| {
            RefCell::new(StableBTreeMap::init(mm.borrow().get(SIGNATURE_MAP_MEM_ID)))
    });
}


#[init]
pub fn init() {
   
}



#[query]
pub fn get_ckicp_config() -> CkicpConfig {
    CKICP_CONFIG.with(|ckicp_config| {
        let ckicp_config = ckicp_config.borrow();
        ckicp_config.get().0.clone().unwrap()
    })
}

#[query]
pub fn get_ckicp_state() -> CkicpState {
    CKICP_STATE.with(|ckicp_state| {
        let ckicp_state = ckicp_state.borrow();
        ckicp_state.get().0.clone().unwrap()
    })
}

#[update]
pub fn mint_ckicp(amount: Amount, target_eth_wallet: [u8;20]) -> Result<EcdsaSignature, ReturnError> {
    let caller = ic_cdk::caller();
    let config: CkicpConfig = get_ckicp_config();

    // Generate tECDSA signature

    // Add signature to map for future queries

    // Return tECDSA signature
    unimplemented!();

}



/// An ECDSA private key
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey {
    key: k256::ecdsa::SigningKey,
}

impl PrivateKey {
    /// Serialize the private key to a simple bytestring
    ///
    /// This uses the SEC1 encoding, which is just the representation
    /// of the secret integer in a 32-byte array, encoding it using
    /// big-endian notation.
    pub fn serialize_sec1(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }


    /// Sign a message
    ///
    /// The message is hashed with SHA-256 and the signature is
    /// normalized (using the minimum-s approach of BitCoin)
    pub fn sign_message(&self, message: &[u8]) -> [u8; 64] {
        use k256::ecdsa::{signature::Signer, Signature};
        let sig: Signature = self.key.sign(message);
        sig.to_bytes().into()
    }

    /// Sign a message digest
    ///
    /// The signature is normalized (using the minimum-s approach of BitCoin)
    pub fn sign_digest(&self, digest: &[u8]) -> Option<[u8; 64]> {
        if digest.len() < 16 {
            // k256 arbitrarily rejects digests that are < 128 bits
            return None;
        }

        use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature};
        let sig: Signature = self
            .key
            .sign_prehash(digest)
            .expect("Failed to sign digest");
        Some(sig.to_bytes().into())
    }

    /// Return the public key cooresponding to this private key
    pub fn public_key(&self) -> PublicKey {
        let key = VerifyingKey::from(&self.key);
        PublicKey::from(&key)
        
    }
}
