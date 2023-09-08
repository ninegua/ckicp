use async_trait::async_trait;
use candid::CandidType;
use candid::Principal;
use ic_cdk::api::call::{call_with_payment, CallResult};
use ic_cdk::call;
use serde::{Deserialize, Serialize};

pub type CanisterId = candid::Principal;

#[derive(CandidType, Serialize, Debug)]
pub struct PublicKeyReply {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug)]
pub struct ECDSAPublicKey {
    pub canister_id: Option<CanisterId>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Serialize, Debug)]
pub struct SignatureReply {
    pub signature: Vec<u8>,
}

#[async_trait]
pub trait ManagementCanister {
    async fn raw_rand(&self) -> CallResult<(Vec<u8>,)>;
    async fn ecdsa_public_key(&self, canister_id: Principal) -> CallResult<(ECDSAPublicKeyReply,)>;
    async fn sign(&self, message: Vec<u8>) -> CallResult<(SignWithECDSAReply,)>;
}

#[async_trait]
impl ManagementCanister for Principal {
    async fn raw_rand(&self) -> CallResult<(Vec<u8>,)> {
        call(*self, "raw_rand", ()).await
    }

    async fn ecdsa_public_key(&self, canister_id: Principal) -> CallResult<(ECDSAPublicKeyReply,)> {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "key_1".to_string(),
            // name: "dfx_test_key".to_string(),
        };

        let request = ECDSAPublicKey {
            canister_id: Some(canister_id),
            derivation_path: vec![],
            key_id: key_id.clone(),
        };
        ic_cdk::println!("request {:?}", request);
        call(*self, "ecdsa_public_key", (request,)).await
    }

    async fn sign(&self, message: Vec<u8>) -> CallResult<(SignWithECDSAReply,)> {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: "key_1".to_string(),
            // name: "dfx_test_key".to_string(),
        };

        let request = SignWithECDSA {
            message_hash: message.clone(),
            derivation_path: vec![],
            key_id,
        };
        call_with_payment(*self, "sign_with_ecdsa", (request,), 25_000_000_000).await
    }
}
