use ic_stable_structures::{BoundedStorable, Storable};
use std::borrow::Cow;

#[derive(Clone, candid::CandidType, serde::Serialize, serde::Deserialize)]
#[repr(C)]
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
    const MAX_SIZE: u32 = 65;
    const IS_FIXED_SIZE: bool = true;
}

impl EcdsaSignature {
    // pub fn from_sec1(bytes: &[u8]) -> Self {
    //     let mut bytes = bytes.to_vec();
    //     let s = bytes.split_off(32);
    //     Self {
    //         r: bytes.try_into().unwrap(),
    //         s: s.try_into().unwrap(),
    //         v: 0,
    //     }
    // }

    pub fn from_rsv(r: &[u8], s: &[u8], v: u8) -> Self {
        Self {
            r: r.try_into().unwrap(),
            s: s.try_into().unwrap(),
            v,
        }
    }

    pub fn from_signature_v(signature: &[u8], v: u8) -> Self {
        let mut signature = signature.to_vec();
        let s = signature.split_off(32);
        Self {
            r: signature.try_into().unwrap(),
            s: s.try_into().unwrap(),
            v,
        }
    }
}
