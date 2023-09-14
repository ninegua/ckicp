use candid::Principal;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use sha2::{Digest, Sha256};

pub fn subaccount_from_principal(principal: &Principal) -> Subaccount {
    let mut subaccount = [0; 32];
    let principal = principal.as_slice();
    subaccount[0] = principal.len() as u8;
    subaccount[1..principal.len() + 1].copy_from_slice(principal);
    subaccount
}

pub fn principal_from_subaccount(subaccount: &Subaccount) -> Principal {
    let len = subaccount[0] as usize;
    Principal::from_slice(&subaccount[1..1 + std::cmp::min(len, 29)])
}

pub fn calc_msgid(caller: &Subaccount, nonce: u32) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(caller);
    hasher.update(&nonce.to_le_bytes());
    let hashed = hasher.finalize();
    // Return XOR of 128 bit chunks of the hashed principal
    let mut id = 0;
    for i in 0..2 {
        id ^= u128::from_le_bytes(hashed[i * 16..(i + 1) * 16].try_into().unwrap_or_default());
    }
    id
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
