#![no_std]
use serde::{Deserialize, Serialize};
use risc0_zkvm_core::Digest;

#[derive(Deserialize, Serialize)]
pub struct Student<'a> {
    pub id: u64,
    pub name: &'a str,
}

#[derive(Deserialize, Serialize)]
pub struct FileContent<'a> {
    pub nonce: [u8; 12],
    pub key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub ciphertext: &'a[u8],
}

#[derive(Deserialize, Serialize)]
pub struct ProofResult {
   pub hash:Digest,
   pub available: bool,
}

#[derive(Deserialize, Serialize)]
pub struct AddProof {
   pub hash_before:Digest,
   pub hash_after:Digest,
}