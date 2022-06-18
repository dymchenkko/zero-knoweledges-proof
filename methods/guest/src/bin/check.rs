#![no_main]
#![no_std]

use risc0_zkvm_guest::{env, sha};

risc0_zkvm_guest::entry!(main);
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use checker_core::{Student, FileContent, ProofResult};
use cbor_no_std::{de::from_bytes, value::Value};

#[macro_use]
extern crate alloc;

pub fn main() {

    let student_to_check: Student = env::read();
    let file_content: FileContent = env::read();

    let key = Key::from_slice(&file_content.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&file_content.nonce);

    let plaintext = cipher.decrypt(nonce, file_content.ciphertext.as_ref())
    .expect("decryption failure!");
    let map = from_bytes(plaintext.clone());
    
    let mut map = map.as_map().unwrap().clone();
    let result =  map.get(&Value::Int(student_to_check.id)) == Some(&Value::String(format!("{}", student_to_check.name)));

    env::commit(&ProofResult{
        hash: *sha::digest(&file_content.ciphertext),
        available: result,
    });
}
