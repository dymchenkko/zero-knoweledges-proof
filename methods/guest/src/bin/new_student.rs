#![no_main]
#![no_std]

use risc0_zkvm_guest::{env, sha};

risc0_zkvm_guest::entry!(main);
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use checker_core::{Student, FileContent, AddProof};
use cbor_no_std::{ ser::to_bytes, de::from_bytes, value::Value};
#[macro_use]
extern crate alloc;

pub fn main() {

    let student_to_add: Student = env::read();
    let file_content: FileContent = env::read();

    let key = Key::from_slice(&file_content.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&file_content.nonce);

    let before = sha::digest(&file_content.ciphertext);
    let plaintext = cipher.decrypt(nonce, file_content.ciphertext.as_ref())
    .expect("decryption failure!");
    let map = from_bytes(plaintext.clone());
    
    let mut map = map.as_map().unwrap().clone();
    map.insert( Value::Int(student_to_add.id),Value::String(format!("{}", student_to_add.name)));
    let map = Value::Map(map.clone());

    let mut e = to_bytes(map.clone());

    let ciphertext = cipher.encrypt(nonce, e.as_ref())
    .expect("encryption failure!");
    let after = sha::digest(&ciphertext);

    env::commit(&AddProof{
        hash_before:*before,
        hash_after:*after,
    });
}
