use methods::{CHECK_ID, CHECK_PATH, NEW_STUDENT_ID, NEW_STUDENT_PATH};
use risc0_zkvm_host::Prover;
use risc0_zkvm_serde::{from_slice, to_vec};
use std::io::prelude::*;
use std::fs::File;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use checker_core::{Student, FileContent, ProofResult, AddProof};
use cbor_no_std::{ ser::to_bytes, value::Value};
use std::collections::BTreeMap;
use std::time::Instant;

fn main() {
    let mut file = File::open("students_db.txt").expect("Couldn't open database");

    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Couldn't read a database");

    let nonce_bytes = b"uniiue nonce";
    let secret_key_bytes = b"an example very very secret key.";
    let key = Key::from_slice(secret_key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
   
    let e = to_bytes(Value::Map(db_to_map(contents)));

    let ciphertext = cipher.encrypt(nonce, e.as_ref())
    .expect("encryption failure!");
   
    let mut file = File::create("students_db_encrypted.txt")
    .expect("Error encountered while creating file!");
    file.write_all(&ciphertext)
    .expect("Error while writing to file");

    let mut file = File::create("students_db_nonce_key.txt")
    .expect("Error encountered while creating file!");
    file.write_all(&nonce)
    .expect("Error while writing to file");
    file.write_all(b"\n")
    .expect("Error while writing to file");
    file.write_all(key)
    .expect("Error while writing to file");

    let student_to_check: Student = Student {
        id: 65,
        name: "Pavel"
    };

    let student_to_add: Student = Student {
        id: 111,
        name: "Anton"
    };
    let file_content: FileContent = FileContent{
        nonce: *nonce_bytes,
        key: *secret_key_bytes,
        ciphertext:&ciphertext,
    };

    let proof_check = proof(&student_to_check, &file_content);
    let new_student_proof = new_student_proof(&student_to_add, &file_content);

   println!("Checking:");
   println!("Hash: {:?}", &proof_check.hash);
   println!("Available: {}", &proof_check.available);

   println!();

   println!("Add:");
   println!("Hash before: {:?}", &new_student_proof.hash_before);
   println!("Hash after: {}", &new_student_proof.hash_after);

}

fn new_student_proof(student_to_add: &Student, file_content: &FileContent) -> AddProof {

    let mut prover = Prover::new(&NEW_STUDENT_PATH, NEW_STUDENT_ID).unwrap();

    prover.add_input(to_vec(&student_to_add).unwrap().as_slice()).unwrap();
    prover.add_input(to_vec(&file_content).unwrap().as_slice()).unwrap();

    let now = Instant::now();
    let receipt = prover.run().unwrap();
    let elapsed = now.elapsed();
    println!("Elapsed new student proof: {:.3?}", elapsed);

    let proof: AddProof = from_slice(&receipt.get_journal_vec().unwrap()).unwrap();
    proof

}

fn proof (student: &Student, file_content: &FileContent) -> ProofResult {
    let mut prover = Prover::new(&CHECK_PATH, CHECK_ID).unwrap();

    prover.add_input(to_vec(&student).unwrap().as_slice()).unwrap();
    prover.add_input(to_vec(&file_content).unwrap().as_slice()).unwrap();

    let now = Instant::now();
    let receipt = prover.run().unwrap();
    let elapsed = now.elapsed();
    println!("Elapsed check student proof: {:.3?}", elapsed);


    let proof: ProofResult = from_slice(&receipt.get_journal_vec().unwrap()).unwrap();
    proof
}

fn db_to_map (contents: String) -> BTreeMap<Value, Value> {
    let mut data = BTreeMap::new();
    let lines = contents.lines();
    for line in lines {
        let mut res = line.split_whitespace();
        let  number = res.next().unwrap().parse::<u64>().unwrap();
        let  name = res.next().unwrap().to_owned();
        data.insert( Value::Int(number),Value::String(name));
    }
    data
}
