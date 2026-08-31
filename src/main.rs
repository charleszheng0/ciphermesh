use ciphermesh::{send_over_simulated_transport, Alice, Bob};

fn main() {
    let alice = Alice::local();
    let bob = Bob::local();
    let message = "hello bob, this is alice";

    let ciphertext = alice.encrypt_for_bob(message).expect("alice encrypts");
    println!("Alice plaintext: {message}");
    println!("Transport payload: {ciphertext:?}");

    let received_ciphertext = send_over_simulated_transport(ciphertext);
    let plaintext = bob
        .decrypt_from_alice(&received_ciphertext)
        .expect("bob decrypts");
    println!("Bob decrypted: {plaintext}");
}
