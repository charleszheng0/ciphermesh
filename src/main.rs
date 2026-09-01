use ciphermesh::{send_over_simulated_transport, Alice, Bob, SimulatedDirectory};

fn main() {
    let mut alice = Alice::local();
    let mut bob = Bob::local();
    let message = "hello bob, this is alice";

    let alice_exchange = alice.signed_key_exchange();
    let bob_exchange = bob.signed_key_exchange();
    println!(
        "Alice identity public key: {:?}",
        alice_exchange.identity_public_key
    );
    println!(
        "Alice X25519 public key: {:?}",
        alice_exchange.x25519_public_key
    );
    println!("Alice signature: {:?}", alice_exchange.signature);
    println!(
        "Bob identity public key: {:?}",
        bob_exchange.identity_public_key
    );
    println!(
        "Bob X25519 public key: {:?}",
        bob_exchange.x25519_public_key
    );
    println!("Bob signature: {:?}", bob_exchange.signature);

    alice
        .derive_session_key(&bob_exchange)
        .expect("alice derives session key");
    bob.derive_session_key(&alice_exchange)
        .expect("bob derives session key");

    let ciphertext = alice.encrypt_for_bob(message).expect("alice encrypts");
    println!("Alice plaintext: {message}");
    println!("Transport payload: {ciphertext:?}");

    let received_ciphertext = send_over_simulated_transport(ciphertext);
    let plaintext = bob
        .decrypt_from_alice(&received_ciphertext)
        .expect("bob decrypts");
    println!("Bob decrypted: {plaintext}");

    let mut offline_bob = Bob::local();
    let mut directory = SimulatedDirectory::new();
    directory
        .publish_bob_bundle(&offline_bob)
        .expect("bob publishes prekey bundle");

    let mut alice = Alice::local();
    let bob_bundle = directory
        .take_bob_prekey_bundle()
        .expect("alice retrieves bob prekey bundle while bob is offline");
    let initial_message = alice
        .encrypt_initial_message(&bob_bundle, "hello offline bob")
        .expect("alice encrypts initial message");
    println!(
        "Offline initial transport payload: {:?}",
        initial_message.ciphertext
    );

    let plaintext = offline_bob
        .decrypt_initial_message(&initial_message)
        .expect("bob decrypts initial message after coming online");
    println!("Offline Bob decrypted later: {plaintext}");
}
