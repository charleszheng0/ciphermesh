use ciphermesh::{
    crdt::{event_record, materialize_conversation, ConversationEvent},
    mailbox_storage::{mailbox_now_unix_secs, MailboxEnvelopeRecord, MailboxStorage},
    storage::{
        now_unix_secs, EventRecord, MessageDirection, MessageRecord, MessageStatus, OutboxItem,
        OutboxStatus, Storage, VersionVector,
    },
    Alice, AliceState, Bob, BobState, InitialMessage, PreKeyBundle, RatchetMessage,
    SimulatedDirectory,
};
use futures::StreamExt;
use libp2p::{
    autonat, dcutr, identify, identity, kad, mdns,
    multiaddr::Protocol,
    relay, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, time};

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const DISCOVERY_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/0";
const DISCOVERY_PROTOCOL: &str = "/ciphermesh/discovery/3c/1.0.0";
const APP_RELAY_PROTOCOL: &str = "/ciphermesh/app-bytes/3c/1.0.0";
const MAILBOX_PROTOCOL: &str = "/ciphermesh/mailbox/3d/1.0.0";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const DIRECT_DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAILBOX_ENVELOPE_TTL_SECS: u64 = 5 * 60;
const MAILBOX_MAX_ENVELOPES: usize = 64;

#[tokio::main]
async fn main() -> AppResult<()> {
    let args = std::env::args().collect::<Vec<_>>();

    match args.get(1).map(String::as_str) {
        Some("bob") => {
            let listen_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            let bootstrap_peers = parse_bootstrap_peers(&args[3..])?;
            run_bob(listen_addr, bootstrap_peers).await
        }
        Some("alice") => {
            let bob_peer_id = parse_peer_id(args.get(2))?;
            let message = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("hello bob over quic");
            let bootstrap_peers = parse_bootstrap_peers(&args[4..])?;
            run_alice_discovered(bob_peer_id, message, bootstrap_peers).await
        }
        Some("alice-direct") => {
            let bob_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            let message = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("hello bob over quic");
            run_alice(bob_addr, message).await
        }
        Some("chat-bob") => {
            let listen_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            run_chat_bob(listen_addr).await
        }
        Some("chat-alice") => {
            let bob_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            run_chat_alice(bob_addr).await
        }
        Some("alice-relay") => {
            let bob_peer_id = parse_peer_id(args.get(2))?;
            let message = args.get(3).map(String::as_str).unwrap_or("hello via relay");
            let relay_peers = parse_bootstrap_peers(&args[4..])?;
            run_alice_relayed(bob_peer_id, message, relay_peers).await
        }
        Some("kad-demo") => run_kademlia_demo().await,
        Some("relay") => {
            let listen_addr = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("/ip4/0.0.0.0/tcp/4001")
                .parse()?;
            run_relay_server(listen_addr).await
        }
        Some("relay-demo") => run_relay_demo().await,
        Some("mailbox") => {
            let listen_addr = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("/ip4/0.0.0.0/tcp/7000")
                .parse()?;
            let db_path = args
                .get(3)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/ciphermesh-mailbox.sqlite"));
            run_mailbox_node(listen_addr, &db_path).await
        }
        Some("alice-mailbox") => {
            let mailbox_addr = parse_required_multiaddr(args.get(2), "mailbox multiaddr")?;
            let message = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("hello offline bob");
            let db_path = args
                .get(4)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/ciphermesh-alice-mailbox.sqlite"));
            run_alice_mailbox_deposit(mailbox_addr, message, &db_path).await
        }
        Some("bob-mailbox") => {
            let mailbox_addr = parse_required_multiaddr(args.get(2), "mailbox multiaddr")?;
            let db_path = args
                .get(3)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/ciphermesh-bob-mailbox.sqlite"));
            run_bob_mailbox_fetch(mailbox_addr, &db_path).await
        }
        Some("restart-demo") => {
            let db_path = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/ciphermesh-4a-demo.sqlite"));
            run_restart_demo(&db_path)
        }
        Some("outbox-demo") => {
            let db_path = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/ciphermesh-4b-outbox-demo.sqlite"));
            run_outbox_demo(&db_path)
        }
        Some("sync-demo") => run_sync_demo(),
        Some("crdt-demo") => run_crdt_demo(),
        _ => {
            run_local_demo()?;
            print_usage();
            Ok(())
        }
    }
}

fn parse_addr(addr: Option<&String>, default: &str) -> AppResult<SocketAddr> {
    Ok(addr.map(String::as_str).unwrap_or(default).parse()?)
}

fn parse_required_multiaddr(addr: Option<&String>, label: &str) -> AppResult<Multiaddr> {
    addr.ok_or_else(|| format!("missing {label}"))?
        .parse()
        .map_err(|error| format!("invalid {label}: {error}").into())
}

fn print_usage() {
    println!();
    println!("Phase 3B mDNS discovery test:");
    println!("  Terminal 1: cargo run -- bob 0.0.0.0:5000");
    println!("  Terminal 2: cargo run -- alice <bob-libp2p-peer-id> \"hello from alice\"");
    println!();
    println!("Optional bootstrap/Kademlia demo:");
    println!("  cargo run -- kad-demo");
    println!();
    println!("Optional relay fallback demo:");
    println!("  Terminal 1: cargo run -- relay /ip4/0.0.0.0/tcp/4001");
    println!("  Terminal 2: cargo run -- bob 0.0.0.0:5000 <relay-multiaddr>");
    println!("  Terminal 3: cargo run -- alice <bob-libp2p-peer-id> \"hello via relay\" <relay-multiaddr>");
    println!("  Force relay path: cargo run -- alice-relay <bob-libp2p-peer-id> \"hello via relay\" <relay-multiaddr>");
    println!("  Or run: cargo run -- relay-demo");
    println!();
    println!("Phase 3A direct QUIC comparison:");
    println!("  Terminal 1: cargo run -- bob 127.0.0.1:5000");
    println!("  Terminal 2: cargo run -- alice-direct 127.0.0.1:5000 \"hello from alice\"");
    println!();
    println!("Interactive CLI chat:");
    println!("  Terminal 1: cargo run -- chat-bob 127.0.0.1:5000");
    println!("  Terminal 2: cargo run -- chat-alice 127.0.0.1:5000");
    println!();
    println!("Phase 3D mailbox demo:");
    println!("  Terminal 1: cargo run -- mailbox /ip4/0.0.0.0/tcp/7000 target/mailbox.db");
    println!(
        "  Terminal 2: cargo run -- alice-mailbox <mailbox-multiaddr> \"hello offline bob\" target/alice-mailbox.db"
    );
    println!("  Terminal 3: cargo run -- bob-mailbox <mailbox-multiaddr> target/bob-mailbox.db");
    println!();
    println!("Phase 4A SQLite restart demo:");
    println!("  cargo run -- restart-demo [target/ciphermesh-4a-demo.sqlite]");
    println!();
    println!("Phase 4B durable outbox demo:");
    println!("  cargo run -- outbox-demo [target/ciphermesh-4b-outbox-demo.sqlite]");
    println!();
    println!("Phase 4D version-vector sync demo:");
    println!("  cargo run -- sync-demo");
    println!();
    println!("Phase 4E deterministic convergence demo:");
    println!("  cargo run -- crdt-demo");
}

fn run_local_demo() -> AppResult<()> {
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

    alice.derive_session_key(&bob_exchange)?;
    bob.derive_session_key(&alice_exchange)?;

    let ciphertext = alice.encrypt_for_bob(message)?;
    println!("Alice plaintext: {message}");
    println!("Transport payload: {ciphertext:?}");

    let plaintext = bob.decrypt_from_alice(&ciphertext)?;
    println!("Bob decrypted: {plaintext}");

    let mut offline_bob = Bob::local();
    let mut directory = SimulatedDirectory::new();
    directory.publish_bob_bundle(&offline_bob)?;

    let mut alice = Alice::local();
    let bob_bundle = directory.take_bob_prekey_bundle()?;
    let initial_message = alice.encrypt_initial_message(&bob_bundle, "hello offline bob")?;
    println!(
        "Offline initial transport payload: {:?}",
        initial_message.message
    );

    let plaintext = offline_bob.decrypt_initial_message(&initial_message)?;
    println!("Offline Bob decrypted later: {plaintext}");

    Ok(())
}

fn run_restart_demo(db_path: &Path) -> AppResult<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conversation_id = format!("alice-bob-{}", now_unix_secs());
    let mut storage = Storage::open(db_path)?;
    let mut alice = Alice::local();
    let mut bob = Bob::local();
    let alice_exchange = alice.signed_key_exchange();
    let bob_exchange = bob.signed_key_exchange();

    alice.derive_session_key(&bob_exchange)?;
    bob.derive_session_key(&alice_exchange)?;
    storage.save_local_identity(
        "alice",
        "alice",
        &bincode::serialize(&alice.export_state())?,
    )?;
    storage.save_local_identity("bob", "bob", &bincode::serialize(&bob.export_state())?)?;
    storage.save_session(
        &conversation_id,
        "bob",
        "alice",
        &bincode::serialize(
            &alice
                .session_state()
                .ok_or("Alice session missing after handshake")?,
        )?,
    )?;
    println!("SQLite database: {}", db_path.display());
    println!("Created session {conversation_id} and saved initial local identity/session state");

    let first_plaintext = "first message before restart";
    let first_ciphertext = alice.encrypt_for_bob(first_plaintext)?;
    let first_bytes = bincode::serialize(&first_ciphertext)?;
    let first_message_id = message_id_for(&first_bytes);
    persist_actor_message(
        &mut storage,
        "alice",
        "alice",
        &bincode::serialize(&alice.export_state())?,
        &conversation_id,
        "bob",
        "alice",
        &bincode::serialize(
            &alice
                .session_state()
                .ok_or("Alice session missing after first send")?,
        )?,
        &MessageRecord {
            message_id: format!("alice-{first_message_id}"),
            conversation_id: conversation_id.clone(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Sent,
            status: MessageStatus::Sent,
            protocol_counter: Some(first_ciphertext.number),
            ciphertext: first_bytes.clone(),
            plaintext: Some(first_plaintext.to_string()),
            created_at_unix_secs: now_unix_secs(),
        },
    )?;
    println!("Persisted Alice ratchet advance + outgoing ciphertext in one SQLite transaction");

    let first_decrypted = bob.decrypt_from_alice(&first_ciphertext)?;
    persist_actor_message(
        &mut storage,
        "bob",
        "bob",
        &bincode::serialize(&bob.export_state())?,
        &conversation_id,
        "alice",
        "bob",
        &bincode::serialize(
            &bob.session_state()
                .ok_or("Bob session missing after first receive")?,
        )?,
        &MessageRecord {
            message_id: format!("bob-{first_message_id}"),
            conversation_id: conversation_id.clone(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Received,
            status: MessageStatus::Received,
            protocol_counter: Some(first_ciphertext.number),
            ciphertext: first_bytes,
            plaintext: Some(first_decrypted),
            created_at_unix_secs: now_unix_secs(),
        },
    )?;
    println!("Persisted Bob ratchet advance + accepted message in one SQLite transaction");

    drop(alice);
    drop(bob);
    drop(storage);
    println!("Simulated shutdown: dropped in-memory Alice, Bob, and SQLite connection");

    let mut storage = Storage::open(db_path)?;
    let alice_state: AliceState = bincode::deserialize(
        &storage
            .load_local_identity("alice")?
            .ok_or("Alice state missing after restart")?,
    )?;
    let bob_state: BobState = bincode::deserialize(
        &storage
            .load_local_identity("bob")?
            .ok_or("Bob state missing after restart")?,
    )?;
    let mut alice = Alice::from_state(alice_state);
    let mut bob = Bob::from_state(bob_state);
    let loaded_session = storage
        .load_session(&conversation_id)?
        .ok_or("session row missing after restart")?;
    println!(
        "Restart loaded Alice, Bob, and {} bytes of serialized session state",
        loaded_session.len()
    );

    let second_plaintext = "second message after restart";
    let second_ciphertext = alice.encrypt_for_bob(second_plaintext)?;
    let second_bytes = bincode::serialize(&second_ciphertext)?;
    let second_message_id = message_id_for(&second_bytes);
    persist_actor_message(
        &mut storage,
        "alice",
        "alice",
        &bincode::serialize(&alice.export_state())?,
        &conversation_id,
        "bob",
        "alice",
        &bincode::serialize(
            &alice
                .session_state()
                .ok_or("Alice session missing after second send")?,
        )?,
        &MessageRecord {
            message_id: format!("alice-{second_message_id}"),
            conversation_id: conversation_id.clone(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Sent,
            status: MessageStatus::Sent,
            protocol_counter: Some(second_ciphertext.number),
            ciphertext: second_bytes.clone(),
            plaintext: Some(second_plaintext.to_string()),
            created_at_unix_secs: now_unix_secs(),
        },
    )?;

    let second_decrypted = bob.decrypt_from_alice(&second_ciphertext)?;
    persist_actor_message(
        &mut storage,
        "bob",
        "bob",
        &bincode::serialize(&bob.export_state())?,
        &conversation_id,
        "alice",
        "bob",
        &bincode::serialize(
            &bob.session_state()
                .ok_or("Bob session missing after second receive")?,
        )?,
        &MessageRecord {
            message_id: format!("bob-{second_message_id}"),
            conversation_id: conversation_id.clone(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Received,
            status: MessageStatus::Received,
            protocol_counter: Some(second_ciphertext.number),
            ciphertext: second_bytes,
            plaintext: Some(second_decrypted),
            created_at_unix_secs: now_unix_secs(),
        },
    )?;
    println!("Restored ratchet state sent and decrypted a post-restart message");

    let messages = storage.messages_for_conversation(&conversation_id)?;
    println!("Stored conversation events read back from SQLite:");
    for message in messages {
        println!(
            "  id={} direction={:?} counter={:?} ciphertext_bytes={} local_plaintext={:?}",
            message.message_id,
            message.direction,
            message.protocol_counter,
            message.ciphertext.len(),
            message.plaintext
        );
    }

    Ok(())
}

fn persist_actor_message(
    storage: &mut Storage,
    local_identity_id: &str,
    local_identity_role: &str,
    local_identity_state: &[u8],
    conversation_id: &str,
    peer_id: &str,
    session_role: &str,
    session_state: &[u8],
    message: &MessageRecord,
) -> AppResult<()> {
    storage.save_state_session_and_insert_message(
        local_identity_id,
        local_identity_role,
        local_identity_state,
        conversation_id,
        peer_id,
        session_role,
        session_state,
        message,
    )?;
    Ok(())
}

fn run_outbox_demo(db_path: &Path) -> AppResult<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if db_path.exists() {
        std::fs::remove_file(db_path)?;
    }

    let conversation_id = format!("alice-bob-outbox-{}", now_unix_secs());
    let mut storage = Storage::open(db_path)?;
    let mut alice = Alice::local();
    let mut bob = Bob::local();
    let alice_exchange = alice.signed_key_exchange();
    let bob_exchange = bob.signed_key_exchange();

    alice.derive_session_key(&bob_exchange)?;
    bob.derive_session_key(&alice_exchange)?;
    storage.save_local_identity(
        "alice",
        "alice",
        &bincode::serialize(&alice.export_state())?,
    )?;
    storage.save_local_identity("bob", "bob", &bincode::serialize(&bob.export_state())?)?;
    println!("SQLite database: {}", db_path.display());
    println!("Bob is unavailable, so Alice will queue encrypted ciphertext durably");

    let plaintext = "durable hello while bob is offline";
    let ciphertext = alice.encrypt_for_bob(plaintext)?;
    let wire_envelope = DurableAppEnvelope {
        message_id: format!("msg-{}", message_id_for(&bincode::serialize(&ciphertext)?)),
        message: ciphertext,
    };
    let payload = bincode::serialize(&wire_envelope)?;
    let message_record = MessageRecord {
        message_id: wire_envelope.message_id.clone(),
        conversation_id: conversation_id.clone(),
        sender_id: "alice".to_string(),
        recipient_id: "bob".to_string(),
        direction: MessageDirection::Sent,
        status: MessageStatus::Stored,
        protocol_counter: Some(wire_envelope.message.number),
        ciphertext: payload.clone(),
        plaintext: Some(plaintext.to_string()),
        created_at_unix_secs: now_unix_secs(),
    };
    let outbox_item = OutboxItem {
        message_id: wire_envelope.message_id.clone(),
        recipient_id: "bob".to_string(),
        payload: payload.clone(),
        status: OutboxStatus::Pending,
        retry_count: 0,
        created_at_unix_secs: now_unix_secs(),
        last_attempt_unix_secs: None,
    };

    storage.save_state_session_message_and_outbox(
        "alice",
        "alice",
        &bincode::serialize(&alice.export_state())?,
        &conversation_id,
        "bob",
        "alice",
        &bincode::serialize(
            &alice
                .session_state()
                .ok_or("Alice session missing after outbox encrypt")?,
        )?,
        &message_record,
        &outbox_item,
    )?;
    println!("[OUTBOX] queued {}", wire_envelope.message_id);

    println!("Network delivery attempt fails because Bob is offline");
    println!(
        "Pending outbox items before shutdown: {}",
        storage.pending_outbox_items()?.len()
    );
    drop(alice);
    drop(storage);
    println!("Stopped Alice; only SQLite state remains");

    let mut storage = Storage::open(db_path)?;
    let alice_state: AliceState = bincode::deserialize(
        &storage
            .load_local_identity("alice")?
            .ok_or("Alice state missing after outbox restart")?,
    )?;
    let _alice = Alice::from_state(alice_state);
    let mut bob = Bob::from_state(bincode::deserialize(
        &storage
            .load_local_identity("bob")?
            .ok_or("Bob state missing after outbox restart")?,
    )?);
    let pending = storage.pending_outbox_items()?;
    println!(
        "Restarted Alice with same DB; pending outbox items: {}",
        pending.len()
    );

    for item in pending {
        println!("[OUTBOX] retrying {}", item.message_id);
        storage.record_outbox_attempt(&item.message_id)?;
        let ack = deliver_outbox_item_to_bob(&mut storage, &mut bob, &conversation_id, &item)?;
        handle_ack(&storage, ack)?;
    }

    let delivered = storage
        .outbox_item(&wire_envelope.message_id)?
        .ok_or("outbox row missing after delivery")?;
    println!(
        "Outbox status after ACK: {:?}, retry_count={}",
        delivered.status, delivered.retry_count
    );

    println!("Retrying the same encrypted payload once to show receiver deduplication");
    let duplicate = OutboxItem {
        message_id: delivered.message_id.clone(),
        recipient_id: delivered.recipient_id.clone(),
        payload: delivered.payload.clone(),
        status: OutboxStatus::Pending,
        retry_count: delivered.retry_count,
        created_at_unix_secs: delivered.created_at_unix_secs,
        last_attempt_unix_secs: delivered.last_attempt_unix_secs,
    };
    let ack = deliver_outbox_item_to_bob(&mut storage, &mut bob, &conversation_id, &duplicate)?;
    handle_ack(&storage, ack)?;

    let messages = storage.messages_for_conversation(&conversation_id)?;
    println!("Stored conversation events after retry demo:");
    for message in messages {
        println!(
            "  id={} direction={:?} counter={:?} ciphertext_bytes={} local_plaintext={:?}",
            message.message_id,
            message.direction,
            message.protocol_counter,
            message.ciphertext.len(),
            message.plaintext
        );
    }

    Ok(())
}

fn run_sync_demo() -> AppResult<()> {
    let alice = Storage::open_in_memory()?;
    let bob = Storage::open_in_memory()?;
    let conversation_id = "demo-conversation";

    for event in [
        demo_sync_event("AliceDevice", 1),
        demo_sync_event("AliceDevice", 2),
        demo_sync_event("AliceDevice", 3),
        demo_sync_event("BobDevice", 1),
    ] {
        alice.append_event(&event)?;
    }
    for event in [
        demo_sync_event("AliceDevice", 1),
        demo_sync_event("AliceDevice", 2),
        demo_sync_event("BobDevice", 1),
        demo_sync_event("BobDevice", 2),
    ] {
        bob.append_event(&event)?;
    }

    let alice_vector = alice.version_vector(conversation_id)?;
    let bob_vector = bob.version_vector(conversation_id)?;
    println!("Alice starts with vector: {alice_vector:?}");
    println!("Bob starts with vector: {bob_vector:?}");

    let alice_request = SyncRequest {
        version_vector: alice_vector.clone(),
    };
    let bob_missing_for_alice =
        bob.missing_events_for(conversation_id, &alice_request.version_vector)?;
    let bob_response = SyncResponse {
        events: bob_missing_for_alice
            .into_iter()
            .map(SyncEvent::from)
            .collect(),
    };
    println!(
        "Bob sends Alice {} missing event(s): {:?}",
        bob_response.events.len(),
        sync_event_positions(&bob_response.events)
    );
    let bob_response_bytes = bincode::serialize(&bob_response)?;
    let decoded_bob_response: SyncResponse = bincode::deserialize(&bob_response_bytes)?;
    let alice_received = decoded_bob_response
        .events
        .into_iter()
        .map(EventRecord::from)
        .collect::<Vec<_>>();
    alice.append_events(&alice_received)?;

    let bob_request = SyncRequest {
        version_vector: bob_vector.clone(),
    };
    let alice_missing_for_bob =
        alice.missing_events_for(conversation_id, &bob_request.version_vector)?;
    let alice_response = SyncResponse {
        events: alice_missing_for_bob
            .into_iter()
            .map(SyncEvent::from)
            .collect(),
    };
    println!(
        "Alice sends Bob {} missing event(s): {:?}",
        alice_response.events.len(),
        sync_event_positions(&alice_response.events)
    );
    let alice_response_bytes = bincode::serialize(&alice_response)?;
    let decoded_alice_response: SyncResponse = bincode::deserialize(&alice_response_bytes)?;
    let bob_received = decoded_alice_response
        .events
        .into_iter()
        .map(EventRecord::from)
        .collect::<Vec<_>>();
    bob.append_events(&bob_received)?;

    println!(
        "Alice final vector: {:?}",
        alice.version_vector(conversation_id)?
    );
    println!(
        "Bob final vector: {:?}",
        bob.version_vector(conversation_id)?
    );
    println!("No CRDT merge semantics are applied here; this demo only syncs missing append-only events.");

    Ok(())
}

fn run_crdt_demo() -> AppResult<()> {
    let alice = Storage::open_in_memory()?;
    let bob = Storage::open_in_memory()?;
    let conversation_id = "crdt-demo-conversation";
    let create = crdt_demo_event(
        conversation_id,
        "AliceDevice",
        1,
        ConversationEvent::MessageCreated {
            message_id: "message-1".to_string(),
            author_id: "alice".to_string(),
            payload: b"hello converged bob".to_vec(),
        },
    )?;
    let alice_reaction = crdt_demo_event(
        conversation_id,
        "AliceDevice",
        2,
        ConversationEvent::ReactionAdded {
            message_id: "message-1".to_string(),
            reaction: "+1".to_string(),
            actor_id: "alice".to_string(),
        },
    )?;
    let bob_reaction = crdt_demo_event(
        conversation_id,
        "BobDevice",
        1,
        ConversationEvent::ReactionAdded {
            message_id: "message-1".to_string(),
            reaction: "<3".to_string(),
            actor_id: "bob".to_string(),
        },
    )?;
    let bob_read = crdt_demo_event(
        conversation_id,
        "BobDevice",
        2,
        ConversationEvent::ReadAdvanced {
            actor_id: "bob".to_string(),
            read_device_id: "AliceDevice".to_string(),
            read_counter: 2,
        },
    )?;

    alice.append_event(&alice_reaction)?;
    alice.append_event(&create)?;
    bob.append_event(&bob_read)?;
    bob.append_event(&bob_reaction)?;
    bob.append_event(&create)?;

    println!(
        "Alice pre-sync state: {:?}",
        materialize_conversation(&all_sync_events(&alice, conversation_id)?)
    );
    println!(
        "Bob pre-sync state: {:?}",
        materialize_conversation(&all_sync_events(&bob, conversation_id)?)
    );

    let alice_vector = alice.version_vector(conversation_id)?;
    let bob_vector = bob.version_vector(conversation_id)?;
    let bob_to_alice = bob.missing_events_for(conversation_id, &alice_vector)?;
    let alice_to_bob = alice.missing_events_for(conversation_id, &bob_vector)?;
    alice.append_events(&bob_to_alice)?;
    bob.append_events(&alice_to_bob)?;

    let alice_state = materialize_conversation(&all_sync_events(&alice, conversation_id)?);
    let bob_state = materialize_conversation(&all_sync_events(&bob, conversation_id)?);
    println!("Alice final state: {alice_state:?}");
    println!("Bob final state: {bob_state:?}");
    println!("Converged: {}", alice_state == bob_state);

    Ok(())
}

fn demo_sync_event(device_id: &str, counter: u64) -> EventRecord {
    EventRecord {
        device_id: device_id.to_string(),
        counter,
        conversation_id: "demo-conversation".to_string(),
        event_type: "message".to_string(),
        message_id: Some(format!("{device_id}-{counter}")),
        payload: format!("{device_id}:{counter}").into_bytes(),
        created_at_unix_secs: now_unix_secs(),
    }
}

fn crdt_demo_event(
    conversation_id: &str,
    device_id: &str,
    counter: u64,
    event: ConversationEvent,
) -> AppResult<EventRecord> {
    Ok(event_record(conversation_id, device_id, counter, event)?)
}

fn all_sync_events(storage: &Storage, conversation_id: &str) -> AppResult<Vec<EventRecord>> {
    Ok(storage.missing_events_for(conversation_id, &VersionVector::new())?)
}

fn sync_event_positions(events: &[SyncEvent]) -> Vec<String> {
    events
        .iter()
        .map(|event| format!("{}:{}", event.device_id, event.counter))
        .collect()
}

fn deliver_outbox_item_to_bob(
    storage: &mut Storage,
    bob: &mut Bob,
    conversation_id: &str,
    item: &OutboxItem,
) -> AppResult<DurableAck> {
    println!("[OUTBOX] sending {}", item.message_id);
    let envelope: DurableAppEnvelope = bincode::deserialize(&item.payload)?;

    if !storage.accept_message_once(&envelope.message_id)? {
        println!(
            "[DEDUP] duplicate {}, not processing twice",
            envelope.message_id
        );
        return Ok(DurableAck {
            message_id: envelope.message_id,
        });
    }

    let plaintext = bob.decrypt_from_alice(&envelope.message)?;
    println!("Bob decrypted accepted message: {plaintext}");
    persist_actor_message(
        storage,
        "bob",
        "bob",
        &bincode::serialize(&bob.export_state())?,
        conversation_id,
        "alice",
        "bob",
        &bincode::serialize(
            &bob.session_state()
                .ok_or("Bob session missing after outbox receive")?,
        )?,
        &MessageRecord {
            message_id: format!("bob-{}", envelope.message_id),
            conversation_id: conversation_id.to_string(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Received,
            status: MessageStatus::Received,
            protocol_counter: Some(envelope.message.number),
            ciphertext: item.payload.clone(),
            plaintext: Some(plaintext),
            created_at_unix_secs: now_unix_secs(),
        },
    )?;

    Ok(DurableAck {
        message_id: envelope.message_id,
    })
}

fn handle_ack(storage: &Storage, ack: DurableAck) -> AppResult<()> {
    println!("[ACK] received {}", ack.message_id);
    storage.mark_outbox_delivered(&ack.message_id)?;
    println!("[OUTBOX] marked delivered {}", ack.message_id);
    Ok(())
}

async fn run_bob(listen_addr: SocketAddr, bootstrap_peers: Vec<Multiaddr>) -> AppResult<()> {
    let bob = Arc::new(Mutex::new(Bob::local()));
    let endpoint = Endpoint::server(server_config()?, listen_addr)?;
    let app_addr = endpoint.local_addr()?;
    println!("Bob QUIC app listening on {app_addr}");

    let direct_bob = Arc::clone(&bob);
    let mut direct = tokio::spawn(async move { run_bob_quic_once(endpoint, direct_bob).await });

    let relayed_bob = Arc::clone(&bob);
    let mut relayed = tokio::spawn(async move {
        run_discovery_advertiser(app_addr, bootstrap_peers, Some(relayed_bob)).await
    });

    tokio::select! {
        result = &mut direct => {
            relayed.abort();
            result??;
        }
        result = &mut relayed => {
            direct.abort();
            result??;
        }
    }

    Ok(())
}

async fn run_bob_quic_once(endpoint: Endpoint, bob: Arc<Mutex<Bob>>) -> AppResult<()> {
    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let connection = incoming.await?;
    println!(
        "direct connection established: Bob accepted QUIC connection from {}",
        connection.remote_address()
    );

    let mut send = connection.open_uni().await?;
    let bundle = bob
        .lock()
        .map_err(|_| "Bob state lock poisoned")?
        .prekey_bundle()?;
    let bundle_bytes = bincode::serialize(&bundle)?;
    log_boundary("Bob -> Alice PreKeyBundle", &bundle_bytes);
    send_bytes(&mut send, &bundle_bytes).await?;

    let mut recv = connection.accept_uni().await?;
    let encrypted_bytes = receive_bytes(&mut recv).await?;
    log_boundary("Alice -> Bob InitialMessage", &encrypted_bytes);
    let initial_message: InitialMessage = bincode::deserialize(&encrypted_bytes)?;
    let plaintext = bob
        .lock()
        .map_err(|_| "Bob state lock poisoned")?
        .decrypt_initial_message(&initial_message)?;
    println!("Bob decrypted plaintext: {plaintext}");

    let mut ack = connection.open_uni().await?;
    send_bytes(&mut ack, b"ok").await?;
    endpoint.wait_idle().await;
    Ok(())
}

async fn run_alice_discovered(
    bob_peer_id: PeerId,
    message: &str,
    bootstrap_peers: Vec<Multiaddr>,
) -> AppResult<()> {
    println!("Alice looking for Bob PeerId {bob_peer_id}");
    let bob_addr = discover_app_addr(bob_peer_id, bootstrap_peers.clone()).await?;
    println!("Alice discovered Bob's QUIC app address: {bob_addr}");

    match time::timeout(DIRECT_DIAL_TIMEOUT, run_alice(bob_addr, message)).await {
        Ok(Ok(())) => {
            println!("direct connection established; QUIC path used");
            Ok(())
        }
        Ok(Err(error)) => {
            println!("direct connection failed: {error}");
            println!("falling back to relay");
            run_alice_relayed(bob_peer_id, message, bootstrap_peers).await
        }
        Err(_) => {
            println!("direct connection attempt timed out after {DIRECT_DIAL_TIMEOUT:?}");
            println!("falling back to relay");
            run_alice_relayed(bob_peer_id, message, bootstrap_peers).await
        }
    }
}

async fn run_alice(bob_addr: SocketAddr, message: &str) -> AppResult<()> {
    let mut alice = Alice::local();
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    endpoint.set_default_client_config(insecure_client_config()?);

    let connection = endpoint.connect(bob_addr, "localhost")?.await?;
    println!("Alice connected to Bob at {}", connection.remote_address());

    let mut recv = connection.accept_uni().await?;
    let bundle_bytes = receive_bytes(&mut recv).await?;
    log_boundary("Bob -> Alice PreKeyBundle", &bundle_bytes);
    let bundle: PreKeyBundle = bincode::deserialize(&bundle_bytes)?;

    let initial_message = alice.encrypt_initial_message(&bundle, message)?;
    let encrypted_bytes = bincode::serialize(&initial_message)?;
    log_boundary("Alice -> Bob InitialMessage", &encrypted_bytes);
    let mut send = connection.open_uni().await?;
    send_bytes(&mut send, &encrypted_bytes).await?;
    let mut ack = connection.accept_uni().await?;
    let ack_bytes = receive_bytes(&mut ack).await?;
    println!(
        "Alice received transport ack: {}",
        String::from_utf8_lossy(&ack_bytes)
    );
    println!("Alice plaintext before network send: {message}");

    Ok(())
}

async fn run_chat_bob(listen_addr: SocketAddr) -> AppResult<()> {
    let mut bob = Bob::local();
    let endpoint = Endpoint::server(server_config()?, listen_addr)?;
    println!("Bob chat listening on {}", endpoint.local_addr()?);

    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let connection = incoming.await?;
    println!("Alice connected from {}", connection.remote_address());

    let mut send = connection.open_uni().await?;
    let bundle = bob.prekey_bundle()?;
    send_bytes(&mut send, &bincode::serialize(&bundle)?).await?;

    let mut recv = connection.accept_uni().await?;
    let initial_bytes = receive_bytes(&mut recv).await?;
    let initial_message: InitialMessage = bincode::deserialize(&initial_bytes)?;
    let initial_plaintext = bob.decrypt_initial_message(&initial_message)?;
    if !initial_plaintext.is_empty() {
        println!("Alice: {initial_plaintext}");
    }
    println!("Connected to Alice");
    println!("Type messages and press Enter:");

    chat_loop_bob(connection, bob).await
}

async fn run_chat_alice(bob_addr: SocketAddr) -> AppResult<()> {
    let mut alice = Alice::local();
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    endpoint.set_default_client_config(insecure_client_config()?);

    let connection = endpoint.connect(bob_addr, "localhost")?.await?;

    let mut recv = connection.accept_uni().await?;
    let bundle_bytes = receive_bytes(&mut recv).await?;
    let bundle: PreKeyBundle = bincode::deserialize(&bundle_bytes)?;

    let initial_message = alice.encrypt_initial_message(&bundle, "")?;
    let mut send = connection.open_uni().await?;
    send_bytes(&mut send, &bincode::serialize(&initial_message)?).await?;
    println!("Connected to Bob");
    println!("Type messages and press Enter:");

    chat_loop_alice(connection, alice).await
}

async fn chat_loop_alice(connection: quinn::Connection, alice: Alice) -> AppResult<()> {
    let alice = Arc::new(Mutex::new(alice));
    let mut stdin_rx = spawn_stdin_reader();

    loop {
        tokio::select! {
            line = stdin_rx.recv() => {
                let Some(line) = line else {
                    println!("stdin closed; chat ending");
                    return Ok(());
                };
                send_alice_chat_line(&connection, Arc::clone(&alice), line).await?;
            }
            incoming = connection.accept_uni() => {
                let mut recv = incoming?;
                let frame_bytes = receive_bytes(&mut recv).await?;
                let frame: ChatFrame = bincode::deserialize(&frame_bytes)?;
                match frame {
                    ChatFrame::Message(message) => {
                        let plaintext = alice
                            .lock()
                            .map_err(|_| "Alice state lock poisoned")?
                            .decrypt_from_bob(&message)?;
                        println!("Bob: {plaintext}");
                    }
                }
            }
        }
    }
}

async fn chat_loop_bob(connection: quinn::Connection, bob: Bob) -> AppResult<()> {
    let bob = Arc::new(Mutex::new(bob));
    let mut stdin_rx = spawn_stdin_reader();

    loop {
        tokio::select! {
            line = stdin_rx.recv() => {
                let Some(line) = line else {
                    println!("stdin closed; chat ending");
                    return Ok(());
                };
                send_bob_chat_line(&connection, Arc::clone(&bob), line).await?;
            }
            incoming = connection.accept_uni() => {
                let mut recv = incoming?;
                let frame_bytes = receive_bytes(&mut recv).await?;
                let frame: ChatFrame = bincode::deserialize(&frame_bytes)?;
                match frame {
                    ChatFrame::Message(message) => {
                        let plaintext = bob
                            .lock()
                            .map_err(|_| "Bob state lock poisoned")?
                            .decrypt_from_alice(&message)?;
                        println!("Alice: {plaintext}");
                    }
                }
            }
        }
    }
}

async fn send_alice_chat_line(
    connection: &quinn::Connection,
    alice: Arc<Mutex<Alice>>,
    line: String,
) -> AppResult<()> {
    if line.is_empty() {
        return Ok(());
    }

    let message = alice
        .lock()
        .map_err(|_| "Alice state lock poisoned")?
        .encrypt_for_bob(&line)?;
    send_chat_frame(connection, ChatFrame::Message(message)).await
}

async fn send_bob_chat_line(
    connection: &quinn::Connection,
    bob: Arc<Mutex<Bob>>,
    line: String,
) -> AppResult<()> {
    if line.is_empty() {
        return Ok(());
    }

    let message = bob
        .lock()
        .map_err(|_| "Bob state lock poisoned")?
        .encrypt_for_alice(&line)?;
    send_chat_frame(connection, ChatFrame::Message(message)).await
}

async fn send_chat_frame(connection: &quinn::Connection, frame: ChatFrame) -> AppResult<()> {
    let bytes = bincode::serialize(&frame)?;
    let mut send = connection.open_uni().await?;
    send_bytes(&mut send, &bytes).await
}

fn spawn_stdin_reader() -> mpsc::UnboundedReceiver<String> {
    let (tx, rx) = mpsc::unbounded_channel();
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

async fn run_alice_relayed(
    bob_peer_id: PeerId,
    message: &str,
    relay_peers: Vec<Multiaddr>,
) -> AppResult<()> {
    let mut alice = Alice::local();
    let mut swarm = new_discovery_swarm()?;
    let local_peer_id = *swarm.local_peer_id();
    let relay_addresses = relay_dial_addresses(&relay_peers, bob_peer_id);

    if relay_addresses.is_empty() {
        return Err(
            "relay fallback requested but no relay bootstrap multiaddr was provided".into(),
        );
    }

    listen_and_bootstrap(&mut swarm, relay_peers.clone())?;
    for address in &relay_addresses {
        swarm.add_peer_address(bob_peer_id, address.clone());
    }

    println!("Alice libp2p PeerId for relay fallback: {local_peer_id}");
    println!("falling back to relay addresses: {relay_addresses:?}");
    println!("DCUtR hole punch attempt will be coordinated if a relayed connection is established");

    let mut requested_bundle = false;
    let mut sent_initial = false;
    let timeout = time::sleep(DISCOVERY_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => return Err("relay fallback timed out".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!(
                            "Alice libp2p listening on {}",
                            address.with(Protocol::P2p(local_peer_id))
                        );
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } if peer_id == bob_peer_id => {
                        if endpoint.is_relayed() {
                            println!("connected through relay: Alice connected to Bob");
                            println!("DCUtR hole punch attempt started");
                        } else {
                            println!("hole punch succeeded: Alice has a direct libp2p connection to Bob");
                        }
                        if !requested_bundle {
                            swarm.behaviour_mut().app.send_request(&bob_peer_id, CipherMeshRequest::PreKeyBundle);
                            requested_bundle = true;
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } if peer_id == Some(bob_peer_id) => {
                        println!("direct or relayed libp2p dial failed for Bob: {error}");
                    }
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Relay(event)) => log_relay_event("Alice", event),
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Dcutr(event)) => log_dcutr_event("Alice", event),
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new })) => {
                        println!("reachability changed: {old:?} -> {new:?}");
                        if matches!(new, autonat::NatStatus::Private) {
                            println!("peer appears private/unreachable; relay fallback may be needed");
                        }
                    }
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::App(request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    })) => {
                        match response {
                            CipherMeshResponse::PreKeyBundle(bundle_bytes) if !sent_initial => {
                                log_boundary("Bob -> Alice PreKeyBundle over relay", &bundle_bytes);
                                let bundle: PreKeyBundle = bincode::deserialize(&bundle_bytes)?;
                                let initial_message = alice.encrypt_initial_message(&bundle, message)?;
                                let encrypted_bytes = bincode::serialize(&initial_message)?;
                                log_boundary("Alice -> Bob InitialMessage over relay", &encrypted_bytes);
                                swarm.behaviour_mut().app.send_request(
                                    &bob_peer_id,
                                    CipherMeshRequest::InitialMessage(encrypted_bytes),
                                );
                                sent_initial = true;
                            }
                            CipherMeshResponse::Ack(ack_bytes) => {
                                println!(
                                    "Alice received relay transport ack: {}",
                                    String::from_utf8_lossy(&ack_bytes)
                                );
                                println!("Alice plaintext before network send: {message}");
                                return Ok(());
                            }
                            CipherMeshResponse::Error(error) => return Err(error.into()),
                            _ => {}
                        }
                    }
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::App(request_response::Event::OutboundFailure {
                        error,
                        ..
                    })) => {
                        return Err(format!("relay app request failed: {error}").into());
                    }
                    _ => {}
                }
            }
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct DiscoveryBehaviour {
    app: request_response::cbor::Behaviour<CipherMeshRequest, CipherMeshResponse>,
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    mdns: mdns::tokio::Behaviour,
    relay: relay::client::Behaviour,
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct RelayServerBehaviour {
    identify: identify::Behaviour,
    relay: relay::Behaviour,
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct MailboxBehaviour {
    identify: identify::Behaviour,
    mailbox: request_response::cbor::Behaviour<MailboxRequest, MailboxResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CipherMeshRequest {
    PreKeyBundle,
    InitialMessage(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CipherMeshResponse {
    PreKeyBundle(Vec<u8>),
    Ack(Vec<u8>),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableAppEnvelope {
    message_id: String,
    message: RatchetMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableAck {
    message_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncEvent {
    device_id: String,
    counter: u64,
    conversation_id: String,
    event_type: String,
    message_id: Option<String>,
    payload: Vec<u8>,
    created_at_unix_secs: u64,
}

impl From<EventRecord> for SyncEvent {
    fn from(event: EventRecord) -> Self {
        Self {
            device_id: event.device_id,
            counter: event.counter,
            conversation_id: event.conversation_id,
            event_type: event.event_type,
            message_id: event.message_id,
            payload: event.payload,
            created_at_unix_secs: event.created_at_unix_secs,
        }
    }
}

impl From<SyncEvent> for EventRecord {
    fn from(event: SyncEvent) -> Self {
        Self {
            device_id: event.device_id,
            counter: event.counter,
            conversation_id: event.conversation_id,
            event_type: event.event_type,
            message_id: event.message_id,
            payload: event.payload,
            created_at_unix_secs: event.created_at_unix_secs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncRequest {
    version_vector: VersionVector,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncResponse {
    events: Vec<SyncEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ChatFrame {
    Message(RatchetMessage),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OfflineEnvelope {
    recipient_token: String,
    message_id: String,
    encrypted_payload: Vec<u8>,
    expires_at_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum MailboxRequest {
    Deposit(OfflineEnvelope),
    Fetch { recipient_token: String },
    Acknowledge { message_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum MailboxResponse {
    Deposited { message_id: String },
    Pending { envelopes: Vec<OfflineEnvelope> },
    Acknowledged { message_id: String },
    Error(String),
}

fn new_relay_server_swarm() -> AppResult<Swarm<RelayServerBehaviour>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(move |key| {
            Ok(RelayServerBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    DISCOVERY_PROTOCOL.to_string(),
                    key.public(),
                )),
                relay: relay::Behaviour::new(local_peer_id, relay::Config::default()),
            })
        })?
        .build();

    Ok(swarm)
}

fn new_mailbox_swarm() -> AppResult<Swarm<MailboxBehaviour>> {
    let local_key = identity::Keypair::generate_ed25519();

    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(move |key| {
            Ok(MailboxBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    MAILBOX_PROTOCOL.to_string(),
                    key.public(),
                )),
                mailbox: request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new(MAILBOX_PROTOCOL),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default().with_request_timeout(DISCOVERY_TIMEOUT),
                ),
            })
        })?
        .build();

    Ok(swarm)
}

fn new_discovery_swarm() -> AppResult<Swarm<DiscoveryBehaviour>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    let store = kad::store::MemoryStore::new(local_peer_id);
    let mut kademlia = kad::Behaviour::new(local_peer_id, store);
    kademlia.set_mode(Some(kad::Mode::Server));

    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
        .with_behaviour(move |key, relay| {
            Ok(DiscoveryBehaviour {
                app: request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new(APP_RELAY_PROTOCOL),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default().with_request_timeout(DISCOVERY_TIMEOUT),
                ),
                autonat: autonat::Behaviour::new(local_peer_id, autonat::Config::default()),
                dcutr: dcutr::Behaviour::new(local_peer_id),
                identify: identify::Behaviour::new(identify::Config::new(
                    DISCOVERY_PROTOCOL.to_string(),
                    key.public(),
                )),
                kad: kademlia,
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
                relay,
            })
        })?
        .build();

    Ok(swarm)
}

async fn run_discovery_advertiser(
    app_addr: SocketAddr,
    bootstrap_peers: Vec<Multiaddr>,
    bob: Option<Arc<Mutex<Bob>>>,
) -> AppResult<()> {
    let mut swarm = new_discovery_swarm()?;
    let local_peer_id = *swarm.local_peer_id();
    let app_multiaddr = socket_to_app_multiaddr(app_addr);
    let record = kad::Record::new(
        record_key(local_peer_id),
        app_multiaddr.to_string().into_bytes(),
    );

    swarm
        .behaviour_mut()
        .kad
        .put_record(record, kad::Quorum::One)?;
    listen_and_bootstrap(&mut swarm, bootstrap_peers.clone())?;
    reserve_on_relays(&mut swarm, &bootstrap_peers)?;

    println!("Bob libp2p PeerId: {local_peer_id}");
    println!("Bob advertised QUIC app address record: {app_multiaddr}");
    let mut final_relay_ack_pending = false;

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!(
                    "Bob libp2p listening on {}",
                    address.with(Protocol::P2p(local_peer_id))
                );
            }
            SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Mdns(mdns::Event::Discovered(
                peers,
            ))) => {
                for (peer, address) in peers {
                    println!("Bob mDNS discovered {peer} at {address}");
                    swarm.behaviour_mut().kad.add_address(&peer, address);
                }
            }
            SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                for (peer, address) in peers {
                    swarm.behaviour_mut().kad.remove_address(&peer, &address);
                }
            }
            SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Kad(
                kad::Event::OutboundQueryProgressed { result, .. },
            )) => {
                if let kad::QueryResult::Bootstrap(result) = result {
                    println!("Bob Kademlia bootstrap result: {result:?}");
                }
            }
            SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                for address in info.listen_addrs {
                    swarm.behaviour_mut().kad.add_address(&peer_id, address);
                }
            }
            SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Autonat(
                autonat::Event::StatusChanged { old, new },
            )) => {
                println!("reachability changed: {old:?} -> {new:?}");
                if matches!(new, autonat::NatStatus::Private) {
                    println!("peer appears private/unreachable; relay fallback may be needed");
                }
            }
            SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Relay(event)) => {
                log_relay_event("Bob", event);
            }
            SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Dcutr(event)) => {
                log_dcutr_event("Bob", event);
            }
            SwarmEvent::Behaviour(DiscoveryBehaviourEvent::App(event)) => {
                if let Some(bob) = &bob {
                    if handle_bob_app_event(
                        &mut swarm,
                        Arc::clone(bob),
                        event,
                        &mut final_relay_ack_pending,
                    )? {
                        return Ok(());
                    }
                }
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if endpoint.is_relayed() {
                    println!("connected through relay: Bob connected to {peer_id}");
                    println!("DCUtR hole punch coordination available over relayed connection");
                } else {
                    println!("direct libp2p connection established: Bob connected to {peer_id}");
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                println!("direct/libp2p dial failed for {peer_id:?}: {error}");
            }
            _ => {}
        }
    }
}

async fn discover_app_addr(
    target_peer_id: PeerId,
    bootstrap_peers: Vec<Multiaddr>,
) -> AppResult<SocketAddr> {
    let mut swarm = new_discovery_swarm()?;
    let local_peer_id = *swarm.local_peer_id();
    let mut discovered_addresses = BTreeMap::<PeerId, BTreeSet<Multiaddr>>::new();
    let mut asked_kad = false;

    listen_and_bootstrap(&mut swarm, bootstrap_peers)?;
    println!("Alice libp2p PeerId: {local_peer_id}");

    let timeout = time::sleep(DISCOVERY_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                return Err(format!("timed out discovering {target_peer_id}").into());
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!(
                            "Alice libp2p listening on {}",
                            address.with(Protocol::P2p(local_peer_id))
                        );
                    }
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                        for (peer, address) in peers {
                            println!("Alice mDNS discovered {peer} at {address}");
                            discovered_addresses.entry(peer).or_default().insert(address.clone());
                            swarm.behaviour_mut().kad.add_address(&peer, address);
                            if peer == target_peer_id && !asked_kad {
                                swarm.behaviour_mut().kad.get_record(record_key(target_peer_id));
                                asked_kad = true;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Mdns(mdns::Event::Expired(peers))) => {
                        for (peer, address) in peers {
                            swarm.behaviour_mut().kad.remove_address(&peer, &address);
                        }
                    }
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Identify(identify::Event::Received {
                        peer_id,
                        info,
                        ..
                    })) => {
                        for address in info.listen_addrs {
                            discovered_addresses.entry(peer_id).or_default().insert(address.clone());
                            swarm.behaviour_mut().kad.add_address(&peer_id, address);
                        }
                        if peer_id == target_peer_id && !asked_kad {
                            swarm.behaviour_mut().kad.get_record(record_key(target_peer_id));
                            asked_kad = true;
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target_peer_id && !asked_kad => {
                        swarm.behaviour_mut().kad.get_record(record_key(target_peer_id));
                        asked_kad = true;
                    }
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))),
                        ..
                    })) => {
                        let value = String::from_utf8(peer_record.record.value)?;
                        let app_multiaddr: Multiaddr = value.parse()?;
                        let fallback_ip = discovered_addresses
                            .get(&target_peer_id)
                            .and_then(|addresses| addresses.iter().find_map(multiaddr_ip));
                        return socket_from_app_multiaddr(&app_multiaddr, fallback_ip);
                    }
                    SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetRecord(Err(error)),
                        ..
                    })) => {
                        println!("Alice Kademlia record query has not found Bob yet: {error:?}");
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn run_kademlia_demo() -> AppResult<()> {
    let bootstrap_app_addr: SocketAddr = "127.0.0.1:5001".parse()?;
    let target_app_addr: SocketAddr = "127.0.0.1:5002".parse()?;
    let mut bootstrap = new_discovery_swarm()?;
    let mut target = new_discovery_swarm()?;
    let mut alice = new_discovery_swarm()?;
    let bootstrap_peer_id = *bootstrap.local_peer_id();
    let target_peer_id = *target.local_peer_id();
    let alice_peer_id = *alice.local_peer_id();

    bootstrap.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    target.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    alice.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;

    bootstrap.behaviour_mut().kad.put_record(
        kad::Record::new(
            record_key(bootstrap_peer_id),
            socket_to_app_multiaddr(bootstrap_app_addr)
                .to_string()
                .into_bytes(),
        ),
        kad::Quorum::One,
    )?;
    bootstrap.behaviour_mut().kad.put_record(
        kad::Record::new(
            record_key(target_peer_id),
            socket_to_app_multiaddr(target_app_addr)
                .to_string()
                .into_bytes(),
        ),
        kad::Quorum::One,
    )?;

    let bootstrap_addr = next_listen_addr(&mut bootstrap)
        .await?
        .with(Protocol::P2p(bootstrap_peer_id));
    target
        .behaviour_mut()
        .kad
        .add_address(&bootstrap_peer_id, strip_p2p(&bootstrap_addr).0);
    alice
        .behaviour_mut()
        .kad
        .add_address(&bootstrap_peer_id, strip_p2p(&bootstrap_addr).0);
    target.dial(bootstrap_addr.clone())?;
    alice.dial(bootstrap_addr.clone())?;

    let mut target_connected = false;
    let mut alice_connected = false;
    let mut queried = false;
    let timeout = time::sleep(DISCOVERY_TIMEOUT);
    tokio::pin!(timeout);

    println!("Bootstrap PeerId: {bootstrap_peer_id}");
    println!("Target PeerId: {target_peer_id}");
    println!("Alice discovery PeerId: {alice_peer_id}");
    println!("Bootstrap address: {bootstrap_addr}");

    loop {
        tokio::select! {
            _ = &mut timeout => return Err("Kademlia demo timed out".into()),
            event = bootstrap.select_next_some() => handle_demo_event("bootstrap", &mut bootstrap, event),
            event = target.select_next_some() => {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = &event {
                    if *peer_id == bootstrap_peer_id {
                        target_connected = true;
                        let _ = target.behaviour_mut().kad.bootstrap();
                    }
                }
                handle_demo_event("target", &mut target, event);
            }
            event = alice.select_next_some() => {
                if let SwarmEvent::ConnectionEstablished { peer_id, .. } = &event {
                    if *peer_id == bootstrap_peer_id {
                        alice_connected = true;
                        let _ = alice.behaviour_mut().kad.bootstrap();
                    }
                }
                if target_connected && alice_connected && !queried {
                    alice.behaviour_mut().kad.get_closest_peers(target_peer_id);
                    alice.behaviour_mut().kad.get_record(record_key(target_peer_id));
                    queried = true;
                }
                if let SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))),
                    ..
                })) = &event {
                    let value = String::from_utf8(peer_record.record.value.clone())?;
                    println!("Kademlia found target app-address record: {value}");
                    println!("Demo note: these PeerIds are libp2p identities only; CipherMesh Ed25519/X25519 authentication is not used by discovery.");
                    return Ok(());
                }
                handle_demo_event("alice", &mut alice, event);
            }
        }
    }
}

async fn run_relay_server(listen_addr: Multiaddr) -> AppResult<()> {
    let mut swarm = new_relay_server_swarm()?;
    let local_peer_id = *swarm.local_peer_id();

    swarm.listen_on(listen_addr)?;
    println!("Relay PeerId: {local_peer_id}");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                swarm.add_external_address(address.clone().with(Protocol::P2p(local_peer_id)));
                println!(
                    "Relay listening on {}",
                    address.with(Protocol::P2p(local_peer_id))
                );
            }
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if endpoint.is_relayed() {
                    println!("Relay observed relayed connection with {peer_id}");
                } else {
                    println!("Relay direct control connection established with {peer_id}");
                }
            }
            SwarmEvent::Behaviour(RelayServerBehaviourEvent::Relay(event)) => {
                println!("Relay server event: {event:?}");
            }
            _ => {}
        }
    }
}

async fn run_relay_demo() -> AppResult<()> {
    let mut relay_swarm = new_relay_server_swarm()?;
    let relay_peer_id = *relay_swarm.local_peer_id();

    relay_swarm.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
    let relay_addr = next_relay_listen_addr(&mut relay_swarm)
        .await?
        .with(Protocol::P2p(relay_peer_id));

    println!("Relay demo PeerId: {relay_peer_id}");
    println!("Relay demo address: {relay_addr}");
    println!("Run Bob with: cargo run -- bob 127.0.0.1:5999 {relay_addr}");
    println!("Run Alice with: cargo run -- alice <bob-peer-id> \"hello\" {relay_addr}");
    println!("Keeping demo relay alive for 30 seconds...");

    let timeout = time::sleep(DISCOVERY_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => return Ok(()),
            event = relay_swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        relay_swarm.add_external_address(address.clone().with(Protocol::P2p(relay_peer_id)));
                        println!("Relay listening on {}", address.with(Protocol::P2p(relay_peer_id)));
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        if endpoint.is_relayed() {
                            println!("Relay demo observed relayed connection with {peer_id}");
                        } else {
                            println!("Relay demo direct control connection established with {peer_id}");
                        }
                    }
                    SwarmEvent::Behaviour(RelayServerBehaviourEvent::Relay(event)) => {
                        println!("Relay demo event: {event:?}");
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn run_mailbox_node(listen_addr: Multiaddr, db_path: &Path) -> AppResult<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut swarm = new_mailbox_swarm()?;
    let local_peer_id = *swarm.local_peer_id();
    let store = MailboxStorage::open(db_path, MAILBOX_MAX_ENVELOPES)?;
    let pending_count = store.pending_count()?;

    swarm.listen_on(listen_addr)?;
    println!("Mailbox PeerId: {local_peer_id}");
    println!("Mailbox SQLite database: {}", db_path.display());
    println!("Mailbox loaded {pending_count} pending opaque envelope(s) from SQLite");
    println!("Mailbox is untrusted: it stores routing tokens and encrypted bytes only");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!(
                    "Mailbox listening on {}",
                    address.with(Protocol::P2p(local_peer_id))
                );
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                println!("Mailbox connected to peer {peer_id}");
            }
            SwarmEvent::Behaviour(MailboxBehaviourEvent::Mailbox(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => match request {
                MailboxRequest::Deposit(envelope) => {
                    println!(
                        "[MAILBOX] storing opaque envelope id={} recipient_token={} encrypted_bytes={} expires_at={:?}",
                        envelope.message_id,
                        envelope.recipient_token,
                        envelope.encrypted_payload.len(),
                        envelope.expires_at_unix_secs
                    );
                    let message_id = envelope.message_id.clone();
                    let record = MailboxEnvelopeRecord {
                        message_id: envelope.message_id,
                        recipient_token: envelope.recipient_token,
                        encrypted_payload: envelope.encrypted_payload,
                        created_at_unix_secs: mailbox_now_unix_secs(),
                        expires_at_unix_secs: envelope.expires_at_unix_secs,
                    };
                    let response = match store.deposit(&record, mailbox_now_unix_secs()) {
                        Ok(inserted) => {
                            if inserted {
                                println!(
                                    "[MAILBOX] stored envelope {}, {} bytes",
                                    record.message_id,
                                    record.encrypted_payload.len()
                                );
                            } else {
                                println!(
                                    "[MAILBOX] duplicate deposit {}, keeping one row",
                                    record.message_id
                                );
                            }
                            MailboxResponse::Deposited { message_id }
                        }
                        Err(error) => MailboxResponse::Error(error.to_string()),
                    };
                    let _ = swarm
                        .behaviour_mut()
                        .mailbox
                        .send_response(channel, response);
                    println!("Mailbox accepted deposit request from {peer}");
                }
                MailboxRequest::Fetch { recipient_token } => {
                    let envelopes =
                        match store.fetch_pending(&recipient_token, mailbox_now_unix_secs()) {
                            Ok(records) => records
                                .into_iter()
                                .map(|record| OfflineEnvelope {
                                    recipient_token: record.recipient_token,
                                    message_id: record.message_id,
                                    encrypted_payload: record.encrypted_payload,
                                    expires_at_unix_secs: record.expires_at_unix_secs,
                                })
                                .collect::<Vec<_>>(),
                            Err(error) => {
                                let _ = swarm.behaviour_mut().mailbox.send_response(
                                    channel,
                                    MailboxResponse::Error(error.to_string()),
                                );
                                continue;
                            }
                        };
                    println!(
                        "[MAILBOX] returning {} pending opaque envelope(s) for recipient_token={recipient_token}",
                        envelopes.len()
                    );
                    let _ = swarm
                        .behaviour_mut()
                        .mailbox
                        .send_response(channel, MailboxResponse::Pending { envelopes });
                    println!("Mailbox accepted fetch request from {peer}");
                }
                MailboxRequest::Acknowledge { message_id } => {
                    let response =
                        match store.acknowledge_retrieval(&message_id, mailbox_now_unix_secs()) {
                            Ok(()) => {
                                println!("[MAILBOX] marked envelope {message_id} delivered");
                                MailboxResponse::Acknowledged { message_id }
                            }
                            Err(error) => MailboxResponse::Error(error.to_string()),
                        };
                    let _ = swarm
                        .behaviour_mut()
                        .mailbox
                        .send_response(channel, response);
                    println!("Mailbox accepted retrieval ACK from {peer}");
                }
            },
            SwarmEvent::Behaviour(MailboxBehaviourEvent::Mailbox(
                request_response::Event::ResponseSent { peer, .. },
            )) => {
                println!("Mailbox response sent to {peer}");
            }
            SwarmEvent::Behaviour(MailboxBehaviourEvent::Mailbox(
                request_response::Event::InboundFailure { peer, error, .. },
            )) => {
                println!("Mailbox inbound failure from {peer}: {error}");
            }
            _ => {}
        }
    }
}

async fn run_alice_mailbox_deposit(
    mailbox_addr: Multiaddr,
    message: &str,
    db_path: &Path,
) -> AppResult<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mailbox_peer_id = peer_id_from_multiaddr(&mailbox_addr)?;
    let mut storage = Storage::open(db_path)?;
    let mut alice = Alice::local();
    let bob_bundle = Bob::mailbox_demo_prekey_bundle()?;
    let recipient_token = recipient_token_for_bundle(&bob_bundle);
    let initial_message = alice.encrypt_initial_message(&bob_bundle, message)?;
    let encrypted_payload = bincode::serialize(&initial_message)?;
    let message_id = message_id_for(&encrypted_payload);
    let conversation_id = format!("mailbox-{recipient_token}");
    let envelope = OfflineEnvelope {
        recipient_token: recipient_token.clone(),
        message_id: message_id.clone(),
        encrypted_payload: encrypted_payload.clone(),
        expires_at_unix_secs: Some(current_unix_secs() + MAILBOX_ENVELOPE_TTL_SECS),
    };
    let outbox = OutboxItem {
        message_id: message_id.clone(),
        recipient_id: recipient_token.clone(),
        payload: encrypted_payload.clone(),
        status: OutboxStatus::Pending,
        retry_count: 0,
        created_at_unix_secs: now_unix_secs(),
        last_attempt_unix_secs: None,
    };

    storage.save_state_session_message_and_outbox(
        "alice-mailbox",
        "alice",
        &bincode::serialize(&alice.export_state())?,
        &conversation_id,
        &recipient_token,
        "alice",
        &bincode::serialize(
            &alice
                .session_state()
                .ok_or("Alice session missing after mailbox encrypt")?,
        )?,
        &MessageRecord {
            message_id: message_id.clone(),
            conversation_id: conversation_id.clone(),
            sender_id: "alice".to_string(),
            recipient_id: recipient_token.clone(),
            direction: MessageDirection::Sent,
            status: MessageStatus::Stored,
            protocol_counter: Some(initial_message.message.number),
            ciphertext: encrypted_payload.clone(),
            plaintext: Some(message.to_string()),
            created_at_unix_secs: now_unix_secs(),
        },
        &outbox,
    )?;
    println!("[OUTBOX] queued {message_id} for mailbox deposit");
    println!(
        "Alice depositing encrypted offline envelope id={} encrypted_bytes={}",
        envelope.message_id,
        envelope.encrypted_payload.len()
    );
    println!("Alice plaintext before mailbox deposit: {message}");

    let response = mailbox_request(
        mailbox_addr.clone(),
        mailbox_peer_id,
        MailboxRequest::Deposit(envelope),
    )
    .await?;

    match response {
        MailboxResponse::Deposited { message_id } => {
            println!("[MAILBOX-ACK] mailbox stored encrypted envelope id={message_id}");
            println!("Alice outbox remains pending until Bob ACKs actual receipt");
            Ok(())
        }
        MailboxResponse::Error(error) => Err(error.into()),
        MailboxResponse::Pending { .. } => Err("unexpected pending-envelope response".into()),
        MailboxResponse::Acknowledged { .. } => Err("unexpected mailbox ACK response".into()),
    }
}

async fn run_bob_mailbox_fetch(mailbox_addr: Multiaddr, db_path: &Path) -> AppResult<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mailbox_peer_id = peer_id_from_multiaddr(&mailbox_addr)?;
    let storage = Storage::open(db_path)?;
    let mut bob = Bob::mailbox_demo();
    let bob_bundle = bob.prekey_bundle()?;
    let recipient_token = recipient_token_for_bundle(&bob_bundle);

    println!("Bob fetching offline envelopes for recipient_token={recipient_token}");
    let response = mailbox_request(
        mailbox_addr.clone(),
        mailbox_peer_id,
        MailboxRequest::Fetch {
            recipient_token: recipient_token.clone(),
        },
    )
    .await?;

    match response {
        MailboxResponse::Pending { envelopes } => {
            println!(
                "Bob received {} encrypted offline envelope(s)",
                envelopes.len()
            );
            for envelope in envelopes {
                println!(
                    "Bob decrypting envelope id={} encrypted_bytes={}",
                    envelope.message_id,
                    envelope.encrypted_payload.len()
                );
                if !storage.accept_message_once(&envelope.message_id)? {
                    println!(
                        "[DEDUP] duplicate {}, not processing twice",
                        envelope.message_id
                    );
                } else {
                    let initial_message: InitialMessage =
                        bincode::deserialize(&envelope.encrypted_payload)?;
                    let plaintext = bob.decrypt_initial_message(&initial_message)?;
                    println!("Bob decrypted offline plaintext: {plaintext}");
                    storage.insert_message(&MessageRecord {
                        message_id: envelope.message_id.clone(),
                        conversation_id: format!("mailbox-{recipient_token}"),
                        sender_id: "alice".to_string(),
                        recipient_id: "bob".to_string(),
                        direction: MessageDirection::Received,
                        status: MessageStatus::Received,
                        protocol_counter: Some(initial_message.message.number),
                        ciphertext: envelope.encrypted_payload.clone(),
                        plaintext: Some(plaintext),
                        created_at_unix_secs: now_unix_secs(),
                    })?;
                    storage.save_local_identity(
                        "bob-mailbox",
                        "bob",
                        &bincode::serialize(&bob.export_state())?,
                    )?;
                }
                let ack_response = mailbox_request(
                    mailbox_addr.clone(),
                    mailbox_peer_id,
                    MailboxRequest::Acknowledge {
                        message_id: envelope.message_id.clone(),
                    },
                )
                .await?;
                match ack_response {
                    MailboxResponse::Acknowledged { message_id } => {
                        println!("[ACK] Bob confirmed mailbox retrieval for {message_id}");
                    }
                    MailboxResponse::Error(error) => return Err(error.into()),
                    _ => return Err("unexpected mailbox retrieval ACK response".into()),
                }
            }
            Ok(())
        }
        MailboxResponse::Error(error) => Err(error.into()),
        MailboxResponse::Deposited { .. } => Err("unexpected deposit response".into()),
        MailboxResponse::Acknowledged { .. } => Err("unexpected mailbox ACK response".into()),
    }
}

async fn mailbox_request(
    mailbox_addr: Multiaddr,
    mailbox_peer_id: PeerId,
    request: MailboxRequest,
) -> AppResult<MailboxResponse> {
    let mut swarm = new_mailbox_swarm()?;
    let local_peer_id = *swarm.local_peer_id();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    swarm.add_peer_address(mailbox_peer_id, strip_p2p(&mailbox_addr).0);
    swarm
        .behaviour_mut()
        .mailbox
        .send_request(&mailbox_peer_id, request);
    println!("Mailbox client PeerId: {local_peer_id}");

    let timeout = time::sleep(DISCOVERY_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => return Err("mailbox request timed out".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("Mailbox client listening on {}", address.with(Protocol::P2p(local_peer_id)));
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == mailbox_peer_id => {
                        println!("Mailbox client connected to mailbox {peer_id}");
                    }
                    SwarmEvent::Behaviour(MailboxBehaviourEvent::Mailbox(request_response::Event::Message {
                        message: request_response::Message::Response { response, .. },
                        ..
                    })) => return Ok(response),
                    SwarmEvent::Behaviour(MailboxBehaviourEvent::Mailbox(request_response::Event::OutboundFailure {
                        error,
                        ..
                    })) => return Err(format!("mailbox request failed: {error}").into()),
                    _ => {}
                }
            }
        }
    }
}

async fn next_relay_listen_addr(swarm: &mut Swarm<RelayServerBehaviour>) -> AppResult<Multiaddr> {
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return Ok(address);
        }
    }
}

async fn next_listen_addr(swarm: &mut Swarm<DiscoveryBehaviour>) -> AppResult<Multiaddr> {
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return Ok(address);
        }
    }
}

fn handle_demo_event(
    name: &str,
    swarm: &mut Swarm<DiscoveryBehaviour>,
    event: SwarmEvent<DiscoveryBehaviourEvent>,
) {
    match event {
        SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            for address in info.listen_addrs {
                swarm.behaviour_mut().kad.add_address(&peer_id, address);
            }
        }
        SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Kad(kad::Event::RoutingUpdated {
            peer,
            ..
        })) => {
            println!("{name} Kademlia learned peer {peer}");
        }
        SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Kad(
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetClosestPeers(result),
                ..
            },
        )) => {
            println!("{name} Kademlia closest-peer query: {result:?}");
        }
        _ => {}
    }
}

fn handle_bob_app_event(
    swarm: &mut Swarm<DiscoveryBehaviour>,
    bob: Arc<Mutex<Bob>>,
    event: request_response::Event<CipherMeshRequest, CipherMeshResponse>,
    final_ack_pending: &mut bool,
) -> AppResult<bool> {
    match event {
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        } => match request {
            CipherMeshRequest::PreKeyBundle => {
                let bundle = bob
                    .lock()
                    .map_err(|_| "Bob state lock poisoned")?
                    .prekey_bundle()?;
                let bundle_bytes = bincode::serialize(&bundle)?;
                log_boundary("Bob -> Alice PreKeyBundle over relay", &bundle_bytes);
                let _ = swarm
                    .behaviour_mut()
                    .app
                    .send_response(channel, CipherMeshResponse::PreKeyBundle(bundle_bytes));
                println!("Bob served prekey bundle over libp2p request-response to {peer}");
                Ok(false)
            }
            CipherMeshRequest::InitialMessage(encrypted_bytes) => {
                log_boundary("Alice -> Bob InitialMessage over relay", &encrypted_bytes);
                let result: AppResult<String> =
                    bincode::deserialize::<InitialMessage>(&encrypted_bytes)
                        .map_err(|error| error.into())
                        .and_then(|initial_message| {
                            bob.lock()
                                .map_err(|_| "Bob state lock poisoned".into())
                                .and_then(|mut bob| {
                                    bob.decrypt_initial_message(&initial_message)
                                        .map_err(|error| error.into())
                                })
                        });

                match result {
                    Ok(plaintext) => {
                        println!("Bob decrypted plaintext: {plaintext}");
                        let _ = swarm
                            .behaviour_mut()
                            .app
                            .send_response(channel, CipherMeshResponse::Ack(b"ok".to_vec()));
                        *final_ack_pending = true;
                    }
                    Err(error) => {
                        let _ = swarm
                            .behaviour_mut()
                            .app
                            .send_response(channel, CipherMeshResponse::Error(error.to_string()));
                    }
                }

                Ok(false)
            }
        },
        request_response::Event::InboundFailure { peer, error, .. } => {
            println!("Bob relay app inbound failure from {peer}: {error}");
            Ok(false)
        }
        request_response::Event::ResponseSent { peer, .. } => {
            println!("Bob relay app response sent to {peer}");
            if *final_ack_pending {
                *final_ack_pending = false;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        _ => Ok(false),
    }
}

fn log_relay_event(name: &str, event: relay::client::Event) {
    match event {
        relay::client::Event::ReservationReqAccepted { relay_peer_id, .. } => {
            println!("{name} relay reservation accepted by {relay_peer_id}");
        }
        relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
            println!("{name} connected through relay {relay_peer_id}");
        }
        relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
            println!("{name} accepted inbound relayed circuit from {src_peer_id}");
        }
    }
}

fn log_dcutr_event(name: &str, event: dcutr::Event) {
    match event.result {
        Ok(_) => println!(
            "hole punch succeeded: {name} upgraded relayed connection with {} to direct",
            event.remote_peer_id
        ),
        Err(error) => println!(
            "hole punch failed: {name} could not upgrade relayed connection with {}: {error}",
            event.remote_peer_id
        ),
    }
}

fn listen_and_bootstrap(
    swarm: &mut Swarm<DiscoveryBehaviour>,
    bootstrap_peers: Vec<Multiaddr>,
) -> AppResult<()> {
    swarm.listen_on(DISCOVERY_LISTEN_ADDR.parse()?)?;

    for bootstrap_peer in bootstrap_peers {
        let (address, peer_id) = strip_p2p(&bootstrap_peer);
        if let Some(peer_id) = peer_id {
            swarm.behaviour_mut().kad.add_address(&peer_id, address);
        }
        swarm.dial(bootstrap_peer)?;
    }

    if let Err(error) = swarm.behaviour_mut().kad.bootstrap() {
        println!("Kademlia bootstrap deferred until a peer is known: {error}");
    }

    Ok(())
}

fn reserve_on_relays(
    swarm: &mut Swarm<DiscoveryBehaviour>,
    relay_peers: &[Multiaddr],
) -> AppResult<()> {
    for relay_peer in relay_peers {
        if strip_p2p(relay_peer).1.is_some() {
            let relay_listener = relay_peer.clone().with(Protocol::P2pCircuit);
            println!("requesting relay reservation at {relay_listener}");
            swarm.listen_on(relay_listener)?;
        }
    }

    Ok(())
}

fn relay_dial_addresses(relay_peers: &[Multiaddr], target_peer_id: PeerId) -> Vec<Multiaddr> {
    relay_peers
        .iter()
        .filter(|addr| strip_p2p(addr).1.is_some())
        .map(|addr| {
            addr.clone()
                .with(Protocol::P2pCircuit)
                .with(Protocol::P2p(target_peer_id))
        })
        .collect()
}

fn parse_peer_id(value: Option<&String>) -> AppResult<PeerId> {
    value
        .ok_or("missing Bob PeerId")?
        .parse()
        .map_err(|error| format!("invalid Bob PeerId: {error}").into())
}

fn parse_bootstrap_peers(values: &[String]) -> AppResult<Vec<Multiaddr>> {
    values
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|error| format!("invalid bootstrap multiaddr {value}: {error}").into())
        })
        .collect()
}

fn peer_id_from_multiaddr(addr: &Multiaddr) -> AppResult<PeerId> {
    strip_p2p(addr)
        .1
        .ok_or_else(|| format!("mailbox multiaddr must include /p2p/<peer-id>: {addr}").into())
}

fn recipient_token_for_bundle(bundle: &PreKeyBundle) -> String {
    let digest = Sha256::digest(bundle.identity_public_key);
    hex_encode(&digest[..16])
}

fn message_id_for(encrypted_payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(current_unix_secs().to_be_bytes());
    hasher.update(encrypted_payload);
    hex_encode(&hasher.finalize()[..16])
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn record_key(peer_id: PeerId) -> kad::RecordKey {
    kad::RecordKey::new(&format!("/ciphermesh/quic/{peer_id}"))
}

fn socket_to_app_multiaddr(addr: SocketAddr) -> Multiaddr {
    let mut multiaddr = Multiaddr::empty();
    match addr.ip() {
        IpAddr::V4(ip) => multiaddr.push(Protocol::Ip4(ip)),
        IpAddr::V6(ip) => multiaddr.push(Protocol::Ip6(ip)),
    }
    multiaddr.push(Protocol::Udp(addr.port()));
    multiaddr
}

fn socket_from_app_multiaddr(
    addr: &Multiaddr,
    fallback_ip: Option<IpAddr>,
) -> AppResult<SocketAddr> {
    let mut ip = None;
    let mut port = None;

    for protocol in addr.iter() {
        match protocol {
            Protocol::Ip4(value) => ip = Some(IpAddr::V4(value)),
            Protocol::Ip6(value) => ip = Some(IpAddr::V6(value)),
            Protocol::Udp(value) => port = Some(value),
            _ => {}
        }
    }

    let mut ip = ip.ok_or("app multiaddr is missing an IP address")?;
    if ip.is_unspecified() {
        ip =
            fallback_ip.ok_or("discovered app address was unspecified and no peer IP was known")?;
    }

    Ok(SocketAddr::new(
        ip,
        port.ok_or("app multiaddr is missing a UDP port")?,
    ))
}

fn multiaddr_ip(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) if !ip.is_unspecified() => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) if !ip.is_unspecified() => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

fn strip_p2p(addr: &Multiaddr) -> (Multiaddr, Option<PeerId>) {
    let mut stripped = Multiaddr::empty();
    let mut peer_id = None;

    for protocol in addr.iter() {
        match protocol {
            Protocol::P2p(value) => peer_id = Some(value),
            other => stripped.push(other),
        }
    }

    (stripped, peer_id)
}

async fn send_bytes(send: &mut quinn::SendStream, bytes: &[u8]) -> AppResult<()> {
    send.write_all(bytes).await?;
    send.finish()?;
    Ok(())
}

async fn receive_bytes(recv: &mut quinn::RecvStream) -> AppResult<Vec<u8>> {
    Ok(recv.read_to_end(64 * 1024).await?)
}

fn server_config() -> AppResult<ServerConfig> {
    let cert = generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = quinn::rustls::pki_types::CertificateDer::from(cert.cert);
    let priv_key =
        quinn::rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    Ok(ServerConfig::with_single_cert(
        vec![cert_der],
        priv_key.into(),
    )?)
}

fn insecure_client_config() -> AppResult<ClientConfig> {
    let client_crypto = quinn::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    )))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<quinn::rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(
            quinn::rustls::crypto::ring::default_provider(),
        )))
    }
}

impl quinn::rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &quinn::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[quinn::rustls::pki_types::CertificateDer<'_>],
        _server_name: &quinn::rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: quinn::rustls::pki_types::UnixTime,
    ) -> Result<quinn::rustls::client::danger::ServerCertVerified, quinn::rustls::Error> {
        Ok(quinn::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<quinn::rustls::client::danger::HandshakeSignatureValid, quinn::rustls::Error> {
        quinn::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &quinn::rustls::pki_types::CertificateDer<'_>,
        dss: &quinn::rustls::DigitallySignedStruct,
    ) -> Result<quinn::rustls::client::danger::HandshakeSignatureValid, quinn::rustls::Error> {
        quinn::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<quinn::rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn log_boundary(label: &str, bytes: &[u8]) {
    println!("{label}: {} bytes", bytes.len());
    println!("{label} bytes: {}", hex_preview(bytes));
}

fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(96)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn unspecified_app_address_uses_discovered_peer_ip() {
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let app_multiaddr = socket_to_app_multiaddr("0.0.0.0:5000".parse().unwrap());

        let resolved = socket_from_app_multiaddr(&app_multiaddr, Some(peer_ip)).unwrap();

        assert_eq!(resolved, SocketAddr::new(peer_ip, 5000));
    }

    #[test]
    fn discovery_record_key_uses_libp2p_peer_id_not_ciphermesh_identity() {
        let alice = Alice::local();
        let ciphermesh_identity = alice.signed_key_exchange().identity_public_key;
        let libp2p_peer_id = PeerId::from(identity::Keypair::generate_ed25519().public());
        let key = record_key(libp2p_peer_id);
        let key_text = String::from_utf8_lossy(key.as_ref());

        assert!(key_text.contains(&libp2p_peer_id.to_string()));
        assert!(!key_text.contains(&format!("{ciphermesh_identity:?}")));
    }

    #[test]
    fn relay_dial_address_targets_peer_through_circuit() {
        let relay_peer_id = PeerId::from(identity::Keypair::generate_ed25519().public());
        let target_peer_id = PeerId::from(identity::Keypair::generate_ed25519().public());
        let relay_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{relay_peer_id}")
            .parse()
            .unwrap();

        let addresses = relay_dial_addresses(&[relay_addr], target_peer_id);
        assert_eq!(addresses.len(), 1);
        let address = &addresses[0];
        let rendered = address.to_string();

        assert!(rendered.contains("/p2p-circuit/"));
        assert!(rendered.ends_with(&format!("/p2p/{target_peer_id}")));
    }
}
