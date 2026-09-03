use ciphermesh::{
    active_device_certificates,
    crdt::{event_record, materialize_conversation, ConversationEvent},
    is_device_currently_authorized,
    mailbox_storage::{mailbox_now_unix_secs, MailboxEnvelopeRecord, MailboxStorage},
    storage::{
        now_unix_secs, ChatSummary, ContactRecord, EventRecord, InviteRecord, KnownPeerRecord,
        MessageDirection, MessageRecord, MessageStatus, OutboxItem, OutboxStatus,
        PendingPeerMessage, Storage, VersionVector,
    },
    verify_authorized_sibling_devices, verify_device_certificate, verify_device_revocation,
    AccountIdentity, Alice, AliceState, Bob, BobState, DeviceCertificate, DeviceDeliveryEnvelope,
    DeviceIdentity, DeviceRevocation, DeviceSession, InitialMessage, PreKeyBundle, RatchetMessage,
    SimulatedDirectory,
};
use futures::StreamExt;
use getrandom::fill as fill_random;
use libp2p::{
    autonat, dcutr, identify, identity, kad, mdns,
    multiaddr::Protocol,
    relay, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder,
};
use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig};
use rcgen::generate_simple_self_signed;
use rustyline::{error::ReadlineError, DefaultEditor, ExternalPrinter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{mpsc as std_mpsc, Arc, Mutex},
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
const MAILBOX_ENVELOPE_TTL_SECS: u64 = 5 * 60;
const MAILBOX_MAX_ENVELOPES: usize = 64;
const CHAT_PROMPT: &str = "> ";
const CHAT_INPUT_INSTRUCTION: &str = "Type a message, or /back to return to Chat History.";
const INVITE_CODE_LEN: usize = 6;
const INVITE_TTL_SECS: u64 = 5 * 60;
const INVITE_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const DEFAULT_INVITE_DB: &str = "target/ciphermesh-invites.sqlite";
const DEFAULT_INVITE_LISTEN_ADDR: &str = "127.0.0.1:5000";
const RECENT_CHAT_LIMIT: usize = 3;
const CHAT_HISTORY_PAGE_SIZE: usize = 6;
const PENDING_DELIVERY_ACK_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> AppResult<()> {
    let mut args = std::env::args().collect::<Vec<_>>();
    let verbose = take_verbose_flag(&mut args);

    match args.get(1).map(String::as_str) {
        Some("bob") => {
            let listen_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            let bootstrap_peers = parse_bootstrap_peers(tail_args(&args, 3))?;
            run_bob(listen_addr, bootstrap_peers, &default_chat_db("bob")).await
        }
        Some("alice") => {
            let bob_peer_id = parse_peer_id(args.get(2))?;
            let (message, bootstrap_args) =
                split_optional_message_and_bootstrap(tail_args(&args, 3));
            let bootstrap_peers = parse_bootstrap_peers(bootstrap_args)?;
            run_alice_discovered(
                bob_peer_id,
                message,
                bootstrap_peers,
                &default_chat_db("alice"),
            )
            .await
        }
        Some("alice-direct") => {
            let bob_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            let message = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("hello bob over quic");
            run_alice(bob_addr, message, &default_chat_db("alice")).await
        }
        Some("chat-bob") => {
            let listen_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            let db_path = args
                .get(3)
                .map(PathBuf::from)
                .unwrap_or_else(|| default_chat_db("bob"));
            run_chat_bob(listen_addr, &db_path).await
        }
        Some("chat-alice") => {
            let bob_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            let db_path = args
                .get(3)
                .map(PathBuf::from)
                .unwrap_or_else(|| default_chat_db("alice"));
            run_chat_alice(bob_addr, &db_path).await
        }
        Some("alice-relay") => {
            let bob_peer_id = parse_peer_id(args.get(2))?;
            let message = args.get(3).map(String::as_str).unwrap_or("hello via relay");
            let relay_peers = parse_bootstrap_peers(tail_args(&args, 4))?;
            run_alice_relayed(bob_peer_id, message, relay_peers).await
        }
        Some("kad-demo") => run_kademlia_demo().await,
        Some("relay") => {
            let listen_addr = parse_multiaddr(
                args.get(2),
                "/ip4/0.0.0.0/tcp/4001",
                "relay listen multiaddr",
            )?;
            run_relay_server(listen_addr).await
        }
        Some("relay-demo") => run_relay_demo().await,
        Some("mailbox") => {
            let listen_addr = parse_multiaddr(
                args.get(2),
                "/ip4/0.0.0.0/tcp/7000",
                "mailbox listen multiaddr",
            )?;
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
        Some("create-invite") => {
            let rendezvous_db = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/ciphermesh-invites.sqlite"));
            let listen_addr = parse_addr(args.get(3), "127.0.0.1:5000")?;
            let profile_db = args
                .get(4)
                .map(PathBuf::from)
                .unwrap_or_else(|| default_chat_db("invite-host"));
            run_create_invite(listen_addr, &rendezvous_db, &profile_db).await
        }
        Some("join-invite") => {
            let code = args.get(2).ok_or("missing invite code")?;
            let rendezvous_db = args
                .get(3)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/ciphermesh-invites.sqlite"));
            let profile_db = args
                .get(4)
                .map(PathBuf::from)
                .unwrap_or_else(|| default_chat_db("invite-joiner"));
            run_join_invite(code, &rendezvous_db, &profile_db).await
        }
        Some("invite-demo") => {
            let db_path = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("target/ciphermesh-invite-demo.sqlite"));
            run_invite_demo(&db_path)
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
        Some("device-demo") => run_device_identity_demo(),
        Some("fanout-demo") => run_device_fanout_demo(),
        Some("own-device-sync-demo") => run_own_device_sync_demo(),
        Some("revocation-demo") => run_device_revocation_demo(),
        Some("demo") => {
            run_local_demo(verbose)?;
            print_usage();
            Ok(())
        }
        Some("help") | Some("--help") | Some("-h") => {
            print_usage();
            Ok(())
        }
        None if verbose => {
            run_local_demo(true)?;
            print_usage();
            Ok(())
        }
        None => run_product_menu().await,
        Some(command) => {
            Err(format!("invalid command '{command}'; run without arguments to see usage").into())
        }
    }
}

fn take_verbose_flag(args: &mut Vec<String>) -> bool {
    let env_verbose = std::env::var("CIPHERMESH_VERBOSE")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    let mut cli_verbose = false;

    args.retain(|arg| {
        if arg == "--verbose" || arg == "-v" {
            cli_verbose = true;
            false
        } else {
            true
        }
    });

    env_verbose || cli_verbose
}

fn parse_addr(addr: Option<&String>, default: &str) -> AppResult<SocketAddr> {
    addr.map(String::as_str)
        .unwrap_or(default)
        .parse()
        .map_err(|error| format!("invalid socket address: {error}").into())
}

fn parse_required_multiaddr(addr: Option<&String>, label: &str) -> AppResult<Multiaddr> {
    addr.ok_or_else(|| format!("missing {label}"))?
        .parse()
        .map_err(|error| format!("invalid {label}: {error}").into())
}

fn parse_multiaddr(addr: Option<&String>, default: &str, label: &str) -> AppResult<Multiaddr> {
    addr.map(String::as_str)
        .unwrap_or(default)
        .parse()
        .map_err(|error| format!("invalid {label}: {error}").into())
}

fn tail_args(args: &[String], start: usize) -> &[String] {
    args.get(start..).unwrap_or(&[])
}

fn split_optional_message_and_bootstrap(values: &[String]) -> (Option<&str>, &[String]) {
    match values.split_first() {
        None => (None, values),
        Some((first, _)) if first.parse::<Multiaddr>().is_ok() => (None, values),
        Some((first, rest)) => (Some(first.as_str()), rest),
    }
}

fn short_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn print_usage() {
    println!();
    println!("Product menu:");
    println!("  cargo run");
    println!("  cargo run -- help");
    println!();
    println!("Phase 3B mDNS discovery test:");
    println!("  Terminal 1: cargo run -- bob 0.0.0.0:5000");
    println!("  Terminal 2: cargo run -- alice <bob-libp2p-peer-id>");
    println!("  One-shot send: cargo run -- alice <bob-libp2p-peer-id> \"hello from alice\"");
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
    println!("Short-lived invite-code pairing demo:");
    println!("  Terminal 1: cargo run -- create-invite [target/ciphermesh-invites.sqlite] [127.0.0.1:5000]");
    println!(
        "  Terminal 2: cargo run -- join-invite <6-char-code> [target/ciphermesh-invites.sqlite]"
    );
    println!("  cargo run -- invite-demo [target/ciphermesh-invite-demo.sqlite]");
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
    println!();
    println!("Phase 5A account/device identity demo:");
    println!("  cargo run -- device-demo");
    println!();
    println!("Phase 5B per-device fanout demo:");
    println!("  cargo run -- fanout-demo");
    println!();
    println!("Phase 5C own-device sync demo:");
    println!("  cargo run -- own-device-sync-demo");
    println!();
    println!("Phase 5D device revocation demo:");
    println!("  cargo run -- revocation-demo");
}

fn run_local_demo(verbose: bool) -> AppResult<()> {
    let mut alice = Alice::local();
    let mut bob = Bob::local();
    let message = "hello bob, this is alice";

    let alice_exchange = alice.signed_key_exchange();
    let bob_exchange = bob.signed_key_exchange();
    println!("Local E2EE smoke test");
    println!(
        "Alice identity: {}",
        short_hex(&alice_exchange.identity_public_key)
    );
    println!(
        "Bob identity: {}",
        short_hex(&bob_exchange.identity_public_key)
    );
    if verbose {
        println!(
            "Alice X25519 public key: {:?}",
            alice_exchange.x25519_public_key
        );
        println!("Alice signature: {:?}", alice_exchange.signature);
        println!(
            "Bob X25519 public key: {:?}",
            bob_exchange.x25519_public_key
        );
        println!("Bob signature: {:?}", bob_exchange.signature);
    }

    alice.derive_session_key(&bob_exchange)?;
    bob.derive_session_key(&alice_exchange)?;

    let ciphertext = alice.encrypt_for_bob(message)?;
    println!("Alice encrypted local demo message");
    println!(
        "Transport payload: encrypted message {} bytes",
        ciphertext.ciphertext.len()
    );
    if verbose {
        println!("Verbose transport payload: {ciphertext:?}");
    }

    let plaintext = bob.decrypt_from_alice(&ciphertext)?;
    println!("Bob decrypted: {plaintext}");

    let mut offline_bob = Bob::local();
    let mut directory = SimulatedDirectory::new();
    directory.publish_bob_bundle(&offline_bob)?;

    let mut alice = Alice::local();
    let bob_bundle = directory.take_bob_prekey_bundle()?;
    let initial_message = alice.encrypt_initial_message(&bob_bundle, "hello offline bob")?;
    println!(
        "Offline initial transport payload: encrypted message {} bytes",
        initial_message.message.ciphertext.len()
    );
    if verbose {
        println!(
            "Verbose offline initial transport payload: {:?}",
            initial_message.message
        );
    }

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
            "  id={} direction={:?} counter={:?} ciphertext_bytes={} local_plaintext_present={}",
            message.message_id,
            message.direction,
            message.protocol_counter,
            message.ciphertext.len(),
            message.plaintext.is_some()
        );
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
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
            "  id={} direction={:?} counter={:?} ciphertext_bytes={} local_plaintext_present={}",
            message.message_id,
            message.direction,
            message.protocol_counter,
            message.ciphertext.len(),
            message.plaintext.is_some()
        );
    }

    Ok(())
}

fn run_invite_demo(db_path: &Path) -> AppResult<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if db_path.exists() {
        std::fs::remove_file(db_path)?;
    }

    let storage = Storage::open(db_path)?;
    let code = generate_invite_code()?;
    let code_hash = invite_code_hash(&code);
    let now = now_unix_secs();
    let mut alice = Alice::local();
    let mut bob = Bob::local();
    let alice_exchange = alice.signed_key_exchange();
    let bob_exchange = bob.signed_key_exchange();
    let rendezvous_payload = bincode::serialize(&bob_exchange)?;

    storage.save_invite_record(&InviteRecord {
        code_hash: code_hash.clone(),
        rendezvous_payload: hex_encode(&rendezvous_payload),
        expires_at_unix_secs: now + INVITE_TTL_SECS,
        consumed_at_unix_secs: None,
        created_at_unix_secs: now,
    })?;

    println!("Create invite");
    println!("Invite: {code}");
    println!("Invite expires in 5 minutes");
    println!("Waiting for peer");

    let entered_code = normalize_invite_code(&code)?;
    let invite = storage
        .consume_invite_record(&invite_code_hash(&entered_code), now + 1)?
        .ok_or("invalid invite")?;
    let resolved_bob_exchange = bob_exchange_from_payload(&invite.rendezvous_payload)?;

    println!("Join with invite code");
    println!("Pairing...");
    alice.derive_session_key(&resolved_bob_exchange)?;
    bob.derive_session_key(&alice_exchange)?;

    let safety_number = safety_number(
        &alice_exchange.identity_public_key,
        &resolved_bob_exchange.identity_public_key,
    );
    let conversation_id = format!("invite-{}", invite_code_hash(&entered_code));
    storage.save_local_identity(
        "alice-invite-demo",
        "alice",
        &bincode::serialize(&alice.export_state())?,
    )?;
    storage.save_local_identity(
        "bob-invite-demo",
        "bob",
        &bincode::serialize(&bob.export_state())?,
    )?;
    storage.save_session(
        &conversation_id,
        "bob-contact",
        "alice",
        &bincode::serialize(
            &alice
                .session_state()
                .ok_or("Alice session missing after invite pairing")?,
        )?,
    )?;
    storage.save_contact(&ContactRecord {
        contact_id: "bob-contact".to_string(),
        display_name: "Bob".to_string(),
        identity_public_key: resolved_bob_exchange.identity_public_key.to_vec(),
        discovery_hint: "resolved through short-lived invite rendezvous".to_string(),
        saved_at_unix_secs: now + 1,
    })?;

    println!("Identity established");
    println!("Contact saved");
    println!("Connected securely to Bob");
    println!("Safety number: {safety_number}");

    if storage
        .consume_invite_record(&code_hash, now + 2)?
        .is_none()
    {
        println!("Invite already used");
    }

    Ok(())
}

enum ScreenAction {
    Stay,
    Back,
    Quit,
}

async fn run_product_menu() -> AppResult<()> {
    loop {
        match run_main_menu_screen().await? {
            ScreenAction::Stay | ScreenAction::Back => {}
            ScreenAction::Quit => return Ok(()),
        }
    }
}

async fn run_main_menu_screen() -> AppResult<ScreenAction> {
    println!("CipherMesh");
    println!();
    println!("[1] Create invite");
    println!("[2] Join invite");
    println!("[3] Chat History");
    println!("[Q] Quit");
    println!();

    match prompt_line("Select: ")?.trim() {
        "1" => {
            run_create_invite_menu().await?;
            Ok(ScreenAction::Stay)
        }
        "2" => {
            run_join_invite_menu().await?;
            Ok(ScreenAction::Stay)
        }
        "3" => {
            run_chat_history_menu().await?;
            Ok(ScreenAction::Stay)
        }
        selection if is_quit_selection(selection) => Ok(ScreenAction::Quit),
        selection if is_back_selection(selection) => Ok(ScreenAction::Back),
        _ => {
            println!("Invalid selection");
            println!();
            Ok(ScreenAction::Stay)
        }
    }
}

async fn run_create_invite_menu() -> AppResult<()> {
    loop {
        println!();
        println!("Create Invite");
        println!();
        println!("[1] Create invite");
        println!("[B] Back");
        println!();

        match prompt_line("Select: ")?.trim() {
            "1" => {
                let rendezvous_db = PathBuf::from(DEFAULT_INVITE_DB);
                let listen_addr = DEFAULT_INVITE_LISTEN_ADDR.parse()?;
                run_create_invite(listen_addr, &rendezvous_db, &default_chat_db("invite-host"))
                    .await?;
                return Ok(());
            }
            selection if is_back_selection(selection) => return Ok(()),
            _ => {
                println!("Invalid selection");
                println!();
            }
        }
    }
}

async fn run_join_invite_menu() -> AppResult<()> {
    loop {
        println!();
        println!("Join Invite");
        println!();
        println!("[1] Enter invite code");
        println!("[B] Back");
        println!();

        match prompt_line("Select: ")?.trim() {
            "1" => {
                let code = prompt_line("Invite code: ")?;
                if is_back_selection(&code) {
                    return Ok(());
                }
                let rendezvous_db = PathBuf::from(DEFAULT_INVITE_DB);
                run_join_invite(
                    code.trim(),
                    &rendezvous_db,
                    &default_chat_db("invite-joiner"),
                )
                .await?;
                return Ok(());
            }
            selection if is_back_selection(selection) => return Ok(()),
            _ => {
                println!("Invalid selection");
                println!();
            }
        }
    }
}

async fn run_chat_history_menu() -> AppResult<()> {
    loop {
        let profile_db = default_chat_db("invite-joiner");
        let storage = Storage::open(&profile_db)?;
        let chats = storage.recent_chat_summaries(RECENT_CHAT_LIMIT)?;

        println!();
        println!("Chat History");
        println!();

        if chats.is_empty() {
            println!("No saved chats yet.");
            println!();
            println!("[B] Back");
            println!();

            let selection = prompt_line("Select: ")?;
            if is_back_selection(&selection) {
                return Ok(());
            }
            println!("Invalid selection");
            println!();
            continue;
        }

        let recent_count = chats.len().min(RECENT_CHAT_LIMIT);
        for (index, summary) in chats.iter().take(recent_count).enumerate() {
            print_recent_chat_summary(index + 1, summary);
        }
        println!("[A] View All Chats");
        println!("[B] Back");
        println!();

        let selection = prompt_line("Select: ")?;
        if is_back_selection(&selection) {
            return Ok(());
        }
        if selection.eq_ignore_ascii_case("a") {
            run_all_chat_history_menu(&profile_db)?;
            continue;
        }

        match selection
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|index| (1..=recent_count).contains(index))
            .and_then(|index| chats.get(index.saturating_sub(1)))
        {
            Some(selected) => open_saved_conversation(
                &profile_db,
                &selected.contact.contact_id,
                &selected.contact.display_name,
            )?,
            None => {
                println!("Invalid selection");
                println!();
            }
        }
    }
}

fn run_all_chat_history_menu(profile_db: &Path) -> AppResult<()> {
    let mut page = 0usize;

    loop {
        let storage = Storage::open(profile_db)?;
        let chat_count = storage.chat_summary_count()?;
        let total_pages = chat_count.div_ceil(CHAT_HISTORY_PAGE_SIZE).max(1);
        page = page.min(total_pages - 1);
        let page_start = page * CHAT_HISTORY_PAGE_SIZE;
        let page_chats = storage.chat_summaries_page(CHAT_HISTORY_PAGE_SIZE, page_start)?;

        println!();
        println!("Chat History (Page {} of {})", page + 1, total_pages);
        println!();

        if page_chats.is_empty() {
            println!("No saved chats yet.");
            println!();
        } else {
            for (index, summary) in page_chats.iter().enumerate() {
                print_all_chat_summary(index + 1, summary);
            }
        }

        if page > 0 {
            println!("[P] Previous Page");
        }
        if page + 1 < total_pages {
            println!("[N] Next Page");
        }
        println!("[B] Back");
        println!();

        let selection = prompt_line("Select: ")?;
        if is_back_selection(&selection) {
            return Ok(());
        }
        if selection.eq_ignore_ascii_case("p") {
            if page > 0 {
                page -= 1;
            } else {
                println!("Already on first page");
                println!();
            }
            continue;
        }
        if selection.eq_ignore_ascii_case("n") {
            if page + 1 < total_pages {
                page += 1;
            } else {
                println!("Already on last page");
                println!();
            }
            continue;
        }

        match selection
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|index| (1..=page_chats.len()).contains(index))
            .and_then(|index| page_chats.get(index.saturating_sub(1)))
        {
            Some(selected) => open_saved_conversation(
                profile_db,
                &selected.contact.contact_id,
                &selected.contact.display_name,
            )?,
            None => {
                println!("Invalid selection");
                println!();
            }
        }
    }
}

fn print_recent_chat_summary(index: usize, summary: &ChatSummary) {
    println!("[{}] {}", index, summary.contact.display_name);
    println!("    {}", chat_preview_line(summary));
    println!();
}

fn print_all_chat_summary(index: usize, summary: &ChatSummary) {
    println!("[{}] {}", index, summary.contact.display_name);
    println!("    {}", chat_preview_line(summary));
    println!();
}

fn chat_preview_line(summary: &ChatSummary) -> String {
    if summary.pending_count > 0 {
        let label = if summary.pending_count == 1 {
            "1 pending message".to_string()
        } else {
            format!("{} pending messages", summary.pending_count)
        };
        return format!("Offline · {label}");
    }

    match &summary.last_message {
        Some(message) => {
            let mut plaintext = message
                .plaintext
                .as_deref()
                .unwrap_or("[encrypted]")
                .trim()
                .to_string();
            if plaintext.is_empty() {
                plaintext = "[empty message]".to_string();
            }
            if matches!(message.direction, MessageDirection::Sent) {
                plaintext = format!("you: {plaintext}");
            }
            format!(
                "Offline · last message: {} · {}",
                truncate_preview(&plaintext, 48),
                relative_time(message.created_at_unix_secs)
            )
        }
        None => "Offline · No messages".to_string(),
    }
}

fn truncate_preview(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

fn open_saved_conversation(
    profile_db: &Path,
    conversation_id: &str,
    display_name: &str,
) -> AppResult<()> {
    let peer = load_known_peer_for_conversation(profile_db, conversation_id)?;

    loop {
        print_offline_conversation(profile_db, conversation_id, display_name)?;
        println!("{CHAT_INPUT_INSTRUCTION}");
        println!("Use /clear to clear local history.");
        println!();

        let line = prompt_line(CHAT_PROMPT)?;
        if is_chat_back_command(&line) {
            return Ok(());
        }
        if line.trim().eq_ignore_ascii_case("/clear") {
            let storage = Storage::open(profile_db)?;
            let removed = storage.clear_conversation_history(conversation_id)?;
            println!(
                "Cleared {removed} local message(s). This does not delete copies on other devices."
            );
            println!();
            continue;
        }
        if line.is_empty() {
            continue;
        }

        match &peer {
            Some(peer) => {
                queue_offline_peer_message(profile_db, peer, &line)?;
                println!("✓ Queued for delivery");
            }
            None => {
                println!("This legacy conversation is missing a cryptographic peer profile.");
                println!("Reconnect with this peer once before queueing offline messages.");
            }
        }
        println!();
    }
}

fn load_known_peer_for_conversation(
    profile_db: &Path,
    conversation_id: &str,
) -> AppResult<Option<KnownPeerRecord>> {
    let storage = Storage::open(profile_db)?;
    if let Some(peer) = storage.known_peer_for_conversation(conversation_id)? {
        return Ok(Some(peer));
    }

    let Some(contact) = storage.load_contact(conversation_id)? else {
        return Ok(None);
    };
    let Ok(identity) = <&[u8; 32]>::try_from(contact.identity_public_key.as_slice()) else {
        return Ok(None);
    };

    Ok(Some(KnownPeerRecord {
        peer_id: contact_id_for_identity(identity),
        identity_public_key: contact.identity_public_key,
        display_name: contact.display_name,
        conversation_id: contact.contact_id,
        last_seen_at_unix_secs: contact.saved_at_unix_secs,
    }))
}

fn queue_offline_peer_message(
    profile_db: &Path,
    peer: &KnownPeerRecord,
    plaintext: &str,
) -> AppResult<()> {
    let message_id = pending_peer_message_id(&peer.peer_id, plaintext)?;
    let created_at = now_unix_secs();
    let storage = Storage::open(profile_db)?;
    storage.queue_pending_peer_message(&PendingPeerMessage {
        message_id: message_id.clone(),
        peer_id: peer.peer_id.clone(),
        conversation_id: peer.conversation_id.clone(),
        plaintext: plaintext.to_string(),
        created_at_unix_secs: created_at,
        retry_count: 0,
        last_attempt_unix_secs: None,
    })?;
    storage.insert_message(&MessageRecord {
        message_id,
        conversation_id: peer.conversation_id.clone(),
        sender_id: "you".to_string(),
        recipient_id: peer.display_name.clone(),
        direction: MessageDirection::Sent,
        status: MessageStatus::Stored,
        protocol_counter: None,
        ciphertext: plaintext.as_bytes().to_vec(),
        plaintext: Some(plaintext.to_string()),
        created_at_unix_secs: created_at,
    })?;
    Ok(())
}

async fn run_create_invite(
    listen_addr: SocketAddr,
    rendezvous_db: &Path,
    profile_db: &Path,
) -> AppResult<()> {
    if let Some(parent) = rendezvous_db.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let code = generate_invite_code()?;
    let now = now_unix_secs();
    {
        let storage = Storage::open(rendezvous_db)?;
        storage.save_invite_record(&InviteRecord {
            code_hash: invite_code_hash(&code),
            rendezvous_payload: listen_addr.to_string(),
            expires_at_unix_secs: now + INVITE_TTL_SECS,
            consumed_at_unix_secs: None,
            created_at_unix_secs: now,
        })?;
    }

    println!("Invite created");
    println!("Invite: {code}");
    println!("Invite expires in 5 minutes");
    println!("Waiting for peer");
    run_chat_bob(listen_addr, profile_db).await
}

async fn run_join_invite(code: &str, rendezvous_db: &Path, profile_db: &Path) -> AppResult<()> {
    let normalized_code = normalize_invite_code(code)?;
    let invite = {
        let storage = Storage::open(rendezvous_db)?;
        storage
            .consume_invite_record(&invite_code_hash(&normalized_code), now_unix_secs())?
            .ok_or("invalid invite")?
    };
    let peer_addr: SocketAddr = invite
        .rendezvous_payload
        .parse()
        .map_err(|error| format!("invite resolved to invalid peer address: {error}"))?;

    println!("Pairing...");
    println!("Identity established");
    run_chat_alice(peer_addr, profile_db).await
}

fn prompt_line(prompt: &str) -> AppResult<String> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end().to_string())
}

fn is_back_selection(selection: &str) -> bool {
    let selection = selection.trim();
    selection.eq_ignore_ascii_case("b") || selection.eq_ignore_ascii_case("back")
}

fn is_quit_selection(selection: &str) -> bool {
    let selection = selection.trim();
    selection.eq_ignore_ascii_case("q") || selection.eq_ignore_ascii_case("quit")
}

fn is_chat_back_command(line: &str) -> bool {
    let line = line.trim();
    line.eq_ignore_ascii_case("/back") || line.eq_ignore_ascii_case("/exit")
}

fn generate_invite_code() -> AppResult<String> {
    let mut random = [0u8; INVITE_CODE_LEN];
    fill_random(&mut random)?;
    Ok(random
        .iter()
        .map(|byte| {
            let index = (*byte as usize) % INVITE_CODE_ALPHABET.len();
            INVITE_CODE_ALPHABET[index] as char
        })
        .collect())
}

fn normalize_invite_code(code: &str) -> AppResult<String> {
    let normalized = code
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .map(|ch| ch.to_ascii_uppercase())
        .collect::<String>();

    if normalized.len() != INVITE_CODE_LEN {
        return Err(format!("invite code must be {INVITE_CODE_LEN} characters").into());
    }
    if !normalized
        .bytes()
        .all(|byte| INVITE_CODE_ALPHABET.contains(&byte))
    {
        return Err("invite code contains unsupported characters".into());
    }

    Ok(normalized)
}

fn invite_code_hash(code: &str) -> String {
    let normalized = code.to_ascii_uppercase();
    let mut hasher = Sha256::new();
    hasher.update(b"ciphermesh.invite-code.v1");
    hasher.update(normalized.as_bytes());
    hex_encode(&hasher.finalize()[..16])
}

fn bob_exchange_from_payload(payload_hex: &str) -> AppResult<ciphermesh::SignedKeyExchange> {
    let payload = hex_decode(payload_hex)?;
    Ok(bincode::deserialize(&payload)?)
}

fn safety_number(first_identity: &[u8; 32], second_identity: &[u8; 32]) -> String {
    let (low, high) = if first_identity <= second_identity {
        (first_identity, second_identity)
    } else {
        (second_identity, first_identity)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"ciphermesh.safety-number.v1");
    hasher.update(low);
    hasher.update(high);
    hex_encode(&hasher.finalize()[..20])
}

fn hex_decode(value: &str) -> AppResult<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex value has odd length".into());
    }

    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            let text = std::str::from_utf8(chunk)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect::<AppResult<Vec<_>>>()
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

fn run_device_identity_demo() -> AppResult<()> {
    let storage = Storage::open_in_memory()?;
    let account = AccountIdentity::generate();
    let laptop = DeviceIdentity::generate(account.account_id());
    let phone = DeviceIdentity::generate(account.account_id());
    let laptop_certificate = account.authorize_device(&laptop);
    let phone_certificate = account.authorize_device(&phone);

    verify_device_certificate(account.public_key(), &laptop_certificate)?;
    verify_device_certificate(account.public_key(), &phone_certificate)?;
    persist_phase_5a_identity(&storage, &account, &laptop, &laptop_certificate)?;
    persist_phase_5a_identity(&storage, &account, &phone, &phone_certificate)?;

    let known_certs = storage.device_certificates_for_account(account.account_id())?;

    println!("Alice AccountId: {}", account.account_id());
    println!("Alice Laptop DeviceId: {}", laptop.device_id());
    println!("Alice Phone DeviceId: {}", phone.device_id());
    println!(
        "Both devices belong to same account: {}",
        laptop.account_id() == account.account_id() && phone.account_id() == account.account_id()
    );
    println!(
        "Laptop and Phone have different Ed25519 keys: {}",
        laptop.ed25519_public_key() != phone.ed25519_public_key()
    );
    println!(
        "Laptop and Phone have different X25519 keys: {}",
        laptop.x25519_public_key() != phone.x25519_public_key()
    );
    println!(
        "Stored {} authorized device certificate(s) in SQLite",
        known_certs.len()
    );
    println!("libp2p PeerId remains separate from AccountId and DeviceId");

    Ok(())
}

fn run_device_fanout_demo() -> AppResult<()> {
    let mut storage = Storage::open_in_memory()?;
    let alice_account = AccountIdentity::generate();
    let alice_laptop = DeviceIdentity::generate(alice_account.account_id());
    let alice_phone = DeviceIdentity::generate(alice_account.account_id());
    let bob_device = DeviceIdentity::generate("bob-account");
    let laptop_certificate = alice_account.authorize_device(&alice_laptop);
    let phone_certificate = alice_account.authorize_device(&alice_phone);

    persist_phase_5a_identity(&storage, &alice_account, &alice_laptop, &laptop_certificate)?;
    persist_phase_5a_identity(&storage, &alice_account, &alice_phone, &phone_certificate)?;

    let authorized_devices = storage
        .device_certificates_for_account(alice_account.account_id())?
        .into_iter()
        .map(|blob| bincode::deserialize::<DeviceCertificate>(&blob))
        .collect::<Result<Vec<_>, _>>()?;
    let mut bob_sessions = BTreeMap::new();
    for certificate in &authorized_devices {
        let session =
            bob_device.create_outbound_session(alice_account.public_key(), certificate)?;
        bob_sessions.insert(certificate.device_id.clone(), session);
    }
    let mut laptop_session = alice_laptop.create_inbound_session(
        bob_device.device_id().to_string(),
        bob_device.x25519_public_key(),
    )?;
    let mut phone_session = alice_phone.create_inbound_session(
        bob_device.device_id().to_string(),
        bob_device.x25519_public_key(),
    )?;

    println!("Alice AccountId: {}", alice_account.account_id());
    println!(
        "Authorized Alice devices found: {}",
        authorized_devices.len()
    );
    println!("Laptop DeviceId: {}", alice_laptop.device_id());
    println!("Phone DeviceId: {}", alice_phone.device_id());

    let laptop_first = encrypt_and_queue_device_delivery(
        &mut storage,
        bob_sessions
            .get_mut(alice_laptop.device_id())
            .ok_or("missing laptop session")?,
        "logical-1",
        "hello alice",
    )?;
    let phone_first = encrypt_and_queue_device_delivery(
        &mut storage,
        bob_sessions
            .get_mut(alice_phone.device_id())
            .ok_or("missing phone session")?,
        "logical-1",
        "hello alice",
    )?;

    println!(
        "Logical message ID shared by both deliveries: {}",
        laptop_first.logical_message_id == phone_first.logical_message_id
    );
    println!(
        "Ciphertexts differ across devices: {}",
        laptop_first.message.ciphertext != phone_first.message.ciphertext
    );

    let laptop_plaintext = laptop_session.decrypt(&laptop_first)?;
    let phone_plaintext = phone_session.decrypt(&phone_first)?;
    storage.mark_outbox_delivered(&delivery_outbox_id(&laptop_first))?;
    storage.mark_outbox_delivered(&delivery_outbox_id(&phone_first))?;
    println!("Laptop decrypted: {laptop_plaintext}");
    println!("Phone decrypted: {phone_plaintext}");

    let laptop_second = encrypt_and_queue_device_delivery(
        &mut storage,
        bob_sessions
            .get_mut(alice_laptop.device_id())
            .ok_or("missing laptop session")?,
        "logical-2",
        "second message",
    )?;
    let phone_second = encrypt_and_queue_device_delivery(
        &mut storage,
        bob_sessions
            .get_mut(alice_phone.device_id())
            .ok_or("missing phone session")?,
        "logical-2",
        "second message",
    )?;

    let laptop_second_plaintext = laptop_session.decrypt(&laptop_second)?;
    storage.mark_outbox_delivered(&delivery_outbox_id(&laptop_second))?;
    println!("Laptop received while Phone is offline: {laptop_second_plaintext}");
    println!(
        "Pending outbox deliveries while Phone is offline: {}",
        storage.pending_outbox_items()?.len()
    );

    let pending_phone_delivery = storage
        .pending_outbox_items()?
        .into_iter()
        .find(|item| item.recipient_id == alice_phone.device_id())
        .ok_or("phone delivery did not remain pending")?;
    let restored_phone_envelope: DeviceDeliveryEnvelope =
        bincode::deserialize(&pending_phone_delivery.payload)?;
    assert_eq!(restored_phone_envelope, phone_second);
    let phone_second_plaintext = phone_session.decrypt(&restored_phone_envelope)?;
    storage.mark_outbox_delivered(&pending_phone_delivery.message_id)?;
    println!("Phone later reconnected and decrypted: {phone_second_plaintext}");
    println!(
        "Pending outbox deliveries after Phone ACK: {}",
        storage.pending_outbox_items()?.len()
    );

    Ok(())
}

fn run_own_device_sync_demo() -> AppResult<()> {
    let laptop = Storage::open_in_memory()?;
    let phone = Storage::open_in_memory()?;
    let conversation_id = "alice-own-device-sync";
    let account = AccountIdentity::generate();
    let laptop_device = DeviceIdentity::generate(account.account_id());
    let phone_device = DeviceIdentity::generate(account.account_id());
    let laptop_certificate = account.authorize_device(&laptop_device);
    let phone_certificate = account.authorize_device(&phone_device);

    verify_authorized_sibling_devices(
        account.public_key(),
        &laptop_certificate,
        &phone_certificate,
    )?;

    for counter in 1..=3 {
        let event = crdt_demo_event(
            conversation_id,
            laptop_device.device_id(),
            counter,
            ConversationEvent::MessageCreated {
                message_id: format!("laptop-message-{counter}"),
                author_id: account.account_id().to_string(),
                payload: format!("laptop event {counter}").into_bytes(),
            },
        )?;
        laptop.append_event(&event)?;
        if counter == 1 {
            phone.append_event(&event)?;
        }
    }

    let phone_reply = crdt_demo_event(
        conversation_id,
        phone_device.device_id(),
        1,
        ConversationEvent::MessageCreated {
            message_id: "phone-message-1".to_string(),
            author_id: account.account_id().to_string(),
            payload: b"phone event 1".to_vec(),
        },
    )?;
    phone.append_event(&phone_reply)?;

    println!("Alice AccountId: {}", account.account_id());
    println!("Laptop DeviceId: {}", laptop_device.device_id());
    println!("Phone DeviceId: {}", phone_device.device_id());
    println!(
        "Sibling certificates verify: {}",
        verify_authorized_sibling_devices(
            account.public_key(),
            &laptop_certificate,
            &phone_certificate,
        )
        .is_ok()
    );
    println!(
        "Laptop vector before sync: {:?}",
        laptop.version_vector(conversation_id)?
    );
    println!(
        "Phone vector before sync: {:?}",
        phone.version_vector(conversation_id)?
    );

    let SyncRoundTrip {
        left_to_right,
        right_to_left,
    } = sync_authorized_sibling_devices(
        account.public_key(),
        &laptop_certificate,
        &phone_certificate,
        &[],
        &laptop,
        &phone,
        conversation_id,
    )?;

    let duplicate_inserted = phone.append_events(&left_to_right)?;
    let laptop_state = materialize_conversation(&all_sync_events(&laptop, conversation_id)?);
    let phone_state = materialize_conversation(&all_sync_events(&phone, conversation_id)?);

    println!(
        "Laptop sent Phone missing events: {:?}",
        event_positions(&left_to_right)
    );
    println!(
        "Phone sent Laptop missing events: {:?}",
        event_positions(&right_to_left)
    );
    println!("Duplicate sync insert count: {duplicate_inserted}");
    println!(
        "Laptop vector after sync: {:?}",
        laptop.version_vector(conversation_id)?
    );
    println!(
        "Phone vector after sync: {:?}",
        phone.version_vector(conversation_id)?
    );
    println!(
        "CRDT materialized states match: {}",
        laptop_state == phone_state
    );

    Ok(())
}

fn run_device_revocation_demo() -> AppResult<()> {
    let storage = Storage::open_in_memory()?;
    let alice_account = AccountIdentity::generate();
    let alice_laptop = DeviceIdentity::generate(alice_account.account_id());
    let alice_phone = DeviceIdentity::generate(alice_account.account_id());
    let bob_device = DeviceIdentity::generate("bob-account");
    let laptop_certificate = alice_account.authorize_device(&alice_laptop);
    let phone_certificate = alice_account.authorize_device(&alice_phone);

    persist_phase_5a_identity(&storage, &alice_account, &alice_laptop, &laptop_certificate)?;
    persist_phase_5a_identity(&storage, &alice_account, &alice_phone, &phone_certificate)?;

    let phone_history = crdt_demo_event(
        "revocation-demo-conversation",
        alice_phone.device_id(),
        1,
        ConversationEvent::MessageCreated {
            message_id: "old-phone-message".to_string(),
            author_id: alice_account.account_id().to_string(),
            payload: b"old phone history remains".to_vec(),
        },
    )?;
    storage.append_event(&phone_history)?;

    let certificates_before = load_device_certificates(&storage, alice_account.account_id())?;
    let active_before =
        active_device_certificates(alice_account.public_key(), &certificates_before, &[])?;

    let revocation = alice_account.revoke_device(alice_phone.device_id().to_string(), 1);
    verify_device_revocation(alice_account.public_key(), &revocation)?;
    storage.save_device_revocation(
        alice_account.account_id(),
        alice_phone.device_id(),
        revocation.revocation_counter,
        &bincode::serialize(&revocation)?,
    )?;
    storage.save_device_revocation(
        alice_account.account_id(),
        alice_phone.device_id(),
        revocation.revocation_counter,
        &bincode::serialize(&revocation)?,
    )?;

    let certificates_after = load_device_certificates(&storage, alice_account.account_id())?;
    let revocations_after = load_device_revocations(&storage, alice_account.account_id())?;
    let active_after = active_device_certificates(
        alice_account.public_key(),
        &certificates_after,
        &revocations_after,
    )?;
    let mut bob_sessions = BTreeMap::new();
    let mut new_envelopes = Vec::new();
    for certificate in &active_after {
        let mut session =
            bob_device.create_outbound_session(alice_account.public_key(), certificate)?;
        let envelope = session.encrypt("post-revocation-logical-1", "future laptop only")?;
        bob_sessions.insert(certificate.device_id.clone(), session);
        new_envelopes.push(envelope);
    }

    let laptop_envelope = new_envelopes
        .iter()
        .find(|envelope| envelope.recipient_device_id == alice_laptop.device_id())
        .ok_or("laptop did not receive post-revocation envelope")?;
    let phone_envelope_exists = new_envelopes
        .iter()
        .any(|envelope| envelope.recipient_device_id == alice_phone.device_id());
    let mut laptop_session = alice_laptop.create_inbound_session(
        bob_device.device_id().to_string(),
        bob_device.x25519_public_key(),
    )?;
    let laptop_plaintext = laptop_session.decrypt(laptop_envelope)?;

    let sync_to_phone_allowed = sync_authorized_sibling_devices(
        alice_account.public_key(),
        &laptop_certificate,
        &phone_certificate,
        &revocations_after,
        &storage,
        &storage,
        "revocation-demo-conversation",
    )
    .is_ok();

    println!("Alice AccountId: {}", alice_account.account_id());
    println!("Laptop DeviceId: {}", alice_laptop.device_id());
    println!("Phone DeviceId: {}", alice_phone.device_id());
    println!("Active devices before revocation: {}", active_before.len());
    println!("Revoked DeviceId: {}", revocation.device_id);
    println!("Stored revocation records: {}", revocations_after.len());
    println!("Active devices after revocation: {}", active_after.len());
    println!(
        "Bob created post-revocation envelopes: {}",
        new_envelopes.len()
    );
    println!("Laptop decrypted future message: {laptop_plaintext}");
    println!("Phone received new envelope: {phone_envelope_exists}");
    println!("Own-device sync to revoked Phone allowed: {sync_to_phone_allowed}");
    println!(
        "Old historical events still stored: {}",
        all_sync_events(&storage, "revocation-demo-conversation")?.len()
    );
    println!(
        "Bob kept sessions only for active devices: {}",
        bob_sessions.contains_key(alice_laptop.device_id())
            && !bob_sessions.contains_key(alice_phone.device_id())
    );

    Ok(())
}

fn persist_phase_5a_identity(
    storage: &Storage,
    account: &AccountIdentity,
    device: &DeviceIdentity,
    certificate: &ciphermesh::DeviceCertificate,
) -> AppResult<()> {
    let account_state = account.export_state();
    let device_state = device.export_state();

    storage.save_account_identity(
        account.account_id(),
        &account.public_key(),
        Some(&account_state.account_secret_key),
    )?;
    storage.save_device_identity(
        device.device_id(),
        device.account_id(),
        &device.ed25519_public_key(),
        &device_state.device_secret_key,
        &device.x25519_public_key(),
        &device_state.device_x25519_private_key,
    )?;
    storage.save_device_certificate(
        account.account_id(),
        device.device_id(),
        &bincode::serialize(certificate)?,
    )?;

    Ok(())
}

fn load_device_certificates(
    storage: &Storage,
    account_id: &str,
) -> AppResult<Vec<DeviceCertificate>> {
    storage
        .device_certificates_for_account(account_id)?
        .into_iter()
        .map(|blob| bincode::deserialize::<DeviceCertificate>(&blob).map_err(Into::into))
        .collect()
}

fn load_device_revocations(
    storage: &Storage,
    account_id: &str,
) -> AppResult<Vec<DeviceRevocation>> {
    storage
        .device_revocations_for_account(account_id)?
        .into_iter()
        .map(|blob| bincode::deserialize::<DeviceRevocation>(&blob).map_err(Into::into))
        .collect()
}

fn encrypt_and_queue_device_delivery(
    storage: &mut Storage,
    session: &mut DeviceSession,
    logical_message_id: &str,
    plaintext: &str,
) -> AppResult<DeviceDeliveryEnvelope> {
    let envelope = session.encrypt(logical_message_id, plaintext)?;
    let outbox_item = OutboxItem {
        message_id: delivery_outbox_id(&envelope),
        recipient_id: envelope.recipient_device_id.clone(),
        payload: bincode::serialize(&envelope)?,
        status: OutboxStatus::Pending,
        retry_count: 0,
        created_at_unix_secs: now_unix_secs(),
        last_attempt_unix_secs: None,
    };
    let session_state = bincode::serialize(&session.export_state())?;

    storage.save_device_pair_session_and_outbox(
        session.local_device_id(),
        session.remote_device_id(),
        &session_state,
        &outbox_item,
    )?;

    Ok(envelope)
}

struct SyncRoundTrip {
    left_to_right: Vec<EventRecord>,
    right_to_left: Vec<EventRecord>,
}

fn sync_authorized_sibling_devices(
    account_public_key: ciphermesh::IdentityPublicKeyBytes,
    left_certificate: &DeviceCertificate,
    right_certificate: &DeviceCertificate,
    revocations: &[DeviceRevocation],
    left: &Storage,
    right: &Storage,
    conversation_id: &str,
) -> AppResult<SyncRoundTrip> {
    verify_authorized_sibling_devices(account_public_key, left_certificate, right_certificate)?;
    if !is_device_currently_authorized(account_public_key, left_certificate, revocations)?
        || !is_device_currently_authorized(account_public_key, right_certificate, revocations)?
    {
        return Err("sibling device is revoked".into());
    }

    let right_request = SyncRequest {
        version_vector: right.version_vector(conversation_id)?,
    };
    let left_response = SyncResponse {
        events: left
            .missing_events_for(conversation_id, &right_request.version_vector)?
            .into_iter()
            .map(SyncEvent::from)
            .collect(),
    };
    let left_response_bytes = bincode::serialize(&left_response)?;
    let decoded_left_response: SyncResponse = bincode::deserialize(&left_response_bytes)?;
    let left_to_right = decoded_left_response
        .events
        .into_iter()
        .map(EventRecord::from)
        .collect::<Vec<_>>();
    right.append_events(&left_to_right)?;

    let left_request = SyncRequest {
        version_vector: left.version_vector(conversation_id)?,
    };
    let right_response = SyncResponse {
        events: right
            .missing_events_for(conversation_id, &left_request.version_vector)?
            .into_iter()
            .map(SyncEvent::from)
            .collect(),
    };
    let right_response_bytes = bincode::serialize(&right_response)?;
    let decoded_right_response: SyncResponse = bincode::deserialize(&right_response_bytes)?;
    let right_to_left = decoded_right_response
        .events
        .into_iter()
        .map(EventRecord::from)
        .collect::<Vec<_>>();
    left.append_events(&right_to_left)?;

    Ok(SyncRoundTrip {
        left_to_right,
        right_to_left,
    })
}

fn delivery_outbox_id(envelope: &DeviceDeliveryEnvelope) -> String {
    format!(
        "{}:{}",
        envelope.logical_message_id, envelope.recipient_device_id
    )
}

fn event_positions(events: &[EventRecord]) -> Vec<String> {
    events
        .iter()
        .map(|event| format!("{}:{}", event.device_id, event.counter))
        .collect()
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

async fn run_bob(
    listen_addr: SocketAddr,
    bootstrap_peers: Vec<Multiaddr>,
    db_path: &Path,
) -> AppResult<()> {
    let local_display_name = load_or_prompt_display_name(db_path)?;
    let bob = Arc::new(Mutex::new(Bob::local()));
    let endpoint = Endpoint::server(server_config()?, listen_addr)?;
    let app_addr = endpoint.local_addr()?;
    println!("Chat listening on {app_addr}");

    let direct_bob = Arc::clone(&bob);
    let direct_display_name = local_display_name.clone();
    let direct_db_path = db_path.to_path_buf();
    let mut direct = tokio::spawn(async move {
        run_bob_quic_once(endpoint, direct_bob, direct_display_name, direct_db_path).await
    });

    let relayed_bob = Arc::clone(&bob);
    let mut relayed = tokio::spawn(async move {
        run_discovery_advertiser(app_addr, bootstrap_peers, Some(relayed_bob)).await
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            direct.abort();
            relayed.abort();
            println!("Ctrl+C received; Bob shutting down cleanly");
        }
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

async fn run_bob_quic_once(
    endpoint: Endpoint,
    bob: Arc<Mutex<Bob>>,
    local_display_name: String,
    db_path: PathBuf,
) -> AppResult<()> {
    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let connection = incoming.await?;
    println!(
        "direct connection established: accepted QUIC connection from {}",
        connection.remote_address()
    );

    let mut send = connection.open_uni().await?;
    let bundle = bob
        .lock()
        .map_err(|_| "Bob state lock poisoned")?
        .prekey_bundle()?;
    let bundle_bytes = bincode::serialize(&ChatPreKeyBundle {
        sender_display_name: local_display_name.clone(),
        bundle,
    })?;
    log_boundary("Bob -> Alice PreKeyBundle", &bundle_bytes);
    send_bytes(&mut send, &bundle_bytes).await?;

    let mut recv = connection.accept_uni().await?;
    let encrypted_bytes = receive_bytes(&mut recv).await?;
    log_boundary("Alice -> Bob InitialMessage", &encrypted_bytes);
    let initial_message = decode_chat_initial_message(&encrypted_bytes)?;
    let remote_display_name = initial_message.sender_display_name;
    let conversation_id = initial_message
        .sender_identity_public_key
        .as_ref()
        .map(contact_id_for_identity)
        .unwrap_or_else(|| contact_id_for_display_name(&remote_display_name));
    save_contact_for_chat(
        &db_path,
        &conversation_id,
        &remote_display_name,
        initial_message
            .sender_identity_public_key
            .as_ref()
            .map(|key| key.as_slice())
            .unwrap_or(b"legacy display-name contact"),
        "direct QUIC",
    )?;
    let plaintext = {
        let mut bob = bob.lock().map_err(|_| "Bob state lock poisoned")?;
        bob.decrypt_initial_message(&initial_message.message)?
    };

    if !plaintext.is_empty() {
        persist_chat_message(
            &db_path,
            ChatHistoryEntry {
                message_id: None,
                conversation_id: &conversation_id,
                sender_display_name: &remote_display_name,
                peer_display_name: &local_display_name,
                direction: MessageDirection::Received,
                status: MessageStatus::Received,
                protocol_counter: None,
                ciphertext: &encrypted_bytes,
                plaintext: &plaintext,
            },
        )?;
        let mut ack = connection.open_uni().await?;
        send_bytes(&mut ack, b"ok").await?;
    }

    println!("Connected securely");
    chat_loop_bob_shared(
        connection,
        bob,
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path,
    )
    .await
    .map(|_| ())
}

async fn run_alice_discovered(
    bob_peer_id: PeerId,
    message: Option<&str>,
    bootstrap_peers: Vec<Multiaddr>,
    db_path: &Path,
) -> AppResult<()> {
    println!("Looking for peer {bob_peer_id}");
    let bob_addr = discover_app_addr(bob_peer_id, bootstrap_peers.clone()).await?;
    println!("Discovered peer QUIC app address: {bob_addr}");

    let Some(message) = message else {
        return run_chat_alice(bob_addr, db_path).await;
    };

    match run_alice(bob_addr, message, db_path).await {
        Ok(()) => {
            println!("direct connection established; QUIC path used");
            Ok(())
        }
        Err(error) => {
            println!("direct connection failed: {error}");
            println!("falling back to relay");
            run_alice_relayed(bob_peer_id, message, bootstrap_peers).await
        }
    }
}

async fn run_alice(bob_addr: SocketAddr, message: &str, db_path: &Path) -> AppResult<()> {
    let local_display_name = load_or_prompt_display_name(db_path)?;
    let mut alice = Alice::local();
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    endpoint.set_default_client_config(insecure_client_config()?);

    let connection = endpoint.connect(bob_addr, "localhost")?.await?;
    println!("Connected to peer at {}", connection.remote_address());

    let mut recv = connection.accept_uni().await?;
    let bundle_bytes = receive_bytes(&mut recv).await?;
    log_boundary("Bob -> Alice PreKeyBundle", &bundle_bytes);
    let (remote_display_name, bundle) = decode_chat_prekey_bundle(&bundle_bytes)?;
    let conversation_id = contact_id_for_identity(&bundle.identity_public_key);
    save_contact_for_chat(
        db_path,
        &conversation_id,
        &remote_display_name,
        &bundle.identity_public_key,
        "direct QUIC",
    )?;

    let initial_message = alice.encrypt_initial_message(&bundle, message)?;
    let encrypted_bytes = bincode::serialize(&ChatInitialMessage {
        sender_display_name: local_display_name.clone(),
        sender_identity_public_key: Some(alice.signed_key_exchange().identity_public_key),
        message: initial_message,
    })?;
    log_boundary("Alice -> Bob InitialMessage", &encrypted_bytes);
    let mut send = connection.open_uni().await?;
    send_bytes(&mut send, &encrypted_bytes).await?;
    let mut ack = connection.accept_uni().await?;
    let ack_bytes = receive_bytes(&mut ack).await?;
    println!(
        "Received transport ack: {}",
        String::from_utf8_lossy(&ack_bytes)
    );
    println!("Connected to peer");
    println!(
        "Remote display name: {}",
        display_name_or_anonymous(&remote_display_name)
    );
    flush_pending_messages_to_bob(
        &connection,
        &mut alice,
        &local_display_name,
        &remote_display_name,
        &conversation_id,
        db_path,
    )
    .await?;

    if !message.is_empty() {
        persist_chat_message(
            db_path,
            ChatHistoryEntry {
                message_id: None,
                conversation_id: &conversation_id,
                sender_display_name: &local_display_name,
                peer_display_name: &remote_display_name,
                direction: MessageDirection::Sent,
                status: MessageStatus::Sent,
                protocol_counter: None,
                ciphertext: &encrypted_bytes,
                plaintext: message,
            },
        )?;
    }

    chat_loop_alice(
        connection,
        alice,
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path.to_path_buf(),
    )
    .await
    .map(|_| ())
}

async fn run_chat_bob(listen_addr: SocketAddr, db_path: &Path) -> AppResult<()> {
    let local_display_name = load_or_prompt_display_name(db_path)?;
    let mut bob = Bob::local();
    let endpoint = Endpoint::server(server_config()?, listen_addr)?;
    println!("Waiting for peer");

    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let connection = incoming.await?;

    let mut send = connection.open_uni().await?;
    let bundle = bob.prekey_bundle()?;
    send_bytes(
        &mut send,
        &bincode::serialize(&ChatPreKeyBundle {
            sender_display_name: local_display_name.clone(),
            bundle,
        })?,
    )
    .await?;

    let mut recv = connection.accept_uni().await?;
    let initial_bytes = receive_bytes(&mut recv).await?;
    let initial_message = decode_chat_initial_message(&initial_bytes)?;
    let remote_display_name = initial_message.sender_display_name;
    let initial_plaintext = bob.decrypt_initial_message(&initial_message.message)?;
    let conversation_id = initial_message
        .sender_identity_public_key
        .as_ref()
        .map(contact_id_for_identity)
        .unwrap_or_else(|| contact_id_for_display_name(&remote_display_name));
    save_contact_for_chat(
        db_path,
        &conversation_id,
        &remote_display_name,
        initial_message
            .sender_identity_public_key
            .as_ref()
            .map(|key| key.as_slice())
            .unwrap_or(b"legacy display-name contact"),
        "direct QUIC",
    )?;
    if !initial_plaintext.is_empty() {
        persist_chat_message(
            db_path,
            ChatHistoryEntry {
                message_id: None,
                conversation_id: &conversation_id,
                sender_display_name: &remote_display_name,
                peer_display_name: &local_display_name,
                direction: MessageDirection::Received,
                status: MessageStatus::Received,
                protocol_counter: None,
                ciphertext: &initial_bytes,
                plaintext: &initial_plaintext,
            },
        )?;
    }
    println!("Connected securely");
    flush_pending_messages_to_alice(
        &connection,
        &mut bob,
        &local_display_name,
        &remote_display_name,
        &conversation_id,
        db_path,
    )
    .await?;

    chat_loop_bob(
        connection,
        bob,
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path.to_path_buf(),
    )
    .await
}

async fn run_chat_alice(bob_addr: SocketAddr, db_path: &Path) -> AppResult<()> {
    let local_display_name = load_or_prompt_display_name(db_path)?;
    let mut alice = Alice::local();
    let mut endpoint = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    endpoint.set_default_client_config(insecure_client_config()?);

    let connection = endpoint.connect(bob_addr, "localhost")?.await?;

    let mut recv = connection.accept_uni().await?;
    let bundle_bytes = receive_bytes(&mut recv).await?;
    let (remote_display_name, bundle) = decode_chat_prekey_bundle(&bundle_bytes)?;
    let conversation_id = contact_id_for_identity(&bundle.identity_public_key);
    save_contact_for_chat(
        db_path,
        &conversation_id,
        &remote_display_name,
        &bundle.identity_public_key,
        "direct QUIC",
    )?;

    let initial_message = alice.encrypt_initial_message(&bundle, "")?;
    let mut send = connection.open_uni().await?;
    send_bytes(
        &mut send,
        &bincode::serialize(&ChatInitialMessage {
            sender_display_name: local_display_name.clone(),
            sender_identity_public_key: Some(alice.signed_key_exchange().identity_public_key),
            message: initial_message,
        })?,
    )
    .await?;
    println!("Connected securely");
    flush_pending_messages_to_bob(
        &connection,
        &mut alice,
        &local_display_name,
        &remote_display_name,
        &conversation_id,
        db_path,
    )
    .await?;

    chat_loop_alice(
        connection,
        alice,
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path.to_path_buf(),
    )
    .await
}

async fn chat_loop_alice(
    connection: quinn::Connection,
    alice: Alice,
    local_display_name: String,
    remote_display_name: String,
    conversation_id: String,
    db_path: PathBuf,
) -> AppResult<()> {
    let alice = Arc::new(Mutex::new(alice));
    print_conversation_history(&db_path, &conversation_id, &remote_display_name)?;
    let mut terminal = spawn_line_editor()?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Ctrl+C received; chat shutting down cleanly");
                return Ok(());
            }
            line = terminal.lines.recv() => {
                let Some(line) = line else {
                    println!("Terminal input closed; chat shutting down cleanly");
                    return Ok(());
                };
                if is_chat_back_command(&line) {
                    println!("Returning to Chat History");
                    return Ok(());
                }
                send_alice_chat_line(
                    &connection,
                    Arc::clone(&alice),
                    &local_display_name,
                    &remote_display_name,
                    &conversation_id,
                    &db_path,
                    line,
                ).await?;
            }
            incoming = connection.accept_uni() => {
                let mut recv = incoming?;
                let frame_bytes = receive_bytes(&mut recv).await?;
                let frame: ChatFrame = bincode::deserialize(&frame_bytes)?;
                match frame {
                    ChatFrame::Message { message_id, sender_display_name, message } => {
                        if !chat_message_already_saved(&db_path, &message_id)? {
                            let plaintext = alice
                                .lock()
                                .map_err(|_| "Alice state lock poisoned")?
                                .decrypt_from_bob(&message)?;
                            persist_chat_message(
                                &db_path,
                                ChatHistoryEntry {
                                    message_id: Some(message_id.clone()),
                                    conversation_id: &conversation_id,
                                    sender_display_name: &sender_display_name,
                                    peer_display_name: &local_display_name,
                                    direction: MessageDirection::Received,
                                    status: MessageStatus::Received,
                                    protocol_counter: Some(message.number),
                                    ciphertext: &frame_bytes,
                                    plaintext: &plaintext,
                                },
                            )?;
                            mark_incoming_chat_message_accepted(&db_path, &message_id)?;
                            terminal.print_message(&sender_display_name, &plaintext)?;
                        }
                        send_chat_ack(&connection, &message_id).await?;
                    }
                    ChatFrame::Ack { .. } => {}
                }
            }
        }
    }
}

async fn chat_loop_bob(
    connection: quinn::Connection,
    bob: Bob,
    local_display_name: String,
    remote_display_name: String,
    conversation_id: String,
    db_path: PathBuf,
) -> AppResult<()> {
    chat_loop_bob_shared(
        connection,
        Arc::new(Mutex::new(bob)),
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path,
    )
    .await
}

async fn chat_loop_bob_shared(
    connection: quinn::Connection,
    bob: Arc<Mutex<Bob>>,
    local_display_name: String,
    remote_display_name: String,
    conversation_id: String,
    db_path: PathBuf,
) -> AppResult<()> {
    print_conversation_history(&db_path, &conversation_id, &remote_display_name)?;
    let mut terminal = spawn_line_editor()?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Ctrl+C received; chat shutting down cleanly");
                return Ok(());
            }
            line = terminal.lines.recv() => {
                let Some(line) = line else {
                    println!("Terminal input closed; chat shutting down cleanly");
                    return Ok(());
                };
                if is_chat_back_command(&line) {
                    println!("Returning to Chat History");
                    return Ok(());
                }
                send_bob_chat_line(
                    &connection,
                    Arc::clone(&bob),
                    &local_display_name,
                    &remote_display_name,
                    &conversation_id,
                    &db_path,
                    line,
                ).await?;
            }
            incoming = connection.accept_uni() => {
                let mut recv = incoming?;
                let frame_bytes = receive_bytes(&mut recv).await?;
                let frame: ChatFrame = bincode::deserialize(&frame_bytes)?;
                match frame {
                    ChatFrame::Message { message_id, sender_display_name, message } => {
                        if !chat_message_already_saved(&db_path, &message_id)? {
                            let plaintext = bob
                                .lock()
                                .map_err(|_| "Bob state lock poisoned")?
                                .decrypt_from_alice(&message)?;
                            persist_chat_message(
                                &db_path,
                                ChatHistoryEntry {
                                    message_id: Some(message_id.clone()),
                                    conversation_id: &conversation_id,
                                    sender_display_name: &sender_display_name,
                                    peer_display_name: &local_display_name,
                                    direction: MessageDirection::Received,
                                    status: MessageStatus::Received,
                                    protocol_counter: Some(message.number),
                                    ciphertext: &frame_bytes,
                                    plaintext: &plaintext,
                                },
                            )?;
                            mark_incoming_chat_message_accepted(&db_path, &message_id)?;
                            terminal.print_message(&sender_display_name, &plaintext)?;
                        }
                        send_chat_ack(&connection, &message_id).await?;
                    }
                    ChatFrame::Ack { .. } => {}
                }
            }
        }
    }
}

async fn send_alice_chat_line(
    connection: &quinn::Connection,
    alice: Arc<Mutex<Alice>>,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    line: String,
) -> AppResult<()> {
    if line.is_empty() {
        return Ok(());
    }
    send_alice_chat_line_with_id(
        connection,
        alice,
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path,
        line,
        None,
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn send_alice_chat_line_with_id(
    connection: &quinn::Connection,
    alice: Arc<Mutex<Alice>>,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    line: String,
    existing_message_id: Option<String>,
) -> AppResult<String> {
    let message = alice
        .lock()
        .map_err(|_| "Alice state lock poisoned")?
        .encrypt_for_bob(&line)?;
    let message_bytes = bincode::serialize(&message)?;
    let message_id = existing_message_id.unwrap_or_else(|| {
        chat_message_id(
            conversation_id,
            &MessageDirection::Sent,
            Some(message.number),
            &message_bytes,
        )
    });
    let frame = ChatFrame::Message {
        message_id: message_id.clone(),
        sender_display_name: local_display_name.to_string(),
        message,
    };
    let frame_bytes = bincode::serialize(&frame)?;
    send_chat_frame(connection, frame).await?;
    persist_chat_message(
        db_path,
        ChatHistoryEntry {
            message_id: Some(message_id.clone()),
            conversation_id,
            sender_display_name: local_display_name,
            peer_display_name: remote_display_name,
            direction: MessageDirection::Sent,
            status: MessageStatus::Sent,
            protocol_counter: None,
            ciphertext: &frame_bytes,
            plaintext: &line,
        },
    )?;
    Ok(message_id)
}

async fn send_bob_chat_line(
    connection: &quinn::Connection,
    bob: Arc<Mutex<Bob>>,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    line: String,
) -> AppResult<()> {
    if line.is_empty() {
        return Ok(());
    }
    send_bob_chat_line_with_id(
        connection,
        bob,
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path,
        line,
        None,
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn send_bob_chat_line_with_id(
    connection: &quinn::Connection,
    bob: Arc<Mutex<Bob>>,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    line: String,
    existing_message_id: Option<String>,
) -> AppResult<String> {
    let message = bob
        .lock()
        .map_err(|_| "Bob state lock poisoned")?
        .encrypt_for_alice(&line)?;
    let message_bytes = bincode::serialize(&message)?;
    let message_id = existing_message_id.unwrap_or_else(|| {
        chat_message_id(
            conversation_id,
            &MessageDirection::Sent,
            Some(message.number),
            &message_bytes,
        )
    });
    let frame = ChatFrame::Message {
        message_id: message_id.clone(),
        sender_display_name: local_display_name.to_string(),
        message,
    };
    let frame_bytes = bincode::serialize(&frame)?;
    send_chat_frame(connection, frame).await?;
    persist_chat_message(
        db_path,
        ChatHistoryEntry {
            message_id: Some(message_id.clone()),
            conversation_id,
            sender_display_name: local_display_name,
            peer_display_name: remote_display_name,
            direction: MessageDirection::Sent,
            status: MessageStatus::Sent,
            protocol_counter: None,
            ciphertext: &frame_bytes,
            plaintext: &line,
        },
    )?;
    Ok(message_id)
}

async fn send_chat_frame(connection: &quinn::Connection, frame: ChatFrame) -> AppResult<()> {
    let bytes = bincode::serialize(&frame)?;
    let mut send = connection.open_uni().await?;
    send_bytes(&mut send, &bytes).await
}

async fn send_chat_ack(connection: &quinn::Connection, message_id: &str) -> AppResult<()> {
    send_chat_frame(
        connection,
        ChatFrame::Ack {
            message_id: message_id.to_string(),
        },
    )
    .await
}

fn chat_message_already_saved(db_path: &Path, message_id: &str) -> AppResult<bool> {
    let storage = Storage::open(db_path)?;
    Ok(storage.message_exists(message_id)?)
}

fn mark_incoming_chat_message_accepted(db_path: &Path, message_id: &str) -> AppResult<()> {
    let storage = Storage::open(db_path)?;
    let _ = storage.accept_message_once(message_id)?;
    Ok(())
}

async fn flush_pending_messages_to_bob(
    connection: &quinn::Connection,
    alice: &mut Alice,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
) -> AppResult<()> {
    let peer_id = conversation_id;
    let pending = Storage::open(db_path)?.pending_peer_messages_for_peer(peer_id)?;
    if pending.is_empty() {
        return Ok(());
    }

    println!("Delivering {} pending message(s)", pending.len());
    for pending_message in pending {
        let storage = Storage::open(db_path)?;
        storage.record_pending_peer_message_attempt(&pending_message.message_id)?;
        let message = alice.encrypt_for_bob(&pending_message.plaintext)?;
        let frame = ChatFrame::Message {
            message_id: pending_message.message_id.clone(),
            sender_display_name: local_display_name.to_string(),
            message,
        };
        send_chat_frame(connection, frame).await?;

        if wait_for_chat_ack_as_alice(
            connection,
            alice,
            &pending_message.message_id,
            local_display_name,
            remote_display_name,
            conversation_id,
            db_path,
        )
        .await?
        {
            let storage = Storage::open(db_path)?;
            storage.remove_pending_peer_message(&pending_message.message_id)?;
            storage.update_message_status(&pending_message.message_id, MessageStatus::Sent)?;
        } else {
            println!("Peer disconnected before confirming pending delivery");
            break;
        }
    }
    Ok(())
}

async fn flush_pending_messages_to_alice(
    connection: &quinn::Connection,
    bob: &mut Bob,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
) -> AppResult<()> {
    let peer_id = conversation_id;
    let pending = Storage::open(db_path)?.pending_peer_messages_for_peer(peer_id)?;
    if pending.is_empty() {
        return Ok(());
    }

    println!("Delivering {} pending message(s)", pending.len());
    for pending_message in pending {
        let storage = Storage::open(db_path)?;
        storage.record_pending_peer_message_attempt(&pending_message.message_id)?;
        let message = bob.encrypt_for_alice(&pending_message.plaintext)?;
        let frame = ChatFrame::Message {
            message_id: pending_message.message_id.clone(),
            sender_display_name: local_display_name.to_string(),
            message,
        };
        send_chat_frame(connection, frame).await?;

        if wait_for_chat_ack_as_bob(
            connection,
            bob,
            &pending_message.message_id,
            local_display_name,
            remote_display_name,
            conversation_id,
            db_path,
        )
        .await?
        {
            let storage = Storage::open(db_path)?;
            storage.remove_pending_peer_message(&pending_message.message_id)?;
            storage.update_message_status(&pending_message.message_id, MessageStatus::Sent)?;
        } else {
            println!("Peer disconnected before confirming pending delivery");
            break;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_chat_ack_as_alice(
    connection: &quinn::Connection,
    alice: &mut Alice,
    expected_message_id: &str,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
) -> AppResult<bool> {
    loop {
        let incoming =
            match time::timeout(PENDING_DELIVERY_ACK_TIMEOUT, connection.accept_uni()).await {
                Ok(result) => result?,
                Err(_) => return Ok(false),
            };
        let mut recv = incoming;
        let frame_bytes = receive_bytes(&mut recv).await?;
        let frame: ChatFrame = bincode::deserialize(&frame_bytes)?;
        match frame {
            ChatFrame::Ack { message_id } if message_id == expected_message_id => {
                return Ok(true);
            }
            other => {
                handle_incoming_during_alice_flush(
                    connection,
                    alice,
                    local_display_name,
                    remote_display_name,
                    conversation_id,
                    db_path,
                    frame_bytes,
                    other,
                )
                .await?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_chat_ack_as_bob(
    connection: &quinn::Connection,
    bob: &mut Bob,
    expected_message_id: &str,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
) -> AppResult<bool> {
    loop {
        let incoming =
            match time::timeout(PENDING_DELIVERY_ACK_TIMEOUT, connection.accept_uni()).await {
                Ok(result) => result?,
                Err(_) => return Ok(false),
            };
        let mut recv = incoming;
        let frame_bytes = receive_bytes(&mut recv).await?;
        let frame: ChatFrame = bincode::deserialize(&frame_bytes)?;
        match frame {
            ChatFrame::Ack { message_id } if message_id == expected_message_id => {
                return Ok(true);
            }
            other => {
                handle_incoming_during_bob_flush(
                    connection,
                    bob,
                    local_display_name,
                    remote_display_name,
                    conversation_id,
                    db_path,
                    frame_bytes,
                    other,
                )
                .await?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming_during_alice_flush(
    connection: &quinn::Connection,
    alice: &mut Alice,
    local_display_name: &str,
    _remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    frame_bytes: Vec<u8>,
    frame: ChatFrame,
) -> AppResult<()> {
    match frame {
        ChatFrame::Message {
            message_id,
            sender_display_name,
            message,
        } => {
            if !chat_message_already_saved(db_path, &message_id)? {
                let plaintext = alice.decrypt_from_bob(&message)?;
                persist_chat_message(
                    db_path,
                    ChatHistoryEntry {
                        message_id: Some(message_id.clone()),
                        conversation_id,
                        sender_display_name: &sender_display_name,
                        peer_display_name: local_display_name,
                        direction: MessageDirection::Received,
                        status: MessageStatus::Received,
                        protocol_counter: Some(message.number),
                        ciphertext: &frame_bytes,
                        plaintext: &plaintext,
                    },
                )?;
                mark_incoming_chat_message_accepted(db_path, &message_id)?;
            }
            send_chat_ack(connection, &message_id).await?;
        }
        ChatFrame::Ack { .. } => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_incoming_during_bob_flush(
    connection: &quinn::Connection,
    bob: &mut Bob,
    local_display_name: &str,
    _remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    frame_bytes: Vec<u8>,
    frame: ChatFrame,
) -> AppResult<()> {
    match frame {
        ChatFrame::Message {
            message_id,
            sender_display_name,
            message,
        } => {
            if !chat_message_already_saved(db_path, &message_id)? {
                let plaintext = bob.decrypt_from_alice(&message)?;
                persist_chat_message(
                    db_path,
                    ChatHistoryEntry {
                        message_id: Some(message_id.clone()),
                        conversation_id,
                        sender_display_name: &sender_display_name,
                        peer_display_name: local_display_name,
                        direction: MessageDirection::Received,
                        status: MessageStatus::Received,
                        protocol_counter: Some(message.number),
                        ciphertext: &frame_bytes,
                        plaintext: &plaintext,
                    },
                )?;
                mark_incoming_chat_message_accepted(db_path, &message_id)?;
            }
            send_chat_ack(connection, &message_id).await?;
        }
        ChatFrame::Ack { .. } => {}
    }
    Ok(())
}

struct ChatTerminal {
    lines: mpsc::UnboundedReceiver<String>,
    print_tx: std_mpsc::Sender<String>,
}

impl ChatTerminal {
    fn print_message(&mut self, sender_display_name: &str, plaintext: &str) -> AppResult<()> {
        self.print_tx
            .send(format!(
                "> {}: {}",
                display_name_or_anonymous(sender_display_name),
                plaintext
            ))
            .map_err(|error| format!("terminal print failed: {error}").into())
    }
}

fn spawn_line_editor() -> AppResult<ChatTerminal> {
    let (line_tx, line_rx) = mpsc::unbounded_channel();
    let (setup_tx, setup_rx) = std_mpsc::channel();

    thread::spawn(move || {
        let mut editor = match DefaultEditor::new() {
            Ok(editor) => editor,
            Err(error) => {
                let _ = setup_tx.send(Err(error.to_string()));
                return;
            }
        };
        let mut printer = match editor.create_external_printer() {
            Ok(printer) => printer,
            Err(error) => {
                let _ = setup_tx.send(Err(error.to_string()));
                return;
            }
        };
        let (print_tx, print_rx) = std_mpsc::channel::<String>();
        thread::spawn(move || {
            while let Ok(message) = print_rx.recv() {
                let _ = printer.print(message);
            }
        });

        if setup_tx.send(Ok(print_tx)).is_err() {
            return;
        }

        loop {
            match editor.readline(CHAT_PROMPT) {
                Ok(line) => {
                    let _ = editor.add_history_entry(line.as_str());
                    let should_stop = is_chat_back_command(&line);
                    if line_tx.send(line).is_err() {
                        break;
                    }
                    if should_stop {
                        break;
                    }
                }
                Err(ReadlineError::Interrupted | ReadlineError::Eof) => break,
                Err(error) => {
                    eprintln!("terminal input stopped: {error}");
                    break;
                }
            }
        }
    });

    let print_tx = setup_rx
        .recv()
        .map_err(|error| format!("line editor failed to start: {error}"))?
        .map_err(|error| format!("line editor failed to start: {error}"))?;

    Ok(ChatTerminal {
        lines: line_rx,
        print_tx,
    })
}

fn load_or_prompt_display_name(db_path: &Path) -> AppResult<String> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let storage = Storage::open(db_path)?;
    if let Some(display_name) = storage.load_display_name()? {
        return Ok(display_name_or_anonymous(&display_name));
    }

    print!("Enter display name (blank for Anonymous): ");
    io::stdout().flush()?;
    let mut display_name = String::new();
    io::stdin().read_line(&mut display_name)?;
    let display_name = display_name_or_anonymous(display_name.trim());
    storage.save_display_name(&display_name)?;

    Ok(display_name)
}

fn save_contact_for_chat(
    db_path: &Path,
    contact_id: &str,
    display_name: &str,
    identity_public_key: &[u8],
    discovery_hint: &str,
) -> AppResult<()> {
    let storage = Storage::open(db_path)?;
    let display_name = display_name_or_anonymous(display_name);
    storage.save_contact(&ContactRecord {
        contact_id: contact_id.to_string(),
        display_name: display_name.clone(),
        identity_public_key: identity_public_key.to_vec(),
        discovery_hint: discovery_hint.to_string(),
        saved_at_unix_secs: now_unix_secs(),
    })?;
    if let Ok(identity) = <&[u8; 32]>::try_from(identity_public_key) {
        storage.save_known_peer(&KnownPeerRecord {
            peer_id: contact_id_for_identity(identity),
            identity_public_key: identity_public_key.to_vec(),
            display_name,
            conversation_id: contact_id.to_string(),
            last_seen_at_unix_secs: now_unix_secs(),
        })?;
    }
    Ok(())
}

struct ChatHistoryEntry<'a> {
    message_id: Option<String>,
    conversation_id: &'a str,
    sender_display_name: &'a str,
    peer_display_name: &'a str,
    direction: MessageDirection,
    status: MessageStatus,
    protocol_counter: Option<u64>,
    ciphertext: &'a [u8],
    plaintext: &'a str,
}

fn persist_chat_message(db_path: &Path, entry: ChatHistoryEntry<'_>) -> AppResult<()> {
    let storage = Storage::open(db_path)?;
    let message_id = entry.message_id.clone().unwrap_or_else(|| {
        chat_message_id(
            entry.conversation_id,
            &entry.direction,
            entry.protocol_counter,
            entry.ciphertext,
        )
    });
    let (sender_id, recipient_id) = match entry.direction {
        MessageDirection::Sent => ("you", entry.peer_display_name),
        MessageDirection::Received => (entry.sender_display_name, "you"),
    };

    storage.insert_message(&MessageRecord {
        message_id,
        conversation_id: entry.conversation_id.to_string(),
        sender_id: display_name_or_anonymous(sender_id),
        recipient_id: display_name_or_anonymous(recipient_id),
        direction: entry.direction,
        status: entry.status,
        protocol_counter: entry.protocol_counter,
        ciphertext: entry.ciphertext.to_vec(),
        plaintext: Some(entry.plaintext.to_string()),
        created_at_unix_secs: now_unix_secs(),
    })?;
    Ok(())
}

fn print_conversation_history(
    db_path: &Path,
    conversation_id: &str,
    display_name: &str,
) -> AppResult<()> {
    print_conversation(
        db_path,
        conversation_id,
        display_name,
        Some("End-to-end encrypted"),
    )?;
    println!("{CHAT_INPUT_INSTRUCTION}");
    Ok(())
}

fn print_offline_conversation(
    db_path: &Path,
    conversation_id: &str,
    display_name: &str,
) -> AppResult<()> {
    print_conversation(db_path, conversation_id, display_name, Some("Offline"))
}

fn print_conversation(
    db_path: &Path,
    conversation_id: &str,
    display_name: &str,
    status: Option<&str>,
) -> AppResult<()> {
    let storage = Storage::open(db_path)?;
    let messages = storage.messages_for_conversation(conversation_id)?;

    println!();
    match status {
        Some(status) => println!("{} - {status}", display_name_or_anonymous(display_name)),
        None => println!("{}", display_name_or_anonymous(display_name)),
    }
    println!();
    println!("--------------------------------");
    for message in messages {
        let body = message.plaintext.as_deref().unwrap_or("[encrypted]");
        match message.direction {
            MessageDirection::Sent => {
                println!("You: {body}");
                let status = message_status_label(&message.status);
                if status == "queued for delivery" {
                    println!("✓ Queued for delivery");
                } else {
                    println!("    {status}");
                }
            }
            MessageDirection::Received => {
                println!("{}: {body}", display_name_or_anonymous(display_name));
            }
        }
    }
    println!("--------------------------------");
    println!();
    Ok(())
}

fn message_status_label(status: &MessageStatus) -> &'static str {
    match status {
        MessageStatus::Stored => "sending...",
        MessageStatus::Sent => "sent",
        MessageStatus::Received => "delivered",
    }
}

fn chat_message_id(
    conversation_id: &str,
    direction: &MessageDirection,
    protocol_counter: Option<u64>,
    ciphertext: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ciphermesh.local-history.v1");
    hasher.update(conversation_id.as_bytes());
    hasher.update(match direction {
        MessageDirection::Sent => b"sent".as_slice(),
        MessageDirection::Received => b"received".as_slice(),
    });
    if let Some(counter) = protocol_counter {
        hasher.update(counter.to_be_bytes());
    }
    hasher.update(ciphertext);
    hex_encode(&hasher.finalize()[..16])
}

fn pending_peer_message_id(peer_id: &str, plaintext: &str) -> AppResult<String> {
    let mut random = [0u8; 16];
    fill_random(&mut random)?;
    let mut hasher = Sha256::new();
    hasher.update(b"ciphermesh.pending-peer-message.v1");
    hasher.update(peer_id.as_bytes());
    hasher.update(now_unix_secs().to_be_bytes());
    hasher.update(plaintext.as_bytes());
    hasher.update(random);
    Ok(hex_encode(&hasher.finalize()[..16]))
}

fn contact_id_for_identity(identity_public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(identity_public_key);
    format!("contact-{}", hex_encode(&digest[..8]))
}

fn contact_id_for_display_name(display_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ciphermesh.display-contact.v1");
    hasher.update(display_name_or_anonymous(display_name).as_bytes());
    format!("contact-{}", hex_encode(&hasher.finalize()[..8]))
}

fn relative_time(timestamp: u64) -> String {
    let now = now_unix_secs();
    if timestamp >= now {
        return "just now".to_string();
    }

    let age = now - timestamp;
    match age {
        0..=59 => "just now".to_string(),
        60..=119 => "1 min ago".to_string(),
        120..=3599 => format!("{} min ago", age / 60),
        3600..=7199 => "1 hour ago".to_string(),
        7200..=86_399 => format!("{} hours ago", age / 3600),
        86_400..=172_799 => "yesterday".to_string(),
        _ => format!("{} days ago", age / 86_400),
    }
}

fn display_name_or_anonymous(display_name: &str) -> String {
    let display_name = display_name.trim();
    if display_name.is_empty() {
        "Anonymous".to_string()
    } else {
        display_name.chars().take(64).collect()
    }
}

fn default_chat_db(role: &str) -> PathBuf {
    PathBuf::from(format!("target/ciphermesh-{role}-profile.sqlite"))
}

fn decode_chat_prekey_bundle(bytes: &[u8]) -> AppResult<(String, PreKeyBundle)> {
    match bincode::deserialize::<ChatPreKeyBundle>(bytes) {
        Ok(bundle) => Ok((
            display_name_or_anonymous(&bundle.sender_display_name),
            bundle.bundle,
        )),
        Err(_) => {
            let bundle: PreKeyBundle = bincode::deserialize(bytes)?;
            Ok(("Anonymous".to_string(), bundle))
        }
    }
}

fn decode_chat_initial_message(bytes: &[u8]) -> AppResult<ChatInitialMessage> {
    match bincode::deserialize::<ChatInitialMessage>(bytes) {
        Ok(message) => Ok(ChatInitialMessage {
            sender_display_name: display_name_or_anonymous(&message.sender_display_name),
            sender_identity_public_key: message.sender_identity_public_key,
            message: message.message,
        }),
        Err(_) => match bincode::deserialize::<LegacyChatInitialMessage>(bytes) {
            Ok(message) => Ok(ChatInitialMessage {
                sender_display_name: display_name_or_anonymous(&message.sender_display_name),
                sender_identity_public_key: None,
                message: message.message,
            }),
            Err(_) => {
                let message: InitialMessage = bincode::deserialize(bytes)?;
                Ok(ChatInitialMessage {
                    sender_display_name: "Anonymous".to_string(),
                    sender_identity_public_key: None,
                    message,
                })
            }
        },
    }
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
                                println!("Alice sent encrypted message through relay and received transport ack");
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
struct ChatPreKeyBundle {
    sender_display_name: String,
    bundle: PreKeyBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatInitialMessage {
    sender_display_name: String,
    sender_identity_public_key: Option<ciphermesh::IdentityPublicKeyBytes>,
    message: InitialMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyChatInitialMessage {
    sender_display_name: String,
    message: InitialMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ChatFrame {
    Message {
        message_id: String,
        sender_display_name: String,
        message: RatchetMessage,
    },
    Ack {
        message_id: String,
    },
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
                kad::Event::OutboundQueryProgressed {
                    result: kad::QueryResult::Bootstrap(result),
                    ..
                },
            )) => {
                println!("Bob Kademlia bootstrap result: {result:?}");
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
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Ctrl+C received; relay shutting down cleanly");
                return Ok(());
            }
            event = swarm.select_next_some() => {
                match event {
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
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Ctrl+C received; mailbox shutting down cleanly");
                return Ok(());
            }
            event = swarm.select_next_some() => {
                match event {
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
    println!("Alice deposited encrypted mailbox envelope");

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

    let mut config = ServerConfig::with_single_cert(vec![cert_der], priv_key.into())?;
    config.transport_config(long_lived_transport_config()?);

    Ok(config)
}

fn insecure_client_config() -> AppResult<ClientConfig> {
    let client_crypto = quinn::rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)?,
    ));
    config.transport_config(long_lived_transport_config()?);

    Ok(config)
}

fn long_lived_transport_config() -> AppResult<Arc<TransportConfig>> {
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(IdleTimeout::try_from(Duration::from_secs(10 * 60))?));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));

    Ok(Arc::new(transport))
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
    if !env_verbose_enabled() {
        return;
    }
    println!("{label}: {} bytes", bytes.len());
    println!("{label} bytes: {}", hex_preview(bytes));
}

fn env_verbose_enabled() -> bool {
    std::env::var("CIPHERMESH_VERBOSE")
        .map(|value| matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
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

    #[test]
    fn alice_args_allow_no_initial_message() {
        let args = Vec::<String>::new();
        let (message, bootstrap) = split_optional_message_and_bootstrap(tail_args(&args, 3));

        assert_eq!(message, None);
        assert!(bootstrap.is_empty());
    }

    #[test]
    fn alice_args_treat_first_multiaddr_as_bootstrap_without_message() {
        let args = vec![
            "ciphermesh".to_string(),
            "alice".to_string(),
            "peer-id-placeholder".to_string(),
            "/ip4/127.0.0.1/tcp/4001".to_string(),
        ];
        let (message, bootstrap) = split_optional_message_and_bootstrap(tail_args(&args, 3));

        assert_eq!(message, None);
        assert_eq!(bootstrap.len(), 1);
    }

    #[test]
    fn alice_args_still_allow_one_shot_message() {
        let args = vec![
            "ciphermesh".to_string(),
            "alice".to_string(),
            "peer-id-placeholder".to_string(),
            "hello bob".to_string(),
        ];
        let (message, bootstrap) = split_optional_message_and_bootstrap(tail_args(&args, 3));

        assert_eq!(message, Some("hello bob"));
        assert!(bootstrap.is_empty());
    }

    #[test]
    fn generated_invite_code_is_six_characters() {
        let code = generate_invite_code().expect("invite code");

        assert_eq!(code.len(), INVITE_CODE_LEN);
        assert_eq!(code.len(), 6);
        assert!(code
            .bytes()
            .all(|byte| INVITE_CODE_ALPHABET.contains(&byte)));
    }

    #[test]
    fn invite_code_normalization_accepts_exactly_six_characters() {
        assert_eq!(
            normalize_invite_code("ab-c2d3").expect("normalized"),
            "ABC2D3"
        );
        assert!(normalize_invite_code("ABCDE").is_err());
        assert!(normalize_invite_code("ABCDEFG").is_err());
    }

    #[test]
    fn display_names_render_cleanly_for_chat_ui() {
        assert_eq!(display_name_or_anonymous("James"), "James");
        assert_eq!(display_name_or_anonymous("   "), "Anonymous");
        assert_eq!(display_name_or_anonymous("Anonymous"), "Anonymous");
    }

    #[test]
    fn only_slash_commands_leave_active_chat_input() {
        assert!(!is_chat_back_command("B"));
        assert!(!is_chat_back_command("back"));
        assert!(!is_chat_back_command("hello /back"));
        assert!(is_chat_back_command("/back"));
        assert!(is_chat_back_command("/back "));
        assert!(is_chat_back_command("/exit"));
    }

    #[test]
    fn normal_chat_message_ids_do_not_embed_raw_debug_identifiers() {
        let id = chat_message_id(
            "contact-james",
            &MessageDirection::Sent,
            Some(1),
            b"/ip4/127.0.0.1/tcp/4001/p2p/raw-peer-id",
        );

        assert!(!id.contains("127.0.0.1"));
        assert!(!id.contains("raw-peer-id"));
        assert_eq!(id.len(), 32);
    }
}
