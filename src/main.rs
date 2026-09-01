use ciphermesh::{Alice, Bob, InitialMessage, PreKeyBundle, SimulatedDirectory};
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
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time;

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const DISCOVERY_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/0";
const DISCOVERY_PROTOCOL: &str = "/ciphermesh/discovery/3c/1.0.0";
const APP_RELAY_PROTOCOL: &str = "/ciphermesh/app-bytes/3c/1.0.0";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const DIRECT_DIAL_TIMEOUT: Duration = Duration::from_secs(5);

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
