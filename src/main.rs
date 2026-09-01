use ciphermesh::{Alice, Bob, InitialMessage, PreKeyBundle, SimulatedDirectory};
use futures::StreamExt;
use libp2p::{
    identify, identity, kad, mdns,
    multiaddr::Protocol,
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::time;

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const DISCOVERY_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/0";
const DISCOVERY_PROTOCOL: &str = "/ciphermesh/discovery/3b/1.0.0";
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);

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
        Some("kad-demo") => run_kademlia_demo().await,
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
    let mut bob = Bob::local();
    let endpoint = Endpoint::server(server_config()?, listen_addr)?;
    let app_addr = endpoint.local_addr()?;
    println!("Bob QUIC app listening on {app_addr}");

    let discovery = tokio::spawn(async move {
        if let Err(error) = run_discovery_advertiser(app_addr, bootstrap_peers).await {
            eprintln!("Bob discovery stopped: {error}");
        }
    });

    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let connection = incoming.await?;
    println!(
        "Bob accepted QUIC connection from {}",
        connection.remote_address()
    );

    let mut send = connection.open_uni().await?;
    let bundle = bob.prekey_bundle()?;
    let bundle_bytes = bincode::serialize(&bundle)?;
    log_boundary("Bob -> Alice PreKeyBundle", &bundle_bytes);
    send_bytes(&mut send, &bundle_bytes).await?;

    let mut recv = connection.accept_uni().await?;
    let encrypted_bytes = receive_bytes(&mut recv).await?;
    log_boundary("Alice -> Bob InitialMessage", &encrypted_bytes);
    let initial_message: InitialMessage = bincode::deserialize(&encrypted_bytes)?;
    let plaintext = bob.decrypt_initial_message(&initial_message)?;
    println!("Bob decrypted plaintext: {plaintext}");

    let mut ack = connection.open_uni().await?;
    send_bytes(&mut ack, b"ok").await?;
    endpoint.wait_idle().await;
    discovery.abort();
    Ok(())
}

async fn run_alice_discovered(
    bob_peer_id: PeerId,
    message: &str,
    bootstrap_peers: Vec<Multiaddr>,
) -> AppResult<()> {
    println!("Alice looking for Bob PeerId {bob_peer_id}");
    let bob_addr = discover_app_addr(bob_peer_id, bootstrap_peers).await?;
    println!("Alice discovered Bob's QUIC app address: {bob_addr}");
    run_alice(bob_addr, message).await
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

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct DiscoveryBehaviour {
    identify: identify::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    mdns: mdns::tokio::Behaviour,
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
        .with_behaviour(move |key| {
            Ok(DiscoveryBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    DISCOVERY_PROTOCOL.to_string(),
                    key.public(),
                )),
                kad: kademlia,
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
            })
        })?
        .build();

    Ok(swarm)
}

async fn run_discovery_advertiser(
    app_addr: SocketAddr,
    bootstrap_peers: Vec<Multiaddr>,
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
    listen_and_bootstrap(&mut swarm, bootstrap_peers)?;

    println!("Bob libp2p PeerId: {local_peer_id}");
    println!("Bob advertised QUIC app address record: {app_multiaddr}");

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
}
