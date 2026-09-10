use super::*;
use libp2p::swarm::dial_opts::DialOpts;
use std::{
    collections::{HashMap, HashSet},
    future::pending,
};

const PAIRING_PROTOCOL: &str = "/ciphermesh/pairing/1.0.0";
const LIBP2P_IDENTITY_SLOT: &str = "libp2p-installation";
const DIRECT_DIAL_GRACE: Duration = Duration::from_secs(3);
const CHAT_RECONNECT_INTERVAL: Duration = Duration::from_secs(3);
const CHAT_IDLE_CONNECTION_TIMEOUT: Duration = Duration::MAX;

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PairingRequest {
    RegisterInvite {
        code_hash: String,
        expires_at_unix_secs: u64,
        direct_addresses: Vec<String>,
    },
    ResolveInvite {
        code_hash: String,
    },
    PreKeyBundle,
    InitialMessage(Vec<u8>),
    ChatFrame(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PairingResponse {
    Registered,
    Resolved {
        peer_id: String,
        direct_addresses: Vec<String>,
    },
    PreKeyBundle(Vec<u8>),
    Ack(String),
    Error(String),
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct PairingBehaviour {
    app: request_response::cbor::Behaviour<PairingRequest, PairingResponse>,
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    identify: identify::Behaviour,
    mdns: mdns::tokio::Behaviour,
    relay: relay::client::Behaviour,
}

#[derive(NetworkBehaviour)]
#[behaviour(prelude = "libp2p::swarm::derive_prelude")]
struct PublicServiceBehaviour {
    identify: identify::Behaviour,
    relay: relay::Behaviour,
    rendezvous: request_response::cbor::Behaviour<PairingRequest, PairingResponse>,
}

#[derive(Clone)]
struct InviteRegistration {
    peer_id: PeerId,
    direct_addresses: Vec<String>,
    expires_at_unix_secs: u64,
}

pub(super) async fn run_public_service(
    listen_addr: Multiaddr,
    identity_path: &Path,
) -> AppResult<()> {
    let key = load_or_create_service_identity(identity_path)?;
    let local_peer_id = PeerId::from(key.public());
    if identity_path == Path::new(DEFAULT_SERVICE_IDENTITY_PATH)
        && local_peer_id.to_string() != DEFAULT_PAIRING_SERVICE_PEER_ID
    {
        return Err(format!(
            "canonical service identity {} produced unexpected PeerId {local_peer_id}; expected {}",
            identity_path.display(),
            DEFAULT_PAIRING_SERVICE_PEER_ID
        )
        .into());
    }
    let mut swarm = new_public_service_swarm(key)?;
    swarm.listen_on(listen_addr)?;

    run_public_service_swarm(swarm, local_peer_id).await
}

async fn run_public_service_swarm(
    mut swarm: Swarm<PublicServiceBehaviour>,
    local_peer_id: PeerId,
) -> AppResult<()> {
    let mut invitations = HashMap::<String, InviteRegistration>::new();
    let mut reserved_peers = HashSet::<PeerId>::new();

    println!("CipherMesh public rendezvous/relay service");
    println!("Service PeerId: {local_peer_id}");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                swarm.add_external_address(address.clone());
                println!(
                    "Listening on {}",
                    address.with(Protocol::P2p(local_peer_id))
                );
            }
            SwarmEvent::Behaviour(PublicServiceBehaviourEvent::Relay(event)) => match event {
                relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                    reserved_peers.insert(src_peer_id);
                    debug_log(format!("reservation active for {src_peer_id}"));
                }
                relay::Event::ReservationClosed { src_peer_id }
                | relay::Event::ReservationTimedOut { src_peer_id } => {
                    reserved_peers.remove(&src_peer_id);
                    invitations.retain(|_, invite| invite.peer_id != src_peer_id);
                    debug_log(format!("reservation ended for {src_peer_id}"));
                }
                other => debug_log(format!("relay event: {other:?}")),
            },
            SwarmEvent::Behaviour(PublicServiceBehaviourEvent::Rendezvous(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) => {
                invitations.retain(|_, invite| invite.expires_at_unix_secs > now_unix_secs());
                let response = match request {
                    PairingRequest::RegisterInvite {
                        code_hash,
                        expires_at_unix_secs,
                        direct_addresses,
                    } => {
                        if !reserved_peers.contains(&peer) {
                            PairingResponse::Error(
                                "relay reservation is not ready; retrying".to_string(),
                            )
                        } else if expires_at_unix_secs <= now_unix_secs()
                            || expires_at_unix_secs > now_unix_secs() + INVITE_TTL_SECS
                        {
                            PairingResponse::Error("invalid invite expiry".to_string())
                        } else if invitations
                            .get(&code_hash)
                            .is_some_and(|existing| existing.peer_id != peer)
                        {
                            PairingResponse::Error("invite code collision; try again".to_string())
                        } else {
                            let direct_addresses = direct_addresses
                                .into_iter()
                                .filter_map(|address| sanitize_direct_address_text(&address))
                                .collect();
                            invitations.insert(
                                code_hash,
                                InviteRegistration {
                                    peer_id: peer,
                                    direct_addresses,
                                    expires_at_unix_secs,
                                },
                            );
                            PairingResponse::Registered
                        }
                    }
                    PairingRequest::ResolveInvite { code_hash } => {
                        match invitations.remove(&code_hash) {
                            Some(invite) if reserved_peers.contains(&invite.peer_id) => {
                                PairingResponse::Resolved {
                                    peer_id: invite.peer_id.to_string(),
                                    direct_addresses: invite.direct_addresses,
                                }
                            }
                            _ => PairingResponse::Error(
                                "Invite is invalid, expired, or already used.".to_string(),
                            ),
                        }
                    }
                    _ => PairingResponse::Error("unsupported service request".to_string()),
                };
                let _ = swarm
                    .behaviour_mut()
                    .rendezvous
                    .send_response(channel, response);
            }
            SwarmEvent::Behaviour(PublicServiceBehaviourEvent::Rendezvous(event)) => {
                debug_log(format!("rendezvous event: {event:?}"));
            }
            _ => {}
        }
    }
}

pub(super) async fn run_create_invite(profile_db: &Path) -> AppResult<()> {
    let profile_db = profile_db.to_path_buf();
    // Keep the composed libp2p state machine out of the inline #[tokio::main]
    // future. Its first poll can exhaust the smaller Windows main-thread stack.
    tokio::spawn(async move {
        let service_addr = configured_service_addr()?;
        run_create_invite_at(&profile_db, service_addr).await
    })
    .await?
}

async fn run_create_invite_at(profile_db: &Path, service_addr: Multiaddr) -> AppResult<()> {
    let local_display_name = load_or_prompt_display_name(profile_db)?;
    let mut bob = load_or_create_bob_identity(profile_db)?;
    let local_key = load_or_create_libp2p_identity(profile_db)?;
    let service_peer_id = peer_id_from_service_addr(&service_addr)?;
    let mut swarm = new_pairing_swarm(local_key)?;
    let direct_listener_pending = listen_for_direct_connections(&mut swarm)?;
    let mut relay_listener = swarm.listen_on(service_addr.clone().with(Protocol::P2pCircuit))?;
    debug_log("relay reservation request sent".to_string());

    let code = generate_invite_code()?;
    let code_hash = invite_code_hash(&code);
    let expires_at = now_unix_secs() + INVITE_TTL_SECS;
    let mut direct_addresses = Vec::<String>::new();
    let mut registered = false;
    let mut registration_sent = false;
    let mut reservation_confirmed = false;
    let mut direct_listener_ready = !direct_listener_pending;
    let setup_timeout = time::sleep(DISCOVERY_TIMEOUT);
    tokio::pin!(setup_timeout);
    let invite_timeout = time::sleep(Duration::from_secs(INVITE_TTL_SECS));
    tokio::pin!(invite_timeout);

    println!("Connecting...");

    loop {
        let event = tokio::select! {
            _ = &mut setup_timeout, if !registered => {
                return Err("Pairing service is unavailable. Please try again.".into());
            }
            _ = &mut invite_timeout, if registered => {
                return Err("Invite expired. Please create a new invite.".into());
            }
            event = swarm.select_next_some() => event,
        };
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                if !address.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                    if let Some(address) = direct_address_from_listener(&address) {
                        swarm.add_external_address(address.clone());
                        let rendered = address.to_string();
                        if !direct_addresses.contains(&rendered) {
                            direct_addresses.push(rendered);
                        }
                        direct_listener_ready = true;
                        if reservation_confirmed && !registration_sent {
                            send_invite_registration(
                                &mut swarm,
                                service_peer_id,
                                &code_hash,
                                expires_at,
                                &direct_addresses,
                            );
                            registration_sent = true;
                        }
                    }
                }
            }
            SwarmEvent::ListenerClosed { listener_id, .. } if listener_id == relay_listener => {
                debug_log("relay reservation listener closed; reconnecting".to_string());
                reservation_confirmed = false;
                registration_sent = false;
                if registered {
                    registered = false;
                    println!("Connecting...");
                }
                relay_listener =
                    swarm.listen_on(service_addr.clone().with(Protocol::P2pCircuit))?;
                debug_log("relay reservation request sent".to_string());
            }
            SwarmEvent::Behaviour(PairingBehaviourEvent::Relay(
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id,
                    renewal,
                    ..
                },
            )) if relay_peer_id == service_peer_id => {
                debug_log(if renewal {
                    "relay reservation renewed".to_string()
                } else {
                    "relay reservation accepted".to_string()
                });
                reservation_confirmed = true;
                if !registered && !registration_sent && !renewal && direct_listener_ready {
                    send_invite_registration(
                        &mut swarm,
                        service_peer_id,
                        &code_hash,
                        expires_at,
                        &direct_addresses,
                    );
                    registration_sent = true;
                }
            }
            SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                request_response::Event::Message {
                    peer,
                    message: request_response::Message::Response { response, .. },
                    ..
                },
            )) if peer == service_peer_id => match response {
                PairingResponse::Registered => {
                    if !registered {
                        registered = true;
                        debug_log("invite registered".to_string());
                        println!("Invite code: {code}");
                        println!("Waiting for your friend...");
                    }
                }
                PairingResponse::Error(error) => return Err(human_service_error(&error).into()),
                _ => {}
            },
            SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request, channel, ..
                        },
                    ..
                },
            )) if registered && peer != service_peer_id => match request {
                PairingRequest::PreKeyBundle => {
                    bob.replenish_one_time_prekey(now_unix_secs());
                    let payload = bincode::serialize(&ChatPreKeyBundle {
                        sender_display_name: local_display_name.clone(),
                        bundle: bob.prekey_bundle()?,
                    })?;
                    save_bob_identity(profile_db, &bob)?;
                    let _ = swarm
                        .behaviour_mut()
                        .app
                        .send_response(channel, PairingResponse::PreKeyBundle(payload));
                }
                PairingRequest::InitialMessage(payload) => {
                    let initial = decode_chat_initial_message(&payload)?;
                    let remote_display_name = initial.sender_display_name;
                    let plaintext = bob.decrypt_initial_message(&initial.message)?;
                    save_bob_identity(profile_db, &bob)?;
                    let conversation_id = initial
                        .sender_identity_public_key
                        .as_ref()
                        .map(contact_id_for_identity)
                        .unwrap_or_else(|| contact_id_for_display_name(&remote_display_name));
                    save_contact_for_chat(
                        profile_db,
                        &conversation_id,
                        &remote_display_name,
                        initial
                            .sender_identity_public_key
                            .as_ref()
                            .map(|key| key.as_slice())
                            .unwrap_or(b"legacy display-name contact"),
                        "automatic direct/relay",
                    )?;
                    if !plaintext.is_empty() {
                        persist_chat_message(
                            profile_db,
                            ChatHistoryEntry {
                                message_id: None,
                                conversation_id: &conversation_id,
                                sender_display_name: &remote_display_name,
                                peer_display_name: &local_display_name,
                                direction: MessageDirection::Received,
                                status: MessageStatus::Received,
                                protocol_counter: None,
                                ciphertext: &payload,
                                plaintext: &plaintext,
                            },
                        )?;
                    }
                    let _ = swarm
                        .behaviour_mut()
                        .app
                        .send_response(channel, PairingResponse::Ack("paired".to_string()));
                    println!(
                        "Connected to {}",
                        display_name_or_anonymous(&remote_display_name)
                    );
                    return run_pairing_chat(
                        swarm,
                        peer,
                        PairingChatRole::Bob(bob),
                        PairingChatContext {
                            local_display_name,
                            remote_display_name,
                            conversation_id,
                            db_path: profile_db.to_path_buf(),
                            service_addr,
                        },
                        Some(relay_listener),
                    )
                    .await;
                }
                _ => {
                    let _ = swarm.behaviour_mut().app.send_response(
                        channel,
                        PairingResponse::Error("pairing has not completed".to_string()),
                    );
                }
            },
            SwarmEvent::Behaviour(PairingBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                for (peer, address) in peers {
                    if let Some(address) = sanitize_direct_address(&address) {
                        swarm.add_peer_address(peer, address);
                    }
                }
            }
            SwarmEvent::Behaviour(PairingBehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) => add_sanitized_peer_addresses(&mut swarm, peer_id, info.listen_addrs),
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } if peer_id == service_peer_id => {
                debug_log("service connected".to_string());
                debug_log(if endpoint.is_relayed() {
                    "transport used: relay".to_string()
                } else {
                    "service control transport used: direct".to_string()
                });
            }
            SwarmEvent::ConnectionEstablished { endpoint, .. } => {
                debug_log(if endpoint.is_relayed() {
                    "transport used: relay".to_string()
                } else {
                    "transport used: direct".to_string()
                });
            }
            SwarmEvent::Behaviour(PairingBehaviourEvent::Dcutr(event)) => {
                debug_log(format!("DCUtR attempt: {event:?}"));
            }
            SwarmEvent::Behaviour(PairingBehaviourEvent::Relay(event)) => {
                debug_log(format!("relay client event: {event:?}"));
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                debug_log(format!("outgoing connection failed: {error}"));
            }
            _ => {}
        }
    }
}

pub(super) async fn run_join_invite(code: &str, profile_db: &Path) -> AppResult<()> {
    let normalized = normalize_invite_code(code)?;
    let profile_db = profile_db.to_path_buf();
    // Join uses the same libp2p behaviour, so keep it behind the same task
    // boundary even though Create Invite was the first path to expose the bug.
    tokio::spawn(async move {
        let service_addr = configured_service_addr()?;
        run_join_invite_at(&normalized, &profile_db, service_addr).await
    })
    .await?
}

async fn run_join_invite_at(
    code: &str,
    profile_db: &Path,
    service_addr: Multiaddr,
) -> AppResult<()> {
    let local_display_name = load_or_prompt_display_name(profile_db)?;
    let mut alice = load_or_create_alice_identity(profile_db)?;
    let local_key = load_or_create_libp2p_identity(profile_db)?;
    let service_peer_id = peer_id_from_service_addr(&service_addr)?;
    let mut swarm = new_pairing_swarm(local_key)?;
    let _ = listen_for_direct_connections(&mut swarm)?;
    swarm.dial(service_addr.clone())?;

    let code_hash = invite_code_hash(code);
    let mut lookup_sent = false;
    let mut target_peer_id = None::<PeerId>;
    let mut requested_bundle = false;
    let mut relay_started = false;
    let mut fallback_at = None::<time::Instant>;
    let pairing_timeout = time::sleep(DISCOVERY_TIMEOUT + DIRECT_DIAL_GRACE);
    tokio::pin!(pairing_timeout);

    println!("Connecting...");

    loop {
        tokio::select! {
            _ = &mut pairing_timeout => {
                return Err("Could not connect. Please create a new invite and try again.".into());
            }
            _ = async {
                match fallback_at {
                    Some(deadline) => time::sleep_until(deadline).await,
                    None => pending::<()>().await,
                }
            }, if !relay_started => {
                if let Some(target) = target_peer_id {
                    debug_log("relay fallback selected".to_string());
                    dial_target_through_relay(&mut swarm, &service_addr, target)?;
                    relay_started = true;
                    fallback_at = None;
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }
                    if peer_id == service_peer_id && !endpoint.is_relayed() && !lookup_sent =>
                {
                    debug_log("service connected".to_string());
                    swarm.behaviour_mut().app.send_request(
                        &service_peer_id,
                        PairingRequest::ResolveInvite { code_hash: code_hash.clone() },
                    );
                    lookup_sent = true;
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message: request_response::Message::Response { response, .. },
                        ..
                    },
                )) if peer == service_peer_id => match response {
                    PairingResponse::Resolved { peer_id, direct_addresses } => {
                        debug_log("invite resolved".to_string());
                        let target: PeerId = peer_id
                            .parse()
                            .map_err(|error| format!("service returned an invalid peer: {error}"))?;
                        target_peer_id = Some(target);
                        let mut has_direct = false;
                        for address in direct_addresses {
                            if let Some(address) = sanitize_direct_address_text(&address) {
                                let address: Multiaddr = address.parse()?;
                                swarm.add_peer_address(target, address);
                                has_direct = true;
                            }
                        }
                        if has_direct {
                            debug_log("direct connection attempt".to_string());
                            swarm.dial(DialOpts::peer_id(target).build())?;
                            fallback_at = Some(time::Instant::now() + DIRECT_DIAL_GRACE);
                        } else {
                            debug_log("relay fallback selected".to_string());
                            dial_target_through_relay(&mut swarm, &service_addr, target)?;
                            relay_started = true;
                        }
                    }
                    PairingResponse::Error(error) => return Err(human_service_error(&error).into()),
                    _ => {}
                },
                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }
                    if Some(peer_id) == target_peer_id =>
                {
                    debug_log(if endpoint.is_relayed() {
                        "transport used: relay".to_string()
                    } else {
                        "transport used: direct".to_string()
                    });
                    if endpoint.is_relayed() {
                        debug_log("DCUtR attempt started".to_string());
                    }
                    if !requested_bundle {
                        swarm
                            .behaviour_mut()
                            .app
                            .send_request(&peer_id, PairingRequest::PreKeyBundle);
                        requested_bundle = true;
                    }
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message: request_response::Message::Response { response, .. },
                        ..
                    },
                )) if Some(peer) == target_peer_id => match response {
                    PairingResponse::PreKeyBundle(payload) => {
                        let (remote_display_name, bundle) = decode_chat_prekey_bundle(&payload)?;
                        let conversation_id = contact_id_for_identity(&bundle.identity_public_key);
                        save_contact_for_chat(
                            profile_db,
                            &conversation_id,
                            &remote_display_name,
                            &bundle.identity_public_key,
                            "automatic direct/relay",
                        )?;
                        let initial = alice.encrypt_initial_message(&bundle, "")?;
                        save_alice_identity(profile_db, &alice)?;
                        let payload = bincode::serialize(&ChatInitialMessage {
                            sender_display_name: local_display_name.clone(),
                            sender_identity_public_key: Some(
                                alice.signed_key_exchange().identity_public_key,
                            ),
                            message: initial,
                        })?;
                        swarm
                            .behaviour_mut()
                            .app
                            .send_request(&peer, PairingRequest::InitialMessage(payload));
                        // Keep the established identity context until the ACK arrives.
                        let context = JoinContext { remote_display_name, conversation_id };
                        return wait_for_join_ack_and_chat(
                            swarm,
                            peer,
                            alice,
                            local_display_name,
                            context,
                            profile_db.to_path_buf(),
                            service_addr,
                        ).await;
                    }
                    PairingResponse::Error(error) => return Err(human_service_error(&error).into()),
                    _ => {}
                },
                SwarmEvent::Behaviour(PairingBehaviourEvent::Mdns(mdns::Event::Discovered(peers))) => {
                    for (peer, address) in peers {
                        if Some(peer) == target_peer_id {
                            if let Some(address) = sanitize_direct_address(&address) {
                                swarm.add_peer_address(peer, address);
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::Identify(
                    identify::Event::Received { peer_id, info, .. },
                )) => add_sanitized_peer_addresses(&mut swarm, peer_id, info.listen_addrs),
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. }
                    if peer_id == target_peer_id =>
                {
                    debug_log(format!("direct dial failed: {error}"));
                    if !relay_started {
                        if let Some(target) = target_peer_id {
                            debug_log("relay fallback selected".to_string());
                            dial_target_through_relay(&mut swarm, &service_addr, target)?;
                            relay_started = true;
                            fallback_at = None;
                        }
                    }
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::Dcutr(event)) => {
                    debug_log(format!("DCUtR attempt: {event:?}"));
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::Relay(event)) => {
                    debug_log(format!("relay client event: {event:?}"));
                }
                other => debug_log(format!("pairing event: {other:?}")),
            }
        }
    }
}

struct JoinContext {
    remote_display_name: String,
    conversation_id: String,
}

async fn wait_for_join_ack_and_chat(
    mut swarm: Swarm<PairingBehaviour>,
    target: PeerId,
    alice: Alice,
    local_display_name: String,
    context: JoinContext,
    db_path: PathBuf,
    service_addr: Multiaddr,
) -> AppResult<()> {
    let timeout = time::sleep(DISCOVERY_TIMEOUT);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = &mut timeout => return Err("Pairing timed out. Please create a new invite.".into()),
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message: request_response::Message::Response {
                            response: PairingResponse::Ack(_), ..
                        },
                        ..
                    },
                )) if peer == target => {
                    println!("Connected to {}", display_name_or_anonymous(&context.remote_display_name));
                    return run_pairing_chat(
                        swarm,
                        target,
                        PairingChatRole::Alice(alice),
                        PairingChatContext {
                            local_display_name,
                            remote_display_name: context.remote_display_name,
                            conversation_id: context.conversation_id,
                            db_path,
                            service_addr,
                        },
                        None,
                    ).await;
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::OutboundFailure { error, .. },
                )) => return Err(format!("Could not complete pairing: {error}").into()),
                _ => {}
            }
        }
    }
}

struct PairingChatContext {
    local_display_name: String,
    remote_display_name: String,
    conversation_id: String,
    db_path: PathBuf,
    service_addr: Multiaddr,
}

enum PairingChatRole {
    Alice(Alice),
    Bob(Bob),
}

impl PairingChatRole {
    fn prepare_frame(
        &mut self,
        context: &PairingChatContext,
        plaintext: &str,
    ) -> AppResult<(String, Vec<u8>)> {
        match self {
            Self::Alice(alice) => prepare_alice_frame(
                alice,
                &context.local_display_name,
                &context.remote_display_name,
                &context.conversation_id,
                &context.db_path,
                plaintext,
                None,
            ),
            Self::Bob(bob) => prepare_bob_frame(
                bob,
                &context.local_display_name,
                &context.remote_display_name,
                &context.conversation_id,
                &context.db_path,
                plaintext,
                None,
            ),
        }
    }

    fn send_pending(
        &mut self,
        swarm: &mut Swarm<PairingBehaviour>,
        target: PeerId,
        context: &PairingChatContext,
    ) -> AppResult<()> {
        match self {
            Self::Alice(alice) => send_pending_as_alice(
                swarm,
                target,
                alice,
                &context.local_display_name,
                &context.conversation_id,
                &context.db_path,
            ),
            Self::Bob(bob) => send_pending_as_bob(
                swarm,
                target,
                bob,
                &context.local_display_name,
                &context.conversation_id,
                &context.db_path,
            ),
        }
    }

    fn handle_app_event(
        &mut self,
        swarm: &mut Swarm<PairingBehaviour>,
        target: PeerId,
        context: &PairingChatContext,
        terminal: &mut ChatTerminal,
        event: request_response::Event<PairingRequest, PairingResponse>,
    ) -> AppResult<()> {
        match self {
            Self::Alice(alice) => handle_alice_app_event(
                swarm,
                target,
                alice,
                &context.local_display_name,
                &context.remote_display_name,
                &context.conversation_id,
                &context.db_path,
                terminal,
                event,
            ),
            Self::Bob(bob) => handle_bob_pairing_app_event(
                swarm,
                target,
                bob,
                &context.local_display_name,
                &context.remote_display_name,
                &context.conversation_id,
                &context.db_path,
                terminal,
                event,
            ),
        }
    }
}

async fn run_pairing_chat(
    mut swarm: Swarm<PairingBehaviour>,
    target: PeerId,
    mut role: PairingChatRole,
    context: PairingChatContext,
    mut relay_listener: Option<ListenerId>,
) -> AppResult<()> {
    role.send_pending(&mut swarm, target, &context)?;
    print_conversation_history(
        &context.db_path,
        &context.conversation_id,
        &context.remote_display_name,
    )?;
    let mut terminal = spawn_line_editor()?;
    let mut online = true;
    let mut reconnect = time::interval(CHAT_RECONNECT_INTERVAL);
    reconnect.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    reconnect.tick().await;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = reconnect.tick(), if !online => {
                try_reconnect_through_relay(&mut swarm, &context.service_addr, target);
            }
            line = terminal.lines.recv() => {
                let Some(line) = line else { return Ok(()); };
                if is_chat_back_command(&line) { return Ok(()); }
                if line.is_empty() { continue; }
                if !online {
                    queue_message_after_peer_disconnect(
                        &context.db_path,
                        &context.conversation_id,
                        &context.remote_display_name,
                        &line,
                    )?;
                    continue;
                }
                let (message_id, bytes) = role.prepare_frame(&context, &line)?;
                track_pending_chat_delivery(
                    &context.db_path,
                    &context.conversation_id,
                    &message_id,
                    &line,
                )?;
                swarm.behaviour_mut().app.send_request(&target, PairingRequest::ChatFrame(bytes));
                debug_log(format!("sent encrypted chat frame {message_id}"));
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(event)) => {
                    role.handle_app_event(&mut swarm, target, &context, &mut terminal, event)?;
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == target => {
                    if !online {
                        online = true;
                        handle_peer_reconnected(&context.remote_display_name);
                        role.send_pending(&mut swarm, target, &context)?;
                    }
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established, cause, .. }
                    if peer_id == target => {
                    debug_log(format!(
                        "chat connection closed; {num_established} connection(s) remain: {cause:?}"
                    ));
                    if peer_lost_all_connections(peer_id, target, num_established) {
                        if online {
                            online = false;
                            handle_peer_disconnected(&context.remote_display_name);
                        }
                        try_reconnect_through_relay(&mut swarm, &context.service_addr, target);
                    }
                }
                SwarmEvent::ListenerClosed { listener_id, .. }
                    if relay_listener == Some(listener_id) => {
                    debug_log("relay reservation listener closed; reconnecting".to_string());
                    relay_listener = Some(swarm.listen_on(
                        context.service_addr.clone().with(Protocol::P2pCircuit)
                    )?);
                    debug_log("relay reservation request sent".to_string());
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::Relay(
                    relay::client::Event::ReservationReqAccepted { relay_peer_id, renewal, .. }
                )) => {
                    debug_log(if renewal {
                        format!("relay reservation renewed by {relay_peer_id}")
                    } else {
                        format!("relay reservation accepted by {relay_peer_id}")
                    });
                    if !online {
                        try_reconnect_through_relay(&mut swarm, &context.service_addr, target);
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id: Some(peer_id), error, .. }
                    if peer_id == target => debug_log(format!("chat reconnect failed: {error}")),
                SwarmEvent::Behaviour(PairingBehaviourEvent::Dcutr(event)) => debug_log(format!("hole punch event: {event:?}")),
                _ => {}
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_alice_app_event(
    swarm: &mut Swarm<PairingBehaviour>,
    target: PeerId,
    alice: &mut Alice,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    terminal: &mut ChatTerminal,
    event: request_response::Event<PairingRequest, PairingResponse>,
) -> AppResult<()> {
    match event {
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request: PairingRequest::ChatFrame(bytes),
                    channel,
                    ..
                },
            ..
        } if peer == target => {
            let frame: ChatFrame = bincode::deserialize(&bytes)?;
            let ChatFrame::Message {
                message_id,
                sender_display_name,
                message,
            } = frame
            else {
                return Ok(());
            };
            if !chat_message_already_saved(db_path, &message_id)? {
                let plaintext = alice.decrypt_from_bob(&message)?;
                save_alice_identity(db_path, alice)?;
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
                        ciphertext: &bytes,
                        plaintext: &plaintext,
                    },
                )?;
                mark_incoming_chat_message_accepted(db_path, &message_id)?;
                terminal.print_message(
                    remote_sender_label(&sender_display_name, remote_display_name),
                    &plaintext,
                )?;
            }
            let _ = swarm
                .behaviour_mut()
                .app
                .send_response(channel, PairingResponse::Ack(message_id));
        }
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Response {
                    response: PairingResponse::Ack(message_id),
                    ..
                },
            ..
        } if peer == target => mark_delivered_if_pending(db_path, &message_id)?,
        request_response::Event::OutboundFailure { peer, error, .. } if peer == target => {
            debug_log(format!("chat delivery failed: {error}"));
        }
        _ => {}
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_bob_pairing_app_event(
    swarm: &mut Swarm<PairingBehaviour>,
    target: PeerId,
    bob: &mut Bob,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    terminal: &mut ChatTerminal,
    event: request_response::Event<PairingRequest, PairingResponse>,
) -> AppResult<()> {
    match event {
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request: PairingRequest::ChatFrame(bytes),
                    channel,
                    ..
                },
            ..
        } if peer == target => {
            let frame: ChatFrame = bincode::deserialize(&bytes)?;
            let ChatFrame::Message {
                message_id,
                sender_display_name,
                message,
            } = frame
            else {
                return Ok(());
            };
            if !chat_message_already_saved(db_path, &message_id)? {
                let plaintext = bob.decrypt_from_alice(&message)?;
                save_bob_identity(db_path, bob)?;
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
                        ciphertext: &bytes,
                        plaintext: &plaintext,
                    },
                )?;
                mark_incoming_chat_message_accepted(db_path, &message_id)?;
                terminal.print_message(
                    remote_sender_label(&sender_display_name, remote_display_name),
                    &plaintext,
                )?;
            }
            let _ = swarm
                .behaviour_mut()
                .app
                .send_response(channel, PairingResponse::Ack(message_id));
        }
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Response {
                    response: PairingResponse::Ack(message_id),
                    ..
                },
            ..
        } if peer == target => mark_delivered_if_pending(db_path, &message_id)?,
        request_response::Event::OutboundFailure { peer, error, .. } if peer == target => {
            debug_log(format!("chat delivery failed: {error}"));
        }
        _ => {}
    }
    Ok(())
}

fn prepare_alice_frame(
    alice: &mut Alice,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    plaintext: &str,
    existing_message_id: Option<String>,
) -> AppResult<(String, Vec<u8>)> {
    let message = alice.encrypt_for_bob(plaintext)?;
    save_alice_identity(db_path, alice)?;
    prepare_outgoing_frame(
        message,
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path,
        plaintext,
        existing_message_id,
    )
}

fn prepare_bob_frame(
    bob: &mut Bob,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    plaintext: &str,
    existing_message_id: Option<String>,
) -> AppResult<(String, Vec<u8>)> {
    let message = bob.encrypt_for_alice(plaintext)?;
    save_bob_identity(db_path, bob)?;
    prepare_outgoing_frame(
        message,
        local_display_name,
        remote_display_name,
        conversation_id,
        db_path,
        plaintext,
        existing_message_id,
    )
}

fn prepare_outgoing_frame(
    message: RatchetMessage,
    local_display_name: &str,
    remote_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
    plaintext: &str,
    existing_message_id: Option<String>,
) -> AppResult<(String, Vec<u8>)> {
    let message_bytes = bincode::serialize(&message)?;
    let message_id = existing_message_id.unwrap_or_else(|| {
        chat_message_id(
            conversation_id,
            &MessageDirection::Sent,
            Some(message.number),
            &message_bytes,
        )
    });
    let bytes = bincode::serialize(&ChatFrame::Message {
        message_id: message_id.clone(),
        sender_display_name: local_display_name.to_string(),
        message,
    })?;
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
            ciphertext: &bytes,
            plaintext,
        },
    )?;
    Ok((message_id, bytes))
}

fn track_pending_chat_delivery(
    db_path: &Path,
    conversation_id: &str,
    message_id: &str,
    plaintext: &str,
) -> AppResult<()> {
    let peer_id = pending_peer_id_for_conversation(db_path, conversation_id)?;
    Storage::open(db_path)?.queue_pending_peer_message(&PendingPeerMessage {
        message_id: message_id.to_string(),
        peer_id,
        conversation_id: conversation_id.to_string(),
        plaintext: plaintext.to_string(),
        created_at_unix_secs: now_unix_secs(),
        retry_count: 0,
        last_attempt_unix_secs: None,
    })?;
    Ok(())
}

fn send_pending_as_alice(
    swarm: &mut Swarm<PairingBehaviour>,
    target: PeerId,
    alice: &mut Alice,
    local_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
) -> AppResult<()> {
    let pending = Storage::open(db_path)?.pending_peer_messages_for_peer(conversation_id)?;
    for item in pending {
        Storage::open(db_path)?.record_pending_peer_message_attempt(&item.message_id)?;
        let (_, bytes) = prepare_alice_frame(
            alice,
            local_display_name,
            "peer",
            conversation_id,
            db_path,
            &item.plaintext,
            Some(item.message_id),
        )?;
        swarm
            .behaviour_mut()
            .app
            .send_request(&target, PairingRequest::ChatFrame(bytes));
    }
    Ok(())
}

fn send_pending_as_bob(
    swarm: &mut Swarm<PairingBehaviour>,
    target: PeerId,
    bob: &mut Bob,
    local_display_name: &str,
    conversation_id: &str,
    db_path: &Path,
) -> AppResult<()> {
    let pending = Storage::open(db_path)?.pending_peer_messages_for_peer(conversation_id)?;
    for item in pending {
        Storage::open(db_path)?.record_pending_peer_message_attempt(&item.message_id)?;
        let (_, bytes) = prepare_bob_frame(
            bob,
            local_display_name,
            "peer",
            conversation_id,
            db_path,
            &item.plaintext,
            Some(item.message_id),
        )?;
        swarm
            .behaviour_mut()
            .app
            .send_request(&target, PairingRequest::ChatFrame(bytes));
    }
    Ok(())
}

fn mark_delivered_if_pending(db_path: &Path, message_id: &str) -> AppResult<()> {
    let storage = Storage::open(db_path)?;
    storage.remove_pending_peer_message(message_id)?;
    storage.update_message_status(message_id, MessageStatus::Sent)?;
    Ok(())
}

fn new_pairing_swarm(key: identity::Keypair) -> AppResult<Swarm<PairingBehaviour>> {
    let local_peer_id = PeerId::from(key.public());
    Ok(SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_dns()?
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
        .with_behaviour(move |key, relay| {
            Ok(PairingBehaviour {
                app: request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new(PAIRING_PROTOCOL),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default().with_request_timeout(DISCOVERY_TIMEOUT),
                ),
                autonat: autonat::Behaviour::new(local_peer_id, autonat::Config::default()),
                dcutr: dcutr::Behaviour::new(local_peer_id),
                identify: identify::Behaviour::new(identify::Config::new(
                    PAIRING_PROTOCOL.to_string(),
                    key.public(),
                )),
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
                relay,
            })
        })?
        .with_swarm_config(|config| {
            config.with_idle_connection_timeout(CHAT_IDLE_CONNECTION_TIMEOUT)
        })
        .build())
}

fn new_public_service_swarm(key: identity::Keypair) -> AppResult<Swarm<PublicServiceBehaviour>> {
    let local_peer_id = PeerId::from(key.public());
    Ok(SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_dns()?
        .with_behaviour(move |key| {
            Ok(PublicServiceBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    PAIRING_PROTOCOL.to_string(),
                    key.public(),
                )),
                relay: relay::Behaviour::new(local_peer_id, relay::Config::default()),
                rendezvous: request_response::cbor::Behaviour::new(
                    [(
                        StreamProtocol::new(PAIRING_PROTOCOL),
                        request_response::ProtocolSupport::Full,
                    )],
                    request_response::Config::default().with_request_timeout(DISCOVERY_TIMEOUT),
                ),
            })
        })?
        .build())
}

fn load_or_create_libp2p_identity(db_path: &Path) -> AppResult<identity::Keypair> {
    let storage = Storage::open(db_path)?;
    if let Some(bytes) = storage.load_local_identity(LIBP2P_IDENTITY_SLOT)? {
        return Ok(identity::Keypair::from_protobuf_encoding(&bytes)?);
    }
    let key = identity::Keypair::generate_ed25519();
    storage.save_local_identity(LIBP2P_IDENTITY_SLOT, "libp2p", &key.to_protobuf_encoding()?)?;
    Ok(key)
}

fn load_or_create_service_identity(path: &Path) -> AppResult<identity::Keypair> {
    match std::fs::read(path) {
        Ok(bytes) => return Ok(identity::Keypair::from_protobuf_encoding(&bytes)?),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && path == Path::new(DEFAULT_SERVICE_IDENTITY_PATH) =>
        {
            return Err(format!(
                "canonical service identity is missing at {}; restore the permanent key instead of generating a new identity",
                path.display()
            )
            .into())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "could not read service identity {}: {error}",
                path.display()
            )
            .into())
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let key = identity::Keypair::generate_ed25519();
    std::fs::write(path, key.to_protobuf_encoding()?)?;
    Ok(key)
}

fn configured_service_addr() -> AppResult<Multiaddr> {
    let value = std::env::var(PAIRING_SERVICE_ENV)
        .unwrap_or_else(|_| DEFAULT_PAIRING_SERVICE_ADDR.to_string());
    let address: Multiaddr = value
        .parse()
        .map_err(|error| format!("CipherMesh pairing service configuration is invalid: {error}"))?;
    peer_id_from_service_addr(&address)?;
    if !service_address_is_public(&address) {
        return Err("CipherMesh pairing service must use a publicly reachable address.".into());
    }
    Ok(address)
}

fn peer_id_from_service_addr(address: &Multiaddr) -> AppResult<PeerId> {
    strip_p2p(address)
        .1
        .ok_or_else(|| "CipherMesh pairing service configuration is incomplete.".into())
}

fn service_address_is_public(address: &Multiaddr) -> bool {
    address.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_documentation()
        }
        Protocol::Ip6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        }
        Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => true,
        _ => false,
    })
}

fn direct_address_from_listener(address: &Multiaddr) -> Option<Multiaddr> {
    let mut result = Multiaddr::empty();
    let mut has_ip = false;
    let mut has_tcp = false;
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(ip) if ip.is_unspecified() => {
                let IpAddr::V4(lan) = lan_ip_candidate()? else {
                    return None;
                };
                result.push(Protocol::Ip4(lan));
                has_ip = true;
            }
            Protocol::Ip6(ip) if ip.is_unspecified() => return None,
            Protocol::Ip4(ip) if is_usable_remote_ip(IpAddr::V4(ip)) => {
                result.push(Protocol::Ip4(ip));
                has_ip = true;
            }
            Protocol::Ip6(ip) if is_usable_remote_ip(IpAddr::V6(ip)) => {
                result.push(Protocol::Ip6(ip));
                has_ip = true;
            }
            Protocol::Tcp(port) => {
                result.push(Protocol::Tcp(port));
                has_tcp = true;
            }
            _ => {}
        }
    }
    (has_ip && has_tcp).then_some(result)
}

fn sanitize_direct_address_text(address: &str) -> Option<String> {
    let parsed: Multiaddr = address.parse().ok()?;
    sanitize_direct_address(&parsed).map(|address| address.to_string())
}

fn sanitize_direct_address(address: &Multiaddr) -> Option<Multiaddr> {
    if address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return None;
    }
    let mut has_usable_ip = false;
    let mut has_transport = false;
    let mut sanitized = Multiaddr::empty();
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(ip) if is_dialable_peer_ip(IpAddr::V4(ip)) => {
                has_usable_ip = true;
                sanitized.push(Protocol::Ip4(ip));
            }
            Protocol::Ip6(ip) if is_dialable_peer_ip(IpAddr::V6(ip)) => {
                has_usable_ip = true;
                sanitized.push(Protocol::Ip6(ip));
            }
            Protocol::Tcp(port) => {
                has_transport = true;
                sanitized.push(Protocol::Tcp(port));
            }
            _ => {}
        }
    }
    (has_usable_ip && has_transport).then_some(sanitized)
}

fn listen_for_direct_connections(swarm: &mut Swarm<PairingBehaviour>) -> AppResult<bool> {
    let Some(ip) = lan_ip_candidate() else {
        return Ok(false);
    };
    let address: Multiaddr = match ip {
        IpAddr::V4(ip) => format!("/ip4/{ip}/tcp/0").parse()?,
        IpAddr::V6(ip) => format!("/ip6/{ip}/tcp/0").parse()?,
    };
    swarm.listen_on(address)?;
    Ok(true)
}

fn send_invite_registration(
    swarm: &mut Swarm<PairingBehaviour>,
    service_peer_id: PeerId,
    code_hash: &str,
    expires_at_unix_secs: u64,
    direct_addresses: &[String],
) {
    swarm.behaviour_mut().app.send_request(
        &service_peer_id,
        PairingRequest::RegisterInvite {
            code_hash: code_hash.to_string(),
            expires_at_unix_secs,
            direct_addresses: direct_addresses.to_vec(),
        },
    );
}

fn is_dialable_peer_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        }
    }
}

fn add_sanitized_peer_addresses(
    swarm: &mut Swarm<PairingBehaviour>,
    peer: PeerId,
    addresses: Vec<Multiaddr>,
) {
    for address in addresses {
        if let Some(address) = sanitize_direct_address(&address) {
            swarm.add_peer_address(peer, address);
        }
    }
}

fn dial_target_through_relay(
    swarm: &mut Swarm<PairingBehaviour>,
    service_addr: &Multiaddr,
    target: PeerId,
) -> AppResult<()> {
    let address = service_addr
        .clone()
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(target));
    swarm.dial(address)?;
    Ok(())
}

fn try_reconnect_through_relay(
    swarm: &mut Swarm<PairingBehaviour>,
    service_addr: &Multiaddr,
    target: PeerId,
) {
    if swarm.is_connected(&target) {
        return;
    }
    let relay_address = service_addr
        .clone()
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(target));
    let options = DialOpts::peer_id(target)
        .addresses(vec![relay_address])
        .extend_addresses_through_behaviour()
        .build();
    match swarm.dial(options) {
        Ok(()) => debug_log(format!("background reconnect started for {target}")),
        Err(error) => debug_log(format!(
            "background reconnect deferred for {target}: {error}"
        )),
    }
}

fn peer_lost_all_connections(peer_id: PeerId, target: PeerId, num_established: u32) -> bool {
    peer_id == target && num_established == 0
}

fn handle_peer_reconnected(display_name: &str) {
    println!();
    println!("{} reconnected.", display_name_or_anonymous(display_name));
    println!("Status: Online");
    println!("Queued messages are being sent.");
    println!();
}

fn human_service_error(error: &str) -> String {
    debug_log(format!("pairing service error: {error}"));
    if error.contains("invalid") || error.contains("expired") || error.contains("used") {
        "Invite is invalid, expired, or already used.".to_string()
    } else {
        "Pairing service is temporarily unavailable. Please try again.".to_string()
    }
}

fn debug_log(message: String) {
    if env_verbose_enabled() {
        eprintln!("[network] {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_create_invite_startup_future_is_stack_bounded() {
        let path = Path::new("future-size.sqlite");
        let future = run_create_invite(path);
        assert!(
            std::mem::size_of_val(&future) <= 1024,
            "normal Create Invite must keep its network state machine behind a task boundary"
        );
    }

    #[test]
    fn chat_marks_offline_only_after_the_targets_last_connection_closes() {
        let target = PeerId::random();
        let other = PeerId::random();

        assert!(!peer_lost_all_connections(target, target, 1));
        assert!(!peer_lost_all_connections(other, target, 0));
        assert!(peer_lost_all_connections(target, target, 0));
    }

    #[test]
    fn active_chat_connections_do_not_expire_for_inactivity() {
        assert_eq!(CHAT_IDLE_CONNECTION_TIMEOUT, Duration::MAX);
    }

    #[test]
    fn chat_delivery_stays_queued_until_acknowledged() {
        let path = pairing_temp_db("pending-chat-delivery");
        track_pending_chat_delivery(&path, "conversation", "message-1", "hello").unwrap();

        let storage = Storage::open(&path).unwrap();
        assert_eq!(
            storage
                .pending_peer_messages_for_peer("conversation")
                .unwrap()
                .len(),
            1
        );
        mark_delivered_if_pending(&path, "message-1").unwrap();
        assert!(storage
            .pending_peer_messages_for_peer("conversation")
            .unwrap()
            .is_empty());
        drop(storage);
        let _ = std::fs::remove_file(path);
    }

    fn pairing_temp_db(name: &str) -> PathBuf {
        let mut random = [0u8; 8];
        fill_random(&mut random).unwrap();
        std::env::temp_dir().join(format!("ciphermesh-{name}-{}.sqlite", hex_encode(&random)))
    }

    #[test]
    fn persistent_libp2p_identity_keeps_peer_id() {
        let path = pairing_temp_db("persistent-libp2p");
        let first = PeerId::from(load_or_create_libp2p_identity(&path).unwrap().public());
        let second = PeerId::from(load_or_create_libp2p_identity(&path).unwrap().public());
        assert_eq!(first, second);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persistent_service_identity_keeps_peer_id() {
        let path = std::env::temp_dir().join(format!(
            "ciphermesh-service-identity-{}.key",
            PeerId::random()
        ));
        let first = PeerId::from(load_or_create_service_identity(&path).unwrap().public());
        let second = PeerId::from(load_or_create_service_identity(&path).unwrap().public());
        assert_eq!(first, second);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn built_in_service_endpoint_is_the_public_oracle_service() {
        let address: Multiaddr = DEFAULT_PAIRING_SERVICE_ADDR.parse().unwrap();
        assert!(service_address_is_public(&address));
        assert_eq!(
            peer_id_from_service_addr(&address).unwrap().to_string(),
            DEFAULT_PAIRING_SERVICE_PEER_ID
        );
    }

    #[test]
    fn production_service_identity_path_is_absolute_and_canonical() {
        assert_eq!(
            DEFAULT_SERVICE_IDENTITY_PATH,
            "/var/lib/ciphermesh/service.key"
        );
        assert!(DEFAULT_SERVICE_IDENTITY_PATH.starts_with('/'));
    }

    #[test]
    fn wildcard_and_loopback_addresses_are_never_dialable() {
        for address in [
            "/ip4/0.0.0.0/tcp/5000",
            "/ip4/127.0.0.1/tcp/5000",
            "/ip6/::/tcp/5000",
            "/ip6/::1/tcp/5000",
        ] {
            assert!(sanitize_direct_address_text(address).is_none());
        }
        assert_eq!(
            sanitize_direct_address_text("/ip4/192.168.1.20/tcp/5000").as_deref(),
            Some("/ip4/192.168.1.20/tcp/5000")
        );
        let relay_peer = PeerId::random();
        let target_peer = PeerId::random();
        assert!(sanitize_direct_address_text(&format!(
            "/ip4/192.168.1.20/tcp/4001/p2p/{relay_peer}/p2p-circuit/p2p/{target_peer}"
        ))
        .is_none());
    }

    #[test]
    fn private_service_addresses_are_rejected() {
        let peer = PeerId::random();
        let private: Multiaddr = format!("/ip4/10.197.119.208/tcp/4001/p2p/{peer}")
            .parse()
            .unwrap();
        assert!(!service_address_is_public(&private));
        let public: Multiaddr = format!("/ip4/8.8.8.8/tcp/4001/p2p/{peer}").parse().unwrap();
        assert!(service_address_is_public(&public));
    }

    #[test]
    fn invite_code_is_the_only_user_facing_invite_value() {
        let code = generate_invite_code().unwrap();
        assert_eq!(code.len(), 6);
        assert!(!code.contains('.'));
        assert!(!code.contains('/'));
        assert!(!code.contains(':'));
    }

    #[tokio::test]
    async fn public_service_registers_only_after_reservation_and_relays_one_time_invite() {
        time::timeout(Duration::from_secs(20), pairing_service_relay_smoke())
            .await
            .expect("pairing smoke timed out")
            .expect("pairing smoke failed");
    }

    async fn pairing_service_relay_smoke() -> AppResult<()> {
        let service_key = identity::Keypair::generate_ed25519();
        let service_peer = PeerId::from(service_key.public());
        let mut service = new_public_service_swarm(service_key)?;
        service.listen_on("/ip4/127.0.0.1/tcp/0".parse()?)?;
        let service_listen = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = service.select_next_some().await {
                break address;
            }
        };
        service.add_external_address(service_listen.clone());
        let service_addr = service_listen.with(Protocol::P2p(service_peer));
        let service_task = tokio::spawn(run_public_service_swarm(service, service_peer));

        let host_key = identity::Keypair::generate_ed25519();
        let host_peer = PeerId::from(host_key.public());
        let mut host = new_pairing_swarm(host_key)?;
        host.listen_on(service_addr.clone().with(Protocol::P2pCircuit))?;
        let code_hash = invite_code_hash("5UYERM");
        let mut registration_sent = false;
        loop {
            match host.select_next_some().await {
                SwarmEvent::Behaviour(PairingBehaviourEvent::Relay(
                    relay::client::Event::ReservationReqAccepted {
                        relay_peer_id,
                        renewal: false,
                        ..
                    },
                )) if relay_peer_id == service_peer => {
                    host.behaviour_mut().app.send_request(
                        &service_peer,
                        PairingRequest::RegisterInvite {
                            code_hash: code_hash.clone(),
                            expires_at_unix_secs: now_unix_secs() + INVITE_TTL_SECS,
                            direct_addresses: vec![
                                "/ip4/0.0.0.0/tcp/5000".to_string(),
                                "/ip4/127.0.0.1/tcp/5000".to_string(),
                            ],
                        },
                    );
                    registration_sent = true;
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                response: PairingResponse::Registered,
                                ..
                            },
                        ..
                    },
                )) if peer == service_peer && registration_sent => break,
                _ => {}
            }
        }

        let host_db = pairing_temp_db("relay-chat-history");
        let host_db_for_task = host_db.clone();
        let (plaintext_tx, plaintext_rx) = tokio::sync::oneshot::channel::<Vec<String>>();
        let host_task = tokio::spawn(async move {
            let mut bob = Bob::local();
            let mut delivered_plaintexts = Vec::<String>::new();
            let mut plaintext_tx = Some(plaintext_tx);
            loop {
                match host.select_next_some().await {
                    SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                        request_response::Event::Message {
                            message:
                                request_response::Message::Request {
                                    request, channel, ..
                                },
                            ..
                        },
                    )) => match request {
                        PairingRequest::PreKeyBundle => {
                            let payload = bincode::serialize(&ChatPreKeyBundle {
                                sender_display_name: "Mac".to_string(),
                                bundle: bob.prekey_bundle()?,
                            })?;
                            let _ = host
                                .behaviour_mut()
                                .app
                                .send_response(channel, PairingResponse::PreKeyBundle(payload));
                        }
                        PairingRequest::InitialMessage(payload) => {
                            let initial = decode_chat_initial_message(&payload)?;
                            bob.decrypt_initial_message(&initial.message)?;
                            let _ = host
                                .behaviour_mut()
                                .app
                                .send_response(channel, PairingResponse::Ack("paired".to_string()));
                        }
                        PairingRequest::ChatFrame(payload) => {
                            let ChatFrame::Message {
                                message_id,
                                sender_display_name,
                                message,
                            } = bincode::deserialize(&payload)?
                            else {
                                return Err::<(), Box<dyn Error + Send + Sync>>(
                                    "unexpected ACK frame".into(),
                                );
                            };
                            let plaintext = bob.decrypt_from_alice(&message)?;
                            persist_chat_message(
                                &host_db_for_task,
                                ChatHistoryEntry {
                                    message_id: Some(message_id.clone()),
                                    conversation_id: "relay-smoke",
                                    sender_display_name: &sender_display_name,
                                    peer_display_name: "Mac",
                                    direction: MessageDirection::Received,
                                    status: MessageStatus::Received,
                                    protocol_counter: Some(message.number),
                                    ciphertext: &payload,
                                    plaintext: &plaintext,
                                },
                            )?;
                            let _ = host
                                .behaviour_mut()
                                .app
                                .send_response(channel, PairingResponse::Ack(message_id));
                            delivered_plaintexts.push(plaintext);
                        }
                        _ => {}
                    },
                    SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                        request_response::Event::ResponseSent { .. },
                    )) if delivered_plaintexts.len() == 2 => {
                        if let Some(tx) = plaintext_tx.take() {
                            let _ = tx.send(delivered_plaintexts.clone());
                        }
                    }
                    _ => {}
                }
            }
        });

        let join_key = identity::Keypair::generate_ed25519();
        let mut join = new_pairing_swarm(join_key)?;
        join.dial(service_addr.clone())?;
        let mut alice = Alice::local();
        let mut lookup_sent = false;
        let mut second_lookup_rejected = false;
        let chat_messages = ["hello across networks", "another message"];
        let expected_message_ids = ["relay-smoke-message-1", "relay-smoke-message-2"];
        let mut chat_messages_sent = 0usize;
        let mut chat_acks = 0usize;

        loop {
            match join.select_next_some().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. }
                    if peer_id == service_peer && !lookup_sent =>
                {
                    join.behaviour_mut().app.send_request(
                        &service_peer,
                        PairingRequest::ResolveInvite {
                            code_hash: code_hash.clone(),
                        },
                    );
                    lookup_sent = true;
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                response:
                                    PairingResponse::Resolved {
                                        peer_id,
                                        direct_addresses,
                                    },
                                ..
                            },
                        ..
                    },
                )) if peer == service_peer => {
                    assert_eq!(peer_id, host_peer.to_string());
                    assert!(direct_addresses.is_empty());
                    join.behaviour_mut().app.send_request(
                        &service_peer,
                        PairingRequest::ResolveInvite {
                            code_hash: code_hash.clone(),
                        },
                    );
                    dial_target_through_relay(&mut join, &service_addr, host_peer)?;
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                response: PairingResponse::Error(_),
                                ..
                            },
                        ..
                    },
                )) if peer == service_peer => second_lookup_rejected = true,
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == host_peer => {
                    join.behaviour_mut()
                        .app
                        .send_request(&host_peer, PairingRequest::PreKeyBundle);
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                response: PairingResponse::PreKeyBundle(payload),
                                ..
                            },
                        ..
                    },
                )) if peer == host_peer => {
                    let (_, bundle) = decode_chat_prekey_bundle(&payload)?;
                    let initial = alice.encrypt_initial_message(&bundle, "")?;
                    let payload = bincode::serialize(&ChatInitialMessage {
                        sender_display_name: "Windows".to_string(),
                        sender_identity_public_key: Some(
                            alice.signed_key_exchange().identity_public_key,
                        ),
                        message: initial,
                    })?;
                    join.behaviour_mut()
                        .app
                        .send_request(&host_peer, PairingRequest::InitialMessage(payload));
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                response: PairingResponse::Ack(message_id),
                                ..
                            },
                        ..
                    },
                )) if peer == host_peer && message_id == "paired" && chat_messages_sent == 0 => {
                    let message = alice.encrypt_for_bob(chat_messages[0])?;
                    let payload = bincode::serialize(&ChatFrame::Message {
                        message_id: expected_message_ids[0].to_string(),
                        sender_display_name: "Windows".to_string(),
                        message,
                    })?;
                    join.behaviour_mut()
                        .app
                        .send_request(&host_peer, PairingRequest::ChatFrame(payload));
                    chat_messages_sent = 1;
                }
                SwarmEvent::Behaviour(PairingBehaviourEvent::App(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                response: PairingResponse::Ack(message_id),
                                ..
                            },
                        ..
                    },
                )) if peer == host_peer
                    && chat_messages_sent > 0
                    && message_id == expected_message_ids[chat_acks] =>
                {
                    chat_acks += 1;
                    if chat_acks < chat_messages.len() {
                        let message = alice.encrypt_for_bob(chat_messages[chat_acks])?;
                        let payload = bincode::serialize(&ChatFrame::Message {
                            message_id: expected_message_ids[chat_acks].to_string(),
                            sender_display_name: "Windows".to_string(),
                            message,
                        })?;
                        join.behaviour_mut()
                            .app
                            .send_request(&host_peer, PairingRequest::ChatFrame(payload));
                        chat_messages_sent += 1;
                    } else if second_lookup_rejected {
                        break;
                    }
                }
                other => debug_log(format!("smoke join event: {other:?}")),
            }
        }

        assert_eq!(plaintext_rx.await?, chat_messages);
        let history = Storage::open(&host_db)?.messages_for_conversation("relay-smoke")?;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].plaintext.as_deref(), Some(chat_messages[0]));
        assert_eq!(history[1].plaintext.as_deref(), Some(chat_messages[1]));
        host_task.abort();
        service_task.abort();
        let _ = std::fs::remove_file(host_db);
        Ok(())
    }
}
