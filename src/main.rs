use ciphermesh::{Alice, Bob, InitialMessage, PreKeyBundle, SimulatedDirectory};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rcgen::generate_simple_self_signed;
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

type AppResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main]
async fn main() -> AppResult<()> {
    let args = std::env::args().collect::<Vec<_>>();

    match args.get(1).map(String::as_str) {
        Some("bob") => {
            let listen_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            run_bob(listen_addr).await
        }
        Some("alice") => {
            let bob_addr = parse_addr(args.get(2), "127.0.0.1:5000")?;
            let message = args
                .get(3)
                .map(String::as_str)
                .unwrap_or("hello bob over quic");
            run_alice(bob_addr, message).await
        }
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
    println!("Phase 3A manual QUIC test:");
    println!("  Terminal 1: cargo run -- bob 127.0.0.1:5000");
    println!("  Terminal 2: cargo run -- alice 127.0.0.1:5000 \"hello from alice\"");
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

async fn run_bob(listen_addr: SocketAddr) -> AppResult<()> {
    let mut bob = Bob::local();
    let endpoint = Endpoint::server(server_config()?, listen_addr)?;
    println!("Bob listening on {}", endpoint.local_addr()?);

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
    Ok(())
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
