use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::{rand_core::UnwrapErr, SysRng};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod crdt;
pub mod mailbox_storage;
pub mod storage;

const LOCAL_AAD: &[u8] = b"ciphermesh.local.alice-to-bob.v1";
const HKDF_INFO: &[u8] = b"ciphermesh.phase-2a.x25519.chacha20poly1305";
const PREKEY_HKDF_INFO: &[u8] = b"ciphermesh.phase-2c.prekey-initial-session";
const SIGNED_KEY_EXCHANGE_CONTEXT: &[u8] = b"ciphermesh.phase-2b.signed-x25519";
const SIGNED_PREKEY_CONTEXT: &[u8] = b"ciphermesh.phase-2c.signed-prekey";
const INITIAL_CHAIN_INFO: &[u8] = b"ciphermesh.phase-2d.initial-chains";
const CHAIN_STEP_INFO: &[u8] = b"ciphermesh.phase-2d.chain-step";
const DH_RATCHET_INFO: &[u8] = b"ciphermesh.phase-2d.dh-ratchet";
const MAX_SKIPPED_MESSAGE_KEYS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    Encrypt,
    Decrypt,
    KeyDerivation,
    MissingSessionKey,
    PreKeyUnavailable,
    Replay,
    SignatureVerification,
    TooManySkippedMessages,
    Utf8,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for CryptoError {}

pub type PublicKeyBytes = [u8; 32];
pub type IdentityPublicKeyBytes = [u8; 32];
pub type SignatureBytes = Vec<u8>;
pub type AccountId = String;
pub type DeviceId = String;

const DEVICE_CERTIFICATE_CONTEXT: &[u8] = b"ciphermesh.phase-5a.device-certificate";
const DEVICE_REVOCATION_CONTEXT: &[u8] = b"ciphermesh.phase-5d.device-revocation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeyExchange {
    pub identity_public_key: IdentityPublicKeyBytes,
    pub x25519_public_key: PublicKeyBytes,
    pub signature: SignatureBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity_public_key: IdentityPublicKeyBytes,
    pub signed_prekey_public_key: PublicKeyBytes,
    pub signed_prekey_signature: SignatureBytes,
    pub one_time_prekey_id: u64,
    pub one_time_prekey_public_key: PublicKeyBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialMessage {
    pub alice_initial_public_key: PublicKeyBytes,
    pub one_time_prekey_id: u64,
    pub message: RatchetMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetMessage {
    pub number: u64,
    pub ratchet_public_key: PublicKeyBytes,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RatchetRoleState {
    Alice,
    Bob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetSessionState {
    pub role: RatchetRoleState,
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub send_count: u64,
    pub recv_count: u64,
    pub skipped_message_keys: Vec<(u64, [u8; 32])>,
    pub consumed_message_numbers: Vec<u64>,
    pub dh_private_key: [u8; 32],
    pub peer_ratchet_public_key: PublicKeyBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePreKeyState {
    pub id: u64,
    pub private_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliceState {
    pub identity_secret_key: [u8; 32],
    pub x25519_private_key: [u8; 32],
    pub session: Option<RatchetSessionState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BobState {
    pub identity_secret_key: [u8; 32],
    pub x25519_private_key: [u8; 32],
    pub signed_prekey_private_key: [u8; 32],
    pub one_time_prekey: Option<OneTimePreKeyState>,
    pub session: Option<RatchetSessionState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountIdentityState {
    pub account_id: AccountId,
    pub account_secret_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentityState {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub device_secret_key: [u8; 32],
    pub device_x25519_private_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub device_ed25519_public_key: IdentityPublicKeyBytes,
    pub device_x25519_public_key: PublicKeyBytes,
    pub signature: SignatureBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRevocation {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub revocation_counter: u64,
    pub signature: SignatureBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSessionState {
    pub local_device_id: DeviceId,
    pub remote_device_id: DeviceId,
    pub session: RatchetSessionState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDeliveryEnvelope {
    pub logical_message_id: String,
    pub sender_device_id: DeviceId,
    pub recipient_device_id: DeviceId,
    pub message: RatchetMessage,
}

pub struct AccountIdentity {
    account_id: AccountId,
    identity: IdentityKeyPair,
}

pub struct DeviceIdentity {
    account_id: AccountId,
    device_id: DeviceId,
    signing: IdentityKeyPair,
    x25519: X25519KeyPair,
}

pub struct DeviceSession {
    local_device_id: DeviceId,
    remote_device_id: DeviceId,
    session: RatchetSession,
}

struct X25519KeyPair {
    private: StaticSecret,
    public: PublicKey,
}

impl Clone for X25519KeyPair {
    fn clone(&self) -> Self {
        let private = StaticSecret::from(self.private.to_bytes());
        let public = PublicKey::from(&private);

        Self { private, public }
    }
}

impl X25519KeyPair {
    fn generate() -> Self {
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);

        Self { private, public }
    }

    fn from_private_bytes(bytes: [u8; 32]) -> Self {
        let private = StaticSecret::from(bytes);
        let public = PublicKey::from(&private);

        Self { private, public }
    }

    fn public_key(&self) -> PublicKeyBytes {
        self.public.to_bytes()
    }

    fn private_key_bytes(&self) -> [u8; 32] {
        self.private.to_bytes()
    }

    fn derive_aead_key(&self, peer_public_key: PublicKeyBytes) -> Result<[u8; 32], CryptoError> {
        let peer_public_key = PublicKey::from(peer_public_key);
        let shared_secret = self.private.diffie_hellman(&peer_public_key);
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut key = [0u8; 32];

        hkdf.expand(HKDF_INFO, &mut key)
            .map_err(|_| CryptoError::KeyDerivation)?;

        Ok(key)
    }

    fn dh_bytes(&self, peer_public_key: PublicKeyBytes) -> [u8; 32] {
        let peer_public_key = PublicKey::from(peer_public_key);
        self.private.diffie_hellman(&peer_public_key).to_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RatchetRole {
    Alice,
    Bob,
}

impl RatchetRole {
    fn state(self) -> RatchetRoleState {
        match self {
            Self::Alice => RatchetRoleState::Alice,
            Self::Bob => RatchetRoleState::Bob,
        }
    }

    fn from_state(state: RatchetRoleState) -> Self {
        match state {
            RatchetRoleState::Alice => Self::Alice,
            RatchetRoleState::Bob => Self::Bob,
        }
    }

    fn chains(self, first: [u8; 32], second: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        match self {
            Self::Alice => (first, second),
            Self::Bob => (second, first),
        }
    }
}

struct RatchetSession {
    role: RatchetRole,
    root_key: [u8; 32],
    send_chain_key: [u8; 32],
    recv_chain_key: [u8; 32],
    send_count: u64,
    recv_count: u64,
    skipped_message_keys: BTreeMap<u64, [u8; 32]>,
    consumed_message_numbers: BTreeSet<u64>,
    dh_keys: X25519KeyPair,
    peer_ratchet_public_key: PublicKeyBytes,
}

impl RatchetSession {
    fn new(
        root_key: [u8; 32],
        role: RatchetRole,
        dh_keys: X25519KeyPair,
        peer_ratchet_public_key: PublicKeyBytes,
    ) -> Result<Self, CryptoError> {
        let (alice_to_bob, bob_to_alice) = derive_directional_chains(root_key)?;
        let (send_chain_key, recv_chain_key) = role.chains(alice_to_bob, bob_to_alice);

        Ok(Self {
            role,
            root_key,
            send_chain_key,
            recv_chain_key,
            send_count: 0,
            recv_count: 0,
            skipped_message_keys: BTreeMap::new(),
            consumed_message_numbers: BTreeSet::new(),
            dh_keys,
            peer_ratchet_public_key,
        })
    }

    fn encrypt(&mut self, message: &str) -> Result<RatchetMessage, CryptoError> {
        let number = self.send_count;
        let message_key = self.next_send_message_key()?;
        let cipher = ChaCha20Poly1305::new(&message_key.into());
        let ratchet_public_key = self.dh_keys.public_key();
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_for(number)),
                Payload {
                    msg: message.as_bytes(),
                    aad: &ratchet_aad(number, ratchet_public_key),
                },
            )
            .map_err(|_| CryptoError::Encrypt)?;

        Ok(RatchetMessage {
            number,
            ratchet_public_key,
            ciphertext,
        })
    }

    fn decrypt(&mut self, message: &RatchetMessage) -> Result<String, CryptoError> {
        if message.ratchet_public_key != self.peer_ratchet_public_key {
            self.receive_dh_ratchet(message.ratchet_public_key)?;
        }

        if self.consumed_message_numbers.contains(&message.number) {
            return Err(CryptoError::Replay);
        }

        let message_key =
            if let Some(message_key) = self.skipped_message_keys.remove(&message.number) {
                message_key
            } else {
                if message.number < self.recv_count {
                    return Err(CryptoError::Replay);
                }

                while self.recv_count < message.number {
                    if self.skipped_message_keys.len() >= MAX_SKIPPED_MESSAGE_KEYS {
                        return Err(CryptoError::TooManySkippedMessages);
                    }

                    let skipped_key = self.next_recv_message_key()?;
                    self.skipped_message_keys
                        .insert(self.recv_count - 1, skipped_key);
                }

                self.next_recv_message_key()?
            };

        let cipher = ChaCha20Poly1305::new(&message_key.into());
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_for(message.number)),
                Payload {
                    msg: message.ciphertext.as_ref(),
                    aad: &ratchet_aad(message.number, message.ratchet_public_key),
                },
            )
            .map_err(|_| CryptoError::Decrypt)?;

        self.consumed_message_numbers.insert(message.number);
        String::from_utf8(plaintext).map_err(|_| CryptoError::Utf8)
    }

    fn rotate_sending_ratchet(&mut self) -> Result<(), CryptoError> {
        self.dh_keys = X25519KeyPair::generate();
        self.apply_dh_ratchet(self.dh_keys.dh_bytes(self.peer_ratchet_public_key))
    }

    fn receive_dh_ratchet(
        &mut self,
        peer_ratchet_public_key: PublicKeyBytes,
    ) -> Result<(), CryptoError> {
        let dh_output = self.dh_keys.dh_bytes(peer_ratchet_public_key);
        self.peer_ratchet_public_key = peer_ratchet_public_key;
        self.apply_dh_ratchet(dh_output)
    }

    fn apply_dh_ratchet(&mut self, dh_output: [u8; 32]) -> Result<(), CryptoError> {
        let (root_key, alice_to_bob, bob_to_alice) =
            derive_dh_ratchet_state(self.root_key, dh_output)?;
        let (send_chain_key, recv_chain_key) = self.role.chains(alice_to_bob, bob_to_alice);

        self.root_key = root_key;
        self.send_chain_key = send_chain_key;
        self.recv_chain_key = recv_chain_key;
        self.send_count = 0;
        self.recv_count = 0;
        self.skipped_message_keys.clear();
        self.consumed_message_numbers.clear();

        Ok(())
    }

    fn next_send_message_key(&mut self) -> Result<[u8; 32], CryptoError> {
        let (next_chain_key, message_key) = advance_chain(self.send_chain_key)?;
        self.send_chain_key = next_chain_key;
        self.send_count += 1;

        Ok(message_key)
    }

    fn next_recv_message_key(&mut self) -> Result<[u8; 32], CryptoError> {
        let (next_chain_key, message_key) = advance_chain(self.recv_chain_key)?;
        self.recv_chain_key = next_chain_key;
        self.recv_count += 1;

        Ok(message_key)
    }

    fn state(&self) -> RatchetSessionState {
        RatchetSessionState {
            role: self.role.state(),
            root_key: self.root_key,
            send_chain_key: self.send_chain_key,
            recv_chain_key: self.recv_chain_key,
            send_count: self.send_count,
            recv_count: self.recv_count,
            skipped_message_keys: self
                .skipped_message_keys
                .iter()
                .map(|(number, key)| (*number, *key))
                .collect(),
            consumed_message_numbers: self.consumed_message_numbers.iter().copied().collect(),
            dh_private_key: self.dh_keys.private_key_bytes(),
            peer_ratchet_public_key: self.peer_ratchet_public_key,
        }
    }

    fn from_state(state: RatchetSessionState) -> Self {
        Self {
            role: RatchetRole::from_state(state.role),
            root_key: state.root_key,
            send_chain_key: state.send_chain_key,
            recv_chain_key: state.recv_chain_key,
            send_count: state.send_count,
            recv_count: state.recv_count,
            skipped_message_keys: state.skipped_message_keys.into_iter().collect(),
            consumed_message_numbers: state.consumed_message_numbers.into_iter().collect(),
            dh_keys: X25519KeyPair::from_private_bytes(state.dh_private_key),
            peer_ratchet_public_key: state.peer_ratchet_public_key,
        }
    }
}

fn derive_directional_chains(root_key: [u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, &root_key);
    let mut output = [0u8; 64];
    hkdf.expand(INITIAL_CHAIN_INFO, &mut output)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let mut alice_to_bob = [0u8; 32];
    let mut bob_to_alice = [0u8; 32];
    alice_to_bob.copy_from_slice(&output[..32]);
    bob_to_alice.copy_from_slice(&output[32..]);

    Ok((alice_to_bob, bob_to_alice))
}

fn advance_chain(chain_key: [u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, &chain_key);
    let mut output = [0u8; 64];
    hkdf.expand(CHAIN_STEP_INFO, &mut output)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let mut next_chain_key = [0u8; 32];
    let mut message_key = [0u8; 32];
    next_chain_key.copy_from_slice(&output[..32]);
    message_key.copy_from_slice(&output[32..]);

    Ok((next_chain_key, message_key))
}

#[allow(clippy::type_complexity)]
fn derive_dh_ratchet_state(
    root_key: [u8; 32],
    dh_output: [u8; 32],
) -> Result<([u8; 32], [u8; 32], [u8; 32]), CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&root_key), &dh_output);
    let mut output = [0u8; 96];
    hkdf.expand(DH_RATCHET_INFO, &mut output)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let mut next_root_key = [0u8; 32];
    let mut alice_to_bob = [0u8; 32];
    let mut bob_to_alice = [0u8; 32];
    next_root_key.copy_from_slice(&output[..32]);
    alice_to_bob.copy_from_slice(&output[32..64]);
    bob_to_alice.copy_from_slice(&output[64..]);

    Ok((next_root_key, alice_to_bob, bob_to_alice))
}

fn nonce_for(number: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&number.to_be_bytes());
    nonce
}

fn ratchet_aad(number: u64, ratchet_public_key: PublicKeyBytes) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LOCAL_AAD.len() + 8 + ratchet_public_key.len());
    aad.extend_from_slice(LOCAL_AAD);
    aad.extend_from_slice(&number.to_be_bytes());
    aad.extend_from_slice(&ratchet_public_key);
    aad
}

struct IdentityKeyPair {
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    fn generate() -> Self {
        let mut csprng = UnwrapErr(SysRng);
        Self {
            signing_key: SigningKey::generate(&mut csprng),
        }
    }

    fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    fn public_key(&self) -> IdentityPublicKeyBytes {
        self.signing_key.verifying_key().to_bytes()
    }

    fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    fn sign_key_exchange(&self, x25519_public_key: PublicKeyBytes) -> SignedKeyExchange {
        let identity_public_key = self.public_key();
        let signed_bytes = signed_key_exchange_bytes(identity_public_key, x25519_public_key);
        let signature = self.signing_key.sign(&signed_bytes);

        SignedKeyExchange {
            identity_public_key,
            x25519_public_key,
            signature: signature.to_bytes().to_vec(),
        }
    }

    fn sign_prekey(&self, signed_prekey_public_key: PublicKeyBytes) -> SignatureBytes {
        let signed_bytes = signed_prekey_bytes(self.public_key(), signed_prekey_public_key);
        self.signing_key.sign(&signed_bytes).to_bytes().to_vec()
    }
}

fn signed_key_exchange_bytes(
    identity_public_key: IdentityPublicKeyBytes,
    x25519_public_key: PublicKeyBytes,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        SIGNED_KEY_EXCHANGE_CONTEXT.len() + identity_public_key.len() + x25519_public_key.len(),
    );
    bytes.extend_from_slice(SIGNED_KEY_EXCHANGE_CONTEXT);
    bytes.extend_from_slice(&identity_public_key);
    bytes.extend_from_slice(&x25519_public_key);
    bytes
}

fn verify_signed_key_exchange(exchange: &SignedKeyExchange) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(&exchange.identity_public_key)
        .map_err(|_| CryptoError::SignatureVerification)?;
    let signature = Signature::try_from(&exchange.signature[..])
        .map_err(|_| CryptoError::SignatureVerification)?;
    let signed_bytes =
        signed_key_exchange_bytes(exchange.identity_public_key, exchange.x25519_public_key);

    verifying_key
        .verify(&signed_bytes, &signature)
        .map_err(|_| CryptoError::SignatureVerification)
}

fn signed_prekey_bytes(
    identity_public_key: IdentityPublicKeyBytes,
    signed_prekey_public_key: PublicKeyBytes,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        SIGNED_PREKEY_CONTEXT.len() + identity_public_key.len() + signed_prekey_public_key.len(),
    );
    bytes.extend_from_slice(SIGNED_PREKEY_CONTEXT);
    bytes.extend_from_slice(&identity_public_key);
    bytes.extend_from_slice(&signed_prekey_public_key);
    bytes
}

fn verify_signed_prekey(bundle: &PreKeyBundle) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(&bundle.identity_public_key)
        .map_err(|_| CryptoError::SignatureVerification)?;
    let signature = Signature::try_from(&bundle.signed_prekey_signature[..])
        .map_err(|_| CryptoError::SignatureVerification)?;
    let signed_bytes =
        signed_prekey_bytes(bundle.identity_public_key, bundle.signed_prekey_public_key);

    verifying_key
        .verify(&signed_bytes, &signature)
        .map_err(|_| CryptoError::SignatureVerification)
}

fn derive_prekey_aead_key(
    first_dh: [u8; 32],
    second_dh: [u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let mut key_material = [0u8; 64];
    key_material[..32].copy_from_slice(&first_dh);
    key_material[32..].copy_from_slice(&second_dh);

    let hkdf = Hkdf::<Sha256>::new(None, &key_material);
    let mut key = [0u8; 32];
    hkdf.expand(PREKEY_HKDF_INFO, &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;

    Ok(key)
}

struct OneTimePreKey {
    id: u64,
    keys: X25519KeyPair,
}

impl OneTimePreKey {
    fn generate(id: u64) -> Self {
        Self {
            id,
            keys: X25519KeyPair::generate(),
        }
    }

    fn state(&self) -> OneTimePreKeyState {
        OneTimePreKeyState {
            id: self.id,
            private_key: self.keys.private_key_bytes(),
        }
    }

    fn from_state(state: OneTimePreKeyState) -> Self {
        Self {
            id: state.id,
            keys: X25519KeyPair::from_private_bytes(state.private_key),
        }
    }
}

pub struct SimulatedDirectory {
    bob_bundle: Option<PreKeyBundle>,
}

impl SimulatedDirectory {
    pub fn new() -> Self {
        Self { bob_bundle: None }
    }

    pub fn publish_bob_bundle(&mut self, bob: &Bob) -> Result<(), CryptoError> {
        self.bob_bundle = Some(bob.prekey_bundle()?);
        Ok(())
    }

    pub fn take_bob_prekey_bundle(&mut self) -> Result<PreKeyBundle, CryptoError> {
        self.bob_bundle.take().ok_or(CryptoError::PreKeyUnavailable)
    }
}

impl Default for SimulatedDirectory {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountIdentity {
    pub fn generate() -> Self {
        let identity = IdentityKeyPair::generate();
        let account_id = account_id_for_public_key(identity.public_key());

        Self {
            account_id,
            identity,
        }
    }

    pub fn from_state(state: AccountIdentityState) -> Self {
        Self {
            account_id: state.account_id,
            identity: IdentityKeyPair::from_secret_bytes(state.account_secret_key),
        }
    }

    pub fn export_state(&self) -> AccountIdentityState {
        AccountIdentityState {
            account_id: self.account_id.clone(),
            account_secret_key: self.identity.secret_key_bytes(),
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn public_key(&self) -> IdentityPublicKeyBytes {
        self.identity.public_key()
    }

    pub fn authorize_device(&self, device: &DeviceIdentity) -> DeviceCertificate {
        let mut certificate = DeviceCertificate {
            account_id: self.account_id.clone(),
            device_id: device.device_id.clone(),
            device_ed25519_public_key: device.signing.public_key(),
            device_x25519_public_key: device.x25519.public_key(),
            signature: Vec::new(),
        };
        let signed_bytes = device_certificate_bytes(&certificate);
        certificate.signature = self
            .identity
            .signing_key
            .sign(&signed_bytes)
            .to_bytes()
            .to_vec();
        certificate
    }

    pub fn revoke_device(
        &self,
        device_id: impl Into<DeviceId>,
        revocation_counter: u64,
    ) -> DeviceRevocation {
        let mut revocation = DeviceRevocation {
            account_id: self.account_id.clone(),
            device_id: device_id.into(),
            revocation_counter,
            signature: Vec::new(),
        };
        let signed_bytes = device_revocation_bytes(&revocation);
        revocation.signature = self
            .identity
            .signing_key
            .sign(&signed_bytes)
            .to_bytes()
            .to_vec();
        revocation
    }
}

impl DeviceIdentity {
    pub fn generate(account_id: impl Into<AccountId>) -> Self {
        let account_id = account_id.into();
        let signing = IdentityKeyPair::generate();
        let x25519 = X25519KeyPair::generate();
        let device_id = device_id_for_public_key(signing.public_key());

        Self {
            account_id,
            device_id,
            signing,
            x25519,
        }
    }

    pub fn from_state(state: DeviceIdentityState) -> Self {
        Self {
            account_id: state.account_id,
            device_id: state.device_id,
            signing: IdentityKeyPair::from_secret_bytes(state.device_secret_key),
            x25519: X25519KeyPair::from_private_bytes(state.device_x25519_private_key),
        }
    }

    pub fn export_state(&self) -> DeviceIdentityState {
        DeviceIdentityState {
            account_id: self.account_id.clone(),
            device_id: self.device_id.clone(),
            device_secret_key: self.signing.secret_key_bytes(),
            device_x25519_private_key: self.x25519.private_key_bytes(),
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn ed25519_public_key(&self) -> IdentityPublicKeyBytes {
        self.signing.public_key()
    }

    pub fn x25519_public_key(&self) -> PublicKeyBytes {
        self.x25519.public_key()
    }

    pub fn create_outbound_session(
        &self,
        remote_account_public_key: IdentityPublicKeyBytes,
        remote_certificate: &DeviceCertificate,
    ) -> Result<DeviceSession, CryptoError> {
        verify_device_certificate(remote_account_public_key, remote_certificate)?;
        let key = self
            .x25519
            .derive_aead_key(remote_certificate.device_x25519_public_key)?;

        Ok(DeviceSession {
            local_device_id: self.device_id.clone(),
            remote_device_id: remote_certificate.device_id.clone(),
            session: RatchetSession::new(
                key,
                RatchetRole::Alice,
                self.x25519.clone(),
                remote_certificate.device_x25519_public_key,
            )?,
        })
    }

    pub fn create_inbound_session(
        &self,
        remote_device_id: impl Into<DeviceId>,
        remote_device_x25519_public_key: PublicKeyBytes,
    ) -> Result<DeviceSession, CryptoError> {
        let key = self
            .x25519
            .derive_aead_key(remote_device_x25519_public_key)?;

        Ok(DeviceSession {
            local_device_id: self.device_id.clone(),
            remote_device_id: remote_device_id.into(),
            session: RatchetSession::new(
                key,
                RatchetRole::Bob,
                self.x25519.clone(),
                remote_device_x25519_public_key,
            )?,
        })
    }
}

impl DeviceSession {
    pub fn from_state(state: DeviceSessionState) -> Self {
        Self {
            local_device_id: state.local_device_id,
            remote_device_id: state.remote_device_id,
            session: RatchetSession::from_state(state.session),
        }
    }

    pub fn export_state(&self) -> DeviceSessionState {
        DeviceSessionState {
            local_device_id: self.local_device_id.clone(),
            remote_device_id: self.remote_device_id.clone(),
            session: self.session.state(),
        }
    }

    pub fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    pub fn remote_device_id(&self) -> &str {
        &self.remote_device_id
    }

    pub fn encrypt(
        &mut self,
        logical_message_id: impl Into<String>,
        plaintext: &str,
    ) -> Result<DeviceDeliveryEnvelope, CryptoError> {
        Ok(DeviceDeliveryEnvelope {
            logical_message_id: logical_message_id.into(),
            sender_device_id: self.local_device_id.clone(),
            recipient_device_id: self.remote_device_id.clone(),
            message: self.session.encrypt(plaintext)?,
        })
    }

    pub fn decrypt(&mut self, envelope: &DeviceDeliveryEnvelope) -> Result<String, CryptoError> {
        if envelope.recipient_device_id != self.local_device_id
            || envelope.sender_device_id != self.remote_device_id
        {
            return Err(CryptoError::Decrypt);
        }

        self.session.decrypt(&envelope.message)
    }

    pub fn session_state(&self) -> RatchetSessionState {
        self.session.state()
    }
}

pub fn verify_device_certificate(
    account_public_key: IdentityPublicKeyBytes,
    certificate: &DeviceCertificate,
) -> Result<(), CryptoError> {
    if certificate.account_id != account_id_for_public_key(account_public_key) {
        return Err(CryptoError::SignatureVerification);
    }

    let verifying_key = VerifyingKey::from_bytes(&account_public_key)
        .map_err(|_| CryptoError::SignatureVerification)?;
    let signature = Signature::try_from(&certificate.signature[..])
        .map_err(|_| CryptoError::SignatureVerification)?;

    verifying_key
        .verify(&device_certificate_bytes(certificate), &signature)
        .map_err(|_| CryptoError::SignatureVerification)
}

pub fn verify_authorized_sibling_devices(
    account_public_key: IdentityPublicKeyBytes,
    first: &DeviceCertificate,
    second: &DeviceCertificate,
) -> Result<(), CryptoError> {
    verify_device_certificate(account_public_key, first)?;
    verify_device_certificate(account_public_key, second)?;

    if first.account_id != second.account_id || first.device_id == second.device_id {
        return Err(CryptoError::SignatureVerification);
    }

    Ok(())
}

pub fn verify_device_revocation(
    account_public_key: IdentityPublicKeyBytes,
    revocation: &DeviceRevocation,
) -> Result<(), CryptoError> {
    if revocation.account_id != account_id_for_public_key(account_public_key) {
        return Err(CryptoError::SignatureVerification);
    }

    let verifying_key = VerifyingKey::from_bytes(&account_public_key)
        .map_err(|_| CryptoError::SignatureVerification)?;
    let signature = Signature::try_from(&revocation.signature[..])
        .map_err(|_| CryptoError::SignatureVerification)?;

    verifying_key
        .verify(&device_revocation_bytes(revocation), &signature)
        .map_err(|_| CryptoError::SignatureVerification)
}

pub fn is_device_currently_authorized(
    account_public_key: IdentityPublicKeyBytes,
    certificate: &DeviceCertificate,
    revocations: &[DeviceRevocation],
) -> Result<bool, CryptoError> {
    verify_device_certificate(account_public_key, certificate)?;

    for revocation in revocations {
        if revocation.account_id == certificate.account_id
            && revocation.device_id == certificate.device_id
        {
            verify_device_revocation(account_public_key, revocation)?;
            return Ok(false);
        }
    }

    Ok(true)
}

pub fn active_device_certificates(
    account_public_key: IdentityPublicKeyBytes,
    certificates: &[DeviceCertificate],
    revocations: &[DeviceRevocation],
) -> Result<Vec<DeviceCertificate>, CryptoError> {
    certificates
        .iter()
        .filter_map(|certificate| {
            match is_device_currently_authorized(account_public_key, certificate, revocations) {
                Ok(true) => Some(Ok(certificate.clone())),
                Ok(false) => None,
                Err(error) => Some(Err(error)),
            }
        })
        .collect()
}

fn account_id_for_public_key(public_key: IdentityPublicKeyBytes) -> AccountId {
    format!("acct-{}", short_hash(&public_key))
}

fn device_id_for_public_key(public_key: IdentityPublicKeyBytes) -> DeviceId {
    format!("dev-{}", short_hash(&public_key))
}

fn short_hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn device_certificate_bytes(certificate: &DeviceCertificate) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DEVICE_CERTIFICATE_CONTEXT);
    bytes.extend_from_slice(certificate.account_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(certificate.device_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&certificate.device_ed25519_public_key);
    bytes.extend_from_slice(&certificate.device_x25519_public_key);
    bytes
}

fn device_revocation_bytes(revocation: &DeviceRevocation) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(DEVICE_REVOCATION_CONTEXT);
    bytes.extend_from_slice(revocation.account_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(revocation.device_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&revocation.revocation_counter.to_be_bytes());
    bytes
}

pub struct Alice {
    identity: IdentityKeyPair,
    keys: X25519KeyPair,
    session: Option<RatchetSession>,
}

pub struct Bob {
    identity: IdentityKeyPair,
    keys: X25519KeyPair,
    signed_prekey: X25519KeyPair,
    one_time_prekey: Option<OneTimePreKey>,
    session: Option<RatchetSession>,
}

impl Alice {
    pub fn local() -> Self {
        Self {
            identity: IdentityKeyPair::generate(),
            keys: X25519KeyPair::generate(),
            session: None,
        }
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        self.keys.public_key()
    }

    pub fn signed_key_exchange(&self) -> SignedKeyExchange {
        self.identity.sign_key_exchange(self.public_key())
    }

    pub fn derive_session_key(
        &mut self,
        bob_exchange: &SignedKeyExchange,
    ) -> Result<(), CryptoError> {
        verify_signed_key_exchange(bob_exchange)?;
        let key = self.keys.derive_aead_key(bob_exchange.x25519_public_key)?;
        self.session = Some(RatchetSession::new(
            key,
            RatchetRole::Alice,
            self.keys.clone(),
            bob_exchange.x25519_public_key,
        )?);

        Ok(())
    }

    pub fn encrypt_for_bob(&mut self, message: &str) -> Result<RatchetMessage, CryptoError> {
        self.session
            .as_mut()
            .ok_or(CryptoError::MissingSessionKey)?
            .encrypt(message)
    }

    pub fn decrypt_from_bob(&mut self, message: &RatchetMessage) -> Result<String, CryptoError> {
        self.session
            .as_mut()
            .ok_or(CryptoError::MissingSessionKey)?
            .decrypt(message)
    }

    pub fn encrypt_initial_message(
        &mut self,
        bundle: &PreKeyBundle,
        message: &str,
    ) -> Result<InitialMessage, CryptoError> {
        verify_signed_prekey(bundle)?;

        let initial_keys = X25519KeyPair::generate();
        let first_dh = initial_keys.dh_bytes(bundle.signed_prekey_public_key);
        let second_dh = initial_keys.dh_bytes(bundle.one_time_prekey_public_key);
        let key = derive_prekey_aead_key(first_dh, second_dh)?;
        self.session = Some(RatchetSession::new(
            key,
            RatchetRole::Alice,
            initial_keys,
            bundle.signed_prekey_public_key,
        )?);

        let ciphertext = self.encrypt_for_bob(message)?;

        Ok(InitialMessage {
            alice_initial_public_key: ciphertext.ratchet_public_key,
            one_time_prekey_id: bundle.one_time_prekey_id,
            message: ciphertext,
        })
    }

    pub fn rotate_sending_ratchet(&mut self) -> Result<(), CryptoError> {
        self.session
            .as_mut()
            .ok_or(CryptoError::MissingSessionKey)?
            .rotate_sending_ratchet()
    }

    pub fn export_state(&self) -> AliceState {
        AliceState {
            identity_secret_key: self.identity.secret_key_bytes(),
            x25519_private_key: self.keys.private_key_bytes(),
            session: self.session.as_ref().map(RatchetSession::state),
        }
    }

    pub fn from_state(state: AliceState) -> Self {
        Self {
            identity: IdentityKeyPair::from_secret_bytes(state.identity_secret_key),
            keys: X25519KeyPair::from_private_bytes(state.x25519_private_key),
            session: state.session.map(RatchetSession::from_state),
        }
    }

    pub fn session_state(&self) -> Option<RatchetSessionState> {
        self.session.as_ref().map(RatchetSession::state)
    }
}

impl Bob {
    pub fn local() -> Self {
        Self {
            identity: IdentityKeyPair::generate(),
            keys: X25519KeyPair::generate(),
            signed_prekey: X25519KeyPair::generate(),
            one_time_prekey: Some(OneTimePreKey::generate(1)),
            session: None,
        }
    }

    pub fn mailbox_demo() -> Self {
        Self {
            identity: IdentityKeyPair::from_secret_bytes([0x3d; 32]),
            keys: X25519KeyPair::from_private_bytes([0x3e; 32]),
            signed_prekey: X25519KeyPair::from_private_bytes([0x3f; 32]),
            one_time_prekey: Some(OneTimePreKey {
                id: 1,
                keys: X25519KeyPair::from_private_bytes([0x40; 32]),
            }),
            session: None,
        }
    }

    pub fn mailbox_demo_prekey_bundle() -> Result<PreKeyBundle, CryptoError> {
        Self::mailbox_demo().prekey_bundle()
    }

    pub fn public_key(&self) -> PublicKeyBytes {
        self.keys.public_key()
    }

    pub fn signed_key_exchange(&self) -> SignedKeyExchange {
        self.identity.sign_key_exchange(self.public_key())
    }

    pub fn prekey_bundle(&self) -> Result<PreKeyBundle, CryptoError> {
        let one_time_prekey = self
            .one_time_prekey
            .as_ref()
            .ok_or(CryptoError::PreKeyUnavailable)?;
        let signed_prekey_public_key = self.signed_prekey.public_key();

        Ok(PreKeyBundle {
            identity_public_key: self.identity.public_key(),
            signed_prekey_public_key,
            signed_prekey_signature: self.identity.sign_prekey(signed_prekey_public_key),
            one_time_prekey_id: one_time_prekey.id,
            one_time_prekey_public_key: one_time_prekey.keys.public_key(),
        })
    }

    pub fn derive_session_key(
        &mut self,
        alice_exchange: &SignedKeyExchange,
    ) -> Result<(), CryptoError> {
        verify_signed_key_exchange(alice_exchange)?;
        let key = self
            .keys
            .derive_aead_key(alice_exchange.x25519_public_key)?;
        self.session = Some(RatchetSession::new(
            key,
            RatchetRole::Bob,
            self.keys.clone(),
            alice_exchange.x25519_public_key,
        )?);

        Ok(())
    }

    pub fn decrypt_from_alice(&mut self, message: &RatchetMessage) -> Result<String, CryptoError> {
        self.session
            .as_mut()
            .ok_or(CryptoError::MissingSessionKey)?
            .decrypt(message)
    }

    pub fn encrypt_for_alice(&mut self, message: &str) -> Result<RatchetMessage, CryptoError> {
        self.session
            .as_mut()
            .ok_or(CryptoError::MissingSessionKey)?
            .encrypt(message)
    }

    pub fn decrypt_initial_message(
        &mut self,
        message: &InitialMessage,
    ) -> Result<String, CryptoError> {
        let one_time_prekey = self
            .one_time_prekey
            .take()
            .ok_or(CryptoError::PreKeyUnavailable)?;

        if one_time_prekey.id != message.one_time_prekey_id {
            self.one_time_prekey = Some(one_time_prekey);
            return Err(CryptoError::PreKeyUnavailable);
        }

        let first_dh = self
            .signed_prekey
            .dh_bytes(message.alice_initial_public_key);
        let second_dh = one_time_prekey
            .keys
            .dh_bytes(message.alice_initial_public_key);
        let key = derive_prekey_aead_key(first_dh, second_dh)?;
        self.session = Some(RatchetSession::new(
            key,
            RatchetRole::Bob,
            self.signed_prekey.clone(),
            message.alice_initial_public_key,
        )?);

        self.decrypt_from_alice(&message.message)
    }

    pub fn export_state(&self) -> BobState {
        BobState {
            identity_secret_key: self.identity.secret_key_bytes(),
            x25519_private_key: self.keys.private_key_bytes(),
            signed_prekey_private_key: self.signed_prekey.private_key_bytes(),
            one_time_prekey: self.one_time_prekey.as_ref().map(OneTimePreKey::state),
            session: self.session.as_ref().map(RatchetSession::state),
        }
    }

    pub fn from_state(state: BobState) -> Self {
        Self {
            identity: IdentityKeyPair::from_secret_bytes(state.identity_secret_key),
            keys: X25519KeyPair::from_private_bytes(state.x25519_private_key),
            signed_prekey: X25519KeyPair::from_private_bytes(state.signed_prekey_private_key),
            one_time_prekey: state.one_time_prekey.map(OneTimePreKey::from_state),
            session: state.session.map(RatchetSession::from_state),
        }
    }

    pub fn session_state(&self) -> Option<RatchetSessionState> {
        self.session.as_ref().map(RatchetSession::state)
    }
}

pub fn send_over_simulated_transport<T>(payload: T) -> T {
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alice_and_bob_derive_equivalent_aead_keys() {
        let alice = Alice::local();
        let bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();

        verify_signed_key_exchange(&alice_exchange).expect("alice signature verifies");
        verify_signed_key_exchange(&bob_exchange).expect("bob signature verifies");

        let alice_key = alice
            .keys
            .derive_aead_key(bob_exchange.x25519_public_key)
            .expect("alice derives key");
        let bob_key = bob
            .keys
            .derive_aead_key(alice_exchange.x25519_public_key)
            .expect("bob derives key");

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn valid_signatures_allow_encrypted_round_trip() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let message = "hello bob, this is alice";
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();

        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let encrypted = alice.encrypt_for_bob(message).expect("encrypt");
        assert_ne!(encrypted.ciphertext, message.as_bytes());

        let received_ciphertext = send_over_simulated_transport(encrypted);
        let plaintext = bob
            .decrypt_from_alice(&received_ciphertext)
            .expect("decrypt");

        assert_eq!(plaintext, message);
    }

    #[test]
    fn bob_rejects_modified_ciphertext() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();

        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let mut encrypted = alice.encrypt_for_bob("tamper with me").expect("encrypt");
        encrypted.ciphertext[0] ^= 0x01;

        let received_ciphertext = send_over_simulated_transport(encrypted);
        let result = bob.decrypt_from_alice(&received_ciphertext);

        assert_eq!(result, Err(CryptoError::Decrypt));
    }

    #[test]
    fn modified_x25519_public_key_fails_signature_verification() {
        let mallory = Alice::local();
        let mut bob = Bob::local();
        let mut substituted_exchange = mallory.signed_key_exchange();
        substituted_exchange.x25519_public_key[0] ^= 0x01;

        let result = bob.derive_session_key(&substituted_exchange);

        assert_eq!(result, Err(CryptoError::SignatureVerification));
    }

    #[test]
    fn bob_can_publish_valid_prekey_bundle() {
        let bob = Bob::local();
        let bundle = bob.prekey_bundle().expect("bob publishes prekey bundle");

        assert_eq!(bundle.identity_public_key, bob.identity.public_key());
        assert_eq!(
            bundle.signed_prekey_public_key,
            bob.signed_prekey.public_key()
        );
        assert_eq!(bundle.one_time_prekey_id, 1);
        verify_signed_prekey(&bundle).expect("signed prekey verifies");
    }

    #[test]
    fn bob_can_be_offline_while_alice_encrypts_initial_message() {
        let mut bob = Bob::local();
        let mut directory = SimulatedDirectory::new();
        directory
            .publish_bob_bundle(&bob)
            .expect("directory stores bundle");

        let mut alice = Alice::local();
        let bundle = directory
            .take_bob_prekey_bundle()
            .expect("alice retrieves public bundle");
        verify_signed_prekey(&bundle).expect("alice verifies signed prekey");
        let initial_message = alice
            .encrypt_initial_message(&bundle, "hello offline bob")
            .expect("alice encrypts while bob is offline");

        let plaintext = bob
            .decrypt_initial_message(&initial_message)
            .expect("bob decrypts after returning");

        assert_eq!(plaintext, "hello offline bob");
    }

    #[test]
    fn alice_and_bob_derive_compatible_prekey_session_keys() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let bundle = bob.prekey_bundle().expect("bob publishes prekey bundle");

        let initial_message = alice
            .encrypt_initial_message(&bundle, "prekey session")
            .expect("alice encrypts initial message");
        let plaintext = bob
            .decrypt_initial_message(&initial_message)
            .expect("bob derives compatible key and decrypts");

        assert_eq!(plaintext, "prekey session");
    }

    #[test]
    fn modified_signed_prekey_fails_verification() {
        let mut alice = Alice::local();
        let bob = Bob::local();
        let mut bundle = bob.prekey_bundle().expect("bob publishes prekey bundle");
        bundle.signed_prekey_public_key[0] ^= 0x01;

        let result = alice.encrypt_initial_message(&bundle, "should not encrypt");

        assert_eq!(result, Err(CryptoError::SignatureVerification));
    }

    #[test]
    fn consumed_one_time_prekey_is_not_reused_as_fresh_prekey() {
        let mut bob = Bob::local();
        let mut directory = SimulatedDirectory::new();
        directory
            .publish_bob_bundle(&bob)
            .expect("directory stores bundle");

        let mut alice = Alice::local();
        let bundle = directory
            .take_bob_prekey_bundle()
            .expect("first retrieval consumes directory prekey");
        let initial_message = alice
            .encrypt_initial_message(&bundle, "use once")
            .expect("alice encrypts");

        assert_eq!(
            directory.take_bob_prekey_bundle(),
            Err(CryptoError::PreKeyUnavailable)
        );
        bob.decrypt_initial_message(&initial_message)
            .expect("bob consumes private one-time prekey");
        assert_eq!(
            bob.decrypt_initial_message(&initial_message),
            Err(CryptoError::PreKeyUnavailable)
        );
        assert_eq!(bob.prekey_bundle(), Err(CryptoError::PreKeyUnavailable));
    }

    #[test]
    fn consecutive_messages_use_different_encryption_keys() {
        let root_key = [7u8; 32];
        let (send_chain, _) = derive_directional_chains(root_key).expect("chains derive");
        let (_, first_message_key) = advance_chain(send_chain).expect("first key");
        let (second_chain, _) = advance_chain(send_chain).expect("first advance");
        let (_, second_message_key) = advance_chain(second_chain).expect("second key");

        assert_ne!(first_message_key, second_message_key);
    }

    #[test]
    fn alice_and_bob_derive_compatible_ratchet_message_keys() {
        let root_key = [9u8; 32];
        let (alice_to_bob, bob_to_alice) =
            derive_directional_chains(root_key).expect("chains derive");
        let (_, alice_message_key) = advance_chain(alice_to_bob).expect("alice send key");
        let (_, bob_message_key) = advance_chain(alice_to_bob).expect("bob receive key");

        assert_eq!(alice_message_key, bob_message_key);
        assert_ne!(alice_message_key, bob_to_alice);
    }

    #[test]
    fn multiple_ratcheted_messages_encrypt_and_decrypt_successfully() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let first = send_over_simulated_transport(alice.encrypt_for_bob("one").expect("one"));
        let second = send_over_simulated_transport(alice.encrypt_for_bob("two").expect("two"));
        let third = send_over_simulated_transport(alice.encrypt_for_bob("three").expect("three"));

        assert_eq!(bob.decrypt_from_alice(&first).expect("decrypt one"), "one");
        assert_eq!(bob.decrypt_from_alice(&second).expect("decrypt two"), "two");
        assert_eq!(
            bob.decrypt_from_alice(&third).expect("decrypt three"),
            "three"
        );
    }

    #[test]
    fn bob_can_send_ratcheted_messages_back_to_alice() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let encrypted = bob
            .encrypt_for_alice("hello alice")
            .expect("bob encrypts to alice");

        assert_eq!(
            alice.decrypt_from_bob(&encrypted).expect("alice decrypts"),
            "hello alice"
        );
    }

    #[test]
    fn account_authorizes_two_distinct_devices() {
        let account = AccountIdentity::generate();
        let laptop = DeviceIdentity::generate(account.account_id());
        let phone = DeviceIdentity::generate(account.account_id());
        let laptop_certificate = account.authorize_device(&laptop);
        let phone_certificate = account.authorize_device(&phone);

        verify_device_certificate(account.public_key(), &laptop_certificate)
            .expect("laptop verifies");
        verify_device_certificate(account.public_key(), &phone_certificate)
            .expect("phone verifies");

        assert_eq!(laptop.account_id(), account.account_id());
        assert_eq!(phone.account_id(), account.account_id());
        assert_ne!(laptop.device_id(), phone.device_id());
        assert_ne!(laptop.ed25519_public_key(), phone.ed25519_public_key());
        assert_ne!(laptop.x25519_public_key(), phone.x25519_public_key());
    }

    #[test]
    fn modified_device_certificate_fails_verification() {
        let account = AccountIdentity::generate();
        let laptop = DeviceIdentity::generate(account.account_id());
        let mut certificate = account.authorize_device(&laptop);

        certificate.device_x25519_public_key[0] ^= 0x01;

        assert_eq!(
            verify_device_certificate(account.public_key(), &certificate),
            Err(CryptoError::SignatureVerification)
        );
    }

    #[test]
    fn certificate_signed_by_other_account_does_not_authorize_alice_device() {
        let alice_account = AccountIdentity::generate();
        let other_account = AccountIdentity::generate();
        let laptop = DeviceIdentity::generate(alice_account.account_id());
        let certificate = other_account.authorize_device(&laptop);

        assert_eq!(
            verify_device_certificate(alice_account.public_key(), &certificate),
            Err(CryptoError::SignatureVerification)
        );
    }

    #[test]
    fn account_identity_survives_export_and_restore() {
        let account = AccountIdentity::generate();
        let state = account.export_state();
        let restored = AccountIdentity::from_state(state);

        assert_eq!(account.account_id(), restored.account_id());
        assert_eq!(account.public_key(), restored.public_key());
    }

    #[test]
    fn authorized_sibling_devices_verify_for_same_account() {
        let account = AccountIdentity::generate();
        let laptop = DeviceIdentity::generate(account.account_id());
        let phone = DeviceIdentity::generate(account.account_id());
        let laptop_cert = account.authorize_device(&laptop);
        let phone_cert = account.authorize_device(&phone);

        verify_authorized_sibling_devices(account.public_key(), &laptop_cert, &phone_cert)
            .expect("same account siblings verify");
    }

    #[test]
    fn sibling_device_check_rejects_other_account_certificate() {
        let account = AccountIdentity::generate();
        let other = AccountIdentity::generate();
        let laptop = DeviceIdentity::generate(account.account_id());
        let phone = DeviceIdentity::generate(other.account_id());
        let laptop_cert = account.authorize_device(&laptop);
        let phone_cert = other.authorize_device(&phone);

        assert_eq!(
            verify_authorized_sibling_devices(account.public_key(), &laptop_cert, &phone_cert),
            Err(CryptoError::SignatureVerification)
        );
    }

    #[test]
    fn revoked_device_certificate_is_not_currently_authorized() {
        let account = AccountIdentity::generate();
        let phone = DeviceIdentity::generate(account.account_id());
        let certificate = account.authorize_device(&phone);
        let revocation = account.revoke_device(phone.device_id().to_string(), 1);

        verify_device_certificate(account.public_key(), &certificate)
            .expect("old certificate was valid");
        verify_device_revocation(account.public_key(), &revocation).expect("revocation verifies");
        assert_eq!(
            is_device_currently_authorized(account.public_key(), &certificate, &[revocation]),
            Ok(false)
        );
    }

    #[test]
    fn modified_device_revocation_fails_verification() {
        let account = AccountIdentity::generate();
        let phone = DeviceIdentity::generate(account.account_id());
        let mut revocation = account.revoke_device(phone.device_id().to_string(), 1);

        revocation.device_id.push_str("-modified");

        assert_eq!(
            verify_device_revocation(account.public_key(), &revocation),
            Err(CryptoError::SignatureVerification)
        );
    }

    #[test]
    fn active_device_certificates_excludes_revoked_phone() {
        let (account, laptop, phone, _, laptop_cert, phone_cert) = fanout_identities();
        let revocation = account.revoke_device(phone.device_id().to_string(), 1);

        let active = active_device_certificates(
            account.public_key(),
            &[laptop_cert, phone_cert],
            &[revocation],
        )
        .expect("active list");

        assert_eq!(active.len(), 1);
        assert_eq!(active[0].device_id, laptop.device_id());
        assert_ne!(active[0].device_id, phone.device_id());
    }

    #[test]
    fn fanout_encrypts_separately_per_authorized_device() {
        let (account, laptop, phone, bob, laptop_cert, phone_cert) = fanout_identities();
        let mut laptop_sender = bob
            .create_outbound_session(account.public_key(), &laptop_cert)
            .expect("laptop sender session");
        let mut phone_sender = bob
            .create_outbound_session(account.public_key(), &phone_cert)
            .expect("phone sender session");
        let mut laptop_receiver = laptop
            .create_inbound_session(bob.device_id().to_string(), bob.x25519_public_key())
            .expect("laptop receiver session");
        let mut phone_receiver = phone
            .create_inbound_session(bob.device_id().to_string(), bob.x25519_public_key())
            .expect("phone receiver session");

        let laptop_envelope = laptop_sender
            .encrypt("logical-1", "hello alice")
            .expect("laptop encrypt");
        let phone_envelope = phone_sender
            .encrypt("logical-1", "hello alice")
            .expect("phone encrypt");

        assert_eq!(
            laptop_envelope.logical_message_id,
            phone_envelope.logical_message_id
        );
        assert_ne!(
            laptop_envelope.message.ciphertext,
            phone_envelope.message.ciphertext
        );
        assert_eq!(
            laptop_receiver
                .decrypt(&laptop_envelope)
                .expect("laptop decrypt"),
            "hello alice"
        );
        assert_eq!(
            phone_receiver
                .decrypt(&phone_envelope)
                .expect("phone decrypt"),
            "hello alice"
        );
    }

    #[test]
    fn incorrect_device_cannot_decrypt_another_device_envelope() {
        let (account, laptop, phone, bob, laptop_cert, _) = fanout_identities();
        let mut laptop_sender = bob
            .create_outbound_session(account.public_key(), &laptop_cert)
            .expect("laptop sender session");
        let mut phone_receiver = phone
            .create_inbound_session(bob.device_id().to_string(), bob.x25519_public_key())
            .expect("phone receiver session");
        let envelope = laptop_sender
            .encrypt("logical-1", "for laptop only")
            .expect("encrypt");

        assert_eq!(phone_receiver.decrypt(&envelope), Err(CryptoError::Decrypt));
        assert_eq!(envelope.recipient_device_id, laptop.device_id());
    }

    #[test]
    fn per_device_session_counters_advance_independently() {
        let (account, _, _, bob, laptop_cert, phone_cert) = fanout_identities();
        let mut laptop_sender = bob
            .create_outbound_session(account.public_key(), &laptop_cert)
            .expect("laptop sender session");
        let mut phone_sender = bob
            .create_outbound_session(account.public_key(), &phone_cert)
            .expect("phone sender session");

        laptop_sender
            .encrypt("logical-1", "first laptop copy")
            .expect("first laptop encrypt");
        laptop_sender
            .encrypt("logical-2", "second laptop copy")
            .expect("second laptop encrypt");
        phone_sender
            .encrypt("logical-1", "first phone copy")
            .expect("phone encrypt");

        assert_eq!(laptop_sender.session_state().send_count, 2);
        assert_eq!(phone_sender.session_state().send_count, 1);
    }

    fn fanout_identities() -> (
        AccountIdentity,
        DeviceIdentity,
        DeviceIdentity,
        DeviceIdentity,
        DeviceCertificate,
        DeviceCertificate,
    ) {
        let account = AccountIdentity::generate();
        let laptop = DeviceIdentity::generate(account.account_id());
        let phone = DeviceIdentity::generate(account.account_id());
        let bob = DeviceIdentity::generate("bob-account");
        let laptop_cert = account.authorize_device(&laptop);
        let phone_cert = account.authorize_device(&phone);

        (account, laptop, phone, bob, laptop_cert, phone_cert)
    }

    #[test]
    fn consumed_message_keys_are_not_reused() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let encrypted = alice.encrypt_for_bob("use once").expect("encrypt");
        assert_eq!(
            bob.decrypt_from_alice(&encrypted).expect("first decrypt"),
            "use once"
        );

        assert_eq!(bob.decrypt_from_alice(&encrypted), Err(CryptoError::Replay));
    }

    #[test]
    fn replayed_message_is_rejected() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let encrypted = alice.encrypt_for_bob("no replay").expect("encrypt");
        bob.decrypt_from_alice(&encrypted).expect("first decrypt");
        let replay = send_over_simulated_transport(encrypted);

        assert_eq!(bob.decrypt_from_alice(&replay), Err(CryptoError::Replay));
    }

    #[test]
    fn exported_state_restores_ratchet_without_new_handshake() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let before_restart = alice
            .encrypt_for_bob("before restart")
            .expect("encrypt before restart");
        assert_eq!(
            bob.decrypt_from_alice(&before_restart)
                .expect("decrypt before restart"),
            "before restart"
        );

        let mut restored_alice = Alice::from_state(alice.export_state());
        let mut restored_bob = Bob::from_state(bob.export_state());
        let after_restart = restored_alice
            .encrypt_for_bob("after restart")
            .expect("encrypt after restart");

        assert_eq!(
            restored_bob
                .decrypt_from_alice(&after_restart)
                .expect("decrypt after restart"),
            "after restart"
        );
    }

    #[test]
    fn limited_out_of_order_delivery_decrypts_correctly() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let first = alice.encrypt_for_bob("first").expect("first");
        let second = alice.encrypt_for_bob("second").expect("second");
        let third = alice.encrypt_for_bob("third").expect("third");

        assert_eq!(bob.decrypt_from_alice(&third).expect("third"), "third");
        assert_eq!(bob.decrypt_from_alice(&first).expect("first"), "first");
        assert_eq!(bob.decrypt_from_alice(&second).expect("second"), "second");
    }

    #[test]
    fn dh_ratchet_step_changes_state_and_communication_still_succeeds() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice
            .derive_session_key(&bob_exchange)
            .expect("alice derives session key");
        bob.derive_session_key(&alice_exchange)
            .expect("bob derives session key");

        let old_root = alice.session.as_ref().expect("alice session").root_key;
        alice
            .rotate_sending_ratchet()
            .expect("alice rotates sending ratchet");
        let ratcheted = alice
            .encrypt_for_bob("after dh ratchet")
            .expect("encrypt after ratchet");

        assert_ne!(
            old_root,
            alice.session.as_ref().expect("alice session").root_key
        );
        assert_eq!(
            bob.decrypt_from_alice(&ratcheted).expect("bob decrypts"),
            "after dh ratchet"
        );
        assert_eq!(
            alice.session.as_ref().expect("alice session").root_key,
            bob.session.as_ref().expect("bob session").root_key
        );
    }

    #[test]
    fn prekey_bundle_and_initial_message_serialize_as_network_bytes() {
        let mut alice = Alice::local();
        let bob = Bob::local();
        let bundle = bob.prekey_bundle().expect("bob publishes prekey bundle");

        let bundle_bytes = bincode::serialize(&bundle).expect("serialize bundle");
        assert!(!bundle_bytes
            .windows("hello network".len())
            .any(|window| window == b"hello network"));
        let decoded_bundle: PreKeyBundle =
            bincode::deserialize(&bundle_bytes).expect("deserialize bundle");
        assert_eq!(decoded_bundle, bundle);

        let initial_message = alice
            .encrypt_initial_message(&decoded_bundle, "hello network")
            .expect("encrypt initial message");
        let message_bytes = bincode::serialize(&initial_message).expect("serialize message");
        assert!(!message_bytes
            .windows("hello network".len())
            .any(|window| window == b"hello network"));
        let decoded_message: InitialMessage =
            bincode::deserialize(&message_bytes).expect("deserialize message");

        assert_eq!(decoded_message, initial_message);
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use crate::{
        crdt::{event_record, materialize_conversation, ConversationEvent},
        mailbox_storage::{MailboxEnvelopeRecord, MailboxStorage},
        storage::{
            now_unix_secs, EventRecord, MessageDirection, MessageRecord, MessageStatus, OutboxItem,
            OutboxStatus, Storage, VersionVector,
        },
    };

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct HardeningEnvelope {
        message_id: String,
        message: RatchetMessage,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct HardeningAck {
        message_id: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct HardeningEventWire {
        device_id: String,
        counter: u64,
        conversation_id: String,
        event_type: String,
        message_id: Option<String>,
        payload: Vec<u8>,
        created_at_unix_secs: u64,
    }

    impl From<EventRecord> for HardeningEventWire {
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

    impl From<HardeningEventWire> for EventRecord {
        fn from(event: HardeningEventWire) -> Self {
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

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Fault {
        Drop,
        Delay,
        Duplicate,
        Reorder,
        Replay,
        Tamper(usize),
        Partition,
    }

    #[derive(Default)]
    struct FaultInjector {
        delayed: Vec<(String, Vec<u8>)>,
        replayed: Vec<(String, Vec<u8>)>,
        logs: Vec<String>,
    }

    impl FaultInjector {
        fn deliver(&mut self, id: &str, payload: Vec<u8>, faults: &[Fault]) -> Vec<Vec<u8>> {
            if faults.contains(&Fault::Partition) {
                self.logs.push(format!("[FAULT] partitioned {id}"));
                return Vec::new();
            }
            if faults.contains(&Fault::Drop) {
                self.logs.push(format!("[FAULT] dropped {id}"));
                return Vec::new();
            }

            let mut payload = payload;
            for fault in faults {
                if let Fault::Tamper(index) = fault {
                    if let Some(byte) = payload.get_mut(*index) {
                        *byte ^= 0x01;
                        self.logs.push(format!("[FAULT] tampered {id}"));
                    }
                }
            }

            if faults.contains(&Fault::Delay) {
                self.logs.push(format!("[FAULT] delayed {id}"));
                self.delayed.push((id.to_string(), payload.clone()));
                return Vec::new();
            }

            let mut delivered = vec![payload.clone()];
            if faults.contains(&Fault::Duplicate) {
                self.logs.push(format!("[FAULT] duplicated {id}"));
                delivered.push(payload.clone());
            }
            if faults.contains(&Fault::Replay) {
                self.logs.push(format!("[FAULT] replay scheduled {id}"));
                self.replayed.push((id.to_string(), payload));
            }
            if faults.contains(&Fault::Reorder) {
                self.logs.push("[FAULT] reordered batch".to_string());
                delivered.reverse();
            }

            delivered
        }

        fn flush_delayed(&mut self) -> Vec<Vec<u8>> {
            let mut flushed = std::mem::take(&mut self.delayed);
            flushed.sort_by(|left, right| right.0.cmp(&left.0));
            flushed.into_iter().map(|(_, payload)| payload).collect()
        }

        fn replay(&self) -> Vec<Vec<u8>> {
            self.replayed
                .iter()
                .map(|(_, payload)| payload.clone())
                .collect()
        }
    }

    #[test]
    fn fault_injector_is_deterministic_and_disabled_by_default() {
        let payload = b"encrypted bytes".to_vec();
        let mut injector = FaultInjector::default();

        assert_eq!(
            injector.deliver("M1", payload.clone(), &[]),
            vec![payload.clone()]
        );
        assert!(injector.logs.is_empty());

        assert!(injector
            .deliver("M2", payload.clone(), &[Fault::Drop])
            .is_empty());
        assert!(injector
            .deliver("M3", payload.clone(), &[Fault::Delay])
            .is_empty());
        assert_ne!(
            injector.deliver("M4", payload.clone(), &[Fault::Tamper(0)]),
            vec![payload.clone()]
        );
        assert_eq!(injector.flush_delayed(), vec![payload]);
        assert!(injector
            .logs
            .iter()
            .any(|line| line == "[FAULT] dropped M2"));
        assert!(injector
            .logs
            .iter()
            .any(|line| line == "[FAULT] delayed M3"));
        assert!(injector
            .logs
            .iter()
            .any(|line| line == "[FAULT] tampered M4"));
    }

    #[test]
    fn dropped_message_and_partition_leave_outbox_pending_until_retry() {
        let mut sender = Storage::open_in_memory().expect("sender storage");
        let receiver = Storage::open_in_memory().expect("receiver storage");
        let (mut alice, mut bob) = paired_alice_bob();
        let outbox = queue_alice_message(&mut sender, &mut alice, "M1", "drop then retry");
        let mut fault = FaultInjector::default();

        assert!(fault
            .deliver(&outbox.message_id, outbox.payload.clone(), &[Fault::Drop])
            .is_empty());
        assert_eq!(sender.pending_outbox_items().unwrap().len(), 1);

        sender.record_outbox_attempt(&outbox.message_id).unwrap();
        for payload in fault.deliver(&outbox.message_id, outbox.payload.clone(), &[]) {
            let ack = receive_for_bob(&receiver, &mut bob, &payload).expect("retry accepted");
            sender.mark_outbox_delivered(&ack.message_id).unwrap();
        }

        assert!(sender.pending_outbox_items().unwrap().is_empty());
        assert!(fault.logs.iter().any(|line| line == "[FAULT] dropped M1"));

        let partitioned = queue_alice_message(&mut sender, &mut alice, "M2", "partitioned");
        assert!(fault
            .deliver(
                &partitioned.message_id,
                partitioned.payload,
                &[Fault::Partition]
            )
            .is_empty());
        assert_eq!(sender.pending_outbox_items().unwrap().len(), 1);
    }

    #[test]
    fn dropped_ack_causes_retry_without_duplicate_processing() {
        let mut sender = Storage::open_in_memory().expect("sender storage");
        let receiver = Storage::open_in_memory().expect("receiver storage");
        let (mut alice, mut bob) = paired_alice_bob();
        let outbox = queue_alice_message(&mut sender, &mut alice, "M1", "ack may drop");
        let payload = outbox.payload.clone();

        let ack = receive_for_bob(&receiver, &mut bob, &payload).expect("first receive");
        let mut fault = FaultInjector::default();
        assert!(fault
            .deliver(
                &ack.message_id,
                bincode::serialize(&ack).unwrap(),
                &[Fault::Drop]
            )
            .is_empty());
        assert_eq!(sender.pending_outbox_items().unwrap().len(), 1);

        sender.record_outbox_attempt(&outbox.message_id).unwrap();
        let retry_ack = receive_for_bob(&receiver, &mut bob, &payload).expect("duplicate ack");
        sender.mark_outbox_delivered(&retry_ack.message_id).unwrap();

        assert!(sender.pending_outbox_items().unwrap().is_empty());
        assert_eq!(
            receiver
                .messages_for_conversation("hardening")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn duplicate_delayed_reordered_and_replayed_delivery_processes_once() {
        let receiver = Storage::open_in_memory().expect("receiver storage");
        let (mut alice, mut bob) = paired_alice_bob();
        let first = hardening_payload(&mut alice, "M1", "first");
        let second = hardening_payload(&mut alice, "M2", "second");
        let mut fault = FaultInjector::default();
        let mut delivered = Vec::new();

        delivered.extend(fault.deliver("M1", first.clone(), &[Fault::Delay, Fault::Replay]));
        delivered.extend(fault.deliver("M2", second, &[Fault::Duplicate]));
        delivered.extend(fault.flush_delayed());
        delivered.extend(fault.replay());
        delivered.reverse();

        for payload in delivered {
            let _ = receive_for_bob(&receiver, &mut bob, &payload);
        }

        assert_eq!(
            receiver
                .messages_for_conversation("hardening")
                .unwrap()
                .len(),
            2
        );
        assert!(fault.logs.iter().any(|line| line == "[FAULT] delayed M1"));
        assert!(fault
            .logs
            .iter()
            .any(|line| line == "[FAULT] duplicated M2"));
    }

    #[test]
    fn sender_and_receiver_restart_keep_pending_ciphertext_deliverable() {
        let path = std::env::temp_dir().join(format!(
            "ciphermesh-hardening-outbox-{}.sqlite",
            now_unix_secs()
        ));
        let mut sender = Storage::open(&path).expect("sender storage");
        let receiver = Storage::open_in_memory().expect("receiver storage");
        let (mut alice, bob) = paired_alice_bob();
        let bob_state = bob.export_state();
        let outbox = queue_alice_message(&mut sender, &mut alice, "M1", "after restart");
        drop(sender);

        let sender = Storage::open(&path).expect("sender restarted");
        let pending = sender
            .pending_outbox_items()
            .expect("pending after restart");
        let mut restarted_bob = Bob::from_state(bob_state);
        let ack = receive_for_bob(&receiver, &mut restarted_bob, &pending[0].payload)
            .expect("receiver accepts after restart");

        assert_eq!(pending[0].payload, outbox.payload);
        sender.mark_outbox_delivered(&ack.message_id).unwrap();
        assert!(sender.pending_outbox_items().unwrap().is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mailbox_fallback_and_duplicate_direct_mailbox_delivery_process_once() {
        let receiver = Storage::open_in_memory().expect("receiver storage");
        let mailbox = MailboxStorage::open_in_memory(8).expect("mailbox");
        let (mut alice, mut bob) = paired_alice_bob();
        let payload = hardening_payload(&mut alice, "M1", "via mailbox");

        mailbox
            .deposit(
                &MailboxEnvelopeRecord {
                    message_id: "M1".to_string(),
                    recipient_token: "bob-device".to_string(),
                    encrypted_payload: payload.clone(),
                    created_at_unix_secs: 1,
                    expires_at_unix_secs: None,
                },
                1,
            )
            .expect("deposit");
        receive_for_bob(&receiver, &mut bob, &payload).expect("direct receive");
        let fetched = mailbox.fetch_pending("bob-device", 2).expect("fetch");
        let ack = receive_for_bob(&receiver, &mut bob, &fetched[0].encrypted_payload)
            .expect("mailbox duplicate ack");
        mailbox.acknowledge_retrieval(&ack.message_id, 3).unwrap();

        assert_eq!(
            receiver
                .messages_for_conversation("hardening")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(mailbox.pending_count().unwrap(), 0);
    }

    #[test]
    fn tampered_ciphertext_and_authentication_tag_are_rejected() {
        let (_alice, mut bob, mut payload) = encrypted_payload_for_bob("M1", "do not alter");
        let receiver = Storage::open_in_memory().expect("receiver storage");
        let mut tampered_body = payload.clone();

        let middle = tampered_body.len() / 2;
        tampered_body[middle] ^= 0x01;
        assert!(receive_for_bob(&receiver, &mut bob, &tampered_body).is_err());

        let (_alice, mut bob, tag_payload) = encrypted_payload_for_bob("M2", "tag check");
        let mut tampered_tag = tag_payload;
        let last = tampered_tag.len() - 1;
        tampered_tag[last] ^= 0x01;
        assert!(receive_for_bob(&receiver, &mut bob, &tampered_tag).is_err());

        payload[0] ^= 0x01;
        assert!(bincode::deserialize::<HardeningEnvelope>(&payload).is_err());
    }

    #[test]
    fn skipped_key_bound_is_enforced() {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice.derive_session_key(&bob_exchange).unwrap();
        bob.derive_session_key(&alice_exchange).unwrap();

        let mut messages = Vec::new();
        for index in 0..=MAX_SKIPPED_MESSAGE_KEYS as u64 + 1 {
            messages.push(
                alice
                    .encrypt_for_bob(&format!("message {index}"))
                    .expect("encrypt"),
            );
        }

        assert_eq!(
            bob.decrypt_from_alice(messages.last().unwrap()),
            Err(CryptoError::TooManySkippedMessages)
        );
    }

    #[test]
    fn revoked_device_gets_no_future_hardening_envelope() {
        let account = AccountIdentity::generate();
        let laptop = DeviceIdentity::generate(account.account_id());
        let phone = DeviceIdentity::generate(account.account_id());
        let bob = DeviceIdentity::generate("bob-account");
        let laptop_cert = account.authorize_device(&laptop);
        let phone_cert = account.authorize_device(&phone);
        let revocation = account.revoke_device(phone.device_id().to_string(), 1);
        let active = active_device_certificates(
            account.public_key(),
            &[laptop_cert.clone(), phone_cert],
            &[revocation],
        )
        .expect("active devices");

        let mut envelopes = Vec::new();
        for certificate in active {
            let mut session = bob
                .create_outbound_session(account.public_key(), &certificate)
                .expect("session");
            envelopes.push(session.encrypt("M1", "future only").unwrap());
        }

        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].recipient_device_id, laptop_cert.device_id);
    }

    #[test]
    fn eventually_same_valid_event_set_converges_despite_faults() {
        let alice = Storage::open_in_memory().expect("alice");
        let bob = Storage::open_in_memory().expect("bob");
        let conversation = "hardening-crdt";
        let events = [
            crdt_message(conversation, "AliceDevice", 1, "message-1", "alice"),
            crdt_reaction(conversation, "BobDevice", 1, "message-1", "+1", "bob"),
            crdt_delete(conversation, "AliceDevice", 2, "message-1"),
            crdt_read(conversation, "BobDevice", 2, "AliceDevice", 2),
        ];
        let mut fault = FaultInjector::default();
        let mut encoded = events
            .iter()
            .cloned()
            .map(HardeningEventWire::from)
            .map(|event| bincode::serialize(&event).unwrap())
            .collect::<Vec<_>>();
        encoded.reverse();

        for payload in encoded.clone() {
            let decoded: HardeningEventWire = bincode::deserialize(&payload).unwrap();
            let decoded = EventRecord::from(decoded);
            alice.append_event(&decoded).unwrap();
        }
        for payload in fault.deliver(
            "events",
            bincode::serialize(&HardeningEventWire::from(events[0].clone())).unwrap(),
            &[Fault::Duplicate],
        ) {
            let decoded: HardeningEventWire = bincode::deserialize(&payload).unwrap();
            let decoded = EventRecord::from(decoded);
            bob.append_event(&decoded).unwrap();
        }
        for payload in encoded {
            let decoded: HardeningEventWire = bincode::deserialize(&payload).unwrap();
            let decoded = EventRecord::from(decoded);
            bob.append_event(&decoded).unwrap();
        }

        assert_eq!(
            materialize_conversation(&all_events(&alice, conversation)),
            materialize_conversation(&all_events(&bob, conversation))
        );
    }

    #[test]
    fn multiple_alice_devices_create_events_offline_then_sync_converges() {
        let laptop = Storage::open_in_memory().expect("laptop");
        let phone = Storage::open_in_memory().expect("phone");
        let conversation = "hardening-own-devices";

        laptop
            .append_event(&crdt_message(
                conversation,
                "AliceLaptop",
                1,
                "laptop-message",
                "alice",
            ))
            .unwrap();
        phone
            .append_event(&crdt_message(
                conversation,
                "AlicePhone",
                1,
                "phone-message",
                "alice",
            ))
            .unwrap();

        let phone_missing = laptop
            .missing_events_for(conversation, &phone.version_vector(conversation).unwrap())
            .unwrap();
        let laptop_missing = phone
            .missing_events_for(conversation, &laptop.version_vector(conversation).unwrap())
            .unwrap();
        phone.append_events(&phone_missing).unwrap();
        laptop.append_events(&laptop_missing).unwrap();

        assert_eq!(
            materialize_conversation(&all_events(&laptop, conversation)),
            materialize_conversation(&all_events(&phone, conversation))
        );
    }

    fn paired_alice_bob() -> (Alice, Bob) {
        let mut alice = Alice::local();
        let mut bob = Bob::local();
        let alice_exchange = alice.signed_key_exchange();
        let bob_exchange = bob.signed_key_exchange();
        alice.derive_session_key(&bob_exchange).unwrap();
        bob.derive_session_key(&alice_exchange).unwrap();
        (alice, bob)
    }

    fn encrypted_payload_for_bob(message_id: &str, plaintext: &str) -> (Alice, Bob, Vec<u8>) {
        let (mut alice, bob) = paired_alice_bob();
        let payload = hardening_payload(&mut alice, message_id, plaintext);
        (alice, bob, payload)
    }

    fn hardening_payload(alice: &mut Alice, message_id: &str, plaintext: &str) -> Vec<u8> {
        let message = alice.encrypt_for_bob(plaintext).expect("encrypt");
        bincode::serialize(&HardeningEnvelope {
            message_id: message_id.to_string(),
            message,
        })
        .expect("serialize envelope")
    }

    fn queue_alice_message(
        storage: &mut Storage,
        alice: &mut Alice,
        message_id: &str,
        plaintext: &str,
    ) -> OutboxItem {
        let payload = hardening_payload(alice, message_id, plaintext);
        let wire: HardeningEnvelope = bincode::deserialize(&payload).unwrap();
        let outbox = OutboxItem {
            message_id: message_id.to_string(),
            recipient_id: "bob".to_string(),
            payload,
            status: OutboxStatus::Pending,
            retry_count: 0,
            created_at_unix_secs: 1,
            last_attempt_unix_secs: None,
        };
        let message = MessageRecord {
            message_id: message_id.to_string(),
            conversation_id: "hardening".to_string(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Sent,
            status: MessageStatus::Sent,
            protocol_counter: Some(wire.message.number),
            ciphertext: wire.message.ciphertext,
            plaintext: Some(plaintext.to_string()),
            created_at_unix_secs: 1,
        };
        let alice_state = bincode::serialize(&alice.export_state()).unwrap();
        let session_state = bincode::serialize(&alice.session_state().unwrap()).unwrap();

        storage
            .save_state_session_message_and_outbox(
                "alice",
                "alice",
                &alice_state,
                "hardening",
                "bob",
                "alice",
                &session_state,
                &message,
                &outbox,
            )
            .unwrap();

        outbox
    }

    fn receive_for_bob(
        storage: &Storage,
        bob: &mut Bob,
        payload: &[u8],
    ) -> Result<HardeningAck, Box<dyn Error + Send + Sync>> {
        let envelope: HardeningEnvelope = bincode::deserialize(payload)?;
        if storage
            .messages_for_conversation("hardening")?
            .iter()
            .any(|message| message.message_id == envelope.message_id)
        {
            return Ok(HardeningAck {
                message_id: envelope.message_id,
            });
        }

        let plaintext = bob.decrypt_from_alice(&envelope.message)?;
        if !storage.accept_message_once(&envelope.message_id)? {
            return Ok(HardeningAck {
                message_id: envelope.message_id,
            });
        }
        storage.insert_message(&MessageRecord {
            message_id: envelope.message_id.clone(),
            conversation_id: "hardening".to_string(),
            sender_id: "alice".to_string(),
            recipient_id: "bob".to_string(),
            direction: MessageDirection::Received,
            status: MessageStatus::Received,
            protocol_counter: Some(envelope.message.number),
            ciphertext: envelope.message.ciphertext,
            plaintext: Some(plaintext),
            created_at_unix_secs: 1,
        })?;

        Ok(HardeningAck {
            message_id: envelope.message_id,
        })
    }

    fn crdt_message(
        conversation: &str,
        device_id: &str,
        counter: u64,
        message_id: &str,
        author_id: &str,
    ) -> EventRecord {
        event_record(
            conversation,
            device_id,
            counter,
            ConversationEvent::MessageCreated {
                message_id: message_id.to_string(),
                author_id: author_id.to_string(),
                payload: format!("{message_id} body").into_bytes(),
            },
        )
        .unwrap()
    }

    fn crdt_reaction(
        conversation: &str,
        device_id: &str,
        counter: u64,
        message_id: &str,
        reaction: &str,
        actor_id: &str,
    ) -> EventRecord {
        event_record(
            conversation,
            device_id,
            counter,
            ConversationEvent::ReactionAdded {
                message_id: message_id.to_string(),
                reaction: reaction.to_string(),
                actor_id: actor_id.to_string(),
            },
        )
        .unwrap()
    }

    fn crdt_delete(
        conversation: &str,
        device_id: &str,
        counter: u64,
        message_id: &str,
    ) -> EventRecord {
        event_record(
            conversation,
            device_id,
            counter,
            ConversationEvent::MessageDeleted {
                message_id: message_id.to_string(),
            },
        )
        .unwrap()
    }

    fn crdt_read(
        conversation: &str,
        device_id: &str,
        counter: u64,
        read_device_id: &str,
        read_counter: u64,
    ) -> EventRecord {
        event_record(
            conversation,
            device_id,
            counter,
            ConversationEvent::ReadAdvanced {
                actor_id: "bob".to_string(),
                read_device_id: read_device_id.to_string(),
                read_counter,
            },
        )
        .unwrap()
    }

    fn all_events(storage: &Storage, conversation: &str) -> Vec<EventRecord> {
        storage
            .missing_events_for(conversation, &VersionVector::new())
            .unwrap()
    }
}
