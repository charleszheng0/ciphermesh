use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::{rand_core::UnwrapErr, SysRng};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};
use x25519_dalek::{PublicKey, StaticSecret};

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
