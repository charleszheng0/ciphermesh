use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::{rand_core::UnwrapErr, SysRng};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const ONE_MESSAGE_NONCE: [u8; 12] = [
    0x61, 0x6c, 0x69, 0x63, 0x65, 0x2d, 0x62, 0x6f, 0x62, 0x2d, 0x30, 0x31,
];
const LOCAL_AAD: &[u8] = b"ciphermesh.local.alice-to-bob.v1";
const HKDF_INFO: &[u8] = b"ciphermesh.phase-2a.x25519.chacha20poly1305";
const PREKEY_HKDF_INFO: &[u8] = b"ciphermesh.phase-2c.prekey-initial-session";
const SIGNED_KEY_EXCHANGE_CONTEXT: &[u8] = b"ciphermesh.phase-2b.signed-x25519";
const SIGNED_PREKEY_CONTEXT: &[u8] = b"ciphermesh.phase-2c.signed-prekey";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    Encrypt,
    Decrypt,
    KeyDerivation,
    MissingSessionKey,
    PreKeyUnavailable,
    SignatureVerification,
    Utf8,
}

pub type PublicKeyBytes = [u8; 32];
pub type IdentityPublicKeyBytes = [u8; 32];
pub type SignatureBytes = [u8; 64];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKeyExchange {
    pub identity_public_key: IdentityPublicKeyBytes,
    pub x25519_public_key: PublicKeyBytes,
    pub signature: SignatureBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreKeyBundle {
    pub identity_public_key: IdentityPublicKeyBytes,
    pub signed_prekey_public_key: PublicKeyBytes,
    pub signed_prekey_signature: SignatureBytes,
    pub one_time_prekey_id: u64,
    pub one_time_prekey_public_key: PublicKeyBytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialMessage {
    pub alice_initial_public_key: PublicKeyBytes,
    pub one_time_prekey_id: u64,
    pub ciphertext: Vec<u8>,
}

struct X25519KeyPair {
    private: StaticSecret,
    public: PublicKey,
}

impl X25519KeyPair {
    fn generate() -> Self {
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);

        Self { private, public }
    }

    fn public_key(&self) -> PublicKeyBytes {
        self.public.to_bytes()
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

    fn public_key(&self) -> IdentityPublicKeyBytes {
        self.signing_key.verifying_key().to_bytes()
    }

    fn sign_key_exchange(&self, x25519_public_key: PublicKeyBytes) -> SignedKeyExchange {
        let identity_public_key = self.public_key();
        let signed_bytes = signed_key_exchange_bytes(identity_public_key, x25519_public_key);
        let signature = self.signing_key.sign(&signed_bytes);

        SignedKeyExchange {
            identity_public_key,
            x25519_public_key,
            signature: signature.to_bytes(),
        }
    }

    fn sign_prekey(&self, signed_prekey_public_key: PublicKeyBytes) -> SignatureBytes {
        let signed_bytes = signed_prekey_bytes(self.public_key(), signed_prekey_public_key);
        self.signing_key.sign(&signed_bytes).to_bytes()
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
    cipher: Option<ChaCha20Poly1305>,
}

pub struct Bob {
    identity: IdentityKeyPair,
    keys: X25519KeyPair,
    signed_prekey: X25519KeyPair,
    one_time_prekey: Option<OneTimePreKey>,
    cipher: Option<ChaCha20Poly1305>,
}

impl Alice {
    pub fn local() -> Self {
        Self {
            identity: IdentityKeyPair::generate(),
            keys: X25519KeyPair::generate(),
            cipher: None,
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
        self.cipher = Some(ChaCha20Poly1305::new(&key.into()));

        Ok(())
    }

    pub fn encrypt_for_bob(&self, message: &str) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .as_ref()
            .ok_or(CryptoError::MissingSessionKey)?
            .encrypt(
                Nonce::from_slice(&ONE_MESSAGE_NONCE),
                Payload {
                    msg: message.as_bytes(),
                    aad: LOCAL_AAD,
                },
            )
            .map_err(|_| CryptoError::Encrypt)
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
        self.cipher = Some(ChaCha20Poly1305::new(&key.into()));

        let ciphertext = self.encrypt_for_bob(message)?;

        Ok(InitialMessage {
            alice_initial_public_key: initial_keys.public_key(),
            one_time_prekey_id: bundle.one_time_prekey_id,
            ciphertext,
        })
    }
}

impl Bob {
    pub fn local() -> Self {
        Self {
            identity: IdentityKeyPair::generate(),
            keys: X25519KeyPair::generate(),
            signed_prekey: X25519KeyPair::generate(),
            one_time_prekey: Some(OneTimePreKey::generate(1)),
            cipher: None,
        }
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
        self.cipher = Some(ChaCha20Poly1305::new(&key.into()));

        Ok(())
    }

    pub fn decrypt_from_alice(&self, ciphertext: &[u8]) -> Result<String, CryptoError> {
        let plaintext = self
            .cipher
            .as_ref()
            .ok_or(CryptoError::MissingSessionKey)?
            .decrypt(
                Nonce::from_slice(&ONE_MESSAGE_NONCE),
                Payload {
                    msg: ciphertext,
                    aad: LOCAL_AAD,
                },
            )
            .map_err(|_| CryptoError::Decrypt)?;

        String::from_utf8(plaintext).map_err(|_| CryptoError::Utf8)
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
        self.cipher = Some(ChaCha20Poly1305::new(&key.into()));

        self.decrypt_from_alice(&message.ciphertext)
    }
}

pub fn send_over_simulated_transport(ciphertext: Vec<u8>) -> Vec<u8> {
    ciphertext
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

        let ciphertext = alice.encrypt_for_bob(message).expect("encrypt");
        assert_ne!(ciphertext, message.as_bytes());

        let received_ciphertext = send_over_simulated_transport(ciphertext);
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

        let mut ciphertext = alice.encrypt_for_bob("tamper with me").expect("encrypt");
        ciphertext[0] ^= 0x01;

        let received_ciphertext = send_over_simulated_transport(ciphertext);
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
}
