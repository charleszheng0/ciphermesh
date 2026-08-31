use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};

const LOCAL_SHARED_KEY: [u8; 32] = [
    0x29, 0x8d, 0x52, 0xb4, 0x3a, 0x9f, 0x1c, 0x77, 0xe5, 0x68, 0x0b, 0x22, 0x93, 0xa1, 0xdf,
    0x44, 0x18, 0x67, 0xf0, 0xbe, 0x3c, 0x9a, 0x25, 0x6d, 0xca, 0x71, 0x04, 0xee, 0x5b, 0x38,
    0x90, 0x13,
];
const ONE_MESSAGE_NONCE: [u8; 12] = [0x61, 0x6c, 0x69, 0x63, 0x65, 0x2d, 0x62, 0x6f, 0x62, 0x2d, 0x30, 0x31];
const LOCAL_AAD: &[u8] = b"ciphermesh.local.alice-to-bob.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    Encrypt,
    Decrypt,
    Utf8,
}

pub struct Alice {
    cipher: ChaCha20Poly1305,
}

pub struct Bob {
    cipher: ChaCha20Poly1305,
}

impl Alice {
    pub fn local() -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&LOCAL_SHARED_KEY.into()),
        }
    }

    pub fn encrypt_for_bob(&self, message: &str) -> Result<Vec<u8>, CryptoError> {
        self.cipher
            .encrypt(
                Nonce::from_slice(&ONE_MESSAGE_NONCE),
                Payload {
                    msg: message.as_bytes(),
                    aad: LOCAL_AAD,
                },
            )
            .map_err(|_| CryptoError::Encrypt)
    }
}

impl Bob {
    pub fn local() -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&LOCAL_SHARED_KEY.into()),
        }
    }

    pub fn decrypt_from_alice(&self, ciphertext: &[u8]) -> Result<String, CryptoError> {
        let plaintext = self
            .cipher
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
}

pub fn send_over_simulated_transport(ciphertext: Vec<u8>) -> Vec<u8> {
    ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alice_encrypts_and_bob_decrypts_one_message() {
        let alice = Alice::local();
        let bob = Bob::local();
        let message = "hello bob, this is alice";

        let ciphertext = alice.encrypt_for_bob(message).expect("encrypt");
        assert_ne!(ciphertext, message.as_bytes());

        let received_ciphertext = send_over_simulated_transport(ciphertext);
        let plaintext = bob.decrypt_from_alice(&received_ciphertext).expect("decrypt");

        assert_eq!(plaintext, message);
    }

    #[test]
    fn bob_rejects_modified_ciphertext() {
        let alice = Alice::local();
        let bob = Bob::local();

        let mut ciphertext = alice.encrypt_for_bob("tamper with me").expect("encrypt");
        ciphertext[0] ^= 0x01;

        let received_ciphertext = send_over_simulated_transport(ciphertext);
        let result = bob.decrypt_from_alice(&received_ciphertext);

        assert_eq!(result, Err(CryptoError::Decrypt));
    }
}
