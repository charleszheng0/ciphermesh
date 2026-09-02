# CipherMesh Security Model

CipherMesh is a prototype decentralized end-to-end encrypted messenger. Its security boundary is the application encryption layer, not the network path.

## Assets Protected

- Message plaintext.
- Account and device private keys.
- Session and Double Ratchet state.
- Message authenticity and tamper detection.
- Future message confidentiality as ratchet keys evolve.

## Attacker Model

An attacker may:

- Observe network traffic.
- Operate or control a relay.
- Operate or control a mailbox.
- Manipulate bootstrap, mDNS, or Kademlia discovery results.
- Replay, drop, delay, reorder, or tamper with traffic.
- Cause temporary partitions or disconnects.

## Provided Protections

- Application-level E2EE between authorized devices.
- Ed25519 signatures for identity and device authorization.
- X25519 key agreement with HKDF-derived symmetric keys.
- ChaCha20-Poly1305 authenticated encryption.
- Double Ratchet key evolution.
- Replay protection and skipped-key bounds.
- Per-device cryptographic sessions.
- Revoked devices excluded from future delivery.
- Durable outbox retry without re-encrypting old logical messages.
- Relay and mailbox nodes only see opaque encrypted bytes.

## Non-Goals And Limitations

- Compromised endpoints or malware reading local plaintext.
- Malicious authorized recipients.
- First-contact MITM without independent identity verification.
- Complete metadata privacy.
- Traffic-analysis resistance.
- Denial-of-service prevention.
- Remote deletion of data already stored on a stolen device.
- Account recovery, password reset, or cloud backup.
- Group chat.

## Identities

- `AccountId`: the user/account identity. It is derived from the account/root signing public key.
- `DeviceId`: one physical or logical device. Each device has its own Ed25519 and X25519 keys.
- `libp2p PeerId`: a networking identity used for discovery/connectivity. It is separate from CipherMesh account and device identity.

## Trust Boundaries

```text
User plaintext
    |
    v
CipherMesh crypto/session layer
    |
    v
Encrypted protocol bytes
    |
    +--> QUIC direct path
    +--> libp2p relay path
    +--> untrusted mailbox SQLite

Discovery: mDNS / bootstrap / Kademlia find peers and addresses.
Authentication: CipherMesh Ed25519/X25519/session logic verifies identities.
```

## Transport vs Application Encryption

QUIC/TLS protects a transport connection. CipherMesh also encrypts messages before they enter the network layer. Relays, mailboxes, and discovery systems are not trusted with plaintext or session keys.

## Discovery Trust

mDNS, bootstrap peers, and Kademlia help find peer addresses. They do not prove CipherMesh identity authenticity. A peer found through discovery must still be authenticated by the CipherMesh account/device/session layer.

## Relay Trust Model

Circuit Relay is untrusted forwarding infrastructure. It may observe metadata, drop traffic, delay traffic, or refuse service. It must not receive CipherMesh plaintext or keys.

## Mailbox Trust Model

The mailbox stores only routing tokens, message IDs, expiry/status metadata, and encrypted envelopes. Mailbox acceptance means ciphertext was stored for later; it does not mean the recipient accepted the message.

## SQLite Trust Assumptions

SQLite stores local identity, device keys, ratchet/session state, outbox items, message history, event history, version vectors, mailbox envelopes, and revocations. Local database files are sensitive and should be protected by the operating system. At this phase, database-at-rest encryption is not implemented.

## Device Revocation

An account/root key can sign a revocation for one `DeviceId`. Peers that learn the revocation treat the old certificate as historically valid but no longer current. Revocation protects future delivery only; it cannot erase data or keys already present on that device.
