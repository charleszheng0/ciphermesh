# CipherMesh

CipherMesh is a Rust prototype of a decentralized end-to-end encrypted messenger. It is built incrementally to show how encrypted messaging, peer discovery, reliable delivery, local persistence, CRDT-style event convergence, and multi-device identity fit together.

## Why It Exists

The project is a learning and architecture prototype: each phase keeps the application crypto independent from the network path. Messages are encrypted before QUIC, relays, mailboxes, or discovery infrastructure see them.

## Architecture

```text
Alice / Bob CLI
    |
    v
CipherMesh account/device/session logic
    |
    v
Encrypted protocol bytes
    |
    +--> direct QUIC
    +--> libp2p discovery + relay fallback
    +--> persistent untrusted mailbox
    |
    v
SQLite local state / outbox / events / vectors
```

## Cross-Network Pairing Context

CipherMesh is being extended from same-LAN messaging to reliable cross-network
messaging between devices on different Wi-Fi networks. A small public libp2p
rendezvous/circuit-relay service gives peers a globally reachable meeting point
when direct LAN discovery or NAT traversal is insufficient. Users still see
only **Create Invite** with a short code and **Join Invite** with that code;
CipherMesh resolves peer routing internally, attempts a direct connection where
possible, and automatically falls back to the relay while preserving end-to-end
encryption. The selected initial deployment target is an Oracle Cloud Always
Free-eligible VM. See [PROJECT_CONTEXT.md](PROJECT_CONTEXT.md) for the reusable
project and resume summary.

## Crypto Stack

- Ed25519 for identity signatures and device certificates.
- X25519 for identity/session DH material.
- HKDF for key derivation.
- ChaCha20-Poly1305 for authenticated encryption.
- Double Ratchet for key evolution.
- Replay protection, skipped-key bounds, and per-device ratchet sessions.

## Networking Stack

- Tokio async runtime.
- QUIC transport via `quinn`.
- libp2p for persistent installation PeerIds and encrypted peer transport.
- A public CipherMesh rendezvous/circuit-relay service for six-character invites.
- mDNS and sanitized LAN addresses for direct same-network connections.
- Kademlia DHT for distributed peer/address lookup.
- AutoNAT/DCUtR/Circuit Relay support through rust-libp2p features.
- Persistent untrusted offline mailbox for store-and-forward.

## Storage And Distributed State

- SQLite via `rusqlite`.
- Local chat history for the endpoint's own conversation UI.
- Durable outbox with pending/delivered status.
- ACK/retry/deduplication.
- Append-only event history.
- Per-device event counters.
- Version vectors for missing-event sync.
- CRDT-style deterministic materialization.

## Multi-Device Model

- `AccountId`: user/account identity.
- `DeviceId`: one authorized device.
- `DeviceCertificate`: account-signed authorization for a device.
- Per-device sessions: one ratchet per local/remote device pair.
- Fanout: one logical message becomes separate encrypted envelopes per active recipient device.
- Own-device sync: authorized same-account devices exchange missing events.
- Revocation: account-signed removal of one device from future delivery/sync.

## Protocol And Data

Current wire/demo types are Rust structs serialized with `serde`/`bincode`, plus libp2p CBOR request-response for discovery/mailbox messages. `prost`/Protobuf is not currently wired in this repo.

Main message shapes include:

- `RatchetMessage`
- `InitialMessage`
- `DurableAppEnvelope`
- `DeviceDeliveryEnvelope`
- `SyncRequest`
- `SyncResponse`
- `OfflineEnvelope`
- `DeviceCertificate`
- `DeviceRevocation`

## Build

```bash
cargo build
```

Release binary:

```bash
cargo build --release
```

Windows packaging helper:

```powershell
.\scripts\package-release.ps1
.\dist\ciphermesh-windows-x64-ciphermesh.exe
```

macOS/Linux packaging helper:

```bash
./scripts/package-release.sh
./dist/ciphermesh-<macos|linux>-<x64|arm64>-ciphermesh
```

## CLI

```bash
cargo run
cargo run -- --verbose
cargo run -- create-invite [profile.sqlite]
cargo run -- join-invite <six-character-code> [profile.sqlite]
cargo run -- service /ip4/0.0.0.0/tcp/4001 [service-identity.key]
cargo run -- bob [listen-ip:port] [bootstrap-multiaddr...]
cargo run -- alice <bob-libp2p-peer-id> [message] [bootstrap-multiaddr...]
cargo run -- alice-direct [bob-ip:port] [message]
cargo run -- chat-bob [listen-ip:port]
cargo run -- chat-alice [bob-ip:port]
cargo run -- relay-demo
cargo run -- kad-demo
cargo run -- mailbox [/ip4/0.0.0.0/tcp/7000] [target/ciphermesh-mailbox.sqlite]
cargo run -- alice-mailbox <mailbox-multiaddr> [message] [target/ciphermesh-alice-mailbox.sqlite]
cargo run -- bob-mailbox <mailbox-multiaddr> [target/ciphermesh-bob-mailbox.sqlite]
cargo run -- restart-demo [target/ciphermesh-4a-demo.sqlite]
cargo run -- outbox-demo [target/ciphermesh-4b-outbox-demo.sqlite]
cargo run -- sync-demo
cargo run -- crdt-demo
cargo run -- device-demo
cargo run -- fanout-demo
cargo run -- own-device-sync-demo
cargo run -- revocation-demo
cargo run -- phase6-lan-smoke
cargo run -- phase6-invite-discovery-smoke
cargo run -- phase6-relay-smoke
cargo run -- phase6-mailbox-smoke
cargo run -- phase6-listener-doctor [0.0.0.0:5000] [hold-seconds]
```

Verbose logging is enabled with `--verbose`, `-v`, or `CIPHERMESH_VERBOSE=1`.

## Public Pairing Service

Run one persistent service on a VPS with TCP port 4001 open. Keep the identity
file on durable storage so the service PeerId does not change:

```bash
cargo run --release -- service /ip4/0.0.0.0/tcp/4001 /var/lib/ciphermesh/service.key
```

The service prints its listening address with its PeerId. Configure every
CipherMesh installation once, using the VPS public IP or DNS name and that
PeerId:

```text
CIPHERMESH_RENDEZVOUS=/ip4/PUBLIC_IP/tcp/4001/p2p/SERVICE_PEER_ID
```

Run the service command under the host's normal process supervisor (for
example, systemd) with the same identity-file path. The service keeps only
hashed, five-minute invite codes, the inviter's PeerId, and sanitized routing
addresses in memory. It will not register an invite until the inviter has an
active relay reservation, removes registrations when reservations end, and
consumes a code on its first successful resolution.

## Pairing On Any Network

On the host computer:

```bash
cargo run
```

Choose `Create invite`. CipherMesh prints only:

```text
Connecting...
Invite code: ABC2D3
Waiting for peer
```

On the joining computer:

```bash
cargo run
```

Choose `Join invite` and enter `ABC2D3`. CipherMesh tries a valid direct LAN
address first, lets DCUtR attempt a direct upgrade when available, and falls
back to the public circuit relay automatically. IP addresses, ports, PeerIds,
and multiaddrs are never part of the normal pairing UI.

## Local History Security

CipherMesh encrypts messages before they leave the device. QUIC peers, relays,
mailboxes, bootstrap nodes, and discovery infrastructure handle ciphertext or
routing metadata, not decrypted chat history.

The conversation history shown in the terminal is local endpoint state stored in
SQLite so the user can reopen chats after restart. That local plaintext history
is not uploaded by the invite, relay, mailbox, discovery, outbox, sync, or CRDT
paths, but a compromised endpoint or unprotected local database can expose it.
Database encryption at rest is a future hardening item; CipherMesh should use a
well-reviewed local key wrapping/database encryption design rather than a custom
scheme.

## Developer Networking Demos

The commands below are retained for protocol development. They expose raw
network addresses and are not part of the product pairing flow.

### Same-Machine Interactive Chat

Terminal 1:

```bash
cargo run -- chat-bob 127.0.0.1:5000
```

Terminal 2:

```bash
cargo run -- chat-alice 127.0.0.1:5000
```

Both sides stay alive, read stdin asynchronously, and print incoming messages immediately. Press Ctrl+C to shut down cleanly.

## Same-LAN Discovery Demo

Terminal 1:

```bash
cargo run -- bob 0.0.0.0:5000
```

Copy Bob's printed libp2p PeerId.

Terminal 2:

```bash
cargo run -- alice <bob-libp2p-peer-id>
```

Alice discovers Bob through mDNS/Kademlia and then starts interactive chat.

### Legacy Relay Test

Terminal 1:

```bash
cargo run -- service /ip4/0.0.0.0/tcp/4001 target/dev-service.key
```

Terminal 2:

```bash
cargo run -- bob 0.0.0.0:5000 <relay-multiaddr>
```

Wait for Bob to print both `Relay reservation accepted by <relay-peer-id>` and the
full `Bob relayed listening address: .../p2p-circuit/p2p/<bob-peer-id>` address.
A direct control connection to the relay by itself is not a reservation.

Terminal 3:

```bash
cargo run -- alice-relay <bob-libp2p-peer-id> "hello via relay" <relay-multiaddr>
```

You can also run:

```bash
cargo run -- relay-demo
```

## Offline Mailbox Demo

Terminal 1:

```bash
cargo run -- mailbox /ip4/0.0.0.0/tcp/7000 target/mailbox.db
```

Terminal 2, while Bob is offline:

```bash
cargo run -- alice-mailbox <mailbox-multiaddr> "hello offline bob" target/alice-mailbox.db
```

Terminal 3:

```bash
cargo run -- bob-mailbox <mailbox-multiaddr> target/bob-mailbox.db
```

The mailbox stores opaque ciphertext in SQLite and cannot decrypt it.

## Persistence And Outbox Demos

```bash
cargo run -- restart-demo target/ciphermesh-4a-demo.sqlite
cargo run -- outbox-demo target/ciphermesh-4b-outbox-demo.sqlite
```

These show identity/session/message persistence, atomic ratchet/message writes, durable pending outbox items, retry, ACK, and deduplication.

## Sync, CRDT, Multi-Device, Revocation

```bash
cargo run -- sync-demo
cargo run -- crdt-demo
cargo run -- device-demo
cargo run -- fanout-demo
cargo run -- own-device-sync-demo
cargo run -- revocation-demo
```

These demonstrate version-vector missing-event sync, CRDT convergence, account/device identity, per-device message fanout, own-device sync, and signed device revocation.

## Testing

Full suite:

```bash
cargo test
```

Phase 6 validation loop:

```bash
./scripts/phase6-loop.sh
```

Windows:

```powershell
.\scripts\phase6-loop.ps1
```

The Phase 6 loop also runs:

```bash
cargo run -- phase6-lan-smoke
cargo run -- phase6-invite-discovery-smoke
cargo run -- phase6-relay-smoke
cargo run -- phase6-mailbox-smoke
```

That smoke starts a real local QUIC listener on `0.0.0.0:<ephemeral>`, queues a pending message before connect, establishes a fresh chat, waits for an ACK, and fails if the pending message is not delivered exactly once and cleared.
The invite discovery smoke covers the legacy mDNS developer path. The pairing
test suite also starts the new combined public service locally, waits for a
confirmed reservation before registering, strips wildcard and loopback
addresses, consumes the invite once, forces circuit-relay delivery, and
verifies an encrypted ratchet message and ACK.
The relay smoke starts a local circuit relay, reserves Bob through it, dials Bob's relayed multiaddr from Alice, and verifies the secure message handshake plus ACK over the relay path.
The mailbox smoke starts an in-process libp2p mailbox, deposits an encrypted offline envelope, fetches it as Bob, ACKs retrieval, and fails if the mailbox still has pending ciphertext afterward.

For the Mac invite/listener check:

```bash
cargo run -- phase6-listener-doctor 0.0.0.0:5000 60
lsof -nP -iUDP:5000
```

The doctor uses the same QUIC listener startup and advertised-address logic as Create Invite, then keeps the listener alive long enough to inspect it.

Hardening suite:

```bash
cargo test hardening -- --nocapture
```

Lint:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

## Security Summary

CipherMesh treats the network as untrusted. Discovery can find addresses, relays can forward bytes, and mailboxes can store ciphertext, but CipherMesh authentication and encryption live at the application layer. See [SECURITY.md](SECURITY.md).

## Known Limitations

- Prototype CLI, not production UX.
- No metadata privacy or traffic-analysis resistance.
- No endpoint compromise protection.
- No encrypted database-at-rest.
- No account recovery or backup.
- No group chat.
- Internet reachability still depends on operating the public pairing service described above.
- Manual reconnect UX is intentionally disabled while the protocol is hardened; use a fresh invite after restart/disconnect.
