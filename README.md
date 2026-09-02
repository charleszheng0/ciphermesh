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
- libp2p for PeerIds and discovery framework.
- mDNS for same-LAN discovery.
- Bootstrap peers as entry points.
- Kademlia DHT for distributed peer/address lookup.
- AutoNAT/DCUtR/Circuit Relay support through rust-libp2p features.
- Persistent untrusted offline mailbox for store-and-forward.

## Storage And Distributed State

- SQLite via `rusqlite`.
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

## CLI

```bash
cargo run
cargo run -- --verbose
cargo run -- bob [listen-ip:port] [bootstrap-multiaddr...]
cargo run -- alice <bob-libp2p-peer-id> [message] [bootstrap-multiaddr...]
cargo run -- alice-direct [bob-ip:port] [message]
cargo run -- chat-bob [listen-ip:port]
cargo run -- chat-alice [bob-ip:port]
cargo run -- relay [/ip4/0.0.0.0/tcp/4001]
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
```

Verbose logging is enabled with `--verbose`, `-v`, or `CIPHERMESH_VERBOSE=1`.

## Same-Machine Interactive Chat

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

## Relay Test

Terminal 1:

```bash
cargo run -- relay /ip4/0.0.0.0/tcp/4001
```

Terminal 2:

```bash
cargo run -- bob 0.0.0.0:5000 <relay-multiaddr>
```

Terminal 3:

```bash
cargo run -- alice <bob-libp2p-peer-id> "hello via relay" <relay-multiaddr>
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
- No full production NAT traversal test harness in this repo.
