# CipherMesh Demo Script

This is a 3-5 minute terminal demo.

## 1. Build

```bash
cargo build
```

## 2. Same-Machine Interactive Chat

Terminal 1:

```bash
cargo run -- chat-bob 127.0.0.1:5000
```

Terminal 2:

```bash
cargo run -- chat-alice 127.0.0.1:5000
```

Say:

```text
hello bob
how are you
```

Bob should print Alice's messages immediately. Bob can type a reply and Alice prints it immediately.

## 3. Show Encrypted Transport Briefly

Run:

```bash
cargo run -- --verbose
```

Point out that verbose mode can show raw key/protocol details, while normal mode only shows short identities and encrypted byte counts.

## 4. Offline Mailbox

Terminal 1:

```bash
cargo run -- mailbox /ip4/0.0.0.0/tcp/7000 target/mailbox.db
```

Copy the printed mailbox multiaddr including `/p2p/<peer-id>`.

Terminal 2:

```bash
cargo run -- alice-mailbox <mailbox-multiaddr> "hello offline bob" target/alice-mailbox.db
```

Expected: the mailbox logs an opaque encrypted envelope and byte length.

Terminal 3:

```bash
cargo run -- bob-mailbox <mailbox-multiaddr> target/bob-mailbox.db
```

Expected: Bob fetches and decrypts `hello offline bob`, then the mailbox marks the envelope delivered.

## 5. Restart And Durable Outbox

```bash
cargo run -- restart-demo target/ciphermesh-4a-demo.sqlite
cargo run -- outbox-demo target/ciphermesh-4b-outbox-demo.sqlite
```

Point out that ratchet/session state survives restart and pending encrypted outbox items are retried without re-encryption.

## 6. Multi-Device And Revocation

```bash
cargo run -- device-demo
cargo run -- fanout-demo
cargo run -- own-device-sync-demo
cargo run -- revocation-demo
```

Expected highlights:

- One Alice account authorizes Laptop and Phone.
- Bob creates separate encrypted envelopes for each active device.
- Laptop and Phone sync missing events with version vectors.
- Revocation removes Phone from future fanout and own-device sync.

## 7. Hardening Tests

```bash
cargo test hardening -- --nocapture
```

This exercises deterministic drop, delay, duplicate, replay, tamper, reorder, and partition behavior around encrypted payload delivery.
