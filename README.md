# CipherMesh

CipherMesh is a Rust end-to-end encrypted peer-to-peer messenger for Windows,
macOS, and Linux. Its normal terminal UI supports short-code pairing on the
same LAN or across networks, persistent conversations, durable queued delivery,
and automatic reconnection through direct or relayed connections.

## Why It Exists

CipherMesh keeps application encryption independent from the network path.
Messages are encrypted before QUIC, relays, mailboxes, or discovery
infrastructure handle them, so changing transports does not expose plaintext or
session keys. It remains a prototype rather than an audited production
messenger; see [SECURITY.md](SECURITY.md) for its guarantees and limitations.

## Architecture

```text
Device A                                              Device B
Terminal UI                                           Terminal UI
    |                                                      |
SQLite history/outbox <-- Double Ratchet ciphertext --> SQLite history/outbox
    |                                                      |
    +------ direct peer connection / DCUtR hole punch -----+
    |                                                      |
    +-- Oracle rendezvous + Circuit Relay v2 fallback -----+

Optional mailbox protocol stores opaque encrypted envelopes for later retrieval.
```

Private application and ratchet keys remain on the endpoints. The public
service coordinates short-lived invite discovery and forwards relayed bytes;
it does not terminate CipherMesh's application encryption.

## Cross-Network Pairing

CipherMesh supports messaging between devices on the same LAN and on different
networks. The deployed Oracle Cloud libp2p rendezvous/Circuit Relay v2 service
provides a globally reachable meeting point when LAN discovery or NAT traversal
is insufficient. Users select **Create Invite** or **Join Invite** and exchange
only a six-character code. CipherMesh resolves the peer internally, attempts a
direct connection, allows DCUtR hole punching, and falls back to the relay while
preserving application-layer end-to-end encryption.

### Connection Selection: Direct, Hole Punch, Relay

```text
Resolve six-character invite
          |
          v
Try the inviter's sanitized direct address
          |
          +-- connected --------------------> encrypted chat
          |
          v
Allow DCUtR to negotiate a direct NAT traversal path
          |
          +-- connected --------------------> encrypted chat
          |
          v
Dial /p2p/<relay>/p2p-circuit/p2p/<peer> ---> encrypted chat
```

The inviter establishes a Circuit Relay v2 reservation before its invite is
published. The direct path is preferred; after a short grace period, the joiner
uses the reserved circuit when direct connectivity is unavailable. A failed
direct or DCUtR attempt does not tear down an existing relay connection.

## Quick Demo

On the first computer, run `cargo run`, select **Create Invite**, and share the
six-character code:

```text
Connecting...
Invite code: ABC2D3
Waiting for your friend...
```

On the second computer, run `cargo run`, select **Join Invite**, and enter that
code. Both users are placed into the encrypted chat when pairing completes.
The same steps work on one LAN or across separate networks through the public
service; the normal interface does not ask for an IP address, port, PeerId, or
relay multiaddr. Use `cargo run -- --verbose` when a demo needs to show transport
selection and relay/DCUtR diagnostics.

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
- Automatic relay reservation renewal and background reconnect for active chats.
- Optional untrusted mailbox protocol/demo for encrypted store-and-forward.

## Storage And Distributed State

- SQLite via bundled `rusqlite`.
- Local chat history for the endpoint's own conversation UI.
- Durable outbox with pending/delivered status.
- ACK/retry/deduplication.
- Persistent local libp2p, application identity, and ratchet state.
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

Current wire/demo types are Rust structs serialized with `serde`/`bincode`,
plus libp2p CBOR request-response for pairing, chat frames, and mailbox
messages. `prost`/Protobuf is not currently wired in this repo.

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

## Install And Run

Requirements:

- A current stable [Rust toolchain](https://www.rust-lang.org/tools/install).
- Git and the native C/C++ build tools required by the Rust toolchain on the
  host platform.
- Internet access to the public pairing service for cross-network invites.

Clone and run the normal application:

```bash
git clone https://github.com/charleszheng0/ciphermesh.git
cd ciphermesh
cargo run --release
```

For development, build or run the debug target:

```bash
cargo build
cargo run
```

Install the current checkout into Cargo's binary directory:

```bash
cargo install --path .
ciphermesh
```

Local profiles, identities, ratchet state, history, and pending delivery state
are stored in SQLite. The current default development profile is created under
`target/`; pass an explicit profile path to `create-invite` or `join-invite`
when testing persistence independently of Cargo build artifacts.

## Packaging Installers

`target/release/ciphermesh` (or `ciphermesh.exe`) is Cargo's optimized build
output. Files under `dist/` are the copies intended for testing or distribution;
users do not need Rust or Cargo to run them.

### Windows

The portable Windows binary can be built with:

```powershell
.\scripts\package-release.ps1
.\dist\ciphermesh-windows-x64-ciphermesh.exe
```

To create the per-user Windows installer, install Inno Setup 6 and run:

```powershell
winget install --id JRSoftware.InnoSetup -e
.\scripts\package-windows-installer.ps1
```

The result is `dist/CipherMesh-<version>-windows-x64-setup.exe`. It installs
CipherMesh under the user's local application directory, adds Start Menu and
optional desktop shortcuts, and uses a writable per-user working directory for
the SQLite profile. No Rust toolchain is needed on the destination computer.

### macOS

Run the installer build on each target macOS architecture:

```bash
bash scripts/package-macos-installer.sh
```

The result is `dist/CipherMesh-<version>-macos-<x64|arm64>.pkg`, which installs
the `ciphermesh` command into `/usr/local/bin`. After installation, users run:

```bash
ciphermesh
```

The existing portable macOS/Linux helper remains available:

```bash
./scripts/package-release.sh
./dist/ciphermesh-<macos|linux>-<x64|arm64>-ciphermesh
```

The **Package installers** GitHub Actions workflow builds the Windows x64,
macOS Intel, and macOS Apple Silicon packages on their native runners. Run it
manually from the Actions tab or push a version tag such as `v0.1.0`, then
download the artifacts from the workflow run.

These local/CI packages are unsigned by default. Public Windows distribution
requires an Authenticode code-signing certificate. Public macOS distribution
requires Developer ID Application and Developer ID Installer certificates plus
Apple notarization; the macOS script supports `MACOS_APPLICATION_IDENTITY`,
`MACOS_INSTALLER_IDENTITY`, and an `APPLE_NOTARY_PROFILE` stored in the macOS
keychain. Packaging without those credentials does not bypass Smart App Control
or Gatekeeper.

## CLI

Normal user commands:

```bash
cargo run
cargo run -- --verbose
cargo run -- create-invite [profile.sqlite]
cargo run -- join-invite <six-character-code> [profile.sqlite]
```

Running without a subcommand opens the product menu:

```text
Create Invite
Join Invite
Messages
Profile
Quit
```

Service-operator commands:

```bash
cargo run -- service /ip4/0.0.0.0/tcp/4001
cargo run -- relay /ip4/0.0.0.0/tcp/4001
cargo run -- service-dev /ip4/127.0.0.1/tcp/4001 [dev-service.key]
```

Developer and protocol-validation commands:

```bash
cargo run -- bob [listen-ip:port] [bootstrap-multiaddr...]
cargo run -- alice <bob-libp2p-peer-id> [message] [bootstrap-multiaddr...]
cargo run -- alice-relay <bob-libp2p-peer-id> [message] [relay-multiaddr...]
cargo run -- alice-direct [bob-ip:port] [message]
cargo run -- chat-bob [listen-ip:port]
cargo run -- chat-alice [bob-ip:port]
cargo run -- chat-listen [listen-ip:port] [profile.sqlite]
cargo run -- relay-demo
cargo run -- kad-demo
cargo run -- mailbox [/ip4/0.0.0.0/tcp/7000] [target/ciphermesh-mailbox.sqlite]
cargo run -- alice-mailbox <mailbox-multiaddr> [message] [target/ciphermesh-alice-mailbox.sqlite]
cargo run -- bob-mailbox <mailbox-multiaddr> [target/ciphermesh-bob-mailbox.sqlite]
cargo run -- invite-demo [target/ciphermesh-invite-demo.sqlite]
cargo run -- restart-demo [target/ciphermesh-4a-demo.sqlite]
cargo run -- outbox-demo [target/ciphermesh-4b-outbox-demo.sqlite]
cargo run --release -- storage-bench [messages] [database]
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
Normal mode hides PeerIds, IP addresses, multiaddrs, Kademlia activity, relay
internals, and DCUtR events. Both `cargo run` and `cargo run -- --verbose` open
the normal product UI.

## Public Pairing Service

Run one persistent service on the Oracle VM with TCP port 4001 open. Keep the
identity file on durable storage so the service PeerId does not change:

```bash
cargo run --release -- service /ip4/0.0.0.0/tcp/4001
```

The service loads `/var/lib/ciphermesh/service.key` on every production restart.
It refuses to generate a replacement when that canonical file is missing,
unreadable, invalid, or produces the wrong PeerId. Back up this private key. The
deployed key must print the expected service PeerId
`12D3KooWRkaMJMXVTTgsBSmjvZ6L26mbb39h7NXrKPMvMgL5drpj`.

The public endpoint is built into CipherMesh:

```text
/ip4/150.136.135.150/tcp/4001/p2p/12D3KooWRkaMJMXVTTgsBSmjvZ6L26mbb39h7NXrKPMvMgL5drpj
```

No client configuration is required. Developers can override it with:

```text
CIPHERMESH_RENDEZVOUS=/ip4/OTHER_PUBLIC_IP/tcp/4001/p2p/OTHER_SERVICE_PEER_ID
```

Both production commands, `service` and `relay`, always use
`/var/lib/ciphermesh/service.key`, independent of the working directory. They do
not accept an alternate identity path and refuse to start if the canonical key
is absent or produces a PeerId other than the built-in production PeerId. For
local development, use `service-dev` with an explicit test key;
`CIPHERMESH_SERVICE_IDENTITY` supplies its default path when no path argument is
given. A missing development key is generated once and reused.

Promote the existing permanent identity once on Oracle (this copies the key; it
does not generate one):

```bash
sudo install -d -o opc -g opc -m 700 /var/lib/ciphermesh
sudo install -o opc -g opc -m 600 \
  /home/opc/ciphermesh/ciphermesh-service.key \
  /var/lib/ciphermesh/service.key
sha256sum \
  /home/opc/ciphermesh/ciphermesh-service.key \
  /var/lib/ciphermesh/service.key
```

Both checksums must be
`62015426bea5afd3f6c030a292c9dc59c525a1e2a18f92d03b6ba296378e8fcd`.
After building the deployed revision, verify two separate launches:

```bash
cd /home/opc/ciphermesh
cargo build --release
timeout 5s ./target/release/ciphermesh service /ip4/127.0.0.1/tcp/0 || test $? -eq 124
timeout 5s ./target/release/ciphermesh service /ip4/127.0.0.1/tcp/0 || test $? -eq 124
```

Each launch must print the same expected `Service PeerId`. Run the production
service under the host's normal process supervisor (for example, systemd) as:

```bash
/home/opc/ciphermesh/target/release/ciphermesh service /ip4/0.0.0.0/tcp/4001
```

The deployed service should run under systemd (or an equivalent supervisor)
with automatic restart enabled. Its unit must execute the production command
above as a user that can read `/var/lib/ciphermesh/service.key`. Because the
canonical identity lives outside the repository, it survives binary rebuilds,
process restarts, and VM reboots.

The service keeps only hashed, five-minute invite codes, the inviter's PeerId,
and sanitized routing addresses in memory. It rejects wildcard, loopback,
private, link-local, multicast, and documentation addresses. It will not
register an invite until the inviter has an active relay reservation, removes
registrations when reservations end, and consumes a code on its first
successful resolution. Restarting the service clears outstanding invite codes
but preserves its PeerId through the canonical key.

## Pairing On Any Network

On the host computer:

```bash
cargo run
```

Choose `Create invite`. After the local profile name is set, CipherMesh shows
user-facing setup status such as:

```text
Connecting...
Invite code: ABC2D3
Waiting for your friend...
```

On the joining computer:

```bash
cargo run
```

Choose `Join invite` and enter `ABC2D3`. CipherMesh tries a valid direct LAN
address first, lets DCUtR attempt a direct upgrade when available, and falls
back to the public circuit relay automatically. IP addresses, ports, PeerIds,
and multiaddrs are never part of the normal pairing UI.

## Chat, Reconnection, And Queued Delivery

After pairing, both peers enter the same persistent chat flow. Messages are
written to the local SQLite history, tracked as pending, retried without
creating duplicate history entries, and cleared from the outbox only after an
ACK. If every connection to the peer disappears, CipherMesh marks the chat
offline, keeps newly typed messages queued, retries the relay route every three
seconds, and flushes pending messages when connectivity returns.

An active chat has no inactivity timeout and can remain open until a user enters
`/back`, presses Ctrl+C, or exits the application. Closing one libp2p connection
or failing a direct/DCUtR attempt does not mark the peer offline while another
viable connection remains. Reopening a saved conversation from **Messages**
shows its local history and allows messages to be queued for later delivery.

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
cargo run -- service-dev /ip4/127.0.0.1/tcp/4001 target/dev-service.key
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

CipherMesh treats the network and public infrastructure as untrusted:

- X25519 establishes shared secret material; Ed25519 authenticates identities
  and device authorization.
- HKDF and the Double Ratchet evolve per-session keys, and
  ChaCha20-Poly1305 authenticates and encrypts message payloads.
- Relays and mailboxes handle ciphertext plus necessary routing metadata, not
  message plaintext or session keys.
- Replay checks, bounded skipped keys, durable ACK/retry state, and
  deduplication protect the message-processing path.
- Local SQLite databases contain sensitive identities, ratchet state, and
  plaintext history and are not currently encrypted at rest.

CipherMesh does not claim complete metadata privacy, traffic-analysis
resistance, endpoint-compromise protection, or audited production security.
The full trust boundaries and attacker model are documented in
[SECURITY.md](SECURITY.md).

## Known Limitations

- Prototype CLI, not production UX.
- No metadata privacy or traffic-analysis resistance.
- No endpoint compromise protection.
- No encrypted database-at-rest.
- No account recovery or backup.
- No group chat.
- Internet reachability still depends on operating the public pairing service described above.
- Automatic reconnect runs while the paired chat remains open; there is no
  background messaging daemon after the application exits.
- The persistent mailbox is a separate protocol/demo path rather than part of
  the deployed rendezvous/relay service.
