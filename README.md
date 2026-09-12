# CipherMesh

CipherMesh is a cross-platform, end-to-end encrypted peer-to-peer messenger
written in Rust. Its terminal interface supports six-character invite pairing,
same-LAN and cross-network messaging, persistent conversations, durable queued
delivery, and automatic reconnection.

> CipherMesh is an experimental project, not an independently audited
> production messenger. Review the [security model](SECURITY.md) before using it
> for sensitive communication.

## Features

- End-to-end encrypted sessions using X25519, Ed25519, HKDF, the Double Ratchet,
  and ChaCha20-Poly1305.
- Six-character **Create Invite** / **Join Invite** pairing without exposing IP
  addresses, ports, PeerIds, or relay addresses in the normal interface.
- Direct peer connectivity with DCUtR hole punching and automatic Circuit Relay
  v2 fallback through a persistent public service.
- SQLite chat history, cryptographic identities, ratchet state, and delivery
  state that survive application restarts.
- Durable outbox with ACK, retry, deduplication, and queued delivery after a
  transient disconnect.
- Automatic reconnect while an active chat remains open; one closed connection
  does not mark a peer offline when another viable connection remains.
- Account/device identities, signed device certificates, per-device sessions,
  encrypted fanout, synchronization, and device revocation primitives.
- Native Windows, macOS, and Linux builds.

## Architecture

```text
Device A                                              Device B
Terminal UI                                           Terminal UI
    |                                                      |
SQLite history/outbox <-- Double Ratchet ciphertext --> SQLite history/outbox
    |                                                      |
    +--------- direct peer connection / DCUtR -------------+
    |                                                      |
    +-- public rendezvous + Circuit Relay v2 fallback -----+

Optional mailbox protocol: opaque encrypted store-and-forward envelopes
```

Application encryption is independent of the selected transport. Private keys,
ratchet state, and plaintext remain on the endpoints; the public service
coordinates short-lived invite discovery and forwards relayed ciphertext.

### Direct → Hole Punch → Relay

```text
Resolve six-character invite
          |
          v
Try the inviter's sanitized direct address
          |
          +-- connected --------------------> encrypted chat
          |
          v
Allow DCUtR to negotiate a direct NAT path
          |
          +-- connected --------------------> encrypted chat
          |
          v
Dial the inviter through Circuit Relay v2 --> encrypted chat
```

The inviter establishes and maintains a relay reservation before publishing an
invite. CipherMesh prefers direct connectivity, allows a short window for NAT
traversal, and falls back to the reserved relay circuit when necessary. A
failed direct or DCUtR attempt does not tear down a working relay connection.

## Install

Download the package for your platform from the repository's
[Releases](https://github.com/charleszheng0/ciphermesh/releases) page.

### Windows

Download and run:

```text
CipherMesh-<version>-windows-x64-setup.exe
```

The installer adds a Start Menu shortcut, offers a desktop shortcut, and can be
removed through Windows **Installed apps**. It installs for the current user and
does not require Rust or Cargo.

### macOS

Choose the package matching the Mac:

```text
CipherMesh-<version>-macos-arm64.pkg  # Apple Silicon
CipherMesh-<version>-macos-x64.pkg    # Intel
```

The package installs the `ciphermesh` command in `/usr/local/bin`. Launch it
from Terminal:

```bash
ciphermesh
```

### Package signing

Release packages are unsigned unless the release explicitly says otherwise.
Unsigned builds may trigger Windows Smart App Control or macOS Gatekeeper.
Packaging alone does not establish publisher trust: public Windows releases
require Authenticode signing, while public macOS releases require Developer ID
signing and Apple notarization.

## Use

Launch CipherMesh and choose from the main menu:

```text
[1] Create invite
[2] Join invite
[3] Messages
[4] Profile
[Q] Quit
```

To start a conversation:

1. One user selects **Create invite** and shares the displayed six-character
   code.
2. The other user selects **Join invite** and enters the code within five
   minutes.
3. CipherMesh resolves the route and opens the encrypted chat automatically.

Typical inviter output:

```text
Connecting...
Invite code: ABC2D3
Waiting for your friend...
```

The same workflow works on one LAN or across separate networks. No network
configuration is required for the built-in public service.

Within a chat, enter `/back` to return to **Messages** or press Ctrl+C to exit.
An active chat has no inactivity timeout and can remain open until a user
leaves or exits the application.

## Delivery And Persistence

Messages are persisted locally and tracked until acknowledged. If all
connections to a peer disappear, CipherMesh marks the chat offline, queues new
messages, retries the relay route every three seconds, and flushes pending
messages after reconnection. Duplicate retries do not create duplicate history
entries.

The terminal history is local SQLite state and is not uploaded to the pairing
service or relay. Local databases contain plaintext history and sensitive keys
and are not currently encrypted at rest; protect the user account and device
that store them.

## Security Model

CipherMesh treats discovery, relays, mailboxes, and the network as untrusted:

- X25519 establishes shared secret material.
- Ed25519 authenticates identities and device authorization.
- HKDF and the Double Ratchet evolve per-session keys.
- ChaCha20-Poly1305 encrypts and authenticates message payloads.
- Replay checks and bounded skipped keys constrain replay and out-of-order
  processing.
- Relays and mailboxes receive ciphertext and necessary routing metadata, not
  message plaintext or session keys.

CipherMesh does not provide complete metadata privacy, traffic-analysis
resistance, endpoint-compromise protection, encrypted local databases, account
recovery, or group chat. First-contact identity verification also requires an
independent trusted channel. See [SECURITY.md](SECURITY.md) for the complete
attacker model and trust boundaries.

## Technology

- Rust and Tokio
- libp2p TCP, Noise, Yamux, mDNS, Kademlia, AutoNAT, DCUtR, and Circuit Relay v2
- QUIC through `quinn`
- SQLite through bundled `rusqlite`
- `serde`, `bincode`, and libp2p CBOR request-response protocols
- Oracle Cloud public rendezvous/relay service with a persistent identity and
  systemd restart supervision

## Build From Source

Install a current stable [Rust toolchain](https://www.rust-lang.org/tools/install),
then run:

```bash
git clone https://github.com/charleszheng0/ciphermesh.git
cd ciphermesh
cargo run --release
```

Enable networking diagnostics when needed:

```bash
cargo run --release -- --verbose
```

Normal mode hides PeerIds, addresses, Kademlia activity, relay internals, and
DCUtR events.

## Building Installers

### Windows

Install Inno Setup 6 and run:

```powershell
winget install --id JRSoftware.InnoSetup -e
.\scripts\package-windows-installer.ps1
```

### macOS

Build on the target Mac architecture:

```bash
bash scripts/package-macos-installer.sh
```

The **Package installers** GitHub Actions workflow builds Windows x64, macOS
Intel, and macOS Apple Silicon artifacts when a version tag such as `v0.1.0` is
pushed.

### Publishing a release

1. Set the release version in `Cargo.toml` and commit it.
2. Create and push the matching tag, for example `git tag v0.1.0` followed by
   `git push origin v0.1.0`.
3. In GitHub **Actions**, wait for **CI** and **Package installers** to finish,
   then download and extract the Windows, macOS Intel, and macOS Apple Silicon
   workflow artifacts.
4. Draft a GitHub release using the existing tag, attach the extracted `.exe`
   and two `.pkg` files, mark it as a prerelease while CipherMesh remains
   experimental, and publish it.

## Development

Pull requests and pushes run formatting, linting, and tests on Windows, macOS,
and Linux through GitHub Actions. Run the same checks locally with:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Additional protocol demos and validation notes are kept in [DEMO.md](DEMO.md)
and [PHASE6.md](PHASE6.md) rather than the main user documentation.

## Public Service

The bundled production endpoint points to the CipherMesh rendezvous/Circuit
Relay v2 service on Oracle Cloud. The service uses a persistent libp2p identity,
accepts invite registration only after the inviter's relay reservation is
active, stores hashed five-minute invite codes in memory, removes registrations
when reservations end, and consumes each code after one successful resolution.

The service observes connection and routing metadata and can delay, drop, or
refuse traffic, but application-layer encryption prevents it from decrypting
message content. Availability still depends on the public service remaining
online.

## Current Limitations

- Terminal interface rather than a native desktop or mobile UI.
- Experimental implementation without an independent security audit.
- No complete metadata privacy or traffic-analysis resistance.
- No protection against a compromised endpoint or malicious recipient.
- No encrypted local database, account recovery, cloud backup, or group chat.
- Automatic reconnect operates while the paired chat remains open; CipherMesh
  does not run a background messaging daemon after application exit.
- The persistent mailbox remains a separate protocol/demo rather than part of
  the deployed public service.
