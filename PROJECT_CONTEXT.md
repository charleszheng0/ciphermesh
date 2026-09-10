# CipherMesh Project Context

## Cross-Network Pairing

CipherMesh is being extended from same-LAN messaging to reliable cross-network
messaging between devices on different Wi-Fi networks. The architecture uses a
small public libp2p rendezvous/circuit-relay service as a globally reachable
meeting point when direct LAN discovery or NAT traversal is insufficient.
Normal users never handle IP addresses, ports, PeerIds, relay multiaddrs, or
networking commands: one device selects **Create Invite** and receives a short
code, while the other selects **Join Invite** and enters that code. Internally,
CipherMesh resolves the invite, attempts direct connectivity and DCUtR where
possible, and automatically falls back to the public relay while keeping the
existing end-to-end encrypted messaging and local persistence model.

## Infrastructure Decision

The initial public service is intended to run on an Oracle Cloud
Always Free-eligible Ubuntu VM with a public IPv4 address and TCP port 4001
open. The current implementation uses the combined `service` command, which
provides both invite rendezvous and circuit relay; `relay` remains a compatible
command alias. The service identity file must remain on persistent storage so
its PeerId stays stable:

```bash
cargo run --release -- service /ip4/0.0.0.0/tcp/4001
```

Client releases should eventually embed the resulting public service address
as their default. `CIPHERMESH_RENDEZVOUS` remains available as an operator or
development override, ensuring ordinary users only interact with invite codes.
Cloud eligibility and pricing should be confirmed when provisioning the VM.

## Resume-Ready Summary

Built cross-network peer discovery and NAT traversal for a decentralized Rust
messenger using short-code rendezvous, persistent libp2p identities, DCUtR,
circuit-relay fallback, and end-to-end encrypted messaging with durable local
state.
