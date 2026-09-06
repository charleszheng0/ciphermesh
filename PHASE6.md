# Phase 6 Validation And Ship

This branch is for iterative validation hardening before shipping CipherMesh.

## Loop Commands

Windows PowerShell:

```powershell
.\scripts\phase6-loop.ps1 -Iterations 0 -DelaySeconds 10 -Full
```

macOS/Linux:

```bash
ITERATIONS=0 DELAY_SECONDS=10 FULL=1 ./scripts/phase6-loop.sh
```

Use `Iterations = 0` / `ITERATIONS=0` for an infinite loop. Use `-NoClippy` or `NO_CLIPPY=1` while iterating quickly.

## Ordered Work

1. 6A fault injection: expand deterministic bad Wi-Fi, delay, reorder, drop, tamper, partition simulations.
2. 6B reliable delivery: prove retry, ACK, dedupe, and pending outbox behavior under faults.
3. 6C crypto/security verification: replay, tamper, wrong identity, and device impersonation tests.
4. 6D sync/CRDT convergence: prove replicas converge after missing, duplicated, delayed, and reordered events.
5. 6E same-LAN two-machine integration: Mac and Windows invite/discovery/connect transcript.
6. 6E different-network integration: direct path, hole punch, then relay fallback transcript.
7. 6F CLI/UX cleanup: keep the happy path obvious and remove misleading controls.
8. 6G threat model/docs: document guarantees, limitations, and local-state risks.
9. 6H README/demo: make GitHub reproduction clear.
10. 6I final cleanup/ship: warnings, release binaries, and final checklist.

## Current Coverage Map

- 6A: `hardening_tests::fault_injector_is_deterministic_and_disabled_by_default`
- 6B: `hardening_tests::*outbox*`, `*ack*`, `*duplicate*`, `*mailbox*`
- 6C: tamper/replay tests in `tests` and `hardening_tests`
- 6D: `crdt::tests`, sync and own-device sync storage tests
- 6E: manual two-machine validation still required
- 6F: reconnect UI removed; LAN invite listener lifecycle fixed
- 6G-6I: docs and packaging still pending

## Manual Two-Machine Transcript Template

Host:

```bash
cargo run
```

Choose Create Invite, then record:

```text
Invite:
Listening on:
lsof -nP -iUDP:5000
```

Joiner:

```bash
cargo run
```

Choose Join Invite, paste the full invite token, then record:

```text
Connected securely:
First message sent:
First reply received:
```

Both machines:

```text
OS:
Network:
Firewall prompts:
Observed failure, if any:
```
