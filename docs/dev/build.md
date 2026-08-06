# Build Guide

## Local Development

### Prerequisites

- Rust 1.85+ (see `rust-toolchain.toml`)
- `rustfmt` and `clippy` components

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test --workspace
```

## CI Checks

Run all CI checks locally before submitting a pull request:

```bash
cargo xtask ci
```

This runs:
1. `cargo fmt --all --check` - Code formatting check
2. `cargo clippy --workspace --all-targets -- -D warnings` - Linting
3. `cargo test --workspace` - Unit and integration tests
4. `cargo deny check` - Dependency license and security checks (skipped if `cargo-deny` not installed)

## E2E Tests

End-to-end testing requires Linux, root privileges, the kernel `wireguard` module, and `jq`:

```bash
cargo xtask e2e
```

This builds the workspace, then runs `scripts/netns-e2e.sh` as root: two network namespaces
(`hxt-a`/`hxt-b`) joined by a veth pair simulate two public-IPv6 hosts; the script drives the
`hextet` binary through `keygen` → `init` (b joins via `--network-key`) → `up` → `ping -6` between
overlay addresses → `status --json` (asserts `connected`) → `down`, and exits `0` printing `E2E OK`
on success.

Not runnable on macOS (netns and the kernel WireGuard backend are Linux-only) — the CI `e2e` job
(`.github/workflows/ci.yml`) covers it on every push/PR. To point the script at a different binary,
set `HEXTET_BIN` (defaults to `target/debug/hextet`):

```bash
sudo -E env HEXTET_BIN=target/release/hextet scripts/netns-e2e.sh
```
