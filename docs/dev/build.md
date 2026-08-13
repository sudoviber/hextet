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

### Workspace crates

The workspace produces a single `hextet` binary from `hextet-cli`. Notable crates:
`hextet-core` (config/identity/addressing), `hextet-wg` (`WgBackend` trait + Linux kernel
backend), `hextet-wg-userspace` (boringtun userspace backend), `hextet-proto` (shared
serde status types for `status --json` / the HTTP server), `hextet-engine` (daemon loop),
`hextet-platform` (OS networking), and `hextet-discovery` (DHT rendezvous).

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
cargo xtask e2e            # 跑全部场景
cargo xtask e2e static     # M1：静态直连
cargo xtask e2e dynamic    # M2 阶段 A：daemon + 换前缀恢复 + 缓存重连
cargo xtask e2e doctor     # M2 阶段 B：状态防火墙打洞 + doctor 三分类
```

| 场景 | 脚本 | 覆盖 |
|---|---|---|
| static | `scripts/netns-e2e.sh` | keygen → init → up → ping → status → down |
| dynamic | `scripts/netns-e2e-dynamic.sh` | 两侧 daemon 常驻；A 换前缀后 B 在 5s 内跟随新 endpoint；SIGTERM 优雅退出；删掉配置里的 endpoint 后仅靠 `endpoints.json` 重连 |
| doctor | `scripts/netns-e2e-doctor.sh` | 双侧 nftables 状态防火墙下仍能打洞互连；doctor 在 open/stateful/blocked 三种规则下分类正确 |

`dynamic` 与 `doctor` 用 `hxt2-*` / `hxt3-*` 命名 netns，与 `static` 的 `hxt-*` 隔离，
三者可分别独立运行。CI 分别对应 `e2e` / `e2e-dynamic` / `e2e-doctor` 三个 job。

Not runnable on macOS (netns and the kernel WireGuard backend are Linux-only) — the CI `e2e` job
(`.github/workflows/ci.yml`) covers it on every push/PR. To point the script at a different binary,
set `HEXTET_BIN` (defaults to `target/debug/hextet`):

```bash
sudo -E env HEXTET_BIN=target/release/hextet scripts/netns-e2e.sh
```
