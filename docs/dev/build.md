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

## Windows

The Windows platform backend (`crates/platform/src/windows.rs`, wintun TUN + `net-route` routing +
`ipconfig` enumeration + `netsh` address assignment) and the `hextet service install|uninstall|run`
service wrapper are gated behind `#[cfg(target_os = "windows")]` and do not affect
`cargo build --workspace` on macOS (see `docs/adr/ADR-0010-windows-platform.md`). The platform
crate's Windows branch is **type-check verified** (`cargo check -p hextet-platform --target
x86_64-pc-windows-gnu` passes), but full codegen/link is unverified — the first real full-compile
verification is the CI Windows runner (`release.yml`). To cross-compile locally:

```bash
# Option A: mingw (via the cross-rs container, if Docker is available)
docker run --rm -v "$PWD":/app ghcr.io/cross-rs/x86_64-pc-windows-gnu:latest cargo build

# Option B: cargo-xwin (MSVC target, needs a Windows SDK / wine for the MSVC toolchain)
cargo install cargo-xwin
cargo xwin build
```

Runtime requirements (unverified): a `wintun.dll` matching the target architecture placed next to
`hextet.exe` (or set via the `tun` crate's `PlatformConfig::wintun_file`), and administrator /
LocalSystem privileges to open the wintun adapter. The `hextet` binary will not fully compile for
Windows until `crates/engine`'s `backend::platform_default()` gains a Windows branch (separate slice).

## Android FFI (core-ffi)

`crates/core-ffi` is the UniFFI (Mozilla, `=0.32.0`, proc-macro era) surface over `hextet-core`'s
pure logic for Android onboarding — see `docs/adr/ADR-0012-android-ffi-boundary.md`. It exports six
synchronous functions (`generate_identity`, `identity_public_key`, `derive_network_prefix`,
`derive_node_address`, `render_config`, `load_config`) with no tokio, no `.udl`, no `build.rs`. It
builds a `cdylib` (`.dylib`/`.so`) plus an `rlib` so the surface is testable in plain Rust:

```bash
cargo test -p hextet-core-ffi      # Rust-side roundtrip tests (runs on macOS, no Android toolchain)
cargo build -p hextet-core-ffi     # produces target/debug/libhextet_core_ffi.dylib (and .rlib)
```

### Regenerating Kotlin bindings (deferred to the Android slice)

The Rust-side scaffolding is generated at compile time by `uniffi::setup_scaffolding!()`; the
metadata is embedded in the compiled library. Kotlin bindings are generated in **library mode**
(no `.udl` file) once the Android toolchain exists:

```bash
# 1. install the bindgen CLI (pin to the same version as the workspace dep)
cargo install uniffi_bindgen --version 0.32.0

# 2. cross-compile the cdylib for the target ABIs (e.g. aarch64-linux-android)
#    (requires the Android NDK / a cross toolchain — NOT verified on macOS, see ADR-0012)
cargo build -p hextet-core-ffi --release --target aarch64-linux-android

# 3. generate Kotlin bindings from the compiled library's embedded metadata
uniffi-bindgen generate --library target/aarch64-linux-android/release/libhextet_core_ffi.so \
    --language kotlin --out-dir apps/android/app/src/main/generated/uniffi
```

The generated Kotlin package is `uniffi.hextet_core_ffi` (default = crate name; override with
`uniffi::setup_scaffolding!("<name>")` if a cleaner package is wanted). The Android app links the
`.so` via JNI and calls the generated top-level functions directly. The `unsafe` in the FFI path
lives in `uniffi_core` (third-party); this crate's own generated scaffolding is `unsafe`-free for
the current sync surface (verified — see ADR-0012 decision 5).

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
