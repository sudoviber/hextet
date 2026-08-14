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
backend), `hextet-wg-userspace` (gotatun userspace backend, macOS/Windows/Android),
`hextet-proto` (shared serde status types for `status --json` / the HTTP server),
`hextet-engine` (daemon loop), `hextet-platform` (OS networking), and
`hextet-discovery` (DHT rendezvous).

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

The Windows platform backend (`crates/platform/src/windows.rs`) uses the `windows` crate
(IpHelper/Ndis/WinSock) for global IPv6 enumeration (`GetAdaptersAddresses`), routing
(`CreateIpForwardEntry2`/`DeleteIpForwardEntry2`), and address assignment
(`CreateUnicastIpAddressEntry`); the TUN device goes through the `tun` crate's wintun branch,
and `hextet service run` (`windows-service`) is the service entry point — see
`docs/adr/ADR-0011-windows-wintun-service.md`. The data plane is gotatun 0.8.1 (cross-platform,
ADR-0012). Windows code is compile-verified by the `check-windows` CI job; locally it can be
type-checked with:

```bash
cargo check -p hextet-platform --target x86_64-pc-windows-gnu
```

Runtime requirements (unverified): a `wintun.dll` matching the target architecture placed next to
`hextet.exe`, and administrator / LocalSystem privileges. `hextet down`/`delete_interface` remain
`Unsupported` (wintun adapter persistence is a design gap, ADR-0011).

## Android FFI (core-ffi)

`crates/core-ffi` is the UniFFI (Mozilla, `=0.32.0`, proc-macro era) surface over `hextet-core`'s
pure logic for Android onboarding — see `docs/adr/ADR-0013-android-ffi-boundary.md`. It exports six
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
#    (requires the Android NDK / a cross toolchain — NOT verified on macOS, see ADR-0013)
cargo build -p hextet-core-ffi --release --target aarch64-linux-android

# 3. generate Kotlin bindings from the compiled library's embedded metadata
uniffi-bindgen generate --library target/aarch64-linux-android/release/libhextet_core_ffi.so \
    --language kotlin --out-dir <android-app>/app/src/main/generated/uniffi
```

The generated Kotlin package is `uniffi.hextet_core_ffi` (default = crate name; override with
`uniffi::setup_scaffolding!("<name>")` if a cleaner package is wanted). The Android app links the
`.so` via JNI and calls the generated top-level functions directly. The `unsafe` in the FFI path
lives in `uniffi_core` (third-party); this crate's own generated scaffolding is `unsafe`-free for
the current sync surface (verified — see ADR-0013 decision 5).

## E2E Tests

E2E 需要 Linux + root + 内核 `wireguard` 模块 + `jq`（部分场景还要 `nftables`）。

### Docker（macOS 上也能跑）

Docker Desktop 的 linuxkit 内核把 wireguard **内置**了，`--privileged` 容器里能完整
跑通全部 9 个场景，外加一条**用户态（gotatun）后端真实 TUN 冒烟**（
`crates/wg-userspace/tests/userspace_backend_tun.rs` 开真实 `/dev/net/tun` 跑
apply/status/set_peer_endpoint/add_peer/remove_peer/down）。首次会自动构建镜像
（`scripts/Dockerfile.e2e`），源码 bind mount 进容器、用独立命名卷缓存 `target/`
与 cargo registry，不污染宿主机：

```bash
scripts/e2e-docker.sh                  # TUN 冒烟 + 全部 9 个场景
scripts/e2e-docker.sh dht gossip       # TUN 冒烟 + 指定场景
```

### Linux 原生（CI 路径）

```bash
cargo xtask e2e            # 跑全部场景
cargo xtask e2e static     # M1：静态直连
cargo xtask e2e dynamic    # M2 阶段 A：daemon + 换前缀恢复 + 缓存重连
cargo xtask e2e doctor     # M2 阶段 B：状态防火墙打洞 + doctor 三分类
```

| 场景 | 脚本 | 覆盖 |
|---|---|---|
| static | `scripts/netns-e2e.sh` | keygen → init → up → ping → status → down |
| lan | `scripts/netns-e2e-lan.sh` | 配置里无 endpoint、缓存空，仅靠 LAN 组播发现互连 |
| dht | `scripts/netns-e2e-dht.sh` | 仅靠本地 Mainline DHT 会合互连；双端同时换前缀秒级恢复 |
| gossip | `scripts/netns-e2e-gossip.sh` | A/B 互不知对方地址，仅靠 R 的隧道内 gossip 转介互连；双端换前缀恢复 |
| relay | `scripts/netns-e2e-relay.sh` | nftables 阻断直连后经中继逃生舱连通；直连恢复即退出中继 |
| site | `scripts/netns-e2e-site.sh` | site-to-site 通告路由（`[[peers]] routes`） |
| dynamic | `scripts/netns-e2e-dynamic.sh` | 两侧 daemon 常驻；A 换前缀后 B 在 5s 内跟随新 endpoint；仅靠 `endpoints.json` 重连 |
| doctor | `scripts/netns-e2e-doctor.sh` | 双侧 nftables 状态防火墙下仍能打洞互连；doctor 在 open/stateful/blocked 三种规则下分类正确 |
| ddns | `scripts/netns-e2e-ddns.sh` | 仅靠本地 DDNS mock（webhook HTTP + DNS TXT，`hextet ddns node`）会合互连；双端同时换前缀秒级恢复 |

各脚本自行创建并清理 netns（`hxt*-*` 命名），可分别独立运行。CI 对应
`.github/workflows/ci.yml` 里的 `e2e` job。要指向不同二进制，设 `HEXTET_BIN`
（缺省 `target/debug/hextet`）：

```bash
sudo -E env HEXTET_BIN=target/release/hextet scripts/netns-e2e.sh
```
