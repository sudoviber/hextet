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
