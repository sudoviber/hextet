# hextet M0（项目骨架）+ M1（静态直连）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立正式规范的 cargo workspace，实现身份/地址派生与静态配置，让两台有公网 IPv6 的 Linux 机器通过内核 WireGuard 以 `hextet up` 直连互 ping overlay ULA 地址。

**Architecture:** 纯逻辑放 `hextet-core`（身份 ed25519 → 派生 WG x25519 密钥与 ULA 地址；TOML 配置模型），内核 WireGuard 控制走 `hextet-wg`（`WgBackend` trait + wireguard-control），接口地址/MTU/生命周期走 `hextet-platform`（rtnetlink），`hextet-cli` 组装出 `keygen/init/inspect/up/down/status`。M1 采用 wg-quick 模型（CLI 直接配置内核后退出，无守护进程）；daemon/engine 在 M2 引入。

**Tech Stack:** Rust edition 2024 · ed25519-dalek 2 / x25519-dalek 2 / hkdf 0.12 / sha2 0.10 · wireguard-control 2 · rtnetlink 0.21 + tokio 1 · clap 4 / serde / toml 0.8 · proptest / assert_cmd · GitHub Actions（含 netns E2E）

**设计依据:** `docs/superpowers/specs/2026-08-06-hextet-design.md`（已批准 v2）

## Global Constraints

- **IPv6-only**：一切地址输入用 `Ipv6Addr` / `SocketAddrV6` 类型强制；解析到 IPv4 一律报错。
- **默认值**（`hextet-core::defaults`）：UDP 端口 **4193**、MTU **1400**、接口名 **hextet0**。
- **密码学**：身份 = ed25519；WG 私钥 = `SigningKey::to_scalar_bytes()`，WG 公钥 = `VerifyingKey::to_montgomery().to_bytes()`；哈希 SHA-256；KDF HKDF-SHA256；所有域分隔串以 `hextet-v1` 开头。不自研任何密码学。
- **地址派生**（协议规范，实现必须与 `docs/protocol/addressing.md` 一致）：
  - `network_id = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("network-id", 5B)`
  - 网络前缀 = `0xfd || network_id` → `/48`
  - `subnet_id = SHA-256("hextet-v1 subnet-id" || node_pubkey)[0..2]`（大端 u16）→ 节点 site `/64`
  - `iid = SHA-256("hextet-v1 iid" || node_pubkey)[0..8]`；全零 iid 报错
  - 节点地址 = `前缀(6B) || subnet_id(2B) || iid(8B)`；subnet_id 碰撞在配置加载时检测报错
- **工程规范**：edition 2024，workspace resolver "3"；双许可 **MIT OR Apache-2.0**；`crates/core` 顶部 `#![deny(missing_docs)]`；`unsafe_code = "deny"`（workspace lint）；clippy `-D warnings`。
- **文档同步**：每个任务的提交必须包含其文档更新（至少 CHANGELOG 一行；协议相关任务同步 `docs/protocol/`）。
- **TDD**：每个任务先写失败测试再实现；提交遵循 conventional commits（`feat:`/`test:`/`docs:`/`chore:`/`ci:`），commit message 末尾加 `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`。
- **第三方 API 校验**：涉及 `wireguard-control`/`rtnetlink` 的代码块以本计划为准起步，如与 docs.rs 当前版本 API 有出入，以 docs.rs 为准调整并在 commit message 注明。

---

### Task 1: Workspace 骨架 + CI + xtask

**Files:**
- Create: `Cargo.toml`（workspace 根）
- Create: `rust-toolchain.toml`、`.gitignore`、`deny.toml`、`LICENSE-MIT`、`LICENSE-APACHE`、`README.md`、`CHANGELOG.md`
- Create: `crates/core/Cargo.toml`、`crates/core/src/lib.rs`（暂只含 defaults 模块）
- Create: `xtask/Cargo.toml`、`xtask/src/main.rs`
- Create: `.github/workflows/ci.yml`
- Create: `docs/dev/build.md`

**Interfaces:**
- Consumes: 无
- Produces: workspace 布局与 `[workspace.dependencies]` 版本表（后续任务直接引用）；`hextet_core::defaults::{DEFAULT_PORT: u16 = 4193, DEFAULT_MTU: u32 = 1400, DEFAULT_INTERFACE: &str = "hextet0"}`；`cargo xtask ci` 命令

- [ ] **Step 1: 写 workspace 根 Cargo.toml**

```toml
[workspace]
resolver = "3"
members = ["crates/core", "xtask"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
repository = "https://github.com/sudoviber/hextet"
rust-version = "1.85"

[workspace.dependencies]
hextet-core = { path = "crates/core" }
ed25519-dalek = { version = "2", features = ["rand_core", "zeroize"] }
x25519-dalek = { version = "2", features = ["static_secrets"] }
rand_core = { version = "0.6", features = ["getrandom"] }
hkdf = "0.12"
sha2 = "0.10"
base64 = "0.22"
zeroize = { version = "1", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
thiserror = "2"
anyhow = "1"
clap = { version = "4", features = ["derive"] }
wireguard-control = "2"
rtnetlink = "0.21"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
proptest = "1"
tempfile = "3"
assert_cmd = "2"
predicates = "3"

[workspace.lints.rust]
unsafe_code = "deny"

[workspace.lints.clippy]
dbg_macro = "warn"
todo = "warn"
```

- [ ] **Step 2: 写 crates/core 骨架与 defaults**

`crates/core/Cargo.toml`:

```toml
[package]
name = "hextet-core"
description = "hextet core: identity, address derivation, config model (pure logic, embeddable)"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[lints]
workspace = true

[dependencies]
ed25519-dalek.workspace = true
rand_core.workspace = true
hkdf.workspace = true
sha2.workspace = true
base64.workspace = true
zeroize.workspace = true
serde.workspace = true
toml.workspace = true
thiserror.workspace = true

[dev-dependencies]
x25519-dalek.workspace = true
proptest.workspace = true
tempfile.workspace = true
```

`crates/core/src/lib.rs`:

```rust
//! hextet 核心逻辑：身份、地址派生、配置模型。
//!
//! 本 crate 是纯逻辑层（无 I/O 主循环、无平台依赖），
//! 为 daemon/CLI/移动端 FFI（M7）共同复用。
#![deny(missing_docs)]

pub mod defaults;
```

`crates/core/src/defaults.rs`:

```rust
//! 全局默认值（见设计 spec §5）。

/// 默认 WireGuard UDP 监听端口（致敬 RFC 4193）。
pub const DEFAULT_PORT: u16 = 4193;
/// 默认隧道 MTU（中国家宽 PPPoE 1492 − IPv6 WG 开销 80，留余量）。
pub const DEFAULT_MTU: u32 = 1400;
/// 默认接口名。
pub const DEFAULT_INTERFACE: &str = "hextet0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_stable() {
        assert_eq!(DEFAULT_PORT, 4193);
        assert_eq!(DEFAULT_MTU, 1400);
        assert_eq!(DEFAULT_INTERFACE, "hextet0");
    }
}
```

- [ ] **Step 3: 写 xtask（`ci` 子命令）**

`xtask/Cargo.toml`:

```toml
[package]
name = "xtask"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
anyhow.workspace = true
```

`xtask/src/main.rs`:

```rust
use std::process::Command;

use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
    let task = std::env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "ci" => ci(),
        "e2e" => e2e(),
        _ => bail!("usage: cargo xtask <ci|e2e>"),
    }
}

fn run(program: &str, args: &[&str]) -> Result<()> {
    eprintln!("$ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .status()
        .with_context(|| format!("failed to spawn {program}"))?;
    if !status.success() {
        bail!("{program} {} failed", args.join(" "));
    }
    Ok(())
}

fn ci() -> Result<()> {
    run("cargo", &["fmt", "--all", "--check"])?;
    run("cargo", &["clippy", "--workspace", "--all-targets", "--", "-D", "warnings"])?;
    run("cargo", &["test", "--workspace"])?;
    // cargo-deny 本地未安装时跳过（CI 中由独立 action 保证）
    if Command::new("cargo-deny").arg("--version").status().is_ok_and(|s| s.success()) {
        run("cargo", &["deny", "check"])?;
    } else {
        eprintln!("skip: cargo-deny not installed");
    }
    Ok(())
}

fn e2e() -> Result<()> {
    run("cargo", &["build", "--workspace"])?;
    run("sudo", &["-E", "scripts/netns-e2e.sh"])
}
```

注：`alias` 需在根加 `.cargo/config.toml`：

```toml
[alias]
xtask = "run --package xtask --"
```

- [ ] **Step 4: 写 CI、deny.toml、许可证与元文件**

`.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push: { branches: [main] }
  pull_request:
jobs:
  lint-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: "rustfmt, clippy" }
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace
      - uses: EmbarkStudios/cargo-deny-action@v2
```

`deny.toml`:

```toml
[licenses]
allow = [
  "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
  "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib",
  "Unicode-3.0", "MPL-2.0",
]

[advisories]
yanked = "deny"

[bans]
multiple-versions = "warn"
```

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

`.gitignore`:

```
/target
*.key
hextet.toml
```

`LICENSE-MIT` / `LICENSE-APACHE`：标准全文（版权行 `Copyright (c) 2026 sudoviber`）。

`README.md`（骨架，后续任务补充）：

```markdown
# hextet

IPv6-only、无服务器中转的 P2P 异地组网工具（mesh VPN），Rust 编写。

> hextet：IPv6 地址中每个冒号分隔的 16-bit 段。

- 设计文档：docs/superpowers/specs/2026-08-06-hextet-design.md
- 协议规范：docs/protocol/
- 构建指南：docs/dev/build.md

状态：M0/M1 开发中。
```

`CHANGELOG.md`:

```markdown
# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### Added
- cargo workspace 骨架、CI（fmt/clippy/test/cargo-deny）、xtask（ci/e2e）。
```

`docs/dev/build.md`：写明 `cargo build`、`cargo xtask ci`、netns E2E 需 Linux+root（脚本在 Task 9 落地）。

- [ ] **Step 5: 验证并提交**

Run: `cargo xtask ci`
Expected: fmt/clippy/test 全绿（core 有 1 个测试通过）

```bash
git add -A
git commit -m "chore: cargo workspace 骨架 + CI + xtask

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: core::identity — 节点身份与 WG 密钥派生

**Files:**
- Create: `crates/core/src/identity.rs`
- Modify: `crates/core/src/lib.rs`（加 `pub mod identity;` 与 `pub mod error;`）
- Create: `crates/core/src/error.rs`

**Interfaces:**
- Consumes: 无
- Produces:
  - `NodeIdentity::{generate() -> Self, from_seed(&[u8;32]) -> Self, seed(&self) -> [u8;32], public(&self) -> NodePublicKey, wg_secret_bytes(&self) -> [u8;32], save(&self, &Path) -> Result<(), IdentityError>, load(&Path) -> Result<Self, IdentityError>}`
  - `NodePublicKey::{from_base64(&str) -> Result<Self, IdentityError>, to_base64(&self) -> String, as_bytes(&self) -> &[u8;32], wg_public_bytes(&self) -> [u8;32]}`（`Clone + PartialEq + Eq + Hash + Debug`）
  - 密钥文件格式：单行 base64(32B seed)，Unix 权限 0600

- [ ] **Step 1: 写失败测试**（`crates/core/src/identity.rs` 底部 `#[cfg(test)]`）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seed() {
        let id = NodeIdentity::generate();
        let id2 = NodeIdentity::from_seed(&id.seed());
        assert_eq!(id.public(), id2.public());
    }

    #[test]
    fn pubkey_base64_roundtrip() {
        let pk = NodeIdentity::generate().public();
        let pk2 = NodePublicKey::from_base64(&pk.to_base64()).unwrap();
        assert_eq!(pk, pk2);
    }

    #[test]
    fn save_load_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let id = NodeIdentity::generate();
        id.save(&path).unwrap();
        let loaded = NodeIdentity::load(&path).unwrap();
        assert_eq!(id.public(), loaded.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    proptest::proptest! {
        /// 派生的 WG 私钥经 x25519 基点乘应等于派生的 WG 公钥（两条路径一致）。
        #[test]
        fn wg_key_derivation_consistent(seed in proptest::prelude::any::<[u8; 32]>()) {
            let id = NodeIdentity::from_seed(&seed);
            let sk = x25519_dalek::StaticSecret::from(id.wg_secret_bytes());
            let pk = x25519_dalek::PublicKey::from(&sk);
            proptest::prop_assert_eq!(pk.to_bytes(), id.public().wg_public_bytes());
        }
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-core identity`
Expected: 编译失败（`NodeIdentity` 未定义）

- [ ] **Step 3: 实现**

`crates/core/src/error.rs`:

```rust
//! 核心错误类型。

/// 身份/密钥相关错误。
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// 密钥文件 I/O 失败。
    #[error("key file {path}: {source}")]
    Io {
        /// 出错的文件路径。
        path: std::path::PathBuf,
        /// 底层 I/O 错误。
        #[source]
        source: std::io::Error,
    },
    /// base64 或长度不合法。
    #[error("invalid key encoding")]
    InvalidEncoding,
    /// 不是合法的 ed25519 公钥点。
    #[error("invalid ed25519 public key")]
    InvalidPublicKey,
}
```

`crates/core/src/identity.rs`:

```rust
//! 节点身份：ed25519 签名密钥，并派生 WireGuard x25519 密钥。

use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::error::IdentityError;

/// 节点身份（持有 ed25519 私钥种子）。
pub struct NodeIdentity {
    signing: SigningKey,
}

impl NodeIdentity {
    /// 用系统 CSPRNG 生成新身份。
    pub fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        Self { signing: SigningKey::generate(&mut rng) }
    }

    /// 从 32 字节种子恢复身份。
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { signing: SigningKey::from_bytes(seed) }
    }

    /// 导出 32 字节种子（谨慎处理，勿记录日志）。
    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// 节点公钥。
    pub fn public(&self) -> NodePublicKey {
        NodePublicKey(self.signing.verifying_key())
    }

    /// 派生 WireGuard 私钥（已 clamp 的 x25519 标量）。
    pub fn wg_secret_bytes(&self) -> [u8; 32] {
        self.signing.to_scalar_bytes()
    }

    /// 将种子以单行 base64 写入密钥文件（Unix 上 0600）。
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        let io = |source| IdentityError::Io { path: path.to_owned(), source };
        let data = B64.encode(self.seed());
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        use std::io::Write as _;
        let mut f = opts.open(path).map_err(io)?;
        writeln!(f, "{data}").map_err(io)?;
        Ok(())
    }

    /// 从密钥文件读取身份。
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let io = |source| IdentityError::Io { path: path.to_owned(), source };
        let text = std::fs::read_to_string(path).map_err(io)?;
        let bytes = B64
            .decode(text.trim())
            .map_err(|_| IdentityError::InvalidEncoding)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidEncoding)?;
        Ok(Self::from_seed(&seed))
    }
}

/// 节点公钥（ed25519）。
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct NodePublicKey(VerifyingKey);

impl NodePublicKey {
    /// 从 base64 解析。
    pub fn from_base64(s: &str) -> Result<Self, IdentityError> {
        let bytes = B64.decode(s.trim()).map_err(|_| IdentityError::InvalidEncoding)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| IdentityError::InvalidEncoding)?;
        let vk = VerifyingKey::from_bytes(&arr).map_err(|_| IdentityError::InvalidPublicKey)?;
        Ok(Self(vk))
    }

    /// base64 编码。
    pub fn to_base64(&self) -> String {
        B64.encode(self.0.as_bytes())
    }

    /// 原始 32 字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// 派生 WireGuard 公钥（Montgomery 形式）。
    pub fn wg_public_bytes(&self) -> [u8; 32] {
        self.0.to_montgomery().to_bytes()
    }
}
```

`lib.rs` 增加：

```rust
pub mod error;
pub mod identity;
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-core identity`
Expected: 4 个测试（含 proptest）PASS

- [ ] **Step 5: 提交**

```bash
git add crates/core CHANGELOG.md
git commit -m "feat(core): 节点身份与 WireGuard 密钥派生

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

（CHANGELOG `### Added` 加一行："节点身份（ed25519）与 WG x25519 密钥派生"。）

---

### Task 3: core::network + core::addr — ULA 地址派生 + 协议文档

**Files:**
- Create: `crates/core/src/network.rs`、`crates/core/src/addr.rs`
- Modify: `crates/core/src/lib.rs`、`crates/core/src/error.rs`
- Create: `docs/protocol/addressing.md`

**Interfaces:**
- Consumes: `NodePublicKey`（Task 2）
- Produces:
  - `NetworkKey::{generate() -> Self, from_base64(&str) -> Result<Self, IdentityError>, to_base64(&self) -> String, as_bytes(&self) -> &[u8;32]}`
  - `NetworkPrefix::{derive(&NetworkKey) -> Self, network(&self) -> Ipv6Addr, PREFIX_LEN: u8 = 48}`（`Clone + Copy + PartialEq + Eq + Debug + Display`，Display 形如 `fd6e:3a04:9f::/48`）
  - `NodeAddr { subnet_id: u16, site: Ipv6Addr /* /64 网络地址 */, address: Ipv6Addr }`
  - `derive_node_addr(NetworkPrefix, &NodePublicKey) -> Result<NodeAddr, AddrError>`
  - `check_subnet_collisions(&[(String, NodeAddr)]) -> Result<(), AddrError>`

- [ ] **Step 1: 写失败测试**

```rust
// network.rs tests
#[test]
fn prefix_is_ula_and_deterministic() {
    let key = NetworkKey::generate();
    let p1 = NetworkPrefix::derive(&key);
    let p2 = NetworkPrefix::derive(&key);
    assert_eq!(p1, p2);
    assert_eq!(p1.network().octets()[0], 0xfd);
}

#[test]
fn different_keys_different_prefixes() {
    let p1 = NetworkPrefix::derive(&NetworkKey::generate());
    let p2 = NetworkPrefix::derive(&NetworkKey::generate());
    assert_ne!(p1, p2);
}

/// 回归钉扎向量：首次实现后运行 `cargo test -- --nocapture print_vector`
/// 把输出冻结进本断言（防止未来无意改变派生算法）。
#[test]
fn frozen_derivation_vector() {
    let key = NetworkKey::from_base64("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap();
    let p = NetworkPrefix::derive(&key);
    // 占位断言：实现完成后替换为实际值并删除本注释（见 Step 4）
    assert_eq!(p.to_string(), "<FROZEN>");
}
```

```rust
// addr.rs tests
#[test]
fn same_network_same_prefix_different_nodes() {
    let key = NetworkKey::generate();
    let prefix = NetworkPrefix::derive(&key);
    let a = derive_node_addr(prefix, &NodeIdentity::generate().public()).unwrap();
    let b = derive_node_addr(prefix, &NodeIdentity::generate().public()).unwrap();
    // 同网 /48
    assert_eq!(a.address.octets()[..6], b.address.octets()[..6]);
    // 不同节点几乎必然不同 /64
    assert_ne!(a.address, b.address);
    // site 是 /64 网络地址（后 64 位全零）
    assert_eq!(a.site.octets()[8..], [0u8; 8]);
    // 节点地址落在自己的 site /64 内
    assert_eq!(a.address.octets()[..8], a.site.octets()[..8]);
}

#[test]
fn deterministic_node_addr() {
    let key = NetworkKey::generate();
    let prefix = NetworkPrefix::derive(&key);
    let pk = NodeIdentity::generate().public();
    assert_eq!(derive_node_addr(prefix, &pk).unwrap().address,
               derive_node_addr(prefix, &pk).unwrap().address);
}

#[test]
fn collision_detection() {
    let key = NetworkKey::generate();
    let prefix = NetworkPrefix::derive(&key);
    let a = derive_node_addr(prefix, &NodeIdentity::generate().public()).unwrap();
    let dup = a.clone();
    let err = check_subnet_collisions(&[("a".into(), a), ("b".into(), dup)]).unwrap_err();
    assert!(matches!(err, AddrError::SubnetCollision { .. }));
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-core network addr`
Expected: 编译失败（类型未定义）

- [ ] **Step 3: 实现**

`error.rs` 追加：

```rust
/// 地址派生错误。
#[derive(Debug, thiserror::Error)]
pub enum AddrError {
    /// 派生出全零 interface ID（概率 2^-64，视为密钥不可用）。
    #[error("degenerate interface id derived from public key")]
    DegenerateIid,
    /// 两个节点派生出相同的 16-bit subnet id。
    #[error("subnet id collision between {a} and {b}; one node must regenerate its key")]
    SubnetCollision {
        /// 冲突节点甲。
        a: String,
        /// 冲突节点乙。
        b: String,
    },
}
```

`network.rs`:

```rust
//! 网络密钥与 ULA /48 前缀派生（协议规范：docs/protocol/addressing.md）。

use std::fmt;
use std::net::Ipv6Addr;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::IdentityError;

/// 域分隔盐（协议版本锚点）。
const SALT: &[u8] = b"hextet-v1";

/// 网络密钥：32 字节共享秘密，决定网络身份与 ULA 前缀。
pub struct NetworkKey([u8; 32]);

impl Drop for NetworkKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl NetworkKey {
    /// 随机生成。
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        use rand_core::RngCore as _;
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// 从 base64 解析。
    pub fn from_base64(s: &str) -> Result<Self, IdentityError> {
        let v = B64.decode(s.trim()).map_err(|_| IdentityError::InvalidEncoding)?;
        let arr: [u8; 32] = v.try_into().map_err(|_| IdentityError::InvalidEncoding)?;
        Ok(Self(arr))
    }

    /// base64 编码。
    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    /// 原始字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 网络 ULA /48 前缀（`fd` + 40-bit network id）。
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NetworkPrefix([u8; 6]);

impl NetworkPrefix {
    /// 前缀长度恒为 /48。
    pub const PREFIX_LEN: u8 = 48;

    /// 由网络密钥经 HKDF-SHA256 派生。
    pub fn derive(key: &NetworkKey) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SALT), key.as_bytes());
        let mut id = [0u8; 5];
        hk.expand(b"network-id", &mut id).expect("5 bytes is a valid hkdf length");
        let mut p = [0u8; 6];
        p[0] = 0xfd;
        p[1..].copy_from_slice(&id);
        Self(p)
    }

    /// /48 的网络地址（后 80 位全零）。
    pub fn network(&self) -> Ipv6Addr {
        let mut o = [0u8; 16];
        o[..6].copy_from_slice(&self.0);
        Ipv6Addr::from(o)
    }

    /// 前 6 字节。
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for NetworkPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), Self::PREFIX_LEN)
    }
}
```

`addr.rs`:

```rust
//! 节点地址派生：公钥 → site /64 与节点地址（协议规范：docs/protocol/addressing.md）。

use std::net::Ipv6Addr;

use sha2::{Digest, Sha256};

use crate::error::AddrError;
use crate::identity::NodePublicKey;
use crate::network::NetworkPrefix;

/// 一个节点在 overlay 中的地址簇。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAddr {
    /// 16-bit site subnet id（网络内须唯一，配置加载时校验）。
    pub subnet_id: u16,
    /// 节点的 site /64 网络地址（供 M4 子网路由使用）。
    pub site: Ipv6Addr,
    /// 节点自身 /128 地址。
    pub address: Ipv6Addr,
}

/// 从网络前缀与节点公钥派生地址。
pub fn derive_node_addr(
    prefix: NetworkPrefix,
    pubkey: &NodePublicKey,
) -> Result<NodeAddr, AddrError> {
    let subnet_id = {
        let d = Sha256::new_with_prefix(b"hextet-v1 subnet-id")
            .chain_update(pubkey.as_bytes())
            .finalize();
        u16::from_be_bytes([d[0], d[1]])
    };
    let iid: [u8; 8] = {
        let d = Sha256::new_with_prefix(b"hextet-v1 iid")
            .chain_update(pubkey.as_bytes())
            .finalize();
        d[..8].try_into().expect("sha256 output >= 8 bytes")
    };
    if iid == [0u8; 8] {
        return Err(AddrError::DegenerateIid);
    }

    let mut site = [0u8; 16];
    site[..6].copy_from_slice(prefix.as_bytes());
    site[6..8].copy_from_slice(&subnet_id.to_be_bytes());

    let mut addr = site;
    addr[8..].copy_from_slice(&iid);

    Ok(NodeAddr {
        subnet_id,
        site: Ipv6Addr::from(site),
        address: Ipv6Addr::from(addr),
    })
}

/// 校验一组（节点名, 地址）无 subnet id 冲突。
pub fn check_subnet_collisions(nodes: &[(String, NodeAddr)]) -> Result<(), AddrError> {
    let mut seen: std::collections::HashMap<u16, &str> = std::collections::HashMap::new();
    for (name, addr) in nodes {
        if let Some(prev) = seen.insert(addr.subnet_id, name) {
            return Err(AddrError::SubnetCollision { a: prev.to_owned(), b: name.clone() });
        }
    }
    Ok(())
}
```

- [ ] **Step 4: 冻结回归向量**

先临时加打印测试跑一次拿到全零 key 的实际前缀：

Run: `cargo test -p hextet-core frozen_derivation_vector -- --nocapture`（先把断言改成 `println!("{p}")` + `panic!()` 形式观察输出）
然后把实际字符串写入 `frozen_derivation_vector` 断言，删除占位注释。

Run: `cargo test -p hextet-core`
Expected: 全部 PASS

- [ ] **Step 5: 写协议文档 `docs/protocol/addressing.md`**

```markdown
# hextet 地址派生规范（v1）

状态：已实现（crates/core/src/{network,addr}.rs 与本文档同步维护）

## 输入
- `network_key`：32B 随机共享秘密（base64 存于配置）
- `node_pubkey`：节点 ed25519 公钥（32B）

## 派生
1. `network_id = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("network-id", 5)`
2. 网络前缀 = `0xfd || network_id`，即 ULA fd00::/8 内的一个 /48（RFC 4193）
3. `subnet_id = SHA-256("hextet-v1 subnet-id" || node_pubkey)[0..2]`（大端 u16）
4. 节点 site 前缀 = `网络前缀 || subnet_id`（/64，供 site-to-site 子网路由）
5. `iid = SHA-256("hextet-v1 iid" || node_pubkey)[0..8]`；全零非法（拒绝该公钥）
6. 节点地址 = `网络前缀(6B) || subnet_id(2B) || iid(8B)`（/128，位于其 site /64 内）

## WireGuard 密钥派生
- WG 私钥 = ed25519 `SigningKey::to_scalar_bytes()`（SHA-512 扩展后 clamp 的标量）
- WG 公钥 = ed25519 `VerifyingKey::to_montgomery()`（birational 映射到 Curve25519）
- 两者满足 `x25519(私钥, basepoint) == 公钥`（core 有 proptest 保证）

## 碰撞
- 网络间 /48 碰撞：RFC 4193 L=40，N 网络碰撞率 P≈N²/2⁴¹，可忽略
- 网内 subnet_id 为 16-bit：N 节点碰撞率 ≈ N²/2¹⁷（100 节点约 7%）——
  **必须**在配置加载/成员准入时校验（`check_subnet_collisions`），
  冲突时提示重新生成节点密钥
- 回归向量：全零 network_key → 前缀见 core 测试 `frozen_derivation_vector`

## 测试向量
见 `crates/core/src/network.rs::tests::frozen_derivation_vector`。
```

- [ ] **Step 6: 提交**

```bash
git add crates/core docs/protocol CHANGELOG.md
git commit -m "feat(core): ULA 网络前缀与节点地址派生 + 协议规范文档

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

（CHANGELOG 加："ULA /48 前缀派生（HKDF）与节点地址派生（SHA-256），协议文档 docs/protocol/addressing.md"。）

---

### Task 4: core::config — TOML 配置模型与校验

**Files:**
- Create: `crates/core/src/config.rs`
- Modify: `crates/core/src/lib.rs`、`crates/core/src/error.rs`

**Interfaces:**
- Consumes: Task 2/3 全部类型
- Produces:
  - `Config { pub network_name: String, pub network_key: NetworkKey, pub prefix: NetworkPrefix, pub node: NodeSettings, pub peers: Vec<Peer> }`
  - `NodeSettings { pub key_file: PathBuf, pub listen_port: u16, pub mtu: u32, pub interface: String }`
  - `Peer { pub name: String, pub public_key: NodePublicKey, pub endpoints: Vec<SocketAddrV6>, pub addr: NodeAddr }`
  - `Config::load(path: &Path, own_pubkey: Option<&NodePublicKey>) -> Result<Config, ConfigError>`（解析 + 派生 + 校验；`own_pubkey` 提供时把自身也纳入冲突检测）
  - `Config::render_template(name: &str, network_key: &NetworkKey, key_file: &Path, listen_port: u16) -> String`（`init` 用的 TOML 模板）
  - 配置文件格式（v1）：

```toml
[network]
name = "home"
key = "<base64 32B>"

[node]
key_file = "node.key"
# listen_port = 4193
# mtu = 1400
# interface = "hextet0"

[[peers]]
name = "nas"
public_key = "<base64 ed25519>"
endpoints = ["[2001:db8::1]:4193"]
```

- [ ] **Step 1: 写失败测试**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[network]
name = "home"
key = "{KEY}"

[node]
key_file = "node.key"

[[peers]]
name = "nas"
public_key = "{PK}"
endpoints = ["[2001:db8::1]:4193"]
"#;

    fn sample_toml() -> (String, crate::network::NetworkKey) {
        let nk = crate::network::NetworkKey::generate();
        let pk = crate::identity::NodeIdentity::generate().public();
        let s = SAMPLE.replace("{KEY}", &nk.to_base64()).replace("{PK}", &pk.to_base64());
        (s, nk)
    }

    #[test]
    fn parse_defaults_and_derivation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, nk) = sample_toml();
        std::fs::write(&path, toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.network_name, "home");
        assert_eq!(cfg.node.listen_port, crate::defaults::DEFAULT_PORT);
        assert_eq!(cfg.node.mtu, crate::defaults::DEFAULT_MTU);
        assert_eq!(cfg.node.interface, crate::defaults::DEFAULT_INTERFACE);
        assert_eq!(cfg.prefix, crate::network::NetworkPrefix::derive(&nk));
        assert_eq!(cfg.peers.len(), 1);
        // peer 地址已派生且在网络前缀内
        assert_eq!(cfg.peers[0].addr.address.octets()[..6], *cfg.prefix.as_bytes());
    }

    #[test]
    fn reject_ipv4_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        let bad = toml_text.replace("[2001:db8::1]:4193", "1.2.3.4:4193");
        std::fs::write(&path, bad).unwrap();
        let err = Config::load(&path, None).unwrap_err();
        assert!(matches!(err, ConfigError::Ipv4Endpoint { .. }));
    }

    #[test]
    fn reject_duplicate_peer_pubkey() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        // 复制同一个 [[peers]] 块
        let peers_block = toml_text.split("[[peers]]").nth(1).unwrap().to_owned();
        let dup = format!("{toml_text}\n[[peers]]{peers_block}");
        std::fs::write(&path, dup.replace("name = \"nas\"\n", "name = \"nas2\"\n")).unwrap();
        // 注意：上面 replace 会把两处 name 都改掉——测试里手工构造两个块更直白，
        // 实现时用下面的显式写法：
        let err = Config::load(&path, None).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicatePeer { .. }));
    }

    #[test]
    fn template_roundtrips() {
        let nk = crate::network::NetworkKey::generate();
        let text = Config::render_template("home", &nk, std::path::Path::new("node.key"), 4193);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.network_name, "home");
        assert!(cfg.peers.is_empty());
    }
}
```

（`reject_duplicate_peer_pubkey` 的构造代码按注释在实现时改为显式两个 peer 块、不同 name、相同 public_key。）

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-core config`
Expected: 编译失败

- [ ] **Step 3: 实现**

`error.rs` 追加：

```rust
/// 配置错误。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// 文件读取失败。
    #[error("config {path}: {source}")]
    Io {
        /// 配置文件路径。
        path: std::path::PathBuf,
        /// 底层 I/O 错误。
        #[source]
        source: std::io::Error,
    },
    /// TOML 语法/结构错误。
    #[error("config parse error: {0}")]
    Parse(#[from] toml::de::Error),
    /// 网络密钥或 peer 公钥编码非法。
    #[error("peer {name}: {source}")]
    BadKey {
        /// peer 名。
        name: String,
        /// 底层错误。
        #[source]
        source: crate::error::IdentityError,
    },
    /// endpoint 不是 IPv6。hextet 是 IPv6-only 的。
    #[error("peer {name}: endpoint {endpoint} is IPv4; hextet is IPv6-only")]
    Ipv4Endpoint {
        /// peer 名。
        name: String,
        /// 违规 endpoint 原文。
        endpoint: String,
    },
    /// endpoint 无法解析。
    #[error("peer {name}: invalid endpoint {endpoint}")]
    BadEndpoint {
        /// peer 名。
        name: String,
        /// 违规 endpoint 原文。
        endpoint: String,
    },
    /// 两个 peer 用了同一把公钥。
    #[error("peers {a} and {b} share the same public key")]
    DuplicatePeer {
        /// peer 甲。
        a: String,
        /// peer 乙。
        b: String,
    },
    /// subnet id 碰撞。
    #[error(transparent)]
    Addr(#[from] AddrError),
    /// 网络密钥缺失/非法。
    #[error("invalid network key")]
    BadNetworkKey,
}
```

`config.rs` 核心（serde 原始结构 + 转换校验）：

```rust
//! 节点配置：TOML 解析、默认值、派生与校验。

use std::net::{SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::addr::{check_subnet_collisions, derive_node_addr, NodeAddr};
use crate::defaults;
use crate::error::ConfigError;
use crate::identity::NodePublicKey;
use crate::network::{NetworkKey, NetworkPrefix};

#[derive(Deserialize)]
struct RawConfig {
    network: RawNetwork,
    node: RawNode,
    #[serde(default)]
    peers: Vec<RawPeer>,
}

#[derive(Deserialize)]
struct RawNetwork {
    name: String,
    key: String,
}

#[derive(Deserialize)]
struct RawNode {
    key_file: PathBuf,
    listen_port: Option<u16>,
    mtu: Option<u32>,
    interface: Option<String>,
}

#[derive(Deserialize)]
struct RawPeer {
    name: String,
    public_key: String,
    #[serde(default)]
    endpoints: Vec<String>,
}

/// 节点本地设置。
#[derive(Debug, Clone)]
pub struct NodeSettings { /* 见 Interfaces */ pub key_file: PathBuf, pub listen_port: u16, pub mtu: u32, pub interface: String }

/// 一个已校验的 peer。
#[derive(Debug, Clone)]
pub struct Peer { pub name: String, pub public_key: NodePublicKey, pub endpoints: Vec<SocketAddrV6>, pub addr: NodeAddr }

/// 已加载并校验的配置。
pub struct Config { pub network_name: String, pub network_key: NetworkKey, pub prefix: NetworkPrefix, pub node: NodeSettings, pub peers: Vec<Peer> }

impl Config {
    /// 加载配置：解析 TOML → 派生前缀与 peer 地址 → 校验。
    pub fn load(path: &Path, own_pubkey: Option<&NodePublicKey>) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|source| ConfigError::Io { path: path.to_owned(), source })?;
        let raw: RawConfig = toml::from_str(&text)?;
        let network_key =
            NetworkKey::from_base64(&raw.network.key).map_err(|_| ConfigError::BadNetworkKey)?;
        let prefix = NetworkPrefix::derive(&network_key);

        let mut peers = Vec::with_capacity(raw.peers.len());
        for rp in &raw.peers {
            let public_key = NodePublicKey::from_base64(&rp.public_key)
                .map_err(|source| ConfigError::BadKey { name: rp.name.clone(), source })?;
            let mut endpoints = Vec::with_capacity(rp.endpoints.len());
            for e in &rp.endpoints {
                match e.parse::<SocketAddr>() {
                    Ok(SocketAddr::V6(v6)) => endpoints.push(v6),
                    Ok(SocketAddr::V4(_)) => {
                        return Err(ConfigError::Ipv4Endpoint { name: rp.name.clone(), endpoint: e.clone() })
                    }
                    Err(_) => {
                        return Err(ConfigError::BadEndpoint { name: rp.name.clone(), endpoint: e.clone() })
                    }
                }
            }
            let addr = derive_node_addr(prefix, &public_key)?;
            peers.push(Peer { name: rp.name.clone(), public_key, endpoints, addr });
        }

        // 公钥去重
        for i in 0..peers.len() {
            for j in (i + 1)..peers.len() {
                if peers[i].public_key == peers[j].public_key {
                    return Err(ConfigError::DuplicatePeer { a: peers[i].name.clone(), b: peers[j].name.clone() });
                }
            }
        }

        // subnet 碰撞（含自身）
        let mut all: Vec<(String, NodeAddr)> =
            peers.iter().map(|p| (p.name.clone(), p.addr.clone())).collect();
        if let Some(own) = own_pubkey {
            all.push(("<self>".into(), derive_node_addr(prefix, own)?));
        }
        check_subnet_collisions(&all)?;

        Ok(Config {
            network_name: raw.network.name,
            network_key,
            prefix,
            node: NodeSettings {
                key_file: raw.node.key_file,
                listen_port: raw.node.listen_port.unwrap_or(defaults::DEFAULT_PORT),
                mtu: raw.node.mtu.unwrap_or(defaults::DEFAULT_MTU),
                interface: raw.node.interface.unwrap_or_else(|| defaults::DEFAULT_INTERFACE.into()),
            },
            peers,
        })
    }

    /// 生成 `hextet init` 的配置模板。
    pub fn render_template(
        name: &str,
        network_key: &NetworkKey,
        key_file: &Path,
        listen_port: u16,
    ) -> String {
        format!(
            r#"# hextet 节点配置（v1，静态模式）
# 文档：docs/guides/quickstart.md

[network]
name = "{name}"
# 网络密钥：同一网络的所有节点必须一致。妥善保管。
key = "{key}"

[node]
key_file = "{key_file}"
listen_port = {listen_port}
# mtu = 1400
# interface = "hextet0"

# 每个对端一个 [[peers]] 块：
# [[peers]]
# name = "nas"
# public_key = "<对方 hextet keygen 输出的公钥>"
# endpoints = ["[对方公网IPv6]:4193"]
"#,
            name = name,
            key = network_key.to_base64(),
            key_file = key_file.display(),
            listen_port = listen_port,
        )
    }
}
```

`lib.rs` 增加 `pub mod addr; pub mod config; pub mod network;`（Task 3 已加 network/addr 则只补 config）。

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-core`
Expected: 全部 PASS

- [ ] **Step 5: 提交**

```bash
git add crates/core CHANGELOG.md
git commit -m "feat(core): TOML 配置模型与校验（IPv6-only endpoint、碰撞检测）

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: CLI keygen/init/inspect（M0 验收）

**Files:**
- Create: `crates/cli/Cargo.toml`、`crates/cli/src/main.rs`、`crates/cli/src/lib.rs`、`crates/cli/src/commands/mod.rs`、`crates/cli/src/commands/{keygen,init,inspect}.rs`
- Create: `crates/cli/tests/cli.rs`
- Modify: 根 `Cargo.toml`（members 加 `crates/cli`）、`README.md`（使用示例）

**Interfaces:**
- Consumes: `hextet-core` 全部公开 API
- Produces:
  - 二进制名 `hextet`（package `hextet-cli`，`[[bin]] name = "hextet"`）
  - `hextet keygen [--out node.key] [--force]` → stdout 打印一行 `public-key: <base64>`
  - `hextet init --name <网络名> [--key-file node.key] [--listen-port 4193] [--network-key <b64>] [--out hextet.toml]`：`--network-key` 缺省时生成新密钥（创建新网络），提供时加入既有网络
  - `hextet inspect [-c hextet.toml] [--json]`：人类可读输出（网络前缀/本节点地址/peers 表）；`--json` 输出 `{"network":{"name","prefix"},"node":{"public_key","address","site"},"peers":[{"name","public_key","address","endpoints"}]}`
  - `crates/cli/src/lib.rs` 导出 `inspect::InspectReport`（serde Serialize 的报告结构，Task 8/9 复用）

- [ ] **Step 1: 写失败的 CLI 集成测试**（`crates/cli/tests/cli.rs`）

```rust
use assert_cmd::Command;
use predicates::prelude::*;

fn hextet() -> Command {
    Command::cargo_bin("hextet").unwrap()
}

#[test]
fn keygen_creates_key_and_prints_pubkey() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    hextet()
        .args(["keygen", "--out"])
        .arg(&key)
        .assert()
        .success()
        .stdout(predicate::str::contains("public-key: "));
    assert!(key.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // 不加 --force 重复写入应失败
    hextet().args(["keygen", "--out"]).arg(&key).assert().failure();
}

#[test]
fn init_then_inspect_shows_ula_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    let cfg = dir.path().join("hextet.toml");
    hextet().args(["keygen", "--out"]).arg(&key).assert().success();
    hextet()
        .args(["init", "--name", "testnet", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg)
        .assert()
        .success();
    hextet()
        .args(["inspect", "-c"])
        .arg(&cfg)
        .assert()
        .success()
        .stdout(predicate::str::contains("fd")); // ULA 前缀
}

/// M0 验收：两个身份 + 同一 network key → inspect 显示相同 /48 前缀。
#[test]
fn two_identities_share_network_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let (key_a, key_b) = (dir.path().join("a.key"), dir.path().join("b.key"));
    let (cfg_a, cfg_b) = (dir.path().join("a.toml"), dir.path().join("b.toml"));
    hextet().args(["keygen", "--out"]).arg(&key_a).assert().success();
    hextet().args(["keygen", "--out"]).arg(&key_b).assert().success();

    hextet().args(["init", "--name", "t", "--key-file"]).arg(&key_a)
        .args(["--out"]).arg(&cfg_a).assert().success();
    // 从 a 的配置里抠出 network key（简单 grep）
    let text = std::fs::read_to_string(&cfg_a).unwrap();
    let netkey = text.lines().find(|l| l.starts_with("key = ")).unwrap()
        .trim_start_matches("key = ").trim_matches('"').to_owned();
    hextet().args(["init", "--name", "t", "--key-file"]).arg(&key_b)
        .args(["--network-key", &netkey, "--out"]).arg(&cfg_b).assert().success();

    let prefix = |cfg: &std::path::Path| -> String {
        let out = hextet().args(["inspect", "--json", "-c"]).arg(cfg).output().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["network"]["prefix"].as_str().unwrap().to_owned()
    };
    assert_eq!(prefix(&cfg_a), prefix(&cfg_b));
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-cli`
Expected: 编译失败（crate 不存在）——先把 `crates/cli` 加进 members 后再跑一次，Expected: 找不到二进制/未实现

- [ ] **Step 3: 实现 CLI**

`crates/cli/Cargo.toml`:

```toml
[package]
name = "hextet-cli"
description = "hextet command-line interface"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true

[[bin]]
name = "hextet"
path = "src/main.rs"

[dependencies]
hextet-core.workspace = true
anyhow.workspace = true
clap.workspace = true
serde.workspace = true
serde_json.workspace = true

[dev-dependencies]
assert_cmd.workspace = true
predicates.workspace = true
tempfile.workspace = true
```

`src/main.rs`:

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "hextet", version, about = "IPv6-only serverless mesh VPN")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 生成节点身份密钥
    Keygen(hextet_cli::commands::keygen::Args),
    /// 初始化节点配置（新建网络或以 --network-key 加入既有网络）
    Init(hextet_cli::commands::init::Args),
    /// 查看派生的网络前缀、本节点与 peers 的 overlay 地址
    Inspect(hextet_cli::commands::inspect::Args),
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen(a) => hextet_cli::commands::keygen::run(a),
        Cmd::Init(a) => hextet_cli::commands::init::run(a),
        Cmd::Inspect(a) => hextet_cli::commands::inspect::run(a),
    }
}
```

`commands/keygen.rs`:

```rust
//! `hextet keygen`

use std::path::PathBuf;

use anyhow::{bail, Context};
use hextet_core::identity::NodeIdentity;

#[derive(clap::Args)]
pub struct Args {
    /// 密钥文件输出路径
    #[arg(long, default_value = "node.key")]
    pub out: PathBuf,
    /// 覆盖已存在的文件
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    if args.out.exists() {
        if !args.force {
            bail!("{} 已存在（用 --force 覆盖）", args.out.display());
        }
        std::fs::remove_file(&args.out)
            .with_context(|| format!("删除旧密钥 {}", args.out.display()))?;
    }
    let id = NodeIdentity::generate();
    id.save(&args.out)?;
    println!("public-key: {}", id.public().to_base64());
    println!("key-file: {}", args.out.display());
    Ok(())
}
```

`commands/init.rs`:

```rust
//! `hextet init`

use std::path::PathBuf;

use anyhow::bail;
use hextet_core::config::Config;
use hextet_core::network::NetworkKey;

#[derive(clap::Args)]
pub struct Args {
    /// 网络名
    #[arg(long)]
    pub name: String,
    /// 节点密钥文件路径（须已由 keygen 生成）
    #[arg(long, default_value = "node.key")]
    pub key_file: PathBuf,
    /// WireGuard 监听端口
    #[arg(long, default_value_t = hextet_core::defaults::DEFAULT_PORT)]
    pub listen_port: u16,
    /// 加入既有网络：提供其 network key（缺省则新建网络）
    #[arg(long)]
    pub network_key: Option<String>,
    /// 配置输出路径
    #[arg(long, default_value = "hextet.toml")]
    pub out: PathBuf,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    if args.out.exists() {
        bail!("{} 已存在", args.out.display());
    }
    if !args.key_file.exists() {
        bail!("密钥文件 {} 不存在，先运行 hextet keygen", args.key_file.display());
    }
    let key = match &args.network_key {
        Some(s) => NetworkKey::from_base64(s)?,
        None => NetworkKey::generate(),
    };
    let text = Config::render_template(&args.name, &key, &args.key_file, args.listen_port);
    std::fs::write(&args.out, text)?;
    println!("wrote {}", args.out.display());
    Ok(())
}
```

`commands/inspect.rs`（同时定义 `InspectReport` 于 lib 中导出）：

```rust
//! `hextet inspect`

use std::path::PathBuf;

use hextet_core::addr::derive_node_addr;
use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;

/// 机器可读的 inspect 报告（--json）。
#[derive(serde::Serialize)]
pub struct InspectReport {
    /// 网络信息。
    pub network: NetworkReport,
    /// 本节点。
    pub node: NodeReport,
    /// 对端列表。
    pub peers: Vec<PeerReport>,
}

#[derive(serde::Serialize)]
pub struct NetworkReport { pub name: String, pub prefix: String }
#[derive(serde::Serialize)]
pub struct NodeReport { pub public_key: String, pub address: String, pub site: String }
#[derive(serde::Serialize)]
pub struct PeerReport { pub name: String, pub public_key: String, pub address: String, pub endpoints: Vec<String> }

#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 以 JSON 输出
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    // 先读配置拿 key_file，再载身份，最后带 own_pubkey 重新校验
    let cfg = Config::load(&args.config, None)?;
    let key_path = if cfg.node.key_file.is_relative() {
        args.config.parent().unwrap_or(std::path::Path::new(".")).join(&cfg.node.key_file)
    } else {
        cfg.node.key_file.clone()
    };
    let id = NodeIdentity::load(&key_path)?;
    let cfg = Config::load(&args.config, Some(&id.public()))?;
    let own = derive_node_addr(cfg.prefix, &id.public())?;

    let report = InspectReport {
        network: NetworkReport { name: cfg.network_name.clone(), prefix: cfg.prefix.to_string() },
        node: NodeReport {
            public_key: id.public().to_base64(),
            address: own.address.to_string(),
            site: format!("{}/64", own.site),
        },
        peers: cfg.peers.iter().map(|p| PeerReport {
            name: p.name.clone(),
            public_key: p.public_key.to_base64(),
            address: p.addr.address.to_string(),
            endpoints: p.endpoints.iter().map(|e| e.to_string()).collect(),
        }).collect(),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("network  {}  prefix {}", report.network.name, report.network.prefix);
        println!("node     {}  {}", report.node.address, report.node.public_key);
        for p in &report.peers {
            println!("peer {:12} {}  endpoints {:?}", p.name, p.address, p.endpoints);
        }
    }
    Ok(())
}
```

`lib.rs`：`pub mod commands;`（commands/mod.rs：`pub mod keygen; pub mod init; pub mod inspect;`）。字段 docs 按 `missing_docs` 要求补全（cli crate 不强制 deny，但公开结构加 doc）。

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-cli`
Expected: 3 个测试 PASS（含 M0 验收 `two_identities_share_network_prefix`）

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 更新 README 使用示例并提交**

README 增加：

```markdown
## 快速上手（M0：身份与地址）

```console
$ hextet keygen --out node.key
public-key: 3fK...=
$ hextet init --name home --key-file node.key
wrote hextet.toml
$ hextet inspect
network  home  prefix fdxx:xxxx:xx::/48
node     fdxx:xxxx:xx:ab12:...  3fK...=
```
```

```bash
git add crates/cli Cargo.toml README.md CHANGELOG.md
git commit -m "feat(cli): keygen/init/inspect 命令（M0 验收达成）

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: hextet-wg — WgBackend trait 与内核实现

**Files:**
- Create: `crates/wg/Cargo.toml`、`crates/wg/src/lib.rs`、`crates/wg/src/types.rs`、`crates/wg/src/kernel.rs`、`crates/wg/src/mock.rs`
- Modify: 根 `Cargo.toml`（members 加 `crates/wg`）

**Interfaces:**
- Consumes: 无（独立于 core；密钥以 `[u8;32]` 传入）
- Produces:
  - `DeviceSpec { pub interface: String, pub listen_port: u16, pub wg_secret: [u8;32], pub peers: Vec<PeerSpec> }`
  - `PeerSpec { pub wg_public: [u8;32], pub endpoint: Option<SocketAddrV6>, pub allowed_ips: Vec<(Ipv6Addr, u8)>, pub persistent_keepalive: Option<u16> }`
  - `PeerStatus { pub wg_public: [u8;32], pub endpoint: Option<SocketAddr>, pub last_handshake: Option<SystemTime>, pub rx_bytes: u64, pub tx_bytes: u64 }`
  - `trait WgBackend { fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError>; fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError>; }`
  - `KernelBackend`（Linux，wireguard-control；apply 时自动创建接口）
  - `MockBackend`（记录调用，供 CLI 单测）
  - 注：接口删除不在本 trait（由 platform 的 `delete_interface` 负责，Task 7）

- [ ] **Step 1: 写失败测试**（`crates/wg/src/mock.rs` + types 单测）

```rust
#[cfg(test)]
mod tests {
    use super::super::types::*;
    use super::MockBackend;
    use crate::WgBackend as _;

    #[test]
    fn mock_records_applied_spec() {
        let mock = MockBackend::default();
        let spec = DeviceSpec {
            interface: "hextet0".into(),
            listen_port: 4193,
            wg_secret: [7u8; 32],
            peers: vec![],
        };
        mock.apply(&spec).unwrap();
        assert_eq!(mock.applied.lock().unwrap().len(), 1);
        assert_eq!(mock.applied.lock().unwrap()[0].listen_port, 4193);
    }

    #[test]
    fn key_base64_bridge() {
        // wireguard-control 走 base64 构造 Key：验证桥接函数
        let bytes = [42u8; 32];
        let key = crate::kernel::key_from_bytes(&bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-wg`
Expected: 编译失败

- [ ] **Step 3: 实现**

`crates/wg/Cargo.toml`:

```toml
[package]
name = "hextet-wg"
description = "hextet WireGuard backend abstraction (kernel via netlink)"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true

[dependencies]
thiserror.workspace = true
base64.workspace = true

[target.'cfg(target_os = "linux")'.dependencies]
wireguard-control.workspace = true
```

`types.rs`:

```rust
//! 后端无关的设备/peer 描述。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::SystemTime;

/// 期望的 WireGuard 设备状态（声明式，apply 幂等）。
#[derive(Debug, Clone)]
pub struct DeviceSpec {
    /// 接口名。
    pub interface: String,
    /// UDP 监听端口。
    pub listen_port: u16,
    /// WG 私钥字节。
    pub wg_secret: [u8; 32],
    /// 对端列表。
    pub peers: Vec<PeerSpec>,
}

/// 单个对端的期望状态。
#[derive(Debug, Clone)]
pub struct PeerSpec {
    /// 对端 WG 公钥。
    pub wg_public: [u8; 32],
    /// 静态 endpoint（M1：取配置中第一个）。
    pub endpoint: Option<SocketAddrV6>,
    /// AllowedIPs（IPv6-only）。
    pub allowed_ips: Vec<(Ipv6Addr, u8)>,
    /// keepalive 秒数。
    pub persistent_keepalive: Option<u16>,
}

/// 对端运行时状态。
#[derive(Debug, Clone)]
pub struct PeerStatus {
    /// 对端 WG 公钥。
    pub wg_public: [u8; 32],
    /// 内核记录的当前 endpoint。
    pub endpoint: Option<SocketAddr>,
    /// 最近一次握手时间。
    pub last_handshake: Option<SystemTime>,
    /// 接收字节数。
    pub rx_bytes: u64,
    /// 发送字节数。
    pub tx_bytes: u64,
}

/// WG 后端错误。
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    /// 接口不存在。
    #[error("interface {0} not found")]
    NotFound(String),
    /// 底层系统错误。
    #[error("wireguard backend error: {0}")]
    Backend(String),
}
```

`lib.rs`:

```rust
//! WireGuard 后端抽象：设计 spec §3 D1 的 `WgBackend` trait。
#![deny(missing_docs)]

pub mod mock;
pub mod types;

#[cfg(target_os = "linux")]
pub mod kernel;

use types::{DeviceSpec, PeerStatus, WgError};

/// WireGuard 数据面后端（kernel / 未来 userspace-gotatun）。
pub trait WgBackend {
    /// 幂等地把设备调到 spec 描述的状态（接口不存在则创建）。
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError>;
    /// 读取设备的 peer 运行时状态。
    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError>;
}
```

`mock.rs`:

```rust
//! 测试用 Mock 后端。

use std::sync::Mutex;

use crate::types::{DeviceSpec, PeerStatus, WgError};
use crate::WgBackend;

/// 记录 apply 调用的 mock。
#[derive(Default)]
pub struct MockBackend {
    /// 已 apply 的 spec 序列。
    pub applied: Mutex<Vec<DeviceSpec>>,
}

impl WgBackend for MockBackend {
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError> {
        self.applied.lock().expect("mock lock").push(spec.clone());
        Ok(())
    }

    fn status(&self, _interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        Ok(vec![])
    }
}
```

`kernel.rs`（Linux；API 若与 wireguard-control 2.x docs.rs 有出入，以 docs.rs 为准）：

```rust
//! 内核 WireGuard 后端（netlink，经 wireguard-control）。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use crate::types::{DeviceSpec, PeerStatus, WgError};
use crate::WgBackend;

/// 内核后端。
pub struct KernelBackend;

/// 由原始字节构造 wireguard-control 的 Key（经 base64 桥接，避免依赖内部布局）。
pub fn key_from_bytes(bytes: &[u8; 32]) -> Key {
    Key::from_base64(&B64.encode(bytes)).expect("32 bytes always encode to valid key")
}

fn iface(name: &str) -> Result<InterfaceName, WgError> {
    name.parse().map_err(|_| WgError::Backend(format!("invalid interface name {name}")))
}

impl WgBackend for KernelBackend {
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError> {
        let ifname = iface(&spec.interface)?;
        let mut update = DeviceUpdate::new()
            .set_private_key(key_from_bytes(&spec.wg_secret))
            .set_listen_port(spec.listen_port)
            .replace_peers();
        for p in &spec.peers {
            let mut pc = PeerConfigBuilder::new(&key_from_bytes(&p.wg_public));
            if let Some(ep) = p.endpoint {
                pc = pc.set_endpoint(std::net::SocketAddr::V6(ep));
            }
            for (net, len) in &p.allowed_ips {
                pc = pc.add_allowed_ip(std::net::IpAddr::V6(*net), *len);
            }
            if let Some(ka) = p.persistent_keepalive {
                pc = pc.set_persistent_keepalive_interval(ka);
            }
            update = update.add_peer(pc);
        }
        update
            .apply(&ifname, Backend::Kernel)
            .map_err(|e| WgError::Backend(e.to_string()))
    }

    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        let ifname = iface(interface)?;
        let dev = Device::get(&ifname, Backend::Kernel)
            .map_err(|_| WgError::NotFound(interface.to_owned()))?;
        Ok(dev
            .peers
            .iter()
            .map(|p| PeerStatus {
                wg_public: p.config.public_key.as_bytes().try_into().expect("wg key is 32 bytes"),
                endpoint: p.config.endpoint,
                last_handshake: p.stats.last_handshake_time,
                rx_bytes: p.stats.rx_bytes,
                tx_bytes: p.stats.tx_bytes,
            })
            .collect())
    }
}
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-wg`（macOS 开发机上 kernel 模块不编译，mock/types 测试仍跑；Linux CI 上全编译）
Expected: PASS

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

```bash
git add crates/wg Cargo.toml CHANGELOG.md
git commit -m "feat(wg): WgBackend trait + 内核 netlink 实现 + mock

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: hextet-platform — 接口地址/MTU/生命周期（Linux）

**Files:**
- Create: `crates/platform/Cargo.toml`、`crates/platform/src/lib.rs`、`crates/platform/src/linux.rs`
- Modify: 根 `Cargo.toml`（members 加 `crates/platform`）

**Interfaces:**
- Consumes: 无
- Produces（Linux；`#[cfg(target_os = "linux")]`，其余平台返回 `PlatformError::Unsupported`）：
  - `async fn setup_interface(name: &str, address: Ipv6Addr, prefix_len: u8, mtu: u32) -> Result<(), PlatformError>`——给已存在的接口（wg apply 创建）加地址、设 MTU、拉起 link；以 `address/prefix_len`（M1 传 /48）产生覆盖全网的连通路由
  - `async fn delete_interface(name: &str) -> Result<(), PlatformError>`
  - `PlatformError::{NotFound(String), Unsupported, Netlink(String)}`

- [ ] **Step 1: 写失败测试**（需 root 的测试标记 `#[ignore]`，在 e2e 中真实覆盖）

```rust
// crates/platform/src/linux.rs 底部
#[cfg(test)]
mod tests {
    /// 需要 root + Linux：`sudo -E cargo test -p hextet-platform -- --ignored`
    /// 常规 CI 不跑（netns E2E 已覆盖同等路径）。
    #[tokio::test]
    #[ignore = "requires root"]
    async fn setup_missing_interface_is_not_found() {
        let err = super::setup_interface("hxt-noexist0", "fd00::1".parse().unwrap(), 48, 1400)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::PlatformError::NotFound(_)));
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-platform`
Expected: 编译失败（crate 未建）

- [ ] **Step 3: 实现**

`crates/platform/Cargo.toml`:

```toml
[package]
name = "hextet-platform"
description = "hextet platform integration: interface address, MTU, lifecycle"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true

[dependencies]
thiserror.workspace = true

[target.'cfg(target_os = "linux")'.dependencies]
rtnetlink.workspace = true
tokio.workspace = true
futures = "0.3"

[dev-dependencies]
tokio.workspace = true
```

（`futures` 用于 rtnetlink 返回的 stream 收集；记得同时登记到 `[workspace.dependencies]`。）

`lib.rs`:

```rust
//! 平台集成：接口地址、MTU、生命周期（M1 仅 Linux）。
#![deny(missing_docs)]

/// 平台错误。
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// 接口不存在。
    #[error("interface {0} not found")]
    NotFound(String),
    /// 当前平台未实现。
    #[error("unsupported platform")]
    Unsupported,
    /// netlink 错误。
    #[error("netlink: {0}")]
    Netlink(String),
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{delete_interface, setup_interface};

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::PlatformError;
    use std::net::Ipv6Addr;

    /// 非 Linux 平台暂不支持（M4 起支持 macOS）。
    pub async fn setup_interface(
        _name: &str,
        _address: Ipv6Addr,
        _prefix_len: u8,
        _mtu: u32,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    /// 非 Linux 平台暂不支持。
    pub async fn delete_interface(_name: &str) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
}
#[cfg(not(target_os = "linux"))]
pub use stub::{delete_interface, setup_interface};
```

`linux.rs`:

```rust
//! Linux rtnetlink 实现。

use std::net::{IpAddr, Ipv6Addr};

use futures::TryStreamExt as _;

use crate::PlatformError;

fn nl(e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Netlink(e.to_string())
}

async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, PlatformError> {
    let mut links = handle.link().get().match_name(name.to_owned()).execute();
    match links.try_next().await {
        Ok(Some(link)) => Ok(link.header.index),
        _ => Err(PlatformError::NotFound(name.to_owned())),
    }
}

/// 为接口配置地址/MTU 并拉起。
pub async fn setup_interface(
    name: &str,
    address: Ipv6Addr,
    prefix_len: u8,
    mtu: u32,
) -> Result<(), PlatformError> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(nl)?;
    tokio::spawn(conn);
    let index = link_index(&handle, name).await?;
    handle
        .address()
        .add(index, IpAddr::V6(address), prefix_len)
        .execute()
        .await
        .map_err(nl)?;
    handle
        .link()
        .set(index)
        .mtu(mtu)
        .up()
        .execute()
        .await
        .map_err(nl)?;
    Ok(())
}

/// 删除接口。
pub async fn delete_interface(name: &str) -> Result<(), PlatformError> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(nl)?;
    tokio::spawn(conn);
    let index = link_index(&handle, name).await?;
    handle.link().del(index).execute().await.map_err(nl)
}
```

（注意：rtnetlink 0.21 的 `link().set(index)` 构建方式若已改为 `link().set(LinkMessage)` 风格，按 docs.rs 当前示例调整——本任务允许该幅度的适配，见 Global Constraints 最后一条。）

- [ ] **Step 4: 编译与常规测试**

Run: `cargo xtask ci`
Expected: 全绿（root 测试被 ignore）

- [ ] **Step 5: 提交**

```bash
git add crates/platform Cargo.toml CHANGELOG.md
git commit -m "feat(platform): Linux 接口地址/MTU/生命周期（rtnetlink）

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: CLI up/down/status

**Files:**
- Create: `crates/cli/src/commands/{up,down,status}.rs`、`crates/cli/src/spec.rs`
- Modify: `crates/cli/src/main.rs`、`crates/cli/src/lib.rs`、`crates/cli/src/commands/mod.rs`、`crates/cli/Cargo.toml`（加 hextet-wg / hextet-platform / tokio 依赖）
- Test: `crates/cli/tests/spec.rs`

**Interfaces:**
- Consumes: `Config`/`NodeIdentity`/`derive_node_addr`（core）、`WgBackend`/`DeviceSpec`/`KernelBackend`/`MockBackend`（wg）、`setup_interface`/`delete_interface`（platform）、`InspectReport`（Task 5）
- Produces:
  - `hextet up [-c hextet.toml]`（root）：wg apply（建接口+配 peers）→ 加地址（node 地址、prefix_len=48）→ MTU → up
  - `hextet down [-c hextet.toml]`：删接口
  - `hextet status [-c hextet.toml] [--json]`：表格列 `peer / overlay addr / endpoint / last-handshake / rx / tx / state`；state = `connected`（握手 <180s）/ `stale`（≥180s）/ `no-handshake`
  - `hextet_cli::spec::build_device_spec(cfg: &Config, id: &NodeIdentity) -> DeviceSpec`（纯函数，单测覆盖）：peer 的 `allowed_ips = [(peer.addr.site, 64)]`、`endpoint = 第一个配置 endpoint`、`persistent_keepalive = Some(25)`

- [ ] **Step 1: 写失败测试**（`crates/cli/tests/spec.rs`）

```rust
use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;

fn write_two_node_setup(dir: &std::path::Path) -> (std::path::PathBuf, NodeIdentity) {
    let id = NodeIdentity::generate();
    let peer = NodeIdentity::generate();
    let key_path = dir.join("node.key");
    id.save(&key_path).unwrap();
    let nk = hextet_core::network::NetworkKey::generate();
    let cfg = format!(
        r#"
[network]
name = "t"
key = "{nk}"

[node]
key_file = "node.key"

[[peers]]
name = "b"
public_key = "{pk}"
endpoints = ["[2001:db8::2]:4193"]
"#,
        nk = nk.to_base64(),
        pk = peer.public().to_base64(),
    );
    let cfg_path = dir.join("hextet.toml");
    std::fs::write(&cfg_path, cfg).unwrap();
    (cfg_path, id)
}

#[test]
fn device_spec_maps_config() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg_path, id) = write_two_node_setup(dir.path());
    let cfg = Config::load(&cfg_path, Some(&id.public())).unwrap();
    let spec = hextet_cli::spec::build_device_spec(&cfg, &id);

    assert_eq!(spec.interface, "hextet0");
    assert_eq!(spec.listen_port, 4193);
    assert_eq!(spec.wg_secret, id.wg_secret_bytes());
    assert_eq!(spec.peers.len(), 1);
    let p = &spec.peers[0];
    assert_eq!(p.wg_public, cfg.peers[0].public_key.wg_public_bytes());
    assert_eq!(p.endpoint.unwrap().to_string(), "[2001:db8::2]:4193");
    // AllowedIPs = peer 的 site /64
    assert_eq!(p.allowed_ips, vec![(cfg.peers[0].addr.site, 64)]);
    assert_eq!(p.persistent_keepalive, Some(25));
}

#[test]
fn status_state_classification() {
    use std::time::{Duration, SystemTime};
    let now = SystemTime::now();
    assert_eq!(hextet_cli::commands::status::classify(Some(now - Duration::from_secs(10)), now), "connected");
    assert_eq!(hextet_cli::commands::status::classify(Some(now - Duration::from_secs(600)), now), "stale");
    assert_eq!(hextet_cli::commands::status::classify(None, now), "no-handshake");
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-cli`
Expected: 编译失败（`spec`/`status::classify` 未定义）

- [ ] **Step 3: 实现**

`crates/cli/src/spec.rs`:

```rust
//! 配置 → WG DeviceSpec 的纯映射（可单测）。

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;
use hextet_wg::types::{DeviceSpec, PeerSpec};

/// M1 常电节点 keepalive（设计 spec §5）。
const KEEPALIVE_SECS: u16 = 25;

/// 由配置与身份构建设备期望状态。
pub fn build_device_spec(cfg: &Config, id: &NodeIdentity) -> DeviceSpec {
    DeviceSpec {
        interface: cfg.node.interface.clone(),
        listen_port: cfg.node.listen_port,
        wg_secret: id.wg_secret_bytes(),
        peers: cfg
            .peers
            .iter()
            .map(|p| PeerSpec {
                wg_public: p.public_key.wg_public_bytes(),
                endpoint: p.endpoints.first().copied(),
                allowed_ips: vec![(p.addr.site, 64)],
                persistent_keepalive: Some(KEEPALIVE_SECS),
            })
            .collect(),
    }
}
```

`commands/up.rs`:

```rust
//! `hextet up`：建接口、配 WG、配地址、拉起。

use std::path::PathBuf;

use anyhow::Context as _;
use hextet_core::addr::derive_node_addr;
use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;
use hextet_core::network::NetworkPrefix;
use hextet_wg::WgBackend as _;

#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, id) = super::load_config_and_identity(&args.config)?;
    let own = derive_node_addr(cfg.prefix, &id.public())?;
    let spec = crate::spec::build_device_spec(&cfg, &id);

    #[cfg(target_os = "linux")]
    let backend = hextet_wg::kernel::KernelBackend;
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("M1 仅支持 Linux（macOS 在 M4）");

    #[cfg(target_os = "linux")]
    {
        backend.apply(&spec).context("配置 WireGuard 设备（需要 root/CAP_NET_ADMIN）")?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(hextet_platform::setup_interface(
            &cfg.node.interface,
            own.address,
            NetworkPrefix::PREFIX_LEN,
            cfg.node.mtu,
        ))
        .context("配置接口地址/MTU")?;
        println!("up: {} {} ({} peers)", cfg.node.interface, own.address, cfg.peers.len());
        Ok(())
    }
}
```

（`super::load_config_and_identity`：放 `commands/mod.rs` 的公共函数——读配置→解析 key_file 相对路径→载身份→带 own_pubkey 重载配置，返回 `(Config, NodeIdentity)`；inspect 改为复用它。）

`commands/down.rs`:

```rust
//! `hextet down`：删除接口。

use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(hextet_platform::delete_interface(&cfg.node.interface))?;
    println!("down: {}", cfg.node.interface);
    Ok(())
}
```

`commands/status.rs`:

```rust
//! `hextet status`：peer 连接状态。

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use hextet_wg::WgBackend as _;

#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// JSON 输出
    #[arg(long)]
    pub json: bool,
}

/// 按最近握手时间归类连接状态（<180s = connected）。
pub fn classify(last_handshake: Option<SystemTime>, now: SystemTime) -> &'static str {
    match last_handshake {
        Some(t) => match now.duration_since(t) {
            Ok(d) if d < Duration::from_secs(180) => "connected",
            _ => "stale",
        },
        None => "no-handshake",
    }
}

#[derive(serde::Serialize)]
struct StatusRow {
    peer: String,
    address: String,
    endpoint: Option<String>,
    last_handshake_secs: Option<u64>,
    rx_bytes: u64,
    tx_bytes: u64,
    state: &'static str,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;

    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("M1 仅支持 Linux");

    #[cfg(target_os = "linux")]
    {
        let backend = hextet_wg::kernel::KernelBackend;
        let statuses = backend.status(&cfg.node.interface)?;
        let now = SystemTime::now();
        let rows: Vec<StatusRow> = statuses
            .iter()
            .map(|s| {
                let peer = cfg
                    .peers
                    .iter()
                    .find(|p| p.public_key.wg_public_bytes() == s.wg_public);
                StatusRow {
                    peer: peer.map_or("<unknown>".into(), |p| p.name.clone()),
                    address: peer.map_or(String::new(), |p| p.addr.address.to_string()),
                    endpoint: s.endpoint.map(|e| e.to_string()),
                    last_handshake_secs: s
                        .last_handshake
                        .and_then(|t| now.duration_since(t).ok())
                        .map(|d| d.as_secs()),
                    rx_bytes: s.rx_bytes,
                    tx_bytes: s.tx_bytes,
                    state: classify(s.last_handshake, now),
                }
            })
            .collect();
        if args.json {
            println!("{}", serde_json::to_string_pretty(&rows)?);
        } else {
            println!("{:<12} {:<28} {:<32} {:>10} {:>8} {:>8}  state",
                     "peer", "address", "endpoint", "handshake", "rx", "tx");
            for r in &rows {
                println!("{:<12} {:<28} {:<32} {:>10} {:>8} {:>8}  {}",
                    r.peer, r.address, r.endpoint.clone().unwrap_or_default(),
                    r.last_handshake_secs.map_or("-".into(), |s| format!("{s}s")),
                    r.rx_bytes, r.tx_bytes, r.state);
            }
        }
        Ok(())
    }
}
```

`main.rs` 增加 `Up/Down/Status` 三个子命令分发；`cli/Cargo.toml` 依赖加 `hextet-wg.workspace = true`、`hextet-platform.workspace = true`、`tokio.workspace = true`（workspace.dependencies 里补登 `hextet-wg`/`hextet-platform` path 条目）。

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-cli && cargo xtask ci`
Expected: 全绿（up/down/status 的真实路径在 Task 9 e2e 验证）

- [ ] **Step 5: 提交**

```bash
git add crates/cli Cargo.toml CHANGELOG.md
git commit -m "feat(cli): up/down/status（内核 WG + 地址配置组装）

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: netns E2E + CI e2e job + quickstart（M1 验收）

**Files:**
- Create: `scripts/netns-e2e.sh`
- Modify: `.github/workflows/ci.yml`（加 e2e job）、`docs/dev/build.md`（e2e 用法）
- Create: `docs/guides/quickstart.md`
- Modify: `README.md`、`CHANGELOG.md`

**Interfaces:**
- Consumes: `hextet` 二进制全部命令（Task 5/8）、`inspect --json` 的字段（Task 5）
- Produces: `cargo xtask e2e`（root）一键验证 M1 验收标准

- [ ] **Step 1: 写 E2E 脚本（先写脚本=先写测试，此时跑必然失败即 TDD 红灯）**

`scripts/netns-e2e.sh`:

```bash
#!/usr/bin/env bash
# hextet M1 E2E：两个 netns 经 veth 模拟公网 IPv6，静态配置直连互 ping。
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

NS_A=hxt-a
NS_B=hxt-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)

cleanup() {
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

# 1) 拓扑：ns-a <-veth-> ns-b，2001:db8::/64 当"公网"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns "$NS_A"; ip link set veth-b netns "$NS_B"
ip -n "$NS_A" addr add 2001:db8::a/64 dev veth-a
ip -n "$NS_B" addr add 2001:db8::b/64 dev veth-b
for ns in "$NS_A" "$NS_B"; do
  ip -n "$ns" link set lo up
done
ip -n "$NS_A" link set veth-a up; ip -n "$NS_B" link set veth-b up

# 2) 身份与配置
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e --key-file "$TMP/a.key" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e --key-file "$TMP/b.key" --network-key "$NETKEY" --out "$TMP/b.toml"

cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "b"
public_key = "$PK_B"
endpoints = ["[2001:db8::b]:4193"]
EOF

cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
endpoints = ["[2001:db8::a]:4193"]
EOF

ADDR_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
ADDR_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$ADDR_A b=$ADDR_B"

# 3) 拉起
ip netns exec "$NS_A" "$BIN" up -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" up -c "$TMP/b.toml"

# 4) 验收：互 ping overlay 地址
ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B"
ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A"

# 5) status 显示 connected
ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a.toml" | jq -e '.[0].state == "connected"'

# 6) down 清理干净
ip netns exec "$NS_A" "$BIN" down -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" down -c "$TMP/b.toml"
! ip -n "$NS_A" link show hextet0 2>/dev/null

echo "E2E OK"
```

`chmod +x scripts/netns-e2e.sh`

- [ ] **Step 2: 本地（Linux）或 CI 跑通**

Run（Linux）: `cargo xtask e2e`
Expected: 首轮大概率暴露实现问题（wireguard-control API 差异、接口创建时序、路由等），修复直至输出 `E2E OK`。
macOS 开发机：跳过本地，直接推 CI 观察（下一步）。

- [ ] **Step 3: CI 加 e2e job**

`.github/workflows/ci.yml` 追加：

```yaml
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --workspace
      - run: sudo modprobe wireguard || true
      - run: sudo -E env HEXTET_BIN=target/debug/hextet scripts/netns-e2e.sh
```

- [ ] **Step 4: 写 quickstart 文档**

`docs/guides/quickstart.md`：面向两台有公网 IPv6 的 Linux 真机——keygen/init（B 用 `--network-key` 加入）/互填 `[[peers]]`（endpoint 为对方 GUA:4193）/两侧 `sudo hextet up`/`ping -6 <对方 overlay 地址>`/`hextet status`；「前提」节写明：双方防火墙需放行 UDP 4193 入站或等待 M2 打洞（引用设计 spec §2 诚实边界，附中国光猫 IPv6 SPI 说明一句 + 指向后续 doctor）；「排查」节列：无 IPv6（`ip -6 addr`）、防火墙丢包（`tcpdump udp port 4193`）、内核无 wireguard 模块。

- [ ] **Step 5: M1 验收核对并提交**

核对（对照设计 spec §8 M1 验收行）：
- [ ] netns E2E 绿：两节点互 ping overlay 地址 ✓（CI e2e job）
- [ ] `status` 正确显示 connected/endpoint/握手 ✓
- [ ] 真机验收（两台公网 IPv6 Linux）按 quickstart 手动执行一次，结果记入 `docs/dev/e2e-matrix.md`（新建，表格：日期/场景/结果）

```bash
git add scripts .github docs README.md CHANGELOG.md
git commit -m "test(e2e): netns 双节点直连 E2E + CI job + quickstart（M1 验收）

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## 计划自审记录

1. **Spec 覆盖**（M0/M1 范围）：M0 四项交付（workspace/CI/core/keygen+init）→ Task 1-5；M1 四项交付（内核 WG 后端/静态 peer/up-down-status/验收）→ Task 6-9。设计 spec 中 M2+ 内容（打洞、roaming、DHT、daemon/engine crate、doctor）明确不在本计划。engine crate 未提前创建（YAGNI，M2 引入时 core 已是纯逻辑、天然可嵌入，满足"FFI-ready"约束）。
2. **占位符扫描**：Task 3 的 `<FROZEN>` 是显式的"运行一次后钉扎"流程（Step 4 有操作指引），非未完成占位。无其他 TBD/TODO。
3. **类型一致性**：`NodePublicKey::wg_public_bytes` / `NodeIdentity::wg_secret_bytes`（Task 2 定义，Task 6/8 消费）；`NodeAddr{subnet_id, site, address}`（Task 3 定义，Task 4/5/8 消费）；`DeviceSpec/PeerSpec/PeerStatus`（Task 6 定义，Task 8 消费）；`Config::load(path, own_pubkey)` 双参签名在 Task 4/5/8 一致；`inspect --json` 字段与 Task 9 脚本的 jq 路径（`.node.address`）一致。
4. **已知风险点已内嵌**：wireguard-control / rtnetlink 的 API 细节差异（Global Constraints 最后一条授权按 docs.rs 适配）；macOS 开发机无法本地跑 kernel/e2e（cfg 隔离 + CI 覆盖）。
