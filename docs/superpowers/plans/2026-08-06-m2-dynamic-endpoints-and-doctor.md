# hextet M2（动态端点 + doctor）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 hextet 从「静态直连」升级为「地址会变也能自己恢复的直连」：新增常驻守护进程 `hextet daemon`，监听本机 IPv6 地址变化、轮换候选 endpoint 打洞、持久化端点缓存，并提供 `hextet doctor` 把本机入站可达性正确分类为 open / stateful / blocked。

**Architecture:** 新增一个 crate `hextet-engine`（可嵌入引擎：纯逻辑的打洞状态机 + 端点缓存 + 状态快照 + tokio 主循环），守护进程作为 `hextet daemon` 子命令跑在同一个二进制里。运行时状态经原子写的 JSON 状态文件暴露给 `hextet status`（M2 不引入 IPC）。`hextet doctor` 用一个 32 字节、network key 派生密钥做 HMAC 的 UDP 探针协议，让**对端节点**回探本机，从而在没有任何项目方服务器的前提下判定入站策略。

**Tech Stack:** Rust edition 2024 · tokio 1（rt-multi-thread/macros/net/time/sync/signal）· rtnetlink 0.21（`new_multicast_connection` + `MulticastGroup::Ipv6Ifaddr` 监听地址变化）· wireguard-control 2（不带 `replace_peers` 的增量 peer 更新）· hmac 0.12 + sha2 0.10（探针 MAC）· hkdf 0.12（探针密钥派生）· tracing 0.1 + tracing-subscriber 0.3（daemon 日志）· serde_json（缓存/状态文件）· nftables（netns E2E 里模拟状态防火墙）

**设计依据:** `docs/superpowers/specs/2026-08-06-hextet-design.md`（已批准 v2）§8 M2 行、§5 协议要点、§3 D3；`docs/research/2026-08-06-ipv6-p2p-feasibility.md` §1（打洞成立机制）、§2（动态前缀响应 <5s）。

**前序计划:** `docs/superpowers/plans/2026-08-06-m0-m1-skeleton-and-static-direct.md`（M0/M1 已完成并合入 main）。

---

## Global Constraints

以下约束对**每一个** Task 都生效，实现时无需再被提醒：

- **IPv6-only**：一切地址输入用 `Ipv6Addr` / `SocketAddrV6` 类型强制；解析到 IPv4 一律报错或跳过（探针响应器收到 IPv4 源地址直接忽略）。
- **默认值**（`hextet-core::defaults`）：UDP 端口 **4193**、MTU **1400**、接口名 **hextet0**、探针端口 **4194**、状态目录 **/var/lib/hextet**。
- **密码学**：不自研任何密码学。探针 MAC = HMAC-SHA256 截断 16 字节；探针密钥 = `HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("doctor-probe", 32)`。所有域分隔串以 `hextet-v1` 开头。
- **工程规范**：edition 2024、workspace resolver "3"、双许可 MIT OR Apache-2.0；新 crate `crates/engine` 顶部写 `#![deny(missing_docs)]`（与已有 core/wg/platform 一致）；`unsafe_code = "deny"`（workspace lint）；clippy `-D warnings`。
- **文档同步**：每个 Task 的提交必须包含它自己那部分文档更新（至少 `CHANGELOG.md` 一行；协议相关任务同步 `docs/protocol/`）。
- **TDD**：每个 Task 先写失败测试、跑一次确认失败、再写实现、再跑通、最后提交。提交遵循 conventional commits（`feat:`/`fix:`/`test:`/`docs:`/`chore:`/`ci:`），commit message 末尾加一行：
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  ```
- **不要打印私钥**：任何新增的 `Debug`/日志都不得输出 `wg_secret`、node seed、network key、probe key。`DeviceSpec` 已手写 `Debug` 屏蔽私钥，新增结构照此办理。
- **每个 Task 结束前必须跑** `cargo xtask ci`，并把输出贴进完成报告；不绿不算完成。

### 给执行者的硬规则（不可协商）

1. **只改本 Task「Files」里列出的文件。** 需要改别的文件才能通过编译时，先在完成报告里说明，不要静默扩大改动范围。
2. **不要删除或跳过任何已有测试。** `#[ignore]`、`test.skip`、注释掉断言、把断言改成恒真（如 `assert!(true)`）一律视为未完成。
3. **不要留占位实现。** 没有 `todo!()`、`unimplemented!()`、`// TODO`、空函数体、返回假数据的桩。本计划每一步都给了完整代码，照抄即可。
4. **第三方 API 以本计划给的代码为准起步**（已对照本机 `~/.cargo/registry` 里锁定的 rtnetlink 0.21.0 / netlink-packet-route 0.30.0 / wireguard-control 2.0.0 源码核实过）。若编译报错与计划不符，以 docs.rs 当前版本为准调整，并在 commit message 里写明改了什么、为什么。
5. **报告要如实。** 测试没跑就说没跑；跑失败就贴失败输出。不许把"应该能过"写成"已通过"。
6. **E2E 脚本只在 Linux 上能跑。** 在 macOS 开发机上跳过 E2E 步骤，改为推 CI 观察结果，并在报告里写明"E2E 未本地验证，依赖 CI job X"。

---

## 文件结构

### 新建

| 文件 | 责任 |
|---|---|
| `crates/engine/Cargo.toml` | 新 crate `hextet-engine` 清单 |
| `crates/engine/src/lib.rs` | crate 根，声明各模块与平台 cfg |
| `crates/engine/src/spec.rs` | 从 `hextet-cli` 迁入的 `build_device_spec`（配置 → `DeviceSpec` 纯映射） |
| `crates/engine/src/candidates.rs` | 候选 endpoint 组装 + `normalize`（纯逻辑） |
| `crates/engine/src/fsm.rs` | 每 peer 的打洞/连接状态机（纯逻辑，M2 最核心的可测单元） |
| `crates/engine/src/cache.rs` | 端点缓存 `endpoints.json`（持久化软状态，原子写） |
| `crates/engine/src/state.rs` | 运行时状态快照 `state.json`（原子写，供 `hextet status` 读） |
| `crates/engine/src/daemon.rs` | tokio 主循环：接线 wg 后端 / 地址监听 / FSM / 缓存 / 状态文件 / 信号（Linux） |
| `crates/engine/src/probe_responder.rs` | 探针响应器（回复 solicited + 发 unsolicited，含限速） |
| `crates/engine/src/doctor_client.rs` | 探针客户端：双 socket 收集证据 |
| `crates/core/src/probe.rs` | 探针报文编解码（纯逻辑，含 HMAC 校验） |
| `crates/core/src/doctor.rs` | 可达性分类（纯函数） |
| `crates/cli/src/commands/daemon.rs` | `hextet daemon` 子命令 |
| `crates/cli/src/commands/doctor.rs` | `hextet doctor` / `hextet doctor --serve` 子命令 |
| `scripts/netns-e2e-dynamic.sh` | Phase A 验收：daemon + 换前缀 <5s 恢复 + 仅靠缓存重连 |
| `scripts/netns-e2e-doctor.sh` | Phase B 验收：双侧状态防火墙下打洞互连 + doctor 三分类 |
| `docs/protocol/punching.md` | 打洞/候选轮换/roaming/地址变化响应的协议规范 |
| `docs/protocol/doctor-probe.md` | 探针协议线格式与安全性说明 |
| `docs/dev/state-files.md` | `endpoints.json` / `state.json` 格式与位置 |
| `docs/guides/doctor.md` | 用户向 doctor 指引（三种分类含义 + 中国光猫 IPv6 SPI 关闭教程） |
| `docs/adr/ADR-0001-m2-daemon-shape.md` | 记录 M2 偏离 spec §10 的三项决策 |

### 修改

| 文件 | 改什么 |
|---|---|
| `Cargo.toml`（根） | members 加 `crates/engine`；workspace.dependencies 加 `hextet-engine`/`hmac`/`tracing`/`tracing-subscriber`；tokio features 补 `net`/`time`/`sync`/`signal` |
| `crates/core/src/defaults.rs` | 加 `DEFAULT_PROBE_PORT`、`DEFAULT_STATE_DIR` |
| `crates/core/src/config.rs` | `NodeSettings` 加 `probe_port`/`state_dir`；`render_template` 加 `state_dir` 参数；新增 `load_config_and_identity` |
| `crates/core/src/error.rs` | `ConfigError` 加 `Identity` 变体；新增 `ProbeError` |
| `crates/core/src/lib.rs` | 声明 `probe`、`doctor` 模块 |
| `crates/core/src/network.rs` | 加 `derive_probe_key` |
| `crates/core/Cargo.toml` | 加 `hmac` |
| `crates/wg/src/lib.rs` | `WgBackend` trait 加 `set_peer_endpoint` |
| `crates/wg/src/kernel.rs` | 实现 `set_peer_endpoint`（增量更新，不带 `replace_peers`） |
| `crates/wg/src/mock.rs` | Mock 记录 endpoint 更新 |
| `crates/platform/Cargo.toml` | tokio 从 Linux-only 提到无条件依赖 |
| `crates/platform/src/lib.rs` | 新增 `AddrEvent`/`AddrEventKind`；导出 `list_global_ipv6`/`watch_ipv6_addresses`（含非 Linux 桩） |
| `crates/platform/src/linux.rs` | 实现地址枚举与 netlink 地址变化监听 |
| `crates/cli/Cargo.toml` | 加 `hextet-engine`/`tracing`/`tracing-subscriber` |
| `crates/cli/src/lib.rs` | 删掉 `pub mod spec`（迁到 engine） |
| `crates/cli/src/spec.rs` | **删除**（内容迁到 `crates/engine/src/spec.rs`） |
| `crates/cli/src/commands/mod.rs` | `load_config_and_identity` 改为委托 core |
| `crates/cli/src/commands/up.rs` | 引用 `hextet_engine::spec::build_device_spec` |
| `crates/cli/src/commands/init.rs` | 加 `--state-dir` |
| `crates/cli/src/commands/status.rs` | 重写：合并内核状态 + daemon 状态文件，`--json` 改为对象 |
| `crates/cli/src/main.rs` | 注册 `daemon`/`doctor` 子命令 |
| `crates/cli/tests/spec.rs` | `build_device_spec` 引用路径改到 engine |
| `scripts/netns-e2e.sh` | `--json` 形状变更 → jq 路径 `.[0]` 改 `.peers[0]` |
| `xtask/src/main.rs` | `e2e` 支持场景参数（static/dynamic/doctor/all） |
| `.github/workflows/ci.yml` | 新增 `e2e-dynamic`、`e2e-doctor` 两个 job |
| `docs/dev/build.md`、`docs/guides/quickstart.md`、`docs/dev/e2e-matrix.md`、`README.md`、`CHANGELOG.md` | 同步 |

### 为什么这样切

- **纯逻辑与 I/O 分离**：`fsm.rs`/`candidates.rs`/`cache.rs`/`state.rs`/`core::probe`/`core::doctor` 全部不碰网络与 root，可在 macOS 开发机上用 `cargo test` 完整覆盖；`daemon.rs` 只做接线，由 netns E2E 覆盖。这是 M2 唯一能兼顾「可测」与「必须真跑网络」的切法。
- **一个新 crate 而不是三个**：spec §10 规划了 `engine`/`daemon`/`proto` 三个 crate，但 M2 既没有 axum 也不做 IPC，`daemon`/`proto` 此刻是空壳。按 YAGNI 只建 `engine`，`daemon`/`proto` 留到 M5（UI 落地时）。这条偏离写进 ADR-0001（Task 15）。
- **`build_device_spec` 从 cli 迁到 engine**：daemon 与 `hextet up` 都要用它，放在 cli 里会让 engine 反向依赖 cli。

---

## 阶段划分

| 阶段 | Tasks | 交付 | 独立验收标准 |
|---|---|---|---|
| **A 动态端点自愈** | 1–10 | `hextet daemon`、netlink 地址监听、候选轮换打洞、端点缓存、`status` 合并 daemon 状态 | netns：一侧换前缀后 <5s 内对端 endpoint 跟随更新且 ping 通；删掉配置里的 endpoint 后仅靠缓存重连成功 |
| **B doctor** | 11–15 | 探针协议、响应器、`hextet doctor` | netns + nftables：双侧状态防火墙下两节点仍能打洞互连；doctor 在 open/stateful/blocked 三种规则下分类全对 |

阶段 A 结束时代码是可发布状态（M2 一半功能可用，无半成品裸露）。阶段 B 不改动 A 的任何行为。

---

# 阶段 A：动态端点自愈

### Task 1: core — 状态目录/探针端口配置 + 配置加载上移

**Files:**
- Modify: `Cargo.toml`（根，workspace.dependencies 的 tokio features）
- Modify: `crates/core/src/defaults.rs`
- Modify: `crates/core/src/config.rs`
- Modify: `crates/core/src/error.rs`
- Modify: `crates/cli/src/commands/mod.rs`
- Modify: `crates/cli/src/commands/init.rs`

**Interfaces:**
- Consumes: 已有 `Config`/`NodeIdentity`/`NodeSettings`
- Produces:
  - `hextet_core::defaults::DEFAULT_PROBE_PORT: u16 = 4194`
  - `hextet_core::defaults::DEFAULT_STATE_DIR: &str = "/var/lib/hextet"`
  - `NodeSettings` 新增两个字段：`pub probe_port: u16`、`pub state_dir: PathBuf`
  - `Config::render_template(name: &str, network_key: &NetworkKey, key_file: &Path, listen_port: u16, state_dir: Option<&Path>) -> String`（**签名变了**，多一个末尾参数）
  - `hextet_core::config::load_config_and_identity(config_path: &Path) -> Result<(Config, NodeIdentity), ConfigError>`
  - `ConfigError::Identity { path: PathBuf, source: IdentityError }`
  - `hextet init --state-dir <PATH>`（可选；给出时写进配置的 `[node]`）
- 配置文件新增字段（都可选，缺省走 defaults）：
  ```toml
  [node]
  key_file = "node.key"
  listen_port = 4193
  # probe_port = 4194     # hextet doctor 的探针端口
  # state_dir = "/var/lib/hextet"   # daemon 的端点缓存与状态文件目录
  ```

- [ ] **Step 1: 写失败测试**

在 `crates/core/src/config.rs` 底部的 `mod tests` 里**追加**（不要动已有测试）：

```rust
    #[test]
    fn new_fields_default_and_parse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        let (toml_text, _) = sample_toml();
        std::fs::write(&path, &toml_text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        // 缺省值
        assert_eq!(cfg.node.probe_port, crate::defaults::DEFAULT_PROBE_PORT);
        assert_eq!(
            cfg.node.state_dir,
            std::path::PathBuf::from(crate::defaults::DEFAULT_STATE_DIR)
        );

        // 显式值
        let explicit = toml_text.replace(
            "key_file = \"node.key\"",
            "key_file = \"node.key\"\nprobe_port = 5000\nstate_dir = \"/tmp/hxt-state\"",
        );
        std::fs::write(&path, explicit).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(cfg.node.probe_port, 5000);
        assert_eq!(cfg.node.state_dir, std::path::PathBuf::from("/tmp/hxt-state"));
    }

    #[test]
    fn template_with_state_dir_roundtrips() {
        let nk = crate::network::NetworkKey::generate();
        let text = Config::render_template(
            "home",
            &nk,
            std::path::Path::new("node.key"),
            4193,
            Some(std::path::Path::new("/var/lib/hextet-test")),
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();
        let cfg = Config::load(&path, None).unwrap();
        assert_eq!(
            cfg.node.state_dir,
            std::path::PathBuf::from("/var/lib/hextet-test")
        );
    }

    #[test]
    fn load_config_and_identity_reads_relative_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let id = crate::identity::NodeIdentity::generate();
        id.save(&dir.path().join("node.key")).unwrap();
        let nk = crate::network::NetworkKey::generate();
        let text = Config::render_template(
            "home",
            &nk,
            std::path::Path::new("node.key"),
            4193,
            None,
        );
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();

        let (cfg, loaded) = load_config_and_identity(&path).unwrap();
        assert_eq!(cfg.network_name, "home");
        assert_eq!(loaded.public(), id.public());
    }

    #[test]
    fn load_config_and_identity_reports_missing_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let nk = crate::network::NetworkKey::generate();
        let text = Config::render_template(
            "home",
            &nk,
            std::path::Path::new("does-not-exist.key"),
            4193,
            None,
        );
        let path = dir.path().join("hextet.toml");
        std::fs::write(&path, text).unwrap();

        let err = load_config_and_identity(&path).unwrap_err();
        assert!(matches!(err, ConfigError::Identity { .. }), "got {err:?}");
    }
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-core config`
Expected: 编译失败，报 `no field probe_port on type NodeSettings`、`this function takes 4 arguments but 5 arguments were supplied`、`cannot find function load_config_and_identity`。

- [ ] **Step 3: 实现**

`crates/core/src/defaults.rs` **追加**（保留已有三个常量与已有测试）：

```rust
/// 默认 doctor 探针 UDP 端口（4193 + 1；内核 WireGuard 独占 4193，探针必须换端口）。
pub const DEFAULT_PROBE_PORT: u16 = 4194;
/// 默认状态目录：daemon 在此存放端点缓存与运行时状态文件。
pub const DEFAULT_STATE_DIR: &str = "/var/lib/hextet";
```

并在 `defaults.rs` 的 `mod tests` 里 `defaults_are_stable` 末尾追加两行断言：

```rust
        assert_eq!(DEFAULT_PROBE_PORT, 4194);
        assert_eq!(DEFAULT_STATE_DIR, "/var/lib/hextet");
```

`crates/core/src/error.rs`：在 `ConfigError` 枚举里**追加**一个变体（放在 `BadNetworkKey` 之后）：

```rust
    /// `key_file` 指向的身份文件不可读或格式非法。
    #[error("identity {path}: {source}")]
    Identity {
        /// 身份文件路径。
        path: std::path::PathBuf,
        /// 底层身份错误。
        #[source]
        source: crate::error::IdentityError,
    },
```

`crates/core/src/config.rs` 的四处改动：

1. `RawNode` 加两个可选字段：

```rust
#[derive(Deserialize)]
struct RawNode {
    key_file: PathBuf,
    listen_port: Option<u16>,
    mtu: Option<u32>,
    interface: Option<String>,
    probe_port: Option<u16>,
    state_dir: Option<PathBuf>,
}
```

2. `NodeSettings` 加两个字段：

```rust
/// 节点本地设置。
#[derive(Debug, Clone)]
pub struct NodeSettings {
    /// 节点密钥文件路径。
    pub key_file: PathBuf,
    /// WireGuard UDP 监听端口。
    pub listen_port: u16,
    /// 隧道 MTU。
    pub mtu: u32,
    /// 虚拟网络接口名。
    pub interface: String,
    /// doctor 探针 UDP 端口。
    pub probe_port: u16,
    /// daemon 的端点缓存与状态文件目录。
    pub state_dir: PathBuf,
}
```

3. `Config::load` 里构造 `NodeSettings` 的那段，补上两个字段（其余不动）：

```rust
            node: NodeSettings {
                key_file: raw.node.key_file,
                listen_port: raw.node.listen_port.unwrap_or(defaults::DEFAULT_PORT),
                mtu: raw.node.mtu.unwrap_or(defaults::DEFAULT_MTU),
                interface: raw
                    .node
                    .interface
                    .unwrap_or_else(|| defaults::DEFAULT_INTERFACE.into()),
                probe_port: raw.node.probe_port.unwrap_or(defaults::DEFAULT_PROBE_PORT),
                state_dir: raw
                    .node
                    .state_dir
                    .unwrap_or_else(|| PathBuf::from(defaults::DEFAULT_STATE_DIR)),
            },
```

4. `render_template` 整体替换为（多了 `state_dir` 参数，并把它写进 `[node]`）：

```rust
    /// 生成 `hextet init` 的配置模板。
    ///
    /// `state_dir` 为 `Some` 时写成生效的配置项，为 `None` 时只留一行注释示例
    /// （运行时走 `defaults::DEFAULT_STATE_DIR`）。
    pub fn render_template(
        name: &str,
        network_key: &NetworkKey,
        key_file: &Path,
        listen_port: u16,
        state_dir: Option<&Path>,
    ) -> String {
        let state_dir_line = match state_dir {
            Some(dir) => format!("state_dir = \"{}\"", dir.display()),
            None => format!("# state_dir = \"{}\"", defaults::DEFAULT_STATE_DIR),
        };
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
# probe_port = {probe_port}
{state_dir_line}

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
            probe_port = defaults::DEFAULT_PROBE_PORT,
            state_dir_line = state_dir_line,
        )
    }
```

5. 在 `impl Config { ... }` **之后**（文件里 `mod tests` 之前）新增自由函数：

```rust
/// 读配置 → 解析 `key_file` 相对路径 → 载身份 → 带 own_pubkey 重载配置。
///
/// 配置里的 subnet id 碰撞检测需要先知道本节点公钥，而公钥又要从 `key_file`
/// 指向的身份文件读出——因此第一次加载不带 `own_pubkey`，仅用来拿到 `key_file`
/// 路径，载入身份后再重新加载一次配置。
///
/// `key_file` 是相对路径时，基准目录是**配置文件所在目录**（不是进程 cwd），
/// 这样 `hextet -c /etc/hextet/home.toml` 能找到 `/etc/hextet/node.key`。
pub fn load_config_and_identity(
    config_path: &Path,
) -> Result<(Config, crate::identity::NodeIdentity), ConfigError> {
    let cfg = Config::load(config_path, None)?;
    let key_path = if cfg.node.key_file.is_relative() {
        config_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(&cfg.node.key_file)
    } else {
        cfg.node.key_file.clone()
    };
    let id = crate::identity::NodeIdentity::load(&key_path).map_err(|source| {
        ConfigError::Identity {
            path: key_path.clone(),
            source,
        }
    })?;
    let cfg = Config::load(config_path, Some(&id.public()))?;
    Ok((cfg, id))
}
```

`crates/cli/src/commands/mod.rs` 整体替换为（把实现委托给 core，保留原函数名以免改动 up/down/status/inspect 的调用点）：

```rust
//! CLI command implementations

use std::path::Path;

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;

pub mod down;
pub mod init;
pub mod inspect;
pub mod keygen;
pub mod status;
pub mod up;

/// 读配置 + 载身份（实现见 [`hextet_core::config::load_config_and_identity`]）。
///
/// M2 起 daemon 也要做同样的事，逻辑因此上移到 core；这里保留薄封装，
/// 让既有子命令的调用点不必改动。
pub fn load_config_and_identity(config_path: &Path) -> anyhow::Result<(Config, NodeIdentity)> {
    Ok(hextet_core::config::load_config_and_identity(config_path)?)
}
```

`crates/cli/src/commands/init.rs`：`Args` 追加一个字段，`run` 里传给 `render_template`：

```rust
    /// daemon 的状态目录（端点缓存与运行时状态文件）；缺省用 /var/lib/hextet
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
```

```rust
    let text = Config::render_template(
        &args.name,
        &key,
        &args.key_file,
        args.listen_port,
        args.state_dir.as_deref(),
    );
```

根 `Cargo.toml`：把 tokio 那一行替换为（多四个 feature，daemon 与探针都要用）：

```toml
tokio = { version = "1", features = [
  "rt-multi-thread",
  "macros",
  "net",
  "time",
  "sync",
  "signal",
] }
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-core && cargo test -p hextet-cli`
Expected: 全部 PASS（core 新增 4 个测试；cli 的 3 个既有测试仍绿）

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

`CHANGELOG.md` 的 `### Added` 追加一行：

```markdown
- 配置新增 `[node] probe_port`（默认 4194）与 `[node] state_dir`（默认 /var/lib/hextet）；`hextet init --state-dir`；配置+身份加载逻辑上移到 `hextet_core::config::load_config_and_identity`。
```

```bash
git add Cargo.toml crates/core crates/cli CHANGELOG.md
git commit -m "feat(core): 状态目录与探针端口配置项，配置加载上移到 core

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: wg — 单 peer endpoint 增量更新

**Files:**
- Modify: `crates/wg/src/lib.rs`
- Modify: `crates/wg/src/kernel.rs`
- Modify: `crates/wg/src/mock.rs`

**Interfaces:**
- Consumes: 已有 `WgError`、`key_from_bytes`、`iface`
- Produces:
  - `WgBackend` trait 新方法：
    ```rust
    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: SocketAddrV6,
    ) -> Result<(), WgError>;
    ```
  - `MockBackend` 新字段：`pub endpoint_updates: Mutex<Vec<(String, [u8; 32], SocketAddrV6)>>`
- **语义约定（Task 8 依赖）**：该方法只改 endpoint，**不得**触碰 AllowedIPs、keepalive、私钥、监听端口，也不得删除其他 peer。

- [ ] **Step 1: 写失败测试**

在 `crates/wg/src/mock.rs` 的 `mod tests` 里追加：

```rust
    #[test]
    fn mock_records_endpoint_updates() {
        let mock = MockBackend::default();
        let key = [3u8; 32];
        let ep: std::net::SocketAddrV6 = "[2001:db8::9]:4193".parse().unwrap();
        mock.set_peer_endpoint("hextet0", &key, ep).unwrap();
        let recorded = mock.endpoint_updates.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, "hextet0");
        assert_eq!(recorded[0].1, key);
        assert_eq!(recorded[0].2, ep);
    }
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-wg`
Expected: 编译失败，`no method named set_peer_endpoint` / `no field endpoint_updates`。

- [ ] **Step 3: 实现**

`crates/wg/src/lib.rs`：`use` 与 trait 改为：

```rust
use std::net::SocketAddrV6;

use types::{DeviceSpec, PeerStatus, WgError};

/// WireGuard 数据面后端（kernel / 未来 userspace-gotatun）。
pub trait WgBackend {
    /// 幂等地把设备调到 spec 描述的状态（接口不存在则创建）。
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError>;
    /// 读取设备的 peer 运行时状态。
    fn status(&self, interface: &str) -> Result<Vec<PeerStatus>, WgError>;
    /// 只更新单个 peer 的 endpoint，其余配置（AllowedIPs/keepalive/密钥）保持不变。
    ///
    /// 打洞时要以 2.5s 级别轮换候选 endpoint，走整设备 `apply` 会重放全部 peer
    /// 配置（`replace_peers`），既浪费又有把并发 roaming 结果覆盖掉的风险。
    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: SocketAddrV6,
    ) -> Result<(), WgError>;
}
```

`crates/wg/src/kernel.rs`：在 `impl WgBackend for KernelBackend` 内**追加**方法（`apply`/`status` 不动）：

```rust
    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: std::net::SocketAddrV6,
    ) -> Result<(), WgError> {
        let ifname = iface(interface)?;
        // 不调用 .replace_peers()：内核 WireGuard 在没有 WGDEVICE_F_REPLACE_PEERS
        // 时对列出的 peer 做"合并更新"，未列出的 peer 与本 peer 的其他属性
        // （AllowedIPs/keepalive）都原样保留。同理不调用 .replace_allowed_ips()。
        DeviceUpdate::new()
            .add_peer(
                PeerConfigBuilder::new(&key_from_bytes(wg_public))
                    .set_endpoint(std::net::SocketAddr::V6(endpoint)),
            )
            .apply(&ifname, Backend::Kernel)
            .map_err(|e| WgError::Backend(e.to_string()))
    }
```

`crates/wg/src/mock.rs` 整体替换（保留原有测试并加新测试）：

```rust
//! 测试用 Mock 后端。

use std::net::SocketAddrV6;
use std::sync::Mutex;

use crate::WgBackend;
use crate::types::{DeviceSpec, PeerStatus, WgError};

/// 记录 apply / set_peer_endpoint 调用的 mock。
#[derive(Default)]
pub struct MockBackend {
    /// 已 apply 的 spec 序列。
    pub applied: Mutex<Vec<DeviceSpec>>,
    /// 已执行的 endpoint 更新序列：(接口名, peer WG 公钥, endpoint)。
    pub endpoint_updates: Mutex<Vec<(String, [u8; 32], SocketAddrV6)>>,
}

impl WgBackend for MockBackend {
    fn apply(&self, spec: &DeviceSpec) -> Result<(), WgError> {
        self.applied.lock().expect("mock lock").push(spec.clone());
        Ok(())
    }

    fn status(&self, _interface: &str) -> Result<Vec<PeerStatus>, WgError> {
        Ok(vec![])
    }

    fn set_peer_endpoint(
        &self,
        interface: &str,
        wg_public: &[u8; 32],
        endpoint: SocketAddrV6,
    ) -> Result<(), WgError> {
        self.endpoint_updates
            .lock()
            .expect("mock lock")
            .push((interface.to_owned(), *wg_public, endpoint));
        Ok(())
    }
}
```

（原 `mod tests` 的两个测试整段保留在文件末尾，再加上 Step 1 的新测试。）

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-wg`
Expected: PASS（macOS 上 2 个，Linux 上 3 个）

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- `WgBackend::set_peer_endpoint`：只改单个 peer 的 endpoint 的增量更新（内核后端不使用 `replace_peers`，保留 AllowedIPs 与其他 peer）。
```

```bash
git add crates/wg CHANGELOG.md
git commit -m "feat(wg): 单 peer endpoint 增量更新

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: platform — IPv6 地址枚举 + netlink 地址变化监听

**Files:**
- Modify: `crates/platform/Cargo.toml`
- Modify: `crates/platform/src/lib.rs`
- Modify: `crates/platform/src/linux.rs`

**Interfaces:**
- Consumes: 已有 `PlatformError`、`nl()`、`link_index()`、`is_missing_link()`
- Produces（全平台可见的类型 + Linux 实现 / 其他平台桩）：
  - ```rust
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AddrEventKind { Added, Removed }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AddrEvent {
        pub kind: AddrEventKind,
        pub address: std::net::Ipv6Addr,
        pub if_index: u32,
    }
    ```
  - `pub async fn list_global_ipv6(exclude_interface: Option<&str>) -> Result<Vec<Ipv6Addr>, PlatformError>`
    —— 只返回「可当公网 endpoint 用」的地址：family=Inet6、scope=Universe、非 ULA(fc00::/7)、非 loopback/multicast、未打 Deprecated/Tentative/Dadfailed 标记；结果排序去重。`exclude_interface` 用来排除 hextet 自己的接口（它上面的 overlay ULA 不是公网地址；接口不存在时视为无需排除）。
  - `pub async fn watch_ipv6_addresses(tx: tokio::sync::mpsc::Sender<AddrEvent>) -> Result<(), PlatformError>`
    —— 订阅 `RTNLGRP_IPV6_IFADDR` 组播，把每个 `RTM_NEWADDR`/`RTM_DELADDR` 转成 `AddrEvent` 推给 `tx`；`tx` 关闭时返回 `Ok(())`。**不过滤**（daemon 只需要"有变化"这个信号，过滤留给调用方；连 hextet0 自己的地址事件也照发，因为 daemon 收到后只是重新 nudge，代价可忽略）。

- [ ] **Step 1: 写失败测试**

`crates/platform/src/linux.rs` 底部的 `mod tests` **追加**（需要 root 的标 `#[ignore]`，由 netns E2E 真实覆盖；另加一个不需要 root 的纯逻辑测试）：

```rust
    /// 不需要 root：ULA 判定是 `list_global_ipv6` 过滤逻辑的核心，单独测。
    #[test]
    fn ula_detection() {
        assert!(super::is_ula(&"fd00::1".parse().unwrap()));
        assert!(super::is_ula(&"fc00::1".parse().unwrap()));
        assert!(super::is_ula(&"fdff:ffff::1".parse().unwrap()));
        assert!(!super::is_ula(&"2001:db8::1".parse().unwrap()));
        assert!(!super::is_ula(&"fe80::1".parse().unwrap()));
        assert!(!super::is_ula(&"::1".parse().unwrap()));
    }

    /// 需要 Linux（不需要 root）：本机至少有 lo 的 ::1，但它必须被过滤掉，
    /// 所以这里只断言"调用不报错"，具体内容因机器而异。
    #[tokio::test]
    async fn list_global_ipv6_does_not_error() {
        let addrs = super::list_global_ipv6(None).await.unwrap();
        for a in &addrs {
            assert!(!a.is_loopback(), "loopback 未被过滤: {a}");
            assert!(!super::is_ula(a), "ULA 未被过滤: {a}");
        }
    }

    /// 需要 root + Linux：`sudo -E cargo test -p hextet-platform -- --ignored`
    /// 加地址 → 监听器应在 2s 内收到一个 Added 事件。
    #[tokio::test]
    #[ignore = "requires root"]
    async fn watch_reports_added_address() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move { super::watch_ipv6_addresses(tx).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let status = std::process::Command::new("ip")
            .args(["-6", "addr", "add", "fd00:dead:beef::1/64", "dev", "lo"])
            .status()
            .expect("run ip");
        assert!(status.success(), "ip addr add 失败（需要 root）");

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("2s 内应收到地址事件")
            .expect("channel 未关闭");
        assert_eq!(event.kind, crate::AddrEventKind::Added);

        let _ = std::process::Command::new("ip")
            .args(["-6", "addr", "del", "fd00:dead:beef::1/64", "dev", "lo"])
            .status();
    }
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-platform`
Expected（macOS）：编译失败——`linux.rs` 不参与编译，但 `lib.rs` 里缺 `AddrEvent`/`AddrEventKind`；先按 Step 3 加完 `lib.rs` 再看。
Expected（Linux）：编译失败，`cannot find function is_ula` / `list_global_ipv6` / `watch_ipv6_addresses`。

- [ ] **Step 3: 实现**

`crates/platform/Cargo.toml` 整体替换：

```toml
[package]
name = "hextet-platform"
description = "hextet platform integration: interface address, MTU, lifecycle"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[lints]
workspace = true

[dependencies]
thiserror.workspace = true
# tokio 从 Linux-only 提到无条件依赖：`watch_ipv6_addresses` 的公开签名里有
# `tokio::sync::mpsc::Sender`，非 Linux 的桩函数也要能写出这个类型。
tokio.workspace = true

[target.'cfg(target_os = "linux")'.dependencies]
rtnetlink.workspace = true
futures.workspace = true
libc.workspace = true

[dev-dependencies]
tokio.workspace = true
```

`crates/platform/src/lib.rs` 整体替换：

```rust
//! 平台集成：接口地址、MTU、生命周期、本机地址枚举与变化监听（M2 仅 Linux）。
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

/// 本机地址变化的方向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrEventKind {
    /// 新增地址（`RTM_NEWADDR`）。
    Added,
    /// 删除地址（`RTM_DELADDR`）。
    Removed,
}

/// 一次本机 IPv6 地址变化事件。
///
/// 中国家宽 PPPoE 重拨换前缀时，内核会连续发出多条 `RTM_NEWADDR`/`RTM_DELADDR`
/// （含 valid-lifetime=0 的静默换前缀），调用方需要自行去抖。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrEvent {
    /// 新增还是删除。
    pub kind: AddrEventKind,
    /// 变化的 IPv6 地址。
    pub address: std::net::Ipv6Addr,
    /// 该地址所属接口的 netlink index。
    pub if_index: u32,
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{
    delete_interface, list_global_ipv6, setup_interface, watch_ipv6_addresses,
};

#[cfg(not(target_os = "linux"))]
mod stub {
    use super::{AddrEvent, PlatformError};
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

    /// 非 Linux 平台暂不支持。
    pub async fn list_global_ipv6(
        _exclude_interface: Option<&str>,
    ) -> Result<Vec<Ipv6Addr>, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    /// 非 Linux 平台暂不支持。
    pub async fn watch_ipv6_addresses(
        _tx: tokio::sync::mpsc::Sender<AddrEvent>,
    ) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }

    #[cfg(test)]
    mod tests {
        use super::{
            delete_interface, list_global_ipv6, setup_interface, watch_ipv6_addresses,
        };
        use crate::PlatformError;

        /// 非 Linux 平台（本地 macOS 开发机）唯一真实执行的测试：
        /// 确认四个导出函数都如实返回 `Unsupported`，而不是静默 panic 或
        /// 误报别的错误变体。
        #[tokio::test]
        async fn stub_returns_unsupported() {
            let setup_err = setup_interface("hxt0", "fd00::1".parse().unwrap(), 48, 1400)
                .await
                .unwrap_err();
            assert!(matches!(setup_err, PlatformError::Unsupported));

            let delete_err = delete_interface("hxt0").await.unwrap_err();
            assert!(matches!(delete_err, PlatformError::Unsupported));

            let list_err = list_global_ipv6(None).await.unwrap_err();
            assert!(matches!(list_err, PlatformError::Unsupported));

            let (tx, _rx) = tokio::sync::mpsc::channel(1);
            let watch_err = watch_ipv6_addresses(tx).await.unwrap_err();
            assert!(matches!(watch_err, PlatformError::Unsupported));
        }
    }
}
#[cfg(not(target_os = "linux"))]
pub use stub::{delete_interface, list_global_ipv6, setup_interface, watch_ipv6_addresses};
```

`crates/platform/src/linux.rs`：文件**顶部** `use` 段替换为：

```rust
//! Linux rtnetlink 实现。

use std::net::{IpAddr, Ipv6Addr};

use futures::{StreamExt as _, TryStreamExt as _};
use rtnetlink::LinkUnspec;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::address::{AddressAttribute, AddressHeaderFlags, AddressScope};
use rtnetlink::{MulticastGroup, new_multicast_connection};

use crate::{AddrEvent, AddrEventKind, PlatformError};
```

在 `delete_interface` **之后**（`mod tests` 之前）追加三段实现：

```rust
/// 判断是否 ULA（RFC 4193 fc00::/7）。
///
/// hextet 自己的 overlay 地址就是 ULA，绝不能被当成"可对外的公网 endpoint"
/// 报给 doctor；LAN 上其他设备的 ULA 同理不可用。
fn is_ula(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// 枚举本机可用作公网 endpoint 的 IPv6 地址。
///
/// 过滤规则（顺序即代码顺序）：
/// 1. family 必须是 Inet6；
/// 2. scope 必须是 Universe（排除 link-local fe80::/10、host ::1）；
/// 3. `exclude_interface` 指定的接口上的地址全部排除（hextet0 自己的 overlay）；
/// 4. 打了 Deprecated / Tentative / Dadfailed 标记的排除——换前缀过程中旧地址
///    会先变 Deprecated，拿它当 endpoint 只会打洞到一个即将失效的地址；
/// 5. ULA / loopback / multicast 排除。
pub async fn list_global_ipv6(
    exclude_interface: Option<&str>,
) -> Result<Vec<Ipv6Addr>, PlatformError> {
    let (conn, handle, _) = rtnetlink::new_connection().map_err(nl)?;
    tokio::spawn(conn);

    let excluded = match exclude_interface {
        Some(name) => match link_index(&handle, name).await {
            Ok(idx) => Some(idx),
            // 接口还不存在（daemon 尚未建好）时无需排除任何东西
            Err(PlatformError::NotFound(_)) => None,
            Err(e) => return Err(e),
        },
        None => None,
    };

    let mut out = Vec::new();
    let mut stream = handle.address().get().execute();
    while let Some(msg) = stream.try_next().await.map_err(nl)? {
        if !matches!(msg.header.family, AddressFamily::Inet6) {
            continue;
        }
        if !matches!(msg.header.scope, AddressScope::Universe) {
            continue;
        }
        if excluded == Some(msg.header.index) {
            continue;
        }
        if msg.header.flags.intersects(
            AddressHeaderFlags::Deprecated
                | AddressHeaderFlags::Tentative
                | AddressHeaderFlags::Dadfailed,
        ) {
            continue;
        }
        for attr in &msg.attributes {
            let AddressAttribute::Address(IpAddr::V6(addr)) = attr else {
                continue;
            };
            if is_ula(addr) || addr.is_loopback() || addr.is_multicast() {
                continue;
            }
            out.push(*addr);
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// 监听本机 IPv6 地址变化（`RTNLGRP_IPV6_IFADDR` 组播，等价于 `ip -6 monitor address`）。
///
/// 一直阻塞直到 netlink 流结束或 `tx` 的接收端被丢弃。**不做任何过滤**：
/// daemon 只需要"地址变了"这个信号来触发重新握手，把判断留给调用方更简单，
/// 也避免漏掉「新前缀先 Added、旧前缀后 Removed」这类多事件序列里的任一条。
pub async fn watch_ipv6_addresses(
    tx: tokio::sync::mpsc::Sender<AddrEvent>,
) -> Result<(), PlatformError> {
    let (conn, _handle, mut messages) =
        new_multicast_connection(&[MulticastGroup::Ipv6Ifaddr]).map_err(nl)?;
    tokio::spawn(conn);

    while let Some((message, _)) = messages.next().await {
        let NetlinkPayload::InnerMessage(inner) = message.payload else {
            continue;
        };
        let (kind, msg) = match inner {
            RouteNetlinkMessage::NewAddress(m) => (AddrEventKind::Added, m),
            RouteNetlinkMessage::DelAddress(m) => (AddrEventKind::Removed, m),
            _ => continue,
        };
        let if_index = msg.header.index;
        for attr in &msg.attributes {
            let AddressAttribute::Address(IpAddr::V6(address)) = attr else {
                continue;
            };
            if tx
                .send(AddrEvent {
                    kind,
                    address: *address,
                    if_index,
                })
                .await
                .is_err()
            {
                // 接收端已关闭（daemon 退出）：正常收尾，不算错误
                return Ok(());
            }
        }
    }
    Ok(())
}
```

**注意**：原文件用的是 `use futures::TryStreamExt as _;`，新代码同时需要 `StreamExt`（给 `messages.next()`）与 `TryStreamExt`（给 `stream.try_next()`），已在上面的 `use` 段合并。

- [ ] **Step 4: 运行测试通过**

Run（macOS）: `cargo test -p hextet-platform`
Expected: `stub_returns_unsupported` PASS

Run（Linux）: `cargo test -p hextet-platform`
Expected: `ula_detection` + `list_global_ipv6_does_not_error` PASS，`watch_reports_added_address` 显示 ignored

Run（Linux，可选）: `sudo -E cargo test -p hextet-platform -- --ignored`
Expected: `watch_reports_added_address` PASS

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- hextet-platform：`list_global_ipv6`（枚举可用作公网 endpoint 的 IPv6 地址，过滤 ULA/deprecated/link-local）与 `watch_ipv6_addresses`（netlink RTNLGRP_IPV6_IFADDR 地址变化监听），非 Linux 平台返回 `Unsupported`。
```

```bash
git add crates/platform CHANGELOG.md
git commit -m "feat(platform): IPv6 地址枚举与 netlink 地址变化监听

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: engine crate 骨架 + spec 迁移 + 候选 endpoint 组装

**Files:**
- Create: `crates/engine/Cargo.toml`
- Create: `crates/engine/src/lib.rs`
- Create: `crates/engine/src/spec.rs`
- Create: `crates/engine/src/candidates.rs`
- Delete: `crates/cli/src/spec.rs`
- Modify: `Cargo.toml`（根：members、workspace.dependencies）
- Modify: `crates/cli/Cargo.toml`
- Modify: `crates/cli/src/lib.rs`
- Modify: `crates/cli/src/commands/up.rs`
- Modify: `crates/cli/tests/spec.rs`

**Interfaces:**
- Consumes: `hextet_core::config::Config`、`hextet_core::identity::NodeIdentity`、`hextet_wg::types::{DeviceSpec, PeerSpec}`
- Produces:
  - `hextet_engine::spec::build_device_spec(cfg: &Config, id: &NodeIdentity) -> DeviceSpec`（**行为与 M1 完全一致**，只是换了 crate）
  - `hextet_engine::candidates::normalize(ep: SocketAddrV6) -> SocketAddrV6`
  - `hextet_engine::candidates::MAX_CANDIDATES: usize = 8`
  - `hextet_engine::candidates::build_candidates(configured: &[SocketAddrV6], cached: &[CachedEndpoint], last_good: Option<SocketAddrV6>) -> Vec<SocketAddrV6>`
  - `hextet_engine::cache::CachedEndpoint { pub endpoint: SocketAddrV6, pub last_seen_unix: u64 }`（本 Task 只定义这个类型，其余缓存逻辑在 Task 6）
- 排序契约（Task 5/8 依赖）：`build_candidates` 的输出顺序是 **last_good → configured（保持配置顺序）→ cached（last_seen 由新到旧）**，去重（按归一化后的值），最多 `MAX_CANDIDATES` 个。

- [ ] **Step 1: 写失败测试**

`crates/engine/src/candidates.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    #[test]
    fn empty_inputs_give_empty_output() {
        assert!(build_candidates(&[], &[], None).is_empty());
    }

    #[test]
    fn last_good_comes_first() {
        let configured = vec![ep("[2001:db8::1]:4193"), ep("[2001:db8::2]:4193")];
        let out = build_candidates(&configured, &[], Some(ep("[2001:db8::2]:4193")));
        assert_eq!(out[0], ep("[2001:db8::2]:4193"));
        assert_eq!(out[1], ep("[2001:db8::1]:4193"));
        // last_good 与配置项重复时不出现两次
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn configured_order_is_preserved() {
        let configured = vec![
            ep("[2001:db8::1]:4193"),
            ep("[2001:db8::2]:4193"),
            ep("[2001:db8::3]:4193"),
        ];
        let out = build_candidates(&configured, &[], None);
        assert_eq!(out, configured);
    }

    #[test]
    fn cached_follow_configured_newest_first() {
        let configured = vec![ep("[2001:db8::1]:4193")];
        let cached = vec![
            CachedEndpoint {
                endpoint: ep("[2001:db8::7]:4193"),
                last_seen_unix: 100,
            },
            CachedEndpoint {
                endpoint: ep("[2001:db8::9]:4193"),
                last_seen_unix: 900,
            },
        ];
        let out = build_candidates(&configured, &cached, None);
        assert_eq!(
            out,
            vec![
                ep("[2001:db8::1]:4193"),
                ep("[2001:db8::9]:4193"),
                ep("[2001:db8::7]:4193"),
            ]
        );
    }

    #[test]
    fn duplicates_across_sources_are_deduped() {
        let configured = vec![ep("[2001:db8::1]:4193")];
        let cached = vec![CachedEndpoint {
            endpoint: ep("[2001:db8::1]:4193"),
            last_seen_unix: 5,
        }];
        let out = build_candidates(&configured, &cached, Some(ep("[2001:db8::1]:4193")));
        assert_eq!(out, vec![ep("[2001:db8::1]:4193")]);
    }

    #[test]
    fn output_is_capped() {
        let configured: Vec<SocketAddrV6> = (1..=20)
            .map(|i| ep(&format!("[2001:db8::{i:x}]:4193")))
            .collect();
        let out = build_candidates(&configured, &[], None);
        assert_eq!(out.len(), MAX_CANDIDATES);
        assert_eq!(out[0], configured[0]);
    }

    #[test]
    fn normalize_clears_flowinfo_and_scope() {
        let raw = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4193, 7, 3);
        let n = normalize(raw);
        assert_eq!(n.flowinfo(), 0);
        assert_eq!(n.scope_id(), 0);
        assert_eq!(n.port(), 4193);
        assert_eq!(*n.ip(), "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap());
        // 归一化后两个只差 scope_id 的地址相等（这正是去重与 roaming 判定要的语义）
        assert_eq!(n, normalize(SocketAddrV6::new(*raw.ip(), 4193, 0, 9)));
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-engine`
Expected: `error: package ID specification 'hextet-engine' did not match any packages`（crate 还不存在）→ 按 Step 3 建好后再跑一次，Expected: 编译失败 `cannot find function build_candidates`。

- [ ] **Step 3: 实现**

根 `Cargo.toml`：`members` 与 `workspace.dependencies` 改为（只列改动行，其余保持原样）：

```toml
members = [
  "crates/core",
  "crates/wg",
  "crates/platform",
  "crates/engine",
  "crates/cli",
  "xtask",
]
```

`[workspace.dependencies]` 里追加四行：

```toml
hextet-engine = { path = "crates/engine" }
hmac = "0.12"
tracing = "0.1"
tracing-subscriber = "0.3"
```

`crates/engine/Cargo.toml`:

```toml
[package]
name = "hextet-engine"
description = "hextet embeddable engine: punch state machine, endpoint cache, daemon loop"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[lints]
workspace = true

[dependencies]
hextet-core.workspace = true
hextet-wg.workspace = true
hextet-platform.workspace = true
anyhow.workspace = true
rand_core.workspace = true
serde = { workspace = true }
serde_json.workspace = true
thiserror.workspace = true
tokio.workspace = true
tracing.workspace = true

[dev-dependencies]
tempfile.workspace = true
```

`crates/engine/src/lib.rs`:

```rust
//! hextet 可嵌入引擎：打洞状态机、端点缓存、运行时状态快照与守护进程主循环。
//!
//! 分层原则——本 crate 里除了 [`daemon`] 与探针的 socket 部分，全部是**纯逻辑**
//! （无 I/O、无 root、无平台依赖），因此能在任何开发机上被 `cargo test` 完整覆盖；
//! `daemon` 只做接线，由 `scripts/netns-e2e-*.sh` 覆盖。M7 的 Android FFI 直接
//! 复用本 crate，不要在这里假设"自己是一个进程"以外的东西。
#![deny(missing_docs)]

pub mod candidates;
pub mod spec;
```

（后续 Task 会往 `lib.rs` 里继续追加 `pub mod fsm;`、`pub mod cache;` 等，本 Task 只加这两行。）

`crates/engine/src/spec.rs`（内容与被删掉的 `crates/cli/src/spec.rs` **完全一致**，只是搬家）：

```rust
//! 配置 → WG DeviceSpec 的纯映射（可单测）。

use hextet_core::config::Config;
use hextet_core::identity::NodeIdentity;
use hextet_wg::types::{DeviceSpec, PeerSpec};

/// M1 常电节点 keepalive（设计 spec §5）。
const KEEPALIVE_SECS: u16 = 25;

/// 由配置与身份构建设备期望状态。
///
/// 每个 peer 的 `endpoint` 取配置里的第一个（可能为 `None`）。M2 起真正的
/// endpoint 由打洞状态机（`crate::fsm`，Task 5 引入）在运行时用
/// `set_peer_endpoint` 逐个校正，所以这里不需要知道端点缓存的存在。
///
/// 注意上面那句里的 `crate::fsm` 用反引号而不是 rustdoc 链接 `[...]`：`fsm`
/// 模块此刻还不存在，写成链接会触发 `broken_intra_doc_links` 警告，而
/// `-D warnings` 会让它变成编译失败。
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

`crates/engine/src/candidates.rs`:

```rust
//! 候选 endpoint 组装。
//!
//! IPv6 下端口永远由自己决定，会合记录里只有**地址**在变（设计 spec §5），
//! 所以"打洞"在实现上就是"在若干个候选 `[addr]:port` 之间轮换，看哪个能握手"。

use std::net::SocketAddrV6;

use crate::cache::CachedEndpoint;

/// 候选 endpoint 数量上限。
///
/// 轮换间隔 2.5s，8 个候选跑完一轮 20s；再多会让"一轮都试不完"变成常态，
/// 超出部分丢弃（调用方负责 log 丢了多少）。
pub const MAX_CANDIDATES: usize = 8;

/// 归一化 endpoint：把 `flowinfo` 与 `scope_id` 清零。
///
/// `SocketAddrV6` 的 `PartialEq` 会比较 flowinfo 与 scope_id，而内核报告的
/// endpoint 与配置/缓存里解析出来的值在这两个字段上未必一致。不归一化就会让
/// "内核 endpoint != 当前候选"恒真，于是每个 tick 都被误判成一次 roaming，
/// 不停重写端点缓存。所有跨来源比较与存储都必须先过这个函数。
pub fn normalize(ep: SocketAddrV6) -> SocketAddrV6 {
    SocketAddrV6::new(*ep.ip(), ep.port(), 0, 0)
}

fn push_unique(out: &mut Vec<SocketAddrV6>, ep: SocketAddrV6) {
    let ep = normalize(ep);
    if out.len() < MAX_CANDIDATES && !out.contains(&ep) {
        out.push(ep);
    }
}

/// 组装候选 endpoint 列表。
///
/// 顺序：`last_good` → `configured`（保持配置顺序）→ `cached`（`last_seen_unix`
/// 由新到旧）。上次成功的放最前面，让"重启后立刻重连"成为最快路径；配置项优先于
/// 缓存，让用户手填的地址（终极兜底，设计 spec §3 D3 ⑦）总能生效。
pub fn build_candidates(
    configured: &[SocketAddrV6],
    cached: &[CachedEndpoint],
    last_good: Option<SocketAddrV6>,
) -> Vec<SocketAddrV6> {
    let mut out: Vec<SocketAddrV6> = Vec::new();
    if let Some(ep) = last_good {
        push_unique(&mut out, ep);
    }
    for ep in configured {
        push_unique(&mut out, *ep);
    }
    let mut cached_sorted: Vec<&CachedEndpoint> = cached.iter().collect();
    cached_sorted.sort_by(|a, b| b.last_seen_unix.cmp(&a.last_seen_unix));
    for c in cached_sorted {
        push_unique(&mut out, c.endpoint);
    }
    out
}
```

`crates/engine/src/cache.rs`（本 Task **只**建这个最小版本，Task 6 再补全）：

```rust
//! 端点缓存：把"上次能连上的 endpoint"持久化，重启后直接复用。

use std::net::SocketAddrV6;

use serde::{Deserialize, Serialize};

/// 一个曾经见到过的 endpoint 及其最后一次被证实可用的时间。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedEndpoint {
    /// endpoint 本体（存储前已 [`crate::candidates::normalize`]）。
    pub endpoint: SocketAddrV6,
    /// 最后一次被证实可用的 Unix 时间戳（秒）。
    pub last_seen_unix: u64,
}
```

`lib.rs` 因此要写成：

```rust
pub mod cache;
pub mod candidates;
pub mod spec;
```

`crates/cli/Cargo.toml`：`[dependencies]` 追加：

```toml
hextet-engine.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

`crates/cli/src/lib.rs` 整体替换：

```rust
//! hextet CLI library

pub mod commands;

pub use commands::inspect::{InspectReport, NetworkReport, NodeReport, PeerReport};
```

`crates/cli/src/spec.rs`：**删除文件**（`git rm crates/cli/src/spec.rs`）。

`crates/cli/src/commands/up.rs`：把 `crate::spec::build_device_spec(&cfg, &id)` 改为 `hextet_engine::spec::build_device_spec(&cfg, &id)`（只改这一行）。

`crates/cli/tests/spec.rs`：把第 37 行 `hextet_cli::spec::build_device_spec(&cfg, &id)` 改为 `hextet_engine::spec::build_device_spec(&cfg, &id)`（只改这一行；`status_state_classification` 测试不动）。

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-engine`
Expected: 7 个测试 PASS

Run: `cargo test -p hextet-cli`
Expected: 既有 5 个测试全 PASS（3 个 CLI 集成 + 2 个 spec）

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- 新 crate `hextet-engine`（可嵌入引擎）：`build_device_spec` 由 hextet-cli 迁入；候选 endpoint 组装（last_good → 配置 → 缓存，去重，上限 8）与 endpoint 归一化。
```

```bash
git add Cargo.toml crates/engine crates/cli CHANGELOG.md
git commit -m "feat(engine): 新建 engine crate，迁入 device spec 并实现候选 endpoint 组装

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: engine — 打洞/连接状态机

这是 M2 最核心的可测单元。**先把测试写全再写实现**，实现只有 60 行左右。

**Files:**
- Create: `crates/engine/src/fsm.rs`
- Modify: `crates/engine/src/lib.rs`（加 `pub mod fsm;`）

**Interfaces:**
- Consumes: `crate::candidates::normalize`
- Produces:
  ```rust
  pub const ROTATE_INTERVAL: Duration = Duration::from_millis(2500);
  pub const HANDSHAKE_FRESH: Duration = Duration::from_secs(180);

  pub enum PunchState {
      Probing { candidate_index: usize, rounds: u32 },
      Connected { endpoint: SocketAddrV6 },
  }

  pub struct Observation {
      pub last_handshake: Option<SystemTime>,
      pub kernel_endpoint: Option<SocketAddrV6>,
  }

  pub enum Action {
      SetEndpoint(SocketAddrV6),
      Nudge,
      MarkGood(SocketAddrV6),
  }

  impl PeerFsm {
      pub fn new(candidates: Vec<SocketAddrV6>, now: SystemTime) -> Self;
      pub fn kick(&mut self, now: SystemTime) -> Vec<Action>;
      pub fn tick(&mut self, now: SystemTime, obs: Observation) -> Vec<Action>;
      pub fn state(&self) -> PunchState;
      pub fn candidates_len(&self) -> usize;
      pub fn current_candidate(&self) -> Option<SocketAddrV6>;
  }
  ```
- 语义约定（Task 8 依赖）：
  - `Action::Nudge` = 「向该 peer 的 overlay 地址发一个 UDP 包」，作用是让内核 WireGuard 立刻发起握手 / 用**新的源地址**发一个已认证的包（对端据此 roaming）。
  - `Action::MarkGood(ep)` = 「这个 endpoint 已被证实可用，写进端点缓存」。
  - `kick` 用于两个时机：daemon 启动后的首次触发、本机地址变化后的立刻重试。

- [ ] **Step 1: 写失败测试**

`crates/engine/src/fsm.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    fn three() -> Vec<SocketAddrV6> {
        vec![
            ep("[2001:db8::1]:4193"),
            ep("[2001:db8::2]:4193"),
            ep("[2001:db8::3]:4193"),
        ]
    }

    /// 没有握手时的观测。
    fn cold() -> Observation {
        Observation {
            last_handshake: None,
            kernel_endpoint: None,
        }
    }

    #[test]
    fn starts_in_probing_at_first_candidate() {
        let fsm = PeerFsm::new(three(), t0());
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 0
            }
        );
        assert_eq!(fsm.current_candidate(), Some(ep("[2001:db8::1]:4193")));
        assert_eq!(fsm.candidates_len(), 3);
    }

    #[test]
    fn kick_sets_current_candidate_and_nudges() {
        let mut fsm = PeerFsm::new(three(), t0());
        let actions = fsm.kick(t0());
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::1]:4193")), Action::Nudge]
        );
    }

    #[test]
    fn probing_does_nothing_before_rotate_interval() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let actions = fsm.tick(t0() + Duration::from_millis(2_400), cold());
        assert!(actions.is_empty(), "got {actions:?}");
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 0
            }
        );
    }

    #[test]
    fn probing_rotates_to_next_candidate_after_interval() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let actions = fsm.tick(t0() + Duration::from_millis(2_600), cold());
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::2]:4193")), Action::Nudge]
        );
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 1,
                rounds: 0
            }
        );
    }

    #[test]
    fn rotation_wraps_and_counts_rounds() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let mut now = t0();
        // 0 -> 1 -> 2 -> 0（回到 0 时算走完一轮）
        for expected in [1usize, 2, 0] {
            now += Duration::from_millis(2_600);
            let _ = fsm.tick(now, cold());
            match fsm.state() {
                PunchState::Probing {
                    candidate_index, ..
                } => assert_eq!(candidate_index, expected),
                other => panic!("expected Probing, got {other:?}"),
            }
        }
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 1
            }
        );
    }

    #[test]
    fn single_candidate_keeps_re_nudging_same_endpoint() {
        let mut fsm = PeerFsm::new(vec![ep("[2001:db8::1]:4193")], t0());
        let _ = fsm.kick(t0());
        let actions = fsm.tick(t0() + Duration::from_millis(2_600), cold());
        // 只有一个候选时"轮换"回到自己：仍然要重发 nudge，
        // 否则内核 WireGuard 放弃握手后（约 90s）就再也不会重试。
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::1]:4193")), Action::Nudge]
        );
    }

    #[test]
    fn fresh_handshake_transitions_to_connected_and_marks_good() {
        let mut fsm = PeerFsm::new(three(), t0());
        let _ = fsm.kick(t0());
        let now = t0() + Duration::from_secs(3);
        let actions = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now - Duration::from_secs(1)),
                kernel_endpoint: Some(ep("[2001:db8::2]:4193")),
            },
        );
        assert_eq!(actions, vec![Action::MarkGood(ep("[2001:db8::2]:4193"))]);
        assert_eq!(
            fsm.state(),
            PunchState::Connected {
                endpoint: ep("[2001:db8::2]:4193")
            }
        );
    }

    #[test]
    fn connected_is_quiet_while_handshake_stays_fresh() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        let actions = fsm.tick(
            now + Duration::from_secs(30),
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        assert!(actions.is_empty(), "got {actions:?}");
    }

    #[test]
    fn connected_follows_peer_roaming() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        // 对端换了前缀，内核根据已认证的包更新了 endpoint
        let actions = fsm.tick(
            now + Duration::from_secs(1),
            Observation {
                last_handshake: Some(now + Duration::from_secs(1)),
                kernel_endpoint: Some(ep("[2001:db8:2::1]:4193")),
            },
        );
        assert_eq!(actions, vec![Action::MarkGood(ep("[2001:db8:2::1]:4193"))]);
        assert_eq!(
            fsm.state(),
            PunchState::Connected {
                endpoint: ep("[2001:db8:2::1]:4193")
            }
        );
    }

    #[test]
    fn connected_falls_back_to_probing_when_handshake_goes_stale() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::2]:4193")),
            },
        );
        let actions = fsm.tick(
            now + Duration::from_secs(300),
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::2]:4193")),
            },
        );
        assert_eq!(
            actions,
            vec![Action::SetEndpoint(ep("[2001:db8::1]:4193")), Action::Nudge]
        );
        assert_eq!(
            fsm.state(),
            PunchState::Probing {
                candidate_index: 0,
                rounds: 0
            }
        );
    }

    #[test]
    fn kick_while_connected_only_nudges() {
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let _ = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        // 本机换了前缀：不要动对端 endpoint，只需发一个包让对端 roaming 到我们的新源地址
        assert_eq!(fsm.kick(now + Duration::from_secs(1)), vec![Action::Nudge]);
    }

    #[test]
    fn empty_candidates_never_panic_and_emit_nothing() {
        let mut fsm = PeerFsm::new(vec![], t0());
        assert!(fsm.kick(t0()).is_empty());
        assert!(fsm.tick(t0() + Duration::from_secs(10), cold()).is_empty());
        assert_eq!(fsm.current_candidate(), None);
        assert_eq!(fsm.candidates_len(), 0);
    }

    #[test]
    fn handshake_in_the_future_is_treated_as_fresh() {
        // 时钟回拨 / 内核时间比 SystemTime::now() 新时 duration_since 会 Err，
        // 保守当作"新鲜"，不要把一条正常连接打回打洞状态。
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let actions = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now + Duration::from_secs(60)),
                kernel_endpoint: Some(ep("[2001:db8::1]:4193")),
            },
        );
        assert_eq!(actions, vec![Action::MarkGood(ep("[2001:db8::1]:4193"))]);
    }

    #[test]
    fn connected_without_kernel_endpoint_falls_back_to_candidate() {
        // 极端情况：握手新鲜但内核没报 endpoint —— 用当前候选顶上，不要 panic。
        let mut fsm = PeerFsm::new(three(), t0());
        let now = t0() + Duration::from_secs(3);
        let actions = fsm.tick(
            now,
            Observation {
                last_handshake: Some(now),
                kernel_endpoint: None,
            },
        );
        assert_eq!(actions, vec![Action::MarkGood(ep("[2001:db8::1]:4193"))]);
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-engine fsm`
Expected: 编译失败，`cannot find type PeerFsm`。

- [ ] **Step 3: 实现**

`crates/engine/src/lib.rs` 的模块声明改为（按字母序）：

```rust
pub mod cache;
pub mod candidates;
pub mod fsm;
pub mod spec;
```

`crates/engine/src/fsm.rs`（放在上面 `mod tests` 之前）：

```rust
//! 单个 peer 的打洞/连接状态机（纯逻辑，无 I/O）。
//!
//! 机制（设计 spec §4「关键设计」）：打洞不需要独立信令协议——会合层只负责
//! "知道对方当前 `[addr]:port`"，然后两端同时发 WireGuard 握手包，防火墙 state
//! 相互命中即通。本状态机做的就是「在候选 endpoint 之间轮换，并持续制造出站
//! 握手」，以及在握手成功后跟随内核的 roaming 结果。

use std::net::SocketAddrV6;
use std::time::{Duration, SystemTime};

use crate::candidates::normalize;

/// 候选 endpoint 轮换间隔。
///
/// 内核 WireGuard 的握手重试间隔是 5s（REKEY_TIMEOUT），2.5s 轮换保证每个候选
/// 在被换掉之前至少收到一次我们主动触发的握手初始化。
pub const ROTATE_INTERVAL: Duration = Duration::from_millis(2500);

/// 握手新鲜度阈值：超过它视为连接已断。
///
/// 与 `hextet status` 的 `connected` 判定阈值保持一致（180s）——两处如果不一致，
/// 会出现 status 说 connected 而 daemon 正在打洞这种自相矛盾的输出。
pub const HANDSHAKE_FRESH: Duration = Duration::from_secs(180);

/// 状态机对外可见状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchState {
    /// 正在轮换候选 endpoint 打洞。
    Probing {
        /// 当前候选下标。
        candidate_index: usize,
        /// 已走完的完整轮次数（仅用于可观测性，不参与决策）。
        rounds: u32,
    },
    /// 已有新鲜握手。
    Connected {
        /// 内核当前记录的 endpoint（已归一化）。
        endpoint: SocketAddrV6,
    },
}

/// 每 tick 从内核读到的观测值。
#[derive(Debug, Clone, Copy)]
pub struct Observation {
    /// 最近一次握手时间（内核 WireGuard 报告）。
    pub last_handshake: Option<SystemTime>,
    /// 内核当前记录的 endpoint。调用方必须先 [`normalize`]。
    pub kernel_endpoint: Option<SocketAddrV6>,
}

/// 状态机要求外部执行的副作用。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 把内核里该 peer 的 endpoint 设成给定值。
    SetEndpoint(SocketAddrV6),
    /// 向该 peer 的 overlay 地址发一个包：触发 WireGuard 握手，
    /// 或用本机**新的**源地址发一个已认证的包让对端 roaming。
    Nudge,
    /// 该 endpoint 已被证实可用，记入端点缓存。
    MarkGood(SocketAddrV6),
}

/// 单个 peer 的打洞状态机。
#[derive(Debug)]
pub struct PeerFsm {
    candidates: Vec<SocketAddrV6>,
    state: PunchState,
    last_transition: SystemTime,
}

fn handshake_is_fresh(last_handshake: Option<SystemTime>, now: SystemTime) -> bool {
    match last_handshake {
        // duration_since 在 t > now 时报错（时钟回拨）：保守视为新鲜。
        Some(t) => now
            .duration_since(t)
            .map(|d| d < HANDSHAKE_FRESH)
            .unwrap_or(true),
        None => false,
    }
}

impl PeerFsm {
    /// 用候选列表新建状态机，初始状态为 `Probing { candidate_index: 0, rounds: 0 }`。
    pub fn new(candidates: Vec<SocketAddrV6>, now: SystemTime) -> Self {
        Self {
            candidates: candidates.into_iter().map(normalize).collect(),
            state: PunchState::Probing {
                candidate_index: 0,
                rounds: 0,
            },
            last_transition: now,
        }
    }

    /// 当前状态。
    pub fn state(&self) -> PunchState {
        self.state
    }

    /// 候选数量。
    pub fn candidates_len(&self) -> usize {
        self.candidates.len()
    }

    /// 当前候选（`Connected` 状态下返回已连上的 endpoint）。
    pub fn current_candidate(&self) -> Option<SocketAddrV6> {
        match self.state {
            PunchState::Connected { endpoint } => Some(endpoint),
            PunchState::Probing {
                candidate_index, ..
            } => self.candidates.get(candidate_index).copied(),
        }
    }

    /// 立刻重试当前候选：daemon 启动时调用一次，本机地址变化后再调用。
    ///
    /// `Connected` 状态下只发 `Nudge`——本机地址变了不需要改对端 endpoint，
    /// 只需要让对端收到一个来自新源地址的已认证包（WireGuard roaming）。
    pub fn kick(&mut self, now: SystemTime) -> Vec<Action> {
        self.last_transition = now;
        match self.state {
            PunchState::Connected { .. } => vec![Action::Nudge],
            PunchState::Probing {
                candidate_index, ..
            } => match self.candidates.get(candidate_index) {
                Some(&ep) => vec![Action::SetEndpoint(ep), Action::Nudge],
                None => vec![],
            },
        }
    }

    /// 推进一个 tick。
    pub fn tick(&mut self, now: SystemTime, obs: Observation) -> Vec<Action> {
        let fresh = handshake_is_fresh(obs.last_handshake, now);
        let kernel_endpoint = obs.kernel_endpoint.map(normalize);

        match self.state {
            PunchState::Probing {
                candidate_index,
                rounds,
            } => {
                if fresh {
                    let Some(endpoint) =
                        kernel_endpoint.or_else(|| self.candidates.get(candidate_index).copied())
                    else {
                        return vec![];
                    };
                    self.state = PunchState::Connected { endpoint };
                    self.last_transition = now;
                    return vec![Action::MarkGood(endpoint)];
                }
                if self.candidates.is_empty() {
                    return vec![];
                }
                let elapsed = now
                    .duration_since(self.last_transition)
                    .unwrap_or(Duration::ZERO);
                if elapsed < ROTATE_INTERVAL {
                    return vec![];
                }
                let next = (candidate_index + 1) % self.candidates.len();
                let rounds = if next == 0 {
                    rounds.saturating_add(1)
                } else {
                    rounds
                };
                self.state = PunchState::Probing {
                    candidate_index: next,
                    rounds,
                };
                self.last_transition = now;
                vec![Action::SetEndpoint(self.candidates[next]), Action::Nudge]
            }
            PunchState::Connected { endpoint } => {
                if !fresh {
                    self.state = PunchState::Probing {
                        candidate_index: 0,
                        rounds: 0,
                    };
                    self.last_transition = now;
                    return match self.candidates.first() {
                        Some(&ep) => vec![Action::SetEndpoint(ep), Action::Nudge],
                        None => vec![],
                    };
                }
                match kernel_endpoint {
                    // 对端换了地址，内核已据已认证包 roaming：跟随并记入缓存
                    Some(ke) if ke != endpoint => {
                        self.state = PunchState::Connected { endpoint: ke };
                        self.last_transition = now;
                        vec![Action::MarkGood(ke)]
                    }
                    _ => vec![],
                }
            }
        }
    }
}
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-engine fsm`
Expected: 14 个测试全 PASS

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- hextet-engine：每 peer 打洞/连接状态机（候选轮换 2.5s、握手新鲜度 180s、跟随对端 roaming、地址变化后立刻重试）。
```

```bash
git add crates/engine CHANGELOG.md
git commit -m "feat(engine): 打洞/连接状态机

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: engine — 端点缓存（endpoints.json，原子写）

**Files:**
- Create: `crates/engine/src/atomic.rs`
- Modify: `crates/engine/src/cache.rs`（在 Task 4 的最小版本上补全）
- Modify: `crates/engine/src/lib.rs`（加 `pub mod atomic;`）

**Interfaces:**
- Consumes: `crate::candidates::normalize`
- Produces:
  - `hextet_engine::atomic::write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()>`（tmp + rename 原子写，Unix 下 0600）
  - `hextet_engine::atomic::read_json<T: DeserializeOwned>(path: &Path) -> std::io::Result<T>`
  - `hextet_engine::cache::CACHE_SEEN_MAX: usize = 8`
  - `PeerCacheEntry { pub last_good: Option<SocketAddrV6>, pub seen: Vec<CachedEndpoint> }`
  - `EndpointCache { pub version: u32, pub peers: BTreeMap<String, PeerCacheEntry> }`
    - `EndpointCache::new() -> Self`（version = 1）
    - `EndpointCache::load(path: &Path) -> Self`（**永不失败**：文件缺失/损坏/版本不认识都返回空缓存）
    - `EndpointCache::save(&self, path: &Path) -> std::io::Result<()>`
    - `EndpointCache::record_good(&mut self, peer_key: &str, endpoint: SocketAddrV6, now_unix: u64)`
    - `EndpointCache::entry(&self, peer_key: &str) -> Option<&PeerCacheEntry>`
  - `peer_key` 一律用 peer 的 **ed25519 公钥 base64**（`NodePublicKey::to_base64()`）
- 文件格式（`<state_dir>/endpoints.json`）：
  ```json
  {
    "version": 1,
    "peers": {
      "3fK...=": {
        "last_good": "[2001:db8::b]:4193",
        "seen": [{ "endpoint": "[2001:db8::b]:4193", "last_seen_unix": 1770000000 }]
      }
    }
  }
  ```

- [ ] **Step 1: 写失败测试**

`crates/engine/src/cache.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    #[test]
    fn record_then_roundtrip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");

        let mut cache = EndpointCache::new();
        cache.record_good("peer-a", ep("[2001:db8::1]:4193"), 1000);
        cache.save(&path).unwrap();

        let loaded = EndpointCache::load(&path);
        let entry = loaded.entry("peer-a").expect("entry exists");
        assert_eq!(entry.last_good, Some(ep("[2001:db8::1]:4193")));
        assert_eq!(entry.seen.len(), 1);
        assert_eq!(entry.seen[0].last_seen_unix, 1000);
        assert_eq!(loaded.version, 1);
    }

    #[test]
    fn missing_file_yields_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = EndpointCache::load(&dir.path().join("nope.json"));
        assert!(cache.peers.is_empty());
        assert_eq!(cache.version, 1);
    }

    #[test]
    fn corrupt_file_yields_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        // 缓存是软状态：损坏时必须降级为空，绝不能让 daemon 起不来
        let cache = EndpointCache::load(&path);
        assert!(cache.peers.is_empty());
    }

    #[test]
    fn unknown_version_yields_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        std::fs::write(&path, r#"{"version":999,"peers":{}}"#).unwrap();
        let cache = EndpointCache::load(&path);
        assert!(cache.peers.is_empty());
        assert_eq!(cache.version, 1);
    }

    #[test]
    fn recording_same_endpoint_updates_timestamp_not_length() {
        let mut cache = EndpointCache::new();
        cache.record_good("p", ep("[2001:db8::1]:4193"), 10);
        cache.record_good("p", ep("[2001:db8::1]:4193"), 99);
        let entry = cache.entry("p").unwrap();
        assert_eq!(entry.seen.len(), 1);
        assert_eq!(entry.seen[0].last_seen_unix, 99);
    }

    #[test]
    fn seen_is_newest_first_and_capped() {
        let mut cache = EndpointCache::new();
        for i in 0..(CACHE_SEEN_MAX as u64 + 5) {
            cache.record_good("p", ep(&format!("[2001:db8::{:x}]:4193", i + 1)), i);
        }
        let entry = cache.entry("p").unwrap();
        assert_eq!(entry.seen.len(), CACHE_SEEN_MAX);
        // 最新的排最前
        assert!(entry.seen[0].last_seen_unix > entry.seen[1].last_seen_unix);
        // 最旧的被挤掉
        assert!(entry.seen.iter().all(|c| c.last_seen_unix >= 5));
    }

    #[test]
    fn record_normalizes_endpoint() {
        let mut cache = EndpointCache::new();
        let raw = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4193, 3, 5);
        cache.record_good("p", raw, 1);
        let entry = cache.entry("p").unwrap();
        assert_eq!(entry.last_good, Some(ep("[2001:db8::1]:4193")));
        assert_eq!(entry.seen[0].endpoint.scope_id(), 0);
    }

    #[test]
    fn last_good_switches_when_a_new_endpoint_works() {
        let mut cache = EndpointCache::new();
        cache.record_good("p", ep("[2001:db8::1]:4193"), 1);
        cache.record_good("p", ep("[2001:db8:2::1]:4193"), 2);
        assert_eq!(
            cache.entry("p").unwrap().last_good,
            Some(ep("[2001:db8:2::1]:4193"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        let mut cache = EndpointCache::new();
        cache.record_good("p", ep("[2001:db8::1]:4193"), 1);
        cache.save(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_leaves_no_tmp_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("endpoints.json");
        EndpointCache::new().save(&path).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "leftover tmp files: {leftovers:?}");
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-engine cache`
Expected: 编译失败，`cannot find type EndpointCache` / `CACHE_SEEN_MAX`。

- [ ] **Step 3: 实现**

`crates/engine/src/atomic.rs`:

```rust
//! JSON 文件的原子读写。
//!
//! daemon 每秒重写一次状态文件，而 `hextet status` 随时可能在读——直接
//! `File::create` + 写入会让读者看到半截 JSON。这里统一走"写临时文件 → fsync →
//! rename"：同目录内的 rename 在 POSIX 下是原子替换，读者要么看到旧的完整内容，
//! 要么看到新的完整内容。

use std::io;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

fn invalid_data(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// 原子写入 JSON（Unix 下权限 0600）。
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "state".to_string());
    // 临时文件必须与目标同目录，否则 rename 可能跨文件系统而失败
    let tmp = dir.join(format!(".{stem}.tmp"));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    // 临时文件可能是上次崩溃留下的（权限已存在、mode() 不生效），显式再设一次
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    serde_json::to_writer_pretty(&mut f, value).map_err(invalid_data)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// 读取并解析 JSON 文件。
pub fn read_json<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(invalid_data)
}
```

`crates/engine/src/lib.rs` 模块声明改为：

```rust
pub mod atomic;
pub mod cache;
pub mod candidates;
pub mod fsm;
pub mod spec;
```

`crates/engine/src/cache.rs` 整体替换（保留 Task 4 的 `CachedEndpoint`，其余新增；`mod tests` 接在后面）：

```rust
//! 端点缓存：把"上次能连上的 endpoint"持久化，重启后直接复用。
//!
//! 这是**软状态**——丢了只会让重连慢一点（退回配置里的 endpoint），所以读取
//! 路径上的任何错误都降级为空缓存，绝不阻断 daemon 启动。

use std::collections::BTreeMap;
use std::net::SocketAddrV6;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::candidates::normalize;

/// 缓存文件格式版本。
const CACHE_VERSION: u32 = 1;

/// 每个 peer 保留的历史 endpoint 条数上限。
pub const CACHE_SEEN_MAX: usize = 8;

/// 一个曾经见到过的 endpoint 及其最后一次被证实可用的时间。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedEndpoint {
    /// endpoint 本体（存储前已 [`normalize`]）。
    pub endpoint: SocketAddrV6,
    /// 最后一次被证实可用的 Unix 时间戳（秒）。
    pub last_seen_unix: u64,
}

/// 单个 peer 的缓存条目。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerCacheEntry {
    /// 最近一次被证实可用的 endpoint（候选列表里排第一）。
    #[serde(default)]
    pub last_good: Option<SocketAddrV6>,
    /// 历史 endpoint，按 `last_seen_unix` 由新到旧排列，最多 [`CACHE_SEEN_MAX`] 条。
    #[serde(default)]
    pub seen: Vec<CachedEndpoint>,
}

/// 全部 peer 的端点缓存。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCache {
    /// 文件格式版本。
    pub version: u32,
    /// key = peer 的 ed25519 公钥 base64。
    pub peers: BTreeMap<String, PeerCacheEntry>,
}

impl Default for EndpointCache {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointCache {
    /// 新建空缓存。
    pub fn new() -> Self {
        Self {
            version: CACHE_VERSION,
            peers: BTreeMap::new(),
        }
    }

    /// 从磁盘读取；文件缺失、损坏或版本不认识时返回空缓存（并 warn）。
    pub fn load(path: &Path) -> Self {
        match crate::atomic::read_json::<Self>(path) {
            Ok(cache) if cache.version == CACHE_VERSION => cache,
            Ok(cache) => {
                warn!(
                    path = %path.display(),
                    found = cache.version,
                    expected = CACHE_VERSION,
                    "端点缓存版本不认识，忽略"
                );
                Self::new()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e, "端点缓存不可读，忽略");
                Self::new()
            }
        }
    }

    /// 原子写入磁盘。
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        crate::atomic::write_json(path, self)
    }

    /// 取某个 peer 的缓存条目。
    pub fn entry(&self, peer_key: &str) -> Option<&PeerCacheEntry> {
        self.peers.get(peer_key)
    }

    /// 记录"该 endpoint 已被证实可用"。
    ///
    /// 同一个 endpoint 重复记录只更新时间戳；`seen` 始终保持由新到旧且不超过
    /// [`CACHE_SEEN_MAX`] 条。
    pub fn record_good(&mut self, peer_key: &str, endpoint: SocketAddrV6, now_unix: u64) {
        let endpoint = normalize(endpoint);
        let entry = self.peers.entry(peer_key.to_owned()).or_default();
        entry.last_good = Some(endpoint);
        match entry.seen.iter_mut().find(|c| c.endpoint == endpoint) {
            Some(existing) => existing.last_seen_unix = now_unix,
            None => entry.seen.push(CachedEndpoint {
                endpoint,
                last_seen_unix: now_unix,
            }),
        }
        entry.seen.sort_by(|a, b| b.last_seen_unix.cmp(&a.last_seen_unix));
        entry.seen.truncate(CACHE_SEEN_MAX);
    }
}
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-engine`
Expected: fsm 14 + candidates 7 + cache 10 全 PASS

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- hextet-engine：端点缓存 `<state_dir>/endpoints.json`（原子写 0600、每 peer 最多 8 条历史、损坏时降级为空缓存）与通用 JSON 原子读写。
```

```bash
git add crates/engine CHANGELOG.md
git commit -m "feat(engine): 端点缓存与 JSON 原子读写

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: engine — 运行时状态快照（state.json）

**Files:**
- Create: `crates/engine/src/state.rs`
- Create: `docs/dev/state-files.md`
- Modify: `crates/engine/src/lib.rs`（加 `pub mod state;`）

**Interfaces:**
- Consumes: `crate::cache::CachedEndpoint`
- Produces:
  - ```rust
    pub const STATE_VERSION: u32 = 1;

    pub struct EngineState {
        pub version: u32,
        pub updated_unix: u64,
        pub interface: String,
        pub node_address: Ipv6Addr,
        pub node_public_key: String,
        pub peers: Vec<PeerState>,
    }

    pub struct PeerState {
        pub name: String,
        pub public_key: String,
        pub address: Ipv6Addr,
        pub punch_state: String,      // "probing" | "connected"
        pub endpoint: Option<SocketAddrV6>,
        pub endpoint_source: String,  // "config" | "cache" | "roamed" | "none"
        pub candidates: usize,
        pub candidate_index: usize,
        pub rounds: u32,
    }
    ```
    两者都 `#[derive(Debug, Clone, Serialize, Deserialize)]`
  - `pub fn write(path: &Path, state: &EngineState) -> std::io::Result<()>`
  - `pub fn read(path: &Path) -> std::io::Result<EngineState>`
  - `pub fn endpoint_source(endpoint: Option<SocketAddrV6>, configured: &[SocketAddrV6], cached: &[CachedEndpoint]) -> &'static str`
  - `pub fn unix_secs(t: SystemTime) -> u64`

- [ ] **Step 1: 写失败测试**

`crates/engine/src/state.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn ep(s: &str) -> SocketAddrV6 {
        s.parse().unwrap()
    }

    fn sample() -> EngineState {
        EngineState {
            version: STATE_VERSION,
            updated_unix: 1_770_000_000,
            interface: "hextet0".into(),
            node_address: "fd12:3456:78::1".parse().unwrap(),
            node_public_key: "AAAA".into(),
            peers: vec![PeerState {
                name: "b".into(),
                public_key: "BBBB".into(),
                address: "fd12:3456:78:abcd::2".parse().unwrap(),
                punch_state: "connected".into(),
                endpoint: Some(ep("[2001:db8::b]:4193")),
                endpoint_source: "config".into(),
                candidates: 2,
                candidate_index: 0,
                rounds: 0,
            }],
        }
    }

    #[test]
    fn write_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write(&path, &sample()).unwrap();
        let back = read(&path).unwrap();
        assert_eq!(back.version, STATE_VERSION);
        assert_eq!(back.interface, "hextet0");
        assert_eq!(back.peers.len(), 1);
        assert_eq!(back.peers[0].endpoint, Some(ep("[2001:db8::b]:4193")));
        assert_eq!(back.peers[0].punch_state, "connected");
    }

    #[test]
    fn read_missing_file_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let err = read(&dir.path().join("nope.json")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn endpoint_source_classification() {
        let configured = vec![ep("[2001:db8::1]:4193")];
        let cached = vec![CachedEndpoint {
            endpoint: ep("[2001:db8::7]:4193"),
            last_seen_unix: 1,
        }];
        assert_eq!(endpoint_source(None, &configured, &cached), "none");
        assert_eq!(
            endpoint_source(Some(ep("[2001:db8::1]:4193")), &configured, &cached),
            "config"
        );
        assert_eq!(
            endpoint_source(Some(ep("[2001:db8::7]:4193")), &configured, &cached),
            "cache"
        );
        assert_eq!(
            endpoint_source(Some(ep("[2001:db8:9::9]:4193")), &configured, &cached),
            "roamed"
        );
    }

    #[test]
    fn endpoint_source_ignores_scope_id_differences() {
        let configured = vec![ep("[2001:db8::1]:4193")];
        let with_scope = SocketAddrV6::new("2001:db8::1".parse().unwrap(), 4193, 0, 4);
        assert_eq!(endpoint_source(Some(with_scope), &configured, &[]), "config");
    }

    #[test]
    fn unix_secs_of_epoch_is_zero() {
        assert_eq!(unix_secs(SystemTime::UNIX_EPOCH), 0);
        assert_eq!(
            unix_secs(SystemTime::UNIX_EPOCH + Duration::from_secs(42)),
            42
        );
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-engine state`
Expected: 编译失败，`cannot find type EngineState`。

- [ ] **Step 3: 实现**

`crates/engine/src/lib.rs` 模块声明改为：

```rust
pub mod atomic;
pub mod cache;
pub mod candidates;
pub mod fsm;
pub mod spec;
pub mod state;
```

`crates/engine/src/state.rs`:

```rust
//! 运行时状态快照：daemon 每 tick 原子重写一次，`hextet status` 读它。
//!
//! M2 不做 IPC（见 ADR-0001）：状态文件是 daemon 唯一对外的可观测面。它是
//! **只写不读**的派生数据——daemon 重启后完全从配置与端点缓存重建，因此格式
//! 变更不需要迁移，只需要 [`STATE_VERSION`] 对不上时让读者忽略。

use std::net::{Ipv6Addr, SocketAddrV6};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cache::CachedEndpoint;
use crate::candidates::normalize;

/// 状态文件格式版本。
pub const STATE_VERSION: u32 = 1;

/// daemon 的运行时状态快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineState {
    /// 文件格式版本。
    pub version: u32,
    /// 本次写入时刻（Unix 秒）。读者据此判断 daemon 是否还活着。
    pub updated_unix: u64,
    /// WireGuard 接口名。
    pub interface: String,
    /// 本节点 overlay 地址。
    pub node_address: Ipv6Addr,
    /// 本节点 ed25519 公钥 base64。
    pub node_public_key: String,
    /// 每个 peer 的状态。
    pub peers: Vec<PeerState>,
}

/// 单个 peer 的运行时状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerState {
    /// peer 名。
    pub name: String,
    /// peer 的 ed25519 公钥 base64。
    pub public_key: String,
    /// peer 的 overlay 地址。
    pub address: Ipv6Addr,
    /// 打洞状态机状态："probing" 或 "connected"。
    pub punch_state: String,
    /// 当前 endpoint（`probing` 时是正在试的候选）。
    pub endpoint: Option<SocketAddrV6>,
    /// endpoint 的来源："config" / "cache" / "roamed" / "none"。
    pub endpoint_source: String,
    /// 候选 endpoint 总数。
    pub candidates: usize,
    /// 当前候选下标。
    pub candidate_index: usize,
    /// 已走完的完整轮换轮次数。
    pub rounds: u32,
}

/// 原子写入状态文件。
pub fn write(path: &Path, state: &EngineState) -> std::io::Result<()> {
    crate::atomic::write_json(path, state)
}

/// 读取状态文件。
pub fn read(path: &Path) -> std::io::Result<EngineState> {
    crate::atomic::read_json(path)
}

/// `SystemTime` → Unix 秒（早于 epoch 的时间归零）。
pub fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// 判断当前 endpoint 是从哪来的（供 `hextet status` 展示"这条连接是怎么建起来的"）。
///
/// 判定顺序：配置 → 缓存 → 其余（只能是内核 roaming 学到的新地址）。
pub fn endpoint_source(
    endpoint: Option<SocketAddrV6>,
    configured: &[SocketAddrV6],
    cached: &[CachedEndpoint],
) -> &'static str {
    let Some(ep) = endpoint.map(normalize) else {
        return "none";
    };
    if configured.iter().any(|c| normalize(*c) == ep) {
        return "config";
    }
    if cached.iter().any(|c| normalize(c.endpoint) == ep) {
        return "cache";
    }
    "roamed"
}
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-engine`
Expected: 全部 PASS（新增 5 个）

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 写 `docs/dev/state-files.md`**

```markdown
# daemon 的磁盘状态文件

`hextet daemon` 在 `[node] state_dir`（默认 `/var/lib/hextet`）下维护两个 JSON 文件。
目录由 daemon 首次启动时创建（权限 0700），两个文件均为 0600、写入走
"临时文件 → fsync → rename" 的原子替换（`crates/engine/src/atomic.rs`）。

## endpoints.json —— 端点缓存（持久化软状态）

记录每个 peer "上次能连上的 endpoint"，让重启后的重连走最快路径；也是配置里
没写 endpoint 时唯一的候选来源。

```json
{
  "version": 1,
  "peers": {
    "<peer ed25519 公钥 base64>": {
      "last_good": "[2001:db8::b]:4193",
      "seen": [{ "endpoint": "[2001:db8::b]:4193", "last_seen_unix": 1770000000 }]
    }
  }
}
```

- `last_good`：最近一次被证实可用的 endpoint，排在候选列表最前面。
- `seen`：历史 endpoint，按 `last_seen_unix` 由新到旧，最多 8 条。
- **软状态**：文件缺失、JSON 损坏、`version` 不认识时一律降级为空缓存并写一条
  warn 日志，不影响 daemon 启动。可以随时删除（代价是首次重连慢几秒）。

## state.json —— 运行时状态快照（派生数据）

daemon 每秒重写一次，`hextet status` 读它来补充内核看不到的信息（打洞进度、
endpoint 来源）。

```json
{
  "version": 1,
  "updated_unix": 1770000000,
  "interface": "hextet0",
  "node_address": "fd12:3456:78::1",
  "node_public_key": "<base64>",
  "peers": [
    {
      "name": "b",
      "public_key": "<base64>",
      "address": "fd12:3456:78:abcd::2",
      "punch_state": "connected",
      "endpoint": "[2001:db8::b]:4193",
      "endpoint_source": "config",
      "candidates": 2,
      "candidate_index": 0,
      "rounds": 0
    }
  ]
}
```

- `punch_state`：`probing`（正在轮换候选打洞）或 `connected`（握手新鲜）。
- `endpoint_source`：`config` / `cache` / `roamed` / `none`——`roamed` 表示这个地址
  既不在配置里也不在缓存里，是内核根据已认证的包学到的（对端换了地址）。
- `updated_unix`：`hextet status` 用它判断 daemon 是否还活着（超过 10s 视为已停）。
- **纯派生数据**：删掉不会丢任何东西，daemon 下一秒就重写。

## 为什么是文件而不是 IPC

见 `docs/adr/ADR-0001-m2-daemon-shape.md`。简版：M2 的读者只有本机 CLI，
一个原子写的 JSON 文件就够；unix socket IPC 留到 M5（Web UI/Tauri 真正需要
双向通信时）一次做对。
```

- [ ] **Step 6: 提交**

`CHANGELOG.md` 追加：

```markdown
- hextet-engine：运行时状态快照 `<state_dir>/state.json`（每秒原子重写，含打洞状态与 endpoint 来源）；文档 docs/dev/state-files.md。
```

```bash
git add crates/engine docs/dev/state-files.md CHANGELOG.md
git commit -m "feat(engine): 运行时状态快照文件

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: engine — 守护进程主循环

**Files:**
- Create: `crates/engine/src/daemon.rs`
- Create: `docs/protocol/punching.md`
- Modify: `crates/engine/src/lib.rs`

**Interfaces:**
- Consumes: 前面所有任务的产物 + `hextet_wg::kernel::KernelBackend`、`hextet_platform::{setup_interface, watch_ipv6_addresses, AddrEvent}`
- Produces:
  - `hextet_engine::daemon::run(config_path: &Path) -> anyhow::Result<()>`（阻塞直到收到 SIGINT/SIGTERM；非 Linux 平台直接返回错误）
- 行为契约（Task 9/10 依赖）：
  1. 启动时做的事与 `hextet up` 完全一致（`apply` + `setup_interface`，两者都幂等），因此在已 `up` 的机器上直接启动 daemon 也不会出错；
  2. 退出时**不拆接口**（拆除是 `hextet down` 的职责），只写一行日志；
  3. 每秒写一次 `state.json`；
  4. 收到本机地址变化事件后去抖 200ms，然后对所有 peer 调 `kick`。

- [ ] **Step 1: 本任务不写单元测试（说明 + 替代覆盖）**

`daemon.rs` 只做接线：它的每一个决策都来自已被 Task 5/6/7 单测覆盖的纯逻辑，而它自己需要 root + 真实内核 WireGuard + netlink 才能跑。为它写单测只能靠把 `KernelBackend`/`platform` 全部抽象成 trait 再注入 mock——那层抽象在 M2 没有第二个实现（gotatun 在 M4），属于为测试而生的空转抽象。

**替代覆盖**：Task 10 的 `scripts/netns-e2e-dynamic.sh` 端到端验证这份接线的每一条契约（启动即连通、换前缀 <5s 恢复、仅靠缓存重连、SIGTERM 优雅退出、state.json 内容正确）。

因此本任务的 TDD 红灯是：**先写 Task 10 的 E2E 脚本并确认它失败**——但为避免两个任务互相阻塞，实际执行顺序是「Task 8 实现 → Task 9 接 CLI → Task 10 写 E2E 并跑红→跑绿」。在 Task 8 的完成报告里必须写明「本任务无单测，由 Task 10 E2E 覆盖」。

- [ ] **Step 2: 实现**

`crates/engine/src/lib.rs` 模块声明改为：

```rust
pub mod atomic;
pub mod cache;
pub mod candidates;
pub mod fsm;
pub mod spec;
pub mod state;

#[cfg(target_os = "linux")]
pub mod daemon;

#[cfg(not(target_os = "linux"))]
pub mod daemon {
    //! 非 Linux 平台的守护进程占位（M4 起支持 macOS）。

    use std::path::Path;

    /// 非 Linux 平台暂不支持守护进程。
    pub fn run(_config_path: &Path) -> anyhow::Result<()> {
        anyhow::bail!("hextet daemon 目前仅支持 Linux（macOS 在 M4）")
    }
}
```

`crates/engine/src/daemon.rs`:

```rust
//! 守护进程主循环：把 wg 后端、地址监听、打洞状态机、端点缓存、状态文件接起来。
//!
//! 本文件是 M2 唯一"必须真跑网络才能验证"的部分，由 `scripts/netns-e2e-dynamic.sh`
//! 端到端覆盖；所有判断逻辑都在 `crate::{fsm, candidates, cache, state}` 里且已被单测覆盖。

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::Context as _;
use hextet_core::addr::derive_node_addr;
use hextet_core::config::{Config, load_config_and_identity};
use hextet_core::network::NetworkPrefix;
use hextet_platform::{AddrEvent, setup_interface, watch_ipv6_addresses};
use hextet_wg::WgBackend as _;
use hextet_wg::kernel::KernelBackend;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::cache::EndpointCache;
use crate::candidates::{MAX_CANDIDATES, build_candidates, normalize};
use crate::fsm::{Action, Observation, PeerFsm, PunchState};
use crate::spec::build_device_spec;
use crate::state::{EngineState, PeerState, STATE_VERSION, endpoint_source, unix_secs};

/// 主循环 tick 周期。
const TICK: Duration = Duration::from_secs(1);

/// 本机地址变化事件的去抖窗口。
///
/// PPPoE 重拨换前缀时内核会连发多条 `RTM_NEWADDR`/`RTM_DELADDR`；等 200ms 把这一
/// 串事件吞掉再统一重试，避免对每条事件都发一遍 nudge。
const ADDR_DEBOUNCE: Duration = Duration::from_millis(200);

/// nudge 包的目标端口（RFC 863 discard）。
///
/// nudge 的唯一目的是"让内核 WireGuard 有东西可发"：包本身会被对端丢弃，
/// 但它触发的握手/已认证数据包会让对端学到我们当前的源地址（roaming）。
const NUDGE_PORT: u16 = 9;

/// 每个 peer 的运行时上下文。
struct PeerRuntime {
    name: String,
    key_b64: String,
    wg_public: [u8; 32],
    overlay: Ipv6Addr,
    configured: Vec<SocketAddrV6>,
    fsm: PeerFsm,
}

/// 循环期间不变的上下文。
struct Ctx {
    interface: String,
    node_address: Ipv6Addr,
    node_public_key: String,
    cache_path: PathBuf,
    state_path: PathBuf,
}

/// 启动守护进程，阻塞直到收到 SIGINT/SIGTERM。
pub fn run(config_path: &Path) -> anyhow::Result<()> {
    let rt = tokio::runtime::Runtime::new().context("创建 tokio runtime")?;
    rt.block_on(run_async(config_path))
}

fn ensure_state_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("创建状态目录 {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("设置状态目录权限 {}", dir.display()))?;
    }
    Ok(())
}

/// 内核报告的 endpoint → 归一化后的 `SocketAddrV6`（IPv4 endpoint 直接丢弃）。
fn kernel_endpoint(endpoint: Option<SocketAddr>) -> Option<SocketAddrV6> {
    match endpoint {
        Some(SocketAddr::V6(v6)) => Some(normalize(v6)),
        // hextet 是 IPv6-only 的；内核不该报出 IPv4 endpoint，报了就当没有
        Some(SocketAddr::V4(_)) | None => None,
    }
}

async fn run_async(config_path: &Path) -> anyhow::Result<()> {
    let (cfg, id) = load_config_and_identity(config_path)?;
    let own = derive_node_addr(cfg.prefix, &id.public())?;

    ensure_state_dir(&cfg.node.state_dir)?;
    let ctx = Ctx {
        interface: cfg.node.interface.clone(),
        node_address: own.address,
        node_public_key: id.public().to_base64(),
        cache_path: cfg.node.state_dir.join("endpoints.json"),
        state_path: cfg.node.state_dir.join("state.json"),
    };

    // 1) 数据面就位（与 `hextet up` 同一条路径，两步都幂等）
    let backend = KernelBackend;
    let spec = build_device_spec(&cfg, &id);
    backend
        .apply(&spec)
        .context("配置 WireGuard 设备（需要 root/CAP_NET_ADMIN）")?;
    setup_interface(
        &ctx.interface,
        own.address,
        NetworkPrefix::PREFIX_LEN,
        cfg.node.mtu,
    )
    .await
    .context("配置接口地址/MTU")?;
    info!(
        interface = %ctx.interface,
        address = %own.address,
        peers = cfg.peers.len(),
        "daemon 启动"
    );

    // 2) 端点缓存 + 每 peer 运行时
    let mut cache = EndpointCache::load(&ctx.cache_path);
    let start = SystemTime::now();
    let mut peers: Vec<PeerRuntime> = cfg
        .peers
        .iter()
        .map(|p| {
            let key_b64 = p.public_key.to_base64();
            let entry = cache.entry(&key_b64);
            let cached = entry.map(|e| e.seen.as_slice()).unwrap_or(&[]);
            let candidates = build_candidates(&p.endpoints, cached, entry.and_then(|e| e.last_good));
            let total = p.endpoints.len() + cached.len();
            if total > candidates.len() {
                debug!(
                    peer = %p.name,
                    kept = candidates.len(),
                    limit = MAX_CANDIDATES,
                    "候选 endpoint 去重/截断后减少"
                );
            }
            info!(peer = %p.name, candidates = candidates.len(), "候选 endpoint 就绪");
            PeerRuntime {
                name: p.name.clone(),
                key_b64,
                wg_public: p.public_key.wg_public_bytes(),
                overlay: p.addr.address,
                configured: p.endpoints.clone(),
                fsm: PeerFsm::new(candidates, start),
            }
        })
        .collect();

    // 3) nudge socket：往 overlay 地址发包，逼内核 WireGuard 发握手/已认证包
    let nudge = UdpSocket::bind("[::]:0")
        .await
        .context("绑定 nudge socket")?;

    // 4) 本机地址变化监听（失败只降级，不致命：tick 仍会在 180s 内发现连接失效）
    let (tx, mut addr_rx) = mpsc::channel::<AddrEvent>(64);
    tokio::spawn(async move {
        match watch_ipv6_addresses(tx).await {
            Ok(()) => debug!("IPv6 地址监听正常结束"),
            Err(e) => warn!(error = %e, "IPv6 地址监听退出：换前缀后将退化为 tick 驱动恢复"),
        }
    });

    // 5) 首次触发：让每个 peer 立刻开始握手，而不是等第一次轮换
    let now = SystemTime::now();
    for peer in peers.iter_mut() {
        let actions = peer.fsm.kick(now);
        apply_actions(&backend, &ctx, &nudge, &mut cache, &*peer, &actions).await;
    }

    let mut ticker = tokio::time::interval(TICK);
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("注册 SIGTERM handler")?;

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                tick_once(&backend, &ctx, &nudge, &mut cache, &mut peers).await;
            }
            Some(event) = addr_rx.recv() => {
                debug!(?event, "本机 IPv6 地址变化");
                tokio::time::sleep(ADDR_DEBOUNCE).await;
                let mut extra = 0usize;
                while addr_rx.try_recv().is_ok() {
                    extra += 1;
                }
                let now = SystemTime::now();
                for peer in peers.iter_mut() {
                    let actions = peer.fsm.kick(now);
                    apply_actions(&backend, &ctx, &nudge, &mut cache, &*peer, &actions).await;
                }
                info!(coalesced = extra, "地址变化：已对所有 peer 重新握手/nudge");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("收到 SIGINT");
                break;
            }
            _ = sigterm.recv() => {
                info!("收到 SIGTERM");
                break;
            }
        }
    }

    info!(
        interface = %ctx.interface,
        "daemon 退出（接口保留，用 `hextet down` 拆除）"
    );
    Ok(())
}

async fn tick_once(
    backend: &KernelBackend,
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peers: &mut [PeerRuntime],
) {
    let statuses = match backend.status(&ctx.interface) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "读取 WireGuard 状态失败，跳过本 tick");
            return;
        }
    };
    let by_key: HashMap<[u8; 32], &hextet_wg::types::PeerStatus> =
        statuses.iter().map(|s| (s.wg_public, s)).collect();

    let now = SystemTime::now();
    let mut peer_states = Vec::with_capacity(peers.len());
    for peer in peers.iter_mut() {
        let observed = by_key.get(&peer.wg_public);
        let obs = Observation {
            last_handshake: observed.and_then(|s| s.last_handshake),
            kernel_endpoint: observed.and_then(|s| kernel_endpoint(s.endpoint)),
        };
        let actions = peer.fsm.tick(now, obs);
        apply_actions(backend, ctx, nudge, cache, &*peer, &actions).await;
        peer_states.push(peer_state_of(&*peer, cache));
    }

    let state = EngineState {
        version: STATE_VERSION,
        updated_unix: unix_secs(now),
        interface: ctx.interface.clone(),
        node_address: ctx.node_address,
        node_public_key: ctx.node_public_key.clone(),
        peers: peer_states,
    };
    if let Err(e) = crate::state::write(&ctx.state_path, &state) {
        warn!(path = %ctx.state_path.display(), error = %e, "写状态文件失败");
    }
}

fn peer_state_of(peer: &PeerRuntime, cache: &EndpointCache) -> PeerState {
    let (punch_state, candidate_index, rounds) = match peer.fsm.state() {
        PunchState::Connected { .. } => ("connected", 0usize, 0u32),
        PunchState::Probing {
            candidate_index,
            rounds,
        } => ("probing", candidate_index, rounds),
    };
    let endpoint = peer.fsm.current_candidate();
    let empty: Vec<crate::cache::CachedEndpoint> = Vec::new();
    let cached = cache
        .entry(&peer.key_b64)
        .map(|e| e.seen.as_slice())
        .unwrap_or(&empty);
    PeerState {
        name: peer.name.clone(),
        public_key: peer.key_b64.clone(),
        address: peer.overlay,
        punch_state: punch_state.to_owned(),
        endpoint,
        endpoint_source: endpoint_source(endpoint, &peer.configured, cached).to_owned(),
        candidates: peer.fsm.candidates_len(),
        candidate_index,
        rounds,
    }
}

async fn apply_actions(
    backend: &KernelBackend,
    ctx: &Ctx,
    nudge: &UdpSocket,
    cache: &mut EndpointCache,
    peer: &PeerRuntime,
    actions: &[Action],
) {
    for action in actions {
        match *action {
            Action::SetEndpoint(ep) => {
                match backend.set_peer_endpoint(&ctx.interface, &peer.wg_public, ep) {
                    Ok(()) => debug!(peer = %peer.name, endpoint = %ep, "设置 endpoint"),
                    Err(e) => {
                        warn!(peer = %peer.name, endpoint = %ep, error = %e, "设置 endpoint 失败")
                    }
                }
            }
            Action::Nudge => {
                let target = SocketAddrV6::new(peer.overlay, NUDGE_PORT, 0, 0);
                match nudge.send_to(&[0u8], SocketAddr::V6(target)).await {
                    Ok(_) => debug!(peer = %peer.name, "nudge 已发出"),
                    // 对端还没连通时内核可能返回 ENETUNREACH/EHOSTUNREACH/EPERM，
                    // 这在打洞过程中是常态，不是错误
                    Err(e) => {
                        debug!(peer = %peer.name, error = %e, "nudge 发送失败（打洞中属正常）")
                    }
                }
            }
            Action::MarkGood(ep) => {
                cache.record_good(&peer.key_b64, ep, unix_secs(SystemTime::now()));
                if let Err(e) = cache.save(&ctx.cache_path) {
                    warn!(path = %ctx.cache_path.display(), error = %e, "写端点缓存失败");
                }
                info!(peer = %peer.name, endpoint = %ep, "连接就绪（已记入端点缓存）");
            }
        }
    }
}
```

**借用检查提示**（照抄即可，不要"优化"）：`peers.iter_mut()` 给出的是 `&mut PeerRuntime`，`peer.fsm.tick(..)` 用完可变借用后返回 owned `Vec<Action>`；随后用 `&*peer` 把它重新借为共享引用传给 `apply_actions`，而 `cache` 是独立绑定，因此 `&mut cache` 与 `&*peer` 不冲突。

- [ ] **Step 3: 编译验证**

Run: `cargo build --workspace`
Expected（macOS）: 成功（`daemon` 走非 Linux 占位）
Expected（Linux）: 成功

Run: `cargo xtask ci`
Expected: 全绿（clippy 对 `too_many_arguments` 之类不应触发——`apply_actions` 是 6 参数，阈值是 7）

- [ ] **Step 4: 写 `docs/protocol/punching.md`**

```markdown
# hextet 打洞与端点管理（v1）

状态：已实现（`crates/engine/src/{fsm,candidates}.rs`、`crates/engine/src/daemon.rs` 与本文档同步维护）

## 为什么 IPv6 下打洞是可控的

IPv6 没有 NAT，也就没有端口改写与端口预测：端口永远由自己决定（默认 UDP 4193），
会合记录里**只有地址会变**。剩下的障碍是**状态防火墙**——出站包先建 state，对端
"迟到"的入站包命中 state 即放行。因此打洞不需要独立的信令协议：两端同时发
WireGuard 握手包，握手包本身就是打洞包（设计 spec §4）。

## 端点候选

每个 peer 维护一个有序候选列表，来源三处、按此顺序拼接后去重（归一化后比较），
上限 8 个：

1. `last_good`——端点缓存里最近一次被证实可用的 endpoint（重启后最快路径）；
2. 配置文件 `[[peers]] endpoints` 里的地址，**保持配置顺序**（用户手填的地址是
   设计 spec §3 D3 ⑦ 的终极兜底，必须优先于缓存）；
3. 端点缓存的历史地址，按 `last_seen_unix` 由新到旧。

归一化 = 把 `SocketAddrV6` 的 `flowinfo`/`scope_id` 清零。跨来源（内核 / 配置 /
缓存）比较 endpoint 前必须归一化，否则这两个字段的差异会让"内核 endpoint ≠ 候选"
恒成立。

## 状态机

每个 peer 一个状态机，每秒 tick 一次，输入是内核 WireGuard 报告的
`(last_handshake, endpoint)`：

| 状态 | 条件 | 动作 |
|---|---|---|
| `Probing{i}` | 握手新鲜（<180s） | 转 `Connected`，把当前 endpoint 记入缓存 |
| `Probing{i}` | 距上次切换 ≥2.5s | 切到候选 `i+1`（回绕时轮次 +1），设置 endpoint + nudge |
| `Probing{i}` | 距上次切换 <2.5s | 无动作 |
| `Connected` | 握手过期（≥180s） | 退回 `Probing{0}`，设置 endpoint + nudge |
| `Connected` | 内核 endpoint 变了 | 跟随（对端 roaming），记入缓存 |
| `Connected` | 其余 | 无动作 |

- **2.5s 轮换间隔**：内核 WireGuard 的握手重试间隔是 5s（REKEY_TIMEOUT），2.5s
  保证每个候选在被换掉前至少收到一次我们主动触发的握手初始化。
- **只有一个候选时**「轮换」会回到自己，仍然重发 nudge——否则内核放弃握手后
  （约 90s，MAX_TIMER_HANDSHAKES）就再也不会重试。
- **nudge** = 向该 peer 的 overlay 地址（`[peer]:9`，RFC 863 discard）发一个 1 字节
  UDP 包。包本身会被丢弃，但它让内核 WireGuard 有东西可发：没有会话时触发握手，
  有会话时发出一个用**当前源地址**加密的已认证包。

## 本机地址变化响应（目标 <5s）

daemon 订阅 netlink `RTNLGRP_IPV6_IFADDR`（等价 `ip -6 monitor address`，含
valid-lifetime=0 的静默换前缀）。收到事件后：去抖 200ms 吞掉同一次重拨产生的
事件串 → 对**所有** peer 调 `kick`：

- `Connected` 的 peer 只发 nudge——对端 endpoint 不需要改，我们只要让对端收到一个
  来自新源地址的已认证包，WireGuard 的 roaming 语义就会把对端记录的 endpoint
  更新过来（这是"单侧变化自愈"，无需任何会合）；
- `Probing` 的 peer 重设当前候选并 nudge，重新计时。

因此单侧换前缀的恢复时间 ≈ netlink 事件延迟 + 200ms 去抖 + 一次握手往返，
远小于 5s；不依赖 keepalive（25s）也不依赖握手超时（180s）。

## 双侧同时换前缀

本层不解决——两端的候选都失效时没有任何一方知道对方在哪。M3 的会合链
（mesh peer 转介 / DHT / DDNS / 手动输入）负责补上；在那之前的兜底是
用户在任一侧重填 `[[peers]] endpoints`。

## 不做的事

- 不做端口预测、端口喷射、生日攻击（IPv4 NAT 才需要）；
- 不做 STUN 式地址发现（M2 的候选全部来自配置与缓存；DHT/mDNS 在 M3）；
- 不引入任何路由协议或多跳转发（自有节点中继在 M3，且是显式单跳）。
```

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- hextet-engine：守护进程主循环（每秒 tick、候选轮换打洞、netlink 地址变化去抖后立刻重试、端点缓存与状态文件写入、SIGINT/SIGTERM 优雅退出，退出不拆接口）；协议文档 docs/protocol/punching.md。
```

```bash
git add crates/engine docs/protocol/punching.md CHANGELOG.md
git commit -m "feat(engine): 守护进程主循环 + 打洞协议文档

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: cli — `hextet daemon` 子命令 + `status` 合并 daemon 状态

**Files:**
- Create: `crates/cli/src/commands/daemon.rs`
- Modify: `crates/cli/src/commands/mod.rs`（加 `pub mod daemon;`）
- Modify: `crates/cli/src/commands/status.rs`（重写）
- Modify: `crates/cli/src/main.rs`
- Modify: `crates/cli/tests/spec.rs`（加 `daemon_freshness` 测试）
- Modify: `scripts/netns-e2e.sh`（`--json` 形状变了，jq 路径要跟着改）

**Interfaces:**
- Consumes: `hextet_engine::daemon::run`、`hextet_engine::state::{read, EngineState, PeerState}`
- Produces:
  - `hextet daemon [-c hextet.toml] [-v]`：前台运行守护进程（root）。`-v` 把日志级别从 INFO 提到 DEBUG。
  - `hextet status [-c hextet.toml] [--json]`：合并「内核 WireGuard 状态」与「daemon 状态文件」。
  - `hextet_cli::commands::status::classify`（**签名不变**，既有测试继续用）
  - `hextet_cli::commands::status::daemon_freshness(updated_unix: u64, now_unix: u64) -> (bool, u64)`
  - `--json` 输出形状（**从数组改成对象**，破坏性变更，本 Task 同步改 E2E 脚本与文档）：
    ```json
    {
      "daemon": { "running": true, "updated_secs_ago": 1, "state_file": "/var/lib/hextet/state.json" },
      "peers": [
        {
          "peer": "b", "address": "fd..:2", "endpoint": "[2001:db8::b]:4193",
          "last_handshake_secs": 3, "rx_bytes": 148, "tx_bytes": 212, "state": "connected",
          "endpoint_source": "config", "punch_state": "connected",
          "candidates": 2, "candidate_index": 0
        }
      ]
    }
    ```
    `daemon` 为 `null` 表示状态文件不存在或不可解析；后四个字段在没有 daemon 时为 `null`。

- [ ] **Step 1: 写失败测试**

`crates/cli/tests/spec.rs` 末尾追加：

```rust
#[test]
fn daemon_freshness_classification() {
    use hextet_cli::commands::status::daemon_freshness;

    // 刚写过 → running
    assert_eq!(daemon_freshness(1_000, 1_000), (true, 0));
    assert_eq!(daemon_freshness(1_000, 1_010), (true, 10));
    // 超过 10s 未更新 → 认为 daemon 已停
    assert_eq!(daemon_freshness(1_000, 1_011), (false, 11));
    assert_eq!(daemon_freshness(1_000, 9_999), (false, 8_999));
    // 状态文件时间戳比现在新（时钟回拨）→ 视为 0 秒前，仍算 running
    assert_eq!(daemon_freshness(2_000, 1_000), (true, 0));
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-cli daemon_freshness`
Expected: 编译失败，`cannot find function daemon_freshness`。

- [ ] **Step 3: 实现**

`crates/cli/src/commands/daemon.rs`:

```rust
//! `hextet daemon`：前台运行守护进程（动态端点自愈）。

use std::path::PathBuf;

/// Arguments for the daemon command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 输出 DEBUG 级日志（默认 INFO）
    #[arg(short, long)]
    pub verbose: bool,
}

/// Run the daemon command.
///
/// 前台阻塞运行，收到 SIGINT/SIGTERM 后退出且**不拆除接口**——拆除是
/// `hextet down` 的职责。M4 的 systemd/procd 单元直接调用本命令。
pub fn run(args: Args) -> anyhow::Result<()> {
    let level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .init();
    hextet_engine::daemon::run(&args.config)
}
```

`crates/cli/src/commands/mod.rs`：模块列表加一行（按字母序放最前）：

```rust
pub mod daemon;
```

`crates/cli/src/commands/status.rs` 整体替换：

```rust
//! `hextet status`：peer 连接状态（内核 WireGuard + daemon 状态文件）。

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// 状态文件多久没更新就认为 daemon 已停。
///
/// daemon 每秒重写一次，10s 容忍度足够覆盖负载抖动，又能让"daemon 挂了"
/// 在 10s 内被 status 如实报出来。
const DAEMON_FRESH_SECS: u64 = 10;

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

/// 由状态文件时间戳判断 daemon 是否在跑，以及"多久之前更新的"。
///
/// 时间戳比当前时间新（时钟回拨、或 daemon 与 CLI 看到的时钟有偏差）时按 0 秒前
/// 处理，而不是让 `u64` 减法回绕成一个巨大的数字把 daemon 误报成已停。
pub fn daemon_freshness(updated_unix: u64, now_unix: u64) -> (bool, u64) {
    let secs_ago = now_unix.saturating_sub(updated_unix);
    (secs_ago <= DAEMON_FRESH_SECS, secs_ago)
}

/// Arguments for the status command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// JSON 输出
    #[arg(long)]
    pub json: bool,
}

/// daemon 存活信息（`--json` 的 `daemon` 字段）。
#[cfg(target_os = "linux")]
#[derive(serde::Serialize)]
struct DaemonInfo {
    running: bool,
    updated_secs_ago: u64,
    state_file: String,
}

/// 一行 peer 状态。
#[cfg(target_os = "linux")]
#[derive(serde::Serialize)]
struct StatusRow {
    peer: String,
    address: String,
    endpoint: Option<String>,
    last_handshake_secs: Option<u64>,
    rx_bytes: u64,
    tx_bytes: u64,
    state: &'static str,
    // 以下四项来自 daemon 状态文件，没有 daemon 时为 None
    endpoint_source: Option<String>,
    punch_state: Option<String>,
    candidates: Option<usize>,
    candidate_index: Option<usize>,
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize)]
struct StatusReport {
    daemon: Option<DaemonInfo>,
    peers: Vec<StatusRow>,
}

/// Run the status command.
pub fn run(args: Args) -> anyhow::Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        anyhow::bail!("M2 仅支持 Linux");
    }

    #[cfg(target_os = "linux")]
    {
        use hextet_wg::WgBackend as _;

        let (cfg, _id) = super::load_config_and_identity(&args.config)?;
        let backend = hextet_wg::kernel::KernelBackend;
        let statuses = backend.status(&cfg.node.interface)?;
        let now = SystemTime::now();
        let now_unix = hextet_engine::state::unix_secs(now);

        let state_path = cfg.node.state_dir.join("state.json");
        let engine_state = hextet_engine::state::read(&state_path).ok();
        let daemon = engine_state.as_ref().map(|s| {
            let (running, updated_secs_ago) = daemon_freshness(s.updated_unix, now_unix);
            DaemonInfo {
                running,
                updated_secs_ago,
                state_file: state_path.display().to_string(),
            }
        });

        let rows: Vec<StatusRow> = statuses
            .iter()
            .map(|s| {
                let peer = cfg
                    .peers
                    .iter()
                    .find(|p| p.public_key.wg_public_bytes() == s.wg_public);
                let key_b64 = peer.map(|p| p.public_key.to_base64());
                let engine_peer = engine_state.as_ref().zip(key_b64.as_ref()).and_then(
                    |(state, key)| state.peers.iter().find(|ps| &ps.public_key == key),
                );
                StatusRow {
                    peer: peer.map_or_else(|| "<unknown>".to_string(), |p| p.name.clone()),
                    address: peer.map_or_else(String::new, |p| p.addr.address.to_string()),
                    endpoint: s.endpoint.map(|e| e.to_string()),
                    last_handshake_secs: s
                        .last_handshake
                        .and_then(|t| now.duration_since(t).ok())
                        .map(|d| d.as_secs()),
                    rx_bytes: s.rx_bytes,
                    tx_bytes: s.tx_bytes,
                    state: classify(s.last_handshake, now),
                    endpoint_source: engine_peer.map(|p| p.endpoint_source.clone()),
                    punch_state: engine_peer.map(|p| p.punch_state.clone()),
                    candidates: engine_peer.map(|p| p.candidates),
                    candidate_index: engine_peer.map(|p| p.candidate_index),
                }
            })
            .collect();

        let report = StatusReport { daemon, peers: rows };

        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            match &report.daemon {
                Some(d) if d.running => {
                    println!("daemon   running（状态更新于 {}s 前）", d.updated_secs_ago)
                }
                Some(d) => println!(
                    "daemon   not running（状态文件 {} 停留在 {}s 前）",
                    d.state_file, d.updated_secs_ago
                ),
                None => println!("daemon   not running（无状态文件；动态端点自愈未启用）"),
            }
            println!(
                "{:<12} {:<28} {:<32} {:<8} {:<10} {:>10} {:>8} {:>8}  state",
                "peer", "address", "endpoint", "source", "punch", "handshake", "rx", "tx"
            );
            for r in &report.peers {
                println!(
                    "{:<12} {:<28} {:<32} {:<8} {:<10} {:>10} {:>8} {:>8}  {}",
                    r.peer,
                    r.address,
                    r.endpoint.clone().unwrap_or_default(),
                    r.endpoint_source.clone().unwrap_or_else(|| "-".to_string()),
                    r.punch_state.clone().unwrap_or_else(|| "-".to_string()),
                    r.last_handshake_secs
                        .map_or_else(|| "-".to_string(), |s| format!("{s}s")),
                    r.rx_bytes,
                    r.tx_bytes,
                    r.state
                );
            }
        }
        Ok(())
    }
}
```

`crates/cli/src/main.rs` 整体替换：

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
    /// 建接口、配置 WireGuard 与地址、拉起（仅 Linux）
    Up(hextet_cli::commands::up::Args),
    /// 删除接口
    Down(hextet_cli::commands::down::Args),
    /// 查看 peer 连接状态（仅 Linux）
    Status(hextet_cli::commands::status::Args),
    /// 前台运行守护进程：地址变化监听 + 候选 endpoint 轮换打洞（仅 Linux）
    Daemon(hextet_cli::commands::daemon::Args),
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen(a) => hextet_cli::commands::keygen::run(a),
        Cmd::Init(a) => hextet_cli::commands::init::run(a),
        Cmd::Inspect(a) => hextet_cli::commands::inspect::run(a),
        Cmd::Up(a) => hextet_cli::commands::up::run(a),
        Cmd::Down(a) => hextet_cli::commands::down::run(a),
        Cmd::Status(a) => hextet_cli::commands::status::run(a),
        Cmd::Daemon(a) => hextet_cli::commands::daemon::run(a),
    }
}
```

`scripts/netns-e2e.sh`：两处 jq 路径要改（`--json` 从数组变成对象）。

第 53 行附近，`wait_for_connected` 里：

```bash
      | jq -e '.peers[0].state == "connected"' >/dev/null 2>&1; then
```

第 132 行附近，步骤 5：

```bash
ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a.toml" | jq -e '.peers[0].state == "connected"'
```

（原来是 `.[0].state`。除这两处外脚本不动。）

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-cli`
Expected: 6 个测试全 PASS（含新增 `daemon_freshness_classification`）

Run: `cargo xtask ci`
Expected: 全绿

Run（Linux）: `cargo xtask e2e`
Expected: `E2E OK`——这一步验证 jq 路径改对了；**M1 的 E2E 必须继续绿**。
macOS 上跳过，在报告里写明依赖 CI `e2e` job。

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加两行（一条 Added、一条 Changed；`### Changed` 段不存在就新建在 `### Added` 之后）：

```markdown
### Added
- CLI 命令：`hextet daemon`（前台守护进程：地址变化监听 + 候选 endpoint 轮换打洞，`-v` 开 DEBUG 日志）。

### Changed
- `hextet status --json` 输出从「peer 数组」改为对象 `{ daemon, peers }`，并新增 `endpoint_source`/`punch_state`/`candidates`/`candidate_index` 四列（无 daemon 时为 null）。
```

```bash
git add crates/cli scripts/netns-e2e.sh CHANGELOG.md
git commit -m "feat(cli): hextet daemon 子命令，status 合并 daemon 状态文件

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: E2E — 换前缀 <5s 恢复 + 仅靠缓存重连（阶段 A 验收）

**Files:**
- Create: `scripts/netns-e2e-dynamic.sh`
- Modify: `xtask/src/main.rs`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/dev/build.md`
- Modify: `docs/guides/quickstart.md`
- Modify: `docs/dev/e2e-matrix.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `hextet` 二进制的 `keygen`/`init --state-dir`/`inspect --json`/`daemon`/`status --json`/`down`；`state.json` 与 `endpoints.json` 的字段
- Produces: `cargo xtask e2e dynamic`（root）一键验证阶段 A 全部验收标准

- [ ] **Step 1: 写 E2E 脚本（此时跑必然失败＝TDD 红灯）**

`scripts/netns-e2e-dynamic.sh`（写完执行 `chmod +x scripts/netns-e2e-dynamic.sh`）：

```bash
#!/usr/bin/env bash
# hextet M2 阶段 A E2E：daemon 常驻 → 一侧换前缀 <5s 恢复 → 仅靠端点缓存重连。
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

NS_A=hxt2-a
NS_B=hxt2-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)
# "公网"前缀：A 会从 PREFIX_1 换到 PREFIX_2（模拟 PPPoE 重拨换前缀）
PREFIX_1=2001:db8:1
PREFIX_2=2001:db8:2
# 设计 spec §8 M2 验收：一侧换前缀 <5s 恢复
RECOVERY_BUDGET_MS=5000

A_PID=""
B_PID=""

cleanup() {
  if [ -n "$A_PID" ]; then kill -TERM "$A_PID" 2>/dev/null || true; fi
  if [ -n "$B_PID" ]; then kill -TERM "$B_PID" 2>/dev/null || true; fi
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  # veth 是一对：删任一端即删整对，两端都已转移/已删时是幂等 no-op
  ip link del veth2-a 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  for pair in "a:$NS_A:$TMP/a.toml" "b:$NS_B:$TMP/b.toml"; do
    local_label=${pair%%:*}
    rest=${pair#*:}
    ns=${rest%%:*}
    cfg=${rest#*:}
    echo "--- $local_label: hextet status --json ---" >&2
    ip netns exec "$ns" "$BIN" status --json -c "$cfg" >&2 2>&1 || true
    echo "--- $local_label: wg show all ---" >&2
    ip netns exec "$ns" wg show all >&2 2>&1 || echo "(wg show unavailable)" >&2
    echo "--- $local_label: ip -6 addr / route ---" >&2
    ip netns exec "$ns" ip -6 addr >&2 2>&1 || true
    ip netns exec "$ns" ip -6 route >&2 2>&1 || true
  done
  echo "--- a: state.json ---" >&2
  cat "$TMP/a-state/state.json" >&2 2>&1 || echo "(missing)" >&2
  echo "--- a: endpoints.json ---" >&2
  cat "$TMP/a-state/endpoints.json" >&2 2>&1 || echo "(missing)" >&2
  echo "--- a: daemon log (tail) ---" >&2
  tail -n 80 "$TMP/a.log" >&2 2>&1 || true
  echo "--- b: daemon log (tail) ---" >&2
  tail -n 80 "$TMP/b.log" >&2 2>&1 || true
  echo "===== END DIAGNOSTICS =====" >&2
}

# 等待某侧 status 报 connected（上限 20s：daemon 启动即 nudge，正常 1-3s 内握手）
wait_for_connected() {
  ns=$1; cfg=$2; label=$3
  for i in $(seq 1 20); do
    if ip netns exec "$ns" "$BIN" status --json -c "$cfg" 2>/dev/null \
      | jq -e '.peers[0].state == "connected"' >/dev/null 2>&1; then
      echo "$label: connected after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "$label: 等待 connected 超时" >&2
  return 1
}

# 轮询直到 status 里的 peer endpoint 落在指定前缀上；stdout 只输出耗时(ms)
wait_for_endpoint_prefix() {
  ns=$1; cfg=$2; want=$3; budget_ms=$4; start_ms=$5
  while :; do
    if ip netns exec "$ns" "$BIN" status --json -c "$cfg" 2>/dev/null \
      | jq -e --arg want "[$want" '(.peers[0].endpoint // "") | startswith($want)' \
        >/dev/null 2>&1; then
      echo $(( $(now_ms) - start_ms ))
      return 0
    fi
    if [ $(( $(now_ms) - start_ms )) -gt "$budget_ms" ]; then
      return 1
    fi
    sleep 0.1
  done
}

# 1) 拓扑：ns-a <-veth-> ns-b，PREFIX_1::/64 当"公网"
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth2-a type veth peer name veth2-b
ip link set veth2-a netns "$NS_A"; ip link set veth2-b netns "$NS_B"
# nodad：veth 是自建合成链路无重复地址风险；跳过 DAD 避免地址卡在 tentative
# （tentative 地址不可作出站源地址，会让 WG 用 overlay 地址当源地址造成黑洞，
#   详见 scripts/netns-e2e.sh 里的同一处说明）
ip -n "$NS_A" addr add "${PREFIX_1}::a/64" dev veth2-a nodad
ip -n "$NS_B" addr add "${PREFIX_1}::b/64" dev veth2-b nodad
ip -n "$NS_A" link set lo up; ip -n "$NS_B" link set lo up
ip -n "$NS_A" link set veth2-a up; ip -n "$NS_B" link set veth2-b up
# B 预先知道怎么到达 A 未来的前缀（真实网络里这由上游路由器负责）
ip -n "$NS_B" -6 route replace "${PREFIX_2}::/64" dev veth2-b

# 2) 身份与配置（各自独立 state_dir）
mkdir -p "$TMP/a-state" "$TMP/b-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-dyn --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e-dyn --key-file "$TMP/b.key" --network-key "$NETKEY" \
  --state-dir "$TMP/b-state" --out "$TMP/b.toml"

cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "b"
public_key = "$PK_B"
endpoints = ["[${PREFIX_1}::b]:4193"]
EOF

cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
endpoints = ["[${PREFIX_1}::a]:4193"]
EOF

ADDR_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
ADDR_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$ADDR_A b=$ADDR_B"

# 3) 启动两侧 daemon（前台进程放后台跑，日志落文件）
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

if ! wait_for_connected "$NS_A" "$TMP/a.toml" "a"; then dump_diagnostics; exit 1; fi
if ! wait_for_connected "$NS_B" "$TMP/b.toml" "b"; then dump_diagnostics; exit 1; fi

# 4) daemon 状态文件内容正确
if ! jq -e '.version == 1 and .peers[0].punch_state == "connected"' \
     "$TMP/a-state/state.json" >/dev/null; then
  echo "ERROR: a 的 state.json 未报 connected" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a.toml" \
     | jq -e '.daemon.running == true' >/dev/null; then
  echo "ERROR: status 未识别到运行中的 daemon" >&2; dump_diagnostics; exit 1
fi

# 5) 基线连通
if ! ip netns exec "$NS_A" ping -6 -c 2 -W 5 "$ADDR_B" >/dev/null; then
  echo "ERROR: 基线 ping 失败" >&2; dump_diagnostics; exit 1
fi

# 6) 核心验收：A 换前缀，B 必须在 5s 内把 endpoint 跟到新前缀上
echo "--- 换前缀：a 从 ${PREFIX_1}::a 换到 ${PREFIX_2}::a ---"
T0=$(now_ms)
ip -n "$NS_A" addr add "${PREFIX_2}::a/64" dev veth2-a nodad
ip -n "$NS_A" addr del "${PREFIX_1}::a/64" dev veth2-a
# 删掉旧地址会带走内核自动生成的 on-link 路由，补回到 B 的可达性
# （真实网络里 A 到上游的默认路由不会因为换前缀而消失）
ip -n "$NS_A" -6 route replace "${PREFIX_1}::/64" dev veth2-a

# 轮询预算给到 15s，以便超预算时能报出真实耗时而不是只说"超时"
if ! ELAPSED_MS=$(wait_for_endpoint_prefix "$NS_B" "$TMP/b.toml" "$PREFIX_2" 15000 "$T0"); then
  echo "ERROR: b 在 15s 内未把 a 的 endpoint 更新到 ${PREFIX_2}" >&2
  dump_diagnostics; exit 1
fi
echo "b 观察到 a 的新 endpoint，耗时 ${ELAPSED_MS}ms（预算 ${RECOVERY_BUDGET_MS}ms）"
if [ "$ELAPSED_MS" -gt "$RECOVERY_BUDGET_MS" ]; then
  echo "ERROR: 恢复耗时 ${ELAPSED_MS}ms 超出 ${RECOVERY_BUDGET_MS}ms 预算" >&2
  dump_diagnostics; exit 1
fi

# 恢复后双向仍然通
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A" >/dev/null; then
  echo "ERROR: 换前缀后 b→a ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B" >/dev/null; then
  echo "ERROR: 换前缀后 a→b ping 失败" >&2; dump_diagnostics; exit 1
fi

# 7) 端点缓存已落盘
if ! jq -e 'any(.peers[]; .last_good != null)' "$TMP/a-state/endpoints.json" >/dev/null; then
  echo "ERROR: a 的 endpoints.json 没有 last_good" >&2; dump_diagnostics; exit 1
fi

# 8) SIGTERM 优雅退出（3s 内）
kill -TERM "$A_PID"
for _ in $(seq 1 30); do
  kill -0 "$A_PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$A_PID" 2>/dev/null; then
  echo "ERROR: a 的 daemon 未在 3s 内响应 SIGTERM" >&2; dump_diagnostics; exit 1
fi
wait "$A_PID" 2>/dev/null || true
A_PID=""

# 9) 仅靠端点缓存重连：把配置里 peer 的 endpoints 整行删掉后重启 daemon
grep -v '^endpoints = ' "$TMP/a.toml" >"$TMP/a2.toml"
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a2.toml" >"$TMP/a2.log" 2>&1 &
A_PID=$!
if ! wait_for_connected "$NS_A" "$TMP/a2.toml" "a(仅缓存)"; then
  echo "--- a2 daemon log ---" >&2; tail -n 80 "$TMP/a2.log" >&2 || true
  dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a2.toml" \
     | jq -e '.peers[0].endpoint_source == "cache"' >/dev/null; then
  echo "ERROR: 重连的 endpoint 来源不是 cache" >&2
  ip netns exec "$NS_A" "$BIN" status --json -c "$TMP/a2.toml" >&2 || true
  dump_diagnostics; exit 1
fi

# 10) 收尾：停 daemon、拆接口
kill -TERM "$A_PID" 2>/dev/null || true; wait "$A_PID" 2>/dev/null || true; A_PID=""
kill -TERM "$B_PID" 2>/dev/null || true; wait "$B_PID" 2>/dev/null || true; B_PID=""
ip netns exec "$NS_A" "$BIN" down -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" down -c "$TMP/b.toml"
for ns in "$NS_A" "$NS_B"; do
  if ip -n "$ns" link show hextet0 >/dev/null 2>&1; then
    echo "ERROR: hextet0 still exists in $ns after down" >&2
    exit 1
  fi
done

echo "DYNAMIC E2E OK"
```

- [ ] **Step 2: 跑红灯 → 修到绿**

Run（Linux，root）: `cargo xtask e2e dynamic`（需要先完成 Step 3 的 xtask 改动）
Expected：首轮大概率暴露真实问题。已知的两个坑与**预先批准**的处置方式：

1. **B 侧 endpoint 迟迟不更新，A 的日志显示 nudge 发出但 B 没 roaming**
   → 说明内核 WireGuard 仍在用被删掉的旧源地址（缓存的 `endpoint.src`）。处置：在
   `crates/engine/src/daemon.rs` 的地址变化分支里，`kick` 之前先调一次
   `backend.apply(&spec)`（`replace_peers` 会重建 peer，强制内核重算源地址）。这需要
   把 `spec` 移进循环可见的作用域。**允许**做这个改动，并在 commit message 写明原因。
2. **`ping` 在换前缀瞬间失败一两个包**
   → 正常（路由补回来之前的窗口）。脚本里 ping 已在 endpoint 更新**之后**才发，
   若仍偶发失败，把 `-c 3` 提到 `-c 5` 并保留 `-W 5`。**允许**这个改动。

除上面两条以外的任何偏离，先在报告里说明再改。

macOS 开发机：跳过本地执行，直接推 CI 看 `e2e-dynamic` job。

- [ ] **Step 3: xtask 支持场景参数**

`xtask/src/main.rs` 的 `main` 与 `e2e` 改为：

```rust
fn main() -> Result<()> {
    let task = std::env::args().nth(1).unwrap_or_default();
    match task.as_str() {
        "ci" => ci(),
        "e2e" => e2e(&std::env::args().nth(2).unwrap_or_default()),
        _ => bail!("usage: cargo xtask <ci|e2e [static|dynamic|doctor|all]>"),
    }
}
```

```rust
fn e2e(which: &str) -> Result<()> {
    run("cargo", &["build", "--workspace"])?;
    let scripts: Vec<&str> = match which {
        "" | "all" => vec![
            "scripts/netns-e2e.sh",
            "scripts/netns-e2e-dynamic.sh",
            "scripts/netns-e2e-doctor.sh",
        ],
        "static" => vec!["scripts/netns-e2e.sh"],
        "dynamic" => vec!["scripts/netns-e2e-dynamic.sh"],
        "doctor" => vec!["scripts/netns-e2e-doctor.sh"],
        other => bail!("unknown e2e scenario {other}; use static|dynamic|doctor|all"),
    };
    for script in scripts {
        // 阶段 B 的脚本在阶段 A 期间还不存在：跳过而不是报错
        if !std::path::Path::new(script).exists() {
            eprintln!("skip: {script} (not present)");
            continue;
        }
        run("sudo", &["-E", script])?;
    }
    Ok(())
}
```

- [ ] **Step 4: CI 加 e2e-dynamic job**

`.github/workflows/ci.yml` 末尾追加（与既有 `e2e` job 同级缩进）：

```yaml
  e2e-dynamic:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --workspace
      - run: sudo modprobe wireguard || true
      - run: sudo -E env HEXTET_BIN=target/debug/hextet scripts/netns-e2e-dynamic.sh
```

- [ ] **Step 5: 文档同步**

`docs/dev/build.md` 的 "E2E Tests" 一节，把 `cargo xtask e2e` 那段替换为：

```markdown
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
```

`docs/guides/quickstart.md` 追加一节（放在既有排查章节之前）：

```markdown
## 让连接自己恢复（daemon）

`hextet up` 只配置一次内核就退出，地址一变就断。要让节点在换前缀后自动恢复，
用守护进程代替 `up`：

```console
# 前台跑（Ctrl-C 退出；-v 看详细日志）
$ sudo hextet daemon -c /etc/hextet/home.toml
2026-08-06T12:00:00Z  INFO daemon 启动 interface=hextet0 address=fd.. peers=1
2026-08-06T12:00:01Z  INFO 连接就绪（已记入端点缓存） peer=nas endpoint=[2408:...]:4193
```

daemon 做三件 `up` 不做的事：

1. 监听本机 IPv6 地址变化（PPPoE 重拨换前缀、RA 更新），变化后立刻向所有 peer
   重新握手——对端据此自动跟随（目标 <5s，见 `docs/protocol/punching.md`）；
2. 在多个候选 endpoint 之间轮换打洞（配置里的地址 + 上次连上的地址）；
3. 把"上次能连上的 endpoint"写进 `<state_dir>/endpoints.json`，重启后优先重试它——
   即使配置里根本没写 endpoint 也能重连。

`hextet status` 会显示 daemon 是否在跑，以及每条连接当前 endpoint 的来源
（`config` / `cache` / `roamed`）：

```console
$ sudo hextet status
daemon   running（状态更新于 1s 前）
peer         address                 endpoint              source  punch      handshake   rx    tx  state
nas          fd12:34:56:abcd::2      [2408:...]:4193       config  connected        12s  1.2k  980  connected
```

daemon 退出**不会**拆除接口——拆除仍然是 `sudo hextet down`。状态文件与端点缓存
的位置与格式见 `docs/dev/state-files.md`。
```

`docs/dev/e2e-matrix.md` 在表格下方追加一行说明：

```markdown
CI 的 netns 场景（static / dynamic / doctor）不进本表——本表只记录**真实**
公网 IPv6 双端的手动验收。M2 起需要额外手动验证的项：真实家宽 PPPoE 重拨
（或手动 `ip -6 addr` 换址）后 `hextet status` 在 5s 内恢复 connected。
```

`README.md` 把 "状态：M0/M1 开发中。" 改为：

```markdown
状态：M2 开发中（M0/M1 已完成：身份与地址派生、静态直连）。
```

- [ ] **Step 6: 阶段 A 验收核对并提交**

对照设计 spec §8 M2 验收行逐条核对：

- [ ] netns E2E `dynamic` 绿：一侧换前缀后对端 endpoint 在 5s 内跟随（脚本打印实际耗时）
- [ ] `status` 正确报出 daemon 存活、endpoint 来源与打洞状态
- [ ] 端点缓存生效：删掉配置里的 endpoint 仍能重连，且 `endpoint_source == "cache"`
- [ ] M1 的 `static` E2E 仍绿（未回归）
- [ ] `cargo xtask ci` 全绿

`CHANGELOG.md` 追加：

```markdown
- `scripts/netns-e2e-dynamic.sh`：daemon 常驻 + 换前缀 <5s 恢复 + SIGTERM 优雅退出 + 仅靠端点缓存重连的 netns E2E；`cargo xtask e2e [static|dynamic|doctor|all]`；CI 新增 `e2e-dynamic` job。
- 文档：`docs/dev/state-files.md`、`docs/protocol/punching.md`、quickstart 的 daemon 章节。
```

```bash
git add scripts xtask .github docs README.md CHANGELOG.md
git commit -m "test(e2e): 换前缀恢复与端点缓存重连的 netns E2E（M2 阶段 A 验收）

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## 阶段 A 完成判据

全部满足才能进阶段 B：

1. `cargo xtask ci` 全绿；
2. CI 三个 job（`lint-test`、`e2e`、`e2e-dynamic`）全绿；
3. `scripts/netns-e2e-dynamic.sh` 打印的恢复耗时 <5000ms；
4. 代码里没有 `todo!`/`unimplemented!`/`// TODO`/被跳过的测试；
5. `docs/protocol/punching.md`、`docs/dev/state-files.md` 与实现一致。

---

# 阶段 B：doctor

### Task 11: core — 探针协议编解码 + 探针密钥派生

**Files:**
- Create: `crates/core/src/probe.rs`
- Create: `docs/protocol/doctor-probe.md`
- Modify: `crates/core/src/network.rs`（加 `derive_probe_key`）
- Modify: `crates/core/src/error.rs`（加 `ProbeError`）
- Modify: `crates/core/src/lib.rs`（加 `pub mod probe;`）
- Modify: `crates/core/Cargo.toml`（加 `hmac`）

**Interfaces:**
- Consumes: `NetworkKey`（已有）
- Produces:
  - `hextet_core::network::derive_probe_key(key: &NetworkKey) -> [u8; 32]`
  - `hextet_core::probe::PROBE_PACKET_LEN: usize = 32`
  - `ProbeKind::{Request, Response, Unsolicited}`（线值 1/2/3，`Clone + Copy + PartialEq + Eq + Debug`）
  - `ProbePacket { pub kind: ProbeKind, pub nonce: u64, pub reply_port: u16 }`
    - `encode(&self, probe_key: &[u8; 32]) -> [u8; PROBE_PACKET_LEN]`
    - `decode(bytes: &[u8], probe_key: &[u8; 32]) -> Result<Self, ProbeError>`
  - `ProbeError::{TooShort, BadMagic, BadVersion(u8), BadKind(u8), BadMac}`
- 线格式（32 字节，大端）：

  | 偏移 | 长度 | 字段 |
  |---|---|---|
  | 0 | 4 | magic `HXTP` |
  | 4 | 1 | version = 1 |
  | 5 | 1 | kind：1=Request, 2=Response, 3=Unsolicited |
  | 6 | 8 | nonce（每次探测随机，回包原样带回） |
  | 14 | 2 | reply_port（Request：客户端专门用来收 Unsolicited 的端口；其余为 0） |
  | 16 | 16 | mac = `HMAC-SHA256(probe_key, bytes[0..16])[0..16]` |

- [ ] **Step 1: 写失败测试**

`crates/core/src/probe.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        crate::network::derive_probe_key(
            &crate::network::NetworkKey::from_base64(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            )
            .unwrap(),
        )
    }

    #[test]
    fn frozen_probe_key_vector() {
        // 全零 network key 的探针密钥。改了派生算法就会打破这个断言——
        // 那是协议不兼容变更，必须同步 docs/protocol/doctor-probe.md 与版本号。
        assert_eq!(
            key(),
            [
                0x8c, 0xe2, 0x7a, 0xff, 0xbf, 0x33, 0x6f, 0x05, 0x6d, 0x5c, 0xa3, 0x0a, 0xd6,
                0x49, 0xaa, 0x93, 0x9a, 0x1e, 0x2c, 0x35, 0xb6, 0xc2, 0x8e, 0x1d, 0xeb, 0xa6,
                0xd3, 0xb1, 0xc3, 0xb2, 0x2e, 0x47,
            ]
        );
    }

    #[test]
    fn frozen_wire_vector() {
        let pkt = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 0x0102_0304_0506_0708,
            reply_port: 0x1234,
        };
        let bytes = pkt.encode(&key());
        let expected =
            "4858545001010102030405060708123403ac6ed7c17f6249a9daa95c76e51d18";
        let got: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expected);
        assert_eq!(ProbePacket::decode(&bytes, &key()).unwrap(), pkt);
    }

    #[test]
    fn roundtrip_all_kinds() {
        for kind in [ProbeKind::Request, ProbeKind::Response, ProbeKind::Unsolicited] {
            let pkt = ProbePacket {
                kind,
                nonce: 0xdead_beef_cafe_0001,
                reply_port: 40000,
            };
            let bytes = pkt.encode(&key());
            assert_eq!(bytes.len(), PROBE_PACKET_LEN);
            assert_eq!(ProbePacket::decode(&bytes, &key()).unwrap(), pkt);
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let pkt = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 7,
            reply_port: 1,
        };
        let bytes = pkt.encode(&key());
        let err = ProbePacket::decode(&bytes, &[9u8; 32]).unwrap_err();
        assert!(matches!(err, ProbeError::BadMac), "got {err:?}");
    }

    #[test]
    fn any_flipped_bit_in_the_maced_region_is_rejected() {
        let pkt = ProbePacket {
            kind: ProbeKind::Response,
            nonce: 0x1122_3344_5566_7788,
            reply_port: 0,
        };
        let bytes = pkt.encode(&key());
        for i in 0..PROBE_PACKET_LEN {
            let mut tampered = bytes;
            tampered[i] ^= 0x01;
            let err = ProbePacket::decode(&tampered, &key()).unwrap_err();
            // 前 6 字节被改会先撞上 magic/version/kind 检查，其余一律 BadMac
            assert!(
                matches!(
                    err,
                    ProbeError::BadMac
                        | ProbeError::BadMagic
                        | ProbeError::BadVersion(_)
                        | ProbeError::BadKind(_)
                ),
                "byte {i} tampering slipped through: {err:?}"
            );
        }
    }

    #[test]
    fn short_packet_is_rejected() {
        assert!(matches!(
            ProbePacket::decode(&[0u8; 31], &key()).unwrap_err(),
            ProbeError::TooShort
        ));
        assert!(matches!(
            ProbePacket::decode(&[], &key()).unwrap_err(),
            ProbeError::TooShort
        ));
    }

    #[test]
    fn bad_magic_version_and_kind_are_rejected() {
        let good = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 1,
            reply_port: 2,
        }
        .encode(&key());

        let mut bad_magic = good;
        bad_magic[0] = b'X';
        assert!(matches!(
            ProbePacket::decode(&bad_magic, &key()).unwrap_err(),
            ProbeError::BadMagic
        ));

        let mut bad_version = good;
        bad_version[4] = 2;
        assert!(matches!(
            ProbePacket::decode(&bad_version, &key()).unwrap_err(),
            ProbeError::BadVersion(2)
        ));

        let mut bad_kind = good;
        bad_kind[5] = 9;
        assert!(matches!(
            ProbePacket::decode(&bad_kind, &key()).unwrap_err(),
            ProbeError::BadKind(9)
        ));
    }

    #[test]
    fn longer_datagram_is_accepted_by_ignoring_the_tail() {
        // UDP 收到的包可能带填充；只要前 32 字节合法就接受
        let pkt = ProbePacket {
            kind: ProbeKind::Unsolicited,
            nonce: 5,
            reply_port: 0,
        };
        let mut buf = pkt.encode(&key()).to_vec();
        buf.extend_from_slice(b"trailing junk");
        assert_eq!(ProbePacket::decode(&buf, &key()).unwrap(), pkt);
    }

    proptest::proptest! {
        #[test]
        fn encode_decode_roundtrip(
            kind_idx in 0usize..3,
            nonce in proptest::prelude::any::<u64>(),
            reply_port in proptest::prelude::any::<u16>(),
        ) {
            let kind = [ProbeKind::Request, ProbeKind::Response, ProbeKind::Unsolicited][kind_idx];
            let pkt = ProbePacket { kind, nonce, reply_port };
            let bytes = pkt.encode(&key());
            proptest::prop_assert_eq!(ProbePacket::decode(&bytes, &key()).unwrap(), pkt);
        }
    }
}
```

在 `crates/core/src/network.rs` 的 `mod tests` 里追加：

```rust
    #[test]
    fn probe_key_is_deterministic_and_not_the_network_key() {
        let key = NetworkKey::generate();
        assert_eq!(derive_probe_key(&key), derive_probe_key(&key));
        assert_ne!(derive_probe_key(&key), *key.as_bytes());
        assert_ne!(derive_probe_key(&key), derive_probe_key(&NetworkKey::generate()));
    }
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-core probe`
Expected: 编译失败，`cannot find function derive_probe_key` / `cannot find type ProbePacket`。

- [ ] **Step 3: 实现**

`crates/core/Cargo.toml` 的 `[dependencies]` 追加：

```toml
hmac.workspace = true
```

`crates/core/src/lib.rs` 模块声明改为（**只加 `probe` 一行**；`doctor` 模块到 Task 13 才存在，提前声明会编译失败）：

```rust
pub mod addr;
pub mod config;
pub mod defaults;
pub mod error;
pub mod identity;
pub mod network;
pub mod probe;
```

`crates/core/src/error.rs` 追加：

```rust
/// doctor 探针报文错误。
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// 数据报短于固定长度。
    #[error("probe packet too short")]
    TooShort,
    /// magic 不是 `HXTP`。
    #[error("probe packet has wrong magic")]
    BadMagic,
    /// 协议版本不认识。
    #[error("unsupported probe version {0}")]
    BadVersion(u8),
    /// 报文类型不认识。
    #[error("unknown probe kind {0}")]
    BadKind(u8),
    /// MAC 校验失败（密钥不对或报文被篡改）。
    #[error("probe packet MAC verification failed")]
    BadMac,
}
```

`crates/core/src/network.rs`：`use` 段追加 `use hkdf::Hkdf;`（已有）——只需在文件末尾（`mod tests` 之前）追加自由函数：

```rust
/// 派生 doctor 探针的 HMAC 密钥。
///
/// 不直接用 network key 给探针做 MAC：网络密钥还 gate 着 DHT 记录的派生与加密
/// （M3），一把密钥只干一件事，任何一处的实现失误都不至于牵连另一处。
pub fn derive_probe_key(key: &NetworkKey) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(SALT), key.as_bytes());
    let mut out = [0u8; 32];
    hk.expand(b"doctor-probe", &mut out)
        .expect("32 bytes is a valid hkdf length");
    out
}
```

`crates/core/src/probe.rs`:

```rust
//! doctor 探针报文（协议规范：docs/protocol/doctor-probe.md）。
//!
//! 32 字节定长、HMAC 认证、无状态。存在的唯一目的是让**对端节点**帮本机判定
//! 入站策略：先回一个"已请求"的包证明状态防火墙路径通，再从另一个源端口发一个
//! "未经请求"的包看能不能进来。没有任何项目方服务器参与。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::ProbeError;

/// 探针报文固定长度。
pub const PROBE_PACKET_LEN: usize = 32;

/// 参与 MAC 计算的前缀长度（magic..reply_port）。
const MACED_LEN: usize = 16;
/// 截断后的 MAC 长度。
const MAC_LEN: usize = 16;
/// 报文 magic。
const MAGIC: [u8; 4] = *b"HXTP";
/// 协议版本。
const VERSION: u8 = 1;

type HmacSha256 = Hmac<Sha256>;

/// 报文类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    /// 客户端 → 对端：请求回探。
    Request,
    /// 对端 → 客户端：对 Request 的直接回复（走客户端已建立的出站 state）。
    Response,
    /// 对端 → 客户端：**未经请求**的包，从另一个源端口发向 `reply_port`。
    Unsolicited,
}

impl ProbeKind {
    fn as_u8(self) -> u8 {
        match self {
            Self::Request => 1,
            Self::Response => 2,
            Self::Unsolicited => 3,
        }
    }

    fn from_u8(v: u8) -> Result<Self, ProbeError> {
        match v {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Unsolicited),
            other => Err(ProbeError::BadKind(other)),
        }
    }
}

/// 一个探针报文。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePacket {
    /// 报文类型。
    pub kind: ProbeKind,
    /// 本次探测的随机 nonce，回包原样带回（用来把回包与本次探测配对）。
    pub nonce: u64,
    /// `Request` 里客户端希望收 `Unsolicited` 的 UDP 端口；其余类型为 0。
    pub reply_port: u16,
}

impl ProbePacket {
    /// 编码为线格式。
    pub fn encode(&self, probe_key: &[u8; 32]) -> [u8; PROBE_PACKET_LEN] {
        let mut out = [0u8; PROBE_PACKET_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4] = VERSION;
        out[5] = self.kind.as_u8();
        out[6..14].copy_from_slice(&self.nonce.to_be_bytes());
        out[14..16].copy_from_slice(&self.reply_port.to_be_bytes());
        let mut mac = HmacSha256::new_from_slice(probe_key)
            .expect("HMAC accepts keys of any length");
        mac.update(&out[..MACED_LEN]);
        let tag = mac.finalize().into_bytes();
        out[MACED_LEN..MACED_LEN + MAC_LEN].copy_from_slice(&tag[..MAC_LEN]);
        out
    }

    /// 解析线格式并校验 MAC。
    ///
    /// 长于 [`PROBE_PACKET_LEN`] 的数据报只看前 32 字节（尾部填充忽略）。
    pub fn decode(bytes: &[u8], probe_key: &[u8; 32]) -> Result<Self, ProbeError> {
        if bytes.len() < PROBE_PACKET_LEN {
            return Err(ProbeError::TooShort);
        }
        if bytes[0..4] != MAGIC {
            return Err(ProbeError::BadMagic);
        }
        if bytes[4] != VERSION {
            return Err(ProbeError::BadVersion(bytes[4]));
        }
        let kind = ProbeKind::from_u8(bytes[5])?;
        let mut mac = HmacSha256::new_from_slice(probe_key)
            .expect("HMAC accepts keys of any length");
        mac.update(&bytes[..MACED_LEN]);
        // verify_truncated_left 是常量时间比较，不要换成 == 手写比较
        mac.verify_truncated_left(&bytes[MACED_LEN..MACED_LEN + MAC_LEN])
            .map_err(|_| ProbeError::BadMac)?;
        let nonce = u64::from_be_bytes(
            bytes[6..14].try_into().expect("slice is exactly 8 bytes"),
        );
        let reply_port = u16::from_be_bytes(
            bytes[14..16].try_into().expect("slice is exactly 2 bytes"),
        );
        Ok(Self {
            kind,
            nonce,
            reply_port,
        })
    }
}
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-core`
Expected: 全部 PASS（probe 新增 9 个含 1 个 proptest，network 新增 1 个）

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 写 `docs/protocol/doctor-probe.md`**

```markdown
# hextet doctor 探针协议（v1）

状态：已实现（`crates/core/src/probe.rs`、`crates/engine/src/{probe_responder,doctor_client}.rs` 与本文档同步维护）

## 它解决什么问题

`hextet doctor` 要回答"本机的 IPv6 入站是开放的、只放行已请求流量的（状态防火墙）、
还是全被拦的"。这个判断**必须由外部视角给出**——本机自己看不见自己的入站策略。
而 hextet 没有任何项目方服务器（设计 spec §2 目标 2），所以外部视角只能来自
**同一网络里的另一个节点**。

## 端口

- 响应器监听 `[node] probe_port`（默认 **4194**）。
- 为什么不复用 WireGuard 的 4193：内核 WireGuard 独占那个 UDP 端口，用户态无法
  在同端口上收自己的包。
- 因此本协议测的是"任意 UDP 端口的入站策略"，而不是 4193 本身。住宅 CPE 与光猫
  的默认丢弃规则不区分端口，这个代理指标是可靠的；`doctor` 的输出会说明这一点。

## 线格式（32 字节定长，大端）

| 偏移 | 长度 | 字段 | 说明 |
|---|---|---|---|
| 0 | 4 | magic | ASCII `HXTP` |
| 4 | 1 | version | 1 |
| 5 | 1 | kind | 1=Request, 2=Response, 3=Unsolicited |
| 6 | 8 | nonce | 每次探测随机；回包原样带回 |
| 14 | 2 | reply_port | Request：客户端收 Unsolicited 的端口；其余为 0 |
| 16 | 16 | mac | `HMAC-SHA256(probe_key, bytes[0..16])` 截断前 16 字节 |

- `probe_key = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("doctor-probe", 32)`
- MAC 校验用常量时间比较；校验失败的包**静默丢弃**，不回任何东西（不给探测者
  任何"这里有个 hextet 节点"的信号）。
- 长于 32 字节的数据报只解析前 32 字节。
- 冻结测试向量见 `crates/core/src/probe.rs::tests::{frozen_probe_key_vector, frozen_wire_vector}`。

## 交换流程

客户端（判定**自己**的入站策略）绑两个 UDP socket：

- `S1`：用来发 Request、收 Response；
- `S2`：**只收不发**，端口号写进 Request 的 `reply_port`。

```
客户端 A                                        对端 B（运行 daemon）
  S1 ─── Request{nonce=N, reply_port=P(S2)} ───────► :4194
  S1 ◄── Response{nonce=N}  （源端口 4194）──────── :4194      ① 已请求路径
  S2 ◄── Unsolicited{nonce=N}（源端口=另一个临时端口）──── 新 socket   ② 未经请求路径
```

- ① 之所以能回来，是因为 A 从 S1 发出的 Request 已经在 A 的防火墙上建了 state；
  它证明"A 的出站 + 回包"这条路通（也顺带证明 B 活着、密钥一致）。
- ② 从**另一个源端口**发向 A 从未发过包的 `reply_port`，因此不匹配 A 的任何
  conntrack 条目——只有 A 的防火墙放行未经请求的入站时才会到达。
- B 在收到 Request 后延迟 300ms 再发 ②，确保 A 已在 S2 上等待。
- 客户端每 700ms 重发 Request 直到收到 Response 或超时（默认 5s），容忍丢包。

## 分类

| 有全局 IPv6 | ② 到达 | ① 到达 | 结论 |
|---|---|---|---|
| 否 | — | — | `no-ipv6` |
| 是 | 是 | — | `open` |
| 是 | 否 | 是 | `stateful` |
| 是 | 否 | 否 | `blocked` |

`blocked` 是**合并结论**：可能是本机入站全被拦，也可能是对端没在跑 daemon、
网络密钥不一致、或对端不可达——单靠一个对端无法区分。`doctor` 的输出会如实
列出这三种可能，并建议换一个对端再试。

## 安全性

- **认证**：非网络成员发的包过不了 MAC 校验，直接丢弃。
- **放大**：1 个 Request（32B）最多触发 2 个 32B 回包 = 2× 放大，且需要有效 MAC；
  响应器另外对**每个源 IP 限速 1 次/秒**（表上限 64 项，超出时清理 60s 前的旧条目），
  把它压到可忽略。
- **隐私**：报文里没有公钥、没有节点名、没有 overlay 地址；nonce 是一次性随机数。
- **不放行入站**：响应器只是一个 UDP socket，不改任何防火墙规则。

## 不做的事

- 不做 STUN 式"告诉我我的公网地址"（M2 的候选 endpoint 全部来自配置与缓存）；
- 不做多对端交叉验证（需要 M3 的 gossip 才有节点列表）；
- 不测 TCP、不测 ICMP、不测 4193 本身。
```

- [ ] **Step 6: 提交**

`CHANGELOG.md` 追加：

```markdown
- hextet-core：doctor 探针协议编解码（32 字节定长、HMAC-SHA256 截断认证、常量时间校验）与探针密钥派生 `derive_probe_key`；协议文档 docs/protocol/doctor-probe.md。
```

```bash
git add crates/core docs/protocol/doctor-probe.md CHANGELOG.md
git commit -m "feat(core): doctor 探针协议编解码与探针密钥派生

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: engine — 探针响应器

**Files:**
- Create: `crates/engine/src/probe_responder.rs`
- Modify: `crates/engine/src/lib.rs`（加 `pub mod probe_responder;`）

**Interfaces:**
- Consumes: `hextet_core::probe::{ProbePacket, ProbeKind, PROBE_PACKET_LEN}`
- Produces:
  - `pub const UNSOLICITED_DELAY: Duration = Duration::from_millis(300)`
  - `pub const MIN_REQUEST_INTERVAL: Duration = Duration::from_secs(1)`
  - `RateLimiter::{new() -> Self, allow(&mut self, ip: Ipv6Addr, now: Instant) -> bool, tracked(&self) -> usize}`（`Default` 也实现）
  - `pub async fn serve(socket: UdpSocket, probe_key: [u8; 32]) -> std::io::Result<()>`（永不正常返回；只有 socket 读失败才返回 `Err`）
- 行为契约：
  1. MAC 校验失败、非 `Request`、限速命中 → **静默丢弃**，一个字节都不回；
  2. 合法 `Request` → 立刻从**同一个 socket**（源端口 = probe_port）回 `Response`；
  3. `reply_port != 0` 时，额外 spawn 一个任务，延迟 300ms 后用**新建的临时 socket**（源端口是随机的）向 `[源IP]:reply_port` 发 `Unsolicited`。

- [ ] **Step 1: 写失败测试**

`crates/engine/src/probe_responder.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn rate_limiter_allows_then_denies_then_allows() {
        let mut limiter = RateLimiter::new();
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let t0 = Instant::now();
        assert!(limiter.allow(ip, t0));
        assert!(!limiter.allow(ip, t0 + Duration::from_millis(500)));
        assert!(!limiter.allow(ip, t0 + Duration::from_millis(999)));
        assert!(limiter.allow(ip, t0 + Duration::from_millis(1_001)));
    }

    #[test]
    fn rate_limiter_tracks_ips_independently() {
        let mut limiter = RateLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.allow("2001:db8::1".parse().unwrap(), t0));
        assert!(limiter.allow("2001:db8::2".parse().unwrap(), t0));
        assert!(!limiter.allow("2001:db8::1".parse().unwrap(), t0));
    }

    #[test]
    fn rate_limiter_table_stays_bounded() {
        let mut limiter = RateLimiter::new();
        let t0 = Instant::now();
        for i in 0..500u32 {
            let ip: Ipv6Addr = format!("2001:db8::{i:x}").parse().unwrap();
            limiter.allow(ip, t0 + Duration::from_millis(u64::from(i)));
        }
        assert!(
            limiter.tracked() <= RATE_TABLE_MAX,
            "table grew to {}",
            limiter.tracked()
        );
    }

    /// 端到端（loopback，无需 root）：Request → Response + Unsolicited。
    #[tokio::test]
    async fn responder_answers_and_sends_unsolicited() {
        let responder = UdpSocket::bind("[::1]:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();
        tokio::spawn(async move { serve(responder, key()).await });

        let s1 = UdpSocket::bind("[::1]:0").await.unwrap();
        let s2 = UdpSocket::bind("[::1]:0").await.unwrap();
        let reply_port = s2.local_addr().unwrap().port();

        let request = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 0xabcd,
            reply_port,
        }
        .encode(&key());
        s1.send_to(&request, responder_addr).await.unwrap();

        // ① 已请求路径：Response 回到 s1
        let mut buf = [0u8; 128];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), s1.recv_from(&mut buf))
            .await
            .expect("2s 内应收到 Response")
            .unwrap();
        let resp = ProbePacket::decode(&buf[..n], &key()).unwrap();
        assert_eq!(resp.kind, ProbeKind::Response);
        assert_eq!(resp.nonce, 0xabcd);

        // ② 未经请求路径：Unsolicited 到达 s2（loopback 无防火墙，必达）
        let (n, src) = tokio::time::timeout(Duration::from_secs(2), s2.recv_from(&mut buf))
            .await
            .expect("2s 内应收到 Unsolicited")
            .unwrap();
        let unsol = ProbePacket::decode(&buf[..n], &key()).unwrap();
        assert_eq!(unsol.kind, ProbeKind::Unsolicited);
        assert_eq!(unsol.nonce, 0xabcd);
        // 必须来自另一个源端口，否则它会命中客户端的出站 state，测不出"未经请求"
        assert_ne!(src.port(), responder_addr.port());
    }

    #[tokio::test]
    async fn responder_ignores_bad_mac_and_non_request() {
        let responder = UdpSocket::bind("[::1]:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();
        tokio::spawn(async move { serve(responder, key()).await });

        let s1 = UdpSocket::bind("[::1]:0").await.unwrap();

        // 密钥不对
        let bad = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 1,
            reply_port: 0,
        }
        .encode(&[9u8; 32]);
        s1.send_to(&bad, responder_addr).await.unwrap();

        // 类型不是 Request
        let wrong_kind = ProbePacket {
            kind: ProbeKind::Response,
            nonce: 2,
            reply_port: 0,
        }
        .encode(&key());
        s1.send_to(&wrong_kind, responder_addr).await.unwrap();

        // 完全不是探针
        s1.send_to(b"hello", responder_addr).await.unwrap();

        let mut buf = [0u8; 128];
        let got = tokio::time::timeout(Duration::from_millis(500), s1.recv_from(&mut buf)).await;
        assert!(got.is_err(), "响应器不该回任何东西，却收到了 {got:?}");
    }

    #[tokio::test]
    async fn responder_skips_unsolicited_when_reply_port_is_zero() {
        let responder = UdpSocket::bind("[::1]:0").await.unwrap();
        let responder_addr = responder.local_addr().unwrap();
        tokio::spawn(async move { serve(responder, key()).await });

        let s1 = UdpSocket::bind("[::1]:0").await.unwrap();
        let request = ProbePacket {
            kind: ProbeKind::Request,
            nonce: 5,
            reply_port: 0,
        }
        .encode(&key());
        s1.send_to(&request, responder_addr).await.unwrap();

        let mut buf = [0u8; 128];
        // 只应收到一个 Response，之后没有第二个包
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), s1.recv_from(&mut buf))
            .await
            .expect("应收到 Response")
            .unwrap();
        assert_eq!(
            ProbePacket::decode(&buf[..n], &key()).unwrap().kind,
            ProbeKind::Response
        );
        let extra =
            tokio::time::timeout(Duration::from_millis(600), s1.recv_from(&mut buf)).await;
        assert!(extra.is_err(), "reply_port=0 时不该有 Unsolicited");
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-engine probe_responder`
Expected: 编译失败，`cannot find type RateLimiter` / `cannot find function serve`。

- [ ] **Step 3: 实现**

`crates/engine/src/lib.rs` 模块声明改为：

```rust
pub mod atomic;
pub mod cache;
pub mod candidates;
pub mod fsm;
pub mod probe_responder;
pub mod spec;
pub mod state;
```

（`daemon` 的两段 cfg 声明保持在后面不动。）

`crates/engine/src/probe_responder.rs`:

```rust
//! doctor 探针响应器（协议规范：docs/protocol/doctor-probe.md）。
//!
//! daemon 常开这个 socket，让网络内其他节点能请它"回探"，从而判定对方的入站
//! 策略。它只是一个 UDP socket：不改任何防火墙规则，不放行任何入站流量。

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

use hextet_core::probe::{ProbeKind, ProbePacket};
use tokio::net::UdpSocket;
use tracing::debug;

/// 收到 Request 后延迟多久发 Unsolicited。
///
/// 给客户端留出把"专门收 Unsolicited 的 socket"准备好的时间；同时让两个回包
/// 在时间上明显分开，便于抓包排查。
pub const UNSOLICITED_DELAY: Duration = Duration::from_millis(300);

/// 同一源 IP 两次请求之间的最小间隔。
pub const MIN_REQUEST_INTERVAL: Duration = Duration::from_secs(1);

/// 限速表条目上限（防止被大量伪造源 IP 撑爆内存）。
const RATE_TABLE_MAX: usize = 64;

/// 清理限速表时丢弃多久之前的条目。
const RATE_ENTRY_TTL: Duration = Duration::from_secs(60);

/// 按源 IP 限速的简易计数器。
#[derive(Debug, Default)]
pub struct RateLimiter {
    seen: HashMap<Ipv6Addr, Instant>,
}

impl RateLimiter {
    /// 新建空限速器。
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    /// 当前跟踪的源 IP 数量（可观测性/测试用）。
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }

    /// 是否放行来自 `ip` 的这次请求。
    pub fn allow(&mut self, ip: Ipv6Addr, now: Instant) -> bool {
        if let Some(prev) = self.seen.get(&ip) {
            if now.duration_since(*prev) < MIN_REQUEST_INTERVAL {
                return false;
            }
        }
        if self.seen.len() >= RATE_TABLE_MAX {
            self.seen
                .retain(|_, t| now.duration_since(*t) < RATE_ENTRY_TTL);
            // 清理后仍然满：整表清空。宁可让限速短暂放宽，也不让表无界增长——
            // 报文本身只有 32 字节且需要有效 MAC，放宽的风险远小于内存耗尽。
            if self.seen.len() >= RATE_TABLE_MAX {
                self.seen.clear();
            }
        }
        self.seen.insert(ip, now);
        true
    }
}

/// 在给定 socket 上提供探针服务，直到读取出错。
///
/// 校验失败、类型不对、限速命中的包一律静默丢弃——不给探测者任何
/// "这个地址上有 hextet 节点"的信号。
pub async fn serve(socket: UdpSocket, probe_key: [u8; 32]) -> std::io::Result<()> {
    let mut limiter = RateLimiter::new();
    let mut buf = [0u8; 128];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let SocketAddr::V6(src6) = src else {
            // hextet 是 IPv6-only 的
            continue;
        };
        let Ok(packet) = ProbePacket::decode(&buf[..n], &probe_key) else {
            continue;
        };
        if packet.kind != ProbeKind::Request {
            continue;
        }
        if !limiter.allow(*src6.ip(), Instant::now()) {
            debug!(peer = %src6.ip(), "探针请求被限速");
            continue;
        }

        // ① 已请求路径：从本 socket 直接回，命中对方的出站 state
        let response = ProbePacket {
            kind: ProbeKind::Response,
            nonce: packet.nonce,
            reply_port: 0,
        }
        .encode(&probe_key);
        if let Err(e) = socket.send_to(&response, src).await {
            debug!(peer = %src6.ip(), error = %e, "回 Response 失败");
        }

        // ② 未经请求路径：延迟后用新的临时 socket（另一个源端口）发向 reply_port
        if packet.reply_port != 0 {
            let target =
                SocketAddrV6::new(*src6.ip(), packet.reply_port, 0, src6.scope_id());
            let nonce = packet.nonce;
            tokio::spawn(async move {
                tokio::time::sleep(UNSOLICITED_DELAY).await;
                match UdpSocket::bind("[::]:0").await {
                    Ok(sock) => {
                        let unsolicited = ProbePacket {
                            kind: ProbeKind::Unsolicited,
                            nonce,
                            reply_port: 0,
                        }
                        .encode(&probe_key);
                        if let Err(e) =
                            sock.send_to(&unsolicited, SocketAddr::V6(target)).await
                        {
                            debug!(target = %target, error = %e, "发 Unsolicited 失败");
                        }
                    }
                    Err(e) => debug!(error = %e, "绑定临时 socket 失败"),
                }
            });
        }
    }
}
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-engine probe_responder`
Expected: 6 个测试 PASS（其中两个 async 测试各需 ~0.3-0.6s）

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- hextet-engine：doctor 探针响应器（回 Response + 延迟从另一源端口发 Unsolicited；按源 IP 限速 1 次/秒、限速表有界；校验失败静默丢弃）。
```

```bash
git add crates/engine CHANGELOG.md
git commit -m "feat(engine): doctor 探针响应器

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: core 分类 + engine 探针客户端

**Files:**
- Create: `crates/core/src/doctor.rs`
- Create: `crates/engine/src/doctor_client.rs`
- Modify: `crates/core/src/lib.rs`（加 `pub mod doctor;`）
- Modify: `crates/engine/src/lib.rs`（加 `pub mod doctor_client;`）

**Interfaces:**
- Produces（core）：
  - `Reachability::{NoIpv6, Open, Stateful, Blocked}`，`#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]`，序列化为 `"no-ipv6"/"open"/"stateful"/"blocked"`，另有 `pub fn as_str(&self) -> &'static str`
  - `ProbeEvidence { pub has_global_ipv6: bool, pub solicited_ok: bool, pub unsolicited_ok: bool }`，`#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]`
  - `pub fn classify(evidence: &ProbeEvidence) -> Reachability`
- Produces（engine）：
  - `pub const REQUEST_RETRY_INTERVAL: Duration = Duration::from_millis(700)`
  - `ProbeOutcome { pub reachability: Reachability, pub evidence: ProbeEvidence, pub target: SocketAddrV6, pub global_addresses: Vec<Ipv6Addr> }`
  - `pub async fn probe_peer(target: SocketAddrV6, probe_key: &[u8; 32], timeout: Duration, global_addresses: Vec<Ipv6Addr>) -> std::io::Result<ProbeOutcome>`
- 分类真值表（与 `docs/protocol/doctor-probe.md` 一致，顺序即优先级）：
  1. `!has_global_ipv6` → `NoIpv6`
  2. `unsolicited_ok` → `Open`
  3. `solicited_ok` → `Stateful`
  4. 否则 → `Blocked`

- [ ] **Step 1: 写失败测试**

`crates/core/src/doctor.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(global: bool, solicited: bool, unsolicited: bool) -> ProbeEvidence {
        ProbeEvidence {
            has_global_ipv6: global,
            solicited_ok: solicited,
            unsolicited_ok: unsolicited,
        }
    }

    #[test]
    fn no_global_ipv6_dominates() {
        // 没有公网 IPv6 时其他证据无意义：先解决"根本没地址"这件事
        assert_eq!(classify(&evidence(false, true, true)), Reachability::NoIpv6);
        assert_eq!(classify(&evidence(false, false, false)), Reachability::NoIpv6);
    }

    #[test]
    fn unsolicited_means_open() {
        assert_eq!(classify(&evidence(true, true, true)), Reachability::Open);
        // 未经请求的包能进来，就算 Response 丢了也说明入站是开放的
        assert_eq!(classify(&evidence(true, false, true)), Reachability::Open);
    }

    #[test]
    fn solicited_only_means_stateful() {
        assert_eq!(classify(&evidence(true, true, false)), Reachability::Stateful);
    }

    #[test]
    fn nothing_arrives_means_blocked() {
        assert_eq!(classify(&evidence(true, false, false)), Reachability::Blocked);
    }

    #[test]
    fn as_str_matches_serde() {
        for (r, s) in [
            (Reachability::NoIpv6, "no-ipv6"),
            (Reachability::Open, "open"),
            (Reachability::Stateful, "stateful"),
            (Reachability::Blocked, "blocked"),
        ] {
            assert_eq!(r.as_str(), s);
            assert_eq!(serde_json::to_string(&r).unwrap(), format!("\"{s}\""));
        }
    }
}
```

`crates/core/Cargo.toml` 的 `[dev-dependencies]` 追加（上面的测试用了 serde_json）：

```toml
serde_json.workspace = true
```

`crates/engine/src/doctor_client.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [11u8; 32]
    }

    fn localhost() -> Vec<Ipv6Addr> {
        // classify 只看"有没有全局地址"，loopback 测试里塞一个假的文档地址即可
        vec!["2001:db8::1".parse().unwrap()]
    }

    /// loopback 上没有任何防火墙：两条路径都应通 → open。
    #[tokio::test]
    async fn probe_against_real_responder_reports_open() {
        let responder = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let port = responder.local_addr().unwrap().port();
        tokio::spawn(async move {
            crate::probe_responder::serve(responder, key()).await
        });

        let target = SocketAddrV6::new("::1".parse().unwrap(), port, 0, 0);
        let outcome = probe_peer(target, &key(), Duration::from_secs(3), localhost())
            .await
            .unwrap();
        assert!(outcome.evidence.solicited_ok, "{outcome:?}");
        assert!(outcome.evidence.unsolicited_ok, "{outcome:?}");
        assert_eq!(outcome.reachability, Reachability::Open);
        assert_eq!(outcome.target, target);
    }

    /// 没人应答（对端没跑 daemon / 不可达 / 本机出站被拦）→ blocked。
    #[tokio::test]
    async fn probe_against_nobody_reports_blocked() {
        // 先绑再释放，拿一个几乎确定没人监听的端口
        let port = {
            let s = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
            s.local_addr().unwrap().port()
        };
        let target = SocketAddrV6::new("::1".parse().unwrap(), port, 0, 0);
        let outcome = probe_peer(target, &key(), Duration::from_millis(800), localhost())
            .await
            .unwrap();
        assert!(!outcome.evidence.solicited_ok);
        assert!(!outcome.evidence.unsolicited_ok);
        assert_eq!(outcome.reachability, Reachability::Blocked);
    }

    /// 密钥不一致时对端静默丢弃 → 客户端什么都收不到 → blocked。
    #[tokio::test]
    async fn mismatched_network_key_reports_blocked() {
        let responder = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let port = responder.local_addr().unwrap().port();
        tokio::spawn(async move {
            crate::probe_responder::serve(responder, [99u8; 32]).await
        });

        let target = SocketAddrV6::new("::1".parse().unwrap(), port, 0, 0);
        let outcome = probe_peer(target, &key(), Duration::from_millis(800), localhost())
            .await
            .unwrap();
        assert_eq!(outcome.reachability, Reachability::Blocked);
    }

    /// 本机没有全局 IPv6 时，无论探测结果如何都先报 no-ipv6。
    #[tokio::test]
    async fn no_global_address_reports_no_ipv6() {
        let responder = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let port = responder.local_addr().unwrap().port();
        tokio::spawn(async move {
            crate::probe_responder::serve(responder, key()).await
        });

        let target = SocketAddrV6::new("::1".parse().unwrap(), port, 0, 0);
        let outcome = probe_peer(target, &key(), Duration::from_secs(3), vec![])
            .await
            .unwrap();
        assert_eq!(outcome.reachability, Reachability::NoIpv6);
        // 证据仍然如实记录（便于诊断"有 daemon 但本机没地址"）
        assert!(outcome.evidence.solicited_ok);
    }
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-core doctor && cargo test -p hextet-engine doctor_client`
Expected: 两处都编译失败（`cannot find type Reachability` / `cannot find function probe_peer`）。

- [ ] **Step 3: 实现**

`crates/core/src/lib.rs` 模块声明改为（现在 `doctor` 存在了）：

```rust
pub mod addr;
pub mod config;
pub mod defaults;
pub mod doctor;
pub mod error;
pub mod identity;
pub mod network;
pub mod probe;
```

`crates/core/src/doctor.rs`:

```rust
//! 入站可达性分类（协议规范：docs/protocol/doctor-probe.md）。

use serde::Serialize;

/// 本机 IPv6 入站可达性。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Reachability {
    /// 本机没有可用的公网 IPv6（GUA）——先解决这个，其他都是后话。
    #[serde(rename = "no-ipv6")]
    NoIpv6,
    /// 未经请求的入站包也能进来：可被动可达。
    #[serde(rename = "open")]
    Open,
    /// 只有"已请求"的回包能进来（住宅 CPE / 光猫 IPv6 SPI 的常态）。
    /// 打洞成立，裸监听不成立。
    #[serde(rename = "stateful")]
    Stateful,
    /// 连自己发出去的请求的回包都收不到，或对端没应答。
    #[serde(rename = "blocked")]
    Blocked,
}

impl Reachability {
    /// 稳定的短字符串形式（与 `--json` 里的取值一致）。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoIpv6 => "no-ipv6",
            Self::Open => "open",
            Self::Stateful => "stateful",
            Self::Blocked => "blocked",
        }
    }
}

/// 一次探测收集到的证据。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProbeEvidence {
    /// 本机是否有可用的公网 IPv6 地址。
    pub has_global_ipv6: bool,
    /// 对端对我们的 Request 的直接回复是否到达（证明"出站+回包"这条路通）。
    pub solicited_ok: bool,
    /// 对端从另一个源端口发来的未经请求的包是否到达。
    pub unsolicited_ok: bool,
}

/// 由证据得出结论。
pub fn classify(evidence: &ProbeEvidence) -> Reachability {
    if !evidence.has_global_ipv6 {
        return Reachability::NoIpv6;
    }
    if evidence.unsolicited_ok {
        return Reachability::Open;
    }
    if evidence.solicited_ok {
        return Reachability::Stateful;
    }
    Reachability::Blocked
}
```

`crates/engine/src/lib.rs` 模块声明改为：

```rust
pub mod atomic;
pub mod cache;
pub mod candidates;
pub mod doctor_client;
pub mod fsm;
pub mod probe_responder;
pub mod spec;
pub mod state;
```

`crates/engine/src/doctor_client.rs`:

```rust
//! doctor 探针客户端：请对端回探，收集证据，得出本机入站可达性。

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use hextet_core::doctor::{ProbeEvidence, Reachability, classify};
use hextet_core::probe::{ProbeKind, ProbePacket};
use rand_core::RngCore as _;
use tokio::net::UdpSocket;
use tracing::debug;

/// Request 的重发间隔（容忍单个包丢失）。
pub const REQUEST_RETRY_INTERVAL: Duration = Duration::from_millis(700);

/// 一次探测的完整结果。
#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    /// 结论。
    pub reachability: Reachability,
    /// 得出结论所依据的证据。
    pub evidence: ProbeEvidence,
    /// 被探测的对端探针地址。
    pub target: SocketAddrV6,
    /// 本机的公网 IPv6 地址列表。
    pub global_addresses: Vec<Ipv6Addr>,
}

/// 请 `target` 上的对端响应器回探本机。
///
/// 绑两个 socket：`s1` 发 Request 并收 Response（走本机已建立的出站 state），
/// `s2` **只收不发**，其端口写进 Request 的 `reply_port`——对端会从另一个源端口
/// 向它发一个未经请求的包，只有本机放行未经请求的入站时才能收到。
///
/// `global_addresses` 由调用方提供（`hextet_platform::list_global_ipv6`），
/// 这样本函数保持平台无关、可在任何机器上用 loopback 测试。
pub async fn probe_peer(
    target: SocketAddrV6,
    probe_key: &[u8; 32],
    timeout: Duration,
    global_addresses: Vec<Ipv6Addr>,
) -> std::io::Result<ProbeOutcome> {
    let s1 = UdpSocket::bind("[::]:0").await?;
    let s2 = UdpSocket::bind("[::]:0").await?;
    let reply_port = s2.local_addr()?.port();
    let nonce = rand_core::OsRng.next_u64();
    let request = ProbePacket {
        kind: ProbeKind::Request,
        nonce,
        reply_port,
    }
    .encode(probe_key);

    let mut solicited_ok = false;
    let mut unsolicited_ok = false;
    let mut buf1 = [0u8; 128];
    let mut buf2 = [0u8; 128];

    // interval 的第一次 tick 立即触发，因此第一个 Request 由循环发出
    let mut retry = tokio::time::interval(REQUEST_RETRY_INTERVAL);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    while !(solicited_ok && unsolicited_ok) {
        tokio::select! {
            _ = &mut deadline => break,
            _ = retry.tick() => {
                if !solicited_ok {
                    if let Err(e) = s1.send_to(&request, SocketAddr::V6(target)).await {
                        debug!(target = %target, error = %e, "发 Request 失败");
                    }
                }
            }
            received = s1.recv_from(&mut buf1) => match received {
                Ok((n, _)) => {
                    if let Ok(p) = ProbePacket::decode(&buf1[..n], probe_key) {
                        if p.kind == ProbeKind::Response && p.nonce == nonce {
                            solicited_ok = true;
                        }
                    }
                }
                // 目标端口无人监听时内核会把 ICMP port-unreachable 转成一次
                // recv 错误：这正是"没人应答"的证据，继续等超时而不是提前返回
                Err(e) => debug!(error = %e, "s1 收包出错（继续等待）"),
            },
            received = s2.recv_from(&mut buf2) => match received {
                Ok((n, _)) => {
                    if let Ok(p) = ProbePacket::decode(&buf2[..n], probe_key) {
                        if p.kind == ProbeKind::Unsolicited && p.nonce == nonce {
                            unsolicited_ok = true;
                        }
                    }
                }
                Err(e) => debug!(error = %e, "s2 收包出错（继续等待）"),
            },
        }
    }

    let evidence = ProbeEvidence {
        has_global_ipv6: !global_addresses.is_empty(),
        solicited_ok,
        unsolicited_ok,
    };
    Ok(ProbeOutcome {
        reachability: classify(&evidence),
        evidence,
        target,
        global_addresses,
    })
}
```

**注意**：`while !(solicited_ok && unsolicited_ok)` 意味着「两条证据都拿到就提前结束」；只拿到 `solicited_ok` 时必须等满 `timeout` 才能断定 `stateful`——这是刻意的，缩短这个等待会把 `open` 误判成 `stateful`。

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-core doctor`
Expected: 5 个测试 PASS

Run: `cargo test -p hextet-engine doctor_client`
Expected: 4 个测试 PASS（`probe_against_nobody` 与 `mismatched_network_key` 各耗 ~0.8s）

Run: `cargo xtask ci`
Expected: 全绿

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- hextet-core：入站可达性分类（no-ipv6/open/stateful/blocked）；hextet-engine：doctor 探针客户端（双 socket 收集已请求/未经请求两条路径的证据，700ms 重发容忍丢包）。
```

```bash
git add crates/core crates/engine CHANGELOG.md
git commit -m "feat: 入站可达性分类与 doctor 探针客户端

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: cli — `hextet doctor` 子命令 + daemon 接线响应器

**Files:**
- Create: `crates/cli/src/commands/doctor.rs`
- Modify: `crates/cli/src/commands/mod.rs`
- Modify: `crates/cli/src/main.rs`
- Modify: `crates/cli/tests/cli.rs`
- Modify: `crates/engine/src/daemon.rs`（启动探针响应器）

**Interfaces:**
- Consumes: `hextet_engine::doctor_client::probe_peer`、`hextet_engine::probe_responder::serve`、`hextet_core::network::derive_probe_key`、`hextet_platform::list_global_ipv6`
- Produces:
  - `hextet doctor [-c hextet.toml] [--peer <NAME>] [--probe-endpoint <[ADDR]:PORT>] [--timeout <SECS>] [--json]`
  - `hextet doctor --serve [-c hextet.toml]`（前台运行响应器，供对端探测；daemon 已在跑时不需要它）
  - `--json` 形状：
    ```json
    {
      "reachability": "stateful",
      "target": "[2001:db8:1::b]:4194",
      "evidence": { "has_global_ipv6": true, "solicited_ok": true, "unsolicited_ok": false },
      "global_addresses": ["2001:db8:1::a"]
    }
    ```
  - 退出码：探测成功即 `0`（无论结论是 open/stateful/blocked——分类不是失败）；只有参数错误/无法确定目标/socket 失败才非 0。
- daemon 侧新增行为：启动时绑 `[::]:probe_port` 并 spawn 响应器；绑定失败只 warn（数据面不受影响）。

- [ ] **Step 1: 写失败测试**

`crates/cli/tests/cli.rs` 末尾追加：

```rust
/// 无法确定探针目标时必须给出可操作的报错，而不是 panic 或静默成功。
#[test]
fn doctor_without_known_endpoint_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    let cfg = dir.path().join("hextet.toml");
    hextet().args(["keygen", "--out"]).arg(&key).assert().success();
    hextet()
        .args(["init", "--name", "t", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg)
        .assert()
        .success();

    // 加一个没有 endpoints 的 peer
    let peer_pk = {
        let peer_key = dir.path().join("peer.key");
        let out = hextet()
            .args(["keygen", "--out"])
            .arg(&peer_key)
            .output()
            .unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("public-key: ").map(str::to_owned))
            .unwrap()
    };
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str(&format!("\n[[peers]]\nname = \"nas\"\npublic_key = \"{peer_pk}\"\n"));
    std::fs::write(&cfg, text).unwrap();

    hextet()
        .args(["doctor", "-c"])
        .arg(&cfg)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--probe-endpoint"));
}

/// 没有 peer 也没有 --probe-endpoint 时同样要清楚报错。
#[test]
fn doctor_without_peers_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    let cfg = dir.path().join("hextet.toml");
    hextet().args(["keygen", "--out"]).arg(&key).assert().success();
    hextet()
        .args(["init", "--name", "t", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg)
        .assert()
        .success();

    hextet()
        .args(["doctor", "-c"])
        .arg(&cfg)
        .assert()
        .failure()
        .stderr(predicate::str::contains("配置里没有任何 peer"));
}

/// IPv4 的 --probe-endpoint 必须被拒绝（hextet 是 IPv6-only 的）。
#[test]
fn doctor_rejects_ipv4_probe_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("node.key");
    let cfg = dir.path().join("hextet.toml");
    hextet().args(["keygen", "--out"]).arg(&key).assert().success();
    hextet()
        .args(["init", "--name", "t", "--key-file"])
        .arg(&key)
        .args(["--out"])
        .arg(&cfg)
        .assert()
        .success();

    hextet()
        .args(["doctor", "-c"])
        .arg(&cfg)
        .args(["--probe-endpoint", "1.2.3.4:4194"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("IPv6-only"));
}
```

- [ ] **Step 2: 运行确认失败**

Run: `cargo test -p hextet-cli doctor`
Expected: 三个测试都失败——`hextet doctor` 子命令还不存在，clap 报 `unrecognized subcommand`。

- [ ] **Step 3: 实现**

`crates/cli/src/commands/doctor.rs`:

```rust
//! `hextet doctor`：判定本机 IPv6 入站可达性（协议见 docs/protocol/doctor-probe.md）。

use std::net::{SocketAddr, SocketAddrV6};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context as _, bail};
use hextet_core::config::Config;
use hextet_core::network::derive_probe_key;

/// Arguments for the doctor command.
#[derive(clap::Args)]
pub struct Args {
    /// 配置文件
    #[arg(short, long, default_value = "hextet.toml")]
    pub config: PathBuf,
    /// 请哪个 peer 回探（配置里只有一个 peer 时可省略）
    #[arg(long)]
    pub peer: Option<String>,
    /// 直接指定对端探针地址，形如 `[2001:db8::b]:4194`（优先于 --peer）
    #[arg(long)]
    pub probe_endpoint: Option<String>,
    /// 等待回包的秒数
    #[arg(long, default_value_t = 5)]
    pub timeout: u64,
    /// JSON 输出
    #[arg(long)]
    pub json: bool,
    /// 前台运行探针响应器，供对端探测（daemon 已在跑时不需要）
    #[arg(long)]
    pub serve: bool,
}

/// 解析要探测的对端探针地址。
///
/// 优先级：`--probe-endpoint` → peer 当前的内核 endpoint（Linux，best-effort）
/// → peer 配置里的第一个 endpoint。端口一律用本机 `[node] probe_port`
/// （假设全网用同一个探针端口；不一致时用 `--probe-endpoint` 覆盖）。
fn resolve_target(cfg: &Config, args: &Args) -> anyhow::Result<SocketAddrV6> {
    if let Some(raw) = &args.probe_endpoint {
        return match raw.parse::<SocketAddr>() {
            Ok(SocketAddr::V6(v6)) => Ok(v6),
            Ok(SocketAddr::V4(_)) => {
                bail!("--probe-endpoint {raw} 是 IPv4 地址；hextet 是 IPv6-only 的")
            }
            Err(_) => bail!("--probe-endpoint {raw} 不是合法的 `[IPv6]:端口`"),
        };
    }

    if cfg.peers.is_empty() {
        bail!(
            "配置里没有任何 peer，无法请对端回探；\
             用 --probe-endpoint '[对端IPv6]:{}' 手动指定",
            cfg.node.probe_port
        );
    }
    let peer = match &args.peer {
        Some(name) => cfg
            .peers
            .iter()
            .find(|p| &p.name == name)
            .with_context(|| format!("配置里没有名为 {name} 的 peer"))?,
        None if cfg.peers.len() == 1 => &cfg.peers[0],
        None => bail!(
            "配置里有 {} 个 peer，用 --peer <名字> 指定请谁回探",
            cfg.peers.len()
        ),
    };

    let mut ip = None;
    // 内核当前记录的 endpoint 比配置更新（对端可能已经 roaming 过）
    #[cfg(target_os = "linux")]
    {
        use hextet_wg::WgBackend as _;
        let backend = hextet_wg::kernel::KernelBackend;
        if let Ok(statuses) = backend.status(&cfg.node.interface) {
            let want = peer.public_key.wg_public_bytes();
            ip = statuses
                .iter()
                .find(|s| s.wg_public == want)
                .and_then(|s| match s.endpoint {
                    Some(SocketAddr::V6(v6)) => Some(*v6.ip()),
                    _ => None,
                });
        }
    }
    let ip = ip.or_else(|| peer.endpoints.first().map(|e| *e.ip()));
    let Some(ip) = ip else {
        bail!(
            "peer {} 没有可用的探针地址：配置里没写 endpoint，内核也还没学到；\
             用 --probe-endpoint '[对端IPv6]:{}' 手动指定",
            peer.name,
            cfg.node.probe_port
        );
    };
    Ok(SocketAddrV6::new(ip, cfg.node.probe_port, 0, 0))
}

#[derive(serde::Serialize)]
struct DoctorReport {
    reachability: hextet_core::doctor::Reachability,
    target: String,
    evidence: hextet_core::doctor::ProbeEvidence,
    global_addresses: Vec<String>,
}

/// Run the doctor command.
pub fn run(args: Args) -> anyhow::Result<()> {
    let (cfg, _id) = super::load_config_and_identity(&args.config)?;
    let probe_key = derive_probe_key(&cfg.network_key);
    let rt = tokio::runtime::Runtime::new()?;

    if args.serve {
        let bind = SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, cfg.node.probe_port, 0, 0);
        println!("探针响应器监听 {bind}（Ctrl-C 退出）");
        return rt.block_on(async move {
            let socket = tokio::net::UdpSocket::bind(bind)
                .await
                .with_context(|| format!("绑定探针端口 {}", cfg.node.probe_port))?;
            hextet_engine::probe_responder::serve(socket, probe_key)
                .await
                .context("探针响应器退出")
        });
    }

    let target = resolve_target(&cfg, &args)?;
    let outcome = rt.block_on(async {
        // 排除 hextet 自己的接口：它上面的 overlay 地址是 ULA，不是公网 endpoint
        let global = hextet_platform::list_global_ipv6(Some(&cfg.node.interface))
            .await
            .context("枚举本机公网 IPv6 地址")?;
        hextet_engine::doctor_client::probe_peer(
            target,
            &probe_key,
            Duration::from_secs(args.timeout),
            global,
        )
        .await
        .context("执行探针交换")
    })?;

    if args.json {
        let report = DoctorReport {
            reachability: outcome.reachability,
            target: outcome.target.to_string(),
            evidence: outcome.evidence,
            global_addresses: outcome
                .global_addresses
                .iter()
                .map(ToString::to_string)
                .collect(),
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("探针对端   {}", outcome.target);
    println!(
        "公网 IPv6  {}",
        if outcome.global_addresses.is_empty() {
            "（无）".to_string()
        } else {
            outcome
                .global_addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "已请求回包 {}",
        if outcome.evidence.solicited_ok { "到达" } else { "未到达" }
    );
    println!(
        "未请求入站 {}",
        if outcome.evidence.unsolicited_ok { "到达" } else { "未到达" }
    );
    println!("结论       {}", outcome.reachability.as_str());
    println!();
    match outcome.reachability {
        hextet_core::doctor::Reachability::Open => println!(
            "入站开放：本机可被动可达，打洞与裸监听都成立。"
        ),
        hextet_core::doctor::Reachability::Stateful => println!(
            "状态防火墙（住宅 CPE / 光猫 IPv6 SPI 的常态）：\n\
             打洞成立（双向同时发包即可），裸入站监听不成立。这是正常且够用的状态。"
        ),
        hextet_core::doctor::Reachability::Blocked => println!(
            "拿不到任何回包。三种可能，请逐一排除：\n\
             1. 对端没在跑 hextet daemon（或没跑 `hextet doctor --serve`）；\n\
             2. 两侧网络密钥不一致（校验失败的探针包会被静默丢弃）；\n\
             3. 本机出站 UDP 或对端入站被拦。\n\
             换一个对端再试一次能区分 1/2 与 3。"
        ),
        hextet_core::doctor::Reachability::NoIpv6 => println!(
            "本机没有可用的公网 IPv6（GUA）。hextet 依赖双端各自有 GUA，\n\
             先解决这个：检查 `ip -6 addr`、光猫/路由器的 IPv6 与 PD 配置。"
        ),
    }
    println!("详细指引（含中国光猫 IPv6 SPI 关闭教程）：docs/guides/doctor.md");
    Ok(())
}
```

`crates/cli/src/commands/mod.rs`：模块列表加 `pub mod doctor;`（按字母序，在 `down` 之前）。

`crates/cli/src/main.rs`：`Cmd` 枚举与 `match` 各加一项：

```rust
    /// 判定本机 IPv6 入站可达性（open/stateful/blocked），或用 --serve 当回探响应器
    Doctor(hextet_cli::commands::doctor::Args),
```

```rust
        Cmd::Doctor(a) => hextet_cli::commands::doctor::run(a),
```

`crates/engine/src/daemon.rs`：两处改动。

1. `use` 段追加：

```rust
use hextet_core::network::derive_probe_key;
```

2. 在「3) nudge socket」之后、「4) 本机地址变化监听」之前插入：

```rust
    // 3.5) 探针响应器：让网络内其他节点能请本机回探（hextet doctor 的对端侧）
    let probe_bind = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, cfg.node.probe_port, 0, 0);
    match UdpSocket::bind(probe_bind).await {
        Ok(socket) => {
            let probe_key = derive_probe_key(&cfg.network_key);
            info!(port = cfg.node.probe_port, "探针响应器已启动");
            tokio::spawn(async move {
                if let Err(e) = crate::probe_responder::serve(socket, probe_key).await {
                    warn!(error = %e, "探针响应器退出：对端将无法用 hextet doctor 探测本机");
                }
            });
        }
        // 端口被占（例如同时跑着 `hextet doctor --serve`）只影响 doctor，
        // 数据面完全不受影响，因此不致命
        Err(e) => warn!(
            port = cfg.node.probe_port,
            error = %e,
            "绑定探针端口失败，跳过探针响应器"
        ),
    }
```

- [ ] **Step 4: 运行测试通过**

Run: `cargo test -p hextet-cli`
Expected: 9 个测试全 PASS（既有 6 个 + 新增 3 个 doctor 测试）

Run: `cargo xtask ci`
Expected: 全绿

Run（Linux，手工冒烟）：两个终端各跑一次，确认互相探测能出 `open`：

```bash
# 终端 1（对端侧）
sudo ./target/debug/hextet doctor --serve -c b.toml
# 终端 2（本机侧，同一台机器上用 ::1 也能验证协议链路）
./target/debug/hextet doctor -c a.toml --probe-endpoint '[::1]:4194' --json
```
Expected: `reachability` 为 `open`（loopback 无防火墙）。注意本机没有公网 IPv6 时会
先报 `no-ipv6`——那属正确行为，真正的三分类由 Task 15 的 netns E2E 验证。

- [ ] **Step 5: 提交**

`CHANGELOG.md` 追加：

```markdown
- CLI 命令：`hextet doctor`（请对端回探判定本机入站可达性：open/stateful/blocked/no-ipv6，含 `--json`、`--probe-endpoint`、`--serve` 响应器模式）；`hextet daemon` 常开探针响应器。
```

```bash
git add crates/cli crates/engine CHANGELOG.md
git commit -m "feat(cli): hextet doctor 子命令，daemon 常开探针响应器

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 15: E2E — 状态防火墙打洞 + doctor 三分类（M2 验收）

**Files:**
- Create: `scripts/netns-e2e-doctor.sh`
- Create: `docs/guides/doctor.md`
- Create: `docs/adr/ADR-0001-m2-daemon-shape.md`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/guides/quickstart.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `hextet daemon`、`hextet doctor --json`、`hextet status --json`
- Produces: `cargo xtask e2e doctor`（root，需要 `nft`）一键验证 M2 剩余两条验收标准

- [ ] **Step 1: 写 E2E 脚本（跑红灯）**

`scripts/netns-e2e-doctor.sh`（写完 `chmod +x`）：

```bash
#!/usr/bin/env bash
# hextet M2 阶段 B E2E：双侧状态防火墙下仍能打洞互连 + doctor 三分类正确。
# 需要：Linux、root、内核 wireguard 模块、nftables（nft）、jq。
set -euo pipefail

NS_A=hxt3-a
NS_B=hxt3-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)
PREFIX=2001:db8:3

A_PID=""
B_PID=""

cleanup() {
  if [ -n "$A_PID" ]; then kill -TERM "$A_PID" 2>/dev/null || true; fi
  if [ -n "$B_PID" ]; then kill -TERM "$B_PID" 2>/dev/null || true; fi
  ip netns del "$NS_A" 2>/dev/null || true
  ip netns del "$NS_B" 2>/dev/null || true
  ip link del veth3-a 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }
command -v nft >/dev/null || { echo "nft (nftables) required" >&2; exit 1; }

# 状态防火墙：住宅 CPE / 光猫 IPv6 SPI 的常态——只放行已请求流量。
#
# 两个关键细节：
# - 用 iifname（字符串匹配）而不是 iif（索引匹配）：规则在 hextet0 存在之前就要
#   装上，iif 会因为查不到接口而加载失败。
# - 必须放行 iifname "hextet0"：只防火墙"公网"侧。解密后的 overlay 流量会再走一遍
#   input hook，若不放行，对端主动发起的 ping 会被当成 ct state new 丢掉。
apply_stateful_fw() {
  ip netns exec "$1" nft -f - <<'EOF'
table inet hxt {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    iifname "hextet0" accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
    ct state established,related accept
  }
}
EOF
}

# 入站全拦：连自己请求的回包都不放行（部分光猫关不掉防火墙时的最坏情况）。
apply_blocked_fw() {
  ip netns exec "$1" nft -f - <<'EOF'
table inet hxt {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    iifname "hextet0" accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
  }
}
EOF
}

clear_fw() {
  ip netns exec "$1" nft delete table inet hxt 2>/dev/null || true
}

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  for pair in "a:$NS_A:$TMP/a.toml" "b:$NS_B:$TMP/b.toml"; do
    label=${pair%%:*}; rest=${pair#*:}; ns=${rest%%:*}; cfg=${rest#*:}
    echo "--- $label: hextet status --json ---" >&2
    ip netns exec "$ns" "$BIN" status --json -c "$cfg" >&2 2>&1 || true
    echo "--- $label: nft list ruleset ---" >&2
    ip netns exec "$ns" nft list ruleset >&2 2>&1 || true
    echo "--- $label: conntrack (udp) ---" >&2
    ip netns exec "$ns" conntrack -L -p udp >&2 2>&1 || echo "(conntrack tool unavailable)" >&2
  done
  echo "--- a: daemon log (tail) ---" >&2; tail -n 60 "$TMP/a.log" >&2 2>&1 || true
  echo "--- b: daemon log (tail) ---" >&2; tail -n 60 "$TMP/b.log" >&2 2>&1 || true
  echo "===== END DIAGNOSTICS =====" >&2
}

wait_for_connected() {
  ns=$1; cfg=$2; label=$3
  for i in $(seq 1 25); do
    if ip netns exec "$ns" "$BIN" status --json -c "$cfg" 2>/dev/null \
      | jq -e '.peers[0].state == "connected"' >/dev/null 2>&1; then
      echo "$label: connected after ${i}s"
      return 0
    fi
    sleep 1
  done
  echo "$label: 等待 connected 超时" >&2
  return 1
}

assert_reachability() {
  ns=$1; cfg=$2; peer=$3; want=$4; label=$5
  if ! out=$(ip netns exec "$ns" "$BIN" doctor -c "$cfg" --peer "$peer" \
              --timeout 4 --json 2>"$TMP/doctor.err"); then
    echo "ERROR: doctor 执行失败（$label）" >&2
    cat "$TMP/doctor.err" >&2
    return 1
  fi
  got=$(echo "$out" | jq -r .reachability)
  if [ "$got" != "$want" ]; then
    echo "ERROR: $label 期望 $want，实际 $got" >&2
    echo "$out" >&2
    return 1
  fi
  echo "$label: reachability=$got"
}

# 1) 拓扑
ip netns add "$NS_A"; ip netns add "$NS_B"
ip link add veth3-a type veth peer name veth3-b
ip link set veth3-a netns "$NS_A"; ip link set veth3-b netns "$NS_B"
ip -n "$NS_A" addr add "${PREFIX}::a/64" dev veth3-a nodad
ip -n "$NS_B" addr add "${PREFIX}::b/64" dev veth3-b nodad
ip -n "$NS_A" link set lo up; ip -n "$NS_B" link set lo up
ip -n "$NS_A" link set veth3-a up; ip -n "$NS_B" link set veth3-b up

# 2) 身份与配置
mkdir -p "$TMP/a-state" "$TMP/b-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-doc --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e-doc --key-file "$TMP/b.key" --network-key "$NETKEY" \
  --state-dir "$TMP/b-state" --out "$TMP/b.toml"

cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "b"
public_key = "$PK_B"
endpoints = ["[${PREFIX}::b]:4193"]
EOF

cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
endpoints = ["[${PREFIX}::a]:4193"]
EOF

ADDR_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
ADDR_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)

# 3) 验收一：双侧状态防火墙**先**装上，再启动 daemon —— 必须靠打洞连通
echo "--- 双侧装状态防火墙，然后启动 daemon ---"
apply_stateful_fw "$NS_A"
apply_stateful_fw "$NS_B"

ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

if ! wait_for_connected "$NS_A" "$TMP/a.toml" "a(防火墙后)"; then dump_diagnostics; exit 1; fi
if ! wait_for_connected "$NS_B" "$TMP/b.toml" "b(防火墙后)"; then dump_diagnostics; exit 1; fi
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$ADDR_B" >/dev/null; then
  echo "ERROR: 防火墙后 a→b ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$ADDR_A" >/dev/null; then
  echo "ERROR: 防火墙后 b→a ping 失败" >&2; dump_diagnostics; exit 1
fi
echo "验收一通过：双侧状态防火墙下打洞互连成功"

# 4) 验收二之一：doctor 在状态防火墙下应报 stateful
if ! assert_reachability "$NS_A" "$TMP/a.toml" b stateful "stateful 场景"; then
  dump_diagnostics; exit 1
fi

# 5) 验收二之二：撤掉 a 的防火墙 → open
clear_fw "$NS_A"
if ! assert_reachability "$NS_A" "$TMP/a.toml" b open "open 场景"; then
  dump_diagnostics; exit 1
fi

# 6) 验收二之三：a 入站全拦 → blocked
#（这会同时打断 a 的隧道，所以放最后）
apply_blocked_fw "$NS_A"
if ! assert_reachability "$NS_A" "$TMP/a.toml" b blocked "blocked 场景"; then
  dump_diagnostics; exit 1
fi

# 7) 收尾
clear_fw "$NS_A"; clear_fw "$NS_B"
kill -TERM "$A_PID" 2>/dev/null || true; wait "$A_PID" 2>/dev/null || true; A_PID=""
kill -TERM "$B_PID" 2>/dev/null || true; wait "$B_PID" 2>/dev/null || true; B_PID=""
ip netns exec "$NS_A" "$BIN" down -c "$TMP/a.toml"
ip netns exec "$NS_B" "$BIN" down -c "$TMP/b.toml"

echo "DOCTOR E2E OK"
```

- [ ] **Step 2: 跑红灯 → 修到绿**

Run（Linux，root）: `cargo xtask e2e doctor`
Expected：首轮可能暴露的问题与**预先批准**的处置：

1. **`nft -f -` 报 `Error: Could not process rule: No such file or directory`**
   → 内核缺 nftables 模块或 `ct` 表达式不可用。处置：在脚本开头加
   `modprobe nf_tables nf_conntrack 2>/dev/null || true`，CI 里也加同样一步。**允许**。
2. **防火墙后 25s 内没连上**
   → 看 `$TMP/a.log`：若两侧都在 2.5s 一次地 nudge 却握手不上，先用
   `ip netns exec hxt3-a conntrack -L -p udp` 确认 conntrack 条目建起来了。若确认是
   两侧出站包"错过"（一侧还没建 state），把 `wait_for_connected` 的上限从 25 提到 40。**允许**。
3. **`stateful` 场景被判成 `open`**
   → 说明 `Unsolicited` 意外命中了 conntrack。检查响应器是否真的用了**新建**的临时
   socket（源端口必须与 4194 不同，Task 12 的 `responder_answers_and_sends_unsolicited`
   已断言这点）。这属于实现 bug，**不要**改脚本迁就，回到 Task 12 修实现。
4. **`open` 场景被判成 `stateful`**
   → `clear_fw` 之后 conntrack 里可能残留旧条目影响判断（不应该，Unsolicited 用的是
   全新端口）。先重跑确认是否偶发；确为竞态则在 `clear_fw` 后加 `sleep 1`。**允许**。

除上述四条外的偏离，先在报告里说明再动。

- [ ] **Step 3: CI 加 e2e-doctor job**

`.github/workflows/ci.yml` 末尾追加：

```yaml
  e2e-doctor:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --workspace
      - run: sudo modprobe wireguard || true
      - run: sudo modprobe nf_tables nf_conntrack || true
      - run: command -v nft || sudo apt-get update && sudo apt-get install -y nftables
      - run: sudo -E env HEXTET_BIN=target/debug/hextet scripts/netns-e2e-doctor.sh
```

- [ ] **Step 4: 写 `docs/guides/doctor.md`**

```markdown
# hextet doctor：判断你的网络能不能打洞

`hextet doctor` 回答一个问题：**本机的 IPv6 入站是什么策略？** 它不是网络测速，
也不是连通性测试——它测的是"别人主动发包能不能进来"，这决定了 hextet 需要打洞
（几乎总是需要）还是能被动可达。

## 怎么用

doctor 需要**另一个节点帮忙回探**（hextet 没有任何项目方服务器，外部视角只能来自
网络内的其他节点）。对端只要在跑 `hextet daemon` 就自带响应器；如果对端只装了 CLI，
让它先跑：

```console
# 对端（B）
$ sudo hextet doctor --serve -c /etc/hextet/home.toml
探针响应器监听 [::]:4194（Ctrl-C 退出）
```

然后在本机（A）：

```console
$ hextet doctor -c /etc/hextet/home.toml --peer nas
探针对端   [2408:8000:1234::b]:4194
公网 IPv6  2408:8000:1234::a
已请求回包 到达
未请求入站 未到达
结论       stateful

状态防火墙（住宅 CPE / 光猫 IPv6 SPI 的常态）：
打洞成立（双向同时发包即可），裸入站监听不成立。这是正常且够用的状态。
```

- 配置里只有一个 peer 时 `--peer` 可省略。
- 对端地址不在配置里（或想指定别的端口）时用
  `--probe-endpoint '[2408:8000:1234::b]:4194'`。
- `--json` 给脚本用；退出码只反映"探测本身有没有跑成功"，结论是 open 还是 blocked
  都返回 0。

## 四种结论

| 结论 | 含义 | 你该做什么 |
|---|---|---|
| `open` | 未经请求的入站包也能进来 | 什么都不用做。这是最理想状态。 |
| `stateful` | 只有你自己请求过的回包能进来 | **什么都不用做**——这是中国家宽最常见的状态，hextet 的打洞正是为它设计的。 |
| `blocked` | 连你请求的回包都收不到 | 见下面「blocked 怎么排查」。 |
| `no-ipv6` | 本机没有公网 IPv6 | 先解决 IPv6：`ip -6 addr` 看有没有 2xxx:/3xxx: 开头的地址；没有就去开光猫/路由器的 IPv6 与 DHCPv6-PD。 |

`stateful` 不是问题，是常态。RFC 6092 建议住宅 CPE 对 UDP 采用
endpoint-independent filtering 且 state 空闲超时 ≥2 分钟（默认 5 分钟），
这给了 hextet 很宽的打洞与保活窗口。

## blocked 怎么排查

`blocked` 是**合并结论**，三种原因都会导致它，按顺序排除：

1. **对端没在跑响应器**——让对端确认 `hextet daemon` 在跑，或临时跑
   `hextet doctor --serve`；
2. **两侧网络密钥不一致**——探针包校验失败会被静默丢弃（这是刻意的，不给扫描者
   任何信号）。核对两边 `hextet.toml` 里 `[network] key` 是否一致；
3. **确实被拦**——换第三个节点再探一次；如果对不同对端都是 blocked，就是本机
   入站被拦。

## 中国光猫 / 运营商的已知情况

- **光猫默认开着 IPv6 SPI 防火墙、丢弃未经请求的入站，是常态**（"很多光猫默认没有
  防火墙"的说法不成立）。这只让你拿不到 `open`，**不影响打洞**——打洞的本质就是
  先出站建 state。所以看到 `stateful` 就可以正常用。
- **移动（CMCC）宽带/蜂窝入站受限最严重**；双 CMCC 蜂窝端点可能连打洞都不成，
  这正是 M3「自有节点中继」存在的理由（家里常电的路由器/PC 做中继）。
- **想拿 `open` 的话**（并非必需）：
  - 移动光猫：多在「安全 → 防火墙 → 攻击保护」里取消 `Ipv6Spi`；
  - 部分地区联通光猫（如广州）**关不掉**，只能改桥接模式 + 自己路由器拨号；
  - 烽火/华为/中兴光猫有 telnet + ip6tables 的民间教程，风险自负。
  相关证据链见 `docs/research/2026-08-06-ipv6-p2p-feasibility.md` §1。

## 它测的到底是什么（诚实的边界）

- 探针跑在 UDP **4194**，不是 WireGuard 的 4193——内核 WireGuard 独占后者，用户态
  没法在同端口收包。住宅 CPE 与光猫的默认丢弃规则不区分端口，所以这是可靠的代理
  指标，但严格来说它测的是"任意 UDP 端口"。
- 只测 UDP，不测 TCP、不测 ICMP。
- 只用一个对端的视角；`blocked` 无法区分"我被拦"和"对端没应答"。
- 协议细节见 `docs/protocol/doctor-probe.md`。
```

- [ ] **Step 5: 写 `docs/adr/ADR-0001-m2-daemon-shape.md`**

```markdown
# ADR-0001：M2 守护进程的形态

- 状态：已接受
- 日期：2026-08-06
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §10（项目结构）、§8（M2）

## 背景

M2 需要一个常驻进程（监听 netlink 地址变化、轮换候选 endpoint、维持打洞重试）。
设计 spec §10 规划的结构是三个 crate：`engine`（可嵌入引擎）、`daemon`（进程壳：
tokio 主循环 + axum Web UI + IPC server）、`proto`（daemon↔UI/CLI 共享类型）。
但 M2 既没有 Web UI 也没有 UI 客户端——axum 与 IPC 的第一个真实消费者是 M5。

## 决策

三项偏离，均为 M2 期限内的简化，不改变 spec 的终局结构：

1. **只建 `crates/engine` 一个新 crate**，`daemon`/`proto` 推迟到 M5。守护进程的
   tokio 主循环放在 `engine::daemon` 模块里。
2. **守护进程是 `hextet daemon` 子命令**，而不是独立的 `hextetd` 二进制。保持单
   二进制，M4 的 systemd/procd 单元直接调用 `hextet daemon`。
3. **运行时状态经原子写的 JSON 状态文件暴露**（`<state_dir>/state.json`），
   而不是 unix socket IPC。`hextet status` 读内核 + 读该文件后合并输出。

## 理由

- **YAGNI**：M2 的状态读者只有本机 CLI，且是只读、非实时。一个 tmp+rename 的 JSON
  文件就完全覆盖，且天然支持"daemon 不在跑"这个必须处理的状态（文件缺失/过期）。
  IPC 会引入连接生命周期、协议版本协商、并发与错误处理四层新面，M2 用不上。
- **`engine` 已经是那个"可嵌入引擎"**：spec 要求 engine 无进程假设、FFI-ready
  （M7 Android 经 UniFFI 复用）。把 tokio 主循环放在 engine 里不违反这一点——它是
  一个 `async fn run()`，调用方决定要不要跑；真正的进程壳（信号、日志初始化、
  命令行解析）在 `hextet-cli`。
- **单二进制降低交付成本**：cargo-dist、OpenWrt ipk、Android 都少一个产物要管。
  spec 里 `daemon` crate 的价值在于"axum + IPC 的落点"，那两样东西 M2 都没有。

## 后果

- **M5 必须补的债**：新建 `crates/proto`（serde 共享类型）与 unix socket IPC；
  届时 `hextet status` 改为优先走 IPC、状态文件降级为兜底（或直接移除）。
  Web UI 的 axum 落在 `crates/daemon` 还是 `engine` 到时再定。
- **状态文件不是公开 API**：`docs/dev/state-files.md` 明确它是派生数据、可随时
  删除、格式变更只需 `version` 对不上时让读者忽略。外部脚本应该用
  `hextet status --json` 而不是直接读文件。
- **`hextet status --json` 的形状在 M2 变过一次**（数组 → `{daemon, peers}` 对象）。
  0.1 发布前不再改。
```

- [ ] **Step 6: 文档收尾**

`docs/guides/quickstart.md` 在 daemon 一节末尾追加：

```markdown
连不上时先跑 `hextet doctor`（需要对端配合，见 `docs/guides/doctor.md`）：它会告诉你
本机的入站策略是 `open` / `stateful` / `blocked` / `no-ipv6`——其中 `stateful` 是中国
家宽的常态且完全够用，`blocked` 与 `no-ipv6` 才需要动光猫设置。
```

`README.md` 把状态行改为：

```markdown
状态：M2 完成（动态端点自愈 + doctor），M3 未开始。
```

- [ ] **Step 7: M2 验收核对**

对照设计 spec §8 的 M2 行（交付：防火墙打洞、roaming、netlink 地址监听、端点缓存、
`hextet doctor`；验收：一侧换前缀 <5s 恢复、防火墙后节点可互连、doctor 正确分类
open/stateful/blocked）逐条核对：

- [ ] **防火墙打洞（双向同时握手）**：`netns-e2e-doctor.sh` 验收一——双侧 nftables
      状态防火墙**先装后启**，两节点仍互连且双向 ping 通
- [ ] **roaming**：`netns-e2e-dynamic.sh` 步骤 6——A 换前缀后 B 的内核 endpoint 跟随
      到新地址（`status` 的 endpoint 字段）
- [ ] **netlink 地址监听**：同上，且恢复耗时远小于 keepalive(25s) 与握手超时(180s)，
      证明是事件驱动而非轮询兜底
- [ ] **端点缓存**：`netns-e2e-dynamic.sh` 步骤 7/9——`endpoints.json` 有 `last_good`；
      删掉配置里的 endpoint 后仅靠缓存重连成功且 `endpoint_source == "cache"`
- [ ] **`hextet doctor`**：`netns-e2e-doctor.sh` 步骤 4/5/6——三种 nftables 规则下
      分别报出 `stateful` / `open` / `blocked`
- [ ] **一侧换前缀 <5s 恢复**：脚本打印的实际耗时 < 5000ms
- [ ] `cargo xtask ci` 全绿；CI 四个 job（`lint-test`/`e2e`/`e2e-dynamic`/`e2e-doctor`）全绿
- [ ] 代码里没有 `todo!`/`unimplemented!`/`// TODO`/被跳过或被改成恒真的测试
- [ ] 文档与实现一致：`docs/protocol/{punching,doctor-probe}.md`、`docs/dev/state-files.md`、
      `docs/guides/doctor.md`、`docs/adr/ADR-0001-m2-daemon-shape.md`

- [ ] **Step 8: 提交**

`CHANGELOG.md` 追加：

```markdown
- `scripts/netns-e2e-doctor.sh`：双侧 nftables 状态防火墙下打洞互连 + doctor 三分类（stateful/open/blocked）的 netns E2E；CI 新增 `e2e-doctor` job。
- 文档：`docs/guides/doctor.md`（用户向 doctor 指引，含中国光猫 IPv6 SPI 说明）、`docs/adr/ADR-0001-m2-daemon-shape.md`（M2 偏离 spec §10 结构的三项决策）。
```

```bash
git add scripts .github docs README.md CHANGELOG.md
git commit -m "test(e2e): 状态防火墙打洞与 doctor 三分类 E2E（M2 验收）

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

## 计划自审记录

1. **Spec 覆盖**（M2 范围）：设计 spec §8 M2 行的五项交付全部有落点——防火墙打洞
   → Task 5（状态机）+ 8（主循环）+ 15（验收）；roaming → Task 5（`Connected` 跟随
   内核 endpoint）+ 2（增量 endpoint 更新）；netlink 地址监听 → Task 3 + 8；端点缓存
   → Task 4（候选组装）+ 6（持久化）；`hextet doctor` → Task 11–14。三条验收标准分别
   由 Task 10（换前缀 <5s）、Task 15（防火墙后互连、doctor 三分类）覆盖。
   M3+ 内容（mDNS、DHT/pkarr、隧道内 QUIC gossip、invite、自有节点中继）明确不在本计划。

2. **占位符扫描**：无 `TBD`/`TODO`/"类似 Task N"。Task 8 显式声明「无单测，由 Task 10
   E2E 覆盖」并给出理由，不是遗漏。Task 10/15 各列出「预先批准的偏离」清单，是有边界的
   授权而非开口子。探针的两个冻结测试向量（`8ce27aff…` 与 32 字节线格式）已用与仓库
   现有 `frozen_derivation_vector` 相同的 HKDF 独立复算核对过（复算出的 `network-id`
   与仓库已冻结的 `fdc1:c82b:b2f4::/48` 完全一致），执行者可直接钉进断言，无需"先跑一次
   再冻结"。

3. **类型一致性**（跨任务签名核对）：
   - `NodeSettings.probe_port/state_dir`（T1 定义 → T8/T9/T14 消费）
   - `Config::render_template` 五参签名（T1 改 → T1 内 init.rs 与 config 测试同步）
   - `load_config_and_identity`（T1 移到 core → T8 直接用、T9/T14 经 cli 薄封装用）
   - `WgBackend::set_peer_endpoint`（T2 定义 → T8 消费；Mock 记录供 T2 自测）
   - `AddrEvent{kind,address,if_index}` / `list_global_ipv6(Option<&str>)`（T3 定义 →
     T8 消费 AddrEvent、T14 消费 list_global_ipv6）
   - `CachedEndpoint{endpoint,last_seen_unix}`（T4 定义最小版 → T6 补全 → T4 的
     `build_candidates` 与 T7 的 `endpoint_source` 都按 slice 消费）
   - `normalize`（T4）在 T5（FSM 构造与比较）、T6（record_good）、T7（endpoint_source）、
     T8（内核 endpoint 转换）四处一致使用
   - `PeerFsm::{new,kick,tick,state,candidates_len,current_candidate}` + `Action` 三变体
     （T5 定义 → T8 全部消费；`peer_state_of` 用 `state()` 与 `current_candidate()`）
   - `EngineState`/`PeerState` 字段名与 `status --json` 的字段、E2E 脚本的 jq 路径
     （`.peers[0].punch_state`、`.peers[0].endpoint_source`、`.daemon.running`、
     `.peers[0].endpoint`）逐一对齐
   - `ProbePacket{kind,nonce,reply_port}` + `ProbeKind` 三变体（T11 → T12 响应器、
     T13 客户端）；`ProbeEvidence`/`Reachability`（T13 core → T13 engine → T14 CLI 的
     `--json` 字段 `reachability`/`evidence`/`target`/`global_addresses`，与 T15 的
     `jq -r .reachability` 对齐）
   - `hextet init --state-dir`（T1）被 T10/T15 两个 E2E 脚本依赖——这是刻意的：
     否则脚本得用 sed 往 `[node]` 表里插行，脆弱

4. **破坏性变更的连带修改都已配对**：`status --json` 从数组改对象（T9）→ 同一 Task 内
   改 `scripts/netns-e2e.sh` 的两处 jq 路径并要求 M1 E2E 继续绿；`render_template` 加参数
   （T1）→ 同一 Task 内改 `init.rs` 与 config 的既有测试；`build_device_spec` 迁 crate
   （T4）→ 同一 Task 内改 `up.rs` 与 `crates/cli/tests/spec.rs`。

5. **已内嵌的风险点**：
   - 内核 WireGuard 缓存的源地址在本机地址被删后可能不刷新 → Task 10 Step 2 预授权
     「地址变化分支里补一次 `backend.apply(&spec)`」；
   - `SocketAddrV6` 的 `flowinfo`/`scope_id` 参与 `PartialEq` 导致 roaming 误判 →
     `normalize` 贯穿全链路，并在 T4/T7 各有专门测试；
   - 探针放大与限速表膨胀 → T12 的限速器（1/s per IP、表上限 64、TTL 清理）与其三个测试；
   - `stateful` 判定必须等满 timeout（提前返回会把 `open` 误判成 `stateful`）→ T13 已
     用注释固定这个语义，T15 的 `open`/`stateful` 两个场景互为回归；
   - nftables 规则要用 `iifname` 而非 `iif`（hextet0 装规则时还不存在）、必须放行
     `iifname "hextet0"`（否则 overlay 侧主动 ping 被 ct new 丢弃）→ T15 脚本注释里写明。

6. **阶段可发布性**：阶段 A（T1–T10）结束时 doctor 尚未存在，但没有任何半成品裸露——
   `probe_port` 配置项存在而无人消费不影响任何行为，`list_global_ipv6` 是未被调用的
   公开 API（不触发 dead_code）。阶段 A 的 CI 三 job 全绿即可发布。













