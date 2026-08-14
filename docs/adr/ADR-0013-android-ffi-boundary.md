# ADR-0013：Android FFI 边界 —— UniFFI 选型、边界范围与类型映射

- **状态**：已接受
- **日期**：2026-08-13
- **决策者**：hextet 项目
- **相关**：`docs/superpowers/specs/2026-08-06-hextet-design.md` §8 M7 / §9 / §10 / §13、
  `crates/core/`（纯逻辑层）、`crates/engine/src/{lib,backend,daemon}.rs`、
  `crates/wg-userspace/src/lib.rs`、`crates/core-ffi/`（本 ADR 落地产物）、
  `docs/superpowers/plans/2026-08-13-m7-android.md`

> **修正记录（2026-08-14）**：本 ADR 决策 1 定的 proc-macro 路线在 `hextet-engine-ffi`
> 落地时被**反转为 UDL**（`crates/engine-ffi/src/hextet.udl` + `build.rs` 的
> `generate_scaffolding`，见 `docs/superpowers/plans/2026-08-14-m7-android.md` §3「落地记录」）。
> 反转理由未在计划/代码中记录，如实标注。现两个 FFI crate 并存：`core-ffi`（proc-macro，
> 本 ADR 决策 1 的产物，六个纯逻辑函数）与 `engine-ffi`（UDL，实际 Android 消费面：
> `load_config`/`status`/`daemon_spawn*`/`join`/`init`）。两条路线的统一与 `core-ffi` 的去留
> 是**待决项**——`engine-ffi` 的 `join`/`init` 已覆盖 `core-ffi` 的身份生成/派生/渲染原语，
> 但 `core-ffi` 尚未删除。

## 背景

M7（Android，v1.0 必含）=「engine FFI 化（UniFFI）+ VpnService 前台服务 + gotatun 数据面
+ 按需连接」。本 ADR 只裁定**第一片**：把 FFI 边界敲定并落地一个经编译验证的最小 UniFFI
骨架，覆盖 `hextet-core` 的纯逻辑。VpnService 前台服务、gotatun 数据面、按需连接都不在本
片内（各需 Android 工具链，另立 ADR，见 M7 计划文档）。

落地前必须裁定五件事：UniFFI 的用法（proc-macro vs `.udl`）、边界范围（纯 core 还是连异步
engine 一起）、错误映射、类型映射、tokio runtime 归属。

本轮查证到的外部事实（截至 2026-08-13，来自 crates.io / docs.rs / uniffi-rs 仓库文档，
未在本机安装 Android 工具链）：

| crate | 最新版 | 许可证 | MSRV | 关键点 |
|---|---|---|---|---|
| `uniffi` | **0.32.0**（2026-06-30 更新） | **MPL-2.0**（deny.toml 已放行） | 未声明（`rust_version` 为 null） | proc-macro 时代：`#[uniffi::export]` + `uniffi::setup_scaffolding!()`，不写 `.udl`、不写 build.rs 即可生成 Rust 侧 scaffolding；Kotlin 绑定用 `uniffi-bindgen generate --library <cdylib>`（library 模式，从编译产物嵌入元数据生成）。默认 feature `cargo-metadata` 仅为 bindgen 工具链读 Cargo.toml 元数据，运行时 proc-macro 路径不需要。错误枚举支持 `#[derive(uniffi::Error)]`（变体可携带数据，tuple 变体 `Generic(String)` 可用）。 |

RUSTSEC：未查到针对 `uniffi` 的公开 advisory（以 CI `cargo-deny check` / `cargo-audit` 为
最终事实来源）。

## 现状（审计：Android 需要什么 vs 现在 FFI 到什么程度）

### A. 立即 FFI-ready（`hextet-core` 纯逻辑层，同步、无 tokio、无平台依赖）

| 能力 | 位置 | FFI 可行性 |
|---|---|---|
| 身份生成 / 种子序列化 / 公钥派生 | `identity.rs`（`NodeIdentity::generate/from_seed/seed/public`，`NodePublicKey`） | 直接。种子 `[u8;32]` 走 base64（与 `NodeIdentity::save` 线格式一致）。 |
| 配置加载 / 校验 | `config.rs`（`Config::load`、`load_config_and_identity`、`render_template`、`render_peer_block`） | 直接，但返回的 `Config` 含 `PathBuf`/`Ipv6Addr`/`SocketAddrV6`/`Vec<Peer>`，FFI 侧需摘要化（本片做了 `ConfigSummary`）。 |
| 网络前缀派生 | `network.rs`（`NetworkKey::from_base64`、`NetworkPrefix::derive`） | 直接。`NetworkKey` 秘密 + `Drop` zeroize，FFI 侧只经 base64 字符串传递、不落 `Config` 对象。 |
| 节点地址派生 | `addr.rs`（`derive_node_addr`、`is_ula`、`is_usable_endpoint_addr`、`check_subnet_collisions`） | 直接。 |
| invite token 编/解码验签 | `invite.rs`（`Invite::encode/decode`，`NodeIdentity::sign`） | 直接（纯字节/字符串）。 |
| 中继控制帧 codec | `relay.rs`（`RelayFrame::encode/decode`） | 直接（纯字节）。 |
| gossip 条目 codec / 收敛 | `gossip.rs`（`Entry`、`GossipStore`） | 直接（纯字节/结构）。 |
| LAN 公告 / doctor 探针 codec | `beacon.rs` / `probe.rs` | 直接（纯字节）。 |

结论：**core 是整个自然 FFI 边界**——零 `tokio`、零平台 cfg、`#![deny(missing_docs)]`、
全部有单测/属性测试/钉扎向量。

### B. 跨边界但当前 async/tokio/进程绑定（`hextet-engine`，本片不碰，诚实列出阻塞重构）

| 组件 | 现状 | Android 要的重构（诚实） |
|---|---|---|
| `daemon::run` | `tokio::runtime::Runtime::new()` + `block_on`，`#[cfg(linux|macos)]` 才编译，其余平台是 `bail` 占位桩（`lib.rs`） | VpnService 的 `establish()` 跑在**专用线程**上，runtime 必须由宿主拥有/控制，不能 `#[tokio::main]`，也不能在 FFI 边界内新建 `Runtime` 再 `block_on`。要拆成「纯逻辑 tick + 宿主注入 runtime」的可嵌入 `Engine`。 |
| `serve()` 循环（lan/gossip/dht/ddns/relay_server/probe_responder） | 每个都是 `tokio::spawn` 的独立任务 + `mpsc` 通道 | 这些是**网络 I/O 循环**，Android 上照跑（socket 层与平台无关），但它们的生命周期要由引擎对象管理、受 VpnService 生命周期约束（onDestroy → 停止所有任务）。 |
| `backend::platform_default()` | 只有 `#[cfg(linux)]`/`#[cfg(macos)]` 两个分支 | Android 走 gotatun（in-process，spec §9），需要一个 `#[cfg(target_os = "android")]` 分支返回 gotatun 后端——这依赖 gotatun 交叉编译 + Android 数据面 ADR，不在本片。 |
| `fsm/candidates/cache/status/state` | 纯逻辑（无 socket/root） | 已 FFI-ready，但依赖 `SystemTime`/`Instant`/`SocketAddrV6` 类型，FFI 侧要映射（见 D）。 |

### C. `cfg(target_os)` 缺口（数据面）

- `platform_default()`（`engine/src/backend.rs`）与 `wg-userspace::create_device` 都只有
  linux/macos 分支，**没有 android 分支**。
- spec §9 平台矩阵：Android 数据面 = **gotatun（in-process）**，不是 boringtun 0.7.1。
  ADR-0007 已记录 gotatun 的 MSRV 1.95 / `aws-lc-rs` 交叉编译坑 / pre-1.0 审计进行中——
  **这些是 Android 数据面的独立 ADR**，本片不裁决，只在此登记缺口。
- 因此 `crates/wg` 的 `WgBackend` trait 复用方案、gotatun 的 `tun`/`udp` trait 适配
  （ADR-0007 决策 2 预留的 `platform::tun`）如何在 Android VpnService 的 fd 上落地，都留到
  M7 数据面片。

### D. 类型映射缺口（UniFFI 内建 vs 需要 wrapper）

| Rust 类型 | UniFFI 内建？ | 本片映射 | 说明 |
|---|---|---|---|
| `String` / `u16` / `u32` / `bool` / `Vec<T>` / `Option<T>` | 是 | 原样 | — |
| `std::net::Ipv6Addr` / `SocketAddrV6` | **否** | `String`（规范文本，边界内 `parse`/`to_string`） | IPv6-only 项目，地址文本无损、可往返。 |
| `[u8; 32]`（种子/密钥） | 否（`Vec<u8>` 可以但语义弱） | base64 `String` | 与 core 线格式/人类格式一致，避免裸字节数组跨 FFI。 |
| `std::path::PathBuf` | 否 | `String` | Android 上路径由 Kotlin 传 app 私有目录；文件写入由宿主接管（Keystore/EncryptedPrefs），不落 core 的 0600 文件。 |
| `std::time::SystemTime` / `Instant` | 否 | **未在本片 surface**，engine-FFI 片再定 | 预案：`SystemTime` → `u64` Unix 秒（core 的 `invite.rs` 已用 `issued_unix`/`expires_unix` 的先例）。 |
| `thiserror` 富枚举（`ConfigError` 等） | 否（错误可 derive，但嵌套 `#[source]` 字段不可） | 扁平 `FfiError`（见决策 3） | — |

### E. async/runtime 问题

UniFFI 0.32 支持 async export（`#[uniffi::export(async_runtime = "tokio")]`）。但 Android 的
VpnService 模型是「专用线程 + 宿主拥有的 runtime」，engine 的 tokio runtime 必须由
`VpnService` 侧创建并拥有，FFI 不能自己 `Runtime::new()` + `block_on`（会阻塞 VpnService
回调线程 / 与宿主 runtime 抢线程池）。本片只导出同步纯逻辑，**不引入任何 async export**。

## 决策

1. **UniFFI 用法：proc-macro（`#[uniffi::export]` + `uniffi::setup_scaffolding!()`），不写
   `.udl`、不写 build.rs。** 版本锁死 `=0.32.0`（沿用 mainline/boringtun/tun 的锁版本先例），
   `default-features = false`（关掉只为 bindgen 工具链服务的 `cargo-metadata`）。Kotlin 绑定
   用 library 模式生成：`uniffi-bindgen generate --library libhextet_core_ffi.so --language kotlin`。

2. **边界范围（本片）：只 `hextet-core` 纯逻辑，同步、无 tokio。** 新 crate `crates/core-ffi`
   只依赖 `hextet-core`（+ `uniffi`/`base64`/`thiserror`），暴露六个函数：`generate_identity` /
   `identity_public_key` / `derive_network_prefix` / `derive_node_address` / `render_config` /
   `load_config`。异步 engine 的 FFI（可嵌入 `Engine` + runtime 归属）留到 engine-FFI 片。

3. **错误映射：thiserror → 扁平 `FfiError` 枚举。** 变体名供 Kotlin 匹配异常类型，`Display`
   文本（thiserror 生成）携带完整人类可读细节。放弃 `ConfigError` 的结构化字段
   （`BadKey { name, source }` 等）的可编程性，换取简单、稳定、可匹配的异常面。

4. **类型映射：地址/endpoint → `String`，密钥/种子 → base64 `String`，路径 → `String`，
   时间 → `u64`（engine-FFI 片再定）。** 全部在 FFI 边界 `parse`/`to_string`，core 不改。

5. **`unsafe`：本片实测**——`cargo check` 在 `unsafe_code = "deny"` 下**不加任何 allow 也
   通过**，即 `setup_scaffolding!()` 与 `#[uniffi::export]` 展开进本 crate 的胶水（纯同步 +
   record + 扁平错误枚举）**零 `unsafe`**。FFI 路径的 `unsafe`（`unsafe impl LowerReturn` 等）
   在 `uniffi_core`（第三方预编译依赖）里，不在本 crate lint 范围。**预案**：engine-FFI 片
   引入 callback interface / async export 时，生成胶水会把 `unsafe` 展开进本 crate，届时加
   一处带 `# SAFETY` 文档的收窄 `#![allow(unsafe_code)]`（镜像 `macos.rs` / `wg_tun_name` 先例）。

6. **tokio runtime 归属（策略，本片不实现）**：runtime 由 VpnService 宿主创建并拥有，engine
   拆成「纯逻辑 tick + 宿主注入 runtime」的可嵌入对象；FFI 只暴露同步控制面
   （start/stop/status），不 `block_on`、不 `#[tokio::main]`、不在 FFI 边界内新建 `Runtime`。

## 备选与理由

- **`.udl` + build.rs 生成 scaffolding**：被否。`.udl` 是旧式写法，Rust 类型与 `.udl` 双份
  真相、易漂移，且 build.rs 生成的 `.rs` 经 `include!` 进 crate 同样受 lint 影响。proc-macro
  时代单份真相（类型声明在 Rust），更符合「类型即接口」。
- **边界范围拉进异步 engine**：被否。engine 的 `serve()` 循环依赖 tokio + `SocketAddrV6` +
  `SystemTime`，FFI 化需要先做 runtime 归属与 gotatun 后端，属于后续片；本片先落地最小、
  可编译验证、对 onboarding 真正有用的纯逻辑面。
- **错误映射用「每个 thiserror 变体一个异常类」**：被否。core 错误变体携带 `io::Error`/
  `IdentityError` 等嵌套字段，不可 FFI，且 20+ 个 `ConfigError` 变体会生成 20+ 个异常类，
  对 Android onboarding 无价值。扁平枚举更稳。
- **`Ipv6Addr` 用 `Vec<u8>` 而非 `String`**：被否。`String` 与配置/状态文件里的人类可读
  形式一致，可往返、可日志、可展示，且项目 IPv6-only 使文本无损。

## 后果

- 新增 workspace crate `crates/core-ffi`（`cdylib` + `lib`），`cargo build/test/clippy` 在
  macOS 全绿（本片验收）。`cdylib` 产物是 Android 数据面/engine-FFI 片的绑定生成输入。
- **诚实边界（本片未验证、待 Android/NDK）**：
  1. **Kotlin 绑定生成**未在本机跑（需 `uniffi-bindgen` + Android Gradle；本机仅验证 Rust
     侧 scaffolding 编译 + 导出类型在纯 Rust 测试里 roundtrip）。绑定生成的命令与 Gradle 接线
     写在 `docs/dev/build.md`。
  2. **Android 目标编译**未验证（需 NDK/交叉 target；本机只验证 macOS host target）。
  3. **gotatun 数据面**、**VpnService 前台服务**、**按需连接**、**与代理 App 的 VpnService
     槽位冲突文档**：全在 M7 后续片，见 M7 计划文档。
- `uniffi` 是 MPL-2.0：deny.toml 已放行（为 gotatun 预留的条目）。锁死 `=0.32.0` 后，
  `cargo-deny`/`cargo-audit` 继续常开兜底。
