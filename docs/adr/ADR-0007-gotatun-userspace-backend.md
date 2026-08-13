# ADR-0007：用户态 WireGuard 后端先用 boringtun 过渡、封装进 crates/wg-userspace，TUN 抽象放 crates/platform

- 状态：已接受
- 日期：2026-08-12
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D1 / §8 M4 / §9 / §10 / §13、
  `docs/superpowers/plans/2026-08-12-m4-macos-and-routers.md` Task 32、
  `crates/wg/src/lib.rs`（`WgBackend` trait）、`crates/platform/src/lib.rs`、
  `crates/discovery/Cargo.toml`（`mainline = "=8.0.0"` 隔离先例）

## 背景

M4 的 Task 32 要在 macOS（utun）与 Linux（TUN）上提供用户态 WireGuard 数据面，实现
`crates/wg/src/lib.rs` 里的 `WgBackend` trait（五个方法：`apply`、`status`、
`set_peer_endpoint`、`add_peer`、`remove_peer`）。spec §13 把 gotatun 标为「年轻
（审计 2026 进行中）」，并用 `WgBackend` trait 隔离、留了「可换 NepTUN/boringtun」的
后路。落地前必须裁定五件事：依赖形态、TUN 抽象放哪、后端怎么选、第一片做到哪、何时
重新评估。

本轮查证到的外部事实（截至 2026-08-12，均来自 crates.io / docs.rs / 仓库源码，未在
本机下载或安装任何东西）：

| crate | 最新版 | 许可证 | MSRV（`rust-version`） | 关键点 |
|---|---|---|---|---|
| `gotatun` | **0.8.1**（crates.io 已发布） | **MPL-2.0** | **1.95**（edition 2024） | pre-1.0；默认 feature 是 `aws-lc-rs`，另有 `ring` / `tun` 可选 feature；API 是 trait 化模块 `device`/`noise`/`packet`/`tun`/`udp`/`x25519`，`device::Device` + `DeviceBuilder` + `DeviceTransports`/`DefaultDeviceTransports`（默认 UDP socket + TUN 设备）。git `main` 工作区 `rust-version = "1.95"`，成员 `gotatun` 版本为 0.9.0（未发布，领先于 crates.io 的 0.8.1）。 |
| `boringtun` | **0.7.1** | **BSD-3-Clause** | 未声明（`rust_version` 为 null，可配 1.85 用） | edition 2018；库本身**不依赖** `tun`/`tokio`（CLI 才依赖），暴露 `Device`/`DeviceHandle`，**没有** `Tun`/`udp` trait 抽象（`Device` 内部硬编码平台 `TunSocket` 与 `socket2::Socket`），控制面是 Unix socket 文本协议（`/var/run/wireguard/{name}.sock` 的 `set=1`/`get=1`）；依赖 `ring 0.17`、`chacha20poly1305 0.10.0-pre.1`、`aead 0.5.0-pre.2`（预发布 aead 是轻微隐患，但已稳定多年）。 |
| `tun`（meh/rust-tun） | **0.8.14** | **WTFPL** | 未声明 | 平台模块齐全：`linux`/`macos`(utun)/`windows`/`freebsd`/`android`/`ios`；有 `async` feature（`AsyncDevice`，mio/tokio）；**安全 API**（ioctl/utun 的 unsafe 全部内聚在 crate 内，调用方零 unsafe）。这是 boringtun-cli 与 gotatun `tun` feature 共用的同一款。 |
| `tokio-tun`（yaa110） | **0.15.2** | **MIT OR Apache-2.0** | 未声明 | 原生 tokio 异步 TUN/TAP，支持 macOS/Linux/Windows；是 WTFPL 不可接受时的备选。 |

RUSTSEC：未能查到针对 `gotatun`、`boringtun`、`tun`、`tokio-tun` 的公开 advisory
（以 CI 的 `cargo-deny check` / `cargo-audit` 为最终事实来源，与 `CONTRIBUTING.md` 立场一致）。

## 决策

1. **依赖形态：封装进新 crate `crates/wg-userspace`，先用 boringtun 过渡（锁死 `=0.7.1`），
   gotatun 作为后续切换目标写进本 ADR。** 不直接引 gotatun 的原因有两条硬事实：
   （a）gotatun MSRV 是 **1.95**，而本工作区 `rust-version = "1.85"`，直接引就要抬工作区
   MSRV（动根 `Cargo.toml` + 影响 OpenWrt musl 交叉编译工具链）；（b）它是 pre-1.0 且审计
   2026 仍在进行。boringtun 无 MSRV 约束、BSD-3-Clause 干净、被 Cloudflare Warp/Firezone/
   NetBird 生产验证多年，正是 spec §13「可换 boringtun」这条后路。隔离与锁版本完全沿用
   `mainline = "=8.0.0"` 先例：`wg-userspace` 之外不暴露 boringtun 类型，版本精确锁定。

2. **TUN 抽象放 `crates/platform`**，由 `tun` crate（meh/rust-tun，安全封装）承接底层
   FFI。`crates/platform` 本就是「接口/地址/路由/服务化」的平台抽象层，TUN 设备是其一等
   能力。**实现时修正本 ADR 初版的一处事实错误**：boringtun 0.7.1 **没有** `Tun`/`udp`
   trait 抽象（`Device` 内部硬编码平台 `TunSocket` 与 `socket2::Socket`），所以「给
   boringtun 写 `TunHandle` 适配器」这条路不成立——`hextet-wg-userspace` 直接调
   `DeviceHandle`，既不需要也不引用 `platform::tun`。`platform::tun` 仍按决策 2 落地并
   保留，供将来切 gotatun（它确有 `gotatun::tun` trait）时写适配器用。`unsafe_code = "deny"` 不放松：
   我们的 `tun.rs` 只调 `tun` crate 的安全 API，不手写 utun/ioctl unsafe。接口草图
   （只签名，不实现）：

   ```rust
   // crates/platform/src/tun.rs
   pub struct TunConfig { pub name: String, pub mtu: u32 }
   pub struct TunHandle { /* 封装 tun::AsyncDevice（或 Device + Reader/Writer） */ }
   pub async fn open_tun(cfg: &TunConfig) -> Result<TunHandle, PlatformError>;
   impl TunHandle {
       pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, PlatformError>; // 返回包长
       pub async fn write_packet(&self, pkt: &[u8]) -> Result<(), PlatformError>;
       pub fn name(&self) -> &str;
   }
   pub async fn close_tun(t: TunHandle) -> Result<(), PlatformError>;
   ```
   macOS 走 `tun` crate 的 `macos`（utun）模块，Linux 走 `linux`（TUN）模块；非
   Linux/macOS 平台按现有 `stub` 惯例返回 `PlatformError::Unsupported`（如 Windows 留到
   M6 用 wintun，Android 留到 M7 走 VpnService 自己的 fd）。注意：这**只覆盖 TUN 设备**
   （打开/读写/关闭），macOS 上给 utun 配地址/路由是另一个缺口——现有 `setup_interface`/
   `add_route` 目前仍是 Linux-only，需单独跟进（见「代价与再评估」）。

3. **后端选择：编译期 `cfg(target_os)`。** Linux → 现有 `kernel`（wireguard-control/netlink）；
   macOS/Windows → `wg-userspace`（boringtun）。`crates/wg` 新增一个 `backend()` 工厂
   （或 `WgBackend` 的 `platform_default()` 关联函数），Linux 下返回 `KernelBackend`、
   其余平台返回 userspace 后端；`crates/engine/src/daemon.rs` 与
   `crates/cli/src/commands/{up,status,doctor}.rs` 里现在的 `KernelBackend` 直接构造点
   统一改成调这个工厂。选 `cfg` 而不是运行时可选：零运行时分支、无 `Box<dyn WgBackend>`
   间接层、每个平台只编译自己的后端（与现有 `kernel` 模块 `#[cfg(target_os = "linux")]`
   的既定模式一致）；「可换 NepTUN/boringtun/gotatun」靠 trait 隔离 + 换依赖完成，不靠
   运行时开关。

4. **第一片（Task 32 的最小诚实增量）**：`crates/platform` 的 TUN 抽象 + `crates/wg-userspace`
   的 boringtun `WgBackend` 实现，能（a）在 macOS 上建立 `hextet0`（utun）、（b）两个
   进程内/loopback 的 boringtun 实例互发 WireGuard 握手并 ping 通 overlay。**macOS 上可测**：
   TUN 打开/读写（需 `sudo`，等价现有 `--ignored` 需要 root 的测试分层）、进程内握手与
   数据包往返（boringtun 的 `noise::Tunn` 点对点 noise 隧道抽象天然支持 in-process 测试，
   不依赖真实网卡——是 `Tunn`，不是不存在的 `Tun` trait）。**macOS 上不可测**：Linux 内核 WG 路径（netns E2E，只在 Linux CI 跑）、launchd
   服务化（Task 33）。诚实边界照 Task 32 所述写进 ADR 与安装指南：macOS 数据面是「可用」
   而非「与 Linux 内核 WG 同等成熟」。

5. **重新评估触发条件**：见下节。

## 与 spec 的偏离记录

spec §3 D1 与 §9 写的是「macOS/Windows 用 gotatun」。本 ADR 决定**先用 boringtun 过渡**，
属范围/时机收敛，不改最终方向（gotatun 仍是目标后端）。触发切换的条件与理由见「代价与
再评估」第 1 条。

## 理由（决策 1 的取舍对照）

- **gotatun 直引（crates.io 0.8.1）**：方向最正（spec 已选），但要抬工作区 MSRV 到 1.95
  且默认 crypto 是 `aws-lc-rs`（spec §13 已列其交叉编译坑，需显式换 `ring` feature），
  叠加 pre-1.0 + 审计未完——对「第一片」风险偏高。
- **gotatun git 依赖**：更糟，git 依赖不可发布、无 `Cargo.lock` 稳定性、审查更难，直接否决。
- **boringtun 过渡（本决策）**：无 MSRV 抬升、BSD-3-Clause、生产验证充分、API 与 gotatun
  同源（gotatun 即其 fork/多线程重写），切换成本最低；代价是「多线程重写带来的性能提升」
  暂不享受——但 macOS/Windows 无内核 WG 可对照，单线程 boringtun 的吞吐对当前里程碑够用。
- **封装进 `crates/wg-userspace`**：让「换 gotatun/NepTUN/boringtun」只动一个 crate 的
  Cargo.toml 与适配层，不在 engine/cli 里散落任何后端类型——与 `mainline` 隔离策略一致。

## 代价与再评估

- **boringtun 的预发布 aead 链**（`chacha20poly1305 0.10.0-pre.1`、`aead 0.5.0-pre.2`）：
  与 `mainline` 的 `ed25519-dalek 3.0.0-pre.1` 同类风险。缓解：锁版本、封装、`cargo-deny`
  常开。若这些预发布版被 yanked 或出 RUSTSEC，与「boringtun 被弃养」一并触发下一条。
- **`tun` crate 是 WTFPL**：非 SPDX 标准宽松许可，`cargo-deny` 默认可能要求显式 allow 一条。
  若组织上不接受 WTFPL，切 `tokio-tun`（MIT OR Apache-2.0）——`platform::tun` 是唯一
  接触点，切换不波及其他 crate。
- **macOS 地址/路由配装缺口**：`open_tun` 只给设备，utun 的地址与路由仍需要 macOS 侧的
  `setup_interface`/`add_route`（现有非 Linux 桩返回 `Unsupported`）。这是 Task 32 的
  隐含后续，需单独评估 `net-route`（spec §13 已列「维护弱，mac/Win 保留 fork 预案」）。
- **boringtun 0.7.1 不支持增量改 endpoint**（实现时发现）：`Device::update_peer` 对
  已存在 peer 直接 `panic!`，`set=1` 协议也没有「只改 endpoint」的增量操作，因此
  `WgBackend::set_peer_endpoint`（打洞时 2.5s 轮换候选的核心路径）在 boringtun 后端
  曾**无法忠实实现**。**（2026-08-13 已实现）** 现已补上「remove + 完整 re-add」重建
  路径：后端维护每 peer 的完整 `PeerSpec`（allowed_ips/keepalive），`set_peer_endpoint`
  时 remove 后用新 endpoint 重加，打洞循环在 boringtun 后端**功能上可用**。仍保留
  「可用 vs 生产成熟」差距——它比内核后端真正的增量更新重（每次 endpoint 轮换是两次
  `set=1` 往返）、且真实 socket 路径需 root 仅编译验证；`daemon.rs` 的 macOS 接线仍是
  单独后续步骤，非本次变更。若切 gotatun（其 API 支持增量）仍可进一步收敛此路径。
- **重新评估的触发条件**：
  1. **gotatun 发布 1.0 或 2026 审计通过** → 把 `crates/wg-userspace` 从 boringtun 切到
     gotatun（届时接受 MSRV 抬到 1.95 或按当时工作区 MSRV 取舍）。
  2. **工作区因其他原因抬 MSRV 到 ≥1.95**（例如 rustls/工具链强制）→ 顺带重新评估直引 gotatun。
  3. **boringtun 被弃养 / 出现 RUSTSEC / 预发布 aead 链被 yanked** → 提前切 gotatun 或 NepTUN。
  4. **`tun` crate 的 WTFPL 成为发布/合规障碍** → 切 `tokio-tun`（MIT OR Apache-2.0）。
  5. **Windows（M6）** 需 wintun 驱动 → 重新评估 `platform::tun` 的 Windows 侧用 `tun` crate
     的 `windows` 模块还是直接接 wintun，必要时新 ADR。
