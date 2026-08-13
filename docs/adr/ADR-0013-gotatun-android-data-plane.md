# ADR-0013：Android 数据面采用 gotatun，并敲定 VpnService fd 的接线方式

- **状态**：已接受（文档 + 决策，未实现；实现是 M7 数据面片的后续）
- **日期**：2026-08-13
- **决策者**：hextet 项目
- **相关**：`docs/superpowers/specs/2026-08-06-hextet-design.md` §8 M7 / §9 Android 行 / §13、
  `docs/superpowers/plans/2026-08-13-m7-android.md` 切片 C、
  `docs/adr/ADR-0007-gotatun-userspace-backend.md`（gotatun 的原始选型与「再评估触发条件」）、
  `docs/adr/ADR-0012-android-ffi-boundary.md`（FFI 边界，本 ADR 的姊妹片）、
  `crates/wg/src/lib.rs`（`WgBackend` trait）、`crates/wg-userspace/src/lib.rs`（现有 boringtun 后端，
  只有 linux/macos 分支、`set_peer_endpoint` 走 remove+re-add）、
  `crates/platform/src/tun.rs`（TUN 抽象，ADR-0007 决策 2 预留的 gotatun `tun` 适配点）、
  `Cargo.toml`（`[workspace.package] rust-version = "1.85"`）、`rust-toolchain.toml`（`channel = "stable"`）、
  `deny.toml`（MPL-2.0 已放行）

## 背景

M7（Android，v1.0 必含）的数据面 = spec §9「gotatun（in-process）+ VpnService 前台服务」。ADR-0012
已敲定 FFI 边界，但把数据面明确留给了本 ADR（`backend::platform_default()` 与
`wg-userspace::create_device` 都只有 linux/macos 分支，没有 android 分支）。ADR-0007 当时（2026-08-12）
因为两条硬事实暂缓直引 gotatun——(a) MSRV 1.95 > 工作区 1.85；(b) pre-1.0 且「审计 2026 进行中」——
并把「发布 1.0 或 2026 审计通过」列为切换触发条件 1。本 ADR 落地前必须重新查证这两条是否已变化，
并裁定四件事：**切换时机（D1）**、**MSRV（D2）**、**crypto provider（D3）**、以及最关键的
**VpnService fd 怎么喂给 gotatun（D4）**——Android 的 `VpnService.Builder.establish()` 返回的是一个
`ParcelFileDescriptor`（一个 fd），**不是** tun 设备名，而 boringtun/gotatun 的常规路径都是「按名开设备」。

本轮查证到的外部事实（截至 2026-08-13，来自 crates.io / docs.rs / GitHub `mullvad/gotatun` 与
`mullvad/mullvadvpn-app` 仓库源码，未在本机安装 Android NDK，也未下载/编译 gotatun）：

| 项 | 事实 | 出处 |
|---|---|---|
| **最新版本** | crates.io 最新仍为 **0.8.1**（2026-07-14 发布），**pre-1.0 未变**；git `main` 工作区成员版本为 0.9.0（未发布）。即 ADR-0007 的「0.8.1」**至今仍是 crates.io 最新**，1.0 尚未发布。 | GitHub Releases（v0.8.1 为最新 tag）、docs.rs「latest = 0.8.1」、`gotatun/Cargo.toml` |
| **MSRV** | `rust-version = "1.95"`（workspace.package，`gotatun` 成员继承），edition 2024。与 ADR-0007 记录一致，未降。 | `mullvad/gotatun` 根 `Cargo.toml` |
| **许可证** | **MPL-2.0**（2026-03-05 之前的贡献在 BSD-3-Clause，见 `LICENSE-CLOUDFLARE`）。`deny.toml` 已放行 MPL-2.0（ADR-0012 亦注明「为 gotatun 预留的条目」）。 | 根 `Cargo.toml` `license = "MPL-2.0"`、`deny.toml` |
| **安全审计** | **已完成并通过**：Assured Security Consultants 于 2026-01-19 至 2026-02-15 审计 v0.2.0（范围含 `tun` 依赖、排除 gotatun-cli 与 DAITA），结论「**no major vulnerabilities found**」；2 个 LOW 均已修复（LFSR 会话索引→随机，v0.3.0；载荷补齐 16 字节，v0.3.0），roaming endpoint 修复于 v0.4.0。报告 2026-02-17 发布、Mullvad 博客 2026-03-06。**这直接满足了 ADR-0007 的触发条件 1 后半段（审计通过）。** | `audits/2026-02-17-Assured.md`、`assured.se` PDF、mullvad.net 博客 |
| **生产验证** | Mullvad 博客原话：「GotaTun was released in our Android app last year… plan to roll it out across all remaining platforms during 2026」——即 gotatun **已是 Mullvad Android 客户端的数据面**（生产同款，spec §8 原话）。 | mullvad.net 博客、`mullvad/mullvadvpn-app` |
| **Android 目标** | `[package.metadata.docs.rs].targets` 含 `aarch64-linux-android`；README「Supported platforms」表列 `x86_64-linux-android` 与 `aarch64-linux-android`（Library ✓）——Android NDK target 是**官方测试**目标。`crate-type = ["cdylib", "rlib", "staticlib"]`。 | `gotatun/Cargo.toml`、README |
| **crypto provider** | features：`default = ["aws-lc-rs"]`、`ring = ["dep:ring"]`、`aws-lc-rs = ["dep:aws-lc-rs"]`，注释明示「`ring`：Combine with `default-features = false` to avoid also pulling in `aws-lc-rs`」「`aws-lc-rs` wins if both」。`ring 0.17.14`、`aws-lc-rs 1.16.2` 均为可选依赖。 | `gotatun/Cargo.toml` `[features]` |
| **`tun` 模块形态** | `tun = ["dep:tun"]`，其中 `tun` 是 **meh/rust-tun 0.8.6 + `async` feature**（即 hextet `platform::tun` 已经在用的同一款 crate）。gotatun 的 tun 侧是 **trait 化**：`DeviceBuilder::with_ip(tun_dev)` 接受任何实现 `TunDevice` trait（`gotatun::tun::tun_async_device::TunDevice`）的类型；gotatun **自己不开设备、也不直接收 fd**，设备 I/O 委托给 `tun` crate 的 `AsyncDevice`。 | `gotatun/Cargo.toml`、`talpid-wireguard/src/gotatun/mod.rs` 的 import |
| **`tun` crate 收 fd** | meh/rust-tun 的 `tun::Configuration` 有 **`raw_fd(fd)`** 方法（从已打开的 fd 构建设备）——这是 Android VpnService fd 的落点。 | docs.rs `tun::Configuration` 方法表、Mullvad 源码 |
| **Mullvad Android 接线** | 见下节「D4 的 Mullvad 先例」，完整机制已从源码确认。 | `talpid-wireguard/src/gotatun/mod.rs`、`talpid-tunnel/src/tun_provider/android/mod.rs` |

RUSTSEC：未查到针对 `gotatun` 的公开 advisory；审计期间曾发现其 `bytes` 依赖的漏洞
（RUSTSEC-2026-0007），但确认 gotatun 不触发、且已升级依赖（以 CI `cargo-deny check` /
`cargo-audit` 为最终事实来源，与 ADR-0007 立场一致）。

### D4 的 Mullvad 先例（从源码逐行确认，这是本 ADR 的核心事实）

Mullvad 的 Android 客户端（`mullvad/mullvadvpn-app`）把 `VpnService` 的 fd 喂给 gotatun 的完整链路，
分四步：

1. **Kotlin 侧**（`TalpidVpnService`）：调 `VpnService.Builder.establish()` 得到 `ParcelFileDescriptor`，
   把它的整数 fd 经 JNI 返回给 Rust——`CreateTunResult::Success { tun_fd: i32 }`。
   （`talpid-tunnel/src/tun_provider/android/mod.rs` 的 `AndroidTunProvider::open_tun_fd` 调
   `openTun` 方法，签名 `(Lnet/mullvad/talpid/model/TunConfig;)Lnet/mullvad/talpid/model/CreateTunResult;`。）
2. **Rust 取 fd**（`talpid-wireguard/src/gotatun/mod.rs` 的 `get_tunnel_for_userspace`）：
   `nix::unistd::dup(&tunnel_device)` → `fd.into_raw_fd()` 得到一个 `RawFd`（dup 是为了把 fd 的所有权
   干净地交给下游，避免 Kotlin 侧与 Rust 侧双重 close）。
3. **fd → `tun` crate 设备**：`tun::Configuration::default(); tun_config.raw_fd(fd);` →
   `tun::Device::new(&tun_config)` → `tun::AsyncDevice::new(device)`。
4. **`tun::AsyncDevice` → gotatun**：`DeviceBuilder::new().with_ip(tun_dev).build()`，其中 `tun_dev`
   是 `tun::AsyncDevice`（实现 gotatun 的 `TunDevice` trait，源码里 `use gotatun::tun::tun_async_device::TunDevice as GotaTunDevice`）。

两个关键旁证（必须一并写进决策，否则 Android 上会踩坑）：

- **MTU 桩**：Mullvad 源码的 HACK 注释——「the `tun` crate does not implement
  `AbstractDevice::(set_)mtu` on Android, instead they are stubbed… GotaTun will try to read the MTU
  from this, so call `set_mtu` here」。即 Android 上 `tun` crate 的 mtu 是桩，须在构造时手动
  `device.set_mtu(config.mtu)`。
- **UDP 必须 `protect()`**：gotatun 的 UDP 出站 socket 在 Android 上必须经 `VpnService.protect(fd)`
  标记，否则隧道的 WG 流量会被 VpnService 自己再次路由进隧道形成死循环。Mullvad 用
  `AndroidUdpSocketFactory`（持 `Arc<Tun>`，`Tun` 内部调 JNI 的 `bypass(int)` → `VpnService.protect`）
  包住 gotatun 的 `UdpTransportFactory`。

## 决策

### D1：切换时机——gotatun 作为「Android 专属第三后端」，编译期选入，不碰 macOS/Linux 的 boringtun 路径

- **Android（`target_os = "android"`）现在就用 gotatun**：审计已通过（LOW 已修）、已是 Mullvad
  Android 生产数据面、官方测试 Android target——ADR-0007 的「pre-1.0 + 审计进行中」两条硬障碍
  已各自消解（审计通过）或大幅弱化（生产验证充分）。
- **macOS/Windows 继续 boringtun，直到 ADR-0007 的全局切换触发条件 1（gotatun 发布 1.0）真正发生**：
  gotatun 仍是 pre-1.0，在「非 Android、已有可用 boringtun 路径」的平台上切过去没有额外收益，
  反而要把已验证的 macOS utun 编排（ADR-0009）再走一遍 gotatun 重写。**风险隔离**：Android 是新
  平台、从零起，用 gotatun 不承担任何回归成本；既有 boringtun 路径一行不动。
- **落点**：`crates/wg-userspace` 新增 `#[cfg(target_os = "android")]` 的 gotatun 后端模块，对外仍导出
  同一个 `UserspaceBackend` 类型（android 上内部选 gotatun，其余平台选 boringtun）；boringtun 实现
  的门控收紧为 `#[cfg(not(target_os = "android"))]`。`crates/engine/src/backend.rs` 的
  `platform_default()` 增加 android 分支返回该后端（ADR-0012 已在「C. cfg 缺口」登记此分支）。
- **不新建 crate**：gotatun 与 boringtun 同属「用户态 WG 数据面」，复用同一个 `WgBackend` 实现骨架
  （`devices`/`aliases`/`peer_specs` 注册表、`DeviceSpec`/`PeerSpec` 类型）与 `mainline`/boringtun 的
  「类型不外泄」隔离纪律。gotatun 的控制面是**进程内 API**（`Device`/`DeviceBuilder`/`Peer`），
  不再是 boringtun 的 Unix socket `set=1/get=1` 文本协议——那套 socket 代码不共享，只共享 trait 与
  类型。若实现时发现 gotatun 模块过大，可再拆 `crates/wg-gotatun`（实现细节，不改变本决策语义）。
- **`set_peer_endpoint` 的增量更新**：gotatun 的进程内 peer API 允许对已存在 peer 更新 endpoint
  （ADR-0007 已断言「gotatun 支持增量」；审计的「endpoint only updated on handshake initiation」
  是 NOTE 且已在 v0.4.0 修复 roaming）。预期可让打洞轮换从 boringtun 的「remove+re-add 两次往返」
  收敛为单次更新——**具体 API 形态（`Device::configure` 还是 `Peer` 重建）实现时验证**，本 ADR 不
  下结论。

### D2：MSRV——保持工作区 `rust-version = "1.85"`，gotatun 用 target 门控依赖隔离，不抬全局 MSRV

- **不改 `[workspace.package] rust-version = "1.85"`**。`rust-version` 是 workspace 级别的元数据字段
  （每个成员默认继承、可各自覆盖），它承诺的是「本工作区用 rustc 1.85 可编译」。gotatun 的
  `rust-version = "1.95"` 约束的是**编译 gotatun 本身**所需的工具链，与我们的 workspace 字段无关。
- **gotatun 写成 `[target.'cfg(target_os = "android")'.dependencies]`**：这样它只进入 Android 目标的
  依赖图，host（macOS）/Linux/OpenWrt 的构建**完全不解析进编译** gotatun，`cargo build --workspace`
  在 1.85 上照旧全绿。Android 交叉编译本来就必须用一套 ≥1.95 的 NDK 工具链——1.95 的约束落在
  本就特殊的 Android 构建里，不产生额外负担。
- **效果**：`rust-version = "1.85"` 的承诺对默认目标集（macOS/Linux/OpenWrt/Windows）依然成立；
  只有「build Android 目标」这一条路隐含要求 ≥1.95（并如实写进 `docs/dev/build.md`）。全局
  1.85→1.95 抬升（动 OpenWrt musl 交叉工具链、CI rust 镜像）**推迟**到全局切换 gotatun
  （ADR-0007 触发条件 1/2）时与其它依赖一起做，不因 Android 而被迫提前。
- 备选（已否）：全局抬 1.95——连带 OpenWrt musl 交叉工具链与 CI 镜像一起动，风险面大且对
  Android 毫无必要；钉老 gotatun 版本绕 1.95——不存在「更低 MSRV 的 gotatun」，gotatun 自 0.1
  起就定位 1.95 附近（workspace 一直是 edition 2024 / rust-version 1.95），无可用旧版。

### D3：crypto provider——显式 `ring`，`default-features = false`

- gotatun 依赖写作 `gotatun = { version = "=0.8.1", default-features = false, features = ["ring", "tun", "device", "socket"] }`。
- **为什么 `ring`**：spec §13 的硬约束——「rustls 默认 aws-lc-rs 交叉编译坑 → 显式 ring provider」。
  `aws-lc-rs` 是 C/汇编（aws-lc 的 Rust 绑定），Android NDK 交叉编译（尤其 `aarch64-linux-android` +
  链接器）是其已知痛点；`ring` 0.17.14 是纯 Rust + 少量预编译汇编，Android 支持成熟。且 boringtun
  本就依赖 `ring 0.17`——选 `ring` 等于**不新增第二套 crypto 依赖树**，`ring 0.17.x` 在依赖图里
  只有一份。
- **必须 `default-features = false`**：gotatun 的 feature 注释明示「aws-lc-rs wins if both」——若留着
  default 的 `aws-lc-rs`，即便同时开 `ring` 也是 aws-lc-rs 胜出，等于没换。关掉 default、只开
  `ring`，把 aws-lc-rs 彻底挡在依赖树外（它的 C 构建也被跳过）。
- **代价（诚实）**：Assured 审计的 NOTE 提到 `ring` 与 `tun` crate 由单/少数人维护、是长期供应链
  风险点，并建议「consider… replacement of select dependencies such as tun and ring」。本决策接受此
  风险：`ring` 是 RustCrypto 之外事实标准的 crypto 原语库、被 boringtun/quinn 生态广泛使用，且与
  现有 boringtun 依赖树一致；若未来 `ring` 出问题，切 `aws-lc-rs` 只是改一行 feature（反向切换
  成本低，且届时 Android 交叉编译工具链可能已改善）。

### D4：VpnService fd 接线——gotatun 不直接收 fd，经 meh/rust-tun 的 `Configuration::raw_fd` 桥接

- **关键事实（回答本 ADR 的核心问题）**：gotatun 的 `tun` 模块**不接受裸 fd**，也**不按名开设备**。
  它是 trait 化的——`DeviceBuilder::with_ip(tun_dev)` 吃一个实现 `TunDevice` trait 的类型。设备的
  打开（含 Android 的「从 fd 打开」）全部在 meh/rust-tun 里，`tun` crate 的 `Configuration::raw_fd(fd)`
  就是 Android VpnService fd 的落点。
- **决定采用 Mullvad 同款四步接线（不做自研 shim）**：
  1. Kotlin `VpnService.Builder.establish()` → `ParcelFileDescriptor` → JNI 把整数 fd 传进 Rust
     （镜像 Mullvad 的 `CreateTunResult::Success { tun_fd: i32 }`；这一半属于 M7 切片 D 的
     VpnService 壳，本 ADR 只约定边界契约）。
  2. Rust 侧 `dup` + `into_raw_fd` 取得独占的 `RawFd`（避免 Kotlin/Rust 双重 close）。
  3. `tun::Configuration::default().raw_fd(fd)` → `tun::Device` → `tun::AsyncDevice`
     （并**手动 `device.set_mtu(mtu)`**，因为 `tun` crate 在 Android 上把 mtu 桩掉了——Mullvad HACK）。
  4. `gotatun::DeviceBuilder::new().with_ip(async_tun).with_udp(protected_udp_factory).build()`。
- **UDP 侧（同样关键）**：gotatun 的 `with_udp` 接受一个 `UdpTransportFactory`；Android 上必须用
  `VpnService.protect(fd)` 把 WG 的 UDP socket 标记为「不进隧道」，否则死循环。镜像 Mullvad 的
  `AndroidUdpSocketFactory`（持 `Arc<Tun>` 调 JNI `bypass(int)`）。
- **与 ADR-0007 决策 2 的关系（须诚实记录的细化）**：ADR-0007 设想「给 gotatun 的 `gotatun::tun`
  trait 写适配器、经 `platform::tun` 承接」。查证后的现实是：gotatun 要的是 `tun` crate 的
  **`AsyncDevice`**（async feature），而不是 `platform::tun` 现在封装的**同步** `tun::Device` +
  `read_packet`/`write_packet` 包装——gotatun 自己驱动设备 I/O（`with_ip`），不需要我们的读写
  抽象。因此**不**经 `platform::tun` 桥接：fd→`AsyncDevice`→gotatun 的接线放在
  `wg-userspace` 的 gotatun 模块内（与 Mullvad 同构），`platform::tun` 保持现状服务
  boringtun/Wintun 路径。这是对 ADR-0007 决策 2「保留 `platform::tun` 供 gotatun 适配」的
  **范围细化**（不是推翻——`platform::tun` 仍为 boringtun 路径服务，只是 gotatun 路径不复用它）。

## 理由（取舍对照）

- **D1 为什么「Android 现在切、其余平台不切」**：审计通过 + 生产验证 + 官方 Android target，把
  ADR-0007 的障碍从「两条硬事实」变成「只剩 pre-1.0 一条软约束」；而 Android 是从零的新平台，用
  gotatun 零回归成本。反过来在 macOS/Windows 切 gotatun 要重做 ADR-0009 的 utun 编排与 wintun 验证，
  却只换来「预 1.0 的线程重写性能提升」——在 macOS/Windows 无内核 WG 对照、单线程 boringtun 够用
  的前提下，风险收益不划算。所以「全局切换」仍等 ADR-0007 触发条件 1（1.0 发布）。
- **D2 为什么「target 门控隔离」而非「全局抬」**：`rust-version` 是 workspace 元数据承诺，不是
  工具链文件（`rust-toolchain.toml` 是 `stable`，本就不锁版本）；真正受 1.95 影响的只有 Android
  交叉这条本就特殊的路径。全局抬 1.95 会连坐 OpenWrt musl 交叉工具链 + CI 镜像，属于「为 Android
  单独买单」，不符合「风险隔离」。
- **D3 为什么 `ring`**：spec §13 直给的交叉编译硬约束 + boringtun 已用 ring 0.17（不新增依赖树）+
  `default-features = false` 才能真把 aws-lc-rs 挡在门外（其 feature 注释明示 aws-lc-rs 优先）。
- **D4 为什么不做自研 fd shim**：gotatun 根本不收 fd，自研 shim 只会是「自己再包一层
  `tun::AsyncDevice` 去实现 `TunDevice`」——无意义地重复 meh/rust-tun 已有的 `raw_fd` 路径，还多一处
  要维护、要 `unsafe` 的代码。Mullvad 已用同一套四步在生产跑通 Android，是「production same model」
  的最强证据。他出 `raw_fd` 已把 fd 的 unsafe 内聚在 crate 内，hextet 侧零 unsafe（满足
  `[workspace.lints.rust] unsafe_code = "deny"`）。

## 与 spec 的偏离记录

- spec §9 写「macOS/Windows 也用 gotatun」——本 ADR 维持 ADR-0007 的「先用 boringtun 过渡」不变，
  只把 **Android** 这个新平台直接用 gotatun。最终方向一致（gotatun 是全局目标后端），时间表分层。
- ADR-0007 决策 2 设想「`platform::tun` 是 gotatun `tun` trait 的适配点」——本 ADR 细化为「gotatun
  路径不复用 `platform::tun`，直接 `tun::AsyncDevice` 接线」（见 D4），`platform::tun` 继续服务
  boringtun/Wintun。属范围细化，不是方向变更。

## 代价与再评估

- **pre-1.0 残留风险**：gotatun 仍是 pre-1.0，API 可能在 0.9/1.0 之间 break。缓解：锁死 `=0.8.1`
  （沿用 mainline/boringtun/uniffi 的锁版本先例）、封装在 `wg-userspace` 内、类型不外泄；升级时
  只在 gotatun 模块内改适配层。
- **`ring`/`tun` 单点维护**（审计 NOTE）：接受，见 D3；反向切 `aws-lc-rs` 成本低。
- **gotatun 依赖树新增**（`zerocopy`、`typed-builder`、`ip_network_table` 等）：比 boringtun 重，
  但只进 Android 目标图，不污染 host 构建；`cargo-deny`/`cargo-audit` 常开兜底。
- **`tun` crate 的 Android 路径是桩/弱实现**（mtu 桩、`name()` 语义、`raw_fd` 的 android 分支）：
  与 ADR-0010 对 wintun 的诚实度一致，真机验证前不声称「能跑」。
- **VpnService 槽位冲突**：与 ADR-0007 无关，属 M7 切片 F，本 ADR 不重复裁决。

### 重新评估的触发条件

1. **gotatun 发布 1.0**（ADR-0007 触发 1）→ 全局切换 boringtun→gotatun，届时一并抬全局 MSRV 到
   1.95（动 OpenWrt musl 交叉 + CI 镜像）、重估 macOS utun 编排与 wintun 路径。
2. **gotatun 0.8.1 出现 RUSTSEC / 被 yanked** → 回退方案：Android 数据面退回 boringtun 的
   Android 分支（boringtun 的 `TunSocket` 平台实现 + `raw_fd` 路径），或评估 NepTUN。
3. **`ring` 出现 RUSTSEC / 弃养** → 切 `aws-lc-rs`（反向一行 feature），或换 RustCrypto 栈。
4. **`tun` crate 的 WTFPL 成为合规障碍**（ADR-0007 触发 4 的延续）→ `tokio-tun` 或评估其
   Android fd 支持，仅 `platform::tun` 与 gotatun 模块两个接触点。

## 未能验证（落地前须确认）

- **Android 目标编译/链接**：本机（macOS）无 NDK，gotatun 未下载、未编译。以上事实全部来自
  crates.io/docs.rs/GitHub 源码与文档，**没有任何一条在本机运行验证过**。第一处真实编译验证点是
  `cargo check --target aarch64-linux-android`（需 NDK）+ CI Android runner。
- **`tun::Configuration::raw_fd` 在 Android 分支的确切行为**（是否要求 `set_mtu` 先于 `Device::new`、
  `name()` 返回什么）：据 Mullvad 源码推断，未本机验证。
- **gotatun 进程内 peer 增量 endpoint 更新的确切 API**（`Device::configure` / `Peer` 更新 vs 重建）：
  实现 `WgBackend::set_peer_endpoint` 时验证。
- **UDP `protect()` 的 JNI 往返**：属于 M7 切片 D 的 VpnService 壳，本 ADR 只约定契约，未验证。
- **`wg-userspace` 的 `#[cfg(not(target_os = "android"))]` 门控对现有 macOS/Linux 编译的影响**：
  实现时确认 boringtun 代码在收紧门控后依旧 macOS/Linux 全绿。

## 后续实现步骤（切片 C-impl，待 Android/NDK 工具链就位后执行）

1. `Cargo.toml`：新增 `[target.'cfg(target_os = "android")'.dependencies]` 的 `gotatun = { =0.8.1, default-features = false, features = [ring, tun, device, socket] }` 与 `tun`（`async` feature）依赖。
2. `crates/wg-userspace`：boringtun 实现门控收紧为 `#[cfg(not(target_os = "android"))]`；新增
   `#[cfg(target_os = "android")]` 的 gotatun 后端模块（`WgBackend` 五方法 + fd→`AsyncDevice`→
   `with_ip`/`with_udp` 接线 + `protect()` UDP factory）。
3. `crates/engine/src/backend.rs`：`platform_default()` 增加 android 分支。
4. `cargo check --target aarch64-linux-android` + CI Android runner 编译验证（类型检查/链接）。
5. M7 切片 D：Kotlin `VpnService.Builder.establish()` → fd 的 JNI 侧 + 前台服务，与本 ADR 的
   Rust 侧 fd 契约对接。
