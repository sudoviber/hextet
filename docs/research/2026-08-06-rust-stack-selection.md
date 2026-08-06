# Rust IPv6-only P2P Mesh VPN 技术选型报告

> 调研日期：2026-08-06。所有版本号与日期均已通过 crates.io API / GitHub / 官方公告核实。
> 项目约束：无服务器中转、WireGuard 数据平面、macOS/Linux/Windows 桌面 + OpenWrt、好看的 UI。
> 本文档是 hextet 项目三份立项调研之一，另见 [竞品分析](2026-08-06-competitor-analysis.md) 与 [IPv6 P2P 可行性](2026-08-06-ipv6-p2p-feasibility.md)。

---

## 0. 结论速览（推荐组合）

| 层 | 推荐 | 版本（核实日期） |
|---|---|---|
| WG 数据平面（macOS/Win/兜底） | **gotatun**（Mullvad） | 0.8.1（2026-07-14） |
| WG 数据平面（Linux/OpenWrt） | **内核 WireGuard** + rust-netlink 栈 | netlink-packet-wireguard 0.4.2（2026-07-31） |
| WG 接口统一管理 | defguard_wireguard_rs 或自写薄层 | 0.11.1（2026-07-23） |
| TUN | **tun-rs** | 2.8.8（2026-07-21） |
| 无服务器会合/发现 | **pkarr + mainline**（BitTorrent DHT） | pkarr 7.0.0（2026-07-17）/ mainline 8.0.0（2026-08-04） |
| 局域网发现 | **mdns-sd** | 0.20.3（2026-07-26） |
| 控制平面信令 | **quinn**（QUIC）+ rustls | 0.11.11（2026-06-22） |
| 路由表 | net-route（跨平台）+ rtnetlink（Linux） | 0.4.6 / 0.21.0 |
| UI | **一套 Web 前端，两个壳**：Tauri 2 桌面壳 + axum 嵌入式 Web UI（路由器） | tauri 2.11.5 / axum 0.8.9 |
| 发布 | cargo workspace + xtask + cargo-dist | dist 0.32.0（2026-05-22） |

---

## 1. WireGuard 实现

### 现状盘点

- **boringtun**（[GitHub](https://github.com/cloudflare/boringtun) / [crates.io](https://crates.io/crates/boringtun)）：**没有归档，但经历了 2023-2025 近两年停滞**（issue [#407 "Is this project dead?"](https://github.com/cloudflare/boringtun/issues/407)），2026 年复活：0.7.0（2026-01-14）、0.7.1（2026-05-01）。但 README 明确警告 *"currently undergoing a restructuring, you should probably not rely on or link to the master branch"*，GitHub Releases 页面停留在 2022 年的 0.5.2。状态：活着但动荡，不适合做新项目地基。
- **GotaTun**（Mullvad，[GitHub](https://github.com/mullvad/gotatun) / [crates.io](https://crates.io/crates/gotatun)）：**本次调研最重要的新变量**。2025-12-19 [官宣](https://mullvad.net/en/blog/announcing-gotatun-the-future-of-wireguard-at-mullvad-vpn)，boringtun 的 fork，多线程 + 零拷贝重写，已在 Mullvad Android 生产环境全量（崩溃率 0.40%→0.01%），2026 年计划第三方安全审计并在全平台替换 wireguard-go。crates.io 上发版节奏很快（0.6.0→0.8.1，2026 年 4-7 月），支持 Linux/macOS/Windows/Android/iOS（x86_64+aarch64），可 `--lib` 构建嵌入。许可 MPL-2.0（2026-03-05 起，此前 BSD-3）。
- **NepTUN**（NordSecurity，[GitHub](https://github.com/NordSecurity/NepTUN)）：boringtun fork，NordVPN 生产使用，最新 v1.0.8（2026-07-21，panic 修复类 hotfix）。**未发布到 crates.io**（需 git 依赖），社区小（16 stars），对外开放度一般。
- **wireguard-rs**（zx2c4 [官方仓库](https://git.zx2c4.com/wireguard-rs/about/)）：早已死亡；crates.io 上 `wireguard-rs` 是 0.0.0 占位（2022）。不要用。
- **defguard_wireguard_rs**（[GitHub](https://github.com/DefGuard/wireguard-rs) / [crates.io](https://crates.io/crates/defguard_wireguard_rs)）：0.11.1（2026-07-23），活跃。定位不是协议实现，而是**统一管理 API**：Linux/FreeBSD/Windows 走内核实现，macOS/用户态走其自维护的 [boringtun fork](https://github.com/DefGuard/boringtun)。defguard 网关和桌面客户端在用，生产验证充分。
- **内核 WG + 用户态控制**：rust-netlink 官方组织活跃 — [rtnetlink](https://crates.io/crates/rtnetlink) 0.21.0（2026-04-18）、[genetlink](https://crates.io/crates/genetlink) 0.2.7（2026-08-04）、[netlink-packet-wireguard](https://crates.io/crates/netlink-packet-wireguard) 0.4.2（2026-07-31）。更高层的 [wireguard-control](https://crates.io/crates/wireguard-control) 2.0.0（2026-07-02，innernet 子 crate，同时支持内核 netlink 与用户态 UAPI socket）、[wireguard-uapi](https://crates.io/crates/wireguard-uapi) 3.0.1（2025-05-10）。
- **tsnet 类比**：Rust 生态没有严格对应物。最接近的是 iroh（"dial by key" 库，见 §3）和 [easytier](https://crates.io/crates/easytier)（整个 mesh VPN 可作为库嵌入）。

### 结论

**推荐**：分平台混合 —
- **Linux 桌面 + OpenWrt**：内核 WireGuard（OpenWrt 上装 `kmod-wireguard`），控制走 netlink（`netlink-packet-wireguard`/`genetlink`，或直接用 `wireguard-control`/`defguard_wireguard_rs` 的高层 API）。性能最好、内存占用最小，路由器上是唯一明智选择。
- **macOS / Windows**：用户态 **gotatun 0.8.1** 嵌入（macOS utun / Windows wintun）。理由：Mullvad 资金充足、生产全量、2026 审计计划、多线程性能是三个 fork 里最好的、且在 crates.io 正常发版。
- 抽象出自己的 `WgBackend` trait（kernel / userspace 两个实现）。boringtun 系 fork 之间 API 相似，后续可换 NepTUN 或回 boringtun，锁定成本低。

**备选**：全平台统一用 defguard_wireguard_rs（省事，但 macOS 侧绑定它的 boringtun fork）；NepTUN（生产验证好但 git 依赖 + 社区封闭）。
**风险**：gotatun 尚未完成第三方审计（2026 计划中）；boringtun 重构走向未知；所有用户态实现吞吐低于内核（一般 1-4 Gbps vs 内核 ~10 Gbps，桌面场景无感）。

---

## 2. TUN 设备

**推荐**：[tun-rs](https://crates.io/crates/tun-rs) 2.8.8（2026-07-21，[GitHub](https://github.com/tun-rs/tun-rs)，极活跃，月更多次）。
理由：同时提供同步/异步 API（tokio 与 async-io 双支持）；平台覆盖最全（Windows/Linux/macOS/FreeBSD/OpenBSD/NetBSD/Android/iOS/OpenHarmony）；Linux 上支持 **TSO/GSO offload 和多队列**（用户态 WG 性能关键，wireguard-go 的提速手段同款）；EasyTier 等 Rust VPN 实际在用。

**备选**：[tun](https://crates.io/crates/tun)（rust-tun）0.8.14（2026-07-21，同样活跃，下载量更大但功能较少）；[tokio-tun](https://crates.io/crates/tokio-tun)（仅 Linux）。tunio、async-tun 已停滞，不选。

平台注意点：
- **macOS**：只有 utun（无 TAP），通过 kernel control socket 创建，接口名强制 `utun[0-9]+`；地址/路由要额外用 `SIOCAIFADDR_IN6`/PF_ROUTE 或 shell out `ifconfig`/`route` 配置；IPv6-only 场景记得设 point-to-point 语义与 NDP 相关 sysctl。
- **Windows**：L3 用 **wintun**（WireGuard 项目的签名驱动 DLL，需随安装包分发 wintun.dll）；绑定选活跃维护的 [wintun-bindings](https://crates.io/crates/wintun-bindings) 0.7.39（2026-06-05），原 `wintun` crate（2025-01）已被它取代。[wireguard-nt](https://crates.io/crates/wireguard-nt) crate（内核 WG 驱动绑定）停在 2024-08，不建议依赖；gotatun 走 wintun 即可。创建适配器需管理员权限——放到 Windows 服务里做。
- **OpenWrt**：数据平面用内核 WG，**根本不需要 TUN**；若一定要用户态，`/dev/net/tun` 可用，但注意 flash/RAM 限制与 netifd 的接口接管（自建接口要么注册为 netifd proto，要么避开它的管理）。

---

## 3. P2P / 发现（无服务器会合的核心）

### pkarr + mainline —— 重点结论：完全满足"无服务器会合"

- [mainline](https://crates.io/crates/mainline) 8.0.0（2026-08-04，[GitHub pubky/mainline](https://github.com/pubky/mainline)）：BitTorrent Mainline DHT 的 Rust 实现，pkarr 作者（Nuhvi/pubky 团队）维护，40.8 万下载，发版频繁（6.x→8.0 半年三个大版本，说明 API 还在演进）。**成熟度：生产可用**——背靠 1000 万+节点、运行 15 年的现存 DHT 网络，无需自举新网络。
- [pkarr](https://crates.io/crates/pkarr) 7.0.0（2026-07-17，[GitHub pubky/pkarr](https://github.com/pubky/pkarr)，104 万下载）：**用 ed25519 公钥作为"主权 TLD"，把签名 DNS 记录发布到 Mainline DHT（BEP44 mutable items）**。对本项目是量身定做：每个节点把自己的 WG 公钥、当前公网 endpoint（IPv6 地址:端口）、mesh 元数据签名后发布，对端只凭公钥即可解析——零服务器。约束要牢记：**记录 ≤1000 字节；DHT 数小时过期，必须周期性 republish**（pkarr 内置 republish 逻辑）；解析延迟秒级，不适合做实时信令，适合做"电话簿"。
- 用法建议：节点身份 = ed25519 密钥（同时派生 WG 密钥与 IPv6 ULA 内网地址，cjdns 式）；pkarr 发布 `_wg.<pubkey>` SVCB/TXT 记录携带 endpoint 候选；打洞信令再走 QUIC 直连或 DHT 中转。

### iroh

[iroh](https://github.com/n0-computer/iroh) 1.0.3（2026-07-20；**1.0 于 2026-06-15 发布**，API 已稳定）：QUIC + NAT 穿透 + 按公钥拨号。关键问题的答案：
- **relay 可选**：`RelayMode::Disabled` / `Endpoint::empty_builder` 支持纯直连模式；默认用 n0 公共 relay 协助打洞并兜底（官方数据 ~90% 能打成直连）。
- **discovery 可插拔**：DNS（n0 托管 dns 服务器）、**pkarr relay、mainline DHT**（`discovery-pkarr-dht` feature）、局域网 swarm discovery（mDNS 类）——它的发现层就是 pkarr 格式（[博客](https://www.iroh.computer/blog/iroh-global-node-discovery)）。
- 定位：如果你想少写打洞代码，iroh 可以整个充当**控制平面**（信令、密钥交换、配置同步走 iroh 连接），WG 走独立 UDP 端口做数据平面。代价：引入它自己的 quinn fork（iroh-quinn）与较大依赖树；纯直连模式下打洞成功率下降（没有 relay 协助的 hole-punch 协调需要你自己在 DHT 上做信令）。

### libp2p

[rust-libp2p](https://github.com/libp2p/rust-libp2p) 0.56.0（2025-06-27）——**workspace 发版已停滞一年以上**，Kademlia 面向内容路由而非节点会合，依赖树和二进制体积代价大（历史 issue [#1051](https://github.com/libp2p/rust-libp2p/issues/1051)），identify/mDNS 能用但整体是为区块链/IPFS 场景设计。**本项目不推荐**。

### 局域网发现

[mdns-sd](https://crates.io/crates/mdns-sd) 0.20.3（2026-07-26，活跃，无 async runtime 依赖，389 万下载）——推荐。searchlight 0.3.2 停在 2023-09，弃。注意 IPv6 multicast scope（ff02::fb）与多接口处理。

**推荐**：pkarr(7) + mainline(8) 做广域会合，mdns-sd 做局域网发现，自实现 UDP 打洞（辅助 crates：[stunclient](https://crates.io/crates/stunclient)、[igd-next](https://crates.io/crates/igd-next) 0.17.1 UPnP、[natpmp](https://crates.io/crates/natpmp)、[if-watch](https://crates.io/crates/if-watch) 3.2.2 监听网卡变化）。IPv6-only 场景打洞压力远小于 IPv4（多数是防火墙放行问题而非 NAT）。
**备选**：直接上 iroh 当控制平面（开发速度最快，接受其依赖树与默认基础设施）。
**风险**：mainline/pkarr 主版本仍在快速迭代（API breakage）；DHT 在国内网络环境可达性可能受干扰（BitTorrent DHT 流量特征明显）；1KB 记录上限要求 endpoint 编码紧凑。

---

## 4. QUIC 控制平面

[quinn](https://github.com/quinn-rs/quinn) 0.11.11（2026-06-22）/ quinn-proto 0.11.16（2026-07-04）：**成熟，生产级**——2.5 亿下载，iroh/hickory 等在其上构建。近期 quinn-proto 有 DoS 修复，锁最新 0.11.x。

用 QUIC 做控制平面信令**完全可行且推荐**：自带 TLS 1.3 双向认证（节点证书从 ed25519 身份派生，rcgen 自签）、多流、0-RTT 重连、连接迁移（漫游换网不掉线）。设计上建议：WG 数据平面一个 UDP 端口，QUIC 控制平面复用同一打洞路径或跑在 WG 隧道内部（mesh 建立后配置同步走隧道内，安全模型更简单）。
**注意**：rustls 0.23 默认 crypto provider 已切到 aws-lc-rs（C 依赖、交叉编译痛苦）——在 OpenWrt/嵌入式 target 上显式选 `rustls/ring` provider 或纯 Rust 的 provider（见 §7）。
**备选**：控制信令跑裸 UDP + Noise（snow crate）——更小但要自己造可靠传输。

---

## 5. 系统集成

- **路由表**：跨平台首选 [net-route](https://github.com/johnyburd/net-route) 0.4.6（Linux rtnetlink / macOS PF_ROUTE / Windows IP Helper 统一异步 API，含路由变更监听）。**风险：单人维护、2025-04 后未发版**——体量小，必要时 fork 或内联。Linux 原生用 [rtnetlink](https://crates.io/crates/rtnetlink) 0.21.0（活跃）；Windows 兜底直接调 [windows](https://crates.io/crates/windows) crate 的 `CreateIpForwardEntry2`/`NotifyRouteChange2`；macOS 兜底写 PF_ROUTE socket（参考 net-route 实现）。
- **防火墙**：Linux 用 [nftables](https://crates.io/crates/nftables) 0.6.3（2025-08，JSON 经 `nft` CLI，稳）或 [rustables](https://gitlab.com/rustwall/rustables)（2026-06 活跃，纯 netlink 无 CLI 依赖）；**OpenWrt 上不要直写 nft**，走 fw4/uci（`config zone`/`config rule`）。Windows WFP：无权威 crate，[windows-wfp](https://github.com/lostyzen/windows-wfp)、[wfp](https://github.com/dlon/wfp-rs)（Mullvad 工程师的库）可参考，基本放行规则用 `INetFwPolicy2` COM 或 netsh 足够；WFP 只有做 killswitch/强制路由时才必要。macOS：pf anchor + `pfctl`。
- **服务化**：Linux systemd unit（`Type=notify` + [sd-notify](https://crates.io/crates/sd-notify)，2026-03 活跃）；macOS launchd（模板化 plist 即可，`launchd` crate 停在 2023 无所谓）；Windows 用 [windows-service](https://crates.io/crates/windows-service) 0.8.1（2026-05-08，**Mullvad 维护**，事实标准）。
- **权限模型**：Linux 非 root 运行——systemd `AmbientCapabilities=CAP_NET_ADMIN`；OpenWrt procd 默认 root。macOS：**root daemon（launchd LaunchDaemon）直接开 utun 即可，不需要 Network Extension**——NE/`NEPacketTunnelProvider` 只有走 App Store / 沙盒分发才必须（Mullvad、Tailscale 的直装版都是 root daemon + utun 路线）；开发者签名 + notarization 要做。Windows：LocalSystem 服务持有 wintun 适配器，GUI 以普通用户跑，走本地 IPC（named pipe，[interprocess](https://crates.io/crates/interprocess) 2.4.3 或 gRPC/tarpc over UDS/pipe）与 daemon 通信——**三平台统一成 "特权 daemon + 无特权 UI" 架构**。

---

## 6. UI 技术

**推荐："一套 Web 前端、两个壳"**——UI 写一次（Svelte/React + TypeScript），两种宿主：
1. **桌面：Tauri 2**（2.11.5，2026-07-01；2.0 稳定版 2024-10 发布，已迭代两年）。系统托盘为内置 `TrayIcon` API（底层即 tauri-apps 自家的 [tray-icon](https://crates.io/crates/tray-icon) 0.24.2，2026-07 活跃），菜单/开机自启/单实例插件齐全，产物 ~5-10MB。GUI 只是 daemon 的客户端（IPC/localhost API），不含特权逻辑。
2. **路由器（及桌面 headless）：axum 0.8.9 + rust-embed** 把同一份前端静态产物编进 daemon 单二进制，监听 mesh 内网地址。OpenWrt 上用户浏览器直接访问，零额外依赖。

理由：这是唯一能让"好看"且桌面/路由器体验一致的方案；Web 生态的 UI 上限远高于 Rust 原生 GUI。EasyTier、defguard 均为此路线。
**备选**：egui 0.36（2026-08-05）——纯 Rust、无 webview 依赖，适合快速做调试面板，但要做出精致 UI 成本高；Slint 1.17.1（2026-07-07）——声明式、嵌入式友好，注意 GPL-3/Royalty-free 双许可选择。观赏性排序：Web(Tauri) > Slint > egui。
**TUI**：[ratatui](https://crates.io/crates/ratatui) 0.30.2（2026-06-19，生态霸主）做 `hextet status --tui`，SSH 进路由器时的体验加分项，成本低值得做。
**风险**：Tauri Linux 侧 WebKitGTK 质量参差 + 托盘需 libayatana-appindicator；WebView2 在精简版 Windows 需引导安装。托盘在 Linux Wayland 下的兼容性统一靠 StatusNotifierItem。

---

## 7. OpenWrt / 交叉编译

- **目标架构**：`aarch64-unknown-linux-musl`、`armv7-unknown-linux-musleabihf`、`x86_64-unknown-linux-musl` 均为 Tier 2（有预编译 std，静态链接顺畅）。**大坑：MIPS 全系（mips/mipsel-unknown-linux-musl）已被降为 Tier 3**（[rust-lang/rust#115238](https://github.com/rust-lang/rust/pull/115238)，因 LLVM MIPS 后端 bug），无预编译 std，需 nightly `-Zbuild-std`，且 codegen 质量存疑——**建议首发只支持 aarch64/armv7/x86_64 路由器，MIPS（mips_24kc 老设备）明确列为不支持或 best-effort**。
- **工具**：[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) 0.23.0（2026-06-16，活跃）优先——zig 作 linker 对 musl 静态链接和指定 ABI 极省心；[cross](https://crates.io/crates/cross) 0.2.5（2023 年后未发版，靠 docker 镜像仍可用）备选；正式 ipk/apk 打包最终应过一遍 OpenWrt SDK。
- **体积**：`opt-level="z"` + `lto="fat"` + `codegen-units=1` + `panic="abort"` + `strip`。实测参考（[Althea 的 OpenWrt 实践](https://blog.althea.net/cross-compiling-complex-rust-programs-for-openwrt-targets/)）：简单程序 3.2MB→285KB；本项目 daemon（tokio+quinn+axum+WG 控制）预期 **3-6MB**，16MB flash 设备可行，8MB 紧张（可裁 feature：路由器版去掉 web UI 换 LuCI、去 quinn 换纯 UDP 信令可压到 ~2MB）。
- **crypto 后端（重点坑）**：rustls 默认 provider 已是 **aws-lc-rs**——C 代码 + cmake，交叉编译 OpenWrt 极痛苦，**显式关掉**；`ring` provider 可用但 ring 已进维护模式（[RUSTSEC-2025-0007](https://rustsec.org/advisories/RUSTSEC-2025-0007.html)，rustls 团队接手仅做安全维护）；[graviola](https://github.com/ctz/graviola) 只支持 x86_64/aarch64，MIPS/armv7 无缘。**WG 本身的密码学无此问题**：boringtun 系（含 gotatun）用纯 Rust 的 RustCrypto 栈（x25519-dalek/chacha20poly1305/blake2），任意 target 可编译。QUIC/TLS 在小设备上选 `rustls + ring`，或考虑纯 Rust provider（rustls-rustcrypto，尚不成熟）。
- **包格式**：**OpenWrt 24.10 仍是 opkg/ipk；25.12.0（2026-03-05 发布）是首个 apk 版本**（[公告](https://lists.openwrt.org/pipermail/openwrt-announce/2026-March/000081.html)）——两种都要出，最省事的办法是维护一个 OpenWrt feed（Makefile 写一次，SDK 按目标版本产出 ipk 或 apk）。
- **系统集成**：procd init 脚本（`/etc/init.d/`，`USE_PROCD=1`，`procd_set_param respawn`）；配置放 UCI（`/etc/config/hextet`），daemon 里解析 UCI 或用 ubus 调 `uci` 服务；接口注册为 netifd 协议（参考 wireguard proto）让 fw4 zone 正常工作；LuCI app 走现代 JS 路线（前端 `/www/luci-static/resources/view/`，后端 rpcd + ubus ACL，模板照 [luci-app-example](https://github.com/openwrt/luci/blob/master/applications/luci-app-example/README.md)）。

---

## 8. 项目结构规范

```
hextet/
├── Cargo.toml            # workspace, resolver = "3", [workspace.dependencies]/[workspace.lints]
├── crates/
│   ├── core/             # 身份/密钥、mesh 协议状态机、pkarr 发现、打洞（纯逻辑，可测试）
│   ├── wg/               # WgBackend trait + kernel(netlink)/userspace(gotatun) 实现
│   ├── platform/         # TUN、路由表、防火墙、服务化的平台抽象
│   ├── daemon/           # tokio 主体 + axum API/Web UI + IPC server
│   ├── cli/              # 控制 CLI + ratatui TUI（与 daemon IPC）
│   └── proto/            # daemon<->UI 的 IPC/API 类型（serde 共享）
├── apps/desktop/         # Tauri 2 壳（Rust 侧薄）
├── web/                  # 前端（同时供 Tauri 与 axum 嵌入）
├── xtask/                # cargo xtask：openwrt 打包、前端构建编排、发版检查
└── openwrt/              # feed：Makefile、procd init、uci 默认配置、luci-app
```

- **xtask 模式**（[matklad/cargo-xtask](https://github.com/matklad/cargo-xtask)）：`cargo xtask dist-openwrt --target aarch64` 之类的自动化不依赖 make/shell，跨平台一致。
- **发布**：[cargo-dist](https://github.com/axodotdev/cargo-dist) 0.32.0（2026-05-22，axodotdev 活跃维护；astral 曾短暂 fork，改进已并回 0.29+）负责 GitHub Releases、安装器（shell/powershell/homebrew/msi）与 checksum；OpenWrt 的 ipk/apk 它不覆盖，放 xtask + SDK CI。配套 release-plz（版本/changelog）、cargo-deny（许可与 RUSTSEC 审计——本项目依赖 ring/MPL 组件，必配）。
- **参考项目**（结构与代码皆可抄）：[innernet](https://github.com/tonarino/innernet)（v1.7.1，2025-11；kernel WG + wireguard-control 的干净范例）、[EasyTier](https://github.com/EasyTier/EasyTier)（v2.6.4，2026-05-12；**与本项目定位最接近的成熟先行者**——Rust/tokio、P2P mesh、打洞、多平台 + OpenWrt，强烈建议通读其架构再动手，并想清楚差异化：本项目的 IPv6-only、纯 WG 数据平面、pkarr 无服务器会合、UI 质量即卖点）、[defguard](https://github.com/defguard)（WG 管理 + Tauri 桌面客户端范例）。

---

## 主要风险汇总

1. **gotatun 年轻**（2025-12 才公开，审计未完成）——用 trait 隔离，保留换 NepTUN/boringtun 的退路。
2. **mainline/pkarr API 仍在快速 break**（半年三个大版本）——锁版本、封装在 discovery crate 内。
3. **net-route 维护性弱**——做好 fork 预案；Linux 侧始终有 rtnetlink 兜底。
4. **MIPS 路由器实际不可行**（Tier 3 + build-std），需在支持矩阵里明说。
5. **rustls 默认 aws-lc-rs 的交叉编译坑**——CI 里对每个 musl target 跑编译验证，crypto provider 显式声明。
6. **DHT 可达性**受网络环境影响（尤其国内）——设计上支持用户自填静态 endpoint / 自建 pkarr relay 作为逃生门。
