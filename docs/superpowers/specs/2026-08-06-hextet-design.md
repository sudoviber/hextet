# hextet 设计文档

> 状态：待用户批准（draft v2——按 2026-08-06 用户反馈修订：手机端提前至 v1.0 内、自有节点中继进 MVP、前端 React、纳入用户既有网络环境共存约束）
> 日期：2026-08-06
> 依据：docs/research/ 下三份立项调研（[竞品分析](../../research/2026-08-06-competitor-analysis.md)、[Rust 技术选型](../../research/2026-08-06-rust-stack-selection.md)、[IPv6 P2P 可行性](../../research/2026-08-06-ipv6-p2p-feasibility.md)）

---

## 1. 概述

**hextet** 是一个用 Rust 编写的 IPv6-only P2P 异地组网工具（mesh VPN）：节点之间走 IPv6 直连，数据不经过任何服务器中转，也没有任何在线协调服务器；极端场景可显式启用**你自己的节点**做中继（加密透传，见 D5）。数据平面直接复用 WireGuard 协议，控制平面完全去中心化。

**命名**：hextet 是 IPv6 术语——IPv6 地址中每个冒号分隔的 16-bit 段就叫 hextet，与项目的 IPv6-only 定位直接呼应。crates.io 上该名称未被占用，GitHub 无同名知名项目（已于 2026-08-06 核实）。

**市场空位**（来自竞品调研）："开源 Tailscale"赛道已经拥挤（NetBird / Headscale / Netmaker），但"**无任何在线控制面 + 现代体验**"只有 Nebula 沾边且体验差。hextet 的定位一句话：**Nebula 的信任模型 + Tailscale 的体验 + Rust 的资源占用，且 IPv6-only 让这一切变得简单**。

**核心洞察**：IPv6 消除了 NAT 打洞的算法性失败（无端口改写、无对称 NAT），把"P2P 组网"的难题收敛为两件工程上可控的事——**状态防火墙打洞**（双向同时发包，成功率高于 IPv4 打洞）和**会合**（对端地址变了怎么重新找到彼此）。省下的 STUN/TURN/DERP/生日攻击全部复杂度，兑换成小而可审计的代码库。

## 2. 目标与非目标

### 目标

1. **IPv6 直连优先**：默认所有节点间流量走 IPv6 P2P 直连，零服务器中转；唯一例外是显式启用的自有节点中继（D5），且状态永远透明可见。
2. **无在线控制面**：没有协调服务器；成员管理靠离线签发的邀请/证书 + 网内 gossip。
3. **穿透状态防火墙**：把 IPv6 防火墙打洞做成一等公民（业界空白），内置可达性诊断（`doctor`）。
4. **动态前缀自愈**：中国家宽 PPPoE 重拨换前缀后自动恢复连接（目标 <5s），双端同变有完整兜底链。
5. **路由器组网**：OpenWrt 一等公民——site-to-site 子网路由，LAN 设备无需装客户端。
6. **好看的 UI**：桌面 GUI（Tauri）+ 路由器 Web UI 同一套精心设计的前端；CLI/TUI 同样讲究。
7. **正式项目工程规范**：cargo workspace 多 crate、CI、文档同步、测试策略、发布工程从第一天就位。
8. **移动端（Android 优先，v1.0 必含）**：Android 客户端（VpnService + 按需连接模式）在 v1.0 前交付；iOS 紧随 v1.0 之后（需 Apple 开发者账号与 NEPacketTunnelProvider，流程重）。核心引擎从 M0 起保持可嵌入（FFI-ready），避免 Nebula 式"移动端事后补"的残缺。
9. **与既有网络环境共存**：与 Clash/mihomo 系透明代理（TUN + fake-IP）及迁移期的 Tailscale 无冲突并存——hextet 永不接管系统 DNS，路由只加自己的 ULA 前缀。

### 非目标（明确不做）

1. **项目方运营的中继基础设施**（DERP/TURN 舰队类）——任何中继只能是**该网络内用户自有的节点**，默认关闭、显式启用、UI 明确标示 relayed 状态与原因（见 D5）。
2. **IPv4 NAT 穿透全家桶**——无 STUN 分类、无 UPnP/NAT-PMP、无端口预测。
3. **IPv4 overlay 地址管理**——overlay 地址由密钥派生，无 IPAM。
4. **L2 以太网仿真/桥接/组播**——L3-only。
5. **多跳全局路由算法**（Yggdrasil 树路由 / Mycelium Babel / EasyTier OSPF）——不做任意拓扑动态收敛；自有节点中继是显式配置的单跳转发，不引入路由协议。
6. **企业 SSO/IdP/审计**——身份=密钥；OIDC 留给未来。
7. **自研密码学**——Noise/WireGuard 之外不发明任何加密协议。中继节点只转发加密的 WG 包，端到端加密不变、中继不可读流量。

### 诚实的边界（写进产品文档的前提假设）

- 双端都必须有可用的公网 IPv6（GUA）。产品内置 `hextet doctor` 检测并给出指引（含中国光猫 IPv6 SPI 防火墙的机型关闭教程）。
- DHT 会合层需要 IPv4 出站 UDP（Mainline DHT 是 IPv4 网络，BEP32 未普及）——仅控制面弱依赖，数据面纯 IPv6。
- 中国移动（CMCC）蜂窝/部分宽带入站受限最严重；双 CMCC 场景打洞可能失败——此场景正是"自有节点中继"存在的理由（家里常电的路由器/PC 节点做中继）。
- 手机定位是"主动发起方 + 按需连接"，不承诺被动可达（无服务器 = 无推送唤醒通道）；Android 上 hextet 占用 VpnService 单一槽位，与代理类 App 的冲突与 Tailscale 相同——家庭场景优先靠路由器组网让手机在家零客户端。

## 3. 关键设计决策

每项决策附备选与理由；调研出处见三份研究文档。

### D1 数据平面：WireGuard 协议，分平台后端

**决策**：数据面 = WireGuard 协议。Linux/OpenWrt 用**内核 WireGuard**（netlink 控制）；macOS/Windows 用**用户态 gotatun**（Mullvad 的 boringtun 后继，多线程重写，生产验证）。以自有 `WgBackend` trait 隔离两种实现。

**备选**：
- 全用户态（boringtun 系）统一实现——放弃内核性能（内核 ~10Gbps vs 用户态 1-4Gbps），路由器上不可接受；
- 自研 Noise 协议（Nebula/Mycelium 路线）——多年成熟成本，且放弃 WireGuard 生态（配置工具、内核实现、审计积累）；
- NepTUN（NordSecurity）——生产验证好，但不发 crates.io、社区封闭。

**理由**：竞品调研结论——"所有成功者要么用 WG 要么花了数年成熟自研密码学"；WireGuard 的 cryptokey routing（AllowedIPs = 路由+ACL 二合一）与 endpoint roaming（对端换地址自动跟随）正是本项目最需要的两个原语。控制面的本质工作就是"自动化生成与更新 WireGuard 配置"。

### D2 寻址：ULA 前缀 + 密钥派生地址

**决策**：overlay 用 RFC 4193 ULA。`network_id = HKDF(network_key)` 取 40 bit → 网络获得唯一 `fdXX:XXXX:XX::/48`；每节点分得一个 /64（site 前缀，供子网路由）；节点自身地址的 interface ID = `hash(node_pubkey)` 截 64 bit。地址可反查公钥做一致性校验（Yggdrasil 同款防伪）。

**备选**：
- 直接用底层 GUA + 传输模式加密——GUA 一变，上层连接/ACL/DNS 全作废，把动态前缀问题传导给所有应用，不可用；
- 挪用未分配地址段（Yggdrasil 200::/7、Mycelium 400::/7）——IANA 合规瑕疵，ULA 做同样的事完全合规。

**理由**：密钥即地址 → 无 IPAM、无地址冲突、地址自认证；碰撞概率实践为零（RFC 4193 40-bit 前缀 + 网内 64-bit interface ID，成员准入时再做唯一性校验彻底排除）。上层体验稳定：无论家宽前缀怎么变，overlay 地址永不变。

### D3 会合：分层兜底链，全部无项目方服务器

**决策**：按序自动降级（并发预热）：

```
① LAN mDNS/组播发现（同网零成本）
② 缓存端点并发试探（含历史地址；IPv6 无 NAT，端口自己定，只有地址会变）
③ WireGuard roaming（单侧变化自愈，无需任何会合）
④ mesh peer 转介（N≥3 核心机制：存活的第三节点 gossip 双方新地址）
⑤ Mainline DHT / pkarr（BEP44 签名记录；DHT key 用网络密钥加盐派生 + 载荷加密；
   ~1h 重发布 + 地址变化即时发布；DHT 节点表持久化，bootstrap 仅首次冷启动）
⑥ 用户自托管 DDNS（可选：用户自己的域名，客户端调注册商 API 更新 AAAA/TXT；
   中国网络下可达性最好的兜底）
⑦ 手动输入 [GUA]:port（终极兜底：任一侧粘贴即可重新缝合全网）
```

**备选**：iroh 整体充当控制面（开发最快）——但引入其依赖树与默认公共基础设施，且其 relay 语义与"无中转"定位冲突；libp2p——为 IPFS/区块链设计，体积与复杂度不匹配。

**理由**（可行性调研核心结论）：信息论上"双端同时换地址"必须有公共汇合点；最接近"无服务器"的汇合点是 Mainline DHT（1000 万+第三方节点，非项目方运营）。pkarr+mainline 有 iroh 生产先例。N≥3 网络内 ④ 已覆盖绝大多数场景——全网同时换前缀在中国"事件驱动换前缀"现实下是小概率事件。

### D4 控制平面：静态配置起步，隧道内 gossip 演进

**决策**：
- **身份**：每节点一把 ed25519 身份密钥（派生 WG x25519 密钥与 overlay 地址）。
- **成员资格**：邀请制。admin 生成一次性 invite token = {network 参数, 引导端点, 一次性授权}；新节点凭 token 与任一现有节点建立 WG 会话，网内注册，获得 admin 签发（或授权节点代签）的成员证书，gossip 全网。吊销 = 签名 revocation 条目 gossip + 数据面立即拒绝该公钥。
- **状态分发**：M1–M2 用静态配置文件（TOML，可 git 管理）；M3 起控制面消息（endpoint 更新、成员增删、子网路由宣告）走 **QUIC over WG 隧道内**（quinn，连 overlay ULA 地址）的签名 gossip，LWW/单调 seq 收敛。静态配置作为兜底方式永久保留。
- **信任双层**：network key（gate DHT 记录派生与加密，泄露只泄露"谁在哪"）+ 节点密钥（数据面认证，泄露才破机密性）。

**备选**：TOFU（不适合 VPN 信任模型）；纯共享密钥（EasyTier 模式——无 ACL、无吊销，反面教材）；在线 CA 服务（违背无服务器定位）。

**理由**：innernet 证明"控制面流量走隧道内"安全模型漂亮（协调件无公网暴露面）；Nebula 证明"离线签发"可行但纯静态在 10 台规模就痛苦——所以 gossip 自动化是必需的演进，不是可选项。

### D5 转发策略：直连优先 + 自有节点中继逃生舱（MVP 内）

**决策**：直连永远是第一选择与默认唯一路径。同时 MVP（M3）就提供**自有节点中继**：用户可把网络内任一常电节点（典型：家里的路由器/PC）显式声明为 relay；两端直连失败时（典型场景：双 CMCC 蜂窝）经该节点转发。约束：
- 中继节点**只在 UDP 层转发加密的 WireGuard 包**，不解密、不终结会话——端到端加密不变，中继不可读流量；
- **默认关闭**，须网络管理员显式启用某节点为 relay；
- 单跳、显式配置，不引入任何路由收敛协议（区别于 EasyTier/Yggdrasil 的转发型 mesh）；
- UI/CLI 明确标示每条连接是 direct 还是 relayed 及其原因，绝不静默降级到让用户以为是直连。

**备选**：完全不做转发（v1 直连或失败）——被用户否决：可靠性优先，双 CMCC 等真实场景必须可用；自动选任意节点做中继（Tailscale Peer Relays 自动化语义）——放弃，保持行为可预测。

**理由**：语义与 Tailscale Peer Relays 同源（用户自有节点、加密透传），但永远显式。"不经过任何服务器中转"的承诺不变——中继者是你自己的设备，不是任何人的服务器。innernet 的教训依然成立：`doctor` 与失败诊断仍是 MVP 功能。

### D6 UI：一套 Web 前端，两个壳

**决策**：UI 只写一份（TypeScript + **React**，用户指定；视觉方向后续用 taste/design skill 单独打磨）：
- **桌面**：Tauri 2 壳 + 系统托盘，GUI 是 daemon 的无特权客户端（IPC）；
- **路由器/headless**：同一前端产物经 rust-embed 编进 daemon（axum），监听 overlay 地址供浏览器访问；
- **CLI**：一等公民，覆盖全部功能；`hextet status --tui`（ratatui）作为 SSH 场景加分项。

**备选**：egui/Slint 原生 GUI——"好看"上限低于 Web 栈；仅 LuCI（路由器）——桌面无解；Svelte——体积更小但用户指定 React（生态最大）。

**理由**：唯一能让桌面与路由器体验一致且达到"好看"要求的方案；EasyTier/defguard 同路线验证。三平台统一"特权 daemon + 无特权 UI"架构（Mullvad/Tailscale 同款）。React 产物体积对路由器 flash 的压力用构建裁剪（vite + 代码分割 + gzip 静态资源）控制，超限时路由器版可退化为轻量状态页 + LuCI。

### D7 许可证：MIT OR Apache-2.0 双许可

从第一天锁定（Rust 生态惯例）。ZeroTier 许可证反复横跳摧毁社区信任的反面教材；宽松许可也是进 OpenWrt 官方 feed 的前提之一。

## 4. 系统架构

```
┌─────────────────────────── 一个节点 ───────────────────────────┐
│                                                                │
│  hextet-daemon（特权，tokio）                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ engine：状态机（peer 生命周期/打洞/会合调度）               │  │
│  │ discovery：mDNS · 端点缓存 · DHT(pkarr/mainline) · DDNS    │  │
│  │ gossip：QUIC(quinn) over 隧道内 · 签名条目 · seq 收敛      │  │
│  │ wg：WgBackend trait ──> kernel(netlink) / userspace(gotatun)│ │
│  │ platform：TUN(tun-rs) · 路由表 · 防火墙 · 地址变化监听      │  │
│  │ api：axum（Web UI + REST）+ IPC(unix socket/named pipe)    │  │
│  └──────────────────────────────────────────────────────────┘  │
│         ▲ IPC                ▲ IPC/HTTP             ▲ HTTP      │
│   hextet-cli (+TUI)    Tauri 桌面壳            浏览器(路由器)    │
└────────────────────────────────────────────────────────────────┘
```

**数据流**：应用 → TUN（ULA overlay）→ WG 加密 → 底层 IPv6 UDP 直连对端 → 对端 TUN。
**控制流**：所有 peer 间控制消息（gossip/成员/路由宣告）走 WG 隧道内的 QUIC；隧道外只有三样东西——WG 握手（兼做打洞探测包）、DHT 查询/发布、mDNS。

**关键设计**：打洞不需要独立信令协议——会合层只负责"知道对方当前 [addr]:port"，然后两端同时发 WireGuard 握手包（指数退避 ≤10s），防火墙 state 相互命中即通。握手包本身就是打洞包。

## 5. 协议要点

- **端口**：每节点固定 UDP 端口（默认 **4193**，致敬 RFC 4193，避开原生 WireGuard 的 51820 以免与用户既有 WG 配置冲突；可配置），IPv6 无 NAT → 端口永远由自己决定，会合记录里只有地址在变。
- **MTU**：默认 1400（中国家宽 PPPoE 1492 − WG IPv6 overhead 80 = 1412，留余量）；TCP MSS clamp；主动 padding 探测（不依赖 PMTUD），可自动升到探测值。
- **keepalive 分级**：常电节点（路由器/PC）25s；探测到纯 IPv6 路径（防火墙 state ≥2min，RFC 6092）自动放宽至 ~110s；移动设备未来按需连接。
- **地址变化响应**：监听 netlink/RA 事件（含 valid-lifetime=0 的静默换前缀），变化后立即：向所有 peer 旧地址发新握手 + gossip 广播 + DHT 即时重发布。目标恢复 <5s。
- **DHT 记录**：`put(key=HMAC(network_key, node_pubkey), value=AEAD_network_key({endpoints, port, epoch}), seq)`——外人无法定位记录也看不懂内容；粗粒度 epoch 保护作息隐私。
- **成员/gossip 条目**：ed25519 签名 + 单调 seq，分区重连后自动收敛（LWW 语义）。
- **中继帧**：relay 节点维护 {双方公钥 → 当前 endpoint} 的会话映射，收到注册后的加密 WG 包按映射转发（UDP 层透传，不解密）；两端持续尝试直连升级，直连恢复即退出中继。
- **DNS 姿态**：hextet **永不接管系统 DNS**。节点名解析用 MagicDNS-lite（生成 hosts 条目），与 Clash/mihomo fake-IP、Tailscale accept-dns 等 DNS 争夺战绝缘——这是用户实际环境（Clash Verge TUN + Tailscale 共存曾因 DNS 冲突踩坑）直接导出的硬约束。
- **路由姿态**：只添加本网络 ULA /48 的路由，前缀具体、优先级明确，与 Clash TUN 的分段默认路由（1/8、2/7…）及 Tailscale 的 100.64/10 + fd7a::/48 天然共存（派生前缀与 Tailscale 的 fd7a:115c:a1e0::/48 冲突概率为零，安装时仍校验）。迁移期与 Tailscale 并跑完全可行。

## 6. 安全模型摘要

| 资产 | 机制 |
|---|---|
| 数据机密性/完整性 | WireGuard（Noise IK），自动 rekey |
| 节点身份 | ed25519 密钥对，地址由公钥派生可验证 |
| 准入 | 一次性 invite token + admin 签发成员证书 |
| 授权/ACL | v1.0：全网互通 + AllowedIPs 前缀约束；v1.0 后：前缀即策略（site /64 层级 → 编译为 AllowedIPs + nftables） |
| 吊销 | 签名 revocation gossip + 数据面拒绝 |
| 会合隐私 | DHT key 加盐派生 + 载荷 AEAD 加密 |
| 中继安全 | 仅转发加密 WG 包（端到端加密不变，中继不可读）；relay 身份=网内成员节点，须 admin 显式授权 |
| 密钥轮换 | 会话：Noise 自动；身份：旧签新 continuity 记录；network key：epoch 双发布渐进迁移 |
| admin key 单点 | 冷存储；多 admin 签名后置 |

## 7. 路由器组网（site-to-site）

- OpenWrt 节点作 site 网关，在成员记录中宣告自己的 overlay ULA /64（+可选额外前缀）；其余节点自动写入 AllowedIPs 与路由表。LAN 设备经 RA/SLAAC 拿到该 ULA /64 地址（与运营商 GUA 多前缀共存，IPv6 原生能力），**无需安装客户端**。
- 跨 site 互访走 overlay ULA（RFC 6724 源地址选择天然正确），**不路由对方动态 GUA**，NPTv6 不需要。
- 两家 LAN 网段冲突问题在 IPv6 下天然消解（每 site 的 /64 由网络前缀派生，全网唯一）。
- OpenWrt 集成：内核 WG + procd init + uci 配置 + 独立 firewall zone（自动注入 lan↔hextet forwarding，IPv6 默认 forward=drop 的坑）+ LuCI app；`sourcefilter` 等 RPF 陷阱在安装时处理。
- 交付：自维护 feed（一份 Makefile，SDK 产出 ipk[24.10] 与 apk[25.12+]）；首发支持 aarch64/armv7/x86_64（MIPS 因 Rust Tier 3 明确不支持）。
- 光猫路由模式下 OpenWrt 是二级路由（如用户环境：华为 V175 FTTR 光猫路由一体作主路由，OpenWrt 路由器接其 LAN 口）→ 二级路由拿到的是光猫 PD 子前缀或仅 /64，且流量要穿两层状态防火墙——打洞语义不变（两层均先建出站 state），但 `doctor` 需识别此拓扑并给出建议（桥接 or 光猫防火墙设置）；overlay ULA 本身不依赖上游 PD。
- **与透明代理共存**（用户实际部署形态：同一台 OpenWrt 跑 OpenClash/mihomo + hextet）：hextet 不碰 DNS（见 §5）、路由仅 ULA 前缀、独立 nftables table/firewall zone，与 Clash TUN 的 fake-IP 分流互不干扰；文档提供该组合的实测指南（Tailscale+OpenClash 共存是社区成熟实践，hextet 同理且更简单——因为根本不参与 DNS）。

## 8. 功能路线图

### MVP（v0.1–v0.3，可用的 CLI 产品）

| 里程碑 | 交付 | 验收 |
|---|---|---|
| **M0 骨架** | cargo workspace、CI（fmt/clippy/test/cargo-deny）、`hextet-core`（身份、地址派生、配置模型）、`hextet keygen/init` | 单测通过；两个身份能派生出同网 ULA |
| **M1 静态直连** | Linux 内核 WG 后端、静态 peer 配置、`hextet up/down/status` | 两台公网 IPv6 Linux 互 ping overlay 地址，吞吐≈内核 WG |
| **M2 动态端点** | 防火墙打洞（双向同时握手）、roaming、netlink 地址监听、端点缓存、`hextet doctor` | 一侧换前缀 <5s 恢复；防火墙后节点可互连；doctor 正确分类 open/stateful/blocked |
| **M3 无服务器会合 + 中继逃生舱** | mDNS、DHT/pkarr（加盐+加密）、隧道内 QUIC gossip（endpoint 更新+peer 转介）、invite 流程、自有节点中继（显式启用，UDP 层加密透传） | 双端同时换前缀后经 DHT 自动恢复；新节点凭 invite 一条命令入网；netns 模拟双端入站全阻场景经第三节点中继连通且 status 标示 relayed |

### v0.4–v1.0

| 里程碑 | 交付 |
|---|---|
| **M4 macOS + 路由器** | gotatun 用户态后端（utun）、launchd 服务、OpenWrt feed 包 + procd/uci + site-to-site 子网路由 + LuCI 骨架 |
| **M5 UI** | axum 嵌入式 Web UI、Tauri 桌面壳 + 托盘（React 前端）、`status --tui`（ratatui）；视觉设计单独立项打磨 |
| **M6 Windows + 发布工程** | wintun + Windows service、cargo-dist 全平台发布、自托管 DDNS 兜底、MagicDNS-lite（hosts 生成）、安全自审文档 |
| **M7 Android（v1.0 必含）** | engine FFI 化（UniFFI）、VpnService 前台服务、gotatun 数据面（Mullvad Android 生产同款）、按需连接模式（打洞 <1s，无常驻 keepalive 省电）、与代理 App 的 VpnService 槽位冲突文档与指引 |

### v1.0 之后（背景板）

iOS（NEPacketTunnelProvider，复用 M7 的 FFI 层）、前缀即策略 ACL、TCP/QUIC 伪装传输（抗 UDP QoS）、多 admin 阈值签名、HA routing peer、中继自动协商（在显式授权节点集合内）。

## 9. 平台支持矩阵（v1.0 目标）

| 平台 | 数据面 | 服务化 | UI |
|---|---|---|---|
| Linux (x86_64/aarch64) | 内核 WG | systemd (`CAP_NET_ADMIN`) | CLI/TUI/Web/Tauri |
| OpenWrt (aarch64/armv7/x86_64, ≥64MB RAM) | 内核 WG | procd + uci | LuCI + 内嵌 Web |
| macOS (arm64/x86_64) | gotatun + utun | launchd root daemon（直装，不走 App Store/NE） | CLI/TUI/Tauri |
| Windows 10+ | gotatun + wintun | Windows service (LocalSystem) | CLI/Tauri |
| Android 10+ | gotatun（in-process） | VpnService 前台服务 | App（复用 React 前端于 WebView 或原生轻壳，M7 定） |
| iOS | — v1.0 后（复用 M7 FFI）— | | |

## 10. 项目结构（cargo workspace）

```
hextet/
├── Cargo.toml            # workspace，resolver="3"，workspace.{dependencies,lints}
├── crates/
│   ├── core/             # 身份/密钥/地址派生、配置模型、协议状态机（纯逻辑，全平台可测）
│   ├── discovery/        # mDNS、端点缓存、pkarr/mainline DHT、DDNS（封锁 API 波动）
│   ├── wg/               # WgBackend trait + kernel(netlink) / userspace(gotatun)
│   ├── platform/         # TUN、路由表、防火墙、地址监听、服务化的平台抽象
│   ├── engine/           # 可嵌入引擎：组装 core+discovery+wg+platform（无进程假设，FFI-ready，M7 经 UniFFI 供 Android 复用）
│   ├── daemon/           # 进程壳：tokio 主循环 + axum(Web UI/REST) + IPC server（桌面/路由器形态）
│   ├── cli/              # hextet 命令行 + ratatui TUI（经 IPC 控制 daemon）
│   └── proto/            # daemon<->UI/CLI 共享类型（serde）
├── apps/desktop/         # Tauri 2 壳（Rust 侧薄）
├── apps/android/         # M7：VpnService 壳 + UniFFI 绑定
├── web/                  # React 前端（Tauri 与 axum 共用同一构建产物）
├── xtask/                # cargo xtask：OpenWrt 打包、前端构建编排、发版检查、doc 检查
├── openwrt/              # feed：Makefile、procd init、uci 默认值、luci-app
└── docs/                 # 见 §11
```

发布工程：cargo-dist（桌面三平台安装器）+ xtask/SDK CI（ipk/apk）+ release-plz（版本/changelog）+ cargo-deny（许可/RUSTSEC）。
参考项目：innernet（wireguard-control 用法）、EasyTier（tokio 工程组织）、defguard（Tauri 客户端）。

## 11. 文档规范（用户硬性要求：每次代码改动同步更新文档）

```
docs/
├── research/             # 立项调研（已有三份，不再随代码更新）
├── superpowers/specs/    # 设计规格（本文档）与后续 feature spec
├── adr/                  # 架构决策记录（ADR-NNNN-*.md）：偏离本设计或新增重大决策时必写
├── protocol/             # 协议规范：地址派生、DHT 记录格式、gossip 条目、打洞流程
│                         #（实现落地时同步撰写，是"协议一页纸讲完"承诺的载体）
├── guides/               # 用户文档：安装、入网、doctor 指引（含中国光猫机型教程）、OpenWrt
└── dev/                  # 贡献者文档：构建、测试、发布、crate 地图
CHANGELOG.md              # Keep a Changelog 格式，release-plz 维护
```

**执行机制**（写进 CONTRIBUTING 与 PR 模板，CI 辅助）：
1. 每个改变行为的 commit/PR 必须同步更新受影响的 docs/ 与 CHANGELOG（PR 模板 checklist）。
2. 协议相关代码（core/discovery）改动必须同步 docs/protocol/ ——CI 用路径规则提示（改了 `crates/core/src/addr*` 却没动 `docs/protocol/addressing.md` 时警告）。
3. 公共 API 全部 rustdoc，`#![deny(missing_docs)]` 于 core/proto 两个 crate。
4. 重大设计变更走 ADR，而不是直接改本 spec（本 spec 冻结为立项基线）。

## 12. 测试策略

- **单元测试**：core/discovery 纯逻辑（地址派生向量、配置解析、gossip 收敛、状态机转换）。
- **属性测试**（proptest）：地址派生无碰撞/可逆校验、协议编解码 roundtrip。
- **网络仿真集成测试**（Linux CI，netns）：多 netns 模拟多节点 + nftables 模拟状态防火墙，覆盖：静态直连、打洞、单侧/双侧换址恢复、peer 转介、成员增删吊销、双端入站全阻下的自有节点中继与直连升级回切。这是本项目最重要的测试层。
- **DHT 测试**：against 本地 mainline 测试网（crate 自带 testnet 支持），不打真实 DHT。
- **E2E 手动矩阵**（发布前）：真实家宽（电信/联通/移动 × 光猫路由/桥接）、OpenWrt 实机、macOS/Windows。结果记录进 docs/dev/e2e-matrix.md。
- **Fuzz**（cargo-fuzz）：所有从网络解析的格式（gossip 条目、DHT 记录）。
- **cargo-deny + cargo-audit** 在 CI 常开。

## 13. 主要风险与缓解

| 风险 | 缓解 |
|---|---|
| gotatun 年轻（审计 2026 进行中） | WgBackend trait 隔离，可换 NepTUN/boringtun |
| pkarr/mainline API 快速 break | 锁版本，全部封装在 discovery crate |
| DHT 在中国区域性受干扰 | 兜底链 ⑥⑦；bootstrap IP 直连列表 + 节点缓存 + DoH |
| 光猫防火墙关不掉/UDP state 异常 | doctor 诊断 + 机型指引；极端场景如实报告不可达 |
| net-route 维护弱 | Linux 走 rtnetlink；mac/Win 保留 fork 预案 |
| rustls 默认 aws-lc-rs 交叉编译坑 | 显式 ring provider；CI 对每个 musl target 编译验证 |
| 范围蔓延（大项目） | 里程碑制；M1-M3 之前不碰 UI/多平台 |

## 14. 用户决策记录（2026-08-06）

1. **手机端优先级**：用户裁定**提前到 v1.0 前**（手机是刚需）→ 新增 M7 Android 里程碑（v1.0 必含），iOS 紧随其后；engine 从 M0 起保持 FFI-ready。
2. **peer 中继逃生舱**：用户裁定 **MVP 就要**（可靠性优先）→ 并入 M3；语义为自有节点、显式启用、UDP 层加密透传、状态透明。
3. **前端框架**：用户裁定 **React**。
4. **既有环境输入**：用户提供其家庭网络调研笔记（联通 FTTR 华为 V175 主路由 + 规划中的 OpenWrt 透明代理路由器 + 现役 Tailscale + Clash 系代理）→ 导出两条硬约束写入 §5：不接管 DNS、路由仅自有 ULA 前缀；§7 增加二级路由拓扑与透明代理共存条目。

### 仍开放

- **GitHub 仓库**：主仓库 `~/CodeSpace/github/hextet` 目前无 remote。按全局惯例应建 `sudoviber/hextet`（个人开源，gh-sudoviber alias）——设计批准后、M0 开工时执行（届时确认公开/私有）。

---

## 附：与用户原始需求的对照

| 原始需求 | 落点 |
|---|---|
| 1. 起名并改名 | hextet；文件夹已改名，其余引用随 M0 建立 |
| 2. 需要哪些功能 | §8 路线图 + 竞品调研 §四（table stakes/差异化/不做） |
| 3. 用什么技术 | §3 决策 + 技术选型调研全文 |
| 4. IPv6-only 无中转 | §2 目标 1/2、§3 D5（中继仅限用户自有节点、显式启用，无任何第三方服务器）、可行性调研全文 |
| 5. 没考虑到的地方 | 防火墙打洞、动态前缀会合、DHT 的 IPv4 依赖、MTU、手机功耗、光猫防火墙、MIPS 不可行、许可证策略（§2 诚实边界、§13 风险） |
| 6. 详细文档 | 三份调研 + 本 spec + §11 文档体系 |
| 7. 每次代码改动更新文档 | §11 执行机制（PR 模板 + CI 路径规则） |
| 8. UI 好看 | §3 D6 + M5 里程碑（视觉单独用 design skill 打磨） |
| 9. 正式项目规范 | §10 结构 + §12 测试 + CI/发布工程 |
| 10. 路由器组网 | §7 + M4 里程碑 |
