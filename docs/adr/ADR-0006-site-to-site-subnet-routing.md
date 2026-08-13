# ADR-0006：site-to-site 子网路由用「peer 声明 + 路由管理器按连接状态增删」而非静态路由表

- 状态：已接受
- 日期：2026-08-12
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §8 M4、
  `docs/protocol/addressing.md`、`docs/guides/site-to-site.md`、
  `crates/core/src/route.rs`、`crates/engine/src/route_manager.rs`

## 背景

M4 的第一片是 site-to-site：节点 B 声明「某些 IPv6 子网在我背后可达」，节点 A
连上 B 后把发往这些前缀的流量送进隧道。实现上有几个必须拍板的点：

1. **路由的权威来源**是「配置里 peer 声明的 `routes`」，还是运行时通过协议发现？
   会不会与 overlay 自己的 /48 或某个节点的 /64 site 冲突？
2. **AllowedIPs 与 OS 路由表**是两回事：AllowedIPs 决定「哪个 peer 收这些包」，
   OS 路由决定「这些包从哪条接口出去」。两者都要派生，且必须一致。
3. **何时装 OS 路由**：一直装着，还是只在 peer 真的连上时装？打洞中/断连时装着
   等于把黑洞写进路由表。

## 决策

1. **静态声明，不自动发现**。M4 第一片只做配置里显式写的 `routes`，不引入任何
   "子网可达性"协议——那属于后续里程碑的路由收敛。配置加载时做完整校验：
   IPv6-only、长度 `1..=128`、host 位必须为零（前缀必须是网络地址）、peer 内不
   重复、不与 overlay /48 冲突、不与**本节点自己的 /64 site** 冲突、两个 peer 的
   通告子网不互相重叠。冲突一律 `ConfigError` 拒绝，不留"部分生效"的灰区。
2. **单一派生点**。AllowedIPs 由 `hextet_core::route::allowed_ips_for(site, routes)`
   派生（site /64 + 各通告路由），`spec.rs` 与 `daemon` 都调它，杜绝两处各写一份
   导致不一致。OS 路由表则由 `route_manager` 从同一份 `routes` 派生（`oif=hextet0`，
   不设网关——网关由 AllowedIPs 决定）。
3. **路由只在 `Connected` 时装**。引入 `RouteManager`：跟踪每个 peer 当前装了几条
   路由，每 tick 把「期望集合 = 连上时的 `routes`、否则空」与「已装集合」做差集，
   精确增删，绝不覆盖别的来源装的路由。daemon 退出时 `remove_all`。这比"静态装一次
   永不拆"更诚实：连接断了就撤路由，避免流量黑洞。
4. **归一化到网络地址**。`Ipv6Route` 构造即强制 host 位为零（解析时拒绝，不静默
   归一化）。选择"拒绝而非归一化"：写了个主机地址当 /64 通告，几乎可以肯定是
   用户笔误，静默改掉反而掩盖错误。

## 与 spec 的偏离记录

spec §8 对 M4 只给了"site-to-site 子网路由"一句方向。本文档是它的第一次落地细化，
不构成对 spec 的偏离；第 1 点的"只做静态声明、不自动发现"是范围收敛，如实记录在
「诚实的边界」一节（`docs/guides/site-to-site.md`）。

## 代价与风险

- **转发是操作系统的事**：hextet 只负责送进/送出隧道，网关节点背后子网是否真的
  能转发取决于 `net.ipv6.conf.*.forwarding`。指南里显式写了这个前提，避免用户
  以为"加了 route 就通了"。
- **断连即撤路由**：路由随连接状态抖动。对"对端短暂断线"的场景，撤路由会短暂
  不可达，但换来的是"绝不把流量送进黑洞"。若将来需要"路由与连接解耦"（例如
  对端是常驻站点、路由长期稳定），用新 ADR 覆盖。
