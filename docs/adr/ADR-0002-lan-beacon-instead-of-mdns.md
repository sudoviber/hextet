# ADR-0002：LAN 发现用自有组播公告，而不是 mDNS/DNS-SD

- 状态：已接受
- 日期：2026-08-11
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D3（会合兜底链第 ① 层）、
  `docs/protocol/lan-discovery.md`

## 背景

设计 spec §3 D3 把兜底链第 ① 层写成「LAN **mDNS**/组播发现（同网零成本）」。
落地时要在两条路之间选：

1. **标准 mDNS/DNS-SD**（`_hextet._udp.local`）：要么自己实现一套 DNS 报文编解码
   （还得处理 conflict detection、probing、known-answer suppression、
   cache-flush 位），要么引入一个 mDNS crate。
2. **自有组播公告**：一个定长头 + 地址数组 + HMAC 的 130 字节报文，
   发到自选的链路本地组播组。

## 决策

选 2：自有组播公告（`HXTL` 报文，`ff02::4193`，UDP 4195），线格式见
`docs/protocol/lan-discovery.md`。

## 理由

1. **需要认证，mDNS 给不了。** hextet 要广播的是「某个成员当前在哪个 IPv6 上」，
   而收到之后我们会**据此发 WireGuard 握手包**。如果任何 LAN 设备都能伪造这条信息，
   它就能让我们对任意地址发包（一个低成本的反射放大原语），也能污染候选列表把真正
   的地址挤出去。用 network key 派生的密钥做 HMAC 一次解决，而 mDNS 没有认证概念
   （DNSSEC 在 mDNS 上不实用）。
2. **要广播的信息只有三样**：公钥、若干 IPv6、UDP 端口。DNS-SD 的 PTR/SRV/TXT
   三段式加上名字冲突协商，全是为「服务名可读、可被任意客户端浏览」设计的——
   而我们的"客户端"只有 hextet 自己。
3. **代码量与可测性**：编解码 ~120 行纯逻辑 + 表逻辑 ~80 行，全部能用单测覆盖到
   逐字节篡改、重放、TTL、表满。一个 mDNS 实现（自研或第三方）都远超这个量级，
   而多出来的部分对我们没有产出。
4. **少一个依赖**：mDNS crate 会带进 DNS 解析栈与自己的后台线程模型；
   OpenWrt（M4）与 Android（M7）都要为此付交叉编译与体积的代价。
5. **协议一页纸讲完**（项目对外承诺之一）：一张字段表就说清了，
   而"我们实现了 DNS-SD 的哪个子集"永远说不清。

## 代价

- **不能用标准工具观察**：`avahi-browse` / `dns-sd` 看不到 hextet 节点。
  替代手段：`hextet status` 的 `endpoint_source=lan` 与 `lan_endpoints` 列、
  daemon 的 `-v` 日志、`tcpdump -i any udp port 4195`。
- **别的软件也发现不了 hextet**：如果将来希望第三方工具（例如某个网络扫描器或
  家庭网关 UI）能列出 hextet 节点，需要额外提供一个 mDNS 广告面。
  目前没有这个需求，也不打算主动暴露成员信息。
- **组 ID 是自选的**：`ff02::4193` 未经 IANA 分配。链路本地 scope 内的碰撞概率
  极低，且报文有 magic + MAC 双重保护，收到别人的包只会被静默丢弃。

## 重新评估的条件

出现下列任一情况就该重开这个决策：

- 需要让**非 hextet 软件**发现 hextet 节点（那时增加一个 mDNS 广告面，
  而不是替换本协议——认证需求不会消失）；
- 某平台禁止应用自选组播组或原始 UDP 组播（届时按平台加适配层）；
- 需要在同一链路上区分多个 hextet 网络的公告并做流量隔离（现在靠 MAC 校验天然区分：
  别的网络的公告算不出我们的 MAC，直接丢弃）。
