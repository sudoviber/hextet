# hextet 安全自审文档

> 状态：M6 切片 E 交付（spec §8「安全自审文档」）；2026-08-14 更新，纳入 M6 切片 C/D 与 M7 的
> 安全加固批次（CHANGELOG「Unreleased」→「Fixed」）。
> 日期：2026-08-14。
> 依据：本仓库实际代码（`crates/**`）、ADR-0001..0014、`docs/protocol/**` 与 `docs/guides/**`。
> 定位：这是一份**诚实边界**式的自审，不是安全证书。它如实记录「做了什么、挡了什么、
> 挡不住什么、还没做什么」；每一条结论都落到具体文件/ADR/协议文档，凡无法确认的明确写
> 「未能确认」，不虚构漏洞、也不夸大防护。

---

## 1. 威胁模型

先回答「谁在攻击、能做什么、不能做什么」。信任模型是双层的（spec §3 D4）：

- **network key（32 字节共享秘密）是根密钥**：所有派生用途子密钥（见 §2）都由它经
  HKDF 派生。**持有 network key 的人 == 网络成员**——他能派生网络 /48 前缀、伪造
  LAN 公告与 DHT 会合记录、解密别人的 DHT 记录、在中继上建会话。这是 hextet 的
  根本信任边界：network key 泄露 == 全网「谁在哪、什么时候在哪」的隐私泄露。
- **节点 ed25519 身份密钥**：每个节点一把，是**数据面身份**。它派生 WireGuard x25519
  密钥与 overlay 地址（`crates/core/src/identity.rs`、`crates/core/src/addr.rs`）。
  泄露节点身份密钥才会破坏**数据机密性/节点冒充**——这是比 network key 更严重的一层。

两者的分工（spec §6）：network key gate「会合/公告/中继控制」这类**元数据**面；
节点密钥 gate **数据面**（WireGuard cryptokey routing）。

| 攻击者 | 能 | 不能 |
|---|---|---|
| **LAN 观察者**（同一链路，被动） | 看到明文 LAN 公告（公钥 + IPv6 地址 + WG 端口），据此判断「这里在用 hextet」；观察到 `HXTL` 组播流量 | 伪造成员公告（算不出 `lan_key` 的 HMAC）；读取数据面（WG 加密）；把公告送出 LAN 之外（链路本地 scope + hop limit 1） |
| **DHT 观察者**（外部 Mainline 节点/网络） | 观察到「某个 target 上有记录在发布/查询」、发布节奏（~55min）、时间相关性 | 定位记录（target 是网络密钥派生公钥的 SHA1，算不出）；解密记录（AEAD）；反推 overlay 地址或成员身份 |
| **DDNS 观察者**（DNS 解析器/注册商/能读到该域名 TXT 的人） | 看到 `hxdd1.` 前缀的密文 TXT 记录与更新节奏；知道「该域名被用于 hextet 会合」 | 解密记录（AEAD 密钥 `ddns_key` 由 network key 派生，非成员算不出）；读出 endpoint 明文；反推成员身份或 overlay 地址 |
| **恶意网络成员**（持有 network key） | 派生全部用途子密钥；伪造任意节点的 LAN 公告、DHT 与 DDNS 会合记录（候选污染 DoS）；解密 DHT/DDNS 记录；在中继上建会话；看到成员表；**默认（`admin_keys` 空白）可伪造 gossip 的 Member/Revocation 条目（自签即有效）** | **设了 `[node] admin_keys` 白名单后伪造非 admin 签名的 Member/Revocation（只有列出的 admin ed25519 公钥签的才被采纳，见 §4）**；冒充某节点过 WG 握手（需要该节点的身份密钥）；读取中继透传的数据面（WG 加密） |
| **被攻陷的中继节点** | 看到**密文 + 元数据**（谁在跟谁通、多少量、什么时候）；丢弃或篡改转发包 | 读明文（转发的是 WG 加密包，中继无任何一方的私钥）；篡改后伪造成功（篡改会被 WG 认证挡下，表现为丢包） |
| **被攻陷的 DHT bootstrap 节点** | 看到 BEP44 的 put/get 请求（含 target 哈希）、时间与来源 | 解密记录；从 target 反推网络密钥或节点公钥 |
| **用户自己的 OS / root** | 读配置文件（network key）与密钥文件（身份种子）、改任何本地状态、篡改/替换进程 | —— 无。root 拥有整台机器，这是所有 VPN 的共同边界，不是 hextet 能防的 |
| **网络（ISP / 中间盒）** | 看到 WG 密文（包大小、时序、endpoint 地址、端口 4193）、DHT 的 IPv4 UDP 出站流量 | 解密 WG；解密 DHT 记录；伪造 WG 认证包 |

**关键诚实点**：hextet 不做「对抗恶意网络成员」的强隔离——network key 就是成员资格，
网内成员天然能污染会合候选、观察元数据、占用中继资源。设计上用**上限**（候选去重/
截断 8、中继 256 会话 + 2000 pps、LAN 表 64）把这些影响压到「可用性 DoS」而非
「机密性破坏」，真正的身份认证收敛到 WireGuard 握手（`crates/engine/src/candidates.rs`、
`crates/engine/src/relay_server.rs`、`crates/engine/src/lan.rs`）。

---

## 2. 密钥与密码学

### 2.1 密钥派生：一把密钥只干一件事

`network_key` 不直接使用，而是经 `HKDF-SHA256(salt="hextet-v1", ikm=network_key)`
派生出一系列**用途隔离**的子密钥（`crates/core/src/network.rs`、
`crates/discovery/src/record.rs`、`crates/discovery/src/ddns/mod.rs`）：

| 用途串（purpose string） | 派生长度 | 用途 | 位置 |
|---|---|---|---|
| `"network-id"` | 5 字节 | ULA /48 前缀（`fd` + 40-bit） | `crates/core/src/network.rs` |
| `"doctor-probe"` | 32 字节 | doctor 探针的 HMAC 密钥 | `crates/core/src/network.rs` |
| `"lan-beacon"` | 32 字节 | LAN 组播公告的 HMAC 密钥 | `crates/core/src/network.rs` |
| `"relay"` | 32 字节 | 中继控制帧的 HMAC 密钥 | `crates/core/src/network.rs` |
| `"dht-record"` | 32 字节 | DHT 会合记录的 AEAD 密钥 + 会合密钥种子派生 | `crates/discovery/src/record.rs` |
| `"ddns-record"` | 32 字节 | DDNS 会合 TXT 记录的 AEAD 密钥 | `crates/discovery/src/ddns/mod.rs` |

盐 `"hextet-v1"` 是协议版本锚点，同一把 network key 在所有节点上派生出相同结果
（有 `frozen_*_vector` 钉扎向量回归，防止无意改动派生算法）。

**「一把密钥只干一件事」的理由**（`network.rs` 的 doc 注释原文）：LAN 公告是网络里
最容易被观察到的报文，即便它的密钥经侧信道泄露，也不该牵连 doctor 探针、中继控制
与 DHT 记录。中继密钥的特别之处在于它决定「谁能在别人机器上建中继会话」——它与数据面
机密性无关（中继转发的是已加密 WG 包），但与中继可用性有关。

**诚实更正一处常见误解**：gossip **不使用**网络密钥派生的对称 MAC。它在 WG 隧道内
运行（隧道已由 WireGuard 认证加密），条目靠**每个节点的 ed25519 身份密钥**签名
（非对称），因此没有 `"gossip"` 这个用途串。见 `crates/core/src/gossip.rs` 与
`docs/adr/ADR-0004-gossip-signed-udp-instead-of-quic.md`。

### 2.2 节点身份（ed25519）

- 身份是 ed25519 签名密钥（`ed25519-dalek` 2），`NodeIdentity::generate` 用系统 CSPRNG
  （`rand_core::OsRng`）。`crates/core/src/identity.rs`。
- 私钥种子 → WG x25519 私钥经 `SigningKey::to_scalar_bytes()`（RFC 8032 的 clamp 派生）；
  有 proptest 证明「派生私钥 × 基点 == 派生公钥」两条路径一致。
- **验签用 `verify_strict`** 而非 `verify`：额外拒绝小阶公钥点，消除「同一消息存在多个
  有效签名」的可延展性——hextet 里的签名是准入凭证（invite、gossip Member/Revocation），
  可延展性会让「这条记录是不是同一条」变含糊（`identity.rs` 的 `NodePublicKey::verify`）。

### 2.3 密钥落在哪、怎么保护

- **节点身份种子**：`NodeIdentity::save` 以单行 base64 写入密钥文件，Unix 上
  `create_new(true)` + `mode(0o600)`（`crates/core/src/identity.rs`）。
- **网络密钥**：存在 TOML 配置文件里（base64），`hextet join`/`init` 落盘 0600
  （`docs/guides/joining.md` §2）。
- **内存零化**：`NetworkKey` 实现 `Drop` 时 `zeroize()`；`ed25519-dalek` 以 `zeroize`
  feature 引入（`Cargo.toml`）。
- **不打印密钥**：`Config`、`Invite` 手写 `Debug` 把 `network_key` 打码成 `<redacted>`
  （`crates/core/src/config.rs`、`invite.rs`）；`CONTRIBUTING.md` 硬性要求「新增结构
  不得输出 network key / 种子 / 任何派生子密钥」，并有断言测试（如 `debug_redacts_network_key`）。

### 2.4 什么**不**加密/不签名，以及为什么（诚实）

| 对象 | 认证/加密状态 | 为什么这样 |
|---|---|---|
| LAN 公告 | HMAC 认证，**不加密** | 公钥与地址是明文——同 LAN 观察者能看出在用 hextet。ADR-0002 明确接受（标准 mDNS 同样如此）；认证的目的只是「不能让外人伪造成员地址诱导我们打洞」 |
| gossip 条目 | ed25519 签名，**不加密** | 隧道内已被 WireGuard 认证加密，再加密一层是重复（ADR-0004 理由 1） |
| DHT 会合记录 | **AEAD 加密** + BEP44 签名 | 定位（派生公钥）与读懂（AEAD）双保险；见 §5 |
| DDNS 会合记录 | **AEAD 加密**（TXT 密文，无 BEP44 签名层） | 定位是用户自己的域名（公开、归用户所有，ADR-0010 决策 1）；内容 AEAD 加密与 DHT 对齐；见 §5 |
| doctor 探针 | HMAC 认证，**不加密** | 报文只有 nonce/reply_port，无私密信息；认证只为挡住非成员 |
| **invite token** | ed25519 签名，**不加密**（载荷是 base64） | 这是唯一要格外小心的：token 里的 `network_key` 是**明文 base64**，任何截获 token 的人都能解出 network key。签名只保证「签发后未被篡改」，不保证保密——所以文档反复要求走安全信道传递（`docs/protocol/invite.md` 信任模型、`docs/guides/joining.md` §1） |
| WireGuard 数据面 | Noise 协议认证加密 | 复用 WG 成熟密码学，见 §3 |

---

## 3. 数据面

数据面完全复用 WireGuard 的 Noise 协议（自动 rekey、cryptokey routing、endpoint
roaming），hextet 不发明任何加密协议（spec §2 非目标 7、§6）。控制面的本质工作是
「自动化生成与更新 WireGuard 配置」，由 `WgBackend` trait 隔离两种后端实现
（`crates/wg/src/lib.rs`）：

- **Linux / OpenWrt**：内核 WireGuard（netlink，经 `wireguard-control`）。
  `crates/wg/src/kernel.rs`。
- **macOS / Windows**：用户态 gotatun 0.8.1（Mullvad，MPL-2.0）。
  `crates/wg-userspace/src/lib.rs`（ADR-0012：boringtun 过渡后端已迁移到 gotatun）。

### 3.1 `set_peer_endpoint` 增量更新（macOS 用户态后端）

内核后端支持「只改单个 peer 的 endpoint 的增量更新」（`kernel.rs::set_peer_endpoint`
刻意不用 `replace_peers`）。用户态后端经 gotatun 的 `modify_peer` 实现同样的增量更新
（`wg-userspace/src/lib.rs::set_peer_endpoint`），收敛了 boringtun 时代「remove + 完整
re-add」的缺口（见 ADR-0007「代价与再评估」）。这是 macOS/Windows `hextet daemon`
打洞循环（2.5s 轮换候选）能跑起来的关键（编译验证；真实 utun/root 运行时仍待真机）。

### 3.2 与 ADR-0007 决策 2 的偏差（历史记录）

ADR-0007 决策 2 设想 boringtun 暴露 `Tun` trait + `udp` trait 可写适配器；查证 0.7.1
源码后确认这两个 trait 不存在。该偏差已随 boringtun→gotatun 迁移（ADR-0012）失效——
gotatun 的 `DeviceBuilder::with_ip/with_ip_pair` 提供了自定义 transport 注入点（M7 的
`RawFdTun` 正用这个），不再需要 boringtun 的 trait 抽象。保留本条记录 boringtun 时代的
事实。

### 3.3 可验证的证明

本机 macOS 无 root、无真实 utun，gotatun 的完整 `Device`（开真实 TUN）无法跑；但
gotatun 的数据面核心（`noise::Tunn`）可进程内直跑，`wg-userspace/tests/gotatun_noise.rs`
用它完成了一次完整的 WireGuard 握手 + IPv6 数据包往返（不碰真实网卡、不碰 root）；
真实 TUN 层另由 `tests/userspace_backend_tun.rs` 在 `--privileged` Docker E2E 容器里
跑通 apply/status/set_peer_endpoint/add_peer/remove_peer/down（linuxkit 内核 + 真实
`/dev/net/tun`）。真正的 macOS 端到端（utun + 地址 + 路由 + 握手 + 互 ping）**未在真机
验证**（ADR-0009「未能验证」）。

---

## 4. 控制面协议

各协议逐一列出「认证什么、抗重放/新鲜度、收敛」。所有 MAC 校验都用常量时间比较
（`verify_truncated_left`，注释明确「不要换成 == 手写比较」），校验失败一律**静默丢弃**
（不给探测者反馈）。

### 4.1 LAN 公告（`HXTL`）

- **认证**：`HMAC-SHA256(lan_key, 头部+地址)` 截断 16 字节，覆盖除 MAC 外的全部字段。
- **抗重放/新鲜度**：`seq` = 发送时 Unix 秒；接收方要求 `|seq − 本地时钟| ≤ 300s`
  且 `seq` 单调不减（重放更旧的公告整条丢弃，连 TTL 都不刷新）。
  `crates/core/src/beacon.rs` + `crates/engine/src/lan.rs`。
- **不加密**：见 §2.4。
- **收敛**：无（LAN 是软状态表，60s TTL，5s 周期刷新）。

### 4.2 中继控制帧（`HXTR`）

- **认证**：`HMAC-SHA256(relay_key, 前 80 字节)` 截断 16 字节；`self_key == peer_key`
  直接拒绝（自反射无合法用途）。
- **抗重放/新鲜度**：`seq` = Unix 秒，`|seq − now| ≤ 300s`（`relay_server::SEQ_SKEW_TOLERANCE_SECS`）；
  会话 TTL 180s + 30s 续期。
- **覆盖范围**：MAC 覆盖 `kind`、`port`（WG 监听端口）、`seq`、两个公钥——不覆盖的
  没有（96 字节定长帧）。
- 详见 `crates/core/src/relay.rs`、`docs/protocol/relay.md`。

### 4.3 gossip 条目（`HXTG`）

- **认证**：ed25519 签名覆盖**规范编码**（定长、字节级，无 JSON 规范化歧义）。
- **签名者约束（安全规则，非可选）**：`Endpoint` 必须 `signer == node`（不能替别人
  宣告地址诱导打洞）；`Member`/`Revocation` 必须 `signer != node`（不能自准入/自吊销）。
  约束在 `decode` 里强制（`crates/core/src/gossip.rs`）。
- **准入/吊销的签发授权（可选闸，非默认安全边界）**：`[node] admin_keys` 空白时任何
  成员都能签 `Member`/`Revocation`（默认，向后兼容）；设了之后只有列出的 admin 公钥签的
  条目才被采纳（`engine::gossip::handle_datagram` 在 merge 前拦一道，
  `crates/engine/src/gossip.rs`）。注意这是**可选**授权：不设白名单时「恶意成员伪造
  准入/吊销」仍然成立（见 §1 威胁模型）。
- **抗重放/新鲜度**：单调 `seq` + LWW 收敛。**诚实边界**：gossip **不做绝对时间校验**
  （与 LAN/中继的 ±300s 不同）——它靠「seq 更旧的条目判为 stale 拒绝」抗重放，但没有
  时钟偏差窗口。`engine/src/gossip.rs::broadcast` 保证广播 `seq` 严格单调
  （`(*seq + 1).max(unix_secs(now))`）。
- **第二道防线**：socket 只绑 overlay 地址（隧道内才可达），且收包后校验源地址在网络
  /48 内（`is_within_prefix`）——隧道外注入直接丢。
- **收敛**：同「主体 node × 类型」只留一条，`seq` 大者胜；`seq` 相同取规范编码字节序
  小者（保证两分区确定性收敛）。`crates/core/src/gossip.rs::lww_compare`。

### 4.4 invite token（`hxi1.<payload>.<sig>`）

- **认证**：ed25519 签名覆盖 `payload` 段的 base64 文本本身（绕过 JSON 规范化）。
- **抗重放/新鲜度**：`expires_unix` 过期检查（`check_not_expired`）。
- **诚实边界**：验签只证明「签发后未被篡改」，**不**证明签发者可信（入网时无信任锚点）；
  「一次性」目前只体现为 `id` 字段，**没有任何强制**（`crates/core/src/invite.rs` 模块
  文档原文）。token 载荷不加密，network key 明文可见（§2.4）。
- 见 `docs/protocol/invite.md`。

### 4.5 DHT 会合记录（BEP44 可变项）

- **认证/加密**：`seal` = `nonce(12) || AEAD_ChaCha20Poly1305(key=dht_key, JSON{endpoints, epoch})`；
  BEP44 可变项自带 ed25519 签名 + 单调 `seq` + CAS。
- **诚实边界**：会合密钥对是**全网共享 network key 派生**的，任何网内成员都能伪造
  任意节点的记录——签名**不承担身份认证**，真正的身份认证在 WG 握手完成（ADR-0005
  决策 5）。见 §5。
- 详见 `crates/discovery/src/record.rs`、`docs/protocol/dht-record.md`。

### 4.6 doctor 探针（`HXTP`）

- **认证**：`HMAC-SHA256(probe_key, 前 16 字节)` 截断 16 字节。
- **抗重放/新鲜度**：无状态、**无** seq/重放窗口——它的 `nonce` 只用于把回包与请求
  配对，不是防重放字段。作为补偿：响应器按**源 IP 限速 1 次/秒**、限速表有界（64 项），
  且 1 个 32B Request 最多触发 2 个 32B 回包（2× 放大、需有效 MAC）。
  `crates/core/src/probe.rs`、`crates/engine/src/probe_responder.rs`。

### 4.7 小结：哪个协议**没有**重放保护

- **doctor 探针**：无 seq/重放窗口（无状态），靠限速与低放大缓解。这是唯一一个「无
  显式重放保护」的协议，如实列出。
- **gossip**：有单调 seq 抗重放，但**无绝对时间新鲜度窗口**（与 LAN/中继不同）。
- **invite**：靠过期时间，无一次性强制。
- LAN / 中继：`seq ±300s` 窗口 + 单调性，是防护最完整的两个。

---

## 5. 会合与隐私

DHT 会合是「双端同时换前缀」时唯一的外部汇合点（spec §3 D3 兜底链第 ⑤ 层）。它的
隐私设计分三层（`crates/discovery/src/record.rs`、`docs/adr/ADR-0005-*.md`）：

1. **定位不可算**：`dht_key = HKDF(...).expand("dht-record", 32)`；
   `rendezvous_seed = HMAC-SHA256(dht_key, "hextet-dht-sign" || node_pubkey)`（截 32 字节）
   → ed25519 会合密钥对。BEP44 可变项的 target = `SHA1(会合公钥)`。不知道 network key
   的人算不出这个公钥，也就定位不到记录。
2. **内容不可读**：value 是 AEAD 加密（`seal`），即使碰巧拿到记录也读不出端点。
3. **作息不可推**：载荷里用粗粒度 `epoch = unix_secs / 3600`，而不是精确时间戳
   （spec §5「粗粒度 epoch 保护作息隐私」）。

**与 spec 的诚实差异**（ADR-0005 已记录）：spec §5 写的是
`key = HMAC(network_key, node_pubkey)`（20 字节 infohash）。实现时发现 `mainline` 对
可变项只有「`target = SHA1(ed25519 公钥 || salt)` 且必须由对应私钥签名」的原语，
没有「往任意 20 字节 infohash 发布可变值」的入口。于是把「HMAC 出的 20 字节 key」
换成「派生出的会合 ed25519 密钥对」——**目标不变（外人无法定位），手段不同**。

**外部 DHT 观察者仍能学到什么**（诚实，无法完全消除）：

- 一个记录**存在**于某个 target 上（BEP44 的 put/get 在 DHT 上可见）；
- **发布节奏 ~55min**（`engine/src/dht.rs::PUBLISH_INTERVAL`）与**查询节奏 30s**；
- 发布/查询的**时间相关性**（把两个 target 关联起来）；
- 出站 IPv4 UDP 的**来源地址与时机**（Mainline DHT 是 IPv4 网络，控制面弱依赖 IPv4
  出站——spec §5 已声明，数据面仍纯 IPv6）。

但观察者**看不出**：target 对应哪个网络/哪个节点（无可反推的公开映射）、记录里的
endpoint 明文（AEAD 加密）、以及精确的作息（epoch 只有小时粒度）。

**DDNS 会合（ADR-0010）的隐私差异**：DDNS 的「定位」是用户自己的域名（公开、但域名
归用户所有，不属于第三方观察面），DHT 的「定位」是网络密钥派生的 target（隐藏）；两者的
「读懂」都由 AEAD 同一纪律 gate——`ddns_key` 是 `"ddns-record"` 用途串派生的独立密钥，
载荷复用 DHT 的 `RecordPayload{endpoints, epoch}`。DNS 路径上的观察者（解析器/注册商）
能看到密文与更新节奏，但读不出 endpoint（§1 威胁模型新增行）。信任模型与 DHT 一致：会合
层不做身份认证，网内成员可伪造任意节点的记录（只造成候选污染 DoS，真正的身份认证在
WG 握手，ADR-0010 决策 3）。

---

## 6. 中继

中继（spec §3 D5）是**逃生舱**，不是基础设施（spec §2 非目标 1 明确排除项目方运营的
DERP/TURN 舰队）。安全属性：

- **opt-in**：默认关，须 `[node] relay = true` 显式启用；对端也须显式标
  `[[peers]] relay = true`（`crates/core/src/config.rs`）。
- **member-only**：控制帧用 `relay_key` 做 HMAC 认证，非成员算不出合法 MAC。
- **UDP 层透传，不解密**：会话端口上收到的数据报**不以 `HXTR` 开头就是要转发的
  WireGuard 包**，原样转发（这条判据安全，因为 WG 报文首 4 字节是消息类型 1..=4 的
  小端 u32，与 ASCII `HXTR` 不可能相同——`relay.rs::tests::wireguard_headers_are_never_mistaken_for_relay_frames` 显式钉住）。
- **限流与会话上限**：每会话 2000 pps（≈22 Mbps @1400B）、256 会话上限、180s TTL +
  30s 续期、半开会话不转发（`relay_server.rs`）。
- **可选白名单**：`relay_allow` 分别校验会话两侧；只放行一端时保持半开不转发。

**中继能看到什么**（诚实的元数据泄露）：

- **密文 + 元数据**：两个 IPv6 地址之间的流量大小与时间。**不是明文**——中继没有任何
  一方的私钥。
- 中继**能**丢弃或篡改流量（它在路径上）；篡改会被 WG 认证挡下（表现为丢包），丢弃
  则等价于链路故障。所以中继**必须是你信任的机器**（`docs/guides/relay.md` §1、
  `docs/protocol/relay.md` 安全性表）。

**「无服务器承诺打折」的诚实**：hextet 的「数据不经过任何服务器中转」承诺在走中继时
打了折——数据经过的是**你自己的节点**，不是任何人的服务器，且**绝不静默降级**：
`punch_state` 报 `relayed`（不是 `connected`）、`status` 显示 `relayed via <名字>`、
状态文件有 `relay_via` 字段、进入/离开中继各有一条说明原因的 `info` 日志
（`engine/src/daemon.rs::peer_state_of`、ADR-0003「透明性」）。中继 endpoint 也绝不
进端点缓存，避免下次启动先去试一个死地址。

---

## 7. 已知缺口与残余风险

| # | 缺口/风险 | 影响 | 出处 | 缓解/计划 |
|---|---|---|---|---|
| a | **boringtun 0.7.1 不能增量更新 peer endpoint**（`update_peer` 对已有 peer panic，`set=1` 无「只改 endpoint」） | ~~macOS/Windows 用户态后端无法做 2.5s 轮换候选的增量打洞，`hextet daemon` 被阻塞~~ | ADR-0007（代价）、ADR-0009（决策 6）、`wg-userspace/src/lib.rs` | ✅ 已解决：boringtun→gotatun 0.8.1 迁移完成，`modify_peer` 提供增量更新（ADR-0012） |
| b | **macOS 地址配装需手写最小 unsafe ioctl 封装**（`SIOCAIFADDR_IN6`/`SIOCDIFADDR_IN6`） | 工作区唯一允许 `unsafe` 的点（~30 行），是 `unsafe_code = "deny"` 的刻意、收窄例外 | ADR-0008 决策 1、`CHANGELOG.md`（`assign_ipv6`） | 独立 crate + `#![allow(unsafe_code)]` + root 门控测试；出现安全 crate 即删除 |
| c | **`net-route` 维护弱**（0.4.6 距今 16 个月、20 open issue） | macOS 路由依赖一个低维护 crate | spec §13、ADR-0008 决策 1 | 锁死 `=0.4.6` + `crates/platform` 唯一接触点 + fork/vendor 预案（vendor 其 ~600 行 PF_ROUTE 路径） |
| d | **gotatun MSRV 1.95 阻塞直接采用**（工作区 `rust-version = "1.85"`） | ~~目标后端暂不可直引~~ | ADR-0007 决策 1 | ✅ 已解决：工作区 MSRV 抬到 1.95，gotatun 0.8.1 落地（ADR-0012） |
| e | **`getifaddrs` 枚举缺逐地址 Deprecated/Tentative 过滤** | macOS 端点探测偶尔试到即将失效的旧地址（探测噪声，非正确性破坏） | ADR-0008 决策 2 | 补足需 unsafe 封装 `SIOCGIFAFLAG_IN6`，明确推迟 |
| f | **macOS `hextet up` one-shot 不持久化设备**（进程退出 utun 即销毁） | macOS 没有 Linux 那种「up 后设备常驻、down 再来拆」的模型 | ADR-0009 决策 5/6 | 常驻须 `hextet daemon`（launchd）；已写进安装文档 |
| g | **fuzz 目标未在 CI 长跑** | `fuzz/` 七个目标（beacon/relay/gossip/probe/invite/DHT/ddns）存在，但 `cargo-fuzz` 需 nightly，本机已跑通 smoke（零 panic） | `fuzz/`、`.github/workflows/fuzz-smoke.yml`、`scripts/fuzz-smoke.sh` | fuzz-smoke workflow 已接 CI（30s/目标 smoke）；本机已跑通，见下方「未能确认」 |

**未能确认**（诚实记录，不假装已验证）：

- `fuzz/` 的 cargo-fuzz 目标本机已跑通 smoke（7 目标，零 panic，见 `scripts/fuzz-smoke.sh`）；
  CI 的 `fuzz-smoke` workflow 存在，但其通过状态本机无法验证。
- 真实 macOS 端到端（utun + 地址 + 路由 + gotatun 握手 + 互 ping）**未在真机验证**
  （ADR-0008/0009「未能验证」）。
- `net-route` 的「无网关、仅出接口」IPv6 路由在真实 macOS 的落表行为**未验证**
  （ADR-0008「未能验证」，是触发 fork/vendor 预案的关键实测点）。
- DHT 只在 `mainline::Testnet`（loopback IPv4 测试网）验证，**未打真实 DHT**
  （ADR-0005「代价与风险」）。

---

## 8. 安全自审清单

### 已经做到的（DOES）

- **不自研密码学**：ed25519-dalek（身份/签名）、HMAC-SHA256（认证）、HKDF-SHA256
  （派生）、ChaCha20-Poly1305（DHT AEAD）、WireGuard/Noise（数据面，内核或 gotatun）。
- **密钥永不落日志**：`Config`/`Invite` 手写 `Debug` 打码；`NetworkKey` `Drop` 时
  `zeroize()`；`CONTRIBUTING.md` 第 5 条硬性要求 + 断言测试。
- **`unsafe_code = "deny"`**：工作区根 `Cargo.toml` 的 `[workspace.lints.rust]`，除
  ADR-0008 的 macOS 地址配装这一处收窄例外（§7-b）。
- **clippy `-D warnings`**：`CONTRIBUTING.md` 与 CI 常开；`#![deny(missing_docs)]`
  于 `core`/`wg`/`wg-userspace`。
- **cargo-deny**：`deny.toml` 许可白名单、`yanked = "deny"`；唯一 ignore 是
  `RUSTSEC-2024-0436`（paste 编译期 proc-macro，经 wireguard-control 传递，无运行时
  攻击面，上游无修复）。
- **fuzz 目标**：`fuzz/` 覆盖全部「从网络解析」的格式（beacon/relay/gossip/probe/
  invite/DHT 记录），配合每个解码器的「任意字节不 panic」proptest（stable 工具链第一道
  防线）+ 冻结线格式向量。
- **常量时间 MAC 校验**：所有 HMAC 用 `verify_truncated_left`（不是 `==`）。
- **重放窗口**：LAN/中继 `seq ±300s` + 单调性；gossip 单调 seq；invite 过期检查。
- **限流与有界状态**：probe 响应器 1 次/秒（表 64）；中继 2000 pps + 256 会话；
  LAN 表 64；候选去重 + 上限 8；`verify_strict` 抗签名可延展。
- **认证顺序**：所有解析器「廉价检查 → 认证 → 才解析攻击者可控字段」（beacon/invite/
  relay 均如此），未认证输入不给最贵的曲线点校验。
- **DHT 会合 seq 溢出防护**：发布序列 `seq + 1` 改为 `checked_add(1)`，到顶报错而非
  debug panic / release 回绕成 `i64::MIN` 后记录永久卡死（`crates/discovery/src/client.rs`）。
- **gossip 表无界膨胀封顶**：`MAX_STORE_ENTRIES = 512` 的跨 node 总条目上限，填满后新键
  `Rejected`、已有键的更新仍放行（`crates/core/src/gossip.rs`）。
- **endpoint 读取路径统一过滤**：DHT `lookup` 读取路径复用发布侧的
  `is_usable_endpoint_addr`，排除 loopback/ULA/链路本地/组播/unspecified/IPv4-mapped
  （`crates/core/src/addr.rs`、`crates/discovery/src/client.rs`）。
- **DDNS 读取路径过滤**：`select_endpoints` 解密后同样走 `is_usable_endpoint_addr` 过滤，
  恶意成员塞进的非法地址不会进候选（`crates/discovery/src/ddns/mod.rs`）。
- **`[node] admin_keys` 可选准入/吊销授权**：空白名单 = 任何成员都能签 `Member`/`Revocation`
  （默认，向后兼容）；设了之后只有列出的 admin 公钥签的条目被采纳，堵住「任何成员都能吊销
  admin / 准入任意节点」（`crates/engine/src/gossip.rs`）。
- **keepalive 分级**：`[node] keepalive`（默认 25s，`0` = 关闭常驻 keepalive）+
  `[[peers]] keepalive` 每 peer 覆盖，移动端按需连接省电；gossip 准入路径同走配置值
  （`crates/core/src/config.rs`、`crates/engine/src/spec.rs`、`crates/engine/src/daemon.rs`）。

### 还没做到的（DOES NOT YET）

- **macOS/Windows 数据面真机验证**：gotatun 0.8.1 已落地且 `set_peer_endpoint` 经
  `modify_peer` 增量更新（§7-a 已解决，ADR-0012），但 macOS utun / Windows wintun 的
  真实设备端到端运行时仍未真机验证（§7「未能确认」）。
- **Windows `hextet down`/`delete_interface`**：wintun 适配器持久化缺口（`tun` crate 的
  Windows 分支未暴露 `WintunDeleteAdapter`，ADR-0011），`hextet down` 在 Windows 上如实报错。
- **真实 DHT 网络验证**：只在 Testnet 测过（§7）。
- **第三方安全评审**：本文件是自审，没有外部审计背书。
- **fuzz 长跑与 CI 验证**：fuzz-smoke workflow 已存在但本机未验证（§7-g）。
- **Android 编译/运行验证**：`hextet-engine-ffi` 与 Kotlin `VpnService` 壳
  已写，但本机无 Android SDK/NDK，未编译验证、未真机运行（ADR-0013）。
- **invite「一次性」强制**、**网内成员伪造会合记录的强隔离**、**中继期间边转发边
  探测直连**（内核 WG 单 endpoint 限制，ADR-0003 决策 2）——均为已知、如实记录的范围
  边界，而非隐藏缺陷。

---

## 参考

- 设计：`docs/superpowers/specs/2026-08-06-hextet-design.md`（§2 非目标、§3 D1/D3/D4/D5、
  §5 协议要点、§6 安全模型摘要、§13 风险表）
- 决策：`docs/adr/ADR-0001..0014`（尤其 ADR-0002 LAN 认证、ADR-0003 中继透明性、
  ADR-0004 gossip 签名 UDP、ADR-0005 DHT 会合密钥、ADR-0007 boringtun/缺口、
  ADR-0008 macOS unsafe 例外、ADR-0009 设备所有权、ADR-0010 DDNS TXT+AEAD 会合、
  ADR-0011 Windows wintun/service、ADR-0012 MSRV 1.95 + gotatun、ADR-0013 Android FFI、
  ADR-0014 keepalive 分级）
- 协议：`docs/protocol/{addressing,lan-discovery,doctor-probe,invite,gossip,relay,dht-record,ddns,punching}.md`
- 指南：`docs/guides/{joining,relay,site-to-site,ddns}.md`
- 代码：`crates/core/src/{network,identity,config,addr,beacon,probe,invite,gossip,relay}.rs`、
  `crates/discovery/src/{record,client,nodes,ddns/mod,ddns/resolver,ddns/updater}.rs`、
  `crates/wg/src/{lib,kernel}.rs`、`crates/wg-userspace/src/lib.rs`、
  `crates/engine/src/{daemon,gossip,dht,ddns,members,relay_server,relay_client,route_manager,candidates,fsm,lan,probe_responder}.rs`、
  `crates/engine-ffi/`、`crates/core-ffi/`
