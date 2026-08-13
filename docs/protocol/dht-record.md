# DHT/pkarr 会合记录格式

> 设计出处：`docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D3（会合兜底链第 ⑤ 层）、
> §5。落地决策见 `docs/adr/ADR-0005-dht-bep44-rendezvous-key.md`。
> 实现位置：`crates/discovery/`（`record.rs` 纯逻辑、`client.rs` 传输、`nodes.rs` 持久化）。

## 1. 定位

当「双方都不知道对方现在在哪」且无法直连时，经 Mainline DHT（BEP5/BEP44）作为公共汇合点。
控制面弱依赖 IPv4 出站 UDP（Mainline 是 IPv4 网络），数据面仍是纯 IPv6。

## 2. 密钥派生

`dht_key = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("dht-record", 32)`

这把密钥同时 gate「定位」与「读懂」两件事（同一个会合隐私问题），与数据面、中继、
LAN 公告、gossip 的密钥彼此独立。

## 3. 记录（BEP44 可变项）

记录用 `mainline` 的 **BEP44 可变项**（`MutableItem`）发布/查询，它自带单调 `seq`、
CAS（乐观并发）、ed25519 签名校验、分发给 20 个最近节点的 PUT 语义。

- **寻址密钥**：会合 ed25519 密钥对，种子 =
  `HMAC-SHA256(dht_key, "hextet-dht-sign" || node_pubkey)` 截断 32 字节。
  BEP44 的 target = `SHA1(该密钥的公开部分)`。不知道 `dht_key` 的人无法从节点公钥
  算出 target，因此在 DHT 里定位不到记录（与 spec 想要的「外人无法定位」同层保证，
  见 ADR-0005）。
- **value**（AEAD 密文）：`nonce(12) || AEAD_ChaCha20Poly1305(key=dht_key,
  plaintext=JSON{endpoints, epoch})`。nonce 不保密但不可重复，前置到密文里让记录自包含。

明文载荷：

| 字段 | 类型 | 含义 |
|---|---|---|
| `endpoints` | array | `[v6]:port` 字符串（已过滤可用地址） |
| `epoch` | u64 | `unix_secs / 3600`（粗粒度，保护作息隐私） |

## 4. 发布节奏

- 启动即发、本机地址变化即发。
- 之后每 ~55min 重发（BEP44 的 2h 过期前）。
- 查询各 peer 记录每 30s；bootstrap 节点表每 10min 落盘到 `<state_dir>/dht-nodes.json`。

## 5. 信任模型与诚实边界

- **会合层不做身份认证**：会合密钥对是全网共享网络密钥派生的，任何网内成员都能
  伪造任意节点的记录。这与 LAN 公告的 HMAC 是同一信任模型——会合只提供「候选
  endpoint」，真正的身份认证在 WireGuard 握手（cryptokey routing）完成；伪造只能造成
  「浪费一个候选位」的 DoS，不能冒充节点。
- Mainline DHT 是 **IPv4 网络** → 控制面弱依赖 IPv4 出站 UDP；数据面纯 IPv6 不受影响。
- 中国网络下 Mainline 可能被干扰 → 文档指向兜底链 ⑥⑦（DDNS / 手动输入）。
- 会合只解决「找到地址」，不解决「地址是否可达」——拿到地址后仍走既有的打洞/握手流程。
