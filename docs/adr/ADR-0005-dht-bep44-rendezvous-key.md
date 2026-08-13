# ADR-0005：DHT 会合用 BEP44 可变项 + 网络密钥派生的会合密钥对，而不是 HMAC 派生 infohash

- 状态：已接受
- 日期：2026-08-13
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D3 / §5、
  `docs/protocol/dht-record.md`、`crates/discovery/`

## 背景

spec §5 把 DHT 记录写成
`put(key=HMAC(network_key, node_pubkey), value=AEAD_network_key({endpoints, port, epoch}), seq)`，
其中 `key` 是一个 20 字节的 infohash。实现时要选 DHT 客户端，而事实上的标准选择
`mainline`（BEP5/BEP44，iroh 同款底层）对**可变项**（mutable item，BEP44）的寻址方式
是：`target = SHA1(ed25519_公钥 || salt)`，且必须由那个 ed25519 公钥对应的私钥签名。
它**没有**"往任意 20 字节 infohash 上发布可变值"的原语——`put_immutable` 的目标是
`SHA1(value)` 不可指定、且不可更新；`get_peers`/`announce_peer` 是 BitTorrent peer 列表
语义、只存 IPv4 且泄露地址。三条路都不匹配 spec 的写法。

## 决策

1. **用 `mainline` 的 BEP44 可变项**（`MutableItem`），而不是自造 raw-infohash 传输。
   它自带：单调 `seq`、CAS（乐观并发）、ed25519 签名校验、分发给 20 个最近节点的
   PUT 语义——正是"会合记录"需要的东西，且是久经考验的实现。
2. **用网络密钥派生一个会合 ed25519 密钥对**来寻址，取代 spec 的 HMAC 20 字节 key：
   - `rendezvous_seed = HMAC-SHA256(key=derive_dht_key(network_key), msg = "hextet-dht-sign" || node_pubkey)`，
     截断到 32 字节 → `SigningKey`。
   - 记录的 target = `SHA1(该密钥的公开部分)`。因为公开部分是由网络密钥派生的，
     **外人（不知道网络密钥）无法从节点公钥算出 target，也就定位不到记录**——与 spec
     想要的"外人无法定位"是同一层保证，只是实现载体从"HMAC 出的 20 字节"换成了
     "派生出的 ed25519 公钥"。
3. **载荷继续用 AEAD 加密**（`derive_dht_key` 作 AEAD key，已实现）：内容保密不依赖
   于"记录找不找得到"，双保险。
4. **不用 salt**：会合公钥已经是秘密派生的，target 已经不可猜；加 salt 不带来额外
   隐私，反而多一个要两端都算对的参数。若将来要换记录格式版本，用新 ADR 换用途串。
5. **签名不承担身份认证**：会合密钥对是全网共享网络密钥派生出来的，任何网内成员都能
   给任意节点伪造记录。这与 LAN 公告的 HMAC 是同一信任模型——会合层只提供"候选
   endpoint"，真正的身份认证在 WireGuard 握手（cryptokey routing）完成；伪造只能造成
   "浪费一个候选位"的 DoS，不能冒充节点。

## 与 spec 的偏离记录

spec 写的是 `key = HMAC(network_key, node_pubkey)`（20 字节 infohash）。这条偏离
如实记录：目标不变（会合隐私），手段从"HMAC infohash"换成"BEP44 可变项 + 派生密钥对"，
因为前者在 `mainline` 里没有对应原语。

## 代价与风险

- **新依赖**：`mainline` → `ed25519-dalek 3.0.0-pre.1`（**预发布版本**）。这是 spec §13
  已列的"pkarr/mainline API 快速 break"风险的具体化。缓解：锁死 `mainline = "=8.0.0"`、
  全部封装在 `crates/discovery`（本 crate 之外不暴露 `mainline` 类型）、`cargo deny check`
  常开（预发布版本若被 yanked/出现 RUSTSEC 会立刻可见）。
- **IPv4 弱依赖**：Mainline 是 IPv4 网络，控制面弱依赖 IPv4 出站 UDP（spec §5 已声明）。
  数据面仍纯 IPv6。
- **无 IPv6 直连测试面**：会合的本地验证走 `mainline` 的 `Testnet`（loopback IPv4
  测试网），不打真实 DHT。

## 重新评估的条件

- `ed25519-dalek 3.0` 发布稳定版、或 `mainline` 迁移到稳定版本 → 立即跟进。
- 若发现"网内恶意成员伪造记录"造成的候选污染实际影响了连通性 → 再评估是否在载荷里
  加节点自签（用节点身份密钥签 endpoint，而非会合密钥），用新 ADR 覆盖本条。
