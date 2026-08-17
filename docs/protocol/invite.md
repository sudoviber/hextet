# hextet invite token（v1）

状态：已实现（`crates/core/src/invite.rs` 与本文档同步维护）

## 它解决什么问题

M1/M2 加一台机器要人工搬运四样东西：网络名、network key、引导节点公钥、引导节点
endpoint。抄错一个字符就是一次沉默的失败（前缀不同 → 地址不同 → 看起来"连上了"
但根本不在同一个网络）。invite token 把这四样打成**一行可粘贴的字符串**，并让接收方
能验证它在传输途中没被改动。

hextet 没有任何在线控制面（设计 spec §2 目标 2），所以 token 是**离线签发**的：
签发者用自己的节点密钥签名，不联系任何服务器。

## 线格式

```
hxi1.<payload>.<sig>
```

| 段 | 内容 |
|---|---|
| `hxi1` | 明文前缀，兼作版本标识（人一眼能认出这是什么；未来换格式就换前缀） |
| `payload` | JSON 载荷的 **base64url 无填充**编码 |
| `sig` | ed25519 签名的 base64url 无填充编码 |

**签名覆盖的是 `payload` 段的 ASCII 字节本身**，不是解码后的 JSON。这样验签方验的
就是它在线上看到的那串字符，完全绕开 JSON 规范化问题（键序、空白、数字表示法都不
影响）——与 JWT 同款做法。

token 是单行、无空白字符的，可以安全地放进 shell 单引号、放进聊天消息、写进文件。
典型长度 600 余字符。

### JSON 载荷字段

| 字段 | 类型 | 含义 |
|---|---|---|
| `v` | u32 | 恒为 1；不认识的版本一律拒绝 |
| `id` | string | 16 字节随机值的 base64url 无填充编码（22 字符），一次性标识 |
| `network_name` | string | 网络名 |
| `network_key` | string | 32 字节网络密钥的 base64（标准字母表，与配置文件里一致） |
| `issuer` | string | 签发者 ed25519 公钥的 base64 |
| `issued_unix` | u64 | 签发时刻 |
| `expires_unix` | u64 | 过期时刻（`now == expires_unix` 不算过期） |
| `listen_port` | u16 | 网络约定的 WireGuard 端口，写进新节点配置 |
| `bootstrap` | array | 引导节点，每项 `{name, public_key, endpoints[]}`；1..=8 个 |

- **未知字段一律忽略**（前向兼容）。因为签名覆盖整个载荷，攻击者无法在不持有签发者
  私钥的前提下塞进任何字段。
- `endpoints` 是 `[v6]:port` 字符串；出现 IPv4 直接拒绝（hextet 是 IPv6-only 的）。
- `bootstrap` 为空的 token 无法用来入网，因此**签发与解析两侧都拒绝**。
- 冻结测试向量见 `crates/core/src/invite.rs::tests::frozen_token_vector`。

### 解析顺序（安全边界）

0. **长度上限**：token 字符串总长不得超过 `MAX_TOKEN_LEN`（8192 字节），超限即拒。
   这一步在任何 base64 解码 / JSON 反序列化之前——payload 是未验签的攻击者可控输入，
   不设上限会让 JSON 反序列化 `bootstrap` 数组时按攻击者给的条目数无界分配内存
   （`MAX_BOOTSTRAP` 的计数检查在验签之后，对这条 DoS 路径太晚）。
1. 分段（必须恰好 3 段）→ 前缀 → `payload` base64 解码 → `sig` base64 解码且长度必须 64；
2. JSON 解析 → 版本检查 → 取出 `issuer` 公钥 → **验签**；
3. 验签通过之后才解析 `id` / `network_key` / 引导节点公钥与 endpoint。

也就是说：攻击者可控的地址字段只会在签名验证通过后才被解析；`bootstrap` 数组在验签前
会被反序列化成字符串，但受 `MAX_TOKEN_LEN` 硬上限约束，分配规模有界。

## 信任模型（诚实边界）

- 验签只证明**「token 自签发后未被篡改」**。它**不**证明签发者可信——新节点入网时
  还没有任何信任锚点，信任来自"你从谁手里拿到这个 token"。
- token 携带 network key，**等同于网络准入凭证**：拿到它的人可以派生网络前缀、
  解密未来的 DHT 会合记录（M3-E）、伪造 LAN 公告。因此必须走安全信道传递
  （密码管理器、端到端加密聊天），不要贴进公开群、工单、CI 日志。
- **「一次性」目前没有强制**：`id` 字段只是为将来准备的去重键。要真正做到"一张
  token 只能用一次"，需要引导节点在接纳新成员时记住已用过的 `id` 并 gossip 全网
  ——那是 M3-D 的工作。
- 过期检查在使用侧（`hextet join`）做。签发侧的 TTL 上限是 365 天。
- 签名在 M3-D 会承担真正的授权语义：引导节点用**已知的 admin 公钥**验证 token，
  验过才签发成员证书。届时 `issuer` 就不只是"元数据"了。

## 与命令的对应关系

| 命令 | 干什么 |
|---|---|
| `hextet invite new` | 用本机配置与身份签发一张 token（本机即引导节点） |
| `hextet join <token>` | 验签、查过期、生成/复用身份、写好 `hextet.toml` |
| `hextet peer add` | 引导侧接纳新节点（WireGuard 是双向认证的，这一步省不掉） |

用户向操作指引见 [docs/guides/joining.md](../guides/joining.md)。

## 为什么 `join` 之后还需要 `peer add`

WireGuard 的 cryptokey routing 要求**双方都知道对方的公钥**。token 给了新节点关于
引导节点的一切，但引导节点此刻还不知道新节点的公钥——而 M3-A 还没有 gossip 通道
可以把它自动送过去。因此 `join` 直接打印出引导侧要执行的那一条 `hextet peer add`
命令。

M3-D 落地后这一步会自动化：新节点凭 token 与引导节点建立会话，引导节点验证 invite
签名与 `id` 未被使用过，签发成员条目并 gossip 全网——那时才是 spec §8 承诺的
"新节点凭 invite 一条命令入网"。在此之前，文档与命令输出都如实说明差了哪一步。
