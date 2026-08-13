# 自托管 DDNS 会合记录格式

> 设计出处：`docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D3（会合兜底链第 ⑥ 层）、
> §5。落地决策见 `docs/adr/ADR-0010-ddns-txt-signed-rendezvous.md`。
> 实现位置：`crates/discovery/`（`ddns.rs` 纯逻辑 + `ddns/` 解析/更新传输）、
> `crates/engine/`（调度接线）。

## 1. 定位

当 Mainline DHT（第 ⑤ 层）在中国网络下不可达、且双方同时换前缀时，经用户**自己的域名**
作为汇合点重新找到彼此。控制面走 DNS（TXT 查询）与 HTTP（记录更新），数据面仍是纯 IPv6。

## 2. 密钥派生

`ddns_key = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("ddns-record", 32)`

这把密钥只 gate「读懂」一件事（内容 AEAD 加密）；「定位」由用户自己的域名决定。
它与 DHT（`"dht-record"`）、doctor 探针、LAN 公告、中继的密钥彼此独立。

## 3. 记录（TXT 值）

每个节点在自己的 FQDN（如 `nas.example.com`）上发布一条 TXT 记录：

```
hxdd1.<base64url_nopad( nonce(12) || AEAD_ChaCha20Poly1305(key=ddns_key, json(RecordPayload)) )>
```

- `hxdd1.` 是版本前缀（`hx` = hextet，`dd` = ddns，`1` = 版本 1）。
- `nonce` 不保密但不可重复，前置到密文里让记录自包含（与 DHT 记录同构）。
- 明文载荷复用 DHT 的 `RecordPayload`：

| 字段 | 类型 | 含义 |
|---|---|---|
| `endpoints` | array | `[v6]:port` 字符串（已过滤可用地址；发布端封顶 2 条，超出丢弃并 warn） |
| `epoch` | u64 | `unix_secs / 3600`（粗粒度，保护作息隐私） |

DNS TXT 单条上限 255 字节；1 个 endpoint 的密文 base64url 后约 120 字节，安全。
发布端把 endpoint 数封顶为 2。

## 4. 发布与查询节奏

- **发布**：启动即发、本机地址变化即发；之后每 ~15min 重发（给 TTL 传播留余量）。
- **查询**：对每个配了 `ddns = "..."` 的 peer，每 30s 解析其 FQDN 的 TXT 记录；
  多条 `hxdd1.` 记录里取 **epoch 最大**的那条解密，得到 endpoint。
- 查询结果喂给候选来源 `Source::Ddns`，候选优先级排在 DHT 之后（兜底链 ⑤ 先于 ⑥）。

## 5. 提供方

hextet 通过 `DdnsUpdater` trait（`set_txt(fqdn, value)`）抽象更新动作，内置：

- **Webhook**：POST `{"fqdn","value"}` JSON 到用户自己的 URL（可选 Bearer token）。
  用户在自有服务里接 webhook 再调真实注册商 API，hextet 不关心后端。
- **Cloudflare**：直接调 Cloudflare v4 API（zones → dns_records → upsert TXT），
  用 API token 认证。

## 6. 信任模型与诚实边界

- **会合层不做身份认证**：`ddns_key` 是全网共享网络密钥派生的，任何网内成员都能
  伪造任意节点的记录。伪造只能造成「浪费一个候选位」的 DoS，不能冒充节点——真正的
  身份认证在 WireGuard 握手（cryptokey routing）完成。
- DDNS 的「定位」（域名）公开，但域名是用户自有的，不属于第三方观察面；内容经 AEAD
  加密，DNS 解析器/注册商读不出端点（与 DHT 记录的隐私同一层保证）。
- DDNS 更新有 TTL 传播窗口，恢复速度比 DHT 慢一个 TTL，但在中国网络下可达性更好。
- 会合只解决「找到地址」，不解决「地址是否可达」——拿到地址后仍走既有的打洞/握手流程。
