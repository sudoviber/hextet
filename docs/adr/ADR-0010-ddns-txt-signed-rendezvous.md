# ADR-0010：自托管 DDNS 会合用 TXT 记录 + 网络密钥派生的 AEAD 加密，而不是明文 AAAA

- 状态：已接受
- 日期：2026-08-14
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D3 / §5、
  `docs/protocol/ddns.md`、`crates/discovery/`、`crates/engine/`

## 背景

spec §3 D3 的会合兜底链第 ⑥ 层是「用户自托管 DDNS」：中国网络下 Mainline DHT
（第 ⑤ 层）可能被干扰，需要一个用户自己可控的汇合点。spec §5 把落点写成
「客户端调注册商 API 更新 AAAA/TXT」。实现时要定三件事：载体（AAAA 还是 TXT）、
内容（明文还是加密）、提供方抽象（每家注册商 API 都不一样，怎么封）。

## 决策

1. **载体用 TXT，不是 AAAA**。AAAA 只能带一个地址、带不了端口与新鲜度，而且
   **明文**把「某节点现在在哪个 GUA」长期暴露给 DNS 解析器与注册商。TXT 能带
   端口 + epoch + 多 endpoint，且能把内容加密——隐私与 DHT 记录（第 ⑤ 层）对齐。
2. **内容用 AEAD 加密**，密钥从网络密钥派生：
   `ddns_key = HKDF-SHA256(salt="hextet-v1", ikm=network_key).expand("ddns-record", 32)`。
   载荷**复用** DHT 记录的 `RecordPayload { endpoints, epoch }`（`crates/discovery/src/record.rs`），
   线格式是 DHT 密文的文本安全包装：

   ```
   TXT 值 = "hxdd1." || base64url_nopad( nonce(12) || AEAD_ChaCha20Poly1305(key=ddns_key, json(RecordPayload)) )
   ```

   与 DHT 的差异只在两处：DDNS 的「定位」是用户自己的域名（公开、但域名归用户所有，
   不属于第三方观察面），DHT 的「定位」是网络密钥派生的 target（隐藏）；两者的
   「读懂」都由 AEAD 同一纪律 gate。密钥用途串 `"ddns-record"` 与 `"dht-record"` 分开，
   一把密钥只干一件事。
3. **信任模型与 DHT 一致**（ADR-0005 决策 5）：会合层不做身份认证。`ddns_key` 是全网
   共享网络密钥派生的，任何网内成员都能伪造任意节点的记录；伪造只能造成「浪费一个
   候选位」的 DoS，真正的身份认证在 WireGuard 握手（cryptokey routing）完成。
4. **提供方抽象用 `DdnsUpdater` trait**（edition 2024 原生 `async fn`，不引入 async-trait）：
   `set_txt(fqdn, value) -> Result<(), String>`。内置两个实现：
   - `WebhookUpdater`：把 `{"fqdn","value"}` POST 到用户自己的 URL（可选 Bearer token）。
     这是最「自托管」的路径——用户在自有服务/Cloudflare Worker/注册商网关里接这个
     webhook 再调真实注册商 API，hextet 不关心后端是谁，零注册商锁定。
   - `CloudflareUpdater`：直接调 Cloudflare v4 API（zones → dns_records → upsert TXT）。
     Cloudflare 是国内可达性好、TXT 支持成熟、文档清晰的通用选择，作为内置直接路径。
   - `MockUpdater`：测试替身。
5. **查询用 `hickory-resolver` 的 TXT 查询**：解析 `hxdd1.` 记录、取 epoch 最大的那条
   解密，得到 endpoint，喂给候选来源 `Source::Ddns`。候选优先级排在 DHT(2) 之后为 **3**
   （兜底链 ⑤ 先于 ⑥，与 spec 顺序一致）。
6. **Cloudflare API token 是秘密**：与 network key 同处 0600 配置文件；在 `NodeSettings`
   里用 `SecretString` 新类型包装（Debug 打码 `<redacted>`、Drop 时 zeroize），
   不让任何日志/调试路径泄露。

## 与 spec 的偏离记录

spec §5 写「更新 AAAA/TXT」二选一未定。本决策选定 **TXT**（AAA 被否的理由见决策 1），
如实记录：目标不变（会合兜底 + 隐私），载体从二选一定为 TXT。

## 代价与风险

- **新依赖**：`hickory-resolver`（TXT 查询）与 `reqwest`（webhook/Cloudflare HTTP）。
  两者都是成熟标准库；`reqwest` 用 rustls（default-features 关掉，避开 aws-lc 交叉编译坑，
  spec §13 已列）。
- **DNS TXT 255 字节上限**：密文 base64url 后 ~120 字节/条（1 个 endpoint），安全；
  发布端把 endpoint 数封顶为 2，超出的丢弃并 warn。
- **传播延迟**：DDNS 更新有 TTL 传播窗口，查询侧每 30s 轮询受 TTL 缓存约束；这是
  兜底链第 ⑥ 层的既有属性，可接受（比 DHT 慢一个 TTL，但比 DHT 在中国可达）。
- **无真实注册商可测**：本地验证走 mock HTTP server（webhook/Cloudflare 请求形状）+
  测试用解析器；真实域名更新与解析路径如实标注「未真机验证」。

## 重新评估的条件

- 若某目标平台/提供方只支持 AAAA（不支持 TXT）→ 加明文 AAAA fallback，用新 ADR 覆盖。
- 若 `hickory-resolver` 体积对路由器 flash 压力过大 → 换 `hickory-client` 或延迟到
  rust-embed 构建裁剪时再评估。
- 若发现恶意成员伪造 DDNS 记录造成实际连通性影响 → 在载荷里加节点自签（用节点身份
  密钥签 endpoint），用新 ADR 覆盖本条（与 ADR-0005 的重新评估条件对齐）。
