# 自托管 DDNS 会合（会合兜底链第 ⑥ 层）

当「双方同时换前缀」且 DHT（第 ⑤ 层）在中国网络下被干扰时，hextet 可以用**你自己的域名**
作为汇合点：每个节点把当前 endpoint 加密后发布到自己域名的 TXT 记录上，其他节点解析这个
域名就能重新找到它。这是兜底链第 ⑥ 层，也是最「自托管」的一层——汇合点是你自己的域名，
不依赖任何第三方基础设施。

> 设计出处：`docs/protocol/ddns.md`、`docs/adr/ADR-0010-ddns-txt-signed-rendezvous.md`。

## 它怎么工作

1. 开启 DDNS 的节点把自己的公网 IPv6 地址 + 端口 + 时间戳，用网络密钥派生的 AEAD
   **加密**后，作为一个 TXT 记录发布到自己的 FQDN（如 `home.example.com`）。
2. 配置里带 `ddns = "home.example.com"` 的对端，每 30s 解析一次这个域名的 TXT 记录，
   解密得到 endpoint，喂给打洞候选。
3. DNS 解析器/注册商看到的是密文（`hxdd1.` 开头的一串 base64），读不出「谁在哪」——
   隐私与 DHT 记录（第 ⑤ 层）同一层保证。

会合层**不做身份认证**（与 LAN 公告、DHT 同一信任模型）：伪造记录只能造成「浪费一个
候选位」的 DoS，真正的身份认证在 WireGuard 握手完成。

## 开启发布（本节点）

在 `hextet.toml` 的 `[node]` 段加：

```toml
[node]
ddns = true
ddns_fqdn = "home.example.com"
ddns_provider = "webhook"              # 或 "cloudflare"
ddns_webhook_url = "https://ddns.example.com/update"
# ddns_secret = "..."                  # webhook 的 Bearer token（可选）
```

发布节奏：启动即发、本机地址变化即发，之后每 ~15 分钟重发一次（给 DNS TTL 传播留余量）。

## 让对端按域名找你

在对端（想连你的那台机器）的 `hextet.toml` 里，给对应 peer 加一行 `ddns`：

```toml
[[peers]]
name = "home"
public_key = "<对方 hextet keygen 输出的公钥>"
ddns = "home.example.com"
```

这样对端即使不知道你的当前地址，也会每 30s 解析 `home.example.com` 的 TXT 记录来发现你。

## 两种提供方

hextet 通过 `DdnsUpdater` 抽象「更新 TXT 记录」这个动作，内置两种：

### 1. webhook（推荐，最自托管）

hextet 把 `{"fqdn":"...","value":"..."}` POST 到你自己的 URL。你在这个 URL 后面接自己的
服务，再调真实注册商 API（Cloudflare/DNSPod/阿里云/自建 DNS……）去更新 TXT 记录。hextet
不关心后端是谁，**零注册商锁定**。

一个极简的 Cloudflare Worker 示例（POST 收到后调 Cloudflare API 更新 TXT）：

```js
export default {
  async fetch(req, env) {
    if (req.headers.get("authorization") !== `Bearer ${env.WEBHOOK_TOKEN}`)
      return new Response("unauthorized", { status: 401 });
    const { fqdn, value } = await req.json();
    // 用 env.CF_API_TOKEN 调 Cloudflare v4 API：zones → dns_records → upsert TXT
    // （省略实现，逻辑与 hextet 内置的 cloudflare 提供方一致）
    return new Response("ok");
  },
};
```

可选：`ddns_secret` 设为 webhook 的 Bearer token，hextet 每次请求都带
`Authorization: Bearer <secret>`。

### 2. cloudflare（内置直连）

直接调 Cloudflare v4 API，无需自建服务：

```toml
[node]
ddns = true
ddns_fqdn = "home.example.com"
ddns_provider = "cloudflare"
ddns_secret = "<Cloudflare API token>"   # 只读不到，需要 DNS:Edit 权限
ddns_zone = "example.com"                # 域名所在的 zone 名
```

`ddns_secret` 是**秘密**：它和 network key 一样存在 0600 的 `hextet.toml` 里，
**不要提交进 git**（Debug/日志输出会打码成 `<redacted>`）。

## 诚实的边界

- **是兜底，不是首选**：DDNS 排在会合兜底链第 ⑥ 层（⑤ DHT 之后、⑦ 手动输入之前），
  只在 DHT 不可达的罕见场景才真正派上用场。日常仍是直连 + 缓存 + WireGuard roaming。
- **有 TTL 传播延迟**：DDNS 更新要等 DNS TTL 传播，恢复速度比 DHT 慢一个 TTL；但中国
  网络下它比 DHT 可达性好。
- **不解决「地址是否可达」**：拿到地址后仍走既有的打洞/握手流程，会合只负责「找到地址」。
- **TXT 记录有 255 字节上限**：发布端把 endpoint 数封顶为 2，超出的丢弃并打 warn。
- **真实域名路径未真机验证**：本地测试用 mock HTTP server + 测试用解析器覆盖请求形状与
  解析逻辑；真实注册商更新与真实 DNS 解析路径在真机上验证（与 DHT「本地 Testnet、不打
  真实 DHT」同一验证姿势）。
- **域名公开**：DDNS 的「定位」（域名）是公开的，但内容经 AEAD 加密，解析器/注册商读
  不出端点；域名本身是否绑定实名身份，由你的域名注册方式决定。

## 参考

- 协议与线格式：`docs/protocol/ddns.md`
- 设计决策：`docs/adr/ADR-0010-ddns-txt-signed-rendezvous.md`
- DHT 会合（第 ⑤ 层）：`docs/protocol/dht-record.md`
- 实现计划：`docs/superpowers/plans/2026-08-12-m6-windows-and-release.md`（切片 C）
