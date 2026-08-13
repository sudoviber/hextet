# 自托管 DDNS 兜底

> 会合兜底链第 ⑥ 层。当 LAN 组播、缓存、WireGuard roaming、gossip 转介、DHT 全都
> 找不到对端时，经**你自己的域名**重新缝合全网。中国网络下这是可达性最好的兜底。
> 协议细节见 `docs/protocol/ddns.md`，端口约定见 `docs/adr/ADR-0011-ddns-aaaa-fixed-port.md`。

## 什么时候需要它

默认关。只有当你遇到「双端同时换前缀、DHT 又被干扰、gossip 没第三节点兜底」这类
场景、希望加一道最稳的兜底时才开。大多数网络里 DHT + gossip 已经够用。

## 前提

- 你有一个域名，且能往它加 AAAA 记录（dynv6 / duckdns / 自家 DNS 脚本均可）。
- 每个**节点**各自一个 DDNS 域名（A 节点 `a.example.com`，B 节点 `b.example.com`）。
- 每台机器都知道**对方**的 DDNS 域名。

## 配置（每台机器各一份）

在 `hextet.toml` 里加 `[ddns]` 段，并给每个 peer 写上它的 DDNS 域名：

```toml
[ddns]
enabled = true
# {address} 会被替换成本机 IPv6 地址。token 只存在本地这份配置里，绝不提交。
update_url = "https://dynv6.com/api/update?hostname=a.example.com&token=REPLACE_WITH_YOUR_TOKEN&ipv6={address}"
port = 4193        # 查询到的 AAAA 地址要配的固定端口；省略即 4193

[[peers]]
name = "b"
public_key = "<b 的 hextet keygen 公钥>"
ddns = "b.example.com"
```

A、B 两台机器各填各的 `update_url`（指向自己的域名），`[[peers]]` 里填对方的域名。

## 注册商怎么配

任何「往 URL 里塞地址就能更新 AAAA」的服务都能用。两个常见例子：

- **dynv6**：`https://dynv6.com/api/update?hostname=你的域名&token=你的token&ipv6={address}`
  （token 在 dynv6 面板里对每个 zone 单独生成）。
- **duckdns**：`https://www.duckdns.org/update?domains=你的子域&token=你的token&ipv6={address}`

其它注册商只要能更新 AAAA 记录，就照它的 API 拼 URL、把地址的位置写成 `{address}`。

## 验证

1. 配好后 `hextet daemon` 启动，日志里应出现 `DDNS 会合已接线`。
2. 地址变化后（换前缀）或重启后，`hextet status` 里对端连接的 `endpoint_source`
   应可能显示为 `ddns`。
3. 也可手动验证 DNS 记录：`dig AAAA a.example.com` 应返回本机当前的公网 IPv6 地址。

## 诚实的边界

- **地址是明文的**：写进公共 DNS 的 AAAA 记录对所有人可见。用 DDNS = 接受「我在这」
  对观察者可见。介意地址隐私的请只用 DHT（AEAD 加密）或手动输入。
- **token 只在你机器上**：`update_url` 里嵌了 token，它只在本地 `hextet.toml`
  （gitignored）里，仓库里任何地方都用 `REPLACE_WITH_YOUR_TOKEN` 占位。
- **会合层不认证身份**：能改你域名的人能把记录指到任意地址，但这最多浪费一个候选位，
  无法冒充节点（真正的身份认证在 WireGuard 握手）。
