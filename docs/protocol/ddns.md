# 自托管 DDNS 会合

> 设计出处：`docs/superpowers/specs/2026-08-06-hextet-design.md` §3 D3（会合兜底链第 ⑥ 层）、
> §5。端口约定见 `docs/adr/ADR-0011-ddns-aaaa-fixed-port.md`。
> 实现位置：`crates/discovery/`（`ddns.rs` 客户端）、`crates/engine/src/ddns.rs`（接线）。

## 1. 定位

当 LAN 组播、端点缓存、WireGuard roaming、gossip 转介、DHT/pkarr 全都找不到对端时，
经**用户自己的域名**（自托管 DDNS）作为公共汇合点。这是中国网络下可达性最好的兜底——
用户的域名解析走普通 DNS，不像 Mainline DHT 那样依赖 IPv4 出站 UDP 且易受干扰。

**不绑定任何注册商**：客户端只知道一个「更新 URL 模板」与一个「查询域名」，用户自带
注册商与 token（dynv6 / duckdns / cloudflare 脚本 / 任意支持 HTTP 更新 AAAA 的服务均可）。

## 2. 端口约定（ADR-0011）

**AAAA 记录只承载地址，不承载端口。端口是固定的**（默认 `4193`，`[ddns] port` 可配）。

理由：DNS AAAA 记录的语义就是「纯 IPv6 地址」，塞端口会破坏标准客户端与第三方工具
的互操作；而 IPv6 下端口永远由本机决定（spec §5），对端端口在握手前是已知的固定值。
因此「地址进 AAAA、端口走配置」是最贴合 IPv6 无 NAT 现实、又最不 surprise 的约定。

## 3. 发布（把自己的地址写进域名）

- 每个 `[ddns]` 段的 `update_url` 是模板，`{address}` 占位符会被替换成**裸 IPv6 地址**
  （无方括号、无端口），例如：

  ```
  update_url = "https://dynv6.com/api/update?hostname=MYHOST.dynv6.net&token=REPLACE_WITH_YOUR_TOKEN&ipv6={address}"
  ```

  `token` / 域名 / 路径等其余部分由用户按自己的注册商拼进 URL——它们只存在本地
  `hextet.toml`（gitignored），**绝不入库、绝不提交**。
- 模板缺 `{address}` 占位符时，配置加载阶段即报错（不等到运行时静默写坏记录）。
- 发布节奏：启动即发、本机地址变化即发，之后每 ~10min 重发（多数 DDNS 服务端 TTL
  在 5–60min 之间，10min 是「地址变化后足够快收敛」与「不刷爆注册商限流」的折中）。
- 本机有多个可用 GUA 时**逐地址各发一次**更新。

## 4. 查询（找到对端的地址）

- 每个 `[[peers]]` 块可写 `ddns = "对端域名"`，本机周期性（60s）解析它的 AAAA 记录，
  过滤出可用地址（GUA，丢掉 ULA/链路本地/loopback），配上 `[ddns] port` 得到候选
  `[addr]:port`，喂给打洞候选列表（`endpoint_source == "ddns"`）。
- 解析失败或无可用地址返回空——与 DHT 查询「未找到返回空」同语义：会合层只提供候选，
  真正的身份认证在 WireGuard 握手（cryptokey routing）完成。

## 5. 配置示例

```toml
[ddns]
enabled = true
update_url = "https://dynv6.com/api/update?hostname=MYHOST.dynv6.net&token=REPLACE_WITH_YOUR_TOKEN&ipv6={address}"
port = 4193

[[peers]]
name = "nas"
public_key = "<对方 hextet keygen 输出的公钥>"
ddns = "nas.dynv6.net"
```

## 6. 信任模型与诚实边界

- **会合层不做身份认证**：DDNS 域名/地址是用户自有公共命名空间，任何能改域名记录的人
  都能指到任意地址。这与 LAN 公告、DHT 是同一信任模型——伪造只能造成「浪费一个候选位」
  的 DoS，不能冒充节点；身份认证在 WireGuard 握手完成。
- **地址本身不是秘密**：写入公共 DNS 的 AAAA 记录对所有人可见。hextet 不承诺 DDNS 的
  地址隐私（与 DHT 的「会合隐私」不同——DHT 记录经 AEAD 加密，DDNS 记录是明文 DNS）。
  用 DDNS 意味着接受「我在这」这一事实对观察者可见；介意者请只用 DHT 或手动输入。
- DDNS 解析走系统 DNS，不接管、不污染系统 DNS 配置（spec §5 的硬约束）。
- 配置里 `port` 与 `[[peers]] ddns` 在进程生命周期内不变（配置不热加载），gossip
  准入的成员没有 DDNS 域名可查，因此 DDNS 没有运行时查询目标更新通道（见
  `crates/engine/src/ddns.rs` 模块文档）。
