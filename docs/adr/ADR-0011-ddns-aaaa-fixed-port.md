# ADR-0011 自托管 DDNS 会合：AAAA 只承载地址，端口固定

- **状态**：已接受
- **日期**：2026-08-13
- **决策者**：hextet 项目
- **相关**：`docs/protocol/ddns.md`、spec §3 D3 第 ⑥ 层

## 背景

会合兜底链第 ⑥ 层是「用户自托管 DDNS」——用户自己的域名 + 客户端调注册商 API 更新
`AAAA/TXT` 记录，供对端解析回「我在哪」。落地时有两个待定决策：

1. **端口怎么承载**：IPv6 endpoint 是 `[addr]:port`，但 DDNS 的 AAAA 记录只能放地址。
   spec 原文写「更新 AAAA/TXT」，暗示了两种可能：AAAA 放地址、TXT 放端口，或端口固定。
2. **更新 API 形态**：不同注册商 API 差异巨大（dynv6 的 `/api/update`、duckdns 的
   `domains/token` webhook、cloudflare 的 REST + token…），怎么不绑死任何一家。

## 决策

1. **端口固定，不塞 TXT**。AAAA 记录只承载裸 IPv6 地址，端口固定为节点配置的
   `listen_port`（默认 4193，`[ddns] port` 可覆盖）。不用 TXT 承载端口。
2. **更新 API 走「更新 URL 模板」**。`[ddns] update_url` 是用户提供的模板，`{address}`
   是唯一的保留占位符，替换成裸 IPv6 地址；token/域名/路径等其余部分由用户按自己的
   注册商拼进 URL（webhook 式）。
3. **对端域名声明在 `[[peers]] ddns`**。每个 peer 的 DDNS 域名是静态配置（与静态
   `endpoints` 同属「手动声明」），查询侧据此解析 AAAA。

## 备选与理由

- **TXT 承载端口**（spec 原文的「AAAA/TXT」写法）：被否。TXT 记录用于他途时易冲突、
  解析需二次查询、第三方工具与标准客户端不认「地址在 AAAA、端口在 TXT」的拆分语义；
  而 IPv6 下端口本来就由本机决定（spec §5「端口永远由自己决定」），对端端口在握手前
  是已知固定值，没有「端口也会变」的问题需要 TXT 去解。
- **硬编码单一注册商 API**：被否。违背「用户自带域名 + token」的定位，且把某一家
  注册商的 API 漂移风险锁进代码库。模板化后，任何支持 HTTP 更新 AAAA 的服务都能用，
  换注册商只改一行配置。
- **每 peer 单独一个 update_url**：暂不做。发布侧只关心「把本机地址写进**本机**的
  域名」，一个模板足够；对端域名只在查询侧用，不需要对方暴露其 update_url。

## 后果

- 用户须自行把 token 内嵌进 `update_url`（只存本地 `hextet.toml`，gitignored）；
  配置模板与文档一律用 `REPLACE_WITH_YOUR_TOKEN` 占位，仓库内零 secret。
- DDNS 地址**明文进公共 DNS**，无会合隐私（与 DHT 的 AEAD 加密不同）——这是「可达性
  优先」与「隐私」的取舍，已在 ddns.md §6 诚实标注。
- `DdnsSettings` 的手写 `Debug` 打码 `update_url`（与 `Config` 对 `network_key` 打码
  同一条纪律），杜绝 token 经日志/测试路径泄露。
