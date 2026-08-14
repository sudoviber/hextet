# 查看连接状态

`hextet status` 读内核 WireGuard 状态 + daemon 的状态文件，汇报每条 peer 连接的当前
状态。有三种呈现方式：人类表格、`--json`、`--tui`。

```console
$ hextet status                 # 人类可读表格（一次性）
$ hextet status --json          # JSON（给脚本/前端）
$ hextet status --tui           # 交互式表格（每秒刷新）
```

三种模式读的是同一份报告（`build_report`），字段完全一致。

## 人类表格

```console
$ hextet status -c hextet.toml
daemon   running（状态更新于 1s 前）
peer         address                      endpoint                    source  lan  punch         handshake   rx    tx  routes
nas          fd12:3456:78:abcd::2        [2001:db8::b]:4193           config    1  connected           3s  1.2k  980  -
```

表头各列：

| 列 | 含义 |
|---|---|
| `peer` | peer 名（配置里不认识的内核 peer 记为 `<unknown>`） |
| `address` | peer 的 overlay IPv6 地址 |
| `endpoint` | 内核记录的当前 endpoint |
| `source` | endpoint 来源：`config` / `lan` / `gossip` / `relay` / `cache` / `roamed` / `none` |
| `lan` | LAN 组播发现当前给出的 endpoint 数量 |
| `punch` | 打洞状态：`probing`（轮换候选打洞中）/ `connected`（直连）/ `relayed via <中继名>`（走中继） |
| `handshake` | 距最近握手的秒数（从未握手为 `-`） |
| `rx` / `tx` | 接收 / 发送字节数 |
| `routes` | 已装进路由表的 site-to-site 子网路由（逗号拼接；没有为 `-`） |

`punch` 列在走中继时显示 `relayed via <中继名>`，**绝不显示成 `connected`**——你必须
能看出这条连接经过了另一个节点。中继细节见 [relay](relay.md)。

表格上方有一行 daemon 存活头部：

- `daemon   running（状态更新于 Ns 前）` —— daemon 在跑；
- `daemon   not running（状态文件 <路径> 停留在 Ns 前）` —— daemon 已停（状态文件
  超过 10s 没更新）；
- `daemon   not running（无状态文件；动态端点自愈未启用）` —— 没有状态文件（可能
  根本没跑过 daemon，或状态文件版本不匹配被当作无状态）。

## `--json`

`--json` 输出 `{ "daemon": ..., "peers": [...] }`：

- `daemon`：`{ "running", "updated_secs_ago", "state_file" }`，没有状态文件时为 `null`。
- `peers[]`：每行与人类表格同字段，另含 `state`（`connected` / `stale` /
  `no-handshake`）、`punch_state`、`relay_via`、`candidates`、`candidate_index`、
  `lan_endpoints`、`gossip_endpoints`、`routes`。

JSON 线格式冻结不变，字段含义见 `docs/dev/state-files.md`。

## `--tui`

`--tui` 用 ratatui + crossterm 画一个交互式表格：每秒重读一次状态并重绘，`q`、`Esc`
或 `Ctrl-C` 退出。列与人类表格相同，只是**没有 `lan` 计数列**。

## HTTP 状态服务

daemon 里内嵌了一个 axum HTTP 状态服务器，只读地暴露 `hextet status --json` 的
同一份 `StatusReport`：

| 端点 | 返回 |
|---|---|
| `GET /healthz` | `{"status":"ok"}`（存活探测） |
| `GET /api/status` | 与 `hextet status --json` 完全相同的 `{ daemon, peers }` JSON；读状态失败时返回 500 + `{"error": "..."}` |

它默认**关闭**。要打开，在 `[node]` 里成对配置监听地址与端口：

```toml
[node]
http_addr = "::1"    # 监听地址（IPv6-only，与 http_port 成对出现）
http_port = 8080     # 端口（/healthz + /api/status）
```

`http_addr` 与 `http_port` **要么都设、要么都不设**——只设一个会在配置加载时报错。
hextet 是 IPv6-only 的，`http_addr` 就是 IPv6 地址，不存在 IPv4 泄漏路径。

可选地，设 `[node] web_dir` 指向 `web/` 前端构建产物目录（`web/dist`）时，状态服务
会在 `/` 下静态托管它（`/` 自动回退到 `index.html`；`/healthz` 与 `/api/status` 始终
优先于静态回退）。不设则只有上面两个只读端点。

重启 daemon 后即可访问：

```console
$ curl http://[::1]:8080/healthz
{"status":"ok"}
$ curl http://[::1]:8080/api/status
{"daemon":{"running":true,"updated_secs_ago":1,"state_file":"/var/lib/hextet/state.json"},"peers":[...]}
```

HTTP 服务失败（端口被占等）只打 warn，**不影响数据面**——daemon 照常打洞转发。

## 诚实的边界

- **平台差异**：Linux 上 `hextet status` 读内核 WireGuard 状态（`build_report`，
  完整 peer 列表）；macOS/Windows 上读 `state.json`（`build_report_from_state`，
  v7 起已含 WG 统计）。`--tui` 三个桌面平台都能跑，走同一套按平台分派。
- **`--tui` 需要真实 TTY**：它进 raw mode + alternate screen，在无 TTY 的环境
  （systemd 服务、CI、管道）里跑不起来。
- **HTTP 是只读状态**：`/healthz` 与 `/api/status` 只读，**不能**改配置、加 peer、
  改 endpoint；可选的静态前端托管（`[node] web_dir`）也只是**只读**地 serve `web/` 的
  构建产物，没有任何写操作。
- **状态是快照，可能滞后 ≤1s**：daemon 每秒重写一次状态文件，`status` 读的是这份
  快照；握手新鲜度由内核 WG 状态实时判定。

## 参考

- 状态文件格式与字段含义：`docs/dev/state-files.md`
- 中继（`relayed via X`）：`docs/guides/relay.md`
- 子网路由（`routes` 列）：`docs/guides/site-to-site.md`
- 按名访问（MagicDNS-lite）：`docs/guides/hosts.md`
- 实现计划：`docs/superpowers/plans/2026-08-12-m5-ui.md`
