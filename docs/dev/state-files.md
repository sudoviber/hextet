# daemon 的磁盘状态文件

`hextet daemon` 在 `[node] state_dir`（默认 `/var/lib/hextet`）下维护四个 JSON 文件。
目录由 daemon 首次启动时创建（权限 0700），四个文件均为 0600、写入走
"临时文件 → fsync → rename" 的原子替换（`crates/engine/src/atomic.rs` 或
`crates/discovery/src/nodes.rs` 的内联同语义实现）。

## endpoints.json —— 端点缓存（持久化软状态）

记录每个 peer "上次能连上的 endpoint"，让重启后的重连走最快路径；也是配置里
没写 endpoint 时唯一的候选来源。

```json
{
  "version": 1,
  "peers": {
    "<peer ed25519 公钥 base64>": {
      "last_good": "[2001:db8::b]:4193",
      "seen": [{ "endpoint": "[2001:db8::b]:4193", "last_seen_unix": 1770000000 }]
    }
  }
}
```

- `last_good`：最近一次被证实可用的 endpoint，排在候选列表最前面。
- `seen`：历史 endpoint，按 `last_seen_unix` 由新到旧，最多 8 条。
- **软状态**：文件缺失、JSON 损坏、`version` 不认识时一律降级为空缓存并写一条
  warn 日志，不影响 daemon 启动。可以随时删除（代价是首次重连慢几秒）。

## state.json —— 运行时状态快照（派生数据）

daemon 每秒重写一次，`hextet status` 读它来补充内核看不到的信息（打洞进度、
endpoint 来源）。

```json
{
  "version": 6,
  "updated_unix": 1770000000,
  "interface": "hextet0",
  "node_address": "fd12:3456:78::1",
  "node_public_key": "<base64>",
  "peers": [
    {
      "name": "b",
      "public_key": "<base64>",
      "address": "fd12:3456:78:abcd::2",
      "punch_state": "connected",
      "endpoint": "[2001:db8::b]:4193",
      "endpoint_source": "gossip",
      "lan_endpoints": 0,
      "gossip_endpoints": 1,
      "ddns_endpoints": 0,
      "relay_via": null,
      "routes": ["2001:db8:dead::/64"],
      "candidates": 2,
      "candidate_index": 0,
      "rounds": 0
    }
  ]
}
```

- `punch_state`：`probing`（正在轮换候选打洞）/ `connected`（握手新鲜的直连）/
  `relayed`（握手新鲜，但走的是中继会话 endpoint）。**走中继时绝不显示成 connected**
  ——用户必须能看出这条连接经过了另一个节点。
- `relay_via`：正在经哪个中继（peer 名，配置里的本地名字）；不在中继时为 `null`。
- `endpoint_source`：`relay` / `config` / `lan` / `gossip` / `cache` / `roamed` / `none`。**同一个地址可能同时属于
  多路来源**（例如既写在配置里、又正被对端在 LAN 上公告），此时按下面的顺序取第一个命中的
  ——它回答的是"这个地址最好用什么来解释"，不是"哪一路先送到"。判定顺序：
  `lan` 表示这个地址来自 LAN 组播公告（见 `docs/protocol/lan-discovery.md`），
  `gossip` 表示来自隧道内 gossip 转介（见 `docs/protocol/gossip.md`），
  `relay` 表示这是中继为这对会话分配的 endpoint（见 `docs/protocol/relay.md`），
  `roamed` 表示既不在中继、也不在配置、也不在 LAN 公告、也不在缓存里——是内核根据已认证的包
  学到的（对端换了地址）。
- `lan_endpoints`：LAN 组播发现当前给出的 endpoint 数量。它记录的是**最近一次收到的
  公告内容**：对端 daemon 停掉后这个数字不会归零（内存里的 LAN 表会按 TTL 过期，
  但已经交给候选列表的地址会留着当兜底，语义与端点缓存一致）；daemon 重启即清空。
- `version`：2 起包含 `lan_endpoints` 与 `endpoint_source` 的 `lan` 取值；
  3 起包含 `relay_via`、`punch_state` 的 `relayed` 与 `endpoint_source` 的 `relay`；
  4 起包含 `gossip_endpoints` 与 `endpoint_source` 的 `gossip` 取值；
  5 起包含 `routes`（peer 通告、且本机当前已装进路由表的 site-to-site 子网路由）。
  `hextet status` 只读同版本的文件，版本不认识时当作"没有 daemon 状态"。
- `updated_unix`：`hextet status` 用它判断 daemon 是否还活着（超过 10s 视为已停）。
- `gossip_endpoints`：gossip 转介当前给出的 endpoint 数量（语义同 `lan_endpoints`，
  只是来源是隧道内的 gossip 条目）。
- `routes`：这个 peer 通告、且本机当前已装进路由表的子网路由（`前缀/长度` 字符串数组）。
  只在 peer 处于 `connected`/`relayed` 时非空——断连期间 daemon 会清掉这些路由，
  避免把流量送进黑洞。见 `docs/guides/site-to-site.md`。
- **纯派生数据**：删掉不会丢任何东西，daemon 下一秒就重写。

## members.json —— gossip 准入成员表（持久化软状态）

gossip（见 `docs/protocol/gossip.md`）准入的成员在这里落盘，让 daemon 重启后
无需等下一轮广播就知道这些成员是谁。

```json
{
  "version": 1,
  "members": [
    { "name": "nas", "public_key": "<base64>", "address": "fd12:3456:78:abcd::1" }
  ]
}
```

- **软状态**：与 `endpoints.json` 同规则——缺失、损坏、版本不认识一律降级为空表。
- 吊销会从这里移除对应成员；`member` 与 `revocation` 是 gossip 里不同 key 的条目，
  吊销不删审计信息（gossip store 里仍保留），只是数据面拒绝该公钥。

## dht-nodes.json —— DHT bootstrap 节点表（持久化软状态）

DHT 会合（见 `docs/protocol/dht-record.md`）每次运行时把 `mainline` 路由表里的
bootstrap 节点落盘，下次冷启动直接用它们，避免每次都依赖公开 bootstrap 节点。

```json
{
  "version": 1,
  "nodes": ["1.2.3.4:6881", "5.6.7.8:6881"]
}
```

- **软状态**：与 `endpoints.json` 同规则——缺失、损坏、版本不认识一律降级为空表，
  退回 `mainline` 内置公开 bootstrap 节点。
- `nodes` 是 `"ip:port"` 字符串，上限 128 条（`crates/discovery/src/nodes.rs`）。

## 为什么是文件而不是 IPC

见 `docs/adr/ADR-0001-m2-daemon-shape.md`。简版：M2 的读者只有本机 CLI，
一个原子写的 JSON 文件就够；unix socket IPC 留到 M5（Web UI/Tauri 真正需要
双向通信时）一次做对。
