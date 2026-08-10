# daemon 的磁盘状态文件

`hextet daemon` 在 `[node] state_dir`（默认 `/var/lib/hextet`）下维护两个 JSON 文件。
目录由 daemon 首次启动时创建（权限 0700），两个文件均为 0600、写入走
"临时文件 → fsync → rename" 的原子替换（`crates/engine/src/atomic.rs`）。

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
  "version": 2,
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
      "endpoint_source": "config",
      "lan_endpoints": 0,
      "candidates": 2,
      "candidate_index": 0,
      "rounds": 0
    }
  ]
}
```

- `punch_state`：`probing`（正在轮换候选打洞）或 `connected`（握手新鲜）。
- `endpoint_source`：`config` / `lan` / `cache` / `roamed` / `none`。判定顺序即此顺序：
  `lan` 表示这个地址来自 LAN 组播公告（见 `docs/protocol/lan-discovery.md`），
  `roamed` 表示既不在配置、也不在 LAN 公告、也不在缓存里——是内核根据已认证的包
  学到的（对端换了地址）。
- `lan_endpoints`：LAN 组播发现当前给出的 endpoint 数量。它记录的是**最近一次收到的
  公告内容**：对端 daemon 停掉后这个数字不会归零（内存里的 LAN 表会按 TTL 过期，
  但已经交给候选列表的地址会留着当兜底，语义与端点缓存一致）；daemon 重启即清空。
- `version`：2 起包含 `lan_endpoints` 与 `endpoint_source` 的 `lan` 取值。
  `hextet status` 只读同版本的文件，版本不认识时当作"没有 daemon 状态"。
- `updated_unix`：`hextet status` 用它判断 daemon 是否还活着（超过 10s 视为已停）。
- **纯派生数据**：删掉不会丢任何东西，daemon 下一秒就重写。

## 为什么是文件而不是 IPC

见 `docs/adr/ADR-0001-m2-daemon-shape.md`。简版：M2 的读者只有本机 CLI，
一个原子写的 JSON 文件就够；unix socket IPC 留到 M5（Web UI/Tauri 真正需要
双向通信时）一次做对。
