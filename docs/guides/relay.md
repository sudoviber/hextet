# 中继逃生舱：直连怎么都不成的时候

先说清楚三件事：

1. **中继是你自己的节点**，不是 hextet 项目方的服务器。这个项目没有任何在线基础设施。
2. **默认关闭**。不显式打开，谁也不会经过谁。
3. **中继看不到你的流量内容**。它转发的是已经用 WireGuard 加密好的包，
   没有任何一方的私钥。但它**能看到**"这两个地址之间有多少流量、什么时候有"——
   这就是为什么中继只能是你信任的机器。

什么时候需要它：双方入站都被彻底拦住，打洞打不通。典型是两端都在中国移动的蜂窝网络
（`hextet doctor` 两侧都报 `blocked`）。这时找一台常电、入站可达的机器（家里的路由器、
一直开着的 PC）当中继。

## 1. 中继侧：打开中继服务

在要当中继的节点上（下称 R），配置里加一行：

```toml
[node]
relay = true
# relay_port = 4196     # 控制端口，默认 4196
# relay_allow = []      # 只允许这些公钥用；空 = 本网络任何成员
```

重启 daemon 后日志里会有：

```
INFO 中继服务已启用（只转发加密的 WireGuard 包，不解密） port=4196 allow=0
```

R 需要能被两端**入站**访问（`hextet doctor` 报 `open` 或 `stateful` 都行）。
除了控制端口 4196，中继还会为每一对会话临时占用一个内核分配的高端口——
如果你在 R 上手工写了防火墙规则，记得放行到 R 的 UDP 入站，或至少放行
"已建立/相关"的连接（`stateful` 就够）。

想限制谁能用：

```toml
relay_allow = ["<A 的公钥>", "<B 的公钥>"]
```

## 2. 两端：声明这个 peer 可以当中继

A 与 B 各自在**指向 R 的那个 `[[peers]]` 块**里加 `relay = true`：

```toml
[[peers]]
name = "r"
public_key = "<R 的公钥>"
endpoints = ["[2001:db8:1f::c]:4193"]
relay = true
# relay_port = 4196    # 与 R 的 [node] relay_port 一致
```

`relay = true` 的 peer **必须有 endpoints**——中继地址未知等于没配，
配置加载时就会直接报错。

## 3. 它是怎么工作的

```
直连候选轮换 2 轮（≤40s）仍没有握手
        ↓
向 R 注册这一对会话，R 回带一个专属端口
        ↓
两端把对方的 WireGuard endpoint 设成 [R]:那个端口
        ↓
握手与数据都经 R 透传（仍是端到端加密）
        ↓
出现一个新的直连候选（LAN 公告 / 换了地址）→ 立刻试直连
        ↓
直连一成功 → 注销中继会话，回到 direct
```

每 30s 续期一次；R 上的会话 180s 不续期就自动关闭。

## 4. 怎么确认自己（没）在中继

```console
$ hextet status
daemon   running（状态更新于 1s 前）
peer         address                 endpoint                    source  lan  punch                handshake   rx    tx  state
b            fd12:34:56:abcd::2      [2001:db8:1f::c]:41234      relay     1  relayed via r              3s  4.1k  3.8k  connected
```

- `punch` 列显示 `relayed via r` → 这条连接经过 r。
- `source` 列显示 `relay` → 当前 endpoint 是中继分配的会话端口。
- `--json` 里对应 `punch_state: "relayed"`、`relay_via: "r"`、`endpoint_source: "relay"`。

直连时这两列分别是 `connected` 与 `config`/`lan`/`cache`/`roamed`。
**hextet 绝不会静默地把你降级到中继**：进入中继时日志里一定有一条说明原因的记录：

```
INFO 直连候选已轮换 2 轮仍无握手，尝试经中继连接 peer=b via=r rounds=2
INFO 中继会话就绪（数据仍是端到端加密，中继读不到内容） peer=b via=r endpoint=[2001:db8:1f::c]:41234
```

## 5. 诚实的边界

- **升级回直连是事件驱动的**：只在会合层送来一个**新的**直连候选（LAN 公告、
  M3-D 的 gossip 转介）或你重启 daemon 时才会去试。原因是内核 WireGuard 的每个 peer
  只有一个 endpoint，中继期间没法同时探测直连——想"边中继边探测"要等 M4 的用户态
  数据面。所以：**对端搬到了一个能直连的网络、而你这边毫无察觉时，不会自动升级**，
  重启 daemon 即可。细节见 `docs/adr/ADR-0003-relay-shape.md`。
- **带宽有上限**：每对会话每秒最多 2000 个包（≈22 Mbps）。中继跑在别人的机器上，
  必须有上限。
- **中继本身挂了**会怎样：两端在 180s 内退回打洞状态，`status` 如实显示 `probing`，
  不会假装还连着。
- **一台中继同时最多 256 对会话**。
- 中继**不做多跳**、不做路由收敛、不自动选中继节点（理由见 ADR-0003）。

## 参考

- 协议与安全性表格：`docs/protocol/relay.md`
- 设计决策：`docs/adr/ADR-0003-relay-shape.md`
- 入站可达性诊断：`docs/guides/doctor.md`
