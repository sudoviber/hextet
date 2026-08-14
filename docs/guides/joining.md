# 用 invite 把新节点加进网络

适用于已有一个跑着 hextet 的节点（下称**引导节点**），现在要加进第二台机器
（下称**新节点**）。协议细节见 [docs/protocol/invite.md](../protocol/invite.md)。

三条命令，两台机器：

```
引导节点            hextet invite new  ───► token ───►  新节点   hextet join <token>
引导节点  hextet peer add ...  ◄─── join 打印出的命令 ◄───  新节点
```

## 1. 引导节点：签发 token

```console
$ hextet invite new --endpoint '[2001:db8:1::a]:4193'
hxi1.eyJ2IjoxLCJpZCI6...（一整行）
network   home
issuer    3fK...=
bootstrap bootstrap ["[2001:db8:1::a]:4193"]
expires   unix 1770086400（24h 后过期）

1) 这个 token 含**网络密钥**，等同于网络准入凭证：请走安全信道
   （密码管理器 / 端到端加密聊天）交给对方，不要贴进公开群或工单。
2) 对方执行 `hextet join <token>` 后会打印一条 `hextet peer add ...`；
   在本机执行它，双向接纳才算完成（WireGuard 需要双方都知道对方公钥）。
```

token 打在 **stdout**，其余信息打在 stderr——所以可以直接重定向：

```console
$ hextet invite new --endpoint '[2001:db8:1::a]:4193' > /tmp/token.txt
```

常用选项：

| 选项 | 说明 |
|---|---|
| `--endpoint '[v6]:port'` | 引导节点的公网 endpoint，可重复。**不给时**自动枚举本机公网 IPv6（Linux/macOS/Windows；枚举不到会明确报错让你手填） |
| `--ttl 30m` / `24h`（默认）/ `7d` | 有效期，上限 365d |
| `--name nas` | 新节点配置里这个 peer 叫什么（纯本地元数据，对方可以随便改） |
| `--json` | 机器可读输出 |

`--endpoint` 填什么？填**别的机器能连到你的那个地址**：

```console
$ ip -6 addr show scope global | grep inet6
```
取一个不是 `fd00::/8`（ULA）也不是 `fe80::/10`（链路本地）的地址，端口用配置里的
`listen_port`（默认 4193）。不确定入站能不能进来，先跑
[`hextet doctor`](doctor.md)。

## 2. 新节点：join

```console
$ hextet join 'hxi1.eyJ2IjoxLCJpZCI6...'
joined   home （prefix fd12:3456:78::/48）
node     fd12:3456:78:9abc::1  7Uk...=
config   hextet.toml
key-file node.key
peer     bootstrap    endpoints ["[2001:db8:1::a]:4193"]

还差一步：引导节点也要知道本节点的公钥（WireGuard 是双向认证的）。
在**引导节点**上执行：
  hextet peer add --name new-node --public-key '7Uk...=' --endpoint '[你的公网IPv6]:4193'
然后两侧 `hextet up`（或重启 `hextet daemon`）即可。
```

`join` 做了这些事，**顺序刻意如此**：验签 → 查过期 → 复用已有 `node.key`（没有就
新生成）→ 检查自己与引导节点的 subnet id 不冲突 → 才落盘。任何一步失败都不会在
磁盘上留下半个坏配置；配置写失败时连刚生成的密钥也会删掉。

常用选项：

| 选项 | 说明 |
|---|---|
| `--key-file node.key` | 已存在则**复用**（绝不覆盖你的密钥），不存在则生成 |
| `--out hextet.toml` | 配置输出路径；已存在则报错退出（不覆盖） |
| `--listen-port 4193` | 本机 WG 端口；缺省用 token 里的网络约定端口 |
| `--state-dir /var/lib/hextet` | daemon 的状态目录 |
| `--name laptop` | 打印出来的 `peer add` 命令里给自己起的名字 |
| `--json` | 机器可读输出（含 `peer_add_command`） |

配置与密钥都以 `0600` 落盘（`hextet.toml` 含网络密钥）。

## 3. 引导节点：接纳新节点

把上一步打印的命令在**引导节点**上执行，`[你的公网IPv6]` 换成新节点真实的地址
（新节点没有公网 IPv6、或者你懒得填也可以直接省掉 `--endpoint`——只要有一侧知道
对方地址就能打洞，或者交给 LAN 发现）：

```console
$ hextet peer add --name laptop --public-key '7Uk...=' --endpoint '[2001:db8:2::b]:4193'
added peer laptop fd12:3456:78:9abc::1
下一步：`hextet up` 应用配置，或重启 `hextet daemon` 让它接管这个 peer。
```

`peer add` 是**追加**到 `hextet.toml` 末尾的：你写在配置里的注释、字段顺序、自己加的
说明全部原样保留。以下情况会被拒绝且**配置文件一个字节都不改**：公钥已经是 peer、
名字重复、填的是自己的公钥、endpoint 是 IPv4、与既有节点 subnet id 碰撞。

## 4. 拉起并验证

两侧各自：

```console
$ sudo hextet up          # 或 sudo hextet daemon -v（要动态端点自愈就用这个）
$ hextet inspect          # 确认双方看到的对方 overlay 地址一致
$ ping -6 <对方 overlay 地址>
$ hextet status
```

## 常见问题

**「无法使用这个 invite token」**
token 在传输中被改动了。最常见的原因是聊天软件自动换行/加了不可见字符，或者复制时
漏了尾巴。让对方把原文重发一次（用文件或代码块，别用富文本）。

**「这个 invite token 已过期」**
默认 24h。让对方重新 `hextet invite new`（想久一点就 `--ttl 7d`）。

**`join` 说 `hextet.toml 已存在`**
它不会覆盖你的配置。换 `--out other.toml`，或先把旧配置移开。

**两边 `inspect` 显示的 /48 前缀不一样**
说明用的不是同一个 network key——几乎只可能是没用 token 而是手抄的。重新走 invite
流程即可。

**`up` 之后 ping 不通**
先看 `hextet status` 的 `state` 列。`no-handshake` 说明包没到对端：检查 endpoint
地址对不对、双方入站策略（跑 [`hextet doctor`](doctor.md)）、以及有没有跑
`hextet daemon`（静态 `up` 不会自动轮换候选地址打洞）。

## 为什么不是"一条命令入网"

WireGuard 要求双方都知道对方公钥。token 给了新节点关于引导节点的全部信息，但引导
节点此刻还不知道新节点的公钥，而现在还没有隧道内的 gossip 通道可以自动送过去
（M3 阶段 D 的工作）。所以第 3 步暂时需要人工执行一条命令——我们宁可如实说明，
也不想让你以为已经全自动了。
