# hextet 快速上手（M1：静态直连）

状态：M1（内核 WireGuard 后端 + 静态 peer 配置，`hextet up/down/status`）。

适用场景：两台**都有公网 IPv6（GUA）** 的 Linux 主机，用静态配置直接互连。会合/打洞/roaming
留给 M2+；本指南只覆盖"双方地址都固定且已知"的最简单场景。

## 前提

- 双方都有可用的公网 IPv6 地址（`ip -6 addr` 能看到非 `fe80::`link-local、非 `fd00::/8`
  overlay ULA 的全局地址；参见下方「排查」）。
- **双方防火墙需放行 UDP 4193 入站**（hextet 默认监听端口），否则握手无法建立——当前版本
  没有防火墙打洞能力，双方都必须能被动接受入站 UDP，这是写进设计文档的诚实边界（见
  `docs/superpowers/specs/2026-08-06-hextet-design.md` §2「诚实的边界」）。这一限制会在
  M2（双向同时握手打洞）落地后放宽。
- 中国宽带的光猫/路由器很多默认开启 IPv6 SPI 防火墙，会拦截入站 UDP——多数机型管理界面里有
  「IPv6 SPI 防火墙」开关可手动关闭；后续版本会提供 `hextet doctor` 自动检测并给出机型化指引
  （M2 路线图项，本版本尚未实现）。
- 内核已加载 `wireguard` 模块，且以 root 运行（建接口/配置 WireGuard 需要 `CAP_NET_ADMIN`）。

## 步骤

下面用 A、B 两台机器示例，把 `<A的公网IPv6>`、`<B的公网IPv6>`、`<A的公钥>`、`<B的公钥>` 换成
真实值。

### 1. 两侧各自生成节点身份

```console
$ hextet keygen --out node.key
public-key: <本机公钥 base64>
key-file: node.key
```

A、B 都记下自己打印的 `public-key`，后面互填 `[[peers]]` 要用。

### 2. A 新建网络，B 用 `--network-key` 加入同一网络

> **更省事的做法**：A 跑一次 `hextet invite new`，B 跑 `hextet join <token>`，
> 步骤 2 与 3（B 侧）一次搞定，还免去手抄网络密钥与公钥的抄错风险。
> 见 [用 invite 把新节点加进网络](joining.md)。下面保留手工流程，便于理解每个字段的来处。


```console
# A：新建网络
$ hextet init --name home --key-file node.key
wrote hextet.toml
$ grep '^key = ' hextet.toml
key = "<网络密钥 base64，通过已有的加密渠道传给 B>"
```

```console
# B：加入 A 建的网络（网络密钥决定共同的 ULA /48 前缀，必须一致）
$ hextet init --name home --key-file node.key --network-key "<上一步的网络密钥>"
wrote hextet.toml
```

### 3. 互填 `[[peers]]`

用 `hextet peer add` 追加（会校验公钥、重名与 subnet 碰撞，并保留你写的注释）：

```console
# A 上执行
$ hextet peer add --name b --public-key '<B的公钥>' --endpoint '[<B的公网IPv6>]:4193'
# B 上执行
$ hextet peer add --name a --public-key '<A的公钥>' --endpoint '[<A的公网IPv6>]:4193'
```

等价的手写形式（了解字段结构用）：

```toml
# A 的 hextet.toml 追加（对端 B）
[[peers]]
name = "b"
public_key = "<B的公钥>"
endpoints = ["[<B的公网IPv6>]:4193"]
```

```toml
# B 的 hextet.toml 追加（对端 A）
[[peers]]
name = "a"
public_key = "<A的公钥>"
endpoints = ["[<A的公网IPv6>]:4193"]
```

### 4. 两侧拉起

```console
$ sudo hextet up -c hextet.toml
up: hextet0 <本机overlay地址> (1 peers)
```

### 5. 互 ping overlay 地址

```console
$ hextet inspect -c hextet.toml
network  home  prefix fdxx:xxxx:xx::/48
node     fdxx:xxxx:xx:aaaa:...  <本机公钥>
peer b           fdxx:xxxx:xx:bbbb:...  endpoints ["[<B的公网IPv6>]:4193"]

$ ping -6 -c 3 fdxx:xxxx:xx:bbbb:...
```

对端同样 ping 回本机的 overlay 地址即视为双向连通。

### 6. 查看连接状态

```console
$ hextet status -c hextet.toml
peer         address                      endpoint                          handshake       rx       tx  state
b            fdxx:xxxx:xx:bbbb:...        [<B的公网IPv6>]:4193                    12s     1234    1234  connected
```

`state` 按最近一次握手时间归类：180 秒内为 `connected`；超过为 `stale`；从未握手为
`no-handshake`（多为防火墙拦截或对端未拉起，见下）。

### 7. 拆除

```console
$ sudo hextet down -c hextet.toml
down: hextet0
```

## 让连接自己恢复（daemon）

`hextet up` 只配置一次内核就退出，地址一变就断。要让节点在换前缀后自动恢复，
用守护进程代替 `up`：

```console
# 前台跑（Ctrl-C 退出；-v 看详细日志）
$ sudo hextet daemon -c /etc/hextet/home.toml
2026-08-06T12:00:00Z  INFO daemon 启动 interface=hextet0 address=fd.. peers=1
2026-08-06T12:00:01Z  INFO 连接就绪（已记入端点缓存） peer=nas endpoint=[2408:...]:4193
```

daemon 做四件 `up` 不做的事：

1. 监听本机 IPv6 地址变化（PPPoE 重拨换前缀、RA 更新），变化后立刻向所有 peer
   重新握手——对端据此自动跟随（目标 <5s，见 `docs/protocol/punching.md`）；
2. 在多个候选 endpoint 之间轮换打洞（配置里的地址 + 上次连上的地址 + 会合层发现的地址）；
3. 把"上次能连上的 endpoint"写进 `<state_dir>/endpoints.json`，重启后优先重试它——
   即使配置里根本没写 endpoint 也能重连；
4. 在本地 LAN 上组播公告自己的地址、并监听同网节点的公告（见下一节）。

`hextet status` 会显示 daemon 是否在跑，以及每条连接当前 endpoint 的来源
（`config` / `lan` / `cache` / `roamed`）：

```console
$ sudo hextet status
daemon   running（状态更新于 1s 前）
peer         address                 endpoint              source  lan  punch      handshake   rx    tx  state
nas          fd12:34:56:abcd::2      [2408:...]:4193       config    1  connected        12s  1.2k  980  connected
```

daemon 退出**不会**拆除接口——拆除仍然是 `sudo hextet down`。状态文件与端点缓存
的位置与格式见 `docs/dev/state-files.md`。

## 同一 LAN 内：零配置互连

daemon 默认在本地链路上组播公告自己的公钥与 IPv6 地址（`ff02::4193`，UDP 4195），
并监听同网节点的公告。于是**同一 LAN 内的两台机器根本不需要填 endpoint**：

```console
# 两侧各自只需要知道对方的公钥
$ hextet peer add --name nas --public-key '<对方公钥>'
$ sudo hextet daemon -v -c hextet.toml
```

一个公告周期（5s）内双方就会互相发现并握手，`hextet status` 的 `source` 列显示
`lan`。这一路在**整个 LAN 一起换前缀**（家宽重拨）时格外有用——链路本地组播与公网
前缀无关，双方能立刻重新找到对方，不必等任何缓存或外部会合。

公告用网络密钥派生的密钥做 HMAC 认证：LAN 上的其他设备无法伪造成员的地址。
它不加密——同 LAN 的观察者能看出这里在用 hextet（标准 mDNS 方案同样如此）。
不需要就关掉：

```toml
[node]
lan_discovery = false
```

细节见 `docs/protocol/lan-discovery.md` 与 `docs/adr/ADR-0002-lan-beacon-instead-of-mdns.md`。

连不上时先跑 `hextet doctor`（需要对端配合，见 `docs/guides/doctor.md`）：它会告诉你
本机的入站策略是 `open` / `stateful` / `blocked` / `no-ipv6`——其中 `stateful` 是中国
家宽的常态且完全够用，`blocked` 与 `no-ipv6` 才需要动光猫设置。

## 排查

- **没有公网 IPv6**：`ip -6 addr` 检查有没有非 `fe80::`（link-local）、非 `fd00::/8`
  （hextet 自己的 overlay ULA）的全局地址；没有则需要向 ISP/路由器申请 IPv6 前缀委派（PD），
  或确认光猫/路由器已启用 IPv6。
- **一直是 `no-handshake`，怀疑防火墙丢包**：两侧同时跑
  `sudo tcpdump -i any udp port 4193`，互相 `hextet up` 或重新触发 ping 后观察——如果一侧能
  看到自己发出的包，但另一侧完全收不到，通常是对端防火墙/光猫丢弃了入站 UDP 4193，需要放行该
  端口或关闭光猫的 IPv6 SPI 防火墙。当前版本没有打洞能力，双方都必须能被动接受入站 UDP。
- **内核没有 `wireguard` 模块**：`sudo modprobe wireguard`；若报错模块不存在，说明内核未编译
  WireGuard 支持，需升级内核（Linux ≥5.6 默认内置）或安装发行版对应的
  `wireguard`/`wireguard-dkms` 包，`lsmod | grep wireguard` 确认已加载。

## 参考

- 设计文档：`docs/superpowers/specs/2026-08-06-hextet-design.md` §2（目标与非目标，含
  「诚实的边界」）、§8（功能路线图，M1 验收行）
- 地址派生规范：`docs/protocol/addressing.md`
- 入网（invite）：`docs/guides/joining.md`、`docs/protocol/invite.md`
- LAN 发现：`docs/protocol/lan-discovery.md`
- 构建与自动化 E2E：`docs/dev/build.md`
