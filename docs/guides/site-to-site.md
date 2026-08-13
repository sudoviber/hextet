# 子网路由（site-to-site）：让 peer 背后的子网可达

hextet 默认只路由每个节点的 overlay 地址（`fdxx::/48` 里属于它的 /64）。子网路由
把它扩展成 **site-to-site**：一个节点可以声明「某几个 IPv6 子网在我的背后可达
（例如我家的 LAN）」，别的节点连上它之后，发往这些前缀的流量就会送进 WireGuard
隧道、由它对端转交。典型用途是把异地的两台路由器连起来，让两侧的局域网互相访问。

> **hextet 是 IPv6-only 的**：通告的子网必须是 IPv6 CIDR（`2001:db8:abcd::/64`）。
> 不支持 IPv4 子网——带 IPv4 后缀的路由会在配置加载时被拒绝。

## 它到底做了什么

- **AllowedIPs**：对端（设它为 `B`）通告 `2001:db8:abcd::/64` 后，A 的 WireGuard
  peer 表里 B 的 AllowedIPs 就变成「B 自己的 /64 site」+「`2001:db8:abcd::/64`」。
  内核据此把发往该前缀的包交给 B。
- **OS 路由**：A 的 daemon 在连上 B 之后，往 `hextet0` 加一条
  `ip -6 route add 2001:db8:abcd::/64 dev hextet0`；B 断开/退出时移除，避免黑洞。

## 前提

- **网关节点（通告子网的那台）必须开 IPv6 转发**，否则隧道里的包到不了它背后的
  LAN，也回不来：

  ```console
  $ sysctl -w net.ipv6.conf.all.forwarding=1
  # 只对具体接口开也行：sysctl -w net.ipv6.conf.<lan接口>.forwarding=1
  ```

  要持久化就写进 `/etc/sysctl.d/`。**hextet 不会替你开转发**——它只负责把包送进/
  送出隧道，转发与否是操作系统的事。
- 通告的子网必须**真实存在于网关节点背后**（它得有接口在这个子网里，或有一条到
  它的路由），否则对端路由过去是黑洞。
- 子网不能与网络自己的 overlay 前缀冲突：不能落在网络的 /48 里（那是别的节点的
  site），也不能落在**本节点自己的 /64 site** 里，两个 peer 通告的子网也不能互相
  重叠——这些都会在配置加载时报错。

## 1. 想访问对端子网的节点：声明 peer 的通告路由

`routes` 写在**想访问对端子网**的那台机器（A）上、指向**提供子网**的对端（B）的那个
`[[peers]]` 块里——语义是「这个 peer（B）在这些前缀背后可达，请把发往它们的流量送进
隧道交给 B」：

```toml
[[peers]]
name = "b"
public_key = "<B 的公钥>"
routes = ["2001:db8:abcd::/64", "2001:db8:beef::/64"]
```

或者用命令行：

```console
$ hextet peer add --name b --public-key <B 的公钥> --route '2001:db8:abcd::/64'
```

`--route` 可重复，一次声明多个子网。静态配置下「B 通告」体现在这里：A 的配置里写明了
B 通告哪些子网，连上 B 后 A 就把这些前缀的流量送进隧道。

## 2. 对端（提供子网的 B）：开 IPv6 转发

B 这边**配置里不需要写 `routes`**（它自己就是这些子网的拥有者，不用「向自己」声明）。
B 要做的是确保隧道里的包能继续转发到它背后的 LAN：

```console
$ sysctl -w net.ipv6.conf.all.forwarding=1
```

## 3. 确认生效

```console
$ hextet status
peer   address              endpoint               source  lan  punch       handshake  rx  tx  routes
b      fd12:3456:78:abcd::2  [2001:db8::b]:4193     config    0  connected         3s  1k  2k  2001:db8:abcd::/64
```

- `routes` 列列出当前已装进路由表的子网路由。
- `hextet status --json` 里是 `peers[].routes` 字符串数组。
- 也可以在系统层确认：`ip -6 route show dev hextet0` 应该能看到那条路由。

## 诚实的边界

- **路由只在连上时存在**：daemon 在 peer 打洞中/断连时会清掉它装的那些路由，
  重新连上后自动恢复——这是为了防止在没连上时把流量送进黑洞。
- **不替代防火墙**：把子网通告出去等于把它的可达性交给这个 peer。请自行在网关
  节点上用防火墙限制哪些地址能穿过隧道访问该子网。
- **只支持 IPv6 子网**（见上）。

## 参考

- 设计决策：`docs/adr/ADR-0006-site-to-site-subnet-routing.md`
- 地址派生：`docs/protocol/addressing.md`（节点 /64 site 的来历）
