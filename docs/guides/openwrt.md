# 在 OpenWrt 路由器上跑 hextet

hextet 是 IPv6-only 的无服务器 mesh VPN。在 OpenWrt 上它打包成 feed 包，数据面走
**内核 WireGuard**（netlink 控制），服务由 **procd + uci** 管理，UI 是 **LuCI**（目前
是最小骨架）。本指南假设你已在某台 Linux 机器上用过 hextet（否则先看
[quickstart](quickstart.md) 认识基本流程）。

> **诚实边界先说清楚**：下面描述的是**打包层**——把一个 Linux 二进制用 procd/uci
> 管起来。它不是新实现，数据面就是内核 WireGuard；LuCI 目前只是只读的「状态/概览」
> 页，不驱动 daemon、也不编辑配置；完整的内嵌 Web UI 是 M5 的事（见设计 spec §8）。
> 这个 feed 也**还没在真实 OpenWrt SDK 上构建过**（开发机是 macOS），首次在 Linux
> SDK 上跑要按 [openwrt/README.md](../openwrt/README.md) 的说明核对两个 include 路径。

## 能做什么、不能做什么

- **能**：在 OpenWrt 设备（aarch64 / armv7 / x86_64）上装 hextet，用 uci 开关服务，
  让 `hextet daemon` 常驻，自动在换前缀后恢复连接、LAN 内组播发现、中继逃生舱、
  站点间子网路由（site-to-site）——这些能力都在 Linux 二进制里，路由器照单全收。
- **不能（目前）**：LuCI 只能看服务是否启用、配置文件路径、日志级别；不能点几下就把
  peer 加好。配置仍是「写 `hextet.toml` + 几条 uci 命令」。
- **MIPS 不支持**：Rust 在 MIPS 上是 Tier 3，这个 feed 明确不提供（见 spec §7）。

## 前提

- 设备有**全局 IPv6 地址**（hextet 是 IPv6-only，endpoint 与子网路由都不接受 IPv4）。
- 内核有 WireGuard：`modprobe wireguard` 成功、`lsmod | grep wireguard` 有输出。
- 以 root 运行（建接口/配 WireGuard 需要 `CAP_NET_ADMIN`；procd 默认就是 root）。
- 作 site-to-site 网关时要开 IPv6 转发（见最后「IP 转发」）。

## 1. 安装 feed 与包

把仓库的 `openwrt/` 目录 link 成 feed 并安装：

```console
$ echo "src-link hextet /path/to/hextet/openwrt" >> feeds.conf.default
$ ./scripts/feeds update hextet
$ ./scripts/feeds install hextet luci-app-hextet
$ make menuconfig          # Network → VPN → hextet；LuCI → Applications → luci-app-hextet
$ make package/hextet/compile V=s
```

`hextet/Makefile` 用 `cargo build --release --locked` 在构建主机上交叉编译
`crates/cli` 的 `hextet` 二进制（需要 OpenWrt 的 `rust` host 包），安装时把二进制
放到 `/usr/sbin/hextet`、init 脚本到 `/etc/init.d/hextet`、uci 默认值到
`/etc/config/hextet`、示例配置到 `/etc/hextet/hextet.toml.example`。

## 2. 填节点配置

先复制示例、生成身份、填密钥（示例与默认值里都只有占位符，没有任何真实密钥）：

```console
$ cp /etc/hextet/hextet.toml.example /etc/hextet/hextet.toml
$ hextet keygen --out /etc/hextet/node.key
$ vi /etc/hextet/hextet.toml
```

最小的 `hextet.toml`：

```toml
[network]
name = "home"
key = "<你的网络密钥>"        # 32 字节 base64；hextet init 生成，勿手写

[node]
key_file = "node.key"
listen_port = 4193
state_dir = "/var/lib/hextet"
```

网络密钥怎么来：在这台路由器上 `hextet init --name home --key-file
/etc/hextet/node.key` 新建网络，或已有网络就用 `hextet init --network-key "<已有
网络密钥>"` 加入。加 peer 用 `hextet peer add`（见 [joining](joining.md)）。

## 3. 用 uci 开关服务

```console
$ uci set hextet.hextet.enabled='1'
$ uci set hextet.hextet.config_file='/etc/hextet/hextet.toml'
$ uci set hextet.hextet.verbose='1'     # 可选：DEBUG 日志
$ uci commit hextet
$ /etc/init.d/hextet enable
$ /etc/init.d/hextet start
$ /etc/init.d/hextet status             # running / not running
$ logread -e hextet
```

uci 里只有三样东西：`enabled`（0/1，默认关）、`config_file`（hextet.toml 路径）、
`verbose`（0/1）。init 脚本把它们翻译成 `hextet daemon -c <config_file> [-v]`，
`procd_set_param file` 让 hextet.toml 一变 procd 就自动重启 daemon。改配置后手动兜底：

```console
$ /etc/init.d/hextet reload
```

## 4. 验证

```console
$ hextet inspect -c /etc/hextet/hextet.toml
$ hextet status -c /etc/hextet/hextet.toml
$ ping -6 <对端 overlay 地址>
```

连接自愈、LAN 发现、中继、doctor 的用法与 Linux 上完全一致，见
[quickstart](quickstart.md)、[relay](relay.md)、[doctor](doctor.md)。

## 站点间子网路由（site-to-site）

路由器最典型的作用是当 site 网关：它背后的 LAN 设备不用装客户端，靠它在成员记录里
宣告的 overlay ULA /64 就能被全网访问（详见 [site-to-site](site-to-site.md)）。路由器
这边要在对端的 `[[peers]]` 块里声明对端通告的子网：

```toml
[[peers]]
name = "对端路由器"
public_key = "<对端公钥>"
routes = ["2001:db8:abcd::/64"]
```

而**这台**路由器若通告自己背后的子网，对端要加 `routes`；同时这台必须开 IPv6 转发。

## IP 转发（作网关时必开）

hextet 只负责把包送进/送出隧道，**不会替你开转发**。作 site-to-site 网关的那台必须：

```console
$ sysctl -w net.ipv6.conf.all.forwarding=1
```

持久化写进 `/etc/sysctl.d/`。不开转发的后果是隧道里的包到不了它背后的 LAN。完整
caveat（通告子网必须真实存在于网关背后、不能与 overlay 前缀/自身 site 冲突、路由只在
连上时存在等）见 [site-to-site](site-to-site.md)。

## 与透明代理共存

hextet 不接管 DNS（见 spec §5）、路由只加自己的 ULA 前缀，与 OpenClash/mihomo 的
fake-IP 分流互不干扰。firewall zone / RPF（`sourcefilter`）的自动化处理属于后续交付，
当前这个最小骨架没有做，需要的话先在设备上手工放行 UDP 4193 入站并确认内核转发路径。

## 参考

- 打包层说明：`openwrt/README.md`（feed 布局、include 路径假设、未验证项）
- 设计 spec：`docs/superpowers/specs/2026-08-06-hextet-design.md` §7（路由器组网）、
  §8（M4 交付）、§9（平台矩阵）、§10（`openwrt/` 目录）
- 站点间路由：`docs/guides/site-to-site.md`、`docs/adr/ADR-0006-site-to-site-subnet-routing.md`
- 配置字段全览：`crates/core/src/config.rs`
