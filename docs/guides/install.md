# 在 Linux 上安装并以 systemd 服务运行 hextet

hextet 是 IPv6-only 的无服务器 mesh VPN，数据面走内核 WireGuard（netlink 控制）。
本指南把 `hextet` 装成 Linux 上的 systemd 服务：二进制放 `/usr/sbin/hextet`，
配置放 `/etc/hextet/hextet.toml`，状态目录 `/var/lib/hextet`——与 OpenWrt 的
procd 打包（见 [openwrt](openwrt.md)）用同一套路径，这样同一份配置在两种环境里
含义一致。

> **诚实边界先说清楚**：本仓库的开发机是 macOS，**不能运行 systemd 单元**，下面的
> 单元文件没有在 Linux 上用 `systemd-analyze verify` 校验过；其中的硬化参数（
> `ProtectSystem` / `ProtectHome` / `PrivateTmp`）是按 daemon 的读写需求做的最小保守
> 选择，首次在 Linux 上部署时请先 `systemctl daemon-reload` 再 `systemctl status
> hextet` 确认能正常起来。本指南主要面向 **Linux + systemd**；macOS 上另有一份
> launchd 服务单元，见下方「macOS：launchd 服务」一节——macOS daemon 的运行接线已完成
> （编译验证，数据面 gotatun 的 `modify_peer` 已闭合 `set_peer_endpoint` 缺口），真实
> utun/root 运行时冒烟待真机，那一节里如实标注。

如果你还没用过 hextet，先看 [quickstart](quickstart.md) 认识「生成身份 → 建网络 →
加 peer → up/down」的基本流程，本指南默认你已经会填配置。

## 前提

- 机器有**全局 IPv6 地址**（hextet 是 IPv6-only，endpoint 与子网路由都不接受 IPv4）。
- 内核有 WireGuard：`modprobe wireguard` 成功、`lsmod | grep wireguard` 有输出
  （Linux ≥ 5.6 默认内置）。
- 以 root 运行（建接口/配 WireGuard 需要 `CAP_NET_ADMIN`；systemd 单元默认就是 root）。
- 作 site-to-site 网关时要开 IPv6 转发（见最后「IP 转发」）。

## 1. 装二进制到 `/usr/sbin/hextet`

在仓库根目录构建，再把 `crates/cli` 产出的 `hextet` 装到 `/usr/sbin`：

```console
$ cargo build --release --locked
$ sudo install -m 0755 target/release/hextet /usr/sbin/hextet
$ hextet --help
```

## 2. 放配置与节点密钥到 `/etc/hextet`（0600）

```console
$ sudo install -d -m 0755 /etc/hextet
$ sudo install -d -m 0755 /var/lib/hextet     # state_dir，daemon 启动时也会自建
```

生成节点身份密钥（`hextet keygen` 打印公钥，写到 0600 的密钥文件）：

```console
$ sudo hextet keygen --out /etc/hextet/node.key
public-key: <本机公钥 base64>
key-file: /etc/hextet/node.key
$ sudo chmod 0600 /etc/hextet/node.key
```

然后放一份 0600 的 `hextet.toml`（可用 `hextet init` 生成再落位，或手写）：

```console
$ sudo hextet init --name home --key-file /etc/hextet/node.key \
    --state-dir /var/lib/hextet
$ sudo install -m 0600 hextet.toml /etc/hextet/hextet.toml
```

最小配置形如（密钥只在配置文件里，用占位符表示，勿手写真实 base64）：

```toml
[network]
name = "home"
key = "<你的网络密钥>"        # 32 字节 base64；hextet init 生成，勿手写

[node]
key_file = "node.key"
listen_port = 4193
state_dir = "/var/lib/hextet"
```

网络密钥与 peer 怎么来、`hextet peer add` 怎么用，见 [quickstart](quickstart.md)
和 [joining](joining.md)。**配置与密钥文件都要 `chmod 0600`**——里面是网络密钥与
节点私钥。

## 3. 装 systemd 单元并开机自启

把仓库里的单元装到 systemd，然后重载、启用并启动：

```console
$ sudo install -m 0644 packaging/systemd/hextet.service /etc/systemd/system/hextet.service
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now hextet
$ systemctl status hextet
```

单元做的事：`/usr/sbin/hextet daemon -c /etc/hextet/hextet.toml` 前台常驻，
`Restart=on-failure` + `RestartSec=5` 只对崩溃/非零退出重启（优雅退出不重启），
以 root 运行并带 `NoNewPrivileges` 与最小文件系统硬化。要 DEBUG 日志，把单元里的
`ExecStart` 换成带 `-v` 的那行（单元文件里已注释好）。

## 4. 看日志

```console
$ journalctl -u hextet -f          # 跟日志
$ journalctl -u hextet -b          # 本次启动以来的日志
$ systemctl status hextet          # 最近几行 + 运行状态
```

连接层面的实时状态用 `hextet status`（它会显示 daemon 是否在跑、每条连接的
endpoint 来源与握手新鲜度），与日志互补。

## 5. daemon / up / down 三者关系

- **`hextet daemon -c ...`（常驻，systemd 跑的就是它）**：前台守护进程。除了 `up`
  的建接口+配 peer，它还监听本机 IPv6 地址变化（换前缀后立刻重新握手）、在候选
  endpoint 之间轮换打洞、把「上次能连上的 endpoint」写进 `<state_dir>/endpoints.json`、
  做 LAN 组播发现/中继/gossip/DHT 会合。
- **`hextet up -c ...`（一次性）**：只配置一次内核 WireGuard 就退出，地址一变就断。
  适合临时/手动调试，不适合长驻。
- **`hextet down -c ...`（拆除）**：删接口。**daemon 收到 SIGTERM 优雅退出时不会拆
  接口**——`systemctl stop hextet` 只是停掉进程，接口仍在；要真正拆掉再手动
  `sudo hextet down -c /etc/hextet/hextet.toml`。

## 6. IPv6-only 与 IP 转发

hextet 只认 IPv6：endpoint、子网路由都必须是 IPv6，带 IPv4 的配置会在加载时报错。
作 site-to-site 网关（通告自己背后子网给对端）的那台必须**自己开 IPv6 转发**——
hextet 只把包送进/送出隧道，不会替你开：

```console
$ sudo sysctl -w net.ipv6.conf.all.forwarding=1
```

持久化写进 `/etc/sysctl.d/`。完整 caveat（通告子网必须真实存在于网关背后、不能与
overlay 前缀/自身 site 冲突、路由只在连上时存在等）见 [site-to-site](site-to-site.md)。

## macOS：launchd 服务（打包就绪，运行时编译验证、真机冒烟待做）

> **诚实边界先说清楚**：macOS 上 `hextet daemon`（打洞循环 / 动态 endpoint 自愈）的
> 运行接线**已完成并编译验证**——数据面已从 boringtun 0.7.1 迁到 gotatun 0.8.1
> （ADR-0012），`set_peer_endpoint` 经 gotatun 的 `modify_peer` 增量更新（收敛了
> boringtun「remove + 完整 re-add」缺口）。**仍未做的是真实 utun/root 运行时冒烟**
> （本机 macOS 无 root/真实 utun，`sudo cargo test -p hextet-wg-userspace --test
> userspace_backend_tun` 是 ready-to-run 的冒烟入口）。见
> [ADR-0007](../adr/ADR-0007-gotatun-userspace-backend.md)、
> [ADR-0009](../adr/ADR-0009-macos-device-orchestration.md) 与
> [ADR-0012](../adr/ADR-0012-msrv-1.95-gotatun.md)。因此下面的 launchd 单元是
> **打包就绪 + 编译验证，不是真机冒烟通过**：装上能拉起 daemon，但真实 utun/root 的
> 点对点打洞仍需在 macOS 真机/CI 跑一次。
>
> 同样，macOS 上 one-shot `hextet up` 也不能让设备常驻——utun 归 gotatun 后端所有，
> 进程一退出、句柄释放，utun 立即消失（ADR-0009 决策 5）。macOS 设备随持有它的进程存在；
> 常驻请用 `hextet daemon`（launchd 托管）。相应地，one-shot `hextet down` 也触达不到
> 另一个长驻进程持有的 utun（它会如实报错并让你去停掉持有它的 daemon），真正的 `down`
> 只对长驻进程有意义。这是用户态数据面的固有语义，不是 bug。

### 路径约定（与 Linux 不同）

macOS 不用 `/etc/hextet` + `/var/lib/hextet`（那是 Linux/OpenWrt 的惯例），改用：

| 用途 | macOS 路径 |
|---|---|
| 二进制 | `/usr/local/sbin/hextet` |
| 配置 | `/usr/local/etc/hextet/hextet.toml`（节点密钥 `node.key` 同目录，0600） |
| 状态目录（`[node] state_dir`） | `/Library/Application Support/hextet` |
| 日志 | `/var/log/hextet.log`（stdout）与 `/var/log/hextet.err.log`（stderr） |

选 `/usr/local/etc/hextet` 是因为它是 macOS 本地直装（不经 Homebrew/App Store）配置的
惯例位置，对应 Linux 的 `/etc/hextet`；状态目录用 `/Library/Application Support/hextet`
而非 Linux 的 `/var/lib/hextet`，因为 `/var/lib` 是 Linux 包管理器的惯例、macOS 不这么用。

### 安装与启动

装二进制与配置（0600 要求与 Linux 章节一致）：

```console
$ cargo build --release --locked
$ sudo install -d -m 0755 /usr/local/sbin /usr/local/etc/hextet
$ sudo install -d -m 0755 '/Library/Application Support/hextet'
$ sudo install -m 0755 target/release/hextet /usr/local/sbin/hextet
$ sudo install -m 0600 hextet.toml /usr/local/etc/hextet/hextet.toml
```

> 上面的 `hextet.toml` 里 `[node] state_dir` 要填 `/Library/Application Support/hextet`
> （macOS 路径约定），别沿用 Linux 的 `/var/lib/hextet`。

装 launchd 单元并启动（现代 launchd 用 `bootstrap`/`bootout`，`load`/`unload` 已废弃）：

```console
$ sudo install -m 0644 packaging/launchd/com.hextet.daemon.plist /Library/LaunchDaemons/com.hextet.daemon.plist
$ sudo launchctl bootstrap system /Library/LaunchDaemons/com.hextet.daemon.plist
$ launchctl print system/com.hextet.daemon     # 看状态
```

卸载：

```console
$ sudo launchctl bootout system/com.hextet.daemon
$ sudo rm /Library/LaunchDaemons/com.hextet.daemon.plist
```

### 与 systemd 的语义差异（诚实说明）

- **`KeepAlive=true` ≠ `Restart=on-failure`**：launchd 的 `KeepAlive=true` 会**无条件**
  重启，包括 daemon 收到 SIGTERM 优雅退出（exit 0）之后也重启。所以 `launchctl kill
  SIGTERM system/com.hextet.daemon` 停不掉它，停用要用 `bootout`。若要严格对齐 systemd
  的 `Restart=on-failure`（只在崩溃 / 非零退出时重启），把 plist 里的 `KeepAlive` 改成
  `<dict><key>SuccessfulExit</key><false/></dict>`。
- **`-v` 日志**：daemon 用 tracing，日志级别由 CLI 的 `-v`（DEBUG）/ 默认 INFO 决定，
  **不读 `RUST_LOG`**（所以 plist 里没设 `EnvironmentVariables`）。要 DEBUG 日志就在
  plist 的 `ProgramArguments` 里加 `-v`。
- **日志去哪**：tracing 默认写 stderr，所以主要看 `/var/log/hextet.err.log`。

实时连接状态仍用 `hextet status`（只读，读状态文件），与日志互补。

## 参考

- 快速上手与排查：`docs/guides/quickstart.md`
- 入网（invite/join）：`docs/guides/joining.md`、`docs/protocol/invite.md`
- 查看连接状态与 HTTP 状态服务（`--tui` / `/healthz` / `/api/status`）：`docs/guides/status.md`
- 按名访问（MagicDNS-lite）：`docs/guides/hosts.md`
- 站点间子网路由：`docs/guides/site-to-site.md`
- OpenWrt 打包（同路径约定的 procd 版本）：`docs/guides/openwrt.md`
- 配置字段全览：`crates/core/src/config.rs`
- 状态文件格式：`docs/dev/state-files.md`
