# hextet 的 OpenWrt 打包层

这是 hextet 的 **OpenWrt feed**：把 `crates/cli` 的 `hextet` 二进制打包成 ipk/apk，
用 procd + uci 管理服务，并提供一个 LuCI 最小骨架。这是**打包层**，不新增任何 Rust
代码——数据面是内核 WireGuard（netlink 控制），服务由 `hextet daemon` 承担。

目录结构：

```
openwrt/
├── hextet/                       # 主包：二进制 + procd init + uci 默认值
│   ├── Makefile                  # 用 cargo 交叉编译 hextet 二进制
│   ├── Config.in                 # menuconfig 特性开关（可选）
│   └── files/
│       ├── hextet.init           # procd init 脚本
│       ├── hextet.conf           # uci 默认值（/etc/config/hextet）
│       └── hextet.toml.example   # 带注释的节点配置示例（占位值）
└── luci-app-hextet/              # LuCI 最小骨架（只读状态/概览）
    ├── Makefile
    ├── htdocs/luci-static/resources/view/hextet/status.js
    └── root/usr/share/{luci/menu.d,rpcd/acl.d}/luci-app-hextet.json
```

## 前提

- OpenWrt SDK / buildroot（主包需要 `rust` host 包做交叉编译；luci-app 是 `all` 架构，
  不需要 Rust）。
- 目标架构：aarch64 / armv7 / x86_64（MIPS 因 Rust Tier 3 明确不支持，见 spec §7）。
- 目标设备需要内核 WireGuard（`kmod-wireguard`）与一个全局 IPv6 地址（hextet 是
  IPv6-only，不支持 IPv4 endpoint/子网）。
- 作为 site-to-site 网关时需开 IPv6 转发（见下文「IPv6 转发」）。

## 1. 加入 feed

把本仓库的 `openwrt/` 目录 link 成一个 feed：

```console
$ cd openwrt-sdk   # 你的 OpenWrt 源码树 / SDK 根
$ echo "src-link hextet /path/to/hextet/openwrt" >> feeds.conf.default
$ ./scripts/feeds update hextet
$ ./scripts/feeds install -a   # 或只装 hextet / luci-app-hextet
```

> `hextet/Makefile` 里有两处 include 指向外部 feed：`rust-package.mk`
> （官方 packages feed 的 `lang/rust/`）与 `luci.mk`（luci feed）。默认按
> `./scripts/feeds install -a` 之后的常规布局写成 `$(TOPDIR)/feeds/packages/...`
> 与 `$(TOPDIR)/feeds/luci/luci.mk`；如果布局不同，改这两行（详见文件内注释）。

## 2. 选中并编译

```console
$ make menuconfig          # Network → VPN → hextet（以及 LuCI → Applications → luci-app-hextet）
$ make package/hextet/compile V=s
$ make package/luci-app-hextet/compile V=s
```

产物在 `bin/packages/<arch>/hextet/` 下（ipk[24.10] 或 apk[25.12+]，由 SDK 决定）。

## 3. 配置与启动

包装好后先填节点配置（示例是占位值，不含任何真实密钥）：

```console
$ cp /etc/hextet/hextet.toml.example /etc/hextet/hextet.toml
# 生成节点身份；网络密钥用 `hextet init`（新建网络）或 `hextet init --network-key ...`（加入）生成
$ hextet keygen --out /etc/hextet/node.key
$ vi /etc/hextet/hextet.toml     # 填 name/key/key_file，按需加 [[peers]]
```

再用 uci 打开服务：

```console
$ uci set hextet.hextet.enabled='1'
$ uci set hextet.hextet.config_file='/etc/hextet/hextet.toml'
$ uci commit hextet
$ /etc/init.d/hextet enable
$ /etc/init.d/hextet start
$ /etc/init.d/hextet status      # running / not running
$ logread -e hextet              # 看日志；verbose='1' 时是 DEBUG 级
```

改配置后让 daemon 生效（`procd_set_param file` 会在 hextet.toml 变化时自动重启，
这是兜底）：

```console
$ /etc/init.d/hextet reload
```

## IPv6-only + 内核 WG + 转发要求

- **IPv6-only**：endpoint 与子网路由都必须是 IPv6，配置里出现 IPv4 会在加载时报错。
- **内核 WireGuard**：数据面走 netlink 控制内核 `wireguard` 模块；确认
  `modprobe wireguard` 成功、`lsmod | grep wireguard` 有输出。
- **IP 转发**：当这台 OpenWrt 作 site-to-site 网关（通告它背后的子网）时，必须开
  IPv6 转发，否则隧道里的包到不了它背后的 LAN。hextet **不会**替你开转发：

  ```console
  $ sysctl -w net.ipv6.conf.all.forwarding=1
  ```

  要持久化就写进 `/etc/sysctl.d/`。具体 caveat 见
  [`docs/guides/site-to-site.md`](../docs/guides/site-to-site.md)。

## 诚实边界（本打包层的范围）

- **LuCI 只是最小骨架**：一个只读的「状态/概览」页（显示 enabled / config_file /
  verbose）+ rpcd ACL。它不驱动 daemon、也不编辑 hextet.toml；配置仍走 uci +
  手写 TOML。完整的嵌入式 Web UI 是 M5 的事（见 spec §8）。
- **未在真实 OpenWrt SDK 上构建过**（开发机是 macOS）。`Makefile` 里对
  `rust-package.mk` / `luci.mk` 的变量名与 include 路径是按惯例写的假设，需在
  Linux SDK 上首跑确认。主包依赖 `+kmod-wireguard +libc +libgcc +libssp`（数据面纯
  netlink、无 openssl/ring，见 Cargo.lock），若 SDK 报缺库再加。
- **firewall zone / RPF（sourcefilter）未在本层处理**：spec §7 规划了独立 firewall
  zone 与 `sourcefilter` 处理，属于后续交付，不在此最小骨架内。
