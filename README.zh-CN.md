# hextet

[English](README.md) | **简体中文**

IPv6-only、无服务器中转的 P2P 异地组网工具（mesh VPN），Rust 编写。

> hextet：IPv6 地址中每个冒号分隔的 16-bit 段。

- 设计文档：docs/superpowers/specs/2026-08-06-hextet-design.md
- 协议规范：docs/protocol/
- 构建指南：docs/dev/build.md
- 快速上手（两台公网 IPv6 Linux 直连）：docs/guides/quickstart.md
- 用 invite 入网：docs/guides/joining.md
- Android 只有一个 VPN 槽位（前瞻文档，VpnService 尚未实现）：docs/guides/android-vpn-slot.md

状态：M3 代码完成——invite 入网、LAN 组播发现、自有节点中继、隧道内 gossip（端点转介 + 成员/吊销，可选 `[node] admin_keys` 授权）、DHT/pkarr 会合均已实现，另含 cargo-fuzz 目标。M4（macOS + 路由器）：site-to-site 子网路由、OpenWrt feed（procd/uci + LuCI）、Linux systemd 单元、用户态 WireGuard 后端（gotatun + TUN 抽象 + 进程内握手）、macOS 平台网络层、launchd 单元均已完成；macOS `hextet daemon` 运行时已接线（编译验证；用户态后端已迁到 gotatun 0.8.1——boringtun 移除，`set_peer_endpoint` 走 gotatun 的 `modify_peer` 增量更新），用户态后端的真实 TUN 层已在 `--privileged` Docker E2E 容器里运行时验证（`tests/userspace_backend_tun.rs` 打开真实 `/dev/net/tun` 跑通 apply/status/set_peer_endpoint/add_peer/remove_peer/down）；macOS 特有的 `utun` 命名/读回路径已有 ready-to-run 冒烟测试（`sudo cargo test -p hextet-wg-userspace --test userspace_backend_tun`），仍需真实 utun/root 跑一次。M5（UI）：`status --tui`（ratatui，现已跨 Linux/macOS/Windows）、axum 内嵌状态服务器（`/healthz` + `/api/status` + 可选 `[node] web_dir` 静态托管，经 `[node] http_addr`/`http_port` 接入 daemon）、`web/` React 前端、`apps/desktop` Tauri 2 桌面壳（webview + 系统托盘）均已完成；Tauri 的 GUI 渲染/托盘交互/webview 内取数仍需人工 `cargo tauri dev` 冒烟（`.app`/`.dmg` 已能干净构建）。`hextet hosts`（MagicDNS-lite：peer 名 → overlay IPv6 hosts 行）已完成；M6 切片 C——自托管 DDNS 会合（会合兜底链 ⑥）也已完成：TXT 记录携带由网络密钥派生的 AEAD 加密载荷，`[node] ddns*` / `[[peers]] ddns` 配置，`webhook` + `cloudflare` 更新器接入 daemon，另有 `[node] ddns_resolver` 覆盖与 `hextet ddns node` 本地 mock（webhook HTTP + DNS TXT），使发布→查询→互连整条链路在 netns 套件里端到端验证（ADR-0010；见 docs/protocol/ddns.md 与 docs/guides/ddns.md）。Windows（M6 切片 D）：平台网络层（`list_global_ipv6`/`add_route`/`remove_route`/`setup_interface`/`list_multicast_interfaces`/`watch_ipv6_addresses`，经 `windows` crate）与 TUN 抽象（`tun` crate 的 wintun 分支）已实现并编译验证（`x86_64-pc-windows-gnu` + `check-windows` CI job）；数据面现为 gotatun 0.8.1（跨平台，ADR-0012，MSRV 1.95），Windows 接线（`daemon`/`up`/`status`/`service`，经 `DaemonHandle::spawn` + `windows-service`，均经 `check-windows` CI 编译验证）已完成；剩余 `hextet down`/`delete_interface`（wintun 适配器持久化——设计/FFI 缺口，ADR-0011）。M7（Android）——Rust/FFI 侧已做并编译验证：切片 A UniFFI FFI（`hextet-engine-ffi`：`load_config`/`status`/`daemon_spawn`/`daemon_shutdown`/`daemon_spawn_with_fd`，state.json v7 带 WG 统计支持跨进程 status）、切片 C gotatun 进程内数据面（`raw_fd::RawFdTun` fd 传输 + `UserspaceBackend::apply_with_fd`）、切片 B 的 Rust 接线（`daemon::spawn_with_fd`）；剩余 Kotlin `VpnService` 壳（需 Android SDK/设备）与切片 D 的按需触发 + 纯 IPv6 路径 keepalive 自动放宽（keepalive 分级第一片已落地：`[node] keepalive`，默认 25s，`0` = 按需连接）。单元/往返测试与 clippy 在 macOS 与 Linux 交叉 target 上通过；nightly fuzz smoke 本机通过（7 目标，零 panic）；Linux-only 的 netns E2E 场景（9 脚本：static/lan/dht/gossip/relay/site/dynamic/doctor/ddns）现已在 `--privileged` Docker 容器里端到端跑通（`scripts/e2e-docker.sh`；linuxkit 内核已内置 wireguard）——见 docs/dev/build.md。见 docs/superpowers/plans/2026-08-12-m4-macos-and-routers.md 与 docs/superpowers/plans/2026-08-12-m5-ui.md。

## 快速上手（M0：身份与地址）

```console
$ hextet keygen --out node.key
public-key: 3fK...=
$ hextet init --name home --key-file node.key
wrote hextet.toml
$ hextet inspect
network  home  prefix fdxx:xxxx:xx::/48
node     fdxx:xxxx:xx:ab12:...  3fK...=
```
