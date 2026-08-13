# hextet

[English](README.md) | **简体中文**

IPv6-only、无服务器中转的 P2P 异地组网工具（mesh VPN），Rust 编写。

> hextet：IPv6 地址中每个冒号分隔的 16-bit 段。

- 设计文档：docs/superpowers/specs/2026-08-06-hextet-design.md
- 协议规范：docs/protocol/
- 构建指南：docs/dev/build.md
- 快速上手（两台公网 IPv6 Linux 直连）：docs/guides/quickstart.md
- 用 invite 入网：docs/guides/joining.md

状态：M3 代码完成——invite 入网、LAN 组播发现、自有节点中继、隧道内 gossip（端点转介 + 成员/吊销）、DHT/pkarr 会合均已实现，另含 cargo-fuzz 目标。M4（macOS + 路由器）：site-to-site 子网路由、OpenWrt feed（procd/uci + LuCI）、Linux systemd 单元、用户态 WireGuard 后端（boringtun + TUN 抽象 + 进程内握手）、macOS 平台网络层、launchd 单元均已完成；macOS `hextet daemon` 运行时仍待 `daemon.rs` 的 macOS 接线（boringtun `set_peer_endpoint` 缺口已由 remove+re-add 回退补上）。M5（UI）：`status --tui`（ratatui）与 axum 内嵌状态服务器（`/healthz` + `/api/status`，经 `[node] http_addr`/`http_port` 接入 daemon）已完成；Tauri 壳 + React 前端待做（需 Node/Tauri 工具链）。`hextet hosts`（MagicDNS-lite：peer 名 → overlay IPv6 hosts 行）也已完成。单元/往返测试与 clippy 在 macOS 与 Linux 交叉 target 上通过；Linux-only 的 netns E2E 与 nightly fuzz smoke 仍待 CI 验证。见 docs/superpowers/plans/2026-08-12-m4-macos-and-routers.md 与 docs/superpowers/plans/2026-08-12-m5-ui.md。

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
