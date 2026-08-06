# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### Added
- cargo workspace 骨架、CI（fmt/clippy/test/cargo-deny）、xtask（ci/e2e）。
- 节点身份（ed25519）与 WG x25519 密钥派生。
- ULA /48 前缀派生（HKDF）与节点地址派生（SHA-256），协议文档 docs/protocol/addressing.md。
- TOML 配置模型与校验（IPv6-only endpoint、subnet 碰撞检测）。
- CLI 命令：keygen（身份生成）、init（配置初始化）、inspect（前缀与地址查询）。
- hextet-wg：`WgBackend` trait（DeviceSpec/PeerSpec/PeerStatus）、Linux 内核后端（wireguard-control/netlink）、MockBackend。
- hextet-platform：`setup_interface`/`delete_interface`（Linux rtnetlink：地址/MTU/生命周期），非 Linux 平台返回 `Unsupported`。
- CLI 命令：up（建接口+配 WG peers+加地址+MTU+up）、down（删接口）、status（peer 连接状态，含 `--json`），M1 仅支持 Linux；`commands::load_config_and_identity` 公共加载逻辑（inspect 复用）。
- `scripts/netns-e2e.sh`：netns 双节点直连 E2E（veth 模拟公网 IPv6，keygen/init/up/ping/status/down 全链路），`cargo xtask e2e` 一键跑；CI 新增 `e2e` job（M1 验收）。
- 文档：`docs/guides/quickstart.md`（两台公网 IPv6 Linux 真机直连指南）、`docs/dev/e2e-matrix.md`（真机验收记录表）。
- 配置新增 `[node] probe_port`（默认 4194）与 `[node] state_dir`（默认 /var/lib/hextet）；`hextet init --state-dir`；配置+身份加载逻辑上移到 `hextet_core::config::load_config_and_identity`。
- `WgBackend::set_peer_endpoint`：只改单个 peer 的 endpoint 的增量更新（内核后端不使用 `replace_peers`，保留 AllowedIPs 与其他 peer）。
- hextet-platform：`list_global_ipv6`（枚举可用作公网 endpoint 的 IPv6 地址，过滤 ULA/deprecated/link-local）与 `watch_ipv6_addresses`（netlink RTNLGRP_IPV6_IFADDR 地址变化监听），非 Linux 平台返回 `Unsupported`。
