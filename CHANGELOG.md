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
- 新 crate `hextet-engine`（可嵌入引擎）：`build_device_spec` 由 hextet-cli 迁入；候选 endpoint 组装（last_good → 配置 → 缓存，去重，上限 8）与 endpoint 归一化。
- hextet-engine：每 peer 打洞/连接状态机（候选轮换 2.5s、握手新鲜度 180s、跟随对端 roaming、地址变化后立刻重试）。
- hextet-engine：端点缓存 `<state_dir>/endpoints.json`（原子写 0600、每 peer 最多 8 条历史、损坏时降级为空缓存）与通用 JSON 原子读写。
- hextet-engine：运行时状态快照 `<state_dir>/state.json`（每秒原子重写，含打洞状态与 endpoint 来源）；文档 docs/dev/state-files.md。
- hextet-engine：守护进程主循环（每秒 tick、候选轮换打洞、netlink 地址变化去抖后立刻重试、端点缓存与状态文件写入、SIGINT/SIGTERM 优雅退出，退出不拆接口）；协议文档 docs/protocol/punching.md。
- CLI 命令：`hextet daemon`（前台守护进程：地址变化监听 + 候选 endpoint 轮换打洞，`-v` 开 DEBUG 日志）。

### Changed
- `hextet status --json` 输出从「peer 数组」改为对象 `{ daemon, peers }`，并新增 `endpoint_source`/`punch_state`/`candidates`/`candidate_index` 四列（无 daemon 时为 null）。
