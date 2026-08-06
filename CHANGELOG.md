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
