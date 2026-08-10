# hextet

[English](README.md) | **简体中文**

IPv6-only、无服务器中转的 P2P 异地组网工具（mesh VPN），Rust 编写。

> hextet：IPv6 地址中每个冒号分隔的 16-bit 段。

- 设计文档：docs/superpowers/specs/2026-08-06-hextet-design.md
- 协议规范：docs/protocol/
- 构建指南：docs/dev/build.md
- 快速上手（两台公网 IPv6 Linux 直连）：docs/guides/quickstart.md
- 用 invite 入网：docs/guides/joining.md

状态：M2 完成（动态端点自愈 + doctor）。M3 进行中：invite 入网与 LAN 组播发现已完成；中继、gossip、DHT 会合待做——见 docs/superpowers/plans/2026-08-11-m3-rendezvous-and-relay.md。

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
