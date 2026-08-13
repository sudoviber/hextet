# hextet

**English** | [简体中文](README.zh-CN.md)

An IPv6-only peer-to-peer mesh VPN — no relay servers, no third-party infrastructure. Written in Rust.

> hextet: each colon-separated 16-bit group of an IPv6 address.

- Design doc: docs/superpowers/specs/2026-08-06-hextet-design.md
- Protocol specs: docs/protocol/
- Build guide: docs/dev/build.md
- Quickstart (two Linux hosts with public IPv6, connected directly): docs/guides/quickstart.md
- Joining a network with an invite token: docs/guides/joining.md

Status: M3 code complete — invite-based joining, LAN multicast discovery, self-hosted relay, in-tunnel gossip (endpoint referral + member/revocation), and DHT/pkarr rendezvous are all implemented, along with cargo-fuzz targets. M4 (macOS + routers): site-to-site subnet routing, the OpenWrt feed (procd/uci + LuCI), the Linux systemd unit, the userspace WireGuard backend (boringtun + TUN abstraction + in-process handshake), the macOS platform networking layer, and the launchd unit are done; the macOS `hextet daemon` runtime is now wired up (compile-verified; the boringtun `set_peer_endpoint` gap is closed via a remove+re-add fallback), with real-utun/root runtime verification still pending. M5 (UI): `status --tui` (ratatui), the axum embedded status server (`/healthz` + `/api/status` + optional `[node] web_dir` static hosting, wired into the daemon via `[node] http_addr`/`http_port`), the `web/` React frontend, and the `apps/desktop` Tauri 2 shell (webview + system tray) are done; the Tauri GUI render/tray/webview-fetch path still needs a human `cargo tauri dev` smoke test (a `.app`/`.dmg` bundle builds clean). `hextet hosts` (MagicDNS-lite: peer names → overlay IPv6 hosts lines) is also done. Unit/roundtrip tests and clippy pass on macOS and the Linux cross-target; the Linux-only netns E2E scenarios and nightly fuzz smoke still await CI verification. See docs/superpowers/plans/2026-08-12-m4-macos-and-routers.md and docs/superpowers/plans/2026-08-12-m5-ui.md.

## Quickstart (M0: identity and addressing)

```console
$ hextet keygen --out node.key
public-key: 3fK...=
$ hextet init --name home --key-file node.key
wrote hextet.toml
$ hextet inspect
network  home  prefix fdxx:xxxx:xx::/48
node     fdxx:xxxx:xx:ab12:...  3fK...=
```
