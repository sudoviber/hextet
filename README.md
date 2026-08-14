# hextet

**English** | [简体中文](README.zh-CN.md)

An IPv6-only peer-to-peer mesh VPN — no relay servers, no third-party infrastructure. Written in Rust.

> hextet: each colon-separated 16-bit group of an IPv6 address.

- Design doc: docs/superpowers/specs/2026-08-06-hextet-design.md
- Protocol specs: docs/protocol/
- Build guide: docs/dev/build.md
- Quickstart (two Linux hosts with public IPv6, connected directly): docs/guides/quickstart.md
- Joining a network with an invite token: docs/guides/joining.md

Status: M3 code complete — invite-based joining, LAN multicast discovery, self-hosted relay, in-tunnel gossip (endpoint referral + member/revocation, with optional `[node] admin_keys` authorization), and DHT/pkarr rendezvous are all implemented, along with cargo-fuzz targets. M4 (macOS + routers): site-to-site subnet routing, the OpenWrt feed (procd/uci + LuCI), the Linux systemd unit, the userspace WireGuard backend (gotatun + TUN abstraction + in-process handshake), the macOS platform networking layer, and the launchd unit are done; the macOS `hextet daemon` runtime is now wired up (compile-verified; the userspace backend is now gotatun 0.8.1 — boringtun removed, `set_peer_endpoint` is incremental via gotatun's `modify_peer`), with the userspace backend's real-TUN layer now runtime-verified in the `--privileged` Docker E2E container (`tests/userspace_backend_tun.rs` opens a real `/dev/net/tun` and drives apply/status/set_peer_endpoint/add_peer/remove_peer/down), while the macOS-specific `utun` naming/readback path now has a ready-to-run smoke test (`sudo cargo test -p hextet-wg-userspace --test userspace_backend_tun`) that still needs a real-utun/root run. M5 (UI): `status --tui` (ratatui), the axum embedded status server (`/healthz` + `/api/status` + optional `[node] web_dir` static hosting, wired into the daemon via `[node] http_addr`/`http_port`), the `web/` React frontend, and the `apps/desktop` Tauri 2 shell (webview + system tray) are done; the Tauri GUI render/tray/webview-fetch path still needs a human `cargo tauri dev` smoke test (a `.app`/`.dmg` bundle builds clean). `hextet hosts` (MagicDNS-lite: peer names → overlay IPv6 hosts lines) is also done, as is M6 slice C — self-hosted DDNS rendezvous (rendezvous chain ⑥): TXT records carrying an AEAD-encrypted payload derived from the network key, `[node] ddns*` / `[[peers]] ddns` config, `webhook` + `cloudflare` updaters wired into the daemon, now with a `[node] ddns_resolver` override and a `hextet ddns node` local mock (webhook HTTP + DNS TXT) so the whole publish→query→connect chain is E2E-verified in the netns suite (ADR-0010; see docs/protocol/ddns.md and docs/guides/ddns.md). Windows (M6 slice D): the platform networking layer (`list_global_ipv6`/`add_route`/`remove_route`/`setup_interface`/`list_multicast_interfaces`/`watch_ipv6_addresses` via the `windows` crate) and the TUN abstraction (the `tun` crate's wintun branch) are implemented and compile-verified (`x86_64-pc-windows-gnu` + a `check-windows` CI job); the data plane is now gotatun 0.8.1 (cross-platform, ADR-0012, MSRV 1.95), and the Windows wiring (`daemon`/`up`/`status`/`service` via `DaemonHandle::spawn` + `windows-service`, all compile-verified via `check-windows` CI) is done; what remains is `hextet down`/`delete_interface` (wintun adapter persistence — a design/FFI gap, ADR-0011). M7 (Android) — the Rust/FFI side is done and compile-verified: slice A UniFFI FFI (`hextet-engine-ffi`: `load_config`/`status`/`daemon_spawn`/`daemon_shutdown`/`daemon_spawn_with_fd`, state.json v7 with WG stats for cross-process status), slice C gotatun in-process data plane (`raw_fd::RawFdTun` fd transport + `UserspaceBackend::apply_with_fd`), and slice B's Rust glue (`daemon::spawn_with_fd`). Slice B's Kotlin `VpnService` shell (`apps/android/`: foreground VpnService + `MainActivity` + UniFFI/`org.json` wrapper, built via cargo-ndk → `jniLibs` + Gradle `uniffi-bindgen` Exec task) is now written — compile-check pending on a machine with Android SDK/NDK (this host has none). The first-run `join`/`init` bootstrap is now fully wired end-to-end (`hextet_core::bootstrap` shared by CLI and FFI; FFI `join(token, out_dir)`/`init(name, out_dir)`, compile-verified + unit-tested; Kotlin `HextetClient` + `MainActivity` first-run flow calls them — paste an invite token or create a new network); slice D's on-demand trigger + pure-IPv6 keepalive auto-relax (the keepalive grading first slice landed: `[node] keepalive`, default 25s, `0` = on-demand) remain. Unit/roundtrip tests and clippy pass on macOS and the Linux cross-target; nightly fuzz smoke passes locally (7 targets, zero panics); the Linux-only netns E2E scenarios (9 scripts: static/lan/dht/gossip/relay/site/dynamic/doctor/ddns) now pass end-to-end in a `--privileged` Docker container (`scripts/e2e-docker.sh`; the linuxkit kernel has wireguard built in) — see docs/dev/build.md. See docs/superpowers/plans/2026-08-12-m4-macos-and-routers.md and docs/superpowers/plans/2026-08-12-m5-ui.md.

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
