# hextet

**English** | [简体中文](README.zh-CN.md)

An IPv6-only peer-to-peer mesh VPN — no relay servers, no third-party infrastructure. Written in Rust.

> hextet: each colon-separated 16-bit group of an IPv6 address.

- Design doc: docs/superpowers/specs/2026-08-06-hextet-design.md
- Protocol specs: docs/protocol/
- Build guide: docs/dev/build.md
- Quickstart (two Linux hosts with public IPv6, connected directly): docs/guides/quickstart.md
- Joining a network with an invite token: docs/guides/joining.md

Status: M3 code complete — invite-based joining, LAN multicast discovery, self-hosted relay, in-tunnel gossip (endpoint referral + member/revocation), and DHT/pkarr rendezvous are all implemented, along with cargo-fuzz targets. M4 (macOS + routers): site-to-site subnet routing, the OpenWrt feed (procd/uci + LuCI), the Linux systemd unit, the userspace WireGuard backend (boringtun + TUN abstraction + in-process handshake), the macOS platform networking layer, and the launchd unit are done; the macOS `hextet daemon` runtime is now wired up (compile-verified; the boringtun `set_peer_endpoint` gap is closed via a remove+re-add fallback), with real-utun/root runtime verification still pending. M5 (UI): `status --tui` (ratatui), the axum embedded status server (`/healthz` + `/api/status` + optional `[node] web_dir` static hosting, wired into the daemon via `[node] http_addr`/`http_port`), the `web/` React frontend, and the `apps/desktop` Tauri 2 shell (webview + system tray) are done; the Tauri GUI render/tray/webview-fetch path still needs a human `cargo tauri dev` smoke test (a `.app`/`.dmg` bundle builds clean). `hextet hosts` (MagicDNS-lite: peer names → overlay IPv6 hosts lines) is also done. M6 slice C: self-hosted DDNS rendezvous (fallback chain layer ⑥) is implemented — a provider-agnostic `[ddns]` config (`update_url` template + `{address}` placeholder, token stays in the local gitignored `hextet.toml`), a `DdnsClient` in the discovery crate (HTTP update + AAAA lookup behind a mockable `DdnsTransport`), `Source::Ddns` in the candidate sources, and engine wiring mirroring the DHT layer (see docs/protocol/ddns.md and docs/guides/ddns.md). M6 slice D (Windows platform backend): the full `crates/platform` Windows backend (`windows.rs` — wintun TUN via the `tun` crate, `net-route` routing, `ipconfig` address enumeration, `netsh` zero-unsafe address assignment), the `hextet service install|uninstall|run` Windows service wrapper (`windows-service` crate), and `docs/adr/ADR-0010-windows-platform.md` are landed. All Windows code is `#[cfg(target_os = "windows")]`-gated: the macOS build/test/clippy stay green, and `cargo check -p hextet-platform --target x86_64-pc-windows-gnu` passes (type-check verified), but full codegen/link still needs a mingw/MSVC toolchain or the CI Windows runner — and the `hextet` binary can't fully build on Windows until `crates/engine`'s `platform_default()` gains a Windows branch (owned separately). Unit/roundtrip tests and clippy pass on macOS and the Linux cross-target; the Linux-only netns E2E scenarios are now verified in Docker (see docs/dev/netns-docker.md), and nightly fuzz smoke still awaits CI verification. M7 (Android, v1.0-required): the whole Rust-side Android stack is landed and compile-verified against `aarch64-linux-android` — `crates/core-ffi` (UniFFI 0.32 over hextet-core, ADR-0012), `daemon::spawn_on` + `DaemonHandle` (host-owned runtime + cancellation, ADR-0012/0014), the gotatun Android data plane in `crates/wg-userspace` (`GotatunBackend` with `set_tun_fd` + in-process UAPI bridge, ADR-0013), `crates/engine-ffi` (`create_backend`/`backend_set_tun_fd`/`spawn_daemon`/`stop_daemon`), the `apps/android/` VpnService shell (`HextetVpnService.kt` + Gradle project, `assembleDebug` green), and `[node] keepalive = 0` on-demand keepalive (ADR-0015). Honest boundaries: the Android `.so`/APK are compile-verified only (no emulator/device run), and `VpnService.protect()` for the WG UDP socket is not yet wired (needs a Rust-side `UdpTransportFactory` callback, ADR-0014). See docs/superpowers/plans/2026-08-12-m4-macos-and-routers.md, docs/superpowers/plans/2026-08-12-m5-ui.md, docs/superpowers/plans/2026-08-12-m6-windows-and-release.md and docs/superpowers/plans/2026-08-13-m7-android.md.

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
