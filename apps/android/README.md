# hextet — Android app (`apps/android`)

Android VpnService shell for [hextet](https://github.com/hextet/hextet) — M7 slice D.

This project is the Kotlin side of the Android tunnel: a `VpnService` that (1) builds the tun
via `VpnService.Builder`, (2) hands the tun fd to the Rust engine via JNI, (3) starts the
daemon, and (4) tears it down in `onDestroy`. The heavy lifting (WireGuard handshake, hole
punching, rendezvous, HTTP status) lives in the Rust daemon behind the
`hextet-engine-ffi` UniFFI surface.

Design contract: [`docs/adr/ADR-0014-android-daemon-and-engine-ffi.md`](../../../docs/adr/ADR-0014-android-daemon-and-engine-ffi.md).

## Architecture (slice D)

```
apps/android (this project)
├── app/src/main/java/org/hextet/android/HextetVpnService.kt   ← VpnService shell
├── app/src/main/java/uniffi/hextet_engine_ffi/hextet_engine_ffi.kt  ← generated UniFFI bindings
├── app/src/main/java/uniffi/hextet_core_ffi/hextet_core_ffi.kt     ← generated UniFFI bindings
└── app/src/main/jniLibs/arm64-v8a/libhextet_{engine,core}_ffi.so   ← Rust cdylibs (gitignored)
```

Lifecycle (ADR-0014 D3/D4):

```
createBackend()                       engine-ffi: register a GotatunBackend, return u64 handle
VpnService.Builder.establish()        system returns the tun ParcelFileDescriptor
  .detachFd()                         transfer the raw fd to Kotlin
backendSetTunFd(handle, fd)           engine-ffi: store the fd in the backend's pending_fd
spawnDaemon(handle, configPath)       engine-ffi: spawn_with_backend on its own tokio runtime
  … daemon runs apply() → tun::Device::new(raw_fd) consumes the fd …
onDestroy() → stopDaemon(handle)      engine-ffi: non-blocking, idempotent shutdown signal
```

The address and `/48` route are configured **by Kotlin** (`Builder.addAddress(addr, 128)` +
`addRoute(prefix, 48)`) — the Rust daemon deliberately skips `setup_interface`/`add_route` on
Android (ADR-0014 D1). The values are derived from the on-disk config via `hextet-core-ffi`
(`identityPublicKey(seed)` → `loadConfig(config, ownPublicKey)` → `prefix` + `nodeAddress`).

## Prerequisites

| Tool | Version (verified) | Notes |
|------|--------------------|-------|
| JDK | 17 | AGP 8.7 requires JDK 17. Set `JAVA_HOME` (e.g. `/opt/homebrew/opt/openjdk@17`) |
| Android SDK | `platforms/android-34` (or later), `build-tools/36.0.0` | `sdk.dir` in `local.properties` |
| Gradle | 8.11.1 (wrapper) | the `./gradlew` wrapper downloads it |
| Rust | stable, with the Android target | `rustup target add aarch64-linux-android` |
| `uniffi-bindgen` | matching the `uniffi` crate version | see "regenerate bindings" |
| NDK | r26+ | needed to link the Rust cdylib for Android |

The build pins `compileSdk = 34` (AGP 8.7's well-tested target) and `buildToolsVersion = "36.0.0"`
(what the reference host has installed). If your SDK only has a different platform, bump
`compileSdk` in `app/build.gradle.kts` and accept AGP's "compileSdk newer than tested" warning.

## Build

The Rust side is built separately (its build is *not* driven by Gradle):

```console
# 1. Build the two cdylibs for Android (from the workspace root):
cargo build --target aarch64-linux-android -p hextet-core-ffi -p hextet-engine-ffi
#    → target/aarch64-linux-android/debug/libhextet_core_ffi.so
#    → target/aarch64-linux-android/debug/libhextet_engine_ffi.so

# 2. (Regenerate the Kotlin bindings only if the FFI surface changed — see below.)

# 3. Build the Android app:
cd apps/android
./gradlew :app:assembleDebug
```

The Gradle task `copyRustJniLibs` copies the two `.so` files from
`target/aarch64-linux-android/debug/` into `app/src/main/jniLibs/arm64-v8a/` before the build
(best-effort: if `target/` is absent it only warns and the `.so` files are simply not packaged).
The `.so` files are **gitignored build artifacts** — never committed.

`./gradlew :app:compileDebugKotlin` compiles the Kotlin (including the UniFFI bindings) without
needing the `.so` files present; the native lib is only resolved at runtime via JNA.

### Regenerating the UniFFI Kotlin bindings

The checked-in `app/src/main/java/uniffi/**/*.kt` files are generated from the Rust cdylibs
(library mode — the UniFFI metadata is embedded in the `.so`, no `.udl`):

```console
uniffi-bindgen generate \
    --library target/aarch64-linux-android/debug/libhextet_engine_ffi.so \
    --language kotlin \
    --out-dir app/src/main/java/uniffi/hextet_engine_ffi

uniffi-bindgen generate \
    --library target/aarch64-linux-android/debug/libhextet_core_ffi.so \
    --language kotlin \
    --out-dir app/src/main/java/uniffi/hextet_core_ffi
```

Do **not** hand-edit the generated files; they carry API checksums validated at runtime.

## Running on a device

There is no launcher Activity in this slice (out of scope). To exercise the service:

1. An Activity must first call `VpnService.prepare(context)` and handle the consent result.
2. On grant, start the service with the config path:

```kotlin
val intent = Intent(context, HextetVpnService::class.java)
    .putExtra(HextetVpnService.EXTRA_CONFIG_PATH, File(filesDir, "hextet.toml").absolutePath)
    .putExtra(HextetVpnService.EXTRA_KEY_PATH, File(filesDir, "node.key").absolutePath) // optional
context.startForegroundService(intent)
```

The app must have provisioned `hextet.toml` (with `[network]`, `[node] key_file`, `[[peers]]`)
and the node key file into app-private storage first. The node key file is the desktop
`NodeIdentity::save` format — a single base64 line holding the 32-byte ed25519 seed. (A real
app would store the seed in Keystore/EncryptedSharedPreferences, not plaintext — see
`crates/core-ffi/src/api.rs` `GeneratedIdentity`.)

## KNOWN GAPS (honest)

1. **`VpnService.protect()` for the WireGuard UDP socket is NOT wired up** — this is the big one.
   The Rust `spawn_daemon` uses `GotatunBackend`'s `with_default_udp()` (unprotected), and the
   current engine-ffi surface does not expose a protect hook. Without it, the WG handshake/transport
   UDP socket's egress traffic is routed back into the tunnel (or the socket is not excluded from
   the VPN), which loops or fails. **This needs a future Rust-side `UdpTransportFactory` that
   calls back into `VpnService.protect()`**, per ADR-0014 D4/D5. No protect path is fabricated
   here — see the TODO/comment in `HextetVpnService` and the ADR's "重新评估触发条件" (trigger 2).
2. **No emulator/device verification.** This project is compile-verified only
   (`./gradlew :app:assembleDebug`); the VpnService fd handoff and daemon startup have not been
   exercised on hardware. The Rust daemon is likewise `cargo check`-verified for the Android
   target, not run.
3. **Address/route derivation assumes `node.key` sits next to the config.** If `[node] key_file`
   points elsewhere, pass the real path via `EXTRA_KEY_PATH`. The derivation itself is real
   (`identityPublicKey` + `loadConfig`), not a TOML hand-parse.
4. **No launcher Activity / no consent flow.** Starting the service and requesting
   `POST_NOTIFICATIONS` is left to a future UI slice.
5. **`stop_daemon` is non-blocking and there is no `destroy_backend`.** If `spawnDaemon` fails
   after fd injection, the backend + fd stay in the registry until process exit (ADR-0014's
   acknowledged registry-leak cost). Normal `onDestroy` path is clean.

## Layout

```
apps/android/
├── settings.gradle.kts
├── build.gradle.kts
├── gradle.properties
├── gradle/wrapper/            (Gradle 8.11.1 wrapper)
├── gradlew / gradlew.bat
├── local.properties           (gitignored; sdk.dir)
├── README.md
└── app/
    ├── build.gradle.kts
    ├── proguard-rules.pro
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/org/hextet/android/HextetVpnService.kt
        ├── java/uniffi/**/hextet_{engine,core}_ffi.kt
        ├── jniLibs/arm64-v8a/  (gitignored .so)
        └── res/ (strings.xml, ic_vpn.xml)
```
