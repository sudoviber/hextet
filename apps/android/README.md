# hextet — Android client (M7 slice B: VpnService shell)

**English** | [简体中文](#简体中文)

An Android client shell for [hextet](../../README.md) — an IPv6-only peer-to-peer
mesh VPN. This directory is a complete, build-ready (once an Android SDK is
present) Gradle + Kotlin project implementing the M7 slice B `VpnService` shell:

- `HextetVpnService` — a foreground `VpnService` that establishes the Android
  VPN tunnel, hands the raw fd to the in-process Rust daemon via the UniFFI FFI
  (`daemonSpawnWithFd`), and shuts the daemon down cleanly on destroy.
- `MainActivity` — a minimal launcher that requests `POST_NOTIFICATIONS`, calls
  `VpnService.prepare(...)`, runs the first-run join/init bootstrap (invite
  token OR create a new network), and exposes start/stop + status display.
- `HextetClient` — a thin wrapper over the generated `uniffi.hextet` bindings
  (JSON in/out, parsed with `org.json`).

The Rust side (`crates/engine-ffi`, a `cdylib` named `libhextet_engine_ffi.so`)
is **done and compile-verified**, including the `join`/`init` bootstrap FFI.
This project is Kotlin-only — it does **not** add any Rust code.

---

## Honest boundary (read first)

This machine (macOS) has **no Android SDK/NDK**, so **nothing in this directory
has been compiled or run here**. Status, stated precisely:

| Claim | Status |
|---|---|
| Rust FFI (`crates/engine-ffi`) — `load_config` / `status` / `daemon_spawn` / `daemon_shutdown` / `daemon_spawn_with_fd` | ✅ compile-verified on macOS (the exact API surface the Kotlin calls) |
| Kotlin bindings generation (`uniffi-bindgen generate --library ... --language kotlin`) | ⬜ generated and verified **on the operator's machine**; the generated API surface is what this code was written against |
| This Gradle/Kotlin project | ⬜ written to be correct; **compile-check is pending on a machine with Android SDK/NDK** |
| On-device VPN tunnel behaviour | ⬜ unverified; needs a real device/emulator |

**This README never claims the Kotlin compiles or that any Android build
"passes" or is "verified".** Everything is authored against the verified FFI
surface and Android API 26–35 semantics, and must be compiled on an SDK machine
before it can be trusted.

---

## Prerequisites

- **Rust** with Android cross-compile targets:
  ```console
  $ rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  ```
- **cargo-ndk**:
  ```console
  $ cargo install cargo-ndk
  ```
- **uniffi-bindgen** (≥ 0.32, matching the `uniffi = "0.32"` pin in
  `crates/engine-ffi/Cargo.toml`):
  ```console
  $ cargo install uniffi_bindgen --version 0.32.0
  ```
- **Android SDK** with platform 35, **NDK**, and **JDK 17** (Android Studio
  bundles all of these).
- An **Android device/emulator** with an IPv6-capable network (the mesh is
  IPv6-only).

---

## Build pipeline

The bindings are generated at build time by a Gradle `Exec` task that shells out
to `uniffi-bindgen` (the canonical approach — **no third-party UniFFI Gradle
plugin**). Because the `--library` mode reads metadata from the built cdylib,
the native `.so` must exist **before** Gradle runs.

From the repo root, in order:

```console
# 1. Build the cdylib for the three ABIs into the app's jniLibs dir.
$ cargo ndk \
    -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o apps/android/app/src/main/jniLibs \
    build --release -p hextet-engine-ffi

# 2. Build the APK (preBuild → generateUniffiBindings → Kotlin/Java compile).
$ cd apps/android && ./gradlew assembleDebug
```

Step 2's `generateUniffiBindings` task runs:

```console
$ uniffi-bindgen \
    --config apps/android/uniffi.toml \
    generate \
    --library apps/android/app/src/main/jniLibs/arm64-v8a/libhextet_engine_ffi.so \
    --language kotlin \
    --out-dir apps/android/app/build/generated/source/uniffi/java
```

(You can run that command manually if you prefer to inspect the bindings; the
generated `hextet.kt` is **not** committed — it is regenerated on every build.)

To open in Android Studio instead of the CLI: open `apps/android/` directly.
On first sync, Android Studio may offer to generate the Gradle wrapper
(`gradlew` + `gradle-wrapper.jar`); accept it (or run `gradle wrapper` once on an
SDK machine). The wrapper *properties* are committed; the wrapper *jar/scripts*
are intentionally not (binary).

---

## Config bootstrap — honest boundary

`daemon_spawn_with_fd(config_path, tun_fd, mtu)` loads config via
`hextet_core::config::load_config_and_identity(config_path)`, which reads a
`hextet.toml` **and** an identity file `node.key`. The config's `key_file`
field is resolved **relative to the config file's directory** (not the process
cwd), so the app places both files in the same app-private dir and passes the
absolute path to `hextet.toml`.

First run no longer requires a pre-placed config. The Rust FFI now exposes two
bootstrap functions — `join(token, out_dir)` (decodes+validates an invite token
and writes `hextet.toml` + `node.key` into `out_dir`, refusing to overwrite an
existing config) and `init(name, out_dir)` (generates a brand-new network and
its `node.key`/`hextet.toml`). `MainActivity` wires both: when
`filesDir/hextet.toml` is absent it shows an invite-token field plus "Join
network" / "Create new network" buttons, runs the FFI call on a background
thread (crypto + file IO), and marshals the result back to the UI thread
(`runOnUiThread`) to show the node address or the error message. `HextetClient`
exposes them as `join(token, outDir)` / `init(name, outDir)` returning an
`org.json.JSONObject` (serde snake_case), throwing `HextetFfiException` on an
`{"error":...}` payload. After success the existing `startVpn()` path (which
checks the config file exists) is unchanged.

Pre-placing a config at `context.filesDir/hextet.toml` (with `node.key` beside
it) remains as a **fallback** for out-of-band imports. On a desktop machine you
can generate these with:

```console
$ hextet keygen --out node.key
$ hextet join <invite-token> --out hextet.toml     # or: hextet init --name <net> ...
```

then push `hextet.toml` + `node.key` to the device via `adb push` into the
app's files dir (e.g. `/data/data/org.hextet.android/files/`, reachable with
`adb push` + `run-as org.hextet.android`).

> **Honest boundary unchanged:** this Kotlin wiring is authored against the
> verified `join`/`init` FFI surface and has **not** been compiled or run here
> (no Android SDK/NDK on this machine). `MainActivity`/`HextetVpnService` still
> refuse to start (with a visible error state) if `hextet.toml` is absent.

---

## VpnService single-slot caveat

Android allows only **one** active VPN at a time. If another VPN app (Tailscale,
Mullvad, a corporate MDM VPN, …) holds the slot, `Builder.establish()` returns
`null` and `HextetVpnService` stops with a visible error notification — the same
behaviour and caveat as Tailscale. No VPN can share the slot.

Also note: the mesh is **IPv6-only** — the tunnel routes `::/0` and the Rust
side only forwards IPv6 traffic. The placeholder DNS server (`fd00::1`) is a
stub; mesh DNS (MagicDNS-lite) is a follow-up slice.

---

## Layout

```
apps/android/
├── settings.gradle.kts          pluginManagement + dependencyResolutionManagement; include(":app")
├── build.gradle.kts             AGP + Kotlin plugin versions
├── gradle.properties            AndroidX / Kotlin style / JVM args
├── gradle/wrapper/              gradle-wrapper.properties (wrapper jar/scripts generated on an SDK machine)
├── uniffi.toml                  [bindings.kotlin] android=true, package_name="uniffi.hextet"
├── .gitignore                   local ignores (build/, jniLibs/, local.properties, …)
├── README.md                    this file
└── app/
    ├── build.gradle.kts         app module: Android + Kotlin, sourceSets, generateUniffiBindings, JNA dep
    └── src/main/
        ├── AndroidManifest.xml  VPN/foreground-service permissions + service/activity declarations
        ├── java/org/hextet/android/
        │   ├── HextetApplication.kt   System.loadLibrary("hextet_engine_ffi")
        │   ├── HextetVpnService.kt    the VpnService shell
        │   ├── MainActivity.kt        prepare() + first-run join/init + start/stop + status
        │   └── HextetClient.kt        UniFFI + org.json wrapper
        └── res/                 strings / themes / colors / layout / vector icons (no binary assets)
```

---

## 简体中文

这是 hextet（纯 IPv6 点对点 mesh VPN）的 Android 客户端壳（M7 切片 B：VpnService 壳）。

**诚实边界**：本机（macOS）没有 Android SDK/NDK，本目录**未在本机编译或运行**。
Rust FFI（`crates/engine-ffi`）已编译验证；Kotlin 侧是「按已验证的 FFI 接口与
Android API 26–35 语义写成、待有 SDK 的机器编译验证」。本 README 与项目从不声称
Kotlin 编译通过、构建「pass」或「已验证」。

构建顺序（仓库根目录）：

```console
$ rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
$ cargo install cargo-ndk uniffi_bindgen
$ cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
    -o apps/android/app/src/main/jniLibs build --release -p hextet-engine-ffi
$ cd apps/android && ./gradlew assembleDebug
```

配置引导：`hextet join`/`init` 走 FFI 已落地——Rust 侧新增 `join(token, out_dir)`
（解码并校验邀请令牌，写入 `hextet.toml` + `node.key`，已存在时拒绝覆盖）与
`init(name, out_dir)`（生成全新网络及其 `node.key`/`hextet.toml`）。`MainActivity`
在 `filesDir/hextet.toml` 缺失时显示邀请令牌输入框与「加入网络 / 创建新网络」按钮，
在后台线程执行 FFI（加密 + 文件 IO），再 `runOnUiThread` 回主线程显示节点地址或错误；
`HextetClient` 暴露 `join(token, outDir)` / `init(name, outDir)`，返回
`org.json.JSONObject`（serde snake_case），错误时抛 `HextetFfiException`；成功后现有
`startVpn()` 路径不变。预先放置 `hextet.toml` 与 `node.key` 仍作为**备选**（带外导入）
保留；`key_file` 相对配置文件目录解析。诚实边界不变：本目录未在本机编译或运行，Kotlin
侧按已验证的 FFI 接口写成、待有 SDK 的机器验证。VPN 单一槽位：与其他 VPN 类 App
（Tailscale 等）互斥，`establish()` 返回 null 时以可见错误通知退出，不崩溃。
