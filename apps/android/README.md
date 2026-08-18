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

The SDK/NDK toolchain is now installed and the **build is verified end-to-end at
the compile level** (Rust cross-compile → UniFFI bindings → Kotlin compile →
APK). What remains unverified is **on-device runtime behaviour**, which needs a
real device/emulator with an IPv6-capable network. Status, stated precisely:

| Claim | Status |
|---|---|
| Rust FFI (`crates/engine-ffi`) — `load_config` / `status` / `daemon_spawn` / `daemon_shutdown` / `daemon_spawn_with_fd` | ✅ compile-verified on macOS **and** the three Android targets (`aarch64-linux-android` / `armv7-linux-androideabi` / `x86_64-linux-android` via cargo-ndk) |
| Kotlin bindings generation (`uniffi-bindgen generate --library ... --language kotlin`) | ✅ generated and verified (the `generateUniffiBindings` Gradle task runs it at build time) |
| This Gradle/Kotlin project | ✅ `./gradlew assembleDebug` passes — Kotlin compiles, APK assembles (`app-debug.apk`) |
| On-device VPN tunnel behaviour | ⬜ unverified; needs a real device/emulator (the Rust daemon runs in-process over the VpnService fd — that path is compile-verified but not runtime-tested) |

The build surfaced and fixed several real bugs on first compile: the `daemon`
module was desktop-gated (so `spawn_with_fd` was missing on Android),
`generateUniffiBindings` had the `--config` flag in the wrong order, `uniffi.toml`
used the pre-0.32 flat config format (silently ignored), and the manifest's
`android:foregroundServiceType="vpn"` is not a valid flag (the VPN type is
auto-assigned via the `FOREGROUND_SERVICE_VPN` permission + `android.net.VpnService`
intent filter). See the repo CHANGELOG.

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
  `crates/engine-ffi/Cargo.toml`). The `uniffi-bindgen` binary ships with the
  `uniffi` crate's `cli` feature (the `uniffi_bindgen` crate is library-only):
  ```console
  $ cargo install uniffi --version 0.32.0 --features cli
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
    generate \
    --config apps/android/uniffi.toml \
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
├── uniffi.toml                  [crates.hextet_engine_ffi.bindings.kotlin] android=true, package_name="uniffi.hextet"
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

**诚实边界**：SDK/NDK 工具链已装好，**编译级验证已端到端通过**（Rust 交叉编译 →
UniFFI 绑定 → Kotlin 编译 → APK）；仍缺的是**真机/模拟器运行时验证**（需要带 IPv6
网络的设备）。Rust FFI 已在 macOS 与三个 Android target 上编译验证；Kotlin 侧已通过
`./gradlew assembleDebug` 编译（首次编译修掉了几个真实 bug：daemon 模块被桌面门控、
`generateUniffiBindings` 的 `--config` 参数顺序错误、`uniffi.toml` 用了 0.32 之前的
旧格式被静默忽略、manifest 的 `foregroundServiceType="vpn"` 不是合法 flag——VPN 类型
由 `FOREGROUND_SERVICE_VPN` 权限 + `android.net.VpnService` intent-filter 自动赋予）。
真机/模拟器上的隧道行为仍待验证。

构建顺序（仓库根目录）：

```console
$ rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
$ cargo install cargo-ndk
$ cargo install uniffi --version 0.32.0 --features cli
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
