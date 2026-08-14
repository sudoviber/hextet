package org.hextet.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import uniffi.hextet_core_ffi.identityPublicKey
import uniffi.hextet_core_ffi.loadConfig
import uniffi.hextet_engine_ffi.backendSetTunFd
import uniffi.hextet_engine_ffi.createBackend
import uniffi.hextet_engine_ffi.spawnDaemon
import uniffi.hextet_engine_ffi.stopDaemon
import java.io.File

/**
 * The Android VpnService shell for hextet (M7 slice D).
 *
 * Design contract: `docs/adr/ADR-0014-android-daemon-and-engine-ffi.md`.
 *
 * Responsibilities:
 *  1. Build the tun via [VpnService.Builder] — and, per ADR-0014 **D1**, *own* the overlay
 *     address + `/48` route (the Rust daemon deliberately skips `setup_interface`/`add_route`
 *     on Android; the system VpnService manages them).
 *  2. Hand the tun fd to the Rust engine-ffi via JNI ([backendSetTunFd]) *before* the daemon
 *     runs `WgBackend::apply()` (ADR-0014 **D3/D4**: `create_backend` -> `set_tun_fd` ->
 *     `spawn_daemon`).
 *  3. Start the daemon ([spawnDaemon]) and stop it cleanly in [onDestroy] ([stopDaemon]).
 *  4. Run as a foreground service so Android keeps the tunnel alive in the background.
 *
 * The Rust `spawn_daemon` owns its own tokio runtime on a dedicated thread — this class does
 * NOT hold a runtime, and `stop_daemon` is non-blocking (ADR-0014 D3: `wait` is deliberately
 * not exposed across FFI).
 *
 * @see startTunnel for the fd-ownership reasoning (the `tun` crate takes the fd, no dup).
 */
class HextetVpnService : VpnService() {

    companion object {
        private const val TAG = "HextetVpnService"
        private const val CHANNEL_ID = "hextet-vpn"
        private const val NOTIFICATION_ID = 1

        /** `hextet.toml` path in app-private storage (required Intent extra). */
        const val EXTRA_CONFIG_PATH = "org.hextet.android.extra.CONFIG_PATH"

        /**
         * Optional node key (seed) file path. Defaults to `<configDir>/node.key`, matching the
         * desktop `hextet` convention where `[node] key_file` is resolved relative to the config.
         */
        const val EXTRA_KEY_PATH = "org.hextet.android.extra.KEY_PATH"

        /** Tunnel MTU; mirrors `crates/core/src/defaults.rs` `DEFAULT_MTU` (1400). */
        private const val TUNNEL_MTU = 1400

        /** Overlay network prefix length (a ULA /48). */
        private const val OVERLAY_PREFIX_LEN = 48
    }

    /** engine-ffi backend handle (`createBackend()`); null until the tunnel is up. */
    private var backendHandle: ULong? = null

    private var running = false

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        // Fail fast (loudly, but not fatally) if the native libs are missing from jniLibs.
        // The UniFFI bindings resolve the .so lazily via JNA; this surfaces a packaging
        // problem in logcat at service start instead of on the first FFI call.
        try {
            uniffi.hextet_core_ffi.uniffiEnsureInitialized()
            uniffi.hextet_engine_ffi.uniffiEnsureInitialized()
        } catch (e: UnsatisfiedLinkError) {
            Log.e(
                TAG,
                "native libs not packaged: libhextet_core_ffi.so / libhextet_engine_ffi.so " +
                    "missing from jniLibs (see apps/android/README.md)",
                e,
            )
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val configPath = intent?.getStringExtra(EXTRA_CONFIG_PATH)
        if (configPath.isNullOrBlank()) {
            Log.e(TAG, "EXTRA_CONFIG_PATH missing; refusing to start (nothing to tunnel)")
            stopSelf()
            return START_NOT_STICKY
        }
        if (running) {
            Log.w(TAG, "already running; ignoring duplicate start command")
            return START_NOT_STICKY
        }

        // `startForegroundService` requires startForeground() promptly (within ~5s).
        startForeground(NOTIFICATION_ID, buildNotification())

        try {
            startTunnel(configPath, intent.getStringExtra(EXTRA_KEY_PATH))
            running = true
        } catch (e: Exception) {
            Log.e(TAG, "tunnel start failed", e)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
        return START_NOT_STICKY
    }

    /**
     * Establish the tunnel and start the daemon. Ordering is ADR-0014 D3/D4:
     * `createBackend()` -> `establish()`+`detachFd()` -> `backendSetTunFd(handle, fd)` ->
     * `spawnDaemon(handle, configPath)`.
     */
    private fun startTunnel(configPath: String, keyPath: String?) {
        // 1. Derive the overlay /128 address + /48 prefix via hextet-core-ffi.
        //    ADR-0014 D1: the address/route is the Kotlin side's job (the daemon skips it).
        val overlay = resolveOverlay(configPath, keyPath)

        // 2. Build the tun. hextet is IPv6-only; the overlay is a ULA /48.
        val builder = Builder()
            .setSession("hextet")
            .setMtu(TUNNEL_MTU)
            .addAddress(overlay.address, 128)
            .addRoute(overlay.prefix, OVERLAY_PREFIX_LEN)

        // 3. establish() -> detachFd(). detachFd() transfers ownership of the raw fd out of
        //    the ParcelFileDescriptor and into Kotlin; the returned Int is the raw fd.
        val established = builder.establish()
            ?: throw IllegalStateException("VpnService.Builder.establish() returned null")
        val fd = established.detachFd()

        // 4. create_backend -> set_tun_fd (pre-inject the fd) -> spawn_daemon.
        val handle = createBackend()
        backendHandle = handle

        try {
            backendSetTunFd(handle, fd)
        } catch (e: Exception) {
            // set_tun_fd did NOT store the fd (the error was raised before storing), so the
            // Rust side does not own it — close it here to avoid an fd leak.
            runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
            throw e
        }

        // From this point the Rust side OWNS `fd`: `GotatunBackend::set_tun_fd` stores the raw
        // fd, and `apply()` hands it to `tun::Device::new(raw_fd)` which wraps it with
        // `close_fd_on_drop = true` (the tun crate does NOT dup — verified against
        // tun-0.8.14/src/platform/android/device.rs). Kotlin therefore must NOT close `fd`
        // afterward; the tun device closes it when the daemon tears down.
        //
        // `established` was emptied by detachFd(), so close() is a no-op — kept to mirror the
        // Mullvad pattern (the ParcelFileDescriptor wrapper is released after the handoff).
        established.close()

        spawnDaemon(handle, configPath)

        Log.i(
            TAG,
            "tunnel up: handle=$handle fd=$fd addr=${overlay.address} " +
                "prefix=${overlay.prefix}/$OVERLAY_PREFIX_LEN",
        )
    }

    /**
     * Resolve the overlay /128 address and /48 prefix from the on-disk config.
     *
     * Path (via `hextet-core-ffi`, which is packaged alongside `hextet-engine-ffi`):
     *   1. read the node key file (a single base64 line holding the 32-byte ed25519 seed,
     *      `NodeIdentity::save`'s format);
     *   2. `identityPublicKey(seed)` -> the node's ed25519 public key (base64);
     *   3. `loadConfig(config, ownPublicKey)` -> a validated `ConfigSummary` whose `.prefix`
     *      (`"fd..::/48"`) and `.nodeAddress` (`"fd..:...:..."`) are exactly what
     *      `VpnService.Builder.addRoute`/`addAddress` need.
     */
    private fun resolveOverlay(configPath: String, keyPath: String?): Overlay {
        val seedPath = keyPath ?: defaultKeyPath(configPath)
        val seed = File(seedPath).readText().trim()
        if (seed.isEmpty()) {
            throw IllegalStateException("node key file is empty: $seedPath")
        }
        val ownPublicKey = identityPublicKey(seed)
        val summary = loadConfig(configPath, ownPublicKey)
        // `summary.prefix` is `"<addr>::/48"`; addRoute wants the bare address + prefix length.
        val prefixAddr = summary.prefix.substringBefore('/')
        return Overlay(address = summary.nodeAddress, prefix = prefixAddr)
    }

    private fun defaultKeyPath(configPath: String): String {
        val dir = File(configPath).parentFile
        return if (dir != null) File(dir, "node.key").absolutePath else "node.key"
    }

    override fun onDestroy() {
        // ADR-0014 D3: unconditional stop_daemon in onDestroy (otherwise the backend instance
        // stays in the engine-ffi registry until the process exits — the known registry-leak
        // cost). stop_daemon is non-blocking and idempotent; the runtime thread it spawned
        // lives for the process lifetime by design (ADR-0014 D3).
        backendHandle?.let { handle ->
            runCatching { stopDaemon(handle) }
                .onFailure { Log.w(TAG, "stopDaemon failed", it) }
        }
        backendHandle = null
        running = false
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.description = getString(R.string.channel_desc)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val builder = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)

        // NOTE: no content intent — this slice ships no Activity to open. A full app should
        // set a launcher Activity here via setContentIntent(). Not set = notification is
        // informational only.
        return builder.build()
    }

    /** Overlay address + prefix handed to `VpnService.Builder`. */
    private data class Overlay(val address: String, val prefix: String)
}
