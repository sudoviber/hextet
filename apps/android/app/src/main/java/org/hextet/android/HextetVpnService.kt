package org.hextet.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.File

/**
 * Foreground [VpnService] shell — M7 slice B.
 *
 * 1. Establishes the Android VPN tunnel via [Builder] (which returns a raw fd
 *    owned by the system).
 * 2. Transfers that fd to the in-process Rust daemon via
 *    `uniffi.hextet.daemonSpawnWithFd` (using [ParcelFileDescriptor.detachFd]).
 * 3. Shuts the daemon down cleanly in [onDestroy]/[onRevoke].
 *
 * Config is expected to already exist at [configPath] (`filesDir/hextet.toml`,
 * with `node.key` beside it) — importing/joining over FFI is a follow-up slice.
 */
class HextetVpnService : VpnService() {

    companion object {
        private const val CHANNEL_ID = "hextet-vpn"
        private const val NOTIFICATION_ID = 1
        private const val MTU = 1280

        const val ACTION_START = "org.hextet.android.action.START"
        const val ACTION_STOP = "org.hextet.android.action.STOP"
        const val ACTION_STATE = "org.hextet.android.action.STATE_CHANGED"
        const val EXTRA_ERROR = "org.hextet.android.extra.ERROR"

        /** Absolute path to the app-private `hextet.toml`. */
        fun configPath(context: Context): String =
            File(context.filesDir, "hextet.toml").absolutePath
    }

    private var daemonHandle: ULong? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }

        val cfg = File(configPath(this))
        if (!cfg.exists()) {
            fail(getString(R.string.err_config_missing))
            return START_NOT_STICKY
        }

        // Foreground notification must appear promptly after startForegroundService().
        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.notif_starting)))

        val pfd = establishTunnel()
        if (pfd == null) {
            fail(getString(R.string.err_establish))
            return START_NOT_STICKY
        }

        // detachFd() transfers ownership of the raw fd to Rust (RawFdTun borrows
        // it and does not close it). Do NOT close `pfd` after detaching.
        val rawFd = pfd.detachFd()

        val handle = HextetClient.spawn(configPath(this), rawFd, MTU.toUShort())
        if (handle == null) {
            fail(getString(R.string.err_spawn))
            return START_NOT_STICKY
        }
        daemonHandle = handle

        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(getString(R.string.notif_connected)))
        return START_STICKY
    }

    override fun onDestroy() {
        daemonHandle?.let { handle ->
            daemonHandle = null
            HextetClient.shutdown(handle)
        }
        super.onDestroy()
    }

    override fun onRevoke() {
        // User revoked VPN permission from Settings — tear the daemon down.
        daemonHandle?.let { handle ->
            daemonHandle = null
            HextetClient.shutdown(handle)
        }
        stopSelf()
    }

    /** Error path: visible notification (best-effort) + broadcast + stop, no crash. */
    private fun fail(message: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID + 1, buildNotification(message))
        sendBroadcast(
            Intent(ACTION_STATE).setPackage(packageName).putExtra(EXTRA_ERROR, message)
        )
        stopSelf()
    }

    /** Establishes the tunnel and returns the owned ParcelFileDescriptor, or null. */
    private fun establishTunnel(): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("hextet")
            .setMtu(MTU)

        // Add the node's overlay address (from config). If config can't be parsed
        // here, fall back to a placeholder — the Rust side still configures the
        // real address on the fd from `hextet.toml`.
        val nodeAddr = runCatching {
            HextetClient.loadConfig(configPath(this)).optString("node_address")
        }.getOrNull().orEmpty()
        builder.addAddress(if (nodeAddr.isNotEmpty()) nodeAddr else "fd00::2", 128)

        // Route everything (::/0); the Rust side only forwards IPv6 into the mesh.
        builder.addRoute("::", 0)

        // DNS: the mesh has no resolver yet (MagicDNS-lite is a follow-up); placeholder.
        builder.addDnsServer("fd00::1")

        return try {
            builder.establish()
        } catch (e: Exception) {
            null
        }
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel),
                NotificationManager.IMPORTANCE_LOW
            )
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, HextetVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(contentIntent)
            .addAction(0, getString(R.string.notif_stop), stopIntent)
            .setOngoing(true)
            .build()
    }
}
