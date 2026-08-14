package org.hextet.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import java.io.File

/**
 * Minimal launcher screen (M7 slice B shell — no heavy UI).
 *
 * - Requests `POST_NOTIFICATIONS` (API 33+).
 * - Calls [VpnService.prepare] and launches the returned consent intent.
 * - Starts/stops [HextetVpnService] (start/stop buttons).
 * - Shows the node's overlay address via the FFI `loadConfig`.
 */
class MainActivity : Activity() {

    companion object {
        private const val REQUEST_VPN = 1
        private const val REQUEST_NOTIF = 2
    }

    private lateinit var statusText: TextView
    private lateinit var tokenInput: EditText
    private lateinit var joinButton: Button
    private lateinit var initButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.status_text)
        tokenInput = findViewById(R.id.token_input)
        joinButton = findViewById(R.id.btn_join)
        initButton = findViewById(R.id.btn_init)
        findViewById<Button>(R.id.btn_start).setOnClickListener { startVpn() }
        findViewById<Button>(R.id.btn_stop).setOnClickListener { stopVpn() }
        findViewById<Button>(R.id.btn_status).setOnClickListener { refreshStatus() }
        joinButton.setOnClickListener { joinNetwork() }
        initButton.setOnClickListener { initNetwork() }

        requestNotificationPermissionIfNeeded()
        updateFirstRunVisibility()
    }

    override fun onResume() {
        super.onResume()
        updateFirstRunVisibility()
        refreshStatus()
    }

    private fun updateFirstRunVisibility() {
        val configured = File(filesDir, "hextet.toml").exists()
        val visibility = if (configured) View.GONE else View.VISIBLE
        tokenInput.visibility = visibility
        joinButton.visibility = visibility
        initButton.visibility = visibility
    }

    private fun joinNetwork() {
        val token = tokenInput.text.toString().trim()
        Thread {
            val result = runCatching {
                HextetClient.join(token, filesDir.absolutePath)
            }
            runOnUiThread {
                result
                    .onSuccess { outcome ->
                        statusText.text = getString(
                            R.string.join_ok,
                            outcome.optString("network_name", "?"),
                            outcome.optString("node_address", "?"),
                        )
                        updateFirstRunVisibility()
                    }
                    .onFailure { e ->
                        statusText.text = getString(R.string.err_join, e.message ?: "unknown")
                    }
            }
        }.start()
    }

    private fun initNetwork() {
        Thread {
            val result = runCatching {
                HextetClient.init("home", filesDir.absolutePath)
            }
            runOnUiThread {
                result
                    .onSuccess { outcome ->
                        statusText.text = getString(
                            R.string.init_ok,
                            outcome.optString("network_name", "?"),
                            outcome.optString("node_address", "?"),
                        )
                        updateFirstRunVisibility()
                    }
                    .onFailure { e ->
                        statusText.text = getString(R.string.err_init, e.message ?: "unknown")
                    }
            }
        }.start()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIF)
        }
    }

    private fun startVpn() {
        val cfg = File(filesDir, "hextet.toml")
        if (!cfg.exists()) {
            statusText.text = getString(R.string.config_missing)
            return
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(prepare, REQUEST_VPN)
        } else {
            doStartVpn()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            doStartVpn()
        }
    }

    private fun doStartVpn() {
        val intent = Intent(this, HextetVpnService::class.java)
            .setAction(HextetVpnService.ACTION_START)
        startForegroundService(intent)
        statusText.text = getString(R.string.vpn_starting)
    }

    private fun stopVpn() {
        stopService(Intent(this, HextetVpnService::class.java))
        statusText.text = getString(R.string.vpn_stopped)
    }

    private fun refreshStatus() {
        val cfg = File(filesDir, "hextet.toml")
        if (!cfg.exists()) {
            statusText.text = getString(R.string.config_missing)
            return
        }
        statusText.text = runCatching {
            val summary = HextetClient.loadConfig(cfg.absolutePath)
            val report = HextetClient.status(cfg.absolutePath)
            val sb = StringBuilder()
                .append(getString(R.string.status_node, summary.optString("node_address", "?")))
                .append('\n')
                .append("network: ").append(summary.optString("network_name", "?"))
                .append('\n')
                .append("daemon: ")
                .append(if (report.isNull("daemon")) "stopped" else "running")
                .append('\n')
                .append("peers: ").append(report.optJSONArray("peers")?.length() ?: 0)
            sb.toString()
        }.getOrElse { e ->
            getString(R.string.status_error, e.message ?: "unknown")
        }
    }
}
