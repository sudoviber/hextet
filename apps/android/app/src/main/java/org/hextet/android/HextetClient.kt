package org.hextet.android

import org.json.JSONObject

/**
 * Thin wrapper over the UniFFI-generated `uniffi.hextet` bindings.
 *
 * Every FFI function returns a JSON string. Errors are signalled by the presence
 * of an `"error"` key (`{"error":"..."}`); success shapes differ per function:
 *
 *  - `loadConfig`         → sanitised config summary (network/prefix/node/peers)
 *  - `status`             → full state report (daemon may be `null` when idle)
 *  - `join`               → JoinOutcome (network/prefix/node/peers/…)
 *  - `init`               → InitOutcome (network/prefix/node/network_key_base64/…)
 *  - `daemonSpawnWithFd`  → `{"handle": <u64>}`
 *  - `daemonShutdown`     → `{}`
 *
 * Calls are fully-qualified (`uniffi.hextet.*`) to avoid shadowing the wrapper
 * methods with the same names.
 */
object HextetClient {

    /** Loads the config at [path] and returns the sanitised summary JSON. */
    fun loadConfig(path: String): JSONObject =
        JSONObject(uniffi.hextet.loadConfig(path)).requireNoError()

    /** Reads the daemon state report for the config at [configPath]. */
    fun status(configPath: String): JSONObject =
        JSONObject(uniffi.hextet.status(configPath)).requireNoError()

    /**
     * Joins an existing network from an [invite token][token], writing
     * `hextet.toml` + `node.key` into [outDir]. Returns the `JoinOutcome` JSON
     * (serde snake_case); throws [HextetFfiException] on error.
     */
    fun join(token: String, outDir: String): JSONObject =
        JSONObject(uniffi.hextet.join(token, outDir)).requireNoError()

    /**
     * Creates a new network named [name], writing `hextet.toml` + `node.key`
     * into [outDir]. Returns the `InitOutcome` JSON (serde snake_case); throws
     * [HextetFfiException] on error.
     */
    fun init(name: String, outDir: String): JSONObject =
        JSONObject(uniffi.hextet.init(name, outDir)).requireNoError()

    /**
     * Spawns the in-process daemon using the VPN fd from [tunFd]; returns the
     * daemon handle, or null on error (the raw error JSON is discarded — the
     * caller already surfaced a user-facing message).
     */
    fun spawn(configPath: String, tunFd: Int, mtu: UShort): ULong? {
        val obj = JSONObject(uniffi.hextet.daemonSpawnWithFd(configPath, tunFd, mtu))
        if (obj.has("error")) return null
        return obj.getLong("handle").toULong()
    }

    /** Gracefully shuts the daemon down; returns the error string, or null on success. */
    fun shutdown(handle: ULong): String? {
        val obj = JSONObject(uniffi.hextet.daemonShutdown(handle))
        return if (obj.has("error")) obj.getString("error") else null
    }

    private fun JSONObject.requireNoError(): JSONObject {
        if (has("error")) throw HextetFfiException(getString("error"))
        return this
    }
}

/** Thrown when a `loadConfig`/`status`/`join`/`init` call returns an `{"error":...}` payload. */
class HextetFfiException(message: String) : Exception(message)
