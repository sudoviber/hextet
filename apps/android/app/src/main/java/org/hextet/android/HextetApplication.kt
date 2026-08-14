package org.hextet.android

import android.app.Application

/**
 * Application subclass that loads the native library before any `uniffi.hextet`
 * call is made.
 *
 * The generated bindings resolve the library name `hextet_engine_ffi` (derived
 * from the cdylib metadata) and load it via JNA. `System.loadLibrary` here makes
 * the `.so` — unpacked from the APK's `lib/<abi>/` (sourced from `jniLibs/`) —
 * available on JNA's default search path, which is exactly what the generated
 * code expects when `android = true`.
 */
class HextetApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        System.loadLibrary("hextet_engine_ffi")
    }
}
