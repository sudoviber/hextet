plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.hextet.android"
    // compileSdk 34 is the well-tested target for AGP 8.7. Bump to 35/36+ only when the
    // corresponding Android SDK platform is installed on the build host (see README).
    compileSdk = 34
    // Build-tools 36.0.0 is what's installed on the reference build host; AGP 8.7 only
    // enforces a *minimum* build-tools version (34.0.0), so pinning the newer one avoids a
    // second download. Any build-tools >= 34.0.0 works.
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "org.hextet.android"
        minSdk = 30          // VpnService + foreground service + notification channels all API 26+; 30 is a safe floor
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Keep the (large) debug .so uncompressed so the linker can mmap it directly on device;
    // also disables APK-level jniLibs compression surprises.
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

// Copy the Rust cdylib artifacts into the app's jniLibs so AGP packages them and so JNA's
// `Native.register(...)` (which resolves `hextet_engine_ffi` / `hextet_core_ffi` via
// `System.loadLibrary`) finds them. The .so files are a cargo build artifact — they are NOT
// checked in (gitignored) and are produced by:
//
//     cargo build --target aarch64-linux-android -p hextet-engine-ffi -p hextet-core-ffi
//
// This task is best-effort: if `target/` is absent (fresh clone, or the Rust side hasn't
// been built), it only warns and leaves jniLibs empty, so `compileDebugKotlin` still works
// (the UniFFI bindings compile without the native lib; the lib is only needed at runtime).
val rustTargetDir = file("${rootProject.projectDir}/../../target/aarch64-linux-android/debug")
val copyRustJniLibs by tasks.registering(Copy::class) {
    group = "hextet"
    description = "Copy prebuilt Rust cdylibs from target/ into app jniLibs (best-effort)."
    from(rustTargetDir) {
        include("libhextet_engine_ffi.so", "libhextet_core_ffi.so")
    }
    into(layout.projectDirectory.dir("src/main/jniLibs/arm64-v8a"))
    onlyIf { rustTargetDir.exists() }
    doLast {
        if (!rustTargetDir.exists()) {
            logger.warn(
                "Rust .so not found under $rustTargetDir — run " +
                    "`cargo build --target aarch64-linux-android -p hextet-engine-ffi -p hextet-core-ffi` first."
            )
        }
    }
}

tasks.named("preBuild") {
    dependsOn(copyRustJniLibs)
}

dependencies {
    // JNA (Android AAR variant): the UniFFI-generated bindings use com.sun.jna to load the
    // native lib and declare the extern-C surface. The AAR bundles jnidispatch.so so the
    // whole thing works as a normal Android dependency.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
