import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Paths.
//   module dir           = apps/android/app
//   rootProject.projectDir = apps/android
//   repoRoot             = tilefish/
val repoRoot: File = rootProject.projectDir.parentFile.parentFile
val uniffiToml: File = rootProject.projectDir.resolve("uniffi.toml")
// The `--library` input: one built cdylib is enough (UniFFI metadata is ABI-independent).
val engineSo: File = file("src/main/jniLibs/arm64-v8a/libhextet_engine_ffi.so")
val uniffiOutDir: File = file("build/generated/source/uniffi/java")

android {
    namespace = "org.hextet.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.hextet.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    sourceSets {
        getByName("main") {
            // Prebuilt .so files from cargo-ndk (arm64-v8a / armeabi-v7a / x86_64).
            jniLibs.srcDir("src/main/jniLibs")
            // UniFFI-generated Kotlin bindings (produced by generateUniffiBindings).
            java.srcDir(uniffiOutDir)
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

/**
 * Generates the UniFFI Kotlin bindings from the built cdylib (library mode).
 *
 * Requires `uniffi-bindgen` (>= 0.32) on PATH and the `.so` produced by the
 * cargo-ndk build. See apps/android/README.md for the exact command order.
 */
val generateUniffiBindings by tasks.registering(Exec::class) {
    group = "hextet"
    description = "Generate Kotlin bindings from libhextet_engine_ffi.so via uniffi-bindgen"
    workingDir = repoRoot
    inputs.file(engineSo)
    inputs.file(uniffiToml)
    outputs.dir(uniffiOutDir)
    doFirst {
        check(engineSo.exists()) {
            "Missing ${engineSo.absolutePath}. " +
                "Run the cargo-ndk build first (see apps/android/README.md)."
        }
    }
    commandLine(
        "uniffi-bindgen",
        "generate",
        "--config", uniffiToml.absolutePath,
        "--library", engineSo.absolutePath,
        "--language", "kotlin",
        "--out-dir", uniffiOutDir.absolutePath,
    )
}

// Generate bindings before any compile.
tasks.named("preBuild") {
    dependsOn(generateUniffiBindings)
}

dependencies {
    // JNA — required by the UniFFI-generated Kotlin (native library loading).
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("androidx.core:core-ktx:1.15.0")
}
