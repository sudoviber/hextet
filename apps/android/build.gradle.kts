// Root build file: only declares plugin versions; the `:app` module applies them.
//
// Do NOT add dependencies here. The Rust crates (`crates/*`, workspace `Cargo.toml`)
// are owned by a separate cargo build and are deliberately untouched by this project —
// see apps/android/README.md for the full build pipeline (cargo -> uniffi-bindgen -> gradle).
plugins {
    id("com.android.application") version "8.7.0" apply false
    id("org.jetbrains.kotlin.android") version "2.0.0" apply false
}
