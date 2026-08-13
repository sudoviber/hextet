// 生成 UniFFI 的 Rust scaffolding（`include_scaffolding!` 从 $OUT_DIR 包含它）。
fn main() {
    uniffi::generate_scaffolding("src/hextet.udl").unwrap();
}
