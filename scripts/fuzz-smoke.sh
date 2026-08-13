#!/usr/bin/env bash
# 模糊测试 smoke：用 cargo-fuzz（libFuzzer 覆盖引导）短时运行每个 fuzz target。
#
# fuzz/ 是独立 cargo workspace（`cargo-fuzz = true`），需要 nightly 工具链 +
# `cargo install cargo-fuzz`。本机已装 nightly 1.99.0-nightly 与 cargo-fuzz 0.13.2
# 并跑通（2026-08-13）：六目标各 30s smoke 全部 DONE、零 panic。CI
# （.github/workflows/fuzz-smoke.yml）会先装好再跑本脚本，作为常开防线。
#
# 用法：scripts/fuzz-smoke.sh（可从任意 CWD 调用）
set -euo pipefail

# 定位仓库根目录：脚本位于 <repo>/scripts/ 下
cd "$(dirname "$0")/.."

# cargo-fuzz 是否可用（作为 cargo 子命令安装）
if ! cargo fuzz --version >/dev/null 2>&1; then
  echo "error: cargo-fuzz 未安装。请先 `cargo install cargo-fuzz`（需 nightly）。" >&2
  exit 1
fi

# nightly 工具链是否可用（cargo-fuzz 编译 target 需要 nightly）
if ! cargo +nightly --version >/dev/null 2>&1; then
  echo "error: nightly 工具链未安装。请先 `rustup toolchain install nightly`。" >&2
  exit 1
fi

# cargo-fuzz 在 CWD（或其子目录）里找 `[package.metadata] cargo-fuzz = true` 的包，
# 因此进入独立 workspace 的 fuzz/ 再执行。
cd fuzz

echo "=== fuzz build：编译全部 target（抓编译错误，主廉价门槛）==="
cargo +nightly fuzz build

# 与 fuzz/fuzz_targets/*.rs 文件名一一对应
TARGETS=(decode_beacon decode_relay decode_gossip decode_probe decode_invite decode_dht_record decode_ddns_record)
for t in "${TARGETS[@]}"; do
  echo ""
  echo "=== fuzz run ${t}（30s smoke）==="
  cargo +nightly fuzz run "$t" -- -max_total_time=30 -print_final_stats=1 -max_len=512
done

echo ""
echo "fuzz-smoke：全部 target 通过"
