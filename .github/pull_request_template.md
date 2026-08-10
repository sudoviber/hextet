<!-- 详细规范见 CONTRIBUTING.md -->

## 做了什么 / 为什么

<!-- 一两段。"怎么做"读 diff 就知道，"为什么"只有你知道。 -->

## 检查清单

- [ ] `cargo xtask ci` 全绿（fmt / clippy -D warnings / 测试 / cargo-deny）
- [ ] 改了 `#[cfg(target_os = "linux")]` 下的代码 → 跑了
      `cargo clippy --target x86_64-unknown-linux-gnu --workspace --all-targets -- -D warnings`
      （macOS 上这些文件不参与本地编译，本机全绿不代表它们对）
- [ ] `CHANGELOG.md` 已更新（`## [Unreleased]`）
- [ ] 协议改动同步了 `docs/protocol/`；用户可见改动同步了 `docs/guides/`
- [ ] 偏离设计 spec 的决策写了 `docs/adr/ADR-NNNN-*.md`（没有偏离则跳过）
- [ ] 新增/改动的行为有测试；从网络解析的新格式有「往返 + 逐字节篡改 + 任意字节不
      panic + 冻结线格式向量」四件套
- [ ] 没有 `todo!()` / `unimplemented!()` / `// TODO` / 空函数体 / 恒真断言 /
      新增的 `#[ignore]`
- [ ] 新增的 `Debug`/日志没有输出任何密钥

## E2E

- [ ] 本地跑过 `cargo xtask e2e <场景>`（仅 Linux + root）
- [ ] 或：**未本地验证，依赖 CI job** `_______`（macOS 开发时的正常情况，请写明哪个 job）
