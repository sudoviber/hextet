# 参与 hextet 开发

## 快速开始

```console
$ cargo xtask ci     # fmt --check + clippy -D warnings + 全量测试 + cargo-deny
```

`cargo xtask ci` 是本地的唯一入口，与 CI 的 `lint-test` job 等价（`cargo-deny`
未安装时会跳过并打印一行提示）。工具链由 `rust-toolchain.toml` 固定为 stable
+ rustfmt + clippy。

需要 root 的网络仿真测试单独跑：

```console
$ cargo xtask e2e [static|dynamic|doctor|lan|all]   # 仅 Linux，需要 root 与内核 wireguard
```

## 硬性要求

### 1. Linux-only 代码必须交叉验证

`crates/platform/src/linux.rs`、`crates/engine/src/daemon.rs`、
`crates/cli/src/commands/{status,doctor}.rs` 的主体都在 `#[cfg(target_os = "linux")]`
下。**在 macOS 开发机上这些文件根本不参与编译**——本机 `cargo xtask ci` 全绿不代表
它们正确，`clippy -D warnings` 也扫不到它们。改动它们时必须额外跑：

```console
$ rustup target add x86_64-unknown-linux-gnu   # 一次性
$ cargo clippy --target x86_64-unknown-linux-gnu --workspace --all-targets -- -D warnings
```

`cargo check`/`clippy` 不需要链接器，所以在 macOS 上可以直接跑。注意这只验证
**编译与 lint**；运行时行为（netlink 是否真投递事件、内核 WG 是否真 roaming、
组播 join 是否真生效）只有 netns E2E 能证明——而 netns E2E 只在 Linux 上跑，
所以 macOS 上开发时**必须推 CI 观察结果**，并在 PR 里写明"E2E 未本地验证，依赖
CI job X"。

### 2. 文档与代码同步（用户硬性要求，见 spec §11）

每个改变行为的 commit/PR 必须同步：

- `CHANGELOG.md` 至少一行（Keep a Changelog 格式，写进 `## [Unreleased]`）；
- 协议相关改动（`crates/core/src/{addr,probe,beacon,invite}*` 等）同步
  `docs/protocol/` 下对应文件；
- 偏离 `docs/superpowers/specs/2026-08-06-hextet-design.md` 的决策写一份
  `docs/adr/ADR-NNNN-*.md`，**不要直接改 spec**（它冻结为立项基线）；
- 影响用户操作的改动同步 `docs/guides/`。

CI 的 `docs-sync` job 会在"改了协议代码却没动对应协议文档"时给出警告
（只警告不拦，避免纯重构被卡；但请认真看）。

### 3. 测试分层

| 层 | 放哪 | 覆盖什么 |
|---|---|---|
| 单元测试 | 与实现同文件的 `mod tests` | 纯逻辑：编解码、状态机、候选组装、地址派生 |
| 属性测试（proptest） | 同上 | 往返一致、任意字节输入不 panic、无碰撞 |
| CLI 集成测试 | `crates/cli/tests/` | 命令行为、退出码、报错文案（用 `assert_cmd`） |
| netns E2E | `scripts/netns-e2e-*.sh` | 真跑网络：打洞、换前缀恢复、防火墙、组播 |

**新增从网络解析的格式时，必须同时加：往返测试、逐字节篡改全拒绝、
任意字节不 panic 的属性测试、以及一个冻结线格式向量（`frozen_*_vector`）。**
冻结向量的作用是让协议不兼容变更无法悄悄发生——它一旦失败，你要改的是版本号与
协议文档，不是断言。

E2E 脚本要自带**前提断言**。例如 `netns-e2e-lan.sh` 会先确认配置里没有 endpoint、
缓存文件不存在，否则"用配置连上了"会被误读成"LAN 发现成功"。测试证明的东西
必须是它声称的那个东西。

### 4. 不许有假实现

`todo!()`、`unimplemented!()`、`// TODO`、空函数体、返回假数据的桩、
`#[ignore]`（除了明确标注"需要 root，由 netns E2E 覆盖"的那些）、
被注释掉的断言、改成恒真的断言——一律视为未完成。

### 5. 不打印密钥

新增的 `Debug` 实现或日志不得输出 network key、节点 seed、任何派生子密钥
（probe/lan/relay/gossip）。`Config`、`DeviceSpec`、`Invite` 都手写了 `Debug`
打码，新结构照此办理，并补一条断言 Debug 输出里没有密钥的测试。

## 提交规范

Conventional commits：`feat:` / `fix:` / `test:` / `docs:` / `chore:` / `ci:` /
`refactor:`，可带 scope（`feat(core):`）。正文说明**为什么**这么做——
"怎么做"读代码就知道，"为什么"只有你知道。

AI 协作产生的提交末尾加一行：

```
Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
```

## 计划与里程碑

大块工作先写计划再动手，计划放 `docs/superpowers/plans/YYYY-MM-DD-<slug>.md`：
阶段划分、每个 Task 的接口签名与行为契约（编号可判定条目）、测试清单、验收标准。
里程碑定义见 spec §8。

## 项目结构

见 spec §10。当前实际结构（M3 阶段 B）：

```
crates/core/      纯逻辑：身份、地址派生、配置、invite、探针与公告报文
crates/wg/        WgBackend trait + Linux 内核后端 + Mock
crates/platform/  平台集成：接口/地址/MTU/netlink 监听/组播接口枚举
crates/engine/    可嵌入引擎：打洞状态机、候选、缓存、状态快照、LAN 发现、daemon 主循环
crates/cli/       hextet 命令行
xtask/            cargo xtask ci|e2e
```

`crates/core` 与 `crates/engine` 顶部有 `#![deny(missing_docs)]`：公开项都要写文档
注释，写"为什么"而不是重复签名。
