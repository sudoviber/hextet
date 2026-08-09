# ADR-0001：M2 守护进程的形态

- 状态：已接受
- 日期：2026-08-06
- 相关：`docs/superpowers/specs/2026-08-06-hextet-design.md` §10（项目结构）、§8（M2）

## 背景

M2 需要一个常驻进程（监听 netlink 地址变化、轮换候选 endpoint、维持打洞重试）。
设计 spec §10 规划的结构是三个 crate：`engine`（可嵌入引擎）、`daemon`（进程壳：
tokio 主循环 + axum Web UI + IPC server）、`proto`（daemon↔UI/CLI 共享类型）。
但 M2 既没有 Web UI 也没有 UI 客户端——axum 与 IPC 的第一个真实消费者是 M5。

## 决策

三项偏离，均为 M2 期限内的简化，不改变 spec 的终局结构：

1. **只建 `crates/engine` 一个新 crate**，`daemon`/`proto` 推迟到 M5。守护进程的
   tokio 主循环放在 `engine::daemon` 模块里。
2. **守护进程是 `hextet daemon` 子命令**，而不是独立的 `hextetd` 二进制。保持单
   二进制，M4 的 systemd/procd 单元直接调用 `hextet daemon`。
3. **运行时状态经原子写的 JSON 状态文件暴露**（`<state_dir>/state.json`），
   而不是 unix socket IPC。`hextet status` 读内核 + 读该文件后合并输出。

## 理由

- **YAGNI**：M2 的状态读者只有本机 CLI，且是只读、非实时。一个 tmp+rename 的 JSON
  文件就完全覆盖，且天然支持"daemon 不在跑"这个必须处理的状态（文件缺失/过期）。
  IPC 会引入连接生命周期、协议版本协商、并发与错误处理四层新面，M2 用不上。
- **`engine` 已经是那个"可嵌入引擎"**：spec 要求 engine 无进程假设、FFI-ready
  （M7 Android 经 UniFFI 复用）。把 tokio 主循环放在 engine 里不违反这一点——它是
  一个 `async fn run()`，调用方决定要不要跑；真正的进程壳（信号、日志初始化、
  命令行解析）在 `hextet-cli`。
- **单二进制降低交付成本**：cargo-dist、OpenWrt ipk、Android 都少一个产物要管。
  spec 里 `daemon` crate 的价值在于"axum + IPC 的落点"，那两样东西 M2 都没有。

## 后果

- **M5 必须补的债**：新建 `crates/proto`（serde 共享类型）与 unix socket IPC；
  届时 `hextet status` 改为优先走 IPC、状态文件降级为兜底（或直接移除）。
  Web UI 的 axum 落在 `crates/daemon` 还是 `engine` 到时再定。
- **状态文件不是公开 API**：`docs/dev/state-files.md` 明确它是派生数据、可随时
  删除、格式变更只需 `version` 对不上时让读者忽略。外部脚本应该用
  `hextet status --json` 而不是直接读文件。
- **`hextet status --json` 的形状在 M2 变过一次**（数组 → `{daemon, peers}` 对象）。
  0.1 发布前不再改。
