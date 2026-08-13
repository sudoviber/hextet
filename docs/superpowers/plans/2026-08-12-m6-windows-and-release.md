# hextet M6（Windows + 发布工程）实现计划

> 本计划覆盖 spec §8 M6 行的交付。按「独立性 × 可本地验证性」排序，先做纯逻辑、
> 零外部工具链的 MagicDNS-lite（hosts 生成）；wintun/Windows service 依赖 Windows
> 平台、cargo-dist 依赖发布工具链，均需各自的环境，放到最后并如实标注。

**Goal:** 补齐发布工程与一台机器即可感知的「按名访问」能力：把 peer 名解析到 overlay
IPv6 地址（MagicDNS-lite，静态 hosts 生成），以及全平台发布（cargo-dist）与 Windows
服务化（wintun + Windows service）。

**设计依据:** `docs/superpowers/specs/2026-08-06-hextet-design.md` §8 M6 行、§10 项目结构
（`xtask` 的发布编排、`openwrt/`、`docs/dev/`）、§11 文档规范。

---

## 进度（2026-08-13）

| 切片 | 状态 | 交付 |
|---|---|---|
| **A MagicDNS-lite（hosts 生成）** | ✅ 完成 | `hextet hosts` 命令：peer 名净化（小写/`[a-z0-9-]`/折叠 `-`/去首尾 `-`）+ 空名跳过 + >63 截断 + 撞名 `-2`/`-3` 去重；IPv6 hosts 行 `<地址>  <名>  <名>.hextet`；`--out` 原子写 0644；单测 + assert_cmd 集成测试 |
| **B cargo-dist 全平台发布** | ✅ 配置已验证 | `dist-workspace.toml` + `.github/workflows/release.yml`；已补装 cargo-dist 0.32.0，`dist plan` 生成 6 目标（Linux/macOS/Windows × x64/arm64）+ shell/powershell 安装器的完整计划、`dist generate --check` 通过（release.yml 与生成产物一致）；修复 `dist-workspace.toml` 缺失的 `[workspace]` 头（`dist plan` 之前报「must have [workspace] or [package]」） |
| **C 自托管 DDNS 兜底** | ⬜ 待做 | 会合兜底链 ⑥⑦ 的落地点（依赖外部服务，风险高） |
| **D wintun + Windows service** | ⬜ 待做 | `platform` 的 Windows 侧 + service（依赖 Windows，需 ADR-0008 的 Windows 分支决策） |
| **E 安全自审文档** | ✅ 完成 | `docs/security.md`：威胁模型（network key 为根密钥）、密钥派生与密钥保护、数据面/控制面密码学、DHT 会合与中继隐私、已知缺口与残余风险、安全自审清单 |

---

## 切片 A：MagicDNS-lite（hosts 生成）

**为什么先做它**：纯逻辑、零外部依赖、可在 macOS 上完整测试。用户价值直接——连上
之后 `ping <peer-name>` 就能解析到 overlay 地址，而不需要背 `fd00:...` 地址。这是
Tailscale「MagicDNS」的 lite 版：不做真 DNS 解析器，只生成静态 hosts 行。

**交付（`crates/cli/src/commands/hosts.rs`）:**
- `hextet hosts [-c hextet.toml] [--out <path>]`：
  - 读配置（`load_config_and_identity`），对每个 `[[peers]]` 输出一行
    `<overlay_ipv6>  <sanitized_name>  <sanitized_name>.hextet`。
  - 名字净化：小写、只保留 `[a-z0-9-]`，其余字符折叠成 `-`；净化为空或长度超限
    （>63）则跳过并 `warn!`；两个 peer 净化后撞名 → `warn!` 并给后一个加 `-2` 后缀
    （确定性去重，不静默覆盖）。
  - 默认打印到 stdout（便于 `sudo tee -a /etc/hosts`）；`--out <path>` 原子写入 0644。
  - IPv6-only：hosts 行只有 IPv6 地址，配置里本就无 IPv4。
- 纯逻辑拆成可测函数：`render_hosts(peers) -> Vec<HostsLine>`（含净化/去重/跳过策略），
  `run()` 只做读写与打印。
- `crates/cli/src/commands/mod.rs` + `main.rs` 注册 `Hosts` 子命令。

**测试（无头，`crates/cli/tests/hosts.rs` 或单测）:**
- 名字净化（大写/空格/特殊字符）、空名跳过、超长跳过、撞名确定性去重、IPv6 行格式、
  `--out` 原子写入、`--json`？不提供 JSON（hosts 是文本）。用 `assert_cmd` 端到端
  跑 `hextet hosts -c <临时配置>` 断言 stdout 行集合。

**验收:** `cargo xtask ci` 全绿；`hextet hosts` 对临时配置输出正确 hosts 行。

---

## 其余切片（依赖外部环境，最后做，如实标注）

- **B cargo-dist**：`dist-workspace.toml` + `dist` CI job；已用 cargo-dist 0.32.0
  验证 `dist plan` 与 `dist generate --check`（本机装好工具后跑通，见上方进度表）。
- **C DDNS 兜底**：spec 会合兜底链 ⑥⑦，依赖自托管 HTTP/TXT 端点，属网络/运维面，
  单独立项。
- **D Windows**：`platform` 的 wintun/Windows service，依赖 Windows 平台 + ADR-0008 的
  Windows 分支（`tun` crate 的 `windows` 模块 vs 直接接 wintun），需新 ADR。
- **E 安全自审**：`docs/security.md` 汇总威胁模型与诚实边界（可做，纯文档）。

---

## 风险与缓解（M6 特有）

| 风险 | 缓解 |
|---|---|
| Windows/wintun 无法在 macOS 上验证 | 最后做 + 新 ADR 决策 + 依赖 CI Windows runner |
| cargo-dist 需装工具 | 已装 cargo-dist 0.32.0 并跑通 `dist plan` / `dist generate --check`；后续版本漂移靠 CI `dist plan` dry-run 兜底 |
| DDNS 依赖外部服务 | 单独立项，不并入本计划的主路径 |
