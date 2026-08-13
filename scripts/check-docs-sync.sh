#!/usr/bin/env bash
# 检查「改了协议/状态相关代码，却没动对应文档」——spec §11 的执行机制之一。
#
# 只**警告**不失败：纯重构、改注释、改测试都可能命中规则，硬拦会制造噪音与
# 绕过习惯。警告用 GitHub Actions 的 ::warning 注解输出，在 PR 页面直接可见。
#
# 用法：scripts/check-docs-sync.sh [base-ref]    默认 base-ref = origin/main
set -euo pipefail

BASE=${1:-origin/main}
if ! git rev-parse --verify --quiet "$BASE" >/dev/null; then
  echo "::warning::docs-sync：拿不到 base ref ${BASE}，跳过检查"
  exit 0
fi

CHANGED=$(git diff --name-only "$BASE"...HEAD)
if [ -z "$CHANGED" ]; then
  echo "docs-sync：没有改动"
  exit 0
fi

changed_matches() { echo "$CHANGED" | grep -qE "$1"; }

# 每行 = "代码路径正则;该同步的文档;人类可读的说明"
# 分隔符用 ';' 而不是 '|'：正则本身要用 '|' 写分支。
RULES=(
  'crates/core/src/addr;docs/protocol/addressing.md;地址派生与分类'
  'crates/core/src/probe;docs/protocol/doctor-probe.md;doctor 探针协议'
  'crates/core/src/beacon;docs/protocol/lan-discovery.md;LAN 公告线格式'
  'crates/engine/src/lan;docs/protocol/lan-discovery.md;LAN 发现行为'
  'crates/core/src/invite;docs/protocol/invite.md;invite token 格式'
  'crates/core/src/gossip;docs/protocol/gossip.md;gossip 条目格式'
  'crates/core/src/relay;docs/protocol/relay.md;中继控制帧格式'
  'crates/engine/src/(gossip|members);docs/protocol/gossip.md;gossip 传输与成员行为'
  'crates/discovery;docs/protocol/dht-record.md;DHT 会合记录格式'
  'crates/engine/src/dht;docs/protocol/dht-record.md;DHT 会合接线'
  'crates/engine/src/(fsm|candidates);docs/protocol/punching.md;打洞与候选策略'
  'crates/engine/src/(state|cache|members);docs/dev/state-files.md;磁盘状态文件格式'
)

warned=0
for rule in "${RULES[@]}"; do
  code=${rule%%;*}
  rest=${rule#*;}
  doc=${rest%%;*}
  what=${rest#*;}
  if changed_matches "$code" && ! changed_matches "${doc//./\\.}"; then
    echo "::warning file=${doc}::改动了 ${what}（${code}）却没有同步 ${doc} —— 如果行为确实没变请忽略本条"
    warned=1
  fi
done

# CHANGELOG：任何 crates/ 下的改动都该留一行
if changed_matches '^crates/' && ! changed_matches '^CHANGELOG\.md$'; then
  echo "::warning file=CHANGELOG.md::改动了 crates/ 下的代码却没有更新 CHANGELOG.md"
  warned=1
fi

if [ "$warned" = 0 ]; then
  echo "docs-sync：代码与文档同步 ✓"
fi
exit 0
