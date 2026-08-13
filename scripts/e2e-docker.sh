#!/usr/bin/env bash
# 在 Docker 里跑 netns E2E（Linux + root + 内核 wireguard 模块）。
#
# 用法：
#   scripts/e2e-docker.sh                         # 跑全部 8 个场景
#   scripts/e2e-docker.sh dht gossip              # 只跑指定场景（`static` 或带后缀的场景名）
#
# 环境变量：
#   HEXTET_E2E_IMAGE  镜像名（缺省 hextet-e2e:latest）
#
# 镜像首次会自动构建（scripts/Dockerfile.e2e）；源码经 bind mount 挂进容器，用独立
# 命名卷缓存 target/ 与 cargo registry，不会污染宿主机的 target/ 与 ~/.cargo。
set -euo pipefail

IMAGE=${HEXTET_E2E_IMAGE:-hextet-e2e:latest}
ROOT=$(cd "$(dirname "$0")/.." && pwd)

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "== 构建 E2E 镜像 $IMAGE =="
  docker build -t "$IMAGE" -f "$ROOT/scripts/Dockerfile.e2e" "$ROOT"
fi

# 场景名：`static` → scripts/netns-e2e.sh，其余 → scripts/netns-e2e-<name>.sh
# （与 `cargo xtask e2e static|dynamic|doctor|lan|relay|gossip|dht|site` 保持一致）
SCRIPTS=("$@")
if [ ${#SCRIPTS[@]} -eq 0 ]; then
  SCRIPTS=(static lan dht gossip relay site dynamic doctor)
fi

docker run --rm --privileged \
  -v "$ROOT":/hextet -w /hextet \
  -v hextet-cargo-target:/target \
  -v hextet-cargo-registry:/cargo-home \
  -e CARGO_TARGET_DIR=/target \
  -e CARGO_HOME=/cargo-home \
  -e HEXTET_BIN=/target/debug/hextet \
  "$IMAGE" bash -c '
    set -u
    echo "== 编译 hextet =="
    cargo build -p hextet-cli --bin hextet 2>&1 | tail -3
    fail=0
    for name in "$@"; do
      if [ "$name" = "static" ]; then
        script="scripts/netns-e2e.sh"
      else
        script="scripts/netns-e2e-$name.sh"
      fi
      echo "=== RUN $script ==="
      if bash "$script"; then
        echo "PASS $script"
      else
        echo "FAIL $script"
        fail=1
      fi
    done
    exit $fail
  ' _ "${SCRIPTS[@]}"
