#!/usr/bin/env bash
# hextet M6 切片 C E2E：A、B 的配置里**没有对方的 endpoint、也没有端点缓存**，
# 仅靠一个本地（离线）DDNS 会合 mock（webhook HTTP + DNS TXT）互相发现并连通；
# 随后 A、B **同时**换地址，仍只靠 DDNS 查询到对方的新地址在秒级自动恢复。
#
# 为什么是本地 DDNS mock 而不是真实注册商/DNS：与 DHT 会合的 netns-e2e-dht.sh 同一
# 纪律——netns 要求确定性、离线、秒级收敛。`hextet ddns node`（隐藏子命令）跑一个
# 进程内服务：webhook HTTP 接收端 + DNS TXT 服务器，daemon 经它发布/查询会合记录，
# 走完真实 HTTP + 真实 DNS 的闭环（差异只剩"单机 DNS、无 TTL 传播"）。
#
# 需要：Linux、root、内核 wireguard 模块、jq。
set -euo pipefail

BR=br-hxt7
NS_A=hxt7-a
NS_B=hxt7-b
BIN=${HEXTET_BIN:-target/debug/hextet}
TMP=$(mktemp -d)

# IPv6 数据面：A、B 挂在同一个 L2（同一 /64 当"同一网络"）；换地址即换端点
NET=2001:db8:40
ADDR_A="${NET}::a"
ADDR_B="${NET}::b"
ADDR_A2="${NET}::aa"
ADDR_B2="${NET}::bb"

# IPv4 控制面：webhook + DNS 都走 IPv4（与 DHT 会合同款"控制面弱依赖 IPv4 出站"）。
# 网桥拿一个 IPv4 当"DDNS mock 地址"，A、B 的 veth 各拿一个同网段 IPv4，好让 daemon
# 的 webhook updater 出站到 mock、解析器也把查询发到 mock。换前缀只动 IPv6 数据面，
# IPv4 控制面全程稳定。
BRIP=172.19.0.1
HTTP_PORT=8081
DNS_PORT=5353
IP_A=172.19.0.2
IP_B=172.19.0.3

# 首次会合：DDNS 查询周期 30s（启动即查），但发布（webhook POST）与查询并发、顺序
# 不保证——首查可能落在发布之前，要等下一个 30s 周期；60s 给足两个查询周期 + 握手。
INITIAL_TIMEOUT=60
# 换址恢复：地址变化即重发（不依赖 30s 周期），但对方要等下一次 30s 查询才拿到新地址；
# 90s 给 CI 抖动留足余量。
RECOVERY_TIMEOUT=90

A_PID=""
B_PID=""
DDNS_PID=""

cleanup() {
  for pid in "$A_PID" "$B_PID" "$DDNS_PID"; do
    [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true
  done
  for ns in "$NS_A" "$NS_B"; do ip netns del "$ns" 2>/dev/null || true; done
  for v in veth7-a veth7-b; do ip link del "$v" 2>/dev/null || true; done
  ip link del "$BR" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq required" >&2; exit 1; }

status_json() { ip netns exec "$1" "$BIN" status --json -c "$2" 2>/dev/null; }

dump_diagnostics() {
  echo "===== DIAGNOSTICS =====" >&2
  echo "--- ddns mock log (tail) ---" >&2
  tail -n 40 "$TMP/ddns.log" >&2 2>&1 || true
  for pair in "a:$NS_A:$TMP/a.toml:$TMP/a-state" "b:$NS_B:$TMP/b.toml:$TMP/b-state"; do
    label=${pair%%:*}; rest=${pair#*:}; ns=${rest%%:*}; rest=${rest#*:}; cfg=${rest%%:*}; state=${rest#*:}
    echo "--- $label: status --json ---" >&2
    status_json "$ns" "$cfg" >&2 || true
    echo "--- $label: wg show all ---" >&2
    ip netns exec "$ns" wg show all >&2 2>&1 || true
    echo "--- $label: ip -6 addr ---" >&2
    ip netns exec "$ns" ip -6 addr >&2 2>&1 || true
    echo "--- $label: ip -4 addr ---" >&2
    ip netns exec "$ns" ip -4 addr >&2 2>&1 || true
    echo "--- $label: daemon log (tail) ---" >&2
    tail -n 80 "$TMP/$label.log" >&2 2>&1 || true
    echo "--- $label: 抓一下 DNS 包（2s，udp ${DNS_PORT}） ---" >&2
    timeout 2 ip netns exec "$ns" tcpdump -n -c 5 -i any "udp port ${DNS_PORT}" >&2 2>&1 \
      || echo "(tcpdump 不可用或没抓到包)" >&2
  done
  echo "===== END DIAGNOSTICS =====" >&2
}

# 轮询直到某侧 status 的 peer（按名字选）满足给定 jq 条件
wait_for_peer() {
  ns=$1; cfg=$2; peer=$3; cond=$4; budget=$5; label=$6
  for i in $(seq 1 "$budget"); do
    if status_json "$ns" "$cfg" \
      | jq -e --arg p "$peer" "(.peers[] | select(.peer == \$p)) | ${cond}" >/dev/null 2>&1; then
      echo "$label: 满足 ${cond}（${i}s）"
      return 0
    fi
    sleep 1
  done
  echo "$label: 等待 ${cond} 超时（${budget}s）" >&2
  return 1
}

# 1) 拓扑：两个 netns 挂在同一个 bridge 上；bridge 带 IPv4 给 webhook/DNS 控制面，
#    veth 带 IPv6（数据面）+ IPv4（控制面）。
ip link add "$BR" type bridge
ip link set "$BR" up
ip addr add "${BRIP}/24" dev "$BR"
for spec in "a|$NS_A|$ADDR_A|$IP_A" "b|$NS_B|$ADDR_B|$IP_B"; do
  IFS='|' read -r tag ns addr ip4 <<< "$spec"
  ip netns add "$ns"
  ip link add "veth7-$tag" type veth peer name "veth7-$tag-p"
  ip link set "veth7-$tag" master "$BR" up
  ip link set "veth7-$tag-p" netns "$ns"
  ip -n "$ns" addr add "${addr}/64" dev "veth7-$tag-p" nodad
  ip -n "$ns" addr add "${ip4}/24" dev "veth7-$tag-p"
  ip -n "$ns" link set lo up
  ip -n "$ns" link set "veth7-$tag-p" up
done

# 2) 身份与配置（各自独立 state_dir，保证端点缓存是空的）
mkdir -p "$TMP/a-state" "$TMP/b-state"
PK_A=$("$BIN" keygen --out "$TMP/a.key" | awk '/public-key:/{print $2}')
PK_B=$("$BIN" keygen --out "$TMP/b.key" | awk '/public-key:/{print $2}')
"$BIN" init --name e2e-ddns --key-file "$TMP/a.key" --state-dir "$TMP/a-state" --out "$TMP/a.toml"
NETKEY=$(grep '^key = ' "$TMP/a.toml" | cut -d'"' -f2)
"$BIN" init --name e2e-ddns --key-file "$TMP/b.key" --network-key "$NETKEY" \
  --state-dir "$TMP/b-state" --out "$TMP/b.toml"

# 关掉 LAN 组播发现 + 隧道内 gossip + 开 DDNS 会合（webhook 发布 + 固定解析器到本地
# mock）。用 awk 在 [node] 段一次性插入，避免 cat >> 把 node 字段落到 peers 之后。
# 关 gossip 是必须的：gossip 优先级高于 DDNS，隧道一旦经 DDNS 建起来它就会立刻转介
# 对方的地址，把 `endpoint_source` 从 "ddns" 污染成 "gossip"（与 DHT 测试同款隔离）。
enable_ddns() {
  awk -v fqdn="$2" -v url="$3" -v resolver="$4" '
    { print }
    /^\[node\]$/ {
      print "lan_discovery = false"
      print "gossip = false"
      print "ddns = true"
      print "ddns_fqdn = \"" fqdn "\""
      print "ddns_provider = \"webhook\""
      print "ddns_webhook_url = \"" url "\""
      print "ddns_resolver = \"" resolver "\""
    }
  ' "$1" >"$1.tmp"
  mv "$1.tmp" "$1"
}
enable_ddns "$TMP/a.toml" "a.example.com" "http://${BRIP}:${HTTP_PORT}/update" "${BRIP}:${DNS_PORT}"
enable_ddns "$TMP/b.toml" "b.example.com" "http://${BRIP}:${HTTP_PORT}/update" "${BRIP}:${DNS_PORT}"

# 关键：互加对端，**不给任何 endpoint**，只给对方的 DDNS FQDN——只能靠 DDNS 会合去发现
cat >>"$TMP/a.toml" <<EOF

[[peers]]
name = "b"
public_key = "$PK_B"
ddns = "b.example.com"
EOF

cat >>"$TMP/b.toml" <<EOF

[[peers]]
name = "a"
public_key = "$PK_A"
ddns = "a.example.com"
EOF

# 3) 前置断言：DDNS 是本测试**唯一**的会合路径。
for cfg in "$TMP/a.toml" "$TMP/b.toml"; do
  if grep -q '^endpoints = ' "$cfg"; then
    echo "ERROR: $cfg 里竟然有 endpoints，本测试的前提被破坏" >&2; exit 1
  fi
  grep -q '^lan_discovery = false$' "$cfg" \
    || { echo "ERROR: $cfg 没有关掉 LAN 发现，DDNS 路径会被掩盖" >&2; exit 1; }
  grep -q '^gossip = false$' "$cfg" \
    || { echo "ERROR: $cfg 没有关掉 gossip，DDNS 路径会被污染" >&2; exit 1; }
  grep -q '^ddns_resolver = ' "$cfg" \
    || { echo "ERROR: $cfg 没有固定 DDNS 解析器，查询会走系统 DNS" >&2; exit 1; }
done
for d in "$TMP/a-state" "$TMP/b-state"; do
  if [ -e "$d/endpoints.json" ]; then
    echo "ERROR: $d 里已有端点缓存，本测试的前提被破坏" >&2; exit 1
  fi
done

OVERLAY_A=$("$BIN" inspect --json -c "$TMP/a.toml" | jq -r .node.address)
OVERLAY_B=$("$BIN" inspect --json -c "$TMP/b.toml" | jq -r .node.address)
echo "overlay: a=$OVERLAY_A b=$OVERLAY_B（配置里没有任何 endpoint，仅 DDNS 会合）"

# 4) 起本地 DDNS mock（根 netns，绑在网桥 IPv4 上）+ 两侧 daemon
"$BIN" ddns node --bind "$BRIP" --http-port "$HTTP_PORT" --dns-port "$DNS_PORT" >"$TMP/ddns.log" 2>&1 &
DDNS_PID=$!
sleep 1
ip netns exec "$NS_A" "$BIN" daemon -v -c "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
A_PID=$!
ip netns exec "$NS_B" "$BIN" daemon -v -c "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
B_PID=$!

# 5) 核心验收（初始）：A、B 仅靠 DDNS 会合连上，且 endpoint_source == "ddns"
if ! wait_for_peer "$NS_A" "$TMP/a.toml" b \
     '.punch_state == "connected" and .endpoint_source == "ddns"' \
     "$INITIAL_TIMEOUT" "a→b 会合"; then dump_diagnostics; exit 1; fi
if ! wait_for_peer "$NS_B" "$TMP/b.toml" a \
     '.punch_state == "connected" and .endpoint_source == "ddns"' \
     "$INITIAL_TIMEOUT" "b→a 会合"; then dump_diagnostics; exit 1; fi

# 6) overlay 双向连通（数据真的通了，不是状态文件自嗨）
if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$OVERLAY_B" >/dev/null; then
  echo "ERROR: a→b overlay ping 失败（DDNS 会合没通）" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$OVERLAY_A" >/dev/null; then
  echo "ERROR: b→a overlay ping 失败（DDNS 会合没通）" >&2; dump_diagnostics; exit 1
fi
echo "经 DDNS 会合的 overlay 双向连通 ✓"

# 7) 换址：A、B **同时**换地址（删旧加新），仅靠 DDNS 查询到对方的新地址恢复。
#    注意只动 IPv6 数据面地址，IPv4 控制面（到 mock 的出站）保持不变。
ip -n "$NS_A" addr del "${ADDR_A}/64" dev veth7-a-p
ip -n "$NS_A" addr add "${ADDR_A2}/64" dev veth7-a-p nodad
ip -n "$NS_B" addr del "${ADDR_B}/64" dev veth7-b-p
ip -n "$NS_B" addr add "${ADDR_B2}/64" dev veth7-b-p nodad
echo "--- A、B 已同时换地址：a=${ADDR_A2} b=${ADDR_B2} ---"

# 恢复后仍应连上，且 A/B 看到的对方 endpoint 是对方的新地址（DDNS 查来的，不是旧地址），
# endpoint_source 仍是 ddns。
if ! wait_for_peer "$NS_A" "$TMP/a.toml" b \
     '.punch_state == "connected" and .endpoint == "[2001:db8:40::bb]:4193" and .endpoint_source == "ddns"' \
     "$RECOVERY_TIMEOUT" "a→b 换址恢复"; then dump_diagnostics; exit 1; fi
if ! wait_for_peer "$NS_B" "$TMP/b.toml" a \
     '.punch_state == "connected" and .endpoint == "[2001:db8:40::aa]:4193" and .endpoint_source == "ddns"' \
     "$RECOVERY_TIMEOUT" "b→a 换址恢复"; then dump_diagnostics; exit 1; fi

if ! ip netns exec "$NS_A" ping -6 -c 3 -W 5 "$OVERLAY_B" >/dev/null; then
  echo "ERROR: 换址后 a→b overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
if ! ip netns exec "$NS_B" ping -6 -c 3 -W 5 "$OVERLAY_A" >/dev/null; then
  echo "ERROR: 换址后 b→a overlay ping 失败" >&2; dump_diagnostics; exit 1
fi
echo "换址后经 DDNS 会合恢复 ✓"

# 8) 收尾
for pid_var in A_PID B_PID DDNS_PID; do
  pid=${!pid_var}
  [ -n "$pid" ] && { kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; }
done
A_PID=""; B_PID=""; DDNS_PID=""
for spec in "$NS_A:$TMP/a.toml" "$NS_B:$TMP/b.toml"; do
  ns=${spec%%:*}; cfg=${spec#*:}
  ip netns exec "$ns" "$BIN" down -c "$cfg"
  if ip -n "$ns" link show hextet0 >/dev/null 2>&1; then
    echo "ERROR: hextet0 still exists in $ns after down" >&2
    exit 1
  fi
done

echo "DDNS E2E OK"
