// `/api/status` 的 JSON 形状与 `hextet status --json` 完全一致，
// 字段名镜像 `crates/proto/src/lib.rs` 的 serde 类型（线格式冻结，不得改动）。

/** daemon 存活信息（`--json` 的 `daemon` 字段）。 */
export interface DaemonInfo {
  /** daemon 是否在跑（由状态文件新鲜度判定）。 */
  running: boolean;
  /** 状态文件距上次更新的秒数。 */
  updated_secs_ago: number;
  /** 状态文件路径。 */
  state_file: string;
}

/** 一行 peer 状态。 */
export interface StatusRow {
  /** peer 名（配置里不认识的内核 peer 记为 `<unknown>`）。 */
  peer: string;
  /** peer 的 overlay IPv6 地址。 */
  address: string;
  /** 内核记录的当前 endpoint。 */
  endpoint: string | null;
  /** 距最近握手的秒数。 */
  last_handshake_secs: number | null;
  /** 接收字节数。 */
  rx_bytes: number;
  /** 发送字节数。 */
  tx_bytes: number;
  /** 连接状态：`connected` / `stale` / `no-handshake`。 */
  state: string;
  /** endpoint 来源（`relay`/`config`/`lan`/`gossip`/`cache`/`roamed`/`none`）。 */
  endpoint_source: string | null;
  /** 打洞状态（`probing`/`connected`/`relayed`）。 */
  punch_state: string | null;
  /** 候选 endpoint 总数。 */
  candidates: number | null;
  /** 当前候选下标。 */
  candidate_index: number | null;
  /** LAN 组播发现当前给出的 endpoint 数量。 */
  lan_endpoints: number | null;
  /** gossip 转介当前给出的 endpoint 数量。 */
  gossip_endpoints: number | null;
  /** DDNS 会合当前给出的 endpoint 数量。 */
  ddns_endpoints: number | null;
  /** 正在经哪个中继（peer 名）；null = 没在中继。 */
  relay_via: string | null;
  /** 这个 peer 通告、且本机当前已装进路由表的子网路由（site-to-site）。 */
  routes: string[];
}

/** 一次完整的 peer 连接状态报告。 */
export interface StatusReport {
  /** daemon 存活信息；没有状态文件时为 `null`。 */
  daemon: DaemonInfo | null;
  /** 每个 peer 的状态行。 */
  peers: StatusRow[];
}
