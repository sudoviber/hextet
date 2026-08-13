import { useEffect, useState } from "react";
import type { StatusReport } from "./types";

/** 轮询 `/api/status` 的间隔。 */
const POLL_MS = 2000;

/**
 * 选择状态 API 的基地址。
 *
 * 浏览器里由 axum 同源托管（或 vite dev proxy 转发），用相对路径即可；
 * Tauri 桌面 webview 的源是 `tauri://localhost`，相对路径会 404，须指向
 * daemon 内嵌 HTTP 状态服务（默认 `[node] http_port = 8080`，与
 * `crates/core/src/config.rs` 的默认值保持一致）。
 */
function apiBase(): string {
  const isTauri =
    typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
  return isTauri ? "http://127.0.0.1:8080" : "";
}

/**
 * 拉取一次 `/api/status`。
 *
 * 请求失败时抛出异常（由调用方渲染错误态），不做静默吞错。
 */
async function fetchStatus(): Promise<StatusReport> {
  const res = await fetch(`${apiBase()}/api/status`);
  if (!res.ok) {
    throw new Error(`/api/status 返回 ${res.status}`);
  }
  return (await res.json()) as StatusReport;
}

/** 把秒数格式化成人类可读的 "1d 2h 3m 4s"。 */
function formatDuration(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  const parts: string[] = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  parts.push(`${r}s`);
  return parts.join(" ");
}

function fmtBytes(n: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function cell(value: string | null | undefined, fallback = "-"): string {
  if (value === null || value === undefined || value === "") return fallback;
  return value;
}

function App() {
  const [report, setReport] = useState<StatusReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const tick = async () => {
      try {
        const next = await fetchStatus();
        if (!cancelled) {
          setReport(next);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    };

    void tick();
    const id = setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const daemon = report?.daemon ?? null;

  return (
    <div className="app">
      <header className="header">
        <h1>hextet</h1>
        {daemon === null ? (
          <span className="badge stopped">no daemon</span>
        ) : daemon.running ? (
          <span className="badge running">daemon running</span>
        ) : (
          <span className="badge stopped">daemon stopped</span>
        )}
      </header>

      {error !== null && <div className="error">无法读取状态：{error}</div>}

      {report === null && error === null && (
        <p className="meta">加载中…</p>
      )}

      {daemon !== null && (
        <p className="meta">
          最近更新 {formatDuration(daemon.updated_secs_ago)} 前 · {daemon.state_file}
        </p>
      )}

      {report !== null && (
        <PeerTable peers={report.peers} />
      )}
    </div>
  );
}

function PeerTable({ peers }: { peers: StatusReport["peers"] }) {
  if (peers.length === 0) {
    return <p className="empty">没有 peer</p>;
  }

  return (
    <table>
      <thead>
        <tr>
          <th>peer</th>
          <th>address</th>
          <th>endpoint</th>
          <th>source</th>
          <th>punch</th>
          <th>handshake</th>
          <th>rx</th>
          <th>tx</th>
          <th>routes</th>
        </tr>
      </thead>
      <tbody>
        {peers.map((p) => {
          const punch =
            p.relay_via !== null
              ? `${cell(p.punch_state)} via ${p.relay_via}`
              : cell(p.punch_state);
          return (
            <tr key={p.peer}>
              <td>{p.peer}</td>
              <td>{p.address}</td>
              <td>{cell(p.endpoint)}</td>
              <td>{cell(p.endpoint_source)}</td>
              <td>{punch}</td>
              <td>
                {p.last_handshake_secs === null
                  ? "-"
                  : formatDuration(p.last_handshake_secs)}
              </td>
              <td>{fmtBytes(p.rx_bytes)}</td>
              <td>{fmtBytes(p.tx_bytes)}</td>
              <td className="routes">
                {p.routes.length === 0 ? (
                  <span className="muted">-</span>
                ) : (
                  p.routes.join(", ")
                )}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

export default App;
