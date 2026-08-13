//! 本地（离线）DDNS 会合 mock——`scripts/netns-e2e-ddns.sh` 用。
//!
//! 生产 daemon 的 DDNS 会合是「webhook/Cloudflare 更新 TXT + 公网 DNS 查询」。netns E2E
//! 要求确定性、离线，于是这里起一个进程内服务，同时提供：
//! - **HTTP webhook 接收端**（`POST /update`，JSON `{fqdn, value}` → 存进表）；
//! - **DNS TXT 服务器**（UDP，TXT 查询 → 从表里取 value 返回）。
//!
//! 于是 daemon 的发布侧（`WebhookUpdater`）与查询侧（`DdnsResolver::with_nameserver`
//! 指向这个 DNS 端口）能在 netns 里走完**真实 HTTP + 真实 DNS** 的闭环，与真实注册商/
//! 公网 DNS 的差异只剩「DNS 是单机、无 TTL 传播」。这与 DHT 会合的
//! `hextet_discovery::node::LocalDhtNode` 同一纪律：把测试用的会合点拉成可由脚本
//! 独立启动的进程。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// DNS TXT 记录类型（RFC 1035）。
const DNS_TYPE_TXT: u16 = 16;
/// DNS IN 类（Internet）。
const DNS_CLASS_IN: u16 = 1;

/// 一个只服务本地测试网络的单节点 DDNS mock。
///
/// 持有 webhook HTTP 线程与 DNS UDP 线程；`Drop` 时置 shutdown 标志并 join。进程
/// 退出即整个 mock 消失——这正是 E2E 想要的：一次测试一套干净的 DDNS 会合点。
pub struct LocalDdnsMock {
    shutdown: Arc<AtomicBool>,
    handles: Vec<thread::JoinHandle<()>>,
    /// webhook HTTP 实际绑定的地址（端口为 0 时是内核分配的临时端口）。
    http_addr: SocketAddr,
    /// DNS UDP 实际绑定的地址。
    dns_addr: SocketAddr,
}

impl LocalDdnsMock {
    /// 起 webhook HTTP（`bind:http_port`）+ DNS（`bind:dns_port`）。
    ///
    /// 两个端口都先同步 bind、失败即报错（端口被占时脚本据此立刻发现，而不是等后面
    /// 断言超时）。`bind` 应是测试拓扑里可达的具体 IPv4（如网桥地址），不能用
    /// `0.0.0.0`，否则对端无从构造 webhook URL / nameserver 地址。`http_port`/`dns_port`
    /// 传 0 时用内核分配的临时端口（进程内单测用，避免并行测试撞固定端口）——实际
    /// 端口经 [`Self::http_addr`] / [`Self::dns_addr`] 读回。
    pub fn spawn(bind: Ipv4Addr, http_port: u16, dns_port: u16) -> Result<Self, String> {
        let store: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let http_listener = TcpListener::bind((bind, http_port))
            .map_err(|e| format!("webhook HTTP 监听失败: {e}"))?;
        let http_addr = http_listener
            .local_addr()
            .map_err(|e| format!("读回 webhook HTTP 实际地址失败: {e}"))?;
        let dns_socket =
            UdpSocket::bind((bind, dns_port)).map_err(|e| format!("DNS UDP 监听失败: {e}"))?;
        let dns_addr = dns_socket
            .local_addr()
            .map_err(|e| format!("读回 DNS 实际地址失败: {e}"))?;

        let http = {
            let store = store.clone();
            let shutdown = shutdown.clone();
            thread::Builder::new()
                .name("ddns-mock-http".into())
                .spawn(move || http_serve(http_listener, store, shutdown))
                .map_err(|e| format!("起 webhook HTTP 线程失败: {e}"))?
        };
        let dns = {
            let store = store.clone();
            let shutdown = shutdown.clone();
            thread::Builder::new()
                .name("ddns-mock-dns".into())
                .spawn(move || dns_serve(dns_socket, store, shutdown))
                .map_err(|e| format!("起 DNS 线程失败: {e}"))?
        };
        Ok(Self {
            shutdown,
            handles: vec![http, dns],
            http_addr,
            dns_addr,
        })
    }

    /// webhook HTTP 实际绑定的地址（端口为 0 时是内核分配的临时端口）。
    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    /// DNS UDP 实际绑定的地址。
    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_addr
    }
}

impl Drop for LocalDdnsMock {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

/// webhook HTTP 接收端：解析 `POST /update` 的 JSON `{fqdn, value}` 存入表。
///
/// 极简 HTTP：只处理单个小请求（webhook POST 体 ~百字节），单次 read 一个 8KB 缓冲
/// 已足够；解析失败静默丢弃（不 4xx——mock 越简单越好，行为是否对由 E2E 断言兜底）。
fn http_serve(
    listener: TcpListener,
    store: Arc<Mutex<HashMap<String, String>>>,
    shutdown: Arc<AtomicBool>,
) {
    listener
        .set_nonblocking(true)
        .expect("set_nonblocking 失败");
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => handle_http(&mut stream, &store),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn handle_http(stream: &mut TcpStream, store: &Mutex<HashMap<String, String>>) {
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let Some(body_start) = req.find("\r\n\r\n") else {
        return;
    };
    let body = req[body_start + 4..].trim();
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
        let fqdn = json["fqdn"].as_str().unwrap_or_default();
        let value = json["value"].as_str().unwrap_or_default();
        if !fqdn.is_empty() {
            store
                .lock()
                .expect("ddns mock store 锁中毒")
                .insert(fqdn.to_string(), value.to_string());
        }
    }
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

/// DNS UDP 服务器：TXT 查询 → 表里的 value；非 TXT 查询直接忽略（丢弃，不回应）。
fn dns_serve(
    socket: UdpSocket,
    store: Arc<Mutex<HashMap<String, String>>>,
    shutdown: Arc<AtomicBool>,
) {
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("set_read_timeout 失败");
    let mut buf = [0u8; 512];
    while !shutdown.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((n, src)) => {
                let store = store.lock().expect("ddns mock store 锁中毒");
                if let Some(resp) = dns_txt_response(&buf[..n], &store) {
                    let _ = socket.send_to(&resp, src);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => break,
        }
    }
}

/// 对一个 DNS 查询报文构造 TXT 应答（纯函数，可单测）。
///
/// 只应答 `TYPE=TXT` 且表里正好有该 FQDN 的查询；其余返回 `None`（丢弃）。
/// 应答：头（echo ID + QR/RA + QD=1/AN=1）+ 原样回问的 question + 一条 TXT answer
/// （NAME 用压缩指针 `0xC00C` 指向 question 里的 QNAME）。
fn dns_txt_response(query: &[u8], store: &HashMap<String, String>) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    // 解析 question 的 QNAME（label 序列），得到 FQDN。
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *query.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            return None; // question 里不该有压缩指针
        }
        let end = pos + 1 + len;
        if end > query.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&query[pos + 1..end]).into_owned());
        pos = end;
    }
    // QTYPE + QCLASS（4 字节）
    let qtype = u16::from_be_bytes([*query.get(pos)?, *query.get(pos + 1)?]);
    let question_end = pos + 4;
    if qtype != DNS_TYPE_TXT || question_end > query.len() {
        return None;
    }
    let name = labels.join(".");
    // 容错：webhook 存的是配置里的字面 FQDN（无尾点），DNS QNAME 也编码成无尾点；
    // 仍兼容带尾点的写法。未发布过的名字回 NOERROR 空应答（ANCOUNT=0），让查询方
    // 干净地拿到「空」，而不是超时（超时在 resolver 里不是 no_records_found）。
    let value = store.get(&name).or_else(|| store.get(&format!("{name}.")));

    let question = &query[12..question_end];
    let mut resp =
        Vec::with_capacity(12 + question.len() + value.as_ref().map_or(0, |v| 16 + v.len()));
    resp.extend_from_slice(&query[0..2]); // echo ID
    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1, NOERROR
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    resp.extend_from_slice(&u16::from(value.is_some()).to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(question); // 原样回问
    if let Some(value) = value {
        resp.extend_from_slice(&0xC00Cu16.to_be_bytes()); // NAME → 偏移 12 的 QNAME
        resp.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        resp.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        resp.extend_from_slice(&0u32.to_be_bytes()); // TTL = 0
        resp.extend_from_slice(&((1 + value.len()) as u16).to_be_bytes()); // RDLENGTH
        resp.push(value.len() as u8); // TXT 字符串长度
        resp.extend_from_slice(value.as_bytes());
    }
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 TXT 查询：`id=0x1234`，question 为 `home.example.com` TXT IN。
    fn txt_query() -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT/NSCOUNT/ARCOUNT
        for label in ["home", "example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0); // root
        q.extend_from_slice(&DNS_TYPE_TXT.to_be_bytes());
        q.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        q
    }

    #[test]
    fn txt_query_gets_the_stored_value_back() {
        let mut store = HashMap::new();
        store.insert("home.example.com".into(), "hxdd1.abc".into());
        let resp = dns_txt_response(&txt_query(), &store).expect("应产生应答");

        // 应答必须包含原始 TXT 值，且把 QDCOUNT/ANCOUNT 都设成 1。
        let payload = String::from_utf8_lossy(&resp);
        assert!(
            payload.contains("hxdd1.abc"),
            "应答里应有 TXT 值，got {payload:?}"
        );
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1, "QDCOUNT=1");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "ANCOUNT=1");
    }

    #[test]
    fn missing_name_gets_noerror_empty_answer() {
        let store: HashMap<String, String> = HashMap::new();
        let resp = dns_txt_response(&txt_query(), &store).expect("未发布应回 NOERROR 空应答");
        assert_eq!(
            u16::from_be_bytes([resp[6], resp[7]]),
            0,
            "未发布：ANCOUNT 应为 0"
        );
    }

    #[test]
    fn non_txt_queries_are_dropped() {
        let store: HashMap<String, String> = HashMap::new();
        // 非 TXT 类型（A=1）→ 丢弃
        let mut q = txt_query();
        let n = q.len();
        q[n - 4] = 0;
        q[n - 3] = 1; // QTYPE = A
        assert!(dns_txt_response(&q, &store).is_none());
    }
}
