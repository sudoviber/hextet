//! hextet 会合层（design spec §3 D3 兜底链第 ⑤、⑥ 层）。
//!
//! 把「某 node 当前在哪」加密后发布到汇合点，让双端同时换前缀时仍能重新找到彼此：
//! - **DHT/pkarr 会合（第 ⑤ 层）**：发布到 Mainline DHT，经第三方 DHT 节点定位。
//! - **自托管 DDNS 会合（第 ⑥ 层）**：发布到用户自己的域名 TXT 记录，经 DNS 解析定位
//!   （中国网络下 DHT 被干扰时的兜底）。
//!
//! - [`record`]：纯逻辑的记录层（密钥派生 + AEAD 编解码），无 I/O，全平台可测。
//! - [`client`]：`mainline` 传输层（BEP44 可变项发布/查询），封装在 `DhtClient` 里，
//!   不向本 crate 之外暴露 `mainline` 类型（ADR-0005）。
//! - [`ddns`]：DDNS 记录纯逻辑（`derive_ddns_key`/`render_record`/`parse_record`/
//!   `select_endpoints`）+ `resolver`（hickory TXT 查询）+ `updater`（webhook/Cloudflare）。
#![deny(missing_docs)]

pub mod client;
pub mod ddns;
pub mod node;
pub mod nodes;
pub mod record;
