//! hextet 会合层（design spec §3 D3 兜底链第 ⑤ 层）。
//!
//! DHT/pkarr 会合：把「某 node 当前在哪」加密后发布到 Mainline DHT，让双端同时
//! 换前缀时仍能经第三方 DHT 节点重新找到彼此。
//!
//! - [`record`]：纯逻辑的记录层（密钥派生 + AEAD 编解码），无 I/O，全平台可测。
//! - [`client`]：`mainline` 传输层（BEP44 可变项发布/查询），封装在 `DhtClient` 里，
//!   不向本 crate 之外暴露 `mainline` 类型（ADR-0005）。
#![deny(missing_docs)]

pub mod client;
pub mod node;
pub mod nodes;
pub mod record;
