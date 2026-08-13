//! hextet 会合层（design spec §3 D3 兜底链第 ⑤、⑥ 层）。
//!
//! 两路「第三方公共汇合点」兜底：
//! - **DHT/pkarr 会合（第 ⑤ 层）**：把「某 node 当前在哪」加密后发布到 Mainline DHT，
//!   让双端同时换前缀时仍能经第三方 DHT 节点重新找到彼此。
//! - **自托管 DDNS 会合（第 ⑥ 层）**：用户自己的域名 + 注册商 API，中国网络下可达性
//!   最好的兜底（不绑定任何注册商，见 [`ddns`]）。
//!
//! - [`record`]：DHT 记录纯逻辑层（密钥派生 + AEAD 编解码），无 I/O，全平台可测。
//! - [`client`]：`mainline` 传输层（BEP44 可变项发布/查询），封装在 `DhtClient` 里，
//!   不向本 crate 之外暴露 `mainline` 类型（ADR-0005）。
//! - [`ddns`]：DDNS 客户端（HTTP 更新 + AAAA 查询），I/O 抽象在 `DdnsTransport` 后，
//!   不向本 crate 之外暴露 `ureq`/DNS 类型（ADR-0011）。
#![deny(missing_docs)]

pub mod client;
pub mod ddns;
pub mod node;
pub mod nodes;
pub mod record;
