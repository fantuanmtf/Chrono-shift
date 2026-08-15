//! chrono-core — Chrono-shift v0.0.8.3 (纯 Rust)
//!
//! 单二进制 daemon：网络层 + DC-Net 轮次引擎 + Web 控制台。
//! 模块: dcnet, pgp, net(会话/中继), crypto, storage, service, web,
//!       round_engine, protocol_filter, address_book

pub mod address_book;
pub mod app;
pub mod crypto;
pub mod dcnet;
pub mod ffi;
pub mod identity;
pub mod net;
pub mod network;
pub mod parser;
pub mod pgp;
pub mod protocol_filter;
pub mod ratchet;
pub mod round_engine;
pub mod service;
pub mod storage;
pub mod web;
