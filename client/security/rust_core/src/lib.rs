//! chrono-core — Chrono-shift v0.0.9 (纯 Rust)
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

/// Validate a peer UID before it is accepted into maps, logs or the UI.
///
/// Rules (v0.0.9 hardening): 1..=64 bytes, ASCII only, characters limited to
/// `A-Za-z0-9`, `.`, `_`, `-`, `@`, `:`, `[`, `]` (the `peer@` anonymous prefix
/// including socket addresses is allowed). Remote-controlled UIDs that fail
/// this check are dropped at the session boundary instead of flowing into
/// storage, logs or the web console DOM.
pub fn validate_uid(uid: &str) -> bool {
    !uid.is_empty()
        && uid.len() <= 64
        && uid.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'@' | b':' | b'[' | b']')
        })
}

#[cfg(test)]
mod uid_validation_tests {
    use super::validate_uid;

    #[test]
    fn accepts_normal_uids() {
        for uid in [
            "alice",
            "bob@example",
            "peer@127.0.0.1:9000",
            "peer@[::1]:9000",
            "a-b_c.d@x",
        ] {
            assert!(validate_uid(uid), "expected {uid:?} to be valid");
        }
    }

    #[test]
    fn rejects_invalid_uids() {
        let long = "a".repeat(65);
        for uid in [
            "",
            " ",
            "名字",
            "a b",
            "x<y",
            "x>y",
            "x&y",
            "x\"y",
            "x'y",
            "a\nb",
            "x/y",
            "x\\y",
            "x;y",
            "x{y",
            "x(y",
            "x)y",
            "x=y",
            "x\u{7}y",
            long.as_str(),
        ] {
            assert!(!validate_uid(uid), "expected {uid:?} to be invalid");
        }
    }
}
