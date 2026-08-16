//! Protocol Filter (v8.0 — Phase 5)
//!
//! Prevents network abuse by restricting proxy traffic to text-based
//! protocols (IRC, BBS). Rejects binary, HTTP, WebSocket, and oversized
//! messages that could degrade DC-Net performance.
//!
//! NOTE: 当前 daemon 尚未把本过滤器接入代理数据通路——此处仅提供库函数与单元测试，
//! 并不构成运行时防护的安全声明。

/// Recognized text protocols
#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    IRC,     // RFC 1459 / RFC 2812 — \r\n terminated, ASCII text
    BBS,     // Simple text posts — UTF-8, {topic, body} JSON or plain text
    Unknown, // Unknown but valid UTF-8 text
}

/// Why a message was rejected
#[derive(Debug, Clone)]
pub enum RejectReason {
    TooLarge { size: usize, max: usize },
    NotText,
    BinaryDetected,
}

/// Protocol filter configuration
pub struct ProtocolFilter {
    pub max_message_bytes: usize,
    pub allow_irc: bool,
    pub allow_bbs: bool,
    pub allow_unknown_text: bool,
}

impl Default for ProtocolFilter {
    fn default() -> Self {
        Self {
            max_message_bytes: 8192,
            allow_irc: true,
            allow_bbs: true,
            allow_unknown_text: false, // strict by default
        }
    }
}

impl ProtocolFilter {
    /// Check if a message passes the filter.
    /// Returns Ok(Protocol) if allowed, Err(RejectReason) if blocked.
    pub fn check(&self, data: &[u8]) -> Result<Protocol, RejectReason> {
        // Size check
        if data.len() > self.max_message_bytes {
            return Err(RejectReason::TooLarge {
                size: data.len(),
                max: self.max_message_bytes,
            });
        }

        // Must be valid UTF-8
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return Err(RejectReason::NotText),
        };

        // Check for binary content (control chars except \r\n\t)
        if contains_binary(text) {
            return Err(RejectReason::BinaryDetected);
        }

        // Detect protocol
        if self.allow_irc && looks_like_irc(text) {
            return Ok(Protocol::IRC);
        }
        if self.allow_bbs && looks_like_bbs(text) {
            return Ok(Protocol::BBS);
        }
        if self.allow_unknown_text {
            return Ok(Protocol::Unknown);
        }

        // Default: reject unknown protocol
        Err(RejectReason::NotText)
    }
}

/// Check for binary content — reject null bytes and non-printable chars
/// (except common whitespace: \r, \n, \t)
fn contains_binary(text: &str) -> bool {
    text.bytes().any(|b| {
        b == 0x00 // null
        || (b < 0x20 && b != b'\r' && b != b'\n' && b != b'\t') // control chars
        || b == 0x7F // DEL
    })
}

/// Heuristic: IRC messages end with \r\n and start with known IRC verbs or ':'
fn looks_like_irc(text: &str) -> bool {
    let text = text.trim_end_matches(&['\r', '\n'][..]);
    if text.len() < 3 {
        return false;
    }

    // IRC commands: PRIVMSG, JOIN, PART, NICK, USER, PING, PONG, QUIT, NOTICE, MODE, TOPIC, KICK
    let irc_verbs = [
        "PRIVMSG", "JOIN", "PART", "NICK", "USER", "PING", "PONG", "QUIT", "NOTICE", "MODE",
        "TOPIC", "KICK", "INVITE", "WHOIS",
    ];

    let upper = text.to_uppercase();
    for verb in &irc_verbs {
        if upper.starts_with(verb) || upper.starts_with(&format!(":{}", verb)) {
            return true;
        }
    }
    // Also accept server numerics (3 digits)
    if text
        .get(..3)
        .is_some_and(|s| s.chars().all(|c| c.is_ascii_digit()))
    {
        return true;
    }
    false
}

/// Heuristic: BBS messages are JSON objects with topic/body fields, or plain text
fn looks_like_bbs(text: &str) -> bool {
    // JSON BBS post
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(text) {
        if obj.is_object()
            && (obj.get("topic").is_some()
                || obj.get("body").is_some()
                || obj.get("title").is_some())
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irc_privmsg_passes() {
        let filter = ProtocolFilter::default();
        let result = filter.check(b"PRIVMSG #channel :hello world\r\n");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Protocol::IRC);
    }

    #[test]
    fn test_irc_join_passes() {
        let filter = ProtocolFilter::default();
        let result = filter.check(b"JOIN #room\r\n");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Protocol::IRC);
    }

    #[test]
    fn test_binary_rejected() {
        let filter = ProtocolFilter::default();
        let data = [0x00, 0x01, 0x02, 0x03];
        assert!(filter.check(&data).is_err());
    }

    #[test]
    fn test_oversized_rejected() {
        let filter = ProtocolFilter::default();
        let data = vec![b'a'; 10000];
        match filter.check(&data) {
            Err(RejectReason::TooLarge { size, max: 8192 }) => {
                assert_eq!(size, 10000);
            }
            other => panic!("Expected TooLarge, got {:?}", other),
        }
    }

    #[test]
    fn test_bbs_json_passes() {
        let filter = ProtocolFilter::default();
        let msg = r#"{"topic":"Welcome","body":"Hello everyone!"}"#;
        let result = filter.check(msg.as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Protocol::BBS);
    }

    #[test]
    fn test_control_chars_rejected() {
        let filter = ProtocolFilter::default();
        let msg = [b'A', b'B', 0x01, b'C']; // SOH control char
        assert!(filter.check(&msg).is_err());
    }

    #[test]
    fn test_unknown_text_rejected_by_default() {
        let filter = ProtocolFilter::default();
        let result = filter.check(b"This is just random text");
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_text_allowed_when_enabled() {
        let filter = ProtocolFilter {
            allow_unknown_text: true,
            ..Default::default()
        };
        let result = filter.check(b"random text data");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Protocol::Unknown);
    }

    #[test]
    fn test_looks_like_irc_multibyte_no_panic() {
        // 两个 e 加重音字符（4 字节）：text[..3] 会落在非字符边界并 panic。
        assert!(!looks_like_irc("éé"));
    }

    #[test]
    fn test_looks_like_irc_numeric_returns_true() {
        assert!(looks_like_irc("123 example"));
    }
}
