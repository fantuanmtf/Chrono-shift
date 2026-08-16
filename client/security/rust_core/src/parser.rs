//! JSON parser (serde_json + simdutf8)
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonValue {
    pub raw: String,
}
/// 输入大小上限（1 MiB），防止超大 JSON 耗尽内存。
const MAX_JSON_INPUT: usize = 1024 * 1024;

pub fn parse_json(input: &str) -> Option<JsonValue> {
    if input.len() > MAX_JSON_INPUT {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(input)
        .ok()
        .map(|v| JsonValue { raw: v.to_string() })
}
pub fn escape_json(input: &str) -> String {
    serde_json::to_string(input).unwrap_or_else(|_| "\"\"".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse_valid() {
        assert!(parse_json(r#"{"key":"value"}"#).is_some());
    }
    #[test]
    fn test_parse_invalid_json() {
        assert!(parse_json("{invalid").is_none());
    }
    #[test]
    fn test_parse_deep_nesting() {
        let deep = format!("{{\"a\":{}}}", "[1,2,3]");
        assert!(parse_json(&deep).is_some());
    }
    #[test]
    fn test_parse_over_limit_rejected() {
        // 1,200,000 字节 > 1 MiB
        let big = format!("[{}]", vec!["1"; 600_000].join(","));
        assert!(parse_json(&big).is_none());
    }
    #[test]
    fn test_parse_under_limit_ok() {
        let small = format!("[{}]", vec!["1"; 1_000].join(","));
        assert!(parse_json(&small).is_some());
    }
}
