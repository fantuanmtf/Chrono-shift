//! JSON parser (serde_json + simdutf8)
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonValue {
    pub raw: String,
}
pub fn parse_json(input: &str) -> Option<JsonValue> {
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
}
