//! Pluggable transport layer (v7.2 M1-M4)
//!
//! Supports: Direct TCP, Tor SOCKS5, obfs4 bridge (via Tor), WebTunnel
//! Config persisted to ~/.chrono/config/transport.json
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

/// Transport mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum Transport {
    /// Direct TCP (default)
    #[default]
    Direct,
    /// Tor SOCKS5 proxy
    Tor { socks5_addr: String },
    /// obfs4 bridge (used with Tor)
    Obfs4 {
        bridge_line: String,
        socks5_addr: String,
    },
    /// WebTunnel bridge
    WebTunnel { url: String, socks5_addr: String },
}

impl Transport {
    pub fn name(&self) -> &str {
        match self {
            Transport::Direct => "direct",
            Transport::Tor { .. } => "tor",
            Transport::Obfs4 { .. } => "obfs4",
            Transport::WebTunnel { .. } => "webtunnel",
        }
    }

    pub fn description(&self) -> String {
        match self {
            Transport::Direct => "Direct TCP".to_string(),
            Transport::Tor { socks5_addr } => format!("Tor SOCKS5 → {}", socks5_addr),
            Transport::Obfs4 {
                bridge_line,
                socks5_addr,
            } => format!("obfs4 → {} (via {})", bridge_line, socks5_addr),
            Transport::WebTunnel { url, socks5_addr } => {
                format!("WebTunnel → {} (via {})", url, socks5_addr)
            }
        }
    }
}

/// Global transport config (thread-safe)
static TRANSPORT: Mutex<Option<TransportConfig>> = Mutex::new(None);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub transport: Transport,
    pub data_dir: String,
}

pub fn get_transport() -> Transport {
    TRANSPORT
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| c.transport.clone())
        .unwrap_or_default()
}

pub fn set_transport(t: Transport, data_dir: &str) {
    let config = TransportConfig {
        transport: t,
        data_dir: data_dir.to_string(),
    };
    let path = PathBuf::from(data_dir)
        .join("config")
        .join("transport.json");
    fs::create_dir_all(path.parent().unwrap()).ok();
    if let Ok(json) = serde_json::to_string_pretty(&config) {
        fs::write(&path, json).ok();
    }
    *TRANSPORT.lock().unwrap() = Some(config);
}

pub fn load_transport(data_dir: &str) -> Transport {
    let path = PathBuf::from(data_dir)
        .join("config")
        .join("transport.json");
    if let Ok(json) = fs::read_to_string(&path) {
        if let Ok(config) = serde_json::from_str::<TransportConfig>(&json) {
            let transport = config.transport.clone();
            *TRANSPORT.lock().unwrap() = Some(config);
            return transport;
        }
    }
    Transport::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_default() {
        assert_eq!(Transport::default(), Transport::Direct);
        assert_eq!(Transport::default().name(), "direct");
    }

    #[test]
    fn test_transport_serialize() {
        let t = Transport::Tor {
            socks5_addr: "127.0.0.1:9050".into(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let parsed: Transport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name(), "tor");
    }

    #[test]
    fn test_transport_persist() {
        let tmp = std::env::temp_dir().join("chrono_test_transport");
        set_transport(
            Transport::Obfs4 {
                bridge_line: "obfs4 1.2.3.4:443 KEY".into(),
                socks5_addr: "127.0.0.1:9050".into(),
            },
            tmp.to_str().unwrap(),
        );
        let loaded = load_transport(tmp.to_str().unwrap());
        assert_eq!(loaded.name(), "obfs4");
        std::fs::remove_dir_all(tmp).ok();
    }
}
