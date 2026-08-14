//! LAN peer discovery via UDP broadcast (v7.1 S4)
//!
//! Simple: broadcast "CHRONO:uid:port" on UDP 9901, listen for peers.
//! No external crate needed — pure std.
use std::net::UdpSocket;
use std::time::Duration;

/// Discovered LAN peer
#[derive(Debug, Clone)]
pub struct LanPeer {
    pub uid: String,
    pub port: u16,
    pub addr: String, // "ip:port"
}

/// Broadcast discovery on LAN and collect responses for `timeout_ms`
pub fn discover_peers(port: u16, uid: &str, timeout_ms: u64) -> Vec<LanPeer> {
    let mut peers = Vec::new();

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return peers,
    };
    socket.set_broadcast(true).ok();
    socket
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();

    // Broadcast our presence
    let msg = format!("CHRONO:{}:{}", uid, port);
    socket.send_to(msg.as_bytes(), "255.255.255.255:9901").ok();

    // Listen for responses
    let mut buf = [0u8; 256];
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    while std::time::Instant::now() < deadline {
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                let data = String::from_utf8_lossy(&buf[..len]);
                if let Some(peer) = parse_announce(&data) {
                    if peer.uid != uid {
                        // Don't add self
                        peers.push(LanPeer {
                            uid: peer.uid.clone(),
                            port: peer.port,
                            addr: format!("{}:{}", src.ip(), peer.port),
                        });
                    }
                }
            }
            Err(_) => break, // timeout
        }
    }
    peers
}

fn parse_announce(data: &str) -> Option<LanPeer> {
    // Format: "CHRONO:uid:port"
    let parts: Vec<&str> = data.trim().split(':').collect();
    if parts.len() == 3 && parts[0] == "CHRONO" {
        let uid = parts[1].to_string();
        let port: u16 = parts[2].parse().ok()?;
        Some(LanPeer {
            uid,
            port,
            addr: format!("0.0.0.0:{}", port),
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_announce() {
        let peer = parse_announce("CHRONO:alice:9000").unwrap();
        assert_eq!(peer.uid, "alice");
    }

    #[test]
    fn test_parse_bad_data() {
        assert!(parse_announce("garbage").is_none());
    }
}
