//! Web Console (v8.1 — Phase 2)
//!
//! Embedded HTTP server at 127.0.0.1:7657.
//! Serves a single-page control panel (like I2P router console).
//! API endpoints return JSON for status, peers, services.

use crate::app::AppState;
use crate::net::connection_manager::ConnectionManager;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const INDEX_HTML: &str = include_str!("../static/index.html");

pub fn start_web_console(state: Arc<Mutex<AppState>>, port: u16, pid: u32, start: Instant) {
    let addr = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            log::error!("Web console bind failed: {}", e);
            return;
        }
    };
    log::info!("Web console: http://{}", addr);
    println!("  Web console: http://{}", addr);

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let state = state.clone();
            std::thread::spawn(move || handle_http(stream, state, pid, start));
        }
    });
}

fn handle_http(mut stream: TcpStream, state: Arc<Mutex<AppState>>, pid: u32, start: Instant) {
    let mut reader = BufReader::new(stream.try_clone().unwrap_or_else(|_| {
        // fallback: can't clone, just return empty
        panic!("stream clone failed")
    }));

    // Read request line
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() {
        return;
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    // Read headers (skip)
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line == "\r\n" || line == "\n" || line.is_empty()
        {
            break;
        }
    }

    // Read body for POST
    let mut body = String::new();
    if method == "POST" {
        // Try to read content-length worth of data
        let _ = reader.read_to_string(&mut body);
    }

    let (status, content_type, response) = route(method, path, &body, &state, pid, start);

    let resp = format!(
        "HTTP/1.0 {} \r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        status,
        content_type,
        response.len(),
        response
    );
    stream.write_all(resp.as_bytes()).ok();
}

fn route(
    method: &str,
    path: &str,
    body: &str,
    state: &Arc<Mutex<AppState>>,
    pid: u32,
    start: Instant,
) -> (&'static str, &'static str, String) {
    match (method, path) {
        // Web console
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", INDEX_HTML.to_string()),

        // API: status
        ("GET", "/api/status") => {
            let s = state.lock().unwrap();
            let uptime = start.elapsed().as_secs();
            let conns = s
                .connection_manager
                .lock()
                .map(|cm| cm.connected_count())
                .unwrap_or(0);
            let json = format!(
                r#"{{"pid":{},"uptime_secs":{},"connections":{},"version":"0.0.8.2","tests":131}}"#,
                pid, uptime, conns
            );
            ("200 OK", "application/json", json)
        }

        // API: peers
        ("GET", "/api/peers") => {
            let s = state.lock().unwrap();
            let peers: Vec<String> = s
                .connection_manager
                .lock()
                .ok()
                .and_then(|cm| {
                    cm.active_connections
                        .lock()
                        .ok()
                        .map(|conns| conns.keys().cloned().collect::<Vec<_>>())
                })
                .unwrap_or_default();
            let json = format!(
                r#"{{"peers":{}}}"#,
                serde_json::to_string(&peers).unwrap_or_default()
            );
            ("200 OK", "application/json", json)
        }

        // API: services
        ("GET", "/api/services") => {
            let json = r#"{"services":[]}"#.to_string();
            ("200 OK", "application/json", json)
        }

        // API: connect — spawns the async authenticated-encrypted connect.
        ("POST", "/api/connect") => {
            if let Ok(req) = serde_json::from_str::<serde_json::Value>(body) {
                let addr = req["addr"].as_str().unwrap_or("");
                let uid = req["uid"].as_str().unwrap_or("peer");
                match addr.parse::<std::net::SocketAddr>() {
                    Ok(socket) => {
                        let (conn, incoming, auth) = {
                            let s = state.lock().unwrap();
                            let auth = match s.identity.signing_key() {
                                Some(signing_key) => crate::net::session::SessionAuth {
                                    uid: s.identity.uid.clone(),
                                    public_hex: s.identity.public_hex().to_string(),
                                    signing_key,
                                },
                                None => {
                                    return (
                                        "500",
                                        "application/json",
                                        r#"{"error":"no identity key"}"#.to_string(),
                                    )
                                }
                            };
                            (s.connection_manager.clone(), s.incoming_tx.clone(), auth)
                        };
                        let uid_owned = uid.to_string();
                        if let Ok(handle) = tokio::runtime::Handle::try_current() {
                            handle.spawn(async move {
                                let (active, known_keys) = match conn.lock() {
                                    Ok(cm) => {
                                        (cm.active_connections.clone(), cm.known_peer_keys.clone())
                                    }
                                    Err(_) => return,
                                };
                                let mut attempts = 0u32;
                                loop {
                                    match ConnectionManager::connect_to_peer(
                                        active.clone(),
                                        known_keys.clone(),
                                        &uid_owned,
                                        socket,
                                        &auth,
                                        incoming.clone(),
                                    )
                                    .await
                                    {
                                        Ok(()) => {
                                            log::info!("Web console: connected to {}", uid_owned);
                                            break;
                                        }
                                        Err(e) => {
                                            attempts += 1;
                                            if attempts >= 5 {
                                                log::warn!(
                                                    "Web connect to {} failed: {}",
                                                    uid_owned,
                                                    e
                                                );
                                                break;
                                            }
                                            tokio::time::sleep(std::time::Duration::from_secs(1))
                                                .await;
                                        }
                                    }
                                }
                            });
                            (
                                "200 OK",
                                "application/json",
                                r#"{"status":"connecting"}"#.to_string(),
                            )
                        } else {
                            (
                                "500",
                                "application/json",
                                r#"{"error":"no runtime"}"#.to_string(),
                            )
                        }
                    }
                    Err(e) => ("400", "application/json", format!(r#"{{"error":"{}"}}"#, e)),
                }
            } else {
                (
                    "400",
                    "application/json",
                    r#"{"error":"invalid json"}"#.to_string(),
                )
            }
        }

        // Default: 404
        _ => ("404 Not Found", "text/plain", "404".to_string()),
    }
}
