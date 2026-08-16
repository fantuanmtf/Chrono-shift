//! Web Console (v8.1 — Phase 2)
//!
//! Embedded HTTP server at 127.0.0.1:10888.
//! Serves a single-page control panel (like I2P router console).
//! API endpoints return JSON for status, peers, services.

use crate::app::AppState;
use crate::net::connection_manager::ConnectionManager;
use rand::rngs::OsRng;
use rand::RngCore;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const INDEX_HTML: &str = include_str!("../static/index.html");

/// 请求行长度上限（超限直接断开）。
const MAX_REQUEST_LINE: usize = 8192;
/// 单个头行长度上限。
const MAX_HEADER_LINE: usize = 2048;
/// 全部头字节上限。
const MAX_HEADER_BYTES: usize = 16384;
/// POST body 上限。
const MAX_BODY_BYTES: usize = 65536;
/// 连接读超时（防慢速连接挂起线程）。
const READ_TIMEOUT_SECS: u64 = 10;
/// 单请求总时限（防慢速攻击）。
const REQUEST_TOTAL_TIMEOUT_SECS: u64 = 30;
/// 全局并发连接上限（防线程耗尽）。
const MAX_WEB_CONNS: usize = 64;

/// 所有响应统一附加的安全头。
/// 注意: index.html 目前内联 JS/CSS，CSP 不能禁 unsafe-inline。
const SECURITY_HEADERS: &str = "X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:\r\n";

pub fn start_web_console(state: Arc<Mutex<AppState>>, port: u16, pid: u32, start: Instant) {
    // B1: 读取或生成 Web console 访问令牌（文件: data_dir/keys/web_token）。
    let data_dir = match state.lock() {
        Ok(s) => s.data_dir.clone(),
        Err(_) => {
            log::error!("Web console: state lock poisoned; refusing to start");
            return;
        }
    };
    let token_path = data_dir.join("keys").join("web_token");
    let token = match std::fs::read_to_string(&token_path) {
        Ok(existing) => {
            let trimmed = existing.trim().to_string();
            if trimmed.is_empty() {
                generate_web_token(&token_path)
            } else {
                trimmed
            }
        }
        Err(_) => generate_web_token(&token_path),
    };
    // 仅记录令牌文件路径，绝不记录令牌明文。
    log::info!("Web console token file: {}", token_path.display());

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

    let active = Arc::new(AtomicUsize::new(0));
    let token = Arc::new(token);

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            // B5: 并发上限，超限直接 503 并关闭。
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_WEB_CONNS {
                active.fetch_sub(1, Ordering::SeqCst);
                let mut s = stream;
                let _ = s.write_all(
                    b"HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                continue;
            }
            let state = state.clone();
            let active = active.clone();
            let token = token.clone();
            std::thread::spawn(move || handle_http(stream, state, pid, start, token, active));
        }
    });
}

/// 生成 32 随机字节并 hex 编码；写入 0600 文件失败时回退为仅内存令牌。
fn generate_web_token(path: &Path) -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = hex::encode(bytes);
    if let Err(e) = crate::identity::write_private_file(path, &token) {
        log::error!(
            "Web console: failed to persist token to {} ({}); using in-memory token only",
            path.display(),
            e
        );
    }
    token
}

fn handle_http(
    mut stream: TcpStream,
    state: Arc<Mutex<AppState>>,
    pid: u32,
    start: Instant,
    token: Arc<String>,
    active: Arc<AtomicUsize>,
) {
    // B5: 连接结束（含提前 return）时递减并发计数。
    struct ConnGuard(Arc<AtomicUsize>);
    impl Drop for ConnGuard {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let _guard = ConnGuard(active);
    let request_start = Instant::now();

    // 读超时: 慢速连接不会永久挂起线程。
    let _ = stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(reader_stream);

    // 请求行（限长）。
    let mut request_line = String::new();
    if !read_limited_line(&mut reader, &mut request_line, MAX_REQUEST_LINE).unwrap_or(false) {
        return;
    }
    if request_start.elapsed() > Duration::from_secs(REQUEST_TOTAL_TIMEOUT_SECS) {
        return;
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    // 头: 限单行长度 + 总长度，解析 Content-Length/Authorization/Host/Origin/Content-Type。
    let mut content_length: usize = 0;
    let mut authorization: Option<String> = None;
    let mut host: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut content_type: Option<String> = None;
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        match read_limited_line(&mut reader, &mut line, MAX_HEADER_LINE) {
            Ok(true) => {}
            _ => return,
        }
        // B5: 每次读行后检查总时限。
        if request_start.elapsed() > Duration::from_secs(REQUEST_TOTAL_TIMEOUT_SECS) {
            return;
        }
        header_bytes += line.len();
        if header_bytes > MAX_HEADER_BYTES {
            return;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        let lower = trimmed.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0).min(MAX_BODY_BYTES);
        } else if let Some(v) = lower.strip_prefix("authorization:") {
            authorization = Some(v.trim().to_string());
        } else if let Some(v) = lower.strip_prefix("host:") {
            host = Some(v.trim().to_string());
        } else if let Some(v) = lower.strip_prefix("origin:") {
            origin = Some(v.trim().to_string());
        } else if let Some(v) = lower.strip_prefix("content-type:") {
            content_type = Some(v.trim().to_string());
        }
    }

    // B2: Host 校验（缺失放行）。
    if let Some(h) = host.as_deref() {
        if !host_allowed(h) {
            write_response(&mut stream, "403 Forbidden", "text/plain", "", "403");
            return;
        }
    }
    // B2: Origin 校验（缺失放行）。
    if let Some(o) = origin.as_deref() {
        if !origin_allowed(o) {
            write_response(&mut stream, "403 Forbidden", "text/plain", "", "403");
            return;
        }
    }
    // B2: POST /api/connect 额外要求 application/json。
    // no-cors 简单请求只能发 text/plain 等，此处是双保险。
    if method == "POST"
        && path == "/api/connect"
        && !content_type.as_deref().is_some_and(ct_allows_json)
    {
        write_response(
            &mut stream,
            "415 Unsupported Media Type",
            "application/json",
            "Cache-Control: no-store\r\n",
            r#"{"error":"unsupported media type"}"#,
        );
        return;
    }

    // body: 按 Content-Length 精确读取（上限 64KB）。
    let mut body = String::new();
    if method == "POST" && content_length > 0 {
        let mut buf = vec![0u8; content_length];
        if reader.read_exact(&mut buf).is_err() {
            return;
        }
        body = String::from_utf8_lossy(&buf).to_string();
    }

    let (status, response_ct, response) = route(
        method,
        path,
        &body,
        &state,
        pid,
        start,
        token.as_str(),
        authorization.as_deref(),
    );

    // B3: 安全头统一附加；api 响应加 Cache-Control: no-store；401 加 WWW-Authenticate。
    let mut extra = String::new();
    if path.starts_with("/api/") {
        extra.push_str("Cache-Control: no-store\r\n");
    }
    if status == "401 Unauthorized" {
        extra.push_str("WWW-Authenticate: Bearer\r\n");
    }
    write_response(&mut stream, status, response_ct, &extra, &response);
}

/// 统一写入响应（含安全头）。
fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    extra_headers: &str,
    body: &str,
) {
    let resp = format!(
        "HTTP/1.0 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n{}{}\r\n{}",
        status,
        content_type,
        body.len(),
        SECURITY_HEADERS,
        extra_headers,
        body
    );
    let _ = stream.write_all(resp.as_bytes());
}

/// 读取一行, 超过 max 字节返回 Err(InvalidData)（连接随后被关闭）。
/// 返回 Ok(false) 表示 EOF。
fn read_limited_line<R: BufRead>(r: &mut R, out: &mut String, max: usize) -> std::io::Result<bool> {
    let mut limited = r.take((max + 1) as u64);
    let mut buf = Vec::new();
    let n = limited.read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(false);
    }
    if n > max {
        return Err(std::io::Error::new(ErrorKind::InvalidData, "line too long"));
    }
    out.push_str(&String::from_utf8_lossy(&buf));
    Ok(true)
}

/// 从 Authorization 头提取 Bearer 令牌（scheme 大小写不敏感）。
fn bearer_token(authorization: Option<&str>) -> Option<&str> {
    let header = authorization?;
    let mut parts = header.trim().splitn(2, ' ');
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = parts.next()?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// 常量时间比较请求令牌与期望令牌。
fn token_authorized(expected: &str, authorization: Option<&str>) -> bool {
    match bearer_token(authorization) {
        Some(provided) => crate::crypto::constant_time_eq(expected.as_bytes(), provided.as_bytes()),
        None => false,
    }
}

/// DNS rebinding 防护: Host 头只允许环回地址。
fn host_allowed(host: &str) -> bool {
    matches!(
        host,
        "127.0.0.1" | "127.0.0.1:10888" | "localhost" | "localhost:10888" | "[::1]" | "[::1]:10888"
    )
}

/// DNS rebinding 防护: Origin 头只允许本机控制台来源。
fn origin_allowed(origin: &str) -> bool {
    matches!(
        origin,
        "http://127.0.0.1:10888" | "http://localhost:10888" | "http://[::1]:10888"
    )
}

/// 是否以 application/json 开头（大小写不敏感）。
fn ct_allows_json(ct: &str) -> bool {
    ct.trim()
        .to_ascii_lowercase()
        .starts_with("application/json")
}

// 参数较多但同属一个路由分发函数；合并会降低可读性。
#[allow(clippy::too_many_arguments)]
fn route(
    method: &str,
    path: &str,
    body: &str,
    state: &Arc<Mutex<AppState>>,
    pid: u32,
    start: Instant,
    token: &str,
    authorization: Option<&str>,
) -> (&'static str, &'static str, String) {
    // B1: /api/* 需要 Bearer 令牌。
    if path.starts_with("/api/") && !token_authorized(token, authorization) {
        return (
            "401 Unauthorized",
            "application/json",
            r#"{"error":"unauthorized"}"#.to_string(),
        );
    }

    match (method, path) {
        // Web console
        ("GET", "/") => ("200 OK", "text/html; charset=utf-8", INDEX_HTML.to_string()),

        // API: status
        ("GET", "/api/status") => {
            let s = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return (
                        "500",
                        "application/json",
                        r#"{"error":"state poisoned"}"#.to_string(),
                    )
                }
            };
            let uptime = start.elapsed().as_secs();
            let conns = s
                .connection_manager
                .lock()
                .map(|cm| cm.connected_count())
                .unwrap_or(0);
            let json = format!(
                r#"{{"pid":{},"uptime_secs":{},"connections":{},"version":"0.0.9","tests":164}}"#,
                pid, uptime, conns
            );
            ("200 OK", "application/json", json)
        }

        // API: peers
        ("GET", "/api/peers") => {
            let s = match state.lock() {
                Ok(s) => s,
                Err(_) => {
                    return (
                        "500",
                        "application/json",
                        r#"{"error":"state poisoned"}"#.to_string(),
                    )
                }
            };
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
                // B4: uid 校验（默认值 "peer" 合法）。
                if !crate::validate_uid(uid) {
                    return (
                        "400",
                        "application/json",
                        r#"{"error":"invalid uid"}"#.to_string(),
                    );
                }
                match addr.parse::<std::net::SocketAddr>() {
                    Ok(socket) => {
                        let (conn, incoming, auth) = {
                            let s = match state.lock() {
                                Ok(s) => s,
                                Err(_) => {
                                    return (
                                        "500",
                                        "application/json",
                                        r#"{"error":"state poisoned"}"#.to_string(),
                                    )
                                }
                            };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_allowed() {
        assert!(host_allowed("127.0.0.1"));
        assert!(host_allowed("127.0.0.1:10888"));
        assert!(host_allowed("localhost"));
        assert!(host_allowed("localhost:10888"));
        assert!(host_allowed("[::1]"));
        assert!(host_allowed("[::1]:10888"));
        assert!(!host_allowed("evil.com"));
        assert!(!host_allowed("evil.com:10888"));
        assert!(!host_allowed("127.0.0.1:9999"));
        assert!(!host_allowed(""));
    }

    #[test]
    fn test_origin_allowed() {
        assert!(origin_allowed("http://127.0.0.1:10888"));
        assert!(origin_allowed("http://localhost:10888"));
        assert!(origin_allowed("http://[::1]:10888"));
        assert!(!origin_allowed("http://evil.com"));
        assert!(!origin_allowed("null"));
        assert!(!origin_allowed("https://127.0.0.1:10888"));
        assert!(!origin_allowed(""));
    }

    #[test]
    fn test_ct_allows_json() {
        assert!(ct_allows_json("application/json"));
        assert!(ct_allows_json("application/json; charset=utf-8"));
        assert!(ct_allows_json("Application/JSON"));
        assert!(!ct_allows_json("text/plain"));
        assert!(!ct_allows_json("application/xml"));
        assert!(!ct_allows_json(""));
    }

    #[test]
    fn test_bearer_token() {
        assert_eq!(bearer_token(Some("Bearer abc123")), Some("abc123"));
        assert_eq!(bearer_token(Some("bearer abc123")), Some("abc123"));
        assert_eq!(bearer_token(Some("Bearer  abc  ")), Some("abc"));
        assert_eq!(bearer_token(Some("Basic abc")), None);
        assert_eq!(bearer_token(Some("Bearer")), None);
        assert_eq!(bearer_token(Some("Bearer ")), None);
        assert_eq!(bearer_token(None), None);
    }

    #[test]
    fn test_token_authorized() {
        assert!(token_authorized("secret", Some("Bearer secret")));
        assert!(!token_authorized("secret", Some("Bearer wrong")));
        assert!(!token_authorized("secret", None));
        assert!(!token_authorized("secret", Some("Basic secret")));
        assert!(!token_authorized("", Some("Bearer secret")));
    }

    #[test]
    fn test_route_auth_and_uid_rejection() {
        let tmp = std::env::temp_dir().join(format!("chrono_test_web_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let state = Arc::new(Mutex::new(AppState::new(tmp.to_str().unwrap())));
        let start = Instant::now();

        // 缺失令牌 → 401。
        let (status, _, _) = route("GET", "/api/status", "", &state, 0, start, "tok", None);
        assert_eq!(status, "401 Unauthorized");
        // 错误令牌 → 401。
        let (status, _, _) = route(
            "GET",
            "/api/status",
            "",
            &state,
            0,
            start,
            "tok",
            Some("Bearer wrong"),
        );
        assert_eq!(status, "401 Unauthorized");
        // 非法 uid → 400（带正确令牌）。
        let body = r#"{"addr":"127.0.0.1:9000","uid":"名字"}"#;
        let (status, _, _) = route(
            "POST",
            "/api/connect",
            body,
            &state,
            0,
            start,
            "tok",
            Some("Bearer tok"),
        );
        assert_eq!(status, "400");

        drop(state);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
