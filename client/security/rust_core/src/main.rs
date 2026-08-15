//! Chrono-shift Daemon v0.0.8.3 — DC-Net P2P Anonymous Proxy
//!
//! Single binary: authenticated-encrypted network, DC-Net round engine,
//! relay admission, web console at :10888.

use chrono_core::app::AppState;
use chrono_core::net::connection_manager::ConnectionManager;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // --port <n>: TCP listen port (default 9000).
    let mut args = std::env::args().skip(1);
    let mut port: u16 = 9000;
    while let Some(a) = args.next() {
        if a == "--port" {
            if let Some(v) = args.next() {
                if let Ok(p) = v.parse() {
                    port = p;
                }
            }
        }
    }

    let data_dir = "./data";
    let pid = std::process::id();
    let start = Instant::now();
    let state = AppState::new_with_port(data_dir, port);
    let shared = state.shared();

    // Spawn network tasks.
    let listen_port = {
        let mut s = shared.lock().unwrap();
        let incoming_tx = s.incoming_tx.clone();
        let conn = s.connection_manager.clone();
        let port = conn.lock().unwrap().listen_port;
        if let Some(outgoing_rx) = s.take_outgoing_rx() {
            // Session auth material: live uid + identity key.
            let public_hex = s.identity.public_hex().to_string();
            let signing_key = match s.identity.signing_key() {
                Some(k) => k,
                None => {
                    eprintln!("[!] Identity key invalid — cannot start listener");
                    std::process::exit(1);
                }
            };
            let uid_shared = s.uid_shared.clone();
            let active_conns = conn.lock().unwrap().active_connections.clone();
            let known_keys = conn.lock().unwrap().known_peer_keys.clone();
            tokio::spawn(async move {
                ConnectionManager::start_listener(
                    port,
                    active_conns,
                    incoming_tx,
                    public_hex,
                    signing_key,
                    uid_shared,
                    known_keys,
                )
                .await;
            });
            // P1 fix: the pump holds ONLY the ConnectionManager Arc —
            // holding AppState here deadlocked shutdown.
            let pump_conn = conn.clone();
            tokio::spawn(async move {
                outgoing_pump(outgoing_rx, pump_conn).await;
            });
        }
        port
    };

    // Incoming message pump: routes round traffic into RoundEngine and
    // relay traffic into AppState's verified relay path.
    let incoming_shared = shared.clone();
    let incoming_rx = shared.lock().unwrap().incoming_rx.clone();
    tokio::spawn(async move {
        incoming_pump(incoming_rx, incoming_shared).await;
    });

    log::info!("TCP listener on port {}", listen_port);

    // Heartbeat
    let hb_shared = shared.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let _ = hb_shared;
        }
    });

    // Start Web console
    chrono_core::web::start_web_console(shared.clone(), 10888, pid, start);

    println!("chrono-daemon v0.0.8.3 started");
    println!("  PID: {}", pid);

    // Block forever
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

async fn outgoing_pump(
    rx: std::sync::mpsc::Receiver<(String, chrono_core::net::tcp::PeerMessage)>,
    conn: Arc<Mutex<ConnectionManager>>,
) {
    tokio::task::spawn_blocking(move || {
        while let Ok((uid, msg)) = rx.recv() {
            if let Ok(cm) = conn.lock() {
                if let Err(e) = cm.send_to(&uid, &msg) {
                    log::debug!("Failed to send to {}: {}", uid, e);
                }
            }
        }
        log::info!("Outgoing pump stopped");
    })
    .await
    .ok();
}

async fn incoming_pump(
    rx: Arc<Mutex<std::sync::mpsc::Receiver<(String, chrono_core::net::tcp::PeerMessage)>>>,
    shared: Arc<Mutex<AppState>>,
) {
    loop {
        let msg = rx.lock().unwrap().try_recv().ok();
        if let Some((from_uid, peer_msg)) = msg {
            // P4: relay traffic has its own verified path.
            if matches!(
                peer_msg,
                chrono_core::net::tcp::PeerMessage::RelayRequest { .. }
                    | chrono_core::net::tcp::PeerMessage::RelayResponse { .. }
            ) {
                let events = {
                    let mut s = shared.lock().unwrap();
                    s.handle_relay_message(&peer_msg)
                };
                for e in events {
                    if let Ok(s) = shared.lock() {
                        s.emit(e);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            let (event, outgoing) = {
                // NOTE: never await while the AppState guard is alive
                // (the spawned future must stay Send).
                let mut s = shared.lock().unwrap();
                let my_uid = s.identity.uid.clone();
                let signing_key = s.identity.signing_key();
                let edge_keys = s.bridge.edge_key_map();
                let known_keys = s
                    .connection_manager
                    .lock()
                    .ok()
                    .and_then(|cm| cm.known_peer_keys.lock().ok().map(|m| m.clone()))
                    .unwrap_or_default();
                match signing_key {
                    Some(signing_key) => {
                        let ctx = chrono_core::dcnet::round_driver::RoundContext {
                            my_uid: &my_uid,
                            signing_key: &signing_key,
                            edge_keys: &edge_keys,
                            known_keys: &known_keys,
                        };
                        s.round_engine.handle_incoming(&peer_msg, &ctx)
                    }
                    None => (None, vec![]),
                }
            };
            if let Some(event) = event {
                log::info!("RoundEvent: {:?} from {}", event, from_uid);
            }
            for (target, msg) in outgoing {
                let s = shared.lock().unwrap();
                let _ = s.outgoing_tx.send((target, msg));
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
