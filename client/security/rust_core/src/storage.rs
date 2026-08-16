//! Persistent storage with Write-Ahead Log (v7.6 — Phase 1.4)
//!
//! WAL guarantees crash-safe persistence:
//!   1. Serialize operation → JSON
//!   2. Write to WAL file
//!   3. fsync / sync_all() force to disk
//!   4. Only then modify in-memory state
//!   5. On failure → return Err, memory state unchanged
//!
//! Checkpoint: every 100 ops or 60 seconds → full state snapshot → truncate WAL

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Maximum WAL size we will replay at startup (64 MiB). A log larger than
/// this is treated as corrupt/attacker-grown and skipped, falling back to
/// the last snapshot only.
const MAX_WAL_BYTES: u64 = 64 * 1024 * 1024;

/// WAL operation — each records a state mutation for replay
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum WalOperation {
    #[serde(rename = "add_friend")]
    AddFriend {
        uid: String,
        addr: String,
        trust: u8,
    },
    #[serde(rename = "remove_friend")]
    RemoveFriend { uid: String },
    #[serde(rename = "update_trust")]
    UpdateTrust { uid: String, trust: u8 },
    #[serde(rename = "create_channel")]
    CreateChannel { name: String },
    #[serde(rename = "join_channel")]
    JoinChannel { channel: String, uid: String },
    #[serde(rename = "leave_channel")]
    LeaveChannel { channel: String, uid: String },
    #[serde(rename = "create_network")]
    CreateNetwork { name: String, admin: String },
    #[serde(rename = "add_member")]
    AddMember { network: String, uid: String },
    #[serde(rename = "remove_member")]
    RemoveMember { network: String, uid: String },
    #[serde(rename = "set_uid")]
    SetUid { uid: String },
    #[serde(rename = "update_edge_key")]
    UpdateEdgeKey { uid: String, key_hex: String },
    #[serde(rename = "send_message")]
    SendMessage {
        from: String,
        to: String,
        text: String,
    },
}

/// Serializable snapshot of the social state (bridge) for WAL checkpoints.
/// Keep this free of any non-serializable fields (Arc/AtomicBool etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SocialSnapshot {
    pub uid: String,
    pub friends: Vec<FriendRecord>,
    pub channels: Vec<ChannelRecord>,
}

/// One friend edge in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendRecord {
    pub uid: String,
    pub addr: String,
    pub trust: u8,
    /// Offline-established edge PSK, hex-encoded. None = not yet set.
    pub edge_key_hex: Option<String>,
}

/// One channel in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRecord {
    pub name: String,
    pub topic: String,
    pub participants: Vec<String>,
}

/// Write-Ahead Log store
pub struct WalStore {
    log_path: PathBuf,
    state_path: PathBuf,
    wal_file: File,
    ops_since_checkpoint: u64,
    last_checkpoint: Instant,
    checkpoint_ops: u64,
    checkpoint_interval: Duration,
}

impl WalStore {
    /// Open or create the WAL at the given data directory
    pub fn open(data_dir: &Path, checkpoint_ops: u64) -> std::io::Result<Self> {
        let log_path = data_dir.join("wal.log");
        let state_path = data_dir.join("state.json");

        // Open WAL file in append mode (create if not exists).
        // P1 fix: create with owner-only permissions — wal.log may contain
        // edge-key material.
        let wal_file = {
            let mut opts = OpenOptions::new();
            opts.append(true);
            opts.create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(&log_path)?
        };

        Ok(Self {
            log_path,
            state_path,
            wal_file,
            ops_since_checkpoint: 0,
            last_checkpoint: Instant::now(),
            checkpoint_ops,
            checkpoint_interval: Duration::from_secs(60),
        })
    }

    /// Append one operation to the WAL.
    /// Returns Err if write or sync fails — caller must NOT modify memory state.
    pub fn append(&mut self, op: &WalOperation) -> std::io::Result<()> {
        let json = serde_json::to_string(op)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        // Write line: [timestamp_ms] [json]\n
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let line = format!("[{}] {}\n", ts, json);

        self.wal_file.write_all(line.as_bytes())?;
        self.wal_file.sync_all()?; // Force to disk before returning

        self.ops_since_checkpoint += 1;
        Ok(())
    }

    /// Replay all WAL entries to rebuild state.
    /// Called once at startup to recover from crashes.
    pub fn replay(&self) -> Vec<WalOperation> {
        let mut ops = Vec::new();
        // Bound the replay: skip a WAL that exceeds MAX_WAL_BYTES rather than
        // reading unbounded attacker-grown input. Trade-off: any valid ops
        // past the limit are lost and we fall back to the last snapshot only.
        if let Ok(meta) = fs::metadata(&self.log_path) {
            if meta.len() > MAX_WAL_BYTES {
                log::error!(
                    "WAL {} is {} bytes (over {} byte limit); skipping replay",
                    self.log_path.display(),
                    meta.len(),
                    MAX_WAL_BYTES
                );
                return ops;
            }
        }
        if let Ok(file) = File::open(&self.log_path) {
            let reader = BufReader::new(file);
            // map_while: stop at the first I/O error (flatten() could spin
            // forever if the underlying read keeps erroring).
            for line in reader.lines().map_while(Result::ok) {
                // Format: [timestamp] {"op":"add_friend",...}
                if let Some(brace_pos) = line.find('{') {
                    let json = &line[brace_pos..];
                    if let Ok(op) = serde_json::from_str::<WalOperation>(json) {
                        ops.push(op);
                    }
                }
            }
        }
        ops
    }

    /// Checkpoint: write full state snapshot, truncate WAL.
    /// Should be called when ops_since_checkpoint >= threshold or timer fires.
    ///
    /// FIX (audit HIGH): the old order was fs::write(state) then truncate(WAL)
    /// — non-atomic and un-synced, so a crash between the two steps (or a
    /// torn state write) lost BOTH the snapshot and the log. New order:
    ///   1. write snapshot to state.json.tmp and fsync it
    ///   2. atomically rename over state.json, fsync the directory
    ///   3. only then truncate + fsync the WAL
    pub fn checkpoint<S: Serialize>(&mut self, state: &S) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        // 1. Write snapshot to a temp file in the SAME directory (rename
        //    across filesystems is not atomic).
        let mut tmp_path = self.state_path.clone().into_os_string();
        tmp_path.push(".tmp");
        let tmp_path = PathBuf::from(tmp_path);
        {
            // P1: snapshot contains edge keys — create with owner-only perms.
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut tmp = opts.open(&tmp_path)?;
            tmp.write_all(json.as_bytes())?;
            tmp.sync_all()?;
        }

        // 2. Atomic replace + directory fsync to make the rename durable.
        // v8.1 port: on Windows, rename over an existing file can fail —
        // remove the target and retry before falling back to a direct write.
        let renamed = fs::rename(&tmp_path, &self.state_path);
        if renamed.is_err() {
            let _ = fs::remove_file(&self.state_path);
            if fs::rename(&tmp_path, &self.state_path).is_err() {
                // Fallback: direct write (rename over existing failed). This
                // path holds plaintext PSKs (edge keys), so create with
                // owner-only permissions and fsync instead of fs::write
                // (which would leave 0644 and skip the sync).
                crate::identity::write_private_file(&self.state_path, &json)?;
                let _ = fs::remove_file(&tmp_path);
            }
        }
        #[cfg(unix)]
        if let Some(dir) = self.state_path.parent() {
            if let Ok(d) = File::open(dir) {
                let _ = d.sync_all();
            }
        }

        // 3. Only now that a durable snapshot exists, clear the WAL.
        self.wal_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.log_path)?;
        self.wal_file.sync_all()?;

        self.ops_since_checkpoint = 0;
        self.last_checkpoint = Instant::now();
        Ok(())
    }

    /// Check if a checkpoint is due
    pub fn should_checkpoint(&self) -> bool {
        self.ops_since_checkpoint >= self.checkpoint_ops
            || self.last_checkpoint.elapsed() >= self.checkpoint_interval
    }

    /// Number of operations since last checkpoint
    pub fn ops_count(&self) -> u64 {
        self.ops_since_checkpoint
    }

    /// Time since last checkpoint
    pub fn time_since_checkpoint(&self) -> Duration {
        self.last_checkpoint.elapsed()
    }

    /// Load state from the last checkpoint snapshot
    pub fn load_state<S: for<'de> Deserialize<'de>>(&self) -> Option<S> {
        let json = fs::read_to_string(&self.state_path).ok()?;
        serde_json::from_str(&json).ok()
    }
}

// Legacy Storage struct retained for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SocialState {
    pub uid: String,
    pub addr: String,
    pub friends: Vec<FriendEntry>,
    pub messages: Vec<MessageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendEntry {
    pub uid: String,
    pub addr: String,
    pub trust_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEntry {
    pub from: String,
    pub to: String,
    pub text: String,
    pub ts: u64,
}

pub struct Storage {
    data_dir: PathBuf,
}

impl Storage {
    pub fn new(data_dir: &str) -> Self {
        let dir = PathBuf::from(data_dir);
        fs::create_dir_all(&dir).ok();
        Self { data_dir: dir }
    }
    pub fn save_social_state(&self, state: &SocialState) -> std::io::Result<()> {
        let path = self.data_dir.join("social_state.json");
        fs::write(path, serde_json::to_string_pretty(state)?)
    }
    pub fn load_social_state(&self) -> Option<SocialState> {
        let path = self.data_dir.join("social_state.json");
        let json = fs::read_to_string(path).ok()?;
        serde_json::from_str(&json).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load() {
        let tmp = std::env::temp_dir().join("chrono_test_s");
        let storage = Storage::new(tmp.to_str().unwrap());
        let state = SocialState {
            uid: "alice".into(),
            addr: "127.0.0.1:9000".into(),
            friends: vec![],
            messages: vec![],
        };
        storage.save_social_state(&state).unwrap();
        let loaded = storage.load_social_state().unwrap();
        assert_eq!(loaded.uid, "alice");
        std::fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_wal_append_and_replay() {
        let tmp = std::env::temp_dir().join("chrono_test_wal");
        fs::create_dir_all(&tmp).unwrap();

        let mut wal = WalStore::open(&tmp, 100).unwrap();
        wal.append(&WalOperation::SetUid {
            uid: "alice".into(),
        })
        .unwrap();
        wal.append(&WalOperation::AddFriend {
            uid: "bob".into(),
            addr: "127.0.0.1:9000".into(),
            trust: 1,
        })
        .unwrap();

        // Replay should recover both operations
        let ops = wal.replay();
        assert_eq!(ops.len(), 2);

        // Verify operation contents
        match &ops[0] {
            WalOperation::SetUid { uid } => assert_eq!(uid, "alice"),
            _ => panic!("Expected SetUid"),
        }
        match &ops[1] {
            WalOperation::AddFriend { uid, addr, trust } => {
                assert_eq!(uid, "bob");
                assert_eq!(addr, "127.0.0.1:9000");
                assert_eq!(*trust, 1);
            }
            _ => panic!("Expected AddFriend"),
        }

        // Cleanup
        drop(wal);
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_wal_checkpoint() {
        let tmp = std::env::temp_dir().join("chrono_test_wal_cp");
        fs::create_dir_all(&tmp).unwrap();

        let mut wal = WalStore::open(&tmp, 3).unwrap(); // checkpoint every 3 ops

        // Write 3 ops → should trigger checkpoint
        for i in 0..3 {
            wal.append(&WalOperation::SetUid {
                uid: format!("user{}", i),
            })
            .unwrap();
        }
        assert!(wal.should_checkpoint());

        // Checkpoint
        let state = SocialState {
            uid: "user2".into(),
            addr: "".into(),
            friends: vec![],
            messages: vec![],
        };
        wal.checkpoint(&state).unwrap();

        // After checkpoint, WAL should be empty
        assert_eq!(wal.ops_count(), 0);
        let ops = wal.replay();
        assert_eq!(ops.len(), 0);

        // State should be recoverable from checkpoint
        let loaded: SocialState = wal.load_state().unwrap();
        assert_eq!(loaded.uid, "user2");

        // Cleanup
        drop(wal);
        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_wal_crash_recovery() {
        let tmp = std::env::temp_dir().join("chrono_test_wal_crash");
        fs::create_dir_all(&tmp).unwrap();

        // Simulate: write ops, no checkpoint, "crash" (drop WalStore)
        {
            let mut wal = WalStore::open(&tmp, 100).unwrap();
            wal.append(&WalOperation::AddFriend {
                uid: "eve".into(),
                addr: "10.0.0.1:9000".into(),
                trust: 1,
            })
            .unwrap();
            wal.append(&WalOperation::CreateChannel {
                name: "#secret".into(),
            })
            .unwrap();
        } // "crash" — wal dropped without checkpoint

        // Recovery: replay WAL
        {
            let wal = WalStore::open(&tmp, 100).unwrap();
            let ops = wal.replay();
            assert_eq!(ops.len(), 2);
            match &ops[0] {
                WalOperation::AddFriend { uid, .. } => assert_eq!(uid, "eve"),
                _ => panic!("Expected AddFriend"),
            }
            match &ops[1] {
                WalOperation::CreateChannel { name } => assert_eq!(name, "#secret"),
                _ => panic!("Expected CreateChannel"),
            }
        }

        fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_wal_replay_skips_oversized() {
        let tmp = std::env::temp_dir().join("chrono_test_wal_oversize");
        fs::create_dir_all(&tmp).unwrap();

        {
            let mut wal = WalStore::open(&tmp, 100).unwrap();
            wal.append(&WalOperation::SetUid {
                uid: "alice".into(),
            })
            .unwrap();
            drop(wal);
            // Blow the WAL past MAX_WAL_BYTES (sparse file, no real 64 MiB).
            let f = File::create(tmp.join("wal.log")).unwrap();
            f.set_len(MAX_WAL_BYTES + 1).unwrap();
        }

        let wal = WalStore::open(&tmp, 100).unwrap();
        let ops = wal.replay();
        assert!(ops.is_empty(), "oversized WAL must be skipped");

        drop(wal);
        fs::remove_dir_all(&tmp).ok();
    }
}
