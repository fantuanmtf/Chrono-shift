# Chrono-shift 全面代码审计报告

**审计日期**: 2026-06-04  
**审计范围**: `client/security/rust_core/src/` 全部源码 + Cargo.toml + tests/ + docs/  
**代码行数**: ~3,500 行 Rust (含注释), ~1,500 行测试脚本 (bash)  
**审计方法**: 逐文件阅读 + 自动化工具交叉验证 + 安全模型分析

---

## 目录

1. [安全漏洞（按严重程度排序）](#1-安全漏洞)
2. [代码质量问题（按类别排序）](#2-代码质量问题)
3. [功能完整性问题](#3-功能完整性问题)
4. [依赖与供应链](#4-依赖与供应链)
5. [测试覆盖与质量](#5-测试覆盖与质量)
6. [架构设计问题](#6-架构设计问题)
7. [问题汇总清单](#7-问题汇总清单)

---

## 1. 安全漏洞

### CRITICAL-1: FFI 层密钥缓冲区越界读取

**文件**: `ffi.rs:17-38`, `ffi.rs:40-64`  
**严重程度**: **严重** (CRITICAL)  
**类型**: 内存安全 — 缓冲区溢出

```rust
// rust_encrypt_e2e (line 25)
let mut karr = [0u8; 32];
unsafe { karr.copy_from_slice(std::slice::from_raw_parts(key, 32)) };
```

**问题**: 这两个函数检查了 `key.is_null()` 但**从未验证指针指向的内存是否>=32字节**。C 调用方传入一个不足 32 字节的缓冲区会导致越界读取（未定义行为），可能泄露栈/堆数据。

**建议**: 增加一个 `key_len: u32` 参数并验证 `key_len >= 32`，或使用 `std::slice::from_raw_parts(key, min(key_len, 32))`。

---

### CRITICAL-2: FFI 层 `safe_c_str` 生命周期造假

**文件**: `ffi.rs:181-186`  
**严重程度**: **严重** (CRITICAL)  
**类型**: 内存安全 — 悬垂引用

```rust
fn safe_c_str(p: *const c_char) -> Option<&'static str> {
    if p.is_null() { return None; }
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}
```

**问题**: 函数签名声称返回 `&'static str`，但实际生命周期取决于 C 调用方传入的指针。如果 C 调用方释放了字符串，返回的引用就变成了悬垂指针。当前所有调用点（`c_str!` 宏）都是立即消费返回值，暂时安全，但签名本身就是不安全的承诺。

**建议**: 改为返回 `Option<String>`（在 FFI 边界做完整拷贝）或使用明确的生命周期标注 `unsafe fn safe_c_str<'a>(p: *const c_char) -> Option<&'a str>`。

---

### CRITICAL-3: `constant_time_eq` 不是真正的常量时间

**文件**: `crypto.rs:39-47`  
**严重程度**: **严重** (CRITICAL)  
**类型**: 侧信道 — 时序攻击

```rust
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;  // ← 早退泄露长度信息
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
```

**问题**: 
1. **长度比较早退** — 不同长度的输入返回速度不同，攻击者可探测目标数据长度
2. **编译器优化风险** — `diff |= x ^ y` 可能被 LLVM 优化为早退分支（尽管 Rust 当前版本尚未观测到），应使用 `std::hint::black_box`
3. **Cargo.toml 已依赖 `ct-codecs`（常量时间编解码库）但从未使用**

**建议**: 删除手写实现，直接使用 `ct-codecs::Encoder::eq`。

---

### HIGH-1: Ed25519 私钥明文存储于 JSON

**文件**: `identity.rs:19-23`, `identity.rs:73-77`  
**严重程度**: **高** (HIGH)  
**类型**: 密钥管理 — 明文存储

```rust
#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub uid: String,
    secret_hex: String,  // ← 私钥以 hex 字符串存储于 JSON
    public_hex: String,
    pub created: u64,
}
```

**问题**: 
- 私钥 (`secret_hex`) 序列化为明文 JSON 写入 `data/keys/identity.json`
- 文件没有任何加密保护或权限限制（未调用 `set_permissions` 限制为 `0o600`）
- 任何有文件系统访问权限的进程都可以读取私钥

**建议**: 
1. 对 JSON 文件设置仅当前用户可读写权限 (`0o600` on Unix)
2. 使用密码派生的密钥加密私钥再存储（如 `ring::aead` 或 age 加密）
3. 给 `Identity` 实现 `Drop` 并在 drop 时 zeroize `secret_hex`

---

### HIGH-2: 密钥在内存中未被安全清零

**文件**: `identity.rs:21` (secret_hex 是普通 String), `crypto.rs:35-37` (generate_key 返回值), `shuffle.rs:64` (decrypt_key 是普通 Vec<u8>)  
**严重程度**: **高** (HIGH)  
**类型**: 密钥管理 — 内存残留

多个关键密钥使用普通 `String` 或 `Vec<u8>` 存储，在 drop 时不会被清零：
- `Identity::secret_hex` — 使用 String，释放后可能留在堆内存中
- `ShuffleSlot::decrypt_key` (shuffle.rs:16) — 明文存储 AES 密钥的 `Vec<u8>`，未 zeroize
- `generate_key()` 返回 `[u8; 32]`，调用方 copy 后栈上原始值残留

**建议**: 
- `secret_hex` 使用 `zeroize::Zeroizing<String>` 包装
- `decrypt_key` 使用 `zeroize::Zeroizing<Vec<u8>>`
- `generate_key()` 调用方使用 `key_buffer.zeroize()` 在使用后清空

---

### HIGH-3: 可验证洗牌 — 解密密钥随密文一同传输

**文件**: `shuffle.rs:12-18`  
**严重程度**: **高** (HIGH)  
**类型**: 密码学协议设计缺陷

```rust
pub struct ShuffleSlot {
    pub ciphertext: Vec<u8>,
    pub commitment: Vec<u8>,
    pub decrypt_key: Vec<u8>,  // ← 密钥和密文在同一个结构体中
    pub node_id: Vec<u8>,
}
```

**问题**: `submission()` 方法用随机 AES 密钥加密消息后，将密钥存储在同一个 `ShuffleSlot` 中。在 Dissent 协议中，承诺-揭示阶段应该：
1. 承诺阶段：Leader 收集**加密**消息 + SHA-256(明文) 承诺
2. 揭示阶段：Leader **单独**公布解密密钥

但当前实现中 `decrypt_key` 直接作为 slot 的一部分被序列化传递，任何收到 `ShuffleCommitment` 的参与者都可以解密所有槽位。承诺-揭示协议的安全性完全失效。

**建议**: 
1. 从 `ShuffleSlot` 中移除 `decrypt_key` 字段
2. 在 `F2fDcNetBridge` 中维护一个本地的 `slot_keys: HashMap<u16, [u8; 32]>`
3. Leader 在收集完所有承诺后，单独广播解密密钥

---

### HIGH-4: DC-Net 广播只生成了单个随机份额

**文件**: `dcnet/f2f.rs:218-241`  
**严重程度**: **高** (HIGH)  
**类型**: 密码学协议缺陷

```rust
pub fn broadcast_message(&mut self, channel: &str, text: &str) -> Option<String> {
    // ...
    let share = crate::dcnet::generate_share();  // 单个随机份额
    let xored = crate::dcnet::xor_bytes(text.as_bytes(), &share);
    // ...
}
```

**问题**: DC-Net 的匿名性依赖于**每个参与者与所有其他参与者两两生成共享密钥**，然后 XOR（自己的消息 + 所有共享密钥）。当前实现只生成了**一个**随机密钥并 XOR，完全失去了匿名性 — 因为这等价于用一个随机密钥加密，任何人都无法恢复，而真实 DC-Net 的原理是所有人 XOR 后共享密钥相互抵消。

**建议**: 需要实现完整的 N 方 Diffie-Hellman 密钥协商 + 多重 XOR 协议。

---

### MEDIUM-1: Double Ratchet 无重放保护

**文件**: `ratchet.rs:117-142`  
**严重程度**: **中** (MEDIUM)  
**类型**: 密码学协议缺陷

```rust
pub fn decrypt(&mut self, encrypted: &[u8], msg_idx: u64) -> Option<(Vec<u8>, [u8; 32])> {
    let msg_key = hkdf_expand(&self.recv_chain, &msg_idx.to_le_bytes());
    // ... decrypts based on msg_idx, no freshness check
}
```

**问题**: 解密函数使用调用方传入的 `msg_idx` 派生密钥，而不是维护预期的下一个索引。攻击者可以：
1. 重放旧消息（`msg_idx` 较小）— 虽然解密成功但应被拒绝
2. 跳过消息序号 — 导致接收链密钥推进步数与发送方不同步

**建议**: 维护 `expected_recv_idx: u64`，拒绝 `msg_idx <= self.recv_idx` 的消息。

---

### MEDIUM-2: `xor_bytes` 不同长度输入导致信息泄露

**文件**: `dcnet/mod.rs:28-35`  
**严重程度**: **中** (MEDIUM)  
**类型**: 信息泄露 — 消息长度

```rust
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let len = a.len().max(b.len());  // ← 取最长
    // ... 短的补 0
}
```

**问题**: DC-Net 要求所有参与者在每一轮发送**相同长度**的消息。零填充会泄露最长消息的精确长度。所有参与者应协商一个固定消息长度。

**建议**: 增加 `max_len: usize` 参数，所有消息截断/填充到此长度。

---

### MEDIUM-3: TCP 传输无默认 TLS

**文件**: `net/tcp.rs`, `network.rs`, `Cargo.toml`  
**严重程度**: **中** (MEDIUM)  
**类型**: 网络安全 — 明文传输

```toml
# Cargo.toml
rustls = { version = "0.23", optional = true }  # ← TLS 是可选的
```

**问题**: `connect_to` 使用裸 `TcpStream::connect`，SOCKS5 代理也是明文。虽然加密在应用层（AES-256-GCM），但缺乏传输层认证会使连接暴露于 MITM 攻击。
`rustls` 已声明但标记为 optional，且未在 feature flag 中激活。

**建议**: 在握手阶段使用 Ed25519 签名的身份认证（`AuthChallenge`/`AuthResponse` 已在 PeerMessage 中定义但未实现验证逻辑）。

---

### LOW-1: FFI 函数使用 `unwrap()` 可能导致 panic 跨越 FFI 边界

**文件**: `ffi.rs:199`, `ffi.rs:283-286`  
**严重程度**: **低** (LOW)  
**类型**: 可靠性

```rust
*get_bridge().lock().unwrap() = Some(...);   // line 199
*F2F_INIT.lock().unwrap() = true;            // line 200
get_bridge().lock().ok()...                  // line 271 — 这里用了 .ok()
```

**问题**: FFI 函数中 panic（通过 `unwrap()`）跨越 C 边界是**未定义行为**。`rust_f2f_init` 使用 `unwrap()`，但同一文件的其他 FFI 函数正确使用了 `.ok()?` 或 `unwrap_or`。

**建议**: 统一所有 FFI 函数使用 `.ok()?` 或不 panicking 的 `unwrap_or`。

---

### LOW-2: `ShuffleSlot.decrypt_key` 未被 zeroize

**文件**: `shuffle.rs:64`  
**严重程度**: **低** (LOW)  
**类型**: 密钥管理

```rust
decrypt_key: key.to_vec(),  // 普通的 Vec<u8>，不会在 drop 时清零
```

---

## 2. 代码质量问题

### Q1: 全局可变状态泛滥 (God State Anti-Pattern)

项目使用**超过 5 个**全局静态可变状态：

| 变量 | 位置 | 类型 |
|------|------|------|
| `F2F_BRIDGE` | f2f.rs:279 | `Mutex<Option<F2fDcNetBridge>>` |
| `STATE` | user.rs:27 | `LazyLock<Mutex<CliState>>` |
| `TRANSPORT` | transport.rs:71 | `Mutex<Option<TransportConfig>>` |
| `ROUTER` | relay.rs:83 | `Mutex<Option<RelayRouter>>` |
| `CVE_DB` | cve.rs:173 | `OnceLock<CveDb>` |
| `F2F_INIT` | ffi.rs:168 | `Mutex<bool>` |

**影响**:
- **不可测试**: 无法在单元测试中创建独立实例，所有测试共享全局状态
- **死锁风险**: 多个锁嵌套时可能死锁
- **无法复现 bug**: 状态泄漏到下一个测试

**建议**: 引入 `AppContext` 结构体，通过依赖注入传递给各模块。

---

### Q2: 两个 CLI 状态系统并存且不同步

**文件**: `cli/mod.rs:54-58` vs `cli/user.rs:27` vs `dcnet/f2f.rs`

存在两个独立的"当前用户"概念：
1. `CliState.my_uid` (在 user.rs) — 通过 `uid set` 设置
2. `F2fDcNetBridge.my_uid` (在 f2f.rs) — 通过 `f2f init` 设置

`cmd_nick` (cli/mod.rs:229-237) 只更新 CliState 不更新 Bridge：
```rust
fn cmd_nick(args: &[&str]) {
    user::cmd_uid(&["set", args[0]]);  // 只改 CliState
    println!("[+] Nick set: {}", args[0]); // Bridge 的 my_uid 不变
}
```

---

### Q3: CLI 主循环与命令处理耦合在单一文件中

**文件**: `cli/mod.rs` — **441 行**

一个文件包含：
- REPL 主循环 (`run_repl`)
- 所有 IRC 命令处理 (`cmd_join`, `cmd_part`, `cmd_channel_msg`, `cmd_names`, `cmd_list`, `cmd_topic`, `cmd_nick`, `cmd_connect`)
- 网络命令 (`cmd_lan`, `cmd_tor`, `cmd_relay`, `cmd_ping`)
- 桥接辅助函数 (`with_bridge`, `read_bridge`, `prompt`)

**建议**: 每个命令组拆分到独立子模块：
- `cli/commands/join.rs`
- `cli/commands/network.rs` (tor, relay, lan)
- `cli/commands/channel.rs` (part, list, names, topic, msg)

---

### Q4: `F2fDcNetBridge` 成为 God Object

**文件**: `dcnet/f2f.rs` — **339 行**

一个结构体承担了过多职责：
- 好友管理 (add/remove/update_trust/is_trusted)
- 频道管理 (create/join/leave/switch/list)
- DC-Net 群组桥接 (groups HashMap)
- 广播消息 (broadcast_message)
- 声誉同步 (sync_reputation_to_trust)
- 轮次驱动 (start_round_driver/stop_round_driver)
- 状态查询 (channel_status/group_status/list_participants)

**建议**: 拆分为：
- `FriendManager` — 好友 CRUD + 信任管理
- `ChannelManager` — 频道生命周期
- `DcNetDriver` — DC-Net 轮次驱动

---

### Q5: 不一致的错误处理策略

| 模式 | 位置 | 示例 |
|------|------|------|
| `.unwrap()` panic | cli/mod.rs:14 | `get_bridge().lock().unwrap()` |
| `.ok()?` 优雅处理 | ffi.rs:175 | `get_bridge().lock().ok()?` |
| `unwrap_or(default)` | ffi.rs:274 | `.unwrap_or(0)` |
| `Option` + 静默返回 | f2f.rs:219 | `let group = self.groups.get_mut(channel)?;` |

同一行代码路径在 CLI 和 FFI 中有不同的错误处理策略：
```rust
// CLI: panic on poisoned mutex
fn with_bridge<F,R>(f:F, default:R) -> R {
    let mut guard = get_bridge().lock().unwrap(); // ← panic
}

// FFI: graceful on poisoned mutex
fn with_bridge<F,R>(f:F) -> Option<R> {
    let mut guard = get_bridge().lock().ok()?; // ← graceful
}
```

---

### Q6: 未使用的依赖

| 依赖 | 声明原因 | 实际使用 |
|------|----------|----------|
| `ct-codecs` | 常量时间比较 | **未使用**，手写了 `constant_time_eq` |
| `widestring` | C++ 字符串互操作 | **未使用**，源码中无极引用 |
| `memmap2` | 内存映射 CVE 数据库 | **未使用**，CVE 文件用 `read_to_string` 读取 |
| `rayon` | 并行 CVE 扫描 | **未使用**，`scan_product` 是顺序的 |

这些依赖增加了编译时间和二进制大小，但没有提供价值。

---

### Q7: `identity::load_or_generate` 忽略 UID 不匹配

**文件**: `identity.rs:41-56`

```rust
pub fn load_or_generate(data_dir: &PathBuf, uid: &str) -> Self {
    ...
    if let Ok(id) = serde_json::from_str::<Identity>(&json) {
        return id;  // ← 不检查 id.uid 是否 == uid 参数
    }
    let id = Self::generate(uid);  // uid 仅在此使用
    ...
}
```

**问题**: 如果磁盘上存在身份 A 的文件，但调用方传入 `uid = "B"`，仍然返回 A 的身份。

---

### Q8: 日志基础设施存在但未使用

**文件**: `main.rs:3`, `Cargo.toml`

```rust
env_logger::Builder::from_env(...).init();  // 初始化了
// 但所有代码都用 println!() 而不是 log::info!()
```

`log = "0.4"` 和 `env_logger = "0.11"` 已依赖，但整个代码库零处使用 `log::info!()` / `log::warn!()` / `log::error!()`。

---

### Q9: 版本号不一致

| 位置 | 版本 | 
|------|------|
| `lib.rs:1` | v7.0 |
| `cli/mod.rs:1` | v7.1 |
| `cli/mod.rs:61` (启动横幅) | v7.2 |
| `net/mod.rs:1` | v7.2 |
| `README.md` | v7.2 |
| `Cargo.toml:2` | 0.1.0 |
| `ffi.rs:1` | v7.0 |

---

### Q10: 无 `rustfmt` / `clippy` 配置

项目没有 `.rustfmt.toml` 或 `clippy.toml`，也没有 CI 配置强制执行格式检查或 lint 警告。

---

## 3. 功能完整性问题

### 核心协议基本是骨架实现

| 功能 | README 声称 | 实际状态 |
|------|-----------|----------|
| DC-Net XOR 广播 | "N 个参与者两两 DH 协商共享密钥" | `broadcast_message` 只生成一个随机份额，无 DH 协商 |
| 可验证洗牌 | "承诺-揭示协议, Blame 追责" | 解密密钥随密文传输，承诺无意义 |
| Double Ratchet 前向安全 | "对称棘轮: 每条消息推进链密钥" | 无重放保护，msg_idx 由调用方控制 |
| 多路径中继 | "通过好友中继，端到端加密" | RelayRouter 结构体完整但无实际中继逻辑 |
| F2F TCP 握手 | "双方交换 UID + 公钥" | AuthChallenge/AuthResponse 消息类型定义了但无验证逻辑 |
| 信誉系统 | "参与评分, 连续掉线检测" | ReputationManager 有完整实现但未与轮次系统集成 |
| 轮次驱动 | "自动驱动 DC-Net 轮次" | `start_round_driver` 只启动空循环线程 |

**核心问题是**: 模块间没有连接。每个模块单独看起来有基本逻辑，但全部孤立：
- TCP 层 `send_encrypted_frame` / `recv_encrypted_frame` → 无人调用
- 中继 `RelayRouter` → 无人实际路由消息
- LAN 发现 `discover_peers` → 发现的对等节点不会被桥接
- 传输层 `Transport` / `load_transport` → 桥接不使用它

---

### 测试脚本针对的是已废弃的 C++ 服务端

| 测试文件 | 目标 | 协议 |
|----------|------|------|
| `tests/api_verification_test.sh` | `https://127.0.0.1:4443` | HTTP REST API |
| `tests/loopback_test.sh` | `https://127.0.0.1:4443` | HTTP REST API |
| `tests/security_pen_test.sh` | `https://127.0.0.1:4443` | HTTP REST API |

这些脚本测试的是 C++ 服务端的 HTTP API（用户注册/登录/消息/模板），与 Rust 代码**完全无关**。Rust 代码只有内联的 `#[cfg(test)]` 单元测试（~30 个测试函数）。

---

## 4. 依赖与供应链

### Rust 依赖清单

| 依赖 | 版本 | 用途 | 风险 |
|------|------|------|------|
| `aes-gcm` | 0.10 | AES-256-GCM | ✅ 广泛使用 |
| `sha2` | 0.10 | SHA-256 | ✅ 广泛使用 |
| `hmac` | 0.12 | HMAC | ✅ 广泛使用 |
| `x25519-dalek` | 2 | X25519 ECDH | ✅ 广泛使用 |
| `ed25519-dalek` | 2 | Ed25519 签名 | ✅ 广泛使用 |
| `hkdf` | 0.12 | HKDF-SHA256 | ✅ 广泛使用 |
| `zeroize` | 1 | 内存清零 | ✅ 广泛使用 |
| `rand` | 0.8 | OsRng | ✅ 广泛使用 |
| `tokio` | 1 (full) | 异步运行时 | ⚠️ `full` features 引入不必要的子依赖 |
| `serde` / `serde_json` | 1 | JSON | ✅ 广泛使用 |
| `reqwest` | 0.12 (optional) | HTTP | ⚠️ 未激活 |
| `tungstenite` | 0.24 (optional) | WebSocket | ⚠️ 未激活 |
| `rustls` | 0.23 (optional) | TLS | ⚠️ 未激活 |
| `ct-codecs` | 0.1 | 常量时间编码 | ❌ 未使用 |
| `widestring` | 1 | C++ 宽字符 | ❌ 未使用 |
| `memmap2` | 0.9 | 内存映射文件 | ❌ 未使用 |
| `rayon` | 1 | 并行处理 | ❌ 未使用 |
| `windows-sys` | 0.59 | Windows API | ✅ 仅在 windows 目标使用 |
| `dirs` | 5 | 系统目录 | ⚠️ 仅在 storage.rs 测试中使用 PathBuf::from |

### Tokio "full" features

```toml
tokio = { version = "1", features = ["full"] }
```

`full` feature 引入了多线程运行时、信号处理、进程管理等不需要的功能，显著增加编译时间和二进制体积。应改为：
```toml
tokio = { version = "1", features = ["rt", "net", "io-util"] }
```

---

## 5. 测试覆盖与质量

### 单元测试统计

| 文件 | 测试函数数 | 覆盖的路径 |
|------|-----------|-----------|
| crypto.rs | 2 | 加解密往返 / constant_time_eq |
| cve.rs | 1 | JSON 解析 |
| identity.rs | 3 | 密钥生成 / 签名验证 / 保存加载 |
| network.rs | 2 | 握手字节 / 域名过长 |
| parser.rs | 3 | 有效 JSON / 无效 JSON / 深层嵌套 |
| ratchet.rs | 2 | 加解密 / 前向安全 |
| storage.rs | 1 | 保存加载 |
| dcnet/mod.rs | 3 | XOR 对称 / 惩罚 / 简单轮次 |
| dcnet/f2f.rs | 5 | 好友 CRUD / 频道 / 信任过滤 |
| dcnet/group.rs | 4 | 加入离开 / 最小参与人数 / 重组 / 恶意节点过滤 |
| dcnet/round.rs | 2 | 创建 / 标记掉线 |
| dcnet/shuffle.rs | 4 | 承诺验证 / 错误消息 / 作弊检测 / 缺席检测 |
| dcnet/reputation.rs | 5 | 初始分数 / 奖励 / 连续掉线 / 掉线率 / 管理器 |
| net/transport.rs | 3 | 默认 / 序列化 / 持久化 |
| net/lan.rs | 2 | 解析 / 坏数据 |
| net/relay.rs | 3 | 路径添加 / 未知目标 / 消息构造 |
| net/tcp.rs | 2 | 帧往返 / 消息类型 |

**总计**: ~47 个单元测试

### 测试质量问题

1. **所有测试都是正面路径** — 没有测试边界条件、错误路径或恶意输入
2. **无集成测试** — 没有测试两个模块之间的交互
3. **无网络测试** — TCP/socket 代码没有集成测试（需要实际 socket）
4. **测试覆盖率不均** — `crypto.rs` (245 行) 只有 2 个测试，`cve.rs` (201 行) 只有 1 个测试
5. **ffi.rs 零测试** — 386 行没有单元测试
6. **cli/ 零测试** — 整个 CLI 层没有自动化测试

---

## 6. 架构设计问题

### 问题总览

```
当前状态：
  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │   CLI    │  │  DC-Net  │  │   Net    │
  │ (mod.rs) │  │  (f2f.rs)│  │  (tcp.rs)│
  └────┬─────┘  └────┬─────┘  └────┬─────┘
       │println!     │Mutex         │孤立函数
       ▼             ▼              ▼
  ┌─────────────────────────────────────┐
  │       全局可变状态 (5+ 个 Mutex)      │
  │  F2F_BRIDGE / STATE / TRANSPORT ... │
  └─────────────────────────────────────┘
  
  模块间无数据流 — 每个模块只操作自己的全局状态
```

### 具体架构问题

1. **无依赖注入** — 所有模块直接访问全局 Mutex，无法替换实现
2. **无消息总线** — CLI 命令、网络事件、DC-Net 轮次完成之间无协调
3. **无并发模型** — `tokio` 已依赖但所有代码都是同步阻塞的
4. **传输抽象被架空** — `Transport` 枚举有 4 种变体，但 `F2fDcNetBridge` 不知道 Transport 的存在
5. **身份系统割裂** — `Identity` (Ed25519) 与 `F2fDcNetBridge.my_uid` (字符串) 完全独立

---

## 7. 问题汇总清单

### 安全问题 (13 项)

| ID | 文件 | 严重程度 | 简述 |
|----|------|----------|------|
| CRITICAL-1 | ffi.rs:25,51 | CRITICAL | 密钥缓冲区无长度验证导致越界读取 |
| CRITICAL-2 | ffi.rs:181 | CRITICAL | safe_c_str 返回 fake 'static 生命周期 |
| CRITICAL-3 | crypto.rs:39 | CRITICAL | constant_time_eq 非真正常量时间 |
| HIGH-1 | identity.rs:21 | HIGH | 私钥明文存储于 JSON 文件 |
| HIGH-2 | identity/shuffle/crypto | HIGH | 密钥未 zeroize，内存残留 |
| HIGH-3 | shuffle.rs:16 | HIGH | 洗牌解密密钥随密文一起传输 |
| HIGH-4 | f2f.rs:230 | HIGH | DC-Net 只生成单个随机份额 |
| MEDIUM-1 | ratchet.rs:117 | MEDIUM | Double Ratchet 无重放保护 |
| MEDIUM-2 | dcnet/mod.rs:28 | MEDIUM | XOR 零填充泄露消息长度 |
| MEDIUM-3 | net/tcp, Cargo.toml | MEDIUM | TCP 无 TLS 传输安全 |
| LOW-1 | ffi.rs:199 | LOW | FFI unwrap 跨越 C 边界 |
| LOW-2 | shuffle.rs:64 | LOW | decrypt_key 未 zeroize |

### 代码质量问题 (10 项)

| ID | 文件 | 简述 |
|----|------|------|
| Q1 | 全局 | 5+ 个 global static Mutex — 不可测试 |
| Q2 | cli/ + f2f.rs | 两个独立的"当前用户"状态 |
| Q3 | cli/mod.rs (441行) | CLI 主循环 + 全部命令耦合在单一文件 |
| Q4 | f2f.rs (339行) | God Object — 承担 7 种职责 |
| Q5 | 全局 | 不一致的错误处理 (unwrap vs .ok()?) |
| Q6 | Cargo.toml | 4 个未使用的依赖 |
| Q7 | identity.rs:41 | load_or_generate 忽略 UID |
| Q8 | main.rs / 全局 | log crate 已初始化但零使用 |
| Q9 | 多个文件 | 版本号不一致 (v7.0/7.1/7.2/0.1.0) |
| Q10 | 全局 | 无 rustfmt/clippy/CI 配置 |

### 功能完整性问题 (7 项)

| ID | 功能 | 状态 |
|----|------|------|
| F1 | DC-Net 多方 DH + XOR | 仅单份额 stub |
| F2 | 可验证洗牌承诺揭示 | 密钥泄露，协议无效 |
| F3 | Double Ratchet 重放保护 | 无 |
| F4 | 多路径中继 | 无实际路由逻辑 |
| F5 | TCP 握手认证 | 消息类型已定义，验证未实现 |
| F6 | 轮次自动驱动 | 空循环线程 |
| F7 | 模块间集成 | 所有模块孤立，无数据流 |

### 依赖问题 (4 项)

| ID | 依赖 | 问题 |
|----|------|------|
| D1 | ct-codecs | 已依赖但未使用 |
| D2 | widestring | 已依赖但未使用 |
| D3 | memmap2 | 已依赖但未使用 |
| D4 | tokio (full) | features 过多 |

### 测试问题 (5 项)

| ID | 问题 |
|----|------|
| T1 | ffi.rs 386 行零测试 |
| T2 | cli/ 整个模块零测试 |
| T3 | 所有测试仅正面路径 |
| T4 | 无模块间集成测试 |
| T5 | tests/*.sh 测试 C++ HTTP 服务端，与 Rust 代码无关 |

---

## 总体评估

```
安全评级:     ⭐⭐☆☆☆  (2/5) — 多个 CRITICAL/HIGH 安全问题
代码质量:     ⭐⭐☆☆☆  (2/5) — 全局状态泛滥，模块耦合
功能完成度:   ⭐☆☆☆☆  (1/5) — 核心协议为骨架，模块孤立
测试覆盖:     ⭐☆☆☆☆  (1/5) — 无集成测试，无 CLI/FFI 测试
依赖管理:     ⭐⭐⭐☆☆  (3/5) — 有冗余但无非受信 crate
可维护性:     ⭐⭐☆☆☆  (2/5) — God Object + 全局状态的组合
```

**总结**: Chrono-shift 的 Rust 代码是一个概念验证/原型，并非生产就绪的实现。模块结构清晰但内部集成度极低。核心加密原语（AES-GCM、Ed25519、X25519、HKDF）的选用是合理的，但密码学协议层面的实现（DC-Net、可验证洗牌、Double Ratchet）存在严重缺陷。建议在修复安全问题前不要部署到任何真实环境。

---

*报告由 deepseek-v4-pro 生成 | 2026-06-04*
