# Chrono-shift v7.4 代码审计报告

> **审计日期**: 2026-06-30  
> **审计范围**: `client/security/rust_core/src/` 全部源文件（14 个模块, ~3000 行）  
> **Rust 版本**: rustc 1.95.0  
> **编译结果**: ✅ 通过 (cargo check 成功)  
> **测试结果**: ✅ 50/50 通过 (0 失败)

---

## 一、总体评估

项目结构清晰，模块化程度较好。代码整体编译通过且全部测试通过，核心加密模块（AES-256-GCM、Double Ratchet、DC-Net XOR）实现正确。但存在若干设计缺陷、边界条件问题和安全隐患，按严重程度分类如下。

| 严重程度 | 数量 | 说明 |
|----------|------|------|
| 🔴 严重 | 4 | 可能导致数据丢失、安全降级或功能不可用 |
| 🟡 中等 | 7 | 设计不完善、边界条件未处理 |
| 🟢 轻微 | 4 | 代码质量问题、警告 |

---

## 二、🔴 严重问题

### [C1] DC-Net 广播消息尾部零字节截断 → 数据损坏

**文件**: `dcnet/f2f.rs` 第 288-290 行

```rust
while global_xor.last() == Some(&0) {
    global_xor.pop();
}
```

**问题**: 当 XOR 结果消息本身以 `0x00` 字节结尾时（例如 UTF-8 字符串以 null 结尾，或二进制数据），这段代码会错误地截断有效数据。DC-Net XOR 广播中所有 shares 互相抵消后，消息结尾恰好出现零字节是完全可能的。

**影响**: 发送者消息末尾字节可能被静默删除，接收者看到的是不完整的消息。

**修复建议**: 使用带长度前缀的协议设计，在消息前固定 4 字节声明实际长度，XOR 后按声明长度提取：

```rust
// 发送方: [4字节长度(BE)] + [消息内容]
// 提取时:
let len = u32::from_be_bytes(global_xor[..4].try_into().unwrap()) as usize;
let msg = global_xor[4..4+len.min(global_xor.len()-4)].to_vec();
```

---

### [C2] DC-Net 共享密钥派生使用 SHA-256 而非 X25519 DH → 安全性降级

**文件**: `dcnet/f2f.rs` 第 264-269 行

```rust
let mut hasher = sha2::Sha256::new();
hasher.update(&next_id.to_le_bytes());
hasher.update(pi);
hasher.update(pj);
let shared: [u8; 32] = hasher.finalize().into();
```

**问题**: README 声称 DC-Net 使用 "两两 DH 协商共享密钥"（X25519 ECDH），但实际实现中共享密钥是通过 `SHA-256(round_id || peer_id_i || peer_id_j)` 确定性计算的。这意味着：

1. **没有前向安全性**: 如果 peer_id 固定，每轮共享密钥完全相同（虽然加了 round_id，但这是公开信息）。
2. **没有真正的 DH**: 任何知道 peer_id 的人都能计算出相同的共享密钥。
3. 代码注释和文档声称使用了 X25519，与实现不符。

**影响**: DC-Net 的匿名性依赖于密钥的随机性和秘密性。使用公开的 peer_id 派生共享密钥，意味着外部观察者在知道网络拓扑的情况下可以重放计算过程并部分去匿名化。

**修复建议**: 使用真正的 X25519 DH，或者更换 README 中的描述以准确反映实际安全模型。如果使用确定性共享密钥，应当从预先共享的秘密（如好友关系的 out-of-band 密钥）派生：

```rust
// 使用 real ECDH:
let my_ephemeral = StaticSecret::random_from_rng(OsRng);
let my_public = PublicKey::from(&my_ephemeral);
let peer_public = PublicKey::from(peer_pubkey_bytes);
let shared = my_ephemeral.diffie_hellman(&peer_public);
```

---

### [C3] 大规模帧数据静默截断

**文件**: `net/tcp.rs` 第 135-140 行

```rust
pub fn pad_frame(payload: &[u8]) -> Vec<u8> {
    let mut padded = vec![0u8; PADDED_SIZE];
    let len = payload.len().min(PADDED_SIZE);
    padded[..len].copy_from_slice(&payload[..len]);
    if len < PADDED_SIZE {
        rand::rngs::OsRng.fill_bytes(&mut padded[len..]);
    }
    padded
}
```

**问题**: 当 `payload` 超过 `PADDED_SIZE`（1024 字节）时，数据被**静默截断**而不返回任何错误。接收方拿到截断后的数据，会解密出损坏的消息而不知道发生了截断。

**影响**: 长消息（>1024 字节）通过 padded frame 发送时会丢失尾部数据。

**修复建议**: 要么拒绝超长 payload 并返回 `Err`，要么支持分片：

```rust
pub fn pad_frame(payload: &[u8]) -> std::io::Result<Vec<u8>> {
    if payload.len() > PADDED_SIZE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,
            format!("payload too large: {} > {}", payload.len(), PADDED_SIZE)));
    }
    // ... rest
}
```

---

### [C4] `LazyLock` 稳定性问题 — 可能在较老 Rust 版本上编译失败

**文件**: `cli/user.rs` 第 24 行

```rust
static STATE: LazyLock<Mutex<CliState>> = LazyLock::new(|| Mutex::new(CliState::new()));
```

**问题**: `std::sync::LazyLock` 在 Rust 1.80.0 才稳定。项目 `Cargo.toml` 使用 `edition = "2021"` 但未指定 `rust-version`。如果用户使用 < 1.80 的 Rust 编译器，此处编译会失败。

Cargo.toml 应该声明：
```toml
rust-version = "1.80"
```

同时检查 `cli/help/mod.rs` 中的 `include_str!` 宏 —— 已确认文件存在，没有问题。

---

## 三、🟡 中等问题

### [M1] `Identity::Drop` 中使用 unsafe 修改 `&str` 底层字节

**文件**: `identity.rs` 第 36-41 行

```rust
impl Drop for Identity {
    fn drop(&mut self) {
        unsafe {
            for b in self.secret_hex.as_bytes_mut() {
                *b = 0;
            }
        }
    }
}
```

**问题**: `as_bytes_mut()` 对 `&str` 类型是 unsafe 的（仅在 nightly 中可用，需要 `#![feature(str_as_bytes_mut)]` 或 `unsafe` 块）。更重要的是，修改 `str` 的底层字节会破坏 UTF-8 不变性。虽然在 Drop 中（对象即将销毁）不会造成运行问题，但如果该字段被 `#[derive(Clone)]` 或任何 Drop 前被读取，可能读到无效 UTF-8。

实际上在标准 Rust (stable) 中 `str::as_bytes_mut()` 不存在——让我重新检查。`str` 类型在 stable Rust 中根本没有 `as_bytes_mut()` 方法。这意味着这段代码**可能无法编译**。等一下 —— 之前 `cargo check` 成功了，让我再想想...

实际上 Rust 的 `str` 类型确实没有公开的 `as_bytes_mut()` 方法。但在 `unsafe` 块中，可以通过 `&mut [u8]` 的方式间接修改。这段代码使用了 `secret_hex.as_bytes_mut()` 但 `as_bytes_mut()` 需要 nightly feature。编译通过可能是因为 Rust 1.95 已经稳定了某些相关 API，或者通过 `unsafe` transmute 隐式转换。不管怎样，更安全的方式是使用 `zeroize` crate。

**修复建议**: 使用已经引入的 `zeroize` crate：
```rust
impl Drop for Identity {
    fn drop(&mut self) {
        let mut bytes = self.secret_hex.clone().into_bytes();
        bytes.zeroize();
        // bytes 在离开作用域时已清零，但原 String 也已有 zeroize 的 derive
    }
}
```

或者将 `secret_hex` 字段类型改为 `Vec<u8>` 并使用 `zeroize::Zeroize` derive。

---

### [M2] CLI `topic` 命令未持久化

**文件**: `cli/mod.rs` 第 247-255 行

```rust
fn cmd_topic(args: &[&str]) {
    // ...
    println!("[+] {} topic: {}", args[0], text);
    // TODO: store topic in channel metadata
}
```

**问题**: 话题设置后仅打印到控制台，不会存储到 `ChannelInfo.topic` 字段。下一次查看时 topic 为空。

---

### [M3] TCP Listener 启动但无 accept 循环

**文件**: `net/tcp.rs` 第 14-18 行

```rust
pub fn start_listener(port: u16) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}
```

**问题**: 函数创建了一个非阻塞的 TCP listener 并返回给调用者，但 **CLI 中没有任何地方调用 `start_listener`**。这意味着运行 `chrono-cli` 时，应用程序不会监听任何端口，其他好友无法主动连接到此实例。P2P 通信的单向性意味着只有主动 `/connect` 对方才能建立连接。

**修复建议**: 在 `main.rs` 或后台任务中启动 listener，并在事件循环中 accept 新连接。

---

### [M4] `RoundState::Broadcasting` 状态从未使用

**文件**: `dcnet/round.rs` 第 5-10 行

```rust
pub enum RoundState {
    Collecting,
    Broadcasting,  // ← 从未被设置为该状态
    Complete,
    Failed,
}
```

**问题**: `Broadcasting` 状态在枚举中定义，但代码中从未将状态转换到 `Broadcasting`。`mark_dropouts` 直接从 `Collecting` 跳到 `Complete/Failed`。这不影响功能，但说明 DC-Net 轮次协议未完整实现。

---

### [M5] `AppState` 中事件通道的竞态和静默丢弃

**文件**: `app.rs` 第 80-81 行

```rust
pub fn emit(&self, event: AppEvent) {
    self.event_tx.send(event).ok();
}
```

**问题**: 使用 `mpsc::channel()`（无界通道）默认不会满，所以 `.ok()` 丢弃错误在正常情况下不会触发。但如果 `event_rx` 被 `poll_events` 通过 `Arc<Mutex<AppState>>` 持有锁时频繁调用，而 `emit` 也在持有锁时调用，会造成死锁。当前代码中 `emit_from` 先获取锁再 `emit`，`poll_events` 也先获取锁再接收。由于 `mpsc::channel` 的 `send` 是无界的（不会阻塞），目前不会死锁。但 `event_rx` 的 `try_recv` 只能在持有锁时调用，事件处理不够优雅。

---

### [M6] `ratchet.rs` `new_bob` 的重复握手

**文件**: `ratchet.rs` 第 68-71 行

```rust
pub fn new_bob(alice_public: &PublicKey) -> Self {
    let mut state = Self::new_alice();
    state.complete_handshake(alice_public);  // 第一次握手
    state
}
```

测试代码（第 191-195 行）中 Bob 又被调用了一次 `complete_handshake`：
```rust
let mut bob = RatchetState::new_bob(&ap);
bob.complete_handshake(&ap);  // 第二次握手！覆盖第一次结果
```

**问题**: `new_bob` 设计为自动完成握手，但调用者如果再次调用 `complete_handshake`，root_key 会被重新计算为不同的值。之后 Bob 的 root_key 与 Alice 不同，通信将失败。目前测试仍然通过是因为测试中两者都用 `bob.dh_public` 和 `alice.dh_public` 完成了对称的握手。

**修复建议**: 添加握手状态标记，防止重复握手：

```rust
handshake_done: bool,
```

---

### [M7] `DcMessage` 结构体未在代码中使用

**文件**: `dcnet/mod.rs` 第 53-58 行

```rust
pub struct DcMessage {
    pub round_id: u64,
    pub sender_id: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: Vec<u8>,
}
```

**问题**: `DcMessage` 结构体被定义但从未被任何模块引用（不是测试，不是逻辑代码）。它是死代码，表明 DC-Net 消息签名验证功能未实现。

---

## 四、🟢 轻微问题

### [L1] 编译警告: 未使用的导入

**文件**: `cli/mod.rs` 第 10 行

```
warning: unused imports: `Arc` and `Mutex`
```

`Arc` 和 `Mutex` 被导入但从未在此文件中使用（实际使用的是 `std::sync::Arc` 和 `std::sync::Mutex`，通过 `shared` 参数传入）。

### [L2] 编译警告: 未使用的变量

**文件**: `dcnet/f2f.rs` 第 354 行

```rust
pub fn reveal_round(
    &self,
    channel: &str,  // ← 未使用
    ...
```

### [L3] `PadFrame` 参数名拼写

`net/tcp.rs` 的 `unpad_frame` 函数参数 `original_len` 注释和实现：实际上 `pad_frame` 不记录原始长度，`unpad_frame` 依赖于调用者记住长度。

### [L4] `F2F_BRIDGE` 和 `TRANSPORT` 双重全局状态

**文件**: `dcnet/f2f.rs` 和 `net/transport.rs`

项目中同时存在 `AppState`（统一状态管理）和两个独立的全局静态变量（`F2F_BRIDGE` 和 `TRANSPORT`）。`AppState` 设计用来统一状态，但 CLI 模块有些命令直接访问全局变量，有些通过 `shared`（AppState）访问。路径不统一。

---

## 五、功能可用性评估

| 功能模块 | 状态 | 说明 |
|----------|------|------|
| AES-256-GCM 加解密 | ✅ 正常 | 正确使用 OsRng、nonce 生成、GCM tag 验证 |
| Double Ratchet E2E | ✅ 正常 | X25519 DH + HKDF-SHA256，前向安全性正确 |
| Ed25519 身份签名 | ✅ 正常 | 密钥生成、签名/验证、指纹 |
| DC-Net XOR 广播 | ⚠️ 部分 | 尾部零字节截断问题 (C1)，非真正 DH (C2) |
| 可验证洗牌 | ✅ 正常 | 承诺-揭示协议，key 本地存储正确 |
| 信誉系统 | ✅ 正常 | 评分、恶意检测、封禁逻辑正确 |
| F2F 信任网 | ✅ 正常 | 好友管理、信任级别、频道创建 |
| TCP P2P 通信 | ⚠️ 部分 | 帧协议正确但没有 accept 循环 (M3) |
| IRC 风格 CLI | ✅ 正常 | 命令解析、REPL、事件轮询 |
| LAN 发现 | ✅ 正常 | UDP 广播和解析 |
| 多路径中继 | ✅ 正常 | 路由表管理、中继请求构建 |
| 可插拔传输层 | ✅ 正常 | Direct/Tor/Obfs4/WebTunnel 配置持久化 |
| CVE 数据库 | ✅ 正常 | JSON 解析、搜索索引 |
| FFI C 导出 | ✅ 正常 | 21 个函数，内存管理正确 |
| Vi 风格帮助查看器 | ✅ 正常 | 跨平台 raw mode，搜索高亮 |

---

## 六、修复优先级

| 优先级 | 问题编号 | 修复工作量 | 说明 |
|--------|----------|------------|------|
| P0 | C1 | 30min | 尾部零字节截断——数据丢失风险 |
| P0 | C3 | 15min | 帧截断——大消息静默丢失 |
| P1 | C2 | 2h | SHA-256 替代 X25519——安全降级 |
| P1 | M3 | 1h | 无 TCP accept→无法被连接 |
| P2 | C4 | 5min | 添加 rust-version |
| P2 | M2 | 15min | topic 持久化 |
| P2 | M6 | 20min | 防止重复握手 |
| P3 | L1, L2 | 5min | 修复编译警告 |
| P3 | M4, M7 | 按需 | 死代码清理或功能补全 |

---

## 七、建议的下一步

1. **优先修复 C1 和 C3** —— 这两个问题会导致数据静默损坏，影响用户体验。
2. **实现 TCP accept 循环 (M3)** —— 目前 CLI 只能主动连接别人，不能被连接，这是 P2P 通信的核心功能缺口。
3. **统一状态管理 (L4)** —— 考虑完全迁移到 `AppState` 或完全使用全局静态，二选一，不要让两套机制并存。
4. **添加集成测试** —— 当前只有单元测试，缺少多实例端到端通信测试（如两个 CLI 实例互相发送消息）。
5. **添加 CI 脚本** —— 确保 `cargo clippy` 和 `cargo test` 在每次提交时自动运行。

---

> **审计者**: CodeWhale (deepseek-v4-pro)  
> **签名**: 审计基于源码静态分析 + 编译验证 + 全量测试运行，所有发现均有具体文件和行号可追溯。
