# Chrono-shift v7.0 代码优美度 & 组织结构审计报告

> **归档**：历史文档，仅作记录参考，不代表当前实现。当前文档见 docs/ 与 README。


**审计日期**: 2026-06-04
**审计范围**: `client/security/rust_core/src/` 全部 18 个 Rust 源文件
**审计重点**: 代码可读性、文件组织、模块拆分、格式化一致性
**审计人员**: AI 辅助代码审计

> **说明**: 本报告是对 `VULNERABILITY_AND_CODE_QUALITY_AUDIT.md`（49项安全/功能问题）的补充，专注于**代码结构和可读性**。安全问题仅在未被前一份报告覆盖时才列入。

---

## 📊 总体评分

| 维度 | 评分 | 说明 |
|------|------|------|
| 模块化设计 | ⭐⭐⭐ | 顶层拆分合理(dcnet/cli/crypto)，但子模块内聚性差 |
| 代码可读性 | ⭐⭐ | 严重两极分化：ratchet/crypto 良好，ffi/f2f 极差 |
| 格式化一致性 | ⭐⭐ | 压缩风格与正常风格混用，无统一规范 |
| 关注点分离 | ⭐⭐ | 多个文件承担 4-5 种不相关职责 |
| 注释/文档 | ⭐⭐⭐ | 模块级文档较好，函数级文档缺失严重 |

---

## 🔴 严重代码质量问题 (影响可维护性)

### Q1: `ffi.rs` — 所有 FFI 函数压缩为单行，完全不可读

- **文件**: `client/security/rust_core/src/ffi.rs`
- **严重程度**: 🔴 严重
- **问题**: 73 行中包含 22 个 FFI 导出函数，几乎所有函数体都压缩在一行内

**典型示例** (rust_encrypt_e2e, 实际代码在一行内):
```rust
// 当前代码 (ffi.rs:12-16) — 7 个语句挤在一行
#[no_mangle] pub extern "C" fn rust_encrypt_e2e(plaintext: *const u8, plaintext_len: u32, key: *const u8, out_len: *mut u32) -> *mut u8 {
    if plaintext.is_null()||key.is_null()||out_len.is_null() { return std::ptr::null_mut(); }
    let pt=unsafe{std::slice::from_raw_parts(plaintext,plaintext_len as usize)};
    let mut karr=[0u8;32]; unsafe{karr.copy_from_slice(std::slice::from_raw_parts(key,32))};
    match crypto::encrypt_e2e(pt,&karr) { Some(r) => { unsafe{*out_len=r.len() as u32}; let mut v=r.into_boxed_slice(); let p=v.as_mut_ptr(); std::mem::forget(v); p } None => std::ptr::null_mut() }
}
```

**应改为**:
```rust
#[no_mangle]
pub extern "C" fn rust_encrypt_e2e(
    plaintext: *const u8,
    plaintext_len: u32,
    key: *const u8,
    out_len: *mut u32,
) -> *mut u8 {
    // SAFETY: Caller must provide valid pointers and correct lengths.
    // Caller must free returned buffer with rust_free_bytes.
    if plaintext.is_null() || key.is_null() || out_len.is_null() {
        return std::ptr::null_mut();
    }

    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len as usize) };

    let mut karr = [0u8; 32];
    unsafe { karr.copy_from_slice(std::slice::from_raw_parts(key, 32)) };

    match crypto::encrypt_e2e(pt, &karr) {
        Some(result) => {
            unsafe { *out_len = result.len() as u32 };
            let mut boxed = result.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            std::mem::forget(boxed);
            ptr
        }
        None => std::ptr::null_mut(),
    }
}
```

类似的压缩单行函数存在于:
- `rust_decrypt_e2e` (line 18-21)
- `rust_secure_random` (line 23)
- `rust_constant_time_eq` (line 24)
- `rust_parse_json` (line 25)
- `rust_escape_json` (line 26)
- `rust_validate_utf8` (line 27)
- `rust_cve_init` (line 28)
- `rust_cve_scan` (line 29)
- `rust_free_string` (line 30)
- `rust_free_bytes` (line 31)
- `rust_secure_clear` (line 32)

**影响**: 任何开发者（包括原作者一个月后）需要 5-10 分钟才能理解一个函数的逻辑。unsafe 代码被压缩后极难审查。

---

### Q2: `f2f.rs` — 4 种不同职责塞进一个 71 行文件

- **文件**: `client/security/rust_core/src/dcnet/f2f.rs`
- **严重程度**: 🔴 严重
- **问题**: 一个文件包含数据模型 + 业务逻辑 + 全局状态 + 公共 API + 测试

**当前结构**:
```
f2f.rs (71 行)
├── F2fFriend 结构体 + impl (数据模型)
├── ChannelInfo 结构体 (数据模型)
├── F2fDcNetBridge 结构体 (核心业务逻辑 — 好友/频道/群组/信誉)
├── F2fDcNetBridge impl (20+ 方法)
├── F2F_BRIDGE 全局静态 (全局状态)
├── get_bridge() 公共函数
├── f2f_status() 公共函数
└── #[cfg(test)] 测试模块
```

**应拆分为**:
```
dcnet/
├── f2f/
│   ├── mod.rs          — 模块入口, 全局状态, get_bridge(), f2f_status()
│   ├── friend.rs       — F2fFriend 数据模型 + 方法
│   ├── channel.rs      — ChannelInfo 数据模型
│   └── bridge.rs       — F2fDcNetBridge 业务逻辑
└── f2f.rs              — (向后兼容重导出)
```

**额外问题**: 方法体同样被严重压缩:
```rust
// f2f.rs:20 — 构造+初始化挤在一行
pub fn new(my_uid: &str) -> Self { Self { friends: HashMap::new(), channels: HashMap::new(), groups: HashMap::new(), reputation: ReputationManager::new(), my_uid: my_uid.into(), current_channel: None, min_trust: 1 } }

// f2f.rs:48 — 信誉同步逻辑不可读
for (uid, peer_id, cur) in updates { let rep = self.reputation.get_or_create(&peer_id); let nt = if rep.is_malicious() { 0 } else if rep.score >= 0.8 { 2 } else if rep.score >= 0.5 { 1 } else { 0 }; if cur != nt { if let Some(f) = self.friends.get_mut(&uid) { f.trust_level = nt; changes.push((uid, nt)); } } } changes
```

---

### Q3: `ffi.rs` 承担 4 个不同领域的 FFI 导出

- **文件**: `client/security/rust_core/src/ffi.rs`
- **严重程度**: 🔴 严重
- **问题**: 单一文件包含 Crypto(6) + Parser(3) + CVE(2) + F2F(13) 共 24 个 FFI 函数

**应拆分为**:
```
ffi/
├── mod.rs         — 模块入口 + 公共辅助函数 (safe_c_str, with_bridge)
├── crypto.rs      — rust_encrypt_e2e, rust_decrypt_e2e, rust_secure_random, rust_constant_time_eq, rust_secure_clear, rust_free_bytes
├── parser.rs      — rust_parse_json, rust_escape_json, rust_validate_utf8, rust_free_string
├── cve.rs         — rust_cve_init, rust_cve_scan
└── f2f.rs         — rust_f2f_init, rust_f2f_add_friend, ... (13 functions)
```

---

### Q4: `cve.rs` — `parse_one` 函数内部嵌套 5 个结构体定义

- **文件**: `client/security/rust_core/src/cve.rs`
- **严重程度**: 🟠 高
- **问题**: `parse_one` 方法体内定义了 5 个 serde 反序列化结构体，使得函数体膨胀到 50+ 行

```rust
// cve.rs:48-101 — 函数内嵌套结构体定义反模式
fn parse_one(json: &str) -> Option<CveRecord> {
    #[derive(Deserialize)]
    struct CveContainer { ... }  // 结构体定义在函数内！

    #[derive(Deserialize)]
    struct DescriptionEntry { ... }

    #[derive(Deserialize)]
    struct MetricsContainer { ... }

    #[derive(Deserialize)]
    struct CvssEntry { ... }

    #[derive(Deserialize)]
    struct CvssData { ... }

    // ... 50 行解析逻辑
}
```

**影响**:
- 这些结构体无法被其他函数复用
- 无法单独测试反序列化逻辑
- IDE 无法在模块级别索引这些类型。Rust 支持函数内结构体，但用于大型解析是反模式

**建议**: 将解析结构体提升到模块级别，或将整个 CVE 解析抽取到 `cve/parser.rs`

---

### Q5: `cli/mod.rs` — REPL 循环 + 9 个命令桩 + 分发逻辑混在一起

- **文件**: `client/security/rust_core/src/cli/mod.rs`
- **严重程度**: 🟠 高
- **问题**: 81 行的文件包含 REPL 主循环、IRC 命令路由、User 命令路由、Dev 命令路由、9 个命令占位桩函数、帮助文本

**当前结构**:
```
cli/mod.rs (81 行)
├── pub fn run_repl()       — REPL 主循环 (~40 行)
├── fn cmd_join()           — 占位桩
├── fn cmd_part()           — 占位桩
├── fn cmd_channel_msg()    — 占位桩
├── fn cmd_names()          — 占位桩
├── fn cmd_list()           — 占位桩
├── fn cmd_topic()          — 占位桩
├── fn cmd_nick()           — 占位桩
├── fn cmd_connect()        — 占位桩
├── fn cmd_ping()           — 占位桩
└── fn print_help()         — 帮助文本
```

**建议**:
- 将 9 个 IRC 命令桩移到 `cli/irc_commands.rs`
- REPL 主循环单独保留在 `mod.rs` 或移到 `cli/repl.rs`
- 帮助文本抽取到常量或独立函数

---

## 🟠 中等代码质量问题

### Q6: 代码格式化风格严重不一致

- **严重程度**: 🟠 高
- **问题**: 代码库中存在两种截然不同的格式化风格

**风格 A — 正常 Rust 风格** (ratchet.rs, crypto.rs):
```rust
pub fn encrypt(&mut self, plaintext: &[u8]) -> (Vec<u8>, u64, [u8; 32]) {
    self.send_idx += 1;
    let msg_key = hkdf_expand(&self.send_chain, &self.send_idx.to_le_bytes());
    let cipher = Aes256Gcm::new_from_slice(&msg_key).expect("AES key");
    // ...
}
```

**风格 B — 极限压缩风格** (ffi.rs, f2f.rs, cli/mod.rs):
```rust
pub fn connect(proxy: &str, target_domain: &str, target_port: u16, timeout_secs: u64) -> std::io::Result<Self> {
    let proxy_addr: Vec<_> = proxy.to_socket_addrs()?.collect();
    let mut stream = TcpStream::connect_timeout(&proxy_addr[0], Duration::from_secs(timeout_secs))?;
    // 无空行，多语句同一行，无空格
}
```

**建议**: 运行 `cargo fmt` 统一格式化，并在 CI 中强制执行 `cargo fmt --check`。

---

### Q7: `cve.rs` — `load` 函数是 45 行的过程式面条代码

- **文件**: `client/security/rust_core/src/cve.rs`
- **严重程度**: 🟠 高
- **问题**: `CveDb::load()` 函数 (lines 18-44) 包含 4 层嵌套的 for/if 循环，无任何抽象

```rust
pub fn load(path: &str, min_year: u16) -> std::io::Result<Self> {
    let mut records: Vec<CveRecord> = Vec::with_capacity(100_000);
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for year in min_year..=2026u16 {           // 第1层
        let ypath = format!("{}/{}", path, year);
        if let Ok(entries) = std::fs::read_dir(&ypath) {
            for entry in entries.flatten() {    // 第2层
                let subdir = entry.path();
                if subdir.is_dir() {
                    if let Ok(sub_entries) = std::fs::read_dir(&subdir) {
                        for f in sub_entries.flatten() {  // 第3层
                            let p = f.path();
                            if p.extension().map_or(false, |e| e == "json") { files.push(p); }
                        }
                    }
                }
            }
        }
    }
    for file in &files {                       // 第4层
        if let Ok(json) = std::fs::read_to_string(file) {
            if let Some(rec) = Self::parse_one(&json) { records.push(rec); }
        }
    }
    // ...
}
```

**建议**:
1. 抽取 `collect_json_files(path, min_year)` 函数
2. 抽取 `parse_files(files)` 函数  
3. 考虑使用 `walkdir` crate 简化目录遍历
4. 使用 `rayon` 并行解析（已在 Cargo.toml 中声明但未使用）

---

### Q8: `dcnet/mod.rs` — 模块入口文件包含过多具体实现

- **文件**: `client/security/rust_core/src/dcnet/mod.rs`
- **严重程度**: 🟡 中
- **问题**: 模块入口文件同时包含数据模型 (Participant, DcMessage) 和工具函数 (xor_bytes, generate_share)

`mod.rs` 应该只做模块声明和重导出。具体的数据模型和工具函数应移到独立文件。

**建议**: 
- `Participant` → `dcnet/participant.rs`
- `DcMessage` → `dcnet/message.rs`
- `xor_bytes`, `generate_share` → `dcnet/utils.rs`

---

### Q9: `cli/user.rs` — 每个命令函数都有重复的 `STATE.lock().unwrap()` 模式

- **文件**: `client/security/rust_core/src/cli/user.rs`
- **严重程度**: 🟡 中
- **问题**: 5 个命令函数中有 11 处 `STATE.lock().unwrap()` 调用，无任何抽象

```rust
pub fn cmd_uid(args: &[&str]) {
    match args.first().copied() {
        Some("set") => {
            STATE.lock().unwrap().my_uid = Some(args[1].to_string());  // 重复
        }
        Some("show") => {
            let uid = STATE.lock().unwrap().my_uid.clone()...           // 重复
        }
    }
}
```

**建议**: 提供 `with_state(f)` 辅助函数：
```rust
fn with_state<F, R>(f: F) -> R where F: FnOnce(&mut CliState) -> R {
    f(&mut STATE.lock().unwrap())
}
```

---

### Q10: `cmd_chat` 交互循环内部每轮迭代都获取 Mutex 锁

- **文件**: `client/security/rust_core/src/cli/user.rs`
- **严重程度**: 🟡 中
- **行号**: 81-99
- **问题**: 聊天循环中每次发送消息都获取/释放 Mutex，这不是必要的（单线程 CLI），但反映了不好的并发编程习惯

```rust
loop {
    // ... 读取用户输入 ...
    let mut state = STATE.lock().unwrap();   // 每轮迭代都 lock/unlock
    let from = state.my_uid.clone()...;
    state.messages.push((from, peer, line));
}
```

**建议**: 在循环外获取一次锁，或收集消息后批量写入。

---

### Q11: `cli/dev.rs` — 占位桩代码无标记表明其未完成

- **文件**: `client/security/rust_core/src/cli/dev.rs`
- **严重程度**: 🟡 中
- **问题**: `cmd_cve` 和 `cmd_f2f` 只打印占位消息，不执行实际操作。无 `// TODO` 或 `unimplemented!()` 宏标记

```rust
pub fn cmd_cve(args: &[&str]) {
    match args.first().copied() {
        Some("search") => println!("  Search '{}': (DB not loaded)", args[1]),
        Some("load") => println!("[*] Loading CVE database..."),
        Some("stats") => println!("  CVE Database: 0 records (use cve load)"),
        _ => println!("  cve load|search|check|stats"),
    }
}
```

**建议**: 使用 `unimplemented!()` 或至少添加 `// TODO: Wire up to cve::CveDb` 注释。

---

## 🟡 轻度代码质量问题

### Q12: 中英文注释混用

- **严重程度**: 🟢 低
- **文件**: `lib.rs`, `dcnet/f2f.rs`, 多处
- **问题**: `lib.rs` 使用中文注释，`f2f.rs` 使用英文注释，`ratchet.rs` 混合使用

```rust
// lib.rs — 中文
//! chrono-core — Chrono-shift v7.0 (纯 Rust)
//! 模块:
//!   - cli:     IRC 风格 CLI REPL

// f2f.rs — 英文
//! F2F trust web -> DC-Net multi-channel bridge (v7.0)
```

**建议**: 统一使用英文注释（开源项目惯例），或在项目范围内统一中文。

---

### Q13: 测试模块位置不一致

- **严重程度**: 🟢 低
- **问题**: 
  - `ratchet.rs` — 测试在独立的 `mod tests` 块中，格式良好
  - `cve.rs` — 使用 `#[cfg(test)] mod tests { use super::*;` 但花括号和代码在同一行
  - `network.rs` — 同上，压缩风格
  - `dcnet/mod.rs` — 测试紧跟在模块代码后，无空行分隔
  - `dcnet/round.rs` — 同上

**建议**: 统一为独立 `tests` 模块，与其他代码用至少一个空行分隔。

---

### Q14: `ShuffleCommitment::decrypt_slot` 是关联函数而非方法

- **文件**: `client/security/rust_core/src/dcnet/shuffle.rs`
- **严重程度**: 🟢 低
- **问题**: `decrypt_slot` 接收 `&ShuffleSlot` 参数但不接收 `&self`。它不访问 `ShuffleCommitment` 的任何字段

```rust
impl ShuffleCommitment {
    pub fn decrypt_slot(slot: &ShuffleSlot) -> Option<Vec<u8>> { ... }
}
```

**建议**: 将 `decrypt_slot` 移到 `ShuffleSlot` 的 `impl` 块中：
```rust
impl ShuffleSlot {
    pub fn decrypt(&self) -> Option<Vec<u8>> { ... }
}
```

---

### Q15: `F2fDcNetBridge` 构造函数参数过多

- **文件**: `client/security/rust_core/src/dcnet/f2f.rs`
- **严重程度**: 🟢 低
- **行号**: 20
- **问题**: `new()` 初始化 8 个字段，其中 7 个是相同的默认值。应使用 `Default` trait 或 builder 模式

```rust
pub fn new(my_uid: &str) -> Self {
    Self {
        friends: HashMap::new(),
        channels: HashMap::new(),
        groups: HashMap::new(),
        reputation: ReputationManager::new(),
        my_uid: my_uid.into(),
        current_channel: None,
        min_trust: 1,
    }
}
```

**建议**: 派生或实现 `Default`，然后仅覆盖 `my_uid`:
```rust
impl F2fDcNetBridge {
    pub fn new(my_uid: &str) -> Self {
        Self { my_uid: my_uid.into(), ..Default::default() }
    }
}
```

---

### Q16: 魔法数字散布各处

- **严重程度**: 🟢 低
- **问题**: 关键常量硬编码在代码中

| 位置 | 魔法值 | 含义 |
|------|--------|------|
| `ratchet.rs:67` | `b"chrono-ratchet-v1"` | HKDF info 字符串 |
| `ratchet.rs:90` | `b"chain-advance"` | 链密钥推进 info |
| `ratchet.rs:144` | `b"dh-ratchet"` | DH 棘轮 info |
| `cve.rs:21` | `2026u16` | 年份上限 |
| `network.rs:9` | `127.0.0.1:9050` | Tor SOCKS5 代理地址 |
| `network.rs:37` | `500 * 2u64.pow(i)` | 指数退避延迟 |
| `dcnet/round.rs:17` | `30` (秒) | 轮次超时 |
| `dcnet/reputation.rs:9` | `0.5`, `0.05`, `0.7`, `1.0` | 信誉评分参数 |
| `dcnet/reputation.rs:13` | `3`, `80`, `10`, `0.5` | 恶意行为阈值 |

**建议**: 定义常量或配置文件：
```rust
// 在 lib.rs 或 config.rs 中
pub const PROTOCOL_VERSION: &[u8] = b"chrono-ratchet-v1";
pub const DEFAULT_TOR_PROXY: &str = "127.0.0.1:9050";
pub const ROUND_TIMEOUT_SECS: u64 = 30;
pub const REPUTATION_INITIAL: f64 = 0.5;
pub const REPUTATION_REWARD: f64 = 0.05;
pub const REPUTATION_PENALTY_MULTIPLIER: f64 = 0.7;
pub const REPUTATION_BAN_THRESHOLD: f64 = 0.3;
pub const REPUTATION_MAX: f64 = 1.0;
```

---

### Q17: `cve.rs` `load` 函数全量加载无流式处理

- **文件**: `client/security/rust_core/src/cve.rs`
- **严重程度**: 🟢 低 (当前可用, 大规模时成问题)
- **行号**: 37-41
- **问题**: 将所有 JSON 文件读入内存后再解析。对于 347,868 条 CVE 记录，如果每个文件平均 5KB，总计约 1.7GB

```rust
for file in &files {
    if let Ok(json) = std::fs::read_to_string(file) {  // 全量读入内存
        if let Some(rec) = Self::parse_one(&json) { records.push(rec); }
    }
}
```

**建议**: 使用 `serde_json::from_reader` 流式解析，或在读取后立即 drop json 字符串。

---

## 🔒 新发现的安全问题 (前报告未覆盖)

### S1: FFI 加密函数中密钥残留在栈上未清零

- **文件**: `client/security/rust_core/src/ffi.rs`
- **严重程度**: 🟠 HIGH
- **行号**: 15, 20
- **状态**: 前报告 MEDIUM-10 提及，但**当前代码仍未修复**

```rust
// ffi.rs:15 — karr 是栈上的 32 字节 AES 密钥，函数返回前未清零
let mut karr=[0u8;32]; unsafe{karr.copy_from_slice(std::slice::from_raw_parts(key,32))};
match crypto::encrypt_e2e(pt,&karr) { ... }
// ⚠️ karr 未清零就随栈帧回收
```

**修复**: 在 match 之后添加 `crypto::secure_clear(&mut karr);`

---

### S2: `f2f.rs` — F2fFriend 的 trust_level 在 `new()` 时用 `.min(2)` 截断，但后续 `update_trust` 中的截断不一致

- **文件**: `client/security/rust_core/src/dcnet/f2f.rs`
- **严重程度**: 🟡 MEDIUM
- **行号**: 9, 23
- **问题**: 
  - `F2fFriend::new()` 使用 `trust_level.min(2)` — 将值限制在 0-2
  - `update_trust()` 同样使用 `.min(2)` — 限制在 0-2
  - 但 `get_trust()` 返回 `trust_level + 1` — 映射为 1-3
  - `is_trusted()` 检查 `trust_level >= self.min_trust` — 与 `trust_level + 1` 的语义不一致
  
  这导致 trust_level 的语义在同一个结构体的不同方法中表示不同范围的值。

---

### S3: `f2f.rs` — `group_status()` 和 `channel_status()` 使用 `format!` 构造 JSON，存在注入风险

- **文件**: `client/security/rust_core/src/dcnet/f2f.rs`
- **严重程度**: 🟡 MEDIUM
- **行号**: 44, 52-54
- **状态**: 前报告 MEDIUM-3 提及

```rust
// 如果 my_uid 是 test"user，会生成非法 JSON
format!(r#"{{"my_uid":"{}"}}"#, self.my_uid)
// 输出: {"my_uid":"test"user"}  ← 非法 JSON
```

**修复**: 使用 serde 序列化，绝不手写 JSON。

---

### S4: `parser.rs` — `JsonValue` 结构体的 `to_string()` 可能产生非 JSON 输出

- **文件**: `client/security/rust_core/src/parser.rs`
- **严重程度**: 🟡 MEDIUM
- **行号**: 8
- **问题**: `serde_json::Value::to_string()` 在某些类型上产生非标准 JSON 格式。浮点数可能使用非标准表示法。建议使用 `serde_json::to_string(&v)` 确保合法 JSON。

---

## 📋 文件质量评分卡

| 文件 | 可读性 | 模块化 | 格式化 | 安全性 | 综合 |
|------|--------|--------|--------|--------|------|
| `crypto.rs` | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| `ratchet.rs` | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| `parser.rs` | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `storage.rs` | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ |
| `network.rs` | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `cve.rs` | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| `ffi.rs` | ⭐ | ⭐ | ⭐ | ⭐⭐ | ⭐ |
| `dcnet/mod.rs` | ⭐⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `dcnet/round.rs` | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `dcnet/group.rs` | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `dcnet/shuffle.rs` | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `dcnet/reputation.rs` | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `dcnet/f2f.rs` | ⭐ | ⭐ | ⭐ | ⭐⭐ | ⭐ |
| `cli/mod.rs` | ⭐⭐ | ⭐⭐ | ⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| `cli/user.rs` | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `cli/dev.rs` | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| `lib.rs` | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | N/A | ⭐⭐⭐⭐ |
| `main.rs` | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | N/A | ⭐⭐⭐⭐ |

---

## 🎯 改进路线图

### 第一步：格式化统一 (1 小时)
1. 运行 `cargo fmt` 自动格式化所有文件
2. 在项目中添加 `.rustfmt.toml` 配置文件
3. 手动展开 ffi.rs 中的单行函数体

### 第二步：文件拆分 (2-3 小时)
1. 拆分 `ffi.rs` → `ffi/{mod, crypto, parser, cve, f2f}.rs`
2. 拆分 `f2f.rs` → `dcnet/f2f/{mod, friend, channel, bridge}.rs`
3. 提取 `cve.rs` 中的解析结构体到模块级别
4. 拆分 `cli/mod.rs` → `cli/{repl, irc_cmds}.rs`

### 第三步：消除魔法数字 (1 小时)
1. 创建 `src/constants.rs` 集中定义所有常量
2. 替换各文件中的硬编码值

### 第四步：代码结构优化 (2-3 小时)
1. 统一测试模块格式 (`#[cfg(test)] mod tests { ... }`)
2. 提取重复的 `STATE.lock().unwrap()` 模式
3. 添加 `Default` 实现
4. 修复函数归属错误 (`decrypt_slot` → `ShuffleSlot`)

### 第五步：安全加固 (与现有报告同步)
1. ffi.rs 加密函数后清零栈上密钥 (MEDIUM-10)
2. JSON 构造改用 serde 序列化 (MEDIUM-3)
3. 添加 `// SAFETY:` 文档到所有 unsafe 块

---

## 📎 附录：模块拆分目标结构

**当前** (18 文件):
```
src/
├── lib.rs, main.rs
├── crypto.rs, ratchet.rs, parser.rs, network.rs, cve.rs
├── ffi.rs          ← 4 个领域混在一起
├── storage.rs
├── cli/{mod.rs, user.rs, dev.rs}
└── dcnet/{mod.rs, round.rs, group.rs, reputation.rs, shuffle.rs, f2f.rs}
                                            ↑ f2f.rs 包含太多
```

**建议目标** (25+ 文件):
```
src/
├── lib.rs, main.rs, constants.rs
├── crypto.rs, ratchet.rs, parser.rs, network.rs, storage.rs
├── cve/
│   ├── mod.rs          — 公共 API, OnceLock 全局单例
│   ├── model.rs        — CveRecord, 解析结构体
│   └── database.rs     — CveDb, load/scan/search/stats
├── ffi/
│   ├── mod.rs          — 模块入口, 公共辅助 (safe_c_str, with_bridge)
│   ├── crypto.rs       — 加密 FFI
│   ├── parser.rs       — 解析 FFI
│   ├── cve.rs          — CVE FFI
│   └── f2f.rs          — F2F Bridge FFI
├── cli/
│   ├── mod.rs          — REPL 入口 + 命令分发
│   ├── user.rs         — 用户管理命令
│   ├── dev.rs          — 开发者命令
│   └── irc_cmds.rs     — IRC 风格命令 (join/part/msg/names/...)
└── dcnet/
    ├── mod.rs          — 模块入口 + re-exports
    ├── participant.rs  — Participant 结构体
    ├── message.rs      — DcMessage 结构体
    ├── utils.rs        — xor_bytes, generate_share
    ├── round.rs        — DcRound
    ├── group.rs        — DcGroup
    ├── reputation.rs   — ReputationManager
    ├── shuffle.rs      — ShuffleSlot, ShuffleCommitment, BlameProtocol
    └── f2f/            — F2F 信任网络桥接
        ├── mod.rs      — 全局状态, get_bridge()
        ├── friend.rs   — F2fFriend
        ├── channel.rs  — ChannelInfo
        └── bridge.rs   — F2fDcNetBridge
```

---

**报告生成**: 2026-06-04 | **维护者**: haiyanfurry | **许可证**: GPLv3
