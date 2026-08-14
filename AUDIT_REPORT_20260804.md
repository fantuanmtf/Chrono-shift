# Chrono-shift v8.0 全面代码审计报告

> **审计日期**: 2026-08-04
> **审计范围**: `client/security/rust_core/src/` 全部 29 个源文件 (~5,500 行)
> **Rust 版本**: rustc 1.80+
> **编译结果**: ✅ 通过 (cargo check, 7 warnings)
> **测试结果**: ✅ 118/118 通过 (0 失败)
> **审计方式**: 4 路并行深度代码审查 + 手动代码审查

---

## 一、总体评估

Chrono-shift v8.0 是一个纯 Rust 重写的 P2P 匿名通信系统，核心由 18 个模块组成，实现了 DC-Net（Dining Cryptographers Network）匿名层、Ed25519 身份认证、AES-256-GCM 加密、Double Ratchet 前向安全、PGP Web of Trust、F2F 信任网、以及 TCP/IPC 网络层。

**总体评分: 6.5/10** — 核心加密设计正确，但安全集成不完整，存在多个严重安全缺陷。

| 维度 | 评分 | 说明 |
|------|------|------|
| 加密实现 | 8/10 | AES-256-GCM、Ed25519、X25519 DH 使用正确 |
| 网络传输安全 | 3/10 | **TCP 明文传输，无 TLS，无连接认证** |
| 模块结构 | 8/10 | 清晰 4 层 DAG，无循环依赖 |
| 错误处理 | 5/10 | 三种不兼容错误策略，大量静默吞错 |
| 测试覆盖 | 7/10 | 118 测试全覆盖，质量中等偏上 |
| 文档 | 7/10 | 模块级注释好，部分过时 |

| 严重程度 | 数量 | 状态 |
|----------|------|------|
| 🔴 CRITICAL | 6 | 需立即修复 |
| 🟠 HIGH | 7 | 需尽快修复 |
| 🟡 MEDIUM | 12 | 建议修复 |
| 🟢 LOW | 8 | 建议改进 |

---

## 二、🔴 CRITICAL 问题

### [CRIT-1] TCP 连接无任何认证 — 任意主机可成为对等节点

**文件**: `net/connection_manager.rs` 第 149-167 行

```rust
for stream in listener.incoming().flatten() {
    let addr = stream.peer_addr()?;
    let uid = format!("__incoming_{}", addr);
    // 无 AuthChallenge/AuthResponse — 直接接受!
    connections.insert(uid.clone(), conn);
}
```

**问题**: TCP 监听器接受所有入站连接，零认证。`handshake.rs` 中完整实现了 Ed25519 Challenge-Response 认证协议（`build_auth_challenge` → `build_auth_response` → `verify_auth_response`），但**从未被集成到连接接受流程中**。任何知道端口号的远程主机可以直接连接并被当作对等节点。

**影响**: 攻击者可以：
- 连接到目标节点，发送伪造的 DC-Net 共享份额
- 注入虚假的 `DcRoundShare` 破坏匿名集合
- 发送超大 payload 消耗资源
- 作为中间人拦截所有 PeerMessage（因为无加密传输）

**修复建议**: 在 `start_listener` 的 accept 循环中，接受连接后立即发起 `AuthChallenge`，等待 `AuthResponse` 并调用 `verify_auth_response`，验证通过后才将连接加入 active_connections。

---

### [CRIT-2] Web of Trust 签名从未经过加密验证

**文件**: `pgp/web_of_trust.rs` 第 101-117 行

```rust
pub fn add_signature(&mut self, sig: TrustSignature) -> Result<(), String> {
    // 检查签名者和主体是否在密钥环中...
    // ⚠️ 无任何 Ed25519 签名验证!
    self.signatures.push(sig);
    Ok(())
}
```

**问题**: `TrustSignature` 结构体包含 `signature_data: Vec<u8>` 字段（注释说 "Ed25519 signature bytes"），但 `add_signature` 方法**从未调用 `ed25519_dalek` 验证签名**。测试代码甚至使用 `vec![1, 2, 3]` 作为有效签名数据（第 346 行）。

**影响**: 攻击者可以完全绕过信任模型：
- 伪造任意信任签名
- 将任何身份提升到 Full/Ultimate 信任级别
- 成为任何 DC-Net 网络的"可信"成员
- 完全破坏 Web of Trust 的安全基础

**修复建议**: 在 `add_signature` 中添加 Ed25519 签名验证：
1. 从密钥环中查找签名者的公钥
2. 构造签名数据：`SHA-256(subject_fingerprint || trust_level || timestamp)`
3. 调用 `verifying_key.verify(&digest, &signature)`
4. 验证失败则拒绝签名

---

### [CRIT-3] 密钥交换缺乏前向安全性 — 会话密钥从长期密钥派生

**文件**: `handshake.rs` 第 122-139 行

```rust
pub fn derive_session_key(our_pubkey: &str, remote_pubkey: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"chrono-handshake-v1");
    hasher.update(our_pubkey.as_bytes());
    hasher.update(remote_pubkey.as_bytes());
    // ⚠️ 仅从长期公钥派生 — 无临时 ECDH!
    hasher.finalize().into()
}
```

**问题**: 会话密钥仅从双方的长期 Ed25519 公钥通过 SHA-256 派生。没有临时密钥交换（ECDH）。一旦任何一方的长期密钥泄露，**所有过去和将来的会话密钥**都可以被计算出来。这违反了前向安全性（Forward Secrecy）的基本要求。

此外，文档注释声称使用 "HKDF-SHA256" 但实际使用的是原始 SHA-256，不包含 HKDF 的 extract/expand 步骤。

**影响**: 长期密钥泄露 = 所有历史会话内容泄露。

**修复建议**: 
1. 集成 X25519 临时密钥交换（ratchet.rs 已有完整实现）
2. 在握手中加入临时公钥交换
3. 使用真正的 HKDF (hkdf crate 已在 Cargo.toml 中)

---

### [CRIT-4] 握手仅单向认证 — 缺少接收方认证

**文件**: `handshake.rs` 整体协议设计

```
Initiator                     Receiver
  │ TCP connect ────────────→  │
  │ ← AuthChallenge ────────── │
  │ AuthResponse ────────────→ │  ← 仅发起方被认证!
  │ ← FriendAccept ─────────── │  ← 接收方从未证明自己
  │                             │
  └── "Encrypted" channel ─────┘
```

**问题**: 握手协议仅认证了发起方（Alice）的身份。接收方（Bob）从未被 challenge，从未提供签名。这意味着：
- 攻击者可以冒充 Bob 接受 Alice 的连接
- Alice 无法确认她正在与真正的 Bob 通信
- 经典的中间人攻击（MITM）场景

**影响**: 即使集成了握手（CRIT-1 修复后），没有相互认证的握手意味着攻击者可以在中间人位置解密所有流量。

**修复建议**: 扩展协议为相互认证：
1. Bob 发送 AuthChallenge（已实现）
2. Alice 发送 AuthResponse（已实现）
3. Bob 验证 Alice 的签名并发送自己的 AuthResponse
4. Alice 验证 Bob 的签名
5. 双方确认后才建立加密通道

---

### [CRIT-5] FFI 边界内存安全缺陷 — 缓冲区溢出风险

**文件**: `ffi.rs` 第 43-66, 95-104 行

```rust
// rust_encrypt_e2e: 假设 key 指针总是有 32 字节
unsafe { karr.copy_from_slice(std::slice::from_raw_parts(key, 32)) };

// rust_secure_random: 无缓冲区边界验证
let b = unsafe { std::slice::from_raw_parts_mut(buf, len as usize) };
b.copy_from_slice(&crypto::secure_random_bytes(len as usize));
```

**问题**: 
1. `rust_encrypt_e2e`/`rust_decrypt_e2e` 假设 `key` 参数指向至少 32 字节的缓冲区 — 无验证，可能导致越界读取
2. `rust_secure_random` 不验证 `buf` 指针指向的缓冲区大小是否 ≥ `len` — 可能导致堆/栈缓冲区溢出
3. `APP_STATE_PTR` 存在 TOCTOU 竞态条件：加载和提领之间的窗口，`AtomicPtr` 可能被修改
4. `rust_free_bytes`/`rust_free_string` 依赖 C 调用者传递正确的分配元数据 — 错误调用即 UB

**影响**: 来自 C 代码的恶意或错误调用可导致内存破坏、信息泄露、或代码执行。

**修复建议**:
1. 对所有 `from_raw_parts` 调用添加明确的长度边界检查
2. 使用 `AtomicPtr::compare_exchange` 或一次性快照来修复 TOCTOU
3. 考虑使用 `#[repr(C)]` 结构体传递参数，减少对原始指针的依赖

---

### [CRIT-6] DC-Net pairwise share 使用确定性 SHA-256 而非真正的 DH — 无密钥保密性

**文件**: `dcnet/round_network.rs` 第 151-172 行

```rust
fn pairwise_share(round_id: u64, peer_a: &str, peer_b: &str, output_len: usize) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(round_id.to_be_bytes());
    hasher.update(p1.as_bytes());  // 仅用公开的 UID 作为输入!
    hasher.update(p2.as_bytes());
    // ...
}
```

**问题**: "pairwise shared secret" 完全由公开信息确定（round_id + UID 对）。任何知道组成员列表的人都可以计算所有成对份额。这**不是共享密钥**—这是一个公开的函数。虽然对于诚实的 DC-Net 参与者来说 XOR 抵消是正确的，但这意味着：
- 被动观察者计算所有配对份额后可以提取发送者的消息
- 不提供任何针对组外观察者的匿名保护
- 代码声称使用 "X25519 ECDH" 但实际是 SHA-256 哈希

**影响**: DC-Net 的匿名性完全依赖于"所有参与者都诚实且不串通"的假设，但即使在这个假设下，外部观察者也能破解。

**修复建议**: 使用真正的临时 ECDH：
1. 每个参与者生成 X25519 临时密钥对
2. 通过安全通道交换公钥
3. 执行 `DH(my_secret, peer_public)` 得到共享密钥
4. 使用 HKDF 派生最终的 XOR 份额

---

## 三、🟠 HIGH 问题

### [HIGH-1] TCP 传输无加密 — 所有 PeerMessage 以明文传输

**文件**: `net/connection_manager.rs` 第 297-362 行, `net/tcp.rs` 第 42-47 行

所有 `PeerMessage`（包括 ChannelMessage、DcRoundShare、NetworkInvite 等）作为纯文本 JSON 在 TCP 上发送。`handshake.rs` 的 `encrypt_frame`/`decrypt_frame` 函数已实现但从未被网络层调用。

**修复**: 在连接认证后启用帧加密层。

---

### [HIGH-2] 私钥以未加密明文存储在磁盘 — Windows 无文件权限保护

**文件**: `identity.rs` 第 42-43, 65, 76 行

```rust
secret_hex: hex_encode(signing_key.as_bytes()), // 十六进制明文
fs::write(&path, json).ok(); // 无文件权限设置（Windows）
```

Unix 下设置了 `0o600` 权限（第 78-82 行），但：
- Windows 上无等效保护
- `load_or_generate` 初始创建时不设权限
- 无密码短语加密，无密钥派生

**修复**: 
1. 使用 `windows-sys` 的 `Win32_Security` 设置 Windows ACL
2. 添加可选的密码短语加密（使用 Argon2/AES 密钥包装）
3. 在所有 `create_dir_all`/`write` 调用后立即设置权限

---

### [HIGH-3] 无连接限制 — 可被 DoS 耗尽线程/内存

**文件**: `connection_manager.rs:149-172`, `daemon.rs:59-67`

- TCP 监听器无限制地接受连接并生成 tokio 任务
- IPC 服务器为每个 CLI 连接生成一个 OS 线程
- mpsc 通道无容量限制（`app.rs:64-66`）
- 无连接超时或空闲断开

**修复**: 添加连接数上限、通道容量限制、空闲超时。

---

### [HIGH-4] 重放攻击 — RoundTracker 允许相同 round_id 重放

**文件**: `dcnet/round_network.rs` 第 261-263, 287-290 行

```rust
pub fn is_stale(&self, round_id: u64) -> bool {
    round_id < self.last_seen_round_id  // 允许 round_id == last_seen 重放
}
```

**修复**: 改为 `round_id <= self.last_seen_round_id`。

---

### [HIGH-5] 心跳/发现任务为空实现 — 网络管理功能缺失

**文件**: `main.rs` 第 54-60 行

```rust
tokio::spawn(async move {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let _ = heartbeat_shared; // 什么都不做!
    }
});
```

**修复**: 实现实际的 LAN 发现广播、连接健康检查和自动重连。

---

### [HIGH-6] DC-Net 去填充 (unpad) 会截断尾部为零的消息

**文件**: `dcnet/round_network.rs` 第 183-189 行

```rust
pub fn unpad_message(padded: &[u8]) -> Vec<u8> {
    let mut end = padded.len();
    while end > 0 && padded[end - 1] == 0 { end -= 1; }
    padded[..end].to_vec()  // ⚠️ 删除所有尾部零!
}
```

任何以零字节结尾的二进制消息都会被截断。

**修复**: 使用长度前缀方案（`f2f.rs` 的 "C1 fix" 方法）。

---

### [HIGH-7] Round driver 线程泄漏 — Arc clone 导致线程永不死

**文件**: `dcnet/f2f.rs` 第 380-387 行

```rust
let running = ch.running.clone();  // Arc clone
std::thread::spawn(move || {
    while running.load(...) {
        std::thread::sleep(...);
        // 实际无任何 DC-Net 工作!
    }
});
```

即使 `F2fDcNetBridge` 被销毁，线程因持有自己的 `Arc` 而永不停止。

**修复**: 使用 `Arc::downgrade` (Weak) 或实际执行 DC-Net 轮次逻辑。

---

## 四、🟡 MEDIUM 问题

| # | 问题 | 文件:行 |
|---|------|---------|
| M1 | `create_channel`/`join_channel` 消息为存根 — 返回成功但无实际操作 | `daemon.rs:274-283` |
| M2 | relay 路由器双重存在 — AppState 实例与全局静态冲突 | `relay.rs:82` vs `app.rs:31` |
| M3 | `unpad_message` 零填充导致二进制消息数据丢失 | `round_network.rs:183-189` |
| M4 | 声誉 `drop_timing_pct` Vec 无界增长 — 长期内存泄漏 | `reputation.rs:41` |
| M5 | `next_leader`/`rotate_leader` 空 `member_join_order` 时除零 panic | `network.rs:89-96` |
| M6 | 传入泵每 100ms 忙轮询 — 效率低下 | `main.rs:104` |
| M7 | `net` feature 为死代码 — 无 `#[cfg(feature="net")]` 使用 | `Cargo.toml:63-65` |
| M8 | 三种不兼容错误策略 — `io::Result` / `Result<T,String>` / `Option<T>` | 全项目 |
| M9 | `group.start_round` 在失败操作上产生副作用 — 移除恶意节点先于人数检查 | `group.rs:34` |
| M10 | 恶意节点移除使用 `Vec<u8>`→`[u8;32]` 静默回退 | `f2f.rs:357` |
| M11 | `sender_idx` 回退到 0 隐藏发件人不在列表中的错误 | `f2f.rs:269` |
| M12 | 握手的 challenge nonce 无时间戳/过期 — 可被捕获后重放 | `handshake.rs:35-45` |

---

## 五、🟢 LOW 问题

| # | 问题 | 文件:行 |
|---|------|---------|
| L1 | IPC handler 中 `.unwrap()` 可能 panic (peer_addr, try_clone) | `daemon.rs:92,95` |
| L2 | 测试 `app.rs:137` 断言总是为真 (tautology) | `app.rs:137` |
| L3 | 7 个编译器警告（未使用变量、mutability） | 全项目 |
| L4 | 用户可见字符串中英文混用 | 全项目 |
| L5 | `lib.rs` 文档注释过时 | `lib.rs:1-10` |
| L6 | SOCKS5 指数回退 `2^retries * 500ms` 高重试次数时可能溢出 | `network.rs:82` |
| L7 | shuffle `merkle_root` 是简单拼接哈希不是真正的 Merkle 树 | `shuffle.rs:116-125` |
| L8 | commitment 验证使用非固定时间字符串比较 | `round_network.rs:322-324` |

---

## 六、模块加载分析

### 6.1 模块结构

`lib.rs` 声明了 18 个公开模块，形成清晰的 4 层无环依赖图 (DAG)：

```
Layer 1 (基础):
  crypto, identity, parser, network, dcnet/{reputation,round}, net/{lan,transport}

Layer 2 (中间):
  pgp, handshake, ratchet, net/{tcp,connection_manager,relay},
  storage, protocol_filter, service, dcnet/{group,shuffle,network}

Layer 3 (上层):
  dcnet/{f2f,round_network}, round_engine, app

Layer 4 (顶层):
  daemon, ffi
```

### 6.2 编译状态

```
cargo check: ✅ PASS (7 warnings, 0 errors)
cargo test:  ✅ 118 passed, 0 failed, 0 ignored
```

所有 7 个警告均为未使用变量和未使用的 mutability，无功能影响。

### 6.3 Crate 目标

| 目标 | 路径 | 类型 |
|------|------|------|
| `chrono-daemon` | `src/main.rs` | 守护进程二进制 |
| `chrono-cli` | `src/cli_main.rs` | CLI 控制台二进制 |
| `chrono-core` | (lib) | staticlib + cdylib + rlib |

`net` feature 目前为死代码 — 三个可选依赖 (`reqwest`, `tungstenite`, `rustls`) 未被任何代码使用。

---

## 七、加密安全评估

### 7.1 做得好的方面 ✅

1. **所有 RNG 使用 `OsRng`**（操作系统 CSPRNG）— 覆盖 crypto, identity, handshake, ratchet, dcnet
2. **AES-256-GCM** 正确使用 — 每条消息新鲜 nonce，认证标签自动验证
3. **Ed25519 签名** — 握手签名绑定到 nonce+公钥，防止重放和身份绑定
4. **Double Ratchet** — Signal 协议风格，每条消息前向安全性，重放保护
5. **常量时间比较** — `crypto::constant_time_eq` 使用 `black_box` 防优化
6. **秘密清零** — `zeroize` crate 用于 Drop 和显式擦除
7. **Shuffle slot keys** — `#[serde(skip)]` 防止密钥序列化传输
8. **发布配置** — `panic="abort"`, `lto=true`, `strip=true` — 安全最佳实践
9. **无硬编码凭据** — grep 全项目未发现硬编码密钥/密码

### 7.2 依赖版本

所有加密依赖均为最新/维护良好的 crate：

| 依赖 | 版本 | 状态 |
|------|------|------|
| aes-gcm | 0.10 | ✅ 当前 |
| ed25519-dalek | 2 | ✅ 当前 |
| x25519-dalek | 2 | ✅ 当前 |
| hkdf | 0.12 | ✅ 当前 |
| sha2 | 0.10 | ✅ 当前 |
| zeroize | 1 | ✅ 当前 |

---

## 八、与上次审计的对比

上次审计报告 (`CODE_AUDIT_REPORT_20260630.md`) 发现的 4 个 CRITICAL 问题的处理状态：

| 上次 # | 问题 | 当前状态 |
|--------|------|---------|
| C1 | 尾部零字节截断 | ✅ **已修复** — f2f.rs 使用长度前缀方案 |
| C2 | SHA-256 替代 X25519 DH | ⚠️ **部分修复** — f2f.rs 有代码但未正确集成; round_network.rs 仍用 SHA-256 |
| C3 | stream cipher 无 IV/无 MAC | ✅ **已修复** — 使用 AES-256-GCM |
| C4 | encrypt/decrypt 同一函数 | ✅ **已修复** — 使用 AES-256-GCM |

上次审计的 HIGH 问题：
- H1-H2 (JSON/命令注入): ✅ **已通过 Rust 迁移修复**（使用 serde_json 替代字符串拼接）
- H3 (Keypair 实际是对称密钥): ✅ **已修复** — 实现了真正的 Ed25519 + X25519
- H4 (加解密同一函数): ✅ **已修复**
- H5 (无消息认证): ⚠️ **部分修复** — GCM 提供 AEAD，但仅在使用加密帧时有效

---

## 九、修复优先级路线图

### Phase 1 — 立即修复 (1-2 周)

| 优先级 | 问题 | 预计工时 |
|--------|------|---------|
| P0 | CRIT-1: 集成握手认证到 TCP 监听器 | 4h |
| P0 | CRIT-2: Web of Trust 签名验证 | 2h |
| P0 | CRIT-3: 临时密钥交换 + 前向安全性 | 4h |
| P0 | CRIT-4: 相互认证握手 | 3h |
| P1 | HIGH-1: 启用传输加密 | 2h |
| P1 | HIGH-4: 重放保护修复 | 0.5h |

### Phase 2 — 近期修复 (2-4 周)

| 优先级 | 问题 | 预计工时 |
|--------|------|---------|
| P2 | CRIT-5: FFI 内存安全加固 | 6h |
| P2 | CRIT-6: 真正的 ECDH pairwise shares | 8h |
| P2 | HIGH-2: Windows 密钥文件权限 + 加密存储 | 4h |
| P2 | HIGH-3: 连接限制 + DoS 防护 | 4h |
| P2 | HIGH-6: 去填充数据丢失修复 | 1h |

### Phase 3 — 后续改进 (1-2 月)

| 优先级 | 问题 | 预计工时 |
|--------|------|---------|
| P3 | M1-M12: 所有 MEDIUM 问题 | ~20h |
| P3 | HIGH-5: 心跳/LAN 发现实现 | 6h |
| P3 | HIGH-7: Round driver 线程管理 | 3h |
| P3 | 统一错误处理策略 | 8h |
| P3 | L1-L8: 所有 LOW 问题 | ~8h |

---

## 十、合规性

- **OWASP Top 10 (2021)**: 覆盖 A02(加密失效), A03(注入), A04(不安全设计), A06(脆弱组件), A07(认证失效)
- **CWE Top 25**: 覆盖 CWE-295(证书验证不当), CWE-306(关键功能缺少认证), CWE-311(敏感数据缺少加密), CWE-327(使用破损/风险加密), CWE-347(签名验证不当), CWE-522(凭证保护不足)
- **NIST SP 800-53**: 对应 AC(访问控制), IA(身份认证), SC(系统与通信保护), SI(系统与信息完整性)

---

## 十一、结论

Chrono-shift v8.0 的加密核心（AES-256-GCM、Ed25519、Double Ratchet）设计正确且实现良好。但**网络层的安全集成严重不足**：TCP 连接无认证无加密，Web of Trust 签名完全不验证，密钥交换缺乏前向安全性。这些问题使得系统的安全模型在当前状态下**不可信赖**。

**建议优先完成 Phase 1 修复（约 15.5 工时），使基本安全机制到位，然后再推进 Phase 2 和 Phase 3。**

---

*本报告由 Claude Code 通过 4 路并行深度代码审查 + 全面手动审查生成*
*审计覆盖: 29 个源文件, ~5,500 行 Rust 代码, 118 个测试*
