# Chrono-shift C++ → Rust 全量重构路线图

> **归档**：历史文档，仅作记录参考，不代表当前实现。当前文档见 docs/ 与 README。


> 版本: v3.3.0 目标 | 2026-05-05

## 动机

C++ 内存安全问题占 CVE 数据库 60%+ (use-after-free, buffer overflow, wild pointers)。
Rust 的 ownership 系统在编译期消除这些问题。

当前 C++ 代码量: ~15,000 行 | Rust 代码量: ~800 行 (chrono-core)

## 迁移优先级

### Phase 1: 网络层 (最危险, 最多 CVE)

| 模块 | C++ 文件 | Rust 替代 | 风险 |
|------|---------|----------|------|
| DNS 解析 | `TcpConnection.cpp` | `network.rs` (已完成) | 高 |
| SOCKS5 | `tls_client.c` | `network.rs` | 高 |
| WebSocket | `WebSocketClient.cpp` | `network/websocket.rs` | 中 |
| HTTP | `HttpConnection.cpp` | `network/http.rs` | 中 |
| TLS | `TlsWrapper.cpp` | `network/tls.rs` (rustls) | 中 |

**Phase 1 产出**: 纯 Rust 网络栈，替代 `src/network/*.cpp`

### Phase 2: 安全层

| 模块 | C++ 文件 | Rust 替代 | 状态 |
|------|---------|----------|------|
| E2E 加密 | `CryptoEngine.cpp` | `crypto.rs` | ✅ 已完成 |
| JSON 解析 | `json_parser.c` | `parser.rs` | ✅ 已完成 |
| 随机数 | `SecureRandom.h` | `rand::OsRng` | ✅ 已完成 |
| Token | `TokenManager.cpp` | `security/token.rs` | 待做 |
| 密钥管理 | `CryptoKey.cpp` | `security/keyring.rs` | 待做 |

### Phase 3: CLI 命令层

| 命令组 | C++ 文件 | Rust 替代 |
|--------|---------|----------|
| 社交 | `cmd_social.cpp` | `cli/social.rs` |
| 传输 | `cmd_tor.cpp`, `cmd_i2p.cpp` | `cli/transport.rs` |
| 安全 | `cmd_crypto.cpp`, `cmd_cve.cpp` | `cli/security.rs` |
| 调试 | `cmd_network.cpp` 等 | `cli/debug.rs` |

### Phase 4: 胶水层 + 构建

| 组件 | 当前 | Rust 替代 |
|------|------|----------|
| FFI 桥接 | `ffi.rs` (已完成) | 保持 |
| 构建系统 | CMake | CMake + cargo |
| CI/CD | 无 | GitHub Actions |

## 技术方案

### C++ ↔ Rust 互操作

```
C++ main() ──extern "C"──► Rust FFI (ffi.rs)
    │                          │
    ▼                          ▼
Legacy C++ code          Rust core (chrono-core crate)
(逐步被替换)              ├── crypto.rs
                          ├── parser.rs
                          ├── network.rs
                          ├── cve.rs
                          └── cli/ (Phase 3)
```

### 渐进迁移策略

1. Rust 模块编译为 `.a` 静态库
2. C++ 通过 `extern "C"` 调用 Rust FFI
3. 新功能用 Rust 开发
4. 旧 C++ 代码逐步删除
5. 最终 `main()` 迁移到 Rust

## 时间估算

| Phase | 内容 | 预计 |
|-------|------|------|
| Phase 1 | 网络层 Rust 化 | 2周 |
| Phase 2 | 安全层 Rust 化 | 1周 |
| Phase 3 | CLI 命令层 | 2周 |
| Phase 4 | 胶水层 + CI | 1周 |
| **总计** | | **6周** |

## 当前进度

```
C++ 保留:  src/network/, src/storage/, devtools/cli/
C++ 删除:  src/app/ (GUI), devtools/core/ (DevToolsEngine)
Rust 完成: crypto.rs, parser.rs, network.rs, cve.rs, ffi.rs (800行)
Rust 待做: token.rs, keyring.rs, websocket.rs, http.rs, cli/*.rs
```
