# Chrono-shift v7.7 依赖清单

> 纯 Rust 项目，零 C/C++ 系统依赖

## Rust 依赖 (Cargo.toml)

### 加密

| Crate | 版本 | 用途 |
|-------|------|------|
| `aes-gcm` | 0.10 | AES-256-GCM 认证加密 |
| `sha2` | 0.10 | SHA-256 哈希 |
| `hmac` | 0.12 | HMAC (HKDF 密钥派生) |
| `hkdf` | 0.12 | HKDF-SHA256 密钥派生 |
| `x25519-dalek` | 2 | X25519 ECDH 密钥协商 |
| `ed25519-dalek` | 2 | Ed25519 签名 (身份 + 信任链) |
| `rand` | 0.8 | 安全随机数 (OsRng) |
| `rand_core` | 0.6 | 随机数核心 trait |
| `zeroize` | 1 | 密钥安全清零 |
| `ct-codecs` | 0.1 | 恒定时间编码 |

### 序列化

| Crate | 版本 | 用途 |
|-------|------|------|
| `serde` | 1 | 序列化框架 |
| `serde_json` | 1 | JSON 解析 |

### 网络 (可选 feature: `net`)

| Crate | 版本 | 用途 |
|-------|------|------|
| `tokio` | 1 | 异步运行时 (full features) |
| `reqwest` | 0.12 | HTTP 客户端 |
| `tungstenite` | 0.24 | WebSocket 客户端 |
| `rustls` | 0.23 | TLS (纯 Rust) |

### 其他

| Crate | 版本 | 用途 |
|-------|------|------|
| `uuid` | 1 | UUID 生成 |
| `log` | 0.4 | 日志门面 |
| `env_logger` | 0.11 | 日志输出 |
| `windows-sys` | 0.59 | Windows 终端原始终端模式 |
| `libc` | 0.2 | Unix termios |

## 构建依赖

| 工具 | 最低版本 | 必需？ | 用途 |
|------|---------|--------|------|
| Rust | 1.70 | **是** | 编译 |
| NSIS | 3.x | 否 | Windows 安装包 |

## 不再需要的依赖 (相比旧版)

| 依赖 | 原因 |
|------|------|
| GCC/MinGW | 无 C++ 代码 |
| CMake | 无 C++ 构建 |
| OpenSSL | rustls 替代 |
| Boost/i2pd/Tor | 已移除，直连 TCP |

## 最小支持 Rust 版本 (MSRV)

- **Rust 1.70** (2021 Edition)
- 建议最新 stable
