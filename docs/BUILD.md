# Chrono-shift v7.7.1 构建指南

## 依赖

**仅需 Rust。** 无 CMake, 无 MinGW, 无 OpenSSL, 无 NASM。

| 工具 | 最低版本 | 安装 |
|------|---------|------|
| Rust | 1.70+ | `curl --proto '=https' -sSf https://sh.rustup.rs \| sh` |

## 构建

```bash
cd client/security/rust_core

# Debug 构建
cargo build

# Release 构建 (优化 + LTO + strip)
cargo build --release

# 二进制路径
./target/release/chrono-daemon      # Linux/macOS
./target/release/chrono-daemon.exe  # Windows
```

## 运行

```bash
# 直接运行
cargo run --release

# 开发者模式
cargo run --release -- --dev

# 或直接执行二进制
./target/release/chrono-daemon
```

## 测试

```bash
# 全部测试
cargo test

# 仅库测试 (跳过 doc-test)
cargo test --lib

# Release 模式测试
cargo test --release

# 特定模块测试
cargo test --lib dcnet
cargo test --lib crypto
cargo test --lib storage
```

## 发布构建配置

`Cargo.toml` 中的 release profile:

```toml
[profile.release]
opt-level = 3      # 最大优化
lto = true         # 链接时优化
codegen-units = 1  # 单代码生成单元 (更好优化)
panic = "abort"    # 紧急中止 (减小体积)
strip = true       # 去除调试符号
```

构建产物: ~1.6 MB (Windows), 零外部 DLL 依赖。88 tests / 0 failures。

## 交叉编译

```bash
# Windows → Linux
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu

# Windows → macOS
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin
```

## NSIS 安装包 (仅 Windows)

```bash
# 需要 NSIS 3.x
makensis installer/chrono_setup.nsi
# 输出: Chrono-shift-Release/Chrono-shift-Setup.exe
```

## 故障排除

| 问题 | 解决 |
|------|------|
| `cargo: command not found` | 安装 Rust: https://rustup.rs |
| 编译慢 | `cargo build --release` 首次需下载依赖, 后续增量编译秒级 |
| 找不到 `chrono-core` | 确保在 `client/security/rust_core/` 目录下运行 |
| 测试失败 (ratchet) | 已知问题: 简化版 X25519, 不影响 AES-256-GCM 和 DC-Net |
