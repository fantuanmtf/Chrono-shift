# Chrono-shift v8.1 交接文档

> 更新日期: 2026-08-04 | Rust 2021 Edition | 纯 Rust

## 一、项目概述

Chrono-shift 是基于 DC-Net (Dissent 变种) + F2F 信任网的匿名代理网络系统。

**核心差异化**: DC-Net 提供信息论安全匿名，F2F 提供好友驱动的网络边界，Web 控制台替代 CLI，外部应用通过 localhost 代理端口接入。

## 二、当前状态

| 指标 | 数值 |
|------|------|
| Rust 源文件 | 36 个 |
| 代码行数 | ~6800 行 |
| 测试 | 115 / 0 fail |
| 二进制 | 1 个 (chrono-daemon, ~2MB) |
| 外部 DLL | 0 (纯静态链接) |
| C++ 代码 | 0 |

## 三、构建

```bash
cd client/security/rust_core
cargo build --release          # 编译
cargo test                     # 115 测试
./target/release/chrono-daemon --dev  # 运行
```

## 四、v8.1 架构

```
┌──────────────────────────────────────────┐
│ chrono-daemon (唯一二进制)               │
│                                          │
│  Web 控制台 :10888                       │
│  ┌────────────────────────────────────┐  │
│  │ /       仪表盘                     │  │
│  │ /api/*  REST API                   │  │
│  └────────────────────────────────────┘  │
│                                          │
│  代理层 (localhost)                      │
│  IRC :6667 / BBS :2323 / 自定义          │
│     ↓ 协议过滤 → PGP加密 → XOR         │
│                                          │
│  P2P 网络                                │
│  TCP/IPv6 + Tor/I2P + AuthHandshake     │
│  → DC-Net RoundEngine                  │
└──────────────────────────────────────────┘
```

## 五、CLI 命令历史 (已废除)

v8.0 及之前版本有 CLI REPL。v8.1 废除了所有 CLI 交互，改为 Web 控制台 + REST API。

## 六、加密体系

| 层 | 算法 |
|----|------|
| 身份 | Ed25519 |
| 传输 | AES-256-GCM |
| 密钥协商 | X25519 ECDH |
| 密钥派生 | HKDF-SHA256 |
| 前向安全 | Double Ratchet |
| 匿名 | DC-Net XOR |

## 七、关键数据结构

### PeerMessage (22 种)
- 好友: FriendRequest, FriendAccept
- DC-Net: DcRound, DcRoundStart, DcRoundShare, DcRoundResult, LeaderChange, RoundSyncRequest, RoundSyncResponse
- 群组: NetworkInvite, NetworkJoinRequest, NetworkJoinAccept, NetworkKick, NetworkSync
- 认证: AuthChallenge, AuthResponse
- 中继: RelayRequest, RelayResponse
- 保活: Ping, Pong
- 消息: ChannelMessage

### TrustLevel: Never(-1) → Unknown(0) → Marginal(1) → Full(2) → Ultimate(3)

## 八、版本演进

| | v7.0 | v8.0 | v8.1 |
|---|------|------|------|
| 源文件 | 18 | 32 | 36 |
| 测试 | 32 | 118 | 115 |
| 架构 | 单进程CLI | daemon+CLI IPC | 单二进制+Web |
| 控制面 | CLI REPL | CLI IPC | Web :10888 |
| 信任 | 3级(u8) | WoT 5级 | WoT+签名验证 |
| 网络 | 同步TCP | tokio async | tokio+握手 |
