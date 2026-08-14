# Chrono-shift v7.6 传输层文档

> **状态说明（2026-08 更新）**：本文档描述传输层的真实状态。
> - ✅ 已实现：TCP 直连 + 认证加密会话（X25519 握手 + Ed25519 验签 +
>   AES-256-GCM 帧，防重放/防反射/防冒充，见 src/net/session.rs）。
> - ⚠️ 仅配置层（未接入连接路径）：Tor SOCKS5 / obfs4 / WebTunnel ——
>   net/transport.rs 只保存配置枚举，真实连接目前永远是 TCP 直连。
> - ❌ 已删除：旧 C++ 时代的 I2P/Tor 内嵌源码在 v7.0 重构时移除，
>   "所有流量经 Tor/I2P" 的说法不再成立。

## 架构

```
应用层: CLI (IRC 风格 REPL)
   ↓
DC-Net 匿名层: XOR 广播 (mesh 轮次)
   ↓
F2F 信任网: 好友驱动的群组形成
   ↓
会话层: 认证握手 + AES-256-GCM 加密帧
   ↓
传输层: TCP 直连 (点对点)
```

## 直连 TCP

v7.6 使用**纯 TCP 直连**，无代理，无 I2P，无 Tor。

### 连接模式

| 模式 | 命令 | 说明 |
|------|------|------|
| 主动连接 | `/connect <uid> <ip:port>` | 向好友发起 TCP 连接 |
| 被动监听 | `TcpListener::bind(port)` | 接受好友入站连接 |

### 网络栈 (Rust)

```
TcpStream (std::net)          — TCP 套接字
   ↓ (可选)
rustls::ServerConnection      — TLS 服务端
rustls::ClientConnection      — TLS 客户端
```

### 端口

| 用途 | 默认端口 |
|------|---------|
| 好友直连 | 9000 (可配置) |

### 无 DNS 泄漏

直连模式下，地址格式为 `ip:port`，不涉及 DNS 查询。所有连接使用 IP 地址直连，无泄漏风险。

## 消息帧

```
┌──────────────────────────────────────┐
│ 帧头 (4 bytes)                       │
│   magic:  0x43485346 ("CHSF")        │
├──────────────────────────────────────┤
│ 类型 (1 byte)                        │
│   0x01 = DC_NET_ROUND                │
│   0x02 = FRIEND_REQUEST              │
│   0x03 = FRIEND_ACCEPT               │
│   0x04 = CHANNEL_JOIN                │
│   0x05 = CHANNEL_MSG                 │
├──────────────────────────────────────┤
│ 长度 (2 bytes, BE)                   │
├──────────────────────────────────────┤
│ 载荷 (变长, max 4096 bytes)          │
│   JSON 格式                          │
└──────────────────────────────────────┘
```

## 与旧版本的对比

| | v5.0 (I2P) | v6.0 | v7.0 |
|---|-----------|------|------|
| 传输 | I2P SAM v3 + SOCKS5 | I2P + 直连过渡 | **TCP 直连** |
| 依赖 | i2pd (10MB) + OpenSSL DLL | OpenSSL DLL | **纯 Rust (零 DLL)** |
| 地址 | .b32.i2p | ip:port | **ip:port** |
| DNS | 代理侧解析 | 代理侧解析 | **无 DNS (直连 IP)** |
| TLS | OpenSSL C | OpenSSL C | **rustls (纯 Rust)** |
| 代理 | SOCKS5:4447 | SOCKS5 | **无代理** |
| 二进制 | 4.8 MB + 4 DLL | 4.3 MB + 4 DLL | **1.4 MB 单文件** |

## TLS 配置 (可选)

当启用 `net` feature 时:

```toml
[features]
net = ["reqwest", "tungstenite", "rustls"]
```

rustls 提供:
- TLS 1.2 / 1.3
- 纯 Rust 实现 (无 OpenSSL 依赖)
- 证书验证 (WebPKI)
- 自签名证书支持 (开发/内网)
