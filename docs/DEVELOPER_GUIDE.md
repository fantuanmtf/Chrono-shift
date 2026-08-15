# Chrono-shift 开发者指南 v0.0.8.3

## 项目概览

纯 Rust 单二进制 daemon：认证加密 P2P 网络 + DC-Net 匿名广播 + Web 控制台。
目标平台 Linux x86_64（Windows 支持已移除）。

## 模块结构 (client/security/rust_core/src/)

| 模块 | 职责 |
|------|------|
| main.rs | daemon 启动：监听器/泵/心跳/web 控制台 |
| app.rs | AppState：身份、桥、WoT、中继准入、WAL 恢复 |
| net/session.rs | X25519+Ed25519 会话握手、加密帧（防反射/防重放） |
| net/connection_manager.rs | 连接池：有界队列、读写超时、死连接清理、TOFU 密钥记录 |
| net/relay.rs | 中继签名/准入/路由（重放/过期/限速/TOFU/防环） |
| net/tcp.rs | PeerMessage 协议枚举 + 帧编解码 |
| net/lan.rs, transport.rs, network.rs | LAN 发现、传输配置、SOCKS5（部分未接线） |
| dcnet/round_engine.rs | DC-Net 轮次协调（Leader 收集模式） |
| dcnet/round_network.rs | 份额构造（边密钥）、消息帧、轮次计数器、签名 |
| dcnet/round_driver.rs | mesh 轮次驱动器（库，当前由 round_engine 承担网络路径） |
| dcnet/f2f.rs | F2F 桥：好友、边密钥、频道、WAL 记录 |
| dcnet/{group,round,reputation,network,shuffle}.rs | 组/轮/信誉/网络管理/洗牌 |
| pgp/ | PgpIdentity + Web of Trust（验签 + 定点信任） |
| identity.rs | Ed25519 身份密钥、指纹、0600 持久化 |
| crypto.rs | AES-256-GCM、HKDF 会话派生、常量时间比较 |
| storage.rs | WAL + 原子 checkpoint + 社交快照 |
| service.rs / web.rs / address_book.rs / protocol_filter.rs | F2F 服务代理 / 控制台 / 地址簿 / 协议过滤 |
| ffi.rs | C ABI（unsafe 标记 + panic 防护） |
| ratchet.rs | 弃用（已知缺陷未接线，勿依赖） |

## 构建与测试

```bash
cd client/security/rust_core
cargo build --release          # 产物 target/release/chrono-daemon
cargo test --release           # 142 tests
cargo clippy --release -- -D warnings
cargo fmt --check
```

## 开发规范

1. **安全声明必须配攻击性测试**（伪造/重放/越权/错误密钥场景）；
2. **无占位代码**：未接线的功能要么删除要么在文档中如实标注；
3. **密钥纪律**：敏感文件 0600、比较常量时间、密钥 zeroize；
4. **版本单一来源**：Cargo.toml 版本 + 用户可见字符串同步更新；
5. **先文档后代码**：协议改动先改 docs/PROTOCOL.md 再改实现；
6. 提交作者用 noreply 邮箱（256490970+fantuanmtf@users.noreply.github.com），
   避免暴露真实邮箱（GitHub 设置已开启 block-push 保护）。

## 发布

见 docs/RELEASES.md：构建 → 打包 → PGP 签名 (scripts/sign_release.sh) →
验证 (scripts/verify_release.sh) → GitHub + Codeberg Releases。
