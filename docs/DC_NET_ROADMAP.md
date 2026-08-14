# Chrono-shift 路线图

## 当前版本: v7.7.1

```
v5.0 ████████ P2P 移除 + F2F 集成       ✅
v6.0 ████████ I2P 移除 + 直连 TCP       ✅
v7.0 ████████ C++ → 纯 Rust 重写        ✅ 18 .rs 文件
v7.1 ████████ Ed25519 身份 + LAN 发现   ✅
v7.2 ████████ 可插拔传输层 + 中继       ✅
v7.4 ████████ AppState 统一 + 事件总线  ✅
v7.7.1 ████████ Phase 1-4                ✅ 32 .rs 文件, 88 tests
```

## v7.7.1 新增

```
Phase 1: 基础重构
  ├── AppState 统一 (消除 3 个全局 Mutex)
  ├── TCP ConnectionManager (P2P 连接池)
  ├── CLI↔网络 channel 解耦
  └── WAL 持久化 + 崩溃恢复

Phase 2: PGP + 信任网
  ├── PgpIdentity (Ed25519)
  ├── TrustLevel (Never→Unknown→Marginal→Full→Ultimate)
  └── Web of Trust (BFS 签名图)

Phase 3: F2F 群组管理
  └── DcNetwork (管理员/邀请/踢人/Leader 轮换)

Phase 4: DC-Net 分布式协议
  ├── RoundCollector (TCP 协调的轮次)
  ├── PeerMessage 扩展 (20 种消息类型)
  ├── 防脑裂 (round_id 单调递增)
  └── tokio::main + 网络任务 spawn
```

## 下一步

- [ ] DC-Net 轮次 TCP 实际网络传输 (协议已定义，需端到端联调)
- [ ] PGP/信任/群组 CLI 命令 (Phase 5)
- [ ] `/debug` 调试命令
- [ ] LAN 发现 + 心跳实际集成
- [ ] NAT 穿透 (未来迭代)
- [ ] TLS 集成 (rustls, feature `net` 已有)

## 里程碑

| 版本 | 主要变更 |
|------|----------|
| v4.0 | DC-Net + P2P + I2P (C++ + Rust) |
| v5.0 | P2P 移除, F2F 信任网集成 |
| v6.0 | I2P 移除, 直连 TCP, IRC CLI |
| v7.0 | C++ 全量删除，纯 Rust |
| v7.1 | Ed25519 身份 + fingerprint, AES 加密帧, UDP LAN |
| v7.2 | 可插拔传输层, obfs4/WebTunnel, 多路径中继 |
| v7.4 | AppState 统一 + 事件总线 |
| v7.7.1 | WAL + PGP/WoT + DcNetwork + 分布式 DC-Net + tokio |
