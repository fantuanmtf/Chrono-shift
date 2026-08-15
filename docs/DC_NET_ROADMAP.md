# Chrono-shift 路线图

> 当前版本: v0.0.8.3 (2026-08-15)

```text
v3.x C++ 客户端 + 服务端        ✅ 已废弃 (2026-05)
v7.0 纯 Rust 重写 + IRC CLI     ✅ 已归档
v7.6 P0-P4 安全修复             ✅ 完成 (WoT 验签/边密钥/会话加密/中继加固)
v8.0/8.1 daemon 化 + Web 控制台 ✅ 完成 (RoundEngine 实测/协议过滤/IPv6)
v0.0.8.2 合流 + 历史清理        ✅ 完成 (2026-08-15)
v0.0.8.3 去 Windows 化          ✅ 当前
```

## 后续候选（无排期）

| 优先级 | 事项 | 说明 |
|--------|------|------|
| 高 | ratchet 替换 | 自研实现弃用；评估 vodozemac 或 matrix-sdk-crypto |
| 高 | 独立安全评审 | 找第三方审计会话/轮次/中继三条路径 |
| 中 | Tor SOCKS5 接线 | net/transport.rs 目前仅配置层 |
| 中 | LAN 发现接线 | net/lan.rs 未接入启动流程 |
| 中 | shuffle/Blame 接入轮次 | 模块存在但未与 round_engine 集成 |
| 低 | 三节点以上 DC-Net 压测 | 规模与超时行为验证 |
| 低 | 1:1 私聊 | 需先完成 ratchet 替换 |
