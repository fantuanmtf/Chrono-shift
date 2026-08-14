# Chrono-shift v5.0 四步开发计划

## Step 1: DC-Net + F2F 核心 (Rust)

```
新建 crate: chrono-dcnet
├── src/dcnet/
│   ├── round.rs        ← 轮次管理
│   ├── group.rs        ← 群组管理
│   ├── shuffle.rs      ← 可验证洗牌 + Blame
│   ├── reputation.rs   ← 信誉评分 (反馈到 F2F)
│   ├── f2f.rs          ← F2F 信任网 → DC-Net 集成桥
│   └── mod.rs          ← XOR 广播 + 参与者类型
└── tests/
    ├── test_dcnet_round.rs
    ├── test_f2f_trust.rs
    └── test_dropout_recovery.rs
```

**验收**: 3节点DC-Net正常轮 + F2F信任过滤 + 1个掉线自动恢复

## Step 2: 安全加固

```
加密优化:
├── Double Ratchet (ECDH + HKDF)
├── 每条消息独立密钥
├── 前向安全性 + 后向安全性
├── ML-KEM-768 (可选后量子)
└── 消息开销: +136B

抗恶意掉线:
├── 信誉系统 (PeerReputation)
├── 纠删码容忍2个掉线
├── 恶意检测: 连续3轮广播前退出 → 封禁
└── 掉线率>50% → 永久排除

防丢上下文:
├── 50条消息自动快照
├── 消息头链哈希 (对端可检测丢失)
└── 群组 Shamir 备份
```

**验收**: 模拟恶意节点连续退出 → 自动封禁 + 轮次继续

## Step 3: C++ → Rust 全量移植

```
删除 (~15,000行C++):
├── src/ai/ src/glue/ src/network/
├── devtools/cli/commands/*.cpp
├── src/i2p/*.cpp src/tor/*.cpp
└── vendor/tor_src/ (48MB, 验证通过后删除)

保留:
├── src/crypto/SecureRandom.h (临时FFI)
├── vendor/i2pd_lib/ (i2pd源码, 预发布)
└── client/security/rust_core/ → 迁移进chrono-dcnet

新增 Rust CLI:
├── clap (参数解析)
├── reedline (REPL编辑器)
└── 3个用户命令: uid / add / chat
    22个dev命令: help显示全部

CLI 双模式:
  用户模式: > uid / add / chat  (3个命令)
  开发者模式: > help → 25个命令 (全部可用)
```

**验收**: 用户3命令可用, dev 25命令可用, C++删除完成

## Step 4: 虚拟化自检 + 清理 + 发布

```
虚拟化内网测试 (boot self-check):
├── 启动 i2pd (本地模拟模式)
├── 检查 SAM:7656 端口开放
├── 检查 SOCKS:4447 端口开放
├── 发送 loopback 测试消息
├── 验证 E2E 加密/解密
├── 验证完整性校验 (integrity.json)
└── 报告: 全部通过 ✅ 或 失败 ❌

清理:
├── rm -rf vendor/tor_src/     (48MB, 已验证)
├── rm -rf data/ui/             (存档, 不删干净)
├── 精简单文件C++ (仅保留FFI桩)

发布:
├── chrono-client.exe → chrono.exe (5MB)
├── Rust crate → crates.io (可选)
└── 文档: 14个MD → GH Pages
```

**验收**: `chrono.exe --self-test` 输出全部 ✅

## 时间线

```
Step 1: ████████████ 2周  DC-Net + P2P
Step 2: ████████████ 2周  安全加固
Step 3: ████████████ 2周  C++→Rust
Step 4: ████████████ 2周  自检+发布
        ─────────────────
总计:   8周
```
