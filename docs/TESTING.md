# Chrono-shift 测试指南 v0.0.8.3

## 全量测试

```bash
cd client/security/rust_core
cargo test --release          # 142 tests / 0 failures
```

质量门禁（CI 同款，.github/workflows/ci.yml）：
```bash
cargo fmt --check
cargo clippy --release -- -D warnings
cargo test --release
```

## 测试分层

| 层 | 位置 | 覆盖 |
|----|------|------|
| 密码学单元 | crypto.rs / ratchet.rs / identity.rs | AES-GCM 往返、零化、重放窗口 |
| WoT | pgp/web_of_trust.rs | 验签入库、定点信任、顺序无关、互签环、缓存失效 |
| DC-Net | dcnet/round_network.rs / round_driver.rs / round_engine.rs | 份额对称/隔离、观察者无法还原、冒充/重复/脑裂注入被拒、冲突平局 |
| 会话 | net/session.rs | 握手密钥一致、方向密钥交叉、冒名被拒 |
| 中继 | net/relay.rs / app.rs | 签名篡改、重放、过期、限速、TOFU 换钥、转发 hop 递减 |
| 存储 | storage.rs / app.rs | WAL 崩溃恢复、checkpoint、快照往返 |
| 连接 | net/connection_manager.rs | 有界队列背压、连接清理 id 匹配 |

## 攻击性测试惯例

每个安全属性配一个"攻击者视角"测试：伪造签名被拒、用错误密钥还原失败、
重放被拒、越权提交被拒。新增安全代码时沿用此惯例。

## 多进程实测（可选，本机）

双节点 DC-Net 轮次：
```bash
# 终端 A: ./target/release/chrono-daemon --port 9101
# 终端 B: ./target/release/chrono-daemon --port 9102
# 通过 Web 控制台 http://127.0.0.1:10888 的 /api/connect 互连,
# 加入频道后由 RoundEngine 驱动轮次。
```

历史测试脚本 tests/ 目录已随 CLI 移除（旧 C++ 服务端时代遗留）。
