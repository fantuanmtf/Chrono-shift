# Chrono-shift v0.0.8.3 交接文档

> 更新日期: 2026-08-15 | 纯 Rust | Linux 单平台 | 单二进制 daemon

## 一、项目定位

DC-Net + F2F 信任网的匿名代理网络。核心组件：

- **daemon**（chrono-daemon）：TCP 监听（默认 9000，`--port` 可调）+
  Web 控制台（127.0.0.1:10888）；
- **DC-Net RoundEngine**：Leader 收集式轮次，边密钥份额 + 签名 + 校验和帧；
- **会话层**：X25519 临时 DH + Ed25519 验签 + AES-256-GCM（防反射/防重放）；
- **中继**：签名 + nonce + 时间窗 + 限速 + TOFU + hops 防环；
- **WoT**：验签入库 + 定点信任计算；
- **WAL**：崩溃安全持久化。

## 二、仓库布局

```text
client/security/rust_core/    Rust crate（二进制 chrono-daemon）
docs/                         活跃文档（BUILD/PROTOCOL/TESTING/RELEASES/
                              DEVELOPER_GUIDE/DEVELOPMENT_PLAN/TRANSPORT）
docs/*_AUDIT*.md, plans/, reports/   历史审计与计划（归档，仅参考）
keys/                          PGP 签名公钥
scripts/                       sign_release.sh / verify_release.sh
.github/workflows/             ci.yml（质量门禁）+ release.yml（标签构建）
```

## 三、关键操作

```bash
# 构建/测试
cd client/security/rust_core && cargo build --release && cargo test --release

# 运行
./target/release/chrono-daemon --port 9000

# 发布（签名在维护者本机，私钥不入 CI）
RELEASE_DIR=client/security/rust_core/release bash scripts/sign_release.sh haiyanfurry@proton.me
```

## 四、仓库与身份

- GitHub: https://github.com/fantuanmtf/Chrono-shift（私有）
- Codeberg: https://codeberg.org/haiyanfurry-mtf/Chrono-Shift
- 提交身份：haiyan-mtf <256490970+fantuanmtf@users.noreply.github.com>
- PGP 签名：haiyan-mtf <haiyanfurry@proton.me>（指纹 F11B C5BB A9C9 32B2 79C8
  55CC F0EE 9751 EB48 1A8D）

## 五、历史与状态

- 2026-08-15：历史清理（单一初始提交）、v0.0.8.2/v0.0.8.3、去 Windows 化；
- 安全路线图 P0-P4 全部落地（docs/DEVELOPMENT_PLAN.md）；
- 遗留/后续：ratchet 弃用待替换（vodozemac 候选）、Tor SOCKS5 未接线、
  LAN 发现未接线、shuffle/Blame 未接入轮次。
