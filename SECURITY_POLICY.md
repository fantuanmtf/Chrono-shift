# Chrono-shift 安全策略

## 支持版本

| 版本 | 支持状态 |
|------|----------|
| v0.0.8.x | 积极支持（当前） |
| 更早版本 | 不再支持 |

## 漏洞报告

- **GitHub**：https://github.com/fantuanmtf/Chrono-shift → Issues，标 `security` 标签；
- **Codeberg**：https://codeberg.org/haiyanfurry-mtf/Chrono-Shift/issues；
- **紧急/敏感**：PGP 加密邮件至维护者 haiyan-mtf <haiyanfurry@proton.me>
  （公钥见 keys/haiyanfurry-mtf.asc）。

请提供：影响版本、复现步骤、影响评估；确认后 7 天内回复。

## 审计周期

- 每季度：全量代码审查（cargo clippy -D warnings + 手工审查安全关键路径）；
- 每次发布前：cargo test 全量 + 攻击性测试复核；
- 依赖检查：CI 每次推送运行 `cargo audit --deny warnings`（RustSec 公告库）；
  `cargo update` 前仍人工审查变更摘要。

## 密钥与签名

- 发布产物全部 PGP 签名（流程见 docs/RELEASES.md）；
- 签名密钥指纹：F11B C5BB A9C9 32B2 79C8 55CC F0EE 9751 EB48 1A8D；
- 密钥轮换时在 Release 说明中声明新指纹。
