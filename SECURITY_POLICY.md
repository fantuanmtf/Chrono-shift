# Chrono-shift 安全策略

## 漏洞报告

发现安全漏洞请通过 GitHub Issues 报告，标记 `security` 标签。
严重漏洞可直接联系项目维护者。

## 支持版本

| 版本 | 支持状态 |
|------|---------|
| v3.2.x | 积极支持 |
| v3.1.x | 安全更新 |
| < v3.0 | 不再支持 |

## 审计周期

- CVE 全量扫描: 每月运行 `python scripts/cve_audit.py --all`
- 依赖版本检查: 每周运行 `python scripts/check_dependencies.py`
- 代码安全审计: 每季度

## 安全架构

```
[用户输入] → [Rust parser (防注入)] → [E2E AES-256-GCM] → [Tor/I2P SOCKS5]
                                                    ↓
                                           [SecureRandom (CSPRNG)]
```

- 所有网络流量通过 Tor SOCKS5 或 I2P SAM 代理
- DNS 解析在代理侧完成，无泄漏
- 密码学随机数使用 BCryptGenRandom / OsRng
- JSON 解析使用 Rust serde_json (防溢出)
- E2E 加密使用 AES-256-GCM (恒定时间实现)
