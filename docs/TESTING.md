# Chrono-shift 测试指南 v3.2.0

## 冒烟测试

```bash
cd client/build
echo "help" | ./chrono-client.exe
echo "crypto test" | ./chrono-client.exe
```

## 全量命令测试

```bash
printf "help\ncrypto test\ni2p status\nuid set test\nfriend add demo\nfriend accept demo\nmsg send demo hello\nmsg inbox\nbridge status\ncve stats\ntor start\nexit\n" | ./chrono-client.exe
```

预期: 所有命令返回正常, 无崩溃。

## Rust 单元测试

```bash
cd client/security/rust_core
cargo test --release
```

预期: 9 个测试全部通过 (crypto, parser, network, cve, ffi)。

## 安全测试

```bash
# CVE 全量审计
python scripts/cve_audit.py --all

# CVE 快速扫描 (近2年)
python scripts/cve_audit.py --year=2024

# 依赖版本检查
python scripts/check_dependencies.py

# 完整性校验
rm -f i2p_data/integrity.json
./chrono-client.exe  # 首次启动自动 seal
cmp i2p_data/integrity.json  # 验证哈希文件已创建
```

## 传输层测试

```bash
# Tor 启动
> tor start
> tor status
> tor log

# I2P 启动 (自动检测已有实例)
> i2p start
> i2p status

# 跨传输桥接
> bridge status
> bridge add alice tor xyz.onion
```

## 社交功能测试

```bash
> uid set testuser
> uid show
> friend add testpeer
> friend pending
> friend accept testpeer
> friend list
> friend reject spammer
> msg send testpeer hello
> msg inbox
> msg chat testpeer
[bob]> test message
[bob]> /quit
```

## 安全验证

```bash
# 随机数质量验证
> crypto test
# 检查: 密钥为64位hex (不可预测)

# CVE 查询
> cve load
> cve search OpenSSL
> cve scan

# 完整性
> i2p start  # 首次 seal, 后续 verify
```

## 回归检查清单

- [ ] `chrono-client.exe` 启动无崩溃
- [ ] `crypto test` AES-256-GCM 通过
- [ ] `i2p start` 不重复启动
- [ ] `tor start` SOCKS5 端口检测
- [ ] `uid set/show` 身份管理
- [ ] `friend add/accept/reject/list` 好友系统
- [ ] `msg send/inbox/chat` 消息收发
- [ ] `cve search/scan` CVE查询
- [ ] `bridge status` 跨传输桥接
- [ ] 完整性校验 seal/verify 正常
- [ ] `cargo test` 9个Rust测试通过
- [ ] `scripts/cve_audit.py` CVE审计正常
