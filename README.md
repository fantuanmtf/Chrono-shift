# Chrono-shift v0.0.8.2

**DC-Net + F2F 信任网 · 匿名代理网络 · 纯 Rust · Web 控制台**

36 源文件 · ~6800 行 Rust · 115 tests / 0 failures · 零 C/C++ 依赖

## 核心特性

- **DC-Net 匿名路由** — Dissent 变种，信息论安全：即使攻击者监控全网也无法确定发送者
- **Web 控制台** — `http://127.0.0.1:10888`，类 I2P 风格，仪表盘/节点/代理/信任
- **纯代理架构** — 外部 IRC/BBS 客户端通过 localhost 端口接入，协议过滤后走 DC-Net
- **F2F 信任网** — 好友驱动网络，5 级信任 (Never→Unknown→Marginal→Full→Ultimate)
- **Web of Trust** — Ed25519 签名图，BFS 信任路径计算，签名验证
- **分布式 DC-Net 轮次** — RoundEngine：Leader 协调，XOR 份额，防脑裂
- **PGP 握手认证** — TCP 连接时 AuthChallenge/Response，Ed25519 双向验证
- **E2E 加密** — AES-256-GCM + Double Ratchet (前向安全)
- **WAL 持久化** — Write-Ahead Log，原子 checkpoint，崩溃恢复
- **可插拔传输** — Direct / Tor SOCKS5 / obfs4 / WebTunnel
- **IPv6 双栈** — `[::]` 绑定自动 fallback IPv4
- **协议过滤** — 仅允许 IRC/BBS 文本协议，拒绝 HTTP/二进制/大文件

## 加密体系

| 层 | 算法 | 说明 |
|----|------|------|
| 身份 | Ed25519 | 密钥对 + fingerprint + 签名 |
| 传输 | AES-256-GCM | 每条消息独立 nonce |
| 密钥协商 | X25519 ECDH | Double Ratchet DH 棘轮 |
| 密钥派生 | HKDF-SHA256 | 根密钥 → 链密钥 → 消息密钥 |
| 前向安全 | Double Ratchet | 对称棘轮推进 |
| DC-Net XOR | 信息论安全 | N 方共享密钥 XOR 广播 |
| 洗牌承诺 | SHA-256 | Merkle 树根，揭示后验证 |
| 随机数 | OsRng | FIPS 140-2 |
| 内存安全 | zeroize | Drop 时自动清零 |

## 快速开始

```bash
cd client/security/rust_core
cargo build --release
./target/release/chrono-daemon --dev

# Web 控制台: http://127.0.0.1:10888
# API: curl http://127.0.0.1:10888/api/status
```

## 项目结构

```
client/security/rust_core/src/
├── main.rs                    # daemon 入口 (tokio::main)
├── lib.rs                     # 模块声明
├── app.rs                     # AppState 统一状态
├── web.rs                     # Web 控制台 HTTP server
├── static/index.html          # 控制面板前端
├── dcnet/
│   ├── mod.rs                 # DC-Net 核心类型 + XOR
│   ├── round.rs               # 轮次状态机
│   ├── round_network.rs       # 分布式轮次 (RoundCollector)
│   ├── round_engine.rs        # RoundEngine (网络协调)
│   ├── group.rs               # 群组管理
│   ├── shuffle.rs             # 可验证洗牌 + Blame
│   ├── reputation.rs          # 信誉评分
│   ├── f2f.rs                 # F2F 信任网桥
│   └── network.rs             # DcNetwork 群组
├── pgp/
│   ├── mod.rs                 # PGP 身份 + TrustLevel
│   └── web_of_trust.rs        # WoT (BFS + 签名验证)
├── net/
│   ├── mod.rs                 # 网络栈
│   ├── tcp.rs                 # TCP 帧 + PeerMessage (22种)
│   ├── connection_manager.rs  # P2P 连接池 + 握手
│   ├── transport.rs           # 可插拔传输
│   ├── relay.rs               # 多路径中继
│   └── lan.rs                 # UDP LAN 发现
├── handshake.rs               # IP→PGP 握手协议
├── identity.rs                # Ed25519 身份密钥
├── crypto.rs                  # AES-256-GCM
├── ratchet.rs                 # Double Ratchet E2E
├── storage.rs                 # WAL 持久化
├── protocol_filter.rs         # 协议过滤 (IRC/BBS)
├── service.rs                 # F2F 服务管理
├── address_book.rs            # 地址簿 + Gossip
├── ffi.rs                     # C ABI 导出
├── network.rs                 # SOCKS5 客户端
└── parser.rs                  # JSON 解析
```

## Web 控制台

`http://127.0.0.1:10888`

| API | 方法 | 说明 |
|-----|------|------|
| `/api/status` | GET | daemon 状态 (运行时间/连接数/版本) |
| `/api/peers` | GET | 已知节点列表 |
| `/api/services` | GET | 活跃代理列表 |
| `/api/connect` | POST | 连接节点 `{"addr":"IP:9000","uid":"name"}` |

## 下载

预编译包在 [GitHub Releases](https://github.com/haiyanfurry/Chrono-shift/releases) 页面：

| 包 | 说明 |
|----|------|
| `chrono-daemon.exe` | Windows 64-bit · 唯一二进制 · 零 DLL |
| `chrono-daemon-linux` | Linux x86_64 ELF |
| `Chrono-shift-Setup.exe` | Windows NSIS 安装包 |
| `chrono-shift_0.0.8.2_amd64.deb` | Debian/Ubuntu 安装包 |
| `chrono-bin.zip` | 全部打包 |
| `chrono-bin.zip.asc` | PGP 签名 |
| `chrono-bin.zip.sha256` | SHA256 校验 |
| `chrono-bin.zip.sig` | 文件验证签名 |

## 更新日志

| 版本 | 变更 |
|------|------|
| v0.0.8.2 | v8.1 daemon + P0-P4 安全合流：真 X25519 会话加密、边密钥 DC-Net 份额、WoT 定点信任、中继加固（签名/限速/TOFU/防环）、WAL 接线、历史清理重置 |
| v8.1 | Web 控制台、废 CLI、单二进制、纯代理架构 |
| v8.0 | RoundEngine 实测 (跨太平洋)、PGP 握手、协议过滤、IPv6 |
| v7.6 | WAL + PGP/WoT + DcNetwork + 分布式 DC-Net + tokio |
| v7.0 | C++ 全量删除，纯 Rust 重写 |

GPLv3
