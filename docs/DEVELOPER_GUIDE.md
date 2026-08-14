# Chrono-shift 开发者指南 v3.2.0

> 本文档为后续开发者提供完整的项目理解、架构说明、开发规范和贡献指南。

## 项目概览

Chrono-shift 是一个纯 CLI 的 Tor/I2P 双传输层即时通讯软件。技术栈: C++23 + Rust 1.95 + NASM。

**核心差异化**: Tor 和 I2P 源码嵌入，无需用户单独安装匿名网络软件。

## 快速上手

### 环境要求

| 工具 | 最低版本 | 安装方式 |
|------|---------|---------|
| GCC (MinGW) | 13.0+ | MSYS2: `pacman -S mingw-w64-x86_64-gcc` |
| CMake | 3.20+ | MSYS2: `pacman -S mingw-w64-x86_64-cmake` |
| OpenSSL | 3.0+ | MSYS2: `pacman -S mingw-w64-x86_64-openssl` |
| Rust | 1.70+ | `curl --proto '=https' -sSf https://sh.rustup.rs \| sh` |
| NASM | 2.16+ | MSYS2: `pacman -S mingw-w64-x86_64-nasm` |
| Python | 3.8+ | 用于 CVE 审计脚本 |

### 首次编译

```bash
# 1. 克隆 (含子模块)
git clone <repo-url> && cd Chrono-shift

# 2. 编译 Rust 安全核心
cd client/security/rust_core
cargo build --release

# 3. 编译主程序
cd ../..
cmake -B build -G "MinGW Makefiles"
cmake --build build -j$(nproc)

# 4. 运行
./build/chrono-client.exe
```

## 源代码导航

```
Chrono-shift/
├── client/
│   ├── src/                   ← 核心源码 (153 C/C++ 文件)
│   │   ├── ai/                ← AI 提供商 (OpenAI/Gemini/DeepSeek)
│   │   ├── crypto/            ← 加密工具 (SecureRandom/TorProxy)
│   │   ├── glue/              ← 胶水层 (TransportInterface/MessageRouter/Bridge)
│   │   ├── i2p/               ← I2P 客户端 (SamClient/I2pdEmbedded/IntegrityCheck)
│   │   ├── network/           ← 网络栈 (TcpConnection/TlsWrapper/WebSocket/Socks5Dns)
│   │   ├── plugin/            ← 插件系统接口
│   │   ├── security/          ← 安全 (CveDatabase/DependencyScanner)
│   │   ├── social/            ← 社交管理器 (好友/消息/信任)
│   │   ├── storage/           ← 本地存储 (LocalStorage/SessionManager)
│   │   ├── tor/               ← Tor 客户端 (TorClient/TorEmbedded)
│   │   └── util/              ← 工具函数 (Logger/Utils)
│   ├── devtools/cli/          ← CLI REPL + 命令实现
│   │   ├── main.cpp           ← 入口点 (REPL 循环)
│   │   ├── commands/          ← 22个命令模块
│   │   └── terminal_style.h   ← 终端美化
│   ├── include/               ← 公共头文件
│   ├── vendor/                ← Tor & i2pd 源码嵌入
│   │   ├── tor_src/           ← Tor 完整 C 源码 (48MB)
│   │   ├── i2pd_lib/          ← i2pd 核心 C++ 源码
│   │   ├── i2pd_client/       ← i2pd 客户端库
│   │   ├── tor_bridge.c       ← Tor 嵌入桥接
│   │   └── i2pd_bridge.cpp    ← i2pd 嵌入桥接
│   └── security/
│       ├── rust_core/         ← Rust 安全核心 (6文件)
│       └── asm/               ← NASM 混淆 (ChronoStream v1)
├── data/ui/                   ← Web UI (存档, Phase 2)
├── docs/                      ← 文档
├── scripts/                   ← 构建/审计/测试脚本
└── tests/                     ← 测试
```

## 架构设计

### 分层架构

```
┌─────────────────────────────────────┐
│  CLI 接口 (main.cpp + 28命令)        │
├─────────────────────────────────────┤
│  胶水层 (glue/)                      │
│  ┌──────────┬──────────┬──────────┐ │
│  │ Transport │ Message  │ Social   │ │
│  │ Interface │ Router   │ Manager  │ │
│  │ (抽象)    │ (跨传输) │ (好友)   │ │
│  └──────────┴──────────┴──────────┘ │
├─────────────────────────────────────┤
│  传输层                              │
│  ┌──────────┬──────────┬──────────┐ │
│  │ Tor      │ I2P      │ Local    │ │
│  │ (SOCKS5) │ (SAM v3) │ (模拟)   │ │
│  └──────────┴──────────┴──────────┘ │
├─────────────────────────────────────┤
│  安全层                              │
│  ┌──────────┬──────────┬──────────┐ │
│  │ E2E加密  │ 完整性   │ CVE审计  │ │
│  │ (Rust)   │ (SHA256) │ (347K条) │ │
│  └──────────┴──────────┴──────────┘ │
├─────────────────────────────────────┤
│  网络层 (TCP/TLS/WebSocket/DNS安全) │
└─────────────────────────────────────┘
```

### 启动流程

```
main()
├── config_init_defaults()      ← 加载默认配置
├── init_commands()             ← 注册所有28个命令
├── SocialManager::load_state() ← 加载社交状态
├── try_auto_connect_i2p()      ← 自动启动i2pd
│   ├── is_port_open(7656)      ← 端口检测(防重复)
│   ├── is_process_running()    ← 进程检测(防重复)
│   └── IntegrityCheck::verify()← SHA256防篡改
├── 显示待处理好友请求
└── REPL 循环 (chrono →)
```

### 命令注册流程

```
main.cpp
  → init_commands()
    → init_cmd_*() for each module
      → register_command(name, desc, usage, handler)
        → g_command_table[]  + g_command_registry.add()
```

## 开发规范

### 添加新命令

```cpp
// 1. 创建 client/devtools/cli/commands/cmd_new.cpp
static int cmd_new(int argc, char** argv) {
    // 命令逻辑
    return 0;
}
extern "C" int init_cmd_new(void) {
    register_command("new", "新命令描述", "new <args>", cmd_new);
    return 0;
}

// 2. 在 init_commands.cpp 中添加:
extern int init_cmd_new(void);  // 声明
init_cmd_new();                  // 调用

// 3. CMakeLists.txt 的 CLI_CPP_SOURCES 中添加:
devtools/cli/commands/cmd_new.cpp
```

### 添加新传输层

```cpp
// 1. 创建 client/src/xxx/XxxClient.h (实现 TransportInterface)
class XxxClient : public glue::TransportInterface {
    bool start() override;
    void stop() override;
    TransportKind kind() const override;
    TransportState get_state() const override;
    bool send(const std::string&, const std::string&) override;
    void on_receive(ReceiveCallback) override;
    std::string lookup(const std::string&) override;
};

// 2. 在 glue/GlueTypes.h 添加 TransportKind 枚举值
// 3. 在 main.cpp 注册
```

### 安全规范

1. **随机数**: 必须使用 `SecureRandom` (C++) 或 `OsRng` (Rust)，禁止 `rand()`/`srand()`
2. **DNS**: 使用 `Socks5Dns::resolve_and_connect()`，禁止 `gethostbyname()`
3. **加密**: 仅 AES-256-GCM，禁止自研密码用于生产
4. **内存**: Rust 模块处理所有解析和加密，C++ 仅做胶水
5. **JSON**: 禁止字符串拼接，使用 `json_build_response()` 或 Rust `serde_json`

### 构建规范

- Rust crate 在 `client/security/rust_core/`，Cargo.toml 管理
- NASM 汇编在 `client/security/asm/`
- Tor/i2pd 源码在 `client/vendor/` (源码嵌入，按需编译)
- `.gitignore` + `.gitattributes` 已配置 (排二进制, 语言统计)

## 测试

```bash
# Rust 单元测试
cd client/security/rust_core && cargo test --release

# C++ 功能测试 (CLI)
cd client/build
echo "crypto test" | ./chrono-client.exe

# 全量测试
printf "crypto test\nuid set test\nfriend add demo\nfriend accept demo\nmsg send demo hello\nexit\n" | ./chrono-client.exe

# CVE 审计
python scripts/cve_audit.py --all

# 依赖版本检查
python scripts/check_dependencies.py
```

## 常见问题

**Q: GitHub 显示 Makefile 为主要语言?**
A: `.gitattributes` 已标记 Makefile 为 `linguist-generated`。提交后刷新。

**Q: Rust 库编译失败?**
A: 检查 Rust 版本 ≥ 1.70，运行 `cargo update` 更新依赖。

**Q: i2pd 重复启动?**
A: `I2pdEmbedded::start()` 先检查端口 7656 是否已开放，已运行则不重复启动。

**Q: Tor 在中国无法连接?**
A: 需要在 `tor_data/torrc` 配置网桥 (bridge)。参见 `docs/TRANSPORT.md`。

**Q: 如何迁移 C++ 到 Rust?**
A: 参见 `docs/RUST_MIGRATION.md`。推荐先迁移网络层 (最大安全收益)。

## 贡献流程

1. Fork 仓库
2. 创建功能分支
3. 添加/修改代码
4. 运行 `cargo test` + CLI 功能测试
5. 运行 `python scripts/cve_audit.py --year=2025` (快速CVE检查)
6. 提交 PR，标记 `security` 如有安全相关变更

## 未来路线图

- [ ] C++ → Rust 全量迁移 (Phase 1: 网络层)
- [ ] i2pd 生产就绪 (Reseed 优化)
- [ ] GUI 桌面版 (基于胶水层 GlueLayer)
- [ ] 移动端 (Rust core + Flutter)
- [ ] 去中心化 DHT 节点发现
- [ ] 文件传输 + 语音通话
