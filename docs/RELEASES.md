# Chrono-shift 发布流程 (Releases)

> v0.0.8.2 · 维护者: haiyan-mtf <haiyanfurry@proton.me>
> 签名密钥: keys/haiyanfurry-mtf.asc (Ed25519)

## 产物清单

| 文件 | 说明 |
|------|------|
| `chrono-daemon-linux-x86_64` | Linux x86_64 ELF（单二进制） |
| `chrono-daemon.exe` | Windows x64（CI 构建） |
| `Chrono-shift-Setup.exe` | Windows NSIS 安装包（需本机 makensis） |
| `chrono-bin-v<VERSION>.zip` | 全部产物打包 |
| `SHA256SUMS` / `SHA256SUMS.asc` | 校验和清单 + 明文签名 |
| `*.asc` | 每个产物的 PGP 分离签名 |

## 流程

### 1. 构建 + 打包（本机或 CI）

```bash
cd client/security/rust_core
cargo build --release
mkdir -p release
cp target/release/chrono-daemon release/chrono-daemon-linux-x86_64
cp ../../LICENSE ../../README.md release/
cd release && sha256sum * > SHA256SUMS
# zip (需要 zip 或 python3)
python3 -c "import shutil,glob; shutil.make_archive('../../chrono-bin-v0.0.8.2','zip','.')"
```

跨平台：推送 `v*` 标签触发 `.github/workflows/release.yml`，
GitHub Actions 构建 Linux + Windows 产物并上传为 artifacts。

Windows NSIS 安装包（本机，需 NSIS 3.x）：
```bash
makensis installer/chrono_setup.nsi
```

### 2. PGP 签名（维护者本机，用私钥）

```bash
bash scripts/sign_release.sh haiyanfurry@proton.me
```

脚本会对 release/ 下每个文件生成 `.asc` 分离签名，并对
`SHA256SUMS` 生成明文签名。**私钥绝不进入 CI。**

### 3. 验证（任何人）

```bash
bash scripts/verify_release.sh
```

脚本使用仓库内的公钥（临时 GNUPGHOME，不污染本机钥匙环）：
先验清单签名 → 校验 SHA256 → 逐个验产物签名。

### 4. 发布

- GitHub Releases（私有仓库）: https://github.com/fantuanmtf/Chrono-shift/releases
- Codeberg Releases: https://codeberg.org/haiyanfurry-mtf/Chrono-Shift/releases
- 每个文件必须同时上传对应的 `.asc`；两个平台发布同一组产物与签名。

## 密钥轮换

换签名密钥时：更新 keys/haiyanfurry-mtf.asc → 重新签名全部产物 → 在
两个平台的 release 说明里声明新指纹。
