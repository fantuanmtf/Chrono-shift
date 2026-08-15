#!/usr/bin/env bash
# Chrono-shift 发布签名脚本
#
# 用你的 PGP 私钥对 release/ 下的所有发布产物做分离签名，
# 并对 SHA256SUMS 做明文签名 (clearsign)。
#
# 用法:
#   bash scripts/sign_release.sh <KEY_ID>
#   例如: bash scripts/sign_release.sh haiyanfurry@proton.me
#
# 前置条件: 私钥已导入 gpg (gpg --list-secret-keys 能看到)

set -euo pipefail

KEY_ID="${1:?用法: sign_release.sh <KEY_ID>}"
RELEASE_DIR="${RELEASE_DIR:-release}"
SUMS="${SUMS:-SHA256SUMS}"

if ! command -v gpg >/dev/null 2>&1; then
    echo "错误: 未找到 gpg" >&2
    exit 1
fi

if [ ! -d "$RELEASE_DIR" ]; then
    echo "错误: 目录 $RELEASE_DIR 不存在 (先运行打包流程)" >&2
    exit 1
fi

# 1. 重新生成校验和 (排除 *.asc 与 SHA256SUMS 自身, 确保签名与内容一致)
( cd "$RELEASE_DIR" && find . -maxdepth 1 -type f ! -name '*.asc' ! -name "$SUMS" -exec sha256sum {} + | sed 's|  \./|  |' > "$SUMS" )

# 2. 对每个产物做分离签名 (.asc) — --batch --yes 避免 TTY 提示
for f in "$RELEASE_DIR"/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
        *.asc) continue ;;
    esac
    echo "签名: $(basename "$f")"
    gpg --batch --yes --armor --detach-sign --local-user "$KEY_ID" "$f"
done

# 3. 对 SHA256SUMS 做明文签名 (校验和清单本身可验证)
( cd "$RELEASE_DIR" && gpg --batch --yes --armor --clearsign --local-user "$KEY_ID" "$SUMS" )

echo
echo "完成。产物:"
ls -la "$RELEASE_DIR"
echo
echo "上传到 GitHub Releases / Codeberg Releases 时，每个文件都要带上"
echo "对应的 .asc 签名文件，并把 SHA256SUMS.asc 一并发布。"
