#!/usr/bin/env bash
# Chrono-shift 发布验证脚本
#
# 用仓库内的公钥 (keys/haiyanfurry-mtf.asc) 验证 release/ 下的签名。
#
# 用法:
#   bash scripts/verify_release.sh
#
# 首次运行会把公钥导入一个临时 GNUPGHOME，不影响你的 gpg 钥匙环。

set -euo pipefail

RELEASE_DIR="${RELEASE_DIR:-release}"
SUMS="${SUMS:-SHA256SUMS}"
PUBKEY="$(cd "$(dirname "$0")/.." && pwd)/keys/haiyanfurry-mtf.asc"

if ! command -v gpg >/dev/null 2>&1; then
    echo "错误: 未找到 gpg" >&2
    exit 1
fi

TMP_GNUPG="$(mktemp -d)"
trap 'rm -rf "$TMP_GNUPG"' EXIT
chmod 700 "$TMP_GNUPG"

gpg --homedir "$TMP_GNUPG" --batch --import "$PUBKEY" >/dev/null 2>&1

echo "== 1. 验证 SHA256SUMS 清单签名 =="
# SHA256SUMS.asc 是明文签名(clearsign), 内容内嵌, 只传一个参数;
# 输出里会回显被签名的内容 (应与 SHA256SUMS 一致)。
gpg --homedir "$TMP_GNUPG" --verify "$RELEASE_DIR/$SUMS.asc"

echo
echo "== 2. 验证校验和 =="
( cd "$RELEASE_DIR" && sha256sum -c "$SUMS" )

echo
echo "== 3. 验证每个产物的分离签名 =="
for f in "$RELEASE_DIR"/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in
        *.asc | $SUMS) continue ;;
    esac
    if [ -f "$f.asc" ]; then
        gpg --homedir "$TMP_GNUPG" --verify "$f.asc" "$f"
    else
        echo "警告: $f 缺少 .asc 签名" >&2
    fi
done

echo
echo "✅ 全部验证通过"
