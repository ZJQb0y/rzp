#!/usr/bin/env bash
#
# RZP 一键打包脚本
#
# 开发者: 张俊琦
# 日期:   2026-10-05
# 邮箱:   mokaifurry@outlook.com
#
# 用法:
#   ./package.sh
#
# 产物:
#   dist/rzp-<版本>-<架构>.tar.gz              可移植二进制 + 文档
#   target/debian/rzp_<版本>-1_<架构>.deb      Debian 安装包（需已安装 cargo-deb）

set -euo pipefail

# 脚本所在目录即项目根目录
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# 从 Cargo.toml 解析版本号
VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' Cargo.toml | head -n1)"
: "${VERSION:?无法从 Cargo.toml 解析版本号}"

# 架构映射
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  DEB_ARCH="amd64" ;;
  aarch64) DEB_ARCH="arm64" ;;
  *)       DEB_ARCH="$ARCH" ;;
esac

DIST="$ROOT/dist"
STAGE="$DIST/rzp-$VERSION-$ARCH"

echo "==> 编译 release 版本"
cargo build --release

echo "==> 收集产物到 $STAGE"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -f target/release/rzp "$STAGE/rzp"
for doc in README.md FORMAT.md API.md LICENSE; do
  [ -f "$doc" ] && cp -f "$doc" "$STAGE/"
done

echo "==> 生成 shell 补全脚本"
mkdir -p "$STAGE/completions"
for sh in bash zsh fish; do
  target/release/rzp completion "$sh" > "$STAGE/completions/rzp.$sh"
done

echo "==> 生成 man page"
mkdir -p "$STAGE/man"
[ -f man/rzp.1 ] && cp -f man/rzp.1 "$STAGE/man/rzp.1"

echo "==> 生成可移植 tar.gz"
tar -C "$DIST" -czf "$DIST/rzp-$VERSION-$ARCH.tar.gz" "rzp-$VERSION-$ARCH"

echo "==> 生成 Debian 安装包 (.deb)"
if command -v cargo-deb >/dev/null 2>&1; then
  cargo deb
  echo "    -> target/debian/rzp_${VERSION}-1_${DEB_ARCH}.deb"
else
  echo "    未检测到 cargo-deb，跳过 .deb 生成（可执行: cargo install cargo-deb）"
fi

echo ""
echo "打包完成："
ls -lh "$DIST"/*.tar.gz 2>/dev/null || true
ls -lh "target/debian/rzp_${VERSION}-1_${DEB_ARCH}.deb" 2>/dev/null || true
