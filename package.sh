#!/usr/bin/env bash
#
# RZP 一键打包脚本（多平台：Linux + Windows）
#
# 开发者: 张俊琦
# 日期:   2026-10-24
# 邮箱:   mokaifurry@outlook.com
#
# 用法:
#   ./package.sh
#
# 产物:
#   dist/rzp-<版本>-<架构>.tar.gz               Linux 可移植二进制 + 文档 + 补全 + man page
#   target/debian/rzp_<版本>-1_<架构>.deb        Debian 安装包（需已安装 cargo-deb）
#   dist/rzp-<版本>-x86_64-windows.zip           Windows 可移植二进制 + 文档（需 mingw-w64）
#   dist/rzp-<版本>-x86_64-windows-setup.exe     Windows 安装包（需 mingw-w64 + NSIS）

set -euo pipefail

# 脚本所在目录即项目根目录
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# 从 Cargo.toml 解析版本号
VERSION="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' Cargo.toml | head -n1)"
: "${VERSION:?无法从 Cargo.toml 解析版本号}"

# Windows 版本资源需要 4 段数字版本号（NSIS VIProductVersion）
IFS='.' read -ra VP <<< "$VERSION"
while [ "${#VP[@]}" -lt 4 ]; do VP+=("0"); done
VIVERSION="${VP[0]}.${VP[1]}.${VP[2]}.${VP[3]}"

# 架构映射
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  DEB_ARCH="amd64" ;;
  aarch64) DEB_ARCH="arm64" ;;
  *)       DEB_ARCH="$ARCH" ;;
esac

WINDOWS_TARGET="x86_64-pc-windows-gnu"
DIST="$ROOT/dist"

# ---------------------------------------------------------------------------
# Linux（本机原生）
# ---------------------------------------------------------------------------
echo "==> 编译 Linux release 版本"
cargo build --release

LINUX_STAGE="$DIST/rzp-$VERSION-$ARCH"
echo "==> 收集 Linux 产物到 $LINUX_STAGE"
rm -rf "$LINUX_STAGE"
mkdir -p "$LINUX_STAGE"
cp -f target/release/rzp "$LINUX_STAGE/rzp"
for doc in README.md FORMAT.md API.md LICENSE; do
  [ -f "$doc" ] && cp -f "$doc" "$LINUX_STAGE/"
done

echo "==> 生成 shell 补全脚本"
mkdir -p "$LINUX_STAGE/completions"
for sh in bash zsh fish; do
  target/release/rzp completion "$sh" > "$LINUX_STAGE/completions/rzp.$sh"
done

echo "==> 生成 man page"
mkdir -p "$LINUX_STAGE/man"
[ -f man/rzp.1 ] && cp -f man/rzp.1 "$LINUX_STAGE/man/rzp.1"

echo "==> 生成 Linux 可移植 tar.gz"
tar -C "$DIST" -czf "$DIST/rzp-$VERSION-$ARCH.tar.gz" "rzp-$VERSION-$ARCH"

echo "==> 生成 Debian 安装包 (.deb)"
if command -v cargo-deb >/dev/null 2>&1; then
  cargo deb
  echo "    -> target/debian/rzp_${VERSION}-1_${DEB_ARCH}.deb"
else
  echo "    未检测到 cargo-deb，跳过 .deb 生成（可执行: cargo install cargo-deb）"
fi

# ---------------------------------------------------------------------------
# Windows（交叉编译，需要 Rust target + mingw-w64 链接器）
# ---------------------------------------------------------------------------
echo ""
build_windows() {
  echo "==> 编译 Windows release 版本 (${WINDOWS_TARGET})"

  if ! rustup target list --installed 2>/dev/null | grep -qx "$WINDOWS_TARGET"; then
    echo "    警告：未安装 Rust 目标 ${WINDOWS_TARGET}，跳过 Windows 打包。"
    echo "    可执行: rustup target add ${WINDOWS_TARGET}"
    return 0
  fi

  if ! command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    echo "    警告：未检测到 mingw-w64 交叉链接器，跳过 Windows 打包。"
    echo "    可执行: sudo apt install gcc-mingw-w64-x86-64"
    return 0
  fi

  cargo build --release --target "$WINDOWS_TARGET"

  local win_stage="$DIST/rzp-$VERSION-x86_64-windows"
  echo "==> 收集 Windows 产物到 $win_stage"
  rm -rf "$win_stage"
  mkdir -p "$win_stage"
  cp -f "target/$WINDOWS_TARGET/release/rzp.exe" "$win_stage/rzp.exe"
  for doc in README.md FORMAT.md API.md LICENSE; do
    [ -f "$doc" ] && cp -f "$doc" "$win_stage/"
  done
  [ -f assets/rzp.ico ] && cp -f assets/rzp.ico "$win_stage/rzp.ico"

  echo "==> 生成 Windows 可移植 zip"
  (cd "$DIST" && zip -qr "rzp-$VERSION-x86_64-windows.zip" "rzp-$VERSION-x86_64-windows")

  if command -v makensis >/dev/null 2>&1; then
    echo "==> 生成 Windows 安装包 (NSIS)"
    local installer="$DIST/rzp-$VERSION-x86_64-windows-setup.exe"
    makensis \
      "-DVERSION=$VERSION" \
      "-DVIVERSION=$VIVERSION" \
      "-DARCH=x86_64" \
      "-DOUTFILE=$installer" \
      "-DSTAGEDIR=$win_stage" \
      "packaging/windows/rzp.nsi"
  else
    echo "    未检测到 NSIS（makensis），跳过安装包生成（可执行: sudo apt install nsis）"
  fi
}
build_windows

echo ""
echo "打包完成："
ls -lh "$DIST"/*.tar.gz 2>/dev/null || true
ls -lh "$DIST"/*.zip 2>/dev/null || true
ls -lh "$DIST"/*-setup.exe 2>/dev/null || true
ls -lh "target/debian/rzp_${VERSION}-1_${DEB_ARCH}.deb" 2>/dev/null || true
