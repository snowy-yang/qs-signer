#!/usr/bin/env bash
# Linux 上交叉编译成 Windows exe(给 Wine 跑)。
# 依赖: apt install mingw-w64   (Debian/Ubuntu)
set -euo pipefail
CXX=${CXX:-x86_64-w64-mingw32-g++}
command -v "$CXX" >/dev/null || { echo "[x] 找不到 $CXX,请先装 mingw-w64"; exit 1; }

"$CXX" -std=c++17 -O2 -Wno-unknown-pragmas \
  -static -static-libgcc -static-libstdc++ \
  -o qs-login.exe qs-login.cpp \
  -pthread -lwinhttp -lbcrypt -lcrypt32 -lversion -luser32

echo "[ok] 生成 qs-login.exe(静态链接,不依赖 libstdc++/winpthread DLL)"
echo "     用法: wine ./qs-login.exe --print   (读 Wine 前缀里的客户端数据)"
