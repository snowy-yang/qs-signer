#!/usr/bin/env bash
# Linux 上交叉编译成 Windows exe(给 Wine 跑)。
# 依赖: apt install mingw-w64   (Debian/Ubuntu)
set -euo pipefail
CXX=${CXX:-x86_64-w64-mingw32-g++}
command -v "$CXX" >/dev/null || { echo "[x] 找不到 $CXX,请先装 mingw-w64"; exit 1; }

"$CXX" -std=c++17 -O2 -Wno-unknown-pragmas \
  -static -static-libgcc -static-libstdc++ \
  -o mssdk-sign.exe mssdk-sign.cpp \
  -pthread -lws2_32 -lversion

echo "[ok] 生成 mssdk-sign.exe(静态链接,不依赖 libstdc++/winpthread DLL)"
echo "     自检: wine ./mssdk-sign.exe --selftest --dll ./metasecml.dll"
