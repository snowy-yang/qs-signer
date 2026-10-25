# qs-signer —— 汽水音乐签名工具链

汽水音乐（qishui / SodaMusic）PC 通道的签名与登录工具，从 [MusicServer](https://github.com/snowy-yang/MusicServer) 拆出独立维护。
MusicServer 侧不直接加载任何官方二进制——设 `QS_SIGN_SERVER` 指向本仓库的签名服务即可（详见 MusicServer 的
`sdk/qs/mssdk.ts` 与其 README「汽水 PC 签名」一节）。

## 内容

| 文件 | 说明 |
|---|---|
| `mssdk-sign/` | 签名服务：**C++ + metasecml.dll**（单文件实现，Windows 直跑 / Wine 跑）。见 [mssdk-sign/README.md](mssdk-sign/README.md)（默认端口 16689）与逆向记录 [mssdk-sign/REVERSE.md](mssdk-sign/REVERSE.md) |
| `qs-login/` | 本机客户端登录态读取工具（C++，**只读不写**）：读官方 PC 客户端的 `DeviceV1` + Chromium Cookies → 可选签名校验（`metasecml.dll`）→ 完整显示 sessionid 并复制到剪贴板，粘到哪由你自己决定。用法见 `qs-login.cpp` 头注释，可直接双击运行 |
| `qs-login-rs/` | 同一工具的 **Rust 版**（生态 crate：flate2/rusqlite(bundled)/serde_json/ureq，功能与 C++ 版对等），`cargo build --release` 即可 |

## 快速开始

```bash
# 1. 官方二进制（自备，不入库）：从官方 PC 客户端提取 metasecml.dll，放 mssdk-sign/
#    SodaMusic-v*-official-win32_x64.exe → Bandizip 解 NSIS → $Var31/app.7z
#    → resources/app.asar.unpacked/metasecml.dll

# 2. 构建并自检（Windows/MSVC；Linux 交叉编译见 mssdk-sign/build-mingw.sh）
cd mssdk-sign && ./build.bat
mssdk-sign.exe --selftest --dll .\metasecml.dll

# 3. MusicServer 侧接入
#    .env 或环境变量：QS_SIGN_SERVER=http://127.0.0.1:16689（及可选 QS_SIGN_TOKEN）
#    未配签名服务时，MusicServer 自动回落 data/qs-sign.json 里的抓包固定值（X-Helios/X-Medusa）

# 4.（可选）本机已装官方客户端时，读出登录态（只读不写，sessionid 自动复制到剪贴板）
cd ../qs-login && ./build.bat
qs-login.exe                     # 可直接双击：窗口等回车才关；DLL 默认自动找 ..\mssdk-sign\
```

## 约定（硬性规则）

- **签名覆盖 URL + 全部请求头**：`headers` 必须是真实要发出去的那一份，一个都不能少（尤其 `cookie`、`x-ss-stub`），否则上游回 `HTTP 200 + 空 body`。
- **`x-ss-stub` = body 的 MD5（大写）**：既是签名输入也要随请求发出；传了 `body` 而没带时服务端自动补。
- **设备要成套**：URL 里的 `device_id`/`iid`/`fp` 与签名绑定的设备一致，改了设备号 → 上游 `200 + 空 body`。
- `metasecml.dll` 是**抖音视界专有文件**：不入库、不再分发，自己从官方客户端提取。
- 签名服务不联网、不存 cookie；仍建议只监听 `127.0.0.1` 并设置 token，不要暴露公网。
