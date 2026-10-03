# qs-signer —— 汽水音乐签名工具链

汽水音乐（qishui / SodaMusic）PC 通道的签名与登录工具，从 [MusicServer](https://gitea.4i.hk/hhhge/MusicServer) 拆出独立维护。
MusicServer 侧不直接加载任何官方二进制——设 `QS_SIGN_SERVER` 指向本仓库任一签名服务即可（详见 MusicServer 的
`sdk/qs/mssdk.ts` 与其 README「汽水 PC 签名」一节）。

## 内容

| 文件 | 说明 |
|---|---|
| `server.mjs` | 签名服务 A：**Wine + bdms.node**（官方 PC 客户端原生模块）。Linux 上用 Wine 跑 Windows 版 Node 加载它，对外 HTTP `/sign`。用法/参数见文件头注释（`QS_SIGNER_*` 环境变量，默认端口 8899） |
| `mssdk-sign/` | 签名服务 B：**C++ + metasecml.dll**（单文件实现，Windows 直跑 / Wine 跑）。见 [mssdk-sign/README.md](mssdk-sign/README.md)（默认端口 16889）与逆向记录 [mssdk-sign/REVERSE.md](mssdk-sign/REVERSE.md) |
| `qs-local-login.mjs` | 本机客户端登录脚本：读官方 PC 客户端的 `DeviceV1` + Chromium Cookies → 校验 → 写 MusicServer 的 `data/auth.json`（免扫码）。用法见脚本头注释 |
| `soda-mssdk/` | **不入库**：官方二进制自取放这里（`bdms.node` + `metasecml.dll`），从官方客户端 `resources/app.asar.unpacked/` 提取 |

两个签名服务 `/sign` 契约互通（请求 `{url, headers, body?}`，响应 `{ok, headers, added?}`），按部署环境任选其一。

## 快速开始

```bash
# 1. 官方二进制（自备，不入库）：从官方 PC 客户端提取，放 soda-mssdk/
#    SodaMusic-v*-official-win32_x64.exe → Bandizip 解 NSIS → $Var31/app.7z
#    → resources/app.asar.unpacked/{bdms.node, metasecml.dll}

# 2a. Node 版签名服务（Windows 直跑；Linux 上配 Wine 跑 Windows 版 Node）
#     模块默认找 ./vendor/bdms.node，这里直接指向 soda-mssdk/
QS_SIGNER_ALLOW_ANONYMOUS=1 QS_SIGNER_BDMS_MODULE=./soda-mssdk/bdms.node node server.mjs   # 默认 127.0.0.1:8899，生产请配 QS_SIGNER_TOKEN

# 2b. 或 C++ 版（需构建，见 mssdk-sign/README.md）
cd mssdk-sign && ./build.bat
mssdk-sign.exe --selftest --dll ../soda-mssdk/metasecml.dll

# 3. MusicServer 侧接入
#    .env 或环境变量：QS_SIGN_SERVER=http://127.0.0.1:8899（及可选 QS_SIGN_TOKEN）
#    未配签名服务时，MusicServer 自动回落 data/qs-sign.json 里的抓包固定值（X-Helios/X-Medusa）

# 4.（可选）本机已装官方客户端时，免扫码导入登录态到 MusicServer
node qs-local-login.mjs --print      # 先看能否读到 sessionid
node qs-local-login.mjs              # 写入 ../MusicServer/data/auth.json
```

## 约定（两个服务共用的硬性规则）

- **签名覆盖 URL + 全部请求头**：`headers` 必须是真实要发出去的那一份，一个都不能少（尤其 `cookie`、`x-ss-stub`），否则上游回 `HTTP 200 + 空 body`。
- **`x-ss-stub` = body 的 MD5（大写）**：既是签名输入也要随请求发出；传了 `body` 而没带时服务端自动补。
- **设备要成套**：URL 里的 `device_id`/`iid`/`fp` 与签名绑定的设备一致，改了设备号 → 上游 `200 + 空 body`。
- 官方二进制（`bdms.node` / `metasecml.dll`）是**抖音视界专有文件**：不入库、不再分发，自己从官方客户端提取。
- 签名服务不联网、不存 cookie；仍建议只监听 `127.0.0.1` 并设置 token，不要暴露公网。
