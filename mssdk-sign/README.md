# mssdk-sign —— 汽水音乐 metasec 签名 HTTP 服务

把汽水 PC 客户端自带的 `metasecml.dll`(字节 metasec,官方签名主体 *Douyin Vision Co., Ltd.*)
关在一个进程里,对外只暴露一个 HTTP `/sign`。于是:

- **Windows**:直接跑。
- **Linux**:丢进 **Wine** 跑,宿主机的服务(MusicServer 等)用 HTTP 调它 —— 专有 DLL 不出 Wine 前缀,宿主机不需要 Windows 运行时。

对应地,MusicServer 侧 `sdk/qs/mssdk.ts` 已改为 HTTP 调签名服务(环境变量 `QS_SIGN_SERVER` 指向本服务,
可选 `QS_SIGN_TOKEN`),没有签名服务时回落 `data/qs-sign.json` 里的抓包固定值——
跨平台部署不用装官方客户端了(二进制仍需自己从官方客户端里取,不入库、不再分发)。

## 文件

| 文件 | 说明 |
|---|---|
| `mssdk-sign.cpp` | 全部实现(单文件,无第三方依赖:Win32 + Winsock + 自带 MD5/JSON) |
| `build.bat` | Windows/MSVC 构建 |
| `build-mingw.sh` | Linux 交叉编译成 exe(给 Wine 跑) |
| `client.mjs` | Node 客户端示例(可直接 `node client.mjs --send` 验证) |
| `REVERSE.md` | **逆向记录**:DLL 身份/壳/真实调用 ABI/行为规则/升级后如何重新定位偏移 |

## 构建

Windows(MSVC,需要 VS BuildTools):

```bat
build.bat
:: 生成 mssdk-sign.exe
mssdk-sign.exe --selftest --dll .\metasecml.dll
```

Linux → Wine(MinGW-w64 交叉编译,静态链接,不依赖 libstdc++/winpthread DLL):

```bash
sudo apt install mingw-w64
./build-mingw.sh          # 生成 mssdk-sign.exe
```

> 注意:源码含中文注释/字符串,**MSVC 必须带 `/utf-8`**(`build.bat` 已带),否则会报一堆莫名其妙的语法错误。

## 运行

Windows:

```bat
mssdk-sign.exe --port 16689 --dll .\metasecml.dll --token 你的口令 -v
```

Wine(建议放在自己的 prefix 里,和 DLL 同目录):

```bash
mkdir -p /opt/mssdk-sign && cd /opt/mssdk-sign
cp mssdk-sign.exe metasecml.dll .
WINEPREFIX=/opt/wine-mssdk wine mssdk-sign.exe --selftest --dll ./metasecml.dll   # 先自检
WINEPREFIX=/opt/wine-mssdk wine mssdk-sign.exe --port 16689 --bind 0.0.0.0 --token 你的口令 -v
```

systemd 单元示例:

```ini
[Unit]
Description=mssdk-sign (metasec signer in Wine)
After=network.target

[Service]
Environment=WINEPREFIX=/opt/wine-mssdk
Environment=WINEDEBUG=-all
WorkingDirectory=/opt/mssdk-sign
ExecStart=/usr/bin/wine /opt/mssdk-sign/mssdk-sign.exe --port 16689 --bind 127.0.0.1 --token CHANGE_ME
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

参数:

| 参数 | 说明 |
|---|---|
| `--port <n>` | 监听端口,默认 16689 |
| `--bind <addr>` | 默认 `127.0.0.1`;容器/跨机调用才用 `0.0.0.0`(务必配 token) |
| `--dll <path>` | `metasecml.dll` 路径,默认 exe 同目录 |
| `--token <t>` | 启用鉴权(`Authorization: Bearer <t>` 或 `X-Auth-Token: <t>`) |
| `--sign-rva <hex>` | 手动指定签名函数偏移(默认按 DLL 版本表,见下) |
| `--selftest` | 只做「加载 DLL + 签名自检」后退出(部署前必跑) |
| `-v` | 打印每个请求的签名耗时 |

## 接口

### `GET /healthz`(免鉴权)

```json
{"ok":true,"service":"mssdk-sign","version":"0.1.0",
 "signer":"D:/MusicServer/soda-mssdk/metasecml.dll",
 "dllVersion":"4.6.1.0","signRva":"0x52af0","auth":true}
```

### `POST /sign`

```jsonc
{
  "url": "https://api.qishui.com/luna/pc/track_v2?aid=386088&…",   // 必填,带完整 query
  "body": "{\"track_id\":\"…\"}",                                  // 可选:给了且没带 x-ss-stub 时,服务端自动补
  "headers": {                                                     // 必填:真实要发出去的那一份
    "content-type": "application/json; charset=utf-8",
    "user-agent": "LunaPC/3.7.0(452316191)",
    "x-luna-background-type": "foreground",
    "x-tt-trace-id": "00-…-…-01"
  }
}
```

```json
{
  "ok": true,
  "headers": {"X-Helios":"…","X-Medusa":"…","X-Neptune":"…"},
  "added": {"x-ss-stub":"DBA20AB94302CB03AC25A216DD953258"},
  "elapsed_ms": 43
}
```

失败时:`{"ok":false,"error":"…"}` + 400(入参错)/ 401(token)/ 500(签名失败)。

### 三条硬性约定(踩过坑)

1. **`headers` 必须是真实要发出的那一份**,一个都不能少(尤其 `cookie`、`x-ss-stub`)。签名覆盖 URL + 全部请求头,
   少一个服务端就回 `HTTP 200 + 空 body`。
2. **`x-ss-stub` = body 的 MD5(大写)**,既是签名输入也要随请求发出。本服务在你传了 `body` 时会自动算并回传
   (`added.x-ss-stub`),记得把它一起发出去。
3. **设备要成套**:URL 里的 `device_id` / `iid` / `fp` 必须是你自己的设备;签名和 URL 里的 `device_id` 绑死,
   改了 URL 设备号 → 服务端 `200 + 空 body`(实测)。

### 客户端(Node)

```js
import { signRequest } from './client.mjs'

const { headers, added } = await signRequest(url, headersToSend, body)
await fetch(url, { method: 'POST', headers: { ...headersToSend, ...headers, ...added }, body })
```

集成到 MusicServer 时,把 `sdk/qs/mssdk.ts` 的 `signQishuiRequest()` 换成上面这次 HTTP 调用即可
(签名覆盖的 headers 与请求实际发出的 headers 保持同一份、同一顺序)。

自检:

```bash
node client.mjs          # healthz + 签一次(不发真实请求)
node client.mjs --send   # 顺带发给 api.qishui.com 验证签名被接受
```

## 它是怎么调 DLL 的(逆向结论,2026-10-02)

- 导出表里的 `MSBridgeML` / `MSBridgeOV` / `o0o0` 都是幌子(桩 / 线程状态初始化),
  **真正的签名函数在 `image base + 0x52af0`**,原型:

  ```c
  char* sign(const char* url, const char* headers_lines);   // headers: "名\r\n值\r\n…"
  ```

- 返回 `"名\r\n值\r\n…"` 的签名头串,由 DLL 自己的释放函数(`base + 0x1d8c0`)回收。
- **不需要 init**;DLL 版本(本机样本)= `metasecbaseml 4.6.1.0`。
- 调用是**串行**的(内部有全局/TLS 状态),服务端用互斥锁包住,实测 20 并发全部成功。

## 客户端升级了怎么办(DLL 换了,偏移会变)

`--selftest` 会**大声失败**,不会静默出错。定位新偏移:

1. 从新版客户端里取 `metasecml.dll`(解包方式见仓库 README「快速开始」:官方安装包 → Bandizip 解 NSIS → `$Var31/app.7z` → `resources/app.asar.unpacked/`)。
2. 拿真实请求自检,确认签名是否被接受(`node client.mjs --send`)。
3. 找新偏移:
   - 先在 `KNOWN_VERSIONS` 里加版本,用旧偏移试;不行就:
   - 用逆向脚本脱壳 + 定位(未入库,当年逆向会话产出):内存脱壳重建 PE(metasec-rebuild)、
     直接调用试偏移(metasec-call-test)、读 `bdms.node` 运行时 IAT 槽拿真实地址(bdms-abi)。
     找到后用 `--sign-rva 0xXXXXX` 验证,再写进 `KNOWN_VERSIONS`。

## 已知限制 / 未验证项

- **Wine 下未实测**(本机没有 Wine):DLL 依赖的都是 Wine 常规实现的 Win32 API(kernel32/advapi32/ole32/
  winhttp/ws2_32/imm32/…),但 metasec 有设备指纹采集,行为可能和原生不同。部署前请先在目标机跑
  `wine mssdk-sign.exe --selftest` 和 `node client.mjs --send`。若加载失败,先看 `WINEDEBUG=+loaddll`
  的缺失依赖,必要时 `winetricks corefonts vcrun2019`、`winecfg` 里把 Windows 版本设为 Win10。
- `metasecml.dll` 是**官方专有二进制**(签名主体抖音视界),不入库、不再分发;本目录只放源码与构建脚本,
  DLL 自己从官方客户端取,放 exe 同目录即可。
- 签名服务本身不联网、不存 cookie;但仍建议只监听 `127.0.0.1` 并设置 `--token`,不要暴露公网。
