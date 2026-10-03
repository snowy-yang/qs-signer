# metasec 签名组件逆向记录

> 面向维护者:**汽水客户端升级后签名失效时,先看这里。**
> 相关代码:`mssdk-sign.cpp`(签名服务);构建与接口用法见同目录 `README.md`。
> 记录时间:2026-10-02,样本:`soda-mssdk/{metasecml.dll, bdms.node}`。

## 1. 速览

| 项 | 结论 |
|---|---|
| 组件身份 | 字节 metasec 官方组件,内部名 `metasecbaseml` **4.6.1.0**(2024-09-04) |
| 数字签名 | Authenticode 主体 **Douyin Vision Co., Ltd.**(DigiCert G4 Code Signing) |
| 保护 | 自解密壳 + 运行期解密字符串表;`LoadLibrary` 后内存里即为明文镜像 |
| 真实签名入口 | `metasecml.dll + 0x52af0`(**本版本**),`char* sign(const char* url, const char* headers)` |
| 需要 init 吗 | **不需要**,冷进程直接调即可出有效签名 |
| 有效性 | 已端到端验证:签名被 `api.qishui.com` 接受;不签名 / 设备不匹配 → `HTTP 200 + 0 字节` |
| 产出能力 | `X-Helios` + `X-Medusa`(部分场景附 `X-Neptune`);**不含** Argus/Ladon/Khronos/Gorgon/a_bogus |

## 2. 两个文件的关系

- `metasecml.dll`(8.8MB):算法本体。导出表只有 3 个符号,且**都是幌子**:
  - `o0o0`(0x191c0):线程局部状态初始化(读 TEB→TLS 槽,条件成立时 memset 一个 0x148 字节结构)。
  - `MSBridgeML` / `MSBridgeOV`(同为 0x1d010):同一个桩 —— 调一次内部函数后**无条件返回 true**,签名结果不经它返回。
- `bdms.node`(164KB):官方客户端的 N-API 胶水。对 JS 暴露 `init` / `generateHttpSignatureHeaders` / `report`;
  通过**延迟导入** `metasecml.dll` 的 `o0o0`、`MSBridgeML` 来用 DLL。

## 3. 真实调用 ABI(核心)

```c
// headers: 官方展平形式 —— 每行 "名字\r\n值",行间也用 "\r\n" 连接
char* sign(const char* url, const char* headers_lines);
```

- 地址:`image base + 0x52af0`(该处是 `jmp` 跳板,实体在 0x52b00)。
- 返回:`"名字\r\n值\r\n…"` 的签名头串,堆分配;释放函数 = `image base + 0x1d8c0`。
- 线程:内部有全局/TLS 状态,**串行调用**(服务端已加互斥锁)。
- addon 是怎么拿到这个地址的:运行时 DLL 改写了它的 IAT 槽(`bdms.node` 的 `.data` 偏移 `0x25e38`),
  槽里躺着的就是 `base+0x52af0` —— 这解释了「导出表说是 0x1d010,实际却在 0x52af0」的矛盾。
- 壳的形态:磁盘上只有 PE 头 + 单个 8.8MB 加密节 `.xs2`(熵≈8.0),`.text/.rdata/.data/.xs0` 均无 raw 数据;
  加载时解密进内存 → **内存 dump 即得完整镜像**(重定位已修好)。

## 4. 行为规则(实测)

| 场景 | 服务端反应 |
|---|---|
| 不带签名 | `HTTP 200 + 0 字节` |
| 带正确签名 | `HTTP 200` + 正常 JSON(曲名/时长/档位齐全) |
| 签名后改 URL 里的 `device_id` | `HTTP 200 + 0 字节` → **签名与 URL 设备参数绑死** |
| headers 少一个(尤其 `cookie`、`x-ss-stub`) | `HTTP 200 + 0 字节` → 签名覆盖**全部**请求头 |

- **`x-ss-stub` = body 的 MD5(大写)**,既是签名输入也必须随请求发出。
- **场景决定头集合**:传完整真实头 → `X-Helios` + `X-Medusa`(有时附 `X-Neptune`);
  只传一个 `user-agent` 这类极简头 → **只给 `X-Neptune`**(网页兜底场景)。
  所以调用方必须把「真实要发出的那一份头」整套传进来。
- 输出含时间戳/nonce,**每次不同**属正常。
- 签名有效 ≠ 能拿整曲:匿名仍只有 30 秒试听(实测 236.6s 曲目 `stream_duration=30`),
  **瓶颈是登录 sessionid,不是签名**。

## 5. 内部结构(RTTI 符号泄漏)

| 类 / 符号 | 作用 |
|---|---|
| `IMSHttpReqSignModule` / `MSHttpReqSignModule` | HTTP 请求签名(本服务的调用目标) |
| `IMSWebsocketReqSignModule` | WebSocket 请求签名 |
| `MSBlackBox` / `IMSBlackBoxItem` | 黑盒数据采集 |
| `IMSSecDeviceIDModule` | 设备指纹(device id) |
| `IMSRiskInspectModule` / `IMSRiskInspector` | 风控检测 |
| `IMSReportModule` | 数据上报 |
| `MSPBSInt32/64`、`MSPBString(List)`(`__ms__`) | protobuf 序列化 |
| `MSNetInterceptor::FuncInterceptor` + `Cronet_UrlRequest_Create`、`Cronet_Engine_SetMD5Header` | 注入 Chromium Cronet 网络栈(`x-ss-stub` 的 MD5 由它算) |
| `MSConfig` / `MSJSON` / `MSHttpClient` / `MSTaskManager` | 基础设施;日志用 spdlog,源路径 `utils/matrix/os/windows/ms_log.cc` |

## 6. 保护强度评估

- 壳是「自解密 + 字符串按需解密」,**没有代码虚拟化**;脱壳后是正常的 MSVC x64 代码,可读可跟。
- 敏感字符串(如 `X-Helios`)静态搜不到,运行期才解密;镜像里没找到明文标准 AES S-box
  (只有 CRC32 表、Base64 表、TEA/Blowfish 类常量)。
- 结论:**算法级复刻不划算**——黑盒调用的集成成本≈0,而且能随官方升级同步。

## 7. 客户端升级后怎么重新定位偏移

`--selftest` 会**大声失败**,不会静默签出无效头。定位步骤:

1. 从新版客户端取 `metasecml.dll`(解包方式见 `sdk/qs/mssdk.ts` 头部注释)。
2. 跑 `mssdk-sign.exe --selftest --dll <新dll>`:会打印它读到的 DLL 版本;失败即偏移变了。
3. 找新偏移(仓库 `tmp/` 下现成脚本):
   - `tmp/metasec-rebuild.py` —— 内存脱壳 + 重建可分析 PE;
   - `tmp/bdms-abi.py` —— 读 `bdms.node` 运行时 IAT 槽,直接拿到真实签名函数地址(**最省事**);
   - `tmp/metasec-call-test.py` —— 用候选偏移直接调用,看返回是否形如 `X-…\r\n…`。
4. 用 `--sign-rva 0xXXXXX` 验证,通过后写进 `mssdk-sign.cpp` 的 `KNOWN_VERSIONS`。
5. 复验:`node client.mjs --send` 应得到 `HTTP 200` + 非空 body。

## 8. 边界

- `metasecml.dll` / `bdms.node` 是**官方专有二进制**,不入库、不随代码分发;各自从自己的官方客户端取,放 exe 同目录。
- 用途限于个人自用/互操作性研究;不要对外提供签名服务,也不要用于批量刷接口。
- 签名服务本身不联网、不落 cookie;部署仍建议只监听 `127.0.0.1` 并设置 `--token`。
