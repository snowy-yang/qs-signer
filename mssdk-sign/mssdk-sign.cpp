// mssdk-sign —— 汽水音乐(metasec)签名 HTTP 服务
//
// 为什么是它:汽水 PC 客户端自带的 metasecml.dll 提供应用级签名(X-Helios/X-Medusa,
// 部分场景附 X-Neptune)。本程序把该 DLL 关在一个进程里,对外只暴露一个 HTTP /sign,
// 于是:Windows 上直接跑;Linux 上丢进 Wine 跑,宿主机的服务(如 MusicServer)用 HTTP 调。
//
// 关于 DLL 的调用方式(2026-10-02 逆向确认,版本 metasecbaseml 4.6.1.0):
//   * 导出表里的 MSBridgeML / MSBridgeOV / o0o0 都是幌子(桩/初始化),
//     真正的签名函数在 image base + 0x52af0,原型 char* f(const char* url, const char* headers)。
//   * headers 是官方展平形式:每个头 "名字\r\n值",头与头之间也用 "\r\n" 连接。
//   * 返回 "名字\r\n值\r\n..." 的签名头串,由 DLL 自己的释放函数(base + 0x1d8c0)回收。
//   * 不需要 init;签名覆盖 URL + 全部请求头,且与 URL 里的 device_id 绑死
//     (改 URL 设备号 → 服务端 200 + 空 body)。
//   * 偏移随客户端版本变化:内置版本表 + 启动自检,不匹配会明确报错(见 README「升级怎么办」)。
//
// 构建(任选其一):
//   Windows/MSVC : build.bat
//   Linux/MinGW  : x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -static-libgcc -static-libstdc++ \
//                    -o mssdk-sign.exe mssdk-sign.cpp -lws2_32 -lversion -lwinpthread
// 运行:
//   mssdk-sign.exe --port 16889 --dll .\metasecml.dll
//   wine mssdk-sign.exe --port 16889 --dll ./metasecml.dll
//
// 依赖:仅 Win32 API + Winsock(无第三方库,无 C++ 异常跨模块问题)。

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winver.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "version.lib")
#endif

// ---------------------------------------------------------------- 工具

static std::string toLower(std::string s) {
    for (auto &c : s) c = (char)tolower((unsigned char)c);
    return s;
}

static std::string trim(const std::string &s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::string jsonEscape(const std::string &s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    snprintf(b, sizeof b, "\\u%04x", c);
                    o += b;
                } else {
                    o += (char)c;
                }
        }
    }
    return o;
}

// ---------------------------------------------------------------- MD5(用于 x-ss-stub = body 的 MD5 大写)

namespace md5impl {
struct Ctx {
    uint32_t a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
    uint64_t len = 0;
    uint8_t buf[64];
    size_t n = 0;
};

static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
static const uint8_t S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static inline uint32_t rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void block(Ctx &ctx, const uint8_t *p) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)p[i * 4] | ((uint32_t)p[i * 4 + 1] << 8) | ((uint32_t)p[i * 4 + 2] << 16) |
               ((uint32_t)p[i * 4 + 3] << 24);
    uint32_t a = ctx.a, b = ctx.b, c = ctx.c, d = ctx.d;
    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) { f = (b & c) | (~b & d); g = (uint32_t)i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (uint32_t)(5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d; g = (uint32_t)(3 * i + 5) & 15; }
        else { f = c ^ (b | ~d); g = (uint32_t)(7 * i) & 15; }
        uint32_t t = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + m[g], S[i]);
        a = t;
    }
    ctx.a += a; ctx.b += b; ctx.c += c; ctx.d += d;
}

static void update(Ctx &ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    ctx.len += len;
    while (len) {
        size_t take = 64 - ctx.n;
        if (take > len) take = len;
        memcpy(ctx.buf + ctx.n, p, take);
        ctx.n += take; p += take; len -= take;
        if (ctx.n == 64) { block(ctx, ctx.buf); ctx.n = 0; }
    }
}

static std::string hex(const Ctx &in) {
    Ctx ctx = in;
    uint64_t bits = ctx.len * 8;
    uint8_t pad = 0x80;
    update(ctx, &pad, 1);
    uint8_t zero = 0;
    while (ctx.n != 56) update(ctx, &zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (8 * i));
    update(ctx, lenb, 8);
    uint32_t v[4] = {ctx.a, ctx.b, ctx.c, ctx.d};
    static const char *H = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) {
            out += H[(v[i] >> (8 * j + 4)) & 0xf];
            out += H[(v[i] >> (8 * j)) & 0xf];
        }
    return out;
}
}  // namespace md5impl

static std::string md5HexUpper(const std::string &data) {
    md5impl::Ctx ctx;
    md5impl::update(ctx, data.data(), data.size());
    std::string h = md5impl::hex(ctx);
    for (auto &c : h) c = (char)toupper((unsigned char)c);
    return h;
}

// ---------------------------------------------------------------- 极简 JSON(只支持本服务需要的子集)

struct JVal {
    enum T { Nul, Bool, Num, Str, Arr, Obj } t = Nul;
    std::string s;                                             // Str / Num / Bool 的原始文本
    std::vector<JVal> a;                                       // Arr
    std::vector<std::pair<std::string, JVal>> o;               // Obj(保序)
    const JVal *get(const std::string &k) const {
        for (auto &kv : o)
            if (kv.first == k) return &kv.second;
        return nullptr;
    }
};

namespace json {
struct P {
    const std::string &s;
    size_t i = 0;
    explicit P(const std::string &src) : s(src) {}
    void ws() { while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++; }
    bool lit(const char *w) {
        size_t n = strlen(w);
        if (s.compare(i, n, w) == 0) { i += n; return true; }
        return false;
    }
    void utf8(uint32_t cp, std::string &out) {
        if (cp < 0x80) out += (char)cp;
        else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }
    bool hex4(uint32_t &v) {
        v = 0;
        for (int k = 0; k < 4; k++) {
            if (i >= s.size()) return false;
            char c = s[i++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (uint32_t)(c - 'A' + 10);
            else return false;
        }
        return true;
    }
    bool str(std::string &out) {
        if (i >= s.size() || s[i] != '"') return false;
        i++;
        out.clear();
        while (i < s.size()) {
            char c = s[i++];
            if (c == '"') return true;
            if (c != '\\') { out += c; continue; }
            if (i >= s.size()) return false;
            char e = s[i++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp;
                    if (!hex4(cp)) return false;
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                        size_t save = i;
                        i += 2;
                        uint32_t lo;
                        if (hex4(lo) && lo >= 0xDC00 && lo <= 0xDFFF)
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        else
                            i = save;
                    }
                    utf8(cp, out);
                    break;
                }
                default: return false;
            }
        }
        return false;
    }
    bool val(JVal &v) {
        ws();
        if (i >= s.size()) return false;
        char c = s[i];
        if (c == '{') {
            v.t = JVal::Obj;
            i++;
            ws();
            if (i < s.size() && s[i] == '}') { i++; return true; }
            while (true) {
                ws();
                std::string k;
                if (!str(k)) return false;
                ws();
                if (i >= s.size() || s[i] != ':') return false;
                i++;
                JVal cv;
                if (!val(cv)) return false;
                v.o.emplace_back(std::move(k), std::move(cv));
                ws();
                if (i < s.size() && s[i] == ',') { i++; continue; }
                if (i < s.size() && s[i] == '}') { i++; return true; }
                return false;
            }
        }
        if (c == '[') {
            v.t = JVal::Arr;
            i++;
            ws();
            if (i < s.size() && s[i] == ']') { i++; return true; }
            while (true) {
                JVal cv;
                if (!val(cv)) return false;
                v.a.push_back(std::move(cv));
                ws();
                if (i < s.size() && s[i] == ',') { i++; continue; }
                if (i < s.size() && s[i] == ']') { i++; return true; }
                return false;
            }
        }
        if (c == '"') { v.t = JVal::Str; return str(v.s); }
        if (lit("true")) { v.t = JVal::Bool; v.s = "true"; return true; }
        if (lit("false")) { v.t = JVal::Bool; v.s = "false"; return true; }
        if (lit("null")) { v.t = JVal::Nul; return true; }
        size_t b = i;
        while (i < s.size() && (isdigit((unsigned char)s[i]) || s[i] == '-' || s[i] == '+' || s[i] == '.' ||
                                s[i] == 'e' || s[i] == 'E'))
            i++;
        if (i == b) return false;
        v.t = JVal::Num;
        v.s = s.substr(b, i - b);
        return true;
    }
};
}  // namespace json

// ---------------------------------------------------------------- 签名器

typedef char *(*SignFn)(const char *, const char *);
typedef void (*FreeFn)(void *);

// SEH 必须放在不含 C++ 析构对象的函数里(否则 MSVC 报 C2712)
#ifdef _MSC_VER
static char *callSignRaw(SignFn fn, const char *url, const char *headers) {
    __try {
        return fn(url, headers);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}
#endif

struct RvaPair {
    uint64_t sign;
    uint64_t freefn;
};

// 已知版本 → 偏移(客户端升级后新增一行;见 README)
static const struct {
    const char *version;
    RvaPair rva;
} KNOWN_VERSIONS[] = {
    {"4.6.1.0", {0x52af0, 0x1d8c0}},
};
static const RvaPair DEFAULT_RVA = {0x52af0, 0x1d8c0};

class Signer {
  public:
    bool load(const std::string &dllPath, uint64_t rvaOverride, std::string &err) {
        dllPath_ = dllPath;
        HMODULE m = LoadLibraryExW(toWide(dllPath).c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
        if (!m) {
            char b[256];
            snprintf(b, sizeof b, "LoadLibraryExW 失败(错误码 %lu): %s", GetLastError(), dllPath.c_str());
            err = b;
            return false;
        }
        mod_ = m;
        version_ = readVersion(dllPath);

        RvaPair use = DEFAULT_RVA;
        if (rvaOverride) {
            use = {rvaOverride, rvaOverride + (DEFAULT_RVA.freefn - DEFAULT_RVA.sign)};
            err.clear();
        } else {
            bool found = false;
            for (auto &kv : KNOWN_VERSIONS) {
                if (version_ == kv.version) { use = kv.rva; found = true; break; }
            }
            if (!found) {
                char b[256];
                snprintf(b, sizeof b,
                         "DLL 版本 %s 不在已知表内(已知: 4.6.1.0)。将按默认偏移 %#llx 试跑,"
                         "失败请用 --sign-rva 指定(见 README)",
                         version_.empty() ? "(读不到)" : version_.c_str(), (unsigned long long)DEFAULT_RVA.sign);
                warn_ = b;
            }
        }

        sign_ = (SignFn)((uint8_t *)mod_ + use.sign);
        free_ = (FreeFn)((uint8_t *)mod_ + use.freefn);
        rva_ = use;

        // 启动自检:签一个探针,确认偏移正确(不发网络请求)
        if (!selfTest()) {
            err = "签名自检失败:偏移 " + hexStr(use.sign) + " 处不是有效的签名函数。"
                  "客户端升级后请重新定位(README「升级怎么办」)";
            sign_ = nullptr;
            free_ = nullptr;
            return false;
        }
        return true;
    }

    bool ready() const { return sign_ != nullptr; }
    std::string version() const { return version_; }
    std::string warn() const { return warn_; }
    std::string dllPath() const { return dllPath_; }
    uint64_t signRva() const { return rva_.sign; }

    // 返回 "名字\r\n值\r\n..." 的签名头串;失败返回空
    std::string sign(const std::string &url, const std::string &headersFlat) {
        if (!sign_) return "";
        std::lock_guard<std::mutex> lk(mu_);  // DLL 内部有全局/TLS 状态,串行调用最稳
#ifdef _MSC_VER
        char *r = callSignRaw(sign_, url.c_str(), headersFlat.c_str());
#else
        // MinGW 无 MSVC 式 __try/__except;调用异常会直接终止进程(签名偏移错时会立刻暴露)
        char *r = sign_(url.c_str(), headersFlat.c_str());
#endif
        if (!r) return "";
        std::string out = r;
        if (free_) free_(r);
        return out;
    }

  private:
    static std::wstring toWide(const std::string &s) {
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(n > 0 ? n - 1 : 0, L'\0');
        if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
        return w;
    }
    static std::string hexStr(uint64_t v) {
        char b[32];
        snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
        return b;
    }
    static std::string readVersion(const std::string &path) {
        DWORD dummy = 0;
        DWORD sz = GetFileVersionInfoSizeW(toWide(path).c_str(), &dummy);
        if (!sz) return "";
        std::vector<char> buf(sz);
        if (!GetFileVersionInfoW(toWide(path).c_str(), 0, sz, buf.data())) return "";
        VS_FIXEDFILEINFO *fi = nullptr;
        UINT len = 0;
        if (!VerQueryValueW(buf.data(), L"\\", (void **)&fi, &len) || !fi) return "";
        char b[64];
        snprintf(b, sizeof b, "%u.%u.%u.%u", HIWORD(fi->dwFileVersionMS), LOWORD(fi->dwFileVersionMS),
                 HIWORD(fi->dwFileVersionLS), LOWORD(fi->dwFileVersionLS));
        return b;
    }
    bool selfTest() {
        const char *probeUrl =
            "https://api.qishui.com/luna/pc/track_v2?aid=386088&app_name=luna_pc&device_id=1";
        const char *probeHdr = "user-agent\r\nLunaPC/3.7.0(452316191)";
        std::string r = sign(probeUrl, probeHdr);
        return r.find("X-") != std::string::npos && r.find("\r\n") != std::string::npos;
    }

    HMODULE mod_ = nullptr;
    SignFn sign_ = nullptr;
    FreeFn free_ = nullptr;
    RvaPair rva_{};
    std::string dllPath_, version_, warn_;
    std::mutex mu_;
};

// ---------------------------------------------------------------- HTTP 服务

struct Config {
    std::string bind = "127.0.0.1";
    int port = 16889;
    std::string dll;
    std::string token;      // 非空则要求 Bearer / X-Auth-Token
    uint64_t signRva = 0;   // 0 = 用版本表
    bool selftestOnly = false;
    bool verbose = false;
};

static std::string httpDate() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char b[64];
    snprintf(b, sizeof b, "%04d-%02d-%02dT%02d:%02d:%02dZ", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
             st.wSecond);
    return b;
}

static std::string respJson(int code, const std::string &body) {
    const char *reason = code == 200 ? "OK" : (code == 400 ? "Bad Request" : (code == 401 ? "Unauthorized" : (code == 404 ? "Not Found" : "Internal Server Error")));
    char head[512];
    snprintf(head, sizeof head,
             "HTTP/1.1 %d %s\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %zu\r\n"
             "Connection: close\r\nServer: mssdk-sign/0.1.0\r\n\r\n",
             code, reason, body.size());
    return std::string(head) + body;
}

static std::string errBody(const std::string &msg) { return "{\"ok\":false,\"error\":\"" + jsonEscape(msg) + "\"}"; }

static bool sendAll(SOCKET s, const std::string &data) {
    size_t sent = 0;
    while (sent < data.size()) {
        int n = send(s, data.data() + sent, (int)(data.size() - sent), 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

// 读一个完整请求(headers + body)
static bool readRequest(SOCKET s, std::string &method, std::string &path, std::string &headersRaw,
                        std::string &body) {
    std::string buf;
    char tmp[4096];
    size_t headEnd = std::string::npos;
    while ((headEnd = buf.find("\r\n\r\n")) == std::string::npos) {
        int n = recv(s, tmp, sizeof tmp, 0);
        if (n <= 0) return false;
        buf.append(tmp, n);
        if (buf.size() > 256 * 1024) return false;
    }
    headersRaw = buf.substr(0, headEnd);
    size_t lineEnd = headersRaw.find("\r\n");
    std::string reqLine = headersRaw.substr(0, lineEnd == std::string::npos ? headersRaw.size() : lineEnd);
    size_t sp1 = reqLine.find(' '), sp2 = reqLine.rfind(' ');
    if (sp1 == std::string::npos || sp2 == std::string::npos || sp2 <= sp1) return false;
    method = reqLine.substr(0, sp1);
    path = reqLine.substr(sp1 + 1, sp2 - sp1 - 1);

    size_t contentLength = 0;
    {
        std::string h = toLower(headersRaw);
        size_t p = h.find("content-length:");
        if (p != std::string::npos) contentLength = (size_t)strtoul(headersRaw.c_str() + p + 15, nullptr, 10);
    }
    if (contentLength > 4 * 1024 * 1024) return false;
    body = buf.substr(headEnd + 4);
    while (body.size() < contentLength) {
        int n = recv(s, tmp, sizeof tmp, 0);
        if (n <= 0) break;
        body.append(tmp, n);
    }
    if (body.size() > contentLength) body.resize(contentLength);
    return true;
}

static bool authorized(const Config &cfg, const std::string &headersRaw) {
    if (cfg.token.empty()) return true;
    std::string h = toLower(headersRaw);
    std::string want = toLower(cfg.token);
    if (h.find("authorization: bearer " + want) != std::string::npos) return true;
    if (h.find("x-auth-token: " + want) != std::string::npos) return true;
    if (h.find("?token=" + want) != std::string::npos) return true;
    return false;
}

static std::string handleSign(Signer &signer, const std::string &body, bool verbose) {
    JVal root;
    json::P p(body);
    if (!p.val(root) || root.t != JVal::Obj) return respJson(400, errBody("请求体不是 JSON 对象"));

    const JVal *jurl = root.get("url");
    if (!jurl || jurl->t != JVal::Str || jurl->s.empty()) return respJson(400, errBody("缺少 url 字段"));

    // 保序收集 headers
    std::vector<std::pair<std::string, std::string>> headers;
    bool hasStub = false;
    if (const JVal *jh = root.get("headers")) {
        if (jh->t != JVal::Obj) return respJson(400, errBody("headers 必须是对象"));
        for (auto &kv : jh->o) {
            if (kv.second.t != JVal::Str) continue;  // 只签名字符串头
            headers.emplace_back(kv.first, kv.second.s);
            if (toLower(kv.first) == "x-ss-stub") hasStub = true;
        }
    }
    if (headers.empty()) return respJson(400, errBody("headers 不能为空(签名覆盖全部请求头,必须传真实要发出的那一份)"));

    // 给了 body 且没带 x-ss-stub → 补上(body 的 MD5 大写),与官方客户端一致
    std::string addedStub;
    if (const JVal *jb = root.get("body")) {
        if (jb->t == JVal::Str && !hasStub) {
            addedStub = md5HexUpper(jb->s);
            headers.emplace_back("x-ss-stub", addedStub);
        }
    }

    std::string flat;
    for (size_t i = 0; i < headers.size(); i++) {
        if (i) flat += "\r\n";
        flat += headers[i].first + "\r\n" + headers[i].second;
    }

    auto t0 = std::chrono::steady_clock::now();
    std::string raw = signer.sign(jurl->s, flat);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();

    if (raw.empty())
        return respJson(500, errBody("签名失败(DLL 未返回内容;检查 headers 是否与将要发出的完全一致)"));

    // 解析 "名字\r\n值\r\n..." 成对
    std::vector<std::string> f;
    {
        size_t b = 0;
        while (b <= raw.size()) {
            size_t e = raw.find("\r\n", b);
            if (e == std::string::npos) { f.push_back(raw.substr(b)); break; }
            f.push_back(raw.substr(b, e - b));
            b = e + 2;
        }
        while (!f.empty() && f.back().empty()) f.pop_back();
    }
    if (f.size() < 2 || (f.size() % 2) != 0) return respJson(500, errBody("DLL 返回格式异常"));

    std::string out = "{\"ok\":true,\"headers\":{";
    for (size_t i = 0; i + 1 < f.size(); i += 2) {
        if (i) out += ",";
        out += "\"" + jsonEscape(f[i]) + "\":\"" + jsonEscape(f[i + 1]) + "\"";
    }
    out += "},\"elapsed_ms\":" + std::to_string(ms);
    if (!addedStub.empty()) out += ",\"added\":{\"x-ss-stub\":\"" + addedStub + "\"}";
    out += "}";
    if (verbose) printf("[sign] %s -> %zu 个签名头, %lldms\n", jurl->s.substr(0, 80).c_str(), f.size() / 2, (long long)ms);
    return respJson(200, out);
}

static void handleConn(SOCKET s, const Config &cfg, Signer &signer) {
    std::string method, path, headersRaw, body;
    if (!readRequest(s, method, path, headersRaw, body)) { closesocket(s); return; }
    std::string route = path;
    size_t q = route.find('?');
    if (q != std::string::npos) route = route.substr(0, q);

    std::string resp;
    if (route == "/healthz") {
        std::string j = "{\"ok\":true,\"service\":\"mssdk-sign\",\"version\":\"0.1.0\",\"signer\":\"" +
                        jsonEscape(signer.dllPath()) + "\",\"dllVersion\":\"" + jsonEscape(signer.version()) +
                        "\",\"signRva\":\"" + [&] {
                            char b[32];
                            snprintf(b, sizeof b, "0x%llx", (unsigned long long)signer.signRva());
                            return std::string(b);
                        }() + "\",\"auth\":" + (cfg.token.empty() ? "false" : "true") + "}";
        resp = respJson(200, j);
    } else if (route == "/config") {
        if (!authorized(cfg, headersRaw)) {
            resp = respJson(401, errBody("缺少或错误的 token"));
        } else {
            resp = respJson(200, "{\"ok\":true,\"signRva\":\"" + std::string("see /healthz") +
                                     "\",\"headersOrder\":\"按请求里的顺序签名,响应里的 headers 需原样发出\"}");
        }
    } else if (route == "/sign") {
        if (method != "POST") resp = respJson(400, errBody("请用 POST /sign"));
        else if (!authorized(cfg, headersRaw)) resp = respJson(401, errBody("缺少或错误的 token"));
        else resp = handleSign(signer, body, cfg.verbose);
    } else if (route == "/") {
        resp = respJson(200, "{\"ok\":true,\"usage\":\"POST /sign {url,headers,body?} | GET /healthz\"}");
    } else {
        resp = respJson(404, errBody("未知路径"));
    }
    sendAll(s, resp);
    closesocket(s);
}

static void printUsage() {
    printf(
        "mssdk-sign —— 汽水音乐 metasec 签名服务\n"
        "用法: mssdk-sign [选项]\n"
        "  --port <n>        监听端口(默认 16889)\n"
        "  --bind <addr>     绑定地址(默认 127.0.0.1;容器内跨机调用用 0.0.0.0)\n"
        "  --dll <path>      metasecml.dll 路径(默认 exe 同目录 metasecml.dll)\n"
        "  --token <t>       启用鉴权(Bearer / X-Auth-Token)\n"
        "  --sign-rva <hex>  手动指定签名函数偏移(默认按 DLL 版本表)\n"
        "  --selftest        只做加载+签名自检后退出\n"
        "  -v                打印每个请求的签名日志\n"
        "接口:\n"
        "  GET  /healthz\n"
        "  POST /sign   {\"url\":\"https://...\",\"body\":\"可选\",\"headers\":{\"user-agent\":\"...\"}}\n"
        "               → {\"ok\":true,\"headers\":{\"X-Helios\":\"...\",\"X-Medusa\":\"...\"}}\n");
}

static std::string exeDir() {
    char b[MAX_PATH];
    DWORD n = GetModuleFileNameA(nullptr, b, MAX_PATH);
    std::string p(b, n);
    size_t s = p.find_last_of("\\/");
    return s == std::string::npos ? "." : p.substr(0, s);
}

int main(int argc, char **argv) {
    Config cfg;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--port") cfg.port = atoi(next().c_str());
        else if (a == "--bind") cfg.bind = next();
        else if (a == "--dll") cfg.dll = next();
        else if (a == "--token") cfg.token = next();
        else if (a == "--sign-rva") cfg.signRva = strtoull(next().c_str(), nullptr, 16);
        else if (a == "--selftest") cfg.selftestOnly = true;
        else if (a == "-v") cfg.verbose = true;
        else if (a == "-h" || a == "--help") { printUsage(); return 0; }
    }
    if (cfg.dll.empty()) cfg.dll = exeDir() + "\\metasecml.dll";

    // MD5 自检(防止 x-ss-stub 算错)
    if (md5HexUpper("abc") != "900150983CD24FB0D6963F7D28E17F72") {
        fprintf(stderr, "MD5 自检失败,拒绝启动\n");
        return 2;
    }

    Signer signer;
    std::string err;
    if (!signer.load(cfg.dll, cfg.signRva, err)) {
        fprintf(stderr, "签名器加载失败: %s\n", err.c_str());
        return 3;
    }
    if (!signer.warn().empty()) fprintf(stderr, "警告: %s\n", signer.warn().c_str());
    printf("签名器就绪: %s (DLL 版本 %s, 签名偏移 0x%llx)\n", cfg.dll.c_str(),
           signer.version().empty() ? "未知" : signer.version().c_str(), (unsigned long long)signer.signRva());
    if (cfg.selftestOnly) {
        printf("自检通过。\n");
        return 0;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup 失败\n");
        return 4;
    }
    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) {
        fprintf(stderr, "socket 失败\n");
        return 4;
    }
    BOOL yes = TRUE;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof yes);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)cfg.port);
    inet_pton(AF_INET, cfg.bind.c_str(), &addr.sin_addr);
    if (bind(srv, (sockaddr *)&addr, sizeof addr) != 0 || listen(srv, 32) != 0) {
        fprintf(stderr, "bind/listen %s:%d 失败(错误码 %d)\n", cfg.bind.c_str(), cfg.port, WSAGetLastError());
        return 4;
    }
    printf("监听 http://%s:%d  (/healthz, POST /sign)%s\n", cfg.bind.c_str(), cfg.port,
           cfg.token.empty() ? "" : " [已启用 token 鉴权]");
    fflush(stdout);

    for (;;) {
        SOCKET c = accept(srv, nullptr, nullptr);
        if (c == INVALID_SOCKET) continue;
        DWORD tv = 15000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
        std::thread(handleConn, c, std::cref(cfg), std::ref(signer)).detach();
    }
    return 0;
}
