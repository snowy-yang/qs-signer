// qs-login —— 汽水音乐「本机客户端登录」导入工具(单文件 C++,原 qs-local-login.mjs)
//
// 做什么:官方 SodaMusic PC 客户端是 Chromium,登录态存在本机
//   %APPDATA%\SodaMusic\Network\Cookies(SQLite),设备身份在 %APPDATA%\SodaMusic\DeviceV1
//   (gzip JSON,含 did/iid)。本工具读出来 → 可选用 metasecml.dll 签名调 /luna/pc/me 校验
//   → 写入 MusicServer 的 data/auth.json 的 qs 字段,免扫码登录。
//
// 用法:
//   qs-login.exe                    # 读取 + 校验 + 写入 ../MusicServer/data/auth.json
//   qs-login.exe --print            # 只打印 sessionid,不落盘
//   qs-login.exe --no-verify        # 跳过 /luna/pc/me 校验
//   qs-login.exe --dir <目录>       # 客户端数据目录(默认 %APPDATA%\SodaMusic,或 QS_SODA_DATA_DIR)
//   qs-login.exe --auth <文件>      # auth.json 路径(默认 ../MusicServer/data/auth.json,或 QS_AUTH_FILE)
//   qs-login.exe --dll <path>       # metasecml.dll(校验签名用;默认 exe 同目录,缺了就跳过校验)
//
// 实现说明(无第三方依赖):
//   * gzip/DEFLATE 解压自带(RFC 1951/1952),用于 DeviceV1
//   * SQLite 读取:优先系统 winsqlite3.dll(Win10+ 自带,支持 WAL);不可用时回退内置只读
//     解析器(不处理 WAL,客户端开着时可能读到旧数据,建议退出客户端后再跑)
//   * cookie 值优先读 value 列;为空时回退解密 encrypted_value(Chromium v10/v11:
//     Local State 里的 key(DPAPI 解出)+ AES-256-GCM;v20 app-bound 无法离线解密,会明确报错)
//   * 签名校验直接调 metasecml.dll(调用 ABI 与 mssdk-sign 一致,见其 REVERSE.md),HTTPS 走 WinHTTP
//
// 构建(任选其一):
//   Windows/MSVC : build.bat
//   Linux/MinGW  : x86_64-w64-mingw32-g++ -std=c++17 -O2 -static -static-libgcc -static-libstdc++ \
//                    -o qs-login.exe qs-login.cpp -lwinhttp -lbcrypt -lcrypt32 -lversion

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winver.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")
#endif

// ---------------------------------------------------------------- 基础工具(路径一律按 UTF-8 存,文件 API 内部转宽字符)

static std::wstring toWide(const std::string &s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n > 0 ? n - 1 : 0, L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}
static std::string fromWide(const std::wstring &w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(n > 0 ? n - 1 : 0, '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
    return s;
}
static std::string envUtf8(const wchar_t *name) {
    const wchar_t *v = _wgetenv(name);
    return v ? fromWide(v) : "";
}

static bool readFile(const std::string &path, std::string &out) {
    HANDLE f = CreateFileW(toWide(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    out.clear();
    char buf[65536];
    DWORD n = 0;
    while (ReadFile(f, buf, sizeof buf, &n, nullptr) && n) out.append(buf, n);
    CloseHandle(f);
    return true;
}
static bool writeFile(const std::string &path, const std::string &data) {
    HANDLE f = CreateFileW(toWide(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    BOOL ok = WriteFile(f, data.data(), (DWORD)data.size(), &w, nullptr) && w == data.size();
    CloseHandle(f);
    return ok;
}
static bool fileExists(const std::string &path) {
    DWORD a = GetFileAttributesW(toWide(path).c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}
static std::string exeDir() {
    wchar_t b[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, b, MAX_PATH);
    std::wstring p(b, n);
    size_t s = p.find_last_of(L"\\/");
    return s == std::wstring::npos ? "." : fromWide(p.substr(0, s));
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
                } else o += (char)c;
        }
    }
    return o;
}

static void die(const std::string &msg) {
    fflush(stdout);  // 管道/重定向时 stderr 不排队,先刷掉已打印的信息行
    fprintf(stderr, "✗ %s\n", msg.c_str());
    exit(1);
}

// ---------------------------------------------------------------- 极简 JSON(解析 + 2 空格缩进序列化,保持对象键序)

struct JVal {
    enum T { Nul, Bool, Num, Str, Arr, Obj } t = Nul;
    std::string s;                                // Str / Num / Bool 的原始文本
    std::vector<JVal> a;                          // Arr
    std::vector<std::pair<std::string, JVal>> o;  // Obj(保序)
    const JVal *get(const std::string &k) const {
        for (auto &kv : o)
            if (kv.first == k) return &kv.second;
        return nullptr;
    }
    JVal *get(const std::string &k) {
        for (auto &kv : o)
            if (kv.first == k) return &kv.second;
        return nullptr;
    }
    void set(const std::string &k, const std::string &v) {  // 已有键原位覆盖,新键追加(保持键序)
        if (JVal *e = get(k)) { e->t = Str; e->s = v; return; }
        JVal nv; nv.t = Str; nv.s = v;
        o.emplace_back(k, std::move(nv));
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

// JSON.stringify(v, null, 2) 风格;数字/布尔保留原文,不重排键
static void jserialize(const JVal &v, std::string &out, int depth) {
    auto pad = [&](int d) { out.append((size_t)d * 2, ' '); };
    switch (v.t) {
        case JVal::Nul: out += "null"; break;
        case JVal::Bool:
        case JVal::Num: out += v.s; break;
        case JVal::Str: out += '"'; out += jsonEscape(v.s); out += '"'; break;
        case JVal::Arr:
            if (v.a.empty()) { out += "[]"; break; }
            out += "[\n";
            for (size_t i = 0; i < v.a.size(); i++) {
                pad(depth + 1);
                jserialize(v.a[i], out, depth + 1);
                out += (i + 1 < v.a.size()) ? ",\n" : "\n";
            }
            pad(depth);
            out += "]";
            break;
        case JVal::Obj:
            if (v.o.empty()) { out += "{}"; break; }
            out += "{\n";
            for (size_t i = 0; i < v.o.size(); i++) {
                pad(depth + 1);
                out += '"'; out += jsonEscape(v.o[i].first); out += "\": ";
                jserialize(v.o[i].second, out, depth + 1);
                out += (i + 1 < v.o.size()) ? ",\n" : "\n";
            }
            pad(depth);
            out += "}";
            break;
    }
}
static std::string jpretty(const JVal &v) {
    std::string out;
    jserialize(v, out, 0);
    return out;
}

// ---------------------------------------------------------------- gzip / DEFLATE 解压(RFC 1951/1952)

namespace gz {

struct BitReader {
    const uint8_t *d;
    size_t n, pos = 0;
    uint32_t bits = 0;
    int cnt = 0;
    bool err = false;
    int getBit() {
        if (!cnt) {
            if (pos >= n) { err = true; return 0; }
            bits = d[pos++];
            cnt = 8;
        }
        int b = bits & 1;
        bits >>= 1;
        cnt--;
        return b;
    }
    uint32_t getBits(int k) {
        uint32_t v = 0;
        for (int i = 0; i < k; i++) v |= (uint32_t)getBit() << i;
        return v;
    }
};

struct Huff {
    uint16_t count[16] = {0};
    uint16_t symbol[320];
    bool build(const uint8_t *lengths, int n) {
        for (int i = 0; i < 16; i++) count[i] = 0;
        for (int i = 0; i < n; i++) count[lengths[i]]++;
        int left = 1;
        for (int len = 1; len < 16; len++) {
            left <<= 1;
            left -= count[len];
            if (left < 0) return false;  // 过订阅
        }
        uint16_t offs[16];
        offs[1] = 0;
        for (int len = 1; len < 15; len++) offs[len + 1] = offs[len] + count[len];
        for (int i = 0; i < n; i++)
            if (lengths[i]) symbol[offs[lengths[i]]++] = (uint16_t)i;
        return true;
    }
    int decode(BitReader &br) const {
        int code = 0, first = 0, index = 0;
        for (int len = 1; len < 16; len++) {
            code |= br.getBit();
            int cnt = count[len];
            if (code - first < cnt) return symbol[index + (code - first)];
            index += cnt;
            first = (first + cnt) << 1;
            code <<= 1;
        }
        return -1;
    }
};

static const uint16_t LBASE[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                   35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const uint8_t LEXT[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t DBASE[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                                   257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t DEXT[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
static const int CLCIDX[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

static bool inflateRaw(const uint8_t *d, size_t n, std::string &out) {
    BitReader br{d, n};
    Huff lt, dt;
    for (;;) {
        int final = br.getBit();
        int type = (int)br.getBits(2);
        if (br.err) return false;
        if (type == 0) {  // stored:对齐到字节边界 + LEN/NLEN
            br.cnt = 0;
            if (br.pos + 4 > br.n) return false;
            uint16_t len = (uint16_t)(br.d[br.pos] | (br.d[br.pos + 1] << 8));
            uint16_t nlen = (uint16_t)(br.d[br.pos + 2] | (br.d[br.pos + 3] << 8));
            br.pos += 4;
            if ((uint16_t)~nlen != len || br.pos + len > br.n) return false;
            out.append((const char *)br.d + br.pos, len);
            br.pos += len;
        } else if (type == 1 || type == 2) {
            if (type == 1) {
                uint8_t ll[288], dl[30];
                for (int i = 0; i < 144; i++) ll[i] = 8;
                for (int i = 144; i < 256; i++) ll[i] = 9;
                for (int i = 256; i < 280; i++) ll[i] = 7;
                for (int i = 280; i < 288; i++) ll[i] = 8;
                for (int i = 0; i < 30; i++) dl[i] = 5;
                if (!lt.build(ll, 288) || !dt.build(dl, 30)) return false;
            } else {
                int hlit = (int)br.getBits(5) + 257;
                int hdist = (int)br.getBits(5) + 1;
                int hclen = (int)br.getBits(4) + 4;
                if (hlit > 286 || hdist > 30) return false;
                uint8_t cl[19] = {0};
                for (int i = 0; i < hclen; i++) cl[CLCIDX[i]] = (uint8_t)br.getBits(3);
                Huff clh;
                if (!clh.build(cl, 19)) return false;
                uint8_t lens[288 + 32] = {0};
                int i = 0;
                while (i < hlit + hdist) {
                    int sym = clh.decode(br);
                    if (br.err || sym < 0) return false;
                    if (sym < 16) lens[i++] = (uint8_t)sym;
                    else if (sym == 16) {
                        if (!i) return false;
                        uint8_t prev = lens[i - 1];
                        for (int r = 3 + (int)br.getBits(2); r-- && i < hlit + hdist;) lens[i++] = prev;
                    } else if (sym == 17) {
                        for (int r = 3 + (int)br.getBits(3); r-- && i < hlit + hdist;) lens[i++] = 0;
                    } else {
                        for (int r = 11 + (int)br.getBits(7); r-- && i < hlit + hdist;) lens[i++] = 0;
                    }
                }
                if (!lt.build(lens, hlit) || !dt.build(lens + hlit, hdist)) return false;
            }
            for (;;) {
                int sym = lt.decode(br);
                if (br.err || sym < 0) return false;
                if (sym < 256) {
                    out += (char)sym;
                } else if (sym == 256) {
                    break;
                } else {
                    int li = sym - 257;
                    if (li >= 29) return false;
                    size_t len = LBASE[li] + br.getBits(LEXT[li]);
                    int ds = dt.decode(br);
                    if (br.err || ds < 0 || ds >= 30) return false;
                    size_t dist = DBASE[ds] + br.getBits(DEXT[ds]);
                    if (dist > out.size()) return false;
                    size_t start = out.size() - dist;
                    for (size_t k = 0; k < len; k++) out += out[start + k];
                }
            }
        } else {
            return false;
        }
        if (br.err) return false;
        if (final) return true;
    }
}

static uint32_t crc32b(const uint8_t *d, size_t n) {
    uint32_t c = 0xFFFFFFFF;
    for (size_t i = 0; i < n; i++) {
        c ^= d[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320 & (uint32_t)(-(int32_t)(c & 1)));
    }
    return ~c;
}

// 完整 gzip 流(带 CRC32/长度校验)
static bool gunzip(const std::string &raw, std::string &out) {
    if (raw.size() < 18 || (uint8_t)raw[0] != 0x1f || (uint8_t)raw[1] != 0x8b || (uint8_t)raw[2] != 8) return false;
    uint8_t flg = (uint8_t)raw[3];
    size_t p = 10;
    auto skipZ = [&]() { while (p < raw.size() && raw[p]) p++; p++; };
    if (flg & 4) {
        if (p + 2 > raw.size()) return false;
        p += 2 + (uint8_t)raw[p] + ((uint8_t)raw[p + 1] << 8);
    }
    if (flg & 8) skipZ();
    if (flg & 16) skipZ();
    if (flg & 2) p += 2;
    if (p + 8 >= raw.size()) return false;
    out.clear();
    if (!inflateRaw((const uint8_t *)raw.data() + p, raw.size() - 8 - p, out)) return false;
    size_t t = raw.size() - 8;
    uint32_t crc = (uint8_t)raw[t] | ((uint8_t)raw[t + 1] << 8) | ((uint32_t)(uint8_t)raw[t + 2] << 16) | ((uint32_t)(uint8_t)raw[t + 3] << 24);
    uint32_t isz = (uint8_t)raw[t + 4] | ((uint8_t)raw[t + 5] << 8) | ((uint32_t)(uint8_t)raw[t + 6] << 16) | ((uint32_t)(uint8_t)raw[t + 7] << 24);
    if (crc32b((const uint8_t *)out.data(), out.size()) != crc || (uint32_t)(out.size() & 0xFFFFFFFF) != isz) return false;
    return true;
}

}  // namespace gz

// ---------------------------------------------------------------- SQLite 读取

struct CookieRow {
    std::string host, name, value, encrypted;
};

// ---- 途径一:系统 winsqlite3.dll(Win10+ 自带;支持 WAL/锁;Wine 下通常没有 → 回退内置解析器)

namespace winsqlite {
struct Api {
    HMODULE h = nullptr;
    int (__cdecl *open_v2)(const char *, void **, int, const char *) = nullptr;
    int (__cdecl *busy_timeout)(void *, int) = nullptr;
    int (__cdecl *prepare_v2)(void *, const char *, int, void **, const char **) = nullptr;
    int (__cdecl *step)(void *) = nullptr;
    const unsigned char *(__cdecl *column_text)(void *, int) = nullptr;
    const void *(__cdecl *column_blob)(void *, int) = nullptr;
    int (__cdecl *column_bytes)(void *, int) = nullptr;
    int (__cdecl *finalize)(void *) = nullptr;
    int (__cdecl *close)(void *) = nullptr;
    const char *(__cdecl *errmsg)(void *) = nullptr;
    bool ok() const { return h != nullptr; }
};
static Api load() {
    Api a;
    a.h = LoadLibraryW(L"winsqlite3.dll");
    if (!a.h) return a;
#define GET(var, name) a.var = (decltype(a.var))(void *)GetProcAddress(a.h, name)
    GET(open_v2, "sqlite3_open_v2");
    GET(busy_timeout, "sqlite3_busy_timeout");
    GET(prepare_v2, "sqlite3_prepare_v2");
    GET(step, "sqlite3_step");
    GET(column_text, "sqlite3_column_text");
    GET(column_blob, "sqlite3_column_blob");
    GET(column_bytes, "sqlite3_column_bytes");
    GET(finalize, "sqlite3_finalize");
    GET(close, "sqlite3_close");
    GET(errmsg, "sqlite3_errmsg");
#undef GET
    if (!a.open_v2 || !a.prepare_v2 || !a.step || !a.column_text || !a.column_blob || !a.column_bytes ||
        !a.finalize || !a.close)
        a.h = nullptr;
    return a;
}

// 返回值:0 查到了(或不为空也继续找)、1 正常结束无行,2 忙/锁,3 其他错误
static int querySessionId(const Api &a, const std::string &dbPath, CookieRow &out, std::string &err) {
    void *db = nullptr;
    if (a.open_v2(dbPath.c_str(), &db, 0x1 /*READONLY*/, nullptr) != 0 || !db) {
        err = "sqlite3_open_v2 失败";
        return 3;
    }
    if (a.busy_timeout) a.busy_timeout(db, 3000);
    int rc = 3;
    void *st = nullptr;
    static const char *SQL =
        "SELECT host_key,name,value,encrypted_value FROM cookies "
        "WHERE host_key IN ('.qishui.com','qishui.com') AND name='sessionid' LIMIT 1";
    if (a.prepare_v2(db, SQL, -1, &st, nullptr) != 0) {
        err = std::string("prepare 失败: ") + (a.errmsg ? a.errmsg(db) : "?");
        a.close(db);
        return 3;
    }
    for (;;) {
        int r = a.step(st);
        if (r == 100 /*ROW*/) {
            const unsigned char *host = a.column_text(st, 0);
            const unsigned char *name = a.column_text(st, 1);
            const unsigned char *val = a.column_text(st, 2);
            out.host = host ? (const char *)host : "";
            out.name = name ? (const char *)name : "";
            out.value = val ? (const char *)val : "";
            const void *eb = a.column_blob(st, 3);
            int en = a.column_bytes(st, 3);
            if (eb && en > 0) out.encrypted.assign((const char *)eb, (size_t)en);
            rc = 0;
            break;
        }
        if (r == 101 /*DONE*/) { rc = 1; break; }
        if (r == 5 /*BUSY*/ || r == 6 /*LOCKED*/) {
            err = a.errmsg ? a.errmsg(db) : "busy";
            rc = 2;
            break;
        }
        err = std::string("step 失败: ") + (a.errmsg ? a.errmsg(db) : "?");
        rc = 3;
        break;
    }
    if (st) a.finalize(st);
    a.close(db);
    return rc;
}
}  // namespace winsqlite

// ---- 途径二:内置只读 SQLite 文件解析器(不依赖任何 DLL;不处理 WAL)

namespace lite {

class Db {
  public:
    bool open(std::string bytes, std::string &err) {
        d_ = std::move(bytes);
        if (d_.size() < 100 || d_.compare(0, 15, "SQLite format 3") != 0) {
            err = "不是 SQLite 数据库文件";
            return false;
        }
        ps_ = be16(16);
        if (ps_ == 1) ps_ = 65536;
        if (ps_ < 512 || ps_ > 65536 || (ps_ & (ps_ - 1)) != 0) {
            err = "非法 page size";
            return false;
        }
        usable_ = ps_ - (uint8_t)d_[20];
        if (be32(56) != 1) {
            err = "仅支持 UTF-8 编码的 SQLite 文件";
            return false;
        }
        return true;
    }

    // 遍历表 b-tree;fn 拿到 (rowid, 解好的记录字段)
    bool walkTable(uint32_t page, const std::function<void(uint64_t, std::vector<std::string> &, std::vector<bool> &)> &fn,
                   std::string &err, int depth = 0) {
        if (depth > 32 || page == 0) {
            err = "页号非法(文件损坏?)";
            return false;
        }
        size_t base = (size_t)(page - 1) * ps_;
        size_t hdr = base + (page == 1 ? 100 : 0);
        if (hdr + 12 > d_.size()) {
            err = "页越界(文件损坏?)";
            return false;
        }
        uint8_t type = (uint8_t)d_[hdr];
        uint16_t ncell = be16(hdr + 3);
        if (type != 5 && type != 13) {
            err = "不是表 b-tree 页";
            return false;
        }
        size_t ptrArr = hdr + (type == 5 ? 12 : 8);
        for (uint16_t i = 0; i < ncell; i++) {
            if (ptrArr + 2 * (size_t)i + 2 > d_.size()) {
                err = "cell 指针越界";
                return false;
            }
            size_t cell = base + be16(ptrArr + 2 * (size_t)i);
            if (cell >= d_.size()) {
                err = "cell 越界";
                return false;
            }
            if (type == 13) {  // leaf: payloadLen varint, rowid varint, payload(+溢出)
                size_t p = cell;
                uint64_t plen = varint(p);
                uint64_t rowid = varint(p);
                std::string payload;
                if (!readPayload(p, plen, payload, err)) return false;
                std::vector<std::string> fields;
                std::vector<bool> nulls;
                if (!parseRecord(payload, fields, nulls, err)) return false;
                fn(rowid, fields, nulls);
            } else {  // interior: 4 字节左子页 + rowid varint
                uint32_t child = be32(cell);
                if (!walkTable(child, fn, err, depth + 1)) return false;
            }
        }
        if (type == 5) {  // 右子指针
            uint32_t right = be32(hdr + 8);
            if (right && !walkTable(right, fn, err, depth + 1)) return false;
        }
        return true;
    }

    uint32_t pageSize() const { return ps_; }

  private:
    uint16_t be16(size_t o) const { return (uint16_t)(((uint8_t)d_[o] << 8) | (uint8_t)d_[o + 1]); }
    uint32_t be32(size_t o) const {
        return ((uint32_t)(uint8_t)d_[o] << 24) | ((uint32_t)(uint8_t)d_[o + 1] << 16) |
               ((uint32_t)(uint8_t)d_[o + 2] << 8) | (uint32_t)(uint8_t)d_[o + 3];
    }
    uint64_t varint(size_t &p) const {
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) {
            if (p >= d_.size()) return v;
            uint8_t b = (uint8_t)d_[p++];
            v = (v << 7) | (b & 0x7f);
            if (!(b & 0x80)) return v;
        }
        if (p < d_.size()) v = (v << 8) | (uint8_t)d_[p++];
        return v;
    }
    bool readPayload(size_t content, uint64_t plen, std::string &out, std::string &err) {
        uint32_t X = usable_ - 35;
        if (plen <= X) {
            if (content + plen > d_.size()) {
                err = "payload 越界";
                return false;
            }
            out.assign(d_, content, (size_t)plen);
            return true;
        }
        uint32_t M = ((usable_ - 12) * 32) / 255 - 23;
        uint32_t K = M + (uint32_t)((plen - M) % (usable_ - 4));
        uint32_t local = (K <= X) ? K : M;
        if (content + local + 4 > d_.size()) {
            err = "payload 越界";
            return false;
        }
        out.assign(d_, content, local);
        uint32_t ovf = be32(content + local);
        uint64_t remain = plen - local;
        int guard = 0;
        while (remain && ovf) {
            if (++guard > 100000 || (size_t)(ovf - 1) * ps_ + 4 > d_.size()) {
                err = "溢出页链异常";
                return false;
            }
            size_t oo = (size_t)(ovf - 1) * ps_;
            uint32_t next = be32(oo);
            uint32_t take = (uint32_t)std::min<uint64_t>(remain, usable_ - 4);
            out.append(d_, oo + 4, take);
            remain -= take;
            ovf = next;
        }
        return remain == 0;
    }
    static bool parseRecord(const std::string &rec, std::vector<std::string> &fields, std::vector<bool> &nulls,
                            std::string &err) {
        size_t p = 0;
        auto rv = [&]() -> uint64_t {  // record 内 varint(小,直接展开)
            uint64_t v = 0;
            for (int i = 0; i < 9 && p < rec.size(); i++) {
                uint8_t b = (uint8_t)rec[p++];
                v = (v << 7) | (b & 0x7f);
                if (!(b & 0x80)) return v;
            }
            return v;
        };
        uint64_t hsz = rv();
        size_t hend = hsz;  // header 长度含自身 varint,从记录起点算
        if (hend > rec.size()) {
            err = "record header 非法";
            return false;
        }
        std::vector<uint64_t> types;
        while (p < hend) types.push_back(rv());
        if (p != hend) {
            err = "record header 非法";
            return false;
        }
        for (uint64_t t : types) {
            int sz;
            bool isNull;
            if (t == 0) { sz = 0; isNull = true; }
            else if (t >= 1 && t <= 4) { sz = (int)t; isNull = false; }
            else if (t == 5) { sz = 6; isNull = false; }
            else if (t == 6 || t == 7) { sz = 8; isNull = false; }
            else if (t == 8 || t == 9) { sz = 0; isNull = false; }
            else if (t >= 12 && (t & 1) == 0) { sz = (int)((t - 12) / 2); isNull = false; }  // blob
            else if (t >= 13) { sz = (int)((t - 13) / 2); isNull = false; }                  // text
            else {
                err = "保留 serial type";
                return false;
            }
            if (p + sz > rec.size()) {
                err = "record 值越界";
                return false;
            }
            nulls.push_back(isNull);
            if (isNull) {
                fields.emplace_back();
            } else if (t == 1 || t == 2 || t == 3 || t == 4 || t == 5 || t == 6) {
                // 大端有符号整数 → 十进制文本
                int64_t v = 0;
                bool neg = ((uint8_t)rec[p]) & 0x80;
                for (int i = 0; i < sz; i++) v = (v << 8) | (uint8_t)rec[p + i];
                if (neg && sz < 8) v -= ((int64_t)1 << (sz * 8));
                char b[32];
                snprintf(b, sizeof b, "%lld", (long long)v);
                fields.emplace_back(b);
            } else if (t == 8) {
                fields.emplace_back("0");
            } else if (t == 9) {
                fields.emplace_back("1");
            } else {
                fields.emplace_back(rec, p, (size_t)sz);
            }
            p += (size_t)sz;
        }
        return true;
    }

    std::string d_;
    uint32_t ps_ = 0, usable_ = 0;
};

// 从 CREATE TABLE sql 提取列名(顶层逗号分段取首 token,剥引号)
static std::vector<std::string> columnNames(const std::string &sql) {
    size_t lp = sql.find('(');
    size_t rp = sql.rfind(')');
    std::vector<std::string> out;
    if (lp == std::string::npos || rp == std::string::npos || rp <= lp) return out;
    int depth = 0;
    std::string seg;
    auto pushSeg = [&]() {
        std::string t = trim(seg);
        seg.clear();
        if (t.empty()) return;
        size_t e = t.find_first_of(" \t\r\n");
        std::string name = e == std::string::npos ? t : t.substr(0, e);
        if (!name.empty() && (name[0] == '"' || name[0] == '`' || name[0] == '[')) {
            char q = name[0] == '[' ? ']' : name[0];
            name = name.substr(1);
            size_t qe = name.find(q);
            if (qe != std::string::npos) name.resize(qe);
        }
        if (!name.empty()) out.push_back(name);
    };
    for (size_t i = lp + 1; i < rp; i++) {
        char c = sql[i];
        if (c == '(') depth++;
        if (c == ')') depth--;
        if (c == ',' && depth == 0) {
            pushSeg();
            continue;
        }
        seg += c;
    }
    pushSeg();
    return out;
}

static bool querySessionId(const std::string &dbFile, CookieRow &out, std::string &err) {
    std::string bytes;
    if (!readFile(dbFile, bytes)) {
        err = "读取数据库文件失败";
        return false;
    }
    Db db;
    if (!db.open(std::move(bytes), err)) return false;

    // 页 1 = sqlite_master:列 (type,name,tbl_name,rootpage,sql),找 cookies 表
    uint32_t root = 0;
    std::string cookiesSql;
    std::string walkErr;
    db.walkTable(1, [&](uint64_t, std::vector<std::string> &f, std::vector<bool> &isNull) {
        if (root || f.size() < 5 || isNull.size() < 5) return;
        if (f[0] == "table" && f[1] == "cookies") {
            root = (uint32_t)strtoul(f[3].c_str(), nullptr, 10);
            cookiesSql = f[4];
        }
    }, walkErr);
    if (!walkErr.empty()) {
        err = walkErr;
        return false;
    }
    if (!root) {
        err = "cookie 库里没有 cookies 表(客户端数据目录不对?)";
        return false;
    }
    std::vector<std::string> cols = columnNames(cookiesSql);
    int iHost = -1, iName = -1, iValue = -1, iEnc = -1;
    for (size_t i = 0; i < cols.size(); i++) {
        if (cols[i] == "host_key") iHost = (int)i;
        else if (cols[i] == "name") iName = (int)i;
        else if (cols[i] == "value") iValue = (int)i;
        else if (cols[i] == "encrypted_value") iEnc = (int)i;
    }
    if (iHost < 0 || iName < 0 || iValue < 0) {
        err = "cookies 表结构异常(找不到 host_key/name/value 列)";
        return false;
    }
    bool found = false;
    db.walkTable(root, [&](uint64_t, std::vector<std::string> &f, std::vector<bool> &isNull) {
        if (found || (size_t)iHost >= f.size() || (size_t)iName >= f.size()) return;
        if (f[iHost] != ".qishui.com" && f[iHost] != "qishui.com") return;
        if (f[iName] != "sessionid") return;
        out.host = f[iHost];
        out.name = f[iName];
        out.value = ((size_t)iValue < f.size() && !(isNull.size() > (size_t)iValue && isNull[iValue])) ? f[iValue] : "";
        if (iEnc >= 0 && (size_t)iEnc < f.size() && !(isNull.size() > (size_t)iEnc && isNull[iEnc])) out.encrypted = f[iEnc];
        found = true;
    }, walkErr);
    if (!walkErr.empty()) {
        err = walkErr;
        return false;
    }
    return found;  // false = 没有该行(未登录)
}

}  // namespace lite

// ---------------------------------------------------------------- Chromium encrypted_value 解密回退
//   v10/v11: "v10" + 12 字节 nonce + 密文 + 16 字节 GCM tag,key 来自 Local State 的
//   os_crypt.encrypted_key(base64,去 "DPAPI" 前缀后 CryptUnprotectData,32 字节)
//   v20(app-bound):离线不可解,明确报错。老格式:整块直接 DPAPI。

static bool chromiumDecrypt(const std::string &enc, const std::string &dataDir, std::string &out, std::string &err) {
    if (enc.empty()) {
        err = "encrypted_value 为空";
        return false;
    }
    std::string prefix = enc.substr(0, enc.size() >= 3 ? 3 : enc.size());
    if (prefix != "v10" && prefix != "v11" && prefix != "v20") {
        // 老格式:直接 DPAPI
        DATA_BLOB in{}, dout{};
        in.pbData = (BYTE *)enc.data();
        in.cbData = (DWORD)enc.size();
        if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &dout)) {
            err = "CryptUnprotectData 失败(错误码 " + std::to_string(GetLastError()) + ")";
            return false;
        }
        out.assign((const char *)dout.pbData, dout.cbData);
        LocalFree(dout.pbData);
        return true;
    }
    if (prefix == "v20") {
        err = "cookie 使用 app-bound 加密(v20),离线无法解密;请在客户端开着的状态下改用官方接口导出,或联系工具更新";
        return false;
    }
    // Local State → key
    std::string ls;
    if (!readFile(dataDir + "\\Local State", ls)) {
        err = "读不到 " + dataDir + "\\Local State(解密 cookie 需要)";
        return false;
    }
    JVal root;
    json::P jp(ls);
    if (!jp.val(root) || root.t != JVal::Obj) {
        err = "Local State 不是合法 JSON";
        return false;
    }
    const JVal *oc = root.get("os_crypt");
    const JVal *ek = oc ? oc->get("encrypted_key") : nullptr;
    if (!ek || ek->t != JVal::Str) {
        err = "Local State 里没有 os_crypt.encrypted_key";
        return false;
    }
    BYTE keybuf[512];
    DWORD keylen = sizeof keybuf;
    if (!CryptStringToBinaryA(ek->s.c_str(), 0, CRYPT_STRING_BASE64, keybuf, &keylen, nullptr, nullptr) ||
        keylen < 6 || memcmp(keybuf, "DPAPI", 5) != 0) {
        err = "encrypted_key 格式异常";
        return false;
    }
    DATA_BLOB kin{}, kout{};
    kin.pbData = keybuf + 5;
    kin.cbData = keylen - 5;
    if (!CryptUnprotectData(&kin, nullptr, nullptr, nullptr, nullptr, 0, &kout) || kout.cbData != 32) {
        err = "解密 cookie key 失败(DPAPI,错误码 " + std::to_string(GetLastError()) + ")";
        return false;
    }
    // AES-256-GCM:v10 + nonce(12) + ct + tag(16)
    if (enc.size() < 3 + 12 + 16) {
        LocalFree(kout.pbData);
        err = "encrypted_value 太短";
        return false;
    }
    const BYTE *nonce = (const BYTE *)enc.data() + 3;
    const BYTE *ct = (const BYTE *)enc.data() + 3 + 12;
    DWORD ctLen = (DWORD)(enc.size() - 3 - 12 - 16);
    const BYTE *tag = (const BYTE *)enc.data() + enc.size() - 16;

    NTSTATUS st;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE kh = nullptr;
    std::string plain;
    bool ok = false;
    if ((st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0)) == 0) {
        if ((st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                    sizeof(BCRYPT_CHAIN_MODE_GCM), 0)) == 0) {
            if ((st = BCryptGenerateSymmetricKey(alg, &kh, nullptr, 0, kout.pbData, 32, 0)) == 0) {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
                RtlZeroMemory(&ai, sizeof ai);
                ai.cbSize = sizeof ai;
                ai.dwInfoVersion = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION;
                ai.pbNonce = (PUCHAR)nonce;
                ai.cbNonce = 12;
                ai.pbTag = (PUCHAR)tag;
                ai.cbTag = 16;
                plain.resize(ctLen + 16);
                DWORD plen = 0;
                if ((st = BCryptDecrypt(kh, (PUCHAR)ct, ctLen, &ai, nullptr, 0, (PUCHAR)plain.data(),
                                        (DWORD)plain.size(), &plen, 0)) == 0) {
                    plain.resize(plen);
                    out = plain;
                    ok = true;
                } else {
                    err = "AES-GCM 解密失败(tag 不匹配 = key 不对或数据损坏)";
                }
                BCryptDestroyKey(kh);
            } else {
                err = "BCryptGenerateSymmetricKey 失败";
            }
        } else {
            err = "BCryptSetAlgorithmProperty 失败";
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    } else {
        err = "BCryptOpenAlgorithmProvider 失败";
    }
    LocalFree(kout.pbData);
    return ok;
}

// ---------------------------------------------------------------- 签名器(与 mssdk-sign 同一 ABI,代码保持一致)

typedef char *(*SignFn)(const char *, const char *);
typedef void (*FreeFn)(void *);

#ifdef _MSC_VER
// SEH 必须放在不含 C++ 析构对象的函数里(否则 MSVC 报 C2712)
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
        if (rvaOverride) use = {rvaOverride, rvaOverride + (DEFAULT_RVA.freefn - DEFAULT_RVA.sign)};
        sign_ = (SignFn)((uint8_t *)mod_ + use.sign);
        free_ = (FreeFn)((uint8_t *)mod_ + use.freefn);
        if (!selfTest()) {
            char b[256];
            snprintf(b, sizeof b, "签名自检失败:偏移 %#llx 处不是有效的签名函数", (unsigned long long)use.sign);
            err = b;
            sign_ = nullptr;
            free_ = nullptr;
            return false;
        }
        return true;
    }
    bool ready() const { return sign_ != nullptr; }
    std::string version() const { return version_; }
    std::string sign(const std::string &url, const std::string &headersFlat) {
        if (!sign_) return "";
        std::lock_guard<std::mutex> lk(mu_);
#ifdef _MSC_VER
        char *r = callSignRaw(sign_, url.c_str(), headersFlat.c_str());
#else
        char *r = sign_(url.c_str(), headersFlat.c_str());
#endif
        if (!r) return "";
        std::string out = r;
        if (free_) free_(r);
        return out;
    }

  private:
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
    std::mutex mu_;
    std::string version_;
};

// ---------------------------------------------------------------- HTTPS(WinHTTP)

struct HttpResult {
    int status = 0;
    std::string body;
    std::string err;
};

static HttpResult httpsGet(const std::wstring &host, const std::string &pathQuery,
                           const std::vector<std::pair<std::string, std::string>> &headers) {
    HttpResult r;
    HINTERNET ses = WinHttpOpen(L"qs-login/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
                                WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) {
        r.err = "WinHttpOpen 失败(错误码 " + std::to_string(GetLastError()) + ")";
        return r;
    }
    WinHttpSetTimeouts(ses, 5000, 5000, 5000, 10000);
    HINTERNET conn = WinHttpConnect(ses, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET req = nullptr;
    if (!conn) {
        r.err = "WinHttpConnect 失败";
        WinHttpCloseHandle(ses);
        return r;
    }
    req = WinHttpOpenRequest(conn, L"GET", toWide(pathQuery).c_str(), nullptr, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) {
        r.err = "WinHttpOpenRequest 失败";
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(ses);
        return r;
    }
    std::string all;
    for (auto &h : headers) all += h.first + ": " + h.second + "\r\n";
    if (!all.empty() && !WinHttpAddRequestHeaders(req, toWide(all).c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD)) {
        r.err = "WinHttpAddRequestHeaders 失败";
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(ses);
        return r;
    }
    if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(req, nullptr)) {
        r.err = std::string("请求失败: ") + (GetLastError() == 12007 ? "DNS 解析失败(无网络?)" : "错误码 " + std::to_string(GetLastError()));
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(ses);
        return r;
    }
    DWORD st = 0, sz = sizeof st;
    WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &st,
                        &sz, WINHTTP_NO_HEADER_INDEX);
    r.status = (int)st;
    for (;;) {
        char buf[8192];
        DWORD n = 0;
        if (!WinHttpReadData(req, buf, sizeof buf, &n) || !n) break;
        r.body.append(buf, n);
    }
    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(ses);
    return r;
}

// ---------------------------------------------------------------- 主流程

static void printUsage() {
    printf(
        "qs-login —— 汽水音乐本机客户端登录导入\n"
        "从官方 PC 客户端数据目录读 sessionid(可选签名校验),写入 MusicServer 的 auth.json。\n"
        "用法: qs-login [选项]\n"
        "  --print          只打印 sessionid,不落盘\n"
        "  --no-verify      跳过 /luna/pc/me 校验\n"
        "  --dir <目录>     客户端数据目录(默认 %%APPDATA%%\\SodaMusic,或 QS_SODA_DATA_DIR)\n"
        "  --auth <文件>    auth.json 路径(默认 ..\\MusicServer\\data\\auth.json,或 QS_AUTH_FILE)\n"
        "  --dll <path>     metasecml.dll(校验签名用;默认 exe 同目录,缺了就跳过校验)\n");
}

int main(int argc, char **argv) {
    // 源码统一 UTF-8,Windows 控制台默认 GBK 代码页,不切会中文乱码
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::string dirArg, authArg, dllArg;
    bool printOnly = false, skipVerify = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : ""; };
        if (a == "--print") printOnly = true;
        else if (a == "--no-verify") skipVerify = true;
        else if (a == "--dir") dirArg = next();
        else if (a == "--auth") authArg = next();
        else if (a == "--dll") dllArg = next();
        else if (a == "-h" || a == "--help") { printUsage(); return 0; }
        else { fprintf(stderr, "未知参数: %s\n", a.c_str()); printUsage(); return 1; }
    }

    std::string root = exeDir();
    std::string dataDir = !dirArg.empty() ? dirArg : envUtf8(L"QS_SODA_DATA_DIR");
    if (dataDir.empty()) {
        std::string ad = envUtf8(L"APPDATA");
        if (ad.empty()) die("读不到 %APPDATA%,请用 --dir 指定客户端数据目录");
        dataDir = ad + "\\SodaMusic";
    }
    std::string deviceFile = dataDir + "\\DeviceV1";
    std::string cookieDb = dataDir + "\\Network\\Cookies";

    // —— 1. 设备身份(DeviceV1:gzip JSON {did,iid};没有也能继续,只是不校验)——
    std::string did, iid;
    {
        std::string raw;
        if (!fileExists(deviceFile)) {
            printf("! 未读到客户端设备身份(%s),校验时将跳过\n", deviceFile.c_str());
        } else if (!readFile(deviceFile, raw)) {
            printf("! 读 %s 失败,校验时将跳过\n", deviceFile.c_str());
        } else {
            std::string text;
            if (!gz::gunzip(raw, text)) text = raw;  // 解压失败当明文试
            JVal dev;
            json::P jp(text);
            if (jp.val(dev) && dev.t == JVal::Obj) {
                const JVal *jd = dev.get("did"), *ji = dev.get("iid");
                if (jd && !jd->s.empty() && ji && !ji->s.empty()) {
                    did = jd->s;  // did/iid 可能是数字或字符串,原文即文本
                    iid = ji->s;
                }
            }
            if (did.empty()) printf("! DeviceV1 里没有 did/iid,校验时将跳过\n");
            else printf("· 客户端设备: did=%s iid=%s\n", did.c_str(), iid.c_str());
        }
    }

    // —— 2. 登录态(Chromium cookie 库:复制副本后只读查询,和客户端不抢锁)——
    if (!fileExists(cookieDb)) {
        die("未找到客户端登录数据:" + cookieDb + "\n  请先安装并登录官方汽水音乐 PC 客户端,或用 --dir 指定数据目录");
    }
    wchar_t tmpDirBuf[MAX_PATH];
    DWORD tn = GetTempPathW(MAX_PATH, tmpDirBuf);
    if (!tn || tn >= MAX_PATH) die("GetTempPathW 失败");
    std::string tmpBase = fromWide(std::wstring(tmpDirBuf, tn)) + "qs-cookies-" + std::to_string(GetCurrentProcessId());
    std::string tmpDb = tmpBase + "-Cookies";
    {
        std::wstring src = toWide(cookieDb), dst = toWide(tmpDb);
        if (!CopyFileW(src.c_str(), dst.c_str(), FALSE)) die("复制 cookie 库失败(错误码 " + std::to_string(GetLastError()) + ")");
        for (const wchar_t *side : {L"-wal", L"-shm"}) {
            std::wstring s2 = src + side, d2 = dst + side;
            if (fileExists(fromWide(s2))) CopyFileW(s2.c_str(), d2.c_str(), FALSE);
        }
    }
    CookieRow row;
    std::string cookieErr;
    int rc = -1;
    auto cleanupTmp = [&]() {
        DeleteFileW(toWide(tmpDb).c_str());
        DeleteFileW(toWide(tmpDb + "-wal").c_str());
        DeleteFileW(toWide(tmpDb + "-shm").c_str());
    };
    {
        // QS_LOGIN_FORCE_LITE=1 时跳过 winsqlite3,强制走内置解析器(调试用)
        winsqlite::Api sq = envUtf8(L"QS_LOGIN_FORCE_LITE").empty() ? winsqlite::load() : winsqlite::Api{};
        if (sq.ok()) {
            rc = winsqlite::querySessionId(sq, tmpDb, row, cookieErr);
            if (rc == 2) {
                cleanupTmp();
                die("客户端正在运行且 cookie 库被占用,请退出汽水音乐客户端后重试");
            }
            if (rc == 3) printf("! winsqlite3 读取失败(%s),改用内置解析器\n", cookieErr.c_str());
        }
        if (rc != 0) {
            if (!lite::querySessionId(tmpDb, row, cookieErr)) {
                cleanupTmp();
                if (!cookieErr.empty()) die("读取 cookie 库失败: " + cookieErr);
                die("客户端未登录(cookie 库中没有 .qishui.com 的 sessionid),请先在客户端登录");
            }
        }
    }
    cleanupTmp();

    std::string sessionid = trim(row.value);
    std::string encErr;
    if (sessionid.empty() && !row.encrypted.empty()) {
        // value 列为空 → 尝试解密 encrypted_value(Chromium 加密存储路径)
        if (!chromiumDecrypt(row.encrypted, dataDir, sessionid, encErr)) {
            die("cookie 存在但值为空且解密失败:" + encErr);
        }
        sessionid = trim(sessionid);
    }
    if (sessionid.empty()) die("客户端未登录(cookie 库中没有 .qishui.com 的 sessionid),请先在客户端登录");

    // —— 3. 可选:签名打 /luna/pc/me 校验(status_code === 0 视为有效)——
    int verified = -1;  // 1 有效 / 0 失效 / -1 无法判定
    std::string dllPath = !dllArg.empty() ? dllArg : root + "\\metasecml.dll";
    if (!skipVerify && !did.empty()) {
        if (!fileExists(dllPath)) {
            printf("! 未找到 %s(--dll 可指定),无法校验\n", dllPath.c_str());
        } else {
            Signer signer;
            std::string serr;
            if (!signer.load(dllPath, 0, serr)) {
                printf("! 校验失败(按未校验处理): %s\n", serr.c_str());
            } else {
                std::string query =
                    "aid=386088&app_name=luna_pc&region=cn&geo_region=cn&os_region=cn&sim_region=&device_id=" + did +
                    "&cdid=&iid=" + iid +
                    "&version_name=3.7.0&version_code=30070000&channel=official&build_mode=master&network_carrier="
                    "&ac=wifi&tz_name=Asia%2FShanghai&resolution=&device_platform=windows&device_type=Windows"
                    "&os_version=Windows+11&fp=" + did;
                std::string url = "https://api.qishui.com/luna/pc/me?" + query;
                std::string flat = "user-agent\r\nLunaPC/3.7.0(452316191)\r\ncookie\r\nsessionid=" + sessionid;
                std::string signed_ = signer.sign(url, flat);
                if (signed_.empty()) {
                    printf("! 校验失败(按未校验处理): 签名失败\n");
                } else {
                    std::vector<std::pair<std::string, std::string>> headers = {
                        {"user-agent", "LunaPC/3.7.0(452316191)"},
                        {"cookie", "sessionid=" + sessionid},
                    };
                    {   // 解析 "名字\r\n值\r\n..." 成对
                        size_t b = 0;
                        std::vector<std::string> parts;
                        while (b <= signed_.size()) {
                            size_t e = signed_.find("\r\n", b);
                            if (e == std::string::npos) { parts.push_back(signed_.substr(b)); break; }
                            parts.push_back(signed_.substr(b, e - b));
                            b = e + 2;
                        }
                        while (!parts.empty() && parts.back().empty()) parts.pop_back();
                        for (size_t i = 0; i + 1 < parts.size(); i += 2)
                            headers.emplace_back(parts[i], parts[i + 1]);
                    }
                    HttpResult r = httpsGet(L"api.qishui.com", "/luna/pc/me?" + query, headers);
                    if (!r.err.empty()) {
                        printf("! 校验失败(按未校验处理): %s\n", r.err.c_str());
                    } else if (r.status != 200) {
                        printf("! 校验失败(按未校验处理): HTTP %d\n", r.status);
                    } else {
                        JVal body;
                        json::P bp(r.body);
                        if (bp.val(body) && body.t == JVal::Obj) {
                            const JVal *sc = body.get("status_code");
                            if (sc && sc->t == JVal::Num) verified = (sc->s == "0") ? 1 : 0;
                        }
                    }
                }
            }
        }
    }
    if (verified == 0) die("客户端登录态已失效,请在汽水音乐客户端重新登录后再跑本工具");

    printf("· sessionid: %s…%s(%zu 字符)\n",
           sessionid.substr(0, 6).c_str(), sessionid.substr(sessionid.size() > 4 ? sessionid.size() - 4 : 0).c_str(),
           sessionid.size());
    printf("· 校验: %s\n", verified == 1 ? "有效" : verified == 0 ? "已失效"
                                    : skipVerify ? "已跳过(--no-verify)" : "无法判定(缺签名模块或网络异常)");

    if (printOnly) {
        printf("%s\n", sessionid.c_str());
        return 0;
    }

    // —— 4. 写 auth.json(默认 ../MusicServer/data/auth.json;凭据归 MusicServer 管)——
    std::string musicServerDir = root + "\\..\\MusicServer";
    std::string authPath = !authArg.empty() ? authArg : envUtf8(L"QS_AUTH_FILE");
    if (authPath.empty()) {
        authPath = musicServerDir + "\\data\\auth.json";
        DWORD a = GetFileAttributesW(toWide(musicServerDir).c_str());
        if (a == INVALID_FILE_ATTRIBUTES) {
            die("未找到同级 MusicServer 仓库(" + musicServerDir + "),请用 --auth <路径>/data/auth.json 指定写入目标");
        }
    }
    JVal auth;
    auth.t = JVal::Obj;
    {
        std::string old;
        if (readFile(authPath, old)) {
            json::P jp(old);
            if (!jp.val(auth) || auth.t != JVal::Obj) {
                die("现有 auth.json 解析失败,请手动检查:" + authPath);
            }
        }
    }
    {
        SYSTEMTIME st;
        GetSystemTime(&st);
        char ts[40];
        snprintf(ts, sizeof ts, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", st.wYear, st.wMonth, st.wDay, st.wHour,
                 st.wMinute, st.wSecond, st.wMilliseconds);
        JVal *qs = auth.get("qs");
        if (!qs || qs->t != JVal::Obj) {
            auth.o.emplace_back("qs", JVal{});
            qs = &auth.o.back().second;
            qs->t = JVal::Obj;
        }
        qs->set("sessionid", sessionid);
        qs->set("cookie", "sessionid=" + sessionid);
        qs->set("source", "local-client");
        qs->set("updatedAt", ts);
    }
    if (!writeFile(authPath, jpretty(auth) + "\n")) {
        die("写入 " + authPath + " 失败(错误码 " + std::to_string(GetLastError()) + ")");
    }
    printf("✓ 已写入 %s(qs.sessionid)\n", authPath.c_str());
    printf("  MusicServer 在运行的话需要重启才生效(凭据已缓存);之后 /login/status 的 qs.logged 应为 true\n");
    return 0;
}
