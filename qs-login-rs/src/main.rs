// qs-login —— 汽水音乐「本机客户端登录态」读取工具(Rust 版,与 ../qs-login/qs-login.cpp 功能对等)
//
// 做什么:官方 SodaMusic PC 客户端是 Chromium,登录态存在本机
//   %APPDATA%\SodaMusic\Network\Cookies(SQLite),设备身份在 %APPDATA%\SodaMusic\DeviceV1
//   (gzip JSON,含 did/iid)。本工具把它们读出来、可选签名校验,然后完整显示 sessionid
//   并复制到剪贴板——只读不写,凭据粘贴到哪由你自己决定。
//
// 用法(与 C++ 版一致):
//   qs-login.exe                    # 读取 + 校验 + 完整显示 + 复制剪贴板(可直接双击:窗口等回车才关)
//   qs-login.exe --print            # 只输出 sessionid 到 stdout(脚本用:不暂停/不写剪贴板)
//   qs-login.exe --no-verify        # 跳过 /luna/pc/me 校验
//   qs-login.exe --no-pause         # 结束时不等待回车(脚本用)
//   qs-login.exe --dir <目录>       # 客户端数据目录(默认 %APPDATA%\SodaMusic,或 QS_SODA_DATA_DIR)
//   qs-login.exe --dll <path>       # metasecml.dll(校验签名用;默认 exe 同目录,其次 ..\mssdk-sign\,缺了跳过校验)
//
// 技术栈:flate2(rust 后端)解压 DeviceV1;rusqlite(bundled,自带 SQLite 源码编译)
//   读 cookie 库——不依赖 winsqlite3.dll、天然支持 WAL,客户端开着也能读到最新数据;
//   serde_json 解析;ureq(native-tls/schannel)发 HTTPS;RustCrypto aes-gcm + DPAPI 解密
//   Chromium 加密 cookie。仅 metasecml.dll 裸偏移调用、剪贴板、控制台代码页为少量 Win32 FFI。
//   与 C++ 版的差异:无 SEH——DLL 偏移不匹配时签名自检会直接崩溃退出(而非报错)。
//
// 构建:build.bat(或 cargo build --release),产物在 target/release/qs-login.exe

#![allow(non_snake_case)]

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, GlobalFree, LocalFree, GENERIC_READ,
                                     GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DeleteFileW, ReadFile, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{GetConsoleMode, GetStdHandle, SetConsoleCP, SetConsoleOutputCP,
                                          STD_INPUT_HANDLE};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::System::Ole::CF_TEXT;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

// ---------------------------------------------------------------- 交互(双击不闪退 + 剪贴板)

static mut PAUSE_ON_EXIT: bool = true; // 单线程,启动时读写,无竞争

fn pause_if_interactive() {
    unsafe {
        if !PAUSE_ON_EXIT {
            return;
        }
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        if h.is_null() || GetConsoleMode(h, &mut mode) == 0 {
            return;
        }
        print!("\n按回车键退出...");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

fn die(msg: &str) -> ! {
    let _ = std::io::stdout().flush();
    eprintln!("✗ {}", msg);
    pause_if_interactive();
    std::process::exit(1);
}

fn copy_to_clipboard(text: &str) -> bool {
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return false;
        }
        if EmptyClipboard() == 0 {
            CloseClipboard();
            return false;
        }
        let mut ok = false;
        let g = GlobalAlloc(GMEM_MOVEABLE, text.len() + 1);
        if !g.is_null() {
            let p = GlobalLock(g) as *mut u8;
            if !p.is_null() {
                std::ptr::copy_nonoverlapping(text.as_ptr(), p, text.len());
                *p.add(text.len()) = 0;
                GlobalUnlock(g);
                ok = !SetClipboardData(CF_TEXT as u32, g).is_null(); // 成功后内存归系统
            }
            if !ok {
                GlobalFree(g);
            }
        }
        CloseClipboard();
        ok
    }
}

// 客户端开着时 SQLite 持有 cookie 库的读写句柄,fs::copy(内部 CopyFileExW)会因共享冲突
// 报错误码 32;用宽松共享模式(READ|WRITE|DELETE)手拷——读取角度最宽松的姿势
fn copy_file_shared(src: &str, dst: &str) -> Result<(), u32> {
    unsafe {
        let wide: Vec<u16> = src.encode_utf16().chain(std::iter::once(0)).collect();
        let h = CreateFileW(wide.as_ptr(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(),
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
        if h == INVALID_HANDLE_VALUE {
            return Err(GetLastError());
        }
        let wd: Vec<u16> = dst.encode_utf16().chain(std::iter::once(0)).collect();
        let o = CreateFileW(wd.as_ptr(), GENERIC_WRITE, 0, std::ptr::null(), CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
        if o == INVALID_HANDLE_VALUE {
            let e = GetLastError();
            CloseHandle(h);
            return Err(e);
        }
        let mut buf = [0u8; 65536];
        let (mut n, mut w): (u32, u32) = (0, 0);
        loop {
            if ReadFile(h, buf.as_mut_ptr(), buf.len() as u32, &mut n, std::ptr::null_mut()) == 0 {
                let e = GetLastError();
                CloseHandle(h);
                CloseHandle(o);
                DeleteFileW(wd.as_ptr());
                return Err(e);
            }
            if n == 0 {
                break;
            }
            if WriteFile(o, buf.as_ptr(), n, &mut w, std::ptr::null_mut()) == 0 || w != n {
                let e = GetLastError();
                CloseHandle(h);
                CloseHandle(o);
                DeleteFileW(wd.as_ptr());
                return Err(e);
            }
        }
        CloseHandle(h);
        CloseHandle(o);
        Ok(())
    }
}

fn temp_copy_of(cookie_db: &str) -> Result<String, String> {
    let pid = unsafe { GetCurrentProcessId() };
    let tmp_dir = env::temp_dir();
    let tmp_db = tmp_dir.join(format!("qs-cookies-{}-Cookies", pid));
    let tmp_db = tmp_db.to_str().ok_or("临时路径不是 UTF-8")?.to_string();
    // 只拷 db 和 -wal(不拷 -shm:共享内存是临时索引,SQLite 打开副本时会自建)
    if let Err(e) = copy_file_shared(cookie_db, &tmp_db) {
        return Err(if e == 32 /*ERROR_SHARING_VIOLATION*/ {
            "cookie 库被独占锁定,复制失败。请退出汽水音乐客户端后重试".to_string()
        } else {
            format!("复制 cookie 库失败(错误码 {})", e)
        });
    }
    let wal = format!("{}-wal", cookie_db);
    if Path::new(&wal).is_file() {
        let _ = copy_file_shared(&wal, &format!("{}-wal", tmp_db)); // 拷失败就只有主库,SQLite 仍可读
    }
    Ok(tmp_db)
}

fn cleanup_tmp(tmp_db: &str) {
    for p in [tmp_db.to_string(), format!("{}-wal", tmp_db), format!("{}-shm", tmp_db)] {
        let wide: Vec<u16> = p.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            DeleteFileW(wide.as_ptr());
        }
    }
}

// ---------------------------------------------------------------- 1. 设备身份(DeviceV1:gzip JSON)

fn read_device(data_dir: &str) -> Option<(String, String)> {
    let path = format!("{}\\DeviceV1", data_dir);
    let raw = fs::read(&path).ok()?;
    let text = {
        let mut s = String::new();
        match flate2::read::GzDecoder::new(&raw[..]).read_to_string(&mut s) {
            Ok(_) => s, // GzDecoder 读完会校验 CRC32/ISIZE
            Err(_) => String::from_utf8_lossy(&raw).into_owned(), // 解压失败当明文试
        }
    };
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    // did/iid 可能是数字或字符串;19 位设备号超 f64 精度,必须走 u64/i64 原值
    let num = |x: &serde_json::Value| -> Option<String> {
        x.as_str().map(String::from)
            .or_else(|| x.as_u64().map(|n| n.to_string()))
            .or_else(|| x.as_i64().map(|n| n.to_string()))
    };
    let did = num(v.get("did")?)?;
    let iid = num(v.get("iid")?)?;
    if did.is_empty() || iid.is_empty() {
        None
    } else {
        Some((did, iid))
    }
}

// ---------------------------------------------------------------- 2. cookie 库(rusqlite bundled,支持 WAL)

fn query_session_id(db_file: &str) -> Result<Option<(String, Vec<u8>)>, String> {
    let conn = Connection::open_with_flags(db_file, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| format!("打开 cookie 库副本失败: {}", e))?;
    conn.busy_timeout(Duration::from_millis(3000)).ok();
    // 对"我们自己的临时副本"读写打开:库处于 WAL 模式且没带 -shm 时,只读打开会因无法恢复 WAL 而失败
    let row: Option<(Option<String>, Vec<u8>)> = conn
        .query_row(
            "SELECT value,encrypted_value FROM cookies \
             WHERE host_key IN ('.qishui.com','qishui.com') AND name='sessionid' LIMIT 1",
            [],
            |r| {
                let v: Option<String> = r.get(0)?;
                // encrypted_value 在真实库里是 BLOB,但可能缺省成 ''(TEXT)或 NULL,宽松取
                let e: rusqlite::types::Value = r.get(1)?;
                let e = match e {
                    rusqlite::types::Value::Blob(b) => b,
                    _ => Vec::new(),
                };
                Ok((v, e))
            },
        )
        .optional()
        .map_err(|e| format!("查询 cookies 失败: {}", e))?;
    Ok(row.map(|(v, e)| (v.unwrap_or_default(), e)))
}

// ---------------------------------------------------------------- 3. Chromium encrypted_value 解密回退
//   v10/v11: "v10" + 12 字节 nonce + 密文 + 16 字节 GCM tag,key 来自 Local State 的
//   os_crypt.encrypted_key(base64,去 "DPAPI" 前缀后 CryptUnprotectData,32 字节)
//   v20(app-bound):离线不可解,明确报错。老格式:整块直接 DPAPI。

fn dpapi(input: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let din = CRYPT_INTEGER_BLOB { cbData: input.len() as u32, pbData: input.as_ptr() as *mut u8 };
        let mut dout = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        if CryptUnprotectData(&din, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(),
                              std::ptr::null(), 0, &mut dout) == 0
        {
            return Err(format!("CryptUnprotectData 失败(错误码 {})", GetLastError()));
        }
        let out = std::slice::from_raw_parts(dout.pbData, dout.cbData as usize).to_vec();
        LocalFree(dout.pbData as _);
        Ok(out)
    }
}

fn chromium_decrypt(enc: &[u8], data_dir: &str) -> Result<String, String> {
    if enc.is_empty() {
        return Err("encrypted_value 为空".into());
    }
    let prefix = String::from_utf8_lossy(&enc[..enc.len().min(3)]).into_owned();
    if prefix == "v20" {
        return Err("cookie 使用 app-bound 加密(v20),离线无法解密;请在客户端开着的状态下改用官方接口导出".into());
    }
    if prefix != "v10" && prefix != "v11" {
        let out = dpapi(enc)?; // 老格式:直接 DPAPI
        return Ok(String::from_utf8_lossy(&out).into_owned());
    }
    // Local State → key
    let ls_path = format!("{}\\Local State", data_dir);
    let ls = fs::read_to_string(&ls_path)
        .map_err(|_| format!("读不到 {}(解密 cookie 需要)", ls_path))?;
    let v: serde_json::Value = serde_json::from_str(&ls).map_err(|_| "Local State 不是合法 JSON".to_string())?;
    let key_b64 = v.get("os_crypt").and_then(|o| o.get("encrypted_key")).and_then(|k| k.as_str())
        .ok_or("Local State 里没有 os_crypt.encrypted_key")?;
    let key_blob = B64.decode(key_b64).map_err(|_| "encrypted_key 不是合法 base64".to_string())?;
    if key_blob.len() < 6 || key_blob[..5] != *b"DPAPI" {
        return Err("encrypted_key 格式异常".into());
    }
    let key = dpapi(&key_blob[5..])?;
    if key.len() != 32 {
        return Err("解出的 cookie key 不是 32 字节".into());
    }
    // AES-256-GCM:v10 + nonce(12) + ct + tag(16)
    if enc.len() < 3 + 12 + 16 {
        return Err("encrypted_value 太短".into());
    }
    let nonce = &enc[3..15];
    let ct_and_tag = &enc[15..];
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct_and_tag, aad: &[] })
        .map_err(|_| "AES-GCM 解密失败(tag 不匹配 = key 不对或数据损坏)".to_string())?;
    Ok(String::from_utf8_lossy(&plain).into_owned())
}

// ---------------------------------------------------------------- 4. 签名器(metasecml.dll 裸偏移调用,与 mssdk-sign 同一 ABI)

type SignFn = unsafe extern "system" fn(*const u8, *const u8) -> *mut u8;
type FreeFn = unsafe extern "system" fn(*mut core::ffi::c_void);

// 已知版本 → 偏移(与 mssdk-sign 的 KNOWN_VERSIONS 保持一致;客户端升级后同步改这里)
const KNOWN_VERSIONS: &[(&str, u64, u64)] = &[("4.6.1.0", 0x52af0, 0x1d8c0)];
const DEFAULT_SIGN_RVA: u64 = 0x52af0;
const DEFAULT_FREE_RVA: u64 = 0x1d8c0;

struct Signer {
    sign: SignFn,
    free: Option<FreeFn>,
}

impl Signer {
    fn load(dll_path: &str, rva_override: u64) -> Result<Signer, String> {
        unsafe {
            let wide: Vec<u16> = dll_path.encode_utf16().chain(std::iter::once(0)).collect();
            let h = LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH);
            if h.is_null() {
                return Err(format!("LoadLibraryExW 失败(错误码 {}): {}", GetLastError(), dll_path));
            }
            let (sr, fr) = if rva_override != 0 {
                (rva_override as usize, (rva_override + DEFAULT_FREE_RVA - DEFAULT_SIGN_RVA) as usize)
            } else {
                // 表里只有一组已知版本偏移(与 mssdk-sign 的 KNOWN_VERSIONS 保持一致)
                KNOWN_VERSIONS.first()
                    .map(|(_, s, f)| (*s as usize, *f as usize))
                    .unwrap_or((DEFAULT_SIGN_RVA as usize, DEFAULT_FREE_RVA as usize))
            };
            let sign: SignFn = std::mem::transmute(h as usize + sr);
            let free: FreeFn = std::mem::transmute(h as usize + fr);
            let s = Signer { sign, free: Some(free) };
            // 启动自检(无 SEH:偏移错误时这里会直接崩溃,版本表兜底)
            if !s.selftest() {
                return Err(format!("签名自检失败:偏移 {:#x} 处不是有效的签名函数", sr));
            }
            Ok(s)
        }
    }

    fn selftest(&self) -> bool {
        let r = self.sign_raw(
            "https://api.qishui.com/luna/pc/track_v2?aid=386088&app_name=luna_pc&device_id=1",
            "user-agent\r\nLunaPC/3.7.0(452316191)",
        );
        match r {
            Some(s) => s.contains("X-") && s.contains("\r\n"),
            None => false,
        }
    }

    fn sign_raw(&self, url: &str, headers_flat: &str) -> Option<String> {
        let mut u = url.as_bytes().to_vec();
        u.push(0);
        let mut h = headers_flat.as_bytes().to_vec();
        h.push(0);
        unsafe {
            let r = (self.sign)(u.as_ptr(), h.as_ptr());
            if r.is_null() {
                return None;
            }
            let out = cstr_to_string(r);
            if let Some(f) = self.free {
                f(r as *mut core::ffi::c_void);
            }
            Some(out)
        }
    }
}

fn cstr_to_string(p: *mut u8) -> String {
    unsafe {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf8_lossy(std::slice::from_raw_parts(p, len)).into_owned()
    }
}

// ---------------------------------------------------------------- 5. HTTPS(ureq + 系统 schannel)

fn https_get(url: &str, headers: &[(String, String)]) -> Result<(u16, String), String> {
    // ureq 的 native-tls(schannel)不会自动成为默认后端,需显式接上
    let tls = ureq::native_tls::TlsConnector::new().map_err(|e| format!("TLS 初始化失败: {}", e))?;
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .tls_connector(std::sync::Arc::new(tls))
        .build();
    let mut req = agent.get(url);
    for (k, v) in headers {
        req = req.set(k, v);
    }
    match req.call() {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.into_string().unwrap_or_default();
            Ok((status, body))
        }
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Ok((code, body))
        }
        Err(e) => Err(format!("请求失败: {}", e)),
    }
}

// ---------------------------------------------------------------- 主流程

fn print_usage() {
    println!(
        "qs-login —— 汽水音乐本机客户端登录态读取(只读不写,Rust 版)\n\
         从官方 PC 客户端数据目录读 sessionid(可选签名校验),完整显示并复制到剪贴板。\n\
         可直接双击运行:窗口会等待回车才关闭。\n\
         用法: qs-login [选项]\n\
         \x20 --print          只输出 sessionid 到 stdout(脚本用,不暂停/不写剪贴板)\n\
         \x20 --no-verify      跳过 /luna/pc/me 校验\n\
         \x20 --no-pause       结束时不等待回车(脚本用)\n\
         \x20 --dir <目录>     客户端数据目录(默认 %APPDATA%\\SodaMusic,或 QS_SODA_DATA_DIR)\n\
         \x20 --dll <path>     metasecml.dll(校验签名用;默认 exe 同目录,其次 ..\\mssdk-sign\\,缺了跳过校验)"
    );
}

fn main() {
    unsafe {
        SetConsoleOutputCP(65001 /*CP_UTF8*/);
        SetConsoleCP(65001);
    }

    let mut dir_arg = String::new();
    let mut dll_arg = String::new();
    let mut print_only = false;
    let mut skip_verify = false;
    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let a = args[i].clone();
        let mut next = || {
            i += 1;
            args.get(i).cloned().unwrap_or_default()
        };
        match a.as_str() {
            "--print" => {
                print_only = true;
                unsafe { PAUSE_ON_EXIT = false }; // --print 给脚本用,不暂停
            }
            "--no-verify" => skip_verify = true,
            "--no-pause" => unsafe { PAUSE_ON_EXIT = false },
            "--dir" => dir_arg = next(),
            "--dll" => dll_arg = next(),
            "-h" | "--help" => {
                print_usage();
                return;
            }
            _ => {
                eprintln!("未知参数: {}", a);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let root = env::current_exe().ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let mut data_dir = if !dir_arg.is_empty() {
        dir_arg.clone()
    } else {
        env::var("QS_SODA_DATA_DIR").unwrap_or_default()
    };
    if data_dir.is_empty() {
        match env::var("APPDATA") {
            Ok(ad) if !ad.is_empty() => data_dir = format!("{}\\SodaMusic", ad),
            _ => die("读不到 %APPDATA%,请用 --dir 指定客户端数据目录"),
        }
    }
    let cookie_db = format!("{}\\Network\\Cookies", data_dir);

    // —— 1. 设备身份(DeviceV1:gzip JSON {did,iid};没有也能继续,只是不校验)——
    let (did, iid) = match read_device(&data_dir) {
        None => {
            println!("! 未读到客户端设备身份({}\\DeviceV1),校验时将跳过", data_dir);
            (String::new(), String::new())
        }
        Some((d, n)) => {
            println!("· 客户端设备: did={} iid={}", d, n);
            (d, n)
        }
    };

    // —— 2. 登录态(Chromium cookie 库:复制副本后查询,bundled SQLite 支持 WAL)——
    if !Path::new(&cookie_db).is_file() {
        die(&format!("未找到客户端登录数据:{}\n  请先安装并登录官方汽水音乐 PC 客户端,或用 --dir 指定数据目录", cookie_db));
    }
    let tmp_db = match temp_copy_of(&cookie_db) {
        Ok(p) => p,
        Err(e) => die(&e),
    };
    let (value, encrypted) = match query_session_id(&tmp_db) {
        Ok(Some(v)) => v,
        Ok(None) => {
            cleanup_tmp(&tmp_db);
            die("客户端未登录(cookie 库中没有 .qishui.com 的 sessionid),请先在客户端登录");
        }
        Err(e) => {
            cleanup_tmp(&tmp_db);
            die(&format!("读取 cookie 库失败: {}", e));
        }
    };
    cleanup_tmp(&tmp_db);

    let mut sessionid = value.trim().to_string();
    if sessionid.is_empty() && !encrypted.is_empty() {
        // value 列为空 → 尝试解密 encrypted_value(Chromium 加密存储路径)
        match chromium_decrypt(&encrypted, &data_dir) {
            Ok(v) => sessionid = v.trim().to_string(),
            Err(e) => die(&format!("cookie 存在但值为空且解密失败:{}", e)),
        }
    }
    if sessionid.is_empty() {
        die("客户端未登录(cookie 库中没有 .qishui.com 的 sessionid),请先在客户端登录");
    }

    // —— 3. 可选:签名打 /luna/pc/me 校验(status_code === 0 视为有效)——
    let mut verified: i32 = -1; // 1 有效 / 0 失效 / -1 无法判定
    let mut dll_path = if !dll_arg.is_empty() {
        dll_arg.clone()
    } else {
        format!("{}\\metasecml.dll", root)
    };
    if dll_arg.is_empty() && !Path::new(&dll_path).is_file() {
        let alt = format!("{}\\..\\mssdk-sign\\metasecml.dll", root); // 本仓库默认布局
        if Path::new(&alt).is_file() {
            dll_path = alt;
        }
    }
    if !skip_verify && !did.is_empty() {
        if !Path::new(&dll_path).is_file() {
            println!("! 未找到 {}(--dll 可指定),无法校验", dll_path);
        } else {
            match Signer::load(&dll_path, 0) {
                Err(e) => println!("! 校验失败(按未校验处理): {}", e),
                Ok(signer) => {
                    let query = format!(
                        "aid=386088&app_name=luna_pc&region=cn&geo_region=cn&os_region=cn&sim_region=&device_id={did}\
                         &cdid=&iid={iid}&version_name=3.7.0&version_code=30070000&channel=official&build_mode=master\
                         &network_carrier=&ac=wifi&tz_name=Asia%2FShanghai&resolution=&device_platform=windows\
                         &device_type=Windows&os_version=Windows+11&fp={did}");
                    let url = format!("https://api.qishui.com/luna/pc/me?{}", query);
                    let flat = format!("user-agent\r\nLunaPC/3.7.0(452316191)\r\ncookie\r\nsessionid={}", sessionid);
                    match signer.sign_raw(&url, &flat) {
                        None => println!("! 校验失败(按未校验处理): 签名失败"),
                        Some(signed) => {
                            let mut headers: Vec<(String, String)> = vec![
                                ("user-agent".into(), "LunaPC/3.7.0(452316191)".into()),
                                ("cookie".into(), format!("sessionid={}", sessionid)),
                            ];
                            {   // 解析 "名字\r\n值\r\n..." 成对
                                let mut parts: Vec<&str> = signed.split("\r\n").collect();
                                while parts.last().map(|p| p.is_empty()).unwrap_or(false) {
                                    parts.pop();
                                }
                                let mut i = 0;
                                while i + 1 < parts.len() {
                                    headers.push((parts[i].to_string(), parts[i + 1].to_string()));
                                    i += 2;
                                }
                            }
                            match https_get(&url, &headers) {
                                Err(e) => println!("! 校验失败(按未校验处理): {}", e),
                                Ok((status, _body)) if status != 200 => {
                                    println!("! 校验失败(按未校验处理): HTTP {}", status);
                                }
                                Ok((_, body)) => {
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                                        if let Some(sc) = v.get("status_code").and_then(|x| x.as_i64()) {
                                            verified = if sc == 0 { 1 } else { 0 };
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if verified == 0 {
        die("客户端登录态已失效,请在汽水音乐客户端重新登录后再跑本工具");
    }

    println!("· 校验: {}", match verified {
        1 => "有效",
        0 => "已失效",
        _ if skip_verify => "已跳过(--no-verify)",
        _ => "无法判定(缺签名模块或网络异常)",
    });

    if print_only {
        println!("{}", sessionid);
        return;
    }

    // 交互模式:完整显示 + 复制到剪贴板,直接可粘贴
    println!("· sessionid: {}({} 字符)", sessionid, sessionid.chars().count());
    println!("{}", if copy_to_clipboard(&sessionid) {
        "· 已复制到剪贴板,可直接 Ctrl+V 粘贴"
    } else {
        "! 复制到剪贴板失败,请手动选中上一行复制"
    });
    println!("· 本工具只读不写,凭据粘贴到哪由你自己决定");

    pause_if_interactive();
}
