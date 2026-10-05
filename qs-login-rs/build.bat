@echo off
rem Rust 版构建。需要 MSVC 工具链(rustup default stable-x86_64-pc-windows-msvc)。
rem 注意:本机 choco 装的 GNU 版 cargo 在 PATH 里靠前,这里强制让 rustup 的代理优先。
setlocal
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
where cargo >nul 2>&1 || (
  echo [x] cargo not found in PATH
  exit /b 1
)
cargo build --release || (
  echo [x] build failed
  exit /b 1
)
echo [ok] built target\release\qs-login.exe
echo     test:   target\release\qs-login.exe --print
echo     verify: target\release\qs-login.exe --dll ..\mssdk-sign\metasecml.dll
