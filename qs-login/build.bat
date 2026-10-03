@echo off
rem MSVC native build (Windows). Source has UTF-8 Chinese comments -> /utf-8 is required.
setlocal
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
  echo [x] vcvars64.bat not found, edit VCVARS in this script
  exit /b 1
)
call "%VCVARS%" >nul
cl /nologo /O2 /EHsc /std:c++17 /utf-8 /W3 qs-login.cpp /link /out:qs-login.exe winhttp.lib bcrypt.lib crypt32.lib version.lib user32.lib
if errorlevel 1 (
  echo [x] build failed
  exit /b 1
)
echo [ok] built qs-login.exe
echo     test:   qs-login.exe --print
echo     verify: qs-login.exe --dll ..\mssdk-sign\metasecml.dll
