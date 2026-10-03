@echo off
rem MSVC native build (Windows). Source has UTF-8 Chinese comments -> /utf-8 is required.
setlocal
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (
  echo [x] vcvars64.bat not found, edit VCVARS in this script
  exit /b 1
)
call "%VCVARS%" >nul
cl /nologo /O2 /EHsc /std:c++17 /utf-8 /W3 mssdk-sign.cpp /link /out:mssdk-sign.exe ws2_32.lib version.lib
if errorlevel 1 (
  echo [x] build failed
  exit /b 1
)
echo [ok] built mssdk-sign.exe
echo     selftest: mssdk-sign.exe --selftest --dll .\metasecml.dll
