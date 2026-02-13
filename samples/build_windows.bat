@echo off
REM Build libobfuscated.dll using VS environment + Makefile
REM Requires: Visual Studio 2022+, GNU make, Git for Windows
REM Usage: build_windows.bat

echo ============================================================
echo   libobfuscated.dll Build
echo ============================================================

REM Step 1: Find VS installation via vswhere
echo.
echo [1/3] Initializing Visual Studio environment...
for /f "usebackq tokens=*" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -products * -latest -property installationPath`) do set VSDIR=%%i
if "%VSDIR%"=="" (
    echo ERROR: Visual Studio not found
    exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
echo   Done.

REM Step 2: Find tools on PATH
echo.
echo [2/3] Verifying toolchain...
where clang-cl.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   clang-cl: found
) else (
    echo   WARNING: clang-cl not found, will use MinGW path
)
where make.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "MAKE="
    for /d %%d in ("%HOMEDRIVE%%HOMEPATH%\scoop\apps\make\*") do (
        if /I not "%%~nxd"=="current" if exist "%%d\bin\make.exe" set "MAKE=%%d\bin\make.exe"
    )
    if not defined MAKE set "MAKE=make.exe"
) else (
    echo ERROR: make.exe not found on PATH
    echo   Install via: scoop install make  or  choco install make
    exit /b 1
)
echo   make: %MAKE%
echo   Done.

REM Step 3: Build
echo.
echo [3/3] Building via Makefile...
cd /d %~dp0

REM Find real sh.exe from Git for Windows (not a shim)
set "REAL_SH="
for /d %%d in ("%HOMEDRIVE%%HOMEPATH%\scoop\apps\git\*") do (
    if /I not "%%~nxd"=="current" if exist "%%d\usr\bin\sh.exe" set "REAL_SH=%%d\usr\bin\sh.exe"
)
if not defined REAL_SH (
    for /f "usebackq tokens=*" %%i in (`where git.exe 2^>nul`) do (
        for %%d in ("%%~dpi..") do (
            if exist "%%~fd\usr\bin\sh.exe" set "REAL_SH=%%~fd\usr\bin\sh.exe"
        )
    )
)

REM Clean everything including .d files (Windows paths in .d break make)
if defined REAL_SH (
    "%MAKE%" clean SHELL="%REAL_SH%" 2>nul
) else (
    "%MAKE%" clean 2>nul
)
del /Q src\c\*.d 2>nul
del /Q src\c\*.o 2>nul

if defined REAL_SH (
    "%MAKE%" TARGET_OS=windows BINARY_NAME=libobfuscated USING_CLANG_CL=1 CC_BASE=clang-cl.exe SHELL="%REAL_SH%"
) else (
    "%MAKE%" TARGET_OS=windows BINARY_NAME=libobfuscated USING_CLANG_CL=1 CC_BASE=clang-cl.exe
)
if %ERRORLEVEL% neq 0 (
    echo.
    echo ERROR: Build failed (make returned %ERRORLEVEL%)
    exit /b %ERRORLEVEL%
)
if not exist "bins\libobfuscated.dll" (
    echo.
    echo ERROR: DLL not created
    exit /b 1
)

echo.
echo ============================================================
echo   BUILD SUCCESSFUL
echo ============================================================
dir bins\libobfuscated.dll bins\libobfuscated.pdb 2>nul
