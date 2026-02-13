<#
.SYNOPSIS
    Build libobfuscated.dll on Windows using the project Makefile.

.DESCRIPTION
    Initializes VS environment via Enter-VsDevShell, then calls make.
    Requires Visual Studio 2022+, GNU make, and Git for Windows.

.EXAMPLE
    .\build_windows.ps1
#>

$ErrorActionPreference = "Stop"

# --- Configuration ---

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- Helpers ---

function Write-Step([int]$Num, [int]$Total, [string]$Title) {
    Write-Host "`n[$Num/$Total] $Title..." -ForegroundColor Cyan
}

function Write-Banner([string]$Text) {
    $sep = "=" * 60
    Write-Host "`n$sep"
    Write-Host "  $Text"
    Write-Host $sep
}

function Assert-Success([string]$Message) {
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: $Message" -ForegroundColor Red
        exit 1
    }
}

# --- Main ---

Write-Banner "libobfuscated.dll Build"

$TotalSteps = 3

# Step 1: Initialize VS environment
Write-Step 1 $TotalSteps "Initializing Visual Studio environment"
$vswhere = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    Write-Host "ERROR: vswhere.exe not found - is Visual Studio installed?" -ForegroundColor Red
    exit 1
}
$vs = & $vswhere -products * -latest -format json | ConvertFrom-Json
$DevShellDll = "$($vs.InstallationPath)\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
if (-not (Test-Path $DevShellDll)) {
    Write-Host "ERROR: VS DevShell module not found at $DevShellDll" -ForegroundColor Red
    exit 1
}
Import-Module $DevShellDll
Enter-VsDevShell $vs.InstanceId -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64 -no_logo" | Out-Null
Write-Host "  Done."

# Step 2: Verify toolchain
Write-Step 2 $TotalSteps "Verifying toolchain"

# Find make.exe
$MakeExe = (Get-Command make.exe -ErrorAction SilentlyContinue).Source
if (-not $MakeExe) {
    Write-Host "ERROR: make.exe not found on PATH" -ForegroundColor Red
    Write-Host "  Install via: scoop install make  or  choco install make" -ForegroundColor Yellow
    exit 1
}

$clangcl = Get-Command clang-cl.exe -ErrorAction SilentlyContinue
if ($clangcl) {
    Write-Host "  clang-cl: $($clangcl.Source)" -ForegroundColor Green
} else {
    Write-Host "  clang-cl not found, Makefile will use fallback" -ForegroundColor Yellow
}
Write-Host "  make: $MakeExe" -ForegroundColor Green
Write-Host "  Done."

# Step 3: Build
Write-Step 3 $TotalSteps "Building libobfuscated.dll via Makefile"
Set-Location $ScriptDir

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $MakeExe clean 2>&1 | Out-Null
# Pass USING_CLANG_CL=1 and CC_BASE explicitly because make's sh.exe can't run 'where'
& $MakeExe TARGET_OS=windows BINARY_NAME=libobfuscated USING_CLANG_CL=1 "CC_BASE=clang-cl.exe" 2>&1
$ErrorActionPreference = $prevEAP

$DllPath = Join-Path $ScriptDir "bins\libobfuscated.dll"
$PdbPath = Join-Path $ScriptDir "bins\libobfuscated.pdb"

if (-not (Test-Path $DllPath)) {
    Write-Host "ERROR: DLL not created at $DllPath" -ForegroundColor Red
    exit 1
}

# Verify output
Write-Banner "BUILD SUCCESSFUL"
Write-Host "  Output directory: $ScriptDir\bins"
if (Test-Path $DllPath) {
    $DllSize = (Get-Item $DllPath).Length
    Write-Host "  libobfuscated.dll: $([math]::Round($DllSize/1KB, 1)) KB"
}
if (Test-Path $PdbPath) {
    $PdbSize = (Get-Item $PdbPath).Length
    Write-Host "  libobfuscated.pdb: $([math]::Round($PdbSize/1KB, 1)) KB"
}
