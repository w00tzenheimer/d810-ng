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
$SamplesDir = Split-Path -Parent $ScriptDir

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

# Find make.exe (prefer non-shim binary when available)
$MakeCandidates = @(Get-Command make.exe -All -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
$MakeExe = $MakeCandidates | Where-Object { $_ -notmatch '\\shims\\' } | Select-Object -First 1
if (-not $MakeExe) {
    $MakeExe = $MakeCandidates | Select-Object -First 1
}
if (-not $MakeExe) {
    $ScoopCandidates = @(
        Get-ChildItem -Path "$Env:HOMEDRIVE$Env:HOMEPATH\scoop\apps\make\*" -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne "current" } |
            ForEach-Object { Join-Path $_.FullName "bin\make.exe" } |
            Where-Object { Test-Path $_ }
    )
    $MakeExe = $ScoopCandidates | Select-Object -Last 1
}
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
Set-Location $SamplesDir

# Prefer a real Git bash shell path for GNU make recipes.
$RealSh = $null
$GitShCandidates = @(
    Get-ChildItem -Path "$Env:HOMEDRIVE$Env:HOMEPATH\scoop\apps\git\*" -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne "current" } |
        ForEach-Object { Join-Path $_.FullName "usr\bin\sh.exe" } |
        Where-Object { Test-Path $_ }
)
if ($GitShCandidates.Count -gt 0) {
    $RealSh = $GitShCandidates[-1]
}

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
if ($RealSh) {
    & $MakeExe clean "SHELL=$RealSh" 2>&1 | Out-Null
} else {
    & $MakeExe clean 2>&1 | Out-Null
}
# Pass USING_CLANG_CL=1 and CC_BASE explicitly because make's sh.exe can't run 'where'
$makeArgs = @("TARGET_OS=windows", "BINARY_NAME=libobfuscated", "USING_CLANG_CL=1", "CC_BASE=clang-cl.exe")
if ($RealSh) {
    $makeArgs += "SHELL=$RealSh"
}
& $MakeExe @makeArgs 2>&1
$ErrorActionPreference = $prevEAP

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed (make exited with code $LASTEXITCODE)" -ForegroundColor Red
    exit $LASTEXITCODE
}

$DllPath = Join-Path $SamplesDir "bins\libobfuscated.dll"
$PdbPath = Join-Path $SamplesDir "bins\libobfuscated.pdb"

if (-not (Test-Path $DllPath)) {
    Write-Host "ERROR: DLL not created at $DllPath" -ForegroundColor Red
    exit 1
}

# Verify output
Write-Banner "BUILD SUCCESSFUL"
Write-Host "  Output directory: $SamplesDir\bins"
if (Test-Path $DllPath) {
    $DllSize = (Get-Item $DllPath).Length
    Write-Host "  libobfuscated.dll: $([math]::Round($DllSize/1KB, 1)) KB"
}
if (Test-Path $PdbPath) {
    $PdbSize = (Get-Item $PdbPath).Length
    Write-Host "  libobfuscated.pdb: $([math]::Round($PdbSize/1KB, 1)) KB"
}
