param(
    [Parameter(Mandatory = $true)]
    [string]$OutFile,
    [Parameter(Mandatory = $true)]
    [string]$Objects,
    [string]$MasmSources = ""
)

$ErrorActionPreference = "Stop"

$ObjdumpExe = (Get-Command objdump.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
if (-not $ObjdumpExe) {
    $mingwCandidates = @(
        "$Env:HOMEDRIVE$Env:HOMEPATH\scoop\apps\mingw\current\bin\objdump.exe"
    ) + @(
        Get-ChildItem -Path "$Env:HOMEDRIVE$Env:HOMEPATH\scoop\apps\mingw\*\bin\objdump.exe" -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName
    )

    $ObjdumpExe = $mingwCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if (-not $ObjdumpExe) {
    Write-Warning "[generate_auto_exports] objdump.exe not found. Writing empty export list."
    Set-Content -Path $OutFile -Value $null -Encoding ascii
    exit 0
}

$exports = New-Object "System.Collections.Generic.HashSet[string]" ([System.StringComparer]::Ordinal)

$ObjectList = $Objects -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

foreach ($obj in $ObjectList) {
    if (-not (Test-Path $obj)) {
        continue
    }

    $lines = & $ObjdumpExe -t $obj 2>$null
    foreach ($line in $lines) {
        if ($line -notmatch '\(ty\s+20\)\(scl\s+2\)') {
            continue
        }

        $parts = $line.Trim() -split '\s+'
        if ($parts.Length -eq 0) {
            continue
        }

        $symbol = $parts[-1]
        if (
            [string]::IsNullOrWhiteSpace($symbol) -or
            $symbol -match '^(__imp_|__NULL_IMPORT_DESCRIPTOR|_NULL_IMPORT_DESCRIPTOR|@feat\.00|\.)'
        ) {
            continue
        }

        [void]$exports.Add("/EXPORT:$symbol")
    }
}

# MASM sources export only their basename by Makefile convention. Additional
# fixture entry points and call-site oracle anchors must opt in explicitly,
# matching samples/scripts/build_masm.sh. Exporting every PUBLIC symbol would
# leak internal data and labels from large structural fixtures.
$MasmSourceList = $MasmSources -split '\s+' | Where-Object {
    -not [string]::IsNullOrWhiteSpace($_)
}
foreach ($source in $MasmSourceList) {
    if (-not (Test-Path $source)) {
        throw "MASM source '$source' was not found while generating exports"
    }
    foreach ($line in Get-Content -Path $source) {
        if ($line -match '^\s*;\s*D810_EXPORT\s+([A-Za-z0-9_]+)\s*$') {
            [void]$exports.Add("/EXPORT:$($Matches[1])")
            continue
        }
        if ($line -match '^\s*PUBLIC\s+(d810_callsite_[A-Za-z0-9_]+)\s*$') {
            [void]$exports.Add("/EXPORT:$($Matches[1])")
        }
    }
}

$sorted = $exports | Sort-Object
Set-Content -Path $OutFile -Value $sorted -Encoding ascii
Write-Host "[generate_auto_exports] Wrote $($sorted.Count) exports to $OutFile"
