param(
    [Parameter(Mandatory = $true)]
    [string]$OutFile,
    [Parameter(Mandatory = $true)]
    [string]$Objects
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

$sorted = $exports | Sort-Object
Set-Content -Path $OutFile -Value $sorted -Encoding ascii
Write-Host "[generate_auto_exports] Wrote $($sorted.Count) exports to $OutFile"
