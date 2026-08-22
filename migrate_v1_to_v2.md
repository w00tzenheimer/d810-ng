# Manually Migrate D810 Project Config v1 to Config v2

This guide is for users upgrading from D810 0.6.x, including 0.6.6, to
D810 1.0.0 or a 1.0.0 prerelease.

There are two different version numbers involved:

- **D810 1.0.0** is the plugin release.
- **Config v2** is the project JSON format used by D810 1.0.0.

D810 1.0.0 does not execute legacy `ins_rules` and `blk_rules` projects. Their
presence is rejected even when the arrays are empty. The runtime accepts only
projects with a non-empty
`additional_configuration.pipeline_v2`. Migration is deliberately offline and
fail-closed: D810 will not rewrite a project during startup and the migration
tool will not silently discard an unsupported rule or option.

The standalone `d810-migrations` package described for a future release does
not exist yet. Until it is published, run the migration tool from the source
tree for the exact D810 1.0.0 build you are installing.

## Before you start

You need:

1. The D810 1.0.0 source tree or release source archive.
2. Python 3.11 or newer with `typing-extensions` installed. This is the only
   declared runtime dependency of the current `d810-ng` package.
3. The path to IDA's user directory.
4. A backup location outside IDA's active `cfg/d810` directory.

Close every running IDA process before replacing configuration files. IDA may
otherwise retain an old project in memory or save unrelated configuration into
the same user directory while you are working.

Do not run the converter from a random branch or from D810 0.6.6. The converter
and its canonical templates must come from the D810 version that will consume
the result.

## 1. Find the active D810 project directory

In IDA's Python console, run:

```python
import ida_diskio
print(ida_diskio.get_user_idadir())
```

Append `cfg/d810` to the printed directory. That is the writable project
directory D810 scans. A user project in this directory overrides a bundled
project with the same filename.

For example, if IDA prints:

```text
/Users/alice/.idapro
```

then the D810 project directory is:

```text
/Users/alice/.idapro/cfg/d810
```

Do not assume the example path is correct for your installation. Use the path
reported by `ida_diskio.get_user_idadir()`.

## 2. Set paths for the commands

### macOS or Linux

```bash
export D810_SOURCE="/path/to/the/d810-1.0.0-source-tree"
export D810_CONFIG_DIR="/path/printed/by/ida/cfg/d810"
export D810_MIGRATOR="$D810_SOURCE/tools/migrations/migrate_project_config_v2.py"
```

Confirm that the expected files exist:

```bash
test -f "$D810_MIGRATOR"
find "$D810_CONFIG_DIR" -maxdepth 1 -type f -name '*.json' -print
```

### Windows PowerShell

```powershell
$D810Source = "C:\path\to\the\d810-1.0.0-source-tree"
$D810ConfigDir = "C:\path\printed\by\ida\cfg\d810"
$D810Migrator = Join-Path $D810Source "tools\migrations\migrate_project_config_v2.py"
```

Confirm that the expected files exist:

```powershell
Test-Path -LiteralPath $D810Migrator
Get-ChildItem -LiteralPath $D810ConfigDir -Filter *.json -File
```

Stop if the migrator does not exist or the configuration directory is not the
one reported by IDA.

## 3. Back up the complete directory

The current migration command does **not** create a backup automatically.
Create one before previewing or replacing anything.

The backup must live outside the active `cfg/d810` directory. If backup files
ending in `.json` remain inside that directory, D810 and `--check` will treat
them as active projects.

### macOS or Linux

```bash
export D810_BACKUP_DIR="${D810_CONFIG_DIR}.pre-v1.0.0.$(date +%Y%m%d-%H%M%S)"
cp -a "$D810_CONFIG_DIR" "$D810_BACKUP_DIR"
find "$D810_BACKUP_DIR" -maxdepth 1 -type f -name '*.json' -print
```

### Windows PowerShell

```powershell
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$D810BackupDir = "$D810ConfigDir.pre-v1.0.0.$Timestamp"
Copy-Item -LiteralPath $D810ConfigDir -Destination $D810BackupDir -Recurse
Get-ChildItem -LiteralPath $D810BackupDir -Filter *.json -File
```

Do not continue until the backup contains the expected project files.

## 4. Audit the directory without writing

From the D810 1.0.0 source root, run:

### macOS or Linux

```bash
cd "$D810_SOURCE"
python3 tools/migrations/migrate_project_config_v2.py "$D810_CONFIG_DIR" --check
status=$?
printf 'migration audit exit status: %s\n' "$status"
```

### Windows PowerShell

```powershell
Set-Location -LiteralPath $D810Source
Write-Host "The current directory audit uses POSIX stable-directory APIs."
Write-Host "Audit Windows projects one file at a time using Step 5."
```

Exit statuses are:

| Status | Meaning |
|---:|---|
| `0` | Every discovered JSON project is already canonical config v2. |
| `1` | At least one project needs migration, cannot be migrated, is malformed, or could not be inspected safely. |
| `2` | The command line is invalid. |

Status `1` is the expected result when legacy projects are present. Read every
diagnostic. The audit reports files in stable filename order and writes
nothing.

The directory audit requires POSIX stable directory-handle operations and is
not the supported Windows path in this source-only release. On Windows, audit
each regular JSON file individually using the preview procedure below. On
macOS or Linux, if the tool reports that stable directory enumeration or child
opening is unsupported, use the same per-file fallback. Do not weaken the
safety check or replace the tool with an unreviewed bulk-edit script.

## 5. Preview one project

Running the converter without `--output` or `--in-place` prints canonical JSON
to stdout and leaves the source untouched.

### macOS or Linux

```bash
export PROJECT="$D810_CONFIG_DIR/example.json"
python3 "$D810_MIGRATOR" "$PROJECT" > /tmp/example.config-v2.preview.json
```

### Windows PowerShell

```powershell
$Project = Join-Path $D810ConfigDir "example.json"
$Preview = Join-Path $env:TEMP "example.config-v2.preview.json"
py -3.11 $D810Migrator $Project --output $Preview
if ($LASTEXITCODE -ne 0) { throw "Migration preview failed" }
```

Replace `example.json` with the actual project filename. The filename matters:
the migrator recognizes historical bundled portfolios using both the basename
and an exact document fingerprint. A customized file with a familiar name does
not receive a stock mapping unless its content also matches a known historical
portfolio.

For a no-clobber preview file beside a separate review directory, prefer
`--output`:

### macOS or Linux

```bash
mkdir -p "$D810_BACKUP_DIR/migrated-preview"
python3 "$D810_MIGRATOR" "$PROJECT" \
  --output "$D810_BACKUP_DIR/migrated-preview/$(basename "$PROJECT")"
```

### Windows PowerShell

```powershell
$PreviewDir = Join-Path $D810BackupDir "migrated-preview"
New-Item -ItemType Directory -Path $PreviewDir -Force | Out-Null
$PreviewProject = Join-Path $PreviewDir (Split-Path $Project -Leaf)
py -3.11 $D810Migrator $Project --output $PreviewProject
if ($LASTEXITCODE -ne 0) { throw "Migration preview failed" }
```

`--output` refuses to overwrite an existing path. That refusal includes an
existing regular file, directory, or dangling symlink.

## 6. Inspect the generated pipeline

A successful migration should have these structural properties:

- No top-level `ins_rules`.
- No top-level `blk_rules`.
- No `pipeline_v2_mode` or `config_v2_canary` routing markers.
- A non-empty `additional_configuration.pipeline_v2` array.
- Every pipeline row has a stable `pass_id` and typed pass configuration.

Print the ordered pass IDs:

```bash
python3 - "/path/to/example.config-v2.preview.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
document = json.loads(path.read_text(encoding="utf-8-sig"))
assert "ins_rules" not in document
assert "blk_rules" not in document
additional = document["additional_configuration"]
pipeline = additional["pipeline_v2"]
assert isinstance(pipeline, list) and pipeline
for index, entry in enumerate(pipeline):
    print(f"{index:02d}: {entry['pass_id']}")
PY
```

The PowerShell equivalent is:

```powershell
$Document = Get-Content -LiteralPath $Preview -Raw | ConvertFrom-Json
if ($null -ne $Document.ins_rules -or $null -ne $Document.blk_rules) {
    throw "Legacy rule arrays remain in the preview"
}
$Pipeline = $Document.additional_configuration.pipeline_v2
if ($null -eq $Pipeline -or $Pipeline.Count -eq 0) {
    throw "The migrated pipeline is empty"
}
for ($Index = 0; $Index -lt $Pipeline.Count; $Index++) {
    "{0:D2}: {1}" -f $Index, $Pipeline[$Index].pass_id
}
```

Also review the complete JSON. Do not judge equivalence only by counting
passes: one legacy unflattening rule intentionally expands into an ordered
state-machine recovery pipeline.

The generic migrator rejects rather than guesses when it encounters:

- An unknown rule name.
- A rule in the wrong instruction/block section.
- An unsupported or lossy rule option.
- Duplicate ownership of one behavior.
- A partial legacy constant-simplification bundle.
- Active legacy rules mixed with `pipeline_v2`.
- A result that would have an empty pipeline.
- Unowned fields in `additional_configuration`.

If migration fails, keep the original project and its backup. The error names
the failing JSON path, such as `ins_rules[0].name` or a specific option. Do not
delete the named rule merely to make the converter pass; doing so changes the
project's behavior. Preserve a sanitized copy and report the unsupported shape
to D810 maintainers.

## 7. Decide how to handle stock user overrides

A JSON file in the user directory overrides a bundled project with the same
filename.

If you know that a user file is an unchanged copy of a stock D810 project and
you do not intend to pin it, the better upgrade is usually:

1. Preserve it in the external backup.
2. Rename or move the user copy so it no longer ends in `.json` inside
   `cfg/d810`.
3. Allow D810 1.0.0 to use its bundled canonical config-v2 project.

For example:

```bash
mv "$D810_CONFIG_DIR/default_unflattening_ollvm.json" \
   "$D810_CONFIG_DIR/default_unflattening_ollvm.json.pre-v1"
```

Only do this when you know the file was not customized. If it was customized
or you are uncertain, migrate it and retain it as an intentional user
override.

## 8. Replace one customized project atomically

After reviewing the preview and confirming the external backup, replace the
original using `--in-place`:

### macOS or Linux

```bash
python3 "$D810_MIGRATOR" "$PROJECT" --in-place
```

### Windows PowerShell

```powershell
py -3.11 $D810Migrator $Project --in-place
if ($LASTEXITCODE -ne 0) { throw "In-place migration failed" }
```

The tool stages and validates canonical JSON before atomically replacing the
input. On a migration or publication failure, it reports an error and attempts
to preserve the original. The external directory backup remains the recovery
authority.

Repeat the preview, inspection, and in-place steps for each customized project.
There is intentionally no unchecked “rewrite every file” mode.

## 9. Re-run the audit

After migrating or archiving every legacy project on macOS or Linux:

```bash
python3 "$D810_MIGRATOR" "$D810_CONFIG_DIR" --check
```

The desired result is exit status `0` with no output. On Windows or another
platform where directory audit is unsupported, run the converter against each
remaining `.json` file without a write option and confirm that every command
exits `0`. Canonical config-v2 input is normalized idempotently, so this check
does not require changing the files again.

## 10. Start D810 1.0.0 and verify activation

Start IDA and D810, then:

1. Open the D810 project selector.
2. Confirm that every intended migrated project is present.
3. Select each important project at least once.
4. Confirm the pipeline overview renders its pass rows without an unknown pass
   ID warning.
5. Check the D810 log for project-load or config-v2 validation errors.
6. Decompile a small known function to confirm the selected project activates.

The migration is not verified merely because JSON was written. The runtime
must load and activate the migrated project successfully.

## Roll back

If a migrated project does not activate correctly:

1. Close all IDA processes.
2. Move the failed active directory aside.
3. Restore the complete external backup to the original `cfg/d810` path.
4. Keep using D810 0.6.6 while the unsupported migration is investigated, or
   use a known-good bundled D810 1.0.0 config-v2 project.

### macOS or Linux

```bash
mv "$D810_CONFIG_DIR" "${D810_CONFIG_DIR}.failed-migration"
cp -a "$D810_BACKUP_DIR" "$D810_CONFIG_DIR"
```

### Windows PowerShell

```powershell
Move-Item -LiteralPath $D810ConfigDir -Destination "$D810ConfigDir.failed-migration"
Copy-Item -LiteralPath $D810BackupDir -Destination $D810ConfigDir -Recurse
```

Restored legacy projects are usable by D810 0.6.6. D810 1.0.0 will continue to
reject and skip them until they are migrated; it will not run them through a
legacy compatibility path.

## Command reference

```text
python tools/migrations/migrate_project_config_v2.py INPUT
    Print canonical config v2 to stdout. Do not write.

python tools/migrations/migrate_project_config_v2.py INPUT --output OUTPUT
    Create OUTPUT without overwriting an existing destination. Do not modify
    INPUT.

python tools/migrations/migrate_project_config_v2.py INPUT --in-place
    Validate, stage, and atomically replace INPUT.

python tools/migrations/migrate_project_config_v2.py DIRECTORY --check
    Inspect regular *.json files without writing. Exit 1 when migration or
    invalid-project findings exist.
```

Invalid combinations such as `--output --in-place`, `--check --in-place`, or
`--check` with a regular-file input are rejected with exit status `2`.
