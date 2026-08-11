# `sub_7FF859C06F60` MASM Fixture Design

## Goal

Turn `sub_7FF859C06F60` into a rebuildable, portable MASM fixture whose
deobfuscation behavior is enforced by the tracked system-test corpus. The
fixture description will identify only the Hodur-like obfuscation family and
will not name the source product or binary.

## Fixture construction

Use the structural exporter against the live IDB on MCP port 13340. Export the
function as `samples/src/masm/sub_7FF859C06F60.asm` with both
`materialize_data=True` and `const_data=True`, preserving the real instruction
stream and placing the referenced data closure in a read-only `CONST` segment.

Do not invent call targets or rewrite unresolved internal calls. Retargeting is
allowed only if the exporter proves that a target is a named import or a
dependency-free leaf required for the semantic oracle. Validate the raw export
with `llvm-ml64` before any remote build.

## Regression authority

Register the fixture in `DAC_MASM_CASES` with
`skip_if_function_absent=True`. Use the existing
`hodur_flag2_s1a_config_v2_canary_constant_simplification.json` project unless
the observed run proves that a different tracked Hodur-like profile is the
actual authority.

The case starts red because the export is not yet present in
`libobfuscated.dll`. Semantic assertions must come from an observed before and
after pseudocode dump; no expected string, rule, or completion claim may be
guessed. The case must require a real change and preserve recognizable semantic
effects while excluding the observed dispatcher residue.

## Authoritative build

Copy the current `samples` sources to an isolated directory on
`reversepc.local` and invoke `samples/scripts/build_windows.ps1`. Build every
MASM fixture, not only the new symbol, so the rebuilt PE retains all existing
exports. Pull back `libobfuscated.dll` and `libobfuscated.pdb`, verify their
formats and export table, and keep the locally built Mach-O artifact unchanged
unless fixture-source changes require rebuilding it.

The original source DLL and the temporary INTERR configuration remain
untracked and untouched.

## Verification

1. Assemble the fixture locally with `llvm-ml64`.
2. Verify the new export and all existing MASM exports in the rebuilt PE.
3. Run the exact regression on IDA 9.3 and IDA 9.4.
4. Run the entire Docker system suite with zero failures.
5. Run Ruff, `git diff --check`, ast-grep, import-linter, and
   `graphify update .`.

## Commit boundary

After all gates pass, commit the MASM source, semantic case, and authoritative
rebuilt PE/PDB artifacts together as one fixture commit. Any production repair
revealed by the new fixture must be test-driven and committed separately before
the fixture/artifact commit.
