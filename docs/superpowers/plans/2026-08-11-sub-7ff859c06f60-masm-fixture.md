# `sub_7FF859C06F60` MASM Fixture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `sub_7FF859C06F60` as a rebuildable MASM fixture with an observed Hodur-like semantic regression and zero-failure Docker acceptance.

**Architecture:** Export the function and referenced data closure from the live IDB into the existing auto-discovered MASM corpus. Prove the old PE lacks the symbol, rebuild every fixture on `reversepc.local`, then derive the final DSL assertions from real IDA 9.3 and 9.4 before/after dumps.

**Tech Stack:** IDA Pro/Hex-Rays MCP, d810 structural MASM exporter, `llvm-ml64`, MSVC `ml64`/`link.exe`, PowerShell, pytest, Docker.

## Global Constraints

- Describe the fixture only as Hodur-like; do not name the source product or binary in tracked test data.
- Preserve every existing MASM export in the rebuilt PE.
- Do not retarget unresolved calls without a proven named import or dependency-free leaf.
- Keep the original source DLL and `src/d810/conf/_tmp_interr_on.json` untracked and untouched.
- Semantic assertions must be copied from observed before/after output, never guessed.
- IDA 9.3, IDA 9.4, and the complete Docker system suite must finish with zero failures.

---

### Task 1: Export and locally validate the function

**Files:**
- Create: `samples/src/masm/sub_7FF859C06F60.asm`

**Interfaces:**
- Consumes: live IDB function `sub_7FF859C06F60` at `0x7FF859C06F60` on MCP port 13340.
- Produces: a self-contained MSVC-COFF MASM source with `PUBLIC sub_7FF859C06F60` and a materialized read-only data closure.

- [ ] **Step 1: Verify the live IDB and function identity**

Call the IDA MCP health endpoint and evaluate:

```python
import ida_funcs, ida_name
ea = ida_name.get_name_ea(idaapi.BADADDR, "sub_7FF859C06F60")
(hex(ea), ida_funcs.get_func(ea) is not None)
```

Expected: `('0x7ff859c06f60', True)`.

- [ ] **Step 2: Export through the structural exporter**

Execute in the live IDA process:

```python
from pathlib import Path
from d810.ui.export_disasm_masm_emit import generate_masm_for_function

target = Path("/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer/samples/src/masm/sub_7FF859C06F60.asm")
text = generate_masm_for_function(
    0x7FF859C06F60,
    materialize_data=True,
    const_data=True,
)
target.write_text(text, encoding="utf-8")
{"path": str(target), "bytes": len(text.encode("utf-8")), "lines": len(text.splitlines())}
```

Expected: a non-empty file containing `PUBLIC sub_7FF859C06F60` and ending in `END`.

- [ ] **Step 3: Assemble locally**

Run:

```bash
/opt/homebrew/opt/llvm/bin/llvm-ml64 /nologo /c \
  /Fo.tmp/sub_7FF859C06F60.obj \
  samples/src/masm/sub_7FF859C06F60.asm
file .tmp/sub_7FF859C06F60.obj
```

Expected: exit 0 and an Intel amd64 COFF object.

- [ ] **Step 4: Record the artifact red gate**

Run:

```bash
llvm-objdump -p samples/bins/libobfuscated.dll | rg 'sub_7FF859C06F60'
```

Expected: exit 1 because the current tracked PE predates the new export.

### Task 2: Register the initial semantic case

**Files:**
- Modify: `tests/system/cases/libobfuscated_comprehensive.py`

**Interfaces:**
- Consumes: the exported function name and tracked Hodur-like profile.
- Produces: one `DAC_MASM_CASES` entry selected by `TestDacMasmFixtures`.

- [ ] **Step 1: Add the initial case**

Add this entry after the existing `sub_7FF85A5CB920` case:

```python
DeobfuscationCase(
    function="sub_7FF859C06F60",
    description=(
        "Hodur-like state-machine fixture exported from a live IDB. "
        "Guards removal of the comparison dispatcher while preserving "
        "the allocated-object initialization and event-handle publication."
    ),
    project="hodur_flag2_s1a_config_v2_canary_constant_simplification.json",
    obfuscated_contains=["0x7E174EE2", "while ( 2 )", "0x78CAFFE"],
    deobfuscated_contains=["0x98", "CreateEventW", "0xEB87C50AC31977ED"],
    deobfuscated_not_contains=["0x7E174EE2", "while ( 2 )", "0x78CAFFE"],
    must_change=True,
    required_rules=[],
    skip_if_function_absent=True,
)
```

- [ ] **Step 2: Verify the pre-build case cannot run against the old PE**

Run the dump command before rebuilding:

```bash
tools/scripts/run_system_tests_docker.sh dump \
  -f sub_7FF859C06F60 \
  -p hodur_flag2_s1a_config_v2_canary_constant_simplification.json \
  -o sub_7FF859C06F60_prebuild_red.txt
```

Expected: failure containing `Function 'sub_7FF859C06F60' not found`.

### Task 3: Rebuild the authoritative PE on reversepc.local

**Files:**
- Modify: `samples/bins/libobfuscated.dll`
- Modify: `samples/bins/libobfuscated.pdb`

**Interfaces:**
- Consumes: the complete current `samples` source tree, including every `src/masm/*.asm` file.
- Produces: a PE/PDB pair exporting the new function and all prior fixture symbols.

- [ ] **Step 1: Create an isolated remote build directory**

Use `G:\codex\d810-lrea-masm-c06f60-20260811` and upload the current `samples` tree by tar-over-SSH. Do not build in the shared plugin checkout.

- [ ] **Step 2: Invoke the authoritative build**

Run `samples/scripts/build_windows.ps1` from the isolated directory with Git `usr/bin` on `PATH`, preserving the script's default all-MASM export discovery.

- [ ] **Step 3: Pull artifacts and validate formats**

Pull `samples/bins/libobfuscated.dll` and `samples/bins/libobfuscated.pdb` by tar-over-SSH, remove only the known PowerShell stdout preamble when present, then run:

```bash
file samples/bins/libobfuscated.dll
head -c 4 samples/bins/libobfuscated.pdb
```

Expected: PE32+ x86-64 DLL and `Micr` PDB header.

- [ ] **Step 4: Verify all exports**

Run:

```bash
llvm-objdump -p samples/bins/libobfuscated.dll | rg \
  'sub_7FF859C06F60|sub_7FF85A5CB920|sub_1815C8C30|sub_7FFD3338C040|Java_dimension_DimensionAPI_getHuzpsbPY'
```

Expected: all five names are present.

### Task 4: Replace provisional strings with observed semantic authority

**Files:**
- Modify: `tests/system/cases/libobfuscated_comprehensive.py`

**Interfaces:**
- Consumes: exact IDA 9.3 and 9.4 before/after dumps from the rebuilt PE.
- Produces: stable cross-SDK `obfuscated_contains`, `deobfuscated_contains`, and `deobfuscated_not_contains` lists.

- [ ] **Step 1: Capture IDA 9.3 output**

Run:

```bash
D810_DOCKER_IMAGE=idapro-9.3 tools/scripts/run_system_tests_docker.sh dump \
  -f sub_7FF859C06F60 \
  -p hodur_flag2_s1a_config_v2_canary_constant_simplification.json \
  -o sub_7FF859C06F60_ida93.txt
```

- [ ] **Step 2: Capture IDA 9.4 output**

Run the same command with `D810_DOCKER_IMAGE=idapro-9.4-speedups:latest` and output `sub_7FF859C06F60_ida94.txt`.

- [ ] **Step 3: Enforce the cross-SDK intersection**

Keep the exact case shown in Task 2 only if every listed string has the declared before/after polarity in both dumps. Remove a provisional string that differs by SDK rendering; add no replacement unless it is visibly present in both dumps. Record the actual instruction and CFG rules reported by both runs as `expected_rules`, leaving `required_rules=[]` unless one rule is semantically mandatory in both SDKs.

- [ ] **Step 4: Run the exact case on both SDKs**

Run `TestDacMasmFixtures` filtered to `sub_7FF859C06F60` under IDA 9.3 and IDA 9.4. Expected: one pass on each SDK, no skip.

### Task 5: Acceptance and commit

**Files:**
- Modify: `graphify-out/*` only through `graphify update .` when tracked by the repository.

**Interfaces:**
- Consumes: the completed fixture, case, and rebuilt artifacts.
- Produces: one verified fixture commit.

- [ ] **Step 1: Run the complete MASM family**

Run `TestDacMasmFixtures` under IDA 9.3. Expected: every MASM case passes.

- [ ] **Step 2: Run the complete Docker system suite**

Run:

```bash
tools/scripts/run_system_tests_docker.sh system \
  -o full_docker_system_sub_7FF859C06F60_20260811.log
```

Expected: zero failures.

- [ ] **Step 3: Run repository boundary gates**

Run Ruff on the changed Python file, `git diff --check`,
`sg scan --config sgconfig.yml --report-style short`,
`PYTHONPATH=src lint-imports --config .importlinter`, and `graphify update .`.

- [ ] **Step 4: Commit the fixture slice**

Stage only the new MASM source, semantic case, and rebuilt PE/PDB artifacts.
Leave the original source DLL and temporary INTERR config unstaged. Commit with:

```bash
git commit -m "test(fixtures): add portable Hodur state-machine case"
```
