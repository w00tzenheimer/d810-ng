# Constant Simplification Global Annotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the existing `constant-simplification` operation persist safe whole-table `const` types even when a runtime index prevents computing a concrete read address.

**Architecture:** Add an IDA-free item-level decision beside the concrete-read oracle, then add a Hex-Rays annotation backend with IDB-local ownership receipts. Defined items come from data xrefs; undefined dynamic tables come from bounded `ldx` microcode footprints. The existing public bundle enables persistence on its private memory rule, while direct legacy activation leaves it disabled.

**Tech Stack:** Python 3.11+, pytest, IDA 9.x/Hex-Rays hooks, IDAPython type/xref/netnode APIs, config-v2, ast-grep, import-linter, graphify.

**Status:** Implemented and verified on 2026-08-03. The realized integration
uses the private memory rule's microcode callbacks rather than a flowchart redo;
the design document records that evidence-driven correction.

## Global Constraints

- Work only in `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer` on branch `diff/lrea-portable-cfg-case-producer`.
- Keep `constant-simplification` as the only public constant operation.
- Portable analysis and pass packages must not import IDA or Hex-Rays.
- Classification must not branch on OS, binary format, architecture, or segment name.
- `allow_executable_readonly` remains very dangerous, defaults to false, and never authorizes persistent `const`.
- `aggressive_no_direct_writes` never authorizes persistent `const` on writable memory.
- Never remove user-authored or user-edited type information.
- Legacy rules do not activate the new persistent annotation stage.
- Do not add ast-grep ignores or import-linter exceptions.
- Every production behavior change follows red-green-refactor TDD.

---

### Task 1: Portable item-level constness decision

**Files:**
- Modify: `src/d810/analyses/value_flow/global_constness.py`
- Modify: `tests/unit/analyses/value_flow/test_global_constness.py`

**Interfaces:**
- Consumes: `GlobalItemConstEvidence(item_head, item_end, readable, writable, executable, item_kind, has_direct_write)`.
- Produces: `decide_global_item_const(evidence) -> GlobalItemConstDecision` with `can_persist_const` and a stable `GlobalConstReason`.

- [ ] **Step 1: Write failing decision-table tests**

  Add literal tests for R-only data, R+X data, R+X code, writable data with and without direct writes, invalid bounds, and missing readability. Assert that no test supplies a read width or value.

- [ ] **Step 2: Run the focused test and verify RED**

  Run: `pyenv exec python -m pytest -q tests/unit/analyses/value_flow/test_global_constness.py`

  Expected: collection fails because `GlobalItemConstEvidence` and `decide_global_item_const` do not exist.

- [ ] **Step 3: Implement the immutable item decision**

  Add the evidence and decision dataclasses and apply this precedence: invalid item range, unreadable, write evidence, writable, unsupported item kind, then accept data. Executable permission does not veto a proven data item.

- [ ] **Step 4: Run the focused test and verify GREEN**

  Run the Task 1 command and require zero failures.

### Task 2: Hex-Rays reference discovery and persistent annotation backend

**Files:**
- Create: `src/d810/backends/hexrays/global_const_annotation.py`
- Create: `tests/system/runtime/backends/hexrays/test_global_const_annotation.py`

**Interfaces:**
- Consumes: a function EA and an optional receipt mapping.
- Produces: `annotate_function_global_consts(function_ea, *, receipt_store=None) -> GlobalConstAnnotationReport`.

- [ ] **Step 1: Write a failing real-IDA dynamic-table test**

  Locate `global_const_simple_lookup`, enumerate its data xrefs, and assert the wished-for backend finds the complete `LOOKUP_TABLE` item even though the microcode index is runtime-dependent.

- [ ] **Step 2: Run the supported system-test wrapper and verify RED**

  Run: `tools/scripts/run_system_tests_docker.sh test -w lrea-portable-cfg-case-producer -- tests/system/runtime/backends/hexrays/test_global_const_annotation.py -q`

  Expected: collection fails because the annotation backend does not exist.

- [ ] **Step 3: Implement canonical discovery and type application**

  Enumerate function items and outgoing data xrefs, canonicalize each target with `ida_bytes.get_item_head`, capture permissions/kind/write xrefs over the full range, obtain existing tinfo or the bounded unsigned scalar fallback, and apply top-level const with `TINFO_DEFINITE` only for accepted items.

- [ ] **Step 4: Implement ownership receipts and safe removal**

  Use `d810.core.persistence.Netnode` with a dedicated versioned node. Store original/applied type renderings by item EA. Remove top-level const only when the receipt owns it, the current type still equals the applied rendering, and item evidence now rejects persistence due to writes.

- [ ] **Step 5: Run the backend test and verify GREEN**

  Run the Task 2 command and require zero failures.

### Task 3: Config-v2 activation through the existing memory rule

**Files:**
- Modify: `src/d810/passes/constant_simplification.py`
- Modify: `src/d810/optimizers/microcode/instructions/peephole/fold_readonlydata.py`
- Modify: `tests/unit/passes/test_pipeline_v2_hook_bridge.py`
- Modify: `tests/system/runtime/backends/hexrays/test_global_const_annotation.py`

**Interfaces:**
- Consumes: validated `ConstantSimplificationOptions` from the public config-v2 pass.
- Produces: a bundle-owned `persist_global_const_annotations` setting that is false for direct legacy rule activation.

- [ ] **Step 1: Write failing activation and public-operation tests**

  Assert bundle expansion configures persistence on the memory rule. In the real-IDA test, remove const from the lookup table, decompile once with the operation active, and assert the table becomes const and a repeated backend run is idempotent.

- [ ] **Step 2: Run both focused tests and verify RED**

  Run the unit activation test and the Task 2 Docker command. Require failures for the missing activation field and missing callback behavior.

- [ ] **Step 3: Wire the internal bundle option**

  Set the private memory-rule option in `constant_simplification.py`; keep the rule's schema default false.

- [ ] **Step 4: Add the microcode annotation bridge**

  At `MMAT_CALLS`, annotate defined referenced items once and inspect `ldx` instructions for bounded dynamic table footprints. Keep annotation failures non-fatal and independent of read-folding eligibility.

- [ ] **Step 5: Run focused tests and verify GREEN**

  Re-run both Task 3 tests and require zero failures.

### Task 4: Regression, boundary, and before/after verification

**Files:**
- Modify: `tests/system/runtime/test_constant_simplification_global_reads.py`

**Interfaces:**
- Consumes: the completed public operation.
- Produces: real-IDA evidence that dynamic tables receive persistent const while concrete-read folding remains intact.

- [ ] **Step 1: Add the public-operation regression assertion**

  Extend the consolidated system test to assert that `global_const_simple_lookup` references a canonical array item whose tinfo is const after decompilation with the config-v2 operation active.

- [ ] **Step 2: Run focused unit and system suites**

  Run the portable oracle, pipeline bridge, annotation backend, constant-simplification global-read, and forward-constant-propagation regression tests. Require zero failures.

- [ ] **Step 3: Run architecture-boundary checks**

  Run:

  ```bash
  sg scan --config sgconfig.yml --report-style short
  PYTHONPATH=src lint-imports --config .importlinter
  ```

  Require zero ast-grep findings and 14 kept import contracts.

- [ ] **Step 4: Refresh the knowledge graph**

  Run: `graphify update .`

- [ ] **Step 5: Capture supported before/after evidence**

  Run the real-IDA public-operation regression against `global_const_simple_lookup` through `run_system_tests_docker.sh`. Record the table tinfo before and after and the resulting pseudocode without claiming that an unknown runtime index became one literal.
