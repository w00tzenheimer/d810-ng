# Remove GlobalConstantInliner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete `GlobalConstantInliner` while preserving its pointer-value rejection and direct flow-level global-load coverage in the consolidated constant-simplification stages.

**Architecture:** The portable global-constness oracle rejects a backend-supplied pointer-like value fact. The Hex-Rays evidence adapter owns IDA address-space probing, and `FoldReadonlyDataRule` owns all supported memory-read shapes and immediate materialization. Legacy registration, configuration, and tests are removed rather than retained as aliases.

**Tech Stack:** Python 3.11+, pytest, IDA 9.x/Hex-Rays microcode, D810 config-v2, ast-grep, import-linter, graphify.

## Global Constraints

- Work only in `/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-case-producer` on branch `diff/lrea-portable-cfg-case-producer`.
- Preserve unrelated and pre-existing worktree changes; the dirty logging fix targets the module being deleted and must not leak into unrelated files.
- Portable packages do not import IDA or infer operating system, file format, or CPU architecture.
- `FoldReadonlyDataRule` is the only memory-read materializer used by `constant-simplification`.
- Do not add ast-grep ignores or import-linter exceptions.
- Every production behavior change follows red-green-refactor TDD.

---

### Task 1: Centralize pointer-like value rejection

**Files:**
- Modify: `src/d810/analyses/value_flow/global_constness.py`
- Modify: `src/d810/backends/hexrays/evidence/global_constness.py`
- Modify: `tests/unit/analyses/value_flow/test_global_constness.py`
- Modify: `tests/system/runtime/backends/hexrays/test_global_constness.py`

**Interfaces:**
- Produces: `GlobalConstEvidence.value_is_pointer_like: bool` and `GlobalConstReason.POINTER_LIKE_VALUE`.
- Consumes: IDA mapping and image-base facts only inside the Hex-Rays adapter.

- [ ] **Step 1: Write portable decision tests** proving an otherwise-safe read is rejected when `value_is_pointer_like=True`, while zero and narrow ordinary values remain governed by the backend fact.
- [ ] **Step 2: Run the portable selector and verify RED** with `pyenv exec python -m pytest -q tests/unit/analyses/value_flow/test_global_constness.py`.
- [ ] **Step 3: Add real-IDA adapter tests** for mapped values, rebased RVAs, BADADDR, normal constants, and safe handling of invalid segment lookup inputs.
- [ ] **Step 4: Run the adapter selector and verify RED** with the repository IDA system-test wrapper.
- [ ] **Step 5: Implement the evidence field, rejection reason, and Hex-Rays pointer fact capture** by moving the existing heuristic behavior out of the flow module.
- [ ] **Step 6: Re-run both selectors and verify GREEN**.

### Task 2: Port the direct flow load shape into FoldReadonlyDataRule

**Files:**
- Modify: `src/d810/optimizers/microcode/instructions/peephole/fold_readonlydata.py`
- Modify: `tests/system/runtime/expr/test_opaque_table_folding.py`
- Modify: `tests/system/runtime/test_global_const_inline.py`

**Interfaces:**
- Consumes: `decide_hexrays_global_read()` with pointer filtering already applied.
- Produces: whole-instruction folding for `m_ldx` with `ins.r.t == mop_v`.

- [ ] **Step 1: Write a failing behavior test** that constructs the direct `ldx` shape and expects an immediate-load replacement rather than an in-place address mutation.
- [ ] **Step 2: Run the focused selector and verify RED**.
- [ ] **Step 3: Extend the direct-load EA resolver** to recognize the direct address-operand form and route it through the existing whole-load materializer.
- [ ] **Step 4: Convert the RVA decompilation case and maturity assertions** to target Simplify constants and FoldReadonlyDataRule.
- [ ] **Step 5: Re-run focused selectors and verify GREEN**.

### Task 3: Delete the legacy implementation and identity

**Files:**
- Delete: `src/d810/optimizers/microcode/flow/constant_prop/global_const_inline.py`
- Modify: `src/d810/optimizers/microcode/flow/__init__.py`
- Modify: `src/d810/passes/legacy_flow_rules.py`
- Modify: `src/d810/passes/pipeline_v2_hook_bridge.py`
- Modify: `src/d810/conf/default_instruction_only.json`
- Modify: `src/d810/conf/flatfold.json`
- Modify: `src/d810/conf/example_libobfuscated.json`
- Modify: affected pass/config/catalog tests and sample comments
- Delete or replace: class-specific runtime tests

**Interfaces:**
- Removes: `GlobalConstantInliner`, `global-constant-inliner`, and `global_const_inline`.

- [ ] **Step 1: Update pass/config tests** to require the legacy ID to be unregistered and unbuildable.
- [ ] **Step 2: Run focused pass/config tests and verify RED**.
- [ ] **Step 3: Remove the module, imports, registry rows, conflict checks, config entries, and obsolete tests**.
- [ ] **Step 4: Update generic fixture comments and active tests** to name Simplify constants.
- [ ] **Step 5: Run focused pass/config/runtime tests and verify GREEN**.
- [ ] **Step 6: Search for removed identities** and allow only historical design/plan prose where explicitly useful.

### Task 4: Full verification and graph refresh

**Files:**
- Update: `graphify-out/*` through `graphify update .`

**Interfaces:**
- Produces: verified branch state with the graph synchronized to source.

- [ ] **Step 1: Run focused and broad pytest suites** for constness, peephole, passes, configuration, and runtime behavior.
- [ ] **Step 2: Run `sg scan --config sgconfig.yml --report-style short`** from the target worktree.
- [ ] **Step 3: Run `PYTHONPATH=src lint-imports --config .importlinter`** from the target worktree.
- [ ] **Step 4: Run `graphify update .`** and inspect the resulting diff/status.
- [ ] **Step 5: Review the complete diff** for deletion completeness, accidental unrelated changes, and preservation of the user's worktree state.
