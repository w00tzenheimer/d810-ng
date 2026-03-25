# Execution Policy Redesign: Replace `tolerate_verify_failure` Bool

**Ticket**: d81-3hdl
**Branch**: `structure-recovery-pass`
**Date**: 2026-03-25
**Status**: PLAN

## Problem

`tolerate_verify_failure: bool` on `IDAIRTranslator` is too broad. It was introduced to
let `StateConstantReturnFixupStrategy` NOP stale `m_xdu state_var → return_slot` feeders
without being aborted by INTERR 50846 (transient undefined-use that IDA resolves at later
maturities). The flag works for that narrow case but has no type-level enforcement: any
future strategy can opt into "verifier failure is okay" without restriction, turning
structural CFG mutations into silent corruption.

Current mitigations (as of `83fc15af`):
- A step-type guard in `lower()` rejects plans with non-NOP steps when the flag is set.
- The flag is reset per stage in `executor._execute_stage()` from fragment metadata.

These are comments-and-discipline fixes, not architecture.

## Option A — Dedicated cleanup lowering path (Best)

Create a second entry point on `IDAIRTranslator` (or a sibling class) that only accepts
`PatchNopInstructions` / `PatchZeroStateWrite` steps and is structurally incapable of
applying CFG edits.

```python
# New method — only reachable for NOP cleanup plans
def lower_nop_cleanup(self, patch_plan: PatchPlan, mba) -> int:
    """NOP-only path. Tolerates transient verify failure. Rejects any non-NOP step."""
    _ALLOWED = (PatchNopInstructions, PatchZeroStateWrite)
    if any(not isinstance(s, _ALLOWED) for s in patch_plan.steps):
        raise TypeError("lower_nop_cleanup: non-NOP steps are forbidden")
    # apply without rollback, tolerate verify failure
    ...
```

- Main `lower()` stays strict (rollback enabled, verify fatal).
- Executor routes cleanup-family plans to `lower_nop_cleanup` based on fragment family or metadata.
- No flag on translator; enforcement is structural.

**Pros**: Strongest guarantee. Future misuse is a call-site error, not a silent flag.
**Cons**: Duplicates some `lower()` logic; executor must route correctly; two code paths to maintain.

---

## Option B — `ExecutionPolicy` enum on `PatchPlan` (Second-best)

Add a field to `PatchPlan` (frozen dataclass) and enforce in `lower()`.

```python
class ExecutionPolicy(str, Enum):
    STRICT = "strict_cfg"
    NOP_CLEANUP_RELAXED = "nop_cleanup_relaxed"

@dataclass(frozen=True)
class PatchPlan:
    ...
    execution_policy: ExecutionPolicy = ExecutionPolicy.STRICT
```

In `lower()`:
- If `execution_policy == NOP_CLEANUP_RELAXED`: assert all steps are NOP-kind, disable rollback, tolerate verify failure.
- Otherwise: strict path, unchanged.

Fragment metadata maps to policy at compile time:
```python
# in executor._execute_stage(), when compiling the plan:
policy = ExecutionPolicy.NOP_CLEANUP_RELAXED if fragment.metadata.get(
    "execution_policy") == "nop_cleanup_relaxed" else ExecutionPolicy.STRICT
patch_plan = compile_patch_plan(modifications, pre_cfg, execution_policy=policy)
```

**Pros**: Policy travels with the plan (not the translator). Type-safe. Single `lower()` path.
**Cons**: `PatchPlan` is frozen — requires `compile_patch_plan` to accept a policy arg. Propagation chain is longer (fragment metadata → executor → compile_patch_plan → PatchPlan → lower).

---

## Option C — Rename + enforce (minimal churn)

Keep current bool but:
- Rename `tolerate_verify_failure` → `_nop_cleanup_only_tolerate_verify`
  (long name discourages casual reuse)
- The existing step-type guard in `lower()` already enforces NOP-only when the flag is set.
- Add a comment in `IDAIRTranslator.__init__` explaining this is only for NOP cleanup paths.

**Pros**: Zero churn. Already has the enforcement.
**Cons**: Still a flag. Doesn't prevent reuse via metadata key copy-paste. Discipline-dependent long-term.

---

## Option D — Cleanup subtype split on strategy family (Cleaner architecture)

Split `FAMILY_CLEANUP` into two subtypes in `strategy.py`:
```python
FAMILY_CLEANUP_STRICT = "cleanup_strict"     # verifier failure fatal, CFG edits OK
FAMILY_CLEANUP_NOP    = "cleanup_nop_only"   # NOP-only, transient verify OK
```

Executor routes by family:
```python
if fragment.family == FAMILY_CLEANUP_NOP:
    result = self._apply_nop_cleanup_stage(fragment, ...)
else:
    result = self._apply_strict_stage(fragment, ...)
```

`_apply_nop_cleanup_stage` uses `lower_nop_cleanup` (Option A) or the enum policy (Option B).

**Pros**: Most readable at the strategy level. Family name communicates intent to strategy authors.
**Cons**: Requires changes across strategy.py, executor.py, and the translator. Largest diff.

---

## Recommendation

**Short-term**: Option C (already done in `83fc15af`, step-type guard present).

**Target architecture**: Option B (policy enum on PatchPlan).
- Lower churn than A or D.
- Policy travels with the plan, not the translator — easier to audit.
- Upgrade path: rename fragment metadata key from `tolerate_verify_failure` to `execution_policy: "nop_cleanup_relaxed"` and wire through `compile_patch_plan`.

**Naming** (from user recommendation):
- `ExecutionPolicy.STRICT` — default, current behavior
- `ExecutionPolicy.NOP_CLEANUP_RELAXED` — transient verify OK, NOP-only enforced

**Not recommended**: generic `bool` on translator (current shape), `best_effort`, `safe_mode`, or any effect-oriented name.

---

## Files to change (for Option B)

| File | Change |
|-|-|
| `src/d810/cfg/plan.py` | Add `ExecutionPolicy` enum; add `execution_policy` field to `PatchPlan`; update `compile_patch_plan` signature |
| `src/d810/hexrays/mutation/ir_translator.py` | Replace `tolerate_verify_failure` bool with enum check; remove per-stage reset |
| `src/d810/optimizers/microcode/flow/flattening/hodur/executor.py` | Pass `execution_policy` from fragment metadata to `compile_patch_plan` |
| `src/d810/optimizers/microcode/flow/flattening/hodur/strategies/state_constant_return_fixup.py` | Change metadata key from `tolerate_verify_failure` to `execution_policy: "nop_cleanup_relaxed"` |
| `tests/system/runtime/hexrays/test_ir_translator.py` | Update regression tests |

## Regressions to write before implementation

1. `test_tolerate_verify_failure_rejects_cfg_edits` — plan with `PatchRedirectGoto` + flag → `lower()` returns 0
2. `test_tolerate_verify_failure_allows_nop_only` — plan with only `PatchNopInstructions` + flag → proceeds past guard
3. System-level: sub_7FFD AFTER pseudocode must not contain `0x4C77464F` or `0x5644FD01B1049C4B`
