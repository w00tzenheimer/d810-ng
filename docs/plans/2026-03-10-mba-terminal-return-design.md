# MBA Terminal Return Detection — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix leaked state constants (`return 0x41FB8FBB`) by detecting MBA-computed exit states that resolve to BST default and redirecting them to the terminal exit target instead.

**Architecture:** In the conditional transition emission loop in `direct_linearization.py` (L1438-1568), when `resolve_target_via_bst()` returns None, try BST root-walk. If the resolved target is the BST default block AND the state is not a known handler state, redirect the conditional arm to the terminal exit target (preserving byte counter). Single file change.

**Tech Stack:** Python, IDA Hex-Rays microcode API, Docker E2E testing

**CRITICAL GOTCHA:** A previous attempt (memory: "BST root-walk fallback at L1440") redirected ALL unresolved conditional transitions via BST root-walk → 646 lines, 140 gotos. Our design is NARROWER: only redirect when BST root-walk resolves to the BST default block (the m_xdu clobber block). All other unresolved transitions still skip.

---

### Task 1: Identify BST default block serial

**Files:**
- Read: `src/d810/optimizers/microcode/flow/flattening/hodur/strategies/direct_linearization.py:1438-1568`
- Read: `src/d810/optimizers/microcode/flow/flattening/hodur/_helpers.py` (find_bst_default_block_snapshot)
- Read: `src/d810/recon/flow/bst_model.py` (BstResult fields)

**Step 1: Understand BST default detection**

Find how `find_bst_default_block_snapshot` is already called in direct_linearization.py (grep shows L1662, L1828). Determine what it returns — this is the "BST default serial" we need to match against.

Check if there's an existing field like `bst_result.bst_default_serial` or if it must be computed. Note the calling convention used at the existing callsites.

**Step 2: Understand terminal exit target**

Find how `find_terminal_exit_target_snapshot` is called (L1598, L1758, L1984, L2166). This returns the return block serial (blk[218]) that does `m_mov rax.8 = %var_8.8` → BLT_STOP.

Note: PTS may have cloned this block. The function returns the ORIGINAL shared entry, which PTS clones reference. Redirecting to the original is fine — PTS cloning happens in a separate pass.

**Step 3: Note handler_state_map access**

`bst_result.handler_state_map` (bst_model.py:15) maps `handler_serial -> state_const`. To check if a state is a known handler state, test `ct.target_state in {v for v in bst_result.handler_state_map.values()}` (values, not keys — keys are serials).

---

### Task 2: Implement MBA terminal return detection

**Files:**
- Modify: `src/d810/optimizers/microcode/flow/flattening/hodur/strategies/direct_linearization.py:1441-1447`

**Step 1: Add helper function**

Add this function as a module-level helper near the top of the file (around L100-120, near other helpers):

```python
def _is_bst_default_terminal(
    resolved_serial: int,
    target_state: int,
    bst_result: "BstResult",
    bst_default_serial: int | None,
) -> bool:
    """Return True when a conditional transition's BST resolution lands on
    the BST default block AND the target state is not a known handler state.

    This detects the OLLVM MBA off-by-one pattern where computed states
    (e.g., 0x6E958F9A) deliberately fall through all BST comparisons to the
    default return block, clobbering the return slot via m_xdu.
    """
    if bst_default_serial is None:
        return False
    if resolved_serial != bst_default_serial:
        return False
    # Only treat as terminal if the state is NOT a known handler entry
    known_states = set(bst_result.handler_state_map.values())
    return target_state not in known_states
```

**Step 2: Compute BST default serial and terminal target once before the handler loop**

Find where the main handler loop begins (around L1300-1350). Before the loop, add:

```python
# Pre-compute BST default serial for MBA terminal return detection
_bst_default_serial: int | None = None
_bst_default_snap = find_bst_default_block_snapshot(fg, dispatcher_serial)
if _bst_default_snap is not None:
    _bst_default_serial = _bst_default_snap  # or .serial depending on return type

# Pre-compute terminal exit target
_terminal_exit_target: int | None = find_terminal_exit_target_snapshot(
    fg, dispatcher_serial, sm_blocks
)
```

Check the return type of `find_bst_default_block_snapshot` — it may return a serial (int) or a snapshot object. Match usage at existing callsites (L1662, L1828).

**Step 3: Replace the `ct_target is None` skip block (L1441-1447)**

Replace:
```python
                    if ct_target is None:
                        logger.info(
                            "CONDITIONAL_TRANSITION_SKIP: handler=blk[%d] "
                            "target_state=0x%X no BST resolution",
                            ct.handler_entry, ct.target_state,
                        )
                        continue
```

With:
```python
                    if ct_target is None:
                        # Try BST root-walk fallback — but ONLY redirect if
                        # it resolves to the BST default block (MBA terminal
                        # return pattern).  Do NOT redirect for any other
                        # unresolved target — that causes 646/140 regression.
                        _ct_bst_resolved: int | None = None
                        if _bst_default_serial is not None:
                            _ct_bst_resolved = resolve_exit_via_bst_default_snapshot(
                                fg, dispatcher_serial, ct.target_state,
                            )
                        if (
                            _ct_bst_resolved is not None
                            and _terminal_exit_target is not None
                            and _is_bst_default_terminal(
                                _ct_bst_resolved,
                                ct.target_state,
                                bst_result,
                                _bst_default_serial,
                            )
                        ):
                            logger.info(
                                "MBA_TERMINAL_RETURN: handler=blk[%d] "
                                "branch=blk[%d] arm=%d state=0x%X "
                                "resolved_to_bst_default=blk[%d] -> "
                                "redirect to terminal_exit=blk[%d]",
                                ct.handler_entry, ct.branch_block,
                                ct.branch_arm, ct.target_state,
                                _ct_bst_resolved, _terminal_exit_target,
                            )
                            # Override ct_target with terminal exit
                            ct_target = _terminal_exit_target
                            # Fall through to the existing redirect logic
                            # (arm=1 emits RedirectBranch, arm=0 defers)
                        else:
                            logger.info(
                                "CONDITIONAL_TRANSITION_SKIP: handler=blk[%d] "
                                "target_state=0x%X no BST resolution "
                                "(bst_resolved=%s, is_default=%s)",
                                ct.handler_entry, ct.target_state,
                                _ct_bst_resolved,
                                _ct_bst_resolved == _bst_default_serial
                                if _ct_bst_resolved is not None else "N/A",
                            )
                            continue
                    ct.target_handler = ct_target
```

**Key design note:** By setting `ct_target = _terminal_exit_target` and falling through to the existing arm-aware redirect logic (L1499-1527), we reuse ALL existing guards (edge claim check, no-op check, duplicate arm check) and the arm=0/arm=1 branching. No duplication of redirect logic.

**Step 4: Commit**

```bash
git add src/d810/optimizers/microcode/flow/flattening/hodur/strategies/direct_linearization.py
git commit -m "feat(hodur): detect MBA terminal returns in conditional transitions

When a conditional transition's target state resolves to the BST default
block (MBA off-by-one pattern), redirect the arm to the terminal exit
target instead. This preserves the byte counter in the return slot,
eliminating leaked state constants (return 0x41FB8FBB).

Guard: ONLY fires for BST-default resolution. All other unresolved
conditional transitions still skip (avoids 646/140 goto regression
from previous root-walk fallback attempt)."
```

---

### Task 3: Docker E2E verification

**Step 1: Run sub_7FFD docker dump**

```bash
./tools/scripts/run_system_tests_docker.sh dump -f sub_7FFD3338C040 -p hodur_flag2.json -o sub7FFD_mba_terminal.txt -l
```

**Step 2: Check AFTER pseudocode for leaked constants**

In `.tmp/sub7FFD_mba_terminal.txt`:
- Search for `return 0x41FB8FBB` — expected: 0 occurrences (was 2)
- Search for `return 0x432DC789` — expected: 1 occurrence (separate issue, unchanged)
- Search for `MBA_TERMINAL_RETURN` log lines — expected: 2+ hits (v53==4 and v53==5 arms)
- Record AFTER metrics: lines/returns/whiles/gotos/calls

**Step 3: Run hodur_func regression check**

```bash
./tools/scripts/run_system_tests_docker.sh dump -f hodur_func -p example_hodur.json -o hodur_mba_terminal.txt -l
```

Verify: 114/3/0/1 (no regression).

**Step 4: Check PTS still fires**

In the sub_7FFD log output, search for:
- `[pts-strategy]` — should still show 10 anchors
- `PTS group applied` — should still show SUCCESS
- No new `SUCC_MISMATCH` errors from PTS stage

**Step 5: Update E2E baselines if metrics changed**

If sub_7FFD metrics changed from 358/9/2/6:
```bash
# Edit tests/system/e2e/test_hodur_baselines.py with new expected values
# Then run:
pytest tests/system/e2e/test_hodur_baselines.py -v
```

**Step 6: Commit baseline update**

```bash
git add tests/system/e2e/test_hodur_baselines.py
git commit -m "test(hodur): update E2E baselines after MBA terminal return fix"
```

---

### Task 4: Edge case audit (optional)

**Step 1: Verify no false positives on other test functions**

Run docker dumps for any other hodur-covered functions and verify no regressions. The `_is_bst_default_terminal` guard should prevent false positives because:
- It only fires when BST resolution lands on the SPECIFIC default block
- It only fires when the target state is NOT a known handler state
- hodur_func's PTS bucket is `benign_shared_suffix` — no conditional transitions resolve to BST default

**Step 2: Check conditional transition counts**

In the sub_7FFD log, compare:
- Previous: "17 detected, 13 redirected"
- After: should be "17 detected, 13+N redirected" where N = MBA terminal returns

---

## Reference: Key file locations

| What | Where |
|-|-|
| Conditional transition emission loop | `direct_linearization.py:1438-1568` |
| `resolve_target_via_bst` | `bst_model.py:27-52` |
| `resolve_exit_via_bst_default_snapshot` | `_helpers.py:194-281` |
| `find_bst_default_block_snapshot` | `_helpers.py` (grep for def) |
| `find_terminal_exit_target_snapshot` | `_helpers.py` (grep for def) |
| `handler_state_map` | `bst_model.py:15` (BstResult dataclass field) |
| PTS strategy | `private_terminal_suffix.py:96-466` |
| Docker dump script | `tools/scripts/run_system_tests_docker.sh` |
| E2E baselines | `tests/system/e2e/test_hodur_baselines.py` |

## Success criteria

1. `return 0x41FB8FBB` drops from 2 to 0
2. hodur_func: no regression (114/3/0/1)
3. PTS: 10 anchors, 10 clones, SUCCESS (unaffected)
4. No new gotos explosion (guard prevents 646/140 regression)
5. `MBA_TERMINAL_RETURN` log lines confirm detection
