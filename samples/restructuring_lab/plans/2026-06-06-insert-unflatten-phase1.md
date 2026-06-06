# Insert-Based Unflattening Phase 1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reconstruct a mini flattened function's linear CFG by *inserting* private blocks (not patching/cloning), proving `mba.verify()`-clean + clean render — the safe replacement for the abandoned clone-and-replay path.

**Architecture:** A new C fixture compiles to a 3-handler dispatcher loop. A `tests/system/runtime/` test installs a one-shot hook at `MMAT_GLBOPT1`, builds a plan of `DeferredGraphModifier.queue_create_and_redirect` ops (one per handler transition, `old_target_serial=dispatcher`), applies it through the verify+rollback path, then asserts the pseudocode renders as a linear chain with no dispatcher loop.

**Tech Stack:** IDA Hex-Rays (`ida_hexrays`), d810 `DeferredGraphModifier`, the restructuring-lab Docker build (`build_lab.sh`) + `run_system_tests_docker.sh test` harness. Spec: `samples/restructuring_lab/specs/2026-06-06-insert-unflatten-phase1.md`.

**Execution note:** All IDA-runtime tasks (2–5) run in the Docker IDA harness, not locally. The TDD loop is "write the assertion, run it in the harness, watch it fail, implement, run again." Identify blocks by **EA** (serials are maturity-local; project rule), then resolve to live serials.

---

## File Structure

- `samples/restructuring_lab/c/lab_flat_mini.c` — new fixture; one function `lab_flat_mini`, a 3-handler large-const dispatcher loop. Sole responsibility: be a minimal flattened host.
- `samples/bins/restructuring_lab.dll` — rebuilt to include the fixture; re-tracked.
- `tools/hexrays_structuring_lab/registry.json` — one new `compiled_cfg_validated` case `flat_mini` recording the flattened shape (optional but keeps the lab's gate discipline).
- `tests/system/runtime/hexrays/test_insert_unflatten_mini.py` — new live mutate-and-render test. Sole responsibility: drive + assert the Phase-1 insert.
- No `src/d810/` changes (uses existing `queue_create_and_redirect`).

---

## Task 1: Mini flattened fixture + build + gate

**Files:**
- Create: `samples/restructuring_lab/c/lab_flat_mini.c`

- [ ] **Step 1: Write the fixture**

```c
/*
 * Restructuring-lab: minimal flattened host for insert-based unflattening (Phase 1).
 *
 * 3 linear handlers behind a large-const state dispatcher. True CFG is
 * entry -> H0 -> H1 -> H2 -> return; compiled CFG funnels every handler through
 * the dispatcher. Large 32-bit states avoid the MIN_STATE_CONSTANT floor.
 * See specs/2026-06-06-insert-unflatten-phase1.md.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

EXPORT D810_NOINLINE int lab_flat_mini(int token)
{
    unsigned int state = 0xC6685257u;            /* K0 */
    int r = token;
    for (;;) {
        switch (state) {
        case 0xC6685257u: r += 0x11; g_hexrays_lab_sink = r; state = 0xB92456DEu; break; /* H0 */
        case 0xB92456DEu: r ^= 0x22; g_hexrays_lab_sink = r; state = 0x3C8960A9u; break; /* H1 */
        case 0x3C8960A9u: r -= 0x33; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break; /* H2 */
        default:          return r;                                                       /* terminal */
        }
    }
}
```

- [ ] **Step 2: Rebuild the lab DLL**

Run: `samples/restructuring_lab/build_lab.sh`
Expected: `[lab] wrote .../samples/bins/restructuring_lab.dll`; `libobfuscated.dll untouched`.

- [ ] **Step 3: Confirm the export and a sane disassembly (dispatcher present)**

Run:
```bash
docker run --rm -v "$PWD/samples/bins":/b restructuring-lab \
  sh -c 'llvm-readobj --coff-exports /b/restructuring_lab.dll | grep lab_flat_mini'
```
Expected: `Name: lab_flat_mini`.

- [ ] **Step 4: Re-track the DLL and commit**

```bash
git add samples/restructuring_lab/c/lab_flat_mini.c samples/bins/restructuring_lab.dll
git commit -m "feat(lab): lab_flat_mini fixture for insert-based unflattening"
```

---

## Task 2: Runtime test scaffold — decompile, map EAs, confirm flattened baseline

**Files:**
- Create: `tests/system/runtime/hexrays/test_insert_unflatten_mini.py`

- [ ] **Step 1: Write the scaffold + baseline assertion (the failing test)**

```python
"""Phase 1: reconstruct lab_flat_mini's linear CFG via block INSERT (not patch).

Runs in the Docker IDA harness with D810_TEST_BINARY=restructuring_lab.dll.
"""
from __future__ import annotations

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")
import idaapi
import ida_funcs

FUNCTION = "lab_flat_mini"
# Large-const states from the fixture; identify the dispatcher by these compares.
STATE_K0 = 0xC6685257
STATE_K1 = 0xB92456DE
STATE_K2 = 0x3C8960A9


def _func_ea(name: str) -> int:
    ea = idaapi.get_name_ea(idaapi.BADADDR, name)
    assert ea != idaapi.BADADDR, f"symbol not found: {name}"
    return ea


def test_baseline_is_flattened(configure_hexrays):
    """Sanity: lab_flat_mini decompiles to a dispatcher loop (it is flattened)."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    cfunc = idaapi.decompile(_func_ea(FUNCTION))
    assert cfunc is not None
    text = str(cfunc)
    # Flattened baseline: a loop driven by the state constants.
    assert "while" in text or "for" in text or "do" in text, text
    assert (f"{STATE_K1:X}" in text.upper()) or (f"{STATE_K1:#x}" in text), text
```

- [ ] **Step 2: Run it in the harness; verify it PASSES (baseline is flattened)**

Run:
```bash
D810_TEST_BINARY=restructuring_lab.dll \
  ./tools/scripts/run_system_tests_docker.sh test -- \
  tests/system/runtime/hexrays/test_insert_unflatten_mini.py::test_baseline_is_flattened -q
```
Expected: `1 passed`. If it FAILS because no loop/const appears, the fixture compiled to an already-structured shape — return to Task 1 and force an explicit `if (state==K) goto` chain instead of `switch`.

- [ ] **Step 3: Commit**

```bash
git add tests/system/runtime/hexrays/test_insert_unflatten_mini.py
git commit -m "test(lab): flattened baseline for lab_flat_mini insert unflatten"
```

---

## Task 3: Insert the private blocks at MMAT_GLBOPT1 and verify clean

**Files:**
- Modify: `tests/system/runtime/hexrays/test_insert_unflatten_mini.py`

- [ ] **Step 1: Add a one-shot GLBOPT1 mutation hook (the failing test)**

Add to the test module. The hook mirrors d810's live mutation pattern
(`src/d810/hexrays/hooks/hexrays_hooks.py:936-1061`: gate on
`mba.maturity == MMAT_GLBOPT1`, build `DeferredGraphModifier(mba)`, `apply`).

```python
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier


def _serial_of_block_writing_state(mba, state_const: int) -> int:
    """Find the handler block whose body writes `state = state_const` (next-state)."""
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        ins = blk.head
        while ins is not None:
            # m_mov of an immediate next-state into the state slot.
            if ins.r is not None and ins.r.t == ida_hexrays.mop_n and \
               int(ins.r.nnn.value) == (state_const & 0xFFFFFFFF):
                return blk.serial
            ins = ins.next
    return -1


class _InsertUnflattenHook(ida_hexrays.Hexrays_Hooks):
    """At MMAT_GLBOPT1, splice private blocks so handlers chain directly."""

    def __init__(self):
        super().__init__()
        self.applied = 0
        self.verify_ok = None

    def glbopt(self, mba):  # fires after global optimization at GLBOPT1
        if int(mba.maturity) != int(ida_hexrays.MMAT_GLBOPT1):
            return 0
        # Map handlers H0/H1/H2 by the next-state constant each writes.
        h0 = _serial_of_block_writing_state(mba, STATE_K1)  # H0 sets state=K1
        h1 = _serial_of_block_writing_state(mba, STATE_K2)  # H1 sets state=K2
        h2 = _serial_of_block_writing_state(mba, 0x1A2B3C4D)  # H2 sets terminal
        if min(h0, h1, h2) < 0:
            return 0
        # Each handler's current successor is the dispatcher loop header.
        disp = mba.get_mblock(h0).succset[0]
        # Terminal/return block = the dispatcher's default exit (block with m_ret).
        ret = _serial_of_return_block(mba)
        mod = DeferredGraphModifier(mba)
        mod.queue_create_and_redirect(h0, h1, [], old_target_serial=disp)
        mod.queue_create_and_redirect(h1, h2, [], old_target_serial=disp)
        mod.queue_create_and_redirect(h2, ret, [], old_target_serial=disp)
        mod.coalesce()
        self.applied = mod.apply(enable_snapshot_rollback=True, verify_each_mod=True)
        try:
            mba.verify(True)
            self.verify_ok = True
        except Exception:
            self.verify_ok = False
        return 0


def _serial_of_return_block(mba) -> int:
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        tail = blk.tail
        if tail is not None and tail.opcode == ida_hexrays.m_ret:
            return blk.serial
    return mba.qty - 1
```

- [ ] **Step 2: Add the verify-clean assertion test**

```python
def test_insert_verifies_clean(configure_hexrays):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    hook = _InsertUnflattenHook()
    assert hook.hook()
    try:
        cfunc = idaapi.decompile(_func_ea(FUNCTION))
    finally:
        hook.unhook()
    assert cfunc is not None
    assert hook.applied >= 3, f"expected >=3 inserts, applied={hook.applied}"
    assert hook.verify_ok is True, "mba.verify() reported INTERR after insert"
```

- [ ] **Step 3: Run it in the harness; expect FAIL first, then iterate**

Run:
```bash
D810_TEST_BINARY=restructuring_lab.dll \
  ./tools/scripts/run_system_tests_docker.sh test -- \
  tests/system/runtime/hexrays/test_insert_unflatten_mini.py::test_insert_verifies_clean -q \
  --enable-debug-logging
```
Expected first run: FAIL (handler mapping or apply needs tuning). Iterate on
`_serial_of_block_writing_state` / `glbopt` vs the actual maturity event using
the debug log in `.tmp/logs/d810_logs/` until `applied >= 3` and `verify_ok`.
Note: if `glbopt` does not fire / fires post-GLBOPT1, switch to the per-block
optimizer hook shape used in `hexrays_hooks.py:893-1061`.

- [ ] **Step 4: Commit once green**

```bash
git add tests/system/runtime/hexrays/test_insert_unflatten_mini.py
git commit -m "test(lab): insert private blocks at GLBOPT1, verify clean (no INTERR)"
```

---

## Task 4: Render assertions — linear chain, no dispatcher loop

**Files:**
- Modify: `tests/system/runtime/hexrays/test_insert_unflatten_mini.py`

- [ ] **Step 1: Add the render assertion (the failing test)**

```python
def test_insert_renders_linear(configure_hexrays):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    hook = _InsertUnflattenHook()
    assert hook.hook()
    try:
        cfunc = idaapi.decompile(_func_ea(FUNCTION))
    finally:
        hook.unhook()
    text = str(cfunc).upper()
    # Dispatcher gone: the state-compare constants no longer drive a loop.
    assert f"{STATE_K1:X}" not in text, f"state compare survived:\n{text}"
    assert f"{STATE_K2:X}" not in text, f"state compare survived:\n{text}"
    # Handler effects survive in order (the +0x11 / ^0x22 / -0x33 arithmetic).
    assert "0X11" in text and "0X22" in text and "0X33" in text, text
```

- [ ] **Step 2: Run; if state-write residue or a loop survives, add cleanup**

Run:
```bash
D810_TEST_BINARY=restructuring_lab.dll \
  ./tools/scripts/run_system_tests_docker.sh test -- \
  tests/system/runtime/hexrays/test_insert_unflatten_mini.py::test_insert_renders_linear -q
```
If the state constants still appear (dead `state=K` writes rendered as
induction), add a cleanup call per handler inside `glbopt` *before* `apply`,
using `DeferredGraphModifier.queue_zero_state_write` (signature at
`src/d810/hexrays/mutation/deferred_modifier.py:1469`) targeting each handler's
state store. Re-run until the constants are gone. If a trivial inserted block
renders as a visible `goto` shell, clear `MBL_KEEP` on it (spec §8) and re-run.

- [ ] **Step 3: Commit once green**

```bash
git add tests/system/runtime/hexrays/test_insert_unflatten_mini.py
git commit -m "test(lab): insert-unflatten renders linear chain, no dispatcher loop"
```

---

## Task 5: Record the observation

**Files:**
- Create: `tools/hexrays_structuring_lab/observations/flat_mini_insert_unflatten.json` (a compact summary: before block count, after block count, verify_ok, render verdict)
- Modify: `samples/restructuring_lab/specs/2026-06-06-insert-unflatten-phase1.md` (append a "Result" line: what MBL_KEEP / state-write cleanup turned out to be needed empirically)

- [ ] **Step 1: Write the observation artifact**

```json
{
  "case_id": "flat_mini_insert_unflatten",
  "binary": "restructuring_lab.dll",
  "function": "lab_flat_mini",
  "verify_ok": true,
  "rollback_fired": false,
  "render": "linear H0->H1->H2->return; dispatcher loop and state var absent",
  "mbl_keep_needed": false,
  "state_write_cleanup_needed": null
}
```
(Set `mbl_keep_needed` / `state_write_cleanup_needed` to the empirically observed values from Task 3–4.)

- [ ] **Step 2: Commit**

```bash
git add tools/hexrays_structuring_lab/observations/flat_mini_insert_unflatten.json \
        samples/restructuring_lab/specs/2026-06-06-insert-unflatten-phase1.md
git commit -m "docs(lab): record flat_mini insert-unflatten Phase 1 observation"
```

---

## Self-Review

- **Spec coverage:** fixture (§3 → Task 1); manual insert plan (§4 → Task 3); apply path/maturity (§5 → Task 3); verify-clean + no-rollback (§6 → Task 3); render linear/no-dispatcher (§6 → Task 4); MBL_KEEP empirical + state-write cleanup (§8 → Task 4 conditional steps + Task 5 record); placement (§7 → all). Covered.
- **Placeholder scan:** no TBD/TODO; the only deferred values are the *empirically-measured* results in Task 5's JSON (by design) and the `queue_zero_state_write` cleanup which is conditional with a cited signature reference, not a vague instruction.
- **Type/name consistency:** `_InsertUnflattenHook`, `_serial_of_block_writing_state`, `_serial_of_return_block`, `STATE_K0/K1/K2`, `queue_create_and_redirect(source, final, instructions, old_target_serial=)`, `apply(enable_snapshot_rollback=, verify_each_mod=)` used consistently across Tasks 2–4.
- **Known runtime risk:** the exact mutation event (`glbopt` vs per-block optimizer hook) is the one thing to confirm in-harness (Task 3 Step 3 names the fallback). This is inherent to IDA-runtime work and is why Tasks 2–5 are TDD-in-harness.
