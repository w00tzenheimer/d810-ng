# BST Block Removal Investigation

**Date**: 2026-03-14
**Branch**: `structure-recovery-pass`
**Goal**: Eliminate 3 while loops in sub_7FFD3338C040 caused by BST dispatcher structure

## Problem

After Hodur linearization, sub_7FFD has 3 while loops (target: 1 do-while). All caused by
BST comparison blocks surviving linearization — IDA's structurer sees the BST tree as
irreducible control flow and represents it with `while(1) { if (v8 > ...) }` nesting.

Current metrics: 966 lines, 0 returns, 3 whiles, 69 gotos, 9 calls.

## What We Tried

### Approach 1: NOP BST instructions (failed)

NOP state variable comparison instructions in BST blocks. 5 variants tested:

1. NOP all BST+dispatcher + sever edges → INTERR 52719
2. NOP all BST+dispatcher + keep edges → segfault
3. NOP BST body only (keep tail jcc) → segfault
4. NOP dispatcher only → massive handler DCE
5. NOP tail goto on severed blocks → DCE

**Root cause**: BST variable definitions are part of IDA's global def-use chains. NOP'ing
cascades into handler body elimination.

### Approach 2: Edge severing (partially works, not durable)

Phase 1: Sever 1-way handler→dispatcher back-edges (`succset._del` + `predset._del`).
Phase 2: Convert 2-way handler→dispatcher conditionals to gotos (`make_2way_block_goto`).

Result: 1014→966 lines, 75→69 gotos. But whiles stay at 3.
IDA regenerates severed edges between maturity passes (GLBOPT1→GLBOPT2).

### Approach 3: `mba.remove_block()` on BST blocks (failed — INTERR 51919)

Called `mba.remove_block(blk)` directly on BST blocks without disconnecting edges first.
All calls failed with INTERR 51919 (undocumented internal assertion — block has live edges).

### Approach 4: Disconnect-then-remove (failed — handler DCE)

Proper 5-step sequence per block:
1. Sever all outgoing edges
2. Sever all incoming edges + NOP predecessor tails
3. Clear own pred/succ lists
4. NOP all instructions
5. Call `mba.remove_block(blk)`

Safety checks: skip BST blocks whose handler successors would become unreachable
(no non-BST predecessors). Also skip blocks with non-BST predecessors.

Result: 31 BST internal blocks passed safety, were removed. 46 skipped (handler
successors would lose reachability). Output: **84 lines** — massive DCE.

**Root cause**: Removing BST internal nodes at GLBOPT1 breaks the tree structure.
Even "safe" internal nodes (all preds/succs are BST) cause transitive unreachability
for handler-reaching leaf descendants. IDA's reachability analysis at GLBOPT1 depends
on the BST tree being intact.

### Approach 5: `remove_empty_and_unreachable_blocks()` at GLBOPT1 (failed)

Segfaults. Works only at MMAT_CALLS+. Corrupts IDA internal caches at earlier maturities.

## How hrtng Does It

Reference: `~/src/idapro/hrtng/src/unflat.cpp`

hrtng **never directly removes BST/dispatcher blocks**. Instead, it makes them
unreachable, then prunes.

### Phase 1: `RemoveSingleGotos()` (line 981-1061)

Pre-pass: eliminates goto-chain trampolines. Rewrites goto/jcond target operands
directly, manually updates `succset`/`predset`, then calls `mba->merge_blocks()`.

### Phase 2: Redirect all dispatcher predecessors (line 1067-1228)

Main loop iterates `mba->get_mblock(cfi.iDispatch)->predset`. For each predecessor:
- Resolves target handler via state value + BST lookup
- `dgm.ChangeGoto(mb, iDispatch, iDestNo)` — rewrites instruction operand in-place
  AND queues edge change (`Remove(src, oldDest)` + `Add(src, newDest)`)

**Key**: this redirects EVERY block that jumps to the dispatcher. After this phase,
the dispatcher has zero predecessors.

### Phase 3: `ProcessErasures()` (line 1655-1668)

NOPs the chain of `m_mov` instructions that wrote state constants. Standard
`mb->make_nop(erase.insMov)` + `mb->mark_lists_dirty()`.

### Phase 4: `dgm.Apply()` (line 1962)

Batch-applies all queued edge modifications:
- Remove old edges: `succset.del()` + `predset.del()`
- Add new edges: `predset.add_unique()` + `succset.add()`
- Handles INTERR(50860) duplicate-successor by NOPing jcond tail

### Phase 5: `PruneUnreachable()` (line 940-971)

Forward BFS from block 0 via `succset`. Any unvisited block gets `DeleteBlock()`:
1. Remove all outgoing edges from successor predsets
2. Clear `mb->succset`
3. Set `mb->type = BLT_NONE`
4. Delete all instructions (manual linked-list traversal, `delete pCurr`)
5. Call `mba->remove_block(b)` — now safe because block is fully disconnected

### Phase 6: Finalize (line 1980-1983)

`mba->mark_chains_dirty()` + `mba->optimize_local(0)` for IDA re-optimization.

## Critical Difference: d810 vs hrtng

| Aspect | hrtng | d810 |
|-|-|-|
| Redirect scope | ALL dispatcher predecessors | Only resolved handler exits |
| BST after redirect | Zero predecessors (unreachable) | Still reachable (46 handler entries only have BST preds) |
| Block removal | Only after BFS proves unreachable | Attempted directly on still-reachable blocks |
| Cleanup trigger | Unreachability (natural) | Manual selection (fragile safety checks) |

**The fundamental gap**: d810's linearization doesn't redirect ALL handler exits.
42 handler exits have TAIL_CHASE_FAILED — forward eval can't fold MBA arithmetic
in shared tail blocks. Those unresolved exits keep the BST/dispatcher reachable.

In hrtng, every dispatcher predecessor is resolved and redirected. The BST becomes
dead code naturally. Then `PruneUnreachable()` removes it safely.

### Correction: "46 BST-only handlers" was a red herring

The Phase 3 safety check flagged 46 BST blocks, but analysis shows:
- 32 handler entries already have linearization predecessors (chained)
- 13 are dead BST ranges / internal nodes (not real handlers)
- **0 handler entries are truly isolated**

All handler ENTRIES are reachable. The problem is handler EXITS: 42 TAIL_CHASE_FAILED
exits still point back to the dispatcher because forward eval couldn't determine
the exit state value.

## Path Forward: Backward Dispatcher-Predecessor Scan + PruneUnreachable

### Rationale

hrtng works backward: iterate `dispatcher.predset`, backward-walk each predecessor
to find the state constant, look up target handler via BST. d810 works forward: DFS
from handler entry, evaluate instructions. Same data, different direction.

hrtng's backward walk uses `build_def_list(insn, MUST_ACCESS|FULL_XDSU)` to chain
through `m_mov`/`m_xdu`/`m_xds` copies across block boundaries (single-predecessor
only). d810's UD chain phase only does 1-level backward lookup — this is the key gap.

### Phase 1: Diagnostic backward scan

Add diagnostic to `_post_apply_bst_cleanup` that iterates `dispatcher.predset` AFTER
linearization. For each predecessor still pointing to dispatcher:
- Backward-walk to find state var write
- Try to resolve constant (literal, 1-level copy, valrange)
- Log: total predecessors, already-redirected, newly-resolvable, unresolvable

This tells us how many of the 42 TAIL_CHASE_FAILED exits the backward approach fixes.

### Phase 2: BackwardDispatcherPredScanStrategy

New strategy in the hodur pipeline, positioned after DirectLinearization:

```
Input:  dispatcher_serial, state_var_stkoff, BSTAnalysisResult, IntervalDispatcher
Algorithm:
  1. Iterate disp_blk.predset
  2. For each predecessor not already redirected:
     a. Backward-walk instructions to find state var write
     b. Chain through m_mov/m_xdu/m_xds copies (cross-block, single-pred, depth 8)
     c. If literal found: IntervalDispatcher.lookup(value) → target handler
     d. If MBA expression: try valranges (VR_EXACT > VR_AT_START > VR_AT_END)
  3. Emit RedirectGoto for each resolved predecessor → target handler
Output: list of RedirectGoto modifications via ModificationBuilder
```

Resolution cascade (modeled on hrtng):
1. Direct numeric backward walk (literal m_mov → state_var)
2. Multi-block copy chain (m_mov/m_xdu/m_xds, single-pred boundaries)
3. 2-predecessor conditional split (jcc-ending block → per-arm resolution)
4. Valrange fallback (existing `resolve_state_via_valranges`)

### Phase 3: PruneUnreachable (hrtng-style)

After ALL strategies complete and all redirects are applied:
1. Forward BFS from block 0 via succset
2. Any block NOT visited → unreachable
3. For each unreachable block:
   a. Remove all outgoing edges (succ predsets)
   b. Clear own succset/predset
   c. Delete all instructions
   d. `mba.remove_block(blk)`
4. `mba.mark_chains_dirty()`

This is safe at any maturity — only removes blocks proven unreachable via BFS.

### Expected outcome

If backward scan resolves all 42 TAIL_CHASE_FAILED exits:
- Dispatcher has zero predecessors → BST becomes fully unreachable
- PruneUnreachable removes all BST blocks safely
- No BST structure → no irreducible CFG → no while loops
- Target: 3 whiles → 1 (real do-while) or 0

## Experimental Results (2026-03-14)

### Proven: BST IS unreachable

BFS from block 0 confirms 77/77 BST blocks are unreachable at both GLBOPT1 and GLBOPT2:

| Maturity | Reachable | Total | Unreachable BST |
|-|-|-|-|
| GLBOPT1 | 24/325 | 301 unreachable | 77 |
| GLBOPT2 | 18/279 | 261 unreachable | 77 |

Dispatcher has 0 predecessors after Phase 1 edge severing (confirmed via backward scan).

### Proven: `remove_block` at GLBOPT1 does NOT work

5 approaches tried, all fail:

| Approach | Error | Root cause |
|-|-|-|
| `remove_block` without disconnect | INTERR 51919 | Block has live pred/succ edges |
| Disconnect edges + `make_nop` + `remove_block` | INTERR 52719 | Stale serial references after renumbering (`get_mblock(n >= qty)`) |
| Disconnect + `make_nop` without `remove_block` | Segfault | `make_nop` triggers def-use chain updates that corrupt at GLBOPT1 |
| hrtng-style: `remove_from_block` + `remove_block` (reverse serial) | INTERR 51920 | Block still has predecessors (children removed before parents) |
| hrtng-style: forward serial order | INTERR 51920 | blk[3] has predecessors from reachable blocks (Phase 1 severs edge lists, not instruction operands) |

### Why hrtng works but d810 doesn't

hrtng's block removal works because:
1. **Maturity**: hrtng runs at **MMAT_LOCOPT** (before global def-use chains are built). d810 runs at **MMAT_GLBOPT1** (after). `remove_block` has stricter internal assertions at GLBOPT1.
2. **Complete redirect**: hrtng redirects ALL dispatcher predecessors (instruction operands changed, not just edge lists). After redirect, no reachable block has an instruction targeting BST blocks. d810's Phase 1 severs edge lists but leaves goto instruction operands intact — IDA rebuilds edges from instructions.
3. **C++ `delete` vs `make_nop`**: hrtng deletes instructions with C++ `delete` (no def-use chain bookkeeping). d810 uses `make_nop` which triggers chain updates that corrupt state at GLBOPT1.
4. **INTERR 52719 source**: `hexrays.hpp:5291` — `QASSERT(52719, n < qty)` in `get_mblock()`. After removing blocks, `qty` decreases but stale serial references (in instruction operands of reachable blocks) still reference old serials.

### Remaining viable approaches

**A. Run block removal at MMAT_LOCOPT** (match hrtng's maturity):
- Requires running BST analysis at LOCOPT (before global optimization)
- d810's analysis currently depends on GLBOPT1-level optimization results
- Significant architectural change

**B. Persist BST info, remove at MMAT_CALLS+**:
- At GLBOPT1: record BST block start_ea values
- Register separate optimizer at MMAT_CALLS
- Re-find blocks by EA, sever edges + NOP + `remove_empty_and_unreachable_blocks()` (safe at CALLS+)
- Challenge: edge severing at GLBOPT1 doesn't persist (instruction operands unchanged)

**C. Modify instruction operands at GLBOPT1** (make edge changes durable):
- Phase 1: instead of just severing edge lists, change goto instruction operands to redirect to BLT_STOP or self
- This makes the redirect persist across maturities
- At MMAT_CALLS+, BST is unreachable from instruction-level analysis
- Call `remove_empty_and_unreachable_blocks()` at MMAT_CALLS

**D. Accept current baseline** (966 lines, 3 whiles):
- The 3 while loops are structural artifacts, not semantic errors
- All handler bodies are correctly decompiled
- The while loops don't affect program correctness

### Current state (committed)

- Phase 1 (1-way edge severing) + Phase 2 (2-way conversion): working, 966 lines baseline
- Diagnostic: backward scan + BFS reachability logging (no mutations)
- All mutation code reverted
