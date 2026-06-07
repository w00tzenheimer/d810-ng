# Insert-Based Unflattening — Phase 1 Spec (edge-split on a mini host)

Status: approved design (2026-06-06). Spec lives here (not `docs/`, which this
repo gitignores), alongside `samples/restructuring_lab/DESIGN.md`.

Phase 1 of a 3-phase series:
1. **(this spec)** edge-split insert — reconstruct a linear flattened mini-CFG.
2. conditional transition -> new branch (`queue_create_conditional_redirect`).
3. shared-block de-share -> multi-block capture-then-insert
   (`capture_payload` + `InsertBlock(captured_body=...)`).

## 1. Context & motivation

d810 unflattens today by **patching** handler tails (rewrite the back-edge
`goto` in place). The **clone-and-replay** alternative (`DuplicateBlock` /
`DuplicateReplayAndRedirect`, built on live `mba.copy_block`) was abandoned
because a *live clone inherits a web of stale state* that must be scrubbed
perfectly or Hex-Rays sweeps it / `INTERR`s / mis-renders:

| failure mode | cause (grounded) |
|-|-|
| clone vanishes | `copy_block` doesn't inherit `MBL_KEEP`; `optimize_global` sweeps it (`cfg_mutations.py:19`) |
| INTERR / wrong CFG | stale `predset`/`succs`, stale `m_goto` operands, stale `m_jtbl` targets, unrebuilt use/def (`cfg_mutations.py:173,583,688`) |
| orphaned clone | legacy FixPredecessor only redirects `arm==1`; `arm==0` orphans the clone (`graph_modification.py:304`) |
| stale value -> return | IDA propagates the clone's stale value into a `return` unless liveness is killed (`graph_modification.py:405`) |

This spec proves the safe alternative end-to-end on a minimal host:
**capture-then-insert** via `InsertBlock` / `BLOCK_CREATE_WITH_REDIRECT`
(`queue_create_and_redirect`). It is **additive** (new node + one edge redirect,
`StagedAtomicClassification.ADDITIVE`), builds the new block from *explicit*
instructions (no inherited live refs), and leaves originals intact — so
`projected_contract` can verify the rebuilt graph *before* commit. This is the
AGENTS.md proven-lowering loop made concrete: the clone path is the one that
trips the INTERR/sweep failures; the insert path is the one that does not.

## 2. Goals / non-goals

**Goal.** A `tests/system/runtime/` test that takes a mini flattened fixture,
reconstructs its true linear CFG by **inserting** private blocks (not patching,
not cloning), and proves the result is `mba.verify()`-clean and renders as a
clean linear chain (no dispatcher loop).

**Non-goals (YAGNI for Phase 1).**
- No recon/detection: the plan is built manually for the known fixture
  (detection already exists; this isolates the *lowering*).
- No conditional transitions (Phase 2), no shared-block de-share (Phase 3).
- No production-pipeline integration; no `libobfuscated.dll`; no
  `src/d810/` changes (uses the existing `queue_create_and_redirect` API).

## 3. The mini host fixture

`samples/restructuring_lab/c/lab_flat_mini.c` — a minimal flattened function
with large-const states (so it is not the tiny-state shape the
`MIN_STATE_CONSTANT` floor rejects) and three linear handlers:

```c
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

- **True CFG:** `entry -> H0 -> H1 -> H2 -> return` (linear).
- **Compiled (flattened) shape:** a dispatcher region `D` (loop header + sparse
  `state == K` compares) that routes to `H0/H1/H2`; each handler updates `r`,
  writes the next state, and loops back to `D`.
- **Baseline render (before):** a `while`/dispatcher loop over `state` — the
  flattened pseudocode we want to eliminate.
- **Build:** `samples/restructuring_lab/build_lab.sh` -> rebuild
  `restructuring_lab.dll`, re-track it, re-run the `validate-cfg` gate. The
  fixture is valid evidence only if the compiled CFG matches the flattened shape
  (DESIGN.md status model). If clang emits a jump table instead of an if-chain,
  fall back to an explicit `if (state==K) goto` chain in C.

## 4. The reconstruction plan (manual, additive insert)

1. Decompile `lab_flat_mini` once to map **EAs -> serials** for `D`, `H0`, `H1`,
   `H2`, and the terminal/return block. Identify blocks by **EA** (serials are
   maturity-local; the project serialize-with-EA rule), then resolve to serials
   on the live mba being mutated.
2. For each transition `H_i -> H_{i+1}` (and `H2 -> return`), queue one insert:

   ```python
   modifier.queue_create_and_redirect(
       source_block_serial=H_i,
       final_target_serial=H_next,     # H1 / H2 / return-block
       instructions_to_copy=[],        # trivial private 1-way block (goto-only)
       old_target_serial=D,            # redirect H_i OFF the dispatcher arm
   )
   ```

   This splices a fresh private `N_i` (`H_i -> N_i -> H_next`), leaving `H_i`'s
   body intact and the dispatcher untouched.
3. For each handler, remove the now-dead next-state write so no induction
   residue survives:

   ```python
   modifier.queue_zero_state_write(...)   # the `state = K_next` store in H_i
   ```
4. `modifier.coalesce()` then `modifier.apply(...)`.

After apply + Hex-Rays `optimize_global`: the dispatcher `D` becomes unreachable;
the `state` variable is dead; the trivial `N_i` (single-pred/single-succ) are
coalesced by Hex-Rays (the lab's `single_pred_chain_merge` finding); the linear
`H0 -> H1 -> H2 -> return` chain remains.

## 5. Apply path (proven-lowering phases)

A one-shot `ida_hexrays.Hexrays_Hooks` installed by the test, firing at
**`MMAT_GLBOPT1`** (the maturity d810's CFG passes run at). In the maturity
callback it builds the plan of §4 on the live `mba` via `DeferredGraphModifier`,
exercising the transaction phases from `passes/transaction_policy.py`:
`projected_contract` (verify the rebuilt FlowGraph before mutation) ->
`backend_apply` (`DeferredGraphModifier.apply`) -> `post_apply_contract` ->
`native_verify` (`mba.verify()`). The new block is created via `insert_nop_blk`
(which calls `copy_block_keep`), so it carries `MBL_GOTO` + `MBL_KEEP` — but it
is wired **reachable**, so `MBL_KEEP` is incidental here, not load-bearing (see
§8).

## 6. Success criteria / assertions

- **`mba.verify()` is clean — no `INTERR`.** Headline: this is exactly the
  failure class clone-and-replay tripped.
- **Contracts green:** `projected_contract` and `post_apply_contract` pass;
  **rollback did NOT fire** (the transaction stayed clean through the additive
  region). A fired rollback is a test failure.
- **Render (the point):** the final pseudocode shows the `H0/H1/H2` effects as a
  **linear sequence with no dispatcher `while`** and no `state` variable. Assert
  on the rendered `cfunc` text: handler ops present in order; the `state == K`
  constant compares absent.
- **Reachability, not raw count:** assert `D` is **unreachable / not rendered**
  (see §8 — `D` is an original `MBL_KEEP` block so it may persist in the block
  list even when unreachable; that is acceptable because the decompiler does not
  render unreachable blocks). Do not assert `mba.qty` shrank by a fixed amount.

## 7. Components & files

- `samples/restructuring_lab/c/lab_flat_mini.c` — new fixture.
- `samples/bins/restructuring_lab.dll` — rebuilt + re-tracked (gate-validated).
- `tools/hexrays_structuring_lab/registry.json` — optional new
  `compiled_cfg_validated` case for `lab_flat_mini` (records the flattened shape).
- `tests/system/runtime/hexrays/test_insert_unflatten_mini.py` — new live test
  (mutate-and-render; note existing deferred-modifier runtime tests are *pure*
  queue/coalesce tests — this is the first live insert+render one).
- No `src/d810/` changes.

## 8. Error handling, rollback, and risks to resolve in implementation

- **Native-verify failure -> rollback.** `transaction_policy` snapshot-restores
  on `native_verify` failure. The test treats any fired rollback as failure.
- **Invalid fixture.** If the compiled CFG is not the flattened shape, the
  `validate-cfg` gate fails -> the fixture is invalid; no structuring conclusion.
- **`MBL_KEEP` is not load-bearing here (resolve empirically).** Inserted blocks
  are reachable, so they survive the sweep without relying on `MBL_KEEP` — the
  KEEP hack was a *clone-and-replay* need (possibly-unreachable clones), not an
  insert need. Open question the test answers **by observation**: does
  `MBL_KEEP` on a trivial inserted goto-block stop Hex-Rays from coalescing it
  (`single_pred_chain_merge`)? If a trivial `N_i` persists as a visible goto
  shell in the render, clear `MBL_KEEP` on it. The dispatcher `D`
  (original -> KEEP) goes unreachable and should not render; confirm by
  observation rather than pre-emptively stripping its edges.
- **Risk: empty private block.** `instructions_to_copy=[]` must yield a valid
  goto-only 1-way block; if the API requires >=1 instruction, insert a single
  `nop`. Confirm against `queue_create_and_redirect` materialization.
- **Risk: maturity timing.** Confirm blocks inserted at `MMAT_GLBOPT1` flow
  through to final pseudocode (not re-folded undesirably); adjust maturity if so.
- **Risk: state-write removal completeness.** Residual `state=K` writes render as
  loop induction; ensure every handler's write is zeroed.

## 9. How to run

```bash
# rebuild + gate the fixture
samples/restructuring_lab/build_lab.sh
python -m tools.hexrays_structuring_lab validate-cfg lab_flat_mini   # if a case is added

# run the live insert+render test
D810_TEST_BINARY=restructuring_lab.dll \
  ./tools/scripts/run_system_tests_docker.sh test -- \
  tests/system/runtime/hexrays/test_insert_unflatten_mini.py -q
```

## Result (2026-06-06, Phase 1)

- **INSERT VALIDITY PROVEN.** Inserting 3 private blocks
  (`queue_create_and_redirect`, `old_target=dispatcher`) to rewire
  `H0 -> H1 -> H2 -> terminal` on a live GLBOPT1 mba applies 3/3, 0 rollback, and
  `mba.verify()` is clean — **no INTERR**. This is the safe replacement for
  clone-and-replay (the core thesis). Test: `test_insert_verifies_clean`.
- **GLBOPT1 state map** (dest-filtered): dispatcher=blk2; handlers H0=blk6 (writes
  K1), H1=blk7 (writes K2), H2=blk8 (writes TERM); terminal=blk5; state
  slot=`%var_8.4`. Mapped by state-write value (robust to serial renumbering).
- **LIVE RENDER WORKS (optblock stage).** Applying the insert plan via an
  `optblock_t` during the GLBOPT1 pass (and returning the change count so IDA
  re-runs optimization) makes `lab_flat_mini` decompile to the true linear chain
  with no dispatcher loop, no state var, no INTERR:
  ```c
  int __cdecl lab_flat_mini(int token) {
      g_hexrays_lab_sink = token + 0x11;
      g_hexrays_lab_sink = (token + 0x11) ^ 0x22;
      g_hexrays_lab_sink = ((token + 0x11) ^ 0x22) - 0x33;
      return ((token + 0x11) ^ 0x22) - 0x33;
  }
  ```
  Test: `test_insert_renders_linear_optblock` (PASS). The stage is the critical
  variable.
- **NEGATIVE CONTROL (xfail).** The same plan applied in a `glbopt` Hexrays_Hooks
  (post-optimization) trips **INTERR 50346** at ctree. Reverse-engineered (hexx64
  `mba_finalize_glbopt__verify_graphcache_50346`): 50346 fires when the mba
  graph/chains cache (`mbl_graph_t` at `*(mba+0x310)`) is left dirty; the cheap
  post-mutation fixes (`mark_chains_dirty`+`build_graph`) do NOT clear the
  structural bit0. Only the optblock pass (where IDA rebuilds the cache) clears
  it. Test: `test_insert_renders_linear` (xfail) — kept as the stage A/B control.
- **`MBL_KEEP`: not load-bearing**, as predicted in §8 — the inserts are
  reachable; `verify()` is clean whether or not KEEP is set (`insert_nop_blk`
  sets it via `copy_block_keep`).
- **State-write cleanup: not needed for validity** — `verify()` is clean without
  `queue_zero_state_write`; the render gap is the mutation stage, not residue.

## Phase 2 result (conditional transition -> if/else)

- **2a DONE.** `lab_flat_cond` (H0 conditionally -> H1/H2) reconstructs to a clean
  `if (token&1) H1 else H2` (no dispatcher loop) via the optblock-stage path: a
  mini dispatcher-routing extractor (`m_jz`/`m_jnz` matched on known state
  constants, since the compared state sits in a register) + 4 linear inserts that
  redirect H0's arms -> their handlers and the handlers -> terminal, **preserving
  the handler's existing jcc**. Test: `test_cond_renders_branch_optblock` (PASS).
  Hex-Rays folds the else-arm constant (`(token+0x11)-0x33` -> `token-0x22`), so
  assert the if/else structure, not literal handler constants.
- **Finding:** compiler flattening keeps the branch predicate in the HANDLER as a
  real jcc, so a conditional transition reconstructs by *preserving* that jcc
  (linear inserts) -- NOT via `queue_create_conditional_redirect`. The
  conditional-insert primitive is for *synthesizing* a branch (branchless/cmov
  predicate, or one recovered from dataflow), which has no clean
  compiler-flattened fixture.
- **2b DEFERRED:** `queue_create_conditional_redirect` validation is a separate
  focused task (needs a branchless / recovered-predicate scenario).

## Phase 3 result (de-share via state-free capture-then-insert)

- **DONE.** `lab_flat_shared` (paths A,B converge on a SHARED block via the
  dispatcher) de-shares SHARED into two **private STATE-FREE copies** (one per
  path) using `queue_create_and_redirect(instructions_to_copy=captured)` at the
  optblock stage. The captured payload (`_capture_state_free`) strips **all**
  state-constant writes (to any slot) and all control-flow, so the copies carry
  only SHARED's real work (`-0x33`, the sink store) — state-free **by
  construction, not by DCE**. Render: `if(token&1){A;-0x33} else {B;-0x33}`, no
  dispatcher loop; KS/KT gone. Test: `test_shared_deshare_optblock` (PASS).
- **State-var detection lesson:** several slots receive state-constant writes
  (an entry conditional's register temp; a decoy copy slot). The true state var
  is the one that receives the **terminal state** (`STATE_TERM`); decoy copies
  only carry routed next-states. `_state_slot` discriminates on that.
- **INTERR 50860 (`CFG_SUCC_MISMATCH`)** appeared when the captured payload still
  contained SHARED's tail `goto` (the `ins is blk.tail` identity check fails —
  SWIG returns fresh wrappers). Strip control-flow by **opcode**, not identity;
  the inserted block supplies its own goto.
- **Residual (out of scope):** the entry selector `v1 = K0/K1` survives because
  the entry conditional is reg-sourced and un-reconstructed — that is a Phase 2
  entry reconstruction, not part of the de-share.

## 10. Out of scope

- Conditional/branching transitions (Phase 2), shared-block duplication (Phase 3).
- Recon/dispatcher detection; production pipeline wiring.
- `libobfuscated.dll`, `sub_7FFD3338C040`, any real obfuscated function.
- Reviving `DuplicateBlock` / clone-and-replay (this spec is its replacement).
