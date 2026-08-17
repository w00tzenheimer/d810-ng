# Eid Config-V2 Unflattening Completeness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking. Use
> `superpowers:test-driven-development` for every production change and
> `superpowers:verification-before-completion` before every completion claim.

**Goal:** Safely and completely unflatten the three confirmed Eid
config-v2 failures while preserving every exact call and semantic terminal.

**Architecture:** Keep `eidolon_v3_const_solve.json` unchanged and repair the
existing portable config-v2 recovery/planning pipeline. First make the exact
MASM fixtures reproduce the live failures under that profile. Then add one
fail-closed concrete-state route resolver, same-block entry-prefix recovery,
effectful shared-corridor preservation, and semantic-terminal preservation.
Every mutation remains transaction-atomic and must pass exact post-D810
reachability oracles.

**Tech Stack:** Python 3.13, IDA/Hex-Rays 9.4 microcode, immutable D810
`FlowGraph`/`BlockSnapshot`/`InsnSnapshot`, config-v2 pass runtime, MASM PE
fixtures, SQLite diagnostic snapshots, pytest, IDA Docker system tests,
ast-grep, import-linter, graphify.

**Spec:** `docs/plans/2026-08-17-eid-v2-unflattening-completeness-design.md`

## Global Constraints

- Work only in `.worktrees/eid-v2-unflattening-completeness` on branch
  `diff/eid-v2-unflattening-completeness`, created from the current
  `cfg-recon-mainline` tip after this plan is committed.
- Do not modify, delete, or add tests for the legacy unflattening engine in this
  plan. Changing the A/B fixture profile from legacy to Eid v2 is required
  test correction, not legacy migration.
- Do not change `eidolon_v3_const_solve.json` unless a RED fixture proves a
  required existing v2 pass is disabled. Current live diagnostics prove the
  passes execute, so the expected implementation makes no profile change.
- Do not place function addresses, sample names, API names, state constants,
  or block serials in production decision logic.
- Never weaken effect-reachability, authoritative-handler,
  terminal-reachability, poison/quarantine, predecessor-ownership, or
  transaction validation.
- Never classify calls, stores, unknown effects, or reachable semantic
  terminals as removable dispatcher infrastructure.
- Treat a rejected unflattening transaction as a failure even if later cleanup
  passes make local pseudocode changes.
- Every diagnostic block identity is `blk<serial>@<ea>`; never report a bare
  block serial.
- Every production change follows strict RED-GREEN-REFACTOR. Save the exact RED
  and GREEN commands/output paths in the task report.
- Run local commands inside the feature worktree with `PYTHONPATH=src`.
- Run all IDA-dependent commands from `/Users/mahmoud/src/idapro/d810`, never
  from inside the worktree, using:

```bash
./tools/scripts/run_system_tests_docker.sh <action> \
  -w eid-v2-unflattening-completeness ...
```

- Write Docker output with `-o <bare-filename>` so it lands in the worktree's
  `.tmp/` directory. Use `-l` whenever diagnostic DB/log assertions are needed.
- If a Docker decompilation spends minutes in an uninstrumented interval, stop
  that run, retain the partial log, and use the repository pyinstrument/cProfile
  support before retrying. Do not run blind timing matrices.
- Do not add ast-grep ignores or `.importlinter` exceptions.
- Do not merge or push. The controller owns final integration decisions.

## Worktree Convention

The controller creates the worktree from the plan-bearing tip:

```bash
cd /Users/mahmoud/src/idapro/d810
git worktree add \
  .worktrees/eid-v2-unflattening-completeness \
  -b diff/eid-v2-unflattening-completeness \
  cfg-recon-mainline
```

Use these paths in every report:

```text
MAIN=/Users/mahmoud/src/idapro/d810
WORKTREE=/Users/mahmoud/src/idapro/d810/.worktrees/eid-v2-unflattening-completeness
PROFILE=eidolon_v3_const_solve.json
```

---

### Task 1: Reproduce All Three Failures Under The Exact Eid V2 Profile

**Files:**
- Modify: `tests/system/e2e/test_unflattening_effect_safety_fixtures.py`
- Modify: `tests/unit/test_unflattening_effect_safety_masm_fixtures.py`
- Modify: `samples/scripts/build_masm.sh`
- Create: `samples/src/masm/sub_7FF855576B50.asm`
- Inspect: `samples/src/masm/sub_7FF8569F0540.asm`
- Inspect: `samples/src/masm/sub_7FF8568132D0.asm`
- Inspect: `tests/system/e2e/unflattening_effect_safety_oracle.py`
- Create: `docs/plans/evidence/2026-08-17-eid-v2-unflattening-red-baseline.md`

**Interfaces:**
- Consumes: existing MASM export/build flow and session-scoped exact-call BFS
  oracle.
- Produces: three exact, profile-v2 system regressions whose current expected
  result is RED for the diagnosed reason.
- Produces: stable callsite marker names and target-size entries consumed by
  Tasks 4-6.

- [ ] **Step 1: Read the fixture and runner contracts before editing**

Run inside `WORKTREE`:

```bash
sed -n '1,760p' tests/system/e2e/test_unflattening_effect_safety_fixtures.py
sed -n '1,260p' tests/system/e2e/unflattening_effect_safety_oracle.py
sed -n '1,180p' tests/unit/test_unflattening_effect_safety_masm_fixtures.py
sed -n '1,260p' samples/scripts/build_masm.sh
```

Record the existing target-size table, CONST data-marker format, diagnostic
session selection, and post-D810 BFS contract in the report. Do not introduce a
second oracle implementation.

- [ ] **Step 2: Write the missing-fixture RED tests first**

Extend `tests/unit/test_unflattening_effect_safety_masm_fixtures.py` with tests
that require `samples/src/masm/sub_7FF855576B50.asm` to export:

```text
PUBLIC sub_7FF855576B50
PUBLIC d810_callsite_sub_7FF855576B50_message_box
PUBLIC d810_callsite_sub_7FF855576B50_get_current_process
PUBLIC d810_callsite_sub_7FF855576B50_terminate_process
```

The tests must parse the MASM/PE metadata through the existing fixture helpers;
they must not merely grep arbitrary source strings. Each marker must resolve to
one instruction inside the function extent.

Run:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/test_unflattening_effect_safety_masm_fixtures.py -vv
```

Expected RED: the `sub_7FF855576B50` fixture or its exports do not exist. Save
the output as `.tmp/task1_fixture_red.txt`.

- [ ] **Step 3: Export and normalize the third MASM fixture**

Use the repository's existing IDA MASM export fixture flow against MCP port
13337 and function entry `0x7FF855576B50`. Preserve the complete native
function body and imports; do not hand-reconstruct the dispatcher.

Add three CONST QWORD data markers using the same form as the existing A/B
fixtures. Each marker stores the object-relative offset of the corresponding
native callsite so relocation or generic imported-call retargeting does not
break the oracle. Update `samples/scripts/build_masm.sh` to assemble/link the
new source and verify all three PUBLIC marker exports.

Build through the canonical Docker flow from `MAIN`:

```bash
./tools/scripts/run_system_tests_docker.sh exec \
  -w eid-v2-unflattening-completeness -- \
  bash -lc 'samples/scripts/build_masm.sh unflattening_effect_safety'
```

If the script's established target selector differs, use its documented
selector and record the exact command. Remove the generated DLL after tests;
only source and build metadata are committed.

- [ ] **Step 4: Make every effect-safety system test select Eid v2**

In `TestUnflatteningEffectSafetyDecompilation`, replace the two existing
`state.for_project("default_unflattening_ollvm.json")` selections with:

```python
with state.for_project("eidolon_v3_const_solve.json"):
```

Add `test_target_c_after_preserves_termination_effects_and_commits`. It must:

1. resolve the loaded function entry for `sub_7FF855576B50`;
2. resolve each of the three callsite data markers;
3. decompile with the Eid profile;
4. require a committed transaction from the same diagnostic session;
5. require all three exact call EAs in the latest reachable post-D810 snapshot;
6. reject residual dispatcher state constants `0x16AA65E9`, `0x079323F9`,
   `0x1888937E`, and `0x1BABC1DC` in normalized pseudocode;
7. reject the nested dispatcher-loop form while allowing legitimate loops;
8. print function EA, committed modification count, and pseudocode byte count.

Do not make a function-wide call-count assertion. The oracle must bind and
prove each exact native callsite separately.

- [ ] **Step 5: Run exact RED Docker cases individually**

From `MAIN`, run each case separately so a 10-minute target cannot hide the
other failure:

```bash
./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task1_target_a_red.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_a_after_preserves_memcpy_effect_and_commits \
  -vv -s

./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task1_target_b_red.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_b_after_preserves_srw_lock_effect_and_commits \
  -vv -s

./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task1_target_c_red.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_c_after_preserves_termination_effects_and_commits \
  -vv -s
```

Expected outcomes:

- A rejects with `authoritative_handler_lost` and identifies the source-anchored
  `memcpy` corridor/cut loss.
- B rejects because the reachable semantic trap would be lost.
- C reports no entry bridge (`initial_state=None`) and/or unresolved interval
  routes.

If any expected failure is absent, correct fixture extent, marker binding, or
profile parity before Task 2. Do not manufacture a production fix for a
nonreproducing fixture.

- [ ] **Step 6: Record and commit the RED baseline**

The report must include commit, source/binary hashes, function extents, exact
marker EAs, profile name, Docker commands, elapsed times, transaction verdicts,
and the stable-EA form of every lost/unresolved block.

Remove `samples/bins/unflattening_effect_safety.dll`, then run:

```bash
git status --short
git diff --check
git add \
  samples/src/masm/sub_7FF855576B50.asm \
  samples/scripts/build_masm.sh \
  tests/unit/test_unflattening_effect_safety_masm_fixtures.py \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py
git add -f \
  docs/plans/evidence/2026-08-17-eid-v2-unflattening-red-baseline.md
git commit -m "test(unflatten): reproduce Eid v2 completeness gaps"
```

---

### Task 2: Add One Fail-Closed Concrete-State Route Resolver

**Files:**
- Create: `src/d810/analyses/control_flow/concrete_state_route.py`
- Create: `tests/unit/analyses/control_flow/test_concrete_state_route.py`
- Modify: `src/d810/transforms/reconstruction_bridge_planning.py`
- Create: `tests/unit/transforms/test_reconstruction_bridge_planning.py`
- Inspect: `src/d810/analyses/control_flow/dispatcher_resolution.py`
- Inspect: `src/d810/analyses/control_flow/interval_map.py`

**Interfaces:**
- Produces: immutable `ConcreteStateRoute` evidence containing normalized state,
  target block, and source kinds.
- Produces: `resolve_concrete_state_route(...) -> ConcreteStateRoute | None`.
- Consumers in later tasks use this one resolver rather than combining
  `dict.get`, `StateDispatcherMap.resolve_target`, and interval lookup ad hoc.

- [ ] **Step 1: Define the portable behavior in RED tests**

Create `tests/unit/analyses/control_flow/test_concrete_state_route.py`. The
tests use real `StateDispatcherMap` and `IntervalDispatcher` objects and assert:

```python
def test_exact_route_is_returned_with_exact_provenance(): ...
def test_interval_only_route_is_returned_with_interval_provenance(): ...
def test_agreeing_exact_and_interval_routes_merge_provenance(): ...
def test_conflicting_exact_and_interval_routes_abstain(): ...
def test_uncovered_state_abstains(): ...
def test_bool_or_out_of_range_state_is_normalized_or_rejected_by_contract(): ...
```

Use literal state/target values and hand-built rows. The conflict case must
prove that an exact route to block 10 and interval route to block 11 returns
`None`; it must not encode precedence that silently picks one.

Run and capture RED:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/analyses/control_flow/test_concrete_state_route.py -vv
```

Expected RED: module/import missing.

- [ ] **Step 2: Implement the immutable resolver**

In `concrete_state_route.py`, define a frozen slotted result carrying only
portable primitives. The resolver accepts:

```python
resolve_concrete_state_route(
    state_value: int,
    *,
    exact_dispatcher_map: StateDispatcherMap | None = None,
    interval_dispatcher: object | None = None,
) -> ConcreteStateRoute | None
```

Required algorithm:

1. reject `bool`; convert `state_value` to `int` and mask to 32 bits;
2. ask `StateDispatcherMap.resolve_target()` when available;
3. ask `interval_dispatcher.lookup_row()` rather than only `lookup()`, validate
   `lo <= state < hi`, and extract one integer target;
4. collect all proven targets;
5. return no evidence for zero targets or more than one distinct target;
6. return one result with deterministic sorted provenance when all providers
   agree.

Catch only provider-shape/value exceptions that mean evidence is unavailable;
do not blanket-catch `Exception`.

- [ ] **Step 3: Replace the private exact-then-interval implementation**

Replace `_resolve_exact_then_interval()` in
`reconstruction_bridge_planning.py` with the shared resolver. Existing callers
continue receiving `int | None`; convert the evidence to `.target_block` at the
call boundary.

Add a regression proving conflicting exact and interval evidence causes the
bridge planner to emit no modification.

- [ ] **Step 4: Run focused GREEN and boundaries**

```bash
PYTHONPATH=src pytest -q \
  tests/unit/analyses/control_flow/test_concrete_state_route.py \
  tests/unit/transforms/test_reconstruction_bridge_planning.py -vv
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
```

- [ ] **Step 5: Commit the shared resolver**

```bash
git add \
  src/d810/analyses/control_flow/concrete_state_route.py \
  src/d810/transforms/reconstruction_bridge_planning.py \
  tests/unit/analyses/control_flow/test_concrete_state_route.py \
  tests/unit/transforms/test_reconstruction_bridge_planning.py
git commit -m "feat(unflatten): resolve concrete states across exact and interval routes"
```

---

### Task 3: Recover A Constant Initial State From The Dispatcher-Entry Prefix

**Files:**
- Modify: `src/d810/analyses/control_flow/dispatcher_recovery.py`
- Modify: `tests/unit/analyses/control_flow/test_reachability_and_recover_dispatcher.py`
- Modify: `src/d810/passes/unflatten/state_machine.py`
- Modify: `tests/unit/passes/test_state_machine_entry_bridge_policy.py`

**Interfaces:**
- Extends: `recover_entry_dominated_initial_state(graph, dmap) -> int | None`.
- Produces: `StateDispatcherMap.initial_state` for a proven same-block prefix.
- Does not create an emit-only override or mutate live Hex-Rays objects.

- [ ] **Step 1: Write same-block prefix RED tests**

Use portable `FlowGraph`, `BlockSnapshot`, `InsnSnapshot`, and `MopSnapshot`
builders already present in dispatcher recovery tests. Add separate tests for:

```python
def test_entry_dominated_initial_state_reads_constant_before_dispatch_tail(): ...
def test_entry_dominated_initial_state_rejects_write_after_dispatch_tail(): ...
def test_entry_dominated_initial_state_rejects_conflicting_prefix_writes(): ...
def test_entry_dominated_initial_state_rejects_nonconstant_prefix_write(): ...
def test_entry_dominated_initial_state_rejects_wrong_state_identity(): ...
def test_entry_dominated_initial_state_rejects_effect_barrier_after_write(): ...
def test_predecessor_initialization_behavior_is_unchanged(): ...
```

The positive graph's entry block is also `dmap.dispatcher_entry_block`; it has
one `MOV #0x16AA65E9 -> state_slot`, ordinary pure arithmetic, then an
`EQUALITY_JUMP`. The expected value is the literal `0x16AA65E9`.

For the barrier case, place a `CALL` or unknown `STORE` between the write and
dispatcher tail and expect `None`. Do not mock the recovery function.

Run and capture RED:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/analyses/control_flow/test_reachability_and_recover_dispatcher.py \
  tests/unit/passes/test_state_machine_entry_bridge_policy.py -vv
```

- [ ] **Step 2: Implement prefix-bounded state recovery**

Extract the existing stack/register destination and constant-source checks into
one private predicate used by both `_read_state_init_const()` and the new
same-block prefix scan. Do not change the predecessor-path search. When the
function entry equals dispatcher entry:

1. locate the first dispatcher routing tail using portable control-transfer
   semantics (`EQUALITY_JUMP`, `COND_JUMP`, `TABLE_JUMP`, or
   `INDIRECT_JUMP`), never rendered text;
2. inspect only instructions before that boundary;
3. require exactly one constant write to the recovered stack/register identity;
4. reject a conflicting or nonconstant write;
5. reject a call, unknown store, or unsupported effect after the candidate
   write and before the boundary;
6. return the masked constant only after all checks pass.

If no reliable boundary exists, return `None`. Keep the existing unique
predecessor path byte-for-byte equivalent in behavior.

- [ ] **Step 3: Thread the result through normal recovery authority**

Ensure dispatcher recovery stores the value on
`StateDispatcherMap.initial_state`, and `_resolve_initial_state()` in
`passes/unflatten/state_machine.py` continues to prefer that map value. Do not
add a target-specific fallback to `emit_minimal_unflatten()`.

Add a pass-level test proving a same-block map initial state wins over a stale
range-evidence hint.

- [ ] **Step 4: Run focused GREEN and protected recovery tests**

```bash
PYTHONPATH=src pytest -q \
  tests/unit/analyses/control_flow/test_reachability_and_recover_dispatcher.py \
  tests/unit/passes/test_state_machine_entry_bridge_policy.py \
  tests/unit/preanalysis/flow/test_minimal_state_recovery.py -vv
git diff --check
```

- [ ] **Step 5: Commit same-block recovery**

```bash
git add \
  src/d810/analyses/control_flow/dispatcher_recovery.py \
  src/d810/passes/unflatten/state_machine.py \
  tests/unit/analyses/control_flow/test_reachability_and_recover_dispatcher.py \
  tests/unit/passes/test_state_machine_entry_bridge_policy.py
git commit -m "fix(unflatten): recover same-block dispatcher initial state"
```

---

### Task 4: Resolve Interval-Routed Entry And Back-Edge States

**Files:**
- Modify: `src/d810/analyses/control_flow/minimal_state_recovery.py`
- Modify: `tests/unit/preanalysis/flow/test_minimal_state_recovery.py`
- Modify: `src/d810/transforms/minimal_unflatten_emit.py`
- Modify: `tests/unit/transforms/test_minimal_unflatten_emit.py`
- Consume: `src/d810/analyses/control_flow/concrete_state_route.py`

**Interfaces:**
- Consumes: `resolve_concrete_state_route()` from Task 2.
- Consumes: `StateDispatcherMap.initial_state` from Task 3.
- Produces: one target handler for interval-routed initial/back-edge states only
  when all active route evidence agrees.

- [ ] **Step 1: Write interval-transition RED tests**

Add portable tests representing target C's shape without copying its entire
function. Use an interval table whose rows route:

```text
[0x079323FA, 0x1888937E) -> handler 10
[0x1888937E, 0x1888937F) -> handler 13
[0x1BABC1DC, 0x1BABC1DD) -> handler 2
```

Required tests:

```python
def test_initial_state_inside_interval_builds_entry_bridge(): ...
def test_back_edge_state_inside_interval_resolves_handler(): ...
def test_uncovered_interval_state_remains_unresolved(): ...
def test_conflicting_exact_and_interval_target_remains_unresolved(): ...
def test_interval_default_or_dispatcher_self_route_does_not_become_handler(): ...
```

The positive entry-state literal is `0x16AA65E9` and must resolve to handler
10. Tests assert emitted modification source/old/new targets and proof
provenance, not a private helper call.

Run RED:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/preanalysis/flow/test_minimal_state_recovery.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py -vv
```

- [ ] **Step 2: Use the shared resolver in transition recovery**

Replace exact-only or precedence-based route selection in the relevant
minimal-state recovery paths with `resolve_concrete_state_route()`. Preserve
existing terminal classification: an interval route is a normal handler only
when its target is a live non-dispatcher handler; terminal evidence remains
explicit.

Remove only duplicated route-selection logic proven equivalent by tests. Do
not broadly refactor `minimal_state_recovery.py`.

- [ ] **Step 3: Use the shared resolver for the entry bridge**

In `minimal_unflatten_emit.py`, replace the entry bridge's independent
combination of materialized/exact/interval lookups with candidate collection:

1. collect the shared exact/interval route;
2. collect existing materialized/native-bound route candidates;
3. require one distinct target across all candidates;
4. retain each source's provenance in diagnostics;
5. emit no bridge when candidates conflict.

Keep conditional-forest, bootstrap, and register-conditional entry paths
unchanged.

- [ ] **Step 4: Run target C exact Docker GREEN**

First run focused local tests. Then from `MAIN`:

```bash
./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task4_target_c_green.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_c_after_preserves_termination_effects_and_commits \
  -vv -s
```

Required GREEN evidence:

- transaction status committed;
- all three exact callsite EAs reachable in the same post-D810 session;
- no `no entry bridge` or `interval-router-insufficient` abstention;
- the four dispatcher constants absent;
- no residual dispatcher loop.

If the exact target still fails, diagnose the first remaining abstention and
add a new portable RED test before changing production code.

- [ ] **Step 5: Run protected local suites and commit**

```bash
PYTHONPATH=src pytest -q \
  tests/unit/analyses/control_flow/test_concrete_state_route.py \
  tests/unit/analyses/control_flow/test_reachability_and_recover_dispatcher.py \
  tests/unit/preanalysis/flow/test_minimal_state_recovery.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py \
  tests/unit/passes/test_state_machine_entry_bridge_policy.py
git diff --check
git add \
  src/d810/analyses/control_flow/minimal_state_recovery.py \
  src/d810/transforms/minimal_unflatten_emit.py \
  tests/unit/preanalysis/flow/test_minimal_state_recovery.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py
git commit -m "fix(unflatten): route interval-backed entry and transition states"
```

---

### Task 5: Preserve Effectful Shared And Synthetic-Cut Corridors

**Files:**
- Modify: `src/d810/transforms/minimal_unflatten_emit.py`
- Modify: `src/d810/transforms/dispatcher_corridor_coverage.py`
- Modify: `tests/unit/transforms/test_minimal_unflatten_emit.py`
- Modify: `tests/unit/transforms/test_dispatcher_corridor_coverage.py`
- Inspect: `src/d810/analyses/control_flow/graph_checks.py`
- Inspect: `src/d810/transforms/cfg_transaction.py`

**Interfaces:**
- Consumes: immutable source graph, conditional-arm evidence, corridor coverage,
  and exact block anchors.
- Produces: a redirect plan that retains an owned semantic/effectful route
  through a shared suffix or synthetic cut.
- Preserves: existing transaction preflight as the final independent veto.

- [ ] **Step 1: Write the shared-effect corridor RED graph**

Build the smallest portable graph that reproduces
`shared_suffix_or_cut_unproven`:

```text
predicate arm -> state-write block -> shared/cut block -> dispatcher
                                      |
                                      +-> effectful CALL block -> handler
```

Give every block a stable nonzero EA. Add separate tests proving:

```python
def test_owned_shared_cut_corridor_retains_effectful_call_route(): ...
def test_shared_cut_with_unrelated_predecessor_abstains_atomically(): ...
def test_shared_cut_with_two_candidate_effect_targets_abstains(): ...
def test_synthetic_cut_anchor_maps_to_source_effect_route(): ...
def test_effect_block_is_never_retired_as_comparison_infrastructure(): ...
```

The positive test must fail before production changes because no redirect or
coverage proof preserves the call. The negative tests must already abstain or
be tightened before GREEN; none may become permissive.

Run RED:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/transforms/test_minimal_unflatten_emit.py \
  tests/unit/transforms/test_dispatcher_corridor_coverage.py -vv
```

- [ ] **Step 2: Implement source-owned shared-corridor planning**

Extend the existing conditional-arm path around the
`shared_suffix_or_cut_unproven` diagnostic. Accept only when immutable source
evidence proves all of:

1. one source predicate/arm owns the candidate route, or the existing
   predecessor-partition proof explicitly assigns ownership;
2. one state value resolves to one handler;
3. the shared/cut path has no unowned predecessor;
4. every call/store/terminal/unknown-effect block is retained, never bypassed;
5. synthetic blocks map to exact native/source anchors;
6. redirecting the arm does not sever another successor's semantic path.

Emit a fragment-atomic set of modifications. If any sibling redirect lacks
proof, reject the fragment rather than applying the remaining redirects.

- [ ] **Step 3: Tighten corridor retirement proof without broadening loss**

Update `dispatcher_corridor_coverage.py` only if needed to distinguish retained
semantic corridor blocks from retired comparison/state plumbing. Preserve the
existing invariant:

```python
lost_blocks <= derived_retired_comparison_infrastructure
```

The `memcpy`/CALL block must be post-reachable, not admitted through an
allowance. Raw proof payload anchors must continue matching recomputed source
anchors exactly.

- [ ] **Step 4: Run target A exact Docker GREEN**

From `MAIN`:

```bash
./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task5_target_a_green.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_a_after_preserves_memcpy_effect_and_commits \
  -vv -s
```

Required evidence:

- committed transaction, not cleanup-only mutations;
- exact marker-resolved `memcpy` call reachable;
- `0x0EE1BCAD` source route represented in the receipt/snapshot oracle;
- no `authoritative_handler_lost` or effectful-unreachable preflight failure;
- residual dispatcher loop absent.

- [ ] **Step 5: Run protected tests and commit**

```bash
PYTHONPATH=src pytest -q \
  tests/unit/transforms/test_minimal_unflatten_emit.py \
  tests/unit/transforms/test_dispatcher_corridor_coverage.py \
  tests/unit/backends/hexrays/test_mutation_backend.py
git diff --check
git add \
  src/d810/transforms/minimal_unflatten_emit.py \
  src/d810/transforms/dispatcher_corridor_coverage.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py \
  tests/unit/transforms/test_dispatcher_corridor_coverage.py
git commit -m "fix(unflatten): preserve effectful shared corridors"
```

---

### Task 6: Preserve Reachable Conditional Semantic Terminals

**Files:**
- Modify: `src/d810/analyses/control_flow/graph_checks.py` only if the portable
  terminal classifier lacks required semantics
- Modify: `src/d810/transforms/minimal_unflatten_emit.py`
- Modify: `src/d810/transforms/dispatcher_corridor_coverage.py`
- Modify: `tests/unit/test_graph_checks.py`
- Modify: `tests/unit/transforms/test_minimal_unflatten_emit.py`
- Modify: `tests/unit/transforms/test_dispatcher_corridor_coverage.py`

**Interfaces:**
- Produces: generalized semantic-terminal retention based on reachable portable
  control-flow/instruction semantics.
- Does not produce: an `int3`, `__debugbreak`, Eid, or address-specific
  special case.

- [ ] **Step 1: Write the conditional-terminal RED tests**

Construct a portable source graph with a real conditional predicate whose one
arm reaches a normal handler and whose other arm reaches a zero-way semantic
terminal. Give the terminal a stable EA and instruction evidence matching the
portable representation actually observed in the fixture.

Required tests:

```python
def test_reachable_conditional_terminal_remains_post_reachable(): ...
def test_unreferenced_alignment_trap_is_not_added_to_authoritative_handlers(): ...
def test_terminal_and_handler_under_shared_comparison_subtree_are_both_retained(): ...
def test_unknown_terminal_semantics_abstain_instead_of_retiring_block(): ...
def test_mixed_terminal_and_unrelated_semantic_loss_rejects_transaction(): ...
```

The positive test must fail because the current proposal loses the terminal;
the padding test must distinguish absence from the source-reachable graph from
a reachable terminal.

Run RED:

```bash
PYTHONPATH=src pytest -q \
  tests/unit/test_graph_checks.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py \
  tests/unit/transforms/test_dispatcher_corridor_coverage.py -vv
```

- [ ] **Step 2: Preserve terminal routes at planning authority**

Prefer existing `BlockKind.ZERO_WAY`, `RET`, helper-call, and terminal metadata.
If the portable graph already classifies the block as semantic/effectful, leave
`graph_checks.py` unchanged and fix route planning only.

The planner must retain the conditional edge when:

1. the source predicate/arm is exact;
2. the terminal is source-reachable;
3. the terminal is not comparison or state-plumbing infrastructure;
4. its route does not conflict with a materialized/native-bound route;
5. the post-projection graph keeps both the terminal and ordinary handler
   reachable.

Unknown or ambiguous terminal semantics cause whole-fragment abstention.

- [ ] **Step 3: Verify no trap-removal policy reappears**

Search the branch diff and production tree:

```bash
rg -n "int3|__debugbreak|typed.trap|remove.*trap|trap.*remove" src/d810
```

Existing diagnostic/comment references are allowed. New production policy
must be phrased in semantic-terminal terms and operate from portable evidence.

- [ ] **Step 4: Run target B exact Docker GREEN**

From `MAIN`:

```bash
./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task6_target_b_green.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_b_after_preserves_srw_lock_effect_and_commits \
  -vv -s
```

Required evidence:

- committed transaction;
- exact SRW-lock call reachable;
- `__debugbreak()` present and its source EA reachable;
- dispatcher constants absent and label/goto ceilings satisfied;
- no lost-handler or effect-reachability veto.

- [ ] **Step 5: Run protected tests and commit**

```bash
PYTHONPATH=src pytest -q \
  tests/unit/test_graph_checks.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py \
  tests/unit/transforms/test_dispatcher_corridor_coverage.py \
  tests/unit/backends/hexrays/test_mutation_backend.py
git diff --check
git add \
  src/d810/analyses/control_flow/graph_checks.py \
  src/d810/transforms/minimal_unflatten_emit.py \
  src/d810/transforms/dispatcher_corridor_coverage.py \
  tests/unit/test_graph_checks.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py \
  tests/unit/transforms/test_dispatcher_corridor_coverage.py
git commit -m "fix(unflatten): preserve conditional semantic terminals"
```

Stage only files that actually changed; do not create an empty graph-checks
change merely because it appears in the plan.

---

### Task 7: Run Combined Config-V2 Acceptance And Protected Baselines

**Files:**
- Inspect: `tests/system/e2e/test_unflattening_effect_safety_fixtures.py`
- Create: `docs/plans/evidence/2026-08-17-eid-v2-unflattening-acceptance.md`
- Inspect: all files changed by Tasks 1-6

**Interfaces:**
- Consumes: all three exact system fixtures and every portable proof.
- Produces: combined acceptance evidence and a clean, reviewable branch.

- [ ] **Step 1: Run all changed portable tests together**

```bash
PYTHONPATH=src pytest -q \
  tests/unit/analyses/control_flow/test_concrete_state_route.py \
  tests/unit/analyses/control_flow/test_reachability_and_recover_dispatcher.py \
  tests/unit/test_graph_checks.py \
  tests/unit/preanalysis/flow/test_minimal_state_recovery.py \
  tests/unit/transforms/test_reconstruction_bridge_planning.py \
  tests/unit/transforms/test_minimal_unflatten_emit.py \
  tests/unit/transforms/test_dispatcher_corridor_coverage.py \
  tests/unit/passes/test_state_machine_entry_bridge_policy.py \
  tests/unit/backends/hexrays/test_mutation_backend.py \
  tests/unit/test_unflattening_effect_safety_masm_fixtures.py
```

Expected: zero failures. Record exact count and elapsed time.

- [ ] **Step 2: Run all three exact system cases together**

From `MAIN`:

```bash
./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task7_exact_eid_v2_acceptance.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py \
  -vv -s
```

Expected: A, B, and C pass in one clean container/session sequence. Confirm each
test selected `eidolon_v3_const_solve.json` and each receipt is session-bound.

- [ ] **Step 3: Run protected strategy and poison baselines**

Use the repository's existing protected test selection. At minimum include
OLLVM, Hodur, Tigress, Approov, poison restart/quarantine, and the complete
mutation transaction runtime file. Run from `MAIN`:

```bash
./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task7_protected_unflattening_baselines.txt -- \
  tests/system/e2e/test_strategy_migration_baselines.py \
  tests/system/e2e/test_approov_engine_wrapper_baselines.py \
  tests/system/e2e/test_poison_restart.py \
  -vv -s

./tools/scripts/run_system_tests_docker.sh test \
  -w eid-v2-unflattening-completeness -l \
  -o task7_transaction_runtime.txt -- \
  tests/system/runtime/optimizers/microcode/flow/flattening/engine/test_runtime.py \
  -vv -s
```

If a listed path has moved at execution time, locate its current tracked path
with `rg --files tests/system` and record the substitution. Do not silently
drop a protected family.

- [ ] **Step 4: Run architecture and hygiene gates**

Inside `WORKTREE`:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
ruff check <every changed Python file>
git diff --check
graphify update . --no-cluster
```

Do not add rule ignores. Remove generated DLLs and confirm `git status --short`
contains only intentional tracked changes plus any explicitly pre-existing
untracked artifact.

- [ ] **Step 5: Audit the acceptance report against the spec**

The report must list, for each target:

```text
fixture source hash and linked extent
profile name
committed modification count/batches
exact retained effect EAs
post-D810 snapshot/session identity
dispatcher-removal assertions
elapsed time
Docker log path
```

It must also list every protected suite count, warning count, architecture gate,
and any unresolved concern. Do not call live MCP verification complete here.

- [ ] **Step 6: Commit combined acceptance evidence**

```bash
git add \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py
git add -f \
  docs/plans/evidence/2026-08-17-eid-v2-unflattening-acceptance.md
git commit -m "test(unflatten): verify Eid v2 completeness repairs"
```

Stage the test file only if Task 7 required a test-only correction. Never commit
`.tmp` logs or generated binaries.

---

### Task 8: Verify The Original Live MCP Targets

**Files:**
- Create: `docs/plans/evidence/2026-08-17-eid-v2-unflattening-live.md`
- Do not modify production code unless a new live RED regression is added first.

**Interfaces:**
- Consumes: feature worktree installed in a freshly restarted IDA process and
  MCP port 13337.
- Produces: live before/after pseudocode and mutation receipts for the three
  original functions plus two successful controls.

- [ ] **Step 1: Establish the live runtime identity**

Record IDB path, image base, module name, process ID, MCP port, loaded D810
repository root/commit, selected project, and active log/diagnostic DB paths.
Reject mixed-root or stale-process evidence. A restart is required after the
feature worktree is installed.

- [ ] **Step 2: Decompile the three repaired targets individually**

Use MCP to decompile:

```text
0x7FF8569F0540
0x7FF8568132D0
0x7FF855576B50
```

For each function capture pseudocode, elapsed time, transaction receipt,
post-D810 reachability snapshot, and exact effect anchors. Require the same
semantic conditions as the fixtures. Do not infer success from classification,
pass eligibility, or mutation count alone.

- [ ] **Step 3: Recheck the two successful controls**

Decompile `0x7FF8554C4E30` and the function entry `0x7FF856884940` containing
`0x7FF856886B70`. Confirm neither regressed to a residual dispatcher or lost
semantic calls.

- [ ] **Step 4: Handle live-only failures with a new RED fixture**

If a live target fails after fixture acceptance:

1. identify the first differing CFG/evidence shape using stable EAs;
2. add the smallest portable or MASM RED regression that reproduces it;
3. run and retain the RED output;
4. implement the generalized fix;
5. rerun focused GREEN, combined fixture acceptance, protected baselines, and
   the live target.

Never patch the IDB or add address-specific production behavior.

- [ ] **Step 5: Finalize the live report and commit**

The report distinguishes fixture-proven and live-proven claims and includes
every artifact path. Run `git diff --check`, then:

```bash
git add -f docs/plans/evidence/2026-08-17-eid-v2-unflattening-live.md
git commit -m "docs(unflatten): record live Eid v2 acceptance"
```

If the user has not yet restarted/installed the worktree, record Task 8 as
pending rather than claiming completion. The feature branch may be Docker-green
but is not definition-of-done complete until live verification succeeds.

---

## Final Review Checklist

The controller and final reviewer must verify all items before offering merge:

- [ ] Every A/B/C system test selects `eidolon_v3_const_solve.json`.
- [ ] No production code contains the five live function addresses, their API
  names, or their state constants.
- [ ] Target A's exact `memcpy` EA is post-D810 reachable.
- [ ] Target B's exact SRW-lock EA and conditional trap EA are post-D810
  reachable, and `__debugbreak()` remains rendered.
- [ ] Target C's three exact termination-related call EAs are post-D810
  reachable.
- [ ] All three transactions commit atomically; cleanup-only mutation is not
  accepted.
- [ ] Conflicting route evidence, unowned predecessors, unknown effects, and
  incomplete coverage still abstain.
- [ ] Protected strategy, poison/quarantine, and transaction runtime tests pass.
- [ ] ast-grep, import-linter, Ruff, `git diff --check`, and graphify update pass.
- [ ] Generated DLLs are absent from git status.
- [ ] Live MCP evidence exists or is explicitly reported pending.
