# Hex-Rays Structuring Lab Plan

## Strategy

Build a narrow vertical slice before adding breadth.

The first objective is not to catalog every CFG pattern. The first objective is
to prove that the lab can take one small fixture, run it through Hex-Rays,
capture snapshots, classify what happened, and produce a registry entry that
helps d810 make a concrete lowering decision.

The first fixtures should target the current d810 pain point: block-boundary
collapse after d810 emits or removes state-transition scaffolding.

## Parallel Execution Model

This work should be split by artifact ownership, not by vague research themes.
Subagents are useful only when each one owns a small, testable slice with a
clear output file set.

Recommended parallel workstreams:

- Registry and CLI scaffolding owner:
  owns `tools/hexrays_structuring_lab/__main__.py`, registry loading, case
  listing, command rendering, and output-directory naming.
- Fixture owner:
  owns the first C/ASM sample additions and any build-system hooks needed to
  expose `single_pred_chain_merge` and `multi_pred_boundary_barrier` as stable
  functions in the sample binary.
- Diagnostic summarizer owner:
  owns summary extraction from dump output and diag DBs, including
  `merge-causality`, snapshot selection, pseudocode metrics, and generated
  `summary.md` / `summary.json` files.
- d810 feedback owner:
  owns translating lab observations into d810 invariants, contracts, or targeted
  regression tests. This owner should not modify the fixture runner until the
  first vertical slice is stable.

Dependency order:

1. Registry schema and case ids must land first.
2. CLI command rendering and fixture authoring can proceed in parallel once case
   ids and expected output layout are stable.
3. Diagnostic summarization can proceed from mocked or existing diag DBs before
   the new fixtures are fully compiled.
4. d810 feedback tests should wait until at least one fixture has a real
   observed result.

Subagent boundaries:

- Do not let two agents edit the same file unless one is explicitly reviewing.
- Give fixture agents sample/build ownership only.
- Give CLI agents orchestration ownership only.
- Give summarizer agents read-only access to fixture definitions and write
  access only to summary tooling.
- Keep d810 production code out of the lab milestone until a pattern has a
  measured result.

## Milestone 1: Minimal Registry And Runner Shape

Deliverables:

- Add a small registry file, likely `registry.json` or `registry.yaml`.
- Add a minimal lab CLI under `tools/hexrays_structuring_lab/`.
- Teach the CLI to list cases and print the exact Docker command needed to run
  one case.
- Reuse the existing dump harness instead of writing a new IDA runner.
- Store generated outputs under `.tmp/hexrays_structuring_lab/`.

Initial command shape:

```bash
python -m tools.hexrays_structuring_lab list
python -m tools.hexrays_structuring_lab command single_pred_chain_merge
python -m tools.hexrays_structuring_lab summarize --db path/to/diag.sqlite3
```

The first version can be mostly orchestration and metadata. It does not need to
own all IDA execution yet.

## Milestone 2: Pattern 1, Single-Pred Chain Merge

Pattern id:

```text
single_pred_chain_merge
```

Question:

```text
When Hex-Rays sees a chain of BLT_1WAY blocks where each successor has exactly
one predecessor, does it merge the chain after nop/und cleanup?
```

Why this matters:

```text
d810 reconstruction can emit a semantically valid handler chain that Hex-Rays
later compresses. If this pattern is confirmed in isolation, we can stop
treating post-d810 block shrinkage as generic DCE and classify it as expected
chain coalescing.
```

Fixture approach:

- Prefer an assembly fixture or microcode mutation fixture.
- Avoid relying only on C source because the compiler may erase the exact chain.
- Create a tiny function with three or four linear blocks.
- Ensure each intermediate block has `npred == 1`, `nsucc == 1`, and `BLT_1WAY`.
- Include at least one cleanup candidate that becomes `m_und` or a goto-only
  shell, if practical.

Captured evidence:

- Snapshot before mutation or baseline microcode.
- Snapshot after controlled d810-style mutation.
- Snapshot after Hex-Rays optimization.
- `merge-causality` report from post-apply to post-d810.
- Pseudocode before/after.

Expected outcome:

- The chain collapses across one or more block boundaries.
- `merge-causality` classifies vanished blocks as `absorbed` where real EAs
  survive in a remaining block.
- The registry records the exact pre-collapse predicates: block type, preds,
  succs, instruction count, and tail opcode.

Decision this should inform:

```text
If d810 emits a long single-pred/single-succ semantic handler chain, it should
expect Hex-Rays to merge boundaries unless a real CFG-shaping barrier exists.
```

## Milestone 3: Pattern 2, Boundary Barrier Candidate

Pattern id:

```text
multi_pred_boundary_barrier
```

Question:

```text
What is the smallest CFG change that prevents Hex-Rays from merging across a
handler boundary without leaking bad pseudocode?
```

Why this matters:

```text
The failed dispatcher-preservation experiment showed that preserving the wrong
edge does not stop post-d810 collapse. We need a controlled fixture that tests
barrier candidates directly, instead of assuming which predecessor matters.
```

Fixture approach:

- Start from the same chain shape as `single_pred_chain_merge`.
- Add one boundary-preservation candidate at the middle block.
- Candidate A: a genuine second predecessor.
- Candidate B: a small non-empty anchor instruction that survives cleanup.
- Candidate C: a conditional shell that Hex-Rays will not flatten immediately.
- Only test one candidate first; do not branch into a matrix until the harness
  works.

Captured evidence:

- Same snapshots and pseudocode as Pattern 1.
- `block` query for the protected boundary before and after optimization.
- `block-trace` or `ea-trace` proving where the protected block's body landed.
- `merge-causality` proving whether the boundary survived, was absorbed, or was
  deleted.

Expected outcome:

- At least one boundary survives post-d810 optimization.
- If it survives but pseudocode gets worse, record that as a failed barrier.
- If it prevents merge and pseudocode stays acceptable, promote the barrier into
  a candidate d810 CFG-shaping primitive.

Decision this should inform:

```text
d810 should preserve semantic handler/region boundaries using the cheapest
barrier that survives Hex-Rays and does not create visible dispatcher scaffolding
or goto noise.
```

## Milestone 4: Automate The First Vertical Slice

Deliverables:

- A lab command that runs Pattern 1 and Pattern 2 through Docker.
- A generated output directory per run.
- A summary file per run containing:
  - pseudocode metrics
  - snapshot ids
  - block count delta
  - merge-causality cross-tab
  - pass/fail classification
- One checked-in registry update with observed behavior.

The output should be boring and repeatable. If the first two examples require
manual archaeology every time, the lab has failed.

## Milestone 5: Expand Only After The Slice Works

Candidate next patterns:

- `clean_conditional_fork`
- `fallthrough_alias_tail`
- `shared_tail_fold`
- `do_while_cycle_scc`
- `irreducible_two_entry_cycle`
- `dispatcher_switch_preserved`
- `m_und_state_write_cleanup`
- `goto_only_frontier_bypass`

Do not add these until the first two patterns can run and summarize cleanly.

## Immediate Next Step

Implement the minimal registry and CLI around two cases:

1. `single_pred_chain_merge`
2. `multi_pred_boundary_barrier`

The CLI can initially emit commands rather than execute them. That is enough to
force the registry format, naming, output layout, and expected evidence model.
Once that is stable, wire it to Docker execution and summary extraction.
