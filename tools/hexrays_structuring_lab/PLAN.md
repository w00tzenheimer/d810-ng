# Hex-Rays Structuring Lab Plan

## Strategy

Build a narrow vertical slice before adding breadth.

The first objective is not to catalog every CFG pattern. The first objective is
to prove that the lab can take one small fixture, run it through Hex-Rays,
capture snapshots, classify what happened, and produce a registry entry that
helps d810 make a concrete lowering decision.

The first fixtures should target the current d810 pain point: block-boundary
collapse after d810 emits or removes state-transition scaffolding.

Use C fixtures first, but require compiled-CFG validation before treating them
as evidence. Assembly is the fallback when C cannot force the intended shape.
Microcode mutation is the last resort for d810-specific backend behavior.

The case lifecycle is:

```text
planned -> compiled_cfg_validated -> observed
planned -> invalid_compiled_cfg
```

`validate-cfg` must fail hard once implemented. A failed compiled-CFG validation
invalidates the fixture; it does not produce a Hex-Rays structuring conclusion.

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

- Add a small registry file, likely `registry.json` or `registry.yaml`. Done:
  `registry.json`.
- Add a minimal lab CLI under `tools/hexrays_structuring_lab/`. Done:
  `python -m tools.hexrays_structuring_lab`.
- Teach the CLI to list cases and print the exact Docker command needed to run
  one case. Done for planned fixtures.
- Reuse the existing dump harness instead of writing a new IDA runner. Done:
  command rendering targets `tools/scripts/run_system_tests_docker.sh dump`.
- Store generated outputs under `.tmp/hexrays_structuring_lab/`. Done in the
  rendered command layout.

Initial command shape:

```bash
python -m tools.hexrays_structuring_lab list
python -m tools.hexrays_structuring_lab validate-cfg single_pred_chain_merge
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

- Start with a C fixture.
- Use `volatile` locals/globals, `noinline`, opaque external calls, `goto`
  labels, and `asm volatile("" ::: "memory")` only as needed.
- Compile with the least surprising flags first, likely `-O0`, then adjust if
  Hex-Rays needs a different shape.
- Validate the compiled CFG before running the Hex-Rays experiment.
- Assert a tiny function with three or four linear blocks.
- Assert each intermediate block has `npred == 1`, `nsucc == 1`, and `BLT_1WAY`.
- Assert expected label EAs or anchors survive in the compiled binary.
- Include at least one cleanup candidate that becomes `m_und` or a goto-only
  shell, if practical.
- If compiled-CFG validation fails after a reasonable C attempt, replace the
  fixture with assembly. Do not treat the failed C shape as Hex-Rays evidence.

Authoritative DLL build loop:

1. Add or update only the first fixture under `samples/src/c/`, initially:
   `samples/src/c/hexrays_structuring_lab.c`.
2. Sync sample sources to the Windows build tree:

   ```bash
   rsync -av samples/src/ /Volumes/re/idapro/plugins/d810-ng/samples/src/
   ```

3. Build the Windows DLL on `reversepc.local`:

   ```powershell
   cd G:\idapro\plugins\d810-ng\samples
   .\scripts\build_windows.ps1
   ```

4. Sync the produced DLL/PDB back into this worktree:

   ```bash
   rsync -av \
     /Volumes/re/idapro/plugins/d810-ng/samples/bins/libobfuscated.dll \
     /Volumes/re/idapro/plugins/d810-ng/samples/bins/libobfuscated.pdb \
     samples/bins/
   ```

5. Run the compiled-CFG validation gate:

   ```bash
   python -m tools.hexrays_structuring_lab validate-cfg single_pred_chain_merge
   ```

Notes:

- If `/Volumes/re` is not mounted, use SSH to copy the same paths to/from
  `reversepc.local`.
- Do not sync the whole repo unless the sample build requires it. Start with
  `samples/src/` and add `samples/include/` only if headers changed.
- The lab evidence should be generated against `samples/bins/libobfuscated.dll`,
  because that is the binary the Docker/IDA system tests decompile.

Captured evidence:

- Compiled-CFG validation report.
- Validation status, expected predicates, observed predicates, compiler flags,
  binary hash, and artifact path in the run summary.
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
- Start as a C fixture and validate the compiled CFG first.
- Add one boundary-preservation candidate at the middle block.
- Candidate A: a genuine second predecessor.
- Candidate B: a small non-empty anchor instruction that survives cleanup.
- Candidate C: a conditional shell that Hex-Rays will not flatten immediately.
- Only test one candidate first; do not branch into a matrix until the harness
  works.
- If C cannot reliably produce the boundary shape, drop to assembly for this
  case. Keep microcode mutation as a last resort.

Captured evidence:

- Compiled-CFG validation report.
- Validation status, expected predicates, observed predicates, compiler flags,
  binary hash, and artifact path in the run summary.
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

Current decision rule:

```text
Do not optimize for preserving blocks. Optimize for preserving semantic
structure that Hex-Rays can render cleanly.
```

Observed outcome vocabulary:

- `expression_folded_deleted`: GLBOPT1 deletes/folds content into expressions.
- `absorbed_cleanly`: GLBOPT1 absorbs blocks without degrading pseudocode.
- `semantic_visible_boundary_folded`: the semantic side effect remains visible,
  but the boundary block identity does not.
- `clean_structured_compaction`: GLBOPT1 compacts the CFG into readable,
  semantically faithful structured pseudocode.
- `bad_topology_collapse`: compaction creates misleading or unreadable
  pseudocode and should not be copied into d810 lowering.

The `matrix` and `compare` commands are the decision surface for these cases.
They summarize LOCOPT blocks, GLBOPT1 blocks, vanished count, disposition,
pseudocode-change status, and outcome class across all observed fixtures.

Candidate next patterns:

- `conditional_shell_boundary`
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
