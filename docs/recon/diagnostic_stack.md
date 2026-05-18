# Recon-time diagnostic stack for state-machine deobfuscation

This document is the developer reference for the fact-rooted diagnostic
substrate that captures, classifies, and (optionally) overrides
state-machine reconstruction decisions during D810's Hodur unflattening
pass.  It also records the empirical results from the
``sub_7FFD3338C040`` byte-tail investigation that drove the substrate's
design.

The stack is **observability-first**: every layer persists evidence to
the diag DB and is queryable via the ``d810.diagnostics`` CLI.  The one
behavior consumer (``selected_alternate_edge_override``) is gated on
fact lifecycle evidence, which is enabled by default; set
``D810_FACT_LIFECYCLE=0`` to disable the evidence path. Debug logging is
not behavior-bearing and must not be used as a proxy for this setting.

## Quick reference

| layer | module | persistence table | gate |
| - | - | - | - |
| State-write anchor | `recon.facts.collectors.state_write_anchor` | `fact_observations(kind=StateWriteAnchorFact)` + `fact_mappings(status=STATE_CONST_REWRITTEN)` | enabled by default; `D810_FACT_LIFECYCLE=0` disables |
| State-transition anchor | `recon.facts.collectors.state_transition_anchor` | `fact_observations(kind=StateTransitionAnchorFact)` | enabled by default; `D810_FACT_LIFECYCLE=0` disables |
| Edge classification | `core.diag.edge_diagnostics` | `dag_edge_diagnostics` | none (post-hoc CLI) |
| BST resolution | `core.diag.bst_resolution` | `state_transition_bst_resolutions` | none (post-hoc CLI; reads `INTERVAL_DISPATCHER_ROWS` from log) |
| Alternate correlation | `core.diag.alternate_correlation` | `dag_edge_alternate_correlations` | none (post-hoc CLI) |
| Alternate selection | `core.diag.alternate_selection` | `dag_edge_alternate_selections` | none (post-hoc CLI) |
| Selected-alternate DAG override (BEHAVIOR) | `recon.flow.selected_alternate_edge_override` | (mutates in-memory `LinearizedStateDag.edges`) | fact lifecycle evidence; `D810_FACT_LIFECYCLE=0` disables |
| Terminal-byte fact guards (BEHAVIOR) | `optimizers.microcode.flow.flattening.engine.terminal_byte_emit_fact_guard` and `return_carrier_fact_guard` | (filters CFG modifications during executor) | fact lifecycle evidence; `D810_FACT_LIFECYCLE=0` disables |
| HCC chained-skip terminal-byte gate (BEHAVIOR) | `optimizers.microcode.flow.flattening.hodur.strategies.handler_chain_composer._emit_chained_call_anchor` | (suppresses guard-skip RedirectBranch emission at point) | fact lifecycle evidence; `D810_FACT_LIFECYCLE=0` disables |

## Cascade flow

```
1. StateWriteAnchorFactCollector              (PREOPT/LOCOPT/CALLS/GLBOPT1)
   captures every  mov #const, %var_<stkoff>
                    |
                    v
2. StateTransitionAnchorFactCollector         (PREOPT/LOCOPT/CALLS/GLBOPT1)
   captures source_state_const + transit
   chain via single-successor walk
                    |
                    v
3. TerminalByteEmitterFactCollector           (PREOPT/LOCOPT/CALLS/GLBOPT1)
   classifies byte-emit destinations as
   terminal_tail / non_terminal_byte_emitter
                    |
                    v
   --- HCC reconstruction snapshot ---
                    |
                    v
4. classify_dag_edges                          (post-hoc)
   reads dag_edges + STATE_CONST_REWRITTEN +
   TerminalByteEmitterFact  -->  COLLAPSED_TO_REWRITTEN_TARGET /
                                  TARGET_UNRESOLVED_AFTER_REWRITE /
                                  LOCOPT_REWRITTEN_SOURCE /
                                  SPURIOUS_CONDITIONAL_ARM /
                                  BENIGN
                    |
                    v
5. resolve_state_transition_facts              (post-hoc)
   reads INTERVAL_DISPATCHER_ROWS log line +
   StateTransitionAnchor + StateWriteAnchor
                    |
                    v
6. correlate_collapsed_edges                   (post-hoc)
   pairs every COLLAPSED edge with
   RANGE_BACKED sibling traversal edges
                    |
                    v
7. select_alternate_edges                      (post-hoc)
   bounded BFS depth<=4 from alt target;
   selects when reached_byte_index > source_byte_index
                    |
                    v
8. apply_selected_alternate_edge_overrides_from_diag   (BEHAVIOR, gated)
   substitutes  dag.edges[i].target_state /
   target_entry_anchor / target_key  for
   matched COLLAPSED edges
```

## Schema (additions persisted by the stack)

### `dag_edge_diagnostics`

```
snapshot_id           INTEGER
edge_id               INTEGER
classification        TEXT  CHECK(classification IN (
    'BENIGN', 'LOCOPT_REWRITTEN_SOURCE',
    'TARGET_UNRESOLVED_AFTER_REWRITE',
    'COLLAPSED_TO_REWRITTEN_TARGET',
    'SPURIOUS_CONDITIONAL_ARM'))
source_state_hex      TEXT
target_state_hex      TEXT
edge_kind             TEXT
is_terminal_tail      INTEGER (0/1)
original_state_const  TEXT     # only when LOCOPT_REWRITTEN_*
rewritten_state_const TEXT     # only when LOCOPT_REWRITTEN_*
related_fact_ids      TEXT     # JSON array
reason                TEXT
PRIMARY KEY (snapshot_id, edge_id)
```

### `state_transition_bst_resolutions`

```
snapshot_id, fact_id    PRIMARY KEY
source_block_serial
source_state_const_hex
bst_resolved_next_block_serial    -- single-hop interval lookup result
bst_resolved_next_state_const_hex -- canonical state-write at resolved
                                     handler block at LOCOPT-pre, if any
bst_resolution_reason             -- bst_row_matched_with_local_state_write
                                     bst_row_matched_no_local_state_write_at_handler
                                     no_bst_row
                                     no_bst_intervals_available
                                     successor_kind=<kind>; ...
bst_resolution_maturity           -- always 'MMAT_GLBOPT1' today
```

### `dag_edge_alternate_correlations`

```
snapshot_id, collapsed_edge_id, alternate_edge_id   PRIMARY KEY
collapsed_source_state, collapsed_target_state
alternate_source_state, alternate_target_state
alternate_ordered_path             -- verbatim from dag_edges
overlap_blocks                     -- JSON array of block serials
alternate_classification           -- 'RANGE_BACKED'
reason                             -- range_backed_sibling_traversal /
                                      range_backed_sibling_no_outgoing_edge
```

### `dag_edge_alternate_selections`

```
snapshot_id, collapsed_edge_id, alternate_edge_id   PRIMARY KEY
selected               INTEGER (0/1)
source_byte_index      INTEGER  -- from cross-link with TerminalByteEmitterFact
reached_byte_index     INTEGER  -- via BFS depth <= 4 from alt target
reached_state_hex      TEXT
reason                 TEXT     -- later_terminal_tail_reached /
                                  early_return_arm_no_later_terminal_tail /
                                  no_later_terminal_tail_within_depth /
                                  no_source_byte_index /
                                  alternate_has_no_target_state
evidence_json          TEXT
```

## CLI subcommands

All run via `PYTHONPATH=src python -m d810.diagnostics <cmd> --db <path>`.
Most accept `--persist` to write back into the diag DB and `--json`
for machine-readable output.

| subcommand | purpose |
| - | - |
| `state-write-trace --block N` | trace per-maturity state-write evolution for one block |
| `state-write-rewrites [--block N]` | list every block whose state-write was rewritten between maturities |
| `dag-edge-diagnostics [--snap-id N] [--kind {all,terminal_tail}] [--classification CLS] [--persist]` | classify recon-time `dag_edges` rows |
| `state-transition-bst-resolutions [--snap-id N] [--bst-log PATH] [--block N] [--persist]` | single-hop BST routing for LOCOPT-pre transition facts |
| `dag-edge-alternate-correlations [--snap-id N] [--collapsed-edge ID] [--persist]` | pair COLLAPSED edges with RANGE_BACKED sibling traversals |
| `dag-edge-alternate-selections [--snap-id N] [--collapsed-edge ID] [--max-depth K] [--persist]` | pick alternate edges that preserve byte-tail progression |

Typical workflow on a captured snap:

```bash
DB=$(ls -t .tmp/logs/d810_logs/*.diag.sqlite3 | head -1)

PYTHONPATH=src python -m d810.diagnostics dag-edge-diagnostics \
    --db $DB --snap-id 6 --kind terminal_tail --persist
PYTHONPATH=src python -m d810.diagnostics dag-edge-alternate-correlations \
    --db $DB --snap-id 6 --persist
PYTHONPATH=src python -m d810.diagnostics dag-edge-alternate-selections \
    --db $DB --snap-id 6 --max-depth 4 --persist

# Inspect the byte5 case
PYTHONPATH=src python -m d810.diagnostics dag-edge-alternate-selections \
    --db $DB --snap-id 6 --collapsed-edge 144
```

## Behavior layer (`apply_selected_alternate_edge_overrides_from_diag`)

The single behavior consumer of the diagnostic stack lives at
`d810.recon.flow.selected_alternate_edge_override`.  It is invoked
from `reconstruction.py` and `handler_chain_composer.py` immediately
after `snapshot_reconstruction_dag(...)` and BEFORE
`build_reconstruction_discovery_indexes(...)` so the override
participates in candidate generation.

Strict gates (all must hold for an override to fire):
- fact lifecycle evidence is available (default; `D810_FACT_LIFECYCLE=0`
  disables it)
- caller passed a non-None `(diag_db, snap_id)` from the snapshot result
- `dag_edge_diagnostics.classification = 'COLLAPSED_TO_REWRITTEN_TARGET'`
- exactly ONE `dag_edge_alternate_selections` row with `selected = 1`
  for the same `(snapshot_id, collapsed_edge_id)`
- `source_byte_index` and `reached_byte_index` both present, with
  the reached strictly larger
- the reached state's hex maps to an existing `dag.nodes` node
- in-memory edge mapping by VALUE
  (`source_state, target_state, source_block`) finds exactly one match

Mapping is by value, not persisted `edge_id`, because `edge_id` is
just the enumerate index of `dag.edges` at persistence time.  Both
`StateDagEdge` and `LinearizedStateDag` are
`@dataclass(frozen=True, slots=True)`; substitution returns a NEW dag
via `dataclasses.replace`.

When the override fires it logs
`RECON_DAG_EDGE_REPLACED_BY_SELECTED_ALTERNATE` per substitution and
`RECON_DAG_OVERRIDE_SUMMARY` once per call.

## Empirical results on `sub_7FFD3338C040`

The substrate proved the following on this function (work documented
in commits `87bd185c` through `c9d094ea` and the rolled-back
`TerminalTailPathSplitter` experiment):

1. **Fact guards work end-to-end.**  HCC chained-call-skip and the
   executor terminal-byte filter both successfully suppress
   state-flow predecessor injection on `terminal_tail` byte-emit
   destinations (`108 -> 143`, `129 -> 143`, `39 -> 161`, `62 -> 206`).

2. **Alternate-edge selection works.**  For the byte5 collapsed edge
   `0x385BBE2D -> 0x63D54755` (edge 144), the selector picks
   alternate edge 68 (`0x3873BC53 -> 0x10743C4C`, path
   `[101, 103, 104]`) reaching `STATE_2315233B` at depth 4
   (`reached_byte_index = 6`).  The early-return alternate edge 112
   (`0x3873BC53 -> 0x6E958F99`) is correctly rejected with reason
   `early_return_arm_no_later_terminal_tail`.

3. **Recon-DAG override is empirically inert at the pseudocode
   level.**  With default fact lifecycle evidence, the override fires (22
   substitutions across 4 strategy passes).  The recon DAG's
   `dag.edges` are mutated.  But the modifications emitted by HCC at
   snap 7 are byte-identical between override-on and override-off
   runs (118 mods, including `RedirectGoto: 158 -> 15`,
   `RedirectGoto: 207 -> 217`, etc.), and the AFTER pseudocode is
   byte-identical.  HCC's mutation queue derives `target_entry` from
   `discover_reconstruction_candidate_seed` (which reads
   `edge.target_state`) but the resulting CFG mutations converge
   because `ordered_path` is unchanged and the byte-tail chain
   `RedirectGoto 158 -> 15` is already produced by edge 39 via
   recon's direct-edge discovery, independent of the collapsed-edge
   override.

4. **Byte-tail topology splitting (`blk[143]` per-pred clones) is
   inert at the pseudocode level.**  The
   `TerminalTailPathSplitterStrategy` (rolled back, not committed)
   successfully reduced `blk[143]` post-apply preds from
   `[130, 135]` to `[130]` plus one cloned block, but IDA's
   structurer rendered the same `LABEL_x32DA` pattern.

5. **The for-loop predicate at `blk[81]` is real, not opaque.**
   Z3 confirmed `(v_528 + v_508) == v_4F8` is SAT (counterexample
   `v22 = 0x7FF7E50B1B8DC1EC`).  Folding it would not help.

6. **The remaining harness divergence is loop-predicate value loss.**
   `%var_3A8` (v22) is written only by `blk[151]`/`[186]` *outside*
   the post-HCC loop SCC.  Loop back-edges `[79, 236, 52] -> 81`
   never traverse a v22 writer, so v22 stays invariant per
   iteration in the rendered C transliteration.  D810's HCC
   linearization absorbed the dispatcher round-trip that originally
   refreshed the loop-predicate value each iteration but did not
   preserve a per-iteration value-flow def inside the loop region.

## Architectural ruling and next direction

For state-machine deobfuscation cases where the harness still
diverges after applying every fact-rooted guard, override, and
correlation, the load-bearing failure is **loop-predicate value
preservation**, not byte-tail topology and not opaque-predicate
folding.

The next architectural unit (deferred from the prior session) is a
`LoopPredicateValueFact` substrate that:

1. captures pre-HCC loop-predicate value defs + uses + loop SCC at
   LOCOPT/CALLS,
2. classifies `LOOP_CARRIER_WRITER_OUTSIDE_SCC` violations (the
   serialized fact-kind preserves the legacy name; see the
   value-flow alias registry),
3. persists fact rows mirroring the existing
   `state_write_anchor` / `state_transition_anchor` shape.

Behavior, after the diagnostic substrate proves stable, is one of:
- **preserve route** (preferred first): HCC refuses redirects that
  move a loop-predicate value def out of the loop SCC.  Mirrors the
  return materialization-point rule.
- **reinsert route**: HCC materializes a safe loop-predicate value
  def at the loop update point.

Do NOT pick a route until the `LoopPredicateValueFact` table shows
the violation persisted and queryable for `sub_7FFD`'s v22 case plus
at least one secondary case (likely the byte-counter).

---

## Vocabulary: value-flow facts and historical names

The fact ontology described above is the **value-flow** family per
``docs/plans/2026-05-18-value-flow-terminology-rename-design.md``. Code
symbols and serialized fact-kind strings still use the older
"carrier" vocabulary; the diagnostic alias registry at
``d810.recon.facts.value_flow.alias_registry`` normalizes raw
``FactObservation.kind`` values into canonical fact types at query
time.

When reading older code paths, diag SQL, or archived notes, translate
as follows:

|Read|Mean|
|-|-|
|carrier fact|value-flow fact|
|carrier|abstract location|
|`ObservableStoreFact` (kind)|`ObservableMemoryDefFact` (type)|
|`CarrierStorePromotionFact` (kind)|`ScalarPromotionFact` (type)|
|`SameCarrierAliasFact` (kind)|`MustAliasFact` (type)|
|`LocalStorageScalarizationFact` (kind)|`ScalarReplacementFact` (type)|
|`ExpressionCarrierFact` (kind)|`SymbolicExpressionFact` (type)|
|`LoopPredicateCarrierFact` (kind)|`LoopPredicateValueFact` (type)|
|`CallResultCarrierFact` (kind)|`CallReturnValueFact` (type)|
|`GenericInductionCarrierFact` (kind)|`InductionVariableFact` (type)|
|`TerminalMaterializationFact` (kind)|`MaterializationPointFact` (type)|
|`StateVariableWriteFact` (kind)|`StateWriteFact` (type)|
|`StateTransitionCarrierFact` (kind)|`StateTransitionFact` (type)|
|`SideEffectCorridorFact` (kind)|`EffectPathFact` (type)|
|`CallSideEffectAnchorFact` (kind)|`CallEffectSummaryFact` (type)|
|`InductionCarrierFactCollector`|`InductionVariableFactCollector`|
|`LoopCarrierFactCollector`|`LoopPredicateValueFactCollector`|
|`ReturnCarrierFactCollector`|`ReturnSlotFactCollector` (with `ReturnValueFactCollector` reserved for value-recovery facts)|
|`OllvmSemanticCarrierFactCollector`|`OllvmValueFlowEvidenceCollector`|

The legacy collector class names remain importable as compatibility
aliases. The serialized ``FactObservation.kind`` values stay at their
historical strings; old diag SQLite snapshots therefore remain
queryable through the canonical surface without rewrites.

See the Phase 0 inventory under ``.tmp/terminology_rename/`` for the
full glossary, term definitions (materialization point, ModRef,
MemoryDef vs MemoryUse vs MemoryPhi, etc.), and the rename-map
rationale.
