# Insert-Based Lowering — Roadmap

Status: 2026-06-06. The restructuring lab validates that d810's IR→Hex-Rays
microcode **lowering** renders cleanly, using the proven harness from Phases 1-3:
mutate via an `optblock_t` during `MMAT_GLBOPT1` returning the change count (so
IDA rebuilds the graph/chains cache — avoids INTERR 50346), insert/copy blocks
**state-free by construction**, and assert on the rendered pseudocode.

**Framing:** d810 already *models* the lowering ops (27 in
`transforms/graph_modification.py`) and the analyses (loops/scc/dominators in
`analyses/control_flow/`). For most items the gap is **lab-validation** (prove the
op renders clean via the optblock path) — not net-new code. A minority are
**genuine deficiencies** (the de-flatten deficiency ledger + this session's
findings). Each item below names what d810 HAS and what's MISSING.

## Done (this session)

- **P1 linear insert** — `InsertBlock`/`queue_create_and_redirect`; renders linear chain. (`886*`/`45f*`)
- **P2a conditional preserve** — handler jcc preserved + arm redirects + dispatcher-routing extractor; renders if/else.
- **P3 de-share state-free** — `capture_payload`-style capture stripping all state-const writes + control-flow; renders duplicated work, no state var.
- **INTERR 50346/50860 reverse-engineered** + optblock-stage requirement, documented in `deferred_modifier`, the hexx64 IDB, spec, memory.

## Backlog

| id | item | d810 HAS | gap | prio | spec |
|-|-|-|-|-|-|
| L1 | loops / back-edges | `backedge_classifier`,`loops`,`loop_prover`,`scc_analysis`,`PhaseCycleLowering` | lab-validate a reconstructed loop renders `while`/`do-while` | HIGH | drafted |
| L2 | full state elimination (reg/computed) | `_state_slot`(KT-disc.),`ZeroStateWrite` | strip reg-sourced/computed state; reconstruct the entry selector (P3 residual) | HIGH | drafted |
| L3 | EA / provenance | `insn_snapshot_materializer` | real `insn_ea` on inserted insns (ledger: `StateWriteAnchor` lacks `insn_ea`); we use the `entry_ea` hack | HIGH | drafted |
| L4 | projected-gate wiring | `verify_projected`/`projected_contract` (`transaction_engine`/`policy`/`contract`) | drive lab inserts through the pre-mutation gate ("prove before commit") | HIGH | drafted |
| L5 | INTERR→projected-invariant coverage | `contracts/invariants`,`*parity_matrix.json`,native_oracle | populate the "close a gap" map: each `native_verify` INTERR (50346/50860/…) gets a projected invariant | HIGH | drafted |
| L6 | jump-table / N-way dispatch | `NormalizeNWayDispatcherExit`,`CanonicalizeJumpTableCaseOverlap`,`dispatcher_materialization` | `m_jtbl` fixture + lab-validate (our fixtures are if-chain) | MED | drafted |
| L7 | multi-block subgraph insert | `DuplicateReplayAndRedirect`,`new_blocks: PatchBlockSpec` | insert a captured *region* (2+ blocks, internal edges) as a unit | MED | drafted |
| L8 | conditional synthesis (P2b) | `LowerConditionalStateTransition`,`CreateConditionalRedirect` | branchless/cmov or dataflow-recovered predicate → synthesize the branch | MED | drafted |
| L9 | true dead-def removal | `ZeroStateWrite`,`insn_snapshot_materializer`(IPROP_PERSIST) | deterministic dead-def removal, not DCE-reliance (ledger) | MED | drafted |
| L10 | maturity-timing contract | (none) | formalize which op is legal at which maturity; we hardcode GLBOPT1 (ledger) | MED | drafted |
| L11 | operand / alias fixups | `PromoteOperandToScalar`,`ScalarizeLocalAliasAccess` | stack/alias-operand fixture + lab-validate | LOW | drafted |
| L12 | MBA / opaque-predicate simplification | optimizer rule engine | handler-body simplification (the *structurability* half; separate track) | LOW | drafted |
| L13 | robustness | `ReorderBlocks`,`dispatcher_residue_cleanup` | idempotency across optblock passes, reorder/cleanup, transactional rollback in lab | LOW | drafted |

## Phasing & dependencies

- **Phase A (real-function readiness):** L1 (loops) + L2 (full state elim) + L3 (EA). Without these, no real flattened function (sub_7FFD-class) reconstructs cleanly. Do first.
- **Phase B (provable lowering):** L4 (projected gate) + L5 (INTERR coverage) + L10 (maturity contract). Turns "it rendered" into "provably won't INTERR" — the AGENTS.md vision. Depends on A for realistic INTERR coverage.
- **Phase C (shape breadth):** L6 (jtbl), L7 (multi-block), L8 (conditional synthesis). Each a new fixture + validate.
- **Phase D (polish):** L9, L11, L13. L12 (MBA) is an orthogonal optimizer-rule track.

## Adjacent d810 capabilities to leverage (not just the lowering ops)

The lab uses **manual** plans; production d810 already has automatic machinery the
roadmap should lean on instead of reinventing:

- **Detection / routing** (vs our hand-rolled `_dispatcher_routing`): decision-DAG
  route oracle (`route_predicate`, `decision_dag_extract`), `bst_analysis`,
  `switch_case_transitions`, `carrier_resolver_live`, `state_machine_adapters`,
  `structured_program_live` (under `backends/hexrays/evidence/`). Move the lab
  from hand-mapped routing to recon-driven once the primitives are proven.
- **Abstract domains** (value/predicate recovery for **L8** synthesis + **L12**
  MBA): `analyses/abstract_domains/` — `known_bits`, `wrapped_interval`,
  `interval_set`, `interval_box`, `relational`, `value_domain`. Recover the
  branchless predicate / fold MBA instead of pattern-matching.
- **Production unflatteners** (the integration target the primitives feed):
  `state_machine_cff_unflattener`, `unflattener_emulated_dispatcher_engine`,
  `unflattener_cleanup_family`, hodur.
- **LLVM-shaped deflatten / terminal stack** (already built): `transforms/`
  `deflatten_primitives`, `deflatten_terminals_pass`, `terminal_corridor_emission`
  /`planning`, `terminal_family_split`, `terminal_tail_cascade_egress_planner`,
  `terminal_tail_*` — the terminal-tail cascade (the `ref_cascade` shape the lab
  proved). Reuse for terminal lowering rather than re-deriving it.

## Validation contract (every item)

A lowering item is DONE when its lab fixture: (1) builds + passes the compiled-CFG
gate; (2) applies via the optblock-stage path with `mba.verify()` clean (no
INTERR); (3) renders the expected clean pseudocode; (4) has a checked-in
observation. New blocks/copies are **state-free by construction**; control-flow is
stripped by opcode (not `is blk.tail`). See `AGENTS.md` + the Phase 1-3 spec.
