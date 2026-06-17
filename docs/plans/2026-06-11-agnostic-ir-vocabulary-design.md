# Agnostic IR Vocabulary — design (operations + router + stage gates)

Branch `llvm-lisa-restructure`. 2026-06-11. Epic `llr-rv7p` (program `llr-sqai`).
Inputs: this session's cross-backend study (Hex-Rays µcode, P-Code, VEX, LLVM,
dewolf) + the enums-over-strings + converter-boundary decisions.

## Governing principle — one axis per concept

Every distinction lives on exactly ONE axis; everything else is orthogonal
metadata. This is the same move applied twice:

|domain|the intrinsic axis (the enum)|orthogonal metadata|
|-|-|-|
|operations|the operation (`ValueOpKind` etc.)|signedness→op, width→operand.size, indirect-call→operand, raw opcode→attrs|
|dispatchers|router SHAPE (`RouterKind`)|dispatch KEY transform, EDGE transfer, detector PROVENANCE|

The test for "is this a distinct enum member?" is **"is the routing/operation
ALGORITHM different?"** — NOT "is the predicate/recognition-path different?".
That single test folds `BST`→`CONDITION_CHAIN` and `SWITCH`/`INDIRECT_TABLE`→
`TABLE`: same algorithm, different recognition path = same member + provenance.

---

## Part A — Operation vocabulary (Option 1: one normalized op, raw in attrs)

Three complementary enums (two already exist and already embody the decisions):

* `ValueOpKind` (`ir/expressions.py`) — value-producing ops. GROW it.
* `PredicateKind` (`ir/semantics.py:60`) — compares. DONE (signedness already in
  the op: `SLT` vs `ULT`). No change.
* `ControlTransferKind` (`ir/semantics.py:88`) — terminator/control transfer.
  Already has `INDIRECT_BRANCH`/`TABLE_BRANCH` first-class. Calls stay in a
  separate `CallKind` family; do **not** add `ControlTransferKind.CALL` unless
  that contract is deliberately reopened.

There is NO monolithic "OpKind"; these three together ARE the op vocabulary.

### A1. Grow `ValueOpKind` (P-Code altitude: machine-near, typeless)
Add: `MUL`, `UDIV/SDIV`, `UMOD/SMOD`, `OR`, `XOR`, `NOT`, `NEG`, `SHL`, `SHR/SAR`
(shift signedness in the op), rotates + carry variants, `ZEXT/SEXT/TRUNC`,
`LOW/HIGH`, and a `VENDOR` escape. Switch values `auto()` → `(str, Enum)`
portable tokens (`"add"`, `"sar"`) to match `PredicateKind` and keep diag/golden
serialization stable. YAGNI: enroll only what the backlog (~35 µcode ops) + the
obvious P-Code core need, not a full P-Code clone.

### A2. Collapse rules
* signedness → in the op (`SAR`/`SHR`, `SDIV`/`UDIV`; compares via `PredicateKind`)
* width → never in the op; carried by `varnode.size`
* direct/indirect **call** → `CallKind` sibling vocabulary; indirect = callee
  `varnode.space != CONST` (derived predicate, no `ICALL`). Keep call effects
  out of `ControlTransferKind`, which remains terminator/control-transfer only.
* direct/indirect **jump** → stays first-class (`GOTO` vs `INDIRECT_BRANCH`/
  `TABLE_BRANCH`) — dispatcher recovery needs it (the dewolf asymmetry)
* unmodeled → `ValueOpKind.VENDOR`, raw opcode in `attrs`

Status 2026-06-17: the live IR contract in `ir/semantics.py` already says calls
belong to a separate `CallKind` family. This plan now follows that contract.
Ticket `llr-a5b7` tracks the remaining operation-vocabulary implementation and
lift tests.

### A3. Provenance & lift
`Operation.attrs` carries `raw_opcode_int` + `raw_opcode_name` + backend id
(diagnostics only; the `op_<N>` fallback disappears). Per-backend lift table in
`d810/backends/<vendor>/opcode_lift.py`: `lift_opcode(raw) -> (kind, attrs)`.
Hex-Rays first; `pcode`/`vex`/`llvm` later reuse the SAME three enums.

### A4. Migration off the `OpcodeName` bridge
`ir/opcode_name.py:OpcodeName` (built this session, `(str,Enum)` valued at the
mnemonics) is the TRANSITIONAL bridge: strings→`OpcodeName.X` is behaviour-
neutral and decoupled. End-state: lift emits the three enums; `OpcodeName` +
`op_<N>` retire.

---

## Part B — Router decomposition (the lean model)

Four orthogonal enums replace the conflated `RouterKind` + `DispatcherType`.

```python
class RouterKind(str, enum.Enum):       # the SHAPE only
    TABLE = "table"
    EQUALITY_CHAIN = "equality_chain"
    CONDITION_CHAIN = "condition_chain"  # subsumes BST (interval bisection)
    UNKNOWN = "unknown"

class TableProvenance(str, enum.Enum):   # recognition path, NOT router identity
    COMPILER_SWITCH = "compiler_switch"
    RECOVERED_INDIRECT_JUMP = "recovered_indirect_jump"
    COMPUTED_GOTO = "computed_goto"
    MANUAL_TABLE = "manual_table"

class DispatchKeyTransformKind(str, enum.Enum):   # what is compared/indexed
    IDENTITY = "identity"
    AFFINE = "affine"
    XOR = "xor"
    MBA = "mba"
    HASH = "hash"
    MODULO = "modulo"
    TABLE_LOOKUP = "table_lookup"        # data table: state -> next_state
    PREDICATE = "predicate"

class EdgeTransferKind(str, enum.Enum):  # how a chosen edge transfers control
    DIRECT_BRANCH = "direct_branch"
    FALLTHROUGH = "fallthrough"
    INDIRECT_JUMP = "indirect_jump"
    CALL_THREADED = "call_threaded"
    RETURN_THREADED = "return_threaded"
    EXCEPTION = "exception"
```

### B1. Why each fold
* `BST` → `CONDITION_CHAIN`: both route by interval bisection over the key. BST's
  balanced nesting is a recovery detail; `ComparisonDispatcherModel`/IntervalSet
  becomes the `CONDITION_CHAIN` resolver, not a separate kind.
* `EQUALITY_CHAIN` stays: exact-match map is a different routing primitive.
* `SWITCH`/`INDIRECT_TABLE` → `TABLE`: both are indexed jump through a table of
  code addresses; they differ only in whether `get_switch_info` recognises it →
  `TableProvenance.{COMPILER_SWITCH, RECOVERED_INDIRECT_JUMP}`.
* `LOOKUP_TABLE` strict split: a **code-address** table (`state -> code_ptr`) IS
  `RouterKind.TABLE`; a **data** table (`state -> next_state`) is NOT a router —
  it is `DispatchKeyTransformKind.TABLE_LOOKUP` feeding whatever router consumes
  the resulting key.
* arithmetic/hash/MBA/xor → `DispatchKeyTransformKind` (key, not shape).
* fall-through, default → `EdgeTransferKind` (edge, not shape).
* predicate-without-state-var → `CONDITION_CHAIN` whose key transform is
  `PREDICATE` (no separate `PREDICATE_CHAIN` router).

### B2. Current state being replaced / remaining gaps
Status 2026-06-17:

* `RouterKind.BST` is removed; BST/interval evidence now reports
  `RouterKind.CONDITION_CHAIN`.
* Shared/public comparison-chain vocabulary now uses condition-chain names:
  `condition_chain_model.py`, `ConditionChain*`, `RouteComparison`,
  `StateArmComparison`, and `extract_state_arm_comparisons`. The stale shared
  `extract_bst_comparisons` API was removed by `c927f500e`.
* The old `DispatcherType` enum is retired; dispatcher source vocabulary is now
  routed through `RouterKind`.
* `FixPredSignalsCollector` now emits `router_kind`, not `dispatcher_type`.
* Router-shape fields formerly named `source` are now `router_kind` across
  dispatcher maps, recovered machines, handler maps, and branch witness maps.
  Do not reintroduce a `source` compatibility alias for router shape.
* Generic DAG/lowering surfaces no longer thread comparison-chain evidence
  through retired binary-tree vocabulary. Ticket `llr-x9xt` is closed; the
  public lowering vocabulary is `condition_chain_*`, including condition-chain
  redirect/lowering structures and condition-chain diagnostic snapshot/resolution
  helpers.
* Backend/provider seams no longer expose retired binary-tree walker,
  registration, evidence-module, or runtime-module names. Ticket `llr-am0v` is
  closed; the current provider seam is `ConditionChainWalkerProvider` plus
  `register_condition_chain_walkers` / `get_condition_chain_walkers`, backed by
  `condition_chain_analysis.py` and `condition_chain_runtime.py`.
* Python-facing diagnostics/tooling names moved to condition-chain spelling:
  `condition_chain_snapshot.py`, `transition_condition_chain_adapter.py`,
  `diagnostics/condition_chain_resolution.py`, and
  `--dump-condition-chain-maturity`. This was an intentional hard rename, not a
  persisted-schema compatibility shim.

Remaining gaps:

* `RouterKind` still has `SWITCH` and `INDIRECT_TABLE`; those must collapse to
  `TABLE` with `TableProvenance.{COMPILER_SWITCH, RECOVERED_INDIRECT_JUMP}`.
  This is schema/tooling-sensitive because diag rows, CLI queries, and persisted
  `dispatcher_kind` compatibility currently encode `SWITCH`/`INDIRECT_TABLE`.
* The dispatch-key axis still leaks as
  `TransitionTrustKind.DERIVED_DISPATCH_KEY`; extract it into
  `DispatchKeyTransformKind`.

---

## Part C — Stage / maturity vocabulary (already mostly solved)

No new enum is needed for pass maturity gates. Reuse the split that already
exists:

* `d810.ir.maturity.IRMaturity` is the portable pass-gating vocabulary:
  `LIFTED`, `CANONICAL`, `LOCAL_OPTIMIZED`, `CALL_MODELED`,
  `GLOBAL_ANALYZED`, `GLOBAL_OPTIMIZED`, `STRUCTURED`,
  `VARIABLE_RECOVERED`.
* `d810.hexrays.ir_maturity` is the Hex-Rays adapter from `IRMaturity` to
  `ida_hexrays.MMAT_*`. Other backends add their own adapters.
* `FlowGraph.metadata["snapshot_stage"]` / `SnapshotStage` is the coarse
  read-only snapshot classification for analyses that only need to ask whether
  the graph is raw, normalized, optimized, SSA-like, lvar-recovered, or
  final-pre-render.
* `producer_stage_id` / `producer_stage_name` remain provider-local diagnostic
  metadata. Portable passes should not key behavior on `MMAT_*` strings.

The rule for `PipelineConfig v2`: pass specs declare `IRMaturity` gates; backend
hook adapters resolve those gates to native callback stages. `SnapshotStage` is
not a replacement for `IRMaturity`; it is a lossy analysis hint.

Current migration gap: some collectors and fact lifecycle code still carry raw
Hex-Rays maturity integers / `MMAT_*` strings. Those should move behind the same
adapter boundary over time, but the vocabulary axis itself does not need a new
design.

---

## Migration plan (ordered slices, each behaviour-preserving + Docker-golden-gated)

1. **Fold `BST` → `CONDITION_CHAIN`.** Families pin `CONDITION_CHAIN`; the
   IntervalSet/`ComparisonDispatcherModel` resolver handles range routing. Touch:
   `capabilities/dispatcher.py`, `passes/unflatten/state_machine.py:95`, the
   family PassSpec factories, `bst_model.py` (becomes the CONDITION_CHAIN
   recovery, not a kind).

   Status 2026-06-17: implemented by commits `923225dad` and `c126ee703`.
   `RouterKind.BST` is removed; the BST/interval resolver now reports
   `RouterKind.CONDITION_CHAIN`.

   Refinement 2026-06-17: shared/public names must also stop saying BST.
   Commits `c1c104fa2`, `5ca9c8358`, and `c927f500e` moved generic router API
   parameters, the shared model, and the shared dispatcher extractor onto
   condition-chain/state-arm vocabulary. Remaining `bst` spellings are not
   blanket-approved; each residual hit must classify as persisted schema
   compatibility, historical backend implementation, provider-seam debt, or a
   cleanup item under `llr-x9xt`.
2. **Unify `RouterKind` + `DispatcherType`** into one router-shape enum.

   Status 2026-06-17: implemented by commits `fffd1f6b9` and `cdb876dbc`.
   `dispatcher_kind.py` is deleted, dispatcher maps/rows carry `RouterKind`, and
   FixPred emits the canonical `router_kind` metric. Ticket `llr-m6cs` tracked
   the enum unification; ticket `llr-80s8` tracked the FixPred stale-surface
   follow-up.
3. **Rename `StateDispatcherMap.source` → `router_kind`.**

   Status 2026-06-17: implemented by `ba722831d` under ticket `llr-z0gd`.
   Rows/maps use `router_kind` for shape with no compatibility alias.
4. **Complete condition-chain vocabulary on DAG/lowering surfaces.**

   Status 2026-06-17: implemented. Ticket `llr-x9xt` completed the generic
   DAG/lowering rename, and ticket `llr-am0v` completed the backend/provider
   seam rename. The public vocabulary is condition-chain/range-evidence shaped:
   `condition_chain_*`, `range_evidence`, and `dispatcher_region` according to
   semantic role. Python-facing diagnostics/tooling names also use
   condition-chain spelling, including `--dump-condition-chain-maturity`.

   This unblocks `llr-nulv`. The table-provenance slice no longer has to reason
   through retired comparison-chain vocabulary while also changing the table
   router taxonomy.
5. **Collapse `SWITCH`/`INDIRECT_TABLE` → `TABLE`** + introduce
   `TableProvenance`.

   Ticket: `llr-nulv`. This is not a pure enum rename; it must migrate
   producers, family ownership gates, CLI/diagnostic readers, and persisted diag
   schema compatibility.
6. **Extract dispatch-key** out of `TransitionTrustKind` into
   `DispatchKeyTransformKind`.

   Ticket: `llr-rec9`.
7. **Detector provenance becomes metadata**, not enum identity (the standing
   rule that prevents the debt recurring).

   Breadcrumb cleanup ticket: `llr-zkju` classifies or removes stale comments,
   scripts, and tests that still teach retired router taxonomy.

Each phase: golden suite green via the Docker runner (NEVER local `pytest
tests/system` — false-red). Unit + `lint-imports` locally.

## Risk
Moderate, not high. The remaining risk is not condition-chain router semantics;
it is table-router taxonomy and boundary drift. Condition-chain routing still
uses the same interval/range evidence and the same golden-gated behavior. Do
NOT keep five router kinds "for now" and do NOT let retired comparison-chain
vocabulary leak back into shared APIs; the completed condition-chain rename is
the mitigation.
(`ComparisonDispatcherModel` routes 62/62 sub_7FFD states when the range walk
feeds it; that stays true with the resolver under `CONDITION_CHAIN`.)

## Where it lives
`capabilities/dispatcher.py` (RouterKind, TableProvenance), a new
`analyses/control_flow/dispatch_key.py` (DispatchKeyTransformKind),
`ir/semantics.py` (EdgeTransferKind beside ControlTransferKind),
`ir/expressions.py` (grown ValueOpKind), `backends/<vendor>/opcode_lift.py`
(lift tables). `DispatcherType` retires into `RouterKind`. Maturity/stage
vocabulary stays in `ir/maturity.py` (`IRMaturity`) plus `FlowGraph`
`SnapshotStage`; do not create another stage enum.

## Testing
* cross-backend lift-table test: every backend opcode → a kind, no gaps.
* str-enum equivalence battery (op-vocab) + router-remap parity per phase.
* the family dispatcher goldens (hodur/approov/ollvm/tigress/sub_7FFD) green
  through every phase.
