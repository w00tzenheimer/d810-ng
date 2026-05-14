# Hodur Live-Analysis Strategy Boundary

This note inventories the remaining "smaller live-analysis" Hodur strategies that
mostly emit backend-neutral graph modifications, but still collect evidence by
reading live Hex-Rays microcode directly.

The target boundary is:

- cfg and engine express backend-neutral intent.
- recon owns read-only semantic evidence.
- Hodur owns strategy policy, ordering, gates, logging, and profile defaults.
- Hex-Rays adapters own live `mba_t`, `mblock_t`, `minsn_t`, `mop_t`,
  opcode, block-type, use-def, dirty-chain, verifier, copy, NOP, and rewrite
  mechanics.

The problem in these strategies is not that their final lowering intent is
wrong. Most final actions are already neutral, usually `GraphModification`
objects such as `ConvertToGoto`, `RedirectGoto`, `ZeroStateWrite`, or
`NopInstructions`. The boundary leak is that the strategy code still asks
Hex-Rays-shaped questions while deciding whether those neutral actions are safe.

## Current Inventory

| Strategy | Backend-neutral intent already emitted | Live Hex-Rays detail still mixed in | Suggested boundary |
| --- | --- | --- | --- |
| `spurious_backedge_redirect.py` | Convert selected spurious backedges to gotos using `ConvertToGoto`. | Walks `mba.get_mblock`, `nsucc`, `succ`, `blk.type`, `blk.head`; parses `insn._print()` output for reads and writes. | Move topology and read/write collection behind live topology and predicate evidence backends. Keep cfg planner consuming plain maps. |
| `state_constant_return_fixup.py` | NOP leaked dispatcher-state constant writes on return paths using `NopInstructions`. | Finds STOP blocks, return mux shape, feeder blocks, tail instructions, opcodes, operands, stack offsets, and state-variable fallback with `ida_hexrays` constants and live operands. | Move return-path shape detection and cleanup-site classification behind a return cleanup evidence backend. Hodur only decides whether to accept the cleanup sites. |
| `dead_state_variable_elimination.py` | NOP proven dead dispatcher-state reads using `NopInstructions`. | Finds state-var uses, reaching defs, value ranges, block tail shape, gutted blocks, branch tails, dynamic writes, stack-var operands, constants, and indirect stack definitions using live microcode. | Move use/def/value-range and read cleanup classification behind a dead state-variable evidence backend. Preserve Hodur policy as explicit guards over neutral decisions. |
| `linearized_flow_graph.py` | Emits `RedirectGoto`, `RedirectBranch`, `ConvertToGoto`, `ZeroStateWrite`, `PrivateTerminalSuffix`, and suffix groups from flow graph plans. | Imports `ida_hexrays` for maturity and block type checks, passes live `mba` into use-def safety and projected live DAG helpers, and performs Hex-Rays use-def veto checks during postprocessing. | Move maturity gates, block-type normalization, projected topology views, and redirect use-def safety checks behind backend protocols. Keep graph planning in cfg/recon. |

## Strategy Notes

### Spurious Backedge Redirect

This strategy is a good first migration candidate because it is isolated,
default-off, and already hands neutral dictionaries to cfg planning.

Current intent:

- Detect actionable spurious `BLT_2WAY` backedges inside live SCCs.
- Emit `ConvertToGoto` through `ModificationBuilder.convert_to_goto`.

Current live evidence collection:

- Builds successor and block-type maps from live `mba` blocks.
- Walks live instructions from `blk.head`.
- Uses `insn._print()` and token parsing to infer variable reads and writes.
- Classifies jump-like instruction text to split predicate reads from ordinary
  reads.

Proposed boundary:

- `LiveTopologyBackend` returns normalized block topology:
  block serial, successor serials, predecessor serials when needed, and a
  backend-neutral block-type name.
- `PredicateReadWriteEvidenceBackend` returns per-block write sets and
  predicate-read sets.
- cfg keeps `plan_spurious_backedge_redirects` as the pure planner over those
  maps.

Data crossing the boundary should be normalized evidence such as block serials,
type names, and variable-token strings. It should not include `mblock_t`,
`minsn_t`, opcode constants, or printed instruction text.

### State Constant Return Fixup

This strategy is a cleanup pass for leaked dispatcher-state constants on return
paths after linearization.

Current intent:

- Identify return-path synthetic state writes that survived lowering.
- Emit `NopInstructions` for the accepted cleanup sites.

Current live evidence collection:

- Finds the STOP block by scanning live block types.
- Inspects STOP predecessors and return mux predecessor shape.
- Walks instruction tails and previous instruction links.
- Classifies `m_mov`, `m_xdu`, `m_xds`, `mop_n`, `mop_r`, and `mop_S`.
- Extracts stack offsets from live operands.
- Falls back to the live state-machine `mop_S` state variable when snapshot
  state evidence is incomplete.

Proposed boundary:

- `ReturnPathCleanupEvidenceBackend` detects return mux shapes and candidate
  cleanup sites using live Hex-Rays details.
- Hodur supplies policy inputs: known dispatcher state constants, the known
  state-variable identity when available, and any profile gate.
- The backend returns neutral cleanup candidates with reasons.
- Hodur accepts or rejects candidates and emits `NopInstructions`.

This keeps the Hex-Rays questions inside the adapter:

- "Is this block the STOP block?"
- "Is this feeder instruction a synthetic return write?"
- "Does this operand refer to the return slot?"
- "Does this source operand represent a dispatcher-state constant?"

The strategy should only see answers such as "cleanup instruction at block 42,
EA 0x1234 because it is a leaked state constant write on a return feeder".

### Dead State Variable Elimination

This strategy is the highest-risk item in this group because most of its safety
comes from live Hex-Rays analysis.

Current intent:

- Remove reads of the dispatcher state variable after the dispatcher has been
  linearized.
- Preserve reads that may carry return values, dynamic state, branch-tail use,
  or non-state stack variable data.

Current live evidence collection:

- Resolves the state variable from live `mop_S` fallback data.
- Finds all stack-var uses and reaching definitions through evaluator helpers.
- Runs value-range fixpoint analysis.
- Reads live block shape to skip two-way branch tails.
- Walks live instructions to detect gutted blocks.
- Classifies source and destination operands, constants, stack offsets, and
  dynamic state writes.
- Chases indirect stack-var definitions by walking previous live instructions.

Proposed boundary:

- `DeadStateVariableEvidenceBackend` owns live use/def/value-range collection.
- It returns neutral decisions for each observed use:
  preserve, cleanup, or unknown, with a stable reason code.
- Hodur policy remains explicit:
  skip BST node blocks, preserve return-carrier cases, and only emit cleanup
  when the decision is proven.

The adapter must preserve rejection reasons. The current implementation is
conservative, and weakening one guard can silently damage return-slot semantics.
Tests should assert not just the accepted NOP sites, but also representative
preservation reasons.

### Linearized Flow Graph

This strategy is closest to the desired architecture because most topology
planning already uses `FlowGraph`, cfg planning, and neutral graph
modifications. The remaining leaks are mostly live safety checks and backend
gates.

Current intent:

- Apply linearized graph rewrites selected from recon/cfg evidence.
- Redirect edges, convert dispatcher roots, zero state writes, and isolate
  private terminal suffixes.

Current live Hex-Rays coupling:

- Checks `mba.maturity` against `ida_hexrays.MMAT_GLBOPT1`.
- Uses `ida_hexrays.BLT_2WAY` to avoid unsafe dead dispatcher root conversion.
- Calls live use-def safety helpers to veto redirects.
- Passes live `mba` into effective target and projected DAG helpers.
- Builds projected MBA-like views from flow graph snapshots for some analyses.

Proposed boundary:

- `MaturityGateBackend` converts live maturity into a neutral profile gate such
  as `"global_opt_1"`.
- `BlockTypeBackend` normalizes live block types into strings or enum values
  before strategy code sees them.
- `UseDefSafetyBackend` answers whether a proposed redirect severs a live
  use-def chain.
- `ProjectedTopologyBackend` provides a neutral block/topology view when a
  planner needs live-shaped topology without direct `mba` access.

The strategy should continue to own policy, ordering, and env gates. It should
not own Hex-Rays use-def mechanics.

## Proposed Adapter Surface

Do not create one large materialization object for all of this. These strategies
need small read-only evidence protocols. Mutation still belongs in the Hex-Rays
materialization backend.

Example protocol split:

```python
@dataclass(frozen=True)
class BlockTopologyEvidence:
    serial: int
    block_type: str
    succs: tuple[int, ...]
    preds: tuple[int, ...] = ()


@dataclass(frozen=True)
class PredicateReadWriteEvidence:
    block_serial: int
    writes: frozenset[str]
    predicate_reads: frozenset[str]


@dataclass(frozen=True)
class ReturnCleanupSite:
    block_serial: int
    insn_ea: int
    reason: str
    observed_state: int | None = None


@dataclass(frozen=True)
class StateVariableRef:
    stkoff: int
    size: int | None = None


@dataclass(frozen=True)
class StateVarUseEvidence:
    block_serial: int
    insn_ea: int
    role: str


@dataclass(frozen=True)
class DeadStateReadDecision:
    block_serial: int
    insn_ea: int
    action: str
    reason: str


@dataclass(frozen=True)
class UseDefViolation:
    source_block: int
    use_block: int
    insn_ea: int
    reason: str
```

Possible backend protocols:

```python
class LiveTopologyBackend(Protocol):
    def collect_block_topology(self, live_function: object) -> tuple[BlockTopologyEvidence, ...]:
        ...


class PredicateReadWriteEvidenceBackend(Protocol):
    def collect_predicate_read_write_evidence(
        self,
        live_function: object,
    ) -> tuple[PredicateReadWriteEvidence, ...]:
        ...


class ReturnPathCleanupEvidenceBackend(Protocol):
    def collect_return_cleanup_sites(
        self,
        live_function: object,
        *,
        state_constants: frozenset[int],
        state_variable: StateVariableRef | None,
    ) -> tuple[ReturnCleanupSite, ...]:
        ...


class DeadStateVariableEvidenceBackend(Protocol):
    def classify_dead_state_reads(
        self,
        live_function: object,
        *,
        state_variable: StateVariableRef,
        state_constants: frozenset[int],
        excluded_blocks: frozenset[int],
    ) -> tuple[DeadStateReadDecision, ...]:
        ...


class UseDefSafetyBackend(Protocol):
    def redirect_use_def_violations(
        self,
        live_function: object,
        modification: object,
    ) -> tuple[UseDefViolation, ...]:
        ...
```

The `live_function: object` parameter is intentionally opaque in the generic
protocol examples. In the Hex-Rays implementation it can be an `mba_t`, but cfg,
recon, and generic engine code should not know or import that type.

## Data Contract Rules

Data that may cross into cfg, recon, or generic engine code:

- Block serials.
- Edge endpoints.
- Normalized block-type names.
- State constants as integers.
- State-variable references as neutral stack offsets and sizes.
- Instruction sites as block serial plus EA or stable backend-owned site token.
- Opaque backend-owned capture tokens that cfg may carry but never inspect.
- Reason codes for diagnostics and tests.

Data that must remain Hex-Rays-specific:

- `mba_t`, `mblock_t`, `minsn_t`, and `mop_t`.
- Opcode constants such as `m_mov`, `m_xdu`, `m_xds`, and `m_nop`.
- Operand-kind constants such as `mop_n`, `mop_r`, and `mop_S`.
- Block-type constants such as `BLT_2WAY` and `BLT_STOP`.
- Maturity constants such as `MMAT_GLBOPT1`.
- Instruction identity and copy mechanics.
- `_print()` formatting and printed microcode parsing.
- Dirty-chain, verifier, rollback, and `MBL_KEEP` mechanics.
- Live use-def graph details and value-range fixpoint internals.

## Minimal First Slice

The smallest behavior-preserving slice is `spurious_backedge_redirect.py`:

1. Introduce neutral evidence objects for live topology and predicate read/write
   maps.
2. Implement a Hex-Rays evidence adapter that contains the current `mba` block
   scans and `insn._print()` parsing.
3. Change the strategy to request evidence from the adapter, then pass plain
   maps into the existing cfg planner.
4. Keep the final `ConvertToGoto` emission unchanged.

This proves the boundary with low blast radius because the strategy is
default-off and already planner-shaped.

A second small slice is to wrap `linearized_flow_graph.py` use-def vetoes:

1. Add a `UseDefSafetyBackend` method around the current
   `check_redirect_severs_use_def` call.
2. Keep the redirect planning and rejection policy unchanged.
3. Add fake-backend unit tests that assert the strategy vetoes redirects when
   the backend reports violations.

## Risks

- Printed instruction parsing is backend formatting, not semantic truth. Moving
  it behind an adapter hides the coupling, but does not make it robust.
- Dead state-variable cleanup can corrupt return-slot behavior if guard reasons
  are collapsed or reordered.
- Use-def safety is live-microcode and maturity sensitive. Fake unit tests should
  test the strategy boundary, not attempt to emulate Hex-Rays use-def behavior.
- Instruction sites based only on EA may be ambiguous. Where needed, use a
  backend-owned opaque site token and keep cfg from interpreting it.
- Block-type and maturity names must be normalized before crossing the boundary.
- Diagnostic reason codes should remain stable enough for sub7FFD debugging and
  baseline review.

## Validation Plan

- Pure unit tests for evidence objects and fake backends.
- Focused Hodur strategy tests for the migrated strategy.
- Existing cfg planner tests should remain Hex-Rays-free.
- Import-linter should confirm cfg and recon do not import Hex-Rays or Hodur.
- sub7FFD validation should compare dump/oracle/AFTER output against
  `_gitless/baselines/sub7ffd-structure-recovery-pass-2026-05-13`.
- Run sub7FFD both with and without debug logging when fact lifecycle is enabled,
  because debug logging must not change live decisions.
