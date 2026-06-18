"""Pure dispatcher analysis over portable CFG snapshots.

This module is the pure dispatcher-analysis counterpart to the live
Hex-Rays adapter. It does not import Hex-Rays APIs and does not lift live
microcode. Callers pass a ``FlowGraph`` snapshot plus the two history
values preserved across maturity transitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.ir.flowgraph import (
    PredicateKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)
from d810.ir.expressions import Const
from d810.ir.insn_projection import project_assignment, project_conditional_branch
from d810.ir.mop_identity import mop_snapshot_key, mop_snapshot_offset
from d810.analyses.control_flow.dispatcher_facts import (
    BlockAnalysis,
    DispatcherStrategy,
    StateVariableCandidate,
)
from d810.capabilities.dispatcher import RouterKind, TableProvenance

__all__ = [
    "DispatcherAnalysis",
    "analyze_dispatcher",
]


MIN_HIGH_FAN_IN = 5
MIN_STATE_CONSTANT = 0x100
MIN_UNIQUE_CONSTANTS = 3
MIN_PREDECESSOR_UNIFORMITY_RATIO = 0.8
MAX_DISPATCHER_BLOCK_SIZE = 20


@dataclass
class DispatcherAnalysis:
    """Complete dispatcher analysis for a portable ``FlowGraph``."""

    func_ea: int
    maturity: int

    blocks: dict[int, BlockAnalysis] = field(default_factory=dict)
    dispatchers: list[int] = field(default_factory=list)
    state_variable: StateVariableCandidate | None = None
    state_constants: set[int] = field(default_factory=set)

    router_kind: RouterKind = RouterKind.UNKNOWN
    table_provenance: TableProvenance | None = None
    initial_state: int | None = None
    nested_loop_depth: int = 0

    @property
    def is_conditional_chain(self) -> bool:
        """True if dispatcher uses conditional-chain state comparisons."""
        return self.router_kind == RouterKind.CONDITION_CHAIN

    @property
    def is_switch_table(self) -> bool:
        """True if dispatcher uses a switch/jump-table dispatcher."""
        return (
            self.router_kind == RouterKind.TABLE
            and self.table_provenance is TableProvenance.SWITCH
        )


def analyze_dispatcher(
    flow_graph: FlowGraph,
    *,
    previous_router_kind: RouterKind | None = None,
    persisted_initial_state: int | None = None,
) -> DispatcherAnalysis:
    """Analyze dispatcher structure from a portable ``FlowGraph`` snapshot.

    ``previous_router_kind`` and ``persisted_initial_state`` are the
    explicit dispatcher-history facts. Keeping them as parameters avoids
    introducing a generic maturity history store before a concrete
    consumer needs one.
    """
    analysis = DispatcherAnalysis(
        func_ea=int(flow_graph.func_ea),
        maturity=_metadata_int(flow_graph, "maturity", default=0),
    )

    if _has_table_jump(flow_graph):
        analysis.router_kind = RouterKind.TABLE
        analysis.table_provenance = TableProvenance.SWITCH
        return analysis

    _analyze_block_predecessors(flow_graph, analysis)
    _analyze_state_comparisons(flow_graph, analysis)
    _analyze_loop_structure(flow_graph, analysis)
    _analyze_state_assignments(flow_graph, analysis)
    _analyze_block_sizes(flow_graph, analysis)
    _analyze_switch_jumps(flow_graph, analysis)
    _score_blocks(analysis)
    _classify_router_kind(
        flow_graph,
        analysis,
        previous_router_kind=previous_router_kind,
        persisted_initial_state=persisted_initial_state,
    )

    analysis.dispatchers = [
        serial for serial, info in analysis.blocks.items() if info.is_dispatcher
    ]
    return analysis


def _metadata_int(flow_graph: FlowGraph, key: str, *, default: int) -> int:
    value = flow_graph.metadata.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _iter_blocks(flow_graph: FlowGraph) -> list[tuple[int, BlockSnapshot]]:
    return [
        (serial, flow_graph.blocks[serial])
        for serial in sorted(flow_graph.blocks)
    ]


def _get_or_create_block(
    analysis: DispatcherAnalysis, serial: int
) -> BlockAnalysis:
    if serial not in analysis.blocks:
        analysis.blocks[serial] = BlockAnalysis(serial=serial)
    return analysis.blocks[serial]


def _tail(block: BlockSnapshot) -> InsnSnapshot | None:
    return block.tail


def _tail_kind(block: BlockSnapshot) -> InsnKind | None:
    if block.tail_kind is not None:
        return block.tail_kind
    tail = block.tail
    return tail.kind if tail is not None else None


def _has_table_jump(flow_graph: FlowGraph) -> bool:
    return any(
        _tail_kind(block) is InsnKind.TABLE_JUMP
        for _, block in _iter_blocks(flow_graph)
    )


def _analyze_block_predecessors(
    flow_graph: FlowGraph, analysis: DispatcherAnalysis
) -> None:
    for serial, block in _iter_blocks(flow_graph):
        pred_count = len(block.preds)
        if pred_count < MIN_HIGH_FAN_IN:
            continue

        block_info = _get_or_create_block(analysis, serial)
        block_info.predecessor_count = pred_count
        block_info.strategies |= DispatcherStrategy.HIGH_FAN_IN

        uncond_count = 0
        for pred_serial in block.preds:
            pred_block = flow_graph.get_block(pred_serial)
            if pred_block is None:
                continue
            if _tail_kind(pred_block) is InsnKind.GOTO:
                uncond_count += 1
            elif len(pred_block.succs) == 1:
                uncond_count += 1

        block_info.unconditional_pred_count = uncond_count
        if (
            pred_count > 0
            and uncond_count / pred_count >= MIN_PREDECESSOR_UNIFORMITY_RATIO
        ):
            block_info.strategies |= DispatcherStrategy.PREDECESSOR_UNIFORM


def _is_state_comparison_tail(insn: InsnSnapshot | None) -> bool:
    # Read the portable projected branch (llr-lxas): a conditional jump whose
    # predicate is a real comparison, not the bare TRUTHY of m_jcnd.
    branch = project_conditional_branch(insn)
    if branch is None or branch.predicate is PredicateKind.TRUTHY:
        return False
    return insn.kind in {InsnKind.EQUALITY_JUMP, InsnKind.COND_JUMP}


def _analyze_state_comparisons(
    flow_graph: FlowGraph, analysis: DispatcherAnalysis
) -> None:
    var_comparisons: dict[str, tuple[MopSnapshot, list[tuple[int, int]]]] = {}

    for serial, block in _iter_blocks(flow_graph):
        tail = _tail(block)
        if not _is_state_comparison_tail(tail):
            continue
        if tail is None or tail.r is None or tail.r.kind is not OperandKind.NUMBER:
            continue
        const_val = tail.r.value
        if const_val is None or const_val <= MIN_STATE_CONSTANT:
            continue

        var_key = mop_snapshot_key(tail.l)
        if var_key is None or tail.l is None:
            continue

        if var_key not in var_comparisons:
            var_comparisons[var_key] = (tail.l, [])
        var_comparisons[var_key][1].append((serial, int(const_val)))

        block_info = _get_or_create_block(analysis, serial)
        block_info.state_constants.add(int(const_val))
        analysis.state_constants.add(int(const_val))

    best_mop: MopSnapshot | None = None
    best_comparisons: list[tuple[int, int]] = []
    for mop, comparisons in var_comparisons.values():
        if len(comparisons) > len(best_comparisons):
            best_mop = mop
            best_comparisons = comparisons

    if len(best_comparisons) < MIN_UNIQUE_CONSTANTS or best_mop is None:
        return

    unique_constants = {constant for _, constant in best_comparisons}
    comparison_blocks = [serial for serial, _ in best_comparisons]
    analysis.state_variable = StateVariableCandidate(
        mop=best_mop,
        mop_type=int(best_mop.t),
        mop_offset=mop_snapshot_offset(best_mop),
        mop_size=int(best_mop.size),
        comparison_count=len(best_comparisons),
        unique_constants=unique_constants,
        comparison_blocks=comparison_blocks,
    )

    for serial, _constant in best_comparisons:
        block_info = _get_or_create_block(analysis, serial)
        block_info.strategies |= DispatcherStrategy.STATE_COMPARISON
        if len(unique_constants) >= MIN_UNIQUE_CONSTANTS:
            block_info.strategies |= DispatcherStrategy.CONSTANT_FREQUENCY


def _analyze_loop_structure(
    flow_graph: FlowGraph, analysis: DispatcherAnalysis
) -> None:
    for serial, block in _iter_blocks(flow_graph):
        for succ_serial in block.succs:
            if succ_serial <= serial:
                target_info = _get_or_create_block(analysis, succ_serial)
                target_info.back_edge_sources.append(serial)
                target_info.strategies |= DispatcherStrategy.BACK_EDGE
                if len(target_info.back_edge_sources) >= 2:
                    target_info.strategies |= DispatcherStrategy.LOOP_HEADER

    _detect_nested_loops(analysis)


def _detect_nested_loops(analysis: DispatcherAnalysis) -> None:
    loop_headers = [
        serial
        for serial, info in analysis.blocks.items()
        if DispatcherStrategy.BACK_EDGE in info.strategies
    ]

    if len(loop_headers) < 3:
        return

    nested_count = 0
    for header in loop_headers:
        header_info = analysis.blocks[header]
        for src in header_info.back_edge_sources:
            if src in loop_headers:
                nested_count += 1

    if nested_count < 2:
        return

    analysis.nested_loop_depth = nested_count
    for header in loop_headers:
        analysis.blocks[header].strategies |= DispatcherStrategy.NESTED_LOOP


def _analyze_state_assignments(
    flow_graph: FlowGraph, analysis: DispatcherAnalysis
) -> None:
    if not analysis.state_constants:
        return

    for serial, block in _iter_blocks(flow_graph):
        for insn in block.iter_insns():
            # Proof-of-shape (llr-lxas): consume the portable projected
            # assignment instead of the Hex-Rays-shaped ``l``/``d`` operands.
            # ``value`` is a ``Const`` exactly when the MOV source is a number
            # operand, so this matches the prior
            # ``insn.l.kind is OperandKind.NUMBER`` guard byte-for-byte.
            assignment = project_assignment(insn)
            if assignment is None or not isinstance(assignment.value, Const):
                continue
            const_val = assignment.value.value
            if const_val in analysis.state_constants:
                block_info = _get_or_create_block(analysis, serial)
                block_info.state_constants.add(int(const_val))


def _analyze_block_sizes(flow_graph: FlowGraph, analysis: DispatcherAnalysis) -> None:
    for serial, block in _iter_blocks(flow_graph):
        if len(block.insn_snapshots) > MAX_DISPATCHER_BLOCK_SIZE:
            continue
        if serial not in analysis.blocks:
            continue
        block_info = analysis.blocks[serial]
        if block_info.strategies != DispatcherStrategy.NONE:
            block_info.strategies |= DispatcherStrategy.SMALL_BLOCK


def _analyze_switch_jumps(flow_graph: FlowGraph, analysis: DispatcherAnalysis) -> None:
    for serial, block in _iter_blocks(flow_graph):
        tail = _tail(block)
        if tail is None:
            continue

        is_switch = False
        if tail.kind is InsnKind.TABLE_JUMP:
            is_switch = True
        elif tail.kind is InsnKind.GOTO and tail.l is not None:
            if tail.l.kind is OperandKind.SUBINSN:
                is_switch = True

        if is_switch:
            block_info = _get_or_create_block(analysis, serial)
            block_info.strategies |= DispatcherStrategy.SWITCH_JUMP


def _score_blocks(analysis: DispatcherAnalysis) -> None:
    for block_info in analysis.blocks.values():
        score = 0.0

        if DispatcherStrategy.HIGH_FAN_IN in block_info.strategies:
            score += (block_info.predecessor_count - MIN_HIGH_FAN_IN + 1) * 10
        if DispatcherStrategy.STATE_COMPARISON in block_info.strategies:
            score += 20
        if DispatcherStrategy.LOOP_HEADER in block_info.strategies:
            score += 15
        if DispatcherStrategy.PREDECESSOR_UNIFORM in block_info.strategies:
            score += 10
        if DispatcherStrategy.CONSTANT_FREQUENCY in block_info.strategies:
            score += len(block_info.state_constants) * 5
        if DispatcherStrategy.BACK_EDGE in block_info.strategies:
            score += len(block_info.back_edge_sources) * 10
        if DispatcherStrategy.NESTED_LOOP in block_info.strategies:
            score += 25
        if DispatcherStrategy.SMALL_BLOCK in block_info.strategies:
            score += 5
        if DispatcherStrategy.SWITCH_JUMP in block_info.strategies:
            score += 15

        block_info.score = score


def _classify_router_kind(
    flow_graph: FlowGraph,
    analysis: DispatcherAnalysis,
    *,
    previous_router_kind: RouterKind | None,
    persisted_initial_state: int | None,
) -> None:
    conditional_chain_score = 0

    if analysis.nested_loop_depth >= 2:
        conditional_chain_score += 30
    if len(analysis.state_constants) >= MIN_UNIQUE_CONSTANTS:
        conditional_chain_score += len(analysis.state_constants) * 5

    has_jtbl = _has_table_jump(flow_graph)
    if not has_jtbl and len(analysis.state_constants) >= MIN_UNIQUE_CONSTANTS:
        conditional_chain_score += 20

    min_score = 30 if analysis.nested_loop_depth >= 2 else 50
    if conditional_chain_score >= min_score:
        analysis.router_kind = RouterKind.CONDITION_CHAIN
        _find_initial_state(
            flow_graph,
            analysis,
            persisted_initial_state=persisted_initial_state,
        )
    elif previous_router_kind == RouterKind.CONDITION_CHAIN:
        analysis.router_kind = RouterKind.CONDITION_CHAIN
        _find_initial_state(
            flow_graph,
            analysis,
            persisted_initial_state=persisted_initial_state,
        )
    elif has_jtbl:
        analysis.router_kind = RouterKind.TABLE
        analysis.table_provenance = TableProvenance.SWITCH
    else:
        analysis.router_kind = RouterKind.UNKNOWN
        analysis.table_provenance = None


def _find_initial_state(
    flow_graph: FlowGraph,
    analysis: DispatcherAnalysis,
    *,
    persisted_initial_state: int | None,
) -> None:
    for serial in range(min(5, flow_graph.block_count)):
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        for insn in block.iter_insns():
            if insn.kind is not InsnKind.MOV:
                continue
            if insn.l is None or insn.l.kind is not OperandKind.NUMBER:
                continue
            const_val = insn.l.value
            if const_val in analysis.state_constants:
                analysis.initial_state = int(const_val)
                if analysis.state_variable is not None:
                    analysis.state_variable.init_value = int(const_val)
                return

    if analysis.initial_state is None and persisted_initial_state is not None:
        analysis.initial_state = persisted_initial_state
