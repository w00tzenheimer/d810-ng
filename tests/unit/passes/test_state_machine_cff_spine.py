"""Chain-based StateMachineCffSpine: single detect point + passes by kind (llr-g3l8 slice 2).

``pipeline_for_kind`` maps standard dispatcher kinds (equality-chain / BST / switch) to
the canonical five-pass spine and everything else (indirect-table / unknown) to an empty
no-op pipeline. ``StateMachineCffSpine.detect`` runs the ranked resolver chain over a
portable FlowGraph; on a switch-table graph it resolves a SWITCH ``DispatcherResolution``
whose kind then selects the standard five passes. ``HodurFamily.pipeline_for`` delegates
to the same canonical 5-tuple (DRY regression guard).
"""
from __future__ import annotations

from d810.analyses.control_flow.dispatcher_resolution import DispatcherResolution
from d810.capabilities.dispatcher import RouterKind
from d810.families.state_machine_cff import HodurFamily
from d810.families.state_machine_cff.pipeline import (
    pipeline_for_kind,
    standard_state_machine_passes,
)
from d810.families.state_machine_cff.spine import StateMachineCffSpine
from d810.ir.flowgraph import (
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
)

_STANDARD_PASS_NAMES = (
    "recover_dispatcher",
    "recover_state_transitions",
    "plan_semantic_regions",
    "lower_state_machine",
    "cleanup_residual_dispatcher",
)


# --- fixtures reused from tests/unit/recon/flow/test_switch_table_analysis.py ---
def _mop(
    *,
    kind: OperandKind = OperandKind.UNKNOWN,
    stkoff: int | None = None,
    value: int | None = None,
    stack_refs: tuple[int, ...] = (),
    switch_cases: tuple[tuple[tuple[int, ...], int], ...] = (),
) -> MopSnapshot:
    return MopSnapshot(
        kind=kind,
        stkoff=stkoff,
        value=value,
        stack_refs=stack_refs,
        switch_cases=switch_cases,
    )


def _insn(
    *,
    kind: InsnKind,
    left: MopSnapshot | None = None,
    right: MopSnapshot | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(opcode=1, ea=0, operands=(), l=left, r=right, kind=kind)


def _block(
    serial: int,
    *,
    preds=(),
    succs=(),
    tail: InsnSnapshot | None = None,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=tuple(succs),
        preds=tuple(preds),
        flags=0,
        start_ea=0,
        insn_snapshots=() if tail is None else (tail,),
    )


def _flow_graph(blocks: dict[int, BlockSnapshot]) -> FlowGraph:
    return FlowGraph(
        blocks=blocks,
        entry_serial=min(blocks),
        func_ea=0x401000,
        metadata={"maturity_name": "MMAT_CALLS"},
    )


def _switch_flow_graph() -> FlowGraph:
    state_operand = _mop(kind=OperandKind.SUBINSN, stack_refs=(0x10,))
    switch_cases = _mop(
        kind=OperandKind.CASE_LIST,
        switch_cases=(((0,), 4), ((1, 2), 5), ((), 3)),
    )
    guard_tail = _insn(
        kind=InsnKind.COND_JUMP,
        left=_mop(kind=OperandKind.STACK, stkoff=0x10, stack_refs=(0x10,)),
        right=_mop(kind=OperandKind.NUMBER, value=0xFF),
    )
    table_tail = _insn(
        kind=InsnKind.TABLE_JUMP, left=state_operand, right=switch_cases
    )
    return _flow_graph(
        {
            0: _block(0, succs=(2,)),
            2: _block(2, preds=(0, 6), succs=(3, 9), tail=guard_tail),
            3: _block(3, preds=(2, 6), succs=(4, 5), tail=table_tail),
            4: _block(4),
            5: _block(5),
            6: _block(6, succs=(3,)),
            9: _block(9),
        }
    )


# --- pipeline_for_kind ---
def test_standard_kinds_select_the_five_named_passes():
    for kind in (RouterKind.SWITCH, RouterKind.EQUALITY_CHAIN, RouterKind.BST):
        specs = pipeline_for_kind(kind)
        assert tuple(s.name for s in specs) == _STANDARD_PASS_NAMES, kind


def test_unhandled_kinds_select_empty_pipeline():
    assert pipeline_for_kind(RouterKind.INDIRECT_TABLE) == ()
    assert pipeline_for_kind(RouterKind.UNKNOWN) == ()


# --- StateMachineCffSpine.detect ---
def test_detect_returns_none_without_a_graph():
    spine = StateMachineCffSpine()
    assert spine.detect(graph=None, capabilities=None) is None
    assert spine.detect(graph="not-a-graph", capabilities=None) is None


def test_detect_resolves_switch_table_graph_to_switch_kind():
    resolution = StateMachineCffSpine().detect(
        graph=_switch_flow_graph(), capabilities=None
    )
    assert isinstance(resolution, DispatcherResolution)
    assert resolution.router_kind == RouterKind.SWITCH


# --- StateMachineCffSpine.pipeline_for ---
def test_pipeline_for_resolved_switch_returns_standard_passes():
    spine = StateMachineCffSpine()
    resolution = spine.detect(graph=_switch_flow_graph(), capabilities=None)
    specs = spine.pipeline_for(resolution, None)
    assert tuple(s.name for s in specs) == _STANDARD_PASS_NAMES


# --- HodurFamily DRY regression guard ---
def test_hodur_pipeline_for_delegates_to_standard_passes():
    hodur_specs = HodurFamily().pipeline_for(match=None, context=None)
    canonical = standard_state_machine_passes()
    assert tuple(s.name for s in hodur_specs) == _STANDARD_PASS_NAMES
    assert tuple(s.name for s in hodur_specs) == tuple(s.name for s in canonical)
