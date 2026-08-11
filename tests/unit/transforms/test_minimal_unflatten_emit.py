"""Unit tests for the direct interval-set unflatten emitter (epic d81-jfg2)."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from d810.transforms import minimal_unflatten_emit as minimal_unflatten_emit_module

from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.branch_witness_provider import (
    build_static_equality_chain_witness_map,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.detached_handler_island import (
    AppliedDetachedSnippetDirectBoundaryPort,
    AppliedDetachedSnippetConditionalBoundaryPort,
    DetachedSnippetBoundaryPortOwner,
    DetachedSnippetConditionalBoundaryPort,
    DetachedSnippetDirectBoundaryPort,
)
from d810.analyses.control_flow.interval_map import IntervalDispatcher, IntervalRow
from d810.analyses.control_flow.minimal_state_recovery import (
    HandlerTransition,
    StateWriteTransition,
    TransitionArm,
    TransitionProof,
    _resolve_state_var_alias,
    block_has_live_carrier_write,
    recover_state_write_transitions,
    resolve_materialized_indirect_transfer_targets,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    BootstrapRouteBindingEvidence,
    BootstrapRouteEvidence,
    BootstrapRouteProofKind,
)
from d810.analyses.control_flow.residual_entry_bridge import EntryBridgeEvidence
from d810.analyses.control_flow.route_predicate import DecisionDag, RouteComparison
from d810.analyses.control_flow.state_machine_analysis import (
    run_snapshot_constant_fixpoint,
)
from d810.analyses.value_flow.state_write import (
    MicrocodeEvalSeams,
    forward_eval_insn as _portable_forward_eval_insn,
)
from d810.capabilities.providers import (
    ConditionChainWalkerProvider,
    register_condition_chain_walkers,
)
from d810.ir.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    MopSnapshot,
    OperandKind,
    PredicateKind,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.transforms.graph_modification import (
    ConvertToGoto,
    LowerConditionalStateTransition,
    NopInstructions,
    PreserveLivePredicateCondition,
    RedirectBranch,
    RedirectGoto,
    SyntheticRegisterNonzeroCondition,
    SyntheticStackValueEqualsCondition,
)
from d810.transforms.minimal_unflatten_emit import (
    _applied_conditional_boundary_edge_keys,
    _applied_direct_boundary_edge_keys,
    _exact_live_state_edge_keys,
    _prefer_exact_terminal_route_fragments,
    _preserve_deferred_materialized_handler_exit_paths,
    _recover_initial_state,
    _prove_bound_bootstrap_entry_routes,
    _resolver_proven_dynamic_entry_edges,
    build_conditional_arm_redirects,
    build_exact_terminal_state_route_redirects,
    build_loop_guard_exit_redirects,
    build_materialized_conditional_handler_bridges,
    build_materialized_state_entry_bridges,
    build_materialized_state_route_redirects,
    build_resolver_proven_indirect_call_neutralizations,
    build_stack_carried_state_selector_lowerings,
    _normalize_degenerate_branch_redirects,
    _rebind_materialized_state_route_sources,
    build_source_keyed_handler_redirects,
    build_state_write_redirects,
)
from d810.transforms.dispatcher_corridor_coverage import (
    DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    FULL_UNFLATTENING_CLAIM_METADATA,
    UNFLATTEN_COMPLETION_STATUS_METADATA,
)
from tests.native_preanalysis import make_native_key
from tests.typed_patch_authority import emit_minimal_unflatten, graph_modifications

NATIVE_KEY = make_native_key()

_OP_MOV = 4
_T_NUM, _T_STK, _T_REG = 2, 4, 1
_STATE = 0x64
_CARRIER_OFF = 0x70  # a non-state stack slot (the Approov ``v4`` carrier)


def _seams() -> MicrocodeEvalSeams:
    return MicrocodeEvalSeams(
        mop_type_name=lambda t: {_T_NUM: "mop_n", _T_STK: "mop_S", _T_REG: "mop_r"}.get(
            t
        ),
        mop_type_value=lambda n, d: {
            "mop_n": _T_NUM,
            "mop_S": _T_STK,
            "mop_r": _T_REG,
        }.get(n, d),
        opcode_value=lambda n, d: {"m_mov": _OP_MOV}.get(n, d),
        opcode_name=lambda op: {_OP_MOV: "m_mov"}.get(op),
        fetch_stable_global_value=lambda _a, _s: None,
        lvar_stkoff=lambda _m, _i: -1,
    )


@pytest.fixture
def _seam():
    from d810.capabilities import providers as _p

    s = _seams()

    def _fwd(insn, stk, reg, off, **kw):
        kw.pop("seams", None)
        return _portable_forward_eval_insn(
            insn,
            stk,
            reg,
            off,
            seams=s,
            mba=kw.pop("mba", None),
            state_var_lvar_idx=kw.pop("state_var_lvar_idx", None),
        )

    register_condition_chain_walkers(
        ConditionChainWalkerProvider(
            detect_state_var_stkoff=lambda *a, **k: None,
            dump_dispatcher_node=lambda *a, **k: None,
            find_pre_header_state=lambda *a, **k: None,
            walk_handler_chain=lambda *a, **k: None,
            forward_eval_insn=_fwd,
            resolve_via_condition_chain_walk=lambda *a, **k: None,
        )
    )
    try:
        yield
    finally:
        _p.reset_providers_for_tests()


def _mov_state(ea, const):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_stk(ea, src_off, dst_off):
    # pure stack->stack copy: dst = src (no right operand)
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=src_off, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_STK, size=4, stkoff=dst_off, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_reg(ea, const, dst_reg):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=8, reg=dst_reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _use_nested_reg(ea, reg):
    """A nested sub-instruction use, shaped like an indirect-call operand."""
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(
            t=4,
            size=8,
            kind=OperandKind.SUBINSN,
            sub_l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        ),
        d=MopSnapshot(t=_T_REG, size=8, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _stx_reg(ea, value, ptr_reg):
    return InsnSnapshot(
        opcode=1,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        r=MopSnapshot(t=_T_REG, size=2, reg=256, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_REG, size=8, reg=ptr_reg, kind=OperandKind.REGISTER),
        kind=InsnKind.STORE,
    )


def _mov_reg_const(ea, reg, value=0x1234):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _mov_reg_from_stack(ea, reg, stkoff):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _mov_reg_from_reg(ea, source_reg, destination_reg):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(
            t=_T_REG,
            size=4,
            reg=source_reg,
            kind=OperandKind.REGISTER,
        ),
        d=MopSnapshot(
            t=_T_REG,
            size=4,
            reg=destination_reg,
            kind=OperandKind.REGISTER,
        ),
        kind=InsnKind.MOV,
    )


def _mov_stack_from_reg(ea, stkoff, reg):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _mov_stack_const(ea, stkoff, value=0x1234):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_NUM, size=8, value=value, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=_T_STK, size=8, stkoff=stkoff, kind=OperandKind.STACK),
        kind=InsnKind.MOV,
    )


def _call_reg(ea, reg):
    return InsnSnapshot(
        opcode=0x44,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=8, reg=reg, kind=OperandKind.REGISTER),
        kind=InsnKind.CALL,
    )


def _nested_call_result(ea):
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(
            t=4,
            size=4,
            kind=OperandKind.SUBINSN,
            sub_kind=InsnKind.CALL,
        ),
        d=MopSnapshot(t=_T_REG, size=4, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _state_ne_tail(ea, const):
    return InsnSnapshot(
        opcode=0x33,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=const, kind=OperandKind.NUMBER),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )


def _signed_ge_tail(ea, compared, taken):
    return InsnSnapshot(
        opcode=0x32,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=0x30, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=4, value=compared, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.SGE,
        is_conditional_jump=True,
    )


def _indirect_jump(ea):
    return InsnSnapshot(
        opcode=0x36,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
        kind=InsnKind.INDIRECT_JUMP,
    )


def _b(serial, succs, preds, insns=()):
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=tuple(succs),
        preds=tuple(preds),
        flags=0,
        start_ea=0x1000 + serial * 0x40,
        insn_snapshots=tuple(insns),
    )


def _disp(point_targets, exit_block, hi=0x100000000):
    rows, cur = [], 0
    for st in sorted(point_targets):
        if st > cur:
            rows.append(IntervalRow(lo=cur, hi=st, target=exit_block))
        rows.append(IntervalRow(lo=st, hi=st + 1, target=point_targets[st]))
        cur = st + 1
    if cur < hi:
        rows.append(IntervalRow(lo=cur, hi=hi, target=exit_block))
    return IntervalDispatcher(rows)


def _eq_block(serial, const, taken, fallthrough, preds=(), insns=()):
    """Equality-chain compare block: ``jz state == const -> taken; fallthrough``."""
    tail = InsnSnapshot(
        opcode=100,
        ea=0x1000 + serial * 0x40,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=4, value=const, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.EQ,
        is_conditional_jump=True,
    )
    return BlockSnapshot(
        serial=serial,
        block_type=4,
        succs=(fallthrough, taken),
        preds=tuple(preds),
        flags=0,
        start_ea=0x1000 + serial * 0x40,
        insn_snapshots=(*insns, tail),
    )


def _use_stk(ea, stkoff):
    """A statement that uses a stack slot: ``return use(stkoff)`` proxy via mov."""
    return InsnSnapshot(
        opcode=_OP_MOV,
        ea=ea,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=4, stkoff=stkoff, kind=OperandKind.STACK),
        d=MopSnapshot(t=_T_REG, size=4, reg=0, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )


def _equality_dispatcher(point_targets, entry_block, compare_blocks):
    """Build IntervalDispatcher + StateDispatcherMap for equality-chain rows."""
    rows = tuple(
        StateDispatcherRow(
            state_const=st,
            target_block=target,
            dispatcher_block=entry_block,
            compare_block=cmp_block,
            branch_kind="eq",
            router_kind=RouterKind.CONDITION_CHAIN,
        )
        for st, target, cmp_block in zip(
            sorted(point_targets),
            [point_targets[st] for st in sorted(point_targets)],
            compare_blocks,
        )
    )
    dispatch_map = StateDispatcherMap(
        rows=rows,
        dispatcher_entry_block=entry_block,
        dispatcher_blocks=frozenset(compare_blocks),
        state_var_stkoff=_STATE,
        state_var_lvar_idx=None,
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    interval_rows = [
        IntervalRow(lo=st & 0xFFFFFFFF, hi=(st & 0xFFFFFFFF) + 1, target=target)
        for st, target in point_targets.items()
    ]
    return IntervalDispatcher(interval_rows), dispatch_map


def test_emits_back_edge_redirect_and_entry_bridge(_seam) -> None:
    # entry blk0 -> dispatcher blk2; state-write blk10 writes 0x20 -> dispatcher;
    # route(0x10 initial)=blk10, route(0x20)=blk20.  The transition is anchored on
    # the back-edge blk10->dispatcher, re-pointed onto route(0x20)=blk20.
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),  # entry -> dispatcher
            2: _b(2, (10, 20), (0, 10, 20)),  # dispatcher
            10: _b(
                10, (2,), (2,), (_mov_state(0x1000, 0x20),)
            ),  # writes 0x20 -> dispatcher
            20: _b(20, (2,), (2,)),  # target handler
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    # blk10 is the resolved state-write back-edge -> route(0x20) = blk20
    by_block = {t.write_block: t for t in transitions}
    assert by_block[10].next_state == 0x20
    assert by_block[10].target_handler == 20
    assert by_block[10].is_return is False
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=0x10,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    # back-edge blk10 re-pointed off the dispatcher onto blk20
    assert (10, 2, 20) in gotos
    # entry bridge: blk0 -> route(initial 0x10) = blk10
    assert (0, 2, 10) in gotos


def test_materialized_state_route_rebinds_to_exact_imported_handler_owner() -> None:
    """Handler-exit replay follows the exact PREOPT handler replacement."""
    native_write_ea = 0x40E207
    native_source = 10
    imported_source = 30
    cleanup_handler = 40
    owner_state = 0xD919DEB2
    selected_state = 0x85AE90D3
    fg = FlowGraph(
        blocks={
            0: _b(0, (), ()),
            native_source: _b(
                native_source,
                (20, 21),
                (),
                (_mov_state(native_write_ea, selected_state),),
            ),
            imported_source: _b(
                imported_source,
                (20, 21),
                (),
                (_mov_state(0xF1C01448, selected_state),),
            ),
            20: _b(20, (), (native_source, imported_source)),
            21: _b(21, (), (native_source, imported_source)),
            cleanup_handler: _b(cleanup_handler, (), ()),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    route = MaterializedStateRoute(
        source_block_serial=native_source,
        state_constant=selected_state,
        target_handler_serial=cleanup_handler,
        source_handler_serial=native_source,
        handler_exit_proven=True,
        proof_kind="handler_replay",
    )

    assert _rebind_materialized_state_route_sources(
        fg,
        (route,),
        legacy_handler_by_state={owner_state: native_source},
        materialized_handler_by_state={owner_state: imported_source},
        imported_native_eas_by_serial={
            imported_source: frozenset({native_write_ea}),
        },
    ) == (
        replace(
            route,
            source_block_serial=imported_source,
            source_handler_serial=imported_source,
        ),
    )


def test_resolver_proof_routes_unmatched_folded_state_to_live_handler(_seam) -> None:
    # The state value is not an equality-router key, so legacy recovery marks
    # this concrete back-edge terminal. A materialized-transfer record may
    # correct only that miss when its anchor is present in the transition source.
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0xDEAD),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    # `IntervalDispatcher` represents an equality-router miss as its default
    # target. This is the production false-terminal shape, not a `None` route.
    unresolved = StateWriteTransition(10, 0xDEAD, 99, True, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1000,),
        target_eas=(0x1500,),  # block 20's snapshot start EA
    )

    (resolved,) = resolve_materialized_indirect_transfer_targets(
        (unresolved,), fg, disp, (transfer,)
    )

    assert resolved.target_handler == 20
    assert resolved.is_return is False
    assert resolved.proof is not None
    assert resolved.proof.kind == "computed_goto_target"


def test_resolver_proof_never_overrides_exact_dispatcher_route(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x10),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    exact = StateWriteTransition(10, 0x10, 10, False, None)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1000,),
        target_eas=(0x1500,),
    )

    assert resolve_materialized_indirect_transfer_targets(
        (exact,), fg, disp, (transfer,)
    ) == (exact,)


def test_emitter_uses_materialized_transfer_only_for_default_router_miss(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0xDEAD),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1000,),
        target_eas=(0x1500,),
    )

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_indirect_transfers=(transfer,),
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 2, 20) in gotos


def test_emitter_uses_exact_materialized_state_route_for_default_router_miss(
    _seam,
) -> None:
    state = 0xA5A94B86
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, state),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_state_routes=(MaterializedStateRoute(10, state, 20),),
        condition_chain_handlers=frozenset({20}),
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 2, 20) in gotos


def test_emitter_reports_reachable_dispatcher_corridors_as_partial_not_complete(
    _seam,
    monkeypatch,
) -> None:
    """`unresolved=0` cannot hide a still-reachable dispatcher feeder."""
    from d810.transforms import minimal_unflatten_emit as emit_module

    class _LogCapture:
        info_on = True

        def __init__(self) -> None:
            self.calls: list[tuple[str, tuple[object, ...]]] = []

        def info(self, message: str, *args: object) -> None:
            self.calls.append((message, args))

    log_capture = _LogCapture()
    monkeypatch.setattr(emit_module, "logger", log_capture)
    fg = FlowGraph(
        blocks={
            0: replace(_b(0, (2,), ()), start_ea=0x7FF859C06F60),
            2: replace(_b(2, (10, 20), (0, 10)), start_ea=0x7FF859C070C4),
            # No foldable state write: this is intentionally a residual
            # dispatcher feeder, not an unsafe forced redirect.
            10: replace(_b(10, (2,), (2,)), start_ea=0x7FF859C08D35),
            20: replace(_b(20, (), (2,)), start_ea=0x7FF859C08B37),
        },
        entry_serial=0,
        func_ea=0x7FF859C06F60,
    )

    plan = emit_minimal_unflatten(
        fg,
        _disp({0x10: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
    )

    metadata = plan.metadata_dict()
    assert metadata[UNFLATTEN_COMPLETION_STATUS_METADATA] == "pending_patch_application"
    assert metadata[FULL_UNFLATTENING_CLAIM_METADATA] is False
    coverage = metadata[DISPATCHER_CORRIDOR_COVERAGE_METADATA]
    assert coverage["planned_completion_status"] == "planned_partial_residual_dispatcher"
    assert coverage["residual_corridors"]
    assert any(
        "blk10@0x7ff859c08d35" in corridor["label"]
        and "blk2@0x7ff859c070c4" in corridor["label"]
        for corridor in coverage["residual_corridors"]
    )
    assert any(
        message.startswith("unflat dispatcher corridor coverage:")
        and args[:2]
        == ("pending_patch_application", "planned_partial_residual_dispatcher")
        for message, args in log_capture.calls
    ), log_capture.calls
    assert not any(" unresolved=%d " in message for message, _args in log_capture.calls)


def test_emitter_proof_uses_caller_authoritative_handlers_not_dispatcher_rows(
    _seam,
) -> None:
    """A materialized caller-only handler cannot disappear behind row fallback."""

    class _CleanUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return ()

    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            # The portable CFG includes imported handler blk30, but this
            # interval adapter intentionally has no row that names it.
            2: _b(2, (10, 20, 30), (0, 10, 20, 30)),
            10: _b(10, (2,), (2,), (_mov_state(0x1280, 0x20),)),
            20: _b(20, (2,), (2,), (_mov_state(0x1500, 0x10),)),
            30: _b(30, (2,), (2,), (_mov_state(0x1780, 0x10),)),
            99: _exit_block(99, ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    plan = emit_minimal_unflatten(
        fg,
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20, 30}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    proof = plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    assert {item["serial"] for item in proof["authoritative_handlers"]} == {
        10,
        20,
        30,
    }
    assert proof["proof_status"] == "rejected"
    assert proof["reason"] == "authoritative_handler_lost"


def _complete_two_handler_dispatcher_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10, 20)),
            10: _b(10, (2,), (2,), (_mov_state(0x1280, 0x20),)),
            20: _b(20, (2,), (2,), (_mov_state(0x1500, 0x10),)),
            99: _exit_block(99, ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def test_emitter_narrow_proof_requires_executed_whole_fragment_use_def_check(
    _seam,
) -> None:
    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
    )

    proof = plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    assert proof["proof_status"] == "rejected"
    assert proof["reason"] == "producer_safety_missing"
    assert proof["producer_safety"]["non_state_use_def_checked"] is False


def test_emitter_narrow_proof_abstains_when_use_def_capability_raises(
    _seam,
    monkeypatch,
) -> None:
    monkeypatch.setenv("D810_S1A_SEVERANCE_BAIL", "1")
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)

    class _FailingUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            raise LookupError("live use-def authority unavailable")

    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_FailingUseDefSafety(),
        live_function=object(),
    )

    proof = plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    assert proof["proof_status"] == "rejected"
    assert proof["reason"] == "producer_safety_missing"
    assert proof["producer_safety"]["non_state_use_def_checked"] is False
    assert proof["producer_safety"]["non_state_use_def_severances_zero"] is False
    assert len(graph_modifications(plan)) == 3
    audit = plan.metadata_dict()["use_def_severance_audit"]
    assert audit["executed"] is False
    assert audit["clean"] is False
    assert audit["enforcement_status"] == "safety_unavailable"


def test_partial_use_def_audit_retains_fragment_and_reports_unavailable_safety(
    _seam,
    monkeypatch,
) -> None:
    """A partial enforced audit is not an authoritative fragment rejection."""
    monkeypatch.setenv("D810_S1A_SEVERANCE_BAIL", "1")
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)

    class _PartialUseDefSafety:
        def __init__(self) -> None:
            self.calls = 0

        def redirect_use_def_violations(
            self, *_args: object
        ) -> tuple[object, ...]:
            if self.calls == 0:
                self.calls += 1
                return (SimpleNamespace(var_stkoff=_CARRIER_OFF),)
            self.calls += 1
            raise LookupError("live use-def authority unavailable")

    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_PartialUseDefSafety(),
        live_function=object(),
    )

    assert len(graph_modifications(plan)) == 3
    audit = plan.metadata_dict()["use_def_severance_audit"]
    assert audit["executed"] is False
    assert audit["clean"] is False
    assert audit["severance_count"] == 1
    assert audit["enforced"] is True
    assert audit["enforcement_status"] == "safety_unavailable"
    assert len(audit["violations"]) == 1


def test_emitter_keeps_siblings_for_advisory_use_def_severance(
    _seam,
    monkeypatch,
) -> None:
    """Default heuristic findings are evidence, not a redirect filter."""
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)
    monkeypatch.delenv("D810_S1A_SEVERANCE_BAIL", raising=False)

    class _SeveringUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (SimpleNamespace(var_stkoff=_CARRIER_OFF),)

    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_SeveringUseDefSafety(),
        live_function=object(),
    )

    assert len(graph_modifications(plan)) == 3
    proof = plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    assert proof["proof_status"] == "rejected"
    assert proof["reason"] == "producer_safety_missing"
    assert proof["producer_safety"]["fragment_atomic"] is False
    assert proof["producer_safety"]["non_state_use_def_checked"] is True
    assert proof["producer_safety"]["non_state_use_def_severances_zero"] is False


def test_confirmed_use_def_severance_rejects_partial_fragment_atomically() -> None:
    """Partial dispatcher coverage never weakens the hard fragment veto."""
    from d810.transforms import minimal_unflatten_emit as emit_module

    audit = SimpleNamespace(executed=True, severance_count=1, enforced=False)

    assert not emit_module._must_reject_fragment_for_use_def_audit(audit)
    assert emit_module._must_reject_fragment_for_use_def_audit(
        audit, legacy_bail=True
    )
    audit.enforced = True
    assert emit_module._must_reject_fragment_for_use_def_audit(audit)


def test_emitter_narrow_proof_accepts_clean_executed_use_def_check(_seam) -> None:
    class _CleanUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return ()

    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_CleanUseDefSafety(),
        live_function=object(),
    )

    proof = plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    assert proof["proof_status"] == "accepted"
    assert proof["producer_safety"] == {
        "fragment_atomic": True,
        "non_state_use_def_checked": True,
        "non_state_use_def_severances_zero": True,
        "non_state_use_def_veto": True,
    }


def test_emitter_scans_imported_materialized_handler_root(_seam) -> None:
    state_reg = 99
    imported_state = 0x20
    next_state = 0x30
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 40), (0, 10, 40)),
            10: _b(10, (2,), (2,), (_mov_reg(0x1100, 0x10, state_reg),)),
            30: _b(30, (31,), (), (_mov_reg(0x1300, next_state, state_reg),)),
            31: _b(31, (), (30,)),
            40: _b(40, (2,), (2,), (_mov_reg(0x1400, 0x10, state_reg),)),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 10, next_state: 40}, exit_block=99)

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_computed_goto_profile=True,
        materialized_state_routes=(
            MaterializedStateRoute(98, imported_state, 30),
            MaterializedStateRoute(
                30,
                next_state,
                40,
                source_handler_serial=30,
                handler_exit_proven=True,
            ),
        ),
        condition_chain_handlers=frozenset({10, 40}),
    )

    assert RedirectGoto(
        from_serial=30,
        old_target=31,
        new_target=40,
    ) in graph_modifications(plan)


def test_emitter_abstains_atomically_on_incomplete_materialized_handler_map(
    monkeypatch,
) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    def fail_if_recovery_runs(*_args, **_kwargs):
        raise AssertionError("incomplete exact map must abstain before recovery")

    from d810.transforms import minimal_unflatten_emit as emit_module

    monkeypatch.setattr(
        emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        fail_if_recovery_runs,
    )
    plan = emit_minimal_unflatten(
        fg,
        _disp({0x10: 10}, exit_block=99),
        state_var_stkoff=None,
        state_var_reg=20,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_computed_goto_profile=True,
        missing_materialized_handler_targets=((0x20, 0x402000),),
    )

    assert graph_modifications(plan) == []


@pytest.mark.parametrize(
    (
        "materialized_profile",
        "has_imported_boundary_evidence",
        "state_var_reg",
        "expected_region",
    ),
    (
        (False, False, None, frozenset()),
        (False, True, None, frozenset()),
        (True, False, None, frozenset()),
        (True, True, None, frozenset({2, 3})),
        (True, False, 20, frozenset({2, 3})),
    ),
)
def test_dispatcher_predecessor_filter_requires_imported_boundary_evidence(
    _seam,
    monkeypatch,
    materialized_profile,
    has_imported_boundary_evidence,
    state_var_reg,
    expected_region,
) -> None:
    """Ordinary stack dispatchers retain semantic guard predecessors.

    A comparison block can also be the terminal stack-alias guard that owns a
    handler's source edge.  The strict router-region exclusion is justified
    only when the materialized computed-goto BST has applied PREOPT boundary
    evidence; the legacy CALLS path must retain its semantic predecessors.
    """
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (3, 10), (0, 3)),
            3: _b(3, (2,), (2,)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    captured: list[frozenset[int]] = []
    from d810.transforms import minimal_unflatten_emit as emit_module

    def _capture_region(*_args, **kwargs):
        captured.append(kwargs["dispatcher_region_serials"])
        return ()

    monkeypatch.setattr(
        emit_module,
        "recover_state_write_transitions_via_partitioned_fixpoint",
        _capture_region,
    )
    imported_direct_boundary_evidence = ()
    if has_imported_boundary_evidence:
        imported_direct_boundary_evidence = (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=DetachedSnippetDirectBoundaryPort(
                    source_block_ea=0xDEAD,
                    source_instruction_ea=0xDEAD,
                    endpoint_block_ea=0xDEAD,
                    old_successor_eas=(),
                    target_ea=0xBEEF,
                    state_register=20,
                    state_constant=0x10,
                    source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                    delivery_mode="terminal_goto",
                    resolver_kind="static_fixpoint",
                ),
                endpoint_anchor_eas=(),
                target_anchor_eas=(),
            ),
        )

    emit_minimal_unflatten(
        fg,
        _disp({0x10: 10}, exit_block=99),
        state_var_stkoff=_STATE if state_var_reg is None else None,
        state_var_reg=state_var_reg,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        dispatcher_region_serials=frozenset({2, 3}),
        materialized_computed_goto_profile=materialized_profile,
        imported_direct_boundary_evidence=imported_direct_boundary_evidence,
    )

    assert captured == [expected_region]


def test_emitter_routes_materialized_midtree_entry_to_known_handler(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0xDEAD),)),
            20: _b(20, (30, 99), ()),
            30: _b(30, (), (20,)),
            99: _b(99, (), (20,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1010,
        source_block_ea=0x1000,
        materialized_anchor_eas=(0x1000,),
        target_eas=(0x1500,),
    )
    dag = DecisionDag(
        32,
        {20: RouteComparison(20, "jz", 0xDEAD, 30, 99)},
        root=20,
    )

    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        materialized_indirect_transfers=(transfer,),
        condition_chain_dag=dag,
        condition_chain_handlers=frozenset({30}),
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in graph_modifications(plan)
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 2, 30) in gotos


def test_strict_preheader_prologue_keeps_ring_back_edge_redirectable(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1, 3), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10, 20), (1, 10)),
            3: _b(3, (10,), (0,)),
            10: _b(10, (2,), (2, 3), (_mov_state(0x1000, 0x20),)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = (StateWriteTransition(10, 0x20, 20, False, None),)

    loose = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
    )
    loose_gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in loose
        if isinstance(m, RedirectGoto)
    }
    assert (10, 2, 20) not in loose_gotos

    strict = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        strict_pre_header_prologue=True,
    )
    strict_gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in strict
        if isinstance(m, RedirectGoto)
    }
    assert (10, 2, 20) in strict_gotos


def test_entry_bridge_shortcuts_pure_state_only_witness_exit_path(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (4, 3), (1,), (_state_ne_tail(0x1000, 0x10),)),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5, 6), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (7,), (4,)),
            6: _b(6, (7,), (4,)),
            7: _exit_block(7, (5, 6)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=7)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) in gotos


def test_entry_bridge_preserves_witness_exit_path_with_live_stack_def(_seam) -> None:
    non_state = 0x88
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(
                2,
                (4, 3),
                (1,),
                (_mov_stack_const(0x1000, non_state), _state_ne_tail(0x1004, 0x10)),
            ),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,)),
            8: _b(8, (9,), (5,), (_mov_reg_from_stack(0x1080, 1, non_state),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) not in gotos


def test_entry_bridge_shortcuts_skipped_dead_non_state_def(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(
                2,
                (4, 3),
                (1,),
                (_mov_reg_const(0x1000, 2), _state_ne_tail(0x1004, 0x10)),
            ),
            3: _b(3, (4,), (2,)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,), (_mov_reg_const(0x1050, 2),)),
            8: _b(8, (9,), (5,), (_call_reg(0x1080, 2),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) in gotos


def test_entry_bridge_shortcuts_dispatcher_local_non_state_temp(_seam) -> None:
    temp_stack = 0x88
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(
                2,
                (4, 3),
                (1,),
                (_mov_reg_const(0x1000, 2), _state_ne_tail(0x1004, 0x10)),
            ),
            3: _b(3, (4,), (2,)),
            4: _b(
                4,
                (5, 6),
                (2, 3),
                (
                    _mov_stack_from_reg(0x1010, temp_stack, 2),
                    _state_ne_tail(0x1014, 0x10),
                ),
            ),
            5: _b(5, (7,), (4,)),
            6: _b(6, (7,), (4,)),
            7: _exit_block(7, (5, 6)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=7)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) in gotos


def test_entry_bridge_preserves_witness_exit_path_with_live_call_target_reg(
    _seam,
) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(
                2,
                (4, 3),
                (1,),
                (_mov_reg_const(0x1000, 0), _state_ne_tail(0x1004, 0x10)),
            ),
            3: _b(3, (4,), (2,), (_mov_reg_const(0x1008, 0, value=0x5555),)),
            4: _b(4, (5,), (2, 3), (_state_ne_tail(0x1010, 0x10),)),
            5: _b(5, (8,), (4,)),
            8: _b(8, (9,), (5,), (_call_reg(0x1080, 0),)),
            9: _exit_block(9, (8,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 5}, exit_block=9)

    mods = build_state_write_redirects(
        fg,
        disp,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
        state_var_stkoff=_STATE,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (1, 2, 5) not in gotos


def test_recovers_initial_state_from_prologue(_seam) -> None:
    # prologue blk0 -> blk1(writes initial 0x10) -> dispatcher blk2.  The prologue
    # is a dispatcher predecessor too, so its folded state IS the initial state --
    # recovered without any caller-supplied initial_state / condition-chain evidence.
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),  # entry
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),  # prologue writes 0x10
            2: _b(2, (10, 20), (1, 10, 20)),  # dispatcher
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x20),)),  # handler writes 0x20
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    assert _recover_initial_state(fg, transitions, 2, None) == 0x10


def test_recovers_register_initial_state_across_entry_only_glue(_seam) -> None:
    state_reg = 99
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_reg(0x1100, 0x10, state_reg),)),
            # The dispatcher predecessor is shared with a handler back-edge.
            # Only blk1@0x1040 is reachable before crossing the dispatcher.
            2: _b(2, (3,), (1, 10)),
            3: _b(3, (10,), (2,)),
            10: _b(10, (2,), (3,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert (
        _recover_initial_state(
            fg,
            (),
            3,
            None,
            state_var_reg=state_reg,
        )
        == 0x10
    )


def test_emit_prefers_entry_reaching_initial_state_over_range_hint(_seam) -> None:
    state_reg = 99
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,), (_mov_reg(0x1100, 0x10, state_reg),)),
            2: _b(2, (3,), (1, 10, 20)),
            3: _b(3, (10, 20), (2,)),
            10: _b(10, (2,), (3,), (_mov_reg(0x1400, 0x20, state_reg),)),
            20: _b(20, (2,), (3,), (_mov_reg(0x1500, 0x10, state_reg),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 10, 0x20: 20}, exit_block=99)

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=3,
        initial_state=0x20,
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in graph_modifications(plan)
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (2, 3, 10) in edges
    assert (2, 3, 20) not in edges


def test_emit_bails_when_no_entry_bridge(_seam) -> None:
    # The prologue blk1 writes NO state, so the initial state is unrecoverable and
    # the entry can't be bridged.  Removing the dispatcher would orphan every
    # handler, so emit must BAIL (empty plan) and leave the function intact rather
    # than gut it (the OLLVM current-state-shadow failure mode).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),  # NO state write
            2: _b(2, (10, 20), (1, 10, 20)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x20),)),  # resolvable handler
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=2
    )
    assert len(graph_modifications(plan)) == 0


def test_resolves_state_var_alias_through_header_copy(_seam) -> None:
    # Dispatcher header copies the COMPARED slot (_STATE) FROM the next-state slot
    # (0x40): handlers write 0x40, the header does ``_STATE = 0x40`` then routes on
    # _STATE.  At a back-edge _STATE is still stale, so the fold must read 0x40 --
    # _resolve_state_var_alias follows the header copy (OLLVM -fla shadow).
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(
                2, (10,), (0, 10), (_mov_stk(0x2000, 0x40, _STATE),)
            ),  # _STATE <- 0x40
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    assert _resolve_state_var_alias(fg, 2, _STATE) == 0x40


def test_state_var_alias_unchanged_without_header_copy(_seam) -> None:
    # No copy into the compared slot at the header -> offset unchanged (the clean
    # hodur / sub_7FFD chains must not be remapped).
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),  # no copy
            10: _b(10, (2,), (2,), (_mov_state(0x2000, 0x20),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    assert _resolve_state_var_alias(fg, 2, _STATE) == _STATE


def _mov_carrier(ea, src_off, dst_off=_CARRIER_OFF):
    # pure stack->stack copy to a NON-state slot: the carrier write ``v4 = src``.
    return _mov_stk(ea, src_off, dst_off)


def test_block_has_live_carrier_write_detects_non_state_write() -> None:
    # A block whose only data write is the state-var write is pure glue.
    glue = _b(10, (2,), (8, 9), (_mov_state(0x1000, 0x20),))
    assert block_has_live_carrier_write(glue, _STATE) is False
    # A block that also writes a non-state slot carries a live carrier.
    carrier = _b(
        10,
        (2,),
        (8, 9),
        (_mov_state(0x1000, 0x20), _mov_carrier(0x1004, 0x80)),
    )
    assert block_has_live_carrier_write(carrier, _STATE) is True
    # A block with only a carrier write (no state write) still counts.
    carrier_only = _b(11, (2,), (8,), (_mov_carrier(0x1008, 0x80),))
    assert block_has_live_carrier_write(carrier_only, _STATE) is True


def _exit_block(serial, preds):
    # A 0-successor STOP/exit block (the function return).
    return BlockSnapshot(
        serial=serial,
        block_type=2,
        succs=(),
        preds=tuple(preds),
        flags=0,
        start_ea=0x1000 + serial * 0x40,
        insn_snapshots=(),
    )


def test_carrier_return_arm_flows_through_shared_block(_seam) -> None:
    # The Approov conditional-handler shape: a 2-way branch (blk7) selects two arms
    # that CONVERGE on a shared block (blk10) carrying a LIVE non-state write (the
    # ``v4 = a1`` carrier = the return value).  Arm A (blk8) writes a CONTINUE state
    # (0x20, a real handler that re-enters the loop and overwrites the carrier); arm
    # B (blk9) writes the EXIT state (0x30, routing to the return).  The carrier is
    # live ONLY on the exit arm, so the recovery must keep the exit arm flowing
    # THROUGH blk10 (carrier preserved -> ``return v4``) while the continue arm
    # bypasses blk10 (its carrier copy is dead).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),  # entry
            1: _b(1, (3,), (0,), (_mov_state(0x900, 0x10),)),  # prologue -> 0x10
            3: _b(3, (7, 20, 99), (1, 10), ()),  # dispatcher
            7: _b(7, (8, 9), (3,)),  # selecting 2-way
            8: _b(8, (10,), (7,), (_mov_state(0x1000, 0x20),)),  # CONTINUE arm -> 0x20
            9: _b(9, (10,), (7,), (_mov_state(0x1010, 0x30),)),  # EXIT arm -> 0x30
            10: _b(10, (3,), (8, 9), (_mov_carrier(0x1020, 0x80),)),  # shared carrier
            20: _b(20, (3,), (3,)),  # continue handler
            99: _exit_block(99, (3,)),  # return/exit
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    # 0x30 has no handler row -> routes to the exit (default) = a return.
    disp = _disp({0x10: 7, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=3, initial_state=0x10
    )
    mods = graph_modifications(plan)
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    # The CONTINUE arm bypasses the carrier block: blk8 -> route(0x20)=blk20.
    assert (8, 10, 20) in gotos
    # The carrier block ITSELF is redirected onto the exit route (blk99): the exit
    # arm's edge blk9 -> blk10 stays intact, so ``blk9 -> blk10(carrier) -> exit``.
    assert (10, 3, 99) in gotos
    # The exit arm (blk9) is NOT bypassed -- it must flow through the carrier block.
    assert not [m for m in mods if isinstance(m, RedirectGoto) and m.from_serial == 9]


def test_explicit_stop_row_routes_to_stop_not_catchall(_seam) -> None:
    # OLLVM -fla EXIT shape (ticket llr-gpt3): the EXIT state (0x30) is an EXPLICIT
    # map row routing to a STOP block (blk99), while the dispatcher's catch-all
    # default (blk20) loops back to the dispatcher (NOT a STOP).  The terminal
    # handler blk10 writes the EXIT state, so its back-edge must redirect onto the
    # STOP (blk99) -- routing it to the catch-all default (blk20) strands the
    # output write in a non-returning while(1).
    # blk99 must be a real STOP (BLT_STOP); a bare 0-succ block is ZERO_WAY, not
    # STOP, and _is_stop_block keys on the STOP kind/type.
    stop99 = BlockSnapshot(
        serial=99,
        block_type=1,
        succs=(),
        preds=(2,),
        flags=0,
        start_ea=0x1000 + 99 * 0x40,
        insn_snapshots=(),
        kind=BlockKind.STOP,
    )
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),  # entry
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),  # prologue -> 0x10
            2: _b(2, (10, 20, 99), (1, 10, 20)),  # dispatcher
            10: _b(
                10, (2,), (2,), (_mov_state(0x1000, 0x30),)
            ),  # terminal: writes EXIT 0x30
            20: _b(20, (2,), (2,)),  # catch-all default (loops back)
            99: stop99,  # STOP / return
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    # Explicit rows: 0x10 -> blk10 (terminal handler), 0x30 -> blk99 (STOP).
    # Catch-all default = blk20 (the loop-back catch-all, NOT a STOP).
    disp = _disp({0x10: 10, 0x30: 99}, exit_block=20)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    by_block = {t.write_block: t for t in transitions}
    # blk10 folds to EXIT state 0x30, routed to STOP blk99 -> classified is_return.
    assert by_block[10].next_state == 0x30
    assert by_block[10].target_handler == 99
    assert by_block[10].is_return is True
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
    )
    gotos = {(m.from_serial, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # FIX: the terminal back-edge redirects onto the STOP (blk99), NOT the catch-all
    # default (blk20) -- so the function actually returns.
    assert (10, 99) in gotos
    assert (10, 20) not in gotos


def test_return_redirect_falls_back_to_default_when_not_stop(_seam) -> None:
    # CONTROL (hodur / approov shape): when the return routes to the catch-all
    # default which IS the function's exit, the back-edge must still redirect onto
    # default_target exactly as before (byte-identical legacy path).  Here the EXIT
    # arm's state 0x30 has no explicit row -> routes to the catch-all default = the
    # STOP blk99; target_handler == default, so the fix returns default unchanged.
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            1: _b(1, (2,), (0,), (_mov_state(0x900, 0x10),)),
            2: _b(2, (10, 99), (1, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1000, 0x30),)),  # writes UNMAPPED 0x30
            99: _exit_block(99, (2,)),  # catch-all default = STOP
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    # 0x30 has NO explicit row -> routes to default = exit_block = blk99 (STOP).
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    by_block = {t.write_block: t for t in transitions}
    assert by_block[10].is_return is True
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=0x10,
    )
    gotos = {(m.from_serial, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # default_target IS the STOP -> redirect onto it (unchanged legacy behaviour).
    assert (10, 99) in gotos


def test_exact_static_terminal_delivery_targets_zero_successor_epilogue(_seam) -> None:
    """Resolver-proven epilogues need not be classified as portable STOP blocks."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10,), (0, 10)),
            10: _b(10, (11,), (2,)),
            11: _b(11, (2,), (10,)),
            99: _b(99, (), ()),
            100: BlockSnapshot(
                serial=100,
                block_type=1,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x9000,
                insn_snapshots=(),
                kind=BlockKind.STOP,
            ),
        },
        entry_serial=0,
        func_ea=0x40A560,
    )
    disp = _disp({0x19A7218A: 10}, exit_block=98)
    transition = StateWriteTransition(
        write_block=10,
        next_state=0x19A7218A,
        target_handler=99,
        is_return=True,
        branch_arm=None,
        via_block=11,
        proof=TransitionProof(
            "region_partitioned_fixpoint",
            "computed_goto_exact_terminal_delivery",
            True,
        ),
    )

    mods = build_state_write_redirects(
        fg,
        disp,
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=None,
    )

    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 11, 100) in gotos


def test_pure_glue_via_block_still_bypassed(_seam) -> None:
    # CONTROL: when the shared back-edge block carries ONLY the state-glue (no live
    # carrier write), the predecessor-partitioned model must still BYPASS it exactly
    # as before -- the carrier-preservation must not fire (byte-identical old path).
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (3,), (0,), (_mov_state(0x900, 0x10),)),
            3: _b(3, (7, 20, 99), (1, 10), ()),
            7: _b(7, (8, 9), (3,)),
            8: _b(8, (10,), (7,), (_mov_state(0x1000, 0x20),)),
            9: _b(9, (10,), (7,), (_mov_state(0x1010, 0x30),)),
            10: _b(10, (3,), (8, 9), ()),  # PURE glue
            20: _b(20, (3,), (3,)),
            99: _exit_block(99, (3,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 7, 0x20: 20}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg, disp, state_var_stkoff=_STATE, dispatcher_entry_serial=3, initial_state=0x10
    )
    mods = graph_modifications(plan)
    gotos = {(m.from_serial, m.new_target) for m in mods if isinstance(m, RedirectGoto)}
    # Pure glue: blk8 bypasses to route(0x20)=blk20, blk9 bypasses to the exit
    # (blk99); the shared block is never kept on the path.
    assert (8, 20) in gotos
    assert (9, 99) in gotos
    # The carrier-return path is NOT used (no ``blk10 -> exit`` self-redirect).
    assert (10, 99) not in gotos


def test_terminal_stack_alias_via_block_keeps_carrier_guard(_seam) -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (6,), ()),
            2: _b(2, (3, 5), (8,)),
            6: _b(6, (7, 8), (0,), (_state_ne_tail(0x1600, 0x10),)),
            7: _b(7, (8,), (6,)),
            8: _b(8, (9, 2), (6, 7)),
            9: _b(9, (10,), (8,)),
            10: _exit_block(10, (9,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 7, 0x20: 9}, exit_block=3)
    transitions = (
        StateWriteTransition(
            7,
            0x20,
            9,
            False,
            None,
            via_block=8,
            proof=TransitionProof(
                "region_partitioned_fixpoint",
                "stack_address_alias_terminal_guard_partitioned",
                True,
            ),
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=0x10,
        state_var_stkoff=_STATE,
    )

    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    converts = {
        (m.block_serial, m.goto_target) for m in mods if isinstance(m, ConvertToGoto)
    }
    assert (7, 8, 9) not in gotos
    assert (6, 7) in converts
    assert (8, 9) in converts
    assert (6, 8, 7) not in branches
    assert (8, 2, 9) not in branches


def test_witness_entry_bridge_shortcuts_safe_exit_path(_seam) -> None:
    """Equality-chain entry bridge with a pure exit_path is shortcut."""
    # blk0 -> blk2(dispatcher entry) -> blk4(eq 0x10) -> blk10(handler)
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_preserves_live_stack_exit_path(_seam) -> None:
    """Equality-chain entry bridge with a live stack definition is preserved."""
    # blk0 -> blk2(dispatcher entry) -> blk4(eq 0x10). blk4 defines a non-state
    # stack slot 0x70. blk10(handler) uses 0x70. Shortcut blk0 -> blk10 would
    # bypass the definition, so the entry bridge must be preserved.
    _LIVE_OFF = 0x70
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_stk(0x1080, _STATE, _LIVE_OFF),),  # live def of 0x70
            ),
            10: _b(10, (99,), (2,), (_use_stk(0x10C0, _LIVE_OFF),)),  # use of 0x70
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectBranch)
    }
    # Entry bridge must NOT shortcut because blk2 defines live 0x70.
    assert (0, 2, 10) not in gotos
    # Feasibility is still useful to prove which arm is live, but unsafe
    # exit_path_effect_summaries must preserve the current CFG instead of mutating branch arms.
    assert (2, 99, 10) not in branches


def test_witness_entry_bridge_preserves_nested_register_use(_seam) -> None:
    """Nested sub-instruction uses, like ``icall rax``, keep register defs live."""
    _RAX = 8
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_reg(0x1080, 0x1234, _RAX),),
            ),
            10: _b(10, (99,), (2,), (_use_nested_reg(0x10C0, _RAX),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectBranch)
    }
    assert (0, 2, 10) not in gotos
    assert (2, 99, 10) not in branches


def test_entry_bridge_requires_witness_shortcuts_live_safe_without_provider(
    _seam,
) -> None:
    """Missing witness rows keep legacy shortcutting when the exit_path is live-safe."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_entry_bridge_requires_witness_preserves_live_no_provider_exit_path(
    _seam,
) -> None:
    """No-provider fallback preserves a live register def in the dispatcher entry."""
    _RAX = 8
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_reg(0x1080, 0x1234, _RAX),),
            ),
            10: _b(10, (99,), (2,), (_use_nested_reg(0x10C0, _RAX),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) not in gotos


def test_computed_goto_entry_bridge_ignores_router_only_scratch_liveness(_seam) -> None:
    scratch = 8
    state_reg = 20
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 99), (0,), (_mov_reg(0x1080, 0x1234, scratch),)),
            10: _b(10, (99,), (2,)),
            99: _b(99, (100,), (2, 10), (_use_nested_reg(0x10C0, scratch),)),
            100: _exit_block(100, (99,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    plan = emit_minimal_unflatten(
        fg,
        _disp({0x10: 10}, exit_block=100),
        state_var_stkoff=None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_exit_path_blocks=(2, 99),
        entry_bridge_requires_witness=True,
        materialized_computed_goto_profile=True,
    )
    gotos = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_entry_bridge_requires_witness_preserves_live_no_provider_stack_exit_path(
    _seam,
) -> None:
    """No-provider fallback uses all supplied exit_path blocks, not just old target."""
    _LIVE_OFF = 0x70
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (4,), (0,)),
            4: _b(4, (10,), (2,), (_mov_stk(0x1080, _STATE, _LIVE_OFF),)),
            10: _b(10, (99,), (4,), (_use_stk(0x10C0, _LIVE_OFF),)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
        entry_bridge_exit_path_blocks=(2, 4),
        entry_bridge_requires_witness=True,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) not in gotos


def test_conditional_entry_bridge_without_policy_uses_legacy_shortcut(_seam) -> None:
    """Conditional-looking CFG alone does not force witness-mode projection."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(0,)),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=None,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_shortcuts_dead_non_state_exit_path(_seam) -> None:
    """A non-state definition with no live use can be bypassed."""
    _DEAD_OFF = 0x71
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_stk(0x1080, _STATE, _DEAD_OFF),),  # dead def
            ),
            10: _b(10, (99,), (2,)),  # no use of _DEAD_OFF
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_witness_entry_bridge_shortcuts_state_only_exit_path(_seam) -> None:
    """State-variable definitions are intentionally severed by unflattening."""
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _eq_block(
                2,
                0x10,
                taken=10,
                fallthrough=99,
                preds=(0,),
                insns=(_mov_state(0x1080, 0x10),),  # state-var def
            ),
            10: _b(10, (99,), (2,)),
            99: _exit_block(99, (10,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp, dmap = _equality_dispatcher({0x10: 10}, entry_block=2, compare_blocks=(2,))
    branch_witness_map = build_static_equality_chain_witness_map(fg, dmap)
    plan = emit_minimal_unflatten(
        fg,
        disp,
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        branch_witness_map=branch_witness_map,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in graph_modifications(plan)
        if isinstance(m, RedirectGoto)
    }
    assert (0, 2, 10) in gotos


def test_back_edge_preserves_unresolved_indirect_state_store(_seam) -> None:
    """Do not route a dispatcher back-edge past a pointer-indirected state store."""
    tail = InsnSnapshot(
        opcode=43,
        ea=0x1200,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=0x20, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(8,)),
            8: _b(8, (9, 2), (6, 7), (_stx_reg(0x1180, 0x20, 32), tail)),
            9: _exit_block(9, (8,)),
            10: _b(10, (8,), (2,)),
            99: _exit_block(99, (2,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=8,
            next_state=0x10,
            target_handler=10,
            is_return=False,
            branch_arm=1,
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
    )
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    assert (8, 2, 10) not in branches


def test_back_edge_uses_exact_witness_for_terminal_indirect_state_store(_seam) -> None:
    """A terminal indirect state store may redirect through a local branch witness."""
    terminal = 0xDD1FF05BF465445C
    tail = InsnSnapshot(
        opcode=43,
        ea=0x1200,
        operands=(),
        l=MopSnapshot(t=_T_STK, size=8, stkoff=_STATE, kind=OperandKind.STACK),
        r=MopSnapshot(t=_T_NUM, size=8, value=terminal, kind=OperandKind.NUMBER),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        branch_predicate=PredicateKind.NE,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            2: _eq_block(2, 0x10, taken=10, fallthrough=99, preds=(8,)),
            8: _b(8, (9, 2), (7,), (_stx_reg(0x1180, terminal, 32), tail)),
            9: _exit_block(9, (8,)),
            10: _b(10, (8,), (2,)),
            99: _exit_block(99, (2,)),
        },
        entry_serial=2,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 10}, exit_block=99)
    transitions = (
        StateWriteTransition(
            write_block=8,
            next_state=0x10,
            target_handler=10,
            is_return=False,
            branch_arm=1,
        ),
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        branch_witness_map=None,
    )
    converts = {
        (m.block_serial, m.goto_target) for m in mods if isinstance(m, ConvertToGoto)
    }
    branches = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectBranch)
    }
    assert (8, 9) in converts
    assert (8, 2, 9) not in branches
    assert (8, 2, 10) not in branches


def test_conditional_entry_two_arms_bridge_to_both_handlers(_seam) -> None:
    """d81-3rja: the prologue selects the initial state CONDITIONALLY -- two arms
    each write a distinct leaf state to the state var, then merge into the
    dispatcher (the Rhadamanthys sub_40A560 ``a2 ? S_a : S_b`` entry). Both arms
    must bridge PAST the dispatcher to their own handler, not funnel through a
    single ``initial_state``.

        0(entry) -> 1(cond) -> {11 writes 0x10, 12 writes 0x20} -> 2(dispatcher)
        route(0x10)=21, route(0x20)=22

    Expected 2-way entry bridge: 11 -> 21 and 12 -> 22.
    """
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (11, 12), (0,)),  # conditional split
            11: _b(11, (2,), (1,), (_mov_state(0x1100, 0x10),)),  # arm A: state=0x10
            12: _b(12, (2,), (1,), (_mov_state(0x1200, 0x20),)),  # arm B: state=0x20
            2: _b(2, (21, 22), (11, 12, 21, 22)),  # dispatcher
            21: _b(21, (2,), (2,)),  # handler A
            22: _b(22, (2,), (2,)),  # handler B
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=2
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=None,
        state_var_stkoff=_STATE,
    )
    gotos = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, RedirectGoto)
    }
    assert (11, 2, 21) in gotos, f"arm A not bridged to its handler: {sorted(gotos)}"
    assert (12, 2, 22) in gotos, f"arm B not bridged to its handler: {sorted(gotos)}"


def test_conditional_handler_redirects_unique_arm_glue_before_bst_spine(_seam) -> None:
    """A register-BST arm can write its next state in a unique glue block and
    then enter one of the dispatch root's range-navigation children. Redirect
    that glue edge, preserving its writes, instead of requiring the distant
    shared write boundary to be a direct dispatcher predecessor.
    """
    fg = FlowGraph(
        blocks={
            8: _b(8, (9, 131), ()),
            9: _b(9, (8,), (230,)),
            131: _b(131, (8,), (195,)),
            194: _b(194, (195, 230), ()),
            195: _b(195, (131,), (194,), (_mov_reg(0x1195, 0x20, 20),)),
            230: _b(230, (9,), (194,), (_mov_reg(0x1230, 0x10, 20),)),
            103: _b(103, (500,), ()),
            220: _b(220, (501,), ()),
            500: _b(500, (8,), (103,)),
            501: _b(501, (8,), (220,)),
            104: _b(104, (), ()),
            221: _b(221, (), ()),
        },
        entry_serial=194,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=194,
        states=(0xA0716E5B,),
        arms=(
            TransitionArm(0x20, 221, False, 194, 220, 220, (194, 195, 131, 220)),
            TransitionArm(0x10, 104, False, 194, 103, 103, (194, 230, 9, 103)),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x10: 104, 0x20: 221}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
    )
    gotos = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, RedirectGoto)
    }
    assert gotos == {(195, 131, 221), (230, 9, 104)}


def test_conditional_handler_abstains_on_unmatched_materialized_arm(_seam) -> None:
    """An unproven computed-goto arm is not evidence of a function return."""
    fg = FlowGraph(
        blocks={
            8: _b(8, (9, 10), ()),
            9: _b(9, (8,), (146,)),
            10: _b(10, (8,), (146,)),
            59: _b(59, (), ()),
            99: _b(99, (), ()),
            146: _b(146, (9, 10), ()),
        },
        entry_serial=146,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=146,
        states=(0xEC71CA67,),
        arms=(
            TransitionArm(0x2100AFDD, 59, False, 146, 9, 9, (146, 9, 8)),
            TransitionArm(None, None, True, 146, 10, 10, (146, 10, 8)),
        ),
    )

    mods = build_conditional_arm_redirects(
        fg,
        _disp({0x2100AFDD: 59}, exit_block=99),
        (handler,),
        dispatcher_entry_serial=8,
        existing=set(),
        infer_unmatched_returns=False,
    )
    redirects = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, (RedirectGoto, RedirectBranch))
    }
    assert redirects == {(9, 8, 59)}


def test_state_write_redirect_abstains_on_unmatched_materialized_return(_seam) -> None:
    """The coarse back-edge model must not infer return from an unknown state."""
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (225,)),
            146: _b(146, (147, 225), ()),
            147: _b(147, (), (146,)),
            148: _b(148, (), ()),
            225: _b(225, (8,), (146,)),
        },
        entry_serial=146,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(
        146,
        None,
        148,
        True,
        None,
        via_block=225,
    )

    mods = build_state_write_redirects(
        fg,
        _disp({}, exit_block=148),
        (transition,),
        dispatcher_entry_serial=8,
        pre_header_serial=None,
        initial_state=None,
        state_var_reg=20,
        infer_unmatched_returns=False,
    )

    assert mods == []


def test_loop_guard_exit_abstains_on_unmatched_materialized_arm(_seam) -> None:
    """A detached terminal arm is not proof that its sibling should exit."""
    branch = InsnSnapshot(
        opcode=100,
        ea=0x2000,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=225),
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (225,)),
            146: _b(146, (147, 225), (), (branch,)),
            147: _b(147, (148,), (146,)),
            148: _b(148, (), (147,)),
            225: _b(225, (8,), (146,)),
        },
        entry_serial=146,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=146,
        states=(0xEC71CA67,),
        arms=(
            TransitionArm(0x2100AFDD, 59, False, 146, 225, 225, (146, 225, 8)),
            TransitionArm(None, None, True, 146, 148, 148, (146, 147, 148)),
        ),
    )
    dispatcher = IntervalDispatcher(
        [IntervalRow(0, 1, 59)],
        compute_default=False,
    )

    assert (
        build_loop_guard_exit_redirects(
            fg,
            dispatcher,
            (handler,),
            dispatcher_entry_serial=8,
            infer_unmatched_returns=False,
        )
        == []
    )


def test_source_keyed_arm_overrides_existing_coarse_glue_redirect(_seam) -> None:
    fg = FlowGraph(
        blocks={
            8: _b(8, (9, 131), ()),
            131: _b(131, (8,), (129,)),
            104: _b(104, (129,), ()),
            129: _b(129, (131,), (104,)),
            212: _b(212, (), ()),
        },
        entry_serial=104,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=104,
        states=(0x13921E0E,),
        arms=(
            TransitionArm(
                0xA5540595,
                212,
                False,
                104,
                129,
                129,
                (104, 129),
                source_keyed_block=129,
            ),
            TransitionArm(0xDEF4B7E6, None, True, 104, 104, 104, (104,)),
        ),
    )

    mods = build_source_keyed_handler_redirects(
        fg,
        (handler,),
    )

    assert any(
        isinstance(mod, RedirectGoto)
        and (mod.from_serial, mod.old_target, mod.new_target) == (129, 131, 212)
        for mod in mods
    )


def test_source_keyed_handler_owner_redirects_one_branch_arm(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), ()),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                None,
                12,
                12,
                (10, 12),
                source_keyed_block=10,
            ),
        ),
    )

    mods = build_source_keyed_handler_redirects(fg, (handler,))

    assert mods == [RedirectBranch(10, 12, 20)]


def test_source_keyed_route_does_not_override_exact_live_edge(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (20,), ()),
            20: _b(20, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    stale_route = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x30,
                30,
                False,
                None,
                10,
                10,
                (10,),
                source_keyed_block=10,
            ),
        ),
    )

    assert (
        build_source_keyed_handler_redirects(
            fg,
            (stale_route,),
            protected_edges=frozenset({(10, 20)}),
        )
        == []
    )


def test_source_keyed_internal_owner_redirects_ordered_branch_arm(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (11,), ()),
            11: _b(11, (12, 13), (10,)),
            12: _b(12, (), (11,)),
            13: _b(13, (), (11,)),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                None,
                13,
                13,
                (10, 11, 13),
                source_keyed_block=11,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == [
        RedirectBranch(from_serial=11, old_target=13, new_target=20)
    ]


def test_source_keyed_terminal_handler_connects_to_proven_target(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (), ()),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                10,
                10,
                10,
                (10,),
                source_keyed_block=10,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == [
        ConvertToGoto(block_serial=10, goto_target=20)
    ]


def test_source_keyed_external_stop_never_becomes_a_goto_source(_seam) -> None:
    external_stop = BlockSnapshot(
        serial=10,
        block_type=6,
        succs=(),
        preds=(9,),
        flags=0,
        start_ea=0x40C898,
        insn_snapshots=(),
        kind=BlockKind.EXTERNAL,
    )
    fg = FlowGraph(
        blocks={
            10: external_stop,
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x19A7218A,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                10,
                10,
                10,
                (10,),
                source_keyed_block=10,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == []


def test_source_keyed_terminal_epilogue_routes_to_canonical_stop(_seam) -> None:
    stop = BlockSnapshot(
        serial=313,
        block_type=1,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
        kind=BlockKind.STOP,
    )
    fg = FlowGraph(
        blocks={
            301: _b(301, (302,), ()),
            302: _b(302, (), (301,)),
            313: stop,
        },
        entry_serial=301,
        func_ea=0x40A560,
    )
    handler = HandlerTransition(
        handler=301,
        states=(0x19A7218A,),
        arms=(
            TransitionArm(
                0x19A7218A,
                302,
                True,
                None,
                301,
                301,
                (301,),
                source_keyed_block=301,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == [
        RedirectGoto(from_serial=301, old_target=302, new_target=313)
    ]


def test_exact_terminal_state_writer_routes_to_canonical_stop(_seam) -> None:
    state = 0x19A7218A
    state_reg = 20
    stop = BlockSnapshot(
        serial=313,
        block_type=1,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0xFFFFFFFFFFFFFFFF,
        insn_snapshots=(),
        kind=BlockKind.STOP,
    )
    fg = FlowGraph(
        blocks={
            261: _b(
                261,
                (262,),
                (217,),
                (_mov_reg(0x40C7E5, state, state_reg),),
            ),
            262: _b(262, (5,), (261,)),
            302: _b(302, (), ()),
            313: stop,
        },
        entry_serial=261,
        func_ea=0x40A560,
    )

    assert build_exact_terminal_state_route_redirects(
        fg,
        (
            MaterializedStateRoute(
                261,
                state,
                302,
                proof_kind="terminal_state_route",
            ),
        ),
        state_var_reg=state_reg,
    ) == [RedirectGoto(from_serial=261, old_target=262, new_target=313)]


def test_exact_terminal_route_fragment_rejects_same_source_sibling_rewrites() -> None:
    terminal = RedirectGoto(from_serial=261, old_target=262, new_target=313)
    unrelated = RedirectGoto(from_serial=100, old_target=101, new_target=102)

    assert _prefer_exact_terminal_route_fragments(
        [
            ConvertToGoto(block_serial=261, goto_target=250),
            RedirectGoto(from_serial=261, old_target=262, new_target=250),
            unrelated,
            terminal,
        ],
        [terminal],
    ) == [unrelated, terminal]


def test_materialized_state_route_rebinds_external_handler_placeholder(
    _seam,
) -> None:
    state = 0x12345678
    state_reg = 20
    target_ea = 0x401800
    external = replace(
        _b(20, (), (10,)),
        start_ea=target_ea,
        kind=BlockKind.EXTERNAL,
    )
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (20,),
                (),
                (_mov_reg(0x401700, state, state_reg),),
            ),
            20: external,
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (MaterializedStateRoute(10, state, 30),),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset(),
        authoritative_handler_serials=frozenset({30}),
        handler_entry_eas_by_serial={30: target_ea},
    ) == [RedirectGoto(from_serial=10, old_target=20, new_target=30)]


def test_materialized_state_route_placeholder_rebind_abstains_without_local_write(
    _seam,
) -> None:
    state = 0x12345678
    state_reg = 20
    target_ea = 0x401800
    fg = FlowGraph(
        blocks={
            10: _b(10, (20,), ()),
            20: replace(
                _b(20, (), (10,)),
                start_ea=target_ea,
                kind=BlockKind.EXTERNAL,
            ),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (MaterializedStateRoute(10, state, 30),),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset(),
            authoritative_handler_serials=frozenset({30}),
            handler_entry_eas_by_serial={30: target_ea},
        )
        == []
    )


def test_materialized_state_route_dispatcher_rebind_requires_handler_exit_proof(
    _seam,
) -> None:
    state = 0x12345678
    state_reg = 20
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (20,),
                (),
                (_mov_reg(0x401700, state, state_reg),),
            ),
            20: _b(20, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (MaterializedStateRoute(10, state, 30),),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({20}),
            authoritative_handler_serials=frozenset({30}),
        )
        == []
    )
    assert build_materialized_state_route_redirects(
        fg,
        (
            MaterializedStateRoute(
                10,
                state,
                30,
                source_handler_serial=10,
                handler_exit_proven=True,
            ),
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({20}),
        authoritative_handler_serials=frozenset({30}),
    ) == [RedirectGoto(from_serial=10, old_target=20, new_target=30)]


def test_materialized_handler_exit_keeps_replayed_semantic_body_ownership(
    _seam,
) -> None:
    state = 0x4D34CF70
    state_reg = 20
    imported_clone = 30
    live_handler = 31
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (20,),
                (),
                (_mov_reg(0x401700, state, state_reg),),
            ),
            20: _b(20, (), (10,)),
            imported_clone: _b(imported_clone, (), ()),
            live_handler: _b(live_handler, (), ()),
        },
        entry_serial=10,
        func_ea=0x401000,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (
            MaterializedStateRoute(
                10,
                state,
                imported_clone,
                source_handler_serial=10,
                handler_exit_proven=True,
            ),
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({20}),
        authoritative_handler_serials=frozenset({imported_clone, live_handler}),
    ) == [
        RedirectGoto(
            from_serial=10,
            old_target=20,
            new_target=imported_clone,
        )
    ]


def test_materialized_handler_local_next_state_proves_imported_exit(
    _seam,
) -> None:
    entry_state = 0x4A7ECCB8
    next_state = 0xDC71BBC5
    state_reg = 20
    handler = 10
    router = 20
    next_handler = 30
    fg = FlowGraph(
        blocks={
            handler: _b(
                handler,
                (router,),
                (),
                (_mov_reg(0x40EF7D, next_state, state_reg),),
            ),
            router: _b(router, (), (handler,)),
            next_handler: _b(next_handler, (), ()),
        },
        entry_serial=handler,
        func_ea=0x40D200,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (
            MaterializedStateRoute(99, entry_state, handler),
            MaterializedStateRoute(handler, next_state, next_handler),
            MaterializedStateRoute(
                98,
                next_state,
                next_handler,
                source_handler_serial=handler,
                handler_exit_proven=True,
            ),
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({router}),
        authoritative_handler_serials=frozenset({handler, next_handler}),
    ) == [
        RedirectGoto(
            from_serial=handler,
            old_target=router,
            new_target=next_handler,
        )
    ]


def test_materialized_handler_local_entry_state_does_not_prove_exit(
    _seam,
) -> None:
    entry_state = 0x4A7ECCB8
    state_reg = 20
    handler = 10
    router = 20
    fg = FlowGraph(
        blocks={
            handler: _b(
                handler,
                (router,),
                (),
                (_mov_reg(0x40EF7D, entry_state, state_reg),),
            ),
            router: _b(router, (), (handler,)),
        },
        entry_serial=handler,
        func_ea=0x40D200,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (
                MaterializedStateRoute(99, entry_state, handler),
                MaterializedStateRoute(handler, entry_state, handler),
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({router}),
            authoritative_handler_serials=frozenset({handler}),
        )
        == []
    )


def test_materialized_handler_ambiguous_replay_does_not_prove_clone_exit(
    _seam,
) -> None:
    next_state = 0xDC71BBC5
    state_reg = 20
    handler = 10
    router = 20
    first_target = 30
    second_target = 31
    fg = FlowGraph(
        blocks={
            handler: _b(
                handler,
                (router,),
                (),
                (_mov_reg(0x40EF7D, next_state, state_reg),),
            ),
            router: _b(router, (), (handler,)),
            first_target: _b(first_target, (), ()),
            second_target: _b(second_target, (), ()),
        },
        entry_serial=handler,
        func_ea=0x40D200,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (
                MaterializedStateRoute(handler, next_state, first_target),
                MaterializedStateRoute(
                    98,
                    next_state,
                    first_target,
                    source_handler_serial=handler,
                    handler_exit_proven=True,
                ),
                MaterializedStateRoute(
                    99,
                    next_state,
                    second_target,
                    source_handler_serial=handler,
                    handler_exit_proven=True,
                ),
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({router}),
            authoritative_handler_serials=frozenset(
                {handler, first_target, second_target}
            ),
        )
        == []
    )


def test_materialized_handler_exit_collapses_two_way_dispatcher_port(
    _seam,
) -> None:
    state = 0x6EA4D36E
    state_reg = 20
    route = MaterializedStateRoute(
        10,
        state,
        30,
        source_handler_serial=5,
        handler_exit_proven=True,
    )
    fg = FlowGraph(
        blocks={
            10: _b(10, (20, 21), (5,)),
            20: _b(20, (), (10,)),
            21: _b(21, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (route, route),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({20, 21}),
        authoritative_handler_serials=frozenset({30}),
    ) == [ConvertToGoto(block_serial=10, goto_target=30)]


def test_materialized_handler_exit_two_way_port_abstains_for_semantic_arm(
    _seam,
) -> None:
    state_reg = 20
    fg = FlowGraph(
        blocks={
            10: _b(10, (20, 22), (5,)),
            20: _b(20, (), (10,)),
            22: _b(22, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (
                MaterializedStateRoute(
                    10,
                    0x6EA4D36E,
                    30,
                    source_handler_serial=5,
                    handler_exit_proven=True,
                ),
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({20}),
            authoritative_handler_serials=frozenset({30}),
        )
        == []
    )


def test_materialized_handler_exit_two_way_port_abstains_on_conflicting_route(
    _seam,
) -> None:
    state_reg = 20
    fg = FlowGraph(
        blocks={
            10: _b(10, (20, 21), (5,)),
            20: _b(20, (), (10,)),
            21: _b(21, (), (10,)),
            30: _b(30, (), ()),
            31: _b(31, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )

    assert (
        build_materialized_state_route_redirects(
            fg,
            (
                MaterializedStateRoute(
                    10,
                    0x6EA4D36E,
                    30,
                    source_handler_serial=5,
                    handler_exit_proven=True,
                ),
                MaterializedStateRoute(
                    10,
                    0x6955B42A,
                    31,
                    source_handler_serial=5,
                    handler_exit_proven=True,
                ),
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({20, 21}),
            authoritative_handler_serials=frozenset({30, 31}),
        )
        == []
    )


def test_materialized_handler_exit_rebinds_after_router_classification_is_lost(
    _seam,
) -> None:
    state = 0xB8D2E088
    state_reg = 20
    fg = FlowGraph(
        blocks={
            10: _b(10, (11,), ()),
            11: _b(
                11,
                (20,),
                (10,),
                (),
            ),
            20: _b(20, (), (11,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )
    route = MaterializedStateRoute(
        11,
        state,
        30,
        source_handler_serial=10,
        handler_exit_proven=True,
    )

    assert build_materialized_state_route_redirects(
        fg,
        (route,),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset(),
        authoritative_handler_serials=frozenset({30}),
    ) == [RedirectGoto(from_serial=11, old_target=20, new_target=30)]


def test_deferred_materialized_handler_exit_preserves_parent_path() -> None:
    route = MaterializedStateRoute(
        11,
        0xB8D2E088,
        30,
        source_handler_serial=10,
        handler_exit_proven=True,
    )

    assert _preserve_deferred_materialized_handler_exit_paths(
        [
            RedirectGoto(from_serial=10, old_target=11, new_target=10),
            RedirectGoto(from_serial=11, old_target=20, new_target=30),
        ],
        (route,),
    ) == [RedirectGoto(from_serial=11, old_target=20, new_target=30)]


def test_source_keyed_shared_terminal_redirects_each_owned_predecessor(
    _seam,
) -> None:
    """A shared computed-goto suffix must not be converted globally.

    Each proven handler arm owns the edge immediately preceding the shared
    zero-successor terminal.  Redirecting those predecessor edges preserves the
    sibling path while bypassing the computed-goto suffix for each exact arm.
    """
    fg = FlowGraph(
        blocks={
            10: _b(10, (12,), ()),
            11: _b(11, (13,), ()),
            12: _b(12, (14,), (10,)),
            13: _b(13, (14,), (11,)),
            14: _b(14, (), (12, 13)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    first = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                None,
                12,
                14,
                (10, 12, 14),
                source_keyed_block=10,
            ),
        ),
    )
    second = HandlerTransition(
        handler=11,
        states=(0x11,),
        arms=(
            TransitionArm(
                0x30,
                30,
                False,
                None,
                13,
                14,
                (11, 13, 14),
                source_keyed_block=11,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (first, second)) == [
        RedirectGoto(from_serial=12, old_target=14, new_target=20),
        RedirectGoto(from_serial=13, old_target=14, new_target=30),
    ]


def test_source_keyed_shared_terminal_with_call_abstains(_seam) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (12,), ()),
            12: _b(12, (14,), (10,)),
            13: _b(13, (14,), ()),
            14: _b(14, (), (12, 13), (_call_reg(0x1380, 7),)),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                None,
                12,
                14,
                (10, 12, 14),
                source_keyed_block=10,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == []


def test_source_keyed_handler_owner_preserves_live_arm_to_known_handler(
    _seam,
) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), ()),
            11: _b(11, (20,), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), (11,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    stale_tail = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x30,
                30,
                False,
                None,
                11,
                11,
                (10, 11),
                source_keyed_block=10,
            ),
        ),
    )
    live_handler = HandlerTransition(handler=20, states=(0x20,), arms=())
    replacement_handler = HandlerTransition(handler=30, states=(0x30,), arms=())

    assert (
        build_source_keyed_handler_redirects(
            fg,
            (stale_tail, live_handler, replacement_handler),
        )
        == []
    )


def test_state_write_parent_preserves_fully_resolved_conditional_fork(
    _seam,
) -> None:
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (13, 14)),
            10: _b(10, (11,), ()),
            11: _b(11, (12,), (10,)),
            12: _b(12, (13, 14), (11,)),
            13: _b(13, (8,), (12,)),
            14: _b(14, (8,), (12,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
            40: _b(40, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _disp(
        {0x20: 20, 0x30: 30, 0x40: 40},
        exit_block=99,
    )
    transitions = (
        StateWriteTransition(13, 0x30, 30, False, None),
        StateWriteTransition(14, 0x40, 40, False, None),
        StateWriteTransition(11, 0x20, 20, False, None, via_block=12),
    )

    assert build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=8,
        pre_header_serial=10,
        initial_state=None,
        strict_pre_header_prologue=True,
    ) == [
        RedirectGoto(from_serial=13, old_target=8, new_target=30),
        RedirectGoto(from_serial=14, old_target=8, new_target=40),
    ]


def test_materialized_conditional_handler_bridge_restores_folded_register_arm(
    _seam,
) -> None:
    predicate_ea = 0x1290
    predicate = InsnSnapshot(opcode=55, ea=predicate_ea, operands=())
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (10,)),
            10: _b(10, (8,), (), (predicate,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(fg.get_block(20).start_ea, fg.get_block(30).start_ea),
        condition_code=5,
        true_target_ea=fg.get_block(20).start_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=0x1288,
    )

    assert build_materialized_conditional_handler_bridges(fg, (transfer,)) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=8,
            rewrite_from_ea=predicate_ea,
            condition_operand=SyntheticRegisterNonzeroCondition(44, 4),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_conditional_handler_bridge",
        )
    ]


def test_exact_live_state_edge_protects_existing_source_edge() -> None:
    fg = FlowGraph(
        blocks={
            146: _b(146, (243,), ()),
            243: _b(243, (), (146,)),
        },
        entry_serial=146,
        func_ea=0x40A560,
    )

    assert _exact_live_state_edge_keys(
        fg,
        (
            MaterializedStateRoute(
                146,
                0xA5540595,
                243,
                proof_kind="exact_live_state_edge",
            ),
            MaterializedStateRoute(146, 0xDEF4B7E6, 243),
        ),
    ) == {(146, 243)}


def test_applied_direct_boundary_anchors_protect_existing_live_edge() -> None:
    source_anchor_ea = 0x1290
    target_anchor_ea = 0x1510
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (20,),
                (),
                (InsnSnapshot(opcode=4, ea=source_anchor_ea, operands=()),),
            ),
            20: _b(
                20,
                (),
                (10,),
                (InsnSnapshot(opcode=4, ea=target_anchor_ea, operands=()),),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=0x1280,
        source_instruction_ea=source_anchor_ea,
        endpoint_block_ea=0x1280,
        old_successor_eas=(),
        target_ea=0x1500,
        state_register=20,
        state_constant=0xA5A94B86,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="terminal_goto",
        resolver_kind="static_fixpoint",
    )

    assert _applied_direct_boundary_edge_keys(
        fg,
        (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=port,
                endpoint_anchor_eas=(source_anchor_ea,),
                target_anchor_eas=(target_anchor_ea,),
            ),
        ),
    ) == {(10, 20)}


def test_applied_direct_boundary_prefers_attached_target_anchor_over_native_clone() -> (
    None
):
    endpoint_anchor_ea = 0x1290
    target_ea = 0x1500
    imported_target_anchor_ea = 0xF1C00234
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (21,),
                (),
                (InsnSnapshot(opcode=4, ea=endpoint_anchor_ea, operands=()),),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=target_ea,
                insn_snapshots=(),
            ),
            21: _b(
                21,
                (),
                (10,),
                (
                    InsnSnapshot(
                        opcode=4,
                        ea=imported_target_anchor_ea,
                        operands=(),
                    ),
                ),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=0x1280,
        source_instruction_ea=endpoint_anchor_ea,
        endpoint_block_ea=0x1280,
        old_successor_eas=(),
        target_ea=target_ea,
        state_register=20,
        state_constant=0xA5A94B86,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="terminal_goto",
        resolver_kind="static_fixpoint",
    )

    assert _applied_direct_boundary_edge_keys(
        fg,
        (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=port,
                endpoint_anchor_eas=(endpoint_anchor_ea,),
                target_anchor_eas=(imported_target_anchor_ea,),
            ),
        ),
    ) == {(10, 21)}


def test_resolver_proven_router_port_is_a_dynamic_entry_bridge() -> None:
    endpoint_anchor_ea = 0x40D313
    router_ea = 0x40EAA7
    router_anchor_ea = 0xF1C01FD4
    fg = FlowGraph(
        blocks={
            0: _b(0, (10,), ()),
            10: _b(
                10,
                (20,),
                (0,),
                (InsnSnapshot(opcode=4, ea=endpoint_anchor_ea, operands=()),),
            ),
            20: _b(
                20,
                (30, 40),
                (10,),
                (InsnSnapshot(opcode=4, ea=router_anchor_ea, operands=()),),
            ),
            30: _b(30, (), (20,)),
            40: _b(40, (), (20,)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=endpoint_anchor_ea,
        source_instruction_ea=0x40D348,
        endpoint_block_ea=endpoint_anchor_ea,
        old_successor_eas=(0x40D370,),
        target_ea=router_ea,
        state_register=28,
        state_constant=0x699BC698,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        delivery_mode="redirect_edge",
        resolver_kind="residual_state_route_evidence",
    )
    evidence = AppliedDetachedSnippetDirectBoundaryPort(
        port=port,
        endpoint_anchor_eas=(endpoint_anchor_ea,),
        target_anchor_eas=(router_anchor_ea,),
    )
    router_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40EAA5,
        source_block_ea=0x40EA9B,
        materialized_anchor_eas=(),
        target_eas=(0x40D370,),
        dispatcher_router_eas=(router_ea, 0x40D370),
    )

    assert _resolver_proven_dynamic_entry_edges(
        fg,
        (evidence,),
        (router_transfer,),
    ) == frozenset({(10, 20)})


def test_imported_router_origin_is_a_dynamic_entry_bridge() -> None:
    router_ea = 0x40EAA7
    router_anchor_ea = 0xF1C01FD4
    fg = FlowGraph(
        blocks={
            0: _b(0, (10, 50), ()),
            10: _b(
                10,
                (20,),
                (0,),
                (InsnSnapshot(opcode=4, ea=0x40D313, operands=()),),
            ),
            20: _b(
                20,
                (30, 40),
                (10,),
                (InsnSnapshot(opcode=4, ea=router_anchor_ea, operands=()),),
            ),
            30: _b(30, (), (20,)),
            40: _b(40, (), (20,)),
            50: BlockSnapshot(
                serial=50,
                block_type=0,
                succs=(60,),
                preds=(0,),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(),
            ),
            60: BlockSnapshot(
                serial=60,
                block_type=0,
                succs=(),
                preds=(50,),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(InsnSnapshot(opcode=4, ea=0xF1C01000, operands=()),),
            ),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    router_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40EAA5,
        source_block_ea=0x40EA9B,
        materialized_anchor_eas=(),
        target_eas=(0x40D370,),
        dispatcher_router_eas=(router_ea, 0x40D370, 0x40DBEA),
    )

    assert _resolver_proven_dynamic_entry_edges(
        fg,
        (),
        (router_transfer,),
        imported_native_eas_by_serial={
            20: frozenset({router_ea, 0x40EABA}),
            60: frozenset({0x40DBEA}),
        },
    ) == frozenset({(10, 20)})


def test_dynamic_entry_bridge_suppresses_scalar_entry_shortcut() -> None:
    fg = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: _b(2, (10, 20), (0, 10)),
            10: _b(10, (2,), (2,), (_mov_state(0x1010, 0x20),)),
            20: _b(20, (), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 10, 0x20: 20}, exit_block=99)
    transitions = (StateWriteTransition(10, 0x20, 20, False, None),)

    mods = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=2,
        pre_header_serial=0,
        initial_state=0x10,
        dynamic_entry_bridge_edges=frozenset({(0, 2)}),
    )

    redirects = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, RedirectGoto)
    }
    assert (10, 2, 20) in redirects
    assert not any(source == 0 for source, _old, _new in redirects)


def test_dynamic_entry_bridge_suppresses_materialized_scalar_route(_seam) -> None:
    state_reg = 28
    transient_state = 0x699BC698
    router_ea = 0x40EAA7
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1,
                (2,),
                (0,),
                (_mov_reg(0x1010, transient_state, state_reg),),
            ),
            2: _b(2, (10,), (1, 10)),
            10: _b(10, (2,), (2,)),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({transient_state: 10}, exit_block=99)
    router_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40EAA5,
        source_block_ea=0x40EA9B,
        materialized_anchor_eas=(),
        target_eas=(0x1500,),
        dispatcher_router_eas=(router_ea,),
    )

    plan = emit_minimal_unflatten(
        fg,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=state_reg,
        dispatcher_entry_serial=2,
        initial_state=transient_state,
        materialized_computed_goto_profile=True,
        materialized_indirect_transfers=(router_transfer,),
        materialized_state_routes=(MaterializedStateRoute(1, transient_state, 10),),
        condition_chain_handlers=frozenset({10}),
        authoritative_handler_serials=frozenset({10}),
        dispatcher_region_serials=frozenset({2}),
        imported_native_eas_by_serial={2: frozenset({router_ea})},
    )

    assert not any(
        isinstance(modification, (RedirectGoto, RedirectBranch))
        and int(modification.from_serial) == 1
        and int(modification.old_target) == 2
        for modification in graph_modifications(plan)
    )


def test_applied_direct_boundary_tracks_folded_live_endpoint_into_predecessor() -> None:
    endpoint_ea = 0x1290
    target_ea = 0x1500
    fg = FlowGraph(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(20,),
                preds=(),
                flags=0,
                start_ea=0x1200,
                insn_snapshots=(
                    InsnSnapshot(opcode=4, ea=0x1280, operands=()),
                    InsnSnapshot(opcode=55, ea=0x1000, operands=()),
                ),
            ),
            11: BlockSnapshot(
                serial=11,
                block_type=0,
                succs=(20,),
                preds=(),
                flags=0,
                start_ea=0x1800,
                insn_snapshots=(InsnSnapshot(opcode=55, ea=0x1000, operands=()),),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(10, 11),
                flags=0,
                start_ea=target_ea,
                insn_snapshots=(),
            ),
            21: BlockSnapshot(
                serial=21,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=target_ea,
                insn_snapshots=(),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=endpoint_ea,
        source_instruction_ea=endpoint_ea,
        endpoint_block_ea=endpoint_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        state_register=20,
        state_constant=0xA5A94B86,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
        resolver_kind="static_fixpoint",
    )

    assert _applied_direct_boundary_edge_keys(
        fg,
        (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=port,
                endpoint_anchor_eas=(0x1280, 0x1000),
                target_anchor_eas=(target_ea,),
            ),
        ),
    ) == {(10, 20)}


def test_applied_direct_boundary_ignores_stale_anchor_after_endpoint_fold() -> None:
    class EquivalentLiveOwner:
        value = DetachedSnippetBoundaryPortOwner.LIVE.value

    endpoint_ea = 0x1290
    target_ea = 0x1500
    stale_anchor_ea = 0x1270
    fg = FlowGraph(
        blocks={
            9: BlockSnapshot(
                serial=9,
                block_type=0,
                succs=(10,),
                preds=(),
                flags=0,
                start_ea=0x1100,
                insn_snapshots=(
                    InsnSnapshot(opcode=4, ea=stale_anchor_ea, operands=()),
                ),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(20,),
                preds=(9,),
                flags=0,
                start_ea=0x1200,
                insn_snapshots=(InsnSnapshot(opcode=4, ea=0x1280, operands=()),),
            ),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(10, 11),
                flags=0,
                start_ea=target_ea,
                insn_snapshots=(),
            ),
            11: BlockSnapshot(
                serial=11,
                block_type=0,
                succs=(20,),
                preds=(),
                flags=0,
                start_ea=0x1600,
                insn_snapshots=(InsnSnapshot(opcode=4, ea=0x1600, operands=()),),
            ),
        },
        entry_serial=9,
        func_ea=0x1000,
    )
    port = DetachedSnippetDirectBoundaryPort(
        source_block_ea=endpoint_ea,
        source_instruction_ea=endpoint_ea,
        endpoint_block_ea=endpoint_ea,
        old_successor_eas=(),
        target_ea=target_ea,
        state_register=20,
        state_constant=0xA5A94B86,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        endpoint_owner=EquivalentLiveOwner(),  # type: ignore[arg-type]
        target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        delivery_mode="terminal_goto",
        resolver_kind="static_fixpoint",
    )

    assert _applied_direct_boundary_edge_keys(
        fg,
        (
            AppliedDetachedSnippetDirectBoundaryPort(
                port=port,
                endpoint_anchor_eas=(stale_anchor_ea, 0x1280, 0x1600),
                target_anchor_eas=(target_ea,),
            ),
        ),
    ) == {(10, 20)}


def test_applied_conditional_boundary_protects_materialized_arm_corridors() -> None:
    predicate_ea = 0x1110
    taken_anchor_ea = 0x2010
    fallthrough_anchor_ea = 0x3010
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (11, 12),
                (),
                (InsnSnapshot(opcode=43, ea=predicate_ea, operands=()),),
            ),
            11: _b(11, (20,), (10,)),
            12: _b(12, (30,), (10,)),
            20: _b(
                20,
                (),
                (11,),
                (InsnSnapshot(opcode=4, ea=taken_anchor_ea, operands=()),),
            ),
            30: _b(
                30,
                (),
                (12,),
                (InsnSnapshot(opcode=4, ea=fallthrough_anchor_ea, operands=()),),
            ),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x1100,
            predicate_ea=predicate_ea,
            old_taken_target_ea=0x1200,
            old_fallthrough_target_ea=0x1210,
            taken_target_ea=0x2000,
            fallthrough_target_ea=0x3000,
            state_register=20,
            taken_state=0xA0,
            fallthrough_state=0xB0,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            resolver_kind="static_fixpoint",
        ),
        taken_target_anchor_eas=(taken_anchor_ea,),
        fallthrough_target_anchor_eas=(fallthrough_anchor_ea,),
    )

    assert _applied_conditional_boundary_edge_keys(fg, (evidence,)) == {
        (10, 11),
        (11, 20),
        (10, 12),
        (12, 30),
    }


def test_state_write_redirect_does_not_override_protected_edge() -> None:
    fg = FlowGraph(
        blocks={
            2: _b(2, (), ()),
            10: _b(10, (20,), ()),
            20: _b(20, (), (10,)),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transition = StateWriteTransition(
        write_block=10,
        next_state=0x30,
        target_handler=30,
        is_return=False,
        branch_arm=None,
        via_block=20,
    )

    mods = build_state_write_redirects(
        fg,
        _disp({0x30: 30}, exit_block=99),
        (transition,),
        dispatcher_entry_serial=2,
        pre_header_serial=None,
        initial_state=None,
        protected_edges=frozenset({(10, 20)}),
    )

    assert not [
        mod
        for mod in mods
        if isinstance(mod, RedirectGoto)
        and (mod.from_serial, mod.old_target) == (10, 20)
    ]


def test_materialized_conditional_handler_bridge_uses_post_predecessor_anchor(
    _seam,
) -> None:
    definition_ea = 0x1288
    merged_tail_ea = 0x1100
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (10,)),
            10: _b(
                10,
                (8,),
                (),
                (
                    InsnSnapshot(opcode=4, ea=definition_ea, operands=()),
                    InsnSnapshot(opcode=55, ea=merged_tail_ea, operands=()),
                ),
            ),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1290,
        source_block_ea=0xDEAD,
        materialized_anchor_eas=(0x1290,),
        target_eas=(fg.get_block(20).start_ea, fg.get_block(30).start_ea),
        condition_code=5,
        true_target_ea=fg.get_block(20).start_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=definition_ea,
    )

    (modification,) = build_materialized_conditional_handler_bridges(fg, (transfer,))
    assert modification.rewrite_from_ea == merged_tail_ea


def test_materialized_conditional_handler_bridge_uses_current_state_route_when_target_ea_folds(
    _seam,
) -> None:
    definition_ea = 0x1288
    merged_tail_ea = 0x1100
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (10,)),
            10: _b(
                10,
                (8,),
                (),
                (
                    InsnSnapshot(opcode=4, ea=definition_ea, operands=()),
                    InsnSnapshot(opcode=55, ea=merged_tail_ea, operands=()),
                ),
            ),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    true_state = 0x304E8694
    false_state = 0xA5A94B86
    dispatcher = _disp({true_state: 20, false_state: 30}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x1290,
        source_block_ea=0xDEAD,
        materialized_anchor_eas=(0x1290,),
        target_eas=(0x40B342, 0x40B8E6),
        condition_code=5,
        true_target_ea=0x40B342,
        false_target_ea=0x40B8E6,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=definition_ea,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
    )

    (modification,) = build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        dispatcher=dispatcher,
    )
    assert modification.true_target_serial == 20
    assert modification.false_target_serial == 30


def test_materialized_conditional_handler_bridge_redirects_both_live_predicate_arms(
    _seam,
) -> None:
    predicate_ea = 0x1290
    predecessor_ea = 0x1288
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            10: _b(
                10,
                (11, 12),
                (),
                (
                    InsnSnapshot(opcode=4, ea=predecessor_ea, operands=()),
                    predicate,
                ),
            ),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(fg.get_block(20).start_ea, fg.get_block(30).start_ea),
        condition_code=5,
        true_target_ea=fg.get_block(20).start_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=predecessor_ea,
        predicate_true_is_taken=True,
    )

    assert build_materialized_conditional_handler_bridges(fg, (transfer,)) == [
        RedirectBranch(from_serial=10, old_target=12, new_target=20),
    ]


def test_materialized_conditional_handler_bridge_preserves_live_opaque_predicate(
    _seam,
) -> None:
    predicate_ea = 0x1290
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            9: _b(9, (10,), ()),
            10: _b(
                10,
                (11, 12),
                (9,),
                (predicate,),
            ),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
            40: BlockSnapshot(
                serial=40,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x1000 + 10 * 0x40,
                insn_snapshots=(),
            ),
            41: _b(41, (42, 43), (), (predicate,)),
            42: _b(42, (), (41,)),
            43: _b(43, (), (41,)),
        },
        entry_serial=9,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40C16A, 0x40AAA2),
        condition_code=5,
        true_target_ea=0x40C16A,
        false_target_ea=0x40AAA2,
        resolver_kind="conditional_handler_bridge",
        predicate_register=None,
        # A live opaque predicate (including a memory comparison) does not
        # need a width because d810 preserves its existing microcode instead
        # of synthesizing a replacement operand.
        predicate_size=None,
        predicate_compare_constant=0x62,
        predicate_predecessor_ea=None,
        predicate_true_state=0xCCEC5DE0,
        predicate_false_state=0x742F372A,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    state_routes = (
        MaterializedStateRoute(10, 0xCCEC5DE0, 20),
        MaterializedStateRoute(10, 0x742F372A, 30),
    )
    assert (
        build_materialized_conditional_handler_bridges(
            fg,
            (transfer,),
            materialized_state_routes=state_routes[:1],
            handler_entry_eas_by_serial={20: 0x40C16A, 30: 0x40AAA2},
        )
        == []
    )
    assert build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        materialized_state_routes=state_routes,
        handler_entry_eas_by_serial={20: 0x40C16A, 30: 0x40AAA2},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        ),
    ]
    assert build_materialized_conditional_handler_bridges(
        fg,
        (replace(transfer, condition_code=3),),
        materialized_state_routes=state_routes,
        handler_entry_eas_by_serial={20: 0x40C16A, 30: 0x40AAA2},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        ),
    ]

    # PREOPT replay can publish the same live predicate twice: once under its
    # stable native EA and once under the imported synthetic instruction EA.
    # Equivalent source, polarity, and arm targets are corroborating evidence,
    # not an ambiguity that should erase the conditional.
    imported_predicate_ea = 0xF1C01008
    imported_predicate = replace(predicate, ea=imported_predicate_ea)
    imported_blocks = {
        serial: block
        for serial, block in fg.blocks.items()
        if serial not in {41, 42, 43}
    }
    imported_blocks[10] = replace(
        imported_blocks[10],
        insn_snapshots=(imported_predicate,),
    )
    imported_graph = FlowGraph(
        blocks=imported_blocks,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    synthetic_transfer = replace(
        transfer,
        source_jmp_ea=imported_predicate_ea,
        materialized_anchor_eas=(imported_predicate_ea,),
    )
    assert build_materialized_conditional_handler_bridges(
        imported_graph,
        (transfer, synthetic_transfer),
        materialized_state_routes=state_routes,
        handler_entry_eas_by_serial={20: 0x40C16A, 30: 0x40AAA2},
        imported_native_eas_by_serial={10: frozenset({predicate_ea})},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=imported_predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=imported_predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{imported_predicate_ea:X}:"
                f"native_predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        ),
    ]


def test_applied_late_logical_source_owns_native_predicate_replay(
    _seam,
) -> None:
    owned_predicate_ea = 0x1290
    unrelated_predicate_ea = 0x1690

    def predicate(ea: int, taken: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=55,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (10, 40), ()),
            10: _b(10, (11, 12), (0,), (predicate(owned_predicate_ea, 12),)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
            40: _b(
                40,
                (41, 42),
                (0,),
                (predicate(unrelated_predicate_ea, 42),),
            ),
            41: _b(41, (), (40,)),
            42: _b(42, (), (40,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    true_state = 0xB13A6E93
    false_state = 0x4D34CF70

    def transfer(source: int, predicate_ea: int) -> MaterializedIndirectTransfer:
        return MaterializedIndirectTransfer(
            source_jmp_ea=predicate_ea,
            source_block_ea=flow_graph.get_block(source).start_ea,
            materialized_anchor_eas=(predicate_ea,),
            target_eas=(
                flow_graph.get_block(20).start_ea,
                flow_graph.get_block(30).start_ea,
            ),
            condition_code=5,
            true_target_ea=flow_graph.get_block(20).start_ea,
            false_target_ea=flow_graph.get_block(30).start_ea,
            resolver_kind="conditional_handler_bridge",
            predicate_size=4,
            predicate_true_state=true_state,
            predicate_false_state=false_state,
            predicate_true_is_taken=True,
            predicate_preserve_live=True,
        )

    owned_port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=flow_graph.get_block(10).start_ea,
        predicate_ea=owned_predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=flow_graph.get_block(20).start_ea,
        fallthrough_target_ea=flow_graph.get_block(30).start_ea,
        state_register=20,
        taken_state=true_state,
        fallthrough_state=false_state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="static_stack_carried_state_choice",
        logical_source_anchor_ea=0x1A00,
        predicate_ida_stkoff=0x44,
        predicate_stack_value=1,
        predicate_size=4,
        condition_code=5,
    )
    applied_evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=owned_port,
        taken_target_anchor_eas=(flow_graph.get_block(20).start_ea,),
        fallthrough_target_anchor_eas=(flow_graph.get_block(30).start_ea,),
    )
    modifications = build_materialized_conditional_handler_bridges(
        flow_graph,
        (
            transfer(10, owned_predicate_ea),
            transfer(40, unrelated_predicate_ea),
        ),
        materialized_state_routes=(
            MaterializedStateRoute(10, true_state, 20),
            MaterializedStateRoute(10, false_state, 30),
            MaterializedStateRoute(40, true_state, 20),
            MaterializedStateRoute(40, false_state, 30),
        ),
        handler_entry_eas_by_serial={
            20: flow_graph.get_block(20).start_ea,
            30: flow_graph.get_block(30).start_ea,
        },
        applied_conditional_boundary_evidence=(applied_evidence,),
    )

    assert [
        modification.rewrite_from_ea
        for modification in modifications
        if isinstance(modification, LowerConditionalStateTransition)
    ] == [unrelated_predicate_ea]


def test_emit_accepts_exact_materialized_conditional_entry_without_scalar_state(
    _seam,
    monkeypatch,
) -> None:
    """A live two-arm entry predicate is itself a complete entry bridge.

    Once PREOPT reconnects the entry predicate directly to two known handlers,
    walking from the function entry while merely removing the dispatcher also
    reaches those handlers' tails.  They must not be mistaken for unbridged
    prologue predecessors that require one scalar ``initial_state``.
    """
    predicate_ea = 0x1100
    true_state = 0xA0
    false_state = 0xB0
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=20, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (10, 20), (0,), (predicate,)),
            2: _b(2, (10, 20), (10, 20)),
            10: _b(10, (2,), (1, 2), (_mov_reg(0x1300, true_state, 20),)),
            20: _b(20, (2,), (1, 2), (_mov_reg(0x1400, false_state, 20),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({true_state: 20, false_state: 10}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=flow_graph.get_block(1).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(
            flow_graph.get_block(20).start_ea,
            flow_graph.get_block(10).start_ea,
        ),
        condition_code=5,
        true_target_ea=flow_graph.get_block(20).start_ea,
        false_target_ea=flow_graph.get_block(10).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    monkeypatch.setattr(
        emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        emit_module,
        "_recover_register_conditional_entry",
        lambda *_args, **_kwargs: [],
    )
    plan = emit_minimal_unflatten(
        flow_graph,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=20,
        dispatcher_entry_serial=2,
        initial_state=None,
        materialized_indirect_transfers=(transfer,),
        materialized_state_routes=(
            MaterializedStateRoute(1, true_state, 20),
            MaterializedStateRoute(1, false_state, 10),
        ),
        handler_entry_eas_by_serial={
            10: flow_graph.get_block(10).start_ea,
            20: flow_graph.get_block(20).start_ea,
        },
        materialized_computed_goto_profile=True,
        condition_chain_handlers=frozenset({10, 20}),
    )
    assert any(
        isinstance(modification, LowerConditionalStateTransition)
        and modification.source_serial == 1
        and modification.false_target_serial == 10
        and modification.true_target_serial == 20
        for modification in graph_modifications(plan)
    )
    redirects = {
        (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    }
    assert (10, 2, 20) in redirects
    assert (20, 2, 10) in redirects


def test_bound_bootstrap_route_is_source_scoped_entry_proof() -> None:
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,)),
            2: _b(2, (10,), (1, 10)),
            3: _b(3, (10,), (1,)),
            10: _b(10, (2,), (2, 3)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    source_ea = int(flow_graph.get_block(3).start_ea)
    handler_ea = int(flow_graph.get_block(10).start_ea)
    route = BootstrapRouteEvidence(
        source_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, source_ea + 1),), native_key=NATIVE_KEY
        ),
        source_anchor_ea=source_ea,
        state=0x699BC698,
        handler_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(handler_ea, handler_ea + 1),), native_key=NATIVE_KEY
        ),
        handler_anchor_ea=handler_ea,
        proof_kind=BootstrapRouteProofKind.STATIC_NATIVE,
    )
    binding = BootstrapRouteBindingEvidence(
        route=route,
        source_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, source_ea + 0x20),), native_key=NATIVE_KEY
        ),
        handler_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(handler_ea, handler_ea + 0x20),), native_key=NATIVE_KEY
        ),
        evidence_generation=1,
    )

    proofs = _prove_bound_bootstrap_entry_routes(
        flow_graph,
        (binding,),
        dispatcher_entry_serial=2,
    )

    assert len(proofs) == 1
    assert (
        proofs[0].source_serial,
        proofs[0].handler_serial,
        proofs[0].state,
    ) == (3, 10, 0x699BC698)


def test_materialized_computed_goto_profile_recovers_multi_entry_state_writer(
    _seam,
) -> None:
    """A proven computed-goto profile owns state writes entering BST subtrees."""
    state = 0x20
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (10,), ()),
            2: _b(2, (20,), (12, 20)),
            10: _b(10, (11,), (0,), (_mov_state(0x1010, state),)),
            11: _b(11, (12,), (10,)),
            12: _b(12, (2,), (11,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        _disp({state: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=state,
        materialized_computed_goto_profile=True,
    )

    redirects = {
        (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    }
    assert (10, 11, 20) in redirects


def test_entry_bridge_prefers_unique_materialized_state_route_over_stale_map(
    _seam,
) -> None:
    initial_state = 0x34170401
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (20,), (1, 10, 20)),
            10: _b(10, (2,), ()),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    stale_dispatcher = _disp({0xB101A588: 20}, exit_block=99)

    modifications = build_state_write_redirects(
        flow_graph,
        stale_dispatcher,
        (),
        dispatcher_entry_serial=2,
        pre_header_serial=1,
        initial_state=initial_state,
        materialized_state_routes=(MaterializedStateRoute(1, initial_state, 10),),
        condition_chain_handlers=frozenset({10, 20}),
    )

    assert modifications == [
        RedirectGoto(from_serial=1, old_target=2, new_target=10),
    ]


def test_materialized_state_entry_bridge_bypasses_proven_router_region() -> None:
    state = 0x34170401
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10,), (1, 10)),
            10: _b(10, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert build_materialized_state_entry_bridges(
        flow_graph,
        (MaterializedStateRoute(1, state, 10),),
        dispatcher_region_serials=frozenset({2}),
        authoritative_handler_serials=frozenset({10}),
    ) == [
        RedirectGoto(from_serial=1, old_target=2, new_target=10),
    ]


def test_materialized_state_entry_bridge_abstains_on_conflicting_routes() -> None:
    state = 0x34170401
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: _b(2, (10, 20), (1, 10, 20)),
            10: _b(10, (2,), (2,)),
            20: _b(20, (2,), (2,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert (
        build_materialized_state_entry_bridges(
            flow_graph,
            (
                MaterializedStateRoute(1, state, 10),
                MaterializedStateRoute(1, state, 20),
            ),
            dispatcher_region_serials=frozenset({2}),
            authoritative_handler_serials=frozenset({10, 20}),
        )
        == []
    )


def test_emit_accepts_applied_preopt_conditional_port_when_one_router_row_was_pruned(
    _seam,
    monkeypatch,
) -> None:
    predicate_ea = 0x1100
    taken_state = 0xA0
    fallthrough_state = 0xB0
    taken_target_ea = 0x1500
    fallthrough_target_ea = 0x1600
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=20, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 20), (0,), (predicate,)),
            2: _b(2, (10,), (1,)),
            3: _b(3, (10, 20), (10, 20)),
            10: _b(10, (3,), (2, 3), (_mov_reg(0x1300, taken_state, 20),)),
            20: _b(20, (3,), (1, 3), (_mov_reg(0x1400, fallthrough_state, 20),)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    # The imported arm anchor is authoritative even when CALLS pruning removed
    # one state from the equality-router map.  This is the real-loader shape:
    # the fallthrough state remains in the map while the taken state's detached
    # handler is reachable only through the applied PREOPT boundary port.
    dispatcher = IntervalDispatcher(
        [
            IntervalRow(
                lo=fallthrough_state,
                hi=fallthrough_state + 1,
                target=10,
            )
        ],
        compute_default=False,
    )
    port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x1080,
        predicate_ea=predicate_ea,
        old_taken_target_ea=0x1200,
        old_fallthrough_target_ea=0x1210,
        taken_target_ea=taken_target_ea,
        fallthrough_target_ea=fallthrough_target_ea,
        state_register=20,
        taken_state=taken_state,
        fallthrough_state=fallthrough_state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="static_fixpoint",
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=port,
        # The taken target's PREOPT instructions were all folded away before
        # CALLS; the exact applied predicate and its surviving taken arm remain.
        taken_target_anchor_eas=(0xDEAD,),
        fallthrough_target_anchor_eas=(0x1300,),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    monkeypatch.setattr(
        emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        emit_module,
        "_recover_register_conditional_entry",
        lambda *_args, **_kwargs: [],
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=20,
        dispatcher_entry_serial=3,
        initial_state=None,
        imported_conditional_boundary_evidence=(evidence,),
        handler_entry_eas_by_serial={
            10: fallthrough_target_ea,
        },
        materialized_computed_goto_profile=True,
        condition_chain_handlers=frozenset({10}),
    )

    redirects = {
        (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
        for modification in graph_modifications(plan)
        if isinstance(modification, RedirectGoto)
    }
    assert (20, 3, 10) in redirects


def test_imported_conditional_entry_prefers_native_origin_over_stale_arm_anchor() -> (
    None
):
    predicate_ea = 0x1100
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=3, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (20,), (1,)),
            3: _b(3, (30,), (1,)),
            20: _b(20, (), (2,), (_mov_reg(0xF100, 0xB0, 20),)),
            30: _b(30, (), (3,), (_mov_reg(0xF200, 0xA0, 20),)),
            # A maturity-local clone retained the old arm anchor but is not the
            # block reached by the successfully applied conditional port.
            40: _b(40, (), (), (_mov_reg(0xDEAD, 0xB0, 20),)),
            50: _b(50, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x1080,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=0x1500,
        fallthrough_target_ea=0x1600,
        state_register=20,
        taken_state=0xA0,
        fallthrough_state=0xB0,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="resolver_proven_static_conditional_state_choice",
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=port,
        taken_target_anchor_eas=(0xF200,),
        fallthrough_target_anchor_eas=(0xDEAD,),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({20, 30, 40}),
        state_var_reg=20,
        imported_native_eas_by_serial={
            20: frozenset({0x1600}),
            30: frozenset({0x1500}),
        },
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        proofs=(
            emit_module.ConditionalEntryBridgeProof(
                source_serial=1,
                predicate_ea=predicate_ea,
                false_target_serial=20,
                true_target_serial=30,
            ),
        ),
        root_source_serials=(1,),
    )


def test_imported_conditional_entry_prefers_canonical_handler_for_leaf_ea() -> None:
    predicate_ea = 0x40D299
    taken_target_ea = 0x40EFDD
    fallthrough_target_ea = 0x40D668
    predicate = InsnSnapshot(
        opcode=50,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (30,), (1,)),
            3: _b(3, (40,), (1,)),
            # PREOPT imported ownership clones reached by the applied arms.
            30: _b(30, (50,), (2,)),
            40: _b(40, (50,), (3,)),
            # Canonical equality-router handlers for the same native EAs.
            10: _b(10, (50,), (50,)),
            20: _b(20, (50,), (50,)),
            50: _b(50, (10, 20), (10, 20, 30, 40)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D252,
            predicate_ea=predicate_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=taken_target_ea,
            fallthrough_target_ea=fallthrough_target_ea,
            state_register=28,
            taken_state=0xB13A6E93,
            fallthrough_state=0x4D34CF70,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            resolver_kind="resolver_proven_static_conditional_state_choice",
        ),
        taken_target_anchor_eas=(),
        fallthrough_target_anchor_eas=(),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({10, 20}),
        state_var_reg=28,
        imported_native_eas_by_serial={
            30: frozenset({taken_target_ea}),
            40: frozenset({fallthrough_target_ea}),
        },
        handler_entry_eas_by_serial={
            10: taken_target_ea,
            20: fallthrough_target_ea,
        },
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        proofs=(
            emit_module.ConditionalEntryBridgeProof(
                source_serial=1,
                predicate_ea=predicate_ea,
                false_target_serial=20,
                true_target_serial=10,
            ),
        ),
        root_source_serials=(1,),
    )


def test_imported_conditional_entry_abstains_on_ambiguous_leaf_handler_ea() -> None:
    predicate_ea = 0x40D299
    taken_target_ea = 0x40EFDD
    fallthrough_target_ea = 0x40D668
    predicate = InsnSnapshot(
        opcode=50,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (30,), (1,)),
            3: _b(3, (40,), (1,)),
            10: _b(10, (50,), (50,)),
            11: _b(11, (50,), (50,)),
            20: _b(20, (50,), (50,)),
            30: _b(30, (50,), (2,)),
            40: _b(40, (50,), (3,)),
            50: _b(50, (10, 11, 20), (10, 11, 20, 30, 40)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D252,
            predicate_ea=predicate_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=taken_target_ea,
            fallthrough_target_ea=fallthrough_target_ea,
            state_register=28,
            taken_state=0xB13A6E93,
            fallthrough_state=0x4D34CF70,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            resolver_kind="resolver_proven_static_conditional_state_choice",
        ),
        taken_target_anchor_eas=(),
        fallthrough_target_anchor_eas=(),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    assert (
        emit_module._plan_imported_conditional_entry_bridges(
            flow_graph,
            (evidence,),
            dispatcher_entry_serial=50,
            handler_serials=frozenset({10, 11, 20}),
            state_var_reg=28,
            imported_native_eas_by_serial={
                30: frozenset({taken_target_ea}),
                40: frozenset({fallthrough_target_ea}),
            },
            handler_entry_eas_by_serial={
                10: taken_target_ea,
                11: taken_target_ea,
                20: fallthrough_target_ea,
            },
        )
        is None
    )


def test_imported_conditional_entry_routes_both_states_to_authoritative_handlers() -> (
    None
):
    predicate_ea = 0x40D266
    true_state = 0xB13A6E93
    false_state = 0x4D34CF70
    predicate = InsnSnapshot(
        opcode=50,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (40,), (1,)),
            3: _b(3, (30,), (1,)),
            # Applied PREOPT clone targets.
            30: _b(30, (50,), (3,)),
            40: _b(40, (50,), (2,)),
            # Authoritative equality-router handlers for the two states.
            10: _b(10, (50,), ()),
            20: _b(20, (50,), ()),
            50: _b(50, (10, 20), (10, 20, 30, 40)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x40D252,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        # The live jge is the inverse of the native cmovl condition.
        taken_target_ea=0x40F20B,
        fallthrough_target_ea=0x40DABB,
        state_register=28,
        taken_state=false_state,
        fallthrough_state=true_state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
        resolver_kind="resolver_proven_static_stack_carried_entry_choice",
        predicate_true_is_taken=False,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=port,
        taken_target_anchor_eas=(0xF1C02000,),
        fallthrough_target_anchor_eas=(0xF1C01000,),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({10, 20}),
        state_var_reg=28,
        materialized_state_routes=(
            MaterializedStateRoute(100, true_state, 10),
            MaterializedStateRoute(101, false_state, 20),
        ),
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        proofs=(
            emit_module.ConditionalEntryBridgeProof(
                source_serial=1,
                predicate_ea=predicate_ea,
                false_target_serial=20,
                true_target_serial=10,
                true_is_taken=False,
            ),
        ),
        root_source_serials=(1,),
    )


def test_imported_conditional_entry_binds_distinct_logical_source_owner() -> None:
    proof_predicate_ea = 0x40D221
    logical_source_ea = 0x40E9A8
    live_predicate_ea = 0xF1C02004
    true_state = 0x142718FC
    false_state = 0xF6D08EC5

    def predicate(ea: int, taken: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=50,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (4,), ()),
            # The original proof predicate remains elsewhere in the MBA.  It
            # is not the source where PREOPT applied the logical boundary.
            1: _b(1, (6, 7), (), (predicate(proof_predicate_ea, 6),)),
            4: _b(4, (2, 3), (0,), (predicate(live_predicate_ea, 2),)),
            2: _b(2, (10,), (4,)),
            3: _b(3, (20,), (4,)),
            6: _b(6, (50,), (1,)),
            7: _b(7, (50,), (1,)),
            10: _b(10, (50,), (2, 50)),
            20: _b(20, (50,), (3, 50)),
            50: _b(50, (10, 20), (6, 7, 10, 20)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D200,
            predicate_ea=proof_predicate_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=0x40F1C1,
            fallthrough_target_ea=0x40DDB0,
            state_register=28,
            taken_state=true_state,
            fallthrough_state=false_state,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            resolver_kind="resolver_proven_static_stack_carried_entry_choice",
            logical_source_anchor_ea=logical_source_ea,
            logical_source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            logical_source_replaces_dispatcher_envelope=True,
        ),
        taken_target_anchor_eas=(),
        fallthrough_target_anchor_eas=(),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({10, 20}),
        state_var_reg=28,
        imported_native_eas_by_serial={
            4: frozenset({logical_source_ea}),
        },
        materialized_state_routes=(
            MaterializedStateRoute(100, true_state, 10),
            MaterializedStateRoute(101, false_state, 20),
        ),
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        proofs=(
            emit_module.ConditionalEntryBridgeProof(
                source_serial=4,
                predicate_ea=live_predicate_ea,
                false_target_serial=20,
                true_target_serial=10,
            ),
        ),
        root_source_serials=(4,),
    )


def test_imported_conditional_entry_abstains_on_unproven_nested_boundary_sources() -> (
    None
):
    predicate_ea = 0x40D266
    false_nested_predicate_ea = 0x40D2BC
    true_nested_predicate_ea = 0x40D299
    true_state = 0xB13A6E93
    false_state = 0x4D34CF70
    predicate = InsnSnapshot(
        opcode=50,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate,)),
            2: _b(2, (20,), (1,), (_mov_reg(false_nested_predicate_ea, 1, 8),)),
            3: _b(3, (10,), (1,), (_mov_reg(true_nested_predicate_ea, 1, 8),)),
            10: _b(10, (50,), (3,)),
            20: _b(20, (50,), (2,)),
            50: _b(50, (10, 20), (10, 20)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    port = DetachedSnippetConditionalBoundaryPort(
        source_block_ea=0x40D200,
        predicate_ea=predicate_ea,
        old_taken_target_ea=None,
        old_fallthrough_target_ea=None,
        taken_target_ea=false_nested_predicate_ea,
        fallthrough_target_ea=true_nested_predicate_ea,
        state_register=28,
        taken_state=false_state,
        fallthrough_state=true_state,
        source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
        resolver_kind="resolver_proven_static_conditional_state_choice",
        predicate_true_is_taken=False,
        taken_target_is_boundary_source=True,
        fallthrough_target_is_boundary_source=True,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=port,
        taken_target_anchor_eas=(false_nested_predicate_ea,),
        fallthrough_target_anchor_eas=(true_nested_predicate_ea,),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (evidence,),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({10, 20}),
        state_var_reg=28,
        materialized_state_routes=(
            MaterializedStateRoute(100, true_state, 10),
            MaterializedStateRoute(101, false_state, 20),
        ),
    )

    assert plan is None


def test_imported_conditional_entry_plan_includes_complete_nested_tree() -> None:
    outer_ea = 0x40D266
    taken_nested_ea = 0x40D2BC
    fallthrough_nested_ea = 0x40D299
    state_reg = 28
    states = (0x10, 0x20, 0x30, 0x40)

    def predicate(ea: int, taken_serial: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=50,
            ea=ea,
            operands=(),
            d=MopSnapshot(
                t=0,
                size=0,
                block_ref=taken_serial,
                kind=OperandKind.BLOCK,
            ),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (predicate(outer_ea, 2),)),
            2: _b(2, (20, 21), (1,), (predicate(taken_nested_ea, 20),)),
            3: _b(3, (30, 31), (1,), (predicate(fallthrough_nested_ea, 30),)),
            20: _b(20, (50,), (2, 50)),
            21: _b(21, (50,), (2, 50)),
            30: _b(30, (50,), (3, 50)),
            31: _b(31, (50,), (3, 50)),
            50: _b(50, (20, 21, 30, 31), (20, 21, 30, 31)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )

    outer = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D200,
            predicate_ea=outer_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=taken_nested_ea,
            fallthrough_target_ea=fallthrough_nested_ea,
            state_register=state_reg,
            taken_state=states[0],
            fallthrough_state=states[1],
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            resolver_kind="resolver_proven_static_conditional_state_choice",
            taken_target_is_boundary_source=True,
            fallthrough_target_is_boundary_source=True,
        ),
        taken_target_anchor_eas=(taken_nested_ea,),
        fallthrough_target_anchor_eas=(fallthrough_nested_ea,),
    )

    def nested_evidence(
        predicate_ea: int,
        taken_state: int,
        fallthrough_state: int,
    ) -> AppliedDetachedSnippetConditionalBoundaryPort:
        return AppliedDetachedSnippetConditionalBoundaryPort(
            port=DetachedSnippetConditionalBoundaryPort(
                source_block_ea=predicate_ea,
                predicate_ea=predicate_ea,
                old_taken_target_ea=None,
                old_fallthrough_target_ea=None,
                taken_target_ea=0xF0000000 + taken_state,
                fallthrough_target_ea=0xF0000000 + fallthrough_state,
                state_register=state_reg,
                taken_state=taken_state,
                fallthrough_state=fallthrough_state,
                source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                resolver_kind="resolver_proven_static_conditional_state_choice",
            ),
            taken_target_anchor_eas=(),
            fallthrough_target_anchor_eas=(),
        )

    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (
            outer,
            nested_evidence(taken_nested_ea, states[0], states[1]),
            nested_evidence(fallthrough_nested_ea, states[2], states[3]),
        ),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({20, 21, 30, 31}),
        state_var_reg=state_reg,
        materialized_state_routes=(
            MaterializedStateRoute(100, states[0], 20),
            MaterializedStateRoute(101, states[1], 21),
            MaterializedStateRoute(102, states[2], 30),
            MaterializedStateRoute(103, states[3], 31),
        ),
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        proofs=(
            emit_module.ConditionalEntryBridgeProof(1, outer_ea, 3, 2),
            emit_module.ConditionalEntryBridgeProof(2, taken_nested_ea, 21, 20),
            emit_module.ConditionalEntryBridgeProof(
                3,
                fallthrough_nested_ea,
                31,
                30,
            ),
        ),
        root_source_serials=(1,),
    )
    lowerings = emit_module._lower_conditional_entry_bridge_plan(
        flow_graph,
        plan,
    )
    assert tuple(lowering.source_serial for lowering in lowerings) == (1, 2, 3)


def test_imported_conditional_entry_plan_abstains_on_missing_nested_source() -> None:
    outer_ea = 0x40D266
    nested_ea = 0x40D2BC
    predicate = InsnSnapshot(
        opcode=50,
        ea=outer_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=2, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 20), (0,), (predicate,)),
            2: _b(2, (20,), (1,), (_mov_reg(nested_ea, 1, 8),)),
            20: _b(20, (50,), (1, 2, 50)),
            50: _b(50, (20,), (20,)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )
    evidence = AppliedDetachedSnippetConditionalBoundaryPort(
        port=DetachedSnippetConditionalBoundaryPort(
            source_block_ea=0x40D200,
            predicate_ea=outer_ea,
            old_taken_target_ea=None,
            old_fallthrough_target_ea=None,
            taken_target_ea=nested_ea,
            fallthrough_target_ea=0x40D400,
            state_register=28,
            taken_state=0x10,
            fallthrough_state=0x20,
            source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            taken_target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
            fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
            resolver_kind="resolver_proven_static_conditional_state_choice",
            taken_target_is_boundary_source=True,
        ),
        taken_target_anchor_eas=(nested_ea,),
        fallthrough_target_anchor_eas=(),
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    assert (
        emit_module._plan_imported_conditional_entry_bridges(
            flow_graph,
            (evidence,),
            dispatcher_entry_serial=50,
            handler_serials=frozenset({20}),
            state_var_reg=28,
            materialized_state_routes=(MaterializedStateRoute(100, 0x20, 20),),
        )
        is None
    )


def test_imported_conditional_entry_plan_ignores_handler_local_ambiguity() -> None:
    entry_ea = 0x40D266
    handler_ea = 0x40D4A2
    state_reg = 28

    def predicate(ea: int, target: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=50,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=target, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (20, 21), (0,), (predicate(entry_ea, 20),)),
            20: _b(20, (21, 50), (1, 50), (predicate(handler_ea, 21),)),
            21: _b(21, (50,), (1, 20, 50)),
            50: _b(50, (20, 21), (20, 21)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )

    def evidence(
        predicate_ea: int,
        taken_state: int,
        fallthrough_state: int,
    ) -> AppliedDetachedSnippetConditionalBoundaryPort:
        return AppliedDetachedSnippetConditionalBoundaryPort(
            port=DetachedSnippetConditionalBoundaryPort(
                source_block_ea=predicate_ea,
                predicate_ea=predicate_ea,
                old_taken_target_ea=None,
                old_fallthrough_target_ea=None,
                taken_target_ea=0xF0000000 + taken_state,
                fallthrough_target_ea=0xF0000000 + fallthrough_state,
                state_register=state_reg,
                taken_state=taken_state,
                fallthrough_state=fallthrough_state,
                source_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                resolver_kind="resolver_proven_static_conditional_state_choice",
            ),
            taken_target_anchor_eas=(),
            fallthrough_target_anchor_eas=(),
        )

    from d810.transforms import minimal_unflatten_emit as emit_module

    plan = emit_module._plan_imported_conditional_entry_bridges(
        flow_graph,
        (
            evidence(entry_ea, 0x10, 0x20),
            evidence(handler_ea, 0x20, 0x10),
            evidence(handler_ea, 0x30, 0x40),
        ),
        dispatcher_entry_serial=50,
        handler_serials=frozenset({20, 21}),
        state_var_reg=state_reg,
        materialized_state_routes=(
            MaterializedStateRoute(100, 0x10, 20),
            MaterializedStateRoute(101, 0x20, 21),
            MaterializedStateRoute(102, 0x30, 20),
            MaterializedStateRoute(103, 0x40, 21),
        ),
    )

    assert plan == emit_module.ConditionalEntryBridgePlan(
        proofs=(emit_module.ConditionalEntryBridgeProof(1, entry_ea, 21, 20),),
        root_source_serials=(1,),
    )


def test_emit_does_not_accept_handler_local_conditional_as_entry_bridge(
    _seam,
    monkeypatch,
) -> None:
    predicate_ea = 0x1280
    true_state = 0xA0
    false_state = 0xB0
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=30, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (10,), ()),
            2: _b(2, (10, 20, 30), (20, 30)),
            10: _b(10, (20, 30), (0, 2), (predicate,)),
            20: _b(20, (2,), (10, 2)),
            30: _b(30, (2,), (10, 2)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({true_state: 30, false_state: 20}, exit_block=99)
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=flow_graph.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(
            flow_graph.get_block(30).start_ea,
            flow_graph.get_block(20).start_ea,
        ),
        condition_code=5,
        true_target_ea=flow_graph.get_block(30).start_ea,
        false_target_ea=flow_graph.get_block(20).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    from d810.transforms import minimal_unflatten_emit as emit_module

    monkeypatch.setattr(
        emit_module,
        "_recover_initial_state",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        emit_module,
        "_recover_register_conditional_entry",
        lambda *_args, **_kwargs: [],
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        dispatcher,
        state_var_stkoff=None,
        state_var_reg=20,
        dispatcher_entry_serial=2,
        initial_state=None,
        materialized_indirect_transfers=(transfer,),
        materialized_state_routes=(
            MaterializedStateRoute(10, true_state, 30),
            MaterializedStateRoute(10, false_state, 20),
        ),
        handler_entry_eas_by_serial={
            20: flow_graph.get_block(20).start_ea,
            30: flow_graph.get_block(30).start_ea,
        },
        materialized_computed_goto_profile=True,
        condition_chain_handlers=frozenset({10, 20, 30}),
    )

    assert not graph_modifications(plan)


def test_live_predicate_keeps_exact_arm_when_state_route_precedes_it(
    _seam,
) -> None:
    predicate_ea = 0x1290
    true_state = 0x304E8694
    false_state = 0xA5A94B86
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), (), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), (21,)),
            21: _b(21, (20,), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(
            fg.get_block(20).start_ea,
            fg.get_block(30).start_ea,
        ),
        condition_code=5,
        true_target_ea=fg.get_block(20).start_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        materialized_state_routes=(
            MaterializedStateRoute(12, true_state, 21),
            MaterializedStateRoute(11, false_state, 30),
        ),
        handler_entry_eas_by_serial={
            21: fg.get_block(20).start_ea,
            30: fg.get_block(30).start_ea,
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_uses_native_anchored_dispatcher_targets(_seam) -> None:
    """Canonical dispatcher rows can prove both arms without source routes."""
    predicate_ea = 0xF1C000B8
    true_state = 0x5C46FC3C
    false_state = 0x3EEFBA76
    true_target_ea = 0x40CF38
    false_target_ea = 0x40CF01
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            10: _b(10, (11, 12), (), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    dispatcher = _disp(
        {true_state: 20, false_state: 30},
        exit_block=99,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=flow_graph.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        flow_graph,
        (transfer,),
        dispatcher=dispatcher,
        handler_entry_eas_by_serial={
            20: true_target_ea,
            30: false_target_ea,
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{flow_graph.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_resolves_imported_source_by_native_origin(_seam) -> None:
    native_predicate_ea = 0x40F651
    imported_predicate_ea = 0xF1C01234
    true_state = 0x53514884
    false_state = 0xF940AB9D
    true_target_ea = 0x40F453
    false_target_ea = 0x40E3F0
    predicate = InsnSnapshot(
        opcode=55,
        ea=imported_predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(11, 12),
                preds=(9,),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(predicate,),
            ),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            13: BlockSnapshot(
                serial=13,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40D200,
                insn_snapshots=(InsnSnapshot(opcode=4, ea=0xF1C05678, operands=()),),
            ),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40D200,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=native_predicate_ea,
        source_block_ea=0x40D200,
        materialized_anchor_eas=(native_predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        flow_graph,
        (transfer,),
        dispatcher=_disp({}, exit_block=99),
        handler_entry_eas_by_serial={
            20: true_target_ea,
            30: false_target_ea,
        },
        imported_native_eas_by_serial={
            10: frozenset({native_predicate_ea}),
            13: frozenset({0x40F700}),
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=imported_predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=imported_predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                "source_ea=0x40D200:"
                f"predicate_ea=0x{imported_predicate_ea:X}:"
                f"native_predicate_ea=0x{native_predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_resolves_duplicate_imports_by_native_handler_entry(
    _seam,
) -> None:
    native_source_entry_ea = 0x40B199
    native_predicate_ea = 0x40B1B0
    imported_predicate_ea = 0xF1C00A74
    shadow_predicate_ea = 0xF1C10A74
    true_state = 0x65203D55
    false_state = 0x4DFFC906
    true_target_ea = 0x40A868
    false_target_ea = 0x40A9AE

    def predicate(ea: int, taken: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=55,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(11, 12),
                preds=(9,),
                flags=0,
                start_ea=0x40A560,
                insn_snapshots=(predicate(imported_predicate_ea, 12),),
            ),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            13: BlockSnapshot(
                serial=13,
                block_type=0,
                succs=(14, 15),
                preds=(),
                flags=0,
                start_ea=0x40A560,
                insn_snapshots=(predicate(shadow_predicate_ea, 15),),
            ),
            14: _b(14, (), (13,)),
            15: _b(15, (), (13,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=native_predicate_ea,
        source_block_ea=native_source_entry_ea,
        materialized_anchor_eas=(native_predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=5,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_compare_constant=0x40,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        flow_graph,
        (transfer,),
        dispatcher=_disp({true_state: 20, false_state: 30}, exit_block=99),
        handler_entry_eas_by_serial={
            10: native_source_entry_ea,
            20: true_target_ea,
            30: false_target_ea,
        },
        imported_native_eas_by_serial={
            10: frozenset({native_predicate_ea}),
            13: frozenset({native_predicate_ea}),
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=imported_predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=imported_predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                "source_ea=0x40A560:"
                f"predicate_ea=0x{imported_predicate_ea:X}:"
                f"native_predicate_ea=0x{native_predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_prefers_authoritative_imported_handler_over_native_clone(
    _seam,
) -> None:
    native_source_entry_ea = 0x40B03E
    native_predecessor_ea = 0x40B04A
    native_predicate_ea = 0x40B053
    imported_predicate_ea = 0xF1C008E4
    true_state = 0x456A4274
    false_state = 0xF32B2D3A
    true_target_ea = 0x40B199
    false_target_ea = 0x40BF1B

    def predicate(ea: int, taken: int) -> InsnSnapshot:
        return InsnSnapshot(
            opcode=55,
            ea=ea,
            operands=(),
            d=MopSnapshot(t=0, size=0, block_ref=taken, kind=OperandKind.BLOCK),
            kind=InsnKind.COND_JUMP,
            is_conditional_jump=True,
        )

    flow_graph = FlowGraph(
        blocks={
            9: BlockSnapshot(
                serial=9,
                block_type=0,
                succs=(11, 12),
                preds=(8,),
                flags=0,
                start_ea=0x40B032,
                insn_snapshots=(predicate(native_predicate_ea, 12),),
            ),
            10: BlockSnapshot(
                serial=10,
                block_type=0,
                succs=(13, 14),
                preds=(7,),
                flags=0,
                start_ea=0x40A560,
                insn_snapshots=(predicate(imported_predicate_ea, 14),),
            ),
            11: _b(11, (), (9,)),
            12: _b(12, (), (9,)),
            13: _b(13, (), (10,)),
            14: _b(14, (), (10,)),
            20: _b(20, (), ()),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=native_predicate_ea,
        source_block_ea=native_source_entry_ea,
        materialized_anchor_eas=(native_predicate_ea,),
        target_eas=(true_target_ea, false_target_ea),
        condition_code=13,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        resolver_kind="static_conditional_state_choice_bridge",
        predicate_predecessor_ea=native_predecessor_ea,
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        flow_graph,
        (transfer,),
        dispatcher=_disp({true_state: 20, false_state: 30}, exit_block=99),
        handler_entry_eas_by_serial={
            10: native_source_entry_ea,
            20: true_target_ea,
            30: false_target_ea,
        },
        imported_native_eas_by_serial={
            10: frozenset({native_predecessor_ea, native_predicate_ea}),
        },
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=14,
            rewrite_from_ea=imported_predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=imported_predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                "source_ea=0x40A560:"
                f"predicate_ea=0x{imported_predicate_ea:X}:"
                f"native_predicate_ea=0x{native_predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_live_predicate_abstains_when_state_route_does_not_match_exact_arm_ea(
    _seam,
) -> None:
    predicate_ea = 0x40B2B1
    true_state = 0xA5540595
    false_state = 0xDEF4B7E6
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), (), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            30: BlockSnapshot(
                serial=30,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40BC21,
                insn_snapshots=(),
            ),
            40: BlockSnapshot(
                serial=40,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40BFB2,
                insn_snapshots=(),
            ),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40C4F6, 0x40BC21),
        condition_code=5,
        true_target_ea=0x40C4F6,
        false_target_ea=0x40BC21,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert (
        build_materialized_conditional_handler_bridges(
            fg,
            (transfer,),
            materialized_state_routes=(
                MaterializedStateRoute(12, true_state, 40),
                MaterializedStateRoute(11, false_state, 30),
            ),
        )
        == []
    )


def test_live_predicate_accepts_exact_arm_corridor_into_mapped_handler(
    _seam,
) -> None:
    predicate_ea = 0xF1C01534
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    native_true_leaf = BlockSnapshot(
        serial=50,
        block_type=1,
        succs=(11,),
        preds=(),
        flags=0,
        start_ea=0x40B3F3,
        insn_snapshots=(
            InsnSnapshot(
                opcode=4,
                ea=0x40B40C,
                operands=(),
                kind=InsnKind.MOV,
            ),
        ),
    )
    imported_true_handler = BlockSnapshot(
        serial=20,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x40A560,
        insn_snapshots=(),
    )
    false_handler = BlockSnapshot(
        serial=30,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=0x40C1A0,
        insn_snapshots=(),
    )
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), (), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: imported_true_handler,
            30: false_handler,
            50: native_true_leaf,
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40B3F3, 0x40C1A0),
        condition_code=5,
        true_target_ea=0x40B3F3,
        false_target_ea=0x40C1A0,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        materialized_state_routes=(
            MaterializedStateRoute(12, true_state, 20),
            MaterializedStateRoute(11, false_state, 30),
        ),
        handler_entry_eas_by_serial={20: 0x40B3FF, 30: 0x40C1A0},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=12,
            rewrite_from_ea=predicate_ea,
            condition_operand=PreserveLivePredicateCondition(
                predicate_ea=predicate_ea,
                true_is_taken=True,
            ),
            false_target_serial=30,
            true_target_serial=20,
            proof_id=(
                "conditional_handler_bridge:"
                f"source_ea=0x{fg.get_block(10).start_ea:X}:"
                f"predicate_ea=0x{predicate_ea:X}"
            ),
            reason="resolver_proven_live_conditional_handler_bridge",
        )
    ]


def test_materialized_conditional_handler_bridge_prefers_source_keyed_replacement(
    _seam,
) -> None:
    predicate_ea = 0x40C5D1
    true_state = 0x78BAC34B
    false_state = 0x1F0B7687
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            9: _b(9, (10,), ()),
            10: _b(10, (11, 12), (9,), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40A7AE,
                insn_snapshots=(),
            ),
            30: _b(30, (), ()),
            40: _b(40, (), ()),
        },
        entry_serial=9,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(fg.get_block(40).start_ea, 0x40A7AE),
        condition_code=5,
        true_target_ea=fg.get_block(40).start_ea,
        false_target_ea=0x40A7AE,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    dispatcher = _disp({true_state: 40, false_state: 20}, exit_block=99)

    (modification,) = build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        dispatcher=dispatcher,
        materialized_state_routes=(
            MaterializedStateRoute(11, false_state, 30, proof_kind="conditional_arm"),
            MaterializedStateRoute(12, true_state, 40, proof_kind="conditional_arm"),
        ),
        handler_entry_eas_by_serial={30: 0x40A7AE},
    )

    assert modification.false_target_serial == 30
    assert modification.true_target_serial == 40


def test_materialized_conditional_handler_bridge_maps_folded_target_prefix(
    _seam,
) -> None:
    predicate_ea = 0xF1C015DC
    true_state = 0xBC6EC36C
    false_state = 0x67B7A2BD
    false_handler_entry = 0x40ED00
    false_target_ea = 0x40ED0C
    next_handler_entry = 0x40EE00
    predicate = InsnSnapshot(
        opcode=55,
        ea=predicate_ea,
        operands=(),
        d=MopSnapshot(t=0, size=0, block_ref=12, kind=OperandKind.BLOCK),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    false_handler = BlockSnapshot(
        serial=30,
        block_type=0,
        succs=(),
        preds=(),
        flags=0,
        start_ea=false_handler_entry,
        insn_snapshots=(
            InsnSnapshot(opcode=4, ea=0x40ED14, operands=()),
            InsnSnapshot(opcode=55, ea=0x40ED65, operands=()),
        ),
    )
    fg = FlowGraph(
        blocks={
            9: _b(9, (10,), ()),
            10: _b(10, (11, 12), (9,), (predicate,)),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            30: false_handler,
            31: BlockSnapshot(
                serial=31,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=next_handler_entry,
                insn_snapshots=(),
            ),
            40: _b(40, (), ()),
        },
        entry_serial=9,
        func_ea=0x40D200,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(fg.get_block(40).start_ea, false_target_ea),
        condition_code=5,
        true_target_ea=fg.get_block(40).start_ea,
        false_target_ea=false_target_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_size=4,
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )
    dispatcher = _disp({true_state: 40, false_state: 30}, exit_block=99)

    (modification,) = build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        dispatcher=dispatcher,
        materialized_state_routes=(
            MaterializedStateRoute(11, false_state, 30, proof_kind="conditional_arm"),
            MaterializedStateRoute(12, true_state, 40, proof_kind="conditional_arm"),
        ),
        # The exact live route can be outside the recovered handler registry;
        # its current block provenance must still prove the folded prefix.
        handler_entry_eas_by_serial={31: next_handler_entry},
    )

    assert modification.false_target_serial == 30
    assert modification.true_target_serial == 40

    # A route's recovered handler entry can be the only later registry label.
    # The exact branch target may still be folded between that entry and the
    # route's first surviving instruction.  The route-local bounded interval
    # must remain authoritative instead of requiring an unrelated next
    # handler entry to bound the lookup.
    (modification,) = build_materialized_conditional_handler_bridges(
        fg,
        (transfer,),
        dispatcher=dispatcher,
        materialized_state_routes=(
            MaterializedStateRoute(11, false_state, 30, proof_kind="conditional_arm"),
            MaterializedStateRoute(12, true_state, 40, proof_kind="conditional_arm"),
        ),
        handler_entry_eas_by_serial={30: false_handler_entry},
    )

    assert modification.false_target_serial == 30
    assert modification.true_target_serial == 40

    imported_shadow_serial = 32
    blocks_with_shadow = dict(fg.blocks)
    blocks_with_shadow[30] = replace(false_handler, preds=(9,))
    blocks_with_shadow[imported_shadow_serial] = replace(
        false_handler,
        serial=imported_shadow_serial,
        start_ea=fg.func_ea,
    )
    graph_with_shadow = FlowGraph(
        blocks=blocks_with_shadow,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    route_args = {
        "dispatcher": dispatcher,
        "materialized_state_routes": (
            MaterializedStateRoute(11, false_state, 30, proof_kind="conditional_arm"),
            MaterializedStateRoute(12, true_state, 40, proof_kind="conditional_arm"),
        ),
        "handler_entry_eas_by_serial": {30: false_handler_entry},
    }
    assert (
        build_materialized_conditional_handler_bridges(
            graph_with_shadow,
            (transfer,),
            **route_args,
        )
        == []
    )
    (modification,) = build_materialized_conditional_handler_bridges(
        graph_with_shadow,
        (transfer,),
        imported_native_eas_by_serial={
            30: frozenset({0x40ED14, 0x40ED65}),
            imported_shadow_serial: frozenset({0x40ED14, 0x40ED65}),
        },
        **route_args,
    )

    assert modification.false_target_serial == 30
    assert modification.true_target_serial == 40


def test_degenerate_branch_redirect_becomes_goto(_seam) -> None:
    fg = FlowGraph(
        blocks={
            188: _b(188, (189, 232), ()),
            189: _b(189, (), (188,)),
            232: _b(232, (), (188,)),
        },
        entry_serial=188,
        func_ea=0x1000,
    )

    assert _normalize_degenerate_branch_redirects(
        fg,
        [RedirectBranch(from_serial=188, old_target=232, new_target=189)],
    ) == [ConvertToGoto(block_serial=188, goto_target=189)]


def test_materialized_conditional_handler_bridge_abstains_on_ambiguous_target(
    _seam,
) -> None:
    predicate_ea = 0x1290
    predicate = InsnSnapshot(opcode=55, ea=predicate_ea, operands=())
    duplicate_ea = 0x2000
    fg = FlowGraph(
        blocks={
            8: _b(8, (), (10,)),
            10: _b(10, (8,), (), (predicate,)),
            20: BlockSnapshot(
                serial=20,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=duplicate_ea,
                insn_snapshots=(),
            ),
            21: BlockSnapshot(
                serial=21,
                block_type=0,
                succs=(),
                preds=(),
                flags=0,
                start_ea=duplicate_ea,
                insn_snapshots=(),
            ),
            30: _b(30, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=fg.get_block(10).start_ea,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(duplicate_ea, fg.get_block(30).start_ea),
        condition_code=5,
        true_target_ea=duplicate_ea,
        false_target_ea=fg.get_block(30).start_ea,
        resolver_kind="conditional_handler_bridge",
        predicate_register=44,
        predicate_size=4,
        predicate_predecessor_ea=0x1288,
    )

    assert build_materialized_conditional_handler_bridges(fg, (transfer,)) == []


def test_source_keyed_handler_owner_leaves_recognized_conditional_arm_alone(
    _seam,
) -> None:
    fg = FlowGraph(
        blocks={
            10: _b(10, (11, 12), ()),
            11: _b(11, (), (10,)),
            12: _b(12, (), (10,)),
            20: _b(20, (), ()),
        },
        entry_serial=10,
        func_ea=0x1000,
    )
    handler = HandlerTransition(
        handler=10,
        states=(0x10,),
        arms=(
            TransitionArm(
                0x20,
                20,
                False,
                10,
                12,
                12,
                (10, 12),
                source_keyed_block=10,
            ),
        ),
    )

    assert build_source_keyed_handler_redirects(fg, (handler,)) == []


def test_register_conditional_entry_bridges_leaf_arms(_seam) -> None:
    """d81-3rja step 1: the prologue selects the initial state in a NON-state
    REGISTER (the Rhadamanthys ``sub_40A560`` ``ecx = a2 ? S_a : S_b``) while the
    state var itself carries a decoy. Both leaf-valued arms must bridge past the
    dispatcher to their handlers -- even though the dispatcher compares a DIFFERENT
    variable -- because the conditional's register values still route through the
    dispatcher's leaves.

        0 -> 1(reg99=0x10; branch) -> {3 (a2!=0), 2 (a2==0: reg99=0x20)}
        2 -> 3(merge: state=decoy) -> 4(dispatcher over the state var)
        route(0x10)=21, route(0x20)=22

    Enabled by ``state_var_reg`` (the register path); the walk-back finds merge=3
    and folds each arm's register to a leaf.
    """
    REG = 99
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1, (2, 3), (0,), (_mov_reg(0x1100, 0x10, REG),)
            ),  # reg99=0x10; a2!=0 -> 3, a2==0 -> 2
            2: _b(
                2, (3,), (1,), (_mov_reg(0x1200, 0x20, REG),)
            ),  # a2==0 arm: reg99=0x20
            3: _b(
                3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)
            ),  # merge: decoy state -> dispatcher
            4: _b(4, (21, 22), (3, 21, 22)),  # dispatcher (over the state var)
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=4
    )
    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=REG,
    )
    edges = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges, f"a2!=0 arm not bridged to its handler: {sorted(edges)}"
    assert (2, 3, 22) in edges, f"a2==0 arm not bridged to its handler: {sorted(edges)}"


def test_exact_entry_bridge_suppresses_generic_register_entry_scan(_seam) -> None:
    """An already-proven exact entry route owns entry-path mutation."""
    state_reg = 99
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, 0x10, state_reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, 0x20, state_reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        flow_graph,
        dispatcher,
        _STATE,
        dispatcher_entry_serial=4,
    )

    modifications = build_state_write_redirects(
        flow_graph,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=state_reg,
        exact_entry_bridge_present=True,
    )

    entry_edges = {
        (
            modification.from_serial,
            modification.old_target,
            modification.new_target,
        )
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
        and modification.from_serial in {1, 2, 3}
    }
    assert entry_edges == set()


def test_stack_carried_state_selector_lowers_at_handler_consumer(_seam) -> None:
    state_reg = 28
    carrier_reg = 7
    carrier_stkoff = 0x54
    first_state = 0x4D34CF70
    second_state = 0xB13A6E93
    predicate_ea = 0x40D266
    consumer_ea = 0x40EAA7
    router_ea = 0x40EAB1
    consumer_tail = InsnSnapshot(
        opcode=0x33,
        ea=router_ea,
        operands=(),
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stkoff=carrier_stkoff,
            kind=OperandKind.STACK,
        ),
        r=MopSnapshot(
            t=_T_NUM,
            size=4,
            value=0x10B85E45,
            kind=OperandKind.NUMBER,
        ),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            0: _b(
                0,
                (1, 2),
                (),
                (
                    _mov_reg(predicate_ea - 5, first_state, carrier_reg),
                    InsnSnapshot(
                        opcode=0x33,
                        ea=predicate_ea,
                        operands=(),
                        kind=InsnKind.COND_JUMP,
                        is_conditional_jump=True,
                    ),
                ),
            ),
            1: _b(
                1,
                (2,),
                (0,),
                (_mov_reg(predicate_ea, second_state, carrier_reg),),
            ),
            2: _b(
                2,
                (3,),
                (0, 1),
                (_mov_stack_from_reg(predicate_ea + 3, carrier_stkoff, carrier_reg),),
            ),
            3: _b(3, (4, 5), (2,)),
            4: _b(4, (21,), (3, 10)),
            5: _b(5, (22,), (3, 6)),
            6: _b(
                6,
                (5,),
                (10,),
                (
                    InsnSnapshot(
                        opcode=0x40,
                        ea=router_ea + 6,
                        operands=(),
                        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=5),
                        kind=InsnKind.GOTO,
                        is_unconditional_jump=True,
                    ),
                ),
            ),
            10: _b(
                10,
                (4, 6),
                (21,),
                (
                    _mov_reg_from_stack(consumer_ea, state_reg, carrier_stkoff),
                    consumer_tail,
                ),
            ),
            21: _b(21, (10,), (4,)),
            22: _b(22, (10,), (5,)),
        },
        entry_serial=0,
        func_ea=0x40D200,
    )

    expected = [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=4,
            rewrite_from_ea=router_ea,
            condition_operand=SyntheticStackValueEqualsCondition(
                stack_stkoff=carrier_stkoff,
                stack_size=8,
                value=first_state,
            ),
            false_target_serial=22,
            true_target_serial=21,
            proof_id=(
                "stack_carried_state_selector:source_ea=0x1280:store_ea=0x40D269"
            ),
            reason="resolver_proven_stack_carried_state_selector",
        )
    ]
    dispatcher = _disp({first_state: 21, second_state: 22}, exit_block=99)

    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == expected
    )

    # A PREOPT-imported handler can carry a detached-MBA stack offset that does
    # not match the connected prologue store.  Stable native store/load EAs plus
    # the top-level MBA's converted offset must recover the same two-arm route
    # without requiring the producer diamond to survive in this snapshot.
    detached_stkoff = 0xDC
    detached_blocks = {
        serial: block for serial, block in fg.blocks.items() if serial not in {0, 1, 2}
    }
    detached_blocks[10] = _b(
        10,
        (4, 6),
        (21,),
        (
            _mov_reg_from_stack(0xF0000010, state_reg, detached_stkoff),
            replace(
                consumer_tail,
                l=MopSnapshot(
                    t=_T_STK,
                    size=4,
                    stkoff=detached_stkoff,
                    kind=OperandKind.STACK,
                ),
            ),
        ),
    )
    detached_graph = FlowGraph(
        blocks=detached_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    portable_choice = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40D252,
        materialized_anchor_eas=(0x40D256, predicate_ea, predicate_ea + 3),
        target_eas=(0x2100, 0x2200),
        condition_code=12,
        true_target_ea=0x2100,
        false_target_ea=0x2200,
        selector_state_var_reg=state_reg,
        resolver_kind="static_stack_carried_state_choice",
        predicate_register=20,
        predicate_size=4,
        predicate_compare_constant=0x113,
        predicate_true_state=first_state,
        predicate_false_state=second_state,
        state_carrier_store_ea=predicate_ea + 3,
        state_carrier_stack_displacement=0x44,
        state_carrier_consumer_load_eas=(consumer_ea,),
        state_carrier_ida_stkoff=84,
    )
    portable_expected = [
        replace(
            expected[0],
            condition_operand=replace(
                expected[0].condition_operand,
                stack_stkoff=carrier_stkoff,
                stack_size=4,
            ),
            proof_id=(
                "stack_carried_state_selector_native:"
                "source_ea=0x1280:store_ea=0x40D269:load_ea=0x40EAA7"
            ),
            reason="resolver_proven_native_stack_carried_state_selector",
        )
    ]
    assert (
        build_stack_carried_state_selector_lowerings(
            detached_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == portable_expected
    )

    # Later maturities can coalesce the stack reload into a register alias
    # before copying it to the state register.  The native store/load identity
    # still owns the selector and supplies the current VD stack offset.
    coalesced_blocks = dict(detached_graph.blocks)
    coalesced_blocks[10] = _b(
        10,
        (4, 6),
        (21,),
        (
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=0xF1C00180,
                operands=(),
                l=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=8,
                    kind=OperandKind.REGISTER,
                ),
                d=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=state_reg,
                    kind=OperandKind.REGISTER,
                ),
                kind=InsnKind.MOV,
            ),
            replace(
                consumer_tail,
                ea=0xF1C0019C,
                l=MopSnapshot(kind=OperandKind.SUBINSN),
                r=None,
            ),
        ),
    )
    coalesced_graph = FlowGraph(
        blocks=coalesced_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    assert build_stack_carried_state_selector_lowerings(
        coalesced_graph,
        dispatcher,
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({3, 4, 5}),
        handler_serials=frozenset({10, 21, 22}),
        materialized_indirect_transfers=(portable_choice,),
        handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
        state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
        native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
    ) == [
        replace(
            portable_expected[0],
            rewrite_from_ea=0xF1C0019C,
        )
    ]

    # PREOPT can lower the terminal computed jump to an exact conditional
    # after importing the native pointer-selection envelope.  The original
    # stack selector then has two pure arms which converge on that applied
    # resolver-cut predicate instead of entering the router directly.  The
    # applied receipt plus both exact router arms must authorize bypassing the
    # redundant envelope; topology alone must not.
    cut_predicate_ea = 0x40EABA
    taken_anchor_ea = 0xF1C02028
    fallthrough_anchor_ea = 0xF1C0202C
    envelope_blocks = dict(detached_graph.blocks)
    envelope_blocks[10] = _b(
        10,
        (11, 12),
        (21,),
        (
            _mov_reg_from_stack(0xF1C02004, state_reg, detached_stkoff),
            replace(
                consumer_tail,
                ea=0xF1C02020,
                l=MopSnapshot(kind=OperandKind.SUBINSN),
                r=None,
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=12),
            ),
        ),
    )
    envelope_blocks[11] = _b(
        11,
        (12,),
        (10,),
        (
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=0xF1C02024,
                operands=(),
                l=MopSnapshot(kind=OperandKind.GLOBAL, value=0x48BB98),
                d=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=8,
                    kind=OperandKind.REGISTER,
                ),
                kind=InsnKind.MOV,
            ),
        ),
    )
    envelope_blocks[12] = _b(
        12,
        (4, 5),
        (10, 11),
        (
            replace(
                consumer_tail,
                ea=cut_predicate_ea,
                d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
            ),
        ),
    )
    envelope_blocks[4] = _b(
        4,
        (21,),
        (12,),
        (InsnSnapshot(opcode=0, ea=taken_anchor_ea, operands=(), kind=InsnKind.NOP),),
    )
    envelope_blocks[5] = _b(
        5,
        (22,),
        (12,),
        (
            InsnSnapshot(
                opcode=0,
                ea=fallthrough_anchor_ea,
                operands=(),
                kind=InsnKind.NOP,
            ),
        ),
    )
    envelope_graph = FlowGraph(
        blocks=envelope_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    resolver_cut_conditional_evidence = (
        AppliedDetachedSnippetConditionalBoundaryPort(
            port=DetachedSnippetConditionalBoundaryPort(
                source_block_ea=consumer_ea,
                predicate_ea=cut_predicate_ea,
                old_taken_target_ea=None,
                old_fallthrough_target_ea=None,
                taken_target_ea=0x2100,
                fallthrough_target_ea=0x2200,
                state_register=None,
                taken_state=None,
                fallthrough_state=None,
                source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                taken_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                fallthrough_target_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                resolver_kind="resolver_proven_register_compare_cut",
            ),
            taken_target_anchor_eas=(taken_anchor_ea,),
            fallthrough_target_anchor_eas=(fallthrough_anchor_ea,),
        ),
    )
    envelope_expected = [
        replace(
            portable_expected[0],
            old_dispatcher_serial=11,
            rewrite_from_ea=0xF1C02020,
        )
    ]
    assert (
        build_stack_carried_state_selector_lowerings(
            envelope_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == []
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            envelope_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            imported_conditional_boundary_evidence=(resolver_cut_conditional_evidence),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == envelope_expected
    )

    side_effect_blocks = dict(envelope_blocks)
    side_effect_blocks[11] = _b(
        11,
        (12,),
        (10,),
        (
            InsnSnapshot(
                opcode=0x7F,
                ea=0xF1C02024,
                operands=(),
                l=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=8,
                    kind=OperandKind.REGISTER,
                ),
                d=MopSnapshot(
                    t=_T_STK,
                    size=4,
                    stkoff=carrier_stkoff + 8,
                    kind=OperandKind.STACK,
                ),
                kind=InsnKind.STORE,
            ),
        ),
    )
    side_effect_graph = FlowGraph(
        blocks=side_effect_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            side_effect_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            imported_conditional_boundary_evidence=(resolver_cut_conditional_evidence),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == []
    )

    # Resolver-proven imported handlers must not replace a still-live
    # dispatcher frontier while the choice itself is owned by a detached
    # native consumer.  Connecting those imported regions before the carrier
    # has folded into a live source can expose their synthetic router sink.
    native_stale_leaf_serial = 20
    native_stale_blocks = dict(detached_graph.blocks)
    native_stale_blocks[native_stale_leaf_serial] = _b(
        native_stale_leaf_serial,
        (4,),
        (4,),
    )
    native_stale_graph = FlowGraph(
        blocks=native_stale_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    exact_first_target = MaterializedIndirectTransfer(
        source_jmp_ea=0x2110,
        source_block_ea=0x2100,
        materialized_anchor_eas=(),
        target_eas=(0x2100,),
        selector_state_var_reg=state_reg,
        selector_state_constant=first_state,
        resolver_kind="static_equality_candidate",
    )
    exact_second_target = MaterializedIndirectTransfer(
        source_jmp_ea=0x2210,
        source_block_ea=0x2200,
        materialized_anchor_eas=(),
        target_eas=(0x2200,),
        selector_state_var_reg=state_reg,
        selector_state_constant=second_state,
        resolver_kind="static_equality_candidate",
    )
    assert build_stack_carried_state_selector_lowerings(
        native_stale_graph,
        _disp(
            {first_state: native_stale_leaf_serial, second_state: 22},
            exit_block=99,
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({3, 4, 5}),
        handler_serials=frozenset({10, native_stale_leaf_serial, 21, 22}),
        materialized_indirect_transfers=(
            portable_choice,
            exact_first_target,
            exact_second_target,
        ),
        handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
        state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
        native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
    ) == [
        replace(
            portable_expected[0],
            true_target_serial=native_stale_leaf_serial,
        )
    ]

    # A union-imported consumer may have predecessors inside the imported
    # subgraph and may already use the top-level VD stack offset.  Its native
    # origin still identifies it as imported, so internal connectivity alone
    # must not promote it to the live folded owner.
    connected_imported_blocks = dict(native_stale_blocks)
    connected_imported_blocks[10] = replace(
        connected_imported_blocks[10],
        insn_snapshots=(
            connected_imported_blocks[10].insn_snapshots[0],
            replace(
                connected_imported_blocks[10].insn_snapshots[-1],
                l=MopSnapshot(
                    t=_T_STK,
                    size=4,
                    stkoff=carrier_stkoff,
                    kind=OperandKind.STACK,
                ),
            ),
        ),
    )
    connected_imported_graph = FlowGraph(
        blocks=connected_imported_blocks,
        entry_serial=10,
        func_ea=fg.func_ea,
    )
    assert build_stack_carried_state_selector_lowerings(
        connected_imported_graph,
        _disp(
            {first_state: native_stale_leaf_serial, second_state: 22},
            exit_block=99,
        ),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({3, 4, 5}),
        handler_serials=frozenset({10, native_stale_leaf_serial, 21, 22}),
        materialized_indirect_transfers=(
            portable_choice,
            exact_first_target,
            exact_second_target,
        ),
        imported_native_eas_by_serial={10: frozenset({consumer_ea})},
        handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
        state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
        native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
    ) == [
        replace(
            portable_expected[0],
            true_target_serial=native_stale_leaf_serial,
        )
    ]

    # A PREOPT-imported consumer can remain as a zero-predecessor clone while
    # LOCOPT folds the same stack-carried choice into a connected live handler.
    # At CALLS-pre the live consumer can still compare the exact stack cell to
    # a BST threshold; state equality appears only after route rewrites.  The
    # unique connected two-way consumer of that exact cell must own the
    # lowering, rather than the orphan named by the native load-EA map.
    live_consumer_serial = 11
    live_tail_ea = 0x40DBD3
    live_tail = replace(
        consumer_tail,
        ea=live_tail_ea,
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stkoff=carrier_stkoff,
            kind=OperandKind.STACK,
        ),
        r=MopSnapshot(
            t=_T_NUM,
            size=4,
            value=0x10B85E45,
            kind=OperandKind.NUMBER,
        ),
    )
    folded_blocks = dict(detached_graph.blocks)
    folded_blocks[10] = replace(folded_blocks[10], preds=())
    folded_blocks[live_consumer_serial] = _b(
        live_consumer_serial,
        (4, 6),
        (21,),
        (live_tail,),
    )
    folded_graph = FlowGraph(
        blocks=folded_blocks,
        entry_serial=live_consumer_serial,
        func_ea=fg.func_ea,
    )
    live_expected = [
        replace(
            portable_expected[0],
            source_serial=live_consumer_serial,
            rewrite_from_ea=live_tail_ea,
            proof_id=(
                "stack_carried_state_selector_native:"
                "source_ea=0x12C0:store_ea=0x40D269:load_ea=0x40EAA7"
            ),
        )
    ]
    assert (
        build_stack_carried_state_selector_lowerings(
            folded_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, live_consumer_serial, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == live_expected
    )

    # The live dispatcher map can still name a comparison leaf for a state
    # whose resolver-proven equality target is an imported handler.  Once the
    # selector source is connected, the exact handler must outrank that stale
    # leaf or the selected semantic region remains orphaned.
    stale_leaf_serial = 20
    stale_target_blocks = dict(folded_blocks)
    stale_target_blocks[stale_leaf_serial] = _b(
        stale_leaf_serial,
        (4,),
        (4,),
    )
    stale_target_graph = FlowGraph(
        blocks=stale_target_blocks,
        entry_serial=live_consumer_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            stale_target_graph,
            _disp(
                {first_state: stale_leaf_serial, second_state: 22},
                exit_block=99,
            ),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset(
                {10, live_consumer_serial, stale_leaf_serial, 21, 22}
            ),
            materialized_indirect_transfers=(
                portable_choice,
                exact_first_target,
                exact_second_target,
            ),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == live_expected
    )

    # Ownership must remain fail-closed when two connected folded consumers
    # match the same stack cell and state pair.
    ambiguous_blocks = dict(folded_blocks)
    ambiguous_blocks[12] = _b(12, (4, 6), (22,), (live_tail,))
    ambiguous_graph = FlowGraph(
        blocks=ambiguous_blocks,
        entry_serial=live_consumer_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            ambiguous_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 11, 12, 21, 22}),
            materialized_indirect_transfers=(portable_choice,),
            handler_entry_eas_by_serial={21: 0x2100, 22: 0x2200},
            state_carrier_vd_stkoffs_by_store_ea={predicate_ea + 3: carrier_stkoff},
            native_carrier_consumer_serials_by_load_ea={consumer_ea: 10},
        )
        == []
    )

    # LOCOPT can fold ``mov state_reg, [stack]`` into the conditional tail.
    # The storage identity remains explicit in the tail and must carry the
    # same proof as the unfused form.
    direct_blocks = dict(fg.blocks)
    direct_blocks[10] = _b(10, (4, 5), (21,), (consumer_tail,))
    direct_graph = FlowGraph(
        blocks=direct_blocks,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    direct_expected = [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=4,
            rewrite_from_ea=router_ea,
            condition_operand=SyntheticStackValueEqualsCondition(
                stack_stkoff=carrier_stkoff,
                stack_size=4,
                value=first_state,
            ),
            false_target_serial=22,
            true_target_serial=21,
            proof_id=(
                "stack_carried_state_selector:source_ea=0x1280:store_ea=0x40D269"
            ),
            reason="resolver_proven_stack_carried_state_selector",
        )
    ]
    assert (
        build_stack_carried_state_selector_lowerings(
            direct_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == direct_expected
    )

    # A computed-goto equality leaf can consume the stack-carried state
    # directly.  It remains a valid selector source even when exact imported
    # handler ownership removes that router block from the handler map.
    assert (
        build_stack_carried_state_selector_lowerings(
            direct_graph,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5, 10}),
            handler_serials=frozenset({21, 22}),
        )
        == direct_expected
    )

    imported_target_ea = 0x40DD70
    imported_candidate = MaterializedIndirectTransfer(
        source_jmp_ea=0x40DD6E,
        source_block_ea=0x40DD58,
        materialized_anchor_eas=(),
        target_eas=(imported_target_ea,),
        selector_state_var_reg=state_reg,
        selector_state_constant=second_state,
        resolver_kind="static_equality_candidate",
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21}),
            materialized_indirect_transfers=(imported_candidate,),
            handler_entry_eas_by_serial={22: imported_target_ea},
        )
        == expected
    )

    # PREOPT equality evidence proves the native state-to-handler identity; it
    # does not replace a handler that the current live dispatcher map already
    # owns.  Prefer the maturity-local live handler when both representations
    # are present, otherwise a detached clone can orphan the live frontier.
    imported_clone_serial = 23
    blocks_with_imported_clone = dict(fg.blocks)
    blocks_with_imported_clone[imported_clone_serial] = _b(
        imported_clone_serial,
        (),
        (),
    )
    graph_with_imported_clone = FlowGraph(
        blocks=blocks_with_imported_clone,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_imported_clone,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22, imported_clone_serial}),
            materialized_indirect_transfers=(imported_candidate,),
            handler_entry_eas_by_serial={
                imported_clone_serial: imported_target_ea,
            },
        )
        == expected
    )

    # Exact imported equality ownership outranks a stale legacy route for the
    # same state.  The stale route can still name the comparison leaf that
    # existed before detached-target import; unioning both owners would make
    # the selector ambiguous and preserve the computed goto.
    stale_route = MaterializedStateRoute(
        source_block_serial=10,
        state_constant=second_state,
        target_handler_serial=21,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21}),
            materialized_state_routes=(stale_route,),
            materialized_indirect_transfers=(imported_candidate,),
            handler_entry_eas_by_serial={22: imported_target_ea},
        )
        == expected
    )

    # PREOPT can leave a dead register-copy used only to select the native
    # computed-goto target.  Once an exact resolver edge replaces that target,
    # the copy is transparent only when its destination is not live at either
    # selected handler.
    blocks_with_dead_copy = dict(fg.blocks)
    blocks_with_dead_copy[6] = _b(
        6,
        (5,),
        (10,),
        (
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=router_ea + 4,
                operands=(),
                l=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=9,
                    kind=OperandKind.REGISTER,
                ),
                d=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=8,
                    kind=OperandKind.REGISTER,
                ),
                kind=InsnKind.MOV,
            ),
            fg.blocks[6].insn_snapshots[-1],
        ),
    )
    graph_with_dead_copy = FlowGraph(
        blocks=blocks_with_dead_copy,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_dead_copy,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == expected
    )

    # A dead address formation feeding only the replaced router is equally
    # transparent.  Its destination remains subject to the same handler
    # liveness veto as an ordinary register copy.
    blocks_with_dead_address = dict(fg.blocks)
    blocks_with_dead_address[6] = _b(
        6,
        (5,),
        (10,),
        (
            InsnSnapshot(
                opcode=_OP_MOV,
                ea=router_ea + 4,
                operands=(),
                l=MopSnapshot(
                    size=4,
                    value=0x48B918,
                    kind=OperandKind.ADDRESS,
                ),
                d=MopSnapshot(
                    t=_T_REG,
                    size=4,
                    reg=12,
                    kind=OperandKind.REGISTER,
                ),
                kind=InsnKind.MOV,
            ),
            fg.blocks[6].insn_snapshots[-1],
        ),
    )
    graph_with_dead_address = FlowGraph(
        blocks=blocks_with_dead_address,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_dead_address,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == expected
    )

    # An applied resolver-cut port can prove a larger pure address-computation
    # envelope transparent.  Loads/arithmetic remain bypassable only when each
    # instruction defines a register, the exact endpoint enters the router,
    # and no store/call/control effect is present.
    endpoint_ea = router_ea + 0x20
    target_anchor_ea = router_ea + 0x30
    endpoint_goto = InsnSnapshot(
        opcode=0x40,
        ea=endpoint_ea + 3,
        operands=(),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=5),
        kind=InsnKind.GOTO,
        is_unconditional_jump=True,
    )
    pure_endpoint_insns = (
        InsnSnapshot(
            opcode=2,
            ea=endpoint_ea,
            operands=(),
            l=MopSnapshot(kind=OperandKind.GLOBAL, value=0x48BD50),
            d=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
            kind=InsnKind.LOAD,
        ),
        InsnSnapshot(
            opcode=12,
            ea=endpoint_ea + 2,
            operands=(),
            l=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
            d=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
            kind=InsnKind.ADD,
        ),
        endpoint_goto,
    )
    blocks_with_resolver_envelope = dict(fg.blocks)
    blocks_with_resolver_envelope[5] = _b(
        5,
        (22,),
        (3, 6),
        (InsnSnapshot(opcode=0, ea=target_anchor_ea, operands=(), kind=InsnKind.NOP),),
    )
    blocks_with_resolver_envelope[6] = _b(
        6,
        (5,),
        (10,),
        pure_endpoint_insns,
    )
    graph_with_resolver_envelope = FlowGraph(
        blocks=blocks_with_resolver_envelope,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    resolver_cut_evidence = (
        AppliedDetachedSnippetDirectBoundaryPort(
            port=DetachedSnippetDirectBoundaryPort(
                source_block_ea=0x40DABB,
                source_instruction_ea=0x40DACE,
                endpoint_block_ea=0x40DABB,
                old_successor_eas=(),
                target_ea=0x40D370,
                state_register=None,
                state_constant=None,
                source_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                endpoint_owner=DetachedSnippetBoundaryPortOwner.IMPORTED,
                target_owner=DetachedSnippetBoundaryPortOwner.LIVE,
                delivery_mode="terminal_goto",
                resolver_kind="static_equality_candidate_dispatcher_cut",
            ),
            endpoint_anchor_eas=tuple(insn.ea for insn in pure_endpoint_insns),
            target_anchor_eas=(target_anchor_ea,),
        ),
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_resolver_envelope,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_resolver_envelope,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
            imported_direct_boundary_evidence=resolver_cut_evidence,
        )
        == expected
    )

    # A use reached only after re-entering the dispatcher is not a semantic
    # handler use: the direct lowering replaces that traversal.  Cut liveness
    # at dispatcher entry while retaining uses in the selected handler itself.
    router_use = InsnSnapshot(
        opcode=_OP_MOV,
        ea=router_ea + 8,
        operands=(),
        l=MopSnapshot(t=_T_REG, size=4, reg=8, kind=OperandKind.REGISTER),
        d=MopSnapshot(t=_T_REG, size=4, reg=9, kind=OperandKind.REGISTER),
        kind=InsnKind.MOV,
    )
    blocks_with_router_only_use = dict(blocks_with_dead_copy)
    blocks_with_router_only_use[4] = _b(4, (21,), (3, 10), (router_use,))
    graph_with_router_only_use = FlowGraph(
        blocks=blocks_with_router_only_use,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_router_only_use,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == expected
    )

    blocks_with_handler_use = dict(blocks_with_dead_copy)
    blocks_with_handler_use[21] = _b(21, (10,), (4,), (router_use,))
    graph_with_handler_use = FlowGraph(
        blocks=blocks_with_handler_use,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_handler_use,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )

    # A one-way bridge carrying any operation beyond NOPs and its terminal
    # GOTO is not a transparent dispatcher trampoline.  Preserve it rather
    # than bypassing a potentially meaningful side effect.
    blocks_with_effect = dict(fg.blocks)
    blocks_with_effect[6] = _b(
        6,
        (5,),
        (10,),
        (
            _mov_reg(router_ea + 4, 0xDEADBEEF, carrier_reg),
            fg.blocks[6].insn_snapshots[-1],
        ),
    )
    graph_with_effect = FlowGraph(
        blocks=blocks_with_effect,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            graph_with_effect,
            dispatcher,
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )


def test_snapshot_fixpoint_visits_entry_before_default_budget_expires(
    _seam,
) -> None:
    carrier_reg = 28
    constant = 0x4D34CF70
    branch_ea = 0x40D266
    blocks = {
        0: _b(
            0,
            (1, 2),
            (),
            (
                _mov_reg(branch_ea - 5, constant, carrier_reg),
                InsnSnapshot(
                    opcode=0x32,
                    ea=branch_ea,
                    operands=(),
                    l=MopSnapshot(
                        t=_T_REG,
                        size=4,
                        reg=carrier_reg,
                        kind=OperandKind.REGISTER,
                    ),
                    r=MopSnapshot(
                        t=_T_NUM,
                        size=4,
                        value=0x113,
                        kind=OperandKind.NUMBER,
                    ),
                    d=MopSnapshot(
                        kind=OperandKind.BLOCK,
                        block_ref=2,
                    ),
                    kind=InsnKind.COND_JUMP,
                    branch_predicate=PredicateKind.SLT,
                    is_conditional_jump=True,
                ),
            ),
        ),
        1: _b(1, (), (0,)),
        2: _b(2, (), (0,)),
    }
    blocks.update({serial: _b(serial, (), ()) for serial in range(3, 1005)})
    graph = FlowGraph(
        blocks=blocks,
        entry_serial=0,
        func_ea=0x40D200,
    )

    result = run_snapshot_constant_fixpoint(graph, -1)

    assert result.out_reg_maps[0][carrier_reg] == constant


def test_folded_imported_stack_selector_bypasses_converged_indirect_router(
    _seam,
) -> None:
    state_reg = 28
    carrier_reg = 7
    carrier_stkoff = 0x6C
    imported_frame_stkoff = 0xF4
    first_state = 0x142718FC
    second_state = 0x1D4F9917
    predicate_ea = 0x1100
    consumer_ea = 0x2200
    router_ea = 0x2204
    imported_target_ea = 0x5000
    owner_state = 0xF6D08EC5
    consumer_tail = InsnSnapshot(
        opcode=0x33,
        ea=router_ea,
        operands=(),
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stkoff=carrier_stkoff,
            kind=OperandKind.STACK,
        ),
        r=MopSnapshot(
            t=_T_NUM,
            size=4,
            value=0x10B85E45,
            kind=OperandKind.NUMBER,
        ),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=12),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    terminal_ijmp = InsnSnapshot(
        opcode=0x36,
        ea=router_ea + 8,
        operands=(),
        kind=InsnKind.INDIRECT_JUMP,
    )
    fg = FlowGraph(
        blocks={
            0: _b(
                0,
                (1, 2),
                (),
                (
                    _mov_reg(predicate_ea - 5, first_state, carrier_reg),
                    InsnSnapshot(
                        opcode=0x33,
                        ea=predicate_ea,
                        operands=(),
                        kind=InsnKind.COND_JUMP,
                        is_conditional_jump=True,
                    ),
                ),
            ),
            1: _b(
                1,
                (2,),
                (0,),
                (_mov_reg(predicate_ea, second_state, carrier_reg),),
            ),
            2: _b(
                2,
                (10,),
                (0, 1),
                (_mov_stack_from_reg(predicate_ea + 3, carrier_stkoff, carrier_reg),),
            ),
            # Imported snippets can retain a separate frame load into the
            # state register before a folded tail that compares the actual
            # selector cell directly.  The tail operand is authoritative: the
            # lowering keeps this source block and rewrites only its targets.
            10: _b(
                10,
                (11, 12),
                (2,),
                (
                    _mov_reg_from_stack(
                        consumer_ea,
                        state_reg,
                        imported_frame_stkoff,
                    ),
                    consumer_tail,
                ),
            ),
            11: _b(
                11,
                (12,),
                (10,),
                (
                    InsnSnapshot(
                        opcode=_OP_MOV,
                        ea=router_ea + 4,
                        operands=(),
                        l=MopSnapshot(
                            t=_T_REG,
                            size=4,
                            reg=9,
                            kind=OperandKind.REGISTER,
                        ),
                        d=MopSnapshot(
                            t=_T_REG,
                            size=4,
                            reg=8,
                            kind=OperandKind.REGISTER,
                        ),
                        kind=InsnKind.MOV,
                    ),
                ),
            ),
            12: _b(12, (), (10, 11), (terminal_ijmp,)),
            21: _b(21, (), (), ()),
            22: _b(22, (), (), ()),
            30: _b(30, (), (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    imported_owner = MaterializedIndirectTransfer(
        source_jmp_ea=0x4FF0,
        source_block_ea=0x4FE0,
        materialized_anchor_eas=(),
        target_eas=(imported_target_ea,),
        selector_state_var_reg=state_reg,
        selector_state_constant=owner_state,
        resolver_kind="static_equality_candidate",
    )

    assert build_stack_carried_state_selector_lowerings(
        fg,
        _disp({first_state: 21, second_state: 22}, exit_block=99),
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({30}),
        handler_serials=frozenset({21, 22}),
        materialized_indirect_transfers=(imported_owner,),
        handler_entry_eas_by_serial={10: imported_target_ea},
    ) == [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=11,
            rewrite_from_ea=router_ea,
            condition_operand=SyntheticStackValueEqualsCondition(
                stack_stkoff=carrier_stkoff,
                stack_size=4,
                value=first_state,
            ),
            false_target_serial=22,
            true_target_serial=21,
            proof_id=("stack_carried_state_selector:source_ea=0x1280:store_ea=0x1103"),
            reason="resolver_proven_stack_carried_state_selector",
        )
    ]

    # The converged-indirect exception belongs only to an exact imported
    # equality owner.  An ordinary handler with the same folded stack tail
    # must preserve the unresolved router.
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({30}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )

    # A detached static replay of the exact live indirect endpoint supplies
    # the missing ownership proof when PREOPT assigned the equality state to
    # an imported clone rather than this original live handler.  The replay
    # authorizes the existing stack-selector proof; its router-root EAs are
    # never used as the lowering destinations.
    terminal_transfer = MaterializedIndirectTransfer(
        source_jmp_ea=router_ea + 8,
        source_block_ea=consumer_ea,
        materialized_anchor_eas=(),
        target_eas=(0x6000, 0x7000),
        condition_code=12,
        true_target_ea=0x6000,
        false_target_ea=0x7000,
        resolver_kind="detached_static_fixpoint",
    )
    expected = [
        LowerConditionalStateTransition(
            source_serial=10,
            old_dispatcher_serial=11,
            rewrite_from_ea=router_ea,
            condition_operand=SyntheticStackValueEqualsCondition(
                stack_stkoff=carrier_stkoff,
                stack_size=4,
                value=first_state,
            ),
            false_target_serial=22,
            true_target_serial=21,
            proof_id=("stack_carried_state_selector:source_ea=0x1280:store_ea=0x1103"),
            reason="resolver_proven_stack_carried_state_selector",
        )
    ]
    clone_owned_args = dict(
        state_var_reg=state_reg,
        dispatcher_region_serials=frozenset({30}),
        handler_serials=frozenset({10, 21, 22}),
        handler_entry_eas_by_serial={30: imported_target_ea},
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            materialized_indirect_transfers=(imported_owner, terminal_transfer),
            **clone_owned_args,
        )
        == expected
    )

    mismatched_terminal = replace(
        terminal_transfer,
        source_jmp_ea=router_ea + 0x40,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            materialized_indirect_transfers=(imported_owner, mismatched_terminal),
            **clone_owned_args,
        )
        == []
    )
    incomplete_terminal = replace(terminal_transfer, false_target_ea=None)
    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            materialized_indirect_transfers=(imported_owner, incomplete_terminal),
            **clone_owned_args,
        )
        == []
    )

    # A call at the shared endpoint is a semantic effect, not a disposable
    # computed-jump router.  Exact ownership alone must not bypass it.
    effect_blocks = dict(fg.blocks)
    effect_blocks[12] = _b(
        12,
        (),
        (10, 11),
        (
            InsnSnapshot(
                opcode=0x31,
                ea=router_ea + 8,
                operands=(),
                kind=InsnKind.CALL,
            ),
        ),
    )
    effect_graph = FlowGraph(
        blocks=effect_blocks,
        entry_serial=fg.entry_serial,
        func_ea=fg.func_ea,
    )
    assert (
        build_stack_carried_state_selector_lowerings(
            effect_graph,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({30}),
            handler_serials=frozenset({21, 22}),
            materialized_indirect_transfers=(imported_owner,),
            handler_entry_eas_by_serial={10: imported_target_ea},
        )
        == []
    )


def test_terminal_replay_endpoint_excludes_imported_clone() -> None:
    from d810.transforms import minimal_unflatten_emit as emit_module

    source_jmp_ea = 0x40DACE
    terminal_ijmp = InsnSnapshot(
        opcode=0x36,
        ea=source_jmp_ea,
        operands=(),
        kind=InsnKind.INDIRECT_JUMP,
    )
    fg = FlowGraph(
        blocks={
            12: _b(12, (), (), (terminal_ijmp,)),
            31: _b(31, (), (), (terminal_ijmp,)),
        },
        entry_serial=12,
        func_ea=0x40D200,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=source_jmp_ea,
        source_block_ea=0x40DABB,
        materialized_anchor_eas=(),
        target_eas=(0x40D381, 0x40E5C0),
        condition_code=12,
        true_target_ea=0x40D381,
        false_target_ea=0x40E5C0,
        resolver_kind="detached_static_fixpoint",
    )

    helper = emit_module._resolver_proven_live_terminal_endpoint_serials
    assert (
        helper(
            fg,
            (transfer,),
            imported_endpoint_serials=frozenset(),
        )
        == frozenset()
    )
    assert helper(
        fg,
        (transfer,),
        imported_endpoint_serials=frozenset({31}),
    ) == frozenset({12})
    assert (
        helper(
            fg,
            (transfer,),
            imported_endpoint_serials=frozenset({12, 31}),
        )
        == frozenset()
    )


def test_stack_carried_state_selector_abstains_on_second_cell_write(_seam) -> None:
    state_reg = 28
    carrier_reg = 7
    carrier_stkoff = 0x54
    first_state = 0x10
    second_state = 0x20
    consumer_tail = InsnSnapshot(
        opcode=0x33,
        ea=0x2204,
        operands=(),
        l=MopSnapshot(
            t=_T_STK,
            size=4,
            stkoff=carrier_stkoff,
            kind=OperandKind.STACK,
        ),
        r=MopSnapshot(t=_T_NUM, size=4, value=0, kind=OperandKind.NUMBER),
        d=MopSnapshot(kind=OperandKind.BLOCK, block_ref=4),
        kind=InsnKind.COND_JUMP,
        is_conditional_jump=True,
    )
    fg = FlowGraph(
        blocks={
            0: _b(0, (1, 2), (), (_mov_reg(0x1000, first_state, carrier_reg),)),
            1: _b(1, (2,), (0,), (_mov_reg(0x1040, second_state, carrier_reg),)),
            2: _b(
                2,
                (3,),
                (0, 1),
                (_mov_stack_from_reg(0x1080, carrier_stkoff, carrier_reg),),
            ),
            3: _b(3, (4, 5), (2,)),
            4: _b(4, (21,), (3, 10)),
            5: _b(5, (22,), (3, 10)),
            10: _b(
                10,
                (4, 5),
                (21,),
                (
                    _mov_reg_from_stack(0x2200, state_reg, carrier_stkoff),
                    consumer_tail,
                ),
            ),
            21: _b(21, (10,), (4,)),
            22: _b(22, (10,), (5,)),
            30: _b(
                30, (), (), (_mov_stack_const(0x3000, carrier_stkoff, first_state),)
            ),
        },
        entry_serial=0,
        func_ea=0x1000,
    )

    assert (
        build_stack_carried_state_selector_lowerings(
            fg,
            _disp({first_state: 21, second_state: 22}, exit_block=99),
            state_var_reg=state_reg,
            dispatcher_region_serials=frozenset({3, 4, 5}),
            handler_serials=frozenset({10, 21, 22}),
        )
        == []
    )


def test_scalar_initial_state_suppresses_register_conditional_entry_scan(_seam) -> None:
    state_reg = 99
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, 0x10, state_reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, 0x20, state_reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=0x10,
        state_var_stkoff=None,
        state_var_reg=state_reg,
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (3, 4, 21) in edges
    assert not any(source in {1, 2} for source, _old, _new in edges)


def test_register_conditional_entry_ignores_invariant_leaf_register(_seam) -> None:
    """The carrier must be one register whose value varies across both arms.

    A different register may coincidentally hold a valid dispatcher state on
    both predecessors.  Selecting the first routeable value independently on
    each predecessor collapses both arms onto that unrelated state's handler.
    """
    carrier_reg = 99
    invariant_reg = 77
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1,
                (2, 3),
                (0,),
                (
                    _mov_reg(0x1100, 0x20, invariant_reg),
                    _mov_reg(0x1104, 0x10, carrier_reg),
                ),
            ),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, 0x20, carrier_reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=carrier_reg,
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 22) in edges


def test_register_conditional_entry_abstains_on_two_distinct_route_sets(_seam) -> None:
    carrier_reg = 99
    competing_reg = 77
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(
                1,
                (2, 3),
                (0,),
                (
                    _mov_reg(0x1100, 0x20, competing_reg),
                    _mov_reg(0x1104, 0x10, carrier_reg),
                ),
            ),
            2: _b(
                2,
                (3,),
                (1,),
                (
                    _mov_reg(0x1200, 0x10, competing_reg),
                    _mov_reg(0x1204, 0x20, carrier_reg),
                ),
            ),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({0x10: 21, 0x20: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=carrier_reg,
    )

    assert not any(
        isinstance(modification, (RedirectGoto, RedirectBranch))
        and modification.from_serial in {1, 2}
        for modification in modifications
    )


def test_register_conditional_entry_uses_unique_materialized_state_route(_seam) -> None:
    reg = 99
    live_state = 0xA0716E5B
    residual_state = 0xEC71CA67
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, live_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, residual_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21,), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({live_state: 21}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=4
    )

    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        materialized_state_routes=(MaterializedStateRoute(200, residual_state, 22),),
        condition_chain_handlers=frozenset({21, 22}),
    )

    edges = {
        (m.from_serial, m.old_target, m.new_target)
        for m in mods
        if isinstance(m, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 22) in edges


def test_register_conditional_entry_prefers_portable_live_handler_map(_seam) -> None:
    reg = 99
    parser_state = 0xA0716E5B
    main_state = 0xEC71CA67
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, parser_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, main_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21,), (3, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    coarse_dispatcher = _disp(
        {parser_state: 21, main_state: 21},
        exit_block=99,
    )

    modifications = build_state_write_redirects(
        fg,
        coarse_dispatcher,
        recover_state_write_transitions(
            fg,
            coarse_dispatcher,
            _STATE,
            dispatcher_entry_serial=4,
        ),
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        materialized_handler_by_state={parser_state: 22, main_state: 21},
        condition_chain_handlers=frozenset({21, 22}),
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 22) in edges
    assert (2, 3, 21) in edges


def test_register_conditional_entry_prefers_exact_detached_equality_target(
    _seam,
) -> None:
    reg = 99
    parser_state = 0xA0716E5B
    main_state = 0xEC71CA67
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, parser_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, main_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21,), (3, 21)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (), ()),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    disp = _disp({parser_state: 21}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, disp, _STATE, dispatcher_entry_serial=4
    )
    exact_main = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B9A4,
        source_block_ea=0x40B98C,
        materialized_anchor_eas=(0x40B998, 0x40B99E),
        target_eas=(fg.blocks[22].start_ea, fg.blocks[99].start_ea),
        condition_code=4,
        true_target_ea=fg.blocks[22].start_ea,
        false_target_ea=fg.blocks[99].start_ea,
        selector_state_var_reg=20,
        selector_compare_constant=main_state,
        selector_state_on_left=True,
        resolver_kind="static_equality_fixpoint",
    )

    mods = build_state_write_redirects(
        fg,
        disp,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=20,
        materialized_indirect_transfers=(exact_main,),
        materialized_state_routes=(MaterializedStateRoute(200, main_state, 21),),
        condition_chain_handlers=frozenset({21}),
    )

    edges = {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in mods
        if isinstance(mod, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 22) in edges


def test_register_conditional_entry_rejects_external_exact_target(_seam) -> None:
    """An XTRN placeholder must not outrank the imported dispatcher handler."""
    reg = 20
    first_state = 0x09269BD2
    second_state = 0xA4C94734
    external_target_ea = 0x40CE3C
    external = BlockSnapshot(
        serial=22,
        block_type=6,
        succs=(),
        preds=(),
        flags=0,
        start_ea=external_target_ea,
        insn_snapshots=(),
        kind=BlockKind.EXTERNAL,
    )
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, first_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, second_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(0x1300, 0xDEAD),)),
            4: _b(4, (21, 23), (3, 21, 23)),
            21: _b(21, (4,), (4,)),
            22: external,
            23: _b(23, (4,), (4,)),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp(
        {first_state: 21, second_state: 23},
        exit_block=99,
    )
    exact_first = MaterializedIndirectTransfer(
        source_jmp_ea=0x40CEC6,
        source_block_ea=0x40CEAB,
        materialized_anchor_eas=(0x40CEB0,),
        target_eas=(external_target_ea, fg.blocks[99].start_ea),
        condition_code=4,
        true_target_ea=external_target_ea,
        false_target_ea=fg.blocks[99].start_ea,
        selector_state_var_reg=reg,
        selector_compare_constant=first_state,
        selector_state_on_left=True,
        resolver_kind="static_equality_fixpoint",
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        recover_state_write_transitions(
            fg,
            dispatcher,
            _STATE,
            dispatcher_entry_serial=4,
        ),
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        materialized_indirect_transfers=(exact_first,),
        condition_chain_handlers=frozenset({21, 22, 23}),
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 23) in edges
    assert all(new_target != 22 for _source, _old, new_target in edges)


def test_register_conditional_entry_uses_evidence_store_anchor_past_false_merge(
    _seam,
) -> None:
    """A detached residual chain must not hide the true prologue state merge."""
    reg = 99
    live_state = 0xA0716E5B
    residual_state = 0xEC71CA67
    source_store_ea = 0x1300
    fg = FlowGraph(
        blocks={
            0: _b(0, (1, 6), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, live_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, residual_state, reg),)),
            3: _b(3, (5,), (1, 2), (_mov_state(source_store_ea, 0xDEAD),)),
            5: _b(5, (4,), (3, 6)),
            6: _b(6, (5,), (0,)),
            4: _b(4, (21,), (5, 21, 22)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (), ()),
            99: _b(99, (), ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({live_state: 21}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1000,
        condition_code=5,
        predicate_stack_identity=(4, 4),
        stack_cell_identity=(_STATE, 4),
        taken_state_constant=live_state,
        fallthrough_state_constant=residual_state,
        source_store_ea=source_store_ea,
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        materialized_state_routes=(MaterializedStateRoute(200, residual_state, 22),),
        condition_chain_handlers=frozenset({21, 22}),
        entry_bridge_evidence=evidence,
    )

    edges = {
        (modification.from_serial, modification.old_target, modification.new_target)
        for modification in modifications
        if isinstance(modification, (RedirectGoto, RedirectBranch))
    }
    assert (1, 3, 21) in edges
    assert (2, 3, 22) in edges


def test_register_conditional_entry_abstains_on_ambiguous_evidence_store_anchor(
    _seam,
) -> None:
    reg = 99
    live_state = 0x10
    residual_state = 0x20
    source_store_ea = 0x1300
    fg = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2, 3), (0,), (_mov_reg(0x1100, live_state, reg),)),
            2: _b(2, (3,), (1,), (_mov_reg(0x1200, residual_state, reg),)),
            3: _b(3, (4,), (1, 2), (_mov_state(source_store_ea, 0xDEAD),)),
            4: _b(4, (21, 22), (3, 21, 22)),
            6: _b(6, (), (), (_mov_state(source_store_ea, 0xBEEF),)),
            21: _b(21, (4,), (4,)),
            22: _b(22, (4,), (4,)),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    dispatcher = _disp({live_state: 21, residual_state: 22}, exit_block=99)
    transitions = recover_state_write_transitions(
        fg, dispatcher, _STATE, dispatcher_entry_serial=4
    )
    evidence = EntryBridgeEvidence(
        predicate_ea=0x1000,
        condition_code=5,
        predicate_stack_identity=(4, 4),
        stack_cell_identity=(_STATE, 4),
        taken_state_constant=live_state,
        fallthrough_state_constant=residual_state,
        source_store_ea=source_store_ea,
    )

    modifications = build_state_write_redirects(
        fg,
        dispatcher,
        transitions,
        dispatcher_entry_serial=4,
        pre_header_serial=None,
        initial_state=None,
        state_var_stkoff=_STATE,
        state_var_reg=reg,
        entry_bridge_evidence=evidence,
    )

    assert not any(
        isinstance(modification, (RedirectGoto, RedirectBranch))
        and modification.from_serial in {1, 2}
        for modification in modifications
    )


def test_resolver_proven_indirect_call_neutralization_joins_planned_redirect() -> None:
    transfer_ea = 0x40AE89
    graph = FlowGraph(
        blocks={
            83: _b(
                83,
                (318,),
                (82,),
                (_nested_call_result(transfer_ea),),
            ),
            43: _b(43, (4,), ()),
            318: _b(318, (4,), (83,)),
            4: _b(4, (), (43, 318)),
        },
        entry_serial=83,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=transfer_ea,
        source_block_ea=0x40AE3E,
        materialized_anchor_eas=(),
        target_eas=(0x40A607, 0x40B6C0),
        resolver_kind="detached_static_fixpoint",
    )

    assert build_resolver_proven_indirect_call_neutralizations(
        graph,
        (transfer,),
        (RedirectGoto(from_serial=83, old_target=318, new_target=43),),
        handler_serials=frozenset({43}),
    ) == [
        NopInstructions(block_serial=83, insn_eas=(transfer_ea,)),
    ]


def test_default_use_def_findings_are_advisory_and_keep_all_sibling_redirects(
    _seam,
    monkeypatch,
) -> None:
    """Heuristic severances must not silently drop sibling redirects by default."""

    class _CleanUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return ()

    class _HeuristicUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (
                SimpleNamespace(
                    src_block=10,
                    new_target=20,
                    var_stkoff=_CARRIER_OFF,
                    var_size=4,
                    use_block=20,
                    use_ea=0x1000,
                ),
            )

    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)
    monkeypatch.delenv("D810_S1A_SEVERANCE_BAIL", raising=False)
    kwargs = {
        "state_var_stkoff": _STATE,
        "dispatcher_entry_serial": 2,
        "initial_state": 0x10,
        "authoritative_handler_serials": frozenset({10, 20}),
        "live_function": object(),
    }
    clean_plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        use_def_safety=_CleanUseDefSafety(),
        **kwargs,
    )
    heuristic_plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        use_def_safety=_HeuristicUseDefSafety(),
        **kwargs,
    )

    assert len(graph_modifications(heuristic_plan)) == len(
        graph_modifications(clean_plan)
    )
    proof = heuristic_plan.metadata_dict()[DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA]
    assert proof["producer_safety"]["fragment_atomic"] is False
    audit = heuristic_plan.metadata_dict()["use_def_severance_audit"]
    assert audit["enforced"] is False
    assert len(audit["violations"]) >= 1


def test_legacy_s1a_severance_bail_rejects_the_whole_fragment(
    _seam,
    monkeypatch,
) -> None:
    """The legacy S1A gate rejects an executed actionable audit atomically."""

    class _HeuristicUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (
                SimpleNamespace(
                    src_block=10,
                    new_target=20,
                    var_stkoff=_CARRIER_OFF,
                    var_size=4,
                    use_block=20,
                    use_ea=0x1000,
                ),
            )

    monkeypatch.setenv("D810_S1A_SEVERANCE_BAIL", "1")
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)
    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_HeuristicUseDefSafety(),
        live_function=object(),
    )

    assert graph_modifications(plan) == []
    audit = plan.metadata_dict()["use_def_severance_audit"]
    assert audit["executed"] is True
    assert audit["clean"] is False
    assert audit["enforced"] is True
    assert audit["enforcement_status"] == "fragment_rejected"


def test_legacy_s1a_severance_bail_ignores_state_variable_findings(
    _seam,
    monkeypatch,
) -> None:
    class _StateOnlyUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (SimpleNamespace(var_stkoff=_STATE),)

    monkeypatch.setenv("D810_S1A_SEVERANCE_BAIL", "1")
    monkeypatch.delenv("D810_USE_DEF_VETO", raising=False)
    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_StateOnlyUseDefSafety(),
        live_function=object(),
    )

    assert len(graph_modifications(plan)) == 3
    audit = plan.metadata_dict()["use_def_severance_audit"]
    assert audit["executed"] is True
    assert audit["clean"] is True
    assert audit["severance_count"] == 0


def test_explicit_use_def_veto_rejects_the_whole_fragment_atomically(
    _seam,
    monkeypatch,
) -> None:
    """An enabled veto rejects all sibling redirects, never a filtered subset."""

    class _HeuristicUseDefSafety:
        @staticmethod
        def redirect_use_def_violations(*_args: object) -> tuple[object, ...]:
            return (
                SimpleNamespace(
                    src_block=10,
                    new_target=20,
                    var_stkoff=_CARRIER_OFF,
                    var_size=4,
                    use_block=20,
                    use_ea=0x1000,
                ),
            )

    monkeypatch.setenv("D810_USE_DEF_VETO", "1")
    plan = emit_minimal_unflatten(
        _complete_two_handler_dispatcher_graph(),
        _disp({0x10: 10, 0x20: 20}, exit_block=99),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0x10,
        authoritative_handler_serials=frozenset({10, 20}),
        use_def_safety=_HeuristicUseDefSafety(),
        live_function=object(),
    )

    assert graph_modifications(plan) == []
    audit = plan.metadata_dict()["use_def_severance_audit"]
    assert audit["enforced"] is True
    assert audit["enforcement_status"] == "fragment_rejected"


def test_switch_retirement_breaks_unique_terminal_dispatcher_cycle() -> None:
    """Full switch retirement must explicitly break its detached cycle."""
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (1,), ()),
            1: _b(1, (2,), (0,)),
            2: replace(
                _b(2, (3, 4, 5, 6, 7), (1, 8)),
                kind=BlockKind.N_WAY,
            ),
            3: _b(3, (8,), (2,)),
            4: _b(4, (8,), (2,)),
            5: _b(5, (8,), (2,)),
            6: _b(6, (9,), (2,)),
            7: _b(7, (8,), (2,)),
            8: _b(8, (2,), (3, 4, 5, 7)),
            9: replace(_exit_block(9, (6,)), kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x180001670,
    )
    modifications = [
        RedirectGoto(from_serial=3, old_target=8, new_target=4),
        RedirectGoto(from_serial=4, old_target=8, new_target=5),
        RedirectGoto(from_serial=5, old_target=8, new_target=6),
        RedirectGoto(from_serial=1, old_target=2, new_target=3),
    ]

    rewritten, cleanup_source = (
        minimal_unflatten_emit_module._break_terminal_switch_dispatcher_cycle(
            flow_graph,
            modifications,
            dispatcher_entry_serial=2,
        )
    )

    assert cleanup_source == 8
    assert [mod.from_serial for mod in rewritten if isinstance(mod, RedirectGoto)] == [
        3,
        4,
        5,
        1,
        8,
    ]
    assert rewritten[-1] == RedirectGoto(
        from_serial=8,
        old_target=2,
        new_target=6,
    )


def test_switch_retirement_abstains_when_terminal_corridor_is_ambiguous() -> None:
    """Two terminal candidates provide no authority to choose a cleanup edge."""
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: replace(_b(2, (3, 4), (0, 5, 6)), kind=BlockKind.N_WAY),
            3: _b(3, (9,), (2,)),
            4: _b(4, (9,), (2,)),
            5: _b(5, (2,), ()),
            6: _b(6, (2,), ()),
            9: replace(_exit_block(9, (3, 4)), kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    modifications = [
        RedirectGoto(from_serial=5, old_target=2, new_target=3),
        RedirectGoto(from_serial=6, old_target=2, new_target=4),
    ]

    rewritten, cleanup_source = (
        minimal_unflatten_emit_module._break_terminal_switch_dispatcher_cycle(
            flow_graph,
            modifications,
            dispatcher_entry_serial=2,
        )
    )

    assert rewritten == modifications
    assert cleanup_source is None


def test_switch_emitter_breaks_terminal_dispatcher_cycle_before_compiling_plan(
    _seam,
) -> None:
    """The abc-style plan must make its detached switch residue acyclic."""
    flow_graph = FlowGraph(
        blocks={
            0: _b(0, (2,), ()),
            2: replace(
                _b(2, (3, 4, 5, 6, 7), (0, 8)),
                kind=BlockKind.N_WAY,
            ),
            3: _b(3, (8,), (2,), (_mov_state(0x1300, 1),)),
            4: _b(4, (8,), (2,), (_mov_state(0x1400, 2),)),
            5: _b(5, (8,), (2,), (_mov_state(0x1500, 3),)),
            6: _b(6, (9,), (2,)),
            7: _b(7, (8,), (2,)),
            8: _b(8, (2,), (3, 4, 5, 7)),
            9: replace(_exit_block(9, (6,)), kind=BlockKind.STOP),
        },
        entry_serial=0,
        func_ea=0x180001670,
    )

    plan = emit_minimal_unflatten(
        flow_graph,
        _disp({0: 3, 1: 4, 2: 5, 3: 6}, exit_block=7),
        state_var_stkoff=_STATE,
        dispatcher_entry_serial=2,
        initial_state=0,
        authoritative_handler_serials=frozenset({3, 4, 5, 6}),
    )

    modifications = graph_modifications(plan)
    assert {
        (mod.from_serial, mod.old_target, mod.new_target)
        for mod in modifications
        if isinstance(mod, RedirectGoto)
    } == {
        (0, 2, 3),
        (3, 8, 4),
        (4, 8, 5),
        (5, 8, 6),
        (8, 2, 6),
    }
    coverage = plan.metadata_dict()[DISPATCHER_CORRIDOR_COVERAGE_METADATA]
    assert coverage["planned_completion_status"] == (
        "planned_dispatcher_corridors_covered"
    )
    assert coverage["full_unflattening_claim"] is False
