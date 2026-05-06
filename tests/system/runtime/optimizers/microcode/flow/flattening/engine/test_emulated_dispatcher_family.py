from __future__ import annotations

from dataclasses import asdict, replace
from types import SimpleNamespace

import idaapi
import ida_hexrays
import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    InsertBlock,
    PhaseCycleLowering,
    RedirectGoto,
)
from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from d810.hexrays.mutation.ir_translator import lift as lift_mba
from d810.optimizers.microcode.flow.flattening.engine.provenance import (
    DecisionPhase,
    DecisionReasonCode,
    PipelineProvenance,
)
from d810.optimizers.microcode.flow.flattening.engine.runtime import (
    ExecutedPipeline,
    PlannedPipeline,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import StageResult
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    StateModelSummary,
)
from d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family import (
    EmulatedDispatcherDetection,
    EmulatedDispatcherStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.strategies.emulated_dispatcher_strategy import (
    EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY,
    EMULATED_DISPATCHER_METADATA_KEY,
    EMULATED_DISPATCHER_MODIFICATIONS_KEY,
    EmulatedDispatcherCandidateRecord,
    EmulatedDispatcherMetadata,
    EmulatedDispatcherPhaseArtifact,
    EmulatedDispatcherStrategy,
    extract_emulated_dispatcher_candidate_records,
    extract_emulated_dispatcher_metadata,
    extract_emulated_dispatcher_modifications,
    extract_emulated_dispatcher_phase_artifact,
)
from d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine import (
    EmulatedDispatcherUnflattener,
)
from d810.testing.runner import _resolve_test_project_index, get_func_ea
from tests.system.e2e.test_approov_engine_wrapper_baselines import (
    _apply_engine_wrapper_profile,
    _decompile_with_project,
    _decompile_without_d810,
    _force_rule_scope_to_current_profile,
    _get_default_binary,
    _restore_forced_rule_scope,
)


def _verify_error(mba) -> str | None:
    try:
        mba.verify(True)
    except RuntimeError as exc:
        return str(exc)
    return None


def _find_state_write_ea(
    mba,
    *,
    block_serial: int,
    expected_state: int,
    state_var_stkoff: int = 12,
) -> int:
    blk = mba.get_mblock(block_serial)
    assert blk is not None
    insn = blk.head
    while insn is not None:
        if (
            int(insn.opcode) == int(ida_hexrays.m_mov)
            and int(getattr(getattr(insn, "d", None), "t", ida_hexrays.mop_z))
            == int(ida_hexrays.mop_S)
            and int(getattr(getattr(insn, "d", None), "s", SimpleNamespace(off=-1)).off)
            == state_var_stkoff
            and int(getattr(getattr(insn, "l", None), "t", ida_hexrays.mop_z))
            == int(ida_hexrays.mop_n)
            and int(
                getattr(getattr(getattr(insn, "l", None), "nnn", None), "value", -1)
            )
            == expected_state
        ):
            return int(insn.ea)
        insn = insn.next
    raise AssertionError(
        f"missing state write block={block_serial} state={hex(expected_state)}"
    )


def _filter_emulated_dispatcher_snapshot(
    snapshot: AnalysisSnapshot,
    selected_indexes: tuple[int, ...],
) -> AnalysisSnapshot:
    selected_set = set(selected_indexes)
    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    assert metadata is not None
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
    candidate_records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
    selected_modifications = tuple(
        mod for idx, mod in enumerate(modifications) if idx in selected_set
    )
    selected_records = tuple(
        record
        for record in candidate_records
        if any(idx in selected_set for idx in record.selected_modification_indexes)
    )
    filtered_metadata = replace(
        metadata,
        planning_ready=bool(selected_modifications),
        planning_blocker=None if selected_modifications else metadata.planning_blocker,
        candidate_count=len(selected_modifications),
        candidate_kinds=tuple(type(mod).__name__ for mod in selected_modifications),
        candidate_records=selected_records,
    )
    flow_graph = FlowGraph(
        blocks=snapshot.flow_graph.blocks,
        entry_serial=snapshot.flow_graph.entry_serial,
        func_ea=snapshot.flow_graph.func_ea,
        metadata={
            **dict(snapshot.flow_graph.metadata),
            EMULATED_DISPATCHER_METADATA_KEY: filtered_metadata,
            EMULATED_DISPATCHER_MODIFICATIONS_KEY: selected_modifications,
            EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY: selected_records,
        },
    )
    return replace(snapshot, flow_graph=flow_graph)


def _fake_mba():
    blk = SimpleNamespace(nsucc=lambda: 0)
    return SimpleNamespace(
        qty=1,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
        get_mblock=lambda _serial: blk,
        for_all_topinsns=lambda collector: None,
    )


def _flow_graph() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            )
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _flow_graph_with_edge() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(0,),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _flow_graph_with_conditional_shape() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=ida_hexrays.BLT_1WAY,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0x401000,
                insn_snapshots=(),
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=ida_hexrays.BLT_2WAY,
                succs=(2, 3),
                preds=(0,),
                flags=0,
                start_ea=0x401010,
                insn_snapshots=(),
            ),
            2: BlockSnapshot(
                serial=2,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x401020,
                insn_snapshots=(),
            ),
            3: BlockSnapshot(
                serial=3,
                block_type=ida_hexrays.BLT_0WAY,
                succs=(),
                preds=(1,),
                flags=0,
                start_ea=0x401030,
                insn_snapshots=(),
            ),
        },
        entry_serial=0,
        func_ea=0x401000,
    )


def _snapshot_operand_signature(mop) -> str:
    if mop is None:
        return "z"
    return (
        f"t={getattr(mop, 't', None)},size={getattr(mop, 'size', None)},"
        f"value={getattr(mop, 'value', None)},stkoff={getattr(mop, 'stkoff', None)},"
        f"reg={getattr(mop, 'reg', None)},block_ref={getattr(mop, 'block_ref', None)}"
    )


def _payload_signature_from_instructions(instructions) -> tuple[str, ...]:
    return tuple(
        "|".join(
            (
                f"op={getattr(insn, 'opcode', None)}",
                f"l={_snapshot_operand_signature(getattr(insn, 'l', None))}",
                f"r={_snapshot_operand_signature(getattr(insn, 'r', None))}",
                f"d={_snapshot_operand_signature(getattr(insn, 'd', None))}",
            )
        )
        for insn in instructions
    )


def _compute_nontrivial_sccs(flow_graph: FlowGraph) -> tuple[tuple[int, ...], ...]:
    index = 0
    stack: list[int] = []
    on_stack: set[int] = set()
    indexes: dict[int, int] = {}
    lowlinks: dict[int, int] = {}
    components: list[tuple[int, ...]] = []

    def _strongconnect(serial: int) -> None:
        nonlocal index
        indexes[serial] = index
        lowlinks[serial] = index
        index += 1
        stack.append(serial)
        on_stack.add(serial)

        for succ in flow_graph.successors(serial):
            if succ not in indexes:
                _strongconnect(succ)
                lowlinks[serial] = min(lowlinks[serial], lowlinks[succ])
            elif succ in on_stack:
                lowlinks[serial] = min(lowlinks[serial], indexes[succ])

        if lowlinks[serial] != indexes[serial]:
            return

        component: list[int] = []
        while stack:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == serial:
                break
        normalized = tuple(sorted(component))
        if len(normalized) > 1:
            components.append(normalized)

    for serial in sorted(flow_graph.blocks):
        if serial not in indexes:
            _strongconnect(serial)

    return tuple(sorted(components))


def _compute_backedges(flow_graph: FlowGraph) -> tuple[tuple[int, int], ...]:
    visited: set[int] = set()
    active: set[int] = set()
    backedges: set[tuple[int, int]] = set()

    def _walk(serial: int) -> None:
        visited.add(serial)
        active.add(serial)
        for succ in flow_graph.successors(serial):
            if succ not in flow_graph.blocks:
                continue
            if succ in active:
                backedges.add((serial, succ))
                continue
            if succ not in visited:
                _walk(succ)
        active.remove(serial)

    if flow_graph.entry_serial in flow_graph.blocks:
        _walk(flow_graph.entry_serial)
    return tuple(sorted(backedges))


def _summarize_cfg_shape(
    flow_graph: FlowGraph,
    *,
    payload_signatures: tuple[tuple[str, ...], ...] = (),
) -> dict[str, object]:
    payload_blocks: dict[tuple[str, ...], tuple[int, ...]] = {}
    for payload in payload_signatures:
        matched: list[int] = []
        for serial, block in flow_graph.blocks.items():
            block_signature = _payload_signature_from_instructions(block.insn_snapshots)
            if payload and payload == block_signature:
                matched.append(int(serial))
        payload_blocks[payload] = tuple(sorted(matched))

    return {
        "block_count": len(flow_graph.blocks),
        "edge_count": sum(len(block.succs) for block in flow_graph.blocks.values()),
        "nontrivial_sccs": _compute_nontrivial_sccs(flow_graph),
        "backedges": _compute_backedges(flow_graph),
        "payload_blocks": payload_blocks,
    }


_APPROOV_MULTISTATE_PHASE_STATES = {
    "phase1_header": 0xF6A1F,
    "phase1_update": 0xF6A1E,
    "phase2_multiply": 0xF6A20,
    "phase_exit": 0xF6A25,
}


def _record_attr(record, name: str):
    if isinstance(record, dict):
        return record[name]
    return getattr(record, name)


def _approov_multistate_phase_role(record) -> str:
    state_signature = tuple(int(value) for value in _record_attr(record, "state_signature"))
    if state_signature == (_APPROOV_MULTISTATE_PHASE_STATES["phase1_header"],):
        return "phase1_header"
    if state_signature == (_APPROOV_MULTISTATE_PHASE_STATES["phase1_update"],):
        return "phase1_update"
    if state_signature == (_APPROOV_MULTISTATE_PHASE_STATES["phase2_multiply"],):
        return "phase2_multiply"
    if state_signature == (_APPROOV_MULTISTATE_PHASE_STATES["phase_exit"],):
        return "phase_exit"
    return f"unknown:{state_signature!r}"


def _summarize_approov_multistate_phase_roles(records) -> dict[str, tuple[tuple[int, int, tuple[str, ...]], ...]]:
    grouped: dict[str, list[tuple[int, int, tuple[str, ...]]]] = {}
    for record in records:
        role = _approov_multistate_phase_role(record)
        grouped.setdefault(role, []).append(
            (
                int(_record_attr(record, "father_serial")),
                int(_record_attr(record, "target_serial")),
                tuple(str(kind) for kind in _record_attr(record, "selected_modification_kinds")),
            )
        )
    return {
        role: tuple(sorted(entries))
        for role, entries in sorted(grouped.items())
    }


def _build_approov_multistate_phase_cycle(role_map: dict[str, tuple[tuple[int, int, tuple[str, ...]], ...]]) -> PhaseCycleLowering:
    header_entries = tuple(entry[0] for entry in role_map["phase1_header"])
    body_entries = tuple(entry[0] for entry in role_map["phase1_update"])
    next_phase_entries = tuple(entry[0] for entry in role_map["phase2_multiply"])
    terminal_entries = tuple(entry[0] for entry in role_map["phase_exit"])
    return PhaseCycleLowering(
        header_entries=header_entries,
        header_target=role_map["phase1_header"][0][1],
        body_entries=body_entries,
        body_target=role_map["phase1_update"][0][1],
        next_phase_entries=next_phase_entries,
        next_phase_target=role_map["phase2_multiply"][0][1],
        terminal_entries=terminal_entries,
        terminal_target=role_map["phase_exit"][0][1] if terminal_entries else None,
        state_roles=(
            ("phase1_header", _APPROOV_MULTISTATE_PHASE_STATES["phase1_header"]),
            ("phase1_update", _APPROOV_MULTISTATE_PHASE_STATES["phase1_update"]),
            ("phase2_multiply", _APPROOV_MULTISTATE_PHASE_STATES["phase2_multiply"]),
            ("phase_exit", _APPROOV_MULTISTATE_PHASE_STATES["phase_exit"]),
        ),
    )


def test_emulated_dispatcher_family_detect_reports_dispatcher_cache_collector_gap(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    analysis = SimpleNamespace(
        dispatchers=[7, 9],
        state_constants={0xF6A1E, 0xF6A1F},
        dispatcher_type=SimpleNamespace(name="UNKNOWN"),
    )
    cache = SimpleNamespace(analyze=lambda: analysis)

    class _Collector:
        def __init__(self):
            self._items = ()

        def get_dispatcher_list(self):
            return list(self._items)

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.OllvmDispatcherCollector",
        _Collector,
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(
            lift=lambda _mba: _flow_graph_with_conditional_shape()
        )
    )
    detection = family.detect(mba)

    assert detection.detected is True
    assert detection.analysis_dispatchers == (7, 9)
    assert detection.collector_dispatcher_entries == ()
    assert detection.dispatcher_shape == "unknown"
    assert detection.state_transport == "father_history_emulation"
    assert detection.lowering_mode == "generic_graph_modifications"
    assert detection.provenance_hints == ()
    assert detection.planning_blocker == "dispatcher_cache_detected_but_collector_found_none"


def test_emulated_dispatcher_family_build_snapshot_attaches_observation_metadata(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: _flow_graph_with_edge())
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3, 5),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E, 0xF6A1F),
        collector_dispatcher_entries=(),
        planning_blocker="dispatcher_cache_detected_but_collector_found_none",
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)

    assert snapshot.dispatcher_cache is cache
    assert snapshot.state_summary == StateModelSummary(
        state_constants=frozenset({0xF6A1E, 0xF6A1F}),
        handler_count=2,
        transition_count=0,
    )
    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3, 5),
        state_constants=(0xF6A1E, 0xF6A1F),
        collector_dispatchers=(),
        planning_ready=False,
        planning_blocker="dispatcher_cache_detected_but_collector_found_none",
        candidate_count=0,
        rejected_fathers=0,
        candidate_kinds=(),
        rejection_reasons=(),
        selected_lowering_mode="generic_graph_modifications",
    )


def test_emulated_dispatcher_family_build_snapshot_attaches_lowering_candidates(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(lift=lambda _mba: _flow_graph_with_edge())
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda _mba, _det, *, flow_graph: (
            (RedirectGoto(from_serial=0, old_target=1, new_target=1),),
            ("dispatcher_source_shape_not_lowered",),
            (),
        ),
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E,),
        collector_dispatcher_entries=(2,),
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3,),
        state_constants=(0xF6A1E,),
        collector_dispatchers=(2,),
        planning_ready=False,
        planning_blocker="dispatcher_source_shape_not_lowered",
        candidate_count=1,
        rejected_fathers=1,
        candidate_kinds=("RedirectGoto",),
        rejection_reasons=("dispatcher_source_shape_not_lowered",),
        selected_lowering_mode="generic_graph_modifications",
        selected_modification_count=1,
    )
    assert modifications == (
        RedirectGoto(from_serial=0, old_target=1, new_target=1),
    )
    assert snapshot.flow_graph.metadata[EMULATED_DISPATCHER_MODIFICATIONS_KEY] == modifications


def test_emulated_dispatcher_family_build_snapshot_keeps_safe_conditional_target_candidate(
    monkeypatch,
) -> None:
    mba = _fake_mba()
    cache = object()
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.DispatcherCache",
        SimpleNamespace(get_or_create=lambda _mba: cache),
    )

    family = EmulatedDispatcherStrategyFamily(
        cfg_translator=SimpleNamespace(
            lift=lambda _mba: _flow_graph_with_conditional_shape()
        )
    )
    monkeypatch.setattr(
        family,
        "_collect_lowering_candidates",
        lambda _mba, _det, *, flow_graph: (
            (
                CreateConditionalRedirect(
                    source_block=0,
                    ref_block=1,
                    conditional_target=2,
                    fallthrough_target=3,
                ),
            ),
            (),
            (),
        ),
    )
    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(3,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        state_constants=(0xF6A1E,),
        collector_dispatcher_entries=(2,),
    )

    snapshot = family.build_snapshot(mba, detection)
    observation = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
    modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)

    assert observation == EmulatedDispatcherMetadata(
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        analysis_dispatchers=(3,),
        state_constants=(0xF6A1E,),
        collector_dispatchers=(2,),
        planning_ready=True,
        planning_blocker=None,
        candidate_count=1,
        rejected_fathers=0,
        candidate_kinds=("CreateConditionalRedirect",),
        rejection_reasons=(),
        selected_lowering_mode="generic_graph_modifications",
        selected_modification_count=1,
    )
    assert modifications == (
        CreateConditionalRedirect(
            source_block=0,
            ref_block=1,
            conditional_target=2,
            fallthrough_target=3,
        ),
    )


def test_emulated_dispatcher_family_inserts_safe_copies_before_conditional_target(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily()
    safe_insn = SimpleNamespace(opcode=ida_hexrays.m_mov, name="safe")
    histories = (object(),)
    resolver = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_GLBOPT2),
        get_dispatcher_father_histories=lambda *_args: histories,
        check_if_histories_are_resolved=lambda _histories: True,
        _filter_dependency_safe_copies=lambda _father, insns: list(insns),
    )
    dispatcher_father = SimpleNamespace(
        serial=9,
        nsucc=lambda: 1,
        succ=lambda _idx: 4,
    )
    target_blk = SimpleNamespace(
        serial=1,
        nsucc=lambda: 2,
        tail=SimpleNamespace(opcode=ida_hexrays.m_jnz, d=SimpleNamespace(b=2)),
        nextb=SimpleNamespace(serial=3),
    )
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(serial=7, use_before_def_list=()),
        emulate_dispatcher_with_father_history=lambda _history, resolve_conditional_exits=True: (
            target_blk,
            [safe_insn],
        ),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.get_all_possibles_values",
        lambda _histories, _use_before_def_list, verbose=False: [[0xF6A20]],
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.check_if_all_values_are_found",
        lambda _values: True,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.capture_insn_snapshot",
        lambda insn: f"snap:{insn.name}",
    )

    candidate, reason, _record = family._build_lowering_candidate(
        resolver,
        dispatcher_father,
        dispatcher_info,
        scc_memberships={},
    )

    assert reason is None
    assert candidate == (
        InsertBlock(
            pred_serial=9,
            succ_serial=1,
            instructions=("snap:safe",),
            old_target_serial=4,
        ),
    )


def test_emulated_dispatcher_family_reuses_deferred_side_effects_after_calls(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily()
    safe_insn = SimpleNamespace(opcode=ida_hexrays.m_mov, name="safe")
    histories = (object(),)
    dispatcher_info = SimpleNamespace(
        entry_block=SimpleNamespace(serial=7, use_before_def_list=()),
    )
    dispatcher_father = SimpleNamespace(
        serial=9,
        nsucc=lambda: 1,
        succ=lambda _idx: 4,
    )
    target_blk = SimpleNamespace(
        serial=1,
        nsucc=lambda: 1,
        tail=None,
        nextb=None,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.get_all_possibles_values",
        lambda _histories, _use_before_def_list, verbose=False: [[0xF6A20]],
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.check_if_all_values_are_found",
        lambda _values: True,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.capture_insn_snapshot",
        lambda insn: f"snap:{insn.name}",
    )

    resolver_calls = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_CALLS),
        get_dispatcher_father_histories=lambda *_args: histories,
        check_if_histories_are_resolved=lambda _histories: True,
        _filter_dependency_safe_copies=lambda _father, insns: list(insns),
    )
    dispatcher_info.emulate_dispatcher_with_father_history = (
        lambda _history, resolve_conditional_exits=True: (target_blk, [safe_insn])
    )

    candidate, reason, _record = family._build_lowering_candidate(
        resolver_calls,
        dispatcher_father,
        dispatcher_info,
        scc_memberships={},
    )

    assert candidate is None
    assert reason == "dispatcher_side_effects_deferred_to_later_maturity"

    resolver_glbopt = SimpleNamespace(
        mba=SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_GLBOPT2),
        get_dispatcher_father_histories=lambda *_args: histories,
        check_if_histories_are_resolved=lambda _histories: True,
        _filter_dependency_safe_copies=lambda _father, insns: list(insns),
    )
    dispatcher_info.emulate_dispatcher_with_father_history = (
        lambda _history, resolve_conditional_exits=True: (target_blk, [])
    )

    candidate, reason, _record = family._build_lowering_candidate(
        resolver_glbopt,
        dispatcher_father,
        dispatcher_info,
        scc_memberships={},
    )

    assert reason is None
    assert candidate == (
        InsertBlock(
            pred_serial=9,
            succ_serial=1,
            instructions=("snap:safe",),
            old_target_serial=4,
        ),
    )


def test_emulated_dispatcher_unflattener_records_no_plan_provenance(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    outcomes: list[object] = []
    rule.set_flow_context(
        SimpleNamespace(report_outcome=lambda provenance, source: outcomes.append((provenance, source)))
    )

    detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(7,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        planning_blocker="dispatcher_cache_detected_but_collector_found_none",
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(),
                    planning_ready=False,
                    planning_blocker="dispatcher_cache_detected_but_collector_found_none",
                    candidate_count=0,
                    rejected_fathers=0,
                    candidate_kinds=(),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(rule._family, "detect", lambda _mba: detection)
    monkeypatch.setattr(rule._family, "build_snapshot", lambda _mba, _det: snapshot)

    assert rule.optimize(blk) == 0
    assert rule._last_provenance is not None
    assert {row.strategy_name for row in rule._last_provenance.rows} == {
        "dispatcher_loop_recovery",
        "emulated_dispatcher",
    }
    row = next(
        row
        for row in rule._last_provenance.rows
        if row.strategy_name == "emulated_dispatcher"
    )
    assert row.strategy_name == "emulated_dispatcher"
    assert row.phase == DecisionPhase.INAPPLICABLE
    assert row.reason_code == DecisionReasonCode.REJECTED_INAPPLICABLE
    assert outcomes == [(rule._last_provenance, "planner")]
    assert rule.get_last_observation()["snapshot"] == {
        "dispatcher_shape": "unknown",
        "state_transport": "father_history_emulation",
        "lowering_mode": "generic_graph_modifications",
        "provenance_hints": (),
        "analysis_dispatchers": (7,),
        "state_constants": (),
        "collector_dispatchers": (),
        "planning_ready": False,
        "planning_blocker": "dispatcher_cache_detected_but_collector_found_none",
        "candidate_count": 0,
        "rejected_fathers": 0,
        "candidate_kinds": (),
        "rejection_reasons": (),
        "candidate_records": (),
        "phase_artifact": None,
        "selected_lowering_mode": None,
        "selected_modification_count": 0,
        "loop_recovery_modification_count": 0,
    }


def test_emulated_dispatcher_strategy_plans_validated_snapshot_modifications() -> None:
    strategy = EmulatedDispatcherStrategy()
    snapshot = AnalysisSnapshot(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1, entry_ea=0x401000),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("RedirectGoto",),
                    rejection_reasons=(),
                ),
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                    RedirectGoto(from_serial=0, old_target=1, new_target=1),
                ),
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    fragment = strategy.plan(snapshot)

    assert fragment is not None
    assert fragment.strategy_name == "emulated_dispatcher"
    assert fragment.metadata["safeguard_min_required"] == 1
    assert fragment.modifications == [
        RedirectGoto(from_serial=0, old_target=1, new_target=1),
    ]


def test_emulated_dispatcher_strategy_rejects_partial_lowering_when_blockers_exist() -> None:
    graph = FlowGraph(
        blocks=_flow_graph_with_edge().blocks,
        entry_serial=0,
        func_ea=0x401000,
        metadata={
            EMULATED_DISPATCHER_METADATA_KEY: EmulatedDispatcherMetadata(
                dispatcher_shape="unknown",
                state_transport="father_history_emulation",
                lowering_mode="generic_graph_modifications",
                provenance_hints=(),
                analysis_dispatchers=(7,),
                collector_dispatchers=(2,),
                planning_ready=False,
                planning_blocker="dispatcher_history_missing_values",
                candidate_count=1,
                rejected_fathers=1,
                candidate_kinds=("RedirectGoto",),
                rejection_reasons=("dispatcher_history_missing_values",),
            ),
            EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                RedirectGoto(from_serial=0, old_target=1, new_target=1),
            ),
        },
    )
    snapshot = AnalysisSnapshot(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT1),
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=graph,
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    strategy = EmulatedDispatcherStrategy()
    assert strategy.is_applicable(snapshot) is False
    assert strategy.plan(snapshot) is None


def test_emulated_dispatcher_unflattener_counts_family_post_execute_cleanup(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("RedirectGoto",),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(
        rule._family,
        "detect",
        lambda _mba: EmulatedDispatcherDetection(
            analysis_dispatchers=(7,),
            dispatcher_shape="unknown",
            state_transport="father_history_emulation",
            lowering_mode="generic_graph_modifications",
            provenance_hints=(),
        ),
    )
    monkeypatch.setattr(rule._family, "build_snapshot", lambda _mba, _det: snapshot)
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine.plan_family_pipeline",
        lambda *args, **kwargs: PlannedPipeline(
            pipeline=[object()],
            provenance=PipelineProvenance(),
        ),
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine.execute_family_pipeline",
        lambda *args, **kwargs: ExecutedPipeline(
            pipeline=[object()],
            results=[],
            provenance=PipelineProvenance(),
            total_changes=2,
            executor=None,
        ),
    )
    monkeypatch.setattr(
        rule._family,
        "post_execute_cleanup",
        lambda _mba, *, snapshot, total_changes: 3,
    )

    assert rule.optimize(blk) == 5


def test_emulated_dispatcher_family_skips_deep_cleaning_for_insert_block(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily()
    calls: list[tuple[str, object]] = []
    mba = SimpleNamespace(
        mark_chains_dirty=lambda: calls.append(("mark", None)),
        optimize_local=lambda _arg: calls.append(("optimize_local", _arg)),
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_edge().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                EMULATED_DISPATCHER_METADATA_KEY: EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("InsertBlock",),
                    rejection_reasons=(),
                ),
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                    InsertBlock(
                        pred_serial=0,
                        succ_serial=2,
                        old_target_serial=1,
                        instructions=("snap:safe",),
                    ),
                ),
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.mba_deep_cleaning",
        lambda _mba, _final: calls.append(("deep_clean", None)) or 0,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.safe_verify",
        lambda _mba, context, logger_func=None: calls.append(("verify", context)),
    )

    assert family.post_execute_cleanup(mba, snapshot=snapshot, total_changes=1) == 0
    assert calls == [
        ("mark", None),
        (
            "verify",
            "verifying EmulatedDispatcherUnflattener.optimize after deferred edge-split apply",
        ),
    ]


def test_emulated_dispatcher_family_skips_deep_cleaning_for_conditional_redirect(
    monkeypatch,
) -> None:
    family = EmulatedDispatcherStrategyFamily()
    calls: list[tuple[str, object]] = []
    mba = SimpleNamespace(
        mark_chains_dirty=lambda: calls.append(("mark", None)),
        optimize_local=lambda _arg: calls.append(("optimize_local", _arg)),
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph_with_conditional_shape().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                EMULATED_DISPATCHER_METADATA_KEY: EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(7,),
                    collector_dispatchers=(2,),
                    planning_ready=True,
                    planning_blocker=None,
                    candidate_count=1,
                    rejected_fathers=0,
                    candidate_kinds=("CreateConditionalRedirect",),
                    rejection_reasons=(),
                ),
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: (
                    CreateConditionalRedirect(
                        source_block=0,
                        ref_block=1,
                        conditional_target=2,
                        fallthrough_target=3,
                        instructions=("snap:safe",),
                    ),
                ),
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=1,
            transition_count=0,
        ),
    )

    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.mba_deep_cleaning",
        lambda _mba, _final: calls.append(("deep_clean", None)) or 0,
    )
    monkeypatch.setattr(
        "d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family.safe_verify",
        lambda _mba, context, logger_func=None: calls.append(("verify", context)),
    )

    assert family.post_execute_cleanup(mba, snapshot=snapshot, total_changes=1) == 0
    assert calls == [
        ("mark", None),
        (
            "verify",
            "verifying EmulatedDispatcherUnflattener.optimize after deferred edge-split apply",
        ),
    ]


def test_emulated_dispatcher_unflattener_builds_snapshot_from_detection(
    monkeypatch,
) -> None:
    rule = EmulatedDispatcherUnflattener()
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_GLBOPT1,
        entry_ea=0x401000,
    )
    blk = SimpleNamespace(serial=0, mba=mba)
    initial_detection = EmulatedDispatcherDetection(
        analysis_dispatchers=(2,),
        dispatcher_shape="unknown",
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        collector_dispatcher_entries=(2,),
    )
    snapshot = AnalysisSnapshot(
        mba=mba,
        maturity=ida_hexrays.MMAT_GLBOPT1,
        flow_graph=FlowGraph(
            blocks=_flow_graph().blocks,
            entry_serial=0,
            func_ea=0x401000,
            metadata={
                "emulated_dispatcher": EmulatedDispatcherMetadata(
                    dispatcher_shape="unknown",
                    state_transport="father_history_emulation",
                    lowering_mode="generic_graph_modifications",
                    provenance_hints=(),
                    analysis_dispatchers=(2, 3),
                    collector_dispatchers=(2,),
                    planning_ready=False,
                    planning_blocker="dispatcher_cache_detected_but_collector_found_none",
                    candidate_count=0,
                    rejected_fathers=0,
                    candidate_kinds=(),
                    rejection_reasons=(),
                )
            },
        ),
        state_summary=StateModelSummary(
            state_constants=frozenset(),
            handler_count=2,
            transition_count=0,
        ),
    )
    build_inputs = []

    monkeypatch.setattr(rule._family, "detect", lambda _mba: initial_detection)
    monkeypatch.setattr(
        rule._family,
        "build_snapshot",
        lambda _mba, detection: build_inputs.append(detection) or snapshot,
    )

    assert rule.optimize(blk) == 0
    assert build_inputs == [initial_detection]


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestEmulatedDispatcherManagedContext:
    binary_name = _get_default_binary()

    def test_approov_real_pattern_post_apply_dump_preserves_verify_in_managed_context(
        self,
        libobfuscated_setup,
        d810_state,
        monkeypatch,
    ) -> None:
        import d810.cfg.contracts.transaction_engine as tx_engine_mod
        import d810.optimizers.microcode.flow.flattening.engine.executor as executor_mod
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod
        import d810.hexrays.mutation.ir_translator as ir_translator_mod

        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_real_pattern' not found")

        observed: dict[str, object] = {}
        checkpoints: list[tuple[str, str | None]] = []
        original_tx_apply = tx_engine_mod.CfgTransactionEngine.apply
        original_dump = executor_mod.mba_to_human_readable
        original_execute = engine_mod.execute_family_pipeline
        original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup
        original_lift = ir_translator_mod.IDAIRTranslator.lift
        original_terminal_audit = executor_mod.TransactionalExecutor._run_terminal_return_audit

        def _wrapped_tx_apply(self, *args, **kwargs):
            result = original_tx_apply(self, *args, **kwargs)
            mba = kwargs["mba"]
            observed["transaction_success"] = result.success
            observed["verify_error_after_transaction_apply"] = _verify_error(mba)
            return result

        def _wrapped_dump(mba):
            rendered = original_dump(mba)
            checkpoints.append(("after_post_apply_dump", _verify_error(mba)))
            return rendered

        def _wrapped_lift(self, mba):
            lifted = original_lift(self, mba)
            checkpoints.append(("after_translator_lift", _verify_error(mba)))
            return lifted

        def _wrapped_terminal_audit(self, fragment, pre_cfg, result):
            out = original_terminal_audit(self, fragment, pre_cfg, result)
            checkpoints.append(("after_terminal_return_audit", _verify_error(self.mba)))
            return out

        def _wrapped_execute(*args, **kwargs):
            executed = original_execute(*args, **kwargs)
            snapshot = args[0]
            observed["verify_error_after_execute"] = _verify_error(snapshot.mba)
            observed["total_changes_after_execute"] = executed.total_changes
            return executed

        def _wrapped_cleanup(self, mba, *, snapshot, total_changes):
            observed["verify_error_before_cleanup"] = _verify_error(mba)
            observed["cleanup_total_changes"] = total_changes
            return original_cleanup(self, mba, snapshot=snapshot, total_changes=total_changes)

        monkeypatch.setattr(tx_engine_mod.CfgTransactionEngine, "apply", _wrapped_tx_apply)
        monkeypatch.setattr(executor_mod, "mba_to_human_readable", _wrapped_dump)
        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
        monkeypatch.setattr(ir_translator_mod.IDAIRTranslator, "lift", _wrapped_lift)
        monkeypatch.setattr(
            executor_mod.TransactionalExecutor,
            "_run_terminal_return_audit",
            _wrapped_terminal_audit,
        )
        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "post_execute_cleanup",
            _wrapped_cleanup,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        assert observed["transaction_success"] is True
        assert observed["verify_error_after_transaction_apply"] is None
        assert observed["total_changes_after_execute"] == 3
        assert observed["cleanup_total_changes"] == 3
        assert observed["verify_error_after_execute"] is None
        assert observed["verify_error_before_cleanup"] is None
        assert checkpoints
        first_bad = next((entry for entry in checkpoints if entry[1] is not None), None)
        assert first_bad is None

    def test_approov_real_pattern_stays_verify_clean_before_cleanup_when_post_apply_dump_is_disabled(
        self,
        libobfuscated_setup,
        d810_state,
        monkeypatch,
    ) -> None:
        import d810.cfg.contracts.transaction_engine as tx_engine_mod
        import d810.optimizers.microcode.flow.flattening.engine.executor as executor_mod
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

        func_ea = get_func_ea("approov_real_pattern")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_real_pattern' not found")

        observed: dict[str, object] = {}
        original_tx_apply = tx_engine_mod.CfgTransactionEngine.apply
        original_execute = engine_mod.execute_family_pipeline
        original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup

        def _wrapped_tx_apply(self, *args, **kwargs):
            result = original_tx_apply(self, *args, **kwargs)
            observed["verify_error_after_transaction_apply"] = _verify_error(kwargs["mba"])
            return result

        def _wrapped_execute(*args, **kwargs):
            executed = original_execute(*args, **kwargs)
            observed["verify_error_after_execute"] = _verify_error(args[0].mba)
            observed["total_changes_after_execute"] = executed.total_changes
            return executed

        def _wrapped_cleanup(self, mba, *, snapshot, total_changes):
            observed["verify_error_before_cleanup"] = _verify_error(mba)
            observed["cleanup_total_changes"] = total_changes
            return original_cleanup(self, mba, snapshot=snapshot, total_changes=total_changes)

        monkeypatch.setattr(tx_engine_mod.CfgTransactionEngine, "apply", _wrapped_tx_apply)
        monkeypatch.setattr(executor_mod, "mba_to_human_readable", lambda _mba: [])
        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "post_execute_cleanup",
            _wrapped_cleanup,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        assert observed["verify_error_after_transaction_apply"] is None
        assert observed["total_changes_after_execute"] == 3
        assert observed["verify_error_after_execute"] is None
        assert observed["verify_error_before_cleanup"] is None

    def test_approov_multistate_managed_context_captures_failure_checkpoint(
        self,
        libobfuscated_setup,
        d810_state,
        monkeypatch,
    ) -> None:
        import d810.cfg.contracts.transaction_engine as tx_engine_mod
        import d810.optimizers.microcode.flow.flattening.engine.executor as executor_mod
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod
        import d810.hexrays.mutation.ir_translator as ir_translator_mod

        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        observed: dict[str, object] = {}
        checkpoints: list[tuple[str, str | None]] = []
        original_tx_apply = tx_engine_mod.CfgTransactionEngine.apply
        original_dump = executor_mod.mba_to_human_readable
        original_execute = engine_mod.execute_family_pipeline
        original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup
        original_lift = ir_translator_mod.IDAIRTranslator.lift
        original_terminal_audit = executor_mod.TransactionalExecutor._run_terminal_return_audit

        def _wrapped_tx_apply(self, *args, **kwargs):
            result = original_tx_apply(self, *args, **kwargs)
            mba = kwargs["mba"]
            observed["transaction_success"] = result.success
            observed["transaction_failure_phase"] = result.failure_phase
            observed["transaction_failure_detail"] = result.failure_detail
            observed["transaction_error"] = str(result.error) if result.error else None
            observed["verify_error_after_transaction_apply"] = _verify_error(mba)
            return result

        def _wrapped_dump(mba):
            rendered = original_dump(mba)
            checkpoints.append(("after_post_apply_dump", _verify_error(mba)))
            return rendered

        def _wrapped_lift(self, mba):
            lifted = original_lift(self, mba)
            checkpoints.append(("after_translator_lift", _verify_error(mba)))
            return lifted

        def _wrapped_terminal_audit(self, fragment, pre_cfg, result):
            out = original_terminal_audit(self, fragment, pre_cfg, result)
            checkpoints.append(("after_terminal_return_audit", _verify_error(self.mba)))
            return out

        def _wrapped_execute(*args, **kwargs):
            executed = original_execute(*args, **kwargs)
            snapshot = args[0]
            observed["verify_error_after_execute"] = _verify_error(snapshot.mba)
            observed["total_changes_after_execute"] = executed.total_changes
            return executed

        def _wrapped_cleanup(self, mba, *, snapshot, total_changes):
            observed["verify_error_before_cleanup"] = _verify_error(mba)
            observed["cleanup_total_changes"] = total_changes
            return original_cleanup(self, mba, snapshot=snapshot, total_changes=total_changes)

        monkeypatch.setattr(tx_engine_mod.CfgTransactionEngine, "apply", _wrapped_tx_apply)
        monkeypatch.setattr(executor_mod, "mba_to_human_readable", _wrapped_dump)
        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
        monkeypatch.setattr(ir_translator_mod.IDAIRTranslator, "lift", _wrapped_lift)
        monkeypatch.setattr(
            executor_mod.TransactionalExecutor,
            "_run_terminal_return_audit",
            _wrapped_terminal_audit,
        )
        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "post_execute_cleanup",
            _wrapped_cleanup,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(state, ctx, func_ea)
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        print("APPROOV_MULTISTATE_MANAGED observed=", observed)
        print("APPROOV_MULTISTATE_MANAGED checkpoints=", checkpoints)

        assert "transaction_success" in observed

    def test_approov_multistate_records_candidate_batch_for_triage(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

        def _wrapped_build_snapshot(self, mba, detection):
            snapshot = original_build_snapshot(self, mba, detection)
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
            if metadata is not None and metadata.candidate_count > int(
                captured.get("candidate_count", -1)
            ):
                captured["candidate_count"] = metadata.candidate_count
                captured["snapshot"] = asdict(metadata)
                captured["candidate_records"] = tuple(asdict(record) for record in records)
            return snapshot

        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "build_snapshot",
            _wrapped_build_snapshot,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                dispatcher_rule = next(
                    (
                        rule
                        for rule in ctx.active_blk_rules
                        if type(rule).__name__ == "EmulatedDispatcherUnflattener"
                    ),
                    None,
                )
                assert dispatcher_rule is not None
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        snapshot = captured["snapshot"]
        candidate_records = captured["candidate_records"]
        selected_indexes = tuple(
            sorted(
                {
                    idx
                    for record in candidate_records
                    for idx in record["selected_modification_indexes"]
                }
            )
        )
        print("APPROOV_MULTISTATE_CANDIDATE_RECORDS", candidate_records)
        assert snapshot["candidate_count"] == len(candidate_records) == 6
        assert snapshot["selected_modification_count"] >= len(selected_indexes) == 6
        assert snapshot["rejected_fathers"] == 0
        assert snapshot["selected_lowering_mode"] in {
            "generic_graph_modifications",
            "dispatcher_loop_recovery",
        }
        assert selected_indexes == tuple(range(snapshot["candidate_count"]))
        if snapshot["selected_lowering_mode"] == "dispatcher_loop_recovery":
            assert snapshot["selected_modification_count"] == 9
            assert set(snapshot["candidate_kinds"]) == {
                "ZeroStateWrite",
                "RedirectGoto",
                "RedirectBranch",
            }

    def test_approov_multistate_captures_phase_artifact(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

        def _wrapped_build_snapshot(self, mba, detection):
            snapshot = original_build_snapshot(self, mba, detection)
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            artifact = extract_emulated_dispatcher_phase_artifact(snapshot.flow_graph)
            if (
                metadata is not None
                and artifact is not None
                and metadata.candidate_count > int(captured.get("candidate_count", -1))
            ):
                captured["candidate_count"] = metadata.candidate_count
                captured["phase_artifact"] = asdict(artifact)
            return snapshot

        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "build_snapshot",
            _wrapped_build_snapshot,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        artifact = captured["phase_artifact"]
        print("APPROOV_MULTISTATE_PHASE_ARTIFACT", artifact)

        assert artifact["dispatcher_entry_serial"] == 3
        assert artifact["pre_header_serial"] == 6
        assert artifact["initial_state"] == 0xF6A1F
        handler_state_map = dict(artifact["handler_state_map"])
        assert set(handler_state_map.values()) == {0xF6A1E, 0xF6A1F, 0xF6A25}
        assert handler_state_map[5] == 0xF6A1E
        assert handler_state_map[9] == 0xF6A1F
        assert artifact["dag_node_count"] == 6
        assert artifact["dag_edge_count"] == 13
        assert artifact["semantic_reference_variant"] == "semantic_reference_like"
        assert artifact["semantic_reference_line_count"] >= 30
        assert artifact["semantic_reference_node_count"] == 6
        assert "STATE_000F6A1F:" in artifact["semantic_reference_program"]
        assert "STATE_000F6A1E:" in artifact["semantic_reference_program"]
        # The rendered reference program may canonicalize range/anonymous
        # entries to STATE_00000000, but the structured labels retain the
        # recovered state identity. Assert the stable structured contract here.
        assert "0x000F6A20" in artifact["semantic_state_labels"]
        assert "goto STATE_000F6A1E;" in artifact["semantic_reference_program"]
        assert "goto STATE_000F6A1F;" in artifact["semantic_reference_program"]

    def test_approov_vm_dispatcher_keeps_loop_recovery_disabled_without_phase_contract(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        func_ea = get_func_ea("approov_vm_dispatcher")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_vm_dispatcher' not found")

        captured: dict[str, object] = {}
        original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

        def _wrapped_build_snapshot(self, mba, detection):
            snapshot = original_build_snapshot(self, mba, detection)
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            if (
                metadata is not None
                and metadata.candidate_count >= int(captured.get("candidate_count", -1))
            ):
                captured["candidate_count"] = metadata.candidate_count
                captured["snapshot"] = asdict(metadata)
            return snapshot

        monkeypatch.setattr(
            EmulatedDispatcherStrategyFamily,
            "build_snapshot",
            _wrapped_build_snapshot,
        )

        with d810_state() as state:
            state.stop_d810()
            project_name = "default_unflattening_approov.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        snapshot = captured["snapshot"]
        assert snapshot["candidate_count"] > 0
        assert snapshot["selected_lowering_mode"] == "generic_graph_modifications"
        assert snapshot["loop_recovery_modification_count"] == 0
        assert snapshot["planning_ready"] is False

    def test_dispatcher_loop_recovery_guard_rejects_returning_fallback_artifact(
        self,
    ) -> None:
        family = EmulatedDispatcherStrategyFamily()
        artifact = EmulatedDispatcherPhaseArtifact(
            dispatcher_entry_serial=3,
            state_var_stkoff=4,
            pre_header_serial=11,
            initial_state=0xF6A20,
            bst_node_blocks=(3, 4, 6),
            handler_state_map=((5, 0xF6A20), (7, 0xF6A1F), (12, 0xF6A25)),
            handler_range_map=((5, 0, 0xFFFFFFFF), (7, 0, 0xFFFFFFFF), (11, 0xF6A26, 0xFFFFFFFF)),
            transition_rows=3,
            dag_node_count=6,
            dag_edge_count=11,
            semantic_state_labels=(
                "0x00000000",
                "0x000F6A1F",
                "0x000F6A20",
                "0x000F6A21",
                "0x000F6A25",
                "0x000F6A25_fallback",
            ),
            semantic_reference_variant="semantic_reference_like",
            semantic_reference_line_count=32,
            semantic_reference_node_count=9,
            semantic_reference_program=(
                "STATE_000F6A1F:\\n"
                "    return result;\\n"
                "STATE_000F6A25_fallback:\\n"
                "    goto STATE_000F6A20;\\n"
            ),
        )

        blockers = family._dispatcher_loop_recovery_artifact_blockers(artifact)
        assert blockers == ("dispatcher_loop_recovery_fallback_phase",)

    def test_approov_multistate_marks_cluster_candidates_with_strict_key(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_execute = engine_mod.execute_family_pipeline

        def _wrapped_execute(snapshot, planned, **kwargs):
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
            modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
            if metadata is not None and len(modifications) > int(
                captured.get("candidate_count", -1)
            ):
                captured["candidate_count"] = len(modifications)
                captured["candidate_records"] = tuple(asdict(record) for record in records)
            return original_execute(snapshot, planned, **kwargs)

        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        candidate_records = captured["candidate_records"]
        cluster_records = [
            record for record in candidate_records if record["cluster_candidate"]
        ]
        cluster_groups: dict[tuple[str, ...], list[int]] = {}
        for record in cluster_records:
            cluster_groups.setdefault(record["cluster_key"], []).append(
                record["father_serial"]
            )

        print(
            "APPROOV_MULTISTATE_CLUSTER_CANDIDATES",
            {
                "cluster_groups": {
                    key: tuple(sorted(value)) for key, value in cluster_groups.items()
                },
                "records": cluster_records,
            },
        )

        assert all(record["semantically_valid"] is True for record in candidate_records)
        assert all(
            record["structurally_legacy_equivalent"] is None
            for record in candidate_records
        )
        assert sorted(
            tuple(sorted(fathers)) for fathers in cluster_groups.values()
        ) == [(2, 6), (7, 11)]

    def test_approov_multistate_role_map_identifies_first_phase_unit(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_execute = engine_mod.execute_family_pipeline

        def _wrapped_execute(snapshot, planned, **kwargs):
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
            modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
            if metadata is not None and len(modifications) > int(
                captured.get("candidate_count", -1)
            ):
                captured["candidate_count"] = len(modifications)
                captured["candidate_records"] = tuple(asdict(record) for record in records)
            return original_execute(snapshot, planned, **kwargs)

        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        role_map = _summarize_approov_multistate_phase_roles(
            captured["candidate_records"]
        )

        print("APPROOV_MULTISTATE_PHASE_ROLE_MAP", role_map)

        assert role_map["phase1_header"] == (
            (2, 9, ("InsertBlock",)),
            (6, 9, ("InsertBlock",)),
        )
        assert role_map["phase1_update"] == (
            (10, 5, ("InsertBlock",)),
        )
        assert role_map["phase2_multiply"] == (
            (7, 12, ("InsertBlock",)),
            (11, 12, ("InsertBlock",)),
        )
        assert role_map["phase_exit"] == (
            (14, 15, ("RedirectGoto",)),
        )

    def test_approov_multistate_phase_cycle_contract(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        captured: dict[str, object] = {}
        original_execute = engine_mod.execute_family_pipeline

        def _wrapped_execute(snapshot, planned, **kwargs):
            metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
            records = extract_emulated_dispatcher_candidate_records(snapshot.flow_graph)
            modifications = extract_emulated_dispatcher_modifications(snapshot.flow_graph)
            if metadata is not None and len(modifications) > int(
                captured.get("candidate_count", -1)
            ):
                captured["candidate_count"] = len(modifications)
                captured["candidate_records"] = tuple(asdict(record) for record in records)
            return original_execute(snapshot, planned, **kwargs)

        monkeypatch.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    _ = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        role_map = _summarize_approov_multistate_phase_roles(
            captured["candidate_records"]
        )
        contract = _build_approov_multistate_phase_cycle(role_map)

        print("APPROOV_MULTISTATE_PHASE_CYCLE_CONTRACT", asdict(contract))

        assert contract == PhaseCycleLowering(
            header_entries=(2, 6),
            header_target=9,
            body_entries=(10,),
            body_target=5,
            next_phase_entries=(7, 11),
            next_phase_target=12,
            terminal_entries=(14,),
            terminal_target=15,
            state_roles=(
                ("phase1_header", 0xF6A1F),
                ("phase1_update", 0xF6A1E),
                ("phase2_multiply", 0xF6A20),
                ("phase_exit", 0xF6A25),
            ),
        )

    def test_approov_multistate_cluster_grouping_experiment(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for cluster grouping experiment"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_legacy() -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener as legacy_mod

            captured: dict[str, object] = {}
            original_optimize = legacy_mod.Unflattener.optimize

            def _wrapped_optimize(rule, blk):
                result = original_optimize(rule, blk)
                if getattr(blk.mba, "entry_ea", None) == func_ea:
                    captured["final_flow_graph"] = lift_mba(blk.mba)
                    captured["final_maturity"] = int(blk.mba.maturity)
                return result

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(
                    legacy_mod.Unflattener,
                    "optimize",
                    _wrapped_optimize,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=False,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        def _run_engine(*, clustered: bool) -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

            captured: dict[str, object] = {}
            original_execute = engine_mod.execute_family_pipeline
            original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup

            def _wrap_cleanup(self, mba, *, snapshot, total_changes):
                cleaned = original_cleanup(
                    self,
                    mba,
                    snapshot=snapshot,
                    total_changes=total_changes,
                )
                captured["final_flow_graph"] = lift_mba(mba)
                return cleaned

            def _clustered_execute(snapshot, planned, **kwargs):
                modifications = extract_emulated_dispatcher_modifications(
                    snapshot.flow_graph
                )
                records = extract_emulated_dispatcher_candidate_records(
                    snapshot.flow_graph
                )
                captured["candidate_records"] = tuple(asdict(record) for record in records)

                grouped: dict[tuple[str, ...], list[EmulatedDispatcherCandidateRecord]] = {}
                for record in records:
                    if record.cluster_candidate:
                        grouped.setdefault(record.cluster_key, []).append(record)

                modifier = DeferredGraphModifier(snapshot.mba)
                # create_standalone_block() inserts at the current stop-block
                # serial and shifts the stop block to the new tail.
                next_serial = int(snapshot.mba.qty) - 1
                consumed_indexes: set[int] = set()
                cluster_payloads: list[tuple[str, ...]] = []

                for cluster_key in sorted(grouped):
                    cluster = sorted(grouped[cluster_key], key=lambda item: item.father_serial)
                    anchor = cluster[0]
                    followers = cluster[1:]
                    anchor_index = anchor.selected_modification_indexes[0]
                    anchor_mod = modifications[anchor_index]
                    instructions = ()
                    if isinstance(anchor_mod, InsertBlock):
                        instructions = anchor_mod.instructions
                    elif isinstance(anchor_mod, RedirectGoto):
                        instructions = ()
                    else:
                        raise AssertionError(
                            f"Unexpected clustered modification in experiment: {anchor_mod}"
                        )
                    cluster_payloads.append(anchor.payload_signature)
                    modifier.queue_create_and_redirect(
                        source_block_serial=int(anchor.father_serial),
                        final_target_serial=int(anchor.target_serial),
                        instructions_to_copy=list(instructions),
                        expected_serial=next_serial,
                        description=f"cluster anchor {anchor.father_serial}->{anchor.target_serial}",
                    )
                    consumed_indexes.update(anchor.selected_modification_indexes)
                    for follower in followers:
                        modifier.queue_goto_change(
                            block_serial=int(follower.father_serial),
                            new_target=next_serial,
                            description=f"cluster follower {follower.father_serial}->{next_serial}",
                        )
                        consumed_indexes.update(follower.selected_modification_indexes)
                    next_serial += 1

                for record in records:
                    if any(idx in consumed_indexes for idx in record.selected_modification_indexes):
                        continue
                    idx = record.selected_modification_indexes[0]
                    mod = modifications[idx]
                    if isinstance(mod, InsertBlock):
                        modifier.queue_create_and_redirect(
                            source_block_serial=int(mod.pred_serial),
                            final_target_serial=int(mod.succ_serial),
                            instructions_to_copy=list(mod.instructions),
                            expected_serial=next_serial,
                            description=f"standalone insert {mod.pred_serial}->{mod.succ_serial}",
                        )
                        next_serial += 1
                    elif isinstance(mod, RedirectGoto):
                        modifier.queue_goto_change(
                            block_serial=int(mod.from_serial),
                            new_target=int(mod.new_target),
                            description=f"standalone redirect {mod.from_serial}->{mod.new_target}",
                        )
                    else:
                        raise AssertionError(f"Unexpected modification in experiment: {mod}")

                changes = modifier.apply(
                    run_optimize_local=True,
                    run_deep_cleaning=False,
                )
                captured["cluster_payloads"] = tuple(cluster_payloads)
                captured["post_execute_flow_graph"] = lift_mba(snapshot.mba)
                strategy_name = (
                    planned.pipeline[0].strategy_name
                    if planned.pipeline
                    else "emulated_dispatcher"
                )
                return ExecutedPipeline(
                    pipeline=planned.pipeline,
                    results=[
                        StageResult(
                            strategy_name=strategy_name,
                            edits_applied=changes,
                            success=True,
                        )
                    ],
                    provenance=planned.provenance,
                    total_changes=changes,
                    executor=None,
                )

            def _wrapped_execute(snapshot, planned, **kwargs):
                if not clustered:
                    executed = original_execute(snapshot, planned, **kwargs)
                    captured["candidate_records"] = tuple(
                        asdict(record)
                        for record in extract_emulated_dispatcher_candidate_records(
                            snapshot.flow_graph
                        )
                    )
                    captured["post_execute_flow_graph"] = lift_mba(snapshot.mba)
                    return executed
                return _clustered_execute(snapshot, planned, **kwargs)

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
                patch_ctx.setattr(
                    EmulatedDispatcherStrategyFamily,
                    "post_execute_cleanup",
                    _wrap_cleanup,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=True,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        legacy_code, legacy_capture = _run_legacy()
        current_code, current_capture = _run_engine(clustered=False)
        experimental_code, experimental_capture = _run_engine(clustered=True)

        current_payloads = tuple(
            tuple(record["payload_signature"])
            for record in current_capture["candidate_records"]
            if record["cluster_candidate"]
        )
        experimental_payloads = tuple(experimental_capture.get("cluster_payloads", ()))

        legacy_shape = _summarize_cfg_shape(legacy_capture["final_flow_graph"])
        current_shape = _summarize_cfg_shape(
            current_capture["final_flow_graph"],
            payload_signatures=current_payloads,
        )
        experimental_shape = _summarize_cfg_shape(
            experimental_capture["final_flow_graph"],
            payload_signatures=experimental_payloads,
        )

        summary = {
            "legacy_ast": code_comparator.count_ast_statements(legacy_code),
            "current_ast": code_comparator.count_ast_statements(current_code),
            "experimental_ast": code_comparator.count_ast_statements(experimental_code),
            "legacy_shape": legacy_shape,
            "current_shape": current_shape,
            "experimental_shape": experimental_shape,
            "legacy_code": legacy_code,
            "current_code": current_code,
            "experimental_code": experimental_code,
        }
        print("APPROOV_MULTISTATE_CLUSTER_GROUPING_EXPERIMENT", summary)

        assert current_capture["candidate_records"]
        assert experimental_capture["candidate_records"]
        assert current_shape["payload_blocks"]
        assert experimental_shape["payload_blocks"]

    @pytest.mark.xfail(
        reason=(
            "Experimental phase-SCC monkeypatch assumes phase header records "
            "select InsertBlock edits. Current planning can select bookkeeping "
            "edits such as ZeroStateWrite, so this is no longer a valid "
            "contract test."
        ),
        strict=False,
    )
    def test_approov_multistate_first_phase_scc_experiment(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for first-phase SCC experiment"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_legacy() -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener as legacy_mod

            captured: dict[str, object] = {}
            original_optimize = legacy_mod.Unflattener.optimize

            def _wrapped_optimize(rule, blk):
                result = original_optimize(rule, blk)
                if getattr(blk.mba, "entry_ea", None) == func_ea:
                    captured["final_flow_graph"] = lift_mba(blk.mba)
                return result

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(
                    legacy_mod.Unflattener,
                    "optimize",
                    _wrapped_optimize,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=False,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        def _run_engine(*, phase_experiment: bool) -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

            captured: dict[str, object] = {}
            original_execute = engine_mod.execute_family_pipeline
            original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup

            def _wrap_cleanup(self, mba, *, snapshot, total_changes):
                cleaned = original_cleanup(
                    self,
                    mba,
                    snapshot=snapshot,
                    total_changes=total_changes,
                )
                captured["final_flow_graph"] = lift_mba(mba)
                return cleaned

            def _phase_execute(snapshot, planned, **kwargs):
                modifications = extract_emulated_dispatcher_modifications(
                    snapshot.flow_graph
                )
                records = extract_emulated_dispatcher_candidate_records(
                    snapshot.flow_graph
                )
                captured["candidate_records"] = tuple(asdict(record) for record in records)
                captured["phase_role_map"] = _summarize_approov_multistate_phase_roles(
                    records
                )

                modifier = DeferredGraphModifier(snapshot.mba)
                next_serial = int(snapshot.mba.qty) - 1
                consumed_indexes: set[int] = set()
                phase_payloads: list[tuple[str, ...]] = []

                phase1_header = sorted(
                    (
                        record
                        for record in records
                        if _approov_multistate_phase_role(record) == "phase1_header"
                    ),
                    key=lambda item: item.father_serial,
                )
                if phase1_header:
                    anchor = phase1_header[0]
                    anchor_mod = next(
                        (
                            modifications[idx]
                            for idx in anchor.selected_modification_indexes
                            if isinstance(modifications[idx], InsertBlock)
                        ),
                        None,
                    )
                    assert isinstance(anchor_mod, InsertBlock)
                    phase_payloads.append(anchor.payload_signature)
                    modifier.queue_create_and_redirect(
                        source_block_serial=int(anchor.father_serial),
                        final_target_serial=int(anchor.target_serial),
                        instructions_to_copy=list(anchor_mod.instructions),
                        expected_serial=next_serial,
                        description=f"phase1 header anchor {anchor.father_serial}->{anchor.target_serial}",
                    )
                    consumed_indexes.update(anchor.selected_modification_indexes)
                    for follower in phase1_header[1:]:
                        modifier.queue_goto_change(
                            block_serial=int(follower.father_serial),
                            new_target=next_serial,
                            description=f"phase1 header follower {follower.father_serial}->{next_serial}",
                        )
                        consumed_indexes.update(follower.selected_modification_indexes)
                    next_serial += 1

                for record in records:
                    if _approov_multistate_phase_role(record) != "phase1_update":
                        continue
                    mod = next(
                        (
                            modifications[idx]
                            for idx in record.selected_modification_indexes
                            if isinstance(modifications[idx], InsertBlock)
                        ),
                        None,
                    )
                    assert isinstance(mod, InsertBlock)
                    phase_payloads.append(record.payload_signature)
                    modifier.queue_create_and_redirect(
                        source_block_serial=int(mod.pred_serial),
                        final_target_serial=int(mod.succ_serial),
                        instructions_to_copy=list(mod.instructions),
                        expected_serial=next_serial,
                        description=f"phase1 update {mod.pred_serial}->{mod.succ_serial}",
                    )
                    consumed_indexes.update(record.selected_modification_indexes)
                    next_serial += 1

                for record in records:
                    if any(idx in consumed_indexes for idx in record.selected_modification_indexes):
                        continue
                    idx = record.selected_modification_indexes[0]
                    mod = modifications[idx]
                    if isinstance(mod, InsertBlock):
                        modifier.queue_create_and_redirect(
                            source_block_serial=int(mod.pred_serial),
                            final_target_serial=int(mod.succ_serial),
                            instructions_to_copy=list(mod.instructions),
                            expected_serial=next_serial,
                            description=f"non-phase insert {mod.pred_serial}->{mod.succ_serial}",
                        )
                        next_serial += 1
                    elif isinstance(mod, RedirectGoto):
                        modifier.queue_goto_change(
                            block_serial=int(mod.from_serial),
                            new_target=int(mod.new_target),
                            description=f"non-phase redirect {mod.from_serial}->{mod.new_target}",
                        )
                    else:
                        raise AssertionError(f"Unexpected modification in experiment: {mod}")

                changes = modifier.apply(
                    run_optimize_local=True,
                    run_deep_cleaning=False,
                )
                captured["phase_payloads"] = tuple(phase_payloads)
                captured["post_execute_flow_graph"] = lift_mba(snapshot.mba)
                strategy_name = (
                    planned.pipeline[0].strategy_name
                    if planned.pipeline
                    else "emulated_dispatcher"
                )
                return ExecutedPipeline(
                    pipeline=planned.pipeline,
                    results=[
                        StageResult(
                            strategy_name=strategy_name,
                            edits_applied=changes,
                            success=True,
                        )
                    ],
                    provenance=planned.provenance,
                    total_changes=changes,
                    executor=None,
                )

            def _wrapped_execute(snapshot, planned, **kwargs):
                if not phase_experiment:
                    executed = original_execute(snapshot, planned, **kwargs)
                    records = extract_emulated_dispatcher_candidate_records(
                        snapshot.flow_graph
                    )
                    captured["candidate_records"] = tuple(
                        asdict(record) for record in records
                    )
                    captured["phase_role_map"] = _summarize_approov_multistate_phase_roles(
                        records
                    )
                    return executed
                return _phase_execute(snapshot, planned, **kwargs)

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
                patch_ctx.setattr(
                    EmulatedDispatcherStrategyFamily,
                    "post_execute_cleanup",
                    _wrap_cleanup,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=True,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        legacy_code, legacy_capture = _run_legacy()
        current_code, current_capture = _run_engine(phase_experiment=False)
        experimental_code, experimental_capture = _run_engine(phase_experiment=True)

        current_payloads = tuple(
            tuple(record["payload_signature"])
            for record in current_capture["candidate_records"]
            if _approov_multistate_phase_role(record) in ("phase1_header", "phase1_update")
        )
        experimental_payloads = tuple(experimental_capture.get("phase_payloads", ()))

        legacy_shape = _summarize_cfg_shape(legacy_capture["final_flow_graph"])
        current_shape = _summarize_cfg_shape(
            current_capture["final_flow_graph"],
            payload_signatures=current_payloads,
        )
        experimental_shape = _summarize_cfg_shape(
            experimental_capture["final_flow_graph"],
            payload_signatures=experimental_payloads,
        )

        summary = {
            "phase_role_map": experimental_capture["phase_role_map"],
            "legacy_ast": code_comparator.count_ast_statements(legacy_code),
            "current_ast": code_comparator.count_ast_statements(current_code),
            "experimental_ast": code_comparator.count_ast_statements(experimental_code),
            "legacy_shape": legacy_shape,
            "current_shape": current_shape,
            "experimental_shape": experimental_shape,
            "legacy_code": legacy_code,
            "current_code": current_code,
            "experimental_code": experimental_code,
        }
        print("APPROOV_MULTISTATE_FIRST_PHASE_SCC_EXPERIMENT", summary)

        assert summary["phase_role_map"]["phase1_header"] == (
            (2, 9, ("InsertBlock",)),
            (6, 9, ("InsertBlock",)),
        )
        assert summary["phase_role_map"]["phase1_update"] == (
            (10, 5, ("InsertBlock",)),
        )
        assert summary["legacy_ast"]["ifs"] == 1
        assert summary["current_ast"]["ifs"] == 2
        assert summary["experimental_ast"]["ifs"] == 2
        assert experimental_shape["block_count"] <= current_shape["block_count"]

    def test_approov_multistate_handler_subgraph_experiment(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for handler-subgraph experiment"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_legacy() -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener as legacy_mod

            captured: dict[str, object] = {}
            original_optimize = legacy_mod.Unflattener.optimize

            def _wrapped_optimize(rule, blk):
                result = original_optimize(rule, blk)
                if getattr(blk.mba, "entry_ea", None) == func_ea:
                    captured["final_flow_graph"] = lift_mba(blk.mba)
                return result

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(
                    legacy_mod.Unflattener,
                    "optimize",
                    _wrapped_optimize,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=False,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        def _run_engine(*, experiment: bool) -> tuple[str, dict[str, object]]:
            import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

            captured: dict[str, object] = {}
            original_execute = engine_mod.execute_family_pipeline
            original_cleanup = EmulatedDispatcherStrategyFamily.post_execute_cleanup

            def _wrap_cleanup(self, mba, *, snapshot, total_changes):
                cleaned = original_cleanup(
                    self,
                    mba,
                    snapshot=snapshot,
                    total_changes=total_changes,
                )
                captured["final_flow_graph"] = lift_mba(mba)
                return cleaned

            def _handler_execute(snapshot, planned, **kwargs):
                records = extract_emulated_dispatcher_candidate_records(
                    snapshot.flow_graph
                )
                captured["candidate_records"] = tuple(asdict(record) for record in records)
                captured["phase_role_map"] = _summarize_approov_multistate_phase_roles(
                    records
                )

                modifier = DeferredGraphModifier(snapshot.mba)

                modifier.queue_zero_state_write(
                    2,
                    _find_state_write_ea(
                        snapshot.mba,
                        block_serial=2,
                        expected_state=_APPROOV_MULTISTATE_PHASE_STATES["phase1_header"],
                    ),
                    description="phase loop entry 2 -> 9",
                )
                modifier.queue_goto_change(
                    2,
                    9,
                    description="phase loop entry 2 -> 9",
                )
                modifier.queue_zero_state_write(
                    6,
                    _find_state_write_ea(
                        snapshot.mba,
                        block_serial=6,
                        expected_state=_APPROOV_MULTISTATE_PHASE_STATES["phase1_header"],
                    ),
                    description="phase loop latch 6 -> 9",
                )
                modifier.queue_goto_change(
                    6,
                    9,
                    description="phase loop latch 6 -> 9",
                )
                modifier.queue_zero_state_write(
                    10,
                    _find_state_write_ea(
                        snapshot.mba,
                        block_serial=10,
                        expected_state=_APPROOV_MULTISTATE_PHASE_STATES["phase1_update"],
                    ),
                    description="phase loop body 10 -> 5",
                )
                modifier.queue_goto_change(
                    10,
                    5,
                    description="phase loop body 10 -> 5",
                )
                modifier.queue_conditional_target_change(
                    9,
                    12,
                    description="phase1 header taken -> phase2",
                )
                modifier.queue_conditional_target_change(
                    5,
                    12,
                    description="phase1 update taken -> phase2",
                )
                modifier.queue_conditional_target_change(
                    12,
                    12,
                    description="phase2 taken -> phase2 self loop",
                )

                changes = modifier.apply(
                    run_optimize_local=True,
                    run_deep_cleaning=False,
                )
                captured["post_execute_flow_graph"] = lift_mba(snapshot.mba)
                strategy_name = (
                    planned.pipeline[0].strategy_name
                    if planned.pipeline
                    else "emulated_dispatcher"
                )
                return ExecutedPipeline(
                    pipeline=planned.pipeline,
                    results=[
                        StageResult(
                            strategy_name=strategy_name,
                            edits_applied=changes,
                            success=True,
                        )
                    ],
                    provenance=planned.provenance,
                    total_changes=changes,
                    executor=None,
                )

            def _wrapped_execute(snapshot, planned, **kwargs):
                if not experiment:
                    executed = original_execute(snapshot, planned, **kwargs)
                    captured["candidate_records"] = tuple(
                        asdict(record)
                        for record in extract_emulated_dispatcher_candidate_records(
                            snapshot.flow_graph
                        )
                    )
                    return executed
                return _handler_execute(snapshot, planned, **kwargs)

            with monkeypatch.context() as patch_ctx:
                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)
                patch_ctx.setattr(
                    EmulatedDispatcherStrategyFamily,
                    "post_execute_cleanup",
                    _wrap_cleanup,
                )
                with d810_state() as state:
                    rendered = _decompile_with_project(
                        state,
                        func_ea,
                        "example_libobfuscated.json",
                        pseudocode_to_string,
                        engine_wrappers_only=True,
                    )
            assert "final_flow_graph" in captured
            return rendered, captured

        legacy_code, legacy_capture = _run_legacy()
        current_code, current_capture = _run_engine(experiment=False)
        experimental_code, experimental_capture = _run_engine(experiment=True)

        legacy_shape = _summarize_cfg_shape(legacy_capture["final_flow_graph"])
        current_shape = _summarize_cfg_shape(current_capture["final_flow_graph"])
        experimental_shape = _summarize_cfg_shape(
            experimental_capture["final_flow_graph"]
        )

        summary = {
            "phase_role_map": experimental_capture["phase_role_map"],
            "legacy_ast": code_comparator.count_ast_statements(legacy_code),
            "current_ast": code_comparator.count_ast_statements(current_code),
            "experimental_ast": code_comparator.count_ast_statements(experimental_code),
            "legacy_shape": legacy_shape,
            "current_shape": current_shape,
            "experimental_shape": experimental_shape,
            "legacy_code": legacy_code,
            "current_code": current_code,
            "experimental_code": experimental_code,
        }
        print("APPROOV_MULTISTATE_HANDLER_SUBGRAPH_EXPERIMENT", summary)

        assert summary["phase_role_map"]["phase1_header"] == (
            (2, 9, ("InsertBlock",)),
            (6, 9, ("InsertBlock",)),
        )
        assert summary["phase_role_map"]["phase1_update"] == (
            (10, 5, ("InsertBlock",)),
        )

    def test_approov_multistate_single_record_subset_characterization(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for candidate subset characterization"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_engine_subset(
            selected_indexes: tuple[int, ...] | None = None,
        ) -> tuple[str, dict[str, object] | None]:
            with monkeypatch.context() as patch_ctx:
                import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

                captured: dict[str, object] = {}
                original_execute = engine_mod.execute_family_pipeline

                def _wrapped_execute(snapshot, planned, **kwargs):
                    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
                    records = extract_emulated_dispatcher_candidate_records(
                        snapshot.flow_graph
                    )
                    modifications = extract_emulated_dispatcher_modifications(
                        snapshot.flow_graph
                    )
                    if metadata is not None and len(modifications) > int(
                        captured.get("candidate_count", -1)
                    ):
                        captured["candidate_count"] = len(modifications)
                        captured["snapshot"] = asdict(metadata)
                        captured["candidate_records"] = tuple(
                            asdict(record) for record in records
                        )
                    return original_execute(snapshot, planned, **kwargs)

                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

                if selected_indexes is not None:
                    original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

                    def _subset_build_snapshot(self, mba, detection):
                        snapshot = original_build_snapshot(self, mba, detection)
                        metadata = extract_emulated_dispatcher_metadata(
                            snapshot.flow_graph
                        )
                        if metadata is None or metadata.candidate_count == 0:
                            return snapshot
                        return _filter_emulated_dispatcher_snapshot(
                            snapshot,
                            selected_indexes,
                        )

                    patch_ctx.setattr(
                        EmulatedDispatcherStrategyFamily,
                        "build_snapshot",
                        _subset_build_snapshot,
                    )

                with d810_state() as state:
                    state.stop_d810()
                    project_name = "example_libobfuscated.json"
                    project_index = _resolve_test_project_index(state, project_name)
                    state.load_project(project_index)
                    with state.for_project(project_name) as ctx:
                        _apply_engine_wrapper_profile(ctx)
                        dispatcher_rule = next(
                            (
                                rule
                                for rule in ctx.active_blk_rules
                                if type(rule).__name__ == "EmulatedDispatcherUnflattener"
                            ),
                            None,
                        )
                        assert dispatcher_rule is not None
                        state.stats.reset()
                        state.start_d810()
                        previous_override = _force_rule_scope_to_current_profile(
                            state, ctx, func_ea
                        )
                        try:
                            cfunc = idaapi.decompile(
                                func_ea, flags=idaapi.DECOMP_NO_CACHE
                            )
                            assert cfunc is not None
                            rendered = pseudocode_to_string(cfunc.get_pseudocode())
                            observation = dispatcher_rule.get_last_observation()
                        finally:
                            _restore_forced_rule_scope(state, func_ea, previous_override)
                    state.stop_d810()
            return rendered, (
                captured.get("snapshot")
                if "snapshot" in captured
                else observation["snapshot"]
            )

        with d810_state() as state:
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )

        full_engine_code, full_snapshot = _run_engine_subset()
        assert full_snapshot is not None
        candidate_records = full_snapshot["candidate_records"]
        selected_records = tuple(
            record
            for record in candidate_records
            if record["selected_modification_indexes"]
        )
        assert selected_records

        subset_results: list[tuple[tuple[int, ...], bool, dict[str, int], tuple[str, ...]]] = []
        for record in selected_records:
            subset_indexes = tuple(record["selected_modification_indexes"])
            subset_code, subset_snapshot = _run_engine_subset(subset_indexes)
            subset_results.append(
                (
                    subset_indexes,
                    code_comparator.are_equivalent(subset_code, legacy_code),
                    code_comparator.count_ast_statements(subset_code),
                    tuple(record["selected_modification_kinds"]),
                )
            )
            assert subset_snapshot is not None
            assert subset_snapshot["candidate_count"] == len(subset_indexes)

        print(
            "APPROOV_MULTISTATE_SINGLE_RECORD_SUBSETS",
            {
                "full_engine_ast": code_comparator.count_ast_statements(full_engine_code),
                "legacy_ast": code_comparator.count_ast_statements(legacy_code),
                "subsets": subset_results,
            },
        )

        assert len(subset_results) == len(selected_records)

    def test_approov_multistate_grouped_subset_characterization(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for candidate subset characterization"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        def _run_engine_subset(
            selected_indexes: tuple[int, ...] | None = None,
        ) -> tuple[str, dict[str, object] | None]:
            with monkeypatch.context() as patch_ctx:
                import d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine as engine_mod

                captured: dict[str, object] = {}
                original_execute = engine_mod.execute_family_pipeline

                def _wrapped_execute(snapshot, planned, **kwargs):
                    metadata = extract_emulated_dispatcher_metadata(snapshot.flow_graph)
                    records = extract_emulated_dispatcher_candidate_records(
                        snapshot.flow_graph
                    )
                    modifications = extract_emulated_dispatcher_modifications(
                        snapshot.flow_graph
                    )
                    if metadata is not None and len(modifications) > int(
                        captured.get("candidate_count", -1)
                    ):
                        captured["candidate_count"] = len(modifications)
                        captured["snapshot"] = asdict(metadata)
                        captured["candidate_records"] = tuple(
                            asdict(record) for record in records
                        )
                    return original_execute(snapshot, planned, **kwargs)

                patch_ctx.setattr(engine_mod, "execute_family_pipeline", _wrapped_execute)

                if selected_indexes is not None:
                    original_build_snapshot = EmulatedDispatcherStrategyFamily.build_snapshot

                    def _subset_build_snapshot(self, mba, detection):
                        snapshot = original_build_snapshot(self, mba, detection)
                        metadata = extract_emulated_dispatcher_metadata(
                            snapshot.flow_graph
                        )
                        if metadata is None or metadata.candidate_count == 0:
                            return snapshot
                        return _filter_emulated_dispatcher_snapshot(
                            snapshot,
                            selected_indexes,
                        )

                    patch_ctx.setattr(
                        EmulatedDispatcherStrategyFamily,
                        "build_snapshot",
                        _subset_build_snapshot,
                    )

                with d810_state() as state:
                    state.stop_d810()
                    project_name = "example_libobfuscated.json"
                    project_index = _resolve_test_project_index(state, project_name)
                    state.load_project(project_index)
                    with state.for_project(project_name) as ctx:
                        _apply_engine_wrapper_profile(ctx)
                        dispatcher_rule = next(
                            (
                                rule
                                for rule in ctx.active_blk_rules
                                if type(rule).__name__ == "EmulatedDispatcherUnflattener"
                            ),
                            None,
                        )
                        assert dispatcher_rule is not None
                        state.stats.reset()
                        state.start_d810()
                        previous_override = _force_rule_scope_to_current_profile(
                            state, ctx, func_ea
                        )
                        try:
                            cfunc = idaapi.decompile(
                                func_ea, flags=idaapi.DECOMP_NO_CACHE
                            )
                            assert cfunc is not None
                            rendered = pseudocode_to_string(cfunc.get_pseudocode())
                            observation = dispatcher_rule.get_last_observation()
                        finally:
                            _restore_forced_rule_scope(state, func_ea, previous_override)
                    state.stop_d810()
            return rendered, (
                captured.get("snapshot")
                if "snapshot" in captured
                else observation["snapshot"]
            )

        with d810_state() as state:
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )

        full_engine_code, full_snapshot = _run_engine_subset()
        assert full_snapshot is not None
        candidate_records = full_snapshot["candidate_records"]
        selected_records = tuple(
            record
            for record in candidate_records
            if record["selected_modification_indexes"]
        )
        assert len(selected_records) == 6

        groups = (
            ("first_half", (0, 1, 2)),
            ("second_half", (3, 4, 5)),
            ("insert_only", (0, 1, 2, 3, 4)),
            ("redirect_only", (5,)),
        )
        group_results: list[
            tuple[str, tuple[int, ...], bool, dict[str, int], tuple[str, ...]]
        ] = []
        for label, indexes in groups:
            subset_code, subset_snapshot = _run_engine_subset(indexes)
            group_results.append(
                (
                    label,
                    indexes,
                    code_comparator.are_equivalent(subset_code, legacy_code),
                    code_comparator.count_ast_statements(subset_code),
                    tuple(
                        candidate_records[idx]["selected_modification_kinds"][0]
                        for idx in indexes
                    ),
                )
            )
            assert subset_snapshot is not None

        print(
            "APPROOV_MULTISTATE_GROUPED_SUBSETS",
            {
                "full_engine_ast": code_comparator.count_ast_statements(full_engine_code),
                "legacy_ast": code_comparator.count_ast_statements(legacy_code),
                "groups": group_results,
            },
        )

        assert len(group_results) == len(groups)

    def test_approov_multistate_characterization_without_fake_jump_skip(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        monkeypatch,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for candidate subset characterization"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        from d810.cfg.flowgraph import FlowGraph
        from d810.optimizers.microcode.flow.flattening.hodur.family import (
            HodurStrategyFamily,
        )
        from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
            FAKE_JUMP_FIXES_METADATA_KEY,
            collect_live_fake_jump_fixes,
            serialize_fake_jump_fixes,
        )
        from d810.recon.flow.dispatcher_detection import DispatcherCache

        original_attach_fake_jump = HodurStrategyFamily.attach_fake_jump_fixes_to_flow_graph

        def _attach_fake_jump_without_cleanup_skip(self, mba, flow_graph):
            updated = original_attach_fake_jump(self, mba, flow_graph)
            if FAKE_JUMP_FIXES_METADATA_KEY in dict(updated.metadata):
                return updated
            try:
                fixes = collect_live_fake_jump_fixes(
                    mba,
                    logger=self._logger,
                    max_nb_block=100,
                    max_path=100,
                    allowed_maturities=(ida_hexrays.MMAT_GLBOPT1,),
                )
            except Exception:
                return updated
            if not fixes:
                return updated
            try:
                dispatcher_cache = DispatcherCache.get_or_create(mba)
                dispatcher_analysis = dispatcher_cache.analyze()
            except Exception:
                dispatcher_cache = None
                dispatcher_analysis = None
            if (
                dispatcher_cache is not None
                and dispatcher_analysis is not None
                and dispatcher_analysis.is_conditional_chain
            ):
                fixes = tuple(
                    fix
                    for fix in fixes
                    if not dispatcher_cache.is_dispatcher(fix.fake_block)
                )
            if not fixes:
                return updated
            metadata = dict(updated.metadata)
            metadata[FAKE_JUMP_FIXES_METADATA_KEY] = serialize_fake_jump_fixes(fixes)
            return FlowGraph(
                blocks=updated.blocks,
                entry_serial=updated.entry_serial,
                func_ea=updated.func_ea,
                metadata=metadata,
            )

        monkeypatch.setattr(
            HodurStrategyFamily,
            "attach_fake_jump_fixes_to_flow_graph",
            _attach_fake_jump_without_cleanup_skip,
        )

        with d810_state() as state:
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )

        with d810_state() as state:
            engine_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=True,
            )

        print(
            "APPROOV_MULTISTATE_WITHOUT_FAKEJUMP_SKIP",
            {
                "legacy_ast": code_comparator.count_ast_statements(legacy_code),
                "engine_ast": code_comparator.count_ast_statements(engine_code),
                "equivalent": code_comparator.are_equivalent(engine_code, legacy_code),
            },
        )

    def test_approov_multistate_characterization_with_fixpred_restored(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
    ) -> None:
        assert code_comparator is not None, (
            "libclang required for candidate subset characterization"
        )
        func_ea = get_func_ea("approov_multistate")
        if func_ea == idaapi.BADADDR:
            pytest.skip("Function 'approov_multistate' not found")

        with d810_state() as state:
            legacy_code = _decompile_with_project(
                state,
                func_ea,
                "example_libobfuscated.json",
                pseudocode_to_string,
                engine_wrappers_only=False,
            )

        with d810_state() as state:
            state.stop_d810()
            project_name = "example_libobfuscated.json"
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name) as ctx:
                _apply_engine_wrapper_profile(ctx)
                ctx.add_rule("FixPredecessorOfConditionalJumpBlock")
                state.stats.reset()
                state.start_d810()
                previous_override = _force_rule_scope_to_current_profile(
                    state, ctx, func_ea
                )
                try:
                    cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                    assert cfunc is not None
                    engine_code = pseudocode_to_string(cfunc.get_pseudocode())
                finally:
                    _restore_forced_rule_scope(state, func_ea, previous_override)
            state.stop_d810()

        print(
            "APPROOV_MULTISTATE_WITH_FIXPRED_RESTORED",
            {
                "legacy_ast": code_comparator.count_ast_statements(legacy_code),
                "engine_ast": code_comparator.count_ast_statements(engine_code),
                "equivalent": code_comparator.are_equivalent(engine_code, legacy_code),
            },
        )
