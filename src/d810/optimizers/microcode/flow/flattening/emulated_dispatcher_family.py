"""Family adapter for the extracted emulated-dispatcher detection path."""
from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass
from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    ConvertToGoto,
    GraphModification,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.core import logging
from d810.evaluator.hexrays_microcode.tracker import (
    check_if_all_values_are_found,
    get_all_possibles_values,
)
from d810.hexrays.mutation.cfg_mutations import mba_deep_cleaning
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.mutation.ir_translator import capture_insn_snapshot
from d810.hexrays.utils.hexrays_helpers import CONTROL_FLOW_OPCODES
from d810.optimizers.microcode.flow.flattening.engine.family import (
    CFFStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
    StateModelSummary,
)
from d810.optimizers.microcode.flow.flattening.strategies.emulated_dispatcher_strategy import (
    EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY,
    EMULATED_DISPATCHER_FALLBACK_MODIFICATIONS_KEY,
    EMULATED_DISPATCHER_LOOP_RECOVERY_MODIFICATIONS_KEY,
    EMULATED_DISPATCHER_METADATA_KEY,
    EMULATED_DISPATCHER_MODIFICATIONS_KEY,
    EMULATED_DISPATCHER_PHASE_ARTIFACT_KEY,
    EMULATED_DISPATCHER_PHASE_CONTEXT_KEY,
    DispatcherLoopRecoveryStrategy,
    EmulatedDispatcherCandidateRecord,
    EmulatedDispatcherPhaseArtifact,
    EmulatedDispatcherPhaseContext,
    EmulatedDispatcherMetadata,
    EmulatedDispatcherStrategy,
)
from d810.optimizers.microcode.flow.flattening.unflattener import (
    OllvmDispatcherCollector,
    Unflattener,
)
from d810.recon.flow.bst_analysis import analyze_bst_dispatcher
from d810.recon.flow.dispatcher_detection import DispatcherCache
from d810.recon.flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    build_live_linearized_state_dag_from_graph,
    build_linearized_state_program,
    render_linearized_state_program,
)
from d810.recon.flow.transition_builder import _convert_bst_to_result
from d810.recon.flow.transition_report import build_dispatcher_transition_report_from_graph

family_logger = logging.getLogger(
    "D810.unflat.emulated_dispatcher.family", logging.DEBUG
)

__all__ = ["EmulatedDispatcherDetection", "EmulatedDispatcherStrategyFamily"]


@dataclass(frozen=True)
class EmulatedDispatcherDetection:
    """Concrete detection result for the phenotype-based dispatcher family."""

    dispatcher_analysis: object | None = None
    collector_dispatchers: tuple[object, ...] = ()
    collector_dispatcher_entries: tuple[int, ...] = ()
    analysis_dispatchers: tuple[int, ...] = ()
    dispatcher_shape: str = "none"
    state_transport: str = "none"
    lowering_mode: str = "none"
    provenance_hints: tuple[str, ...] = ()
    state_constants: tuple[int, ...] = ()
    planning_blocker: str | None = None

    @property
    def detected(self) -> bool:
        return bool(self.analysis_dispatchers or self.collector_dispatcher_entries)

    @property
    def description(self) -> str:
        if not self.detected:
            return "no emulated dispatcher detected"
        if self.planning_blocker:
            return (
                f"emulated dispatcher detected via {self.dispatcher_shape}; "
                f"planning blocked: {self.planning_blocker}"
            )
        return f"emulated dispatcher detected via {self.dispatcher_shape}"


class EmulatedDispatcherStrategyFamily(CFFStrategyFamily):
    """Engine-family adapter over the legacy generic dispatcher collector."""

    def __init__(
        self,
        *,
        cfg_translator: IDAIRTranslator | None = None,
        logger=None,
    ) -> None:
        self._cfg_translator = cfg_translator or IDAIRTranslator()
        self._logger = logger or family_logger
        self._strategies = [
            DispatcherLoopRecoveryStrategy(),
            EmulatedDispatcherStrategy(),
        ]
        self._deferred_side_effects: dict[
            tuple[int, int, tuple[int, ...]],
            tuple[object, ...],
        ] = {}

    @property
    def name(self) -> str:
        return "emulated_dispatcher"

    @property
    def strategies(self) -> list:
        return list(self._strategies)

    def strategies_for_maturity(self, maturity: int | None = None) -> list:
        return list(self._strategies)

    def _make_resolver(
        self,
        mba: ida_hexrays.mba_t,
        detection: EmulatedDispatcherDetection,
    ) -> Unflattener:
        resolver = Unflattener()
        resolver.mba = mba
        resolver.cur_maturity = mba.maturity
        resolver.cur_maturity_pass = 0
        resolver.dispatcher_list = list(detection.collector_dispatchers)
        return resolver

    def detect(self, mba: object) -> EmulatedDispatcherDetection:
        cache = DispatcherCache.get_or_create(mba)
        analysis = cache.analyze()

        collector = OllvmDispatcherCollector()
        mba.for_all_topinsns(collector)
        collector_dispatchers = tuple(collector.get_dispatcher_list())
        collector_entries = tuple(
            int(info.entry_block.serial)
            for info in collector_dispatchers
            if getattr(info, "entry_block", None) is not None
        )
        analysis_dispatchers = tuple(int(serial) for serial in analysis.dispatchers)
        state_constants = tuple(sorted(int(value) for value in analysis.state_constants))
        analysis_type = getattr(getattr(analysis, "dispatcher_type", None), "name", "none")
        analysis_type = str(analysis_type).lower()
        detected = bool(analysis_dispatchers or collector_entries)

        planning_blocker = None
        if analysis_dispatchers and not collector_entries:
            planning_blocker = "dispatcher_cache_detected_but_collector_found_none"

        detection = EmulatedDispatcherDetection(
            dispatcher_analysis=analysis,
            collector_dispatchers=collector_dispatchers,
            collector_dispatcher_entries=collector_entries,
            analysis_dispatchers=analysis_dispatchers,
            dispatcher_shape=analysis_type if detected else "none",
            state_transport="father_history_emulation" if detected else "none",
            lowering_mode="generic_graph_modifications" if detected else "none",
            provenance_hints=(),
            state_constants=state_constants,
            planning_blocker=planning_blocker,
        )
        self._logger.info(
            "Emulated-dispatcher detect: shape=%s dispatchers=%s collector=%s blocker=%s",
            detection.dispatcher_shape,
            detection.analysis_dispatchers,
            detection.collector_dispatcher_entries,
            detection.planning_blocker,
        )
        return detection

    def _collect_lowering_candidates(
        self,
        mba: ida_hexrays.mba_t,
        detection: EmulatedDispatcherDetection,
        *,
        flow_graph: FlowGraph,
    ) -> tuple[
        tuple[GraphModification, ...],
        tuple[str, ...],
        tuple[EmulatedDispatcherCandidateRecord, ...],
    ]:
        if not detection.collector_dispatchers:
            return (), (), ()

        resolver = self._make_resolver(mba, detection)
        scc_memberships = self._compute_scc_memberships(flow_graph)

        modifications: list[GraphModification] = []
        blockers: list[str] = []
        candidate_records: list[EmulatedDispatcherCandidateRecord] = []
        seen_fathers: set[tuple[int, int]] = set()

        for dispatcher_info in detection.collector_dispatchers:
            entry_block = getattr(dispatcher_info, "entry_block", None)
            if entry_block is None or getattr(entry_block, "blk", None) is None:
                blockers.append("collector_dispatcher_missing_entry_block")
                continue

            for pred_serial in list(entry_block.blk.predset):
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None:
                    blockers.append("dispatcher_predecessor_missing")
                    continue
                father_key = (int(entry_block.serial), int(pred_blk.serial))
                if father_key in seen_fathers:
                    continue
                seen_fathers.add(father_key)
                start_index = len(modifications)
                candidate, reason, record = self._build_lowering_candidate(
                    resolver,
                    pred_blk,
                    dispatcher_info,
                    scc_memberships=scc_memberships,
                )
                if candidate is not None:
                    modifications.extend(candidate)
                    record = EmulatedDispatcherCandidateRecord(
                        **{
                            **record.__dict__,
                            "selected_modification_indexes": tuple(
                                range(start_index, len(modifications))
                            ),
                        }
                    )
                candidate_records.append(record)
                if reason is not None:
                    blockers.append(reason)

        return (
            tuple(modifications),
            tuple(blockers),
            self._annotate_cluster_candidates(tuple(candidate_records)),
        )

    def _compute_scc_memberships(
        self,
        flow_graph: FlowGraph,
    ) -> dict[int, tuple[int, ...]]:
        index = 0
        stack: list[int] = []
        on_stack: set[int] = set()
        indexes: dict[int, int] = {}
        lowlinks: dict[int, int] = {}
        memberships: dict[int, tuple[int, ...]] = {}

        def _strongconnect(serial: int) -> None:
            nonlocal index
            indexes[serial] = index
            lowlinks[serial] = index
            index += 1
            stack.append(serial)
            on_stack.add(serial)

            for succ in flow_graph.blocks[serial].succs:
                if succ not in flow_graph.blocks:
                    continue
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
            for member in normalized:
                memberships[member] = normalized

        for serial in flow_graph.blocks:
            if serial not in indexes:
                _strongconnect(serial)

        return memberships

    def _resolve_state_var_stkoff(
        self,
        detection: EmulatedDispatcherDetection,
    ) -> int | None:
        candidate = getattr(detection.dispatcher_analysis, "state_variable", None)
        if candidate is None:
            return None
        try:
            if getattr(candidate, "mop_type", None) == ida_hexrays.mop_S:
                return int(getattr(candidate, "mop_offset", None))
        except Exception:
            return None
        return None

    def _primary_dispatcher_entry_serial(
        self,
        detection: EmulatedDispatcherDetection,
    ) -> int | None:
        if detection.collector_dispatchers:
            entry_block = getattr(detection.collector_dispatchers[0], "entry_block", None)
            if entry_block is not None:
                return int(entry_block.serial)
        if detection.analysis_dispatchers:
            return int(detection.analysis_dispatchers[0])
        return None

    def _build_phase_artifact(
        self,
        mba: ida_hexrays.mba_t,
        detection: EmulatedDispatcherDetection,
        *,
        flow_graph: FlowGraph,
    ) -> tuple[EmulatedDispatcherPhaseArtifact, EmulatedDispatcherPhaseContext] | tuple[None, None]:
        dispatcher_entry_serial = self._primary_dispatcher_entry_serial(detection)
        if dispatcher_entry_serial is None:
            return None, None

        state_var_stkoff = self._resolve_state_var_stkoff(detection)
        try:
            bst_result = analyze_bst_dispatcher(
                mba,
                dispatcher_entry_serial,
                state_var_stkoff=state_var_stkoff,
            )
        except Exception:
            self._logger.warning(
                "Failed to build emulated-dispatcher BST artifact",
                exc_info=True,
            )
            return None, None

        transition_result = _convert_bst_to_result(bst_result)
        bst_node_blocks = tuple(sorted(int(serial) for serial in bst_result.bst_node_blocks))
        transition_report = build_dispatcher_transition_report_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=getattr(bst_result, "initial_state", None),
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=bst_node_blocks,
            diagnostics=(),
        )
        dag = build_live_linearized_state_dag_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=getattr(bst_result, "initial_state", None),
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=bst_node_blocks,
            diagnostics=(),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=mba,
            prefer_local_corridors=True,
        )
        semantic_program = build_linearized_state_program(
            dag,
            order_strategy=RenderOrderStrategy.SEMANTIC,
            program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
            label_render_mode=LabelRenderMode.STATE_FAMILY,
            boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
            comment_mode=ProgramCommentMode.MINIMAL,
        )
        semantic_program_text = render_linearized_state_program(semantic_program)
        artifact = EmulatedDispatcherPhaseArtifact(
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=getattr(bst_result, "initial_state", None),
            bst_node_blocks=bst_node_blocks,
            handler_state_map=tuple(
                sorted(
                    (int(serial), int(state))
                    for serial, state in getattr(bst_result, "handler_state_map", {}).items()
                )
            ),
            handler_range_map=tuple(
                sorted(
                    (
                        int(serial),
                        None if lo is None else int(lo),
                        None if hi is None else int(hi),
                    )
                    for serial, (lo, hi) in getattr(bst_result, "handler_range_map", {}).items()
                )
            ),
            transition_rows=len(getattr(transition_report, "rows", ()) or ()),
            dag_node_count=len(getattr(dag, "nodes", ()) or ()),
            dag_edge_count=len(getattr(dag, "edges", ()) or ()),
            semantic_state_labels=tuple(
                str(getattr(node, "state_label", ""))
                for node in getattr(dag, "nodes", ())
            ),
            semantic_reference_variant=str(getattr(semantic_program, "variant_name", None)),
            semantic_reference_line_count=len(getattr(semantic_program, "lines", ()) or ()),
            semantic_reference_node_count=len(getattr(semantic_program, "nodes", ()) or ()),
            semantic_reference_program=semantic_program_text,
        )
        context = EmulatedDispatcherPhaseContext(
            bst_result=bst_result,
            transition_result=transition_result,
            transition_report=transition_report,
            dag=dag,
            semantic_reference_program=semantic_program,
        )
        return artifact, context

    def _collect_loop_recovery_modifications(
        self,
        *,
        mba: ida_hexrays.mba_t,
        snapshot_flow_graph: FlowGraph,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
        candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        if phase_artifact is None or phase_context is None:
            return (), ()
        if phase_artifact.state_var_stkoff is None:
            return (), ("dispatcher_loop_recovery_missing_state_var",)
        artifact_blockers = self._dispatcher_loop_recovery_artifact_blockers(
            phase_artifact
        )
        if artifact_blockers:
            return (), artifact_blockers

        direct_batch, direct_blockers = self._collect_phase_redirect_loop_recovery(
            mba=mba,
            phase_artifact=phase_artifact,
            candidate_records=candidate_records,
        )
        if direct_batch:
            self._logger.info(
                "DispatcherLoopRecovery selected %d direct phase rewrite(s) from %d fallback candidates",
                len(direct_batch),
                len(candidate_records),
            )
            return direct_batch, ()
        # Keep loop recovery on the explicit phase-cycle contract only.
        # The broader DAG reconstruction fallback overfires on samples like
        # approov_vm_dispatcher, where recon sees a dispatcher but does not
        # yet prove a loop phase strong enough for structural recovery.
        return (), direct_blockers

    def _collect_phase_redirect_loop_recovery(
        self,
        *,
        mba: ida_hexrays.mba_t,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        if not candidate_records:
            return (), ()

        phase_cycle = self._build_interval_phase_loop_recovery(
            mba=mba,
            phase_artifact=phase_artifact,
            candidate_records=candidate_records,
        )
        if phase_cycle is not None:
            return phase_cycle, ()

        loop_recovery: list[GraphModification] = []
        blockers: list[str] = []

        for record in candidate_records:
            if record.target_serial is None or record.source_nsucc != 1:
                blockers.append("dispatcher_loop_recovery_requires_one_way_father")
                break
            branch_rewrite = self._build_phase_cycle_branch_recovery(
                mba=mba,
                phase_artifact=phase_artifact,
                record=record,
                candidate_records=candidate_records,
            )
            if branch_rewrite is not None:
                loop_recovery.extend(branch_rewrite)
                continue
            if record.raw_side_effect_count == 0:
                loop_recovery.append(
                    RedirectGoto(
                        from_serial=int(record.father_serial),
                        old_target=int(record.dispatcher_entry_serial),
                        new_target=int(record.target_serial),
                    )
                )
                continue
            if record.raw_side_effect_count != 1 or len(record.state_signature) != 1:
                blockers.append("dispatcher_loop_recovery_requires_single_state_write")
                break

            rewrite = self._build_live_state_write_recovery(
                mba=mba,
                father_serial=int(record.father_serial),
                dispatcher_entry_serial=int(record.dispatcher_entry_serial),
                target_serial=int(record.target_serial),
                expected_state=int(record.state_signature[0]),
                state_var_stkoff=int(phase_artifact.state_var_stkoff),
            )
            if rewrite is None:
                blockers.append("dispatcher_loop_recovery_non_state_write_insert")
                break
            loop_recovery.extend(rewrite)

        if blockers:
            return (), tuple(sorted(set(blockers)))
        return tuple(loop_recovery), ()

    def _dispatcher_loop_recovery_artifact_blockers(
        self,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
    ) -> tuple[str, ...]:
        blockers: list[str] = []
        if phase_artifact.semantic_reference_variant != "semantic_reference_like":
            blockers.append("dispatcher_loop_recovery_nonsemantic_artifact")
        if any(
            "_fallback" in str(label)
            for label in phase_artifact.semantic_state_labels
        ):
            blockers.append("dispatcher_loop_recovery_fallback_phase")
        return tuple(blockers)

    def _build_interval_phase_loop_recovery(
        self,
        *,
        mba: ida_hexrays.mba_t,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[GraphModification, ...] | None:
        if phase_artifact.state_var_stkoff is None or phase_artifact.initial_state is None:
            return None

        state_to_handler = {
            int(state): int(serial)
            for serial, state in phase_artifact.handler_state_map
        }
        if not state_to_handler:
            return None

        header_state = int(phase_artifact.initial_state)
        header_target = state_to_handler.get(header_state)
        if header_target is None:
            return None

        terminal_states = {
            int(record.state_signature[0])
            for record in candidate_records
            if record.target_serial is not None
            and tuple(int(value) for value in record.state_signature)
            and record.raw_side_effect_count == 0
            and tuple(int(target) for target in record.target_scc)
            == (int(record.target_serial),)
        }
        body_states = tuple(
            sorted(
                state
                for state in state_to_handler
                if state not in {header_state, *terminal_states}
            )
        )
        if len(body_states) != 1:
            return None

        body_state = int(body_states[0])
        body_target = int(state_to_handler[body_state])

        point_handler_targets = set(state_to_handler.values())
        next_phase_targets = tuple(
            sorted(
                {
                    int(serial)
                    for serial, _lo, _hi in phase_artifact.handler_range_map
                    if int(serial) not in point_handler_targets
                }
            )
        )
        if len(next_phase_targets) != 1:
            return None
        next_phase_target = int(next_phase_targets[0])

        def _matching_records(expected_state: int, expected_target: int) -> tuple[EmulatedDispatcherCandidateRecord, ...]:
            return tuple(
                record
                for record in candidate_records
                if record.target_serial is not None
                and tuple(int(value) for value in record.state_signature) == (expected_state,)
                and int(record.target_serial) == expected_target
                and int(record.source_nsucc) == 1
                and int(record.raw_side_effect_count) == 1
            )

        header_records = _matching_records(header_state, header_target)
        body_records = _matching_records(body_state, body_target)
        next_phase_records = tuple(
            record
            for record in candidate_records
            if record.target_serial is not None
            and int(record.target_serial) == next_phase_target
            and int(record.source_nsucc) == 1
            and int(record.raw_side_effect_count) == 1
        )
        if not header_records or len(body_records) != 1 or len(next_phase_records) < 1:
            return None

        def _is_2way(serial: int) -> bool:
            blk = mba.get_mblock(serial)
            return blk is not None and int(blk.nsucc()) == 2

        if not all(
            _is_2way(serial)
            for serial in (header_target, body_target, next_phase_target)
        ):
            return None

        modifications: list[GraphModification] = []
        for record in (*header_records, *body_records):
            rewrite = self._build_live_state_write_recovery(
                mba=mba,
                father_serial=int(record.father_serial),
                dispatcher_entry_serial=int(record.dispatcher_entry_serial),
                target_serial=int(record.target_serial),
                expected_state=int(record.state_signature[0]),
                state_var_stkoff=int(phase_artifact.state_var_stkoff),
            )
            if rewrite is None:
                return None
            modifications.extend(rewrite)

        modifications.extend(
            (
                RedirectBranch(
                    from_serial=header_target,
                    old_target=int(phase_artifact.dispatcher_entry_serial),
                    new_target=next_phase_target,
                ),
                RedirectBranch(
                    from_serial=body_target,
                    old_target=int(phase_artifact.dispatcher_entry_serial),
                    new_target=next_phase_target,
                ),
                RedirectBranch(
                    from_serial=next_phase_target,
                    old_target=int(phase_artifact.dispatcher_entry_serial),
                    new_target=next_phase_target,
                ),
            )
        )
        self._logger.info(
            "DispatcherLoopRecovery phase-cycle lowering: header=%s body=%s next_phase=%s mods=%d",
            tuple(int(record.father_serial) for record in header_records),
            tuple(int(record.father_serial) for record in body_records),
            tuple(int(record.father_serial) for record in next_phase_records),
            len(modifications),
        )
        return tuple(modifications)

    def _build_phase_cycle_branch_recovery(
        self,
        *,
        mba: ida_hexrays.mba_t,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        record: EmulatedDispatcherCandidateRecord,
        candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[GraphModification, ...] | None:
        if phase_artifact.semantic_reference_variant != "semantic_reference_like":
            return None
        if record.target_serial is None or record.raw_side_effect_count != 0:
            return None

        father_blk = mba.get_mblock(int(record.father_serial))
        if father_blk is None or father_blk.nsucc() != 1:
            return None
        if int(father_blk.succ(0)) != int(record.target_serial):
            return None

        predecessors = [mba.get_mblock(int(pred)) for pred in list(father_blk.predset)]
        conditional_parents = [
            parent
            for parent in predecessors
            if parent is not None
            and int(parent.nsucc()) == 2
            and int(record.father_serial) in {int(parent.succ(0)), int(parent.succ(1))}
        ]
        if len(conditional_parents) != 1:
            return None

        parent_blk = conditional_parents[0]
        if tuple(int(target) for _, _, target in phase_artifact.handler_range_map) and int(
            parent_blk.serial
        ) not in {
            int(target) for _, _, target in phase_artifact.handler_range_map
        }:
            return None
        if tuple(int(target) for target in record.target_scc) != (
            int(record.target_serial),
        ):
            return None

        self._logger.info(
            "DispatcherLoopRecovery phase-cycle branch: parent=%d terminal_bridge=%d -> self-loop %d",
            int(parent_blk.serial),
            int(record.father_serial),
            int(parent_blk.serial),
        )
        return (
            RedirectBranch(
                from_serial=int(parent_blk.serial),
                old_target=int(record.father_serial),
                new_target=int(parent_blk.serial),
            ),
        )

    def _build_live_state_write_recovery(
        self,
        *,
        mba: ida_hexrays.mba_t,
        father_serial: int,
        dispatcher_entry_serial: int,
        target_serial: int,
        expected_state: int,
        state_var_stkoff: int,
    ) -> tuple[GraphModification, ...] | None:
        blk = mba.get_mblock(father_serial)
        if blk is None:
            return None

        matched_ea: int | None = None
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
                and int(getattr(getattr(getattr(insn, "l", None), "nnn", None), "value", -1))
                == expected_state
            ):
                matched_ea = int(insn.ea)
                break
            insn = insn.next

        if matched_ea is None:
            return None

        return (
            ZeroStateWrite(block_serial=father_serial, insn_ea=matched_ea),
            RedirectGoto(
                from_serial=father_serial,
                old_target=dispatcher_entry_serial,
                new_target=target_serial,
            ),
        )

    def _format_snapshot_mop(self, mop: object | None) -> str:
        if mop is None:
            return "z"
        t = getattr(mop, "t", None)
        size = getattr(mop, "size", None)
        value = getattr(mop, "value", None)
        stkoff = getattr(mop, "stkoff", None)
        reg = getattr(mop, "reg", None)
        block_ref = getattr(mop, "block_ref", None)
        return (
            f"t={t},size={size},value={value},stkoff={stkoff},"
            f"reg={reg},block_ref={block_ref}"
        )

    def _payload_signature(
        self,
        instructions: tuple[object, ...],
    ) -> tuple[str, ...]:
        signature: list[str] = []
        for insn in instructions:
            signature.append(
                "|".join(
                    (
                        f"op={getattr(insn, 'opcode', None)}",
                        f"l={self._format_snapshot_mop(getattr(insn, 'l', None))}",
                        f"r={self._format_snapshot_mop(getattr(insn, 'r', None))}",
                        f"d={self._format_snapshot_mop(getattr(insn, 'd', None))}",
                    )
                )
            )
        return tuple(signature)

    def _annotate_cluster_candidates(
        self,
        records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[EmulatedDispatcherCandidateRecord, ...]:
        repeated_keys = {
            key
            for key, count in Counter(
                record.cluster_key for record in records if record.cluster_key
            ).items()
            if count > 1
        }
        return tuple(
            record
            if not record.cluster_key
            else EmulatedDispatcherCandidateRecord(
                **{
                    **record.__dict__,
                    "cluster_candidate": record.cluster_key in repeated_keys,
                }
            )
            for record in records
        )

    def _summarize_modification(self, mod: GraphModification) -> str:
        if isinstance(mod, RedirectGoto):
            return (
                f"RedirectGoto({mod.from_serial}:{mod.old_target}->{mod.new_target})"
            )
        if isinstance(mod, ConvertToGoto):
            return f"ConvertToGoto({mod.block_serial}->{mod.goto_target})"
        if isinstance(mod, CreateConditionalRedirect):
            return (
                "CreateConditionalRedirect("
                f"src={mod.source_block},ref={mod.ref_block},"
                f"jcc={mod.conditional_target},ft={mod.fallthrough_target},"
                f"insns={len(mod.instructions)})"
            )
        if isinstance(mod, InsertBlock):
            return (
                "InsertBlock("
                f"pred={mod.pred_serial},succ={mod.succ_serial},"
                f"old={mod.old_target_serial},insns={len(mod.instructions)})"
            )
        return type(mod).__name__

    def _legacy_analogue_for_candidate(
        self,
        *,
        modifications: tuple[GraphModification, ...],
        source_nsucc: int,
    ) -> tuple[str | None, bool | None]:
        if not modifications:
            return None, None
        mod = modifications[0]
        if isinstance(mod, RedirectGoto):
            return "redirect_goto", True
        if isinstance(mod, ConvertToGoto):
            return "convert_to_goto", True
        if isinstance(mod, InsertBlock):
            return "create_and_redirect", source_nsucc == 1
        if isinstance(mod, CreateConditionalRedirect):
            if len(mod.instructions) > 0:
                return "create_and_redirect", False
            return "create_conditional_redirect", True
        return None, None

    def _selection_reason_for_candidate(
        self,
        *,
        modifications: tuple[GraphModification, ...],
        raw_side_effect_count: int,
        deferred_side_effect_count: int,
    ) -> str | None:
        if not modifications:
            return None
        mod = modifications[0]
        if isinstance(mod, RedirectGoto):
            return "direct_redirect"
        if isinstance(mod, ConvertToGoto):
            return "convert_conditional_source_to_goto"
        if isinstance(mod, InsertBlock):
            if deferred_side_effect_count > 0:
                return "insert_deferred_side_effect_block"
            if raw_side_effect_count > 0:
                return "insert_side_effect_block"
            return "insert_block"
        if isinstance(mod, CreateConditionalRedirect):
            if mod.source_block == mod.ref_block:
                return "resolved_conditional_exit"
            if deferred_side_effect_count > 0:
                return "conditional_redirect_with_deferred_side_effects"
            if raw_side_effect_count > 0:
                return "conditional_redirect_with_side_effects"
            return "conditional_redirect_clone"
        return type(mod).__name__

    def _build_lowering_candidate(
        self,
        resolver: Unflattener,
        dispatcher_father: ida_hexrays.mblock_t,
        dispatcher_info: object,
        *,
        scc_memberships: dict[int, tuple[int, ...]],
    ) -> tuple[
        tuple[GraphModification, ...] | None,
        str | None,
        EmulatedDispatcherCandidateRecord,
    ]:
        base_record = EmulatedDispatcherCandidateRecord(
            dispatcher_entry_serial=int(dispatcher_info.entry_block.serial),
            father_serial=int(dispatcher_father.serial),
            source_nsucc=int(dispatcher_father.nsucc()),
            source_scc=scc_memberships.get(int(dispatcher_father.serial), ()),
        )

        def _blocked_record(reason: str, **extra) -> EmulatedDispatcherCandidateRecord:
            return EmulatedDispatcherCandidateRecord(
                **{
                    **base_record.__dict__,
                    **extra,
                    "blocker": reason,
                    "semantically_valid": False,
                    "structurally_legacy_equivalent": None,
                }
            )

        histories = resolver.get_dispatcher_father_histories(
            dispatcher_father,
            dispatcher_info.entry_block,
            dispatcher_info,
        )
        if not histories:
            reason = "dispatcher_history_missing"
            return None, reason, _blocked_record(reason)
        if not resolver.check_if_histories_are_resolved(histories):
            reason = "dispatcher_history_unresolved"
            return None, reason, _blocked_record(reason)

        values = get_all_possibles_values(
            histories,
            dispatcher_info.entry_block.use_before_def_list,
            verbose=False,
        )
        if not check_if_all_values_are_found(values):
            reason = "dispatcher_history_missing_values"
            return None, reason, _blocked_record(reason)
        if any(candidate != values[0] for candidate in values[1:]):
            reason = "dispatcher_history_ambiguous"
            return None, reason, _blocked_record(reason)
        state_signature = tuple(int(value) for value in values[0])
        deferred_side_effects = self._deferred_side_effects.get(
            (
                int(resolver.mba.entry_ea),
                int(dispatcher_info.entry_block.serial),
                state_signature,
            )
        )

        target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(
            histories[0],
            resolve_conditional_exits=True,
        )
        if target_blk is None:
            reason = "dispatcher_emulation_returned_no_target"
            return None, reason, _blocked_record(
                reason,
                state_signature=state_signature,
            )
        if target_blk.serial == dispatcher_father.serial:
            reason = "dispatcher_target_self_loop"
            return None, reason, _blocked_record(
                reason,
                state_signature=state_signature,
                target_serial=int(target_blk.serial),
            )

        raw_ins_to_copy = [
            ins
            for ins in disp_ins
            if ins is not None and ins.opcode not in CONTROL_FLOW_OPCODES
        ]
        safe_copy_insns = resolver._filter_dependency_safe_copies(
            dispatcher_father,
            raw_ins_to_copy,
        )
        base_record = EmulatedDispatcherCandidateRecord(
            **{
                **base_record.__dict__,
                "state_signature": state_signature,
                "target_serial": int(target_blk.serial),
                "raw_side_effect_count": len(raw_ins_to_copy),
                "safe_side_effect_count": len(safe_copy_insns),
                "target_scc": scc_memberships.get(int(target_blk.serial), ()),
            }
        )

        def _record_for_modifications(
            modifications: tuple[GraphModification, ...],
        ) -> EmulatedDispatcherCandidateRecord:
            analogue_kind, _legacy_equivalent = self._legacy_analogue_for_candidate(
                modifications=modifications,
                source_nsucc=base_record.source_nsucc,
            )
            payload_signature: tuple[str, ...] = ()
            if safe_copy_insns:
                payload_signature = self._payload_signature(
                    tuple(capture_insn_snapshot(insn) for insn in safe_copy_insns)
                )
            elif deferred_side_effects:
                payload_signature = self._payload_signature(deferred_side_effects)
            cluster_key = ()
            if base_record.target_serial is not None:
                cluster_key = (
                    f"state={','.join(str(value) for value in base_record.state_signature)}",
                    f"target={base_record.target_serial}",
                    f"payload={';'.join(payload_signature)}",
                    f"source_scc={','.join(str(value) for value in base_record.source_scc)}",
                    f"target_scc={','.join(str(value) for value in base_record.target_scc)}",
                    f"source_nsucc={base_record.source_nsucc}",
                )
            return EmulatedDispatcherCandidateRecord(
                **{
                    **base_record.__dict__,
                    "selection_reason": self._selection_reason_for_candidate(
                        modifications=modifications,
                        raw_side_effect_count=len(raw_ins_to_copy),
                        deferred_side_effect_count=len(deferred_side_effects or ()),
                    ),
                    "selected_modification_kinds": tuple(
                        type(mod).__name__ for mod in modifications
                    ),
                    "selected_modification_summaries": tuple(
                        self._summarize_modification(mod) for mod in modifications
                    ),
                    "legacy_analogue_kind": analogue_kind,
                    "semantically_valid": True,
                    "structurally_legacy_equivalent": None,
                    "payload_signature": payload_signature,
                    "cluster_key": cluster_key,
                }
            )

        def _build_conditional_redirect_candidate(
            instructions: tuple[object, ...] = (),
        ) -> tuple[
            tuple[GraphModification, ...],
            None,
            EmulatedDispatcherCandidateRecord,
        ] | tuple[None, str, EmulatedDispatcherCandidateRecord] | None:
            if (
                target_blk.nsucc() != 2
                or target_blk.tail is None
                or not ida_hexrays.is_mcode_jcond(target_blk.tail.opcode)
            ):
                return None
            if dispatcher_father.nsucc() != 1:
                reason = "dispatcher_conditional_target_requires_one_way_source"
                return None, reason, _blocked_record(
                    reason,
                    state_signature=state_signature,
                    target_serial=int(target_blk.serial),
                    raw_side_effect_count=len(raw_ins_to_copy),
                    safe_side_effect_count=len(safe_copy_insns),
                )
            if target_blk.nextb is None:
                reason = "dispatcher_target_missing_fallthrough"
                return None, reason, _blocked_record(
                    reason,
                    state_signature=state_signature,
                    target_serial=int(target_blk.serial),
                    raw_side_effect_count=len(raw_ins_to_copy),
                    safe_side_effect_count=len(safe_copy_insns),
                )
            conditional_target = int(target_blk.tail.d.b)
            fallthrough_target = int(target_blk.nextb.serial)
            if conditional_target == dispatcher_father.serial:
                reason = "dispatcher_conditional_target_self_loop"
                return None, reason, _blocked_record(
                    reason,
                    state_signature=state_signature,
                    target_serial=int(target_blk.serial),
                    raw_side_effect_count=len(raw_ins_to_copy),
                    safe_side_effect_count=len(safe_copy_insns),
                )
            if fallthrough_target == dispatcher_father.serial:
                reason = "dispatcher_fallthrough_target_self_loop"
                return None, reason, _blocked_record(
                    reason,
                    state_signature=state_signature,
                    target_serial=int(target_blk.serial),
                    raw_side_effect_count=len(raw_ins_to_copy),
                    safe_side_effect_count=len(safe_copy_insns),
                )
            modifications = (
                CreateConditionalRedirect(
                    source_block=int(dispatcher_father.serial),
                    ref_block=int(target_blk.serial),
                    conditional_target=conditional_target,
                    fallthrough_target=fallthrough_target,
                    instructions=instructions,
                ),
            )
            return modifications, None, _record_for_modifications(modifications)

        if raw_ins_to_copy and not safe_copy_insns:
            reason = "dispatcher_side_effects_not_dependency_safe"
            return None, reason, _blocked_record(
                reason,
                state_signature=state_signature,
                target_serial=int(target_blk.serial),
                raw_side_effect_count=len(raw_ins_to_copy),
                safe_side_effect_count=len(safe_copy_insns),
            )

        if safe_copy_insns:
            safe_copy_snapshots = tuple(
                capture_insn_snapshot(insn) for insn in safe_copy_insns
            )
            if resolver.mba.maturity == ida_hexrays.MMAT_CALLS:
                self._deferred_side_effects[
                    (
                        int(resolver.mba.entry_ea),
                        int(dispatcher_info.entry_block.serial),
                        state_signature,
                    )
                ] = safe_copy_snapshots
                reason = "dispatcher_side_effects_deferred_to_later_maturity"
                return None, reason, _blocked_record(
                    reason,
                    state_signature=state_signature,
                    target_serial=int(target_blk.serial),
                    raw_side_effect_count=len(raw_ins_to_copy),
                    safe_side_effect_count=len(safe_copy_insns),
                )
            if dispatcher_father.nsucc() != 1:
                reason = "dispatcher_insert_requires_one_way_source"
                return None, reason, _blocked_record(
                    reason,
                    state_signature=state_signature,
                    target_serial=int(target_blk.serial),
                    raw_side_effect_count=len(raw_ins_to_copy),
                    safe_side_effect_count=len(safe_copy_insns),
                )
            modifications = (
                InsertBlock(
                    pred_serial=int(dispatcher_father.serial),
                    succ_serial=int(target_blk.serial),
                    instructions=safe_copy_snapshots,
                    old_target_serial=int(dispatcher_father.succ(0)),
                ),
            )
            return modifications, None, _record_for_modifications(modifications)

        if deferred_side_effects:
            if dispatcher_father.nsucc() != 1:
                reason = "dispatcher_insert_requires_one_way_source"
                return None, reason, _blocked_record(
                    reason,
                    state_signature=state_signature,
                    target_serial=int(target_blk.serial),
                    raw_side_effect_count=len(raw_ins_to_copy),
                    safe_side_effect_count=len(safe_copy_insns),
                )
            modifications = (
                InsertBlock(
                    pred_serial=int(dispatcher_father.serial),
                    succ_serial=int(target_blk.serial),
                    instructions=deferred_side_effects,
                    old_target_serial=int(dispatcher_father.succ(0)),
                ),
            )
            return modifications, None, _record_for_modifications(modifications)

        clone_conditional_targets = (
            os.environ.get("D810_UNFLAT_CLONE_COND_TARGET", "").strip().lower()
            in ("1", "true", "yes", "on")
        )
        if clone_conditional_targets:
            conditional_redirect = _build_conditional_redirect_candidate()
            if conditional_redirect is not None:
                return conditional_redirect

        if dispatcher_father.nsucc() == 1:
            modifications = (
                RedirectGoto(
                    from_serial=int(dispatcher_father.serial),
                    old_target=int(dispatcher_father.succ(0)),
                    new_target=int(target_blk.serial),
                ),
            )
            return modifications, None, _record_for_modifications(modifications)

        if (
            dispatcher_father.nsucc() == 2
            and dispatcher_father.tail is not None
            and ida_hexrays.is_mcode_jcond(dispatcher_father.tail.opcode)
        ):
            modifications = (
                ConvertToGoto(
                    block_serial=int(dispatcher_father.serial),
                    goto_target=int(target_blk.serial),
                ),
            )
            return modifications, None, _record_for_modifications(modifications)

        reason = "dispatcher_source_shape_not_lowered"
        return None, reason, _blocked_record(
            reason,
            state_signature=state_signature,
            target_serial=int(target_blk.serial),
            raw_side_effect_count=len(raw_ins_to_copy),
            safe_side_effect_count=len(safe_copy_insns),
        )

    def build_snapshot(
        self,
        mba: object,
        detection: EmulatedDispatcherDetection,
    ) -> AnalysisSnapshot:
        self._prepare_dispatcher_fathers(mba, detection)
        flow_graph = self._cfg_translator.lift(mba)
        phase_artifact, phase_context = self._build_phase_artifact(
            mba,
            detection,
            flow_graph=flow_graph,
        )
        fallback_modifications, fallback_blockers, candidate_records = self._collect_lowering_candidates(
            mba, detection, flow_graph=flow_graph
        )
        loop_recovery_modifications: tuple[GraphModification, ...] = ()
        loop_recovery_blockers: tuple[str, ...] = ()
        if mba.maturity >= ida_hexrays.MMAT_GLBOPT1 and detection.collector_dispatchers:
            loop_recovery_modifications, loop_recovery_blockers = (
                self._collect_loop_recovery_modifications(
                    mba=mba,
                    snapshot_flow_graph=flow_graph,
                    phase_artifact=phase_artifact,
                    phase_context=phase_context,
                    candidate_records=candidate_records,
                )
            )
        selected_modifications = fallback_modifications
        selected_lowering_mode = detection.lowering_mode
        selected_blockers = fallback_blockers
        if loop_recovery_modifications and not loop_recovery_blockers:
            selected_modifications = loop_recovery_modifications
            selected_lowering_mode = "dispatcher_loop_recovery"
            selected_blockers = ()
        # Match the safer legacy posture for partially-resolved dispatcher
        # families: observe raw candidates for diagnostics, but do not lower
        # any dispatcher edits unless all predecessor histories needed for the
        # current collector view are resolvable.
        planning_ready = bool(selected_modifications) and not selected_blockers
        planning_blocker = None
        if not planning_ready:
            if selected_blockers:
                planning_blocker = selected_blockers[0]
            else:
                planning_blocker = detection.planning_blocker
        observation = EmulatedDispatcherMetadata(
            dispatcher_shape=detection.dispatcher_shape,
            state_transport=detection.state_transport,
            lowering_mode=selected_lowering_mode,
            provenance_hints=detection.provenance_hints,
            analysis_dispatchers=detection.analysis_dispatchers,
            state_constants=detection.state_constants,
            collector_dispatchers=detection.collector_dispatcher_entries,
            planning_ready=planning_ready,
            planning_blocker=planning_blocker,
            candidate_count=len(fallback_modifications),
            rejected_fathers=len(fallback_blockers),
            candidate_kinds=tuple(type(mod).__name__ for mod in selected_modifications),
            rejection_reasons=tuple(sorted(set(fallback_blockers))),
            candidate_records=candidate_records,
            phase_artifact=phase_artifact,
            selected_lowering_mode=selected_lowering_mode,
            selected_modification_count=len(selected_modifications),
            loop_recovery_modification_count=len(loop_recovery_modifications),
        )
        flow_graph = FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata={
                **dict(flow_graph.metadata),
                EMULATED_DISPATCHER_METADATA_KEY: observation,
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: selected_modifications,
                EMULATED_DISPATCHER_FALLBACK_MODIFICATIONS_KEY: fallback_modifications,
                EMULATED_DISPATCHER_LOOP_RECOVERY_MODIFICATIONS_KEY: loop_recovery_modifications,
                EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY: candidate_records,
                EMULATED_DISPATCHER_PHASE_ARTIFACT_KEY: phase_artifact,
                EMULATED_DISPATCHER_PHASE_CONTEXT_KEY: phase_context,
            },
        )
        return AnalysisSnapshot(
            mba=mba,
            dispatcher_cache=DispatcherCache.get_or_create(mba),
            reachability=self.compute_reachability_info(mba),
            maturity=mba.maturity,
            flow_graph=flow_graph,
            state_summary=StateModelSummary(
                state_constants=frozenset(detection.state_constants),
                handler_count=len(detection.analysis_dispatchers),
                transition_count=0,
            ),
        )

    def _prepare_dispatcher_fathers(
        self,
        mba: ida_hexrays.mba_t,
        detection: EmulatedDispatcherDetection,
    ) -> int:
        if mba.maturity != ida_hexrays.MMAT_CALLS:
            return 0
        if not detection.collector_dispatchers:
            return 0

        resolver = self._make_resolver(mba, detection)
        total_changes = resolver.ensure_all_dispatcher_fathers_are_direct()
        if total_changes > 0:
            mba.mark_chains_dirty()
            self._logger.info(
                "Prepared emulated-dispatcher direct fathers: %d change(s)",
                total_changes,
            )
        return int(total_changes)

    def compute_reachability_info(self, mba: ida_hexrays.mba_t) -> ReachabilityInfo:
        visited: set[int] = set()
        queue = [0]
        while queue:
            serial = queue.pop()
            if serial in visited or serial < 0 or serial >= mba.qty:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for i in range(blk.nsucc()):
                queue.append(int(blk.succ(i)))
        return ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset(visited),
            total_blocks=int(mba.qty),
        )

    def post_execute_cleanup(
        self,
        mba: ida_hexrays.mba_t,
        *,
        snapshot: AnalysisSnapshot,
        total_changes: int,
    ) -> int:
        """Mirror the legacy generic post-apply cleanup tail.

        After successful redirect lowering, run deep cleaning and one local
        optimization round so Hex-Rays can collapse the rewritten dispatcher
        shape into cleaner pseudocode, matching the old generic path more
        closely.
        """
        if total_changes <= 0:
            return 0

        lowered_modifications = ()
        if snapshot.flow_graph is not None:
            lowered_modifications = tuple(
                mod
                for mod in snapshot.flow_graph.metadata.get(
                    EMULATED_DISPATCHER_MODIFICATIONS_KEY, ()
                )
                if isinstance(mod, GraphModification)
            )
        if any(
            isinstance(mod, (InsertBlock, CreateConditionalRedirect))
            for mod in lowered_modifications
        ):
            self._logger.info(
                "Skipping post-execute deep cleaning for side-effect or conditional redirect rewrites"
            )
            mba.mark_chains_dirty()
            safe_verify(
                mba,
                "verifying EmulatedDispatcherUnflattener.optimize after deferred edge-split apply",
                logger_func=self._logger.error,
            )
            return 0

        nb_clean = mba_deep_cleaning(mba, False)
        if total_changes + nb_clean > 0:
            mba.mark_chains_dirty()
            mba.optimize_local(0)
        safe_verify(
            mba,
            "optimizing EmulatedDispatcherUnflattener.optimize",
            logger_func=self._logger.error,
        )
        return int(nb_clean)
