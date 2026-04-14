"""Family adapter for the extracted emulated-dispatcher detection path."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    ConvertToGoto,
    GraphModification,
    InsertBlock,
    RedirectGoto,
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
    EMULATED_DISPATCHER_METADATA_KEY,
    EMULATED_DISPATCHER_MODIFICATIONS_KEY,
    EmulatedDispatcherMetadata,
    EmulatedDispatcherStrategy,
)
from d810.optimizers.microcode.flow.flattening.unflattener import (
    OllvmDispatcherCollector,
    Unflattener,
)
from d810.recon.flow.dispatcher_detection import DispatcherCache

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
        self._strategies = [EmulatedDispatcherStrategy()]

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
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        if not detection.collector_dispatchers:
            return (), ()

        resolver = self._make_resolver(mba, detection)

        modifications: list[GraphModification] = []
        blockers: list[str] = []
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
                candidate, reason = self._build_lowering_candidate(
                    resolver,
                    pred_blk,
                    dispatcher_info,
                )
                if candidate is not None:
                    modifications.extend(candidate)
                elif reason is not None:
                    blockers.append(reason)

        return tuple(modifications), tuple(blockers)

    def _build_lowering_candidate(
        self,
        resolver: Unflattener,
        dispatcher_father: ida_hexrays.mblock_t,
        dispatcher_info: object,
    ) -> tuple[tuple[GraphModification, ...] | None, str | None]:
        histories = resolver.get_dispatcher_father_histories(
            dispatcher_father,
            dispatcher_info.entry_block,
            dispatcher_info,
        )
        if not histories:
            return None, "dispatcher_history_missing"
        if not resolver.check_if_histories_are_resolved(histories):
            return None, "dispatcher_history_unresolved"

        values = get_all_possibles_values(
            histories,
            dispatcher_info.entry_block.use_before_def_list,
            verbose=False,
        )
        if not check_if_all_values_are_found(values):
            return None, "dispatcher_history_missing_values"
        if any(candidate != values[0] for candidate in values[1:]):
            return None, "dispatcher_history_ambiguous"

        target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(
            histories[0],
            resolve_conditional_exits=True,
        )
        if target_blk is None:
            return None, "dispatcher_emulation_returned_no_target"
        if target_blk.serial == dispatcher_father.serial:
            return None, "dispatcher_target_self_loop"
        if (
            target_blk.nsucc() == 2
            and target_blk.tail is not None
            and ida_hexrays.is_mcode_jcond(target_blk.tail.opcode)
        ):
            return None, "dispatcher_target_conditional_not_lowered"

        raw_ins_to_copy = [
            ins
            for ins in disp_ins
            if ins is not None and ins.opcode not in CONTROL_FLOW_OPCODES
        ]
        safe_copy_insns = resolver._filter_dependency_safe_copies(
            dispatcher_father,
            raw_ins_to_copy,
        )
        if raw_ins_to_copy and not safe_copy_insns:
            return None, "dispatcher_side_effects_not_dependency_safe"

        if safe_copy_insns:
            if dispatcher_father.nsucc() != 1:
                return None, "dispatcher_insert_requires_one_way_source"
            return (
                (
                    InsertBlock(
                        pred_serial=int(dispatcher_father.serial),
                        succ_serial=int(target_blk.serial),
                        instructions=tuple(
                            capture_insn_snapshot(insn) for insn in safe_copy_insns
                        ),
                    ),
                ),
                None,
            )

        if dispatcher_father.nsucc() == 1:
            return (
                (
                    RedirectGoto(
                        from_serial=int(dispatcher_father.serial),
                        old_target=int(dispatcher_father.succ(0)),
                        new_target=int(target_blk.serial),
                    ),
                ),
                None,
            )

        if (
            dispatcher_father.nsucc() == 2
            and dispatcher_father.tail is not None
            and ida_hexrays.is_mcode_jcond(dispatcher_father.tail.opcode)
        ):
            return (
                (
                    ConvertToGoto(
                        block_serial=int(dispatcher_father.serial),
                        goto_target=int(target_blk.serial),
                    ),
                ),
                None,
            )

        return None, "dispatcher_source_shape_not_lowered"

    def build_snapshot(
        self,
        mba: object,
        detection: EmulatedDispatcherDetection,
    ) -> AnalysisSnapshot:
        flow_graph = self._cfg_translator.lift(mba)
        modifications, blockers = self._collect_lowering_candidates(mba, detection)
        # Match the safer legacy posture for partially-resolved dispatcher
        # families: observe raw candidates for diagnostics, but do not lower
        # any dispatcher edits unless all predecessor histories needed for the
        # current collector view are resolvable.
        planning_ready = bool(modifications) and not blockers
        planning_blocker = None
        if not planning_ready:
            if blockers:
                planning_blocker = blockers[0]
            else:
                planning_blocker = detection.planning_blocker
        observation = EmulatedDispatcherMetadata(
            dispatcher_shape=detection.dispatcher_shape,
            state_transport=detection.state_transport,
            lowering_mode=detection.lowering_mode,
            provenance_hints=detection.provenance_hints,
            analysis_dispatchers=detection.analysis_dispatchers,
            state_constants=detection.state_constants,
            collector_dispatchers=detection.collector_dispatcher_entries,
            planning_ready=planning_ready,
            planning_blocker=planning_blocker,
            candidate_count=len(modifications),
            rejected_fathers=len(blockers),
            candidate_kinds=tuple(type(mod).__name__ for mod in modifications),
            rejection_reasons=tuple(sorted(set(blockers))),
        )
        flow_graph = FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata={
                **dict(flow_graph.metadata),
                EMULATED_DISPATCHER_METADATA_KEY: observation,
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: modifications,
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
