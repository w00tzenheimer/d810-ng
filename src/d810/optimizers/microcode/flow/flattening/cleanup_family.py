"""Generic cleanup family for non-Hodur simple-flattening fragments."""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flowgraph import FlowGraph
from d810.core import getLogger
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.optimizers.microcode.flow.flattening.cleanup_backend import (
    LiveSimpleFlatteningCleanupBackend,
    SimpleFlatteningCleanupBackend,
    SimpleFlatteningCleanupDetection,
)
from d810.optimizers.microcode.flow.flattening.cleanup_evidence import (
    CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY,
    extract_side_effect_replay_candidates,
)
from d810.optimizers.microcode.flow.flattening.engine.family import (
    CFFStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
    StateModelSummary,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BAD_WHILE_LOOP_EDITS_METADATA_KEY,
    BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY,
    BadWhileLoopStrategy,
    extract_bad_while_loop_edits,
    extract_bad_while_loop_follow_up,
    serialize_bad_while_loop_edits,
    serialize_bad_while_loop_follow_up,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpStrategy,
    extract_fake_jump_fixes,
    serialize_fake_jump_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SINGLE_ITERATION_FIXES_METADATA_KEY,
    SingleIterationStrategy,
    extract_single_iteration_fixes,
    serialize_single_iteration_fixes,
)

family_logger = getLogger("D810.unflat.cleanup_family")

CLEANUP_FAMILY_METADATA_KEY = "simple_flattening_cleanup"
LEGACY_CLEANUP_RULE_NAMES = (
    "UnflattenerFakeJump",
    "SingleIterationLoopUnflattener",
    "BadWhileLoop",
)

__all__ = [
    "CLEANUP_FAMILY_METADATA_KEY",
    "LEGACY_CLEANUP_RULE_NAMES",
    "LiveSimpleFlatteningCleanupBackend",
    "SimpleFlatteningCleanupBackend",
    "SimpleFlatteningCleanupDetection",
    "SimpleFlatteningCleanupFamily",
    "SimpleFlatteningCleanupMetadata",
]


@dataclass(frozen=True)
class SimpleFlatteningCleanupMetadata:
    """Diagnostic envelope for comparing engine cleanup with legacy rules."""

    family_name: str
    strategy_names: tuple[str, ...]
    legacy_rule_names: tuple[str, ...]
    maturity: int
    func_ea: int
    collected_fake_jump_fixes: int
    selected_fake_jump_fixes: int
    collected_single_iteration_fixes: int
    selected_single_iteration_fixes: int
    planning_ready: bool
    collection_errors: tuple[str, ...] = ()
    collected_bad_while_loop_edits: int = 0
    selected_bad_while_loop_edits: int = 0
    deferred_bad_while_loop_edits: int = 0
    bad_while_loop_follow_up: int = 0
    collected_bad_while_loop_replay_candidates: int = 0
    selected_bad_while_loop_replay_candidates: int = 0


class SimpleFlatteningCleanupFamily(CFFStrategyFamily):
    """Shared engine family for simple non-Hodur cleanup strategies."""

    def __init__(
        self,
        *,
        backend: SimpleFlatteningCleanupBackend | None = None,
        cfg_translator: IDAIRTranslator | None = None,
        logger=None,
    ) -> None:
        self._backend = backend or LiveSimpleFlatteningCleanupBackend()
        self._cfg_translator = cfg_translator or IDAIRTranslator()
        self._logger = logger or family_logger
        self._strategies = [
            FakeJumpStrategy(),
            SingleIterationStrategy(),
            BadWhileLoopStrategy(),
        ]

    @property
    def name(self) -> str:
        return "simple_flattening_cleanup"

    @property
    def strategies(self) -> list:
        return list(self._strategies)

    def strategies_for_maturity(self, maturity: int | None = None) -> list:
        return list(self._strategies)

    def detect(self, mba: object) -> SimpleFlatteningCleanupDetection:
        detection = self._backend.collect(mba, logger=self._logger)
        self._logger.info("Simple cleanup detect: %s", detection.description)
        return detection

    def build_snapshot(
        self,
        mba: object,
        detection: SimpleFlatteningCleanupDetection,
    ) -> AnalysisSnapshot:
        flow_graph = self._cfg_translator.lift(mba)
        flow_graph = self._attach_cleanup_metadata(flow_graph, detection)
        return AnalysisSnapshot(
            mba=mba,
            reachability=self.compute_reachability_info(mba),
            maturity=int(getattr(mba, "maturity", 0) or 0),
            flow_graph=flow_graph,
            state_summary=StateModelSummary(
                state_constants=frozenset(),
                handler_count=0,
                transition_count=0,
            ),
        )

    def _attach_cleanup_metadata(
        self,
        flow_graph: FlowGraph,
        detection: SimpleFlatteningCleanupDetection,
    ) -> FlowGraph:
        metadata = dict(flow_graph.metadata)
        if detection.fake_jump_fixes:
            metadata[FAKE_JUMP_FIXES_METADATA_KEY] = serialize_fake_jump_fixes(
                detection.fake_jump_fixes
            )
        if detection.single_iteration_fixes:
            metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] = (
                serialize_single_iteration_fixes(detection.single_iteration_fixes)
            )
        if detection.bad_while_loop_edits:
            metadata[BAD_WHILE_LOOP_EDITS_METADATA_KEY] = (
                serialize_bad_while_loop_edits(detection.bad_while_loop_edits)
            )
        if detection.bad_while_loop_replay_candidates:
            metadata[CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY] = tuple(
                detection.bad_while_loop_replay_candidates
            )
        if detection.bad_while_loop_follow_up:
            metadata[BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY] = (
                serialize_bad_while_loop_follow_up(detection.bad_while_loop_follow_up)
            )

        graph_with_candidates = FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata=metadata,
        )
        selected_fake_jump_fixes = extract_fake_jump_fixes(graph_with_candidates)
        selected_single_iteration_fixes = extract_single_iteration_fixes(
            graph_with_candidates
        )
        selected_bad_while_loop_edits = extract_bad_while_loop_edits(
            graph_with_candidates
        )
        selected_bad_while_loop_replay_candidates = (
            extract_side_effect_replay_candidates(graph_with_candidates)
        )
        selected_bad_while_loop_follow_up = extract_bad_while_loop_follow_up(
            graph_with_candidates
        )

        metadata[FAKE_JUMP_FIXES_METADATA_KEY] = serialize_fake_jump_fixes(
            selected_fake_jump_fixes
        )
        metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] = (
            serialize_single_iteration_fixes(selected_single_iteration_fixes)
        )
        metadata[BAD_WHILE_LOOP_EDITS_METADATA_KEY] = (
            serialize_bad_while_loop_edits(selected_bad_while_loop_edits)
        )
        metadata[CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY] = tuple(
            selected_bad_while_loop_replay_candidates
        )
        metadata[BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY] = (
            serialize_bad_while_loop_follow_up(selected_bad_while_loop_follow_up)
        )
        metadata[CLEANUP_FAMILY_METADATA_KEY] = SimpleFlatteningCleanupMetadata(
            family_name=self.name,
            strategy_names=tuple(strategy.name for strategy in self._strategies),
            legacy_rule_names=LEGACY_CLEANUP_RULE_NAMES,
            maturity=detection.maturity,
            func_ea=detection.func_ea,
            collected_fake_jump_fixes=len(detection.fake_jump_fixes),
            selected_fake_jump_fixes=len(selected_fake_jump_fixes),
            collected_single_iteration_fixes=len(detection.single_iteration_fixes),
            selected_single_iteration_fixes=len(selected_single_iteration_fixes),
            planning_ready=bool(
                selected_fake_jump_fixes
                or selected_single_iteration_fixes
                or selected_bad_while_loop_edits
                or selected_bad_while_loop_replay_candidates
            ),
            collection_errors=detection.collection_errors,
            collected_bad_while_loop_edits=(
                len(detection.bad_while_loop_edits)
                + len(detection.bad_while_loop_deferred_edits)
            ),
            selected_bad_while_loop_edits=len(selected_bad_while_loop_edits),
            deferred_bad_while_loop_edits=len(
                detection.bad_while_loop_deferred_edits
            ),
            bad_while_loop_follow_up=len(selected_bad_while_loop_follow_up),
            collected_bad_while_loop_replay_candidates=len(
                detection.bad_while_loop_replay_candidates
            ),
            selected_bad_while_loop_replay_candidates=len(
                selected_bad_while_loop_replay_candidates
            ),
        )
        return FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata=metadata,
        )

    def compute_reachability_info(self, mba: object) -> ReachabilityInfo:
        qty = int(getattr(mba, "qty", 0) or 0)
        visited: set[int] = set()
        queue = [0]
        while queue:
            serial = queue.pop()
            if serial in visited or serial < 0 or serial >= qty:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for index in range(blk.nsucc()):
                queue.append(int(blk.succ(index)))
        return ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset(visited),
            total_blocks=qty,
        )
