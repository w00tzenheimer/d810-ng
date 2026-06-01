"""Generic cleanup family for non-Hodur simple-flattening fragments."""
from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.core import getLogger
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.optimizers.microcode.flow.flattening.cleanup_backend import (
    LiveSimpleFlatteningCleanupBackend,
    SimpleFlatteningCleanupBackend,
    SimpleFlatteningCleanupDetection,
)
from d810.transforms.cleanup_evidence import (
    CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY,
    CLEANUP_DUPLICATE_REPLAY_METADATA_KEY,
    CLEANUP_FOLLOW_UP_RECLASSIFICATION_METADATA_KEY,
    CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY,
    CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY,
    extract_conditional_redirect_proofs,
    extract_duplicate_group_replay_candidates,
    extract_side_effect_replay_candidates,
    extract_trampoline_isolation_candidates,
    reclassify_bad_while_loop_follow_ups,
    serialize_conditional_redirect_proofs,
    serialize_follow_up_reclassifications,
)
from d810.families.state_machine_cff.family import (
    CFFStrategyFamily,
)
from d810.transforms.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
    StateModelSummary,
)
from d810.passes.bad_while_loop import (
    BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY,
    BAD_WHILE_LOOP_EDITS_METADATA_KEY,
    BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY,
    BadWhileLoopStrategy,
    extract_bad_while_loop_dependency_diagnostics,
    extract_bad_while_loop_edits,
    extract_bad_while_loop_follow_up,
    serialize_bad_while_loop_dependency_diagnostics,
    serialize_bad_while_loop_edits,
    serialize_bad_while_loop_follow_up,
)
from d810.passes.fake_jump import (
    FAKE_JUMP_FIXES_METADATA_KEY,
    FakeJumpStrategy,
    extract_fake_jump_fixes,
    serialize_fake_jump_fixes,
)
from d810.passes.fix_predecessor_branch_arm import (
    FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY,
    FixPredecessorBranchArmStrategy,
    build_fix_predecessor_branch_arm_modifications,
    extract_fix_predecessor_branch_arm_fixes,
    serialize_fix_predecessor_branch_arm_fixes,
)
from d810.passes.guarded_state_machine import (
    GuardedStateMachineStrategy,
)
from d810.passes.local_select_loop import (
    LocalSelectLoopStrategy,
)
from d810.passes.side_effect_select_loop import (
    SideEffectSelectLoopStrategy,
)
from d810.passes.selector_shell import (
    SelectorShellStrategy,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SINGLE_ITERATION_CONVERTS_METADATA_KEY,
    SINGLE_ITERATION_FIXES_METADATA_KEY,
    SingleIterationStrategy,
    extract_single_iteration_converts,
    extract_single_iteration_fixes,
    serialize_single_iteration_converts,
    serialize_single_iteration_fixes,
)
from d810.passes.tail_goto_merge import (
    TAIL_GOTO_MERGE_METADATA_KEY,
    TailGotoMergeStrategy,
    extract_tail_goto_merge_candidates,
    serialize_tail_goto_merge_candidates,
)
from d810.analyses.control_flow.graph_reachability import compute_reachable_blocks
from d810.analyses.control_flow.guarded_state_machine import (
    GUARDED_STATE_MACHINE_FIXES_METADATA_KEY,
    extract_guarded_state_machine_fixes,
    serialize_guarded_state_machine_fixes,
)
from d810.analyses.control_flow.local_select_loop import (
    LOCAL_SELECT_LOOP_FIXES_METADATA_KEY,
    extract_local_select_loop_fixes,
    serialize_local_select_loop_fixes,
)
from d810.analyses.control_flow.selector_shell import (
    SELECTOR_SHELL_FACTS_METADATA_KEY,
    extract_selector_shell_facts,
    serialize_selector_shell_facts,
)
from d810.analyses.control_flow.side_effect_select_loop import (
    SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY,
    extract_side_effect_select_loop_fixes,
    serialize_side_effect_select_loop_fixes,
)

family_logger = getLogger("D810.unflat.cleanup_family")

CLEANUP_FAMILY_METADATA_KEY = "simple_flattening_cleanup"

NORMALIZED_RECON_CFG_SCOPE = "normalized_recon_cfg_fact"
ENGINE_CLEANUP_SCOPE = "engine_cleanup"

_STRATEGY_SCOPES = {
    "guarded_state_machine": NORMALIZED_RECON_CFG_SCOPE,
    "local_select_loop": NORMALIZED_RECON_CFG_SCOPE,
    "side_effect_select_loop": NORMALIZED_RECON_CFG_SCOPE,
    "selector_shell": NORMALIZED_RECON_CFG_SCOPE,
}

__all__ = [
    "CLEANUP_FAMILY_METADATA_KEY",
    "LiveSimpleFlatteningCleanupBackend",
    "SimpleFlatteningCleanupBackend",
    "SimpleFlatteningCleanupDetection",
    "SimpleFlatteningCleanupFamily",
    "SimpleFlatteningCleanupMetadata",
]


@dataclass(frozen=True)
class SimpleFlatteningCleanupMetadata:
    """Diagnostic envelope for the generic cleanup engine family."""

    family_name: str
    strategy_names: tuple[str, ...]
    strategy_scopes: tuple[tuple[str, str], ...]
    maturity: int
    func_ea: int
    collected_fake_jump_fixes: int
    selected_fake_jump_fixes: int
    collected_single_iteration_fixes: int
    selected_single_iteration_fixes: int
    planning_ready: bool
    collection_errors: tuple[str, ...] = ()
    collected_single_iteration_converts: int = 0
    selected_single_iteration_converts: int = 0
    collected_bad_while_loop_edits: int = 0
    selected_bad_while_loop_edits: int = 0
    deferred_bad_while_loop_edits: int = 0
    bad_while_loop_follow_up: int = 0
    collected_bad_while_loop_replay_candidates: int = 0
    selected_bad_while_loop_replay_candidates: int = 0
    collected_bad_while_loop_duplicate_replay_candidates: int = 0
    selected_bad_while_loop_duplicate_replay_candidates: int = 0
    collected_bad_while_loop_trampoline_isolation_candidates: int = 0
    selected_bad_while_loop_trampoline_isolation_candidates: int = 0
    collected_bad_while_loop_conditional_redirect_proofs: int = 0
    selected_bad_while_loop_conditional_redirect_proofs: int = 0
    bad_while_loop_follow_up_reclassifications: int = 0
    bad_while_loop_dependency_diagnostics: int = 0
    collected_fix_predecessor_branch_arm_fixes: int = 0
    selected_fix_predecessor_branch_arm_fixes: int = 0
    collected_tail_goto_merges: int = 0
    selected_tail_goto_merges: int = 0
    collected_guarded_state_machine_fixes: int = 0
    selected_guarded_state_machine_fixes: int = 0
    collected_local_select_loop_fixes: int = 0
    selected_local_select_loop_fixes: int = 0
    collected_side_effect_select_loop_fixes: int = 0
    selected_side_effect_select_loop_fixes: int = 0
    collected_selector_shell_facts: int = 0
    selected_selector_shell_facts: int = 0


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
            GuardedStateMachineStrategy(),
            LocalSelectLoopStrategy(),
            SideEffectSelectLoopStrategy(),
            SelectorShellStrategy(),
            BadWhileLoopStrategy(),
            FixPredecessorBranchArmStrategy(),
            TailGotoMergeStrategy(),
        ]

    @property
    def name(self) -> str:
        return "simple_flattening_cleanup"

    @property
    def strategies(self) -> list:
        return list(self._strategies)

    def strategies_for_maturity(self, maturity: int | None = None) -> list:
        return list(self._strategies)

    def _strategy_scopes(self) -> tuple[tuple[str, str], ...]:
        return tuple(
            (
                strategy.name,
                _STRATEGY_SCOPES.get(strategy.name, ENGINE_CLEANUP_SCOPE),
            )
            for strategy in self._strategies
        )

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
            reachability=self.compute_reachability_info(flow_graph),
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
        if detection.single_iteration_converts:
            metadata[SINGLE_ITERATION_CONVERTS_METADATA_KEY] = (
                serialize_single_iteration_converts(detection.single_iteration_converts)
            )
        if detection.bad_while_loop_edits:
            metadata[BAD_WHILE_LOOP_EDITS_METADATA_KEY] = (
                serialize_bad_while_loop_edits(detection.bad_while_loop_edits)
            )
        if detection.bad_while_loop_replay_candidates:
            metadata[CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY] = tuple(
                detection.bad_while_loop_replay_candidates
            )
        if detection.bad_while_loop_duplicate_replay_candidates:
            metadata[CLEANUP_DUPLICATE_REPLAY_METADATA_KEY] = tuple(
                detection.bad_while_loop_duplicate_replay_candidates
            )
        if detection.bad_while_loop_trampoline_isolation_candidates:
            metadata[CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY] = tuple(
                detection.bad_while_loop_trampoline_isolation_candidates
            )
        if detection.bad_while_loop_conditional_redirect_proofs:
            metadata[CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY] = (
                serialize_conditional_redirect_proofs(
                    detection.bad_while_loop_conditional_redirect_proofs
                )
            )
        if detection.bad_while_loop_follow_up:
            metadata[BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY] = (
                serialize_bad_while_loop_follow_up(detection.bad_while_loop_follow_up)
            )
        if detection.bad_while_loop_dependency_diagnostics:
            metadata[BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY] = (
                serialize_bad_while_loop_dependency_diagnostics(
                    detection.bad_while_loop_dependency_diagnostics
                )
            )
        if detection.fix_predecessor_branch_arm_fixes:
            metadata[FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY] = (
                serialize_fix_predecessor_branch_arm_fixes(
                    detection.fix_predecessor_branch_arm_fixes
                )
            )
        if detection.tail_goto_merges:
            metadata[TAIL_GOTO_MERGE_METADATA_KEY] = (
                serialize_tail_goto_merge_candidates(detection.tail_goto_merges)
            )
        if detection.guarded_state_machine_fixes:
            metadata[GUARDED_STATE_MACHINE_FIXES_METADATA_KEY] = (
                serialize_guarded_state_machine_fixes(
                    detection.guarded_state_machine_fixes
                )
            )
        if detection.local_select_loop_fixes:
            metadata[LOCAL_SELECT_LOOP_FIXES_METADATA_KEY] = (
                serialize_local_select_loop_fixes(detection.local_select_loop_fixes)
            )
        if detection.side_effect_select_loop_fixes:
            metadata[SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY] = (
                serialize_side_effect_select_loop_fixes(
                    detection.side_effect_select_loop_fixes
                )
            )
        if detection.selector_shell_facts:
            metadata[SELECTOR_SHELL_FACTS_METADATA_KEY] = (
                serialize_selector_shell_facts(detection.selector_shell_facts)
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
        selected_single_iteration_converts = extract_single_iteration_converts(
            graph_with_candidates
        )
        selected_bad_while_loop_edits = extract_bad_while_loop_edits(
            graph_with_candidates
        )
        selected_bad_while_loop_replay_candidates = (
            extract_side_effect_replay_candidates(graph_with_candidates)
        )
        selected_bad_while_loop_duplicate_replay_candidates = (
            extract_duplicate_group_replay_candidates(graph_with_candidates)
        )
        selected_bad_while_loop_trampoline_isolation_candidates = (
            extract_trampoline_isolation_candidates(graph_with_candidates)
        )
        selected_bad_while_loop_conditional_redirect_proofs = (
            extract_conditional_redirect_proofs(graph_with_candidates)
        )
        selected_bad_while_loop_follow_up = extract_bad_while_loop_follow_up(
            graph_with_candidates
        )
        selected_bad_while_loop_dependency_diagnostics = (
            extract_bad_while_loop_dependency_diagnostics(graph_with_candidates)
        )
        selected_bad_while_loop_follow_up_reclassifications = (
            reclassify_bad_while_loop_follow_ups(
                selected_bad_while_loop_follow_up,
                graph_with_candidates,
                edits=selected_bad_while_loop_edits,
                replay_candidates=selected_bad_while_loop_replay_candidates,
                duplicate_replay_candidates=(
                    selected_bad_while_loop_duplicate_replay_candidates
                ),
                trampoline_isolation_candidates=(
                    selected_bad_while_loop_trampoline_isolation_candidates
                ),
                conditional_redirect_proofs=(
                    selected_bad_while_loop_conditional_redirect_proofs
                ),
                dependency_diagnostics=(
                    selected_bad_while_loop_dependency_diagnostics
                ),
            )
        )
        candidate_branch_arm_fixes = extract_fix_predecessor_branch_arm_fixes(
            graph_with_candidates
        )
        # Pre-validate every branch-arm candidate through the dedicated
        # planner so the metadata records only the count of fixes the
        # engine path would emit primitives for.  Rejections (arm=0,
        # multi-pred target, side effects, etc.) drop here and stay in
        # legacy fallback.
        selected_branch_arm_modifications = (
            build_fix_predecessor_branch_arm_modifications(
                candidate_branch_arm_fixes,
                graph_with_candidates,
            )
        )
        selected_tail_goto_merges = extract_tail_goto_merge_candidates(
            graph_with_candidates
        )
        selected_guarded_state_machine_fixes = (
            extract_guarded_state_machine_fixes(graph_with_candidates)
        )
        selected_local_select_loop_fixes = extract_local_select_loop_fixes(
            graph_with_candidates
        )
        selected_side_effect_select_loop_fixes = (
            extract_side_effect_select_loop_fixes(graph_with_candidates)
        )
        selected_selector_shell_facts = extract_selector_shell_facts(
            graph_with_candidates
        )

        metadata[FAKE_JUMP_FIXES_METADATA_KEY] = serialize_fake_jump_fixes(
            selected_fake_jump_fixes
        )
        metadata[SINGLE_ITERATION_FIXES_METADATA_KEY] = (
            serialize_single_iteration_fixes(selected_single_iteration_fixes)
        )
        metadata[SINGLE_ITERATION_CONVERTS_METADATA_KEY] = (
            serialize_single_iteration_converts(selected_single_iteration_converts)
        )
        metadata[BAD_WHILE_LOOP_EDITS_METADATA_KEY] = (
            serialize_bad_while_loop_edits(selected_bad_while_loop_edits)
        )
        metadata[CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY] = tuple(
            selected_bad_while_loop_replay_candidates
        )
        metadata[CLEANUP_DUPLICATE_REPLAY_METADATA_KEY] = tuple(
            selected_bad_while_loop_duplicate_replay_candidates
        )
        metadata[CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY] = tuple(
            selected_bad_while_loop_trampoline_isolation_candidates
        )
        metadata[CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY] = (
            serialize_conditional_redirect_proofs(
                selected_bad_while_loop_conditional_redirect_proofs
            )
        )
        metadata[CLEANUP_FOLLOW_UP_RECLASSIFICATION_METADATA_KEY] = (
            serialize_follow_up_reclassifications(
                selected_bad_while_loop_follow_up_reclassifications
            )
        )
        metadata[BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY] = (
            serialize_bad_while_loop_follow_up(selected_bad_while_loop_follow_up)
        )
        metadata[BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY] = (
            serialize_bad_while_loop_dependency_diagnostics(
                selected_bad_while_loop_dependency_diagnostics
            )
        )
        metadata[FIX_PREDECESSOR_BRANCH_ARM_FIXES_METADATA_KEY] = (
            serialize_fix_predecessor_branch_arm_fixes(candidate_branch_arm_fixes)
        )
        metadata[TAIL_GOTO_MERGE_METADATA_KEY] = (
            serialize_tail_goto_merge_candidates(selected_tail_goto_merges)
        )
        metadata[GUARDED_STATE_MACHINE_FIXES_METADATA_KEY] = (
            serialize_guarded_state_machine_fixes(
                selected_guarded_state_machine_fixes
            )
        )
        metadata[LOCAL_SELECT_LOOP_FIXES_METADATA_KEY] = (
            serialize_local_select_loop_fixes(selected_local_select_loop_fixes)
        )
        metadata[SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY] = (
            serialize_side_effect_select_loop_fixes(
                selected_side_effect_select_loop_fixes
            )
        )
        metadata[SELECTOR_SHELL_FACTS_METADATA_KEY] = (
            serialize_selector_shell_facts(selected_selector_shell_facts)
        )
        metadata[CLEANUP_FAMILY_METADATA_KEY] = SimpleFlatteningCleanupMetadata(
            family_name=self.name,
            strategy_names=tuple(strategy.name for strategy in self._strategies),
            strategy_scopes=self._strategy_scopes(),
            maturity=detection.maturity,
            func_ea=detection.func_ea,
            collected_fake_jump_fixes=len(detection.fake_jump_fixes),
            selected_fake_jump_fixes=len(selected_fake_jump_fixes),
            collected_single_iteration_fixes=len(detection.single_iteration_fixes),
            selected_single_iteration_fixes=len(selected_single_iteration_fixes),
            collected_single_iteration_converts=len(
                detection.single_iteration_converts
            ),
            selected_single_iteration_converts=len(
                selected_single_iteration_converts
            ),
            planning_ready=bool(
                selected_fake_jump_fixes
                or selected_single_iteration_fixes
                or selected_single_iteration_converts
                or selected_bad_while_loop_edits
                or selected_bad_while_loop_replay_candidates
                or selected_bad_while_loop_duplicate_replay_candidates
                or selected_bad_while_loop_trampoline_isolation_candidates
                or selected_branch_arm_modifications
                or selected_tail_goto_merges
                or selected_guarded_state_machine_fixes
                or selected_local_select_loop_fixes
                or selected_side_effect_select_loop_fixes
                or selected_selector_shell_facts
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
            collected_bad_while_loop_duplicate_replay_candidates=len(
                detection.bad_while_loop_duplicate_replay_candidates
            ),
            selected_bad_while_loop_duplicate_replay_candidates=len(
                selected_bad_while_loop_duplicate_replay_candidates
            ),
            collected_bad_while_loop_trampoline_isolation_candidates=len(
                detection.bad_while_loop_trampoline_isolation_candidates
            ),
            selected_bad_while_loop_trampoline_isolation_candidates=len(
                selected_bad_while_loop_trampoline_isolation_candidates
            ),
            collected_bad_while_loop_conditional_redirect_proofs=len(
                detection.bad_while_loop_conditional_redirect_proofs
            ),
            selected_bad_while_loop_conditional_redirect_proofs=len(
                selected_bad_while_loop_conditional_redirect_proofs
            ),
            bad_while_loop_follow_up_reclassifications=len(
                selected_bad_while_loop_follow_up_reclassifications
            ),
            bad_while_loop_dependency_diagnostics=len(
                selected_bad_while_loop_dependency_diagnostics
            ),
            collected_fix_predecessor_branch_arm_fixes=len(
                detection.fix_predecessor_branch_arm_fixes
            ),
            selected_fix_predecessor_branch_arm_fixes=len(
                selected_branch_arm_modifications
            ),
            collected_tail_goto_merges=len(detection.tail_goto_merges),
            selected_tail_goto_merges=len(selected_tail_goto_merges),
            collected_guarded_state_machine_fixes=len(
                detection.guarded_state_machine_fixes
            ),
            selected_guarded_state_machine_fixes=len(
                selected_guarded_state_machine_fixes
            ),
            collected_local_select_loop_fixes=len(
                detection.local_select_loop_fixes
            ),
            selected_local_select_loop_fixes=len(selected_local_select_loop_fixes),
            collected_side_effect_select_loop_fixes=len(
                detection.side_effect_select_loop_fixes
            ),
            selected_side_effect_select_loop_fixes=len(
                selected_side_effect_select_loop_fixes
            ),
            collected_selector_shell_facts=len(detection.selector_shell_facts),
            selected_selector_shell_facts=len(selected_selector_shell_facts),
        )
        return FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata=metadata,
        )

    def compute_reachability_info(self, flow_graph: FlowGraph) -> ReachabilityInfo:
        reachable = compute_reachable_blocks(
            flow_graph,
            start_serial=flow_graph.entry_serial,
        )
        return ReachabilityInfo(
            entry_serial=int(flow_graph.entry_serial),
            reachable_blocks=frozenset(reachable or ()),
            total_blocks=int(flow_graph.block_count),
        )
