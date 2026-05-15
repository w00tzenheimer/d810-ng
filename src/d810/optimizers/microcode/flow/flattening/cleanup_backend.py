"""Backend boundary for live non-Hodur cleanup candidate collection."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import ida_hexrays

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.core.typing import Protocol
from d810.optimizers.microcode.flow.flattening.cleanup_evidence import (
    CleanupConditionalRedirectProof,
    CleanupDuplicateGroupReplayCandidate,
    CleanupSideEffectReplayCandidate,
    bad_while_loop_duplicate_candidate,
    explain_bad_while_loop_conditional_redirect,
    validate_duplicate_group_replay_candidate,
    validate_side_effect_replay_candidate,
    validate_dispatcher_cleanup_candidate,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BAD_WHILE_LOOP_INSERT_BLOCK,
    BadWhileLoopEdit,
    BadWhileLoopConditionalRedirect,
    BadWhileLoopDependencyDiagnostic,
    BadWhileLoopDuplicateRedirect,
    BadWhileLoopFollowUp,
    BadWhileLoopGotoConversion,
    BadWhileLoopGotoRedirect,
    collect_live_bad_while_loop_analysis,
)
from d810.optimizers.microcode.flow.flattening.strategies.fake_jump import (
    FakeJumpPredFix,
    collect_live_fake_jump_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.fix_predecessor_branch_arm import (
    FixPredecessorBranchArmFix,
    collect_live_fix_predecessor_branch_arm_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SingleIterationPredFix,
    collect_live_single_iteration_fixes,
)
from d810.hexrays.mutation.insn_snapshot_materializer import (
    HEXRAYS_INSN_SNAPSHOT_BODY_BACKEND_ID,
)
from d810.hexrays.mutation.ir_translator import IDAIRTranslator, capture_insn_snapshot

__all__ = [
    "LiveSimpleFlatteningCleanupBackend",
    "SimpleFlatteningCleanupBackend",
    "SimpleFlatteningCleanupDetection",
]


def _is_plannable_bad_while_loop_edit(
    edit: BadWhileLoopEdit,
    cfg: FlowGraph | None = None,
) -> bool:
    safe_edit_types = (BadWhileLoopGotoRedirect, BadWhileLoopGotoConversion)
    if isinstance(edit, safe_edit_types):
        return True
    if isinstance(edit, BadWhileLoopDuplicateRedirect):
        candidate = bad_while_loop_duplicate_candidate(edit)
        return (
            candidate is not None
            and cfg is not None
            and validate_dispatcher_cleanup_candidate(cfg, candidate)
        )
    return False


def _capture_bad_while_loop_side_effect_body(
    source_serial: int,
    instructions: Sequence[object],
) -> CapturedBlockBody | None:
    snapshots = tuple(capture_insn_snapshot(insn) for insn in instructions)
    if not snapshots:
        return None
    call_opcodes = {
        opcode
        for opcode in (
            getattr(ida_hexrays, "m_call", -1),
            getattr(ida_hexrays, "m_icall", -1),
        )
        if int(opcode) >= 0
    }
    source_eas = frozenset(
        int(snapshot.ea) for snapshot in snapshots if int(snapshot.ea) > 0
    )
    capture_id = "bad_while_loop:{source}:{count}:{eas}".format(
        source=int(source_serial),
        count=len(snapshots),
        eas=",".join(f"{ea:x}" for ea in sorted(source_eas)),
    )
    return CapturedBlockBody(
        backend_id=HEXRAYS_INSN_SNAPSHOT_BODY_BACKEND_ID,
        capture_id=capture_id,
        summary=CapturedBlockBodySummary(
            source_blocks=(int(source_serial),),
            instruction_count=len(snapshots),
            source_eas=source_eas,
            contains_call=any(snapshot.opcode in call_opcodes for snapshot in snapshots),
        ),
        payload=snapshots,
        metadata={
            "source_rule": "BadWhileLoop",
            "source_serial": int(source_serial),
        },
    )


def _validation_graph_for_bad_while_loop(
    mba: object,
    edits: tuple[BadWhileLoopEdit, ...],
    replay_candidates: tuple[CleanupSideEffectReplayCandidate, ...],
    duplicate_replay_candidates: tuple[CleanupDuplicateGroupReplayCandidate, ...],
    *,
    logger: object | None = None,
) -> FlowGraph | None:
    if (
        not replay_candidates
        and not duplicate_replay_candidates
        and not any(
            isinstance(
                edit,
                (BadWhileLoopDuplicateRedirect, BadWhileLoopConditionalRedirect),
            )
            for edit in edits
        )
    ):
        return None
    try:
        return IDAIRTranslator().lift(mba)
    except Exception:
        if logger is not None:
            logger.debug(
                "Failed to lift CFG for BadWhileLoop duplicate validation",
                exc_info=True,
            )
        return None


@dataclass(frozen=True)
class SimpleFlatteningCleanupDetection:
    """Live cleanup candidates collected before snapshot construction."""

    fake_jump_fixes: tuple[FakeJumpPredFix, ...] = ()
    single_iteration_fixes: tuple[SingleIterationPredFix, ...] = ()
    bad_while_loop_edits: tuple[BadWhileLoopEdit, ...] = ()
    bad_while_loop_replay_candidates: tuple[CleanupSideEffectReplayCandidate, ...] = ()
    bad_while_loop_duplicate_replay_candidates: tuple[
        CleanupDuplicateGroupReplayCandidate, ...
    ] = ()
    bad_while_loop_conditional_redirect_proofs: tuple[
        CleanupConditionalRedirectProof, ...
    ] = ()
    bad_while_loop_deferred_edits: tuple[BadWhileLoopEdit, ...] = ()
    bad_while_loop_follow_up: tuple[BadWhileLoopFollowUp, ...] = ()
    bad_while_loop_dependency_diagnostics: tuple[
        BadWhileLoopDependencyDiagnostic, ...
    ] = ()
    fix_predecessor_branch_arm_fixes: tuple[FixPredecessorBranchArmFix, ...] = ()
    collection_errors: tuple[str, ...] = ()
    maturity: int = 0
    func_ea: int = 0

    @property
    def detected(self) -> bool:
        return bool(
            self.fake_jump_fixes
            or self.single_iteration_fixes
            or self.bad_while_loop_edits
            or self.bad_while_loop_replay_candidates
            or self.bad_while_loop_duplicate_replay_candidates
            or self.fix_predecessor_branch_arm_fixes
        )

    @property
    def diagnostic_only(self) -> bool:
        return (
            not self.detected
            and bool(
                self.bad_while_loop_deferred_edits
                or self.bad_while_loop_follow_up
                or self.bad_while_loop_dependency_diagnostics
            )
        )

    @property
    def description(self) -> str:
        if not self.detected:
            if self.diagnostic_only:
                return (
                    "no plannable simple cleanup candidates detected: "
                    "bad_while_loop_deferred="
                    f"{len(self.bad_while_loop_deferred_edits)} "
                    f"bad_while_loop_follow_up={len(self.bad_while_loop_follow_up)} "
                    "bad_while_loop_dependency_diagnostics="
                    f"{len(self.bad_while_loop_dependency_diagnostics)} "
                    "bad_while_loop_conditional_redirect_proofs="
                    f"{len(self.bad_while_loop_conditional_redirect_proofs)}"
                )
            return "no simple cleanup candidates detected"
        return (
            "simple cleanup candidates detected: "
            f"fake_jump={len(self.fake_jump_fixes)} "
            f"single_iteration={len(self.single_iteration_fixes)} "
            f"bad_while_loop={len(self.bad_while_loop_edits)} "
            f"bad_while_loop_replay={len(self.bad_while_loop_replay_candidates)}"
            f" bad_while_loop_duplicate_replay="
            f"{len(self.bad_while_loop_duplicate_replay_candidates)}"
            f" bad_while_loop_conditional_redirect_proofs="
            f"{len(self.bad_while_loop_conditional_redirect_proofs)}"
            f" fix_predecessor_branch_arm="
            f"{len(self.fix_predecessor_branch_arm_fixes)}"
        )


class SimpleFlatteningCleanupBackend(Protocol):
    """Collector boundary consumed by the generic cleanup family."""

    def collect(
        self,
        mba: object,
        *,
        logger: object | None = None,
    ) -> SimpleFlatteningCleanupDetection:
        """Return live cleanup candidates for one MBA."""
        ...


class LiveSimpleFlatteningCleanupBackend:
    """Default IDA-backed collector for simple cleanup evidence."""

    def __init__(
        self,
        *,
        fake_jump_max_nb_block: int = 100,
        fake_jump_max_path: int = 100,
        allowed_maturities: tuple[int, ...] = (ida_hexrays.MMAT_GLBOPT1,),
    ) -> None:
        self.fake_jump_max_nb_block = int(fake_jump_max_nb_block)
        self.fake_jump_max_path = int(fake_jump_max_path)
        self.allowed_maturities = tuple(int(maturity) for maturity in allowed_maturities)

    def collect(
        self,
        mba: object,
        *,
        logger: object | None = None,
    ) -> SimpleFlatteningCleanupDetection:
        maturity = int(getattr(mba, "maturity", 0) or 0)
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        errors: list[str] = []

        fake_jump_fixes: tuple[FakeJumpPredFix, ...] = ()
        try:
            fake_jump_fixes = collect_live_fake_jump_fixes(
                mba,
                logger=logger,
                max_nb_block=self.fake_jump_max_nb_block,
                max_path=self.fake_jump_max_path,
                allowed_maturities=self.allowed_maturities,
            )
        except Exception as exc:
            errors.append(f"fake_jump:{type(exc).__name__}")
            if logger is not None:
                logger.debug(
                    "Failed to collect FakeJump cleanup candidates",
                    exc_info=True,
                )

        single_iteration_fixes: tuple[SingleIterationPredFix, ...] = ()
        try:
            single_iteration_fixes = collect_live_single_iteration_fixes(
                mba,
                logger=logger,
                allowed_maturities=self.allowed_maturities,
            )
        except Exception as exc:
            errors.append(f"single_iteration:{type(exc).__name__}")
            if logger is not None:
                logger.debug(
                    "Failed to collect single-iteration cleanup candidates",
                    exc_info=True,
                )

        bad_while_loop_edits: tuple[BadWhileLoopEdit, ...] = ()
        bad_while_loop_replay_candidates: tuple[CleanupSideEffectReplayCandidate, ...] = ()
        bad_while_loop_duplicate_replay_candidates: tuple[
            CleanupDuplicateGroupReplayCandidate, ...
        ] = ()
        bad_while_loop_conditional_redirect_proofs: tuple[
            CleanupConditionalRedirectProof, ...
        ] = ()
        bad_while_loop_deferred_edits: tuple[BadWhileLoopEdit, ...] = ()
        bad_while_loop_follow_up: tuple[BadWhileLoopFollowUp, ...] = ()
        bad_while_loop_dependency_diagnostics: tuple[
            BadWhileLoopDependencyDiagnostic, ...
        ] = ()
        try:
            bad_while_loop_analysis = collect_live_bad_while_loop_analysis(
                mba,
                logger=logger,
                allowed_maturities=self.allowed_maturities,
                side_effect_capture=_capture_bad_while_loop_side_effect_body,
            )
            bad_while_loop_all_edits = tuple(bad_while_loop_analysis.edits)
            bad_while_loop_all_replay_candidates = tuple(
                bad_while_loop_analysis.replay_candidates
            )
            bad_while_loop_all_duplicate_replay_candidates = tuple(
                bad_while_loop_analysis.duplicate_replay_candidates
            )
            bad_while_loop_dependency_diagnostics = tuple(
                bad_while_loop_analysis.dependency_diagnostics
            )
            bad_while_loop_validation_graph = _validation_graph_for_bad_while_loop(
                mba,
                bad_while_loop_all_edits,
                bad_while_loop_all_replay_candidates,
                bad_while_loop_all_duplicate_replay_candidates,
                logger=logger,
            )
            bad_while_loop_edits = tuple(
                edit
                for edit in bad_while_loop_all_edits
                if _is_plannable_bad_while_loop_edit(
                    edit,
                    bad_while_loop_validation_graph,
                )
            )
            bad_while_loop_replay_candidates = tuple(
                candidate
                for candidate in bad_while_loop_all_replay_candidates
                if bad_while_loop_validation_graph is not None
                and validate_side_effect_replay_candidate(
                    bad_while_loop_validation_graph,
                    candidate,
                )
            )
            bad_while_loop_duplicate_replay_candidates = tuple(
                candidate
                for candidate in bad_while_loop_all_duplicate_replay_candidates
                if bad_while_loop_validation_graph is not None
                and validate_duplicate_group_replay_candidate(
                    bad_while_loop_validation_graph,
                    candidate,
                )
            )
            if bad_while_loop_validation_graph is not None:
                conditional_redirect_proofs: list[
                    CleanupConditionalRedirectProof
                ] = []
                for edit in bad_while_loop_all_edits:
                    if not isinstance(edit, BadWhileLoopConditionalRedirect):
                        continue
                    proof = explain_bad_while_loop_conditional_redirect(
                        edit,
                        bad_while_loop_validation_graph,
                        defer_reason="conditional_redirect_not_promoted",
                    )
                    if proof is not None:
                        conditional_redirect_proofs.append(proof)
                bad_while_loop_conditional_redirect_proofs = tuple(
                    conditional_redirect_proofs
                )
            promoted_replay = {
                (
                    candidate.dispatcher_entry,
                    candidate.source_serial,
                    candidate.target_serial,
                )
                for candidate in bad_while_loop_replay_candidates
            }
            promoted_duplicate_replay = {
                (
                    candidate.dispatcher_entry,
                    candidate.source_serial,
                )
                for candidate in bad_while_loop_duplicate_replay_candidates
            }
            bad_while_loop_deferred_edits = tuple(
                edit
                for edit in bad_while_loop_all_edits
                if not _is_plannable_bad_while_loop_edit(
                    edit,
                    bad_while_loop_validation_graph,
                )
            )
            bad_while_loop_follow_up = tuple(
                item
                for item in bad_while_loop_analysis.follow_up
                if not (
                    item.category == BAD_WHILE_LOOP_INSERT_BLOCK
                    and item.reason == "copied_side_effects"
                    and (
                        item.dispatcher_entry,
                        item.from_serial,
                        item.target_serial,
                    )
                    in promoted_replay
                )
                and not (
                    item.reason == "duplicate_group_copied_side_effects"
                    and (
                        item.dispatcher_entry,
                        item.from_serial,
                    )
                    in promoted_duplicate_replay
                )
            )
        except Exception as exc:
            errors.append(f"bad_while_loop:{type(exc).__name__}")
            if logger is not None:
                logger.debug(
                    "Failed to collect BadWhileLoop cleanup candidates",
                    exc_info=True,
                )

        fix_predecessor_branch_arm_fixes: tuple[FixPredecessorBranchArmFix, ...] = ()
        try:
            fix_predecessor_branch_arm_fixes = (
                collect_live_fix_predecessor_branch_arm_fixes(
                    mba,
                    logger=logger,
                    allowed_maturities=self.allowed_maturities,
                )
            )
        except Exception as exc:
            errors.append(f"fix_predecessor_branch_arm:{type(exc).__name__}")
            if logger is not None:
                logger.debug(
                    "Failed to collect FixPredecessor branch-arm cleanup candidates",
                    exc_info=True,
                )

        return SimpleFlatteningCleanupDetection(
            fake_jump_fixes=tuple(fake_jump_fixes),
            single_iteration_fixes=tuple(single_iteration_fixes),
            bad_while_loop_edits=tuple(bad_while_loop_edits),
            bad_while_loop_replay_candidates=tuple(
                bad_while_loop_replay_candidates
            ),
            bad_while_loop_duplicate_replay_candidates=tuple(
                bad_while_loop_duplicate_replay_candidates
            ),
            bad_while_loop_conditional_redirect_proofs=tuple(
                bad_while_loop_conditional_redirect_proofs
            ),
            bad_while_loop_deferred_edits=tuple(bad_while_loop_deferred_edits),
            bad_while_loop_follow_up=tuple(bad_while_loop_follow_up),
            bad_while_loop_dependency_diagnostics=tuple(
                bad_while_loop_dependency_diagnostics
            ),
            fix_predecessor_branch_arm_fixes=tuple(
                fix_predecessor_branch_arm_fixes
            ),
            collection_errors=tuple(errors),
            maturity=maturity,
            func_ea=func_ea,
        )
