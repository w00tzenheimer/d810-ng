"""Backend boundary for live non-Hodur cleanup candidate collection."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace

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
    CleanupTrampolineIsolationCandidate,
    bad_while_loop_duplicate_candidate,
    explain_bad_while_loop_conditional_redirect,
    validate_conditional_duplicate_cleanup_edit,
    validate_conditional_redirect_cleanup_edit,
    validate_duplicate_group_replay_candidate,
    validate_side_effect_replay_candidate,
    validate_dispatcher_cleanup_candidate,
    validate_trampoline_isolation_candidate,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BAD_WHILE_LOOP_INSERT_BLOCK,
    BadWhileLoopEdit,
    BadWhileLoopConditionalDuplicate,
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
)
from d810.optimizers.microcode.flow.flattening.strategies.fix_predecessor_branch_arm import (
    FixPredecessorBranchArmFix,
    collect_live_fix_predecessor_branch_arm_fixes,
)
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SingleIterationPredFix,
)
from d810.optimizers.microcode.flow.flattening.strategies.tail_goto_merge import (
    TailGotoMergeCandidate,
    collect_tail_goto_merge_candidates,
)
from d810.evaluator.hexrays_microcode.instruction_capture_backend import (
    HexRaysInstructionCaptureBackend,
)
from d810.optimizers.microcode.flow.flattening.cleanup_live_evidence import (
    collect_live_fake_jump_block_fixes,
    collect_live_fake_jump_fixes,
    collect_live_single_iteration_block_fixes,
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
    "collect_live_fake_jump_block_fixes",
    "collect_live_fake_jump_fixes",
    "collect_live_single_iteration_block_fixes",
    "collect_live_single_iteration_fixes",
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
    if isinstance(edit, BadWhileLoopConditionalDuplicate):
        return cfg is not None and validate_conditional_duplicate_cleanup_edit(
            cfg,
            edit,
        )
    if isinstance(edit, BadWhileLoopConditionalRedirect):
        return cfg is not None and validate_conditional_redirect_cleanup_edit(
            cfg,
            edit,
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
            "source_rule": "bad_while_loop",
            "source_serial": int(source_serial),
        },
    )


def _capture_bad_while_loop_dependency_rescue_body(
    mba: object,
    source_serial: int,
    instructions: Sequence[object],
    diagnostic: dict[str, object],
) -> CapturedBlockBody | None:
    """Capture the narrow stack-unique def chain before copied side effects."""
    if diagnostic.get("final_bucket") != "stack_unique_def_chain_capturable":
        return None
    initial_reads = _stack_reads_from_dependency_diagnostic(diagnostic)
    if not initial_reads:
        return None

    capture_backend = HexRaysInstructionCaptureBackend()
    def_chain = capture_backend.capture_transitive_def_chain(
        mba,
        int(source_serial),
        initial_reads,
    )
    if def_chain is None:
        return None
    copied_body = _capture_bad_while_loop_side_effect_body(
        source_serial,
        instructions,
    )
    if copied_body is None:
        return None
    combined = capture_backend.combine_bodies(
        (def_chain, copied_body),
        capture_id="bad_while_loop_dependency_rescue:{source}:{count}".format(
            source=int(source_serial),
            count=def_chain.instruction_count + copied_body.instruction_count,
        ),
    )
    if combined.summary.contains_call:
        return None
    if capture_backend.validate_body(combined) is not None:
        return None
    snapshots = capture_backend.snapshots_from_body(combined)
    if capture_backend.collect_unresolved_stkvar_reads(
        snapshots,
        state_variable=None,
    ):
        return None
    return replace(
        combined,
        metadata={
            **(dict(combined.metadata) if combined.metadata is not None else {}),
            "bad_while_loop_dependency_rescue": True,
        },
    )


def _stack_reads_from_dependency_diagnostic(
    diagnostic: dict[str, object],
) -> set[tuple[int, int]] | None:
    reads: set[tuple[int, int]] = set()
    missing_uses = diagnostic.get("missing_uses")
    if not isinstance(missing_uses, Sequence) or isinstance(
        missing_uses,
        (str, bytes, bytearray),
    ):
        return None
    for row in missing_uses:
        if not isinstance(row, dict):
            return None
        if row.get("capture_status") != "capturable":
            return None
        mop = row.get("mop")
        if not isinstance(mop, dict):
            return None
        stack = mop.get("stack")
        if not isinstance(stack, dict):
            return None
        try:
            stkoff = int(stack["stkoff"])
            size = int(stack["size"])
        except (KeyError, TypeError, ValueError):
            return None
        reads.add((stkoff, size))
    return reads


def _validation_graph_for_bad_while_loop(
    mba: object,
    edits: tuple[BadWhileLoopEdit, ...],
    replay_candidates: tuple[CleanupSideEffectReplayCandidate, ...],
    duplicate_replay_candidates: tuple[CleanupDuplicateGroupReplayCandidate, ...],
    trampoline_isolation_candidates: tuple[
        CleanupTrampolineIsolationCandidate, ...
    ],
    *,
    logger: object | None = None,
) -> FlowGraph | None:
    if (
        not replay_candidates
        and not duplicate_replay_candidates
        and not trampoline_isolation_candidates
        and not any(
            isinstance(
                edit,
                (BadWhileLoopDuplicateRedirect, BadWhileLoopConditionalRedirect),
            )
            or isinstance(edit, BadWhileLoopConditionalDuplicate)
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
    bad_while_loop_trampoline_isolation_candidates: tuple[
        CleanupTrampolineIsolationCandidate, ...
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
    tail_goto_merges: tuple[TailGotoMergeCandidate, ...] = ()
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
            or self.bad_while_loop_trampoline_isolation_candidates
            or self.fix_predecessor_branch_arm_fixes
            or self.tail_goto_merges
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
            f" bad_while_loop_trampoline_isolation="
            f"{len(self.bad_while_loop_trampoline_isolation_candidates)}"
            f" bad_while_loop_conditional_redirect_proofs="
            f"{len(self.bad_while_loop_conditional_redirect_proofs)}"
            f" fix_predecessor_branch_arm="
            f"{len(self.fix_predecessor_branch_arm_fixes)}"
            f" tail_goto_merge={len(self.tail_goto_merges)}"
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
        bad_while_loop_trampoline_isolation_candidates: tuple[
            CleanupTrampolineIsolationCandidate, ...
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
                dependency_rescue_capture=(
                    _capture_bad_while_loop_dependency_rescue_body
                ),
            )
            bad_while_loop_all_edits = tuple(bad_while_loop_analysis.edits)
            bad_while_loop_all_replay_candidates = tuple(
                bad_while_loop_analysis.replay_candidates
            )
            bad_while_loop_all_duplicate_replay_candidates = tuple(
                bad_while_loop_analysis.duplicate_replay_candidates
            )
            bad_while_loop_all_trampoline_isolation_candidates = tuple(
                bad_while_loop_analysis.trampoline_isolation_candidates
            )
            bad_while_loop_dependency_diagnostics = tuple(
                bad_while_loop_analysis.dependency_diagnostics
            )
            bad_while_loop_validation_graph = _validation_graph_for_bad_while_loop(
                mba,
                bad_while_loop_all_edits,
                bad_while_loop_all_replay_candidates,
                bad_while_loop_all_duplicate_replay_candidates,
                bad_while_loop_all_trampoline_isolation_candidates,
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
            bad_while_loop_trampoline_isolation_candidates = tuple(
                candidate
                for candidate in bad_while_loop_all_trampoline_isolation_candidates
                if bad_while_loop_validation_graph is not None
                and validate_trampoline_isolation_candidate(
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
                    conditional_redirect_promoted = _is_plannable_bad_while_loop_edit(
                        edit,
                        bad_while_loop_validation_graph,
                    )
                    proof = explain_bad_while_loop_conditional_redirect(
                        edit,
                        bad_while_loop_validation_graph,
                        defer_reason=(
                            "conditional_redirect_promoted"
                            if conditional_redirect_promoted
                            else "conditional_redirect_not_promoted"
                        ),
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
            promoted_dependency_rescue = {
                (
                    candidate.dispatcher_entry,
                    candidate.source_serial,
                    candidate.target_serial,
                )
                for candidate in bad_while_loop_replay_candidates
                if isinstance(candidate.captured_body.metadata, dict)
                and candidate.captured_body.metadata.get(
                    "bad_while_loop_dependency_rescue"
                )
                is True
            }
            promoted_duplicate_replay = {
                (
                    candidate.dispatcher_entry,
                    candidate.source_serial,
                )
                for candidate in bad_while_loop_duplicate_replay_candidates
            }
            promoted_trampoline_isolation = {
                (
                    candidate.dispatcher_entry,
                    candidate.source_serial,
                    candidate.target_serial,
                )
                for candidate in bad_while_loop_trampoline_isolation_candidates
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
                    item.category == BAD_WHILE_LOOP_INSERT_BLOCK
                    and item.reason == "copied_side_effects_not_dependency_safe"
                    and (
                        item.dispatcher_entry,
                        item.from_serial,
                        item.target_serial,
                    )
                    in promoted_dependency_rescue
                )
                and not (
                    item.reason == "duplicate_group_copied_side_effects"
                    and (
                        item.dispatcher_entry,
                        item.from_serial,
                    )
                    in promoted_duplicate_replay
                )
                and not (
                    item.reason == "duplicate_group_requires_trampoline"
                    and (
                        item.dispatcher_entry,
                        item.from_serial,
                        item.target_serial,
                    )
                    in promoted_trampoline_isolation
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

        tail_goto_merges: tuple[TailGotoMergeCandidate, ...] = ()
        try:
            if maturity in self.allowed_maturities:
                tail_goto_merges = collect_tail_goto_merge_candidates(
                    IDAIRTranslator().lift(mba)
                )
        except Exception as exc:
            errors.append(f"tail_goto_merge:{type(exc).__name__}")
            if logger is not None:
                logger.debug(
                    "Failed to collect tail-goto merge cleanup candidates",
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
            bad_while_loop_trampoline_isolation_candidates=tuple(
                bad_while_loop_trampoline_isolation_candidates
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
            tail_goto_merges=tuple(tail_goto_merges),
            collection_errors=tuple(errors),
            maturity=maturity,
            func_ea=func_ea,
        )
