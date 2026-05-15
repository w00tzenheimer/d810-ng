"""Backend boundary for live non-Hodur cleanup candidate collection."""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.cfg.flowgraph import FlowGraph
from d810.core.typing import Protocol
from d810.optimizers.microcode.flow.flattening.cleanup_evidence import (
    bad_while_loop_duplicate_candidate,
    validate_dispatcher_cleanup_candidate,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop import (
    BadWhileLoopEdit,
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
from d810.optimizers.microcode.flow.flattening.strategies.single_iteration import (
    SingleIterationPredFix,
    collect_live_single_iteration_fixes,
)
from d810.hexrays.mutation.ir_translator import IDAIRTranslator

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


def _validation_graph_for_bad_while_loop_edits(
    mba: object,
    edits: tuple[BadWhileLoopEdit, ...],
    *,
    logger: object | None = None,
) -> FlowGraph | None:
    if not any(isinstance(edit, BadWhileLoopDuplicateRedirect) for edit in edits):
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
    bad_while_loop_deferred_edits: tuple[BadWhileLoopEdit, ...] = ()
    bad_while_loop_follow_up: tuple[BadWhileLoopFollowUp, ...] = ()
    collection_errors: tuple[str, ...] = ()
    maturity: int = 0
    func_ea: int = 0

    @property
    def detected(self) -> bool:
        return bool(
            self.fake_jump_fixes
            or self.single_iteration_fixes
            or self.bad_while_loop_edits
        )

    @property
    def diagnostic_only(self) -> bool:
        return (
            not self.detected
            and bool(self.bad_while_loop_deferred_edits or self.bad_while_loop_follow_up)
        )

    @property
    def description(self) -> str:
        if not self.detected:
            if self.diagnostic_only:
                return (
                    "no plannable simple cleanup candidates detected: "
                    "bad_while_loop_deferred="
                    f"{len(self.bad_while_loop_deferred_edits)} "
                    f"bad_while_loop_follow_up={len(self.bad_while_loop_follow_up)}"
                )
            return "no simple cleanup candidates detected"
        return (
            "simple cleanup candidates detected: "
            f"fake_jump={len(self.fake_jump_fixes)} "
            f"single_iteration={len(self.single_iteration_fixes)} "
            f"bad_while_loop={len(self.bad_while_loop_edits)}"
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
        bad_while_loop_deferred_edits: tuple[BadWhileLoopEdit, ...] = ()
        bad_while_loop_follow_up: tuple[BadWhileLoopFollowUp, ...] = ()
        try:
            bad_while_loop_analysis = collect_live_bad_while_loop_analysis(
                mba,
                logger=logger,
                allowed_maturities=self.allowed_maturities,
            )
            bad_while_loop_all_edits = tuple(bad_while_loop_analysis.edits)
            bad_while_loop_validation_graph = _validation_graph_for_bad_while_loop_edits(
                mba,
                bad_while_loop_all_edits,
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
            bad_while_loop_deferred_edits = tuple(
                edit
                for edit in bad_while_loop_all_edits
                if not _is_plannable_bad_while_loop_edit(
                    edit,
                    bad_while_loop_validation_graph,
                )
            )
            bad_while_loop_follow_up = tuple(bad_while_loop_analysis.follow_up)
        except Exception as exc:
            errors.append(f"bad_while_loop:{type(exc).__name__}")
            if logger is not None:
                logger.debug(
                    "Failed to collect BadWhileLoop cleanup candidates",
                    exc_info=True,
                )

        return SimpleFlatteningCleanupDetection(
            fake_jump_fixes=tuple(fake_jump_fixes),
            single_iteration_fixes=tuple(single_iteration_fixes),
            bad_while_loop_edits=tuple(bad_while_loop_edits),
            bad_while_loop_deferred_edits=tuple(bad_while_loop_deferred_edits),
            bad_while_loop_follow_up=tuple(bad_while_loop_follow_up),
            collection_errors=tuple(errors),
            maturity=maturity,
            func_ea=func_ea,
        )
