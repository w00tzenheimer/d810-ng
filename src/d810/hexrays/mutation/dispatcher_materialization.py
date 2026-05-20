"""Hex-Rays materialization helpers for dispatcher rewrite batches."""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable

import ida_hexrays

from d810.hexrays.mutation.cfg_mutations import mba_deep_cleaning
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.mutation.deferred_modifier import (
    DeferredGraphModifier,
    GraphModification,
)


@dataclass(frozen=True, slots=True)
class DispatcherMaterializationResult:
    """Result of applying a live dispatcher rewrite batch."""

    applied_count: int = 0
    verify_failed: bool = False
    canonicalized_cases: int = 0


def apply_scheduled_deferred_modifications(
    *,
    mba: object,
    modifications: tuple[GraphModification, ...] | list[GraphModification],
    verify_each_mod: bool,
    rollback_on_verify_failure: bool,
    continue_on_verify_failure: bool,
) -> DispatcherMaterializationResult:
    """Apply previously scheduled modifications through the Hex-Rays backend."""

    if not modifications:
        return DispatcherMaterializationResult()
    modifier = DeferredGraphModifier(mba)
    modifier.modifications = list(modifications)
    applied = modifier.apply(
        run_optimize_local=True,
        run_deep_cleaning=False,
        verify_each_mod=verify_each_mod,
        rollback_on_verify_failure=rollback_on_verify_failure,
        continue_on_verify_failure=continue_on_verify_failure,
    )
    return DispatcherMaterializationResult(
        applied_count=int(applied),
        verify_failed=bool(modifier.verify_failed),
    )


def apply_dispatcher_deferred_modifier(
    *,
    mba: object,
    modifier: DeferredGraphModifier,
    logger: object,
    case_overlap_edges: tuple[object, ...] = (),
    canonicalize_case_overlaps: Callable[[], int] | None = None,
) -> DispatcherMaterializationResult:
    """Apply dispatcher predecessor rewrites with Hex-Rays safety policy."""

    if not modifier.has_modifications():
        return DispatcherMaterializationResult()

    _downgrade_nway_goto_blocks(mba, logger)
    _log_info(
        logger,
        "Applying %d deferred CFG modifications from resolve_dispatcher_father",
        len(modifier.modifications),
    )
    applied = modifier.apply(
        run_optimize_local=False,
        run_deep_cleaning=False,
        verify_each_mod=True,
        rollback_on_verify_failure=True,
        continue_on_verify_failure=True,
        enable_snapshot_rollback=True,
    )
    canonicalized_cases = 0
    verify_failed = bool(modifier.verify_failed)
    if (
        not verify_failed
        and case_overlap_edges
        and canonicalize_case_overlaps is not None
    ):
        try:
            _log_info(
                logger,
                "Post-apply jtbl overlap scan: %d dispatcher edge-set(s)",
                len(case_overlap_edges),
            )
            canonicalized_cases = int(canonicalize_case_overlaps())
            if canonicalized_cases > 0:
                _log_info(
                    logger,
                    "Applied jtbl overlap canonicalization: %d case target retarget(s)",
                    canonicalized_cases,
                )
            safe_verify(
                mba,
                "after jtbl cross-case overlap canonicalization",
                logger_func=getattr(logger, "error", None),
            )
            mba_deep_cleaning(mba, True)
            safe_verify(
                mba,
                "after post-canonicalization deep clean",
                logger_func=getattr(logger, "error", None),
            )
        except RuntimeError:
            _log_warning(
                logger,
                "verify failed during post-apply canonicalization; "
                "discarding modifications for this function",
            )
            verify_failed = True

    return DispatcherMaterializationResult(
        applied_count=int(applied),
        verify_failed=verify_failed,
        canonicalized_cases=canonicalized_cases,
    )


def _downgrade_nway_goto_blocks(mba: object, logger: object) -> None:
    qty = int(getattr(mba, "qty", 0) or 0)
    for blk_serial in range(qty):
        blk = mba.get_mblock(blk_serial)
        if blk is None or blk.type != ida_hexrays.BLT_NWAY:
            continue
        tail = blk.tail
        if tail is None or tail.opcode != ida_hexrays.m_goto or blk.nsucc() != 1:
            continue
        _log_debug(
            logger,
            "generic: block %d BLT_NWAY+m_goto+nsucc==1 -> BLT_1WAY "
            "(pre-apply sweep)",
            blk_serial,
        )
        blk.type = ida_hexrays.BLT_1WAY
        mba.mark_chains_dirty()


def _log_debug(logger: object, message: str, *args: object) -> None:
    log = getattr(logger, "debug", None)
    if callable(log):
        log(message, *args)


def _log_info(logger: object, message: str, *args: object) -> None:
    log = getattr(logger, "info", None)
    if callable(log):
        log(message, *args)


def _log_warning(logger: object, message: str, *args: object) -> None:
    log = getattr(logger, "warning", None)
    if callable(log):
        log(message, *args)


__all__ = [
    "DispatcherMaterializationResult",
    "apply_dispatcher_deferred_modifier",
    "apply_scheduled_deferred_modifications",
]
