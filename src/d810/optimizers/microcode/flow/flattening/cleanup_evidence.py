"""Neutral evidence for simple flattening cleanup rewrites."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    DuplicateAndRedirect,
    GraphModification,
    InsertBlock,
)
from d810.cfg.materialization_payload import CapturedBlockBody

BAD_WHILE_LOOP_SOURCE_RULE = "BadWhileLoop"
CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY = "cleanup_side_effect_replay_candidates"


class CleanupExitShape(str, Enum):
    """Topology shape proven by a legacy cleanup oracle."""

    SHARED_ONE_WAY_BY_PRED = "shared_one_way_by_pred"
    ONE_WAY_DISPATCHER_PREDECESSOR = "one_way_dispatcher_predecessor"


class CleanupRewriteIntent(str, Enum):
    """Backend-neutral rewrite requested for a cleanup candidate."""

    DUPLICATE_AND_REDIRECT = "duplicate_and_redirect"
    REPLAY_SIDE_EFFECTS_AND_REDIRECT = "replay_side_effects_and_redirect"


@dataclass(frozen=True)
class DispatcherCleanupCandidate:
    """Neutral cleanup evidence collected from a dispatcher cleanup oracle."""

    source_rule: str
    dispatcher_entry: int
    source_serial: int
    exit_shape: CleanupExitShape
    rewrite_intent: CleanupRewriteIntent
    per_pred_targets: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class CleanupSideEffectReplayCandidate:
    """Neutral evidence for replaying copied dispatcher side effects before redirect."""

    source_rule: str
    dispatcher_entry: int
    source_serial: int
    target_serial: int
    exit_shape: CleanupExitShape
    rewrite_intent: CleanupRewriteIntent
    captured_body: CapturedBlockBody
    dispatcher_internal_serials: tuple[int, ...] = ()


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_per_pred_targets(raw: object) -> tuple[tuple[int, int], ...] | None:
    if not isinstance(raw, tuple):
        return None

    per_pred_targets: list[tuple[int, int]] = []
    seen_preds: set[int] = set()
    for pair in raw:
        if not isinstance(pair, tuple) or len(pair) != 2:
            return None
        pred_serial = _coerce_int(pair[0])
        target_serial = _coerce_int(pair[1])
        if pred_serial is None or target_serial is None:
            return None
        if pred_serial in seen_preds:
            return None
        seen_preds.add(pred_serial)
        per_pred_targets.append((pred_serial, target_serial))

    if len(per_pred_targets) < 2:
        return None
    return tuple(per_pred_targets)


def bad_while_loop_duplicate_candidate(
    legacy_edit: object,
) -> DispatcherCleanupCandidate | None:
    """Convert a legacy BadWhileLoop duplicate edit into neutral evidence."""
    if type(legacy_edit).__name__ != "BadWhileLoopDuplicateRedirect":
        return None

    dispatcher_entry = _coerce_int(getattr(legacy_edit, "dispatcher_entry", None))
    source_serial = _coerce_int(getattr(legacy_edit, "source_serial", None))
    per_pred_targets = _coerce_per_pred_targets(
        getattr(legacy_edit, "per_pred_targets", None)
    )
    if dispatcher_entry is None or source_serial is None or per_pred_targets is None:
        return None

    for _pred_serial, target_serial in per_pred_targets:
        if target_serial in (dispatcher_entry, source_serial):
            return None

    return DispatcherCleanupCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=dispatcher_entry,
        source_serial=source_serial,
        exit_shape=CleanupExitShape.SHARED_ONE_WAY_BY_PRED,
        rewrite_intent=CleanupRewriteIntent.DUPLICATE_AND_REDIRECT,
        per_pred_targets=per_pred_targets,
    )


def bad_while_loop_side_effect_replay_candidate(
    *,
    dispatcher_entry: object,
    source_serial: object,
    target_serial: object,
    captured_body: CapturedBlockBody | None,
    dispatcher_internal_serials: Sequence[object] = (),
) -> CleanupSideEffectReplayCandidate | None:
    """Build neutral replay evidence from a live BadWhileLoop side-effect case."""
    dispatcher_entry_int = _coerce_int(dispatcher_entry)
    source_serial_int = _coerce_int(source_serial)
    target_serial_int = _coerce_int(target_serial)
    if (
        dispatcher_entry_int is None
        or source_serial_int is None
        or target_serial_int is None
        or captured_body is None
    ):
        return None
    if target_serial_int in (dispatcher_entry_int, source_serial_int):
        return None
    if captured_body.instruction_count <= 0 or captured_body.summary.contains_call:
        return None

    dispatcher_internal = tuple(
        sorted(
            {
                serial
                for raw_serial in dispatcher_internal_serials
                if (serial := _coerce_int(raw_serial)) is not None
            }
        )
    )
    if target_serial_int in dispatcher_internal:
        return None

    return CleanupSideEffectReplayCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=dispatcher_entry_int,
        source_serial=source_serial_int,
        target_serial=target_serial_int,
        exit_shape=CleanupExitShape.ONE_WAY_DISPATCHER_PREDECESSOR,
        rewrite_intent=CleanupRewriteIntent.REPLAY_SIDE_EFFECTS_AND_REDIRECT,
        captured_body=captured_body,
        dispatcher_internal_serials=dispatcher_internal,
    )


def validate_dispatcher_cleanup_candidate(
    cfg: FlowGraph,
    candidate: DispatcherCleanupCandidate,
) -> bool:
    """Return whether neutral cleanup evidence is valid for the current CFG."""
    if (
        candidate.exit_shape != CleanupExitShape.SHARED_ONE_WAY_BY_PRED
        or candidate.rewrite_intent != CleanupRewriteIntent.DUPLICATE_AND_REDIRECT
    ):
        return False

    dispatcher_entry = cfg.blocks.get(candidate.dispatcher_entry)
    source_block = cfg.blocks.get(candidate.source_serial)
    if dispatcher_entry is None or source_block is None:
        return False
    if source_block.nsucc != 1:
        return False
    if source_block.succs[0] != candidate.dispatcher_entry:
        return False

    source_preds = set(source_block.preds)
    seen_preds: set[int] = set()
    for pred_serial, target_serial in candidate.per_pred_targets:
        if pred_serial in seen_preds:
            return False
        seen_preds.add(pred_serial)

        pred_block = cfg.blocks.get(pred_serial)
        target_block = cfg.blocks.get(target_serial)
        if pred_block is None or target_block is None:
            return False
        if pred_block.nsucc != 1:
            return False
        if pred_block.succs[0] != candidate.source_serial:
            return False
        if target_serial in (candidate.source_serial, candidate.dispatcher_entry):
            return False

    return len(seen_preds) >= 2 and seen_preds == source_preds


def validate_side_effect_replay_candidate(
    cfg: FlowGraph,
    candidate: CleanupSideEffectReplayCandidate,
) -> bool:
    """Return whether neutral replay evidence is valid for the current CFG."""
    if candidate.source_rule != BAD_WHILE_LOOP_SOURCE_RULE:
        return False
    if (
        candidate.exit_shape != CleanupExitShape.ONE_WAY_DISPATCHER_PREDECESSOR
        or candidate.rewrite_intent
        != CleanupRewriteIntent.REPLAY_SIDE_EFFECTS_AND_REDIRECT
    ):
        return False
    if (
        candidate.captured_body.instruction_count <= 0
        or candidate.captured_body.summary.contains_call
    ):
        return False

    dispatcher_entry = cfg.blocks.get(candidate.dispatcher_entry)
    source_block = cfg.blocks.get(candidate.source_serial)
    target_block = cfg.blocks.get(candidate.target_serial)
    if dispatcher_entry is None or source_block is None or target_block is None:
        return False
    if source_block.nsucc != 1:
        return False
    if source_block.succs[0] != candidate.dispatcher_entry:
        return False
    if candidate.target_serial in {
        candidate.source_serial,
        candidate.dispatcher_entry,
        *candidate.dispatcher_internal_serials,
    }:
        return False
    return True


def build_dispatcher_cleanup_modification(
    candidate: DispatcherCleanupCandidate | CleanupSideEffectReplayCandidate,
) -> GraphModification:
    """Lower a neutral cleanup candidate to a graph modification."""
    if (
        isinstance(candidate, DispatcherCleanupCandidate)
        and
        candidate.exit_shape == CleanupExitShape.SHARED_ONE_WAY_BY_PRED
        and candidate.rewrite_intent == CleanupRewriteIntent.DUPLICATE_AND_REDIRECT
    ):
        return DuplicateAndRedirect(
            source_serial=candidate.source_serial,
            per_pred_targets=candidate.per_pred_targets,
        )
    if (
        isinstance(candidate, CleanupSideEffectReplayCandidate)
        and candidate.exit_shape == CleanupExitShape.ONE_WAY_DISPATCHER_PREDECESSOR
        and candidate.rewrite_intent
        == CleanupRewriteIntent.REPLAY_SIDE_EFFECTS_AND_REDIRECT
    ):
        return InsertBlock(
            pred_serial=candidate.source_serial,
            succ_serial=candidate.target_serial,
            old_target_serial=candidate.dispatcher_entry,
            captured_body=candidate.captured_body,
        )
    exit_shape = getattr(candidate.exit_shape, "value", candidate.exit_shape)
    rewrite_intent = getattr(candidate.rewrite_intent, "value", candidate.rewrite_intent)
    raise ValueError(
        f"unsupported cleanup candidate: {exit_shape}/{rewrite_intent}"
    )


def extract_side_effect_replay_candidates(
    flow_graph: FlowGraph | None,
) -> tuple[CleanupSideEffectReplayCandidate, ...]:
    """Read validated side-effect replay candidates from in-memory metadata."""
    if flow_graph is None:
        return ()
    raw = flow_graph.metadata.get(CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    candidates: list[CleanupSideEffectReplayCandidate] = []
    for item in raw:
        if not isinstance(item, CleanupSideEffectReplayCandidate):
            continue
        if validate_side_effect_replay_candidate(flow_graph, item):
            candidates.append(item)
    return tuple(candidates)


__all__ = [
    "BAD_WHILE_LOOP_SOURCE_RULE",
    "CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY",
    "CleanupExitShape",
    "CleanupRewriteIntent",
    "CleanupSideEffectReplayCandidate",
    "DispatcherCleanupCandidate",
    "bad_while_loop_duplicate_candidate",
    "bad_while_loop_side_effect_replay_candidate",
    "build_dispatcher_cleanup_modification",
    "extract_side_effect_replay_candidates",
    "validate_dispatcher_cleanup_candidate",
    "validate_side_effect_replay_candidate",
]
