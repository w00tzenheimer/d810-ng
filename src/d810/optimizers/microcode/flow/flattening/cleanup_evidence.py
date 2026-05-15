"""Neutral evidence for simple flattening cleanup rewrites."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    DuplicateAndRedirect,
    DuplicateReplayAndRedirect,
    DuplicateReplayEntry,
    GraphModification,
    InsertBlock,
)
from d810.cfg.materialization_payload import CapturedBlockBody

BAD_WHILE_LOOP_SOURCE_RULE = "BadWhileLoop"
CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY = (
    "cleanup_conditional_redirect_proofs"
)
CLEANUP_DUPLICATE_REPLAY_METADATA_KEY = "cleanup_duplicate_replay_candidates"
CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY = "cleanup_side_effect_replay_candidates"


class CleanupProofVerdict(str, Enum):
    """Diagnostic-only proof outcome for deferred cleanup rows."""

    SAFE_SHAPE = "safe_shape"
    UNSAFE = "unsafe"
    PROOF_GAP = "proof_gap"


class CleanupExitShape(str, Enum):
    """Topology shape proven by a legacy cleanup oracle."""

    SHARED_ONE_WAY_BY_PRED = "shared_one_way_by_pred"
    ONE_WAY_DISPATCHER_PREDECESSOR = "one_way_dispatcher_predecessor"
    SHARED_ONE_WAY_BY_PRED_WITH_REPLAY = "shared_one_way_by_pred_with_replay"


class CleanupRewriteIntent(str, Enum):
    """Backend-neutral rewrite requested for a cleanup candidate."""

    DUPLICATE_AND_REDIRECT = "duplicate_and_redirect"
    REPLAY_SIDE_EFFECTS_AND_REDIRECT = "replay_side_effects_and_redirect"
    DUPLICATE_REPLAY_AND_REDIRECT = "duplicate_replay_and_redirect"


@dataclass(frozen=True)
class CleanupObservedBlockShape:
    """Observed topology for one block referenced by a diagnostic proof."""

    serial: int
    exists: bool
    preds: tuple[int, ...] = ()
    succs: tuple[int, ...] = ()
    nsucc: int = 0
    current_old_edge: int | None = None
    conditional_tail_target: int | None = None


@dataclass(frozen=True)
class CleanupConditionalRedirectProof:
    """Diagnostic-only proof for a deferred conditional cleanup redirect.

    This is intentionally not a rewrite candidate. It records enough evidence
    to explain why a legacy ``BadWhileLoopConditionalRedirect`` row is still
    deferred and whether the observed CFG currently satisfies the narrow
    safe-shape preconditions. Promotion must remain a separate implementation
    step after these diagnostics prove stable on real cases.
    """

    source_rule: str
    defer_reason: str
    dispatcher_entry: int
    source_serial: int
    ref_block: int
    conditional_target: int
    fallthrough_target: int
    source_shape: CleanupObservedBlockShape
    dispatcher_shape: CleanupObservedBlockShape
    ref_shape: CleanupObservedBlockShape
    dispatcher_internal_serials: tuple[int, ...]
    source_shape_ok: bool
    dispatcher_shape_ok: bool
    ref_shape_ok: bool
    branch_polarity_proven: bool
    targets_exist: bool
    targets_outside_cleanup: bool
    copied_side_effects_absent: bool
    dispatcher_execution_dependency_absent: bool
    projected_dispatcher_cycle_free: bool | None
    verdict: CleanupProofVerdict
    reasons: tuple[str, ...]


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


@dataclass(frozen=True)
class CleanupPerPredReplay:
    """Captured replay payload for one predecessor of a duplicate group."""

    pred_serial: int
    target_serial: int
    captured_body: CapturedBlockBody


@dataclass(frozen=True)
class CleanupDuplicateGroupReplayCandidate:
    """Neutral evidence for duplicate-group side-effect replay.

    ``duplicate_group_copied_side_effects`` cannot use the direct
    ``InsertBlock`` replay path. The serialized legacy follow-up row loses the
    copied instructions and full per-predecessor target map, so this evidence
    must be captured live while the BadWhileLoop oracle still has
    dependency-safe copied instructions. The neutral rewrite is composite:
    ``pred_i -> source/clone_i -> replay_insert_i -> target_i``.
    """

    source_rule: str
    dispatcher_entry: int
    source_serial: int
    exit_shape: CleanupExitShape
    rewrite_intent: CleanupRewriteIntent
    per_pred_replays: tuple[CleanupPerPredReplay, ...]
    dispatcher_internal_serials: tuple[int, ...] = ()


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_optional_int(value: object) -> int | None:
    if value is None:
        return None
    return _coerce_int(value)


def _coerce_bool(value: object) -> bool:
    return bool(value) if isinstance(value, bool) else False


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


def _coerce_dispatcher_internal(
    dispatcher_internal_serials: Sequence[object],
) -> tuple[int, ...]:
    return tuple(
        sorted(
            {
                serial
                for raw_serial in dispatcher_internal_serials
                if (serial := _coerce_int(raw_serial)) is not None
            }
        )
    )


def _coerce_observed_block_shape(raw: object) -> CleanupObservedBlockShape | None:
    if isinstance(raw, CleanupObservedBlockShape):
        return raw
    if not isinstance(raw, Mapping):
        return None

    serial = _coerce_int(raw.get("serial"))
    exists = raw.get("exists")
    if serial is None or not isinstance(exists, bool):
        return None

    def _int_tuple(value: object) -> tuple[int, ...]:
        if not isinstance(value, Sequence) or isinstance(
            value,
            (str, bytes, bytearray),
        ):
            return ()
        return tuple(
            item
            for raw_item in value
            if (item := _coerce_int(raw_item)) is not None
        )

    return CleanupObservedBlockShape(
        serial=serial,
        exists=exists,
        preds=_int_tuple(raw.get("preds", ())),
        succs=_int_tuple(raw.get("succs", ())),
        nsucc=_coerce_int(raw.get("nsucc")) or 0,
        current_old_edge=_coerce_optional_int(raw.get("current_old_edge")),
        conditional_tail_target=_coerce_optional_int(
            raw.get("conditional_tail_target"),
        ),
    )


def _serialize_observed_block_shape(
    shape: CleanupObservedBlockShape,
) -> dict[str, object]:
    return {
        "serial": shape.serial,
        "exists": shape.exists,
        "preds": list(shape.preds),
        "succs": list(shape.succs),
        "nsucc": shape.nsucc,
        "current_old_edge": shape.current_old_edge,
        "conditional_tail_target": shape.conditional_tail_target,
    }


def _operand_block_ref(operand: object) -> int | None:
    for attr in ("block_ref", "block_num", "b"):
        block_ref = getattr(operand, attr, None)
        if isinstance(block_ref, int):
            return block_ref
    return None


def _infer_conditional_tail_target(block: object | None) -> int | None:
    if block is None or getattr(block, "nsucc", 0) != 2:
        return None
    tail = getattr(block, "tail", None)
    if tail is None:
        return None

    for slot_name, operand in getattr(tail, "operand_slots", ()):
        if slot_name != "d":
            continue
        block_ref = _operand_block_ref(operand)
        if block_ref is not None:
            return block_ref

    block_ref = _operand_block_ref(getattr(tail, "d", None))
    if block_ref is not None:
        return block_ref

    return None


def _observed_block_shape(
    cfg: FlowGraph,
    serial: int,
    *,
    current_old_edge: int | None = None,
) -> CleanupObservedBlockShape:
    block = cfg.get_block(serial)
    if block is None:
        return CleanupObservedBlockShape(
            serial=serial,
            exists=False,
            current_old_edge=current_old_edge,
        )
    return CleanupObservedBlockShape(
        serial=serial,
        exists=True,
        preds=tuple(int(pred) for pred in block.preds),
        succs=tuple(int(succ) for succ in block.succs),
        nsucc=int(block.nsucc),
        current_old_edge=current_old_edge,
        conditional_tail_target=_infer_conditional_tail_target(block),
    )


def _reaches_any(
    adjacency: Mapping[int, Sequence[int]],
    *,
    start: int,
    targets: set[int],
) -> bool:
    stack = [start]
    seen: set[int] = set()
    while stack:
        serial = stack.pop()
        if serial in seen:
            continue
        seen.add(serial)
        if serial in targets:
            return True
        stack.extend(int(succ) for succ in adjacency.get(serial, ()))
    return False


def _projected_dispatcher_cycle_free(
    cfg: FlowGraph,
    *,
    dispatcher_entry: int,
    source_serial: int,
    conditional_target: int,
    fallthrough_target: int,
    dispatcher_internal_serials: tuple[int, ...],
) -> bool | None:
    if (
        source_serial not in cfg.blocks
        or conditional_target not in cfg.blocks
        or fallthrough_target not in cfg.blocks
    ):
        return None

    adjacency = {
        int(serial): [int(succ) for succ in block.succs]
        for serial, block in cfg.blocks.items()
    }
    clone_serial = max(adjacency, default=-1) + 1
    fallthrough_clone_serial = clone_serial + 1
    adjacency[source_serial] = [clone_serial]
    adjacency[clone_serial] = [fallthrough_clone_serial, conditional_target]
    adjacency[fallthrough_clone_serial] = [fallthrough_target]

    forbidden = {int(dispatcher_entry), *dispatcher_internal_serials}
    return not _reaches_any(adjacency, start=source_serial, targets=forbidden)


def explain_bad_while_loop_conditional_redirect(
    legacy_edit: object,
    cfg: FlowGraph,
    *,
    defer_reason: str = "conditional_redirect_not_promoted",
) -> CleanupConditionalRedirectProof | None:
    """Classify a deferred legacy conditional redirect without promoting it."""
    if type(legacy_edit).__name__ != "BadWhileLoopConditionalRedirect":
        return None

    dispatcher_entry = _coerce_int(getattr(legacy_edit, "dispatcher_entry", None))
    source_serial = _coerce_int(getattr(legacy_edit, "source_serial", None))
    ref_block = _coerce_int(getattr(legacy_edit, "ref_block", None))
    conditional_target = _coerce_int(
        getattr(legacy_edit, "conditional_target", None),
    )
    fallthrough_target = _coerce_int(
        getattr(legacy_edit, "fallthrough_target", None),
    )
    if (
        dispatcher_entry is None
        or source_serial is None
        or ref_block is None
        or conditional_target is None
        or fallthrough_target is None
    ):
        return None

    dispatcher_internal_serials = _coerce_dispatcher_internal(
        getattr(legacy_edit, "dispatcher_internal_serials", ()),
    )
    copied_side_effects_absent = bool(
        getattr(legacy_edit, "copied_side_effects_absent", False),
    )

    source_block = cfg.get_block(source_serial)
    dispatcher_block = cfg.get_block(dispatcher_entry)
    ref = cfg.get_block(ref_block)
    source_shape = _observed_block_shape(
        cfg,
        source_serial,
        current_old_edge=(
            int(source_block.succs[0])
            if source_block is not None and source_block.nsucc == 1
            else None
        ),
    )
    dispatcher_shape = _observed_block_shape(cfg, dispatcher_entry)
    ref_shape = _observed_block_shape(cfg, ref_block)

    source_shape_ok = (
        source_block is not None
        and source_serial != cfg.entry_serial
        and source_block.nsucc == 1
        and tuple(source_block.succs) == (dispatcher_entry,)
    )
    dispatcher_shape_ok = dispatcher_block is not None
    ref_is_dispatcher_direct = (
        dispatcher_block is not None and ref_block in dispatcher_block.succs
    )
    ref_tail_target = ref_shape.conditional_tail_target
    ref_shape_ok = (
        ref is not None
        and ref_is_dispatcher_direct
        and ref.nsucc == 2
        and ref_tail_target is not None
        and ref_tail_target in ref.succs
    )
    branch_polarity_proven = ref_tail_target == conditional_target
    targets_exist = (
        conditional_target in cfg.blocks and fallthrough_target in cfg.blocks
    )
    ref_targets_match = (
        ref is not None
        and targets_exist
        and set(ref.succs) == {conditional_target, fallthrough_target}
    )
    forbidden_targets = {
        dispatcher_entry,
        source_serial,
        ref_block,
        *dispatcher_internal_serials,
    }
    targets_outside_cleanup = (
        targets_exist
        and conditional_target not in forbidden_targets
        and fallthrough_target not in forbidden_targets
        and conditional_target != fallthrough_target
    )
    projected_cycle_free = _projected_dispatcher_cycle_free(
        cfg,
        dispatcher_entry=dispatcher_entry,
        source_serial=source_serial,
        conditional_target=conditional_target,
        fallthrough_target=fallthrough_target,
        dispatcher_internal_serials=dispatcher_internal_serials,
    )
    dispatcher_execution_dependency_absent = (
        copied_side_effects_absent
        and ref_is_dispatcher_direct
        and targets_outside_cleanup
    )

    reasons: list[str] = []
    proof_gaps: list[str] = []
    unsafe: list[str] = []
    if source_block is None:
        unsafe.append("source_missing")
    elif source_serial == cfg.entry_serial:
        unsafe.append("source_is_entry")
    elif not source_shape_ok:
        unsafe.append("source_not_one_way_to_dispatcher")
    if dispatcher_block is None:
        unsafe.append("dispatcher_missing")
    if ref is None:
        unsafe.append("ref_missing")
    else:
        if not ref_is_dispatcher_direct:
            unsafe.append("ref_not_dispatcher_direct")
        if ref.nsucc != 2:
            unsafe.append("ref_not_two_way")
        if ref_tail_target is None:
            proof_gaps.append("ref_conditional_tail_target_unproven")
        elif ref_tail_target not in ref.succs:
            unsafe.append("ref_tail_target_not_successor")
        elif not branch_polarity_proven:
            unsafe.append("branch_polarity_mismatch")
        if not ref_targets_match:
            unsafe.append("ref_successors_do_not_match_targets")
    if not targets_exist:
        unsafe.append("target_missing")
    elif not targets_outside_cleanup:
        unsafe.append("target_inside_cleanup_or_identical")
    if not copied_side_effects_absent:
        proof_gaps.append("copied_side_effect_absence_unproven")
    if projected_cycle_free is None:
        proof_gaps.append("projected_cycle_check_unavailable")
    elif not projected_cycle_free:
        unsafe.append("projected_reaches_dispatcher")

    if unsafe:
        verdict = CleanupProofVerdict.UNSAFE
        reasons.extend(unsafe)
        reasons.extend(proof_gaps)
    elif proof_gaps:
        verdict = CleanupProofVerdict.PROOF_GAP
        reasons.extend(proof_gaps)
    else:
        verdict = CleanupProofVerdict.SAFE_SHAPE
        reasons.append("safe_shape_preconditions_satisfied")

    return CleanupConditionalRedirectProof(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        defer_reason=str(defer_reason),
        dispatcher_entry=dispatcher_entry,
        source_serial=source_serial,
        ref_block=ref_block,
        conditional_target=conditional_target,
        fallthrough_target=fallthrough_target,
        source_shape=source_shape,
        dispatcher_shape=dispatcher_shape,
        ref_shape=ref_shape,
        dispatcher_internal_serials=dispatcher_internal_serials,
        source_shape_ok=source_shape_ok,
        dispatcher_shape_ok=dispatcher_shape_ok,
        ref_shape_ok=ref_shape_ok,
        branch_polarity_proven=branch_polarity_proven,
        targets_exist=targets_exist,
        targets_outside_cleanup=targets_outside_cleanup,
        copied_side_effects_absent=copied_side_effects_absent,
        dispatcher_execution_dependency_absent=(
            dispatcher_execution_dependency_absent
        ),
        projected_dispatcher_cycle_free=projected_cycle_free,
        verdict=verdict,
        reasons=tuple(reasons),
    )


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

    dispatcher_internal = _coerce_dispatcher_internal(dispatcher_internal_serials)
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


def bad_while_loop_duplicate_group_replay_candidate(
    *,
    dispatcher_entry: object,
    source_serial: object,
    per_pred_replays: Sequence[CleanupPerPredReplay],
    dispatcher_internal_serials: Sequence[object] = (),
) -> CleanupDuplicateGroupReplayCandidate | None:
    """Build neutral replay evidence from a live BadWhileLoop duplicate group."""
    dispatcher_entry_int = _coerce_int(dispatcher_entry)
    source_serial_int = _coerce_int(source_serial)
    if dispatcher_entry_int is None or source_serial_int is None:
        return None
    if len(per_pred_replays) < 2:
        return None

    dispatcher_internal = _coerce_dispatcher_internal(dispatcher_internal_serials)
    normalized_rows: list[CleanupPerPredReplay] = []
    seen_preds: set[int] = set()
    for row in per_pred_replays:
        pred_serial = _coerce_int(row.pred_serial)
        target_serial = _coerce_int(row.target_serial)
        if pred_serial is None or target_serial is None:
            return None
        if pred_serial in seen_preds:
            return None
        seen_preds.add(pred_serial)
        if target_serial in {
            source_serial_int,
            dispatcher_entry_int,
            *dispatcher_internal,
        }:
            return None
        if (
            row.captured_body.instruction_count <= 0
            or row.captured_body.summary.contains_call
        ):
            return None
        normalized_rows.append(
            CleanupPerPredReplay(
                pred_serial=pred_serial,
                target_serial=target_serial,
                captured_body=row.captured_body,
            )
        )

    return CleanupDuplicateGroupReplayCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=dispatcher_entry_int,
        source_serial=source_serial_int,
        exit_shape=CleanupExitShape.SHARED_ONE_WAY_BY_PRED_WITH_REPLAY,
        rewrite_intent=CleanupRewriteIntent.DUPLICATE_REPLAY_AND_REDIRECT,
        per_pred_replays=tuple(normalized_rows),
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


def validate_duplicate_group_replay_candidate(
    cfg: FlowGraph,
    candidate: CleanupDuplicateGroupReplayCandidate,
) -> bool:
    """Return whether duplicate-group replay evidence is valid for the current CFG."""
    if candidate.source_rule != BAD_WHILE_LOOP_SOURCE_RULE:
        return False
    if (
        candidate.exit_shape != CleanupExitShape.SHARED_ONE_WAY_BY_PRED_WITH_REPLAY
        or candidate.rewrite_intent
        != CleanupRewriteIntent.DUPLICATE_REPLAY_AND_REDIRECT
    ):
        return False
    if len(candidate.per_pred_replays) < 2:
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
    for row in candidate.per_pred_replays:
        if row.pred_serial in seen_preds:
            return False
        seen_preds.add(row.pred_serial)

        pred_block = cfg.blocks.get(row.pred_serial)
        target_block = cfg.blocks.get(row.target_serial)
        if pred_block is None or target_block is None:
            return False
        if pred_block.nsucc != 1:
            return False
        if pred_block.succs[0] != candidate.source_serial:
            return False
        if target_block.nsucc > 1:
            return False
        if row.target_serial in {
            candidate.source_serial,
            candidate.dispatcher_entry,
            *candidate.dispatcher_internal_serials,
        }:
            return False
        if (
            row.captured_body.instruction_count <= 0
            or row.captured_body.summary.contains_call
        ):
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
    candidate: (
        DispatcherCleanupCandidate
        | CleanupSideEffectReplayCandidate
        | CleanupDuplicateGroupReplayCandidate
    ),
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
    if (
        isinstance(candidate, CleanupDuplicateGroupReplayCandidate)
        and candidate.exit_shape == CleanupExitShape.SHARED_ONE_WAY_BY_PRED_WITH_REPLAY
        and candidate.rewrite_intent
        == CleanupRewriteIntent.DUPLICATE_REPLAY_AND_REDIRECT
    ):
        return DuplicateReplayAndRedirect(
            source_serial=candidate.source_serial,
            dispatcher_entry=candidate.dispatcher_entry,
            per_pred_replays=tuple(
                DuplicateReplayEntry(
                    pred_serial=row.pred_serial,
                    target_serial=row.target_serial,
                    captured_body=row.captured_body,
                )
                for row in candidate.per_pred_replays
            ),
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


def extract_duplicate_group_replay_candidates(
    flow_graph: FlowGraph | None,
) -> tuple[CleanupDuplicateGroupReplayCandidate, ...]:
    """Read validated duplicate-group replay candidates from in-memory metadata."""
    if flow_graph is None:
        return ()
    raw = flow_graph.metadata.get(CLEANUP_DUPLICATE_REPLAY_METADATA_KEY)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    candidates: list[CleanupDuplicateGroupReplayCandidate] = []
    for item in raw:
        if not isinstance(item, CleanupDuplicateGroupReplayCandidate):
            continue
        if validate_duplicate_group_replay_candidate(flow_graph, item):
            candidates.append(item)
    return tuple(candidates)


def serialize_conditional_redirect_proofs(
    proofs: Sequence[CleanupConditionalRedirectProof],
) -> tuple[dict[str, object], ...]:
    """Serialize diagnostic conditional redirect proofs for metadata storage."""
    return tuple(
        {
            "source_rule": proof.source_rule,
            "defer_reason": proof.defer_reason,
            "dispatcher_entry": proof.dispatcher_entry,
            "source_serial": proof.source_serial,
            "ref_block": proof.ref_block,
            "conditional_target": proof.conditional_target,
            "fallthrough_target": proof.fallthrough_target,
            "source_shape": _serialize_observed_block_shape(proof.source_shape),
            "dispatcher_shape": _serialize_observed_block_shape(
                proof.dispatcher_shape,
            ),
            "ref_shape": _serialize_observed_block_shape(proof.ref_shape),
            "dispatcher_internal_serials": list(
                proof.dispatcher_internal_serials,
            ),
            "source_shape_ok": proof.source_shape_ok,
            "dispatcher_shape_ok": proof.dispatcher_shape_ok,
            "ref_shape_ok": proof.ref_shape_ok,
            "branch_polarity_proven": proof.branch_polarity_proven,
            "targets_exist": proof.targets_exist,
            "targets_outside_cleanup": proof.targets_outside_cleanup,
            "copied_side_effects_absent": proof.copied_side_effects_absent,
            "dispatcher_execution_dependency_absent": (
                proof.dispatcher_execution_dependency_absent
            ),
            "projected_dispatcher_cycle_free": (
                proof.projected_dispatcher_cycle_free
            ),
            "verdict": proof.verdict.value,
            "reasons": list(proof.reasons),
        }
        for proof in proofs
    )


def _coerce_conditional_redirect_proof(
    raw: object,
) -> CleanupConditionalRedirectProof | None:
    if isinstance(raw, CleanupConditionalRedirectProof):
        return raw
    if not isinstance(raw, Mapping):
        return None

    source_rule = raw.get("source_rule")
    defer_reason = raw.get("defer_reason")
    dispatcher_entry = _coerce_int(raw.get("dispatcher_entry"))
    source_serial = _coerce_int(raw.get("source_serial"))
    ref_block = _coerce_int(raw.get("ref_block"))
    conditional_target = _coerce_int(raw.get("conditional_target"))
    fallthrough_target = _coerce_int(raw.get("fallthrough_target"))
    source_shape = _coerce_observed_block_shape(raw.get("source_shape"))
    dispatcher_shape = _coerce_observed_block_shape(raw.get("dispatcher_shape"))
    ref_shape = _coerce_observed_block_shape(raw.get("ref_shape"))
    raw_verdict = raw.get("verdict")
    if (
        not isinstance(source_rule, str)
        or not isinstance(defer_reason, str)
        or dispatcher_entry is None
        or source_serial is None
        or ref_block is None
        or conditional_target is None
        or fallthrough_target is None
        or source_shape is None
        or dispatcher_shape is None
        or ref_shape is None
        or not isinstance(raw_verdict, str)
    ):
        return None
    try:
        verdict = CleanupProofVerdict(raw_verdict)
    except ValueError:
        return None

    raw_reasons = raw.get("reasons", ())
    reasons = (
        tuple(reason for reason in raw_reasons if isinstance(reason, str))
        if isinstance(raw_reasons, Sequence)
        and not isinstance(raw_reasons, (str, bytes, bytearray))
        else ()
    )
    projected_raw = raw.get("projected_dispatcher_cycle_free")
    projected_dispatcher_cycle_free = (
        projected_raw if isinstance(projected_raw, bool) else None
    )
    return CleanupConditionalRedirectProof(
        source_rule=source_rule,
        defer_reason=defer_reason,
        dispatcher_entry=dispatcher_entry,
        source_serial=source_serial,
        ref_block=ref_block,
        conditional_target=conditional_target,
        fallthrough_target=fallthrough_target,
        source_shape=source_shape,
        dispatcher_shape=dispatcher_shape,
        ref_shape=ref_shape,
        dispatcher_internal_serials=_coerce_dispatcher_internal(
            raw.get("dispatcher_internal_serials", ()),
        ),
        source_shape_ok=_coerce_bool(raw.get("source_shape_ok")),
        dispatcher_shape_ok=_coerce_bool(raw.get("dispatcher_shape_ok")),
        ref_shape_ok=_coerce_bool(raw.get("ref_shape_ok")),
        branch_polarity_proven=_coerce_bool(raw.get("branch_polarity_proven")),
        targets_exist=_coerce_bool(raw.get("targets_exist")),
        targets_outside_cleanup=_coerce_bool(raw.get("targets_outside_cleanup")),
        copied_side_effects_absent=_coerce_bool(
            raw.get("copied_side_effects_absent"),
        ),
        dispatcher_execution_dependency_absent=_coerce_bool(
            raw.get("dispatcher_execution_dependency_absent"),
        ),
        projected_dispatcher_cycle_free=projected_dispatcher_cycle_free,
        verdict=verdict,
        reasons=reasons,
    )


def extract_conditional_redirect_proofs(
    flow_graph: FlowGraph | None,
) -> tuple[CleanupConditionalRedirectProof, ...]:
    """Read diagnostic conditional redirect proofs from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    raw = flow_graph.metadata.get(CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    proofs: list[CleanupConditionalRedirectProof] = []
    for item in raw:
        proof = _coerce_conditional_redirect_proof(item)
        if proof is not None:
            proofs.append(proof)
    return tuple(proofs)


__all__ = [
    "BAD_WHILE_LOOP_SOURCE_RULE",
    "CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY",
    "CLEANUP_DUPLICATE_REPLAY_METADATA_KEY",
    "CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY",
    "CleanupConditionalRedirectProof",
    "CleanupDuplicateGroupReplayCandidate",
    "CleanupExitShape",
    "CleanupObservedBlockShape",
    "CleanupPerPredReplay",
    "CleanupProofVerdict",
    "CleanupRewriteIntent",
    "CleanupSideEffectReplayCandidate",
    "DispatcherCleanupCandidate",
    "bad_while_loop_duplicate_candidate",
    "bad_while_loop_duplicate_group_replay_candidate",
    "bad_while_loop_side_effect_replay_candidate",
    "build_dispatcher_cleanup_modification",
    "explain_bad_while_loop_conditional_redirect",
    "extract_conditional_redirect_proofs",
    "extract_duplicate_group_replay_candidates",
    "extract_side_effect_replay_candidates",
    "serialize_conditional_redirect_proofs",
    "validate_dispatcher_cleanup_candidate",
    "validate_duplicate_group_replay_candidate",
    "validate_side_effect_replay_candidate",
]
