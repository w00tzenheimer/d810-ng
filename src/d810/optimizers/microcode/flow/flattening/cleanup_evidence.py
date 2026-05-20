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

BAD_WHILE_LOOP_SOURCE_RULE = "bad_while_loop"
CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY = (
    "cleanup_conditional_redirect_proofs"
)
CLEANUP_DUPLICATE_REPLAY_METADATA_KEY = "cleanup_duplicate_replay_candidates"
CLEANUP_FOLLOW_UP_RECLASSIFICATION_METADATA_KEY = (
    "cleanup_bad_while_loop_follow_up_reclassifications"
)
CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY = "cleanup_side_effect_replay_candidates"
CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY = (
    "cleanup_trampoline_isolation_candidates"
)


class CleanupProofVerdict(str, Enum):
    """Diagnostic-only proof outcome for deferred cleanup rows."""

    SAFE_SHAPE = "safe_shape"
    UNSAFE = "unsafe"
    PROOF_GAP = "proof_gap"


class CleanupProofState(str, Enum):
    """First-class proof state used by runtime cleanup promotion."""

    PROVEN = "proven"
    UNPROVEN = "unproven"
    REJECTED = "rejected"


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
    TRAMPOLINE_ISOLATION = "trampoline_isolation"


class CleanupFollowUpResolutionBucket(str, Enum):
    """Read-only classification for deferred BadWhileLoop follow-up rows."""

    NOW_RESOLVABLE_REDIRECT = "now_resolvable_redirect"
    NOW_RESOLVABLE_DUPLICATE_AND_REDIRECT = (
        "now_resolvable_duplicate_and_redirect"
    )
    NOW_RESOLVABLE_CONDITIONAL_REDIRECT = (
        "now_resolvable_conditional_redirect"
    )
    NOW_RESOLVABLE_CONDITIONAL_DUPLICATE = (
        "now_resolvable_conditional_duplicate"
    )
    NEEDS_INSERTBLOCK_REPLAY = "needs_insertblock_replay"
    NEEDS_TRAMPOLINE_ISOLATION = "needs_trampoline_isolation"
    NEEDS_DEPENDENCY_RESCUE = "needs_dependency_rescue"
    CALL_ANCHOR_REQUIRED = "call_anchor_required"
    STILL_EVIDENCE_GAP = "still_evidence_gap"
    STILL_UNSAFE = "still_unsafe"


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
class CleanupConditionalRedirectPromotionProof:
    """Runtime proof object for BadWhileLoop conditional redirect promotion.

    This object is built from live legacy evidence and the current CFG. It is
    not serialized diagnostic metadata; callers must require ``state=PROVEN``
    before lowering the rewrite.
    """

    source_rule: str
    dispatcher_entry: int
    source_serial: int
    ref_block: int
    conditional_target: int
    fallthrough_target: int
    old_target_serial: int
    dispatcher_internal_serials: tuple[int, ...]
    state: CleanupProofState
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class CleanupFollowUpReclassification:
    """Read-only resolution bucket for one deferred BadWhileLoop row."""

    source_rule: str
    dispatcher_entry: int
    from_serial: int
    category: str
    reason: str
    bucket: CleanupFollowUpResolutionBucket
    proof_state: CleanupProofState
    target_serial: int | None = None
    fallthrough_target: int | None = None
    proof_sources: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class CleanupFollowUpTargetProof:
    """Exact-target proof for one deferred BadWhileLoop follow-up.

    Follow-up rows are diagnostic metadata. This object lets callers feed
    modern recon evidence into the read-only classifier without making the
    cleanup engine depend on transition-report, DAG, BST, or state-fixpoint
    concrete types.
    """

    dispatcher_entry: int
    from_serial: int
    reason: str
    target_serial: int
    proof_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class CleanupFollowUpPerPredTargetProof:
    """Per-predecessor exact-target proof for a duplicate follow-up."""

    dispatcher_entry: int
    from_serial: int
    reason: str
    per_pred_targets: tuple[tuple[int, int], ...]
    proof_sources: tuple[str, ...] = ()


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
    must be captured live while the bad-while-loop analysis still has
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


@dataclass(frozen=True)
class CleanupTrampolineIsolationCandidate:
    """Neutral evidence for inserting an empty isolation block before a case.

    This is the narrow BadWhileLoop trampoline lane: the shared source block is
    already a one-way predecessor of the dispatcher, every legacy predecessor
    resolved to the same risky dispatcher case, and preserving source-body
    execution only requires replacing ``source -> dispatcher`` with
    ``source -> empty_insert -> target_case``.
    """

    source_rule: str
    dispatcher_entry: int
    source_serial: int
    target_serial: int
    exit_shape: CleanupExitShape
    rewrite_intent: CleanupRewriteIntent
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


def bad_while_loop_conditional_redirect_proof(
    legacy_edit: object,
    cfg: FlowGraph,
) -> CleanupConditionalRedirectPromotionProof | None:
    """Build first-class live proof for conditional redirect promotion.

    The proof is computed from the current CFG and the bad-while-loop edit.
    It deliberately does not read serialized diagnostic proof metadata.
    """
    diagnostic = explain_bad_while_loop_conditional_redirect(
        legacy_edit,
        cfg,
        defer_reason="conditional_redirect_promotion_proof",
    )
    if diagnostic is None:
        return None

    if diagnostic.verdict is CleanupProofVerdict.SAFE_SHAPE:
        state = CleanupProofState.PROVEN
    elif diagnostic.verdict is CleanupProofVerdict.PROOF_GAP:
        state = CleanupProofState.UNPROVEN
    else:
        state = CleanupProofState.REJECTED

    return CleanupConditionalRedirectPromotionProof(
        source_rule=diagnostic.source_rule,
        dispatcher_entry=diagnostic.dispatcher_entry,
        source_serial=diagnostic.source_serial,
        ref_block=diagnostic.ref_block,
        conditional_target=diagnostic.conditional_target,
        fallthrough_target=diagnostic.fallthrough_target,
        old_target_serial=diagnostic.dispatcher_entry,
        dispatcher_internal_serials=diagnostic.dispatcher_internal_serials,
        state=state,
        reasons=diagnostic.reasons,
    )


def validate_conditional_duplicate_cleanup_edit(
    cfg: FlowGraph,
    legacy_edit: object,
) -> bool:
    """Return whether a bad-while-loop conditional duplicate is plannable."""
    if type(legacy_edit).__name__ != "BadWhileLoopConditionalDuplicate":
        return False

    dispatcher_entry = _coerce_int(getattr(legacy_edit, "dispatcher_entry", None))
    source_serial = _coerce_int(getattr(legacy_edit, "source_serial", None))
    pred_serial = _coerce_int(getattr(legacy_edit, "pred_serial", None))
    conditional_target = _coerce_int(
        getattr(legacy_edit, "conditional_target", None),
    )
    fallthrough_target = _coerce_int(
        getattr(legacy_edit, "fallthrough_target", None),
    )
    if (
        dispatcher_entry is None
        or source_serial is None
        or pred_serial is None
        or conditional_target is None
        or fallthrough_target is None
    ):
        return False

    dispatcher_internal = _coerce_dispatcher_internal(
        getattr(legacy_edit, "dispatcher_internal_serials", ()),
    )
    source_block = cfg.get_block(source_serial)
    pred_block = cfg.get_block(pred_serial)
    dispatcher_block = cfg.get_block(dispatcher_entry)
    conditional_block = cfg.get_block(conditional_target)
    fallthrough_block = cfg.get_block(fallthrough_target)
    if (
        source_block is None
        or pred_block is None
        or dispatcher_block is None
        or conditional_block is None
        or fallthrough_block is None
    ):
        return False
    if source_serial == cfg.entry_serial:
        return False
    if source_block.nsucc != 2 or dispatcher_entry not in source_block.succs:
        return False
    if pred_block.nsucc != 1 or pred_block.succs[0] != source_serial:
        return False
    if pred_serial not in source_block.preds:
        return False
    if conditional_target == fallthrough_target:
        return False
    if (
        conditional_target not in source_block.succs
        and fallthrough_target not in source_block.succs
    ):
        return False
    forbidden_targets = {
        source_serial,
        dispatcher_entry,
        *dispatcher_internal,
    }
    if (
        conditional_target in forbidden_targets
        or fallthrough_target in forbidden_targets
    ):
        return False
    return True


def validate_conditional_redirect_cleanup_edit(
    cfg: FlowGraph,
    legacy_edit: object,
) -> bool:
    """Return whether a bad-while-loop conditional redirect proof promotes."""
    proof = bad_while_loop_conditional_redirect_proof(legacy_edit, cfg)
    return proof is not None and proof.state is CleanupProofState.PROVEN


def bad_while_loop_duplicate_candidate(
    legacy_edit: object,
) -> DispatcherCleanupCandidate | None:
    """Convert a bad-while-loop duplicate edit into neutral evidence."""
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
    """Build neutral replay evidence from a bad-while-loop side-effect case."""
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
    """Build neutral replay evidence from a bad-while-loop duplicate group."""
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


def bad_while_loop_trampoline_isolation_candidate(
    *,
    dispatcher_entry: object,
    source_serial: object,
    target_serial: object,
    dispatcher_internal_serials: Sequence[object] = (),
) -> CleanupTrampolineIsolationCandidate | None:
    """Build neutral evidence for the narrow empty-block trampoline lane."""
    dispatcher_entry_int = _coerce_int(dispatcher_entry)
    source_serial_int = _coerce_int(source_serial)
    target_serial_int = _coerce_int(target_serial)
    if (
        dispatcher_entry_int is None
        or source_serial_int is None
        or target_serial_int is None
    ):
        return None

    dispatcher_internal = _coerce_dispatcher_internal(dispatcher_internal_serials)
    if target_serial_int in {
        dispatcher_entry_int,
        source_serial_int,
        *dispatcher_internal,
    }:
        return None

    return CleanupTrampolineIsolationCandidate(
        source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
        dispatcher_entry=dispatcher_entry_int,
        source_serial=source_serial_int,
        target_serial=target_serial_int,
        exit_shape=CleanupExitShape.ONE_WAY_DISPATCHER_PREDECESSOR,
        rewrite_intent=CleanupRewriteIntent.TRAMPOLINE_ISOLATION,
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


def validate_trampoline_isolation_candidate(
    cfg: FlowGraph,
    candidate: CleanupTrampolineIsolationCandidate,
) -> bool:
    """Return whether empty-block trampoline isolation is safe to emit."""
    if candidate.source_rule != BAD_WHILE_LOOP_SOURCE_RULE:
        return False
    if (
        candidate.exit_shape != CleanupExitShape.ONE_WAY_DISPATCHER_PREDECESSOR
        or candidate.rewrite_intent != CleanupRewriteIntent.TRAMPOLINE_ISOLATION
    ):
        return False

    dispatcher_block = cfg.blocks.get(candidate.dispatcher_entry)
    source_block = cfg.blocks.get(candidate.source_serial)
    target_block = cfg.blocks.get(candidate.target_serial)
    if dispatcher_block is None or source_block is None or target_block is None:
        return False
    if source_block.nsucc != 1:
        return False
    if source_block.succs[0] != candidate.dispatcher_entry:
        return False
    if candidate.target_serial not in dispatcher_block.succs:
        return False
    if target_block.nsucc != 2:
        return False

    forbidden = {
        candidate.dispatcher_entry,
        candidate.source_serial,
        *candidate.dispatcher_internal_serials,
    }
    if candidate.target_serial in forbidden:
        return False
    if any(int(succ) not in cfg.blocks for succ in target_block.succs):
        return False

    adjacency = {
        int(serial): [int(succ) for succ in block.succs]
        for serial, block in cfg.blocks.items()
    }
    adjacency[candidate.source_serial] = [candidate.target_serial]
    return not _reaches_any(
        adjacency,
        start=candidate.target_serial,
        targets=forbidden,
    )


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
        | CleanupTrampolineIsolationCandidate
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
    if (
        isinstance(candidate, CleanupTrampolineIsolationCandidate)
        and candidate.exit_shape == CleanupExitShape.ONE_WAY_DISPATCHER_PREDECESSOR
        and candidate.rewrite_intent == CleanupRewriteIntent.TRAMPOLINE_ISOLATION
    ):
        return InsertBlock(
            pred_serial=candidate.source_serial,
            succ_serial=candidate.target_serial,
            old_target_serial=candidate.dispatcher_entry,
            instructions=(),
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


def extract_trampoline_isolation_candidates(
    flow_graph: FlowGraph | None,
) -> tuple[CleanupTrampolineIsolationCandidate, ...]:
    """Read validated trampoline isolation candidates from in-memory metadata."""
    if flow_graph is None:
        return ()
    raw = flow_graph.metadata.get(CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    candidates: list[CleanupTrampolineIsolationCandidate] = []
    for item in raw:
        if not isinstance(item, CleanupTrampolineIsolationCandidate):
            continue
        if validate_trampoline_isolation_candidate(flow_graph, item):
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


def reclassify_bad_while_loop_follow_ups(
    follow_up: Sequence[object],
    cfg: FlowGraph | None,
    *,
    target_proofs: Sequence[CleanupFollowUpTargetProof] = (),
    per_pred_target_proofs: Sequence[CleanupFollowUpPerPredTargetProof] = (),
    edits: Sequence[object] = (),
    replay_candidates: Sequence[CleanupSideEffectReplayCandidate] = (),
    duplicate_replay_candidates: Sequence[CleanupDuplicateGroupReplayCandidate] = (),
    trampoline_isolation_candidates: Sequence[
        CleanupTrampolineIsolationCandidate
    ] = (),
    conditional_redirect_proofs: Sequence[CleanupConditionalRedirectProof] = (),
    dependency_diagnostics: Sequence[Mapping[str, object]] = (),
    transition_report: object | None = None,
    dag_authority: object | None = None,
    bst_intervals: Sequence[object] = (),
    state_constants_by_source: Mapping[int, int] | None = None,
) -> tuple[CleanupFollowUpReclassification, ...]:
    """Read-only bucketization for remaining BadWhileLoop follow-up rows.

    The function deliberately does not authorize rewrites.  It combines the
    legacy follow-up row with any modern evidence the caller already has and
    reports the narrowest next lane that could make the row actionable.
    """
    rows: list[CleanupFollowUpReclassification] = []
    for item in follow_up:
        row = reclassify_bad_while_loop_follow_up(
            item,
            cfg,
            target_proofs=target_proofs,
            per_pred_target_proofs=per_pred_target_proofs,
            edits=edits,
            replay_candidates=replay_candidates,
            duplicate_replay_candidates=duplicate_replay_candidates,
            trampoline_isolation_candidates=trampoline_isolation_candidates,
            conditional_redirect_proofs=conditional_redirect_proofs,
            dependency_diagnostics=dependency_diagnostics,
            transition_report=transition_report,
            dag_authority=dag_authority,
            bst_intervals=bst_intervals,
            state_constants_by_source=state_constants_by_source,
        )
        if row is not None:
            rows.append(row)
    return tuple(rows)


def reclassify_bad_while_loop_follow_up(
    follow_up: object,
    cfg: FlowGraph | None,
    *,
    target_proofs: Sequence[CleanupFollowUpTargetProof] = (),
    per_pred_target_proofs: Sequence[CleanupFollowUpPerPredTargetProof] = (),
    edits: Sequence[object] = (),
    replay_candidates: Sequence[CleanupSideEffectReplayCandidate] = (),
    duplicate_replay_candidates: Sequence[CleanupDuplicateGroupReplayCandidate] = (),
    trampoline_isolation_candidates: Sequence[
        CleanupTrampolineIsolationCandidate
    ] = (),
    conditional_redirect_proofs: Sequence[CleanupConditionalRedirectProof] = (),
    dependency_diagnostics: Sequence[Mapping[str, object]] = (),
    transition_report: object | None = None,
    dag_authority: object | None = None,
    bst_intervals: Sequence[object] = (),
    state_constants_by_source: Mapping[int, int] | None = None,
) -> CleanupFollowUpReclassification | None:
    fields = _follow_up_fields(follow_up)
    if fields is None:
        return None
    dispatcher_entry, from_serial, category, reason, target_serial, fallthrough_target = (
        fields
    )

    def make(
        bucket: CleanupFollowUpResolutionBucket,
        proof_state: CleanupProofState,
        *,
        proof_sources: Sequence[str] = (),
        notes: Sequence[str] = (),
    ) -> CleanupFollowUpReclassification:
        return CleanupFollowUpReclassification(
            source_rule=BAD_WHILE_LOOP_SOURCE_RULE,
            dispatcher_entry=dispatcher_entry,
            from_serial=from_serial,
            category=category,
            reason=reason,
            target_serial=target_serial,
            fallthrough_target=fallthrough_target,
            bucket=bucket,
            proof_state=proof_state,
            proof_sources=tuple(proof_sources),
            notes=tuple(notes),
        )

    edit_bucket = _reclassify_from_structured_edit(
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        target_serial=target_serial,
        fallthrough_target=fallthrough_target,
        cfg=cfg,
        edits=edits,
    )
    if edit_bucket is not None:
        return make(
            edit_bucket,
            CleanupProofState.PROVEN,
            proof_sources=("structured_metadata", "graph_modification_feasible"),
        )

    replay_bucket = _reclassify_from_replay_candidate(
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        target_serial=target_serial,
        cfg=cfg,
        replay_candidates=replay_candidates,
        duplicate_replay_candidates=duplicate_replay_candidates,
    )
    if replay_bucket is not None:
        return make(
            replay_bucket,
            CleanupProofState.PROVEN,
            proof_sources=("structured_metadata", "graph_modification_feasible"),
        )

    trampoline_bucket = _reclassify_from_trampoline_candidate(
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        target_serial=target_serial,
        cfg=cfg,
        trampoline_isolation_candidates=trampoline_isolation_candidates,
    )
    if trampoline_bucket is not None:
        return make(
            trampoline_bucket,
            CleanupProofState.PROVEN,
            proof_sources=("structured_metadata", "graph_modification_feasible"),
        )

    proof = _matching_conditional_redirect_proof(
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        target_serial=target_serial,
        fallthrough_target=fallthrough_target,
        proofs=conditional_redirect_proofs,
    )
    if proof is not None:
        if proof.verdict is CleanupProofVerdict.SAFE_SHAPE:
            return make(
                CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_CONDITIONAL_REDIRECT,
                CleanupProofState.PROVEN,
                proof_sources=("structured_metadata", "graph_modification_feasible"),
                notes=proof.reasons,
            )
        if proof.verdict is CleanupProofVerdict.PROOF_GAP:
            return make(
                CleanupFollowUpResolutionBucket.STILL_EVIDENCE_GAP,
                CleanupProofState.UNPROVEN,
                proof_sources=("structured_metadata",),
                notes=proof.reasons,
            )
        return make(
            CleanupFollowUpResolutionBucket.STILL_UNSAFE,
            CleanupProofState.REJECTED,
            proof_sources=("structured_metadata",),
            notes=proof.reasons,
        )

    per_pred_proof = _matching_follow_up_per_pred_target_proof(
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        reason=reason,
        proofs=per_pred_target_proofs,
    )
    if per_pred_proof is not None:
        if cfg is not None and _per_pred_targets_are_plannable(
            cfg,
            dispatcher_entry=dispatcher_entry,
            from_serial=from_serial,
            per_pred_targets=per_pred_proof.per_pred_targets,
        ):
            return make(
                CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_DUPLICATE_AND_REDIRECT,
                CleanupProofState.PROVEN,
                proof_sources=per_pred_proof.proof_sources,
            )
        return make(
            CleanupFollowUpResolutionBucket.STILL_EVIDENCE_GAP,
            CleanupProofState.UNPROVEN,
            proof_sources=per_pred_proof.proof_sources,
            notes=("per_pred_target_proof_not_plannable_on_current_cfg",),
        )

    target_proof = _matching_follow_up_target_proof(
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        reason=reason,
        target_serial=target_serial,
        proofs=target_proofs,
    )
    if target_proof is not None:
        if (
            cfg is not None
            and _one_way_to_dispatcher(
                cfg,
                from_serial,
                dispatcher_entry,
            )
            and _target_is_plannable(
                cfg,
                dispatcher_entry=dispatcher_entry,
                from_serial=from_serial,
                target_serial=target_proof.target_serial,
            )
        ):
            return make(
                CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_REDIRECT,
                CleanupProofState.PROVEN,
                proof_sources=target_proof.proof_sources,
            )
        return make(
            CleanupFollowUpResolutionBucket.STILL_EVIDENCE_GAP,
            CleanupProofState.UNPROVEN,
            proof_sources=target_proof.proof_sources,
            notes=("target_proof_not_plannable_on_current_cfg",),
        )

    modern_target_source = _modern_single_target_source(
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        target_serial=target_serial,
        cfg=cfg,
        transition_report=transition_report,
        dag_authority=dag_authority,
        bst_intervals=bst_intervals,
        state_constants_by_source=state_constants_by_source,
    )
    if modern_target_source is not None:
        return make(
            CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_REDIRECT,
            CleanupProofState.PROVEN,
            proof_sources=modern_target_source,
        )

    diagnostic = _matching_dependency_diagnostic(
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        target_serial=target_serial,
        reason=reason,
        diagnostics=dependency_diagnostics,
    )
    if diagnostic is not None:
        final_bucket = str(diagnostic.get("final_bucket", ""))
        if final_bucket == "call_or_payload_invalid":
            return make(
                CleanupFollowUpResolutionBucket.CALL_ANCHOR_REQUIRED,
                CleanupProofState.REJECTED,
                proof_sources=("dependency_diagnostics",),
                notes=_diagnostic_notes(diagnostic),
            )
        if final_bucket in {
            "stack_unique_def_chain_capturable",
            "stack_ambiguous_defs",
            "stack_external_or_no_reaching_def",
            "reg_single_pred_def",
            "reg_or_lvar_needs_capture",
        }:
            return make(
                CleanupFollowUpResolutionBucket.NEEDS_DEPENDENCY_RESCUE,
                CleanupProofState.UNPROVEN,
                proof_sources=("dependency_diagnostics",),
                notes=_diagnostic_notes(diagnostic),
            )
        if final_bucket in {"memory_or_alias_unknown", "mixed_unknown"}:
            return make(
                CleanupFollowUpResolutionBucket.STILL_EVIDENCE_GAP,
                CleanupProofState.UNPROVEN,
                proof_sources=("dependency_diagnostics",),
                notes=_diagnostic_notes(diagnostic),
            )

    if "contains_call" in reason:
        return make(
            CleanupFollowUpResolutionBucket.CALL_ANCHOR_REQUIRED,
            CleanupProofState.REJECTED,
            proof_sources=("structured_metadata",),
        )
    if "not_dependency_safe" in reason:
        return make(
            CleanupFollowUpResolutionBucket.NEEDS_DEPENDENCY_RESCUE,
            CleanupProofState.UNPROVEN,
            proof_sources=("structured_metadata",),
        )
    if reason in {"copied_side_effects", "duplicate_group_copied_side_effects"}:
        return make(
            CleanupFollowUpResolutionBucket.NEEDS_INSERTBLOCK_REPLAY,
            CleanupProofState.UNPROVEN,
            proof_sources=("structured_metadata",),
        )
    if reason in {
        "duplicate_group_requires_trampoline",
        "dispatcher_case_triangle_requires_trampoline",
        "conditional_exit_non_one_way_predecessor",
    }:
        return make(
            CleanupFollowUpResolutionBucket.NEEDS_TRAMPOLINE_ISOLATION,
            CleanupProofState.UNPROVEN,
            proof_sources=("structured_metadata",),
            notes=_branch_or_trampoline_notes(cfg, from_serial, target_serial),
        )
    if reason in {
        "unresolved_histories",
        "missing_history_values",
        "duplicate_group_unresolved",
        "duplicate_group_missing_values",
        "duplicate_group_emulation_returned_no_target",
        "emulation_returned_no_target",
        "conditional_exit_with_loopback",
        "conditional_exit_missing_predecessors",
    }:
        return make(
            CleanupFollowUpResolutionBucket.STILL_EVIDENCE_GAP,
            CleanupProofState.UNPROVEN,
            proof_sources=("structured_metadata",),
        )
    return make(
        CleanupFollowUpResolutionBucket.STILL_UNSAFE,
        CleanupProofState.REJECTED,
        proof_sources=("structured_metadata",),
    )


def serialize_follow_up_reclassifications(
    reclassifications: Sequence[CleanupFollowUpReclassification],
) -> tuple[dict[str, object], ...]:
    """Serialize follow-up reclassification rows for FlowGraph metadata."""
    return tuple(
        {
            "source_rule": row.source_rule,
            "dispatcher_entry": row.dispatcher_entry,
            "from_serial": row.from_serial,
            "category": row.category,
            "reason": row.reason,
            "target_serial": row.target_serial,
            "fallthrough_target": row.fallthrough_target,
            "bucket": row.bucket.value,
            "proof_state": row.proof_state.value,
            "proof_sources": list(row.proof_sources),
            "notes": list(row.notes),
        }
        for row in reclassifications
    )


def extract_follow_up_reclassifications(
    flow_graph: FlowGraph | None,
) -> tuple[CleanupFollowUpReclassification, ...]:
    """Read BadWhileLoop follow-up reclassification rows from metadata."""
    if flow_graph is None:
        return ()
    raw = flow_graph.metadata.get(CLEANUP_FOLLOW_UP_RECLASSIFICATION_METADATA_KEY)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    rows: list[CleanupFollowUpReclassification] = []
    for item in raw:
        row = _coerce_follow_up_reclassification(item)
        if row is not None:
            rows.append(row)
    return tuple(rows)


def _follow_up_fields(
    follow_up: object,
) -> tuple[int, int, str, str, int | None, int | None] | None:
    def get(name: str) -> object:
        if isinstance(follow_up, Mapping):
            return follow_up.get(name)
        return getattr(follow_up, name, None)

    dispatcher_entry = _coerce_int(get("dispatcher_entry"))
    from_serial = _coerce_int(get("from_serial"))
    category = get("category")
    reason = get("reason")
    if (
        dispatcher_entry is None
        or from_serial is None
        or not isinstance(category, str)
        or not isinstance(reason, str)
    ):
        return None
    return (
        dispatcher_entry,
        from_serial,
        category,
        reason,
        _coerce_optional_int(get("target_serial")),
        _coerce_optional_int(get("fallthrough_target")),
    )


def _reclassify_from_structured_edit(
    *,
    dispatcher_entry: int,
    from_serial: int,
    target_serial: int | None,
    fallthrough_target: int | None,
    cfg: FlowGraph | None,
    edits: Sequence[object],
) -> CleanupFollowUpResolutionBucket | None:
    for edit in edits:
        edit_type = type(edit).__name__
        if (
            edit_type == "BadWhileLoopGotoRedirect"
            and _coerce_int(getattr(edit, "dispatcher_entry", None))
            == dispatcher_entry
            and _coerce_int(getattr(edit, "from_serial", None)) == from_serial
        ):
            return CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_REDIRECT
        if (
            edit_type == "BadWhileLoopGotoConversion"
            and _coerce_int(getattr(edit, "dispatcher_entry", None))
            == dispatcher_entry
            and _coerce_int(getattr(edit, "block_serial", None)) == from_serial
        ):
            return CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_REDIRECT
        if (
            edit_type == "BadWhileLoopDuplicateRedirect"
            and _coerce_int(getattr(edit, "dispatcher_entry", None))
            == dispatcher_entry
            and _coerce_int(getattr(edit, "source_serial", None)) == from_serial
        ):
            candidate = bad_while_loop_duplicate_candidate(edit)
            if candidate is not None and (
                cfg is None or validate_dispatcher_cleanup_candidate(cfg, candidate)
            ):
                return CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_DUPLICATE_AND_REDIRECT
        if (
            edit_type == "BadWhileLoopConditionalDuplicate"
            and _coerce_int(getattr(edit, "dispatcher_entry", None))
            == dispatcher_entry
            and _coerce_int(getattr(edit, "source_serial", None)) == from_serial
            and (
                target_serial is None
                or _coerce_int(getattr(edit, "conditional_target", None))
                == target_serial
            )
            and (
                fallthrough_target is None
                or _coerce_int(getattr(edit, "fallthrough_target", None))
                == fallthrough_target
            )
        ):
            if cfg is None or validate_conditional_duplicate_cleanup_edit(cfg, edit):
                return CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_CONDITIONAL_DUPLICATE
        if (
            edit_type == "BadWhileLoopConditionalRedirect"
            and _coerce_int(getattr(edit, "dispatcher_entry", None))
            == dispatcher_entry
            and _coerce_int(getattr(edit, "source_serial", None)) == from_serial
            and (
                target_serial is None
                or _coerce_int(getattr(edit, "conditional_target", None))
                == target_serial
            )
            and (
                fallthrough_target is None
                or _coerce_int(getattr(edit, "fallthrough_target", None))
                == fallthrough_target
            )
        ):
            if cfg is None or validate_conditional_redirect_cleanup_edit(cfg, edit):
                return CleanupFollowUpResolutionBucket.NOW_RESOLVABLE_CONDITIONAL_REDIRECT
    return None


def _reclassify_from_replay_candidate(
    *,
    dispatcher_entry: int,
    from_serial: int,
    target_serial: int | None,
    cfg: FlowGraph | None,
    replay_candidates: Sequence[CleanupSideEffectReplayCandidate],
    duplicate_replay_candidates: Sequence[CleanupDuplicateGroupReplayCandidate],
) -> CleanupFollowUpResolutionBucket | None:
    for candidate in replay_candidates:
        if (
            candidate.dispatcher_entry == dispatcher_entry
            and candidate.source_serial == from_serial
            and (
                target_serial is None
                or candidate.target_serial == target_serial
            )
            and (
                cfg is None
                or validate_side_effect_replay_candidate(cfg, candidate)
            )
        ):
            return CleanupFollowUpResolutionBucket.NEEDS_INSERTBLOCK_REPLAY
    for candidate in duplicate_replay_candidates:
        if (
            candidate.dispatcher_entry == dispatcher_entry
            and candidate.source_serial == from_serial
            and (
                cfg is None
                or validate_duplicate_group_replay_candidate(cfg, candidate)
            )
        ):
            return CleanupFollowUpResolutionBucket.NEEDS_INSERTBLOCK_REPLAY
    return None


def _reclassify_from_trampoline_candidate(
    *,
    dispatcher_entry: int,
    from_serial: int,
    target_serial: int | None,
    cfg: FlowGraph | None,
    trampoline_isolation_candidates: Sequence[
        CleanupTrampolineIsolationCandidate
    ],
) -> CleanupFollowUpResolutionBucket | None:
    for candidate in trampoline_isolation_candidates:
        if (
            candidate.dispatcher_entry == dispatcher_entry
            and candidate.source_serial == from_serial
            and (
                target_serial is None
                or candidate.target_serial == target_serial
            )
            and (
                cfg is None
                or validate_trampoline_isolation_candidate(cfg, candidate)
            )
        ):
            return CleanupFollowUpResolutionBucket.NEEDS_TRAMPOLINE_ISOLATION
    return None


def _matching_conditional_redirect_proof(
    *,
    dispatcher_entry: int,
    from_serial: int,
    target_serial: int | None,
    fallthrough_target: int | None,
    proofs: Sequence[CleanupConditionalRedirectProof],
) -> CleanupConditionalRedirectProof | None:
    for proof in proofs:
        if (
            proof.dispatcher_entry == dispatcher_entry
            and proof.source_serial == from_serial
            and (
                target_serial is None
                or proof.conditional_target == target_serial
            )
            and (
                fallthrough_target is None
                or proof.fallthrough_target == fallthrough_target
            )
        ):
            return proof
    return None


def _modern_single_target_source(
    *,
    dispatcher_entry: int,
    from_serial: int,
    target_serial: int | None,
    cfg: FlowGraph | None,
    transition_report: object | None,
    dag_authority: object | None,
    bst_intervals: Sequence[object],
    state_constants_by_source: Mapping[int, int] | None,
) -> tuple[str, ...] | None:
    if cfg is not None and not _one_way_to_dispatcher(
        cfg,
        from_serial,
        dispatcher_entry,
    ):
        return None
    report_target = _target_from_transition_report(
        transition_report,
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
    )
    if report_target is not None and _target_matches(target_serial, report_target):
        return ("transition_report",)

    dag_target = _target_from_dag_authority(dag_authority, from_serial)
    if dag_target is not None and _target_matches(target_serial, dag_target):
        return ("semantic_dag",)

    state_const = (
        state_constants_by_source.get(from_serial)
        if state_constants_by_source is not None
        else None
    )
    bst_target = _target_from_bst_intervals(bst_intervals, state_const)
    if bst_target is not None and _target_matches(target_serial, bst_target):
        return ("bst_interval_singleton",)
    return None


def _one_way_to_dispatcher(
    cfg: FlowGraph,
    from_serial: int,
    dispatcher_entry: int,
) -> bool:
    block = cfg.get_block(from_serial)
    return (
        block is not None
        and block.nsucc == 1
        and tuple(block.succs) == (dispatcher_entry,)
    )


def _target_matches(expected: int | None, actual: int) -> bool:
    return expected is None or int(expected) == int(actual)


def _target_is_plannable(
    cfg: FlowGraph,
    *,
    dispatcher_entry: int,
    from_serial: int,
    target_serial: int,
) -> bool:
    return (
        target_serial in cfg.blocks
        and target_serial not in {dispatcher_entry, from_serial}
    )


def _per_pred_targets_are_plannable(
    cfg: FlowGraph,
    *,
    dispatcher_entry: int,
    from_serial: int,
    per_pred_targets: tuple[tuple[int, int], ...],
) -> bool:
    if not _one_way_to_dispatcher(cfg, from_serial, dispatcher_entry):
        return False
    source_block = cfg.get_block(from_serial)
    if source_block is None:
        return False
    if {pred for pred, _target in per_pred_targets} != set(source_block.preds):
        return False
    for pred_serial, target_serial in per_pred_targets:
        pred = cfg.get_block(pred_serial)
        if pred is None or pred.nsucc != 1 or tuple(pred.succs) != (from_serial,):
            return False
        if not _target_is_plannable(
            cfg,
            dispatcher_entry=dispatcher_entry,
            from_serial=from_serial,
            target_serial=target_serial,
        ):
            return False
    return True


def _matching_follow_up_target_proof(
    *,
    dispatcher_entry: int,
    from_serial: int,
    reason: str,
    target_serial: int | None,
    proofs: Sequence[CleanupFollowUpTargetProof],
) -> CleanupFollowUpTargetProof | None:
    for proof in proofs:
        if (
            proof.dispatcher_entry == dispatcher_entry
            and proof.from_serial == from_serial
            and proof.reason == reason
            and _target_matches(target_serial, proof.target_serial)
        ):
            return proof
    return None


def _matching_follow_up_per_pred_target_proof(
    *,
    dispatcher_entry: int,
    from_serial: int,
    reason: str,
    proofs: Sequence[CleanupFollowUpPerPredTargetProof],
) -> CleanupFollowUpPerPredTargetProof | None:
    for proof in proofs:
        if (
            proof.dispatcher_entry == dispatcher_entry
            and proof.from_serial == from_serial
            and proof.reason == reason
        ):
            return proof
    return None


def build_bad_while_loop_follow_up_proofs(
    cfg: FlowGraph,
    follow_ups: Sequence[object],
    *,
    transition_report: object | None = None,
    dag_authority: object | None = None,
    bst_intervals: Sequence[object] = (),
    state_constants_by_source: Mapping[int, int] | None = None,
    per_pred_targets_by_follow_up: (
        Mapping[tuple[int, int, str], tuple[tuple[int, int], ...]] | None
    ) = None,
) -> tuple[
    tuple[CleanupFollowUpTargetProof, ...],
    tuple[CleanupFollowUpPerPredTargetProof, ...],
]:
    """Build read-only BadWhileLoop follow-up proofs from modern evidence.

    This is intentionally an adapter over structural inputs. The cleanup engine
    should not import recon/DAG/BST concrete types, but callers can still feed
    those results into the follow-up classifier through neutral proof rows.
    """

    target_proofs: list[CleanupFollowUpTargetProof] = []
    per_pred_proofs: list[CleanupFollowUpPerPredTargetProof] = []
    seen_targets: set[tuple[int, int, str]] = set()
    seen_per_pred: set[tuple[int, int, str]] = set()

    def add_target(
        *,
        key: tuple[int, int, str],
        target: int | None,
        proof_sources: tuple[str, ...],
    ) -> None:
        dispatcher_entry, from_serial, reason = key
        if target is None or key in seen_targets:
            return
        target_int = int(target)
        if not _target_is_plannable(
            cfg,
            dispatcher_entry=dispatcher_entry,
            from_serial=from_serial,
            target_serial=target_int,
        ):
            return
        seen_targets.add(key)
        target_proofs.append(
            CleanupFollowUpTargetProof(
                dispatcher_entry=dispatcher_entry,
                from_serial=from_serial,
                reason=reason,
                target_serial=target_int,
                proof_sources=proof_sources,
            )
        )

    def add_per_pred(
        *,
        key: tuple[int, int, str],
        per_pred_targets: tuple[tuple[int, int], ...] | None,
        proof_sources: tuple[str, ...],
    ) -> None:
        dispatcher_entry, from_serial, reason = key
        if per_pred_targets is None or key in seen_per_pred:
            return
        coerced = _coerce_per_pred_targets(per_pred_targets)
        if coerced is None:
            return
        if not _per_pred_targets_are_plannable(
            cfg,
            dispatcher_entry=dispatcher_entry,
            from_serial=from_serial,
            per_pred_targets=coerced,
        ):
            return
        seen_per_pred.add(key)
        per_pred_proofs.append(
            CleanupFollowUpPerPredTargetProof(
                dispatcher_entry=dispatcher_entry,
                from_serial=from_serial,
                reason=reason,
                per_pred_targets=coerced,
                proof_sources=proof_sources,
            )
        )

    for follow_up in follow_ups:
        fields = _follow_up_fields(follow_up)
        if fields is None:
            continue
        dispatcher_entry, from_serial, _category, reason, _target, _fallthrough = (
            fields
        )
        key = (dispatcher_entry, from_serial, reason)
        if dispatcher_entry not in cfg.blocks or from_serial not in cfg.blocks:
            continue

        report_target = _target_from_transition_report(
            transition_report,
            dispatcher_entry=dispatcher_entry,
            from_serial=from_serial,
        )
        add_target(
            key=key,
            target=report_target,
            proof_sources=("transition_report",),
        )

        add_target(
            key=key,
            target=_target_from_dag_authority(dag_authority, from_serial),
            proof_sources=("semantic_dag",),
        )

        state_const = (
            state_constants_by_source.get(from_serial)
            if state_constants_by_source is not None
            else None
        )
        add_target(
            key=key,
            target=_target_from_bst_intervals(bst_intervals, state_const),
            proof_sources=("bst_interval_singleton",),
        )

        if per_pred_targets_by_follow_up is not None:
            add_per_pred(
                key=key,
                per_pred_targets=per_pred_targets_by_follow_up.get(key),
                proof_sources=("per_pred_target_map",),
            )

    return tuple(target_proofs), tuple(per_pred_proofs)


def _target_from_transition_report(
    report: object | None,
    *,
    dispatcher_entry: int,
    from_serial: int,
) -> int | None:
    if report is None:
        return None
    if _coerce_int(getattr(report, "dispatcher_entry_serial", None)) not in (
        None,
        dispatcher_entry,
    ):
        return None
    handler_state_map = getattr(report, "handler_state_map", {}) or {}
    rows = getattr(report, "rows", ()) or ()
    for row in rows:
        if _coerce_int(getattr(row, "handler_serial", None)) != from_serial:
            continue
        next_state = _coerce_optional_int(getattr(row, "next_state", None))
        if next_state is None:
            conditional_states = getattr(row, "conditional_states", ()) or ()
            normalized = [
                state
                for raw_state in conditional_states
                if (state := _coerce_int(raw_state)) is not None
            ]
            if len(normalized) != 1:
                continue
            next_state = normalized[0]
        try:
            target = handler_state_map.get(next_state)
        except AttributeError:
            target = None
        target_int = _coerce_int(target)
        if target_int is not None:
            return target_int
    return None


def _target_from_dag_authority(authority: object | None, from_serial: int) -> int | None:
    if authority is None:
        return None
    conflicts = getattr(authority, "conflicts_for_source", None)
    if callable(conflicts):
        try:
            if conflicts(from_serial, None):
                return None
        except Exception:
            return None
    getter = getattr(authority, "canonical_target_for", None)
    if not callable(getter):
        return None
    try:
        return _coerce_int(getter(from_serial, None))
    except Exception:
        return None


def _target_from_bst_intervals(
    intervals: Sequence[object],
    state_const: int | None,
) -> int | None:
    if state_const is None:
        return None
    matches: set[int] = set()
    for interval in intervals:
        lo = _coerce_int(getattr(interval, "lo", None))
        hi = _coerce_int(getattr(interval, "hi", None))
        target = _coerce_int(
            getattr(interval, "target_block", getattr(interval, "target", None)),
        )
        if lo is None or hi is None or target is None:
            continue
        if lo <= int(state_const) < hi:
            matches.add(target)
    if len(matches) == 1:
        return next(iter(matches))
    return None


def _matching_dependency_diagnostic(
    *,
    dispatcher_entry: int,
    from_serial: int,
    target_serial: int | None,
    reason: str,
    diagnostics: Sequence[Mapping[str, object]],
) -> Mapping[str, object] | None:
    for diagnostic in diagnostics:
        if (
            _coerce_int(diagnostic.get("dispatcher_entry")) == dispatcher_entry
            and _coerce_int(diagnostic.get("source_serial")) == from_serial
            and (
                target_serial is None
                or _coerce_optional_int(diagnostic.get("target_serial"))
                == target_serial
            )
            and str(diagnostic.get("reason", "")) == reason
        ):
            return diagnostic
    return None


def _diagnostic_notes(diagnostic: Mapping[str, object]) -> tuple[str, ...]:
    notes: list[str] = []
    for key in ("final_bucket", "bucket_reason"):
        value = diagnostic.get(key)
        if value is not None:
            notes.append(f"{key}={value}")
    return tuple(notes)


def _branch_or_trampoline_notes(
    cfg: FlowGraph | None,
    from_serial: int,
    target_serial: int | None,
) -> tuple[str, ...]:
    if cfg is None:
        return ()
    block = cfg.get_block(from_serial)
    if block is None:
        return ("source_missing",)
    if block.nsucc == 2:
        return ("branch_arm_or_pred_split_required",)
    if block.nsucc == 1 and target_serial is not None:
        target = cfg.get_block(target_serial)
        if target is not None and target.nsucc == 2:
            return ("empty_insertblock_isolation_candidate",)
    return ()


def _coerce_follow_up_reclassification(
    raw: object,
) -> CleanupFollowUpReclassification | None:
    if isinstance(raw, CleanupFollowUpReclassification):
        return raw
    if not isinstance(raw, Mapping):
        return None
    source_rule = raw.get("source_rule")
    dispatcher_entry = _coerce_int(raw.get("dispatcher_entry"))
    from_serial = _coerce_int(raw.get("from_serial"))
    category = raw.get("category")
    reason = raw.get("reason")
    bucket_raw = raw.get("bucket")
    proof_state_raw = raw.get("proof_state")
    if (
        not isinstance(source_rule, str)
        or dispatcher_entry is None
        or from_serial is None
        or not isinstance(category, str)
        or not isinstance(reason, str)
        or not isinstance(bucket_raw, str)
        or not isinstance(proof_state_raw, str)
    ):
        return None
    try:
        bucket = CleanupFollowUpResolutionBucket(bucket_raw)
        proof_state = CleanupProofState(proof_state_raw)
    except ValueError:
        return None

    def str_tuple(value: object) -> tuple[str, ...]:
        if not isinstance(value, Sequence) or isinstance(
            value,
            (str, bytes, bytearray),
        ):
            return ()
        return tuple(item for item in value if isinstance(item, str))

    return CleanupFollowUpReclassification(
        source_rule=source_rule,
        dispatcher_entry=dispatcher_entry,
        from_serial=from_serial,
        category=category,
        reason=reason,
        target_serial=_coerce_optional_int(raw.get("target_serial")),
        fallthrough_target=_coerce_optional_int(raw.get("fallthrough_target")),
        bucket=bucket,
        proof_state=proof_state,
        proof_sources=str_tuple(raw.get("proof_sources", ())),
        notes=str_tuple(raw.get("notes", ())),
    )


__all__ = [
    "BAD_WHILE_LOOP_SOURCE_RULE",
    "CLEANUP_CONDITIONAL_REDIRECT_PROOF_METADATA_KEY",
    "CLEANUP_DUPLICATE_REPLAY_METADATA_KEY",
    "CLEANUP_FOLLOW_UP_RECLASSIFICATION_METADATA_KEY",
    "CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY",
    "CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY",
    "CleanupConditionalRedirectProof",
    "CleanupConditionalRedirectPromotionProof",
    "CleanupDuplicateGroupReplayCandidate",
    "CleanupExitShape",
    "CleanupFollowUpPerPredTargetProof",
    "CleanupFollowUpReclassification",
    "CleanupFollowUpResolutionBucket",
    "CleanupFollowUpTargetProof",
    "CleanupObservedBlockShape",
    "CleanupPerPredReplay",
    "CleanupProofState",
    "CleanupProofVerdict",
    "CleanupRewriteIntent",
    "CleanupSideEffectReplayCandidate",
    "CleanupTrampolineIsolationCandidate",
    "DispatcherCleanupCandidate",
    "bad_while_loop_duplicate_candidate",
    "bad_while_loop_duplicate_group_replay_candidate",
    "bad_while_loop_conditional_redirect_proof",
    "bad_while_loop_side_effect_replay_candidate",
    "bad_while_loop_trampoline_isolation_candidate",
    "build_bad_while_loop_follow_up_proofs",
    "build_dispatcher_cleanup_modification",
    "explain_bad_while_loop_conditional_redirect",
    "extract_conditional_redirect_proofs",
    "extract_duplicate_group_replay_candidates",
    "extract_follow_up_reclassifications",
    "extract_side_effect_replay_candidates",
    "extract_trampoline_isolation_candidates",
    "reclassify_bad_while_loop_follow_up",
    "reclassify_bad_while_loop_follow_ups",
    "serialize_conditional_redirect_proofs",
    "serialize_follow_up_reclassifications",
    "validate_conditional_duplicate_cleanup_edit",
    "validate_conditional_redirect_cleanup_edit",
    "validate_dispatcher_cleanup_candidate",
    "validate_duplicate_group_replay_candidate",
    "validate_side_effect_replay_candidate",
    "validate_trampoline_isolation_candidate",
]
