from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from d810.core import logging
from d810.cfg.flow.edit_simulator import project_post_state
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateAndRedirect,
    EdgeRedirectViaPredSplit,
    RedirectBranch,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.cfg.loop_bound_writer_guard import (
    LoopBoundWriterDiagnostic,
    LoopCounterWritebackDiagnostic,
    detect_loop_bound_writer_redirect,
    detect_loop_counter_writeback_tail,
)
from d810.cfg.plan import compile_patch_plan
from d810.cfg.reconstruction_lowering import SharedGroupEmissionCandidate
from d810.cfg.reconstruction_modification_planning import (
    plan_conditional_arm_reconstruction_modifications,
    plan_direct_reconstruction_modifications,
    plan_passthrough_reconstruction_modifications,
    plan_shared_group_reconstruction_modifications,
)
from d810.cfg.zero_state_write_emission import (
    ZsvSource,
    collect_zero_state_writes,
)

logger = logging.getLogger(
    "D810.cfg.reconstruction_execution",
    logging.DEBUG,
)

_SUB7FFD_POLL_TARGET_STATE = 0x00C0C59F
_SUB7FFD_GROUP_HOIST_SHARED_BLOCK = 95
_SUB7FFD_GROUP_HOIST_PRED = 93
_SUB7FFD_GROUP_HOIST_TARGET = 212
_SUB7FFD_POLL_SUFFIX_SHARED_BLOCK = 45
_SUB7FFD_POLL_SUFFIX_BASE_TARGET = 126
_SUB7FFD_POLL_SUFFIX_CLONE_SOURCE = 122
_SUB7FFD_POLL_SUFFIX_CLONE_TARGET = 180


@dataclass(frozen=True, slots=True)
class ConditionalArmExecutionResult:
    candidate: object
    redirect_count: int
    passthrough_count: int


@dataclass(frozen=True, slots=True)
class DirectExecutionResult:
    accepted_candidate: object | None
    rejected_candidates: tuple[object, ...]
    rejection_reason: str | None
    passthrough_count: int = 0


@dataclass(frozen=True, slots=True)
class SharedGroupExecutionResult:
    shared_block: int
    accepted_candidates: tuple[object, ...]
    rejected_candidates: tuple[object, ...]
    rejection_reason: str | None
    emission_mode: str | None = None
    modifications: tuple[object, ...] = ()
    per_pred_targets: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class PrimaryReconstructionExecutionResult:
    conditional_results: tuple[ConditionalArmExecutionResult, ...]
    direct_results: tuple[DirectExecutionResult, ...]
    shared_group_results: tuple[SharedGroupExecutionResult, ...]


@dataclass(frozen=True, slots=True)
class _PairedConditionalArmGroup:
    horizon_block: int
    source_block: int
    fallthrough_target: int
    conditional_target: int
    emission_kind: str
    candidates: tuple[object, ...]


def _resolve_candidate_horizon_old_target(
    *,
    candidate: object,
    horizon_block: int,
    horizon_succs: tuple[int, ...],
) -> int | None:
    ordered_path = tuple(
        int(serial) for serial in getattr(getattr(candidate, "edge", None), "ordered_path", ()) or ()
    )
    if ordered_path:
        try:
            horizon_index = ordered_path.index(int(horizon_block))
        except ValueError:
            horizon_index = -1
        if horizon_index >= 0 and horizon_index + 1 < len(ordered_path):
            return int(ordered_path[horizon_index + 1])
    branch_arm = getattr(getattr(getattr(candidate, "edge", None), "source_anchor", None), "branch_arm", None)
    if branch_arm in (0, 1) and int(branch_arm) < len(horizon_succs):
        return int(horizon_succs[int(branch_arm)])
    return None


def _collect_zero_state_write_modifications(
    candidates: tuple[object, ...] | list[object],
    *,
    existing_modifications: tuple[object, ...] | list[object] = (),
) -> tuple[ZeroStateWrite, ...]:
    """Collect ZeroStateWrite modifications for reconstruction candidates.

    Thin wrapper around the unified :func:`collect_zero_state_writes`
    emitter (Phase 4 of uee-jrgq, ticket uee-rjo8). Preserves the
    historical signature for the four call sites in
    :func:`execute_primary_reconstruction_modifications`.

    The single-emitter invariant — every ``(block_serial, insn_ea)``
    ZSW decision has exactly one author per pipeline run — is enforced
    by sharing the ``existing_modifications`` accumulator across all
    invocations. The unified module performs the dedup pass once
    (see ``cfg/zero_state_write_emission.py``).
    """
    return collect_zero_state_writes(
        source=ZsvSource.from_candidates(
            candidates,
            provenance="reconstruction_candidates",
        ),
        existing_modifications=existing_modifications,
    )


def _is_conditional_transition(candidate) -> bool:
    edge_kind = getattr(getattr(candidate, "edge", None), "kind", None)
    return getattr(edge_kind, "name", None) == "CONDITIONAL_TRANSITION"


def _is_sub7ffd_poll_candidate(candidate) -> bool:
    edge = getattr(candidate, "edge", None)
    target_state = getattr(edge, "target_state", None)
    return (
        target_state is not None
        and int(target_state) & 0xFFFFFFFF == _SUB7FFD_POLL_TARGET_STATE
    )


def _should_hoist_sub7ffd_shared_group(shared_block: int, candidates: list) -> bool:
    if int(shared_block) != _SUB7FFD_GROUP_HOIST_SHARED_BLOCK:
        return False
    filtered = [candidate for candidate in candidates if getattr(candidate, "via_pred", None) is not None]
    if not filtered:
        return False
    return all(
        int(candidate.via_pred) == _SUB7FFD_GROUP_HOIST_PRED
        and int(candidate.target_entry) == _SUB7FFD_GROUP_HOIST_TARGET
        and int(candidate.edge.source_anchor.block_serial) == _SUB7FFD_GROUP_HOIST_PRED
        and int(candidate.edge.source_anchor.branch_arm or 0) == 1
        for candidate in filtered
    )


def _maybe_build_sub7ffd_poll_corridor_modifications(
    *,
    result: SharedGroupExecutionResult,
    flow_graph,
) -> tuple[object, ...]:
    if (
        result.emission_mode != "deferred_corridor_clone"
        or int(result.shared_block) != _SUB7FFD_POLL_SUFFIX_SHARED_BLOCK
    ):
        return ()

    shared_block_snapshot = flow_graph.get_block(int(result.shared_block))
    if shared_block_snapshot is None or not getattr(shared_block_snapshot, "succs", ()):
        return ()
    old_target = int(shared_block_snapshot.succs[0])

    base_target = None
    corridor_candidate = None
    for candidate in result.accepted_candidates:
        via_pred = getattr(candidate, "via_pred", None)
        target_entry = getattr(candidate, "target_entry", None)
        if via_pred is None or target_entry is None:
            continue
        if (
            int(via_pred) == _SUB7FFD_POLL_SUFFIX_CLONE_SOURCE
            and int(target_entry) == _SUB7FFD_POLL_SUFFIX_CLONE_TARGET
        ):
            corridor_candidate = candidate
        elif int(via_pred) != _SUB7FFD_POLL_SUFFIX_CLONE_SOURCE:
            base_target = int(target_entry)

    if corridor_candidate is None or base_target is None:
        return ()

    ordered_path = tuple(
        int(serial) for serial in getattr(corridor_candidate.edge, "ordered_path", ())
    )
    try:
        corridor_index = ordered_path.index(_SUB7FFD_POLL_SUFFIX_CLONE_SOURCE)
    except ValueError:
        return ()
    if corridor_index == 0:
        return ()
    outer_via_pred = int(ordered_path[corridor_index - 1])

    logger.info(
        "RECON EXEC: materializing deferred sub7ffd poll corridor shared=%d old_target=%d base_target=%d outer_via_pred=%d path=%s",
        int(result.shared_block),
        old_target,
        int(base_target),
        int(outer_via_pred),
        ordered_path,
    )
    return (
        RedirectGoto(
            from_serial=int(result.shared_block),
            old_target=int(old_target),
            new_target=int(base_target),
        ),
        EdgeRedirectViaPredSplit(
            src_block=_SUB7FFD_POLL_SUFFIX_CLONE_SOURCE,
            old_target=int(result.shared_block),
            new_target=_SUB7FFD_POLL_SUFFIX_CLONE_TARGET,
            via_pred=int(outer_via_pred),
            clone_until=int(result.shared_block),
        ),
    )


def _collect_accepted_shared_group_candidates(
    *,
    candidates: list,
    per_pred_targets: tuple[tuple[int, int], ...],
) -> tuple[object, ...]:
    accepted: list[object] = []
    for pred, target in per_pred_targets:
        pred_int = int(pred)
        target_int = int(target)
        accepted.extend(
            candidate
            for candidate in candidates
            if getattr(candidate, "via_pred", None) is not None
            and int(candidate.via_pred) == pred_int
            and int(candidate.target_entry) == target_int
        )
    return tuple(accepted)


def _collect_paired_conditional_arm_groups(
    *,
    candidates: list,
    flow_graph,
) -> tuple[tuple[_PairedConditionalArmGroup, ...], tuple[object, ...]]:
    get_block = getattr(flow_graph, "get_block", None)
    if get_block is None:
        return (), tuple(candidates)

    grouped: defaultdict[tuple[int, int | None], list] = defaultdict(list)
    for candidate in candidates:
        source_state = getattr(getattr(candidate.edge, "source_key", None), "state_const", None)
        grouped[
            (
                int(candidate.horizon_block),
                (
                    int(source_state) & 0xFFFFFFFF
                    if source_state is not None
                    else None
                ),
            )
        ].append(candidate)

    paired_groups: list[_PairedConditionalArmGroup] = []
    leftovers: list[object] = []
    for (horizon_block, _source_state), group in grouped.items():
        horizon_snapshot = get_block(int(horizon_block))
        if horizon_snapshot is None or int(getattr(horizon_snapshot, "nsucc", 0)) != 2:
            leftovers.extend(group)
            continue
        horizon_succs = tuple(int(succ) for succ in getattr(horizon_snapshot, "succs", ()))
        if len(horizon_succs) != 2:
            leftovers.extend(group)
            continue

        by_arm: defaultdict[int, list] = defaultdict(list)
        for candidate in group:
            branch_arm = getattr(getattr(candidate.edge, "source_anchor", None), "branch_arm", None)
            if branch_arm not in (0, 1):
                by_arm.clear()
                break
            by_arm[int(branch_arm)].append(candidate)
        if set(by_arm) != {0, 1}:
            leftovers.extend(group)
            continue

        arm_targets: dict[int, int] = {}
        target_by_old_target: dict[int, int] = {}
        arm_candidates: list[object] = []
        arm_mismatch = False
        for arm in (0, 1):
            arm_group = by_arm[arm]
            targets = {int(candidate.target_entry) for candidate in arm_group}
            if len(targets) != 1:
                arm_mismatch = True
                break
            arm_targets[arm] = next(iter(targets))
            arm_candidates.extend(arm_group)
            for candidate in arm_group:
                old_target = _resolve_candidate_horizon_old_target(
                    candidate=candidate,
                    horizon_block=int(horizon_block),
                    horizon_succs=horizon_succs,
                )
                if old_target is None:
                    arm_mismatch = True
                    break
                target_by_old_target[int(old_target)] = int(candidate.target_entry)
            if arm_mismatch:
                break
        if arm_mismatch or arm_targets[0] == arm_targets[1]:
            leftovers.extend(group)
            continue
        if any(int(succ) not in target_by_old_target for succ in horizon_succs):
            leftovers.extend(group)
            continue

        fallthrough_target = int(target_by_old_target[int(horizon_succs[0])])
        conditional_target = int(target_by_old_target[int(horizon_succs[1])])

        forced_rewrite_horizon = all(
            str(getattr(candidate, "conditional_group_policy", "auto"))
            == "rewrite_horizon"
            for candidate in arm_candidates
        )
        if forced_rewrite_horizon:
            paired_groups.append(
                _PairedConditionalArmGroup(
                    horizon_block=int(horizon_block),
                    source_block=int(horizon_block),
                    fallthrough_target=int(fallthrough_target),
                    conditional_target=int(conditional_target),
                    emission_kind="rewrite_horizon_conditional",
                    candidates=tuple(arm_candidates),
                )
            )
            continue

        if all(
            int(getattr(getattr(candidate.edge, "source_anchor", None), "block_serial", -1))
            == int(horizon_block)
            for candidate in arm_candidates
        ):
            if int(horizon_succs[0]) == int(fallthrough_target):
                paired_groups.append(
                    _PairedConditionalArmGroup(
                        horizon_block=int(horizon_block),
                        source_block=int(horizon_block),
                        fallthrough_target=int(fallthrough_target),
                        conditional_target=int(conditional_target),
                        emission_kind="rewrite_horizon_conditional",
                        candidates=tuple(arm_candidates),
                    )
                )
                continue

            preds = tuple(int(pred) for pred in getattr(horizon_snapshot, "preds", ()))
            if len(preds) != 1:
                leftovers.extend(group)
                continue
            source_block = int(preds[0])
            source_snapshot = get_block(int(source_block))
            if source_snapshot is None:
                leftovers.extend(group)
                continue
            source_nsucc = int(getattr(source_snapshot, "nsucc", 0))
            emission_kind: str | None = None
            if source_nsucc == 1:
                emission_kind = "create_conditional_redirect"
            elif source_nsucc == 2:
                source_succs = tuple(int(succ) for succ in getattr(source_snapshot, "succs", ()))
                if len(source_succs) == 2 and int(source_succs[1]) == int(horizon_block):
                    emission_kind = "duplicate_conditional_block"
            if emission_kind is None:
                leftovers.extend(group)
                continue

            paired_groups.append(
                _PairedConditionalArmGroup(
                    horizon_block=int(horizon_block),
                    source_block=int(source_block),
                    fallthrough_target=int(fallthrough_target),
                    conditional_target=int(conditional_target),
                    emission_kind=str(emission_kind),
                    candidates=tuple(arm_candidates),
                )
            )
            continue

        preds = tuple(int(pred) for pred in getattr(horizon_snapshot, "preds", ()))
        if len(preds) != 1:
            leftovers.extend(group)
            continue
        source_block = int(preds[0])
        source_snapshot = get_block(int(source_block))
        if source_snapshot is None:
            leftovers.extend(group)
            continue
        source_nsucc = int(getattr(source_snapshot, "nsucc", 0))
        emission_kind: str | None = None
        if source_nsucc == 1:
            emission_kind = "create_conditional_redirect"
        elif source_nsucc == 2:
            succs = tuple(int(succ) for succ in getattr(source_snapshot, "succs", ()))
            if len(succs) == 2 and int(succs[1]) == int(horizon_block):
                emission_kind = "duplicate_conditional_block"
        if emission_kind is None:
            leftovers.extend(group)
            continue

        paired_groups.append(
            _PairedConditionalArmGroup(
                horizon_block=int(horizon_block),
                source_block=int(source_block),
                fallthrough_target=int(fallthrough_target),
                conditional_target=int(conditional_target),
                emission_kind=str(emission_kind),
                candidates=tuple(arm_candidates),
            )
        )
    return tuple(paired_groups), tuple(leftovers)


def execute_shared_group_reconstruction(
    *,
    shared_block: int,
    candidates: list,
    flow_graph,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    force_clone: bool = False,
    allow_divergent_per_pred_redirect: bool = False,
    mba=None,
) -> SharedGroupExecutionResult:
    if _should_hoist_sub7ffd_shared_group(int(shared_block), candidates):
        modification = RedirectBranch(
            from_serial=int(_SUB7FFD_GROUP_HOIST_PRED),
            old_target=int(shared_block),
            new_target=int(_SUB7FFD_GROUP_HOIST_TARGET),
        )
        modifications.append(modification)
        owned_blocks.add(int(_SUB7FFD_GROUP_HOIST_PRED))
        owned_edges.add((int(_SUB7FFD_GROUP_HOIST_PRED), int(_SUB7FFD_GROUP_HOIST_TARGET)))
        per_pred_targets = (
            (int(_SUB7FFD_GROUP_HOIST_PRED), int(_SUB7FFD_GROUP_HOIST_TARGET)),
        )
        return SharedGroupExecutionResult(
            shared_block=int(shared_block),
            accepted_candidates=_collect_accepted_shared_group_candidates(
                candidates=candidates,
                per_pred_targets=per_pred_targets,
            ),
            rejected_candidates=(),
            rejection_reason=None,
            emission_mode="source_arm_redirect",
            modifications=(modification,),
            per_pred_targets=per_pred_targets,
        )

    ordered_input_candidates = tuple(
        SharedGroupEmissionCandidate(
            via_pred=int(candidate.via_pred),
            target_entry=int(candidate.target_entry),
        )
        for candidate in candidates
        if candidate.via_pred is not None
    )
    if not ordered_input_candidates:
        return SharedGroupExecutionResult(
            shared_block=int(shared_block),
            accepted_candidates=(),
            rejected_candidates=(),
            rejection_reason=None,
        )

    if mba is None:
        # Surfaced explicitly so we can audit which call paths bypass the
        # loop-carried induction guards.  A silent skip here is what
        # masked the original cascade -- never let the absence of mba
        # happen quietly.
        logger.debug(
            "RECON_SHARED_GROUP_INDUCTION_GUARD_SKIPPED shared=blk[%d] "
            "reason=mba_unavailable via_preds=%s",
            int(shared_block),
            tuple(int(c.via_pred) for c in ordered_input_candidates),
        )
    else:
        # Guard 1 (writeback tail): if the shared_block is itself the
        # commit point of a loop-carried counter advance, redirecting
        # any predecessor away from it leaves the writeback unreachable
        # and IDA's DCE drops the counter update -- non-progressing
        # do-while.  Reject the whole emission for this shared_block.
        writeback_diag: LoopCounterWritebackDiagnostic | None = (
            detect_loop_counter_writeback_tail(mba, int(shared_block))
        )
        if writeback_diag is not None:
            logger.info(
                "RECON_SHARED_GROUP_REJECTED_LOOP_COUNTER_WRITEBACK_TAIL "
                "shared=blk[%d] tail_block=blk[%d] counter_stkoff=0x%x "
                "bound_stkoff=0x%x loop_test_ea=0x%x advance_ea=0x%x "
                "via_preds=%s",
                int(shared_block),
                writeback_diag.tail_block_serial,
                writeback_diag.counter_stkoff,
                writeback_diag.bound_stkoff,
                writeback_diag.loop_test_ea,
                writeback_diag.advance_ea,
                tuple(int(c.via_pred) for c in ordered_input_candidates),
            )
            return SharedGroupExecutionResult(
                shared_block=int(shared_block),
                accepted_candidates=(),
                rejected_candidates=tuple(
                    candidate for candidate in candidates if candidate.via_pred is not None
                ),
                rejection_reason="loop_counter_writeback_tail",
            )

        # Guard 2 (bound writer): if any via_pred is the unique
        # constant-mask writer for a loop bound, cloning the
        # shared_block via DuplicateAndRedirect routes the writer
        # through a fresh predecessor topology and IDA store-forwards
        # the writer into the test, erasing the counter side.
        bound_writer_match: tuple[int, LoopBoundWriterDiagnostic] | None = None
        for candidate in ordered_input_candidates:
            diag = detect_loop_bound_writer_redirect(mba, int(candidate.via_pred))
            if diag is not None:
                bound_writer_match = (int(candidate.via_pred), diag)
                break
        if bound_writer_match is not None:
            via_pred_serial, bw_diag = bound_writer_match
            logger.info(
                "RECON_SHARED_GROUP_REJECTED_BOUND_WRITER shared=blk[%d] "
                "via_pred=blk[%d] bound_stkoff=0x%x bound_writer_ea=0x%x "
                "loop_test_ea=0x%x counter_stkoff=0x%x",
                int(shared_block),
                via_pred_serial,
                bw_diag.bound_stkoff,
                bw_diag.bound_writer_ea,
                bw_diag.loop_test_ea,
                bw_diag.counter_stkoff,
            )
            return SharedGroupExecutionResult(
                shared_block=int(shared_block),
                accepted_candidates=(),
                rejected_candidates=tuple(
                    candidate for candidate in candidates if candidate.via_pred is not None
                ),
                rejection_reason="loop_bound_writer_guard",
            )

    shared_plan = plan_shared_group_reconstruction_modifications(
        flow_graph=flow_graph,
        shared_block=int(shared_block),
        ordered_path=tuple(int(serial) for serial in candidates[0].edge.ordered_path),
        shared_candidates=ordered_input_candidates,
        force_clone=bool(force_clone),
        allow_divergent_per_pred_redirect=bool(allow_divergent_per_pred_redirect),
    )
    if not shared_plan.accepted:
        if poll_candidates := [
            candidate for candidate in candidates if _is_sub7ffd_poll_candidate(candidate)
        ]:
            logger.info(
                "RECON EXEC: poll-target shared-group reject shared=%d reason=%s candidates=%s",
                int(shared_block),
                shared_plan.rejection_reason,
                [
                    {
                        "src": int(candidate.edge.source_anchor.block_serial),
                        "horizon": int(candidate.horizon_block),
                        "target": int(candidate.target_entry),
                        "via_pred": (
                            int(candidate.via_pred)
                            if candidate.via_pred is not None
                            else None
                        ),
                        "path": tuple(int(serial) for serial in candidate.edge.ordered_path),
                    }
                    for candidate in poll_candidates
                ],
            )
        return SharedGroupExecutionResult(
            shared_block=int(shared_block),
            accepted_candidates=(),
            rejected_candidates=tuple(
                candidate for candidate in candidates if candidate.via_pred is not None
            ),
            rejection_reason=shared_plan.rejection_reason,
        )

    accepted_candidates = _collect_accepted_shared_group_candidates(
        candidates=candidates,
        per_pred_targets=tuple(
            (int(pred), int(target))
            for pred, target in shared_plan.per_pred_targets
        ),
    )
    modifications.extend(shared_plan.modifications)
    owned_blocks.add(int(shared_block))
    for _, target_entry in shared_plan.per_pred_targets:
        owned_edges.add((int(shared_block), int(target_entry)))
    if poll_candidates := [
        candidate for candidate in candidates if _is_sub7ffd_poll_candidate(candidate)
    ]:
        logger.info(
            "RECON EXEC: poll-target shared-group accept shared=%d emission=%s per_pred_targets=%s candidates=%s",
            int(shared_block),
            shared_plan.emission_mode,
            tuple(
                (int(pred), int(target))
                for pred, target in shared_plan.per_pred_targets
            ),
            [
                {
                    "src": int(candidate.edge.source_anchor.block_serial),
                    "horizon": int(candidate.horizon_block),
                    "target": int(candidate.target_entry),
                    "via_pred": (
                        int(candidate.via_pred)
                        if candidate.via_pred is not None
                        else None
                    ),
                    "path": tuple(int(serial) for serial in candidate.edge.ordered_path),
                }
                for candidate in poll_candidates
            ],
        )
    return SharedGroupExecutionResult(
        shared_block=int(shared_block),
        accepted_candidates=accepted_candidates,
        rejected_candidates=(),
        rejection_reason=None,
        emission_mode=shared_plan.emission_mode,
        modifications=tuple(shared_plan.modifications),
        per_pred_targets=tuple(
            (int(pred), int(target))
            for pred, target in shared_plan.per_pred_targets
        ),
    )


def _project_primary_reconstruction_flow_graph(base_flow_graph, modifications: list):
    patch_plan = compile_patch_plan(modifications, base_flow_graph)
    return project_post_state(base_flow_graph, patch_plan)


def apply_shared_group_reachability_fallback(
    *,
    shared_group_results: tuple[SharedGroupExecutionResult, ...],
    shared_groups: dict[int, list],
    flow_graph,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    handler_entries: tuple[int, ...],
    compute_reachable_blocks,
    allow_divergent_per_pred_redirect: bool = True,
    force_clone_shared_blocks: frozenset[int] | set[int] = frozenset(),
    force_keep_per_pred_shared_blocks: frozenset[int] | set[int] = frozenset(),
    mba=None,
) -> tuple[SharedGroupExecutionResult, ...]:
    has_per_pred_shared_groups = any(
        result.emission_mode == "per_pred_redirect"
        for result in shared_group_results
    )
    if (
        not has_per_pred_shared_groups
        or not handler_entries
        or compute_reachable_blocks is None
    ):
        return shared_group_results

    try:
        watched_serials = (8, 11, 74, 76, 79, 81, 82, 83, 107, 111)
        forced_clone_block_set = {
            int(block_serial) for block_serial in force_clone_shared_blocks
        }
        forced_keep_block_set = {
            int(block_serial) for block_serial in force_keep_per_pred_shared_blocks
        }

        def _log_reachability_probe(projected_flow_graph, reachable_set: set[int], *, phase: str) -> None:
            logger.info(
                "RECON: reachability probe %s reachable=%s",
                phase,
                sorted(int(serial) for serial in reachable_set if int(serial) in watched_serials),
            )
            for serial in watched_serials:
                block = None
                if projected_flow_graph is not None:
                    get_block = getattr(projected_flow_graph, "get_block", None)
                    if callable(get_block):
                        block = get_block(int(serial))
                    elif hasattr(projected_flow_graph, "blocks"):
                        block = getattr(projected_flow_graph, "blocks", {}).get(int(serial))
                if block is None:
                    logger.info(
                        "RECON: reachability probe %s blk[%d]=missing reachable=%s",
                        phase,
                        int(serial),
                        int(serial) in reachable_set,
                    )
                    continue
                preds = tuple(int(pred) for pred in getattr(block, "preds", ()) or ())
                succs = tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
                logger.info(
                    "RECON: reachability probe %s blk[%d] reachable=%s preds=%s succs=%s",
                    phase,
                    int(serial),
                    int(serial) in reachable_set,
                    preds,
                    succs,
                )

        def _compute_unreachable_handlers(current_modifications: list[object], *, phase: str) -> set[int]:
            projected_flow_graph = _project_primary_reconstruction_flow_graph(
                flow_graph,
                current_modifications,
            )
            reachable_blocks = compute_reachable_blocks(
                projected_flow_graph,
                start_serial=getattr(projected_flow_graph, "entry_serial", None),
            )
            reachable_set = set(reachable_blocks or ())
            _log_reachability_probe(projected_flow_graph, reachable_set, phase=phase)
            return {
                int(entry)
                for entry in handler_entries
                if int(entry) not in reachable_set
            }
        unreachable_handlers = _compute_unreachable_handlers(
            modifications,
            phase="initial_with_all_shared_groups",
        )
        force_clone_results_present = any(
            int(result.shared_block) in forced_clone_block_set
            for result in shared_group_results
            if result.emission_mode == "per_pred_redirect"
        )
        if not unreachable_handlers and not force_clone_results_present:
            return shared_group_results

        if unreachable_handlers:
            logger.info(
                "RECON: per-pred redirect made %d handler entries unreachable: %s "
                "— retrying shared groups selectively",
                len(unreachable_handlers),
                sorted(unreachable_handlers)[:10],
            )
        else:
            logger.info(
                "RECON: retrying shared groups selectively for semantic late-clone blocks=%s",
                sorted(forced_clone_block_set),
            )

        per_pred_results = tuple(
            result
            for result in shared_group_results
            if result.emission_mode == "per_pred_redirect"
        )
        removed_mod_ids = {
            id(modification)
            for result in per_pred_results
            for modification in result.modifications
        }
        modifications[:] = [
            modification
            for modification in modifications
            if id(modification) not in removed_mod_ids
        ]
        for result in per_pred_results:
            owned_blocks.discard(int(result.shared_block))
            for _, target in result.per_pred_targets:
                owned_edges.discard((int(result.shared_block), int(target)))

        kept_results: dict[int, SharedGroupExecutionResult] = {}
        for result in per_pred_results:
            if int(result.shared_block) in forced_keep_block_set:
                modifications.extend(result.modifications)
                owned_blocks.add(int(result.shared_block))
                for _, target in result.per_pred_targets:
                    owned_edges.add((int(result.shared_block), int(target)))
                kept_results[int(result.shared_block)] = result
                logger.info(
                    "RECON: force-keeping per-pred redirect for experiment shared group %d",
                    int(result.shared_block),
                )
                continue
            if int(result.shared_block) in forced_clone_block_set:
                logger.info(
                    "RECON: forcing DuplicateAndRedirect for semantically protected shared group %d at late fallback",
                    int(result.shared_block),
                )
                kept_results[int(result.shared_block)] = execute_shared_group_reconstruction(
                    shared_block=int(result.shared_block),
                    candidates=shared_groups[int(result.shared_block)],
                    flow_graph=flow_graph,
                    modifications=modifications,
                    owned_blocks=owned_blocks,
                    owned_edges=owned_edges,
                    force_clone=True,
                    allow_divergent_per_pred_redirect=bool(
                        allow_divergent_per_pred_redirect
                    ),
                    mba=mba,
                )
                continue
            trial_modifications = list(modifications)
            trial_modifications.extend(result.modifications)
            unreachable_handlers = _compute_unreachable_handlers(
                trial_modifications,
                phase=f"trial_shared_block_{int(result.shared_block)}",
            )
            if not unreachable_handlers:
                modifications.extend(result.modifications)
                owned_blocks.add(int(result.shared_block))
                for _, target in result.per_pred_targets:
                    owned_edges.add((int(result.shared_block), int(target)))
                kept_results[int(result.shared_block)] = result
                logger.info(
                    "RECON: keeping per-pred redirect for %d (all handlers still reachable)",
                    int(result.shared_block),
                )
                continue

            logger.info(
                "RECON: per-pred redirect for %d made handlers unreachable: %s "
                "— falling back to DuplicateAndRedirect for this shared group only",
                int(result.shared_block),
                sorted(unreachable_handlers)[:10],
            )
            kept_results[int(result.shared_block)] = execute_shared_group_reconstruction(
                shared_block=int(result.shared_block),
                candidates=shared_groups[int(result.shared_block)],
                flow_graph=flow_graph,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                force_clone=True,
                allow_divergent_per_pred_redirect=bool(
                    allow_divergent_per_pred_redirect
                ),
                mba=mba,
            )

        rebuilt_results: list[SharedGroupExecutionResult] = []
        for result in shared_group_results:
            if result.emission_mode != "per_pred_redirect":
                rebuilt_results.append(result)
                continue
            rebuilt_results.append(kept_results[int(result.shared_block)])
        return tuple(rebuilt_results)
    except Exception:
        logger.debug(
            "Projected reachability check failed (non-critical)",
            exc_info=True,
        )
        return shared_group_results


def execute_primary_reconstruction_modifications(
    *,
    raw_candidates: list,
    flow_graph,
    node_by_key,
    dispatcher_serial: int,
    modifications: list,
    owned_blocks: set[int],
    owned_edges: set[tuple[int, int]],
    force_clone_shared_blocks: frozenset[int] = frozenset(),
    allow_divergent_shared_group_redirects: bool = True,
    direct_redirect_veto=None,
    conditional_redirect_veto=None,
    mba=None,
) -> PrimaryReconstructionExecutionResult:
    direct_groups: defaultdict[int, list] = defaultdict(list)
    shared_groups: defaultdict[int, list] = defaultdict(list)
    raw_conditional_arm_candidates: list = []
    for candidate in raw_candidates:
        if candidate.emission_mode == "conditional_arm":
            raw_conditional_arm_candidates.append(candidate)
        elif candidate.emission_mode == "direct":
            direct_groups[int(candidate.horizon_block)].append(candidate)
        else:
            assert candidate.first_shared_block is not None
            shared_groups[int(candidate.first_shared_block)].append(candidate)

    conditional_results: list[ConditionalArmExecutionResult] = []
    paired_conditional_groups, conditional_arm_candidates = _collect_paired_conditional_arm_groups(
        candidates=raw_conditional_arm_candidates,
        flow_graph=flow_graph,
    )
    for group in paired_conditional_groups:
        if group.emission_kind == "rewrite_horizon_conditional":
            horizon_snapshot = flow_graph.get_block(int(group.horizon_block))
            succs = tuple(
                int(succ) for succ in getattr(horizon_snapshot, "succs", ())
            ) if horizon_snapshot is not None else ()
            if len(succs) != 2:
                continue
            emitted_old_targets: set[int] = set()
            accepted_candidates: list[object] = []
            for candidate in group.candidates:
                old_target = _resolve_candidate_horizon_old_target(
                    candidate=candidate,
                    horizon_block=int(group.horizon_block),
                    horizon_succs=succs,
                )
                if old_target is None or old_target in emitted_old_targets:
                    continue
                emitted_old_targets.add(int(old_target))
                if int(old_target) == int(candidate.target_entry):
                    accepted_candidates.append(candidate)
                    continue
                if int(candidate.target_entry) == int(group.horizon_block):
                    continue
                modification = RedirectBranch(
                    from_serial=int(group.horizon_block),
                    old_target=int(old_target),
                    new_target=int(candidate.target_entry),
                )
                veto_reason = None
                if callable(conditional_redirect_veto):
                    try:
                        veto_reason = conditional_redirect_veto(
                            modification=modification,
                            candidate=candidate,
                            source_block=int(group.horizon_block),
                            old_target=int(old_target),
                            target_block=int(candidate.target_entry),
                        )
                    except Exception:
                        logger.debug(
                            "RECON EXEC: conditional redirect veto callback raised",
                            exc_info=True,
                        )
                        veto_reason = None
                if veto_reason:
                    logger.warning(
                        "RECON EXEC: conditional redirect vetoed blk[%d] -> blk[%d]"
                        " old=blk[%d] reason=%s",
                        int(group.horizon_block),
                        int(candidate.target_entry),
                        int(old_target),
                        veto_reason,
                    )
                    continue
                modifications.append(modification)
                accepted_candidates.append(candidate)
            if not accepted_candidates:
                continue
            owned_blocks.add(int(group.source_block))
            for candidate in accepted_candidates:
                owned_edges.add((int(group.source_block), int(candidate.target_entry)))
            modifications.extend(
                _collect_zero_state_write_modifications(
                    tuple(accepted_candidates),
                    existing_modifications=modifications,
                )
            )
            for candidate in accepted_candidates:
                conditional_results.append(
                    ConditionalArmExecutionResult(
                        candidate=candidate,
                        redirect_count=1,
                        passthrough_count=0,
                    )
                )
            continue
        elif group.emission_kind == "create_conditional_redirect":
            modifications.append(
                CreateConditionalRedirect(
                    source_block=int(group.source_block),
                    ref_block=int(group.horizon_block),
                    conditional_target=int(group.conditional_target),
                    fallthrough_target=int(group.fallthrough_target),
                )
            )
        elif group.emission_kind == "duplicate_conditional_block":
            modifications.append(
                DuplicateBlock(
                    source_block=int(group.horizon_block),
                    target_block=None,
                    pred_serial=int(group.source_block),
                    patch_kind="reconstruction_paired_conditional",
                    conditional_target=int(group.conditional_target),
                    fallthrough_target=int(group.fallthrough_target),
                )
            )
            owned_blocks.add(int(group.horizon_block))
        else:
            continue
        owned_blocks.add(int(group.source_block))
        owned_edges.add((int(group.source_block), int(group.conditional_target)))
        owned_edges.add((int(group.source_block), int(group.fallthrough_target)))
        modifications.extend(
            _collect_zero_state_write_modifications(
                group.candidates,
                existing_modifications=modifications,
            )
        )
        for candidate in group.candidates:
            conditional_results.append(
                ConditionalArmExecutionResult(
                    candidate=candidate,
                    redirect_count=1,
                    passthrough_count=0,
                )
            )

    for candidate in conditional_arm_candidates:
        source_node = node_by_key.get(candidate.edge.source_key)
        pt_entry: int | None = None
        if source_node is not None and candidate.edge.source_key.state_const is not None:
            pt_entry = source_node.entry_anchor

        cond_plan = plan_conditional_arm_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(candidate.horizon_block),
            target_entry=int(candidate.target_entry),
            branch_arm=int(candidate.edge.source_anchor.branch_arm or 0),
            dispatcher_serial=dispatcher_serial,
            current_entry=pt_entry,
        )
        if not cond_plan.modifications:
            if _is_sub7ffd_poll_candidate(candidate):
                logger.info(
                    "RECON EXEC: poll-target conditional_arm reject src=%d horizon=%d target=%d reason=no_modifications path=%s",
                    int(candidate.edge.source_anchor.block_serial),
                    int(candidate.horizon_block),
                    int(candidate.target_entry),
                    tuple(int(serial) for serial in candidate.edge.ordered_path),
                )
            continue

        effective_cond_modifications: list[object] = []
        for modification in cond_plan.modifications:
            veto_reason = None
            if callable(conditional_redirect_veto):
                try:
                    veto_reason = conditional_redirect_veto(
                        modification=modification,
                        candidate=candidate,
                        source_block=getattr(modification, "from_serial", None),
                        old_target=getattr(modification, "old_target", None),
                        target_block=getattr(modification, "new_target", None),
                    )
                except Exception:
                    logger.debug(
                        "RECON EXEC: conditional redirect veto callback raised",
                        exc_info=True,
                    )
                    veto_reason = None
            if veto_reason:
                logger.warning(
                    "RECON EXEC: conditional redirect vetoed blk[%s] -> blk[%s]"
                    " old=blk[%s] reason=%s",
                    getattr(modification, "from_serial", "?"),
                    getattr(modification, "new_target", "?"),
                    getattr(modification, "old_target", "?"),
                    veto_reason,
                )
                continue
            effective_cond_modifications.append(modification)
        if not effective_cond_modifications:
            continue

        modifications.extend(effective_cond_modifications)
        owned_blocks.add(int(candidate.horizon_block))
        owned_edges.add((int(candidate.horizon_block), int(candidate.target_entry)))
        modifications.extend(
            _collect_zero_state_write_modifications(
                (candidate,),
                existing_modifications=modifications,
            )
        )

        pt_plan = plan_passthrough_reconstruction_modifications(
            flow_graph=flow_graph,
            ordered_path=tuple(int(serial) for serial in candidate.edge.ordered_path),
            horizon_block=int(candidate.horizon_block),
            dispatcher_serial=dispatcher_serial,
            current_state_entry=pt_entry,
        )
        modifications.extend(pt_plan.modifications)
        conditional_results.append(
            ConditionalArmExecutionResult(
                candidate=candidate,
                redirect_count=len(cond_plan.modifications),
                passthrough_count=len(pt_plan.modifications),
            )
        )
        if _is_sub7ffd_poll_candidate(candidate):
            logger.info(
                "RECON EXEC: poll-target conditional_arm accept src=%d horizon=%d target=%d redirects=%d passthrough=%d path=%s",
                int(candidate.edge.source_anchor.block_serial),
                int(candidate.horizon_block),
                int(candidate.target_entry),
                len(cond_plan.modifications),
                len(pt_plan.modifications),
                tuple(int(serial) for serial in candidate.edge.ordered_path),
            )

    direct_results: list[DirectExecutionResult] = []
    for horizon_block in sorted(direct_groups):
        group = direct_groups[horizon_block]
        targets = {candidate.target_entry for candidate in group}
        if len(targets) > 1:
            for candidate in group:
                if _is_sub7ffd_poll_candidate(candidate):
                    logger.info(
                        "RECON EXEC: poll-target direct reject src=%d horizon=%d target=%d reason=direct_conflict group_targets=%s path=%s",
                        int(candidate.edge.source_anchor.block_serial),
                        int(candidate.horizon_block),
                        int(candidate.target_entry),
                        tuple(sorted(int(target) for target in targets)),
                        tuple(int(serial) for serial in candidate.edge.ordered_path),
                    )
            direct_results.append(
                DirectExecutionResult(
                    accepted_candidate=None,
                    rejected_candidates=tuple(group),
                    rejection_reason="direct_conflict",
                )
            )
            continue

        direct_candidate = group[0]
        direct_plan = plan_direct_reconstruction_modifications(
            flow_graph=flow_graph,
            horizon_block=int(direct_candidate.horizon_block),
            target_entry=int(direct_candidate.target_entry),
            ordered_path=tuple(
                int(serial) for serial in direct_candidate.edge.ordered_path
            ),
        )
        if not direct_plan.accepted:
            if _is_sub7ffd_poll_candidate(direct_candidate):
                logger.info(
                    "RECON EXEC: poll-target direct reject src=%d horizon=%d target=%d reason=noop_or_missing_old_target path=%s",
                    int(direct_candidate.edge.source_anchor.block_serial),
                    int(direct_candidate.horizon_block),
                    int(direct_candidate.target_entry),
                    tuple(int(serial) for serial in direct_candidate.edge.ordered_path),
                )
            direct_results.append(
                DirectExecutionResult(
                    accepted_candidate=None,
                    rejected_candidates=(direct_candidate,),
                    rejection_reason="noop_or_missing_old_target",
                )
            )
            continue

        veto_reason: str | None = None
        replacement_modifications: tuple[object, ...] | None = None
        if direct_redirect_veto is not None:
            for modification in direct_plan.modifications:
                try:
                    veto_result = direct_redirect_veto(
                        modification,
                        direct_candidate,
                    )
                except Exception:
                    logger.debug(
                        "RECON EXEC: direct redirect veto callback raised",
                        exc_info=True,
                    )
                    veto_result = None
                if isinstance(veto_result, str) and veto_result:
                    veto_reason = veto_result
                    break
                if isinstance(veto_result, (tuple, list)) and veto_result:
                    replacement_modifications = tuple(veto_result)
                    break
                if veto_result:
                    veto_reason = str(veto_result)
                    break
        if veto_reason:
            if _is_sub7ffd_poll_candidate(direct_candidate):
                logger.info(
                    "RECON EXEC: poll-target direct reject src=%d horizon=%d target=%d reason=%s path=%s",
                    int(direct_candidate.edge.source_anchor.block_serial),
                    int(direct_candidate.horizon_block),
                    int(direct_candidate.target_entry),
                    veto_reason,
                    tuple(int(serial) for serial in direct_candidate.edge.ordered_path),
                )
            direct_results.append(
                DirectExecutionResult(
                    accepted_candidate=None,
                    rejected_candidates=(direct_candidate,),
                    rejection_reason=veto_reason,
                )
            )
            continue

        effective_direct_modifications = (
            replacement_modifications
            if replacement_modifications is not None
            else direct_plan.modifications
        )
        if replacement_modifications is not None:
            logger.info(
                "RECON EXEC: direct redirect replacement src=%d target=%d"
                " replacement_count=%d replacement_types=%s path=%s",
                int(direct_candidate.horizon_block),
                int(direct_candidate.target_entry),
                len(replacement_modifications),
                tuple(type(mod).__name__ for mod in replacement_modifications),
                tuple(int(serial) for serial in direct_candidate.edge.ordered_path),
            )
        modifications.extend(effective_direct_modifications)
        owned_blocks.add(int(direct_candidate.horizon_block))
        owned_edges.add(
            (int(direct_candidate.horizon_block), int(direct_candidate.target_entry))
        )
        modifications.extend(
            _collect_zero_state_write_modifications(
                (direct_candidate,),
                existing_modifications=modifications,
            )
        )

        passthrough_count = 0
        if _is_conditional_transition(direct_candidate):
            source_node = node_by_key.get(direct_candidate.edge.source_key)
            pt_entry_d: int | None = None
            if (
                source_node is not None
                and direct_candidate.edge.source_key.state_const is not None
            ):
                pt_entry_d = source_node.entry_anchor
            pt_plan_d = plan_passthrough_reconstruction_modifications(
                flow_graph=flow_graph,
                ordered_path=tuple(
                    int(serial) for serial in direct_candidate.edge.ordered_path
                ),
                horizon_block=int(direct_candidate.horizon_block),
                dispatcher_serial=dispatcher_serial,
                current_state_entry=pt_entry_d,
            )
            modifications.extend(pt_plan_d.modifications)
            passthrough_count = len(pt_plan_d.modifications)

        direct_results.append(
            DirectExecutionResult(
                accepted_candidate=direct_candidate,
                rejected_candidates=(),
                rejection_reason=None,
                passthrough_count=passthrough_count,
            )
        )
        if _is_sub7ffd_poll_candidate(direct_candidate):
            logger.info(
                "RECON EXEC: poll-target direct accept src=%d horizon=%d target=%d passthrough=%d path=%s",
                int(direct_candidate.edge.source_anchor.block_serial),
                int(direct_candidate.horizon_block),
                int(direct_candidate.target_entry),
                passthrough_count,
                tuple(int(serial) for serial in direct_candidate.edge.ordered_path),
            )

    shared_group_results: list[SharedGroupExecutionResult] = []
    for shared_block in sorted(shared_groups):
        poll_candidates = [
            candidate for candidate in shared_groups[shared_block]
            if _is_sub7ffd_poll_candidate(candidate)
        ]
        if poll_candidates:
            logger.info(
                "RECON EXEC: poll-target shared-group attempt shared=%d candidates=%s",
                int(shared_block),
                [
                    {
                        "src": int(candidate.edge.source_anchor.block_serial),
                        "horizon": int(candidate.horizon_block),
                        "target": int(candidate.target_entry),
                        "via_pred": (
                            int(candidate.via_pred)
                            if candidate.via_pred is not None
                            else None
                        ),
                        "path": tuple(int(serial) for serial in candidate.edge.ordered_path),
                    }
                    for candidate in poll_candidates
                ],
            )
        shared_result = execute_shared_group_reconstruction(
            shared_block=shared_block,
            candidates=shared_groups[shared_block],
            flow_graph=flow_graph,
            modifications=modifications,
            owned_blocks=owned_blocks,
            owned_edges=owned_edges,
            force_clone=bool(int(shared_block) in force_clone_shared_blocks),
            allow_divergent_per_pred_redirect=bool(
                allow_divergent_shared_group_redirects
            ),
            mba=mba,
        )
        zero_mods = _collect_zero_state_write_modifications(
            tuple(shared_result.accepted_candidates),
            existing_modifications=modifications,
        )
        modifications.extend(zero_mods)
        shared_group_results.append(
            SharedGroupExecutionResult(
                shared_block=shared_result.shared_block,
                accepted_candidates=shared_result.accepted_candidates,
                rejected_candidates=shared_result.rejected_candidates,
                rejection_reason=shared_result.rejection_reason,
                emission_mode=shared_result.emission_mode,
                modifications=tuple(shared_result.modifications) + zero_mods,
                per_pred_targets=shared_result.per_pred_targets,
            )
        )

    for shared_result in shared_group_results:
        deferred_modifications = _maybe_build_sub7ffd_poll_corridor_modifications(
            result=shared_result,
            flow_graph=flow_graph,
        )
        if not deferred_modifications:
            continue
        modifications.extend(deferred_modifications)
        owned_blocks.add(_SUB7FFD_POLL_SUFFIX_CLONE_SOURCE)
        owned_blocks.add(int(shared_result.shared_block))
        owned_edges.add(
            (_SUB7FFD_POLL_SUFFIX_CLONE_SOURCE, _SUB7FFD_POLL_SUFFIX_CLONE_TARGET)
        )
        owned_edges.add(
            (int(shared_result.shared_block), _SUB7FFD_POLL_SUFFIX_BASE_TARGET)
        )

    return PrimaryReconstructionExecutionResult(
        conditional_results=tuple(conditional_results),
        direct_results=tuple(direct_results),
        shared_group_results=tuple(shared_group_results),
    )


__all__ = [
    "ConditionalArmExecutionResult",
    "DirectExecutionResult",
    "PrimaryReconstructionExecutionResult",
    "SharedGroupExecutionResult",
    "apply_shared_group_reachability_fallback",
    "execute_primary_reconstruction_modifications",
    "execute_shared_group_reconstruction",
]
