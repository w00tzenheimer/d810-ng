"""Shared helpers and engine strategy wrapper for safe BadWhileLoop cleanup."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from d810.cfg.flowgraph import FlowGraph
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateAndRedirect,
    DuplicateReplayAndRedirect,
    GraphModification,
    InsertBlock,
    RedirectGoto,
)
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.cleanup_evidence import (
    CLEANUP_DUPLICATE_REPLAY_METADATA_KEY,
    CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY,
    CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY,
    CleanupDuplicateGroupReplayCandidate,
    CleanupPerPredReplay,
    CleanupSideEffectReplayCandidate,
    CleanupTrampolineIsolationCandidate,
    bad_while_loop_duplicate_candidate,
    bad_while_loop_duplicate_group_replay_candidate,
    bad_while_loop_side_effect_replay_candidate,
    bad_while_loop_trampoline_isolation_candidate,
    build_dispatcher_cleanup_modification,
    extract_duplicate_group_replay_candidates,
    extract_side_effect_replay_candidates,
    extract_trampoline_isolation_candidates,
    validate_dispatcher_cleanup_candidate,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.strategies.bad_while_loop_dependency_diagnostics import (
    BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY,
    BadWhileLoopDependencyDiagnostic,
    build_bad_while_loop_dependency_diagnostic,
    extract_bad_while_loop_dependency_diagnostics,
    serialize_bad_while_loop_dependency_diagnostics,
)

if TYPE_CHECKING:
    from d810.cfg.materialization_payload import CapturedBlockBody
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )


BAD_WHILE_LOOP_EDITS_METADATA_KEY = "bad_while_loop_edits"
BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY = "bad_while_loop_follow_up"

BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT = "duplicate_and_redirect"
BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT = "create_conditional_redirect"
BAD_WHILE_LOOP_INSERT_BLOCK = "insert_block"
BAD_WHILE_LOOP_UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class BadWhileLoopGotoRedirect:
    """Direct predecessor redirect around a resolved BadWhileLoop dispatcher."""

    dispatcher_entry: int
    from_serial: int
    new_target: int


@dataclass(frozen=True)
class BadWhileLoopGotoConversion:
    """Conversion of a conditional predecessor into a direct goto target."""

    dispatcher_entry: int
    block_serial: int
    goto_target: int


@dataclass(frozen=True)
class BadWhileLoopDuplicateRedirect:
    """Duplicate an immediate dispatcher predecessor per predecessor target."""

    dispatcher_entry: int
    source_serial: int
    per_pred_targets: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class BadWhileLoopConditionalDuplicate:
    """Clone a conditional exit block per predecessor with explicit targets."""

    dispatcher_entry: int
    source_serial: int
    pred_serial: int
    conditional_target: int
    fallthrough_target: int


@dataclass(frozen=True)
class BadWhileLoopConditionalRedirect:
    """Clone a dispatcher conditional case after a 1-way predecessor."""

    dispatcher_entry: int
    source_serial: int
    ref_block: int
    conditional_target: int
    fallthrough_target: int
    dispatcher_internal_serials: tuple[int, ...] = ()
    copied_side_effects_absent: bool = False


BadWhileLoopEdit = (
    BadWhileLoopGotoRedirect
    | BadWhileLoopGotoConversion
    | BadWhileLoopDuplicateRedirect
    | BadWhileLoopConditionalDuplicate
    | BadWhileLoopConditionalRedirect
)


@dataclass(frozen=True)
class BadWhileLoopFollowUp:
    """A skipped legacy BadWhileLoop path that still needs planning parity."""

    dispatcher_entry: int
    from_serial: int
    category: str
    reason: str
    target_serial: int | None = None
    fallthrough_target: int | None = None


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coerce_optional_int(value: object) -> int | None:
    if value is None:
        return None
    return _coerce_int(value)


def _coerce_int_tuple(value: object) -> tuple[int, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(
        item for raw_item in value if (item := _coerce_int(raw_item)) is not None
    )


def _coerce_bad_while_loop_edits(raw: object) -> tuple[BadWhileLoopEdit, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()

    edits: list[BadWhileLoopEdit] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue

        kind = item.get("kind")
        dispatcher_entry = _coerce_int(item.get("dispatcher_entry"))
        if dispatcher_entry is None:
            continue

        if kind == "redirect_goto":
            from_serial = _coerce_int(item.get("from_serial"))
            new_target = _coerce_int(item.get("new_target"))
            if from_serial is None or new_target is None:
                continue
            edits.append(
                BadWhileLoopGotoRedirect(
                    dispatcher_entry=dispatcher_entry,
                    from_serial=from_serial,
                    new_target=new_target,
                )
            )
        elif kind == "convert_to_goto":
            block_serial = _coerce_int(item.get("block_serial"))
            goto_target = _coerce_int(item.get("goto_target"))
            if block_serial is None or goto_target is None:
                continue
            edits.append(
                BadWhileLoopGotoConversion(
                    dispatcher_entry=dispatcher_entry,
                    block_serial=block_serial,
                    goto_target=goto_target,
                )
            )
        elif kind == "duplicate_and_redirect":
            source_serial = _coerce_int(item.get("source_serial"))
            raw_per_pred_targets = item.get("per_pred_targets")
            if source_serial is None or not isinstance(raw_per_pred_targets, Sequence):
                continue

            per_pred_targets: list[tuple[int, int]] = []
            for pair in raw_per_pred_targets:
                if not isinstance(pair, Mapping):
                    continue
                pred_serial = _coerce_int(pair.get("pred_serial"))
                target_serial = _coerce_int(pair.get("target_serial"))
                if pred_serial is None or target_serial is None:
                    continue
                per_pred_targets.append((pred_serial, target_serial))

            if len(per_pred_targets) < 2:
                continue

            edits.append(
                BadWhileLoopDuplicateRedirect(
                    dispatcher_entry=dispatcher_entry,
                    source_serial=source_serial,
                    per_pred_targets=tuple(per_pred_targets),
                )
            )
        elif kind == "duplicate_conditional_redirect":
            source_serial = _coerce_int(item.get("source_serial"))
            pred_serial = _coerce_int(item.get("pred_serial"))
            conditional_target = _coerce_int(item.get("conditional_target"))
            fallthrough_target = _coerce_int(item.get("fallthrough_target"))
            if (
                source_serial is None
                or pred_serial is None
                or conditional_target is None
                or fallthrough_target is None
            ):
                continue
            edits.append(
                BadWhileLoopConditionalDuplicate(
                    dispatcher_entry=dispatcher_entry,
                    source_serial=source_serial,
                    pred_serial=pred_serial,
                    conditional_target=conditional_target,
                    fallthrough_target=fallthrough_target,
                )
            )
        elif kind == "create_conditional_redirect":
            source_serial = _coerce_int(item.get("source_serial"))
            ref_block = _coerce_int(item.get("ref_block"))
            conditional_target = _coerce_int(item.get("conditional_target"))
            fallthrough_target = _coerce_int(item.get("fallthrough_target"))
            if (
                source_serial is None
                or ref_block is None
                or conditional_target is None
                or fallthrough_target is None
            ):
                continue
            edits.append(
                BadWhileLoopConditionalRedirect(
                    dispatcher_entry=dispatcher_entry,
                    source_serial=source_serial,
                    ref_block=ref_block,
                    conditional_target=conditional_target,
                    fallthrough_target=fallthrough_target,
                    dispatcher_internal_serials=_coerce_int_tuple(
                        item.get("dispatcher_internal_serials", ()),
                    ),
                    copied_side_effects_absent=(
                        item.get("copied_side_effects_absent") is True
                    ),
                )
            )
    return tuple(edits)


def _coerce_bad_while_loop_follow_up(raw: object) -> tuple[BadWhileLoopFollowUp, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()

    categories = {
        BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
        BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT,
        BAD_WHILE_LOOP_INSERT_BLOCK,
        BAD_WHILE_LOOP_UNSUPPORTED,
    }
    follow_up: list[BadWhileLoopFollowUp] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue

        dispatcher_entry = _coerce_int(item.get("dispatcher_entry"))
        from_serial = _coerce_int(item.get("from_serial"))
        category = item.get("category")
        reason = item.get("reason")
        target_serial = _coerce_optional_int(item.get("target_serial"))
        fallthrough_target = _coerce_optional_int(item.get("fallthrough_target"))

        if (
            dispatcher_entry is None
            or from_serial is None
            or not isinstance(category, str)
            or category not in categories
            or not isinstance(reason, str)
            or not reason
        ):
            continue

        follow_up.append(
            BadWhileLoopFollowUp(
                dispatcher_entry=dispatcher_entry,
                from_serial=from_serial,
                category=category,
                reason=reason,
                target_serial=target_serial,
                fallthrough_target=fallthrough_target,
            )
        )

    return tuple(follow_up)


def _is_valid_bad_while_loop_edit(
    cfg: FlowGraph,
    edit: BadWhileLoopEdit,
) -> bool:
    dispatcher_entry = cfg.blocks.get(edit.dispatcher_entry)
    if dispatcher_entry is None:
        return False

    match edit:
        case BadWhileLoopGotoRedirect(from_serial=src, new_target=dst):
            src_block = cfg.blocks.get(src)
            dst_block = cfg.blocks.get(dst)
            if src_block is None or dst_block is None:
                return False
            if src == dst:
                return False
            if src_block.nsucc != 1:
                return False
            if src_block.succs[0] != edit.dispatcher_entry:
                return False
            return True
        case BadWhileLoopGotoConversion(block_serial=src, goto_target=dst):
            src_block = cfg.blocks.get(src)
            dst_block = cfg.blocks.get(dst)
            if src_block is None or dst_block is None:
                return False
            if src == dst:
                return False
            if src_block.nsucc != 2:
                return False
            if edit.dispatcher_entry not in src_block.succs:
                return False
            return True
        case BadWhileLoopDuplicateRedirect():
            candidate = bad_while_loop_duplicate_candidate(edit)
            return candidate is not None and validate_dispatcher_cleanup_candidate(
                cfg,
                candidate,
            )
        case BadWhileLoopConditionalDuplicate(
            source_serial=src,
            pred_serial=pred_serial,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
        ):
            src_block = cfg.blocks.get(src)
            pred_block = cfg.blocks.get(pred_serial)
            conditional_block = cfg.blocks.get(conditional_target)
            fallthrough_block = cfg.blocks.get(fallthrough_target)
            if (
                src_block is None
                or pred_block is None
                or conditional_block is None
                or fallthrough_block is None
            ):
                return False
            if src_block.nsucc != 2:
                return False
            if edit.dispatcher_entry not in src_block.succs:
                return False
            if pred_block.nsucc != 1:
                return False
            if pred_block.succs[0] != src:
                return False
            if conditional_target == fallthrough_target:
                return False
            if conditional_target == src or fallthrough_target == src:
                return False
            return True
        case BadWhileLoopConditionalRedirect(
            source_serial=src,
            ref_block=ref,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
        ):
            src_block = cfg.blocks.get(src)
            ref_block = cfg.blocks.get(ref)
            conditional_block = cfg.blocks.get(conditional_target)
            fallthrough_block = cfg.blocks.get(fallthrough_target)
            if (
                src_block is None
                or ref_block is None
                or conditional_block is None
                or fallthrough_block is None
            ):
                return False
            if src_block.nsucc != 1:
                return False
            if src_block.succs[0] != edit.dispatcher_entry:
                return False
            if ref_block.nsucc != 2:
                return False
            if {
                int(conditional_target),
                int(fallthrough_target),
            } != set(ref_block.succs):
                return False
            if conditional_target == fallthrough_target:
                return False
            if src in (ref, conditional_target, fallthrough_target):
                return False
            return True
    return False


def _normalize_bad_while_loop_edits(
    cfg: FlowGraph,
    raw: object,
) -> tuple[BadWhileLoopEdit, ...]:
    edits_by_key: dict[tuple[object, ...], BadWhileLoopEdit] = {}
    conflicts: set[tuple[object, ...]] = set()

    for edit in _coerce_bad_while_loop_edits(raw):
        if not _is_valid_bad_while_loop_edit(cfg, edit):
            continue

        match edit:
            case BadWhileLoopGotoRedirect(from_serial=src):
                key = ("redirect_goto", src)
                target_value = edit.new_target
            case BadWhileLoopGotoConversion(block_serial=src):
                key = ("convert_to_goto", src)
                target_value = edit.goto_target
            case BadWhileLoopDuplicateRedirect(source_serial=src):
                key = ("duplicate_and_redirect", src)
                target_value = edit.per_pred_targets
            case BadWhileLoopConditionalDuplicate(source_serial=src, pred_serial=pred):
                key = ("duplicate_conditional_redirect", src, pred)
                target_value = (edit.conditional_target, edit.fallthrough_target)
            case BadWhileLoopConditionalRedirect(source_serial=src):
                key = ("create_conditional_redirect", src)
                target_value = (
                    edit.ref_block,
                    edit.conditional_target,
                    edit.fallthrough_target,
                )

        previous = edits_by_key.get(key)
        if previous is None:
            edits_by_key[key] = edit
            continue

        previous_target = (
            previous.new_target
            if isinstance(previous, BadWhileLoopGotoRedirect)
            else (
                previous.goto_target
                if isinstance(previous, BadWhileLoopGotoConversion)
                else (
                    previous.per_pred_targets
                    if isinstance(previous, BadWhileLoopDuplicateRedirect)
                    else (
                        (
                            previous.conditional_target,
                            previous.fallthrough_target,
                        )
                        if isinstance(previous, BadWhileLoopConditionalDuplicate)
                        else (
                            previous.ref_block,
                            previous.conditional_target,
                            previous.fallthrough_target,
                        )
                    )
                )
            )
        )
        if previous_target != target_value:
            conflicts.add(key)

    for key in conflicts:
        edits_by_key.pop(key, None)

    return tuple(edits_by_key.values())


def _serialize_bad_while_loop_edits(
    edits: Sequence[BadWhileLoopEdit],
) -> list[dict[str, object]]:
    serialized: list[dict[str, object]] = []
    for edit in edits:
        if isinstance(edit, BadWhileLoopGotoRedirect):
            serialized.append(
                {
                    "kind": "redirect_goto",
                    "dispatcher_entry": edit.dispatcher_entry,
                    "from_serial": edit.from_serial,
                    "new_target": edit.new_target,
                }
            )
        elif isinstance(edit, BadWhileLoopGotoConversion):
            serialized.append(
                {
                    "kind": "convert_to_goto",
                    "dispatcher_entry": edit.dispatcher_entry,
                    "block_serial": edit.block_serial,
                    "goto_target": edit.goto_target,
                }
            )
        elif isinstance(edit, BadWhileLoopDuplicateRedirect):
            serialized.append(
                {
                    "kind": "duplicate_and_redirect",
                    "dispatcher_entry": edit.dispatcher_entry,
                    "source_serial": edit.source_serial,
                    "per_pred_targets": [
                        {
                            "pred_serial": pred_serial,
                            "target_serial": target_serial,
                        }
                        for pred_serial, target_serial in edit.per_pred_targets
                    ],
                }
            )
        elif isinstance(edit, BadWhileLoopConditionalDuplicate):
            serialized.append(
                {
                    "kind": "duplicate_conditional_redirect",
                    "dispatcher_entry": edit.dispatcher_entry,
                    "source_serial": edit.source_serial,
                    "pred_serial": edit.pred_serial,
                    "conditional_target": edit.conditional_target,
                    "fallthrough_target": edit.fallthrough_target,
                }
            )
        elif isinstance(edit, BadWhileLoopConditionalRedirect):
            serialized.append(
                {
                    "kind": "create_conditional_redirect",
                    "dispatcher_entry": edit.dispatcher_entry,
                    "source_serial": edit.source_serial,
                    "ref_block": edit.ref_block,
                    "conditional_target": edit.conditional_target,
                    "fallthrough_target": edit.fallthrough_target,
                    "dispatcher_internal_serials": list(
                        edit.dispatcher_internal_serials,
                    ),
                    "copied_side_effects_absent": edit.copied_side_effects_absent,
                }
            )
        else:
            raise TypeError(f"Unsupported BadWhileLoop edit: {type(edit).__name__}")
    return serialized


def _serialize_bad_while_loop_follow_up(
    follow_up: Sequence[BadWhileLoopFollowUp],
) -> list[dict[str, int | str | None]]:
    serialized: list[dict[str, int | str | None]] = []
    for item in follow_up:
        serialized.append(
            {
                "dispatcher_entry": item.dispatcher_entry,
                "from_serial": item.from_serial,
                "category": item.category,
                "reason": item.reason,
                "target_serial": item.target_serial,
                "fallthrough_target": item.fallthrough_target,
            }
        )
    return serialized


def serialize_bad_while_loop_edits(
    edits: Sequence[BadWhileLoopEdit],
) -> list[dict[str, object]]:
    """Serialize safe BadWhileLoop edits into FlowGraph metadata."""
    return _serialize_bad_while_loop_edits(edits)


def serialize_bad_while_loop_follow_up(
    follow_up: Sequence[BadWhileLoopFollowUp],
) -> list[dict[str, int | str | None]]:
    """Serialize skipped legacy BadWhileLoop paths into FlowGraph metadata."""
    return _serialize_bad_while_loop_follow_up(follow_up)


def extract_bad_while_loop_edits(
    flow_graph: FlowGraph | None,
) -> tuple[BadWhileLoopEdit, ...]:
    """Read validated BadWhileLoop edits from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    return _normalize_bad_while_loop_edits(
        flow_graph,
        flow_graph.metadata.get(BAD_WHILE_LOOP_EDITS_METADATA_KEY),
    )


def extract_bad_while_loop_follow_up(
    flow_graph: FlowGraph | None,
) -> tuple[BadWhileLoopFollowUp, ...]:
    """Read classified BadWhileLoop follow-up paths from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    return _coerce_bad_while_loop_follow_up(
        flow_graph.metadata.get(BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY),
    )


def build_bad_while_loop_modifications(
    edits: Sequence[BadWhileLoopEdit],
) -> list[GraphModification]:
    """Translate safe BadWhileLoop edits into graph modifications."""
    modifications: list[GraphModification] = []
    for edit in edits:
        if isinstance(edit, BadWhileLoopGotoRedirect):
            modifications.append(
                RedirectGoto(
                    from_serial=edit.from_serial,
                    old_target=edit.dispatcher_entry,
                    new_target=edit.new_target,
                )
            )
        elif isinstance(edit, BadWhileLoopGotoConversion):
            modifications.append(
                ConvertToGoto(
                    block_serial=edit.block_serial,
                    goto_target=edit.goto_target,
                )
            )
        elif isinstance(edit, BadWhileLoopDuplicateRedirect):
            candidate = bad_while_loop_duplicate_candidate(edit)
            if candidate is None:
                raise ValueError("Invalid BadWhileLoop duplicate redirect edit")
            modifications.append(build_dispatcher_cleanup_modification(candidate))
        elif isinstance(edit, BadWhileLoopConditionalDuplicate):
            modifications.append(
                DuplicateBlock(
                    source_block=edit.source_serial,
                    target_block=None,
                    pred_serial=edit.pred_serial,
                    conditional_target=edit.conditional_target,
                    fallthrough_target=edit.fallthrough_target,
                )
            )
        elif isinstance(edit, BadWhileLoopConditionalRedirect):
            modifications.append(
                CreateConditionalRedirect(
                    source_block=edit.source_serial,
                    ref_block=edit.ref_block,
                    conditional_target=edit.conditional_target,
                    fallthrough_target=edit.fallthrough_target,
                    old_target_serial=edit.dispatcher_entry,
                )
            )
        else:
            raise TypeError(f"Unsupported BadWhileLoop edit: {type(edit).__name__}")
    return modifications


@dataclass(frozen=True)
class BadWhileLoopAnalysis:
    """Live BadWhileLoop collection result for safe edits plus follow-up cases."""

    edits: tuple[BadWhileLoopEdit, ...]
    follow_up: tuple[BadWhileLoopFollowUp, ...]
    replay_candidates: tuple[CleanupSideEffectReplayCandidate, ...] = ()
    duplicate_replay_candidates: tuple[CleanupDuplicateGroupReplayCandidate, ...] = ()
    trampoline_isolation_candidates: tuple[
        CleanupTrampolineIsolationCandidate, ...
    ] = ()
    dependency_diagnostics: tuple[BadWhileLoopDependencyDiagnostic, ...] = ()


def collect_live_bad_while_loop_analysis(
    mba: object,
    *,
    logger: object | None = None,
    allowed_maturities: Sequence[int] | None = None,
    side_effect_capture: (
        Callable[[int, Sequence[object]], "CapturedBlockBody | None"] | None
    ) = None,
    dependency_rescue_capture: (
        Callable[
            [object, int, Sequence[object], Mapping[str, object]],
            "CapturedBlockBody | None",
        ]
        | None
    ) = None,
) -> BadWhileLoopAnalysis:
    """Collect safe BadWhileLoop edits plus classified follow-up gaps."""
    if mba is None:
        return BadWhileLoopAnalysis(edits=(), follow_up=())

    maturity = getattr(mba, "maturity", None)
    if allowed_maturities is not None and maturity not in set(allowed_maturities):
        return BadWhileLoopAnalysis(edits=(), follow_up=())

    import ida_hexrays

    from d810.evaluator.hexrays_microcode.tracker import (
        check_if_all_values_are_found,
        get_all_possibles_values,
        get_block_with_multiple_predecessors,
    )
    from d810.hexrays.ir.conditional_exit import resolve_loopback_target
    from d810.hexrays.utils.hexrays_helpers import (
        CONDITIONAL_JUMP_OPCODES,
        CONTROL_FLOW_OPCODES,
    )
    from d810.optimizers.microcode.flow.flattening.unflattener_badwhile_loop import (
        BadWhileLoop,
    )
    from d810.recon.flow.conditional_exit import (
        ExitBlockType,
        classify_exit_block,
        get_exit_successor,
        get_loopback_successor,
    )

    rule = BadWhileLoop()
    rule.mba = mba
    rule.retrieve_all_dispatchers()

    edits_by_key: dict[tuple[object, ...], BadWhileLoopEdit] = {}
    conflicts: set[tuple[object, ...]] = set()
    follow_up: list[BadWhileLoopFollowUp] = []
    replay_candidates: list[CleanupSideEffectReplayCandidate] = []
    duplicate_replay_candidates: list[CleanupDuplicateGroupReplayCandidate] = []
    trampoline_isolation_candidates: list[CleanupTrampolineIsolationCandidate] = []
    dependency_diagnostics: list[BadWhileLoopDependencyDiagnostic] = []
    seen_follow_up: set[tuple[object, ...]] = set()

    def record_follow_up(
        *,
        dispatcher_entry: int,
        from_serial: int,
        category: str,
        reason: str,
        target_serial: int | None = None,
        fallthrough_target: int | None = None,
    ) -> None:
        item = BadWhileLoopFollowUp(
            dispatcher_entry=dispatcher_entry,
            from_serial=from_serial,
            category=category,
            reason=reason,
            target_serial=target_serial,
            fallthrough_target=fallthrough_target,
        )
        key = (
            item.dispatcher_entry,
            item.from_serial,
            item.category,
            item.reason,
            item.target_serial,
            item.fallthrough_target,
        )
        if key in seen_follow_up:
            return
        seen_follow_up.add(key)
        follow_up.append(item)
        if logger is not None:
            logger.info("Collected BadWhileLoop follow-up: %s", item)

    def record_dependency_diagnostic(
        *,
        source_blk: object,
        dispatcher_entry: int,
        source_serial: int,
        target_serial: int | None,
        category: str,
        reason: str,
        copied_instructions: Sequence[object],
        dependency_safe_copies: Sequence[object],
    ) -> BadWhileLoopDependencyDiagnostic | None:
        try:
            diagnostic = build_bad_while_loop_dependency_diagnostic(
                mba=mba,
                rule=rule,
                source_blk=source_blk,
                dispatcher_entry=dispatcher_entry,
                source_serial=source_serial,
                target_serial=target_serial,
                category=category,
                reason=reason,
                copied_instructions=copied_instructions,
                dependency_safe_copies=dependency_safe_copies,
            )
        except Exception:
            if logger is not None:
                logger.debug(
                    "Failed to collect BadWhileLoop dependency diagnostic",
                    exc_info=True,
                )
            return None
        dependency_diagnostics.append(diagnostic)
        if logger is not None:
            logger.info("Collected BadWhileLoop dependency diagnostic: %s", diagnostic)
        return diagnostic

    def record_edit(edit: BadWhileLoopEdit) -> None:
        match edit:
            case BadWhileLoopGotoRedirect(from_serial=src):
                key = ("redirect_goto", src)
                target_value: object = edit.new_target
            case BadWhileLoopGotoConversion(block_serial=src):
                key = ("convert_to_goto", src)
                target_value = edit.goto_target
            case BadWhileLoopDuplicateRedirect(source_serial=src):
                key = ("duplicate_and_redirect", src)
                target_value = edit.per_pred_targets
            case BadWhileLoopConditionalDuplicate(source_serial=src, pred_serial=pred):
                key = ("duplicate_conditional_redirect", src, pred)
                target_value = (edit.conditional_target, edit.fallthrough_target)
            case BadWhileLoopConditionalRedirect(source_serial=src):
                key = ("create_conditional_redirect", src)
                target_value = (
                    edit.ref_block,
                    edit.conditional_target,
                    edit.fallthrough_target,
                )

        previous = edits_by_key.get(key)
        if previous is None:
            edits_by_key[key] = edit
            if logger is not None:
                logger.info("Collected safe BadWhileLoop edit: %s", edit)
            return

        previous_target = (
            previous.new_target
            if isinstance(previous, BadWhileLoopGotoRedirect)
            else (
                previous.goto_target
                if isinstance(previous, BadWhileLoopGotoConversion)
                else (
                    previous.per_pred_targets
                    if isinstance(previous, BadWhileLoopDuplicateRedirect)
                    else (
                        (
                            previous.conditional_target,
                            previous.fallthrough_target,
                        )
                        if isinstance(previous, BadWhileLoopConditionalDuplicate)
                        else (
                            previous.ref_block,
                            previous.conditional_target,
                            previous.fallthrough_target,
                        )
                    )
                )
            )
        )
        if previous_target != target_value:
            conflicts.add(key)

    def collect_duplicate_and_redirect_edit(
        *,
        dispatcher_entry_serial: int,
        dispatcher_direct_successors: set[int],
        father_serial: int,
        histories: Sequence[object],
        dispatcher_info: object,
    ) -> tuple[BadWhileLoopEdit | None, int, str | None, int | None]:
        source_block, pred_dict = get_block_with_multiple_predecessors(list(histories))
        if source_block is None or pred_dict is None:
            return None, father_serial, "divergent_history_values", None

        source_serial = int(source_block.serial)
        if source_block.nsucc() != 1:
            return None, source_serial, "shared_block_not_one_way", None
        if int(source_block.succ(0)) != dispatcher_entry_serial:
            return (
                None,
                source_serial,
                "shared_block_not_dispatcher_predecessor",
                None,
            )

        ordered_preds = [int(pred) for pred in list(source_block.predset) if int(pred) in pred_dict]
        for pred_serial in pred_dict:
            pred_int = int(pred_serial)
            if pred_int not in ordered_preds:
                ordered_preds.append(pred_int)
        if len(ordered_preds) < 2:
            return None, source_serial, "shared_block_has_single_predecessor", None

        per_pred_resolved_targets: dict[int, int] = {}
        per_pred_replays: list[CleanupPerPredReplay] = []
        trampoline_targets: set[int] = set()
        saw_copied_side_effects = False
        saw_plain_target = False
        first_replay_target: int | None = None
        first_trampoline_target: int | None = None
        for pred_serial in ordered_preds:
            group_histories = pred_dict.get(pred_serial, ())
            if not group_histories or not rule.check_if_histories_are_resolved(group_histories):
                return None, source_serial, "duplicate_group_unresolved", None

            group_values = get_all_possibles_values(
                group_histories,
                dispatcher_info.entry_block.use_before_def_list,
                verbose=False,
            )
            if not group_values or not check_if_all_values_are_found(group_values):
                return None, source_serial, "duplicate_group_missing_values", None

            reference_values = group_values[0]
            if any(candidate != reference_values for candidate in group_values[1:]):
                return None, source_serial, "duplicate_group_divergent_values", None

            target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(
                group_histories[0],
                resolve_conditional_exits=True,
            )
            if target_blk is None:
                return None, source_serial, "duplicate_group_emulation_returned_no_target", None

            copied_side_effects = [
                ins
                for ins in disp_ins
                if ins is not None and ins.opcode not in CONTROL_FLOW_OPCODES
            ]
            if copied_side_effects:
                # Duplicate-group replay cannot be reconstructed from the
                # serialized follow-up row: that row only records one target and
                # no instruction payload. Capture every dependency-safe body
                # here while the legacy oracle still exposes copied
                # instructions and per-predecessor histories.
                saw_copied_side_effects = True
                if first_replay_target is None:
                    first_replay_target = int(target_blk.serial)
                dependency_safe_copies = rule._filter_dependency_safe_copies(
                    source_block,
                    copied_side_effects,
                )
                if not dependency_safe_copies:
                    record_dependency_diagnostic(
                        source_blk=source_block,
                        dispatcher_entry=dispatcher_entry_serial,
                        source_serial=source_serial,
                        target_serial=int(target_blk.serial),
                        category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
                        reason=(
                            "duplicate_group_copied_side_effects_not_dependency_safe"
                        ),
                        copied_instructions=tuple(copied_side_effects),
                        dependency_safe_copies=tuple(dependency_safe_copies),
                    )
                    return (
                        None,
                        source_serial,
                        "duplicate_group_copied_side_effects_not_dependency_safe",
                        int(target_blk.serial),
                    )
                if side_effect_capture is None:
                    return (
                        None,
                        source_serial,
                        "duplicate_group_copied_side_effects",
                        int(target_blk.serial),
                    )
                captured_body: CapturedBlockBody | None = None
                try:
                    captured_body = side_effect_capture(
                        source_serial,
                        tuple(dependency_safe_copies),
                    )
                except Exception:
                    if logger is not None:
                        logger.debug(
                            "Failed to capture BadWhileLoop duplicate-group replay body",
                            exc_info=True,
                        )
                if captured_body is None:
                    return (
                        None,
                        source_serial,
                        "duplicate_group_copied_side_effects",
                        int(target_blk.serial),
                    )
                if captured_body.summary.contains_call:
                    return (
                        None,
                        source_serial,
                        "duplicate_group_copied_side_effects_contains_call",
                        int(target_blk.serial),
                    )
                per_pred_replays.append(
                    CleanupPerPredReplay(
                        pred_serial=int(pred_serial),
                        target_serial=int(target_blk.serial),
                        captured_body=captured_body,
                    )
                )
                per_pred_resolved_targets[pred_serial] = int(target_blk.serial)
                continue

            if saw_copied_side_effects:
                saw_plain_target = True

            target_is_conditional = (
                target_blk.nsucc() == 2
                and target_blk.tail is not None
                and ida_hexrays.is_mcode_jcond(target_blk.tail.opcode)
            )
            if (
                target_is_conditional
                and int(target_blk.serial) in dispatcher_direct_successors
            ):
                target_serial = int(target_blk.serial)
                trampoline_targets.add(target_serial)
                if first_trampoline_target is None:
                    first_trampoline_target = target_serial

            per_pred_resolved_targets[pred_serial] = int(target_blk.serial)

        if trampoline_targets:
            unique_targets = set(per_pred_resolved_targets.values())
            if len(unique_targets) == 1 and unique_targets == trampoline_targets:
                target_serial = next(iter(unique_targets))
                trampoline_candidate = bad_while_loop_trampoline_isolation_candidate(
                    dispatcher_entry=dispatcher_entry_serial,
                    source_serial=source_serial,
                    target_serial=target_serial,
                    dispatcher_internal_serials=tuple(dispatcher_serials),
                )
                if trampoline_candidate is not None:
                    trampoline_isolation_candidates.append(trampoline_candidate)
            return (
                None,
                source_serial,
                "duplicate_group_requires_trampoline",
                first_trampoline_target,
            )

        if saw_copied_side_effects:
            if saw_plain_target or len(per_pred_replays) != len(ordered_preds):
                return (
                    None,
                    source_serial,
                    "duplicate_group_copied_side_effects",
                    first_replay_target,
                )
            replay_candidate = bad_while_loop_duplicate_group_replay_candidate(
                dispatcher_entry=dispatcher_entry_serial,
                source_serial=source_serial,
                per_pred_replays=tuple(per_pred_replays),
                dispatcher_internal_serials=tuple(dispatcher_serials),
            )
            if replay_candidate is None:
                return (
                    None,
                    source_serial,
                    "duplicate_group_copied_side_effects",
                    first_replay_target,
                )
            duplicate_replay_candidates.append(replay_candidate)
            return (
                None,
                source_serial,
                "duplicate_group_copied_side_effects",
                first_replay_target,
            )

        unique_targets = set(per_pred_resolved_targets.values())
        if len(unique_targets) == 1:
            return (
                BadWhileLoopGotoRedirect(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=source_serial,
                    new_target=next(iter(unique_targets)),
                ),
                source_serial,
                None,
                None,
            )

        target_groups: dict[int, list[int]] = {}
        for pred_serial in ordered_preds:
            target_groups.setdefault(per_pred_resolved_targets[pred_serial], []).append(
                pred_serial
            )
        original_target = min(
            target_groups,
            key=lambda target: (
                -len(target_groups[target]),
                ordered_preds.index(target_groups[target][0]),
            ),
        )
        per_pred_targets: list[tuple[int, int]] = [
            (target_groups[original_target][0], original_target)
        ]
        for pred_serial in ordered_preds:
            if per_pred_resolved_targets[pred_serial] == original_target:
                continue
            per_pred_targets.append(
                (pred_serial, per_pred_resolved_targets[pred_serial])
            )

        if len(per_pred_targets) < 2:
            return (
                BadWhileLoopGotoRedirect(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=source_serial,
                    new_target=original_target,
                ),
                source_serial,
                None,
                None,
            )

        return (
            BadWhileLoopDuplicateRedirect(
                dispatcher_entry=dispatcher_entry_serial,
                source_serial=source_serial,
                per_pred_targets=tuple(per_pred_targets),
            ),
            source_serial,
            None,
            None,
        )

    for dispatcher_info in rule.dispatcher_list:
        dispatcher_entry = dispatcher_info.entry_block.blk
        dispatcher_entry_serial = int(dispatcher_entry.serial)
        dispatcher_serials = {
            blk_info.serial for blk_info in dispatcher_info.dispatcher_internal_blocks
        }
        dispatcher_direct_successors = {
            int(dispatcher_entry.succ(i)) for i in range(dispatcher_entry.nsucc())
        }

        for pred_serial in list(dispatcher_entry.predset):
            father = mba.get_mblock(pred_serial)
            if father is None or father.tail is None:
                continue

            histories = rule.get_dispatcher_father_histories(
                father,
                dispatcher_info.entry_block,
                dispatcher_info,
            )
            if not histories or not rule.check_if_histories_are_resolved(histories):
                record_follow_up(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=int(pred_serial),
                    category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
                    reason="unresolved_histories",
                )
                continue

            values = get_all_possibles_values(
                histories,
                dispatcher_info.entry_block.use_before_def_list,
                verbose=False,
            )
            if not values or not check_if_all_values_are_found(values):
                record_follow_up(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=int(pred_serial),
                    category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
                    reason="missing_history_values",
                )
                continue

            reference = values[0]
            if any(candidate != reference for candidate in values[1:]):
                duplicate_edit, follow_up_serial, follow_up_reason, follow_up_target = (
                    collect_duplicate_and_redirect_edit(
                        dispatcher_entry_serial=dispatcher_entry_serial,
                        dispatcher_direct_successors=dispatcher_direct_successors,
                        father_serial=int(father.serial),
                        histories=histories,
                        dispatcher_info=dispatcher_info,
                    )
                )
                if duplicate_edit is not None:
                    record_edit(duplicate_edit)
                    continue

                record_follow_up(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=follow_up_serial,
                    category=BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT,
                    reason=follow_up_reason or "divergent_history_values",
                    target_serial=follow_up_target,
                )
                continue

            target_blk, disp_ins = dispatcher_info.emulate_dispatcher_with_father_history(
                histories[0],
                resolve_conditional_exits=True,
            )
            if target_blk is None:
                record_follow_up(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=int(father.serial),
                    category=BAD_WHILE_LOOP_UNSUPPORTED,
                    reason="emulation_returned_no_target",
                )
                continue

            copied_side_effects = [
                ins
                for ins in disp_ins
                if ins is not None and ins.opcode not in CONTROL_FLOW_OPCODES
            ]
            if copied_side_effects:
                dependency_safe_copies = rule._filter_dependency_safe_copies(
                    father,
                    copied_side_effects,
                )
                dependency_diagnostic: BadWhileLoopDependencyDiagnostic | None = None
                if not dependency_safe_copies:
                    dependency_diagnostic = record_dependency_diagnostic(
                        source_blk=father,
                        dispatcher_entry=dispatcher_entry_serial,
                        source_serial=int(father.serial),
                        target_serial=int(target_blk.serial),
                        category=BAD_WHILE_LOOP_INSERT_BLOCK,
                        reason="copied_side_effects_not_dependency_safe",
                        copied_instructions=tuple(copied_side_effects),
                        dependency_safe_copies=tuple(dependency_safe_copies),
                    )
                if dependency_safe_copies and side_effect_capture is not None:
                    captured_body: CapturedBlockBody | None = None
                    try:
                        captured_body = side_effect_capture(
                            int(father.serial),
                            tuple(dependency_safe_copies),
                        )
                    except Exception:
                        if logger is not None:
                            logger.debug(
                                "Failed to capture BadWhileLoop side-effect replay body",
                                exc_info=True,
                            )
                    if (
                        captured_body is not None
                        and captured_body.summary.contains_call
                    ):
                        follow_up_reason = "copied_side_effects_contains_call"
                    else:
                        replay_candidate = bad_while_loop_side_effect_replay_candidate(
                            dispatcher_entry=dispatcher_entry_serial,
                            source_serial=int(father.serial),
                            target_serial=int(target_blk.serial),
                            captured_body=captured_body,
                            dispatcher_internal_serials=tuple(dispatcher_serials),
                        )
                        if replay_candidate is not None:
                            replay_candidates.append(replay_candidate)
                        follow_up_reason = "copied_side_effects"
                elif dependency_safe_copies:
                    follow_up_reason = "copied_side_effects"
                else:
                    if (
                        dependency_rescue_capture is not None
                        and dependency_diagnostic is not None
                        and dependency_diagnostic.get("final_bucket")
                        == "stack_unique_def_chain_capturable"
                    ):
                        captured_body = None
                        try:
                            captured_body = dependency_rescue_capture(
                                mba,
                                int(father.serial),
                                tuple(copied_side_effects),
                                dependency_diagnostic,
                            )
                        except Exception:
                            if logger is not None:
                                logger.debug(
                                    "Failed to capture BadWhileLoop dependency rescue body",
                                    exc_info=True,
                                )
                        replay_candidate = bad_while_loop_side_effect_replay_candidate(
                            dispatcher_entry=dispatcher_entry_serial,
                            source_serial=int(father.serial),
                            target_serial=int(target_blk.serial),
                            captured_body=captured_body,
                            dispatcher_internal_serials=tuple(dispatcher_serials),
                        )
                        if replay_candidate is not None:
                            replay_candidates.append(replay_candidate)
                    follow_up_reason = "copied_side_effects_not_dependency_safe"
                record_follow_up(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=int(father.serial),
                    category=BAD_WHILE_LOOP_INSERT_BLOCK,
                    reason=follow_up_reason,
                    target_serial=int(target_blk.serial),
                )
                continue

            exit_type = classify_exit_block(father, dispatcher_serials)
            if exit_type == ExitBlockType.CONDITIONAL_EXIT_WITH_LOOPBACK:
                conditional_target: int | None = None
                fallthrough_target = get_exit_successor(father, dispatcher_serials)
                loopback_serial = get_loopback_successor(father, dispatcher_serials)
                if loopback_serial is not None and fallthrough_target is not None:
                    loopback_result = resolve_loopback_target(
                        father,
                        loopback_serial,
                        dispatcher_info,
                        dispatcher_info.mop_compared,
                    )
                    if loopback_result is not None:
                        conditional_target, _state_value = loopback_result

                if conditional_target is None or fallthrough_target is None:
                    record_follow_up(
                        dispatcher_entry=dispatcher_entry_serial,
                        from_serial=int(father.serial),
                        category=BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT,
                        reason="conditional_exit_with_loopback",
                        target_serial=conditional_target,
                        fallthrough_target=(
                            int(fallthrough_target)
                            if fallthrough_target is not None
                            else None
                        ),
                    )
                    continue

                conditional_exit_preds = [int(pred) for pred in list(father.predset)]
                if not conditional_exit_preds:
                    record_follow_up(
                        dispatcher_entry=dispatcher_entry_serial,
                        from_serial=int(father.serial),
                        category=BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT,
                        reason="conditional_exit_missing_predecessors",
                        target_serial=int(conditional_target),
                        fallthrough_target=int(fallthrough_target),
                    )
                    continue

                if any(
                    (pred_blk := mba.get_mblock(pred_serial)) is None
                    or pred_blk.nsucc() != 1
                    or int(pred_blk.succ(0)) != int(father.serial)
                    for pred_serial in conditional_exit_preds
                ):
                    record_follow_up(
                        dispatcher_entry=dispatcher_entry_serial,
                        from_serial=int(father.serial),
                        category=BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT,
                        reason="conditional_exit_non_one_way_predecessor",
                        target_serial=int(conditional_target),
                        fallthrough_target=int(fallthrough_target),
                    )
                    continue

                for conditional_pred in conditional_exit_preds:
                    record_edit(
                        BadWhileLoopConditionalDuplicate(
                            dispatcher_entry=dispatcher_entry_serial,
                            source_serial=int(father.serial),
                            pred_serial=int(conditional_pred),
                            conditional_target=int(conditional_target),
                            fallthrough_target=int(fallthrough_target),
                        )
                    )
                continue

            target_is_conditional = (
                target_blk.nsucc() == 2
                and target_blk.tail is not None
                and ida_hexrays.is_mcode_jcond(target_blk.tail.opcode)
            )
            if (
                target_is_conditional
                and int(target_blk.serial) in dispatcher_direct_successors
            ):
                if (
                    father.nsucc() == 1
                    and int(father.succ(0)) == dispatcher_entry_serial
                ):
                    record_edit(
                        BadWhileLoopConditionalRedirect(
                            dispatcher_entry=dispatcher_entry_serial,
                            source_serial=int(father.serial),
                            ref_block=int(target_blk.serial),
                            conditional_target=int(target_blk.succ(0)),
                            fallthrough_target=int(target_blk.succ(1)),
                            dispatcher_internal_serials=tuple(
                                sorted(dispatcher_serials),
                            ),
                            copied_side_effects_absent=True,
                        )
                    )
                    continue
                record_follow_up(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=int(father.serial),
                    category=BAD_WHILE_LOOP_UNSUPPORTED,
                    reason="dispatcher_case_triangle_requires_trampoline",
                    target_serial=int(target_blk.serial),
                )
                continue

            source_nsucc = father.nsucc()
            tail_opcode = father.tail.opcode
            if source_nsucc == 1:
                edit = BadWhileLoopGotoRedirect(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=int(father.serial),
                    new_target=int(target_blk.serial),
                )
            elif source_nsucc == 2 and tail_opcode in CONDITIONAL_JUMP_OPCODES:
                edit = BadWhileLoopGotoConversion(
                    dispatcher_entry=dispatcher_entry_serial,
                    block_serial=int(father.serial),
                    goto_target=int(target_blk.serial),
                )
            else:
                record_follow_up(
                    dispatcher_entry=dispatcher_entry_serial,
                    from_serial=int(father.serial),
                    category=BAD_WHILE_LOOP_UNSUPPORTED,
                    reason="unsupported_source_shape",
                    target_serial=int(target_blk.serial),
                )
                continue

            record_edit(edit)

    for key in conflicts:
        edits_by_key.pop(key, None)

    return BadWhileLoopAnalysis(
        edits=tuple(edits_by_key.values()),
        follow_up=tuple(follow_up),
        replay_candidates=tuple(replay_candidates),
        duplicate_replay_candidates=tuple(duplicate_replay_candidates),
        trampoline_isolation_candidates=tuple(trampoline_isolation_candidates),
        dependency_diagnostics=tuple(dependency_diagnostics),
    )


def collect_live_bad_while_loop_edits(
    mba: object,
    *,
    logger: object | None = None,
    allowed_maturities: Sequence[int] | None = None,
) -> tuple[BadWhileLoopEdit, ...]:
    """Collect only the safe, already-resolvable BadWhileLoop edits."""
    return collect_live_bad_while_loop_analysis(
        mba,
        logger=logger,
        allowed_maturities=allowed_maturities,
    ).edits


def collect_live_bad_while_loop_follow_up(
    mba: object,
    *,
    logger: object | None = None,
    allowed_maturities: Sequence[int] | None = None,
) -> tuple[BadWhileLoopFollowUp, ...]:
    """Collect skipped legacy BadWhileLoop cases that still need planning parity."""
    return collect_live_bad_while_loop_analysis(
        mba,
        logger=logger,
        allowed_maturities=allowed_maturities,
    ).follow_up


def _build_ownership(modifications: Sequence[GraphModification]) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()

    for mod in modifications:
        if isinstance(mod, RedirectGoto):
            blocks.add(mod.from_serial)
            edges.add((mod.from_serial, mod.old_target))
        elif isinstance(mod, ConvertToGoto):
            blocks.add(mod.block_serial)
        elif isinstance(mod, DuplicateAndRedirect):
            blocks.add(mod.source_serial)
            for pred_serial, _target_serial in mod.per_pred_targets:
                edges.add((pred_serial, mod.source_serial))
        elif isinstance(mod, DuplicateReplayAndRedirect):
            blocks.add(mod.source_serial)
            for replay in mod.per_pred_replays:
                edges.add((replay.pred_serial, mod.source_serial))
        elif isinstance(mod, DuplicateBlock):
            blocks.add(mod.source_block)
            if mod.pred_serial is not None:
                edges.add((mod.pred_serial, mod.source_block))
        elif isinstance(mod, CreateConditionalRedirect):
            blocks.add(mod.source_block)
            if mod.old_target_serial is not None:
                edges.add((mod.source_block, mod.old_target_serial))
        elif isinstance(mod, InsertBlock):
            blocks.add(mod.pred_serial)
            old_target = (
                mod.old_target_serial
                if mod.old_target_serial is not None
                else mod.succ_serial
            )
            edges.add((mod.pred_serial, old_target))

    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


class BadWhileLoopStrategy:
    """Engine strategy for the safe already-resolvable BadWhileLoop subset."""

    name = "bad_while_loop"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return bool(
            extract_bad_while_loop_edits(snapshot.flow_graph)
            or extract_side_effect_replay_candidates(snapshot.flow_graph)
            or extract_duplicate_group_replay_candidates(snapshot.flow_graph)
            or extract_trampoline_isolation_candidates(snapshot.flow_graph)
        )

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        edits = extract_bad_while_loop_edits(snapshot.flow_graph)
        replay_candidates = extract_side_effect_replay_candidates(snapshot.flow_graph)
        duplicate_replay_candidates = extract_duplicate_group_replay_candidates(
            snapshot.flow_graph
        )
        trampoline_isolation_candidates = extract_trampoline_isolation_candidates(
            snapshot.flow_graph
        )
        if (
            not edits
            and not replay_candidates
            and not duplicate_replay_candidates
            and not trampoline_isolation_candidates
        ):
            return None

        modifications = build_bad_while_loop_modifications(edits)
        modifications.extend(
            build_dispatcher_cleanup_modification(candidate)
            for candidate in replay_candidates
        )
        modifications.extend(
            build_dispatcher_cleanup_modification(candidate)
            for candidate in duplicate_replay_candidates
        )
        modifications.extend(
            build_dispatcher_cleanup_modification(candidate)
            for candidate in trampoline_isolation_candidates
        )
        if not modifications:
            return None

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=_build_ownership(modifications),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=len(modifications),
                conflict_density=0.0,
            ),
            risk_score=0.2,
            metadata={
                BAD_WHILE_LOOP_EDITS_METADATA_KEY: _serialize_bad_while_loop_edits(
                    edits
                ),
                CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY: tuple(replay_candidates),
                CLEANUP_DUPLICATE_REPLAY_METADATA_KEY: tuple(
                    duplicate_replay_candidates
                ),
                CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY: tuple(
                    trampoline_isolation_candidates
                ),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY",
    "BAD_WHILE_LOOP_EDITS_METADATA_KEY",
    "BAD_WHILE_LOOP_FOLLOW_UP_METADATA_KEY",
    "BAD_WHILE_LOOP_CREATE_CONDITIONAL_REDIRECT",
    "BAD_WHILE_LOOP_DUPLICATE_AND_REDIRECT",
    "BAD_WHILE_LOOP_INSERT_BLOCK",
    "BAD_WHILE_LOOP_UNSUPPORTED",
    "BadWhileLoopAnalysis",
    "BadWhileLoopConditionalDuplicate",
    "BadWhileLoopConditionalRedirect",
    "BadWhileLoopDependencyDiagnostic",
    "BadWhileLoopDuplicateRedirect",
    "BadWhileLoopEdit",
    "BadWhileLoopFollowUp",
    "BadWhileLoopGotoConversion",
    "BadWhileLoopGotoRedirect",
    "BadWhileLoopStrategy",
    "build_bad_while_loop_modifications",
    "collect_live_bad_while_loop_analysis",
    "collect_live_bad_while_loop_edits",
    "collect_live_bad_while_loop_follow_up",
    "extract_bad_while_loop_dependency_diagnostics",
    "extract_bad_while_loop_edits",
    "extract_bad_while_loop_follow_up",
    "serialize_bad_while_loop_dependency_diagnostics",
    "serialize_bad_while_loop_edits",
    "serialize_bad_while_loop_follow_up",
]
