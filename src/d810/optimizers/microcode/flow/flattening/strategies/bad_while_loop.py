"""Shared helpers and engine strategy wrapper for safe BadWhileLoop cleanup."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph
from d810.transforms.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    DuplicateReplayAndRedirect,
    GraphModification,
    InsertBlock,
    RedirectGoto,
)
from d810.core.typing import TYPE_CHECKING
from d810.transforms.cleanup_evidence import (
    CLEANUP_DUPLICATE_REPLAY_METADATA_KEY,
    CLEANUP_SIDE_EFFECT_REPLAY_METADATA_KEY,
    CLEANUP_TRAMPOLINE_ISOLATION_METADATA_KEY,
    CleanupDuplicateGroupReplayCandidate,
    CleanupPerPredReplay,
    CleanupSideEffectReplayCandidate,
    CleanupTrampolineIsolationCandidate,
    bad_while_loop_duplicate_group_replay_candidate,
    bad_while_loop_side_effect_replay_candidate,
    bad_while_loop_trampoline_isolation_candidate,
    build_dispatcher_cleanup_modification,
    extract_duplicate_group_replay_candidates,
    extract_side_effect_replay_candidates,
    extract_trampoline_isolation_candidates,
)
from d810.transforms.plan_fragment import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.backends.hexrays.evidence.bad_while_loop_dependency_diagnostics import (
    BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY,
    BadWhileLoopDependencyDiagnostic,
    build_bad_while_loop_dependency_diagnostic,
    extract_bad_while_loop_dependency_diagnostics,
    serialize_bad_while_loop_dependency_diagnostics,
)

if TYPE_CHECKING:
    from d810.transforms.materialization_payload import CapturedBlockBody
    from d810.transforms.snapshot import (
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
    """A skipped bad-while-loop path that still needs planning parity."""

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
            return False
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
    """Serialize skipped bad-while-loop paths into FlowGraph metadata."""
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
            continue
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
    allowed_maturities: Sequence[int] | None = None,
    logger: object | None = None,
    side_effect_capture: CleanupSideEffectCapture | None = None,
    dependency_rescue_capture: CleanupDependencyRescueCapture | None = None,
) -> BadWhileLoopAnalysis:
    """Return no live legacy-oracle results after legacy rule retirement.

    BadWhileLoop cleanup is now driven by already-normalized metadata and
    proof objects.  The former live producer depended on the retired
    ``BadWhileLoop`` rule class; keeping that dependency would reintroduce the
    legacy unflattener through the cleanup-family backend.
    """
    return BadWhileLoopAnalysis(edits=(), follow_up=())

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
    """Collect skipped bad-while-loop cases that still need planning parity."""
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
