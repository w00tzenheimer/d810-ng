from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from d810.core.typing import Callable
from d810.transforms.edit_simulator import project_post_state
from d810.transforms.graph_modification import (
    ExitPathLoweringGroup,
    ExitPathLoweringKind,
    ExitPathLoweringSite,
)
from d810.transforms.plan import compile_patch_plan


@dataclass(frozen=True, slots=True)
class TerminalFamilySplitCandidate:
    source_block: int
    branch_arm: int | None
    family_entry: int
    path: tuple[int, ...]
    value_family_signature: tuple[object, ...]
    lineage_eas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class TerminalFamilySplitProposal:
    suffix_serials: tuple[int, ...]
    selected_candidate_indexes: tuple[int, ...]
    selected_anchors: tuple[int, ...]
    primary_signature: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class TerminalFamilySplitSelection:
    modification: object
    projected_flow_graph: object
    suffix_serials: tuple[int, ...]
    selected_candidate_indexes: tuple[int, ...]
    selected_anchors: tuple[int, ...]
    primary_signature: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class TerminalFamilySplitIteration:
    report: object
    split_candidates: tuple[TerminalFamilySplitCandidate, ...]
    selected: TerminalFamilySplitSelection | None
    selected_candidates: tuple[object, ...] = ()


@dataclass(frozen=True, slots=True)
class TerminalFamilySplitRun:
    projected_flow_graph: object
    emitted_count: int
    iterations: tuple[TerminalFamilySplitIteration, ...]


def _candidate_key(
    candidate: TerminalFamilySplitCandidate,
) -> tuple[int, int | None, int, tuple[int, ...]]:
    return (
        int(candidate.source_block),
        candidate.branch_arm,
        int(candidate.family_entry),
        tuple(int(s) for s in candidate.path),
    )


def _candidate_anchor_for_suffix(
    candidate: TerminalFamilySplitCandidate,
    *,
    suffix_serials: tuple[int, ...],
    projected_flow_graph,
) -> int | None:
    if candidate.path[-len(suffix_serials):] != suffix_serials:
        return None
    if len(candidate.path) > len(suffix_serials):
        anchor_serial = int(candidate.path[-len(suffix_serials) - 1])
    elif candidate.family_entry == suffix_serials[0]:
        anchor_serial = int(candidate.source_block)
    else:
        return None

    anchor_block = projected_flow_graph.get_block(anchor_serial)
    if anchor_block is None or anchor_block.nsucc != 1:
        return None
    if int(anchor_block.succs[0]) != int(suffix_serials[0]):
        return None
    return anchor_serial


def build_terminal_family_split_proposals(
    candidates: tuple[TerminalFamilySplitCandidate, ...],
    *,
    projected_flow_graph,
    excluded_anchors: frozenset[int] = frozenset(),
) -> tuple[TerminalFamilySplitProposal, ...]:
    groups_by_suffix: dict[tuple[int, ...], list[tuple[int, TerminalFamilySplitCandidate]]] = {}
    for index, candidate in enumerate(candidates):
        for suffix_len in range(2, len(candidate.path) + 1):
            suffix = candidate.path[-suffix_len:]
            groups_by_suffix.setdefault(suffix, []).append((index, candidate))

    suffix_groups = sorted(
        groups_by_suffix.items(),
        key=lambda item: (
            -len(item[0]),
            -len({_candidate_key(c) for _idx, c in item[1]}),
            int(item[0][0]),
        ),
    )

    proposals: list[TerminalFamilySplitProposal] = []
    for suffix_serials, group_members in suffix_groups:
        unique_members: dict[
            tuple[int, int | None, int, tuple[int, ...]],
            tuple[int, TerminalFamilySplitCandidate],
        ] = {}
        for index, candidate in group_members:
            unique_members.setdefault(_candidate_key(candidate), (index, candidate))
        members = tuple(unique_members.values())
        if len(members) < 2:
            continue

        signature_buckets: defaultdict[
            tuple[object, ...],
            list[tuple[int, TerminalFamilySplitCandidate]],
        ] = defaultdict(list)
        for member in members:
            index, candidate = member
            signature_buckets[candidate.value_family_signature].append((index, candidate))
        if len(signature_buckets) < 2:
            continue

        sorted_buckets = sorted(
            signature_buckets.items(),
            key=lambda item: (
                -len(item[1]),
                repr(item[0]),
                min(
                    candidate.lineage_eas[0] if candidate.lineage_eas else 0
                    for _index, candidate in item[1]
                ),
            ),
        )
        primary_signature = sorted_buckets[0][0]

        selected_candidate_indexes: list[int] = []
        selected_anchors: list[int] = []
        for _signature, bucket in sorted_buckets[1:]:
            for index, candidate in bucket:
                anchor_serial = _candidate_anchor_for_suffix(
                    candidate,
                    suffix_serials=suffix_serials,
                    projected_flow_graph=projected_flow_graph,
                )
                if (
                    anchor_serial is None
                    or anchor_serial in selected_anchors
                    or anchor_serial in excluded_anchors
                ):
                    continue
                selected_candidate_indexes.append(int(index))
                selected_anchors.append(int(anchor_serial))

        if not selected_anchors:
            continue

        proposals.append(
            TerminalFamilySplitProposal(
                suffix_serials=tuple(int(s) for s in suffix_serials),
                selected_candidate_indexes=tuple(selected_candidate_indexes),
                selected_anchors=tuple(selected_anchors),
                primary_signature=primary_signature,
            )
        )

    return tuple(proposals)


def _direct_lowering_site_anchors(modifications: list[object]) -> frozenset[int]:
    anchors: set[int] = set()
    for mod in modifications:
        if not isinstance(mod, ExitPathLoweringGroup):
            continue
        for site in mod.sites:
            anchors.add(int(site.anchor_serial))
    return frozenset(anchors)


def build_terminal_family_split_candidates(
    candidates: tuple[object, ...],
) -> tuple[TerminalFamilySplitCandidate, ...]:
    return tuple(
        TerminalFamilySplitCandidate(
            source_block=int(candidate.source_block),
            branch_arm=(
                int(candidate.branch_arm)
                if getattr(candidate, "branch_arm", None) is not None
                else None
            ),
            family_entry=int(candidate.family_entry),
            path=tuple(int(s) for s in candidate.path),
            value_family_signature=tuple(candidate.value_family_signature),
            lineage_eas=tuple(int(ea) for ea in candidate.lineage_eas),
        )
        for candidate in candidates
    )


def build_terminal_family_split_modification(
    *,
    builder,
    anchors: tuple[int, ...],
    suffix_serials: tuple[int, ...],
    projected_flow_graph=None,
):
    shared_entry = int(suffix_serials[0])
    stop_block = int(suffix_serials[-1])
    if projected_flow_graph is not None:
        for idx, serial in enumerate(suffix_serials):
            blk = projected_flow_graph.get_block(serial)
            if blk is None:
                return None
            if idx < len(suffix_serials) - 1:
                if blk.nsucc != 1:
                    return None
            elif blk.nsucc != 0:
                return None
    if len(anchors) == 1:
        return builder.private_terminal_suffix(
            anchor_serial=int(anchors[0]),
            shared_entry_serial=shared_entry,
            return_block_serial=stop_block,
            suffix_serials=suffix_serials,
            reason="terminal_family_split",
        )
    return builder.private_terminal_suffix_group(
        anchors=anchors,
        shared_entry_serial=shared_entry,
        return_block_serial=stop_block,
        suffix_serials=suffix_serials,
        reason="terminal_family_split",
    )


def _signature_fields(entry: object) -> dict[str, object]:
    if not isinstance(entry, tuple) or len(entry) < 4:
        return {}
    fields: dict[str, object] = {}
    parts = entry[2:]
    for idx in range(0, len(parts) - 1, 2):
        key = parts[idx]
        if isinstance(key, str):
            fields[key] = parts[idx + 1]
    return fields


def _literal_return_const_from_signature(signature: tuple[object, ...]) -> int | None:
    if not signature:
        return None
    if (
        len(signature) == 2
        and signature[0] == "terminal_value_chain"
        and isinstance(signature[1], tuple)
    ):
        value_chain = signature[1]
        if not value_chain:
            return None
        first_entry = value_chain[0]
    else:
        first_entry = signature[0]
    if (
        isinstance(first_entry, tuple)
        and len(first_entry) == 2
        and first_entry[0] == "terminal_value_chain"
        and isinstance(first_entry[1], tuple)
    ):
        value_chain = first_entry[1]
        if not value_chain:
            return None
        first_entry = value_chain[0]
    fields = _signature_fields(first_entry)
    src_l = fields.get("src_l")
    src_r = fields.get("src_r")
    dst = fields.get("dst")
    if (
        isinstance(src_l, tuple)
        and len(src_l) >= 2
        and src_l[0] == "const"
        and isinstance(src_l[1], int)
        and isinstance(src_r, tuple)
        and src_r[:1] == ("none",)
        and isinstance(dst, tuple)
        and dst[:1] in (("stk",), ("reg",))
    ):
        return int(src_l[1])
    return None


def _candidate_literal_return_const(candidate: object) -> int | None:
    return _literal_return_const_from_signature(
        tuple(getattr(candidate, "value_family_signature", ()) or ())
    )


def build_terminal_family_direct_const_lowering_modification(
    *,
    builder,
    selected_anchors: tuple[int, ...],
    selected_candidates: tuple[object, ...],
    suffix_serials: tuple[int, ...],
):
    sites: list[ExitPathLoweringSite] = []
    for anchor, candidate in zip(selected_anchors, selected_candidates):
        const_value = _candidate_literal_return_const(candidate)
        if const_value is None:
            continue
        sites.append(
            ExitPathLoweringSite(
                anchor_serial=int(anchor),
                kind=ExitPathLoweringKind.RETURN_CONST,
                const_value=const_value,
            )
        )
    if not sites:
        return None
    return builder.direct_terminal_lowering(
        sites=sites,
        shared_entry_serial=int(suffix_serials[0]),
        return_block_serial=int(suffix_serials[-1]),
        suffix_serials=tuple(int(serial) for serial in suffix_serials),
        reason="terminal_family_direct_const_lowering",
    )


def select_terminal_family_split(
    candidates: tuple[TerminalFamilySplitCandidate, ...],
    *,
    base_flow_graph,
    projected_flow_graph,
    builder,
    modifications: list,
    compute_reachable_blocks: Callable[[object], set[int] | None],
) -> TerminalFamilySplitSelection | None:
    current_reachable = compute_reachable_blocks(projected_flow_graph)
    if not current_reachable:
        return None

    baseline_reachable_count = len(current_reachable)
    excluded_anchors = _direct_lowering_site_anchors(modifications)

    for proposal in build_terminal_family_split_proposals(
        candidates,
        projected_flow_graph=projected_flow_graph,
        excluded_anchors=excluded_anchors,
    ):
        candidate_mod = build_terminal_family_split_modification(
            builder=builder,
            anchors=proposal.selected_anchors,
            suffix_serials=proposal.suffix_serials,
            projected_flow_graph=projected_flow_graph,
        )
        if candidate_mod is None:
            continue

        try:
            patch_plan = compile_patch_plan(modifications + [candidate_mod], base_flow_graph)
            candidate_projected = project_post_state(base_flow_graph, patch_plan)
        except Exception:
            continue

        candidate_reachable = compute_reachable_blocks(candidate_projected)
        if candidate_reachable is None or len(candidate_reachable) < baseline_reachable_count:
            continue

        return TerminalFamilySplitSelection(
            modification=candidate_mod,
            projected_flow_graph=candidate_projected,
            suffix_serials=proposal.suffix_serials,
            selected_candidate_indexes=proposal.selected_candidate_indexes,
            selected_anchors=proposal.selected_anchors,
            primary_signature=proposal.primary_signature,
        )

    return None


def plan_terminal_family_splits(
    *,
    dag,
    base_flow_graph,
    projected_flow_graph,
    dispatcher_region: set[int],
    state_var_stkoff: int | None,
    builder,
    modifications: list,
    collect_report,
    compute_reachable_blocks: Callable[[object], set[int] | None],
) -> TerminalFamilySplitRun:
    current_projected_flow_graph = projected_flow_graph
    emitted = 0
    iterations: list[TerminalFamilySplitIteration] = []

    while True:
        reachable_blocks = compute_reachable_blocks(current_projected_flow_graph)
        if not reachable_blocks:
            break

        report = collect_report(
            dag,
            base_flow_graph=base_flow_graph,
            projected_flow_graph=current_projected_flow_graph,
            dispatcher_region=dispatcher_region,
            reachable_blocks=reachable_blocks,
            state_var_stkoff=state_var_stkoff,
        )
        split_candidates = build_terminal_family_split_candidates(
            tuple(report.collection.candidates)
        )
        selected = None
        selected_candidates: tuple[object, ...] = ()
        if len(split_candidates) >= 2:
            selected = select_terminal_family_split(
                split_candidates,
                base_flow_graph=base_flow_graph,
                projected_flow_graph=current_projected_flow_graph,
                builder=builder,
                modifications=modifications,
                compute_reachable_blocks=compute_reachable_blocks,
            )
            if selected is not None:
                selected_candidates = tuple(
                    report.collection.candidates[index]
                    for index in selected.selected_candidate_indexes
                )
        iterations.append(
            TerminalFamilySplitIteration(
                report=report,
                split_candidates=split_candidates,
                selected=selected,
                selected_candidates=selected_candidates,
            )
        )
        if selected is None:
            break

        modifications.append(selected.modification)
        current_projected_flow_graph = selected.projected_flow_graph
        emitted += 1

    return TerminalFamilySplitRun(
        projected_flow_graph=current_projected_flow_graph,
        emitted_count=emitted,
        iterations=tuple(iterations),
    )


__all__ = [
    "TerminalFamilySplitIteration",
    "TerminalFamilySplitRun",
    "TerminalFamilySplitCandidate",
    "TerminalFamilySplitProposal",
    "TerminalFamilySplitSelection",
    "build_terminal_family_split_candidates",
    "build_terminal_family_split_modification",
    "build_terminal_family_direct_const_lowering_modification",
    "build_terminal_family_split_proposals",
    "plan_terminal_family_splits",
    "select_terminal_family_split",
]
