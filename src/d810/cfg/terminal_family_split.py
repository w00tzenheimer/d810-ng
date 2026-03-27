from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass


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
                if anchor_serial is None or anchor_serial in selected_anchors:
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


__all__ = [
    "TerminalFamilySplitCandidate",
    "TerminalFamilySplitProposal",
    "build_terminal_family_split_proposals",
]
