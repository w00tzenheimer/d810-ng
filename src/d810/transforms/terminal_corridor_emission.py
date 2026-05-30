from __future__ import annotations

from dataclasses import dataclass

from d810.ir.flowgraph import InsnKind
from d810.transforms.graph_modification import (
    DirectTerminalLoweringKind,
    DirectTerminalLoweringSite,
)


@dataclass(frozen=True, slots=True)
class PrivateTerminalSuffixExecutionPlan:
    modifications: tuple[object, ...]
    owned_blocks: frozenset[int]
    owned_edges: frozenset[tuple[int, int]]
    safeguard_min_required: int


@dataclass(frozen=True, slots=True)
class DirectTerminalLoweringExecutionPlan:
    modifications: tuple[object, ...]
    owned_blocks: frozenset[int]
    owned_edges: frozenset[tuple[int, int]]
    sites: tuple[DirectTerminalLoweringSite, ...]
    supported_sites: tuple[DirectTerminalLoweringSite, ...]


def plan_private_terminal_suffix_execution(
    *,
    flow_graph,
    builder,
    anchors: tuple[int, ...],
    shared_entry_serial: int,
    return_block_serial: int,
    suffix_serials: tuple[int, ...],
) -> PrivateTerminalSuffixExecutionPlan:
    modifications: list[object] = []
    owned_blocks: set[int] = set()
    pts_anchor_set = set(int(anchor) for anchor in anchors)

    return_blk = flow_graph.get_block(return_block_serial)
    if return_blk is not None:
        for pred_serial in return_blk.preds:
            if pred_serial in pts_anchor_set:
                continue
            pred_blk = flow_graph.get_block(pred_serial)
            if (
                pred_blk is not None
                and pred_blk.nsucc == 1
                and getattr(pred_blk, "tail_kind", InsnKind.UNKNOWN) != InsnKind.GOTO
            ):
                modifications.append(
                    builder.convert_to_goto(
                        source_block=int(pred_serial),
                        target_block=int(return_block_serial),
                    )
                )

    modifications.append(
        builder.private_terminal_suffix_group(
            anchors=tuple(int(anchor) for anchor in anchors),
            shared_entry_serial=int(shared_entry_serial),
            return_block_serial=int(return_block_serial),
            suffix_serials=tuple(int(serial) for serial in suffix_serials),
        )
    )

    owned_blocks.update(int(anchor) for anchor in anchors)
    owned_blocks.update(int(serial) for serial in suffix_serials)
    owned_blocks.add(int(shared_entry_serial))
    owned_blocks.add(int(return_block_serial))

    return PrivateTerminalSuffixExecutionPlan(
        modifications=tuple(modifications),
        owned_blocks=frozenset(owned_blocks),
        owned_edges=frozenset(
            (int(anchor), int(shared_entry_serial)) for anchor in anchors
        ),
        safeguard_min_required=len(modifications),
    )


def _prove_and_classify_anchor(
    *,
    flow_graph: object,
    anchor_serial: int,
    shared_entry_serial: int,
    return_block_serial: int,
    suffix_serials: tuple[int, ...],
) -> DirectTerminalLoweringSite | None:
    get_block = getattr(flow_graph, "get_block", None)
    anchor_blk = get_block(anchor_serial) if callable(get_block) else None
    if anchor_blk is None or getattr(anchor_blk, "nsucc", 0) != 1:
        return None
    succs = tuple(int(succ) for succ in getattr(anchor_blk, "succs", ()) or ())
    if len(succs) != 1 or succs[0] != int(shared_entry_serial):
        return None

    interior_serials = tuple(
        int(serial) for serial in suffix_serials if serial != return_block_serial
    )
    if not interior_serials:
        return None

    return DirectTerminalLoweringSite(
        anchor_serial=int(anchor_serial),
        kind=DirectTerminalLoweringKind.CLONE_MATERIALIZER,
        materializer_serials=interior_serials,
    )


def plan_direct_terminal_lowering_execution(
    *,
    flow_graph: object,
    builder,
    anchors: tuple[int, ...],
    shared_entry_serial: int,
    return_block_serial: int,
    suffix_serials: tuple[int, ...],
) -> DirectTerminalLoweringExecutionPlan:
    sites: list[DirectTerminalLoweringSite] = []
    for anchor_serial in anchors:
        site = _prove_and_classify_anchor(
            flow_graph=flow_graph,
            anchor_serial=int(anchor_serial),
            shared_entry_serial=int(shared_entry_serial),
            return_block_serial=int(return_block_serial),
            suffix_serials=tuple(int(serial) for serial in suffix_serials),
        )
        if site is not None:
            sites.append(site)

    supported_sites = tuple(
        site
        for site in sites
        if site.kind
        in (
            DirectTerminalLoweringKind.RETURN_CONST,
            DirectTerminalLoweringKind.CLONE_MATERIALIZER,
        )
    )

    modifications: tuple[object, ...] = ()
    if supported_sites:
        modifications = (
            builder.direct_terminal_lowering(
                sites=list(supported_sites),
                shared_entry_serial=int(shared_entry_serial),
                return_block_serial=int(return_block_serial),
                suffix_serials=tuple(int(serial) for serial in suffix_serials),
            ),
        )

    owned_blocks: set[int] = set(int(anchor) for anchor in anchors)
    owned_blocks.update(int(serial) for serial in suffix_serials)
    owned_blocks.add(int(shared_entry_serial))
    owned_blocks.add(int(return_block_serial))

    return DirectTerminalLoweringExecutionPlan(
        modifications=modifications,
        owned_blocks=frozenset(owned_blocks),
        owned_edges=frozenset(
            (int(anchor), int(shared_entry_serial)) for anchor in anchors
        ),
        sites=tuple(sites),
        supported_sites=supported_sites,
    )


__all__ = [
    "DirectTerminalLoweringExecutionPlan",
    "PrivateTerminalSuffixExecutionPlan",
    "plan_direct_terminal_lowering_execution",
    "plan_private_terminal_suffix_execution",
]
