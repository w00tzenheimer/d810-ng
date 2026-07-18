"""Plan a resolver-evidenced native semantic closure."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from d810.core.typing import Collection, Mapping


class NativeEdgeKind(str, Enum):
    """Native control-flow relation observed at a block boundary."""

    DIRECT_JUMP = "direct_jump"
    FALLTHROUGH = "fallthrough"
    CONDITIONAL_TRUE = "conditional_true"
    CONDITIONAL_FALSE = "conditional_false"
    CALL = "call"
    INDIRECT = "indirect"


class NativeTerminalKind(str, Enum):
    """Terminal classification retained from the native CFG evidence."""

    NONE = "none"
    RETURN = "return"
    TAIL_CALL = "tail_call"
    STOP = "stop"


class ClosureAbstentionReason(str, Enum):
    """Reasons the planner deliberately excludes a requested relation."""

    UNPROVEN_INDIRECT_TARGET = "unproven_indirect_target"
    UNRESOLVED_DEPENDENCY = "unresolved_dependency"
    AMBIGUOUS_DEPENDENCY = "ambiguous_dependency"
    MISSING_CFG_BLOCK = "missing_cfg_block"


@dataclass(frozen=True)
class NativeEdge:
    """A typed outgoing relation from a native block."""

    kind: NativeEdgeKind
    target_ea: int | None = None
    resolver_proven: bool = False
    provenance: str | None = None
    source_instruction_ea: int | None = None


@dataclass(frozen=True)
class NativeBlock:
    """A native basic block keyed by its stable entry EA."""

    start_ea: int
    end_ea: int
    outgoing_edges: tuple[NativeEdge, ...] = ()
    dependency_eas: tuple[int, ...] = ()
    terminal: NativeTerminalKind = NativeTerminalKind.NONE

    def __post_init__(self) -> None:
        if self.end_ea <= self.start_ea:
            raise ValueError("native block range must be non-empty")


@dataclass(frozen=True)
class NativeCfg:
    """Immutable native CFG indexed by stable block entry EA."""

    blocks_by_ea: Mapping[int, NativeBlock]

    def __post_init__(self) -> None:
        blocks = dict(self.blocks_by_ea)
        for entry_ea, block in blocks.items():
            if entry_ea != block.start_ea:
                raise ValueError("native CFG key must match block start EA")
        object.__setattr__(self, "blocks_by_ea", MappingProxyType(blocks))


@dataclass(frozen=True)
class ResolverProvenHandlerEntry:
    """A handler entry EA with resolver evidence retained for reporting."""

    entry_ea: int
    provenance: str


@dataclass(frozen=True)
class ResolverProvenDependencyDefinition:
    """Resolver-proven defining block for one requested dependency EA."""

    dependency_ea: int
    defining_block_ea: int
    provenance: str


@dataclass(frozen=True)
class NativeRange:
    """A half-open native range suitable for mba_ranges_t construction."""

    start_ea: int
    end_ea: int


@dataclass(frozen=True)
class ProvenInternalEdge:
    """A proven control-flow relation whose endpoints are in this closure."""

    source_ea: int
    target_ea: int
    kind: NativeEdgeKind
    provenance: str | None = None


@dataclass(frozen=True)
class ProvenImportBoundaryEdge:
    """Proven edge that generated ranges cannot express without import wiring."""

    source_ea: int
    source_instruction_ea: int | None
    target_ea: int
    kind: NativeEdgeKind
    provenance: str | None = None


@dataclass(frozen=True)
class ClosureAbstention:
    """An explicit cut point the planner declines to cross."""

    reason: ClosureAbstentionReason
    source_block_ea: int | None
    target_ea: int | None = None
    dependency_ea: int | None = None


@dataclass(frozen=True)
class NativeSemanticClosure:
    """The complete pure closure plan for one PREOPT range construction.

    ``proven_internal_edges`` is evidence for the CFG Hex-Rays constructs from
    the single generated range set. An adapter must not re-add those edges.
    ``proven_import_boundary_edges`` contains only typed outgoing edges whose
    target is either another resolver-proven closure block or explicitly
    allowlisted as belonging to the live import graph.
    """

    included_block_eas: tuple[int, ...]
    native_ranges: tuple[NativeRange, ...]
    proven_internal_edges: tuple[ProvenInternalEdge, ...]
    abstentions: tuple[ClosureAbstention, ...]
    seed_provenance: tuple[ResolverProvenHandlerEntry, ...]
    proven_import_boundary_edges: tuple[ProvenImportBoundaryEdge, ...] = ()


_TRAVERSED_EDGE_KINDS = frozenset(
    {
        NativeEdgeKind.DIRECT_JUMP,
        NativeEdgeKind.FALLTHROUGH,
        NativeEdgeKind.CONDITIONAL_TRUE,
        NativeEdgeKind.CONDITIONAL_FALSE,
    }
)


def _merge_ranges(blocks: tuple[NativeBlock, ...]) -> tuple[NativeRange, ...]:
    merged: list[NativeRange] = []
    for block in sorted(blocks, key=lambda item: (item.start_ea, item.end_ea)):
        if not merged or block.start_ea > merged[-1].end_ea:
            merged.append(NativeRange(block.start_ea, block.end_ea))
            continue
        previous = merged[-1]
        merged[-1] = NativeRange(previous.start_ea, max(previous.end_ea, block.end_ea))
    return tuple(merged)


def plan_native_generation_ranges(
    closure: NativeSemanticClosure,
    *,
    required_entry_eas: Collection[int] = (),
) -> tuple[NativeRange, ...]:
    """Adapt semantic ownership ranges to Hex-Rays snippet range rules.

    Hex-Rays rejects a snippet fragment whose only terminal is an
    unconditional transfer into another fragment, even when both fragments are
    present in the same ``mba_ranges_t``.  Coalesce only components connected
    by unconditional direct flow into contiguous generation envelopes.

    These envelopes are source-generation inputs, not ownership.  Importers
    must continue to select blocks through ``closure.included_block_eas`` so
    native code that merely lies inside an envelope is never imported.

    ``required_entry_eas`` are both split points and generation roots.  Their
    ranges are placed first because Hex-Rays can retain a later range only as
    an empty external placeholder even when that range is otherwise valid in
    isolation.
    """
    ranges = closure.native_ranges

    parents = list(range(len(ranges)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    def containing_range_index(ea: int) -> int | None:
        for index, native_range in enumerate(ranges):
            if native_range.start_ea <= ea < native_range.end_ea:
                return index
        return None

    if len(ranges) >= 2:
        for edge in closure.proven_internal_edges:
            if edge.kind not in {
                NativeEdgeKind.DIRECT_JUMP,
                NativeEdgeKind.FALLTHROUGH,
            }:
                continue
            source_index = containing_range_index(edge.source_ea)
            target_index = containing_range_index(edge.target_ea)
            if source_index is None or target_index is None:
                continue
            union(source_index, target_index)

    grouped: dict[int, list[NativeRange]] = {}
    for index, native_range in enumerate(ranges):
        grouped.setdefault(find(index), []).append(native_range)
    envelopes = tuple(
        NativeRange(
            min(native_range.start_ea for native_range in component),
            max(native_range.end_ea for native_range in component),
        )
        for component in grouped.values()
    )

    merged: list[NativeRange] = []
    for envelope in sorted(envelopes, key=lambda item: (item.start_ea, item.end_ea)):
        if not merged or envelope.start_ea > merged[-1].end_ea:
            merged.append(envelope)
            continue
        previous = merged[-1]
        merged[-1] = NativeRange(
            previous.start_ea,
            max(previous.end_ea, envelope.end_ea),
        )
    required_entries = {int(ea) for ea in required_entry_eas}
    split_ranges: list[NativeRange] = []
    for native_range in merged:
        cuts = (
            int(native_range.start_ea),
            *sorted(
                ea
                for ea in required_entries
                if int(native_range.start_ea) < ea < int(native_range.end_ea)
            ),
            int(native_range.end_ea),
        )
        split_ranges.extend(
            NativeRange(start_ea, end_ea)
            for start_ea, end_ea in zip(cuts, cuts[1:])
        )
    required_roots = tuple(
        native_range
        for native_range in split_ranges
        if int(native_range.start_ea) in required_entries
    )
    other_ranges = tuple(
        native_range
        for native_range in split_ranges
        if int(native_range.start_ea) not in required_entries
    )
    return required_roots + other_ranges


def _sorted_abstentions(
    abstentions: set[ClosureAbstention],
) -> tuple[ClosureAbstention, ...]:
    return tuple(
        sorted(
            abstentions,
            key=lambda item: (
                item.source_block_ea is None,
                item.source_block_ea or 0,
                item.target_ea is None,
                item.target_ea or 0,
                item.dependency_ea is None,
                item.dependency_ea or 0,
                item.reason.value,
            ),
        )
    )


def plan_native_semantic_closure(
    cfg: NativeCfg,
    seeds: tuple[ResolverProvenHandlerEntry, ...],
    definitions: tuple[ResolverProvenDependencyDefinition, ...] = (),
    *,
    import_boundary_target_eas: Collection[int] = (),
) -> NativeSemanticClosure:
    """Build a native closure without crossing an unproven control-flow edge."""

    definitions_by_dependency: dict[
        int, set[ResolverProvenDependencyDefinition]
    ] = {}
    for definition in definitions:
        definitions_by_dependency.setdefault(definition.dependency_ea, set()).add(
            definition
        )

    included: set[int] = set()
    internal_edges: set[ProvenInternalEdge] = set()
    boundary_edges: set[ProvenImportBoundaryEdge] = set()
    abstentions: set[ClosureAbstention] = set()
    import_boundary_targets = {
        int(target_ea) for target_ea in import_boundary_target_eas
    }
    pending = deque(sorted({seed.entry_ea for seed in seeds}))

    while pending:
        entry_ea = pending.popleft()
        if entry_ea in included:
            continue
        block = cfg.blocks_by_ea.get(entry_ea)
        if block is None:
            abstentions.add(
                ClosureAbstention(
                    ClosureAbstentionReason.MISSING_CFG_BLOCK,
                    None,
                    target_ea=entry_ea,
                )
            )
            continue

        included.add(entry_ea)
        if block.terminal in {
            NativeTerminalKind.RETURN,
            NativeTerminalKind.TAIL_CALL,
        }:
            continue

        for edge in block.outgoing_edges:
            if edge.kind is NativeEdgeKind.CALL:
                continue
            if edge.kind is NativeEdgeKind.INDIRECT:
                if not edge.resolver_proven:
                    abstentions.add(
                        ClosureAbstention(
                            ClosureAbstentionReason.UNPROVEN_INDIRECT_TARGET,
                            entry_ea,
                            target_ea=edge.target_ea,
                        )
                    )
                    continue
                target_ea = edge.target_ea
                if target_ea is None or (
                    int(target_ea) not in cfg.blocks_by_ea
                    and int(target_ea) not in import_boundary_targets
                ):
                    abstentions.add(
                        ClosureAbstention(
                            ClosureAbstentionReason.MISSING_CFG_BLOCK,
                            entry_ea,
                            target_ea=target_ea,
                        )
                    )
                    continue
                boundary_edges.add(
                    ProvenImportBoundaryEdge(
                        source_ea=entry_ea,
                        source_instruction_ea=edge.source_instruction_ea,
                        target_ea=int(target_ea),
                        kind=edge.kind,
                        provenance=edge.provenance,
                    )
                )
                continue
            elif edge.kind not in _TRAVERSED_EDGE_KINDS:
                continue

            target_ea = edge.target_ea
            if target_ea is not None and int(target_ea) in import_boundary_targets:
                boundary_edges.add(
                    ProvenImportBoundaryEdge(
                        source_ea=entry_ea,
                        source_instruction_ea=edge.source_instruction_ea,
                        target_ea=int(target_ea),
                        kind=edge.kind,
                        provenance=edge.provenance,
                    )
                )
                continue
            if block.terminal is NativeTerminalKind.STOP:
                if target_ea is None or target_ea not in cfg.blocks_by_ea:
                    abstentions.add(
                        ClosureAbstention(
                            ClosureAbstentionReason.MISSING_CFG_BLOCK,
                            entry_ea,
                            target_ea=target_ea,
                        )
                    )
                continue
            if target_ea is None or target_ea not in cfg.blocks_by_ea:
                abstentions.add(
                    ClosureAbstention(
                        ClosureAbstentionReason.MISSING_CFG_BLOCK,
                        entry_ea,
                        target_ea=target_ea,
                    )
                )
                continue
            internal_edges.add(
                ProvenInternalEdge(
                    entry_ea,
                    target_ea,
                    edge.kind,
                    edge.provenance,
                )
            )
            pending.append(target_ea)

        for dependency_ea in block.dependency_eas:
            candidates = definitions_by_dependency.get(dependency_ea, set())
            defining_blocks = {candidate.defining_block_ea for candidate in candidates}
            if not defining_blocks:
                abstentions.add(
                    ClosureAbstention(
                        ClosureAbstentionReason.UNRESOLVED_DEPENDENCY,
                        entry_ea,
                        dependency_ea=dependency_ea,
                    )
                )
                continue
            if len(defining_blocks) != 1:
                abstentions.add(
                    ClosureAbstention(
                        ClosureAbstentionReason.AMBIGUOUS_DEPENDENCY,
                        entry_ea,
                        dependency_ea=dependency_ea,
                    )
                )
                continue

            defining_block_ea = next(iter(defining_blocks))
            if defining_block_ea not in cfg.blocks_by_ea:
                abstentions.add(
                    ClosureAbstention(
                        ClosureAbstentionReason.UNRESOLVED_DEPENDENCY,
                        entry_ea,
                        target_ea=defining_block_ea,
                        dependency_ea=dependency_ea,
                    )
                )
                continue
            pending.append(defining_block_ea)

    included_blocks = tuple(
        cfg.blocks_by_ea[entry_ea] for entry_ea in sorted(included)
    )
    return NativeSemanticClosure(
        included_block_eas=tuple(sorted(included)),
        native_ranges=_merge_ranges(included_blocks),
        proven_internal_edges=tuple(
            sorted(
                internal_edges,
                key=lambda item: (
                    item.source_ea,
                    item.target_ea,
                    item.kind.value,
                    item.provenance or "",
                ),
            )
        ),
        abstentions=_sorted_abstentions(abstentions),
        seed_provenance=tuple(seeds),
        proven_import_boundary_edges=tuple(
            sorted(
                boundary_edges,
                key=lambda item: (
                    item.source_ea,
                    item.source_instruction_ea is None,
                    item.source_instruction_ea or 0,
                    item.target_ea,
                    item.kind.value,
                    item.provenance or "",
                ),
            )
        ),
    )
