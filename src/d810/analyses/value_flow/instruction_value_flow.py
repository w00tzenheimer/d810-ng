"""Instruction-granular portable liveness and definition-to-use analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.analyses.data_flow.configuration import Direction, FixpointConfiguration
from d810.analyses.data_flow.worklist import run_fixpoint
from d810.analyses.value_flow.def_use import DefUseFacts
from d810.analyses.value_flow.liveness import BlockLivenessFacts, LivenessDomain
from d810.analyses.value_flow.reaching_defs import (
    BlockReachingFacts,
    ReachingDefsDomain,
    reaching_defs_of,
)
from d810.core.typing import Mapping
from d810.ir.handles import InsnHandle
from d810.ir.locations import StorageLocation
from d810.ir.value_refs import (
    DefinitionRef,
    InstructionUseKind,
    InstructionUseRef,
)

__all__ = [
    "InstructionAccessFacts",
    "InstructionFlowGraph",
    "InstructionValueFlowResult",
    "analyze_instruction_value_flow",
]

_MIN_FIXPOINT_ITERATIONS = 1_000
_MAX_FIXPOINT_ITERATIONS = 1_000_000


def _fixpoint_configuration(
    *,
    direction: Direction,
    node_count: int,
    lattice_height: int,
) -> FixpointConfiguration:
    """Budget a finite-height bitvector analysis from its actual dimensions."""
    required = max(1, int(node_count)) * (max(1, int(lattice_height)) + 1)
    return FixpointConfiguration(
        direction=direction,
        max_iterations=min(
            _MAX_FIXPOINT_ITERATIONS,
            max(_MIN_FIXPOINT_ITERATIONS, required),
        ),
    )


@dataclass(frozen=True, slots=True)
class InstructionAccessFacts:
    """Exact tracked-location accesses made by one instruction."""

    uses: frozenset[StorageLocation] = field(default_factory=frozenset)
    must_defs: frozenset[StorageLocation] = field(default_factory=frozenset)
    may_defs: frozenset[StorageLocation] = field(default_factory=frozenset)

    @property
    def partial_defs(self) -> frozenset[StorageLocation]:
        """Locations touched without a proven full overwrite."""
        return self.may_defs - self.must_defs


@dataclass(frozen=True, slots=True)
class InstructionFlowGraph:
    """Callback-local instruction topology and access facts."""

    nodes: tuple[InsnHandle, ...]
    entry_nodes: tuple[InsnHandle, ...]
    successors_by_node: Mapping[InsnHandle, tuple[InsnHandle, ...]]
    predecessors_by_node: Mapping[InsnHandle, tuple[InsnHandle, ...]]
    facts_by_node: Mapping[InsnHandle, InstructionAccessFacts]

    def successors(self, node: InsnHandle) -> tuple[InsnHandle, ...]:
        return tuple(self.successors_by_node.get(node, ()))

    def predecessors(self, node: InsnHandle) -> tuple[InsnHandle, ...]:
        return tuple(self.predecessors_by_node.get(node, ()))

    @property
    def exit_nodes(self) -> tuple[InsnHandle, ...]:
        return tuple(node for node in self.nodes if not self.successors(node))


@dataclass(frozen=True, slots=True)
class InstructionValueFlowResult:
    """Liveness and def-use results over one instruction graph."""

    live_out: Mapping[InsnHandle, frozenset[StorageLocation]]
    def_use: DefUseFacts
    definitions: frozenset[DefinitionRef]

    def is_definition_dead(self, definition: DefinitionRef) -> bool:
        """Return whether a known definition has no explicit or implicit use."""
        if definition not in self.definitions:
            return False
        node = InsnHandle(int(definition.version))
        return not self.def_use.has_uses(
            definition
        ) and definition.location not in self.live_out.get(node, frozenset())


def _liveness_facts(
    graph: InstructionFlowGraph,
) -> dict[InsnHandle, BlockLivenessFacts]:
    return {
        node: BlockLivenessFacts(
            used=facts.uses | facts.partial_defs,
            defined=facts.must_defs,
        )
        for node, facts in graph.facts_by_node.items()
        if facts.uses or facts.must_defs or facts.may_defs
    }


def _reaching_facts(
    graph: InstructionFlowGraph,
) -> tuple[dict[InsnHandle, BlockReachingFacts], frozenset[DefinitionRef]]:
    facts_by_node: dict[InsnHandle, BlockReachingFacts] = {}
    definitions: set[DefinitionRef] = set()
    for node, access in graph.facts_by_node.items():
        generated = {
            location: frozenset({DefinitionRef(location=location, version=int(node))})
            for location in access.must_defs
        }
        definitions.update(site for sites in generated.values() for site in sites)
        if generated:
            facts_by_node[node] = BlockReachingFacts(gen=generated)
    return facts_by_node, frozenset(definitions)


def _nodes_reaching_exit(graph: InstructionFlowGraph) -> frozenset[InsnHandle]:
    """Return nodes with at least one finite path to a function exit."""
    reachable = set(graph.exit_nodes)
    pending = list(graph.exit_nodes)
    while pending:
        node = pending.pop()
        for predecessor in graph.predecessors(node):
            if predecessor not in reachable:
                reachable.add(predecessor)
                pending.append(predecessor)
    return frozenset(reachable)


def analyze_instruction_value_flow(
    graph: InstructionFlowGraph,
    *,
    live_at_exit: frozenset[StorageLocation],
) -> InstructionValueFlowResult:
    """Solve liveness and reaching definitions once over an instruction CFG."""
    if not graph.nodes:
        raise ValueError("instruction value flow requires at least one node")
    node_set = frozenset(graph.nodes)
    if not graph.entry_nodes or not frozenset(graph.entry_nodes) <= node_set:
        raise ValueError("instruction value flow requires valid entry nodes")

    liveness_facts = _liveness_facts(graph)
    liveness_locations = set(live_at_exit)
    for facts in liveness_facts.values():
        liveness_locations.update(facts.used)
        liveness_locations.update(facts.defined)
    liveness = run_fixpoint(
        LivenessDomain(liveness_facts),
        nodes=graph.nodes,
        entry_nodes=graph.exit_nodes,
        entry_state=live_at_exit,
        successors_of=graph.successors,
        predecessors_of=graph.predecessors,
        config=_fixpoint_configuration(
            direction=Direction.BACKWARD,
            node_count=len(graph.nodes),
            lattice_height=len(liveness_locations),
        ),
        raise_on_nonconvergence=True,
    )

    reaching_facts, definitions = _reaching_facts(graph)
    reaching = run_fixpoint(
        ReachingDefsDomain(reaching_facts),
        nodes=graph.nodes,
        entry_nodes=graph.entry_nodes,
        successors_of=graph.successors,
        predecessors_of=graph.predecessors,
        config=_fixpoint_configuration(
            direction=Direction.FORWARD,
            node_count=len(graph.nodes),
            lattice_height=len(definitions),
        ),
        raise_on_nonconvergence=True,
    )

    uses_by_def: dict[DefinitionRef, list[InstructionUseRef]] = {}
    for node in graph.nodes:
        access = graph.facts_by_node.get(node, InstructionAccessFacts())
        occurrences = (
            (access.uses, InstructionUseKind.READ),
            (access.partial_defs, InstructionUseKind.PARTIAL_DEFINITION),
        )
        for locations, kind in occurrences:
            for location in locations:
                use = InstructionUseRef(node, kind=kind)
                for definition in reaching_defs_of(reaching.in_states[node], location):
                    consumers = uses_by_def.setdefault(definition, [])
                    if use not in consumers:
                        consumers.append(use)

    tracked_locations = set(live_at_exit)
    for access in graph.facts_by_node.values():
        tracked_locations.update(access.uses)
        tracked_locations.update(access.must_defs)
        tracked_locations.update(access.may_defs)
    reaches_exit = _nodes_reaching_exit(graph)

    return InstructionValueFlowResult(
        live_out={
            node: (
                liveness.in_states[node]
                if node in reaches_exit
                else frozenset(tracked_locations)
            )
            for node in graph.nodes
        },
        def_use=DefUseFacts(
            uses_by_def={
                definition: tuple(uses) for definition, uses in uses_by_def.items()
            }
        ),
        definitions=definitions,
    )
