"""Lift live Hex-Rays instruction CFG and access evidence into portable facts."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.analyses.value_flow.instruction_value_flow import (
    InstructionAccessFacts,
    InstructionFlowGraph,
)
from d810.core.typing import Collection, Mapping
from d810.evaluator.hexrays_microcode.def_search import (
    instruction_defs,
    instruction_uses,
)
from d810.ir.handles import InsnHandle
from d810.ir.locations import RegisterLocation, StackSlot, StorageLocation

__all__ = [
    "LiveInstructionCoordinate",
    "LiveInstructionFlow",
    "LiveInstructionFlowUnavailable",
    "build_live_instruction_flow",
]


class LiveInstructionFlowUnavailable(RuntimeError):
    """Raised when live microcode cannot be represented safely."""


@dataclass(frozen=True, slots=True)
class LiveInstructionCoordinate:
    """Stable-enough diagnostic coordinates for one callback-local handle."""

    block_serial: int
    block_start_ea: int
    ordinal: int
    insn_ea: int
    instruction: object


@dataclass(frozen=True, slots=True)
class LiveInstructionFlow:
    """Portable graph plus the callback-local native coordinate map."""

    graph: InstructionFlowGraph
    coordinates_by_handle: Mapping[InsnHandle, LiveInstructionCoordinate]
    handles_by_coordinate: Mapping[tuple[int, int], InsnHandle]

    def coordinate(self, handle: InsnHandle) -> LiveInstructionCoordinate:
        return self.coordinates_by_handle[handle]

    def handle_for(self, block_serial: int, ordinal: int) -> InsnHandle:
        return self.handles_by_coordinate[(int(block_serial), int(ordinal))]


def _location_mlist(location: StorageLocation) -> "ida_hexrays.mlist_t":
    locations = ida_hexrays.mlist_t()
    if isinstance(location, StackSlot):
        locations.mem.add(ida_hexrays.ivl_t(int(location.offset), int(location.size)))
        return locations
    if isinstance(location, RegisterLocation):
        locations.reg.add(int(location.register_id), int(location.size))
        return locations
    raise LiveInstructionFlowUnavailable(
        f"unsupported live instruction location: {type(location).__name__}"
    )


def _block_start_ea(block: object) -> int:
    try:
        return max(0, int(block.start))
    except (AttributeError, TypeError, ValueError):
        return -1


def _iter_instructions(block: object):
    instruction = block.head
    visited: set[int] = set()
    while instruction is not None:
        try:
            identity = int(instruction.this)
        except (AttributeError, TypeError, ValueError):
            identity = id(instruction)
        if identity in visited:
            raise LiveInstructionFlowUnavailable(
                "live instruction chain contains a cycle"
            )
        visited.add(identity)
        yield instruction
        instruction = instruction.next


def _access_facts(
    block: object,
    instruction: object,
    tracked: tuple[StorageLocation, ...],
    location_lists: Mapping[StorageLocation, object],
) -> InstructionAccessFacts:
    exact_uses = instruction_uses(block, instruction, ida_hexrays.MUST_ACCESS)
    possible_uses = instruction_uses(block, instruction, ida_hexrays.MAY_ACCESS)
    exact_defs = instruction_defs(block, instruction, ida_hexrays.MUST_ACCESS)
    possible_defs = instruction_defs(block, instruction, ida_hexrays.MAY_ACCESS)

    uses: set[StorageLocation] = set()
    must_defs: set[StorageLocation] = set()
    may_defs: set[StorageLocation] = set()
    for location in tracked:
        native_location = location_lists[location]
        use_list = exact_uses if isinstance(location, StackSlot) else possible_uses
        def_list = exact_defs if isinstance(location, StackSlot) else possible_defs
        if use_list.has_common(native_location):
            uses.add(location)
        if exact_defs.includes(native_location):
            must_defs.add(location)
        if def_list.has_common(native_location):
            may_defs.add(location)
    return InstructionAccessFacts(
        uses=frozenset(uses),
        must_defs=frozenset(must_defs),
        may_defs=frozenset(may_defs),
    )


def build_live_instruction_flow(
    mba: object,
    tracked_locations: Collection[StorageLocation],
    *,
    native_locations: Mapping[StorageLocation, object] | None = None,
) -> LiveInstructionFlow:
    """Build one callback-local portable instruction graph from live microcode."""
    tracked = tuple(dict.fromkeys(tracked_locations))
    provided_locations = native_locations or {}
    location_lists = {
        location: (
            provided_locations[location]
            if location in provided_locations
            else _location_mlist(location)
        )
        for location in tracked
    }
    try:
        mba.build_graph()
        quantity = int(mba.qty)
        blocks = {serial: mba.get_mblock(serial) for serial in range(quantity)}
        if any(block is None for block in blocks.values()):
            raise LiveInstructionFlowUnavailable(
                "live instruction CFG contains an unavailable block"
            )

        coordinates: dict[InsnHandle, LiveInstructionCoordinate] = {}
        handles: dict[tuple[int, int], InsnHandle] = {}
        first_handle: dict[int, InsnHandle] = {}
        last_handle: dict[int, InsnHandle] = {}
        facts: dict[InsnHandle, InstructionAccessFacts] = {}
        nodes: list[InsnHandle] = []

        for serial, block in blocks.items():
            block.make_lists_ready()
            for ordinal, instruction in enumerate(_iter_instructions(block)):
                handle = InsnHandle(len(nodes))
                nodes.append(handle)
                handles[(serial, ordinal)] = handle
                first_handle.setdefault(serial, handle)
                last_handle[serial] = handle
                coordinates[handle] = LiveInstructionCoordinate(
                    block_serial=serial,
                    block_start_ea=_block_start_ea(block),
                    ordinal=ordinal,
                    insn_ea=int(instruction.ea),
                    instruction=instruction,
                )
                facts[handle] = _access_facts(
                    block, instruction, tracked, location_lists
                )

        if not nodes:
            raise LiveInstructionFlowUnavailable(
                "live instruction CFG contains no instructions"
            )

        def routed_heads(
            serial: int, visiting: frozenset[int]
        ) -> tuple[InsnHandle, ...]:
            if serial in first_handle:
                return (first_handle[serial],)
            if serial in visiting:
                return ()
            block = blocks.get(serial)
            if block is None:
                return ()
            found: list[InsnHandle] = []
            nested = visiting | {serial}
            for index in range(int(block.nsucc())):
                successor = int(block.succ(index))
                for handle in routed_heads(successor, nested):
                    if handle not in found:
                        found.append(handle)
            return tuple(found)

        successors: dict[InsnHandle, tuple[InsnHandle, ...]] = {}
        for serial, block in blocks.items():
            block_handles = [
                handles[(serial, ordinal)]
                for ordinal, _ in enumerate(_iter_instructions(block))
            ]
            for current, following in zip(block_handles, block_handles[1:]):
                successors[current] = (following,)
            if block_handles:
                targets: list[InsnHandle] = []
                for index in range(int(block.nsucc())):
                    successor = int(block.succ(index))
                    for target in routed_heads(successor, frozenset()):
                        if target not in targets:
                            targets.append(target)
                successors[last_handle[serial]] = tuple(targets)

        entry_nodes = routed_heads(0, frozenset())
        if not entry_nodes:
            raise LiveInstructionFlowUnavailable(
                "live instruction CFG has no instruction entry"
            )
        predecessors: dict[InsnHandle, list[InsnHandle]] = {node: [] for node in nodes}
        for source, targets in successors.items():
            for target in targets:
                predecessors[target].append(source)

        return LiveInstructionFlow(
            graph=InstructionFlowGraph(
                nodes=tuple(nodes),
                entry_nodes=entry_nodes,
                successors_by_node=successors,
                predecessors_by_node={
                    node: tuple(sources) for node, sources in predecessors.items()
                },
                facts_by_node=facts,
            ),
            coordinates_by_handle=coordinates,
            handles_by_coordinate=handles,
        )
    except LiveInstructionFlowUnavailable:
        raise
    except (AttributeError, RuntimeError, TypeError, ValueError) as exc:
        raise LiveInstructionFlowUnavailable(
            f"live instruction evidence unavailable: {exc}"
        ) from exc
