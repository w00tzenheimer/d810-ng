"""Instruction-granular portable liveness and def-use contracts."""

from __future__ import annotations

from d810.analyses.value_flow.instruction_value_flow import (
    InstructionAccessFacts,
    InstructionFlowGraph,
    analyze_instruction_value_flow,
)
from d810.ir.handles import InsnHandle
from d810.ir.locations import RegisterLocation, StackSlot
from d810.ir.value_refs import (
    DefinitionRef,
    InstructionUseKind,
    InstructionUseRef,
)


def _graph(
    facts: tuple[InstructionAccessFacts, ...],
    successors: dict[int, tuple[int, ...]],
    *,
    entry_nodes: tuple[int, ...] = (0,),
) -> InstructionFlowGraph:
    nodes = tuple(InsnHandle(index) for index in range(len(facts)))
    portable_successors = {
        InsnHandle(node): tuple(InsnHandle(item) for item in targets)
        for node, targets in successors.items()
    }
    predecessors: dict[InsnHandle, list[InsnHandle]] = {node: [] for node in nodes}
    for source, targets in portable_successors.items():
        for target in targets:
            predecessors[target].append(source)
    return InstructionFlowGraph(
        nodes=nodes,
        entry_nodes=tuple(InsnHandle(node) for node in entry_nodes),
        successors_by_node=portable_successors,
        predecessors_by_node={
            node: tuple(sources) for node, sources in predecessors.items()
        },
        facts_by_node={node: facts[int(node)] for node in nodes},
    )


def test_full_overwrite_leaves_first_stack_definition_dead() -> None:
    slot = StackSlot(offset=0x40, size=8)
    result = analyze_instruction_value_flow(
        _graph(
            (
                InstructionAccessFacts(must_defs=frozenset({slot})),
                InstructionAccessFacts(must_defs=frozenset({slot})),
            ),
            {0: (1,), 1: ()},
        ),
        live_at_exit=frozenset(),
    )

    first = DefinitionRef(slot, version=0)
    assert result.is_definition_dead(first) is True
    assert result.def_use.uses_of(first) == ()


def test_explicit_use_wires_def_use_and_keeps_definition_live() -> None:
    slot = StackSlot(offset=0x40, size=8)
    result = analyze_instruction_value_flow(
        _graph(
            (
                InstructionAccessFacts(must_defs=frozenset({slot})),
                InstructionAccessFacts(uses=frozenset({slot})),
            ),
            {0: (1,), 1: ()},
        ),
        live_at_exit=frozenset(),
    )

    definition = DefinitionRef(slot, version=0)
    assert result.is_definition_dead(definition) is False
    assert result.def_use.uses_of(definition) == (
        InstructionUseRef(InsnHandle(1), kind=InstructionUseKind.READ),
    )


def test_partial_definition_is_a_use_and_not_a_kill() -> None:
    slot = StackSlot(offset=0x40, size=8)
    result = analyze_instruction_value_flow(
        _graph(
            (
                InstructionAccessFacts(must_defs=frozenset({slot})),
                InstructionAccessFacts(may_defs=frozenset({slot})),
            ),
            {0: (1,), 1: ()},
        ),
        live_at_exit=frozenset(),
    )

    definition = DefinitionRef(slot, version=0)
    assert result.is_definition_dead(definition) is False
    assert result.def_use.uses_of(definition) == (
        InstructionUseRef(
            InsnHandle(1),
            kind=InstructionUseKind.PARTIAL_DEFINITION,
        ),
    )


def test_use_on_one_branch_keeps_joining_definition_live() -> None:
    slot = StackSlot(offset=0x40, size=8)
    result = analyze_instruction_value_flow(
        _graph(
            (
                InstructionAccessFacts(must_defs=frozenset({slot})),
                InstructionAccessFacts(uses=frozenset({slot})),
                InstructionAccessFacts(),
            ),
            {0: (1, 2), 1: (), 2: ()},
        ),
        live_at_exit=frozenset(),
    )

    assert result.is_definition_dead(DefinitionRef(slot, version=0)) is False


def test_register_is_live_at_exit_while_stack_slot_is_dead() -> None:
    register = RegisterLocation(register_id=7, size=8)
    slot = StackSlot(offset=0x40, size=8)
    result = analyze_instruction_value_flow(
        _graph(
            (
                InstructionAccessFacts(must_defs=frozenset({register})),
                InstructionAccessFacts(must_defs=frozenset({slot})),
            ),
            {0: (1,), 1: ()},
        ),
        live_at_exit=frozenset({register}),
    )

    assert result.is_definition_dead(DefinitionRef(register, version=0)) is False
    assert result.is_definition_dead(DefinitionRef(slot, version=1)) is True


def test_reaching_definitions_from_both_entries_wire_to_join_use() -> None:
    slot = StackSlot(offset=0x40, size=8)
    result = analyze_instruction_value_flow(
        _graph(
            (
                InstructionAccessFacts(must_defs=frozenset({slot})),
                InstructionAccessFacts(must_defs=frozenset({slot})),
                InstructionAccessFacts(uses=frozenset({slot})),
            ),
            {0: (2,), 1: (2,), 2: ()},
            entry_nodes=(0, 1),
        ),
        live_at_exit=frozenset(),
    )

    expected_use = (
        InstructionUseRef(InsnHandle(2), kind=InstructionUseKind.READ),
    )
    assert result.def_use.uses_of(DefinitionRef(slot, version=0)) == expected_use
    assert result.def_use.uses_of(DefinitionRef(slot, version=1)) == expected_use


def test_definition_in_closed_cycle_fails_closed_as_live() -> None:
    slot = StackSlot(offset=0x40, size=8)
    result = analyze_instruction_value_flow(
        _graph(
            (
                InstructionAccessFacts(must_defs=frozenset({slot})),
                InstructionAccessFacts(),
            ),
            {0: (1,), 1: (0,)},
        ),
        live_at_exit=frozenset(),
    )

    assert result.is_definition_dead(DefinitionRef(slot, version=0)) is False
