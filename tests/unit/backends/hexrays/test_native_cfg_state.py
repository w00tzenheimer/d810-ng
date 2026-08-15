"""Fail-closed machine-state proofs for native CFG edge relinking."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.backends.hexrays.native_cfg_state import (
    HexRaysNativeEdgeStateProof,
    NativeFlagAccessStep,
    prove_target_flag_independence,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot

pytestmark = pytest.mark.pure_python


class _List:
    def __init__(self, *tokens: str) -> None:
        self.tokens = frozenset(tokens)

    def has_common(self, other: "_List") -> bool:
        return bool(self.tokens & other.tokens)

    def empty(self) -> bool:
        return not self.tokens

    def dstr(self) -> str:
        return ",".join(sorted(self.tokens))


@dataclass
class _LiveBlock:
    maybuse: _List
    maybdef: _List

    def make_lists_ready(self) -> None:
        return None


class _Mba:
    entry_ea = 0x1000

    def __init__(self, blocks: dict[int, _LiveBlock]) -> None:
        self.blocks = blocks

    def get_mblock(self, serial: int):
        return self.blocks.get(serial)


def _block(
    serial: int,
    successors: tuple[int, ...],
    ea: int,
    *,
    kind: InsnKind,
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=successors,
        preds=(),
        flags=0,
        start_ea=ea,
        native_start_ea=ea,
        insn_snapshots=(
            InsnSnapshot(
                opcode=1,
                ea=ea,
                native_ea=ea,
                operands=(),
                kind=kind,
            ),
        ),
    )


def _graph(corridor_kind: InsnKind = InsnKind.MOV) -> FlowGraph:
    return FlowGraph(
        blocks={
            0: _block(0, (1,), 0x1000, kind=InsnKind.GOTO),
            1: _block(1, (2,), 0x1010, kind=corridor_kind),
            2: _block(2, (), 0x1020, kind=InsnKind.RET),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


def _provider(
    *,
    corridor_defs: tuple[str, ...] = ("dispatcher-state",),
    target_uses: tuple[str, ...] = ("r0",),
    source_spd: int = 0,
    target_spd: int = 0,
    target_reads_flags: bool = False,
) -> HexRaysNativeEdgeStateProof:
    mba = _Mba(
        {
            0: _LiveBlock(_List(), _List()),
            1: _LiveBlock(_List(), _List(*corridor_defs)),
            2: _LiveBlock(_List(*target_uses), _List()),
        }
    )
    spd_by_ea = {0x1000: source_spd, 0x1020: target_spd}
    return HexRaysNativeEdgeStateProof(
        mba,
        stack_delta_for_ea=lambda ea: spd_by_ea.get(ea),
        target_reads_flags=lambda ea: target_reads_flags,
    )


def _prove(provider, graph=None):
    return provider.prove_edge_transition(
        graph=_graph() if graph is None else graph,
        source_block=0,
        inherited_successors=(1,),
        final_successors=(2,),
        semantic_proof_ids=("semantic-route-7",),
    )


def test_dead_dispatcher_state_definition_receives_positive_contract() -> None:
    contract = _prove(_provider())

    assert contract is not None
    assert contract.permits_control_only_relink is True
    assert "semantic-route-7" in contract.proof_ids
    assert contract.unpersisted_body_effects == contract.proven_dead_body_effects
    assert contract.required_target_inputs == contract.proven_equivalent_inputs


@pytest.mark.parametrize(
    "provider",
    (
        _provider(corridor_defs=("r0",)),
        _provider(source_spd=0, target_spd=8),
        _provider(target_reads_flags=True),
    ),
)
def test_live_definition_stack_or_flags_abstain(provider) -> None:
    assert _prove(provider) is None


@pytest.mark.parametrize("kind", (InsnKind.CALL, InsnKind.STORE, InsnKind.UNKNOWN))
def test_observable_or_unresolved_corridor_effect_abstains(kind: InsnKind) -> None:
    assert _prove(_provider(), _graph(kind)) is None


def test_existing_selected_edge_needs_no_bypassed_corridor() -> None:
    original = _graph()
    graph = FlowGraph(
        blocks={
            **original.blocks,
            0: _block(0, (1, 2), 0x1000, kind=InsnKind.COND_JUMP),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    provider = _provider(corridor_defs=("r0",))

    contract = provider.prove_edge_transition(
        graph=graph,
        source_block=0,
        inherited_successors=(1, 2),
        final_successors=(2,),
        semantic_proof_ids=("opaque-predicate",),
    )

    assert contract is not None
    assert contract.permits_control_only_relink is True


def test_direct_dispatch_route_does_not_absorb_cyclic_siblings() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(0, (1,), 0x1000, kind=InsnKind.GOTO),
            1: _block(1, (0, 2, 3), 0x1010, kind=InsnKind.TABLE_JUMP),
            2: _block(2, (), 0x1020, kind=InsnKind.RET),
            3: _block(3, (1,), 0x1030, kind=InsnKind.UNKNOWN),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    provider = HexRaysNativeEdgeStateProof(
        _Mba(
            {
                0: _LiveBlock(_List(), _List()),
                1: _LiveBlock(_List(), _List("dispatcher-state")),
                2: _LiveBlock(_List("r0"), _List()),
                3: _LiveBlock(_List(), _List("observable")),
            }
        ),
        stack_delta_for_ea=lambda _ea: 0,
        target_reads_flags=lambda _ea: False,
    )

    contract = provider.prove_edge_transition(
        graph=graph,
        source_block=0,
        inherited_successors=(1,),
        final_successors=(2,),
        semantic_proof_ids=("direct-dispatch-route",),
    )

    assert contract is not None
    assert contract.permits_control_only_relink is True


def test_deterministic_prefix_to_dispatch_route_is_the_only_bypassed_corridor() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(0, (1,), 0x1000, kind=InsnKind.GOTO),
            1: _block(1, (4,), 0x1010, kind=InsnKind.GOTO),
            2: _block(2, (), 0x1020, kind=InsnKind.RET),
            3: _block(3, (4,), 0x1030, kind=InsnKind.UNKNOWN),
            4: _block(4, (0, 2, 3), 0x1040, kind=InsnKind.TABLE_JUMP),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    provider = HexRaysNativeEdgeStateProof(
        _Mba(
            {
                0: _LiveBlock(_List(), _List()),
                1: _LiveBlock(_List(), _List()),
                2: _LiveBlock(_List("r0"), _List()),
                3: _LiveBlock(_List(), _List("observable")),
                4: _LiveBlock(_List(), _List("dispatcher-state")),
            }
        ),
        stack_delta_for_ea=lambda _ea: 0,
        target_reads_flags=lambda _ea: False,
    )

    contract = provider.prove_edge_transition(
        graph=graph,
        source_block=0,
        inherited_successors=(1,),
        final_successors=(2,),
        semantic_proof_ids=("deterministic-dispatch-route",),
    )

    assert contract is not None
    assert contract.permits_control_only_relink is True


def test_longer_acyclic_route_to_target_forces_abstention() -> None:
    graph = FlowGraph(
        blocks={
            0: _block(0, (1,), 0x1000, kind=InsnKind.GOTO),
            1: _block(1, (2, 3), 0x1010, kind=InsnKind.COND_JUMP),
            2: _block(2, (), 0x1020, kind=InsnKind.RET),
            3: _block(3, (4,), 0x1030, kind=InsnKind.GOTO),
            4: _block(4, (2,), 0x1040, kind=InsnKind.GOTO),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    provider = HexRaysNativeEdgeStateProof(
        _Mba({serial: _LiveBlock(_List(), _List()) for serial in graph.blocks}),
        stack_delta_for_ea=lambda _ea: 0,
        target_reads_flags=lambda _ea: False,
    )

    contract = provider.prove_edge_transition(
        graph=graph,
        source_block=0,
        inherited_successors=(1,),
        final_successors=(2,),
        semantic_proof_ids=("ambiguous-dispatch-route",),
    )

    assert contract is None


def test_target_prefix_rejects_flag_read_after_flag_preserving_instructions() -> None:
    steps = {
        0x1000: NativeFlagAccessStep(0x1001, reads_flags=False, writes_flags=False),
        0x1001: NativeFlagAccessStep(0x1002, reads_flags=False, writes_flags=False),
        0x1002: NativeFlagAccessStep(0x1003, reads_flags=True, writes_flags=False),
    }

    assert (
        prove_target_flag_independence(0x1000, inspect=lambda ea: steps.get(ea))
        is False
    )


def test_target_prefix_accepts_definite_flag_kill_before_any_read() -> None:
    steps = {
        0x1000: NativeFlagAccessStep(0x1001, reads_flags=False, writes_flags=False),
        0x1001: NativeFlagAccessStep(0x1002, reads_flags=False, writes_flags=True),
    }

    assert prove_target_flag_independence(0x1000, inspect=lambda ea: steps.get(ea))


def test_target_prefix_follows_direct_jump_before_definite_flag_kill() -> None:
    steps = {
        0x1000: NativeFlagAccessStep(0x2000, reads_flags=False, writes_flags=False),
        0x2000: NativeFlagAccessStep(0x2001, reads_flags=False, writes_flags=True),
    }

    assert prove_target_flag_independence(0x1000, inspect=lambda ea: steps.get(ea))


def test_target_prefix_follows_backward_direct_jump_before_flag_kill() -> None:
    steps = {
        0x2000: NativeFlagAccessStep(0x1000, reads_flags=False, writes_flags=False),
        0x1000: NativeFlagAccessStep(0x1001, reads_flags=False, writes_flags=True),
    }

    assert prove_target_flag_independence(0x2000, inspect=lambda ea: steps.get(ea))


def test_target_prefix_abstains_on_control_flow_cycle() -> None:
    steps = {
        0x1000: NativeFlagAccessStep(0x2000, reads_flags=False, writes_flags=False),
        0x2000: NativeFlagAccessStep(0x1000, reads_flags=False, writes_flags=False),
    }

    assert not prove_target_flag_independence(0x1000, inspect=lambda ea: steps.get(ea))


@pytest.mark.parametrize(
    "step",
    (
        NativeFlagAccessStep(0x1001, reads_flags=True, writes_flags=True),
        NativeFlagAccessStep(
            0x1001,
            reads_flags=False,
            writes_flags=False,
            stops=True,
        ),
    ),
)
def test_target_prefix_abstains_on_read_modify_flags_or_control_cut(step) -> None:
    assert not prove_target_flag_independence(0x1000, inspect=lambda _ea: step)
