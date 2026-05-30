from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import FlowGraph
from d810.transforms.graph_modification import NopInstructions
from d810.evaluator.hexrays_microcode.dead_state_variable_backend import (
    DeadStateReadCleanupSite,
    DeadStateVariableCleanupEvidence,
    StateVariableRef,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    dead_state_variable_elimination as strategy_module,
)


_MBA = object()


def _snapshot(
    *,
    mba: object = _MBA,
    state_constants=(0x11223344,),
    bst_result=None,
    state_var=object(),
):
    return SimpleNamespace(
        mba=mba,
        flow_graph=FlowGraph(blocks={}, entry_serial=0, func_ea=0x180012B60),
        state_constants=frozenset(state_constants),
        bst_result=bst_result,
        detector=None,
        state_machine=SimpleNamespace(
            handlers={1: object()},
            state_var=state_var,
        ),
    )


class _FakeDeadStateBackend:
    def __init__(
        self,
        *,
        state_variable: StateVariableRef | None = StateVariableRef(0x3C, 4),
        evidence: DeadStateVariableCleanupEvidence | None = None,
    ) -> None:
        self.state_variable = state_variable
        self.evidence = evidence
        self.resolve_calls: list[tuple[object | None, object | None]] = []
        self.collect_calls: list[
            tuple[object, StateVariableRef, frozenset[int], frozenset[int]]
        ] = []

    def resolve_state_variable(self, *, detector, state_var):
        self.resolve_calls.append((detector, state_var))
        return self.state_variable

    def collect_dead_state_read_cleanup_evidence(
        self,
        mba,
        *,
        state_variable,
        known_state_constants,
        bst_node_blocks=frozenset(),
    ):
        self.collect_calls.append(
            (
                mba,
                state_variable,
                frozenset(known_state_constants),
                frozenset(bst_node_blocks),
            )
        )
        if self.evidence is not None:
            return self.evidence
        return DeadStateVariableCleanupEvidence(
            state_variable=state_variable,
            use_site_count=2,
            sites=(
                DeadStateReadCleanupSite(
                    block_serial=41,
                    insn_ea=0x180012EE2,
                    opcode_name="m_mov",
                ),
                DeadStateReadCleanupSite(
                    block_serial=42,
                    insn_ea=0x180012EF0,
                    opcode_name="m_xdu",
                ),
            ),
        )


def test_dsve_emits_nops_from_backend_sites(monkeypatch) -> None:
    backend = _FakeDeadStateBackend()
    monkeypatch.setattr(strategy_module, "_DEAD_STATE_BACKEND", backend)
    bst_result = SimpleNamespace(bst_node_blocks={9})

    plan = strategy_module.DeadStateVariableEliminationStrategy().plan(
        _snapshot(bst_result=bst_result)
    )

    assert plan is not None
    assert plan.modifications == [
        NopInstructions(block_serial=41, insn_eas=(0x180012EE2,)),
        NopInstructions(block_serial=42, insn_eas=(0x180012EF0,)),
    ]
    assert plan.ownership.blocks == frozenset({41, 42})
    assert plan.metadata == {"safeguard_min_required": 1}
    assert backend.collect_calls == [
        (
            _MBA,
            StateVariableRef(0x3C, 4),
            frozenset({0x11223344}),
            frozenset({9}),
        )
    ]


def test_dsve_returns_none_without_state_variable(monkeypatch) -> None:
    backend = _FakeDeadStateBackend(state_variable=None)
    monkeypatch.setattr(strategy_module, "_DEAD_STATE_BACKEND", backend)

    assert (
        strategy_module.DeadStateVariableEliminationStrategy().plan(
            _snapshot()
        )
        is None
    )
    assert backend.collect_calls == []


def test_dsve_returns_none_without_cleanup_sites(monkeypatch) -> None:
    state_variable = StateVariableRef(0x3C, 4)
    backend = _FakeDeadStateBackend(
        state_variable=state_variable,
        evidence=DeadStateVariableCleanupEvidence(
            state_variable=state_variable,
            use_site_count=1,
            sites=(),
        ),
    )
    monkeypatch.setattr(strategy_module, "_DEAD_STATE_BACKEND", backend)

    assert (
        strategy_module.DeadStateVariableEliminationStrategy().plan(
            _snapshot()
        )
        is None
    )
