from __future__ import annotations

import inspect
from types import SimpleNamespace

import d810.analyses.control_flow.exit_transition_discovery as exit_transition_discovery
from d810.analyses.control_flow.exit_transition_discovery import (
    collect_condition_chain_default_transition_candidates,
    collect_valrange_exit_transition_candidates,
)
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot

_STACK_OPERAND = 5


def _insn(*, ea: int = 0x1000) -> InsnSnapshot:
    return InsnSnapshot(opcode=1, ea=ea, operands=(), kind=InsnKind.MOV)


def _block(serial: int, *, insns: tuple[InsnSnapshot, ...], succs: tuple[int, ...] = ()) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1,
        succs=succs,
        preds=(),
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=insns,
    )


def _flow_graph(blocks: dict[int, BlockSnapshot]) -> FlowGraph:
    entry = min(blocks) if blocks else 0
    return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0x1000)


class TestCollectConditionChainDefaultTransitionCandidates:
    def test_collects_path_eval_candidates(self, monkeypatch) -> None:
        snapshot = SimpleNamespace(
            mba=object(),
            detector=None,
        )
        sm = SimpleNamespace(
            state_var=SimpleNamespace(t=_STACK_OPERAND, s=SimpleNamespace(off=0x30)),
        )
        range_evidence = SimpleNamespace()

        seen_calls: list[tuple[int, int, frozenset[int]]] = []

        def fake_evaluate_handler_paths(
            *,
            mba,
            entry_serial,
            incoming_state,
            condition_chain_blocks,
            state_var_stkoff,
            handler_entry_blocks,
        ):
            assert mba is snapshot.mba
            assert state_var_stkoff == 0x30
            seen_calls.append(
                (
                    int(entry_serial),
                    int(incoming_state),
                    frozenset(int(v) for v in handler_entry_blocks),
                )
            )
            return [
                SimpleNamespace(exit_block=24, final_state=0x22),
                SimpleNamespace(exit_block=30, final_state=None),
            ]

        monkeypatch.setattr(
            "d810.analyses.control_flow.exit_transition_discovery.evaluate_handler_paths",
            fake_evaluate_handler_paths,
        )
        monkeypatch.setattr(
            "d810.analyses.control_flow.exit_transition_discovery.resolve_target_via_condition_chain",
            lambda condition_chain, state: 88 if state == 0x22 else None,
        )

        candidates = collect_condition_chain_default_transition_candidates(
            snapshot,
            sm=sm,
            range_evidence=range_evidence,
            handler_state_map={24: 0x11},
            condition_chain_blocks={2, 6},
        )

        assert seen_calls == [(0x11, 24, frozenset({0x11}))]
        assert len(candidates) == 1
        assert candidates[0].handler_state == 24
        assert candidates[0].handler_entry == 0x11
        assert candidates[0].from_block == 24
        assert candidates[0].target_entry == 88
        assert candidates[0].final_state == 0x22

    def test_exit_transition_discovery_does_not_import_live_hexrays(self) -> None:
        assert "import ida_hexrays" not in inspect.getsource(
            exit_transition_discovery
        )


class TestCollectValrangeExitTransitionCandidates:
    def test_collects_unresolved_exit_candidates(self, monkeypatch) -> None:
        flow_graph = _flow_graph({24: _block(24, insns=(_insn(),))})
        transition = SimpleNamespace(from_state=0x11, to_state=0x22, from_block=24)
        sm = SimpleNamespace(
            state_var=SimpleNamespace(name="state"),
            handlers={0x11: SimpleNamespace(transitions=(transition,))},
        )
        range_evidence = SimpleNamespace()

        monkeypatch.setattr(
            "d810.analyses.control_flow.exit_transition_discovery.resolve_target_via_condition_chain",
            lambda condition_chain, state: 88 if state == 0x33 else None,
        )

        seen: list[tuple[int, object]] = []

        def fake_resolver(exit_serial, state_var):
            seen.append((int(exit_serial), state_var))
            return 0x33

        discovery = collect_valrange_exit_transition_candidates(
            flow_graph,
            sm=sm,
            range_evidence=range_evidence,
            resolve_state_via_valranges=fake_resolver,
        )

        assert seen == [(24, sm.state_var)]
        assert discovery.total_unresolved == 1
        assert len(discovery.candidates) == 1
        assert discovery.candidates[0].from_state == 0x11
        assert discovery.candidates[0].to_state == 0x22
        assert discovery.candidates[0].from_block == 24
        assert discovery.candidates[0].target_entry == 88
        assert discovery.candidates[0].resolved_state_value == 0x33

    def test_skips_already_resolved_transitions(self) -> None:
        flow_graph = _flow_graph({24: _block(24, insns=(_insn(),))})
        transition = SimpleNamespace(from_state=0x11, to_state=0x22, from_block=24)
        sm = SimpleNamespace(
            state_var=SimpleNamespace(name="state"),
            handlers={0x11: SimpleNamespace(transitions=(transition,))},
        )

        discovery = collect_valrange_exit_transition_candidates(
            flow_graph,
            sm=sm,
            range_evidence=SimpleNamespace(),
            resolve_state_via_valranges=lambda exit_serial, state_var: 0x33,
            resolved_transitions=frozenset({(0x11, 0x22)}),
        )

        assert discovery.total_unresolved == 0
        assert discovery.candidates == ()

    def test_skips_empty_exit_block(self) -> None:
        flow_graph = _flow_graph({24: _block(24, insns=())})
        transition = SimpleNamespace(from_state=0x11, to_state=0x22, from_block=24)
        sm = SimpleNamespace(
            state_var=SimpleNamespace(name="state"),
            handlers={0x11: SimpleNamespace(transitions=(transition,))},
        )

        discovery = collect_valrange_exit_transition_candidates(
            flow_graph,
            sm=sm,
            range_evidence=SimpleNamespace(),
            resolve_state_via_valranges=lambda exit_serial, state_var: 0x33,
        )

        assert discovery.total_unresolved == 1
        assert discovery.candidates == ()
