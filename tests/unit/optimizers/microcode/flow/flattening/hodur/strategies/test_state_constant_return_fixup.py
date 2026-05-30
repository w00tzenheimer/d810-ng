from __future__ import annotations

from types import SimpleNamespace

from d810.ir.flowgraph import FlowGraph
from d810.transforms.graph_modification import NopInstructions
from d810.evaluator.hexrays_microcode.return_cleanup_backend import (
    ReturnCleanupEvidence,
    ReturnCleanupSite,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies import (
    state_constant_return_fixup as strategy_module,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.state_constant_return_fixup import (
    StateConstantReturnFixupStrategy,
)


def _snapshot(*, mba: object = object(), state_constants=(0x4C77464F,)):
    return SimpleNamespace(
        mba=mba,
        flow_graph=FlowGraph(blocks={}, entry_serial=0, func_ea=0x180012B60),
        state_constants=frozenset(state_constants),
        bst_result=None,
        detector=None,
        state_machine=None,
    )


def test_state_constant_return_fixup_emits_nops_from_backend_sites(monkeypatch):
    mba = object()

    class FakeBackend:
        def __init__(self):
            self.calls = []

        def collect_return_cleanup_evidence(
            self,
            live_function,
            *,
            known_state_constants,
            state_var_stkoff=None,
        ):
            self.calls.append(
                (live_function, frozenset(known_state_constants), state_var_stkoff)
            )
            return ReturnCleanupEvidence(
                stop_serial=90,
                stop_pred_count=2,
                sites=(
                    ReturnCleanupSite(
                        block_serial=41,
                        insn_ea=0x180012EE2,
                        reason="synthetic_return_feeder",
                        mux_block_serial=90,
                    ),
                    ReturnCleanupSite(
                        block_serial=42,
                        insn_ea=0x180012EF0,
                        reason="state_const_mov",
                        observed_state=0x4C77464F,
                    ),
                    ReturnCleanupSite(
                        block_serial=42,
                        insn_ea=0x180012EF0,
                        reason="state_const_mov",
                        observed_state=0x4C77464F,
                    ),
                ),
            )

    fake_backend = FakeBackend()
    monkeypatch.setattr(strategy_module, "_RETURN_CLEANUP_BACKEND", fake_backend)

    plan = StateConstantReturnFixupStrategy().plan(_snapshot(mba=mba))

    assert plan is not None
    assert plan.modifications == [
        NopInstructions(block_serial=41, insn_eas=(0x180012EE2,)),
        NopInstructions(block_serial=42, insn_eas=(0x180012EF0,)),
    ]
    assert plan.ownership.blocks == frozenset({41, 42})
    assert fake_backend.calls == [(mba, frozenset({0x4C77464F}), None)]


def test_state_constant_return_fixup_returns_none_without_stop_block(monkeypatch):
    class FakeBackend:
        def collect_return_cleanup_evidence(self, *args, **kwargs):
            return ReturnCleanupEvidence(
                stop_serial=None,
                stop_pred_count=0,
                sites=(),
            )

    monkeypatch.setattr(strategy_module, "_RETURN_CLEANUP_BACKEND", FakeBackend())

    assert StateConstantReturnFixupStrategy().plan(_snapshot()) is None
