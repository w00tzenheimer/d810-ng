"""Runtime tests for the shared engine executor surface."""
from __future__ import annotations

import sys
import types

if "ida_hexrays" not in sys.modules:
    ida_hexrays_stub = types.ModuleType("ida_hexrays")
    ida_hexrays_stub.mop_z = 0
    sys.modules["ida_hexrays"] = ida_hexrays_stub

from d810.optimizers.microcode.flow.flattening.engine import executor as engine_executor
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.graph_modification import ConvertToGoto, ReorderBlocks
from d810.transforms.plan import PatchConvertToGoto, PatchReorderBlocks, compile_patch_plan
from d810.optimizers.microcode.flow.flattening.engine.executor import (
    TransactionalExecutor as EngineTransactionalExecutor,
)
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur import executor as hodur_executor


def _fragment() -> PlanFragment:
    return PlanFragment(
        strategy_name="profile_probe",
        family="direct",
        ownership=OwnershipScope(
            blocks=frozenset(),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        modifications=[object()],
    )


def _block(serial: int, succs: tuple[int, ...] = ()) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=len(succs),
        succs=succs,
        preds=(),
        flags=0,
        start_ea=0x1000 + serial,
        insn_snapshots=(),
    )


def test_executor_filters_rewrites_to_reorder_materialized_targets() -> None:
    cfg = FlowGraph(
        blocks={
            0: _block(0, (1,)),
            1: _block(1, (2, 3)),
            2: _block(2),
            3: _block(3),
        },
        entry_serial=0,
        func_ea=0x1000,
    )
    modifications = [
        ConvertToGoto(block_serial=1, goto_target=3),
        ReorderBlocks(dfs_block_order=(3,), non_2way_serials=(3,)),
    ]
    patch_plan = compile_patch_plan(modifications, cfg)
    assert any(
        isinstance(step, PatchConvertToGoto) and step.goto_target == 4
        for step in patch_plan.steps
    )

    class _FakeMBA:
        qty = 4

        def get_mblock(self, _serial: int):
            raise AssertionError("future-target filter must not inspect live blocks")

    executor = EngineTransactionalExecutor(mba=_FakeMBA())

    filtered, filtered_plan, removed = executor._filter_backend_unsupported_modifications(
        cfg,
        modifications,
        patch_plan,
    )

    assert removed == 1
    assert filtered == [modifications[1]]
    assert not any(isinstance(step, PatchConvertToGoto) for step in filtered_plan.steps)
    assert any(isinstance(step, PatchReorderBlocks) for step in filtered_plan.steps)


def test_engine_executor_uses_configured_safeguard_profile(monkeypatch) -> None:
    seen: list[str] = []

    def _fake_should_apply(_num_edges, _total_handlers, context="", **_kwargs):
        seen.append(context)
        return False

    monkeypatch.setattr(
        engine_executor,
        "should_apply_bulk_cfg_modifications",
        _fake_should_apply,
    )

    executor = EngineTransactionalExecutor(
        mba=object(),
        safeguard_profile="generic_family",
    )
    [result] = executor.execute_pipeline([_fragment()], total_handlers=1)

    assert seen == ["generic_family"]
    assert result.failure_phase == "safeguard"


def test_hodur_executor_defaults_to_hodur_safeguard_profile(monkeypatch) -> None:
    seen: list[str] = []

    def _fake_should_apply(_num_edges, _total_handlers, context="", **_kwargs):
        seen.append(context)
        return False

    monkeypatch.setattr(
        hodur_executor,
        "should_apply_bulk_cfg_modifications",
        _fake_should_apply,
    )

    executor = hodur_executor.TransactionalExecutor(mba=object())
    [result] = executor.execute_pipeline([_fragment()], total_handlers=1)

    assert seen == ["hodur"]
    assert result.failure_phase == "safeguard"
