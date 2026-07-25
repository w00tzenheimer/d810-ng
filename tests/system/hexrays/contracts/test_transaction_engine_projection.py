"""Projection-interface integration tests for the concrete IDA contract."""

from __future__ import annotations

from d810.hexrays.contracts.cfg_contract import IDACfgContract
from d810.ir.flowgraph import FlowGraph
from d810.passes.transaction_engine import CfgTransactionEngine, TransactionResult
from d810.transforms.cfg_transaction import CfgProjection, LogicalBlockRef, PlanBlockRef
from d810.transforms.plan import PatchPlan


class RecordingIDACfgContract(IDACfgContract):
    """Concrete contract with only live invariant evaluation recorded."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[int, ...] | None]] = []

    def _check(self, _mba, *, phase, focus_serials, include_insn_checks=False):
        self.calls.append(
            (phase, None if focus_serials is None else tuple(focus_serials))
        )
        return []


def test_concrete_ida_contract_does_not_treat_identity_refs_as_live_coordinates() -> (
    None
):
    projection = CfgProjection(
        plan_id="plan-1",
        snapshot_id="snapshot-1",
        graph=FlowGraph(blocks={}, entry_serial=0, func_ea=0),
        focus_refs=(
            PlanBlockRef("plan-1", "created:0"),
            LogicalBlockRef("session-1", "proxy-7", 0),
        ),
    )
    contract = RecordingIDACfgContract()

    assert contract.verify(object(), projection=projection, phase="pre") == ()
    assert contract.calls == [("pre", None)]


def test_engine_uses_concrete_ida_projection_interface() -> None:
    class Translator:
        def lower(self, *_args, **_kwargs) -> int:
            return 1

    contract = RecordingIDACfgContract()
    plan = PatchPlan()
    result = CfgTransactionEngine(Translator(), contract=contract).apply(
        plan,
        pre_cfg=FlowGraph(
            blocks={},
            entry_serial=0,
            func_ea=0,
            metadata={"snapshot_id": plan.snapshot_id},
        ),
        mba=object(),
        mutation_gateway=object(),
    )

    assert result == TransactionResult.ok(1)
    assert contract.calls == [("pre", None)]
