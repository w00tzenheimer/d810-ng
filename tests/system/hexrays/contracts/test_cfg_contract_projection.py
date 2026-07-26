"""Projection-interface integration tests for the concrete IDA contract."""

from __future__ import annotations

from types import SimpleNamespace

from d810.hexrays.contracts.cfg_contract import IDACfgContract
from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
from d810.hexrays.mutation.mba_mutation_events import MbaMutationGateway
from d810.hexrays.mutation.patch_transaction import (
    HexRaysPatchTransactionParticipant,
)
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import (
    CfgProjection,
    LogicalBlockRef,
    PlanBlockRef,
    PreparedCfgTransaction,
)
from d810.transforms.plan import PatchPlan
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


class RecordingIDACfgContract(IDACfgContract):
    """Concrete projection implementation with recorded live checks."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[int, ...] | None]] = []

    def _check(self, _mba, *, phase, focus_serials, include_insn_checks=False):
        del include_insn_checks
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


def test_patch_participant_uses_concrete_ida_projection_interface() -> None:
    plan = PatchPlan(source_generation=0)
    cfg = FlowGraph(
        blocks={},
        entry_serial=0,
        func_ea=0,
        metadata={"snapshot_id": plan.snapshot_id},
    )
    index = MbaBlockIdentityIndex.from_flow_graph(
        session_id="ida-projection-contract",
        generation=0,
        maturity=0,
        snapshot_id=plan.snapshot_id,
        native_key=NATIVE_KEY,
        flow_graph=cfg,
    )
    gateway = MbaMutationGateway(
        session_id=index.session_id,
        generation=index.generation,
        native_key=NATIVE_KEY,
        identity_index=index,
    )
    contract = RecordingIDACfgContract()
    participant = HexRaysPatchTransactionParticipant(
        gateway=gateway,
        translator=object(),
        mba=SimpleNamespace(qty=0),
        plan=plan,
        contract=contract,
    )

    projection = participant.project(plan, cfg)
    prepared = participant.preflight(projection)

    assert isinstance(prepared, PreparedCfgTransaction)
    assert prepared.projection is projection
    assert contract.calls == [("pre", None)]
    assert not gateway.active
