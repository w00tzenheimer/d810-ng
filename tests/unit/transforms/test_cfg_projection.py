from __future__ import annotations

import d810.transforms.contract as contract_module
import pytest

from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind
from d810.transforms.cfg_transaction import CfgProjection, LogicalBlockRef, PlanBlockRef
from d810.transforms.contract import CfgContract, CfgContractViolationError
from d810.transforms.edit_simulator import project_patch_plan
from d810.transforms.plan import PatchBlockSpec, PatchPlan, PatchRelocationMap


def _graph_with_unfocused_violation() -> FlowGraph:
    return FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=2,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=0,
                kind=BlockKind.ZERO_WAY,
                tail_kind=InsnKind.NOP,
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=3,
                succs=(),
                preds=(),
                flags=0,
                start_ea=1,
                insn_snapshots=(),
                tail_opcode=2,
                kind=BlockKind.ONE_WAY,
                tail_kind=InsnKind.GOTO,
            ),
        },
        entry_serial=0,
        func_ea=0,
    )


def test_verify_projection_does_not_treat_logical_refs_as_live_coordinates() -> None:
    """A logical identity cannot be interpreted as a projected block serial."""
    projection = CfgProjection(
        plan_id="plan-1",
        snapshot_id="snapshot-1",
        graph=_graph_with_unfocused_violation(),
        focus_refs=(LogicalBlockRef("session-1", "proxy-0", 0),),
    )

    with pytest.raises(CfgContractViolationError, match="CFG_50860_SUCC_MISMATCH"):
        CfgContract().verify_projection(projection)


def test_verify_projection_checks_created_blocks_when_focus_is_mixed() -> None:
    """A synthetic focus ref must widen projection checks beyond source refs."""
    projection = CfgProjection(
        plan_id="plan-1",
        snapshot_id="snapshot-1",
        graph=_graph_with_unfocused_violation(),
        focus_refs=(
            LogicalBlockRef("session-1", "proxy-0", 0),
            PlanBlockRef("plan-1", "created:0"),
        ),
    )

    with pytest.raises(CfgContractViolationError, match="CFG_50860_SUCC_MISMATCH"):
        CfgContract().verify_projection(projection)


def test_verify_projection_reports_invalid_projected_graph() -> None:
    """A full projection check must reject the invalid goto shape."""
    projection = CfgProjection(
        plan_id="plan-1",
        snapshot_id="snapshot-1",
        graph=_graph_with_unfocused_violation(),
    )

    with pytest.raises(CfgContractViolationError, match="CFG_50860_SUCC_MISMATCH"):
        CfgContract().verify_projection(projection, scope="full")


def test_contract_module_has_no_patch_plan_binding() -> None:
    """The contract boundary must not retain PatchPlan-specific imports."""
    assert not hasattr(contract_module, "PatchPlan")


def test_project_patch_plan_keeps_created_blocks_plan_qualified() -> None:
    """Two plans may assign one serial without sharing a synthetic focus ref."""
    first_plan_id = "first-plan"
    block_id = PlanBlockRef(first_plan_id, "created:0")
    plan = PatchPlan(
        plan_id=first_plan_id,
        snapshot_id="snapshot-1",
        new_blocks=(PatchBlockSpec(block_id=block_id, kind="insert_block"),),
        relocation_map=PatchRelocationMap(planned_lineage=((block_id, None),)),
    )
    pre_cfg = _graph_with_unfocused_violation()

    first = project_patch_plan(pre_cfg, plan, snapshot_id="snapshot-1")
    second = project_patch_plan(
        pre_cfg,
        PatchPlan(
            plan_id="second-plan",
            snapshot_id="snapshot-1",
            new_blocks=(
                PatchBlockSpec(
                    block_id=PlanBlockRef("second-plan", "created:0"),
                    kind="insert_block",
                ),
            ),
            relocation_map=PatchRelocationMap(
                planned_lineage=((PlanBlockRef("second-plan", "created:0"), None),)
            ),
        ),
        snapshot_id="snapshot-1",
    )

    assert first.focus_refs == (PlanBlockRef(first.plan_id, "created:0"),)
    assert second.focus_refs == (PlanBlockRef(second.plan_id, "created:0"),)
    assert first.focus_refs != second.focus_refs
