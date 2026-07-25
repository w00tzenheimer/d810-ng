from __future__ import annotations

import pytest

from d810.transforms.contract import (
    CfgContract,
    CfgContractViolationError,
)
from d810.transforms.report import InvariantViolation
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.transforms.cfg_transaction import CfgProjection


def test_verify_returns_empty_tuple_when_no_violations(monkeypatch: pytest.MonkeyPatch):
    contract = CfgContract()
    monkeypatch.setattr(contract, "_check", lambda *_a, **_k: [])

    assert contract.verify(object(), phase="post") == ()


def test_verify_raises_with_summarized_violations(monkeypatch: pytest.MonkeyPatch):
    contract = CfgContract()
    violations = [
        InvariantViolation(
            code="CFG_BAD",
            message="bad succset",
            phase="post",
            block_serial=7,
        )
    ]
    monkeypatch.setattr(contract, "_check", lambda *_a, **_k: violations)

    with pytest.raises(CfgContractViolationError) as exc_info:
        contract.verify(object(), phase="post")

    assert exc_info.value.phase == "post"
    assert exc_info.value.violations == tuple(violations)
    assert exc_info.value.summary == "CFG_BAD@blk[7]"


def test_verify_projection_returns_empty_on_success():
    contract = CfgContract()
    clean_cfg = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=3,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=2,
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=2,
                succs=(),
                preds=(0,),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=0,
            ),
        },
        entry_serial=0,
        func_ea=0,
    )
    result = contract.verify_projection(
        CfgProjection(
            plan_id="plan-1",
            snapshot_id="snapshot-1",
            graph=clean_cfg,
        )
    )
    assert result == ()


def test_verify_projection_raises_on_violation():
    contract = CfgContract()
    # Block 0 lists block 1 as successor but block 1 does NOT list block 0 as pred
    broken_cfg = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=3,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=2,
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=2,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=0,
            ),
        },
        entry_serial=0,
        func_ea=0,
    )
    with pytest.raises(CfgContractViolationError) as exc_info:
        contract.verify_projection(
            CfgProjection(
                plan_id="plan-1",
                snapshot_id="snapshot-1",
                graph=broken_cfg,
            )
        )

    assert exc_info.value.phase == "projected"
    assert len(exc_info.value.violations) > 0
    assert any(
        v.code == "CFG_50858_SUCC_PRED_MISMATCH" for v in exc_info.value.violations
    )


def test_check_projection_runs_virtual_cfg_invariants():
    contract = CfgContract()
    projected_cfg = FlowGraph(
        blocks={
            0: BlockSnapshot(
                serial=0,
                block_type=3,
                succs=(1,),
                preds=(),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=2,
            ),
            1: BlockSnapshot(
                serial=1,
                block_type=2,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=0,
            ),
        },
        entry_serial=0,
        func_ea=0,
    )

    violations = contract.check_projection(
        CfgProjection(
            plan_id="plan-1",
            snapshot_id="snapshot-1",
            graph=projected_cfg,
        )
    )

    assert [violation.code for violation in violations] == [
        "CFG_50858_SUCC_PRED_MISMATCH",
    ]
