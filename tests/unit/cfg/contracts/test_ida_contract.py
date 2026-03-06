from __future__ import annotations

import pytest

from d810.cfg.flow import edit_simulator
from d810.cfg.contracts.ida_contract import (
    CfgContractViolationError,
    IDACfgContract,
)
from d810.cfg.contracts.report import InvariantViolation
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.plan import PatchPlan


def test_verify_returns_empty_tuple_when_no_violations(monkeypatch: pytest.MonkeyPatch):
    contract = IDACfgContract()
    monkeypatch.setattr(contract, "_check", lambda *_a, **_k: [])

    assert contract.verify(object(), phase="post") == ()


def test_verify_raises_with_summarized_violations(monkeypatch: pytest.MonkeyPatch):
    contract = IDACfgContract()
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


def test_verify_projected_returns_empty_on_success(monkeypatch: pytest.MonkeyPatch):
    contract = IDACfgContract()
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
    monkeypatch.setattr(edit_simulator, "project_post_state", lambda *_a, **_k: clean_cfg)

    result = contract.verify_projected(clean_cfg, PatchPlan())
    assert result == ()


def test_verify_projected_raises_on_violation(monkeypatch: pytest.MonkeyPatch):
    contract = IDACfgContract()
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
    monkeypatch.setattr(edit_simulator, "project_post_state", lambda *_a, **_k: broken_cfg)

    with pytest.raises(CfgContractViolationError) as exc_info:
        contract.verify_projected(broken_cfg, PatchPlan())

    assert exc_info.value.phase == "projected"
    assert len(exc_info.value.violations) > 0
    assert any(v.code == "CFG_50858_SUCC_PRED_MISMATCH" for v in exc_info.value.violations)


def test_check_projected_runs_virtual_cfg_invariants(monkeypatch: pytest.MonkeyPatch):
    contract = IDACfgContract()
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

    monkeypatch.setattr(edit_simulator, "project_post_state", lambda *_a, **_k: projected_cfg)

    violations = contract.check_projected(projected_cfg, PatchPlan())

    assert [violation.code for violation in violations] == [
        "CFG_50858_SUCC_PRED_MISMATCH",
    ]
