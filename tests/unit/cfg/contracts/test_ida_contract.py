from __future__ import annotations

import pytest

from d810.cfg.contracts.ida_contract import (
    CfgContractViolationError,
    IDACfgContract,
)
from d810.cfg.contracts.report import InvariantViolation


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
