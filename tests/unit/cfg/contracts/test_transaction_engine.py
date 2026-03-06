"""Tests for CfgTransactionEngine phase orchestration."""
from __future__ import annotations

from unittest.mock import MagicMock, call

import pytest

from d810.cfg.contracts.ida_contract import CfgContractViolationError
from d810.cfg.contracts.report import InvariantViolation
from d810.cfg.contracts.transaction_engine import (
    CfgTransactionEngine,
    TransactionResult,
)


def _make_violation(code: str = "TEST_001", phase: str = "pre") -> InvariantViolation:
    return InvariantViolation(code=code, message="test violation", phase=phase)


def _make_contract_error(phase: str = "pre") -> CfgContractViolationError:
    return CfgContractViolationError(
        phase=phase,
        violations=[_make_violation(phase=phase)],
    )


@pytest.fixture()
def translator() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def contract() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def plan() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def pre_cfg() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def mba() -> MagicMock:
    return MagicMock()


class TestTransactionResultFactory:
    def test_ok_factory(self) -> None:
        result = TransactionResult.ok(5)
        assert result.success is True
        assert result.applied_count == 5
        assert result.failure_phase is None
        assert result.classification is None
        assert result.error is None

    def test_failed_factory(self) -> None:
        exc = _make_contract_error("projected")
        result = TransactionResult.failed("projected_contract", exc)
        assert result.success is False
        assert result.failure_phase == "projected_contract"
        assert result.classification is not None
        assert result.classification.rollback_needed is False
        assert result.error is exc


class TestCfgTransactionEngine:
    def test_apply_returns_ok_on_success(
        self, translator: MagicMock, plan: MagicMock, pre_cfg: MagicMock, mba: MagicMock,
    ) -> None:
        translator.lower.return_value = 5
        engine = CfgTransactionEngine(translator)

        result = engine.apply(plan, pre_cfg=pre_cfg, mba=mba)

        assert result.success is True
        assert result.applied_count == 5
        translator.lower.assert_called_once()

    def test_apply_projected_contract_failure_rejects_before_mutation(
        self, translator: MagicMock, contract: MagicMock,
        plan: MagicMock, pre_cfg: MagicMock, mba: MagicMock,
    ) -> None:
        contract.verify_projected.side_effect = _make_contract_error("projected")
        engine = CfgTransactionEngine(translator, contract=contract)

        result = engine.apply(plan, pre_cfg=pre_cfg, mba=mba)

        assert result.success is False
        assert result.failure_phase == "projected_contract"
        assert result.classification is not None
        assert result.classification.rollback_needed is False
        translator.lower.assert_not_called()

    def test_apply_pre_check_failure_rejects_before_mutation(
        self, translator: MagicMock, contract: MagicMock,
        plan: MagicMock, pre_cfg: MagicMock, mba: MagicMock,
    ) -> None:
        contract.verify_projected.return_value = ()
        contract.verify.side_effect = _make_contract_error("pre")
        engine = CfgTransactionEngine(translator, contract=contract)

        result = engine.apply(plan, pre_cfg=pre_cfg, mba=mba)

        assert result.success is False
        assert result.failure_phase == "live_pre_check"
        assert result.classification is not None
        assert result.classification.rollback_needed is False
        translator.lower.assert_not_called()

    def test_apply_post_apply_contract_failure(
        self, translator: MagicMock, contract: MagicMock,
        plan: MagicMock, pre_cfg: MagicMock, mba: MagicMock,
    ) -> None:
        contract.verify_projected.return_value = ()
        contract.verify.return_value = ()
        translator.lower.side_effect = _make_contract_error("post")
        engine = CfgTransactionEngine(translator, contract=contract)

        result = engine.apply(plan, pre_cfg=pre_cfg, mba=mba)

        assert result.success is False
        assert result.failure_phase == "post_apply_contract"
        assert result.classification is not None
        assert result.classification.rollback_needed is True

    def test_apply_lower_returns_zero(
        self, translator: MagicMock, plan: MagicMock, pre_cfg: MagicMock, mba: MagicMock,
    ) -> None:
        translator.lower.return_value = 0
        engine = CfgTransactionEngine(translator)

        result = engine.apply(plan, pre_cfg=pre_cfg, mba=mba)

        assert result.success is False
        assert result.failure_phase == "backend_apply"
        assert result.classification is not None
        assert result.classification.rollback_needed is True

    def test_apply_no_contract_skips_checks(
        self, translator: MagicMock, plan: MagicMock, pre_cfg: MagicMock, mba: MagicMock,
    ) -> None:
        translator.lower.return_value = 3
        engine = CfgTransactionEngine(translator, contract=None)

        result = engine.apply(plan, pre_cfg=pre_cfg, mba=mba)

        assert result == TransactionResult.ok(3)
        translator.lower.assert_called_once()

    def test_apply_passes_post_apply_hook_to_lower(
        self, translator: MagicMock, plan: MagicMock, pre_cfg: MagicMock, mba: MagicMock,
    ) -> None:
        hook = MagicMock()
        translator.lower.return_value = 2
        engine = CfgTransactionEngine(translator)

        engine.apply(plan, pre_cfg=pre_cfg, mba=mba, post_apply_hook=hook)

        translator.lower.assert_called_once_with(
            plan, mba, post_apply_hook=hook,
        )
