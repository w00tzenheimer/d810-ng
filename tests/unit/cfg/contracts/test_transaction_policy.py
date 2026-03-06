"""Tests for transaction phase ordering and failure classification."""

from __future__ import annotations

import pytest

from d810.cfg.contracts.transaction_policy import (
    TRANSACTION_PHASES,
    FailureClassification,
    classify_failure,
)


class TestTransactionPhases:
    """Verify the phase list is well-formed."""

    def test_phase_count(self) -> None:
        assert len(TRANSACTION_PHASES) == 9

    def test_no_duplicates(self) -> None:
        assert len(TRANSACTION_PHASES) == len(set(TRANSACTION_PHASES))

    def test_lowering_before_backend_apply(self) -> None:
        assert TRANSACTION_PHASES.index("lowering") < TRANSACTION_PHASES.index(
            "backend_apply"
        )

    def test_projected_before_live_pre_check(self) -> None:
        assert TRANSACTION_PHASES.index("projected_contract") < TRANSACTION_PHASES.index(
            "live_pre_check"
        )

    def test_rollback_phases_at_end(self) -> None:
        idx_restore = TRANSACTION_PHASES.index("rollback_restore")
        idx_verify = TRANSACTION_PHASES.index("rollback_verification")
        assert idx_restore > TRANSACTION_PHASES.index("native_verify")
        assert idx_verify > idx_restore


class TestClassifyFailurePreMutation:
    """Pre-mutation phases must never request rollback."""

    @pytest.mark.parametrize(
        "phase",
        ["semantic_preflight", "projected_contract", "live_pre_check", "lowering"],
    )
    def test_no_rollback_needed(self, phase: str) -> None:
        result = classify_failure(phase, error="some error")
        assert result.rollback_needed is False
        assert result.quarantine is False
        assert result.phase == phase
        assert result.error == "some error"

    def test_projected_contract_no_rollback(self) -> None:
        result = classify_failure("projected_contract", "pred/succ mismatch")
        assert result.rollback_needed is False
        assert result.tag is None

    def test_lowering_no_rollback(self) -> None:
        result = classify_failure("lowering", "queue build error")
        assert result.rollback_needed is False


class TestClassifyFailureLiveMutation:
    """Post-mutation phases must request rollback."""

    @pytest.mark.parametrize(
        "phase",
        ["backend_apply", "post_apply_contract", "native_verify"],
    )
    def test_rollback_needed(self, phase: str) -> None:
        result = classify_failure(phase, error="mutation error")
        assert result.rollback_needed is True
        assert result.quarantine is False
        assert result.phase == phase

    def test_native_verify_tagged(self) -> None:
        result = classify_failure("native_verify", "INTERR 50860")
        assert result.rollback_needed is True
        assert result.tag == "backend_verify_failure"
        assert result.error == "INTERR 50860"

    def test_post_apply_contract_no_special_tag(self) -> None:
        result = classify_failure("post_apply_contract", "block type mismatch")
        assert result.rollback_needed is True
        assert result.tag is None

    def test_backend_apply_no_special_tag(self) -> None:
        result = classify_failure("backend_apply", "apply failed")
        assert result.rollback_needed is True
        assert result.tag is None


class TestClassifyFailureRollback:
    """Rollback-path failures must quarantine."""

    def test_rollback_restore_quarantine(self) -> None:
        result = classify_failure("rollback_restore", "snapshot restore failed")
        assert result.rollback_needed is False
        assert result.quarantine is True
        assert result.tag == "rollback_failed"

    def test_rollback_verification_quarantine(self) -> None:
        result = classify_failure("rollback_verification", "residual damage")
        assert result.rollback_needed is False
        assert result.quarantine is True
        assert result.tag == "rollback_verify_failed"


class TestClassifyFailureEdgeCases:
    """Edge cases and error handling."""

    def test_unknown_phase_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown transaction phase"):
            classify_failure("nonexistent_phase")

    def test_empty_error_string(self) -> None:
        result = classify_failure("semantic_preflight")
        assert result.error == ""

    def test_failure_classification_is_frozen(self) -> None:
        result = classify_failure("projected_contract", "test")
        with pytest.raises(AttributeError):
            result.rollback_needed = True  # type: ignore[misc]

    def test_all_phases_classifiable(self) -> None:
        """Every phase in TRANSACTION_PHASES can be classified without error."""
        for phase in TRANSACTION_PHASES:
            result = classify_failure(phase, error="test")
            assert isinstance(result, FailureClassification)
            assert result.phase == phase


class TestStageResultQuarantineField:
    """P1-3: StageResult quarantine field exists and defaults to False."""

    def test_stage_result_quarantine_field_exists(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur.strategy import StageResult

        result = StageResult(strategy_name="test", quarantine=True)
        assert result.quarantine is True

    def test_stage_result_quarantine_defaults_false(self) -> None:
        from d810.optimizers.microcode.flow.flattening.hodur.strategy import StageResult

        result = StageResult(strategy_name="test")
        assert result.quarantine is False


class TestLazyImportFromPackage:
    """Verify the __init__.py lazy import wiring works."""

    def test_import_classify_failure(self) -> None:
        from d810.cfg.contracts import classify_failure as cf
        assert callable(cf)

    def test_import_transaction_phases(self) -> None:
        from d810.cfg.contracts import TRANSACTION_PHASES as tp
        assert isinstance(tp, list)
        assert len(tp) == 9

    def test_import_failure_classification(self) -> None:
        from d810.cfg.contracts import FailureClassification as fc
        assert fc is FailureClassification
