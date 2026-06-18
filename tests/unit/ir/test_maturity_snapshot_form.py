from __future__ import annotations

from pathlib import Path

import pytest

from d810.ir.maturity import (
    IRMaturity,
    IR_MATURITY_TO_SNAPSHOT_FORM,
    SnapshotForm,
    snapshot_form_for_maturity,
)


@pytest.mark.parametrize(
    ("maturity", "snapshot_form"),
    [
        (IRMaturity.LIFTED, SnapshotForm.RAW_IR),
        (IRMaturity.CANONICAL, SnapshotForm.NORMALIZED_IR),
        (IRMaturity.LOCAL_OPTIMIZED, SnapshotForm.OPTIMIZED_IR),
        (IRMaturity.CALL_MODELED, SnapshotForm.OPTIMIZED_IR),
        (IRMaturity.GLOBAL_ANALYZED, SnapshotForm.OPTIMIZED_IR),
        (IRMaturity.GLOBAL_OPTIMIZED, SnapshotForm.OPTIMIZED_IR),
        (IRMaturity.STRUCTURED, SnapshotForm.FINAL_PRE_RENDER),
        (IRMaturity.VARIABLE_RECOVERED, SnapshotForm.LVAR_RECOVERED),
    ],
)
def test_ir_maturity_maps_to_coarse_snapshot_form(
    maturity: IRMaturity,
    snapshot_form: SnapshotForm,
) -> None:
    assert snapshot_form_for_maturity(maturity) is snapshot_form


def test_ir_maturity_to_snapshot_form_mapping_is_total() -> None:
    assert set(IR_MATURITY_TO_SNAPSHOT_FORM) == set(IRMaturity)


def test_snapshot_stage_is_retired_alias_for_snapshot_form() -> None:
    from d810.ir.flowgraph import SnapshotStage

    assert SnapshotStage is SnapshotForm


def test_pass_gates_do_not_import_coarse_snapshot_form() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    gate_sources = (
        repo_root / "src/d810/passes/pass_pipeline.py",
        repo_root / "src/d810/families/state_machine_cff/base.py",
    )

    for path in gate_sources:
        text = path.read_text(encoding="utf-8")
        assert "SnapshotForm" not in text
        assert "SnapshotStage" not in text
