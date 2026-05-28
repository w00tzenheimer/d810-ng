from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import MopSnapshot, OperandKind
from d810.recon.flow.transition_builder import _get_state_var_stkoff


def _detector_with_state_var(state_var: object | None) -> SimpleNamespace:
    return SimpleNamespace(state_machine=SimpleNamespace(state_var=state_var))


def test_get_state_var_stkoff_reads_snapshot_stkoff() -> None:
    detector = _detector_with_state_var(
        MopSnapshot(kind=OperandKind.STACK, stkoff=0x30, size=4)
    )

    assert _get_state_var_stkoff(detector) == 0x30


def test_get_state_var_stkoff_reads_live_stack_ref_shape() -> None:
    detector = _detector_with_state_var(SimpleNamespace(s=SimpleNamespace(off=0x40)))

    assert _get_state_var_stkoff(detector) == 0x40


def test_get_state_var_stkoff_rejects_missing_stack_offset() -> None:
    detector = _detector_with_state_var(MopSnapshot(kind=OperandKind.REGISTER, reg=2))

    assert _get_state_var_stkoff(detector) is None
