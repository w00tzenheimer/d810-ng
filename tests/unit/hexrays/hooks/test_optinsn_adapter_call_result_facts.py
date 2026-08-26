"""Callback-local validated fact-view plumbing for instruction optimizers."""

from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.hexrays.hooks.optinsn_adapter import (  # noqa: E402
    InstructionOptimizerManager,
)


class _RecordingOptimizer:
    def __init__(self) -> None:
        self.bound = []

    def bind_validated_fact_view(self, view) -> None:
        self.bound.append(view)


def _snapshot_manager(provider=None):
    manager = object.__new__(InstructionOptimizerManager)
    manager._validated_fact_view_provider = provider
    manager._execution_scope_service = None
    manager._execution_scope_project_name = ""
    manager._execution_scope_idb_key = ""
    manager._execution_scope_func_ea = -1
    manager.current_maturity = None
    manager.current_blk_serial = None
    manager.generate_z3_code = False
    manager.dump_intermediate_microcode = False
    manager._decompilation_lifecycle = None
    manager._fact_consumer_callback = None
    manager._run_later_scheduler = None
    manager._active_instruction_rule_names_by_maturity = {}
    manager._residual_admission_cache_key = None
    manager._residual_admission_cache_value = False
    manager._scheduled_stage_identities = frozenset()
    manager._scheduled_implementation_names = frozenset()
    manager.instruction_optimizers = []
    manager._active_optimizers = []
    manager.analyzer = object()
    return manager


def _callback_manager(optimizer, provider=None):
    manager = _snapshot_manager(provider)
    manager.instruction_optimizers = [optimizer]
    manager._active_optimizers = [optimizer]
    manager._cycle_quarantined_rule_names = {}
    manager._last_optimizer_tried = None
    manager._resolve_active_instruction_rule_names = lambda _blk: frozenset()
    manager._has_active_fast_mba_provider = lambda **_kwargs: False
    manager._set_residual_admission = lambda *_args, **_kwargs: None
    manager._capture_callback_nop_sites = lambda _blk: None
    manager._report_callback_nop_delta = lambda *args, **kwargs: None
    manager.log_info_on_input = lambda *_args: True
    return manager


def _block():
    mba = SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_LOCOPT)
    return SimpleNamespace(mba=mba, serial=7)


def test_provider_is_snapshotted_and_restored():
    def original(*_args):
        return None

    def replacement(*_args):
        return None

    manager = _snapshot_manager(original)
    manager._capture_child_runtime_state = lambda _optimizer: object()

    snapshot = manager.capture_runtime_state()
    manager._validated_fact_view_provider = replacement
    manager.restore_runtime_state(snapshot)

    assert manager._validated_fact_view_provider is original
    assert snapshot.validated_fact_view_provider is original


def test_manager_requests_view_for_exact_function_and_maturity():
    optimizer = _RecordingOptimizer()
    calls = []
    view = object()
    manager = _callback_manager(
        optimizer,
        lambda function_ea, maturity: calls.append((function_ea, maturity)) or view,
    )

    assert manager.func(_block(), SimpleNamespace(ea=0x401010)) is True

    assert calls == [(0x401000, ida_hexrays.MMAT_LOCOPT)]


def test_manager_binds_view_only_during_optimizer_callback():
    optimizer = _RecordingOptimizer()
    view = object()
    manager = _callback_manager(optimizer, lambda *_args: view)

    manager.func(_block(), SimpleNamespace(ea=0x401010))

    assert optimizer.bound == [view, None]


def test_manager_clears_view_when_optimizer_raises():
    optimizer = _RecordingOptimizer()
    manager = _callback_manager(optimizer, lambda *_args: object())
    manager.log_info_on_input = lambda *_args: (_ for _ in ()).throw(
        RuntimeError("optimizer failed")
    )

    with pytest.raises(RuntimeError, match="optimizer failed"):
        manager.func(_block(), SimpleNamespace(ea=0x401010))

    assert optimizer.bound[-1] is None


def test_missing_provider_binds_none_and_preserves_safe_default():
    optimizer = _RecordingOptimizer()
    manager = _callback_manager(optimizer)

    manager.func(_block(), SimpleNamespace(ea=0x401010))

    assert optimizer.bound == [None]
