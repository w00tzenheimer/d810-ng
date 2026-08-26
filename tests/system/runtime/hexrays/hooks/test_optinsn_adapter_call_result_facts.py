"""Runtime lifecycle coverage for callback-local validated fact views."""

from types import SimpleNamespace

import pytest
import ida_hexrays

from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager


class _RecordingOptimizer:
    def __init__(self, *, current=None, fail=False) -> None:
        self.bound = []
        self.validated_fact_view = current
        self.fail = fail
        self.rules = SimpleNamespace(_rules={})

    def bind_validated_fact_view(self, view) -> None:
        if self.fail:
            self.validated_fact_view = view
            self.fail = False
            raise RuntimeError("binder failed")
        self.validated_fact_view = view
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
    manager._capture_child_runtime_state = lambda _optimizer: object()
    manager._restore_child_runtime_state = lambda _snapshot: None
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
    return SimpleNamespace(mba=mba, serial=7, mark_lists_dirty=lambda: None)


def _instruction(ea=0x401010):
    return SimpleNamespace(ea=ea, _print=lambda: "instruction", optimize_solo=lambda: None)


def test_provider_is_snapshotted_and_restored():
    def original(*_args):
        return None

    def replacement(*_args):
        return None

    manager = _snapshot_manager(original)
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
    manager.log_info_on_input = lambda *_args: False
    manager.optimize = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("optimizer failed")
    )

    # RuntimeError from the optimizer is handled by the production callback,
    # while its finally block must still restore the prior binding.
    assert manager.func(_block(), _instruction()) is False

    assert optimizer.bound[-1] is None


def test_missing_provider_binds_none_and_preserves_safe_default():
    optimizer = _RecordingOptimizer()
    manager = _callback_manager(optimizer)

    manager.func(_block(), _instruction())

    assert optimizer.bound[-1] is None


def test_provider_exception_does_not_bind_children():
    optimizer = _RecordingOptimizer(current="prior")

    def provider(*_args):
        raise RuntimeError("provider failed")

    manager = _callback_manager(optimizer, provider)

    with pytest.raises(RuntimeError, match="provider failed"):
        manager.func(_block(), _instruction())

    assert optimizer.bound == []
    assert optimizer.validated_fact_view == "prior"


def test_partial_bind_failure_restores_all_prior_views():
    first = _RecordingOptimizer(current="first-prior")
    second = _RecordingOptimizer(current="second-prior", fail=True)
    manager = _callback_manager(first, lambda *_args: object())
    manager.instruction_optimizers = [first, second]

    with pytest.raises(RuntimeError, match="binder failed"):
        manager.func(_block(), _instruction())

    assert first.validated_fact_view == "first-prior"
    assert second.validated_fact_view == "second-prior"


def test_nested_callbacks_restore_outer_view():
    optimizer = _RecordingOptimizer(current=None)
    views = iter(("outer", "inner"))
    manager = _callback_manager(optimizer, lambda *_args: next(views))
    manager.log_info_on_input = lambda *_args: False
    nested_state = []
    entered = False

    def optimize(*_args, **_kwargs):
        nonlocal entered
        nested_state.append(optimizer.validated_fact_view)
        if entered:
            return True
        entered = True
        assert manager.func(_block(), _instruction(0x401011)) is True
        nested_state.append(optimizer.validated_fact_view)
        return True

    manager.optimize = optimize
    manager.instruction_visitor = SimpleNamespace()
    manager._capture_callback_nop_sites = lambda _blk: None
    manager._report_callback_nop_delta = lambda *args, **kwargs: None
    block = _block()
    instruction = _instruction()

    # Avoid invoking unrelated mutation verification in this lifecycle test.
    import d810.hexrays.hooks.optinsn_adapter as adapter

    original_verify = adapter.safe_verify
    adapter.safe_verify = lambda *_args, **_kwargs: None
    try:
        assert manager.func(block, instruction) is True
    finally:
        adapter.safe_verify = original_verify

    assert nested_state == ["outer", "inner", "outer"]
    assert optimizer.validated_fact_view is None


def test_nested_callbacks_restore_outer_view_for_production_z3_optimizer(monkeypatch):
    from d810.optimizers.microcode.instructions.z3.handler import Z3Optimizer

    optimizer = Z3Optimizer([], None)
    views = iter(("outer", "inner"))
    manager = _callback_manager(optimizer, lambda *_args: next(views))
    manager.log_info_on_input = lambda *_args: False
    nested_state = []
    entered = False

    def optimize(*_args, **_kwargs):
        nonlocal entered
        nested_state.append(optimizer.validated_fact_view)
        if entered:
            return True
        entered = True
        assert manager.func(_block(), _instruction(0x401011)) is True
        nested_state.append(optimizer.validated_fact_view)
        return True

    manager.optimize = optimize
    import d810.hexrays.hooks.optinsn_adapter as adapter

    monkeypatch.setattr(adapter, "safe_verify", lambda *_args, **_kwargs: None)
    assert manager.func(_block(), _instruction()) is True

    assert nested_state == ["outer", "inner", "outer"]
    assert optimizer.validated_fact_view is None


def test_partial_bind_failure_restores_production_z3_optimizer_view():
    from d810.optimizers.microcode.instructions.z3.handler import Z3Optimizer

    class FailingOptimizer(Z3Optimizer):
        def __init__(self, *args):
            super().__init__(*args)
            self.fail_once = True

        def bind_validated_fact_view(self, view):
            if self.fail_once:
                self.fail_once = False
                raise RuntimeError("production binder failed")
            super().bind_validated_fact_view(view)

    first = Z3Optimizer([], None)
    second = FailingOptimizer([], None)
    first.bind_validated_fact_view("first-prior")
    second._validated_fact_view = "second-prior"
    manager = _callback_manager(first, lambda *_args: object())
    manager.instruction_optimizers = [first, second]

    with pytest.raises(RuntimeError, match="production binder failed"):
        manager.func(_block(), _instruction())

    assert first.validated_fact_view == "first-prior"
    assert second.validated_fact_view == "second-prior"


def test_manager_binding_reaches_z3_predicate_and_records_call_query(monkeypatch):
    """The production callback seam carries its view into a real Z3 rule."""
    from d810.analyses.value_flow.model import ValidatedFactView
    from d810.backends.ast import z3 as z3_backend
    from d810.evaluator.hexrays_microcode import def_search
    from d810.hexrays.expr.ast import AstLeaf
    from d810.optimizers.microcode.instructions.z3 import handler
    from d810.optimizers.microcode.instructions.z3.predicates import Z3lnotRuleGeneric
    from tests.system.runtime.evaluator.test_def_search_mop_snapshot import (
        _call_result_test_parts,
    )

    assignment, call, destination, block, use = _call_result_test_parts()
    block.mark_lists_dirty = lambda: None
    monkeypatch.setattr(def_search, "find_def_in_block", lambda *_args: assignment)
    monkeypatch.setattr(
        def_search, "_materialize_mop_for_tracking", lambda mop, *_a, **_k: mop
    )
    # The fixture intentionally uses immutable MopSnapshots. Bypass only the
    # native AST conversion so the real contextual resolver and Z3 prover can
    # still run without constructing a live mop_t outside Hex-Rays.
    monkeypatch.setattr(
        z3_backend, "mop_to_ast", lambda *_args, **_kwargs: AstLeaf("call_result")
    )
    seen_queries = []
    original_refiner = handler.refine_call_result

    def recording_refiner(query, view):
        seen_queries.append(query)
        return original_refiner(query, view)

    monkeypatch.setattr(handler, "refine_call_result", recording_refiner)

    rule = Z3lnotRuleGeneric()

    class _Candidate:
        dst_mop = SimpleNamespace(size=1)

        def __getitem__(self, name):
            assert name == "x_0"
            return SimpleNamespace(mop=use)

        def add_constant_leaf(self, *_args):
            raise AssertionError("an empty validated view must not prove lnot")

    class _Z3Child:
        rules = (rule,)

        def __init__(self):
            self.validated_fact_view = None

        def bind_validated_fact_view(self, view):
            self.validated_fact_view = view
            rule.bind_validated_fact_view(view)

        def get_optimized_instruction(self, blk, ins, **_kwargs):
            rule._current_blk = blk
            rule._current_ins = ins
            rule._definition_search_ins = ins
            try:
                rule.check_candidate(_Candidate())
            finally:
                rule._current_blk = None
                rule._current_ins = None
                rule._definition_search_ins = None
            return None

    def assert_view(function_ea, maturity):
        assert function_ea == block.mba.entry_ea
        assert maturity == block.mba.maturity
        return ValidatedFactView(maturity="MMAT_LOCOPT")

    child = _Z3Child()
    manager = _callback_manager(
        child,
        assert_view,
    )
    manager.log_info_on_input = lambda *_args: False
    manager.optimize = lambda blk, ins: (
        child.get_optimized_instruction(blk, ins),
        True,
    )[1]

    import d810.hexrays.hooks.optinsn_adapter as adapter

    monkeypatch.setattr(adapter, "safe_verify", lambda *_args, **_kwargs: None)
    assert manager.func(block, SimpleNamespace(ea=0x401100, optimize_solo=lambda: None))
    assert len(seen_queries) == 2
    assert all(query.function_ea == block.mba.entry_ea for query in seen_queries)
    assert all(query.maturity == block.mba.maturity for query in seen_queries)
    assert all(query.call_ea == call.ea for query in seen_queries)
    assert all(query.callee_ea == 0x402000 for query in seen_queries)
    assert all(query.result_location.kind.name == "REGISTER" for query in seen_queries)
    assert all(query.result_location.key == destination.reg for query in seen_queries)
    assert all(query.result_width_bits == destination.size * 8 for query in seen_queries)
    assert child.validated_fact_view is None


def test_hot_replacement_clears_detached_rules_and_inherits_live_view():
    from d810.optimizers.microcode.instructions.z3.handler import Z3Optimizer
    from d810.optimizers.microcode.instructions.z3.predicates import Z3lnotRuleGeneric

    optimizer = Z3Optimizer([], None)
    old = Z3lnotRuleGeneric()
    new = Z3lnotRuleGeneric()
    optimizer.add_rule(old)
    optimizer.bind_validated_fact_view("live")
    assert old.validated_fact_view == "live"

    optimizer.reset_rules()
    assert old.validated_fact_view is None
    optimizer.add_rule(new)

    assert new.validated_fact_view == "live"


def test_snapshot_restore_clears_removed_and_restored_rule_views():
    old = _RecordingOptimizer()
    old.rules = SimpleNamespace(_rules={old: None})
    manager = _snapshot_manager()
    manager.instruction_optimizers = [old]
    manager.analyzer = old
    del manager._restore_child_runtime_state
    manager._capture_child_runtime_state = lambda optimizer: SimpleNamespace(
        optimizer=optimizer,
        rules_store=optimizer.rules,
        rules=(old,),
        pattern_storage_present=False,
        pattern_storage=None,
        indexed_storage_present=False,
        indexed_storage=None,
        allowed_root_opcodes_store=None,
        allowed_root_opcodes=None,
        structural_rules_store=None,
        structural_rules=None,
        has_patternless_rule=None,
        compiled_view=None,
        generation=None,
    )
    manager._validated_fact_view_provider = object()
    # Use the production snapshot shape while a view is bound.
    old.validated_fact_view = "bound"
    snapshot = manager.capture_runtime_state()
    detached = _RecordingOptimizer(current="detached")
    manager.instruction_optimizers[0] = detached
    manager.restore_runtime_state(snapshot)

    assert detached.validated_fact_view is None
    assert old.validated_fact_view is None
