"""Dispatch capabilities are reused without changing optimizer arguments."""

from types import MethodType, SimpleNamespace

import pytest

from d810.hexrays.hooks import optinsn_adapter as adapter


class _Explicit:
    rules = ()

    def __init__(self):
        self.seen = []

    def get_optimized_instruction(
        self,
        blk,
        ins,
        *,
        contextual_anchor_ins,
        allowed_rule_names,
        scheduled_rule_names,
        observation_context_factory,
    ):
        self.seen.append(observation_context_factory)


class _Legacy(_Explicit):
    def get_optimized_instruction(
        self,
        blk,
        ins,
        *,
        contextual_anchor_ins,
        allowed_rule_names,
        scheduled_rule_names,
    ):
        self.seen.append("legacy")


class _Kwargs(_Explicit):
    def get_optimized_instruction(self, blk, ins, **kwargs):
        self.seen.append(kwargs["observation_context_factory"])


def _manager(optimizer):
    manager = object.__new__(adapter.InstructionOptimizerManager)
    manager.instruction_optimizers = []
    manager._active_optimizers = [optimizer]
    manager.current_maturity = 1
    manager._scheduled_implementation_names = frozenset()
    manager._resolve_active_instruction_rule_names = lambda blk: frozenset()
    manager._has_active_fast_mba_provider = lambda **kwargs: False
    manager._instruction_commit_context_for = lambda blk, ins: None
    manager._cycle_receipt_scope_key = lambda **kwargs: ()
    manager._allowed_rule_names_for_callback = lambda *args: frozenset()
    manager._observation_context_for_rule = object()
    return manager


def _run(manager):
    assert (
        manager.optimize(None, SimpleNamespace(ea=0x401010), analyze_on_abstain=False)
        is False
    )


def _count_signatures(monkeypatch, error=None):
    inspected = []
    original = adapter.inspect.signature

    def signature(callback):
        inspected.append(callback)
        if error is not None:
            raise error("uninspectable")
        return original(callback)

    monkeypatch.setattr(adapter.inspect, "signature", signature)
    return inspected


@pytest.mark.parametrize("optimizer_type", [_Explicit, _Legacy, _Kwargs])
def test_registered_dispatch_reuses_capability(monkeypatch, optimizer_type):
    optimizer = optimizer_type()
    manager = _manager(optimizer)
    inspected = _count_signatures(monkeypatch)
    manager.add_optimizer(optimizer)
    for _ in range(5):
        _run(manager)
    expected = (
        "legacy" if optimizer_type is _Legacy else manager._observation_context_for_rule
    )
    assert optimizer.seen == [expected] * 5
    assert len(inspected) == 1


def test_dispatch_rechecks_replaced_bound_method(monkeypatch):
    optimizer = _Explicit()
    manager = _manager(optimizer)
    inspected = _count_signatures(monkeypatch)
    manager.add_optimizer(optimizer)
    _run(manager)
    optimizer.get_optimized_instruction = MethodType(
        _Legacy.get_optimized_instruction, optimizer
    )
    _run(manager)
    _run(manager)
    assert optimizer.seen == [manager._observation_context_for_rule, "legacy", "legacy"]
    assert len(inspected) == 2


def test_dispatch_rechecks_class_replacement(monkeypatch):
    class Child(_Legacy):
        pass

    optimizer = Child()
    manager = _manager(optimizer)
    inspected = _count_signatures(monkeypatch)
    manager.add_optimizer(optimizer)
    _run(manager)
    monkeypatch.setattr(
        Child, "get_optimized_instruction", _Kwargs.get_optimized_instruction
    )
    _run(manager)
    _run(manager)
    assert optimizer.seen == [
        "legacy",
        manager._observation_context_for_rule,
        manager._observation_context_for_rule,
    ]
    assert len(inspected) == 2


@pytest.mark.parametrize("error", [TypeError, ValueError])
def test_uninspectable_dispatch_keeps_context_fallback(monkeypatch, error):
    optimizer = _Kwargs()
    manager = _manager(optimizer)
    inspected = _count_signatures(monkeypatch, error)
    manager.add_optimizer(optimizer)
    _run(manager)
    _run(manager)
    assert optimizer.seen == [manager._observation_context_for_rule] * 2
    assert len(inspected) == 1


def test_override_dispatch_is_scoped_to_manager(monkeypatch):
    optimizer = _Kwargs()
    first, second = _manager(optimizer), _manager(optimizer)
    inspected = _count_signatures(monkeypatch)
    for manager in (first, second, first, second):
        manager.optimize(
            None,
            SimpleNamespace(ea=0x401010),
            optimizers_override=(optimizer,),
            analyze_on_abstain=False,
        )
    assert (
        optimizer.seen
        == [first._observation_context_for_rule, second._observation_context_for_rule]
        * 2
    )
    assert len(inspected) == 2


def test_dispatch_rechecks_plain_callable_replacement(monkeypatch):
    optimizer = _Legacy()
    manager = _manager(optimizer)
    inspected = _count_signatures(monkeypatch)
    manager.add_optimizer(optimizer)
    _run(manager)

    def replacement(blk, ins, **kwargs):
        optimizer.seen.append(kwargs["observation_context_factory"])

    optimizer.get_optimized_instruction = replacement
    _run(manager)
    _run(manager)
    assert optimizer.seen == [
        "legacy",
        manager._observation_context_for_rule,
        manager._observation_context_for_rule,
    ]
    assert len(inspected) == 2


def test_dispatch_rechecks_explicit_signature_replacement(monkeypatch):
    optimizer = _Legacy()
    manager = _manager(optimizer)

    def callback(blk, ins, **kwargs):
        optimizer.seen.append(kwargs.get("observation_context_factory", "legacy"))

    callback.__signature__ = adapter.inspect.signature(
        optimizer.get_optimized_instruction
    )
    optimizer.get_optimized_instruction = callback
    inspected = _count_signatures(monkeypatch)
    manager.add_optimizer(optimizer)
    _run(manager)
    del callback.__signature__
    _run(manager)
    _run(manager)
    assert optimizer.seen == [
        "legacy",
        manager._observation_context_for_rule,
        manager._observation_context_for_rule,
    ]
    assert len(inspected) == 2


def test_reregistration_refreshes_in_place_wrapper_metadata(monkeypatch):
    optimizer = _Legacy()
    manager = _manager(optimizer)

    def callback(blk, ins, **kwargs):
        optimizer.seen.append(kwargs.get("observation_context_factory", "legacy"))

    callback.__wrapped__ = optimizer.get_optimized_instruction
    optimizer.get_optimized_instruction = callback
    inspected = _count_signatures(monkeypatch)
    manager.add_optimizer(optimizer)
    _run(manager)
    callback.__wrapped__ = _Kwargs().get_optimized_instruction
    manager.add_optimizer(optimizer)
    _run(manager)
    _run(manager)
    assert optimizer.seen == [
        "legacy",
        manager._observation_context_for_rule,
        manager._observation_context_for_rule,
    ]
    assert len(inspected) == 2
