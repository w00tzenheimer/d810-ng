"""Provider cleanup visits registered participants, not the pattern catalogue."""

from d810.optimizers.microcode.instructions.handler import InstructionOptimizer


class _PlainRule:
    pass


class _ProviderRule:
    def __init__(self):
        self.calls = []

    def finalize_provider_observation(self, context, *, accepted, reason):
        self.calls.append((accepted, reason))


def _optimizer():
    return InstructionOptimizer([], None)


def test_cleanup_does_not_dispatch_non_provider_rules(monkeypatch):
    optimizer = _optimizer()
    for _ in range(100):
        optimizer.rules.add(_PlainRule())
    provider = _ProviderRule()
    optimizer.rules.add(provider)
    visited = []
    original = optimizer._finalize_provider_rule

    def finalize(rule, *args, **kwargs):
        visited.append(rule)
        return original(rule, *args, **kwargs)

    monkeypatch.setattr(optimizer, "_finalize_provider_rule", finalize)
    optimizer.clear_pending_provider_observation()
    optimizer.clear_pending_provider_observation()
    assert provider.calls == [(False, "callback_cleanup")]
    assert visited == [provider]


def test_cleanup_uses_replaced_hook_and_reset_discards_participants():
    optimizer = _optimizer()
    provider = _ProviderRule()
    optimizer.rules.add(provider)
    calls = []
    provider.finalize_provider_observation = lambda *a, **kw: calls.append(kw)
    optimizer.clear_pending_provider_observation()
    assert len(calls) == 1
    assert provider.calls == []
    optimizer.reset_rules()
    optimizer.clear_pending_provider_observation()
    assert len(calls) == 1


def test_reregistration_refreshes_provider_capability():
    optimizer = _optimizer()
    rule = _PlainRule()
    optimizer.rules.add(rule)
    calls = []
    rule.finalize_provider_observation = lambda *a, **kw: calls.append(kw)
    optimizer.rules.add(rule)
    optimizer.clear_pending_provider_observation()
    assert len(calls) == 1
    assert len(optimizer.rules) == 1


def test_late_provider_capability_preserves_original_rule_order():
    optimizer = _optimizer()
    first, second = _PlainRule(), _ProviderRule()
    optimizer.rules.add(first)
    optimizer.rules.add(second)
    order = []
    first.finalize_provider_observation = lambda *a, **kw: order.append("first")
    second.finalize_provider_observation = lambda *a, **kw: order.append("second")
    optimizer.rules.add(first)
    optimizer.clear_pending_provider_observation()
    assert order == ["first", "second"]
