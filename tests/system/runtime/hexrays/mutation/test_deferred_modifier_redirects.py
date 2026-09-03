"""Contracts for production redirect lowering."""

from types import SimpleNamespace

from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier


def test_goto_redirect_uses_existing_create_and_redirect_primitive(monkeypatch):
    calls = []
    block = SimpleNamespace(
        serial=3,
        nsucc=lambda: 1,
        succ=lambda index: 7,
    )
    modifier = DeferredGraphModifier.__new__(DeferredGraphModifier)

    def create_and_redirect(*args, **kwargs):
        calls.append((args, kwargs))
        return True

    monkeypatch.setattr(modifier, "_apply_create_and_redirect", create_and_redirect)

    assert modifier._apply_goto_change(block, 11) is True
    assert calls == [
        (
            (block, 11, (), False),
            {"expected_serial": None, "old_target_serial": 7},
        )
    ]
