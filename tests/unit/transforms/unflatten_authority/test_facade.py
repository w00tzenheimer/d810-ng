"""Behavioral tests for the patch-transaction-facing authority facade."""

from d810.transforms import unflatten_authority_facade
from d810.transforms.unflatten_authority import transaction_api


def test_facade_uses_the_live_canonical_transaction_callable(monkeypatch) -> None:
    """Canonical callable replacements remain visible through the facade."""

    sentinel = object()

    def replacement(verdict, kind):
        assert verdict is None
        assert kind == "removal"
        return sentinel

    monkeypatch.setattr(transaction_api, "compatibility_projection", replacement)

    assert unflatten_authority_facade.compatibility_projection(None, "removal") is sentinel
