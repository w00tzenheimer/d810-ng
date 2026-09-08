"""The native facade retains the existing owner through projected preparation."""

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.transforms.cfg_transaction import TransactionAttemptId
from d810.transforms import unflatten_authority_facade as facade
from d810.transforms.unflatten_authority import transaction_api
from d810.transforms.unflatten_authority.structural_transaction import (
    StructuralTransactionContext, StructuralTransactionCoordinates,
)


def _context():
    attempt = TransactionAttemptId.new("plan", "gateway", 3)
    return StructuralTransactionContext(
        attempt, NativePreanalysisKey("input", "metapc", 64, 1, "function", "profile", "sdk"),
        StructuralTransactionCoordinates("snapshot", 4, 3, None, 3),
    )


def test_inventory_owner_crosses_facade_without_replacement(monkeypatch):
    context = _context()
    received = []
    sentinel = object()

    def prepare(**kwargs):
        received.append(kwargs["structural_context"])
        return sentinel

    monkeypatch.setattr(facade._transaction_api, "prepare_unflatten_authority_timed", prepare)
    assert facade.prepare_unflatten_authority_timed(
        source=None, projection=None, plan=None, attempt_id=None, generic_gates=None,
        structural_context=context,
    ) is sentinel
    assert received == [context]


def test_inventory_owner_survives_preparation_codec_session(monkeypatch):
    context = _context()
    received = []
    sentinel = object()

    def prepare(**kwargs):
        received.append(kwargs["structural_context"])
        assert kwargs["structural_context"].source_arena.structural is context.source
        return sentinel

    monkeypatch.setattr(transaction_api, "_prepare_unflatten_authority_in_session", prepare)
    assert transaction_api.prepare_unflatten_authority(
        source=None, projection=None, plan=None, attempt_id=None, generic_gates=None,
        structural_context=context,
    ) is sentinel
    assert received == [context]
    assert not context.source_arena.is_closed


def test_inventory_owner_reaches_private_route_realization(monkeypatch):
    context = _context()
    claim_inventory = object()
    sentinel = object()
    received = []
    monkeypatch.setattr(
        transaction_api.authority_bind,
        "_bind_transaction_projected_claim_inventory",
        lambda **kwargs: claim_inventory,
    )

    def realize(**kwargs):
        assert kwargs["claim_inventory"] is claim_inventory
        received.append(kwargs["structural_context"])
        return sentinel

    monkeypatch.setattr(
        transaction_api.authority_bind,
        "_realize_projected_routes_from_claim_inventory", realize,
    )
    assert transaction_api.realize_projected_routes(
        authority_id_value="authority", derived_claim_inventory=None,
        source_route_authority=None, attempt_id=None, projected_inventory=None,
        raw_effect_gate_fact=None, legacy_effective_gate_facts=None,
        structural_context=context,
    ) is sentinel
    assert received == [context]
