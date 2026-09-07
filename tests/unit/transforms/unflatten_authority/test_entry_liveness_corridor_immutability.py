"""Published entry forecasts and allowances cannot retain mutable edge aliases."""

from dataclasses import fields, replace

import pytest

from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.ids import authority_id, canonical_bytes


@pytest.fixture
def entry_records(monkeypatch):
    from .test_transaction_api import (
        test_closed_entry_forecast_flows_from_canonical_proof_to_transaction_binding,
    )

    records = {}
    with monkeypatch.context() as capture:
        for cls in (
            model.EntryEndpointLivenessForecast,
            model.EntryEndpointLivenessAllowance,
        ):
            original = cls.__post_init__

            def post_init(self, original=original):
                original(self)
                records.setdefault(type(self), self)

            capture.setattr(cls, "__post_init__", post_init)
        test_closed_entry_forecast_flows_from_canonical_proof_to_transaction_binding()
    return records


def _with_corridor(record, path, edges):
    values = {field.name: getattr(record, field.name) for field in fields(record)}
    values.update(delivery_path_refs=path, delivery_path_edges=edges)
    if type(record) is model.EntryEndpointLivenessAllowance:
        values["allowance_id"] = authority_id((
            "unflatten.entry-endpoint-liveness-allowance.v1",
            *(value for name, value in values.items() if name != "allowance_id"),
        ))
    return type(record)(**values)


def test_published_forecast_cannot_change_canonical_bytes_through_edge_alias(entry_records):
    source = entry_records[model.EntryEndpointLivenessForecast]
    alias = []
    try:
        published = replace(source, delivery_path_edges=alias)
    except TypeError as error:
        assert "delivery_path_edges" in str(error)
        return
    before = canonical_bytes(published)
    alias.append((0, 1))
    published.__post_init__()
    assert canonical_bytes(published) == before, "published edge alias changed semantic bytes"


@pytest.mark.parametrize("record_type", [
    model.EntryEndpointLivenessForecast,
    model.EntryEndpointLivenessAllowance,
])
@pytest.mark.parametrize("edges", [
    pytest.param([], id="mutable-empty-outer"),
    pytest.param([(0, 1)], id="mutable-outer"),
    pytest.param(([0, 1],), id="mutable-inner"),
])
def test_corridor_rejects_mutable_outer_and_inner_edges(entry_records, record_type, edges):
    source = entry_records[record_type]
    with pytest.raises(TypeError, match="delivery_path_edges"):
        _with_corridor(source, (), edges)


@pytest.mark.parametrize("record_type", [
    model.EntryEndpointLivenessForecast,
    model.EntryEndpointLivenessAllowance,
])
@pytest.mark.parametrize("edges, error", [
    pytest.param(((False, True),), TypeError, id="bool-indices"),
    pytest.param(((0, 1, 2),), ValueError, id="not-a-pair"),
    pytest.param(((1, 0),), ValueError, id="reversed"),
    pytest.param(((0, 2),), ValueError, id="skips-node"),
    pytest.param((), ValueError, id="missing-edge"),
    pytest.param(((0, 1), (0, 1)), ValueError, id="duplicate-edge"),
])
def test_corridor_requires_exact_adjacent_integer_edges(entry_records, record_type, edges, error):
    source = entry_records[record_type]
    dispatcher = (
        source.dispatcher_ref if record_type is model.EntryEndpointLivenessForecast
        else source.dispatcher_old_target_ref
    )
    path = (source.state_write_source_ref, dispatcher)
    with pytest.raises(error, match="delivery_path_edges"):
        _with_corridor(source, path, edges)


@pytest.mark.parametrize("record_type", [
    model.EntryEndpointLivenessForecast,
    model.EntryEndpointLivenessAllowance,
])
def test_empty_corridor_rejects_orphan_edges(entry_records, record_type):
    with pytest.raises(ValueError, match="delivery_path_edges"):
        _with_corridor(entry_records[record_type], (), ((0, 1),))


@pytest.mark.parametrize("record_type", [
    model.EntryEndpointLivenessForecast,
    model.EntryEndpointLivenessAllowance,
])
def test_corridor_rejects_float_indices_before_deriving_identity(entry_records, record_type):
    source = entry_records[record_type]
    dispatcher = (
        source.dispatcher_ref if record_type is model.EntryEndpointLivenessForecast
        else source.dispatcher_old_target_ref
    )
    with pytest.raises(TypeError, match="delivery_path_edges"):
        replace(source, delivery_path_refs=(source.state_write_source_ref, dispatcher),
                delivery_path_edges=((0.0, 1.0),))


@pytest.mark.parametrize("record_type", [
    model.EntryEndpointLivenessForecast,
    model.EntryEndpointLivenessAllowance,
])
def test_canonical_corridor_revalidation_preserves_identity_and_bytes(entry_records, record_type):
    source = entry_records[record_type]
    dispatcher = (
        source.dispatcher_ref if record_type is model.EntryEndpointLivenessForecast
        else source.dispatcher_old_target_ref
    )
    edges = ((0, 1),)
    record = _with_corridor(source, (source.state_write_source_ref, dispatcher), edges)
    before = canonical_bytes(record)
    record.__post_init__()
    assert record.delivery_path_edges is edges
    assert canonical_bytes(record) == before


def test_legacy_empty_corridor_allowance_identity_remains_valid(entry_records):
    source = entry_records[model.EntryEndpointLivenessAllowance]
    values = tuple(
        getattr(source, field.name) for field in fields(source)
        if field.name not in {"allowance_id", "delivery_path_refs", "delivery_path_edges"}
    )
    legacy_id = authority_id(("unflatten.entry-endpoint-liveness-allowance.v1", *values))
    record = replace(source, allowance_id=legacy_id, delivery_path_refs=(), delivery_path_edges=())
    before = canonical_bytes(record)
    record.__post_init__()
    assert record.allowance_id == legacy_id
    assert canonical_bytes(record) == before
