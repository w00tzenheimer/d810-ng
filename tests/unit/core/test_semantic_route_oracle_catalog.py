"""Exact-input catalog selection for portable semantic-route authority."""

from __future__ import annotations

from copy import deepcopy

import pytest

from d810.core.semantic_route_oracle import (
    ReferenceRouteOracleCatalog,
    ReferenceRouteOracleRegistry,
)
from tests.native_preanalysis import make_native_key


_FUNCTION_EA = 0x40A560
_FIXTURE_SHA256 = "a" * 64


def _manifest() -> dict[str, object]:
    return {
        "schema_version": 2,
        "publication_root_ea": "0x40AE3E",
        "run": {
            "run_id": "a560-v33-boundary",
            "function_ea": "0x40A560",
            "fixture_sha256": _FIXTURE_SHA256,
            "reference_binary_sha256": "b" * 64,
            "candidate_binary_sha256": _FIXTURE_SHA256,
            "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            "runtime_image": "d810-idapro-9.3-test-runtime:py313-v1",
            "runtime_image_id": "sha256:" + "c" * 64,
            "cache_disabled": True,
            "metadata": {"purpose": "unit-test"},
        },
        "routes": [
            {
                "route_id": "rhad:0x40A560:flow_route:0x40B52E",
                "function_ea": "0x40A560",
                "owner_ea": "0x40B51B",
                "rewrite_anchor_ea": "0x40B52E",
                "corridor": [["0x40B51B", "0x40B534"]],
                "reference_phase": "flow_route",
                "original_transfer_kind": "conditional",
                "final_transfer_kind": "direct",
                "direct_target_ea": "0x40AE3E",
                "true_target_ea": None,
                "false_target_ea": None,
                "predicate_kind": None,
                "reference_ledger_identity": "flow_route:0x40B52E",
                "reference_ledger": {"status": "committed"},
            }
        ],
    }


def _native_key(*, digest: str = _FIXTURE_SHA256):
    return make_native_key(
        input_identity=f"sha256:{digest}",
        function_rva=0xA560,
    )


def test_catalog_selects_only_exact_input_function_and_anchor_set() -> None:
    catalog = ReferenceRouteOracleCatalog.from_manifest(_manifest())

    selection = catalog.reference_oracle_for(
        _FUNCTION_EA,
        _native_key(),
        (0x40B52E,),
    )

    assert selection is not None
    assert selection.run == catalog.run
    assert selection.publication_root_ea == 0x40AE3E
    assert tuple(route.rewrite_anchor_ea for route in selection.routes) == (0x40B52E,)

    scope = catalog.reference_oracle_scope_for(
        _FUNCTION_EA,
        _native_key(),
    )
    assert scope is not None
    assert scope.publication_root_ea == 0x40AE3E
    assert scope.routes == catalog.routes

    assert (
        catalog.reference_oracle_for(
            _FUNCTION_EA,
            _native_key(digest="d" * 64),
            (0x40B52E,),
        )
        is None
    )
    assert catalog.reference_oracle_for(0x40D200, _native_key(), (0x40B52E,)) is None
    assert (
        catalog.reference_oracle_for(_FUNCTION_EA, _native_key(), (0x40B52F,)) is None
    )


@pytest.mark.parametrize(
    ("field", "duplicate_value", "message"),
    (
        ("route_id", "rhad:0x40A560:flow_route:0x40B52E", "route ids"),
        ("rewrite_anchor_ea", "0x40B52E", "rewrite anchors"),
        (
            "reference_ledger_identity",
            "flow_route:0x40B52E",
            "ledger identities",
        ),
    ),
)
def test_catalog_rejects_ambiguous_route_authority(
    field: str,
    duplicate_value: str,
    message: str,
) -> None:
    manifest = _manifest()
    routes = manifest["routes"]
    assert isinstance(routes, list)
    duplicate = deepcopy(routes[0])
    duplicate["route_id"] = "rhad:0x40A560:flow_route:0x40B52F"
    duplicate["rewrite_anchor_ea"] = "0x40B52F"
    duplicate["reference_ledger_identity"] = "flow_route:0x40B52F"
    duplicate[field] = duplicate_value
    routes.append(duplicate)

    with pytest.raises(ValueError, match=message):
        ReferenceRouteOracleCatalog.from_manifest(manifest)


def test_catalog_rejects_unpinned_or_cross_function_authority() -> None:
    unpinned = _manifest()
    run = unpinned["run"]
    assert isinstance(run, dict)
    run["cache_disabled"] = False
    with pytest.raises(ValueError, match="cache-disabled"):
        ReferenceRouteOracleCatalog.from_manifest(unpinned)

    malformed = _manifest()
    malformed_run = malformed["run"]
    assert isinstance(malformed_run, dict)
    malformed_run["cache_disabled"] = "true"
    with pytest.raises(ValueError, match="must be a boolean"):
        ReferenceRouteOracleCatalog.from_manifest(malformed)

    cross_function = _manifest()
    routes = cross_function["routes"]
    assert isinstance(routes, list)
    route = routes[0]
    assert isinstance(route, dict)
    route["function_ea"] = "0x40D200"
    with pytest.raises(ValueError, match="function"):
        ReferenceRouteOracleCatalog.from_manifest(cross_function)


def test_registry_selects_one_exact_function_catalog() -> None:
    second = deepcopy(_manifest())
    second_run = second["run"]
    second_routes = second["routes"]
    assert isinstance(second_run, dict)
    assert isinstance(second_routes, list)
    second_route = second_routes[0]
    assert isinstance(second_route, dict)
    second_run["run_id"] = "d200-v33-boundary"
    second_run["function_ea"] = "0x40D200"
    second["publication_root_ea"] = "0x40EAA7"
    second_route["route_id"] = "test:0x40D200:flow_route:0x40D348"
    second_route["function_ea"] = "0x40D200"
    second_route["owner_ea"] = "0x40D340"
    second_route["rewrite_anchor_ea"] = "0x40D348"
    second_route["corridor"] = [["0x40D340", "0x40D350"]]
    second_route["direct_target_ea"] = "0x40EAA7"
    second_route["reference_ledger_identity"] = "flow_route:0x40D348"
    registry = ReferenceRouteOracleRegistry.from_manifests((_manifest(), second))

    selection = registry.reference_oracle_for(
        0x40D200,
        make_native_key(
            input_identity=f"sha256:{_FIXTURE_SHA256}",
            function_rva=0xD200,
        ),
        (0x40D348,),
    )

    assert selection is not None
    assert selection.run.run_id == "d200-v33-boundary"
    assert selection.publication_root_ea == 0x40EAA7
    assert selection.routes[0].rewrite_anchor_ea == 0x40D348


def test_catalog_requires_one_portable_publication_root() -> None:
    missing = _manifest()
    del missing["publication_root_ea"]
    with pytest.raises(ValueError, match="publication_root_ea"):
        ReferenceRouteOracleCatalog.from_manifest(missing)

    malformed = _manifest()
    malformed["publication_root_ea"] = -1
    with pytest.raises(ValueError, match="publication root"):
        ReferenceRouteOracleCatalog.from_manifest(malformed)


def test_registry_rejects_duplicate_input_function_authority() -> None:
    duplicate = deepcopy(_manifest())
    duplicate_run = duplicate["run"]
    assert isinstance(duplicate_run, dict)
    duplicate_run["run_id"] = "duplicate-a560-boundary"

    with pytest.raises(ValueError, match="input/function"):
        ReferenceRouteOracleRegistry.from_manifests((_manifest(), duplicate))
