"""Native pass-contract vocabulary registry tests."""
from __future__ import annotations

from d810.passes.contract_vocabulary import (
    contract_vocabulary_entries,
    contract_vocabulary_entry,
    is_legacy_contract_name,
    legacy_contract_aliases,
    resolve_contract_name,
)


def test_contract_vocabulary_registry_contains_initial_namespaces():
    entries = contract_vocabulary_entries()

    assert {entry.namespace for entry in entries} >= {
        "ir",
        "effect",
        "role",
        "recovered",
    }
    assert contract_vocabulary_entry("ir.branch_target").kind == "evidence"
    assert contract_vocabulary_entry("role.dispatcher").kind == "role"
    assert contract_vocabulary_entry("recovered.state_transition").kind == "recovered"


def test_contract_vocabulary_legacy_aliases_are_centralized():
    aliases = legacy_contract_aliases()

    assert aliases["dispatcher_family"] == "role.dispatcher"
    assert aliases["state_transition"] == "recovered.state_transition"
    assert aliases["semantic_region"] == "recovered.region"
    assert aliases["recovered_cfg_edge"] == "recovered.cfg_edge"
    assert aliases["branch_targets"] == "ir.branch_target"
    assert aliases["state_variable_writes"] == "ir.state_variable_write"
    assert aliases["dispatcher_predicates"] == "role.dispatcher_predicate"
    assert aliases["stale_cfg_shape"] == "ir.cfg_shape.stale"


def test_contract_vocabulary_resolves_known_aliases_only():
    assert is_legacy_contract_name("branch_targets") is True
    assert resolve_contract_name("branch_targets") == "ir.branch_target"
    assert resolve_contract_name("ir.branch_target") == "ir.branch_target"
    assert resolve_contract_name("custom.experimental") == "custom.experimental"
