"""Native pass-contract vocabulary registry tests."""
from __future__ import annotations

from d810.passes.contract_vocabulary import (
    contract_name_in,
    contract_name_variants,
    contract_names_equivalent,
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
    assert contract_vocabulary_entry("ir.memory_def.candidate").kind == "evidence"
    assert contract_vocabulary_entry("ir.branch_cond.candidate").kind == "evidence"
    assert contract_vocabulary_entry("ir.induction_var.candidate").kind == "evidence"
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
    assert aliases["carrier_store_candidates"] == "ir.memory_def.candidate"


def test_contract_vocabulary_resolves_known_aliases_only():
    assert is_legacy_contract_name("branch_targets") is True
    assert resolve_contract_name("branch_targets") == "ir.branch_target"
    assert resolve_contract_name("ir.branch_target") == "ir.branch_target"
    assert resolve_contract_name("custom.experimental") == "custom.experimental"


def test_contract_vocabulary_exposes_alias_equivalence_helpers():
    assert contract_name_variants("ir.branch_target") == frozenset(
        {"ir.branch_target", "branch_targets"}
    )
    assert contract_name_variants("branch_targets") == frozenset(
        {"ir.branch_target", "branch_targets"}
    )
    assert contract_names_equivalent("branch_targets", "ir.branch_target")
    assert contract_names_equivalent(
        "carrier_store_candidates",
        "ir.memory_def.candidate",
    )
    assert contract_name_in("branch_targets", {"ir.branch_target"})
    assert contract_name_in("ir.branch_target", {"branch_targets"})
    assert contract_name_in(
        "ir.memory_def.candidate",
        {"carrier_store_candidates"},
    )
    assert not contract_name_in("ir.branch_target", {"state_variable_writes"})


def test_ollvm_raw_carrier_roles_remain_internal_not_public_aliases():
    aliases = legacy_contract_aliases()

    for raw_role in (
        "LOCAL_WORKING_STORE_CANDIDATE",
        "ARG_OUTPUT_STORE_CANDIDATE",
        "LOOP_INDEX_CARRIER",
        "PASSWORD_COMPARE_RESULT",
    ):
        assert raw_role not in aliases
        assert contract_vocabulary_entry(raw_role) is None
        assert resolve_contract_name(raw_role) == raw_role
