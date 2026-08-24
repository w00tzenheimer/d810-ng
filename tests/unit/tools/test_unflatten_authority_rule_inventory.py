"""Inventory gate for the permanent semantic-authority ast-grep policy."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).parents[3]
RULES = ROOT / "rules"
FIXTURES = ROOT / "rule-tests"

RULE_IDS = (
    "no-unflatten-authority-in-plan-metadata",
    "no-direct-unflatten-proof-metadata-parsing",
    "no-naked-unflatten-loss-authority",
    "no-stringly-unflatten-authority-state",
    "no-direct-unflatten-safety-gates-in-patch-transaction",
    "no-unflatten-producer-transaction-api-import",
    "no-direct-unflatten-verdict-construction",
    "no-local-unflatten-authority-types",
    "no-unanchored-unflatten-diagnostic",
    "no-independent-unflatten-phase-normalization",
)


def _fixture_counts(text: str) -> tuple[int, int]:
    valid_text, invalid_text = text.split("invalid:", 1)
    valid_text = valid_text.split("valid:", 1)[1]
    return (
        len(re.findall(r"(?m)^  - \|$", valid_text)),
        len(re.findall(r"(?m)^  - \|$", invalid_text)),
    )


def test_all_ten_rules_have_required_bypass_fixtures() -> None:
    """Every policy has executable positive and negative bypass coverage."""

    assert len(RULE_IDS) == 10
    for rule_id in RULE_IDS:
        rule_path = RULES / f"{rule_id}.yml"
        fixture_path = FIXTURES / f"{rule_id}-test.yml"
        assert rule_path.is_file(), rule_path
        assert fixture_path.is_file(), fixture_path

        rule_text = rule_path.read_text(encoding="utf-8")
        fixture_text = fixture_path.read_text(encoding="utf-8")
        assert re.search(rf"(?m)^id: {re.escape(rule_id)}$", rule_text)
        assert re.search(rf"(?m)^id: {re.escape(rule_id)}$", fixture_text)
        assert "message:" in rule_text
        assert "note:" in rule_text
        assert re.search(r"(?m)^files:\s*$", rule_text)
        assert not re.search(r"(?m)^ignores:", rule_text)

        valid_count, invalid_count = _fixture_counts(fixture_text)
        assert valid_count >= 2, (rule_id, valid_count)
        assert invalid_count >= 2, (rule_id, invalid_count)

        relational_count = len(re.findall(r"(?m)^\s+(?:-\s+)?(?:has|inside):\s*$", rule_text))
        stop_count = len(re.findall(r"(?m)^\s+stopBy: end$", rule_text))
        assert relational_count == stop_count, (rule_id, relational_count, stop_count)


def test_authority_fixture_matrix_names_each_bypass_family() -> None:
    """Keep the review-critical bypass vocabulary from silently disappearing."""

    required_terms = {
        "no-unflatten-authority-in-plan-metadata": (
            "with_metadata", "PatchPlan(metadata", "semantic_safety_case",
            "exact_state_branch_effect_exclusions",
            "dispatcher_removal_preflight_proof",
            "unflatten_authority_binding_id", "ordinary_diagnostic_label", "legacy_codec",
        ),
        "no-direct-unflatten-proof-metadata-parsing": (
            ".get(", "USE_DEF_SEVERANCE_AUDIT_METADATA",
            "DISPATCHER_CORRIDOR_COVERAGE_METADATA",
            "DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA",
            "SEMANTIC_SAFETY_CASE_METADATA", " in metadata", "for key in metadata",
            "EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA",
            "NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA",
        ),
        "no-naked-unflatten-loss-authority": (
            "validated_source_serials", "allowed_effect_serials", "permitted", "effect_exclusion_serials",
            "lost_block_serials", "alias_effect_exclusion_serials", "reachable_handler_serials",
            "retained_transaction_local_serial_allowance", "anchor_ea",
        ),
        "no-stringly-unflatten-authority-state": (
            "accepted", "projected_preflight", "observed_post_apply",
            "exact_infeasible_effect", "unproven", "satisfied", ".value",
        ),
        "no-direct-unflatten-safety-gates-in-patch-transaction": (
            "_validated_exact_effect_exclusions", "validate_dispatcher_corridor_coverage_metadata",
            "canonicalize_observed_dispatcher_graph", "compose_legacy_unflatten_allowance",
            "coverage.validate_dispatcher_corridor_coverage_metadata",
            "check_terminal_reachability_preserved", "check_effectful_reachability_preserved",
            "check_entry_reachability_not_collapsed", "transaction_api.prepare",
        ),
        "no-unflatten-producer-transaction-api-import": (
            ".bind", ".evaluate", ".transaction_api",
            "from d810.transforms.unflatten_authority import transaction_api",
            "import d810.transforms.unflatten_authority.bind",
            ".model", ".proposal", ".producer_api",
        ),
        "no-direct-unflatten-verdict-construction": (
            "UnflattenAuthorityVerdict", "SemanticSafetyCase", "ObligationEvidenceCell",
            "ObligationEvidenceIndex", "api.UnflattenAuthorityVerdict",
            "model.SemanticSafetyCase", "isinstance", "evaluate_case",
        ),
        "no-local-unflatten-authority-types": (
            "Proof", "Receipt", "Authority", "Allowance", "dataclass", "SemanticSafetyCase",
        ),
        "no-unanchored-unflatten-diagnostic": (
            "serial", "anchor_ea", ".format", "+ str(serial)", "%d", "lost_block_serial",
        ),
        "no-independent-unflatten-phase-normalization": (
            "canonicalize_observed_dispatcher_graph", "_validated_local_alias_effect_exclusions",
            "source_serials - observed_serials", "source_serials.difference(observed_serials)",
            "coverage.canonicalize_observed_dispatcher_graph",
            "source_indexed_lineage", "check_effectful_reachability_preserved",
        ),
    }
    for rule_id, terms in required_terms.items():
        text = (FIXTURES / f"{rule_id}-test.yml").read_text(encoding="utf-8")
        assert all(term in text for term in terms), rule_id
