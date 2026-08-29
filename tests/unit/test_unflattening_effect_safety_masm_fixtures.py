"""Integrity checks for the exact MASM exports used by the safety regressions."""

from __future__ import annotations

from pathlib import Path
import re

import pytest

import tests.system.e2e.unflattening_effect_safety_oracle as safety_oracle
from tests.system.e2e.unflattening_effect_safety_oracle import (
    AuthorityOracleEvidence,
    authority_oracle_marker_payload,
    parse_authority_phase_payloads,
    reachable_call_eas,
    require_target_authority_policy,
    session_scoped_rows,
    select_committed_authority_phase_payloads,
)

WORKTREE = Path(__file__).parents[2]
MASM_DIR = WORKTREE / "samples" / "src" / "masm"


def _authority_phase(
    phase: str,
    *,
    authority_id: str = "authority-1",
    case_id: str | None = None,
    plan_id: str = "plan-1",
    attempt_id: str = "attempt-1",
    session_id: str = "session-1",
) -> dict:
    projected = phase == "projected_preflight"
    case_id = case_id or ("case-p" if projected else "case-o")
    return {
        "schema": "unflatten_authority_phase.v1",
        "phase": phase,
        "authority_id": authority_id,
        "plan_id": plan_id,
        "attempt_id": attempt_id,
        "session_id": session_id,
        "binding_id": None if projected else "binding-1",
        "case_id": case_id,
        "accepted": True,
        "reason": "accepted",
        "source_fingerprint": "source-1",
        "candidate_fingerprint": "candidate-1",
        "generation": 1,
        "bindings": [{"generation": 1}],
        "obligation_states": [{"state": "satisfied"}],
        "coverage": [],
        "loss_ledger": [],
        "observed_only_loss": [],
        "loss_summary": {
            "structurally_lost": [],
            "allowed": [],
            "forbidden": [],
            "conflicting": [],
            "observed_only": [],
        },
        "metrics": {
            "source_inventory_builds": 1,
            "candidate_inventory_builds": 1,
            "index_folds": 1,
            "view_graph_traversals": 0,
        },
        "timings": {
            "inventory_ms": 1.0,
            "binding_ms": 2.0,
            "evaluation_ms": 3.0,
            "views_ms": 4.0,
            "total_authority_ms": 10.0,
        },
    }


def _authority_payloads() -> list[dict]:
    projected = _authority_phase("projected_preflight")
    observed = _authority_phase("observed_post_apply")
    return [projected, observed]


def _loss_row(
    anchor: str,
    classification: str,
    *,
    structural_state: str = "satisfied",
    evidence_ids: list[str] | None = None,
    supporting_justification_ids: list[str] | None = None,
    claim_ids: list[str] | None = None,
    rules: list[str] | None = None,
) -> dict:
    return {
        "subject": anchor,
        "classification": classification,
        "binding_status": "unique",
        "source_binding_status": "unique",
        "anchor": anchor,
        "structural": {
            "dimension": "structural_accounting",
            "state": structural_state,
        },
        "semantic": [],
        "evidence_ids": evidence_ids or ["evidence-1"],
        "supporting_justification_ids": (
            supporting_justification_ids or ["justification-1"]
        ),
        "refuting_justification_ids": [],
        "claim_ids": claim_ids or ["claim-1"],
        "rules": rules or ["retired_infrastructure_proven"],
    }


def _corridor_obligation(subject: str = "blk1@0x1000") -> dict:
    return {
        "subject": subject,
        "dimension": "corridor_coverage",
        "state": "satisfied",
        "supports": [],
        "refutes": [],
    }


def _coverage_row(subject: str = "blk1@0x1000") -> dict:
    return {
        "subject": subject,
        "dimension": "corridor_coverage",
        "state": "satisfied",
    }


def _fixture(name: str) -> str:
    return (MASM_DIR / f"{name}.asm").read_text()


def _parse_callsite_markers(source: str) -> dict[str, tuple[str, str]]:
    """Resolve CONST marker pointers to the following in-function instruction.

    The committed MASM exporter represents exact native callsites as a public
    qword in ``CONST`` that points at a private code label immediately before
    the instruction.  Parse the section metadata rather than treating marker
    names or imported API spellings as sufficient fixture evidence.
    """
    lines = source.splitlines()
    const_start = next(
        index for index, line in enumerate(lines) if line.strip() == "CONST SEGMENT"
    )
    const_end = next(
        index
        for index, line in enumerate(lines[const_start + 1 :], const_start + 1)
        if line.strip() == "CONST ENDS"
    )
    text_start = next(
        index
        for index, line in enumerate(lines)
        if re.match(r"^_TEXT SEGMENT\b", line.strip())
    )
    text_end = next(
        index
        for index, line in enumerate(lines[text_start + 1 :], text_start + 1)
        if line.strip() == "_TEXT ENDS"
    )
    const_lines = lines[const_start + 1 : const_end]
    text_lines = lines[text_start + 1 : text_end]
    marker_names = {
        match.group(1)
        for line in const_lines
        if (match := re.match(r"^\s*PUBLIC\s+(d810_callsite_[A-Za-z0-9_]+)\s*$", line))
    }
    bindings: dict[str, tuple[str, str]] = {}
    for marker in marker_names:
        definition = next(
            (
                line
                for line in const_lines
                if re.match(
                    rf"^\s*{re.escape(marker)}\s+dq\s+([A-Za-z0-9_]+)\s*$",
                    line,
                )
            ),
            None,
        )
        assert definition is not None, f"marker {marker} has no CONST qword"
        target = re.fullmatch(
            rf"\s*{re.escape(marker)}\s+dq\s+([A-Za-z0-9_]+)\s*",
            definition,
        )
        assert target is not None, definition
        target_label = target.group(1)
        label_index = next(
            (
                index
                for index, line in enumerate(text_lines)
                if line.strip() == f"{target_label}:"
            ),
            None,
        )
        assert label_index is not None, (
            f"marker {marker} points at missing code label {target_label}"
        )
        instruction = next(
            (
                line.strip()
                for line in text_lines[label_index + 1 :]
                if line.strip() and not line.lstrip().startswith(";")
            ),
            None,
        )
        assert instruction is not None, f"marker {marker} has no instruction"
        bindings[marker] = (target_label, instruction)
    return bindings


def test_exact_target_a_fixture_preserves_materialized_effectful_corridor():
    source = _fixture("sub_7FF8569F0540")

    assert "; Function: sub_7FF8569F0540  @ 0x7ff8569f0540" in source
    assert "PUBLIC sub_7FF8569F0540" in source
    assert "EXTERN memcpy:PROC" in source
    assert source.count("call memcpy") >= 8
    assert "PUBLIC d810_callsite_sub_7FF8569F0540_memcpy" in source
    assert "CONST SEGMENT" in source
    assert "jmp loc_7FF8569F0600" in source
    marker_bindings = _parse_callsite_markers(source)
    assert (
        marker_bindings["d810_callsite_sub_7FF8569F0540_memcpy"][1]
        .lower()
        .startswith("call ")
    )


def test_exact_target_b_fixture_preserves_dispatcher_trap_and_lock_effect():
    source = _fixture("sub_7FF8568132D0")

    assert "; Function: sub_7FF8568132D0  @ 0x7ff8568132d0" in source
    assert "PUBLIC sub_7FF8568132D0" in source
    assert "EXTERN __imp_RtlAcquireSRWLockExclusive:PROC" in source
    assert "call qword ptr [__imp_RtlAcquireSRWLockExclusive]" in source
    assert "EXTERN Eid_UpdateSharedStateIfSentinelMatches:PROC" in source
    assert source.count("call Eid_UpdateSharedStateIfSentinelMatches") >= 4
    assert "PUBLIC d810_callsite_sub_7FF8568132D0_srw_lock" in source
    assert "int 3" in source
    assert "CONST SEGMENT" in source
    marker_bindings = _parse_callsite_markers(source)
    assert (
        marker_bindings["d810_callsite_sub_7FF8568132D0_srw_lock"][1]
        .lower()
        .startswith("call ")
    )


def test_exact_target_c_fixture_preserves_termination_effects_and_markers():
    source_path = MASM_DIR / "sub_7FF855576B50.asm"
    assert source_path.is_file(), f"missing committed MASM fixture: {source_path}"
    source = source_path.read_text()

    assert "; Function: sub_7FF855576B50  @ 0x7ff855576b50" in source
    assert "PUBLIC sub_7FF855576B50" in source
    assert "EXTERN MessageBoxA:PROC" in source
    assert "EXTERN GetCurrentProcess:PROC" in source
    assert "EXTERN TerminateProcess:PROC" in source
    assert "CONST SEGMENT" in source

    expected = {
        "d810_callsite_sub_7FF855576B50_message_box",
        "d810_callsite_sub_7FF855576B50_get_current_process",
        "d810_callsite_sub_7FF855576B50_terminate_process",
    }
    marker_bindings = _parse_callsite_markers(source)
    assert set(marker_bindings) == expected
    function_start = source.index("sub_7FF855576B50:")
    function_end = source.index("_TEXT ENDS")
    for marker, (target_label, instruction) in marker_bindings.items():
        target_offset = source.index(f"{target_label}:")
        assert function_start < target_offset < function_end, marker
        assert instruction.lower().startswith(("call ", "jmp ")), (
            marker,
            instruction,
        )


def test_masm_build_exports_only_explicit_d810_callsite_markers() -> None:
    sources = {
        "a": _fixture("sub_7FF8569F0540"),
        "b": _fixture("sub_7FF8568132D0"),
        "c": _fixture("sub_7FF855576B50"),
    }
    markers = {
        marker
        for source in sources.values()
        for marker in re.findall(
            r"(?m)^\s*PUBLIC\s+(d810_callsite_[A-Za-z0-9_]+)\s*$",
            source,
        )
    }
    assert markers == {
        "d810_callsite_sub_7FF8569F0540_memcpy",
        "d810_callsite_sub_7FF8568132D0_srw_lock",
        "d810_callsite_sub_7FF855576B50_message_box",
        "d810_callsite_sub_7FF855576B50_get_current_process",
        "d810_callsite_sub_7FF855576B50_terminate_process",
    }


def test_exact_call_reachability_requires_the_bound_native_ea() -> None:
    graph = {
        0: (1, 2),
        1: (3,),
        2: (),
        3: (),
    }
    call_blocks = {3: (0x18001234,)}
    assert reachable_call_eas(graph, call_blocks) == frozenset({0x18001234})


def test_exact_call_reachability_rejects_an_unreachable_native_ea() -> None:
    graph = {0: (1,), 1: ()}
    call_blocks = {2: (0x18001234,)}
    assert reachable_call_eas(graph, call_blocks) == frozenset()


def test_exact_call_reachability_fails_closed_on_unknown_successor() -> None:
    with pytest.raises(ValueError, match="unknown successor"):
        reachable_call_eas({0: (99,)}, {0: (0x18001234,)})


def test_diagnostic_oracle_excludes_receipts_and_attempts_from_other_sessions() -> None:
    receipt_rows = (
        ("batch-current", "committed", "session-current"),
        ("batch-stale", "committed", "session-stale"),
    )
    attempt_rows = (
        ("committed", 1, 0, "session-current"),
        ("committed", 1, 0, "session-stale"),
    )
    assert session_scoped_rows(receipt_rows, "session-current") == (
        ("batch-current", "committed", "session-current"),
    )
    assert session_scoped_rows(attempt_rows, "session-current") == (
        ("committed", 1, 0, "session-current"),
    )


def test_dispatcher_removal_proof_requires_the_committed_attempt_and_batch() -> None:
    matcher = getattr(
        safety_oracle,
        "transaction_bound_dispatcher_removal_proofs",
        None,
    )
    assert callable(matcher), "transaction-bound proof matcher is missing"

    proofs = (
        {
            "application_status": "applied",
            "proof_status": "accepted",
            "plan_id": "stale-plan",
            "attempt_id": "stale-attempt",
        },
        {
            "application_status": "applied",
            "proof_status": "rejected",
            "plan_id": "current-plan",
            "attempt_id": "current-attempt",
        },
    )
    assert matcher(
        proofs,
        committed_attempts={("current-plan", "current-attempt")},
        committed_batches={"current-attempt"},
    ) == (proofs[1],)
    batch_mismatch = {
        **proofs[1],
        "proof_status": "accepted",
    }
    assert (
        matcher(
            (batch_mismatch,),
            committed_attempts={("current-plan", "current-attempt")},
            committed_batches={"different-batch"},
        )
        == ()
    )


def test_exact_call_oracle_rejects_duplicate_native_marker_eas() -> None:
    validator = getattr(safety_oracle, "require_distinct_native_eas", None)
    assert callable(validator), "native-EA uniqueness validator is missing"

    assert validator((0x180044A5A, 0x180044A60, 0x180044AF7), expected_count=3) == (
        0x180044A5A,
        0x180044A60,
        0x180044AF7,
    )
    with pytest.raises(ValueError, match="distinct"):
        validator((0x180044A5A, 0x180044A5A, 0x180044AF7), expected_count=3)


def test_authority_payload_aggregation_returns_valid_projected_observed_rows() -> None:
    evidence = parse_authority_phase_payloads(_authority_payloads())
    assert isinstance(evidence, AuthorityOracleEvidence)
    assert evidence.projected.phase == "projected_preflight"
    assert evidence.observed.phase == "observed_post_apply"
    assert evidence.projected.case_id == "case-p"
    assert evidence.observed.case_id == "case-o"
    assert evidence.projected.authority_id == "authority-1"
    assert evidence.session_id == "session-1"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(
            coverage=[
                {
                    "subject": "blk1@0x1000",
                    "dimension": "corridor_coverage",
                    "state": "satisfied",
                }
            ],
            obligation_states=[
                {"state": "satisfied"},
                _corridor_obligation(),
            ],
        ),
        lambda payload: payload.update(
            loss_ledger=[_loss_row("blk1@0x1000", "retired_dispatcher_infrastructure")],
            loss_summary={
                "structurally_lost": ["blk1@0x1000"],
                "allowed": ["blk1@0x1000"],
                "forbidden": [],
                "conflicting": [],
                "observed_only": [],
            },
        ),
    ],
)
def test_authority_target_a_requires_a_retained_dispatcher_empty_loss_ledger(
    mutation,
) -> None:
    evidence = parse_authority_phase_payloads(_authority_payloads())

    require_target_authority_policy(evidence, "A")

    payloads = _authority_payloads()
    mutation(payloads[0])
    with pytest.raises(ValueError, match="target A"):
        require_target_authority_policy(parse_authority_phase_payloads(payloads), "A")


@pytest.mark.parametrize("target", ["B", "C"])
def test_authority_removal_targets_require_observed_coverage_and_retired_loss(
    target: str,
) -> None:
    payloads = _authority_payloads()
    observed = payloads[1]
    observed["coverage"] = [_coverage_row()]
    observed["obligation_states"] = [
        {"state": "satisfied"},
        _corridor_obligation(),
    ]
    observed["loss_ledger"] = [
        _loss_row("blk1@0x1000", "retired_dispatcher_infrastructure")
    ]
    observed["loss_summary"] = {
        "structurally_lost": ["blk1@0x1000"],
        "allowed": ["blk1@0x1000"],
        "forbidden": [],
        "conflicting": [],
        "observed_only": ["blk1@0x1000"],
    }
    observed["observed_only_loss"] = [
        _loss_row("blk1@0x1000", "retired_dispatcher_infrastructure")
    ]
    evidence = parse_authority_phase_payloads(payloads)

    require_target_authority_policy(evidence, target)

    missing_coverage = _authority_payloads()
    missing_coverage[1]["loss_ledger"] = observed["loss_ledger"]
    missing_coverage[1]["loss_summary"] = observed["loss_summary"]
    missing_coverage[1]["observed_only_loss"] = observed["observed_only_loss"]
    with pytest.raises(ValueError, match="coverage"):
        require_target_authority_policy(
            parse_authority_phase_payloads(missing_coverage), target
        )

    missing_retirement = _authority_payloads()
    missing_retirement[1]["coverage"] = observed["coverage"]
    missing_retirement[1]["obligation_states"] = observed["obligation_states"]
    with pytest.raises(ValueError, match="retired"):
        require_target_authority_policy(
            parse_authority_phase_payloads(missing_retirement), target
        )


def test_authority_parser_preserves_a_typed_observed_only_loss() -> None:
    payloads = _authority_payloads()
    payloads[1]["loss_ledger"] = [_loss_row("blk2@0x2000", "exact_infeasible_effect")]
    payloads[1]["loss_summary"] = {
        "structurally_lost": ["blk2@0x2000"],
        "allowed": ["blk2@0x2000"],
        "forbidden": [],
        "conflicting": [],
        "observed_only": ["blk2@0x2000"],
    }
    payloads[1]["observed_only_loss"] = [
        _loss_row("blk2@0x2000", "exact_infeasible_effect")
    ]
    payloads[1]["loss_summary"]["observed_only"] = ["blk2@0x2000"]

    evidence = parse_authority_phase_payloads(payloads)

    assert evidence.observed.loss_summary.observed_only == ("blk2@0x2000",)
    assert evidence.observed.observed_only_loss_rows[0].classification == (
        "exact_infeasible_effect"
    )


@pytest.mark.parametrize(
    "coverage_rows, obligation_rows, message",
    [
        (
            [_coverage_row(), _coverage_row()],
            [{"state": "satisfied"}, _corridor_obligation()],
            "coverage",
        ),
        (
            [{**_coverage_row(), "state": "unproven"}],
            [{"state": "satisfied"}],
            "coverage",
        ),
        (
            [_coverage_row()],
            [{"state": "satisfied"}],
            "coverage",
        ),
    ],
)
def test_authority_parser_rejects_noncanonical_coverage_projection(
    coverage_rows: list[dict],
    obligation_rows: list[dict],
    message: str,
) -> None:
    payloads = _authority_payloads()
    payloads[1]["coverage"] = coverage_rows
    payloads[1]["obligation_states"] = obligation_rows

    with pytest.raises(ValueError, match=message):
        parse_authority_phase_payloads(payloads)


@pytest.mark.parametrize("failure", ["absent", "projected", "classification"])
def test_authority_parser_rejects_noncanonical_observed_only_delta(
    failure: str,
) -> None:
    payloads = _authority_payloads()
    projected = payloads[0]
    observed = payloads[1]
    projected["loss_ledger"] = [_loss_row("blk1@0x1000", "equivalent_semantic_route")]
    projected["loss_summary"] = {
        "structurally_lost": ["blk1@0x1000"],
        "allowed": ["blk1@0x1000"],
        "forbidden": [],
        "conflicting": [],
        "observed_only": [],
    }
    observed["loss_ledger"] = [
        _loss_row("blk1@0x1000", "equivalent_semantic_route"),
        _loss_row("blk2@0x2000", "exact_infeasible_effect"),
    ]
    observed["loss_summary"] = {
        "structurally_lost": ["blk1@0x1000", "blk2@0x2000"],
        "allowed": ["blk1@0x1000", "blk2@0x2000"],
        "forbidden": [],
        "conflicting": [],
        "observed_only": ["blk2@0x2000"],
    }
    observed["observed_only_loss"] = [
        _loss_row("blk2@0x2000", "exact_infeasible_effect")
    ]
    if failure == "absent":
        observed["observed_only_loss"] = [
            _loss_row("blk3@0x3000", "exact_infeasible_effect")
        ]
        observed["loss_summary"]["observed_only"] = ["blk3@0x3000"]
    elif failure == "projected":
        observed["observed_only_loss"] = [
            _loss_row("blk1@0x1000", "equivalent_semantic_route")
        ]
        observed["loss_summary"]["observed_only"] = ["blk1@0x1000"]
    else:
        observed["observed_only_loss"] = [
            _loss_row("blk2@0x2000", "retired_dispatcher_infrastructure")
        ]

    with pytest.raises(ValueError, match="observed-only"):
        parse_authority_phase_payloads(payloads)


def test_authority_parser_rejects_projected_observed_only_loss() -> None:
    payloads = _authority_payloads()
    payloads[0]["observed_only_loss"] = [
        _loss_row("blk2@0x2000", "exact_infeasible_effect")
    ]
    payloads[0]["loss_summary"]["observed_only"] = ["blk2@0x2000"]

    with pytest.raises(ValueError, match="projected"):
        parse_authority_phase_payloads(payloads)


@pytest.mark.parametrize(
    "field, value",
    [
        ("structural", {"dimension": "structural_accounting", "state": "unproven"}),
        ("evidence_ids", []),
        ("supporting_justification_ids", []),
        ("claim_ids", []),
    ],
)
def test_authority_removal_policy_requires_structural_claim_support(
    field: str,
    value: object,
) -> None:
    payloads = _authority_payloads()
    observed = payloads[1]
    observed["coverage"] = [_coverage_row()]
    observed["obligation_states"] = [{"state": "satisfied"}, _corridor_obligation()]
    retired = _loss_row("blk1@0x1000", "retired_dispatcher_infrastructure")
    retired[field] = value
    observed["loss_ledger"] = [retired]
    observed["loss_summary"] = {
        "structurally_lost": ["blk1@0x1000"],
        "allowed": ["blk1@0x1000"],
        "forbidden": [],
        "conflicting": [],
        "observed_only": ["blk1@0x1000"],
    }
    observed["observed_only_loss"] = [
        _loss_row("blk1@0x1000", "retired_dispatcher_infrastructure")
    ]

    with pytest.raises(ValueError, match="retired|structural|support"):
        require_target_authority_policy(parse_authority_phase_payloads(payloads), "B")


@pytest.mark.parametrize(
    "mutation, message",
    [
        (
            lambda payload: payload["loss_summary"].update(allowed=["blk1@0x1000"]),
            "loss summary",
        ),
        (
            lambda payload: payload.update(
                loss_ledger=[_loss_row("blk1@0x1000", "unclassified")],
                loss_summary={
                    "structurally_lost": ["blk1@0x1000"],
                    "allowed": [],
                    "forbidden": ["blk1@0x1000"],
                    "conflicting": [],
                    "observed_only": [],
                },
            ),
            "forbidden",
        ),
        (
            lambda payload: payload.update(
                loss_ledger=[_loss_row("blk1@0x1000", "conflicting")],
                loss_summary={
                    "structurally_lost": ["blk1@0x1000"],
                    "allowed": [],
                    "forbidden": [],
                    "conflicting": ["blk1@0x1000"],
                    "observed_only": [],
                },
            ),
            "conflicting",
        ),
    ],
)
def test_authority_payload_aggregation_rejects_noncanonical_loss_summary(
    mutation,
    message: str,
) -> None:
    payloads = _authority_payloads()
    mutation(payloads[1])

    with pytest.raises(ValueError, match=message):
        parse_authority_phase_payloads(payloads)


def test_authority_payload_selection_ignores_rejected_groups_after_committed_provenance() -> (
    None
):
    rejected = _authority_phase(
        "projected_preflight", plan_id="rejected-plan", attempt_id="rejected-attempt"
    )
    selected = select_committed_authority_phase_payloads(
        [rejected, *_authority_payloads()],
        clean_committed_correlations={
            ("plan-1", "attempt-1", "session-1"),
        },
        expected_session_id="session-1",
    )
    assert selected == tuple(_authority_payloads())


@pytest.mark.parametrize(
    "clean_committed_correlations, message",
    [
        (set(), "exactly one committed authority correlation"),
        (
            {
                ("plan-1", "attempt-1", "session-1"),
                ("plan-2", "attempt-2", "session-1"),
            },
            "exactly one committed authority correlation",
        ),
    ],
)
def test_authority_payload_selection_rejects_zero_or_multiple_matching_committed_groups(
    clean_committed_correlations: set[tuple[str, str, str]], message: str
) -> None:
    payloads = _authority_payloads()
    if len(clean_committed_correlations) > 1:
        other = _authority_payloads()
        for payload in other:
            payload.update(plan_id="plan-2", attempt_id="attempt-2")
        payloads.extend(other)
    with pytest.raises(ValueError, match=message):
        select_committed_authority_phase_payloads(
            payloads,
            clean_committed_correlations=clean_committed_correlations,
            expected_session_id="session-1",
        )


@pytest.mark.parametrize(
    "payloads, message",
    [
        (_authority_payloads()[:1], "exactly one projected and observed"),
        (
            _authority_payloads() + [_authority_payloads()[0]],
            "duplicate authority phase",
        ),
    ],
)
def test_authority_payload_selection_preserves_strict_selected_pair_validation(
    payloads: list[dict], message: str
) -> None:
    selected = select_committed_authority_phase_payloads(
        payloads,
        clean_committed_correlations={("plan-1", "attempt-1", "session-1")},
        expected_session_id="session-1",
    )
    with pytest.raises(ValueError, match=message):
        parse_authority_phase_payloads(selected, expected_session_id="session-1")


@pytest.mark.parametrize(
    "field, value, message",
    [
        ("session_id", "foreign-session", "cross-session"),
        ("plan_id", None, "correlation"),
    ],
)
def test_authority_payload_selection_rejects_cross_session_or_malformed_correlation(
    field: str, value: object, message: str
) -> None:
    payloads = _authority_payloads()
    payloads[0][field] = value
    with pytest.raises(ValueError, match=message):
        select_committed_authority_phase_payloads(
            payloads,
            clean_committed_correlations={("plan-1", "attempt-1", "session-1")},
            expected_session_id="session-1",
        )


@pytest.mark.parametrize("phase", ["bogus_phase", None])
def test_authority_payload_selection_rejects_unknown_or_missing_phase_before_correlation(
    phase: str | None,
) -> None:
    payloads = _authority_payloads()
    payloads[0].update(phase=phase, session_id="foreign-session")
    with pytest.raises(ValueError, match="phase"):
        select_committed_authority_phase_payloads(
            payloads,
            clean_committed_correlations={("plan-1", "attempt-1", "session-1")},
            expected_session_id="session-1",
        )


def test_production_authority_marker_preserves_plan_and_attempt_for_artifact_oracle() -> (
    None
):
    """The pure production marker payload satisfies the artifact contract."""
    import tools.scripts.unflatten_authority_artifacts as artifacts

    evidence = parse_authority_phase_payloads(_authority_payloads())
    marker = authority_oracle_marker_payload(
        target="A",
        function="sub_7FF8569F0540",
        function_ea=0x1234,
        fixture_sha256="0" * 64,
        session_id="session-1",
        evidence=evidence,
    )
    artifacts._oracle(marker, "A", "0" * 64)


def test_production_authority_marker_uses_canonical_pair_receipt() -> None:
    evidence = parse_authority_phase_payloads(_authority_payloads())
    marker = authority_oracle_marker_payload(
        target="A",
        function="sub_7FF8569F0540",
        function_ea=0x1234,
        fixture_sha256="0" * 64,
        session_id="session-1",
        evidence=evidence,
    )
    assert marker["schema"] == "unflatten-authority-oracle.v2"
    assert set(marker["canonical_pair"]) == {
        "authority_id",
        "projected_case_id",
        "observed_case_id",
        "source_fingerprint",
        "projected_candidate_fingerprint",
        "observed_candidate_fingerprint",
        "observed_binding_id",
        "plan_id",
        "attempt_id",
        "session_id",
        "projected_timings",
        "observed_timings",
    }


def test_production_authority_marker_rejects_session_relabeling() -> None:
    evidence = parse_authority_phase_payloads(_authority_payloads())
    with pytest.raises(ValueError, match="session"):
        authority_oracle_marker_payload(
            target="A",
            function="sub_7FF8569F0540",
            function_ea=0x1234,
            fixture_sha256="0" * 64,
            session_id="foreign-session",
            evidence=evidence,
        )


@pytest.mark.parametrize(
    "payloads, message",
    [
        (_authority_payloads()[:1], "exactly one"),
        (_authority_payloads() + [_authority_payloads()[0]], "duplicate"),
    ],
)
def test_authority_payload_aggregation_rejects_missing_or_duplicate_phase(
    payloads: list[dict],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        parse_authority_phase_payloads(payloads)


@pytest.mark.parametrize("field", ["plan_id", "attempt_id", "session_id"])
def test_authority_payload_aggregation_rejects_cross_phase_provenance_mismatch(
    field: str,
) -> None:
    payloads = _authority_payloads()
    payloads[1][field] = f"foreign-{field}"
    with pytest.raises(ValueError, match=field):
        parse_authority_phase_payloads(payloads)


def test_authority_payload_aggregation_rejects_wrong_expected_session() -> None:
    with pytest.raises(ValueError, match="session|exactly one"):
        parse_authority_phase_payloads(
            _authority_payloads(), expected_session_id="stale-session"
        )
    payloads = _authority_payloads()
    payloads[0]["session_id"] = "foreign-session"
    with pytest.raises(ValueError, match="session|exactly one"):
        parse_authority_phase_payloads(payloads, expected_session_id="session-1")


def test_authority_payload_aggregation_rejects_unknown_obligation_state() -> None:
    payloads = _authority_payloads()
    payloads[0]["obligation_states"] = [{"state": "unsupported"}]
    with pytest.raises(ValueError, match="obligation state"):
        parse_authority_phase_payloads(payloads)


def test_authority_payload_aggregation_rejects_unanchored_loss() -> None:
    payloads = _authority_payloads()
    payloads[0]["loss_ledger"] = [
        {
            **_loss_row("blk1@0x1000", "exact_infeasible_effect"),
            "anchor": "not-anchored",
        }
    ]
    with pytest.raises(ValueError, match="anchor"):
        parse_authority_phase_payloads(payloads)


def test_authority_payload_aggregation_requires_explicit_generation_matching_bindings() -> (
    None
):
    payloads = _authority_payloads()
    payloads[0]["generation"] = 2
    with pytest.raises(ValueError, match="generation"):
        parse_authority_phase_payloads(payloads)
    payloads = _authority_payloads()
    payloads[0]["bindings"][0]["generation"] = 2
    with pytest.raises(ValueError, match="generation"):
        parse_authority_phase_payloads(payloads)


@pytest.mark.parametrize(
    "field, value",
    [
        ("inventory_ms", float("nan")),
        ("views_ms", float("inf")),
        ("total_authority_ms", 99.0),
    ],
)
def test_authority_payload_aggregation_rejects_nonfinite_or_inconsistent_timings(
    field: str, value: float
) -> None:
    payloads = _authority_payloads()
    payloads[0]["timings"][field] = value
    with pytest.raises(ValueError, match="timing"):
        parse_authority_phase_payloads(payloads)
