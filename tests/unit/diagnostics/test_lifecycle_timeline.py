"""Event-native diagnostic timeline query coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from d810.core.diag import create_diag_database, diag_models_on, open_diag_database
from d810.core.diag.lifecycle import (
    persist_diagnostic_session,
    persist_evidence_generation,
    persist_identity_decision,
    persist_mutation_plan,
    persist_mutation_receipt,
)
from d810.core.observability_events import (
    DiagnosticSessionObserved,
    EvidenceGenerationObserved,
    FragmentRootPublicationGroupObserved,
    FragmentValidationOutcomeObserved,
    IdentityDecisionObserved,
    LogicalBlockVersionTransitionObserved,
    MutationPlanItemObserved,
    MutationPlanObserved,
    MutationReceiptObserved,
)
from d810.diagnostics.__main__ import main
from d810.diagnostics.lifecycle_timeline import (
    evidence_lineage,
    lifecycle_timeline,
    mutation_batch,
    render_mutation_batch,
)


def _root_group(*, published: bool) -> FragmentRootPublicationGroupObserved:
    return FragmentRootPublicationGroupObserved(
        group_id="root-group:entry",
        predecessor_block_id="entry",
        predecessor_anchor_ea=0x40C800,
        edge_ids=("replacement:entry:direct",),
        edge_roles=("direct",),
        original_block_ids=("original",),
        replacement_block_ids=("replacement",),
        publication_attempted=published,
        publication_succeeded=published,
    )


@pytest.fixture()
def lifecycle_db_path(tmp_path: Path) -> Path:
    path = tmp_path / "lifecycle.sqlite3"
    db = create_diag_database(str(path))
    with diag_models_on(db):
        conn = db.connection()
        persist_diagnostic_session(
            conn,
            DiagnosticSessionObserved("session-1", 0x40C8B0, 7, "{}", "active", 1.0),
        )
        persist_evidence_generation(
            conn,
            EvidenceGenerationObserved(
                "session-1",
                0x40C8B0,
                "merge",
                0,
                1,
                "stack_selector",
                "changed",
                "calls",
                "six carriers",
                maturity="MMAT_CALLS",
                timestamp=2.0,
            ),
            snapshot_id=None,
        )
        persist_identity_decision(
            conn,
            IdentityDecisionObserved(
                "session-1",
                0x40C8B0,
                "rebind",
                "rhad_importer",
                "target",
                "{}",
                "[4244016]",
                "[]",
                0x40C9B0,
                42,
                3,
                1,
                "MMAT_PREOPTIMIZED",
                "unique",
                "[]",
                "native EA match",
                timestamp=3.0,
            ),
            snapshot_id=None,
        )
        plan = MutationPlanObserved(
            "session-1",
            0x40C8B0,
            "batch-1",
            "redirect",
            1,
            3,
            1,
            "MMAT_PREOPTIMIZED",
            "redirect one carrier",
            items=(
                MutationPlanItemObserved(
                    0,
                    "redirect",
                    42,
                    0x40C9B0,
                    '{"ea":4245936}',
                    51,
                    0x40CA20,
                    '{"ea":4246048}',
                    "planned",
                    "exact identity",
                ),
            ),
            timestamp=4.0,
        )
        persist_mutation_plan(conn, plan)
        persist_mutation_receipt(
            conn,
            MutationReceiptObserved(
                "session-1",
                0x40C8B0,
                "batch-1",
                "redirect",
                3,
                4,
                1,
                1,
                1,
                "MMAT_PREOPTIMIZED",
                "committed",
                "redirect one carrier",
                "",
                ('{"ea":4245936}',),
                (0x40C9B0,),
                timestamp=5.0,
            ),
        )
        conn.commit()
    db.close()
    return path


def test_timeline_is_ordered_and_event_native(lifecycle_db_path: Path) -> None:
    db = open_diag_database(str(lifecycle_db_path))
    rows = lifecycle_timeline(db.connection(), session_id="session-1")
    assert [row["event_seq"] for row in rows] == [1, 2, 3, 4]
    assert [row["event_kind"] for row in rows] == [
        "evidence_generation",
        "identity_decision",
        "mutation_plan",
        "mutation_receipt",
    ]
    assert rows[1]["ea_anchor_hex"] == "0x000000000040c9b0"
    assert rows[3]["outcome"] == "committed"
    assert all(row["snapshot_id"] is None for row in rows)
    db.close()


def test_mutation_batch_correlates_plan_items_and_receipt(
    lifecycle_db_path: Path,
) -> None:
    db = open_diag_database(str(lifecycle_db_path))
    result = mutation_batch(db.connection(), "batch-1")
    assert result["plan"]["planned_operation_count"] == 1
    assert result["items"][0]["source_block"] == "blk[42]@0x40C9B0"
    assert result["items"][0]["target_block"] == "blk[51]@0x40CA20"
    assert result["receipt"]["outcome"] == "committed"
    assert (
        result["receipt_identities"][0]["primary_anchor_ea_hex"] == "0x000000000040c9b0"
    )
    db.close()


def test_evidence_lineage_combines_generation_and_identity(
    lifecycle_db_path: Path,
) -> None:
    db = open_diag_database(str(lifecycle_db_path))
    rows = evidence_lineage(db.connection(), session_id="session-1")
    assert [(row["event_kind"], row["evidence_generation"]) for row in rows] == [
        ("evidence_generation", 1),
        ("identity_decision", 1),
    ]
    assert rows[1]["identity"] == "blk[42]@0x40C9B0"
    db.close()


def test_cli_timeline_does_not_require_a_snapshot(
    lifecycle_db_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["timeline", "--db", str(lifecycle_db_path), "--session", "session-1"])
    assert rc == 0
    output = capsys.readouterr().out
    assert "evidence_generation" in output
    assert "mutation_receipt" in output
    assert "blk[42]@0x40C9B0" in output


def test_cli_mutation_batch_and_evidence_lineage(
    lifecycle_db_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["mutation-batch", "--db", str(lifecycle_db_path), "batch-1"]) == 0
    assert "committed" in capsys.readouterr().out
    assert (
        main(
            [
                "evidence-lineage",
                "--db",
                str(lifecycle_db_path),
                "--session",
                "session-1",
            ]
        )
        == 0
    )
    assert "stack_selector" in capsys.readouterr().out


def test_mutation_batch_renders_complete_semantic_fragment_evidence() -> None:
    db = create_diag_database(":memory:")
    conn = db.connection()
    persist_diagnostic_session(
        conn,
        DiagnosticSessionObserved(
            "fragment-session",
            0x40C8B0,
            1,
            "{}",
            "active",
        ),
    )
    persist_mutation_plan(
        conn,
        MutationPlanObserved(
            session_id="fragment-session",
            func_ea=0x40C8B0,
            mutation_batch_id="fragment-batch",
            mutation_kind="fragment_publication",
            planned_operation_count=1,
            mba_generation=8,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            description="publish semantic fragment",
            fragment_plan_id="fragment-plan",
            fragment_atomic_group_id="atomic-group",
            fragment_plan_json=(
                '{"atomic_group_id":"atomic-group","blocks":[],'
                '"plan_id":"fragment-plan"}'
            ),
            root_publication_groups=(_root_group(published=False),),
        ),
    )
    persist_mutation_receipt(
        conn,
        MutationReceiptObserved(
            session_id="fragment-session",
            func_ea=0x40C8B0,
            mutation_batch_id="fragment-batch",
            mutation_kind="fragment_publication",
            pre_generation=8,
            post_generation=9,
            planned_operation_count=1,
            applied_operation_count=1,
            evidence_generation=3,
            maturity="MMAT_PREOPT",
            outcome="committed",
            description="publish semantic fragment",
            reason="",
            fragment_plan_id="fragment-plan",
            fragment_atomic_group_id="atomic-group",
            root_publication_groups=(_root_group(published=True),),
            fragment_staged=True,
            root_publication_attempted=True,
            root_publication_succeeded=True,
            validation_outcomes=(
                FragmentValidationOutcomeObserved(
                    phase="prepublication",
                    postcondition="dispatcher_absence",
                    subject_id="dispatcher",
                    passed=True,
                    reason="dispatcher unreachable",
                ),
                FragmentValidationOutcomeObserved(
                    phase="postpublication",
                    postcondition="root_authority",
                    subject_id="fragment-plan",
                    passed=True,
                    reason="root authority published",
                ),
            ),
            version_transitions=(
                LogicalBlockVersionTransitionObserved(
                    proxy_token="logical-route",
                    version=0,
                    physical_handle_token="physical-route-v0",
                    generation=8,
                    provenance="native",
                    stable_identity_json="{}",
                    anchor_ea=0x40C800,
                    predecessor_version=None,
                    from_state="published",
                    to_state="retired",
                ),
                LogicalBlockVersionTransitionObserved(
                    proxy_token="logical-route",
                    version=1,
                    physical_handle_token="physical-route-v1",
                    generation=9,
                    provenance="native",
                    stable_identity_json="{}",
                    anchor_ea=0x40C800,
                    predecessor_version=0,
                    from_state="staged",
                    to_state="published",
                ),
            ),
        ),
    )

    result = mutation_batch(conn, "fragment-batch")

    assert result["semantic_fragment"]["plan_id"] == "fragment-plan"
    assert [row["postcondition"] for row in result["fragment_validations"]] == [
        "dispatcher_absence",
        "root_authority",
    ]
    assert [
        (row["from_state"], row["to_state"]) for row in result["version_transitions"]
    ] == [("published", "retired"), ("staged", "published")]
    assert [
        (
            row["group_id"],
            row["predecessor_anchor_ea_i64"],
            row["publication_succeeded"],
        )
        for row in result["root_publication_groups"]
    ] == [("root-group:entry", 0x40C800, 1)]
    assert [row["event_kind"] for row in result["fragment_events"]] == [
        "plan_recorded",
        "fragment_staged",
        "prepublication_validation",
        "root_group_publication",
        "root_publication",
        "postpublication_validation",
        "receipt",
    ]
    rendered = render_mutation_batch(result)
    assert "fragment plan=fragment-plan atomic-group=atomic-group" in rendered
    assert "root-group[root-group:entry] predecessor=ea@0x000000000040c800" in rendered
    assert "prepublication:dispatcher_absence:dispatcher passed" in rendered
    assert (
        "logical-route@v1 physical=physical-route-v1 generation=9 "
        "provenance=native anchor=ea@0x000000000040c800 "
        "predecessor=v0 staged->published"
    ) in rendered
    db.close()
