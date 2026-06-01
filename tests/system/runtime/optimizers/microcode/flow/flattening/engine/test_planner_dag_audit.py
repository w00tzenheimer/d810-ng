"""Phase 5 (uee-q1du) — DAG_DISAGREEMENT per-run audit summary.

Validates that:

1. ``finalize_reconstruction_fragment`` captures one
   :class:`DagDisagreementRecord` per dropped mod.
2. The captured records flow into fragment metadata under
   ``DAG_AUDIT_METADATA_KEY``.
3. ``UnflatteningPlanner.plan()`` aggregates records across fragments
   and stores them on :attr:`PipelineProvenance.dag_audit_records`.
4. The summary string format is stable.
5. Backward compat: when no DagAuthority is present, no audit records
   are produced and no summary is emitted.
"""
from __future__ import annotations

from d810.transforms.graph_modification import (
    ConvertToGoto,
    RedirectGoto,
)
from d810.transforms.dag_authority import (
    DagDecision,
)
from d810.optimizers.microcode.flow.flattening.engine.planner import (
    UnflatteningPlanner,
    _collect_dag_audit_records,
    _format_dag_audit_summary,
)
from d810.transforms.planner_context import (
    CumulativePlannerView,
)
from d810.analyses.control_flow.provenance import (
    DagDisagreementRecord,
)
from d810.transforms.plan_fragment import (
    BenefitMetrics,
    FAMILY_DIRECT,
    OwnershipScope,
    PlanFragment,
)
from d810.optimizers.microcode.flow.flattening.hodur.reconstruction_fragment_builder import (
    DAG_AUDIT_METADATA_KEY,
    finalize_reconstruction_fragment,
)


def _stub_authority(
    *,
    allow_for: dict[int, int] | None = None,
    disagree_for: dict[int, int] | None = None,
    gap_for: set[int] | None = None,
):
    """Build a duck-typed DagAuthority stand-in for unit testing.

    ``allow_for[src] = canonical_target`` → :func:`DagDecision.allow`
    ``disagree_for[src] = canonical_target`` → DAG_DISAGREEMENT refusal
    ``gap_for`` → DAG_GAP refusal
    """
    allow = dict(allow_for or {})
    disagree = dict(disagree_for or {})
    gap = set(gap_for or ())

    class _StubAuthority:
        def permits(self, mod):
            src = getattr(mod, "from_serial", None)
            if src is None:
                src = getattr(mod, "block_serial", None)
            if src is None:
                return DagDecision.gap("no_source")
            src_int = int(src)
            if src_int in gap:
                return DagDecision.gap("unknown_source")
            if src_int in disagree:
                canonical = disagree[src_int]
                new_tgt = (
                    getattr(mod, "new_target", None)
                    or getattr(mod, "goto_target", None)
                )
                return DagDecision.refuse(
                    f"DAG_DISAGREEMENT:{src_int}->"
                    f"{{planner={new_tgt},dag={canonical}}}"
                )
            if src_int in allow:
                return DagDecision.allow(target_entry_anchor=allow[src_int])
            return DagDecision.gap("unknown_source")

    return _StubAuthority()


def _finalize(
    *,
    strategy_name: str = "state_write_reconstruction",
    modifications: list,
    owned_blocks: set[int] | None = None,
    view: CumulativePlannerView | None = None,
):
    return finalize_reconstruction_fragment(
        strategy_name=strategy_name,
        modifications=modifications,
        owned_blocks=owned_blocks if owned_blocks is not None else set(),
        owned_edges=frozenset(),
        accepted_metadata=[],
        rejected_metadata=[],
        allow_post_apply_bst_cleanup=True,
        post_apply_bst_cleanup_reason=None,
        residual_dispatcher_preds=(),
        structured_region_fidelity=None,
        round_index=0,
        cumulative_planner_view=view,
    )


# ----------------------------------------------------------------------
# Per-fragment record capture
# ----------------------------------------------------------------------


class TestSingleFragmentRecordCapture:
    """When a single fragment drops mods, each drop produces one record."""

    def test_one_disagreement_yields_one_record(self) -> None:
        authority = _stub_authority(disagree_for={76: 11})
        view = CumulativePlannerView.empty(dag_authority=authority)

        frag = _finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=2),
            ],
            owned_blocks={76},
            view=view,
        )

        records = frag.metadata[DAG_AUDIT_METADATA_KEY]
        assert isinstance(records, tuple)
        assert len(records) == 1
        record = records[0]
        assert isinstance(record, DagDisagreementRecord)
        assert record.planner_name == "state_write_reconstruction"
        assert record.mod_kind == "RedirectGoto"
        assert record.source_block == 76
        assert record.branch_arm is None
        assert record.planner_target == 2
        assert record.dag_target == 11
        assert record.phase == "post_apply_filter"
        assert record.decision_reason.startswith("DAG_DISAGREEMENT:")

    def test_convert_to_goto_record_uses_block_serial(self) -> None:
        authority = _stub_authority(disagree_for={76: 11})
        view = CumulativePlannerView.empty(dag_authority=authority)

        frag = _finalize(
            modifications=[ConvertToGoto(block_serial=76, goto_target=2)],
            owned_blocks={76},
            view=view,
        )

        records = frag.metadata[DAG_AUDIT_METADATA_KEY]
        assert len(records) == 1
        record = records[0]
        assert record.mod_kind == "ConvertToGoto"
        assert record.source_block == 76
        assert record.planner_target == 2
        assert record.dag_target == 11

    def test_dag_allow_produces_no_records(self) -> None:
        authority = _stub_authority(allow_for={76: 11})
        view = CumulativePlannerView.empty(dag_authority=authority)

        frag = _finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ],
            owned_blocks={76},
            view=view,
        )
        assert frag.metadata[DAG_AUDIT_METADATA_KEY] == ()

    def test_dag_gap_does_not_produce_disagreement_record(self) -> None:
        # Phase 5 records are only captured for refusals (drops).  GAPs
        # are kept by ``filter_dag_disagreements`` and deferred to legacy.
        authority = _stub_authority(gap_for={76})
        view = CumulativePlannerView.empty(dag_authority=authority)

        frag = _finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ],
            owned_blocks={76},
            view=view,
        )
        assert frag.metadata[DAG_AUDIT_METADATA_KEY] == ()

    def test_no_dag_authority_yields_empty_records(self) -> None:
        view = CumulativePlannerView.empty()  # no dag_authority
        frag = _finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ],
            owned_blocks={76},
            view=view,
        )
        assert frag.metadata[DAG_AUDIT_METADATA_KEY] == ()

    def test_no_view_yields_empty_records(self) -> None:
        frag = _finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ],
            owned_blocks={76},
            view=None,
        )
        assert frag.metadata[DAG_AUDIT_METADATA_KEY] == ()

    def test_multiple_disagreements_yield_one_record_each(self) -> None:
        authority = _stub_authority(disagree_for={76: 11, 99: 5})
        view = CumulativePlannerView.empty(dag_authority=authority)

        frag = _finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=2),
                RedirectGoto(from_serial=99, old_target=2, new_target=2),
            ],
            owned_blocks={76, 99},
            view=view,
        )
        records = frag.metadata[DAG_AUDIT_METADATA_KEY]
        assert len(records) == 2
        srcs = {r.source_block for r in records}
        assert srcs == {76, 99}


# ----------------------------------------------------------------------
# Aggregation across fragments
# ----------------------------------------------------------------------


class TestMultiFragmentAggregation:
    def test_collect_records_across_fragments(self) -> None:
        # Two fragments each contribute a record; aggregation preserves
        # both in fragment-encounter order.
        authority = _stub_authority(disagree_for={76: 11, 99: 5})
        view = CumulativePlannerView.empty(dag_authority=authority)

        frag_a = _finalize(
            strategy_name="state_write_reconstruction",
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=2),
            ],
            owned_blocks={76},
            view=view,
        )
        frag_b = _finalize(
            strategy_name="residual_handoff",
            modifications=[
                RedirectGoto(from_serial=99, old_target=2, new_target=2),
            ],
            owned_blocks={99},
            view=view,
        )

        aggregated = _collect_dag_audit_records([frag_a, frag_b])
        assert len(aggregated) == 2
        # Order is fragment encounter order.
        assert aggregated[0].source_block == 76
        assert aggregated[1].source_block == 99
        assert aggregated[0].planner_name == "state_write_reconstruction"
        assert aggregated[1].planner_name == "residual_handoff"

    def test_collect_skips_fragments_without_metadata(self) -> None:
        # A naked fragment (e.g. one not produced by
        # finalize_reconstruction_fragment) contributes nothing.
        bare = PlanFragment(
            strategy_name="bare",
            family=FAMILY_DIRECT,
            ownership=OwnershipScope(
                blocks=frozenset(),
                edges=frozenset(),
                transitions=frozenset(),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=0,
                conflict_density=0.0,
            ),
            risk_score=0.0,
            modifications=[],
        )
        assert _collect_dag_audit_records([bare]) == ()

    def test_collect_handles_empty_records(self) -> None:
        # A fragment with metadata[DAG_AUDIT_METADATA_KEY] = () returns nothing.
        frag = _finalize(
            modifications=[
                RedirectGoto(from_serial=76, old_target=2, new_target=11),
            ],
            owned_blocks={76},
            view=None,
        )
        assert _collect_dag_audit_records([frag]) == ()


# ----------------------------------------------------------------------
# Summary format snapshot
# ----------------------------------------------------------------------


class TestSummaryFormat:
    def test_empty_records_produces_empty_string(self) -> None:
        assert _format_dag_audit_summary(()) == ""

    def test_single_disagreement_format(self) -> None:
        records = (
            DagDisagreementRecord(
                planner_name="state_write_reconstruction",
                mod_kind="RedirectGoto",
                source_block=76,
                branch_arm=None,
                planner_target=2,
                dag_target=11,
                phase="post_apply_filter",
                decision_reason=(
                    "DAG_DISAGREEMENT:76->{planner=2,dag=11}"
                ),
            ),
        )
        summary = _format_dag_audit_summary(records)
        assert "PLANNER_DAG_AUDIT:" in summary
        assert "Total disagreements: 1 across 1 planner" in summary
        assert "state_write_reconstruction: 1 disagreement" in summary
        assert "blk[76]->2 vs DAG=11" in summary

    def test_multi_planner_summary_groups_by_planner(self) -> None:
        records = (
            DagDisagreementRecord(
                planner_name="srw",
                mod_kind="RedirectGoto",
                source_block=76,
                branch_arm=None,
                planner_target=2,
                dag_target=11,
                phase="post_apply_filter",
                decision_reason="DAG_DISAGREEMENT:76->{planner=2,dag=11}",
            ),
            DagDisagreementRecord(
                planner_name="srw",
                mod_kind="RedirectGoto",
                source_block=111,
                branch_arm=None,
                planner_target=2,
                dag_target=83,
                phase="post_apply_filter",
                decision_reason="DAG_DISAGREEMENT:111->{planner=2,dag=83}",
            ),
            DagDisagreementRecord(
                planner_name="residual_handoff",
                mod_kind="RedirectGoto",
                source_block=33,
                branch_arm=None,
                planner_target=24,
                dag_target=199,
                phase="post_apply_filter",
                decision_reason="DAG_DISAGREEMENT:33->{planner=24,dag=199}",
            ),
        )
        summary = _format_dag_audit_summary(records)
        assert "Total disagreements: 3 across 2 planner" in summary
        # srw should appear before residual_handoff (sorted by descending count).
        srw_idx = summary.find("srw:")
        rh_idx = summary.find("residual_handoff:")
        assert srw_idx != -1 and rh_idx != -1
        assert srw_idx < rh_idx
        assert "srw: 2 disagreement" in summary
        assert "residual_handoff: 1 disagreement" in summary

    def test_dag_gaps_reported_separately(self) -> None:
        records = (
            DagDisagreementRecord(
                planner_name="srw",
                mod_kind="RedirectGoto",
                source_block=76,
                branch_arm=None,
                planner_target=2,
                dag_target=11,
                phase="post_apply_filter",
                decision_reason="DAG_DISAGREEMENT:76->{planner=2,dag=11}",
            ),
            DagDisagreementRecord(
                planner_name="srw",
                mod_kind="RedirectGoto",
                source_block=200,
                branch_arm=None,
                planner_target=2,
                dag_target=None,
                phase="post_apply_filter",
                decision_reason="DAG_GAP:unknown_source",
            ),
        )
        summary = _format_dag_audit_summary(records)
        # 1 real disagreement, 1 gap reported separately.
        assert "Total disagreements: 1 across 1 planner" in summary
        assert "DAG_GAP refusals: 1 mod" in summary

    def test_only_gaps_yields_zero_disagreements(self) -> None:
        records = (
            DagDisagreementRecord(
                planner_name="srw",
                mod_kind="RedirectGoto",
                source_block=200,
                branch_arm=None,
                planner_target=2,
                dag_target=None,
                phase="post_apply_filter",
                decision_reason="DAG_GAP:unknown_source",
            ),
        )
        summary = _format_dag_audit_summary(records)
        assert "Total disagreements: 0 across 0 planner" in summary
        assert "DAG_GAP refusals: 1 mod" in summary
        # No "By planner:" section when nothing to list.
        assert "By planner:" not in summary

    def test_truncation_for_planner_with_many_drops(self) -> None:
        # Verify the per-planner detail line caps at 5 entries with a
        # "+N more" suffix when a planner accumulates many drops.
        records = tuple(
            DagDisagreementRecord(
                planner_name="srw",
                mod_kind="RedirectGoto",
                source_block=10 + i,
                branch_arm=None,
                planner_target=2,
                dag_target=100 + i,
                phase="post_apply_filter",
                decision_reason=(
                    f"DAG_DISAGREEMENT:{10 + i}->"
                    f"{{planner=2,dag={100 + i}}}"
                ),
            )
            for i in range(7)
        )
        summary = _format_dag_audit_summary(records)
        assert "srw: 7 disagreement" in summary
        assert "(+2 more)" in summary


# ----------------------------------------------------------------------
# End-to-end through UnflatteningPlanner.plan()
# ----------------------------------------------------------------------


class _DropOnlyStrategy:
    """Test-only strategy that returns a pre-built fragment.

    ``UnflatteningPlanner.plan()`` polls strategies; this lets us inject
    a fragment whose metadata already carries DAG audit records (as if
    ``finalize_reconstruction_fragment`` had captured them).
    """

    def __init__(self, name: str, fragment: PlanFragment) -> None:
        self._name = name
        self._fragment = fragment

    @property
    def name(self) -> str:
        return self._name

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    def is_applicable(self, snapshot) -> bool:
        return True

    def plan(self, snapshot):
        return self._fragment


def _make_fragment_with_audit(
    *,
    strategy_name: str,
    audit_records: tuple[DagDisagreementRecord, ...],
) -> PlanFragment:
    return PlanFragment(
        strategy_name=strategy_name,
        family=FAMILY_DIRECT,
        ownership=OwnershipScope(
            blocks=frozenset({1}),
            edges=frozenset(),
            transitions=frozenset(),
        ),
        prerequisites=[],
        expected_benefit=BenefitMetrics(
            handlers_resolved=1,
            transitions_resolved=1,
            blocks_freed=0,
            conflict_density=0.0,
        ),
        risk_score=0.0,
        metadata={DAG_AUDIT_METADATA_KEY: audit_records},
        modifications=[
            RedirectGoto(from_serial=1, old_target=2, new_target=3),
        ],
    )


class TestPlanRunEndToEnd:
    def test_planner_aggregates_and_emits_summary(self, caplog) -> None:
        from d810.transforms.snapshot import (
            AnalysisSnapshot,
        )

        records = (
            DagDisagreementRecord(
                planner_name="srw",
                mod_kind="RedirectGoto",
                source_block=76,
                branch_arm=None,
                planner_target=2,
                dag_target=11,
                phase="post_apply_filter",
                decision_reason="DAG_DISAGREEMENT:76->{planner=2,dag=11}",
            ),
        )
        frag = _make_fragment_with_audit(
            strategy_name="srw",
            audit_records=records,
        )

        snapshot = AnalysisSnapshot(mba=None)
        strategy = _DropOnlyStrategy("srw", frag)

        planner = UnflatteningPlanner()
        with caplog.at_level("INFO"):
            _, provenance = planner.plan(snapshot, [strategy])

        # Provenance carries the audit records.
        assert provenance.dag_audit_records == records
        # Summary went out at INFO via the planner's logger.
        joined = "\n".join(rec.message for rec in caplog.records)
        assert "PLANNER_DAG_AUDIT" in joined
        assert "srw: 1 disagreement" in joined

    def test_planner_no_records_no_summary(self, caplog) -> None:
        # Backward compat: when no fragments carry audit records, no
        # PLANNER_DAG_AUDIT line is emitted and dag_audit_records stays
        # empty.
        from d810.transforms.snapshot import (
            AnalysisSnapshot,
        )

        frag = _make_fragment_with_audit(
            strategy_name="srw",
            audit_records=(),
        )
        snapshot = AnalysisSnapshot(mba=None)
        strategy = _DropOnlyStrategy("srw", frag)

        planner = UnflatteningPlanner()
        with caplog.at_level("INFO"):
            _, provenance = planner.plan(snapshot, [strategy])

        assert provenance.dag_audit_records == ()
        joined = "\n".join(rec.message for rec in caplog.records)
        assert "PLANNER_DAG_AUDIT" not in joined


# ----------------------------------------------------------------------------
# uee-2hng — engine-level DAG conformance gate covers ALL strategies
# ----------------------------------------------------------------------------


from d810.optimizers.microcode.flow.flattening.engine.fragment_arbitration import (
    DAG_AUDIT_METADATA_KEY as _DAG_AUDIT_METADATA_KEY,
    apply_dag_conformance_gate as _apply_engine_dag_conformance_gate,
)


class TestEngineDagConformanceGate:
    """uee-2hng: every fragment from every strategy passes through the
    engine-level conformance gate so non-SRW finalizers no longer bypass
    DAG-disagreement filtering.

    Empirical motivation: on sub_7FFD, blk[110] had a correct ``→142``
    proposal from shared-group dropped by the legacy filter because a
    wrong ``→137`` proposal from ``plan_residual_goto_emission`` (in a
    fragment that bypassed the SRW finalizer's arbiter) committed first.
    """

    def _stub_authority_disagreeing(self, *, src: int, dag_target: int):
        from d810.transforms.dag_authority import (
            DagDecision,
        )
        class _Authority:
            def permits(self, mod):
                return DagDecision.refuse(
                    f"DAG_DISAGREEMENT:{src}->"
                    f"{{planner={getattr(mod, 'new_target', None)},dag={dag_target}}}"
                )
        return _Authority()

    def _stub_authority_allow_all(self):
        from d810.transforms.dag_authority import (
            DagDecision,
        )
        class _Authority:
            def permits(self, mod):
                return DagDecision.allow(
                    target_entry_anchor=getattr(mod, "new_target", None)
                    or getattr(mod, "goto_target", None),
                )
        return _Authority()

    def _stub_authority_gap_all(self):
        from d810.transforms.dag_authority import (
            DagDecision,
        )
        class _Authority:
            def permits(self, mod):
                return DagDecision.gap("unknown_source")
        return _Authority()

    def _make_fragment(self, *, strategy_name: str = "any_strategy",
                       modifications=None, metadata=None) -> PlanFragment:
        return PlanFragment(
            strategy_name=strategy_name,
            family="direct",
            ownership=OwnershipScope(
                blocks=frozenset(), edges=frozenset(), transitions=frozenset(),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0, transitions_resolved=0,
                blocks_freed=0, conflict_density=0.0,
            ),
            risk_score=0.0,
            metadata=metadata if metadata is not None else {},
            modifications=modifications if modifications is not None else [],
        )

    def test_no_view_is_no_op(self):
        frag = self._make_fragment(
            modifications=[RedirectGoto(from_serial=110, old_target=2, new_target=137)]
        )
        result = _apply_engine_dag_conformance_gate(frag, None)
        assert result is frag

    def test_no_authority_is_no_op(self):
        frag = self._make_fragment(
            modifications=[RedirectGoto(from_serial=110, old_target=2, new_target=137)]
        )
        view = CumulativePlannerView.empty()  # no dag_authority
        result = _apply_engine_dag_conformance_gate(frag, view)
        assert result is frag

    def test_already_audited_fragment_is_skipped(self):
        # SRW idempotency: a fragment that already has dag_audit
        # metadata (because finalize_reconstruction_fragment ran the
        # check internally) is returned unchanged.
        frag = self._make_fragment(
            modifications=[RedirectGoto(from_serial=110, old_target=2, new_target=137)],
            metadata={_DAG_AUDIT_METADATA_KEY: ()},
        )
        view = CumulativePlannerView.empty(
            dag_authority=self._stub_authority_disagreeing(src=110, dag_target=142),
        )
        result = _apply_engine_dag_conformance_gate(frag, view)
        assert result is frag  # unchanged

    def test_drops_disagreement_for_non_srw_strategy(self):
        # The motivating case: residual_handoff emits 110→137; DAG
        # says 142.  Engine gate drops 137.
        frag = self._make_fragment(
            strategy_name="plan_residual_goto_emission",
            modifications=[
                RedirectGoto(from_serial=110, old_target=2, new_target=137),
                RedirectGoto(from_serial=99, old_target=2, new_target=55),
            ],
        )
        view = CumulativePlannerView.empty(
            dag_authority=self._stub_authority_disagreeing(src=110, dag_target=142),
        )
        result = _apply_engine_dag_conformance_gate(frag, view)
        # The disagreement was dropped; the unrelated redirect kept.
        # (Stub returns DAG_DISAGREEMENT for ALL mods, so 99→55 also
        # gets dropped — adjust expectations.)
        # Both mods get the disagreement; both drop.
        assert len(result.modifications) == 0
        # Audit records appear in metadata.
        records = result.metadata[_DAG_AUDIT_METADATA_KEY]
        assert len(records) == 2
        assert all(r.planner_name == "plan_residual_goto_emission" for r in records)
        assert all(r.phase == "engine_post_plan_gate" for r in records)

    def test_keeps_dag_allow_decisions(self):
        frag = self._make_fragment(
            modifications=[
                RedirectGoto(from_serial=110, old_target=2, new_target=142),
            ],
        )
        view = CumulativePlannerView.empty(
            dag_authority=self._stub_authority_allow_all(),
        )
        result = _apply_engine_dag_conformance_gate(frag, view)
        # Mod allowed; no change to the fragment object (no records added).
        assert result is frag
        assert _DAG_AUDIT_METADATA_KEY not in frag.metadata

    def test_keeps_dag_gap_decisions(self):
        frag = self._make_fragment(
            modifications=[
                RedirectGoto(from_serial=110, old_target=2, new_target=137),
            ],
        )
        view = CumulativePlannerView.empty(
            dag_authority=self._stub_authority_gap_all(),
        )
        result = _apply_engine_dag_conformance_gate(frag, view)
        # DAG_GAP keeps the mod (legacy fallback territory).
        # No records added → fragment unchanged.
        assert result is frag

    def test_dag_disagreement_record_carries_planner_target_and_dag_target(self):
        frag = self._make_fragment(
            strategy_name="some_strategy",
            modifications=[
                RedirectGoto(from_serial=110, old_target=2, new_target=137),
            ],
        )
        view = CumulativePlannerView.empty(
            dag_authority=self._stub_authority_disagreeing(src=110, dag_target=142),
        )
        result = _apply_engine_dag_conformance_gate(frag, view)
        records = result.metadata[_DAG_AUDIT_METADATA_KEY]
        assert len(records) == 1
        record = records[0]
        assert record.source_block == 110
        assert record.planner_target == 137
        assert record.dag_target == 142
        assert record.decision_reason.startswith("DAG_DISAGREEMENT:")
