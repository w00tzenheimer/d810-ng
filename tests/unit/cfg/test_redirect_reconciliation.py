"""Tests for the redirect reconciliation algorithm."""
from __future__ import annotations

from d810.analyses.control_flow.redirect_reconciliation import (
    EdgeReconciliation,
    ReconciliationBucket,
    StrategyLogSignals,
    format_summary,
    parse_log_signals,
    parse_logged_intent,
    reconcile_edge,
    reconcile_edges,
)


def _empty_signals() -> StrategyLogSignals:
    return StrategyLogSignals(
        prior_use_def_vetoed=frozenset(),
        dag_disagreement={},
        planner_ctx_conflict=frozenset(),
    )


def _hcc_signals(
    *,
    dup: frozenset[int] = frozenset(),
    anchors: frozenset[int] = frozenset(),
    preds: frozenset[int] = frozenset(),
    handlers: frozenset[int] = frozenset(),
) -> StrategyLogSignals:
    return StrategyLogSignals(
        prior_use_def_vetoed=frozenset(),
        dag_disagreement={},
        planner_ctx_conflict=frozenset(),
        hcc_dup_redirect_sources=dup,
        hcc_region_anchors=anchors,
        hcc_region_preds=preds,
        hcc_region_handlers=handlers,
    )


class TestParseLogSignals:
    def test_use_def_vetoed_extracted(self) -> None:
        text = (
            "RECON_REDIRECT_REJECTED_PRIOR_USE_DEF_VETO source=blk[42] old_target=blk[2]\n"
            "RECON_REDIRECT_REJECTED_PRIOR_USE_DEF_VETO source=blk[109] old_target=blk[2]\n"
        )
        sig = parse_log_signals(text)
        assert sig.prior_use_def_vetoed == frozenset({42, 109})

    def test_dag_disagreement_extracted(self) -> None:
        text = (
            "ENGINE DAG_GATE: dropped 2 mod(s) ... "
            "RedirectGoto(src=110 reason=DAG_DISAGREEMENT:110->{planner=143,dag=142}); "
            "RedirectGoto(src=111 reason=DAG_DISAGREEMENT:111->{planner=80,dag=83})"
        )
        sig = parse_log_signals(text)
        assert sig.dag_disagreement == {110: (143, 142), 111: (80, 83)}

    def test_planner_ctx_conflict_extracted(self) -> None:
        text = (
            "PLANNER_CTX_CONFLICT: strategy 'foo' emitted 2 redirect(s) "
            "conflicting: src=16 prior_tgt=68 new_tgt=71"
        )
        sig = parse_log_signals(text)
        assert sig.planner_ctx_conflict == frozenset({16})

    def test_empty_log_returns_empty_signals(self) -> None:
        sig = parse_log_signals("")
        assert sig.prior_use_def_vetoed == frozenset()
        assert sig.dag_disagreement == {}
        assert sig.planner_ctx_conflict == frozenset()


class TestParseLoggedIntent:
    def test_basic_emission_lines(self) -> None:
        text = (
            "trampoline skip: blk[42] state=0x737189D5 -> blk[51]\n"
            "trampoline skip: blk[12] state=0x64AFC49D -> blk[26]\n"
        )
        got = parse_logged_intent(text)
        assert got[42] == (0x737189D5, 51)
        assert got[12] == (0x64AFC49D, 26)

    def test_lowercase_hex_accepted(self) -> None:
        text = "trampoline skip: blk[42] state=0xabcdef01 -> blk[7]"
        got = parse_logged_intent(text)
        assert got[42] == (0xABCDEF01, 7)

    def test_empty_log(self) -> None:
        assert parse_logged_intent("") == {}


class TestReconcileEdgeBuckets:
    def test_agree_full(self) -> None:
        e = reconcile_edge(
            src_serial=42, tgt_serial=2,
            resolver_target=51, logged_intent_target=51, persisted_target=51,
            state_const=0x737189D5, state_in_condition_chain=True,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.AGREE_FULL

    def test_agree_intent_dropped_dag(self) -> None:
        sig = StrategyLogSignals(
            prior_use_def_vetoed=frozenset(),
            dag_disagreement={110: (143, 142)},
            planner_ctx_conflict=frozenset(),
        )
        e = reconcile_edge(
            src_serial=110, tgt_serial=2,
            resolver_target=143, logged_intent_target=143, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=sig,
        )
        assert e.bucket is ReconciliationBucket.AGREE_INTENT_DROPPED_DAG
        assert "planner=143" in e.note
        assert "dag=142" in e.note

    def test_agree_intent_dropped_planner_ctx(self) -> None:
        sig = StrategyLogSignals(
            prior_use_def_vetoed=frozenset(),
            dag_disagreement={},
            planner_ctx_conflict=frozenset({16}),
        )
        e = reconcile_edge(
            src_serial=16, tgt_serial=2,
            resolver_target=71, logged_intent_target=71, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=sig,
        )
        assert e.bucket is ReconciliationBucket.AGREE_INTENT_DROPPED_PLANNER_CTX

    def test_agree_intent_dropped_hcc_dup_redirect(self) -> None:
        sig = _hcc_signals(dup=frozenset({200}))
        e = reconcile_edge(
            src_serial=200, tgt_serial=2,
            resolver_target=23, logged_intent_target=23, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=sig,
        )
        assert e.bucket is ReconciliationBucket.AGREE_INTENT_DROPPED_HCC_DUP_REDIRECT
        assert "intra-fragment dedup" in e.note

    def test_agree_intent_dropped_hcc_region_handler(self) -> None:
        sig = _hcc_signals(handlers=frozenset({21}))
        e = reconcile_edge(
            src_serial=21, tgt_serial=2,
            resolver_target=75, logged_intent_target=75, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=sig,
        )
        assert e.bucket is ReconciliationBucket.AGREE_INTENT_DROPPED_HCC_REGION_HANDLER

    def test_agree_intent_dropped_hcc_region_pred(self) -> None:
        sig = _hcc_signals(preds=frozenset({100}))
        e = reconcile_edge(
            src_serial=100, tgt_serial=2,
            resolver_target=21, logged_intent_target=21, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=sig,
        )
        assert e.bucket is ReconciliationBucket.AGREE_INTENT_DROPPED_HCC_REGION_PRED

    def test_agree_intent_dropped_hcc_region_target(self) -> None:
        sig = _hcc_signals(anchors=frozenset({42}))
        e = reconcile_edge(
            src_serial=56, tgt_serial=2,
            resolver_target=42, logged_intent_target=42, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=sig,
        )
        assert e.bucket is ReconciliationBucket.AGREE_INTENT_DROPPED_HCC_REGION_TARGET
        assert "anchor" in e.note

    def test_hcc_priority_below_dag_and_planner_ctx(self) -> None:
        # If both DAG_DISAGREEMENT and HCC_DUP signals fire for the same
        # source, DAG wins because it represents an EXPLICIT planner-level
        # rejection rather than a downstream subsumption.
        sig = StrategyLogSignals(
            prior_use_def_vetoed=frozenset(),
            dag_disagreement={42: (51, 50)},
            planner_ctx_conflict=frozenset(),
            hcc_dup_redirect_sources=frozenset({42}),
        )
        e = reconcile_edge(
            src_serial=42, tgt_serial=2,
            resolver_target=51, logged_intent_target=51, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=sig,
        )
        assert e.bucket is ReconciliationBucket.AGREE_INTENT_DROPPED_DAG

    def test_agree_intent_dropped_other_when_no_log_signal(self) -> None:
        # Resolver and strategy intent agreed, but pipeline dropped without
        # a per-source log signal — this is the "hidden gate" bucket Piece 5.6
        # is meant to eliminate.
        e = reconcile_edge(
            src_serial=42, tgt_serial=2,
            resolver_target=51, logged_intent_target=51, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.AGREE_INTENT_DROPPED_OTHER
        assert "no per-source drop log line" in e.note

    def test_disagree_target(self) -> None:
        e = reconcile_edge(
            src_serial=54, tgt_serial=2,
            resolver_target=101, logged_intent_target=100, persisted_target=100,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.DISAGREE_TARGET
        assert "resolver=101" in e.note
        assert "strategy_intent=100" in e.note

    def test_resolver_only_use_def_veto(self) -> None:
        sig = StrategyLogSignals(
            prior_use_def_vetoed=frozenset({109}),
            dag_disagreement={},
            planner_ctx_conflict=frozenset(),
        )
        e = reconcile_edge(
            src_serial=109, tgt_serial=2,
            resolver_target=190, logged_intent_target=None, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=sig,
        )
        assert e.bucket is ReconciliationBucket.RESOLVER_OK_STRATEGY_USE_DEF_VETO

    def test_resolver_only_no_strategy_log_no_known_veto(self) -> None:
        e = reconcile_edge(
            src_serial=42, tgt_serial=2,
            resolver_target=51, logged_intent_target=None, persisted_target=None,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.RESOLVER_ONLY_STRATEGY_DIDNT_LOG

    def test_strategy_only_resolver_no_state(self) -> None:
        e = reconcile_edge(
            src_serial=69, tgt_serial=2,
            resolver_target=None, logged_intent_target=122, persisted_target=122,
            state_const=None, state_in_condition_chain=False,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.STRATEGY_ONLY_RESOLVER_NO_STATE

    def test_strategy_only_state_not_in_condition_chain(self) -> None:
        e = reconcile_edge(
            src_serial=145, tgt_serial=2,
            resolver_target=None, logged_intent_target=155, persisted_target=155,
            state_const=0x7A1A2C0, state_in_condition_chain=False,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.STRATEGY_ONLY_STATE_NOT_IN_CONDITION_CHAIN
        assert "0x7a1a2c0" in e.note

    def test_strategy_only_other(self) -> None:
        e = reconcile_edge(
            src_serial=999, tgt_serial=2,
            resolver_target=None, logged_intent_target=42, persisted_target=42,
            state_const=0xABC, state_in_condition_chain=True,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.STRATEGY_ONLY_OTHER

    def test_both_none_no_state(self) -> None:
        e = reconcile_edge(
            src_serial=42, tgt_serial=2,
            resolver_target=None, logged_intent_target=None, persisted_target=None,
            state_const=None, state_in_condition_chain=False,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.BOTH_NONE_NO_STATE

    def test_both_none_state_not_in_condition_chain(self) -> None:
        e = reconcile_edge(
            src_serial=42, tgt_serial=2,
            resolver_target=None, logged_intent_target=None, persisted_target=None,
            state_const=0xDEAD, state_in_condition_chain=False,
            log_signals=_empty_signals(),
        )
        assert e.bucket is ReconciliationBucket.BOTH_NONE_STATE_NOT_IN_CONDITION_CHAIN


class TestReconcileEdgesBatch:
    def test_count_and_summary(self) -> None:
        sig = StrategyLogSignals(
            prior_use_def_vetoed=frozenset({109}),
            dag_disagreement={},
            planner_ctx_conflict=frozenset(),
        )
        edges = [(42, 2), (109, 2), (145, 2)]
        s = reconcile_edges(
            edges,
            resolver_targets={(42, 2): 51, (109, 2): 190, (145, 2): None},
            logged_intent={42: (0x737189D5, 51), 145: (0x10F2434, 155)},
            persisted={42: (2, 51), 145: (2, 155)},
            state_consts={42: 0x737189D5, 109: 0xABC, 145: 0x10F2434},
            condition_chain_table={0x737189D5: 51, 0xABC: 1},  # 145's state not in table
            log_signals=sig,
        )
        counts = s.bucket_counts
        assert counts[ReconciliationBucket.AGREE_FULL] == 1
        assert counts[ReconciliationBucket.RESOLVER_OK_STRATEGY_USE_DEF_VETO] == 1
        assert counts[ReconciliationBucket.STRATEGY_ONLY_STATE_NOT_IN_CONDITION_CHAIN] == 1
        assert s.total == 3
        assert s.safe_overlap == 1

    def test_format_summary_renders_table(self) -> None:
        edges = [(1, 0), (2, 0)]
        s = reconcile_edges(
            edges,
            resolver_targets={(1, 0): 5, (2, 0): None},
            logged_intent={1: (0x1, 5)},
            persisted={1: (0, 5)},
            state_consts={1: 0x1, 2: None},
            condition_chain_table={0x1: 5},
            log_signals=_empty_signals(),
        )
        text = format_summary(s)
        assert "| bucket | count |" in text
        assert "AGREE_FULL" in text
        assert "TOTAL | 2 |" in text


class TestEdgeReconciliationDataclass:
    def test_constructible(self) -> None:
        e = EdgeReconciliation(
            src_serial=42, tgt_serial=2,
            bucket=ReconciliationBucket.AGREE_FULL,
            resolver_target=51, logged_intent_target=51, persisted_target=51,
            state_const=0x737189D5,
        )
        assert e.bucket is ReconciliationBucket.AGREE_FULL
        assert e.note == ""
