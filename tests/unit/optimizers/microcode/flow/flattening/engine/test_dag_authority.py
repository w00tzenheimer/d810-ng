"""Unit tests for DagAuthority — Phase 1 of the DAG-as-arbiter epic (uee-jrgq).

Tests are built against synthetic ``LinearizedStateDag`` fixtures so they
have zero IDA dependency and run in the unit-test tier.
"""
from __future__ import annotations

import pytest

from d810.cfg.graph_modification import (
    ConvertToGoto,
    DuplicateAndRedirect,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.cfg.state_dag_key import StateDagNodeKey
from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
    DagAuthority,
    DagDecision,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateNodeKind,
    StateRedirectAnchor,
)


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _node(
    *,
    handler_serial: int,
    entry_anchor: int | None = None,
    state_const: int | None = None,
) -> StateDagNode:
    """Minimal node — sufficient for arbiter tests; ignores local CFG details."""
    return StateDagNode(
        key=StateDagNodeKey(
            handler_serial=handler_serial,
            state_const=state_const,
        ),
        kind=StateNodeKind.EXACT,
        state_label=f"state_{state_const:#x}" if state_const is not None else "",
        handler_serial=handler_serial,
        entry_anchor=entry_anchor if entry_anchor is not None else handler_serial,
        owned_blocks=(),
        exclusive_blocks=(),
        shared_suffix_blocks=(),
        local_segments=(),
        local_edges=(),
    )


def _edge(
    *,
    source_handler: int,
    target_handler: int | None,
    target_entry_anchor: int | None,
    source_block: int,
    branch_arm: int | None = None,
    kind: SemanticEdgeKind = SemanticEdgeKind.TRANSITION,
    source_state_const: int | None = None,
    target_state_const: int | None = None,
) -> StateDagEdge:
    return StateDagEdge(
        kind=kind,
        source_key=StateDagNodeKey(
            handler_serial=source_handler,
            state_const=source_state_const,
        ),
        target_key=(
            None
            if target_handler is None
            else StateDagNodeKey(
                handler_serial=target_handler, state_const=target_state_const,
            )
        ),
        target_state=target_state_const,
        target_entry_anchor=target_entry_anchor,
        target_label=f"state_{target_state_const:#x}" if target_state_const is not None else "",
        source_anchor=StateRedirectAnchor(
            kind=(
                RedirectSourceKind.UNCONDITIONAL
                if branch_arm is None
                else RedirectSourceKind.CONDITIONAL_BRANCH
            ),
            block_serial=source_block,
            branch_arm=branch_arm,
        ),
        ordered_path=(source_block,)
        if target_entry_anchor is None
        else (source_block, target_entry_anchor),
    )


def _dag(
    *,
    nodes: tuple[StateDagNode, ...] = (),
    edges: tuple[StateDagEdge, ...] = (),
    bst_node_blocks: tuple[int, ...] = (),
) -> LinearizedStateDag:
    return LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=1,
        initial_state=0x5D0AEBD3,
        bst_node_blocks=bst_node_blocks,
        nodes=nodes,
        edges=edges,
        transient_entry_blocks=(),
        transient_state_values=(),
        supplemental_selected_entries=(),
        diagnostics={},
    )


# --------------------------------------------------------------------------
# canonical_target_for
# --------------------------------------------------------------------------


class TestCanonicalTargetFor:
    """The single highest-volume duplication consolidator (R1 finding).

    Every legacy planner reaches into ``dag.edges`` and linear-scans for
    matching source anchor.  ``canonical_target_for`` gives them an O(1)
    lookup with no DAG-internal-conflict ambiguity.
    """

    def test_unique_edge_returns_target(self):
        edge = _edge(
            source_handler=10, target_handler=20,
            target_entry_anchor=20, source_block=10,
        )
        node10 = _node(handler_serial=10, entry_anchor=10)
        node20 = _node(handler_serial=20, entry_anchor=20)
        dag = _dag(nodes=(node10, node20), edges=(edge,))
        auth = DagAuthority(dag)
        assert auth.canonical_target_for(10) == 20

    def test_unknown_source_returns_none(self):
        dag = _dag()
        auth = DagAuthority(dag)
        assert auth.canonical_target_for(99) is None

    def test_branch_arm_disambiguates_anchors_on_same_block(self):
        # Same source block, two distinct branch arms → independent
        # decisions, each with its own target.  Not a conflict.
        edge_arm0 = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10, branch_arm=0,
        )
        edge_arm1 = _edge(
            source_handler=10, target_handler=30, target_entry_anchor=30,
            source_block=10, branch_arm=1,
        )
        dag = _dag(edges=(edge_arm0, edge_arm1))
        auth = DagAuthority(dag)
        assert auth.canonical_target_for(10, branch_arm=0) == 20
        assert auth.canonical_target_for(10, branch_arm=1) == 30
        # Implicit "unconditional" lookup is a different anchor key.
        assert auth.canonical_target_for(10) is None

    def test_dag_internal_conflict_returns_none_and_records_conflict(self):
        # Two edges from same anchor disagree on target — DAG-internal bug.
        # canonical_target_for returns None; conflicts_for_source surfaces
        # the conflict.
        edge_a = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        edge_b = _edge(
            source_handler=10, target_handler=30, target_entry_anchor=30,
            source_block=10,
        )
        dag = _dag(edges=(edge_a, edge_b))
        auth = DagAuthority(dag)
        assert auth.canonical_target_for(10) is None
        conflicts = auth.conflicts_for_source(10)
        assert len(conflicts) == 2

    def test_dag_internal_consensus_collapses_duplicate_edges(self):
        # Two edges from same anchor agreeing on target → not a conflict;
        # canonical lookup returns the agreed target.
        edge_a = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        edge_b = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        dag = _dag(edges=(edge_a, edge_b))
        auth = DagAuthority(dag)
        assert auth.canonical_target_for(10) == 20
        assert auth.conflicts_for_source(10) == ()

    def test_out_of_scope_edge_kinds_ignored(self):
        # Only TRANSITION and CONDITIONAL_TRANSITION are in planner scope.
        # CONDITIONAL_RETURN / EXIT_ROUTINE / UNKNOWN edges must not
        # contribute to canonical_target_for; they're handled by separate
        # PrivateTerminalSuffix / return-family lowering strategies.
        edge_return = _edge(
            source_handler=10, target_handler=None, target_entry_anchor=None,
            source_block=10, kind=SemanticEdgeKind.CONDITIONAL_RETURN,
        )
        dag = _dag(edges=(edge_return,))
        auth = DagAuthority(dag)
        assert auth.canonical_target_for(10) is None

    def test_edge_without_target_entry_ignored(self):
        # Edges with target_entry_anchor=None aren't planner-emittable
        # — ``select_plannable_dag_edges`` filters them out, and so do we.
        edge = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=None,
            source_block=10,
        )
        dag = _dag(edges=(edge,))
        auth = DagAuthority(dag)
        assert auth.canonical_target_for(10) is None


# --------------------------------------------------------------------------
# permits_redirect_goto
# --------------------------------------------------------------------------


class TestPermitsRedirectGoto:
    """The first arbiter the existing _drop_conflicting_redirects filter
    will switch to in Phase 3."""

    def test_allows_when_target_matches_dag(self):
        edge = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        dag = _dag(edges=(edge,))
        auth = DagAuthority(dag)
        decision = auth.permits_redirect_goto(
            RedirectGoto(from_serial=10, old_target=2, new_target=20)
        )
        assert decision.allowed is True
        assert decision.target_entry_anchor == 20
        assert decision.reason == "ALLOW"

    def test_refuses_when_target_disagrees_with_dag(self):
        edge = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        dag = _dag(edges=(edge,))
        auth = DagAuthority(dag)
        decision = auth.permits_redirect_goto(
            RedirectGoto(from_serial=10, old_target=2, new_target=99)
        )
        assert decision.allowed is False
        assert decision.is_disagreement
        assert "DAG_DISAGREEMENT:10" in decision.reason
        assert "planner=99" in decision.reason
        assert "dag=20" in decision.reason

    def test_refuses_with_gap_when_dag_silent(self):
        dag = _dag()
        auth = DagAuthority(dag)
        decision = auth.permits_redirect_goto(
            RedirectGoto(from_serial=10, old_target=2, new_target=20)
        )
        assert decision.allowed is False
        assert decision.is_gap
        assert decision.reason == "DAG_GAP:unknown_source"

    def test_refuses_with_gap_when_dag_internally_conflicting(self):
        edge_a = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        edge_b = _edge(
            source_handler=10, target_handler=30, target_entry_anchor=30,
            source_block=10,
        )
        dag = _dag(edges=(edge_a, edge_b))
        auth = DagAuthority(dag)
        decision = auth.permits_redirect_goto(
            RedirectGoto(from_serial=10, old_target=2, new_target=20)
        )
        assert decision.allowed is False
        assert decision.is_gap
        assert decision.reason == "DAG_GAP:dag_internal_conflict"


# --------------------------------------------------------------------------
# permits_convert_to_goto
# --------------------------------------------------------------------------


class TestPermitsConvertToGoto:
    """ConvertToGoto answers the same DAG question as RedirectGoto:
    'what unconditional target does the source commit to?'"""

    def test_allows_when_target_matches_dag(self):
        edge = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        dag = _dag(edges=(edge,))
        auth = DagAuthority(dag)
        decision = auth.permits_convert_to_goto(
            ConvertToGoto(block_serial=10, goto_target=20)
        )
        assert decision.allowed is True
        assert decision.target_entry_anchor == 20

    def test_refuses_when_target_disagrees(self):
        edge = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        dag = _dag(edges=(edge,))
        auth = DagAuthority(dag)
        decision = auth.permits_convert_to_goto(
            ConvertToGoto(block_serial=10, goto_target=99)
        )
        assert decision.is_disagreement


# --------------------------------------------------------------------------
# Strict DAG_GAP refusals for DupAndRedirect / ZSW
# --------------------------------------------------------------------------


class TestStrictGapRefusals:
    """DupAndRedirect remains a strict DAG_GAP until the safety
    annotations land (uee-7wcd, uee-7snc, uee-qli0, uee-bwdk).
    ZSW was previously gap-refused; Phase 4 (uee-rjo8) consolidated
    the three legacy collectors into a single emitter that enforces
    the canonical-owner invariant by construction, so ZSW is now
    permitted (see test_zero_state_write_allows_post_phase4_consolidation).
    """

    def test_dup_and_redirect_refuses_with_named_gap(self):
        dag = _dag()
        auth = DagAuthority(dag)
        decision = auth.permits_duplicate_and_redirect(
            DuplicateAndRedirect(source_serial=10, per_pred_targets=((9, 20), (8, 21)))
        )
        assert decision.is_gap
        assert decision.reason == "DAG_GAP:duplicate_and_redirect_safety"

    def test_zero_state_write_allows_post_phase4_consolidation(self):
        """ZSW collector consolidation (uee-rjo8, Phase 4) replaced the
        ``DAG_GAP:zero_state_write_legality`` strict refusal with an
        ALLOW. The single-emitter invariant
        (``cfg/zero_state_write_emission.py``) means a ZSW reaching
        the arbiter is by construction the canonical owner's emission,
        so the prior gap is closed.
        """
        dag = _dag()
        auth = DagAuthority(dag)
        decision = auth.permits_zero_state_write(
            ZeroStateWrite(block_serial=10, insn_ea=0x1000)
        )
        assert decision.allowed
        assert decision.reason == "ALLOW"


# --------------------------------------------------------------------------
# permits dispatcher
# --------------------------------------------------------------------------


class TestPermitsDispatcher:
    def test_dispatches_redirect_goto(self):
        edge = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        dag = _dag(edges=(edge,))
        auth = DagAuthority(dag)
        decision = auth.permits(
            RedirectGoto(from_serial=10, old_target=2, new_target=20)
        )
        assert decision.allowed

    def test_dispatches_convert_to_goto(self):
        edge = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10,
        )
        dag = _dag(edges=(edge,))
        auth = DagAuthority(dag)
        decision = auth.permits(ConvertToGoto(block_serial=10, goto_target=20))
        assert decision.allowed

    def test_dispatches_dup_to_gap(self):
        dag = _dag()
        auth = DagAuthority(dag)
        decision = auth.permits(
            DuplicateAndRedirect(source_serial=10, per_pred_targets=((9, 20),))
        )
        assert decision.is_gap

    def test_dispatches_zsw_to_allow(self):
        """Post-Phase-4 (uee-rjo8): ZSW dispatch ALLOWS via the
        canonical-owner invariant from the consolidated emitter."""
        dag = _dag()
        auth = DagAuthority(dag)
        decision = auth.permits(ZeroStateWrite(block_serial=10, insn_ea=0x1000))
        assert decision.allowed

    def test_unknown_mod_kind_refuses_with_gap(self):
        dag = _dag()
        auth = DagAuthority(dag)
        decision = auth.permits(object())
        assert decision.is_gap
        assert "unknown_mod_kind:object" in decision.reason


# --------------------------------------------------------------------------
# DagDecision construction
# --------------------------------------------------------------------------


class TestDagDecision:
    def test_allow_carries_target(self):
        d = DagDecision.allow(target_entry_anchor=42)
        assert d.allowed
        assert d.target_entry_anchor == 42
        assert d.reason == "ALLOW"

    def test_refuse_requires_reason(self):
        with pytest.raises(ValueError):
            DagDecision.refuse("")

    def test_gap_carries_named_reason(self):
        d = DagDecision.gap("my_gap_name")
        assert not d.allowed
        assert d.reason == "DAG_GAP:my_gap_name"
        assert d.is_gap

    def test_disagreement_classification(self):
        d = DagDecision.refuse("DAG_DISAGREEMENT:10->{planner=20,dag=30}")
        assert d.is_disagreement
        assert not d.is_gap


# --------------------------------------------------------------------------
# Index helpers (node lookups, outgoing edges)
# --------------------------------------------------------------------------


class TestIndexHelpers:
    def test_node_for_handler_returns_matching_node(self):
        node = _node(handler_serial=10, entry_anchor=10, state_const=0xABCD)
        dag = _dag(nodes=(node,))
        auth = DagAuthority(dag)
        assert auth.node_for_handler(10) is node

    def test_node_for_entry_anchor_returns_matching_node(self):
        node = _node(handler_serial=10, entry_anchor=42, state_const=0xABCD)
        dag = _dag(nodes=(node,))
        auth = DagAuthority(dag)
        assert auth.node_for_entry_anchor(42) is node

    def test_edges_from_returns_outgoing_edges(self):
        edge = _edge(
            source_handler=10, target_handler=20, target_entry_anchor=20,
            source_block=10, source_state_const=0x1,
        )
        dag = _dag(edges=(edge,))
        auth = DagAuthority(dag)
        out = auth.edges_from(StateDagNodeKey(handler_serial=10, state_const=0x1))
        assert out == (edge,)


# ----------------------------------------------------------------------------
# uee-7wcd — corridor splice (EdgeRedirectViaPredSplit) gap closure
# ----------------------------------------------------------------------------


from d810.cfg.graph_modification import EdgeRedirectViaPredSplit
from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
    CorridorSpliceData,
)


class TestCorridorSpliceClosure:
    """uee-7wcd: DagAuthority gains awareness of function-specific
    corridor splices, moving the gap from
    ``DAG_GAP:unknown_mod_kind:EdgeRedirectViaPredSplit`` to either
    authoritative ALLOW (when seed data matches) or
    ``DAG_GAP:edge_redirect_via_pred_split_seed_missing`` (when no
    seed data is available for the shared block).
    """

    def _seeded_authority(self, *seeds: CorridorSpliceData) -> DagAuthority:
        return DagAuthority(_dag(), corridor_data=tuple(seeds))

    def test_canonical_corridor_splice_for_returns_seed(self) -> None:
        seed = CorridorSpliceData(
            function_ea=0x180012B60,
            shared_block=45,
            base_target=126,
            clone_source=122,
            clone_target=180,
        )
        auth = self._seeded_authority(seed)
        assert auth.canonical_corridor_splice_for(45) is seed

    def test_canonical_corridor_splice_for_returns_none_when_unseeded(self) -> None:
        auth = self._seeded_authority()
        assert auth.canonical_corridor_splice_for(45) is None

    def test_permits_edge_redirect_via_pred_split_allows_when_seed_matches(self) -> None:
        seed = CorridorSpliceData(
            function_ea=0x180012B60,
            shared_block=45,
            base_target=126,
            clone_source=122,
            clone_target=180,
        )
        auth = self._seeded_authority(seed)
        mod = EdgeRedirectViaPredSplit(
            src_block=122,
            old_target=45,
            new_target=180,
            via_pred=37,
            clone_until=45,
        )
        decision = auth.permits_edge_redirect_via_pred_split(mod)
        assert decision.allowed
        assert decision.target_entry_anchor == 180
        assert decision.proof_edge_key[0] == "corridor_splice"

    def test_permits_edge_redirect_via_pred_split_disagrees_on_target_mismatch(self) -> None:
        seed = CorridorSpliceData(
            function_ea=0x180012B60,
            shared_block=45,
            base_target=126,
            clone_source=122,
            clone_target=180,
        )
        auth = self._seeded_authority(seed)
        mod = EdgeRedirectViaPredSplit(
            src_block=122,
            old_target=45,
            new_target=999,  # disagrees with seed clone_target=180
            via_pred=37,
        )
        decision = auth.permits_edge_redirect_via_pred_split(mod)
        assert decision.is_disagreement
        assert "corridor_splice@45" in decision.reason

    def test_permits_edge_redirect_via_pred_split_gap_when_no_seed(self) -> None:
        auth = self._seeded_authority()  # no seeds
        mod = EdgeRedirectViaPredSplit(
            src_block=122,
            old_target=45,
            new_target=180,
            via_pred=37,
        )
        decision = auth.permits_edge_redirect_via_pred_split(mod)
        assert decision.is_gap
        assert decision.reason == "DAG_GAP:edge_redirect_via_pred_split_seed_missing"

    def test_permits_dispatcher_routes_edge_redirect_via_pred_split(self) -> None:
        # The named gap is a strict improvement over the prior
        # DAG_GAP:unknown_mod_kind:EdgeRedirectViaPredSplit.
        auth = self._seeded_authority()
        mod = EdgeRedirectViaPredSplit(
            src_block=122, old_target=45, new_target=180, via_pred=37,
        )
        decision = auth.permits(mod)
        assert decision.is_gap
        assert decision.reason == "DAG_GAP:edge_redirect_via_pred_split_seed_missing"


# ----------------------------------------------------------------------------
# uee-7snc — dead-block-terminator validator
# ----------------------------------------------------------------------------


class _StubProjectedBlock:
    def __init__(self, *, preds: tuple[int, ...] = (), succs: tuple[int, ...] = ()):
        self.preds = preds
        self.succs = succs


class _StubProjectedFlowGraph:
    def __init__(self, blocks: dict[int, _StubProjectedBlock]):
        self.blocks = blocks
    def get_block(self, serial: int):
        return self.blocks.get(int(serial))


class TestDeadBlockTerminatorClosure:
    """uee-7snc: DagAuthority gains a validator for the dead-dispatcher-
    root cleanup pattern.  Mirrors the predicate
    ``_collect_dead_dispatcher_root_cleanup_modifications`` already
    uses inline; the new ``permits_dead_block_terminator_redirect``
    method exposes it through the arbiter so the consumer can record
    an audit trail rather than re-deriving the predicate.
    """

    def test_allows_unreachable_block_with_dispatcher_succ(self) -> None:
        auth = DagAuthority(_dag())
        graph = _StubProjectedFlowGraph({
            42: _StubProjectedBlock(preds=(), succs=(2,)),
        })
        mod = RedirectGoto(from_serial=42, old_target=2, new_target=99)
        decision = auth.permits_dead_block_terminator_redirect(
            mod,
            projected_flow_graph=graph,
            dispatcher_serial=2,
            original_stop_serial=99,
        )
        assert decision.allowed
        assert decision.target_entry_anchor == 99
        assert decision.proof_edge_key[0] == "dead_block_terminator"

    def test_refuses_block_with_preds(self) -> None:
        # Block has predecessors → not dead → can't be retargeted to STOP.
        auth = DagAuthority(_dag())
        graph = _StubProjectedFlowGraph({
            42: _StubProjectedBlock(preds=(10,), succs=(2,)),
        })
        mod = RedirectGoto(from_serial=42, old_target=2, new_target=99)
        decision = auth.permits_dead_block_terminator_redirect(
            mod,
            projected_flow_graph=graph,
            dispatcher_serial=2,
            original_stop_serial=99,
        )
        assert decision.is_disagreement
        assert "block_has_preds" in decision.reason

    def test_refuses_block_succ_not_dispatcher(self) -> None:
        auth = DagAuthority(_dag())
        graph = _StubProjectedFlowGraph({
            42: _StubProjectedBlock(preds=(), succs=(50,)),  # not dispatcher
        })
        mod = RedirectGoto(from_serial=42, old_target=50, new_target=99)
        decision = auth.permits_dead_block_terminator_redirect(
            mod,
            projected_flow_graph=graph,
            dispatcher_serial=2,
            original_stop_serial=99,
        )
        assert decision.is_disagreement
        assert "succ_not_dispatcher" in decision.reason

    def test_refuses_target_not_stop(self) -> None:
        auth = DagAuthority(_dag())
        graph = _StubProjectedFlowGraph({
            42: _StubProjectedBlock(preds=(), succs=(2,)),
        })
        mod = RedirectGoto(from_serial=42, old_target=2, new_target=88)  # not 99
        decision = auth.permits_dead_block_terminator_redirect(
            mod,
            projected_flow_graph=graph,
            dispatcher_serial=2,
            original_stop_serial=99,
        )
        assert decision.is_disagreement
        assert "expected_stop=99" in decision.reason

    def test_gap_when_inputs_missing(self) -> None:
        auth = DagAuthority(_dag())
        mod = RedirectGoto(from_serial=42, old_target=2, new_target=99)
        decision = auth.permits_dead_block_terminator_redirect(
            mod,
            projected_flow_graph=None,
            dispatcher_serial=None,
            original_stop_serial=None,
        )
        assert decision.is_gap
        assert decision.reason == "DAG_GAP:dead_block_terminator_no_projected_graph"

    def test_refuses_block_not_in_graph(self) -> None:
        auth = DagAuthority(_dag())
        graph = _StubProjectedFlowGraph({})  # no block 42
        mod = RedirectGoto(from_serial=42, old_target=2, new_target=99)
        decision = auth.permits_dead_block_terminator_redirect(
            mod,
            projected_flow_graph=graph,
            dispatcher_serial=2,
            original_stop_serial=99,
        )
        assert decision.is_disagreement
        assert "block_not_in_projected_graph" in decision.reason
