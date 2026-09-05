"""Executable encoding of the DagAuthority grant invariant (d81-9q6e).

Invariant under test
--------------------

    DagAuthority may restrict which proposals are emitted; it must never
    independently grant final mutation or semantic-loss permission.

Two things follow from that sentence, and each gets its own test class:

``TestArbiterIsSubtractive``
    The only production consumer of a ``DagDecision``
    (:func:`d810.transforms.fragment_arbitration.filter_dag_disagreements`)
    must only ever *remove* planner proposals. It may not create, mutate, or
    reorder them, and it may not turn an empty proposal list into a non-empty
    one. An arbiter that can only subtract cannot grant.

``TestNoIndependentGrant``
    No ``permits_*`` verdict may be ``ALLOW`` unless the underlying
    ``LinearizedStateDag`` actually says so. An authority built over an *empty*
    DAG knows nothing, so it must refuse everything. Any ``ALLOW`` from an empty
    authority is by definition an independent grant.

``TestNoGrantShapedApiSurface``
    Neither ``DagAuthority`` nor ``DagDecision`` may grow an API that applies,
    commits, or certifies a mutation, or that speaks about semantic loss. The
    arbiter answers a question; it does not carry out or bless the answer.

See ``.tmp/audit/2026-09-05-dag-authority-audit.md`` for the full call-site
enumeration this file encodes.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
import pathlib
import textwrap

import pytest

from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
    StateNodeKind,
    StateRedirectAnchor,
)
from d810.ir.state_dag_key import StateDagNodeKey
from d810.transforms.dag_authority import DagAuthority, DagDecision
from d810.transforms.fragment_arbitration import (
    filter_dag_disagreements,
    redirect_source,
)
from d810.transforms.graph_modification import (
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.transforms.planner_context import (
    CumulativePlannerView,
    LinearizationDecision,
)
from d810.transforms.fragment_arbitration import (
    DAG_AUDIT_METADATA_KEY,
    apply_dag_conformance_gate,
)
from d810.transforms.plan_fragment import (
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.transforms.reconstruction_fragment_builder import (
    finalize_reconstruction_fragment,
)

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _dag(*, edges: tuple[StateDagEdge, ...] = ()) -> LinearizedStateDag:
    """A DAG carrying only the fields the arbiter reads."""
    return LinearizedStateDag(
        dispatcher_entry_serial=2,
        state_var_stkoff=0x3C,
        pre_header_serial=1,
        initial_state=0x5D0AEBD3,
        condition_chain_blocks=(),
        nodes=(),
        edges=edges,
        transient_entry_blocks=(),
        transient_state_values=(),
        supplemental_selected_entries=(),
        diagnostics={},
    )


def _edge(*, source_block: int, target_entry_anchor: int) -> StateDagEdge:
    """One in-scope unconditional TRANSITION edge."""
    return StateDagEdge(
        kind=SemanticEdgeKind.TRANSITION,
        source_key=StateDagNodeKey(handler_serial=source_block, state_const=None),
        target_key=StateDagNodeKey(
            handler_serial=target_entry_anchor, state_const=None
        ),
        target_state=None,
        target_entry_anchor=target_entry_anchor,
        target_label="",
        source_anchor=StateRedirectAnchor(
            kind=RedirectSourceKind.UNCONDITIONAL,
            block_serial=source_block,
            branch_arm=None,
        ),
        ordered_path=(source_block, target_entry_anchor),
    )


def _empty_authority() -> DagAuthority:
    """An authority that knows nothing: no edges, no corridor seed."""
    return DagAuthority(_dag())


def _view(authority: DagAuthority | None) -> CumulativePlannerView:
    return CumulativePlannerView.empty(dag_authority=authority)


class _ProjectedBlock:
    """Minimal duck-typed stand-in for a projected-CFG block."""

    def __init__(
        self, *, preds: tuple[int, ...] = (), succs: tuple[int, ...] = ()
    ) -> None:
        self.preds = preds
        self.succs = succs


class _ProjectedFlowGraph:
    """Minimal duck-typed stand-in for the caller's projected post-mod CFG."""

    def __init__(self, blocks: dict[int, _ProjectedBlock]) -> None:
        self.blocks = blocks

    def get_block(self, serial: int) -> _ProjectedBlock | None:
        return self.blocks.get(int(serial))


#: Every modification kind ``DagAuthority.permits`` dispatches on. Each entry
#: is (label, factory).
ALL_DISPATCHED_MODS = (
    ("RedirectGoto", lambda: RedirectGoto(from_serial=10, old_target=2, new_target=20)),
    ("ConvertToGoto", lambda: ConvertToGoto(block_serial=10, goto_target=20)),
    ("ZeroStateWrite", lambda: ZeroStateWrite(block_serial=10, insn_ea=0x1000)),
    (
        "EdgeRedirectViaPredSplit",
        lambda: EdgeRedirectViaPredSplit(
            src_block=122,
            old_target=45,
            new_target=180,
            via_pred=44,
            clone_until=123,
        ),
    ),
)


#: Reflection-driven coverage of ``DagAuthority.permits*``.
#:
#: The audit's original matrix was a hand-written list, so a newly added
#: ``permits_whatever()`` returning ``DagDecision.allow(...)`` would have been
#: invisible to this file *and* to ``rules/no-dag-authority-mutation-grant.yml``
#: (which exempts the whole ``permits_`` vocabulary). The tests below discover
#: the methods with :mod:`inspect` and fail on any that is not enrolled here,
#: so adding an arbiter method forces a decision about its evidence.
#:
#: ``dag_edges`` is the DAG state that would back an ALLOW; ``can_allow``
#: records whether any DAG state at all can earn one.
@dataclasses.dataclass(frozen=True)
class _PermitsCase:
    make_mod: object
    dag_edges: tuple[tuple[int, int], ...] = ()
    kwargs: dict[str, object] = dataclasses.field(default_factory=dict)
    can_allow: bool = True


PERMITS_COVERAGE: dict[str, _PermitsCase] = {
    "permits": _PermitsCase(
        make_mod=lambda: RedirectGoto(from_serial=10, old_target=2, new_target=20),
        dag_edges=((10, 20),),
    ),
    "permits_redirect_goto": _PermitsCase(
        make_mod=lambda: RedirectGoto(from_serial=10, old_target=2, new_target=20),
        dag_edges=((10, 20),),
    ),
    "permits_convert_to_goto": _PermitsCase(
        make_mod=lambda: ConvertToGoto(block_serial=10, goto_target=20),
        dag_edges=((10, 20),),
    ),
    "permits_edge_redirect_via_pred_split": _PermitsCase(
        make_mod=lambda: EdgeRedirectViaPredSplit(
            src_block=122,
            old_target=45,
            new_target=180,
            via_pred=37,
            clone_until=45,
        ),
        dag_edges=((122, 180),),
    ),
    # ZSW legality is a single-emitter invariant owned by another module; no
    # DAG state can back it (aa-v8et).
    "permits_zero_state_write": _PermitsCase(
        make_mod=lambda: ZeroStateWrite(block_serial=10, insn_ea=0x1000),
        dag_edges=((10, 20),),
        can_allow=False,
    ),
    # Every input is caller-supplied projected-CFG state; no DAG state can
    # back it (aa-v8et).
    "permits_dead_block_terminator_redirect": _PermitsCase(
        make_mod=lambda: RedirectGoto(from_serial=42, old_target=2, new_target=99),
        dag_edges=((42, 99),),
        kwargs={
            "projected_flow_graph": _ProjectedFlowGraph(
                {42: _ProjectedBlock(preds=(), succs=(2,))}
            ),
            "dispatcher_serial": 2,
            "original_stop_serial": 99,
        },
        can_allow=False,
    ),
}


def _permits_methods_dispatched_by_permits() -> frozenset[str]:
    """The ``permits_*`` methods ``DagAuthority.permits`` can actually route to.

    Read off the dispatch table by reflection, so a newly added route shows up
    here without anyone remembering to update a list.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(DagAuthority.permits)))
    return frozenset(
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.startswith("permits_")
    )


def _discovered_permits_methods() -> tuple[str, ...]:
    """Every arbiter verdict method, found by reflection rather than by list."""
    return tuple(
        sorted(
            name
            for name, _ in inspect.getmembers(DagAuthority, inspect.isfunction)
            if name.startswith("permits")
        )
    )


def _authority_for(case: _PermitsCase) -> DagAuthority:
    return DagAuthority(
        _dag(
            edges=tuple(
                _edge(source_block=src, target_entry_anchor=tgt)
                for src, tgt in case.dag_edges
            )
        )
    )


def _assert_allow_is_edge_backed(authority: DagAuthority, decision: DagDecision):
    """An ALLOW's proof must name an edge that is actually in the DAG."""
    key = decision.proof_edge_key
    assert key is not None, "ALLOW carries no proof_edge_key"
    block_serial, branch_arm, target, _mod_kind = key
    matches = [
        edge
        for edge in authority.dag.edges
        if int(edge.source_anchor.block_serial) == int(block_serial)
        and edge.source_anchor.branch_arm == branch_arm
        and edge.target_entry_anchor == target
    ]
    assert matches, (
        f"ALLOW proof {key!r} names no edge present in the DAG; the arbiter "
        "granted on something other than DAG state"
    )
    assert decision.target_entry_anchor == target


# --------------------------------------------------------------------------
# The arbiter may only subtract
# --------------------------------------------------------------------------


class TestArbiterIsSubtractive:
    """``filter_dag_disagreements`` may remove proposals and nothing else."""

    def test_empty_proposal_list_stays_empty(self) -> None:
        """An arbiter cannot conjure a modification out of a DAG edge.

        The DAG below canonically commits block 10 to anchor 20. That is a
        strictly stronger fact than any planner has, yet the arbiter must not
        emit the corresponding ``RedirectGoto`` on its own.
        """
        authority = DagAuthority(
            _dag(edges=(_edge(source_block=10, target_entry_anchor=20),))
        )
        kept, records = filter_dag_disagreements(
            [],
            _view(authority),
            strategy_name="test",
            phase="unit",
        )
        assert kept == []
        assert records == ()

    def test_kept_modifications_are_a_subset_of_the_input(self) -> None:
        """Output identities must be drawn from the input, never synthesised."""
        authority = DagAuthority(
            _dag(edges=(_edge(source_block=10, target_entry_anchor=20),))
        )
        conforming = RedirectGoto(from_serial=10, old_target=2, new_target=20)
        disagreeing = RedirectGoto(from_serial=10, old_target=2, new_target=99)
        gap_region = RedirectGoto(from_serial=77, old_target=2, new_target=88)
        proposals = [conforming, disagreeing, gap_region]

        kept, records = filter_dag_disagreements(
            list(proposals),
            _view(authority),
            strategy_name="test",
            phase="unit",
        )

        assert all(any(k is p for p in proposals) for k in kept), (
            "arbiter returned an object it did not receive"
        )
        assert len(kept) <= len(proposals)
        # The disagreeing mod is the only one dropped: ALLOW and DAG_GAP keep.
        assert [id(m) for m in kept] == [id(conforming), id(gap_region)]
        assert len(records) == 1

    def test_input_modifications_are_not_mutated(self) -> None:
        """A refused proposal must not be rewritten into a conforming one."""
        authority = DagAuthority(
            _dag(edges=(_edge(source_block=10, target_entry_anchor=20),))
        )
        disagreeing = RedirectGoto(from_serial=10, old_target=2, new_target=99)
        before = (
            disagreeing.from_serial,
            disagreeing.old_target,
            disagreeing.new_target,
        )

        filter_dag_disagreements(
            [disagreeing],
            _view(authority),
            strategy_name="test",
            phase="unit",
        )

        after = (
            disagreeing.from_serial,
            disagreeing.old_target,
            disagreeing.new_target,
        )
        assert before == after, (
            "arbiter retargeted a planner mod instead of refusing it"
        )

    def test_absent_authority_keeps_every_proposal(self) -> None:
        """Fail-open is only safe because the arbiter is subtractive."""
        proposals = [RedirectGoto(from_serial=10, old_target=2, new_target=99)]
        kept, records = filter_dag_disagreements(
            list(proposals),
            _view(None),
            strategy_name="test",
            phase="unit",
        )
        assert [id(m) for m in kept] == [id(m) for m in proposals]
        assert records == ()


# --------------------------------------------------------------------------
# ALLOW must be earned from DAG state
# --------------------------------------------------------------------------


class TestNoIndependentGrant:
    """An authority over an empty DAG must not permit anything."""

    @pytest.mark.parametrize("label,make_mod", ALL_DISPATCHED_MODS)
    def test_empty_authority_refuses_every_mod_kind(self, label, make_mod) -> None:
        decision = _empty_authority().permits(make_mod())
        assert not decision.allowed, (
            f"{label}: DagAuthority granted ALLOW with no DAG evidence "
            f"(reason={decision.reason!r})"
        )

    def test_empty_authority_refuses_unknown_mod_kinds(self) -> None:
        decision = _empty_authority().permits(object())
        assert not decision.allowed
        assert decision.is_gap

    def test_allow_requires_a_matching_dag_edge(self) -> None:
        """ALLOW is granted only where the DAG committed the same target."""
        authority = DagAuthority(
            _dag(edges=(_edge(source_block=10, target_entry_anchor=20),))
        )
        assert authority.permits(
            RedirectGoto(from_serial=10, old_target=2, new_target=20)
        ).allowed
        assert not authority.permits(
            RedirectGoto(from_serial=10, old_target=2, new_target=21)
        ).allowed
        assert not authority.permits(
            RedirectGoto(from_serial=11, old_target=2, new_target=20)
        ).allowed

    def test_dag_internal_conflict_is_not_an_allow(self) -> None:
        """When the DAG contradicts itself the arbiter must not pick a winner."""
        authority = DagAuthority(
            _dag(
                edges=(
                    _edge(source_block=10, target_entry_anchor=20),
                    _edge(source_block=10, target_entry_anchor=21),
                )
            )
        )
        for target in (20, 21):
            decision = authority.permits(
                RedirectGoto(from_serial=10, old_target=2, new_target=target)
            )
            assert not decision.allowed
            assert decision.is_gap

    def test_refusal_requires_a_reason(self) -> None:
        with pytest.raises(ValueError):
            DagDecision.refuse("")


# --------------------------------------------------------------------------
# Per-latent-surface regressions (aa-v8et)
#
# The audit (section 3) found three ALLOW paths that read no DAG state. Each
# was unreachable from production for its *own* reason, and only one of the
# three was caught by the original strict-xfail:
#
#   permits_zero_state_write
#       Dispatched by ``permits()``. Unreachable because
#       ``redirect_source(ZeroStateWrite)`` is ``None``, so
#       ``filter_dag_disagreements`` keeps the mod at
#       ``fragment_arbitration.py:104-105`` before ``permits()`` is called.
#       This is the one the strict xfail detected.
#
#   permits_edge_redirect_via_pred_split
#       Also dispatched by ``permits()`` (``dag_authority.py:475-480``) — the
#       dispatch is NOT the missing link. Unreachable for the same reason as
#       ZSW: ``redirect_source(EdgeRedirectViaPredSplit)`` is ``None``, so the
#       production filter bypasses ``permits()``.
#
#   permits_dead_block_terminator_redirect
#       NOT protected by the ``redirect_source`` guard at all: its mod is a
#       ``RedirectGoto``, for which ``redirect_source`` *does* return a
#       source. It is unreachable only because ``permits()`` never dispatches
#       to it (keyword-only projected-graph arguments) and it has no
#       production caller.
#
# One regression per path, named for the path.
# --------------------------------------------------------------------------


class TestLatentGrantSurfaces:
    """Each of the three audited ALLOW paths must now require DAG evidence."""

    def test_permits_zero_state_write_is_a_gap_not_a_grant(self) -> None:
        """ZSW legality is a single-emitter invariant, not a DAG fact.

        ``zero_state_write_emission.collect_zero_state_writes`` enforces one
        author per ``(block_serial, insn_ea)``. That is a real invariant but it
        belongs to a different module; ``DagAuthority`` cannot check it and
        must not vouch for it.
        """
        decision = _empty_authority().permits_zero_state_write(
            ZeroStateWrite(block_serial=10, insn_ea=0x1000)
        )
        assert not decision.allowed
        assert decision.is_gap
        assert decision.reason == "DAG_GAP:zero_state_write_not_dag_derivable"
        assert decision.target_entry_anchor is None
        assert decision.proof_edge_key is None

    def test_zero_state_write_gap_holds_for_a_populated_dag(self) -> None:
        """Not even a DAG that knows the block turns ZSW into a grant."""
        authority = DagAuthority(
            _dag(edges=(_edge(source_block=10, target_entry_anchor=20),))
        )
        decision = authority.permits(ZeroStateWrite(block_serial=10, insn_ea=0x1000))
        assert decision.is_gap

    def test_permits_edge_redirect_via_pred_split_requires_dag_evidence(
        self,
    ) -> None:
        """The corridor splice must be backed by a DAG edge, not a literal.

        The old ALLOW matched a ``CorridorSpliceData`` seeded at construction
        from a hardcoded per-function registry in the planner
        (``shared_block=45, clone_source=122, clone_target=180`` for
        ``sub_7FFD3338C040`` only). Its ``proof_edge_key`` was
        ``("corridor_splice", 45, 122, 180)`` — it named no DAG edge, so the
        authority was vouching for a constant a human typed.

        Note this path *is* dispatched by ``permits()``; the dispatch was never
        the missing link. It is unreachable in production only because
        ``redirect_source(EdgeRedirectViaPredSplit)`` is ``None``, so the
        production filter keeps the mod before ``permits()`` is called.
        """
        mod = EdgeRedirectViaPredSplit(
            src_block=122,
            old_target=45,
            new_target=180,
            via_pred=37,
            clone_until=45,
        )

        # No DAG edge for the corridor source -> gap, never a grant.
        silent = _empty_authority()
        decision = silent.permits_edge_redirect_via_pred_split(mod)
        assert not decision.allowed
        assert decision.is_gap
        assert (
            decision.reason
            == "DAG_GAP:edge_redirect_via_pred_split_no_dag_evidence"
        )
        assert decision.proof_edge_key is None

        # A DAG edge committing the corridor source to the proposed target is
        # the only thing that earns an ALLOW, and the proof names that edge.
        backed = DagAuthority(
            _dag(edges=(_edge(source_block=122, target_entry_anchor=180),))
        )
        allowed = backed.permits_edge_redirect_via_pred_split(mod)
        assert allowed.allowed
        assert allowed.target_entry_anchor == 180
        assert allowed.proof_edge_key == (122, None, 180, "EdgeRedirectViaPredSplit")

        # A DAG that commits the source somewhere else is a disagreement.
        contrary = DagAuthority(
            _dag(edges=(_edge(source_block=122, target_entry_anchor=999),))
        )
        refused = contrary.permits_edge_redirect_via_pred_split(mod)
        assert not refused.allowed
        assert refused.is_disagreement
        assert "dag=999" in refused.reason

    def test_no_seeded_corridor_channel_survives(self) -> None:
        """The non-DAG seeding channel itself is gone, not just its match arm.

        Leaving ``corridor_data=`` reachable with no producer would re-open the
        exact door the audit closed: any caller could inject a literal and get
        an ALLOW back.
        """
        import d810.passes.planner as planner_module
        import d810.transforms.dag_authority as dag_authority_module

        assert not hasattr(planner_module, "_corridor_seed_data_for_snapshot")
        assert not hasattr(dag_authority_module, "CorridorSpliceData")
        assert not hasattr(DagAuthority, "canonical_corridor_splice_for")
        with pytest.raises(TypeError):
            DagAuthority(_dag(), corridor_data=())  # type: ignore[call-arg]

    def test_permits_dead_block_terminator_redirect_is_a_gap_not_a_grant(
        self,
    ) -> None:
        """A caller-supplied projected CFG is not DAG evidence.

        Every input to the old ALLOW (``projected_flow_graph``,
        ``dispatcher_serial``, ``original_stop_serial``) came from the caller,
        and the method's own docstring conceded the projected post-mod CFG is
        "a graph the DAG doesn't model". The arbiter would have been vouching
        for the consumer's own belief.

        Note this path was never protected by the ``redirect_source`` guard
        that makes the other two unreachable: its mod is a ``RedirectGoto``,
        for which ``redirect_source`` returns a source. It is unreachable only
        because ``permits()`` never dispatches to it and it has no production
        caller.
        """
        authority = _empty_authority()
        graph = _ProjectedFlowGraph({42: _ProjectedBlock(preds=(), succs=(2,))})
        decision = authority.permits_dead_block_terminator_redirect(
            RedirectGoto(from_serial=42, old_target=2, new_target=99),
            projected_flow_graph=graph,
            dispatcher_serial=2,
            original_stop_serial=99,
        )
        assert not decision.allowed
        assert decision.is_gap
        assert decision.reason == "DAG_GAP:dead_block_terminator_caller_derived"
        assert decision.target_entry_anchor is None
        assert decision.proof_edge_key is None

    def test_dead_block_terminator_keeps_every_refusal_branch(self) -> None:
        """Downgrading the ALLOW must not soften any existing rejection.

        Each malformed shape stays a ``DAG_DISAGREEMENT`` (a hard drop at the
        consumer), not a gap; only the previously-conforming shape moves from
        ALLOW to gap.
        """
        authority = _empty_authority()
        mod = RedirectGoto(from_serial=42, old_target=2, new_target=99)
        cases = {
            "block_not_in_projected_graph": _ProjectedFlowGraph({}),
            "block_has_preds": _ProjectedFlowGraph(
                {42: _ProjectedBlock(preds=(10,), succs=(2,))}
            ),
            "succ_not_dispatcher": _ProjectedFlowGraph(
                {42: _ProjectedBlock(preds=(), succs=(50,))}
            ),
        }
        for expected_reason, graph in cases.items():
            decision = authority.permits_dead_block_terminator_redirect(
                mod,
                projected_flow_graph=graph,
                dispatcher_serial=2,
                original_stop_serial=99,
            )
            assert decision.is_disagreement, expected_reason
            assert expected_reason in decision.reason

        target_mismatch = authority.permits_dead_block_terminator_redirect(
            RedirectGoto(from_serial=42, old_target=2, new_target=88),
            projected_flow_graph=_ProjectedFlowGraph(
                {42: _ProjectedBlock(preds=(), succs=(2,))}
            ),
            dispatcher_serial=2,
            original_stop_serial=99,
        )
        assert target_mismatch.is_disagreement
        assert "expected_stop=99" in target_mismatch.reason

        missing_inputs = authority.permits_dead_block_terminator_redirect(mod)
        assert missing_inputs.is_gap
        assert (
            missing_inputs.reason
            == "DAG_GAP:dead_block_terminator_no_projected_graph"
        )


# --------------------------------------------------------------------------
# No grant-shaped API surface
# --------------------------------------------------------------------------

#: Verbs and nouns that mark an API as carrying out, committing, or blessing a
#: mutation rather than answering a question about one.
_GRANT_SHAPED_NAME_FRAGMENTS = (
    "apply",
    "authorize",
    "certif",
    "commit",
    "emit",
    "grant",
    "mutate",
    "receipt",
    "rewrite",
    "semantic_loss",
    "transaction",
)

#: ``permits_*`` and ``permit`` are the arbiter's own restrict-shaped vocabulary
#: and are explicitly not grants.
_ALLOWED_PUBLIC_PREFIXES = ("permits",)


def _public_api(obj: type) -> tuple[str, ...]:
    return tuple(
        name
        for name in dir(obj)
        if not name.startswith("_")
        and not any(name.startswith(p) for p in _ALLOWED_PUBLIC_PREFIXES)
    )


class TestNoGrantShapedApiSurface:
    """Structural guard: the arbiter must stay a query interface."""

    @pytest.mark.parametrize("cls", [DagAuthority, DagDecision])
    def test_no_grant_shaped_public_names(self, cls) -> None:
        offenders = [
            name
            for name in _public_api(cls)
            for fragment in _GRANT_SHAPED_NAME_FRAGMENTS
            if fragment in name.lower()
        ]
        assert not offenders, (
            f"{cls.__name__} exposes grant-shaped API: {sorted(set(offenders))}. "
            "DagAuthority may restrict which proposals are emitted; it must "
            "never independently grant final mutation or semantic-loss "
            "permission."
        )

    def test_every_permits_method_returns_a_dag_decision(self) -> None:
        """A verdict is the only thing an arbiter may hand back."""
        for name, member in inspect.getmembers(DagAuthority, inspect.isfunction):
            if not name.startswith("permits"):
                continue
            annotation = inspect.signature(member).return_annotation
            assert annotation in (DagDecision, "DagDecision"), (
                f"DagAuthority.{name} returns {annotation!r}, not a DagDecision"
            )

    def test_dag_decision_carries_no_mutation_handle(self) -> None:
        """A verdict describes a decision; it must not carry a way to act."""
        decision = DagDecision.allow(target_entry_anchor=20)
        for value in (
            decision.allowed,
            decision.reason,
            decision.target_entry_anchor,
            decision.proof_edge_key,
        ):
            assert value is None or isinstance(value, (bool, str, int, tuple)), (
                f"DagDecision field holds a live object: {value!r}"
            )

    def test_authority_does_not_expose_a_mutable_dag(self) -> None:
        """The arbiter never amends the DAG it arbitrates over."""
        authority = _empty_authority()
        with pytest.raises((AttributeError, TypeError)):
            authority.dag = _dag()  # type: ignore[misc]



# --------------------------------------------------------------------------
# ALLOW has exactly one construction site, and it takes the edge as proof
# --------------------------------------------------------------------------

#: The sole helper permitted to build an ``ALLOW`` verdict. It takes the
#: authorising :class:`StateDagEdge` as its first parameter, so an ALLOW cannot
#: be constructed without one in hand.
ALLOW_HELPER_NAME = "_allow_from_dag_edge"


def _dag_authority_source() -> str:
    path = inspect.getsourcefile(DagAuthority)
    assert path is not None
    return pathlib.Path(path).read_text()


def _allow_call_site_functions(source: str) -> tuple[str, ...]:
    """Names of the functions containing every ``DagDecision.allow(...)`` call."""
    sites: list[str] = []
    stack: list[str] = []

    class _Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "allow"
                and isinstance(func.value, ast.Name)
                and func.value.id == "DagDecision"
            ):
                sites.append(stack[-1] if stack else "<module>")
            self.generic_visit(node)

    _Visitor().visit(ast.parse(source))
    return tuple(sites)


class TestAllowHasOneDagBackedConstructionSite:
    """``DagDecision.allow`` is reachable only through the edge-proof helper.

    Without this, the restrict-never-grant invariant is unpinned: the ast-grep
    rule exempts the entire ``permits_`` vocabulary, so a new
    ``permits_whatever()`` returning ``DagDecision.allow(...)`` passed every
    guard. Funnelling ALLOW through one helper that *takes the edge* makes the
    evidence a parameter rather than a convention.
    """

    def test_only_the_helper_constructs_an_allow(self) -> None:
        sites = _allow_call_site_functions(_dag_authority_source())
        assert set(sites) == {ALLOW_HELPER_NAME}, (
            f"DagDecision.allow is constructed in {sorted(set(sites))}; the "
            f"only permitted construction site is {ALLOW_HELPER_NAME}"
        )
        assert len(sites) == 1, (
            f"expected exactly one DagDecision.allow call site, found {len(sites)}"
        )

    def test_the_helper_takes_a_dag_edge_as_its_proof(self) -> None:
        helper = getattr(DagAuthority, ALLOW_HELPER_NAME)
        params = list(inspect.signature(helper).parameters.values())
        positional = [
            p
            for p in params
            if p.kind
            in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
            and p.name != "self"
        ]
        assert positional, f"{ALLOW_HELPER_NAME} takes no positional proof"
        assert positional[0].annotation in (StateDagEdge, "StateDagEdge"), (
            f"{ALLOW_HELPER_NAME}'s proof parameter is "
            f"{positional[0].annotation!r}, not a StateDagEdge"
        )

    def test_no_permits_method_constructs_an_allow_directly(self) -> None:
        for name in _discovered_permits_methods():
            method = getattr(DagAuthority, name)
            sites = _allow_call_site_functions(
                textwrap.dedent(inspect.getsource(method))
            )
            assert not sites, (
                f"DagAuthority.{name} constructs an ALLOW itself instead of "
                f"routing through {ALLOW_HELPER_NAME}"
            )


class TestEveryPermitsMethodIsEnrolled:
    """Discovered by reflection, so a new arbiter method cannot slip through."""

    def test_coverage_matrix_matches_the_discovered_methods(self) -> None:
        discovered = set(_discovered_permits_methods())
        enrolled = set(PERMITS_COVERAGE)
        assert discovered == enrolled, (
            "PERMITS_COVERAGE is out of sync with DagAuthority. "
            f"unenrolled={sorted(discovered - enrolled)} "
            f"stale={sorted(enrolled - discovered)}. Every arbiter verdict "
            "method must declare what DAG evidence, if any, can earn it an "
            "ALLOW."
        )

    @pytest.mark.parametrize("name", _discovered_permits_methods())
    def test_no_permits_method_grants_without_dag_evidence(self, name) -> None:
        case = PERMITS_COVERAGE[name]
        decision = getattr(_empty_authority(), name)(case.make_mod(), **case.kwargs)
        assert not decision.allowed, (
            f"DagAuthority.{name} granted ALLOW over an empty DAG "
            f"(reason={decision.reason!r})"
        )

    @pytest.mark.parametrize("name", _discovered_permits_methods())
    def test_every_permits_method_either_gaps_denies_or_routes_through_the_helper(
        self, name
    ) -> None:
        """The whole invariant in one assertion, per discovered method."""
        case = PERMITS_COVERAGE[name]
        authority = _authority_for(case)
        decision = getattr(authority, name)(case.make_mod(), **case.kwargs)
        if not decision.allowed:
            assert decision.reason, "a refusal must carry a reason"
            return
        assert case.can_allow, (
            f"DagAuthority.{name} is enrolled as never-granting but returned "
            f"ALLOW ({decision!r})"
        )
        _assert_allow_is_edge_backed(authority, decision)

    @pytest.mark.parametrize(
        "name",
        [n for n, c in PERMITS_COVERAGE.items() if not c.can_allow],
    )
    def test_never_granting_methods_stay_gaps_even_with_a_populated_dag(
        self, name
    ) -> None:
        case = PERMITS_COVERAGE[name]
        decision = getattr(_authority_for(case), name)(
            case.make_mod(), **case.kwargs
        )
        assert not decision.allowed
        assert decision.is_gap
        assert decision.target_entry_anchor is None
        assert decision.proof_edge_key is None


# --------------------------------------------------------------------------
# A GAP confers nothing, at every consumer
# --------------------------------------------------------------------------


class TestGapCarriesNoGrantPayload:
    """Structural fail-closed core: a gap verdict has no authorisation fields."""

    @pytest.mark.parametrize("name", _discovered_permits_methods())
    def test_gap_verdicts_carry_no_target_and_no_proof(self, name) -> None:
        case = PERMITS_COVERAGE[name]
        decision = getattr(_empty_authority(), name)(case.make_mod(), **case.kwargs)
        if not decision.is_gap:
            pytest.skip(f"{name} did not gap for this input")
        assert decision.target_entry_anchor is None
        assert decision.proof_edge_key is None
        assert decision.reason.startswith("DAG_GAP:")


class TestGapIsFailClosedAtEveryConsumer:
    """One test per consumer of a ``DagDecision`` (audit section 2.1).

    Consumers, re-verified by ``rg '\\.permits\\(|filter_dag_disagreements' src/``:

      1. ``fragment_arbitration.filter_dag_disagreements``       (:107)
      2. ``fragment_arbitration.apply_dag_conformance_gate``     (:169)
      3. ``reconstruction_fragment_builder.finalize_reconstruction_fragment``
         (:186)

    "Fail-closed" here means a GAP confers *nothing*: it never authorises a
    modification, never synthesises one, never rewrites one, never records a
    proof, and never shields a modification from the restriction filters that
    own it. A gap-region mod that survives a consumer survives on the
    planner's authority and the legacy filter's sufferance, never on the
    arbiter's -- which is what keeps the arbiter subtractive.
    """

    @staticmethod
    def _gap_authority() -> DagAuthority:
        """Knows one edge, so every *other* source is a genuine gap region."""
        return DagAuthority(
            _dag(edges=(_edge(source_block=10, target_entry_anchor=20),))
        )

    # -- consumer 1: filter_dag_disagreements ------------------------------

    def test_consumer_1_filter_dag_disagreements_grants_nothing_on_gap(
        self,
    ) -> None:
        authority = self._gap_authority()
        gap_mod = RedirectGoto(from_serial=77, old_target=2, new_target=88)
        assert authority.permits(gap_mod).is_gap

        kept, records = filter_dag_disagreements(
            [gap_mod],
            _view(authority),
            strategy_name="test",
            phase="unit",
        )

        # Nothing synthesised, nothing rewritten, no proof recorded.
        assert all(k is gap_mod for k in kept)
        assert len(kept) <= 1
        assert records == ()
        assert (gap_mod.from_serial, gap_mod.new_target) == (77, 88)

    def test_consumer_1_gap_never_turns_a_refusal_into_a_pass(self) -> None:
        """A gap for one mod must not rescue a disagreeing sibling."""
        authority = self._gap_authority()
        gap_mod = RedirectGoto(from_serial=77, old_target=2, new_target=88)
        refused = RedirectGoto(from_serial=10, old_target=2, new_target=99)

        kept, records = filter_dag_disagreements(
            [gap_mod, refused],
            _view(authority),
            strategy_name="test",
            phase="unit",
        )
        assert [id(m) for m in kept] == [id(gap_mod)]
        assert len(records) == 1
        assert records[0].source_block == 10

    # -- one test per retired grant path (aa-v8et; review round 2, R4) -----
    #
    # The three latent grants are unreachable from production for *different*
    # reasons, and a single shared test could not say which reason applied to
    # which path -- the first version of this file asserted a reachability
    # statement that was wrong for two of the three. Each path now gets its own
    # test that exercises only that path and names its own mechanism.

    def test_consumer_1_zero_state_write_is_dispatched_then_bypassed(
        self,
    ) -> None:
        """ZeroStateWrite: ``permits()`` dispatches it; the filter never asks.

        ``redirect_source`` returns ``None`` for a ZSW, so
        ``filter_dag_disagreements`` keeps it at
        ``fragment_arbitration.py:103-105`` before any verdict is requested.
        It therefore survives on the planner's authority, never the DAG's --
        and the verdict it would have received is a named gap, not an ALLOW.
        """
        authority = self._gap_authority()
        zsw = ZeroStateWrite(block_serial=77, insn_ea=0x1000)

        assert redirect_source(zsw) is None

        kept, records = filter_dag_disagreements(
            [zsw],
            _view(authority),
            strategy_name="test",
            phase="unit",
        )
        assert [id(m) for m in kept] == [id(zsw)]
        assert records == ()

        decision = authority.permits(zsw)
        assert decision.reason == "DAG_GAP:zero_state_write_not_dag_derivable"
        assert not decision.allowed

    def test_consumer_1_pred_split_is_dispatched_then_bypassed(self) -> None:
        """EdgeRedirectViaPredSplit: dispatched by ``permits()``, bypassed too.

        Same mechanism as the ZSW above and a different verdict: the corridor
        splice reaches the DAG-evidence validator, which has no in-scope edge
        for the corridor source and names that gap explicitly.
        """
        authority = self._gap_authority()
        splice = EdgeRedirectViaPredSplit(
            src_block=122, old_target=45, new_target=180, via_pred=37
        )

        assert redirect_source(splice) is None

        kept, records = filter_dag_disagreements(
            [splice],
            _view(authority),
            strategy_name="test",
            phase="unit",
        )
        assert [id(m) for m in kept] == [id(splice)]
        assert records == ()

        decision = authority.permits(splice)
        assert decision.reason == (
            "DAG_GAP:edge_redirect_via_pred_split_no_dag_evidence"
        )
        assert not decision.allowed

    def test_consumer_1_dead_block_terminator_is_never_dispatched(self) -> None:
        """Dead-terminator: a different mechanism -- ``permits()`` never routes.

        Its argument is a ``RedirectGoto``, for which ``redirect_source`` *does*
        return a source, so the filter asks for a verdict; but ``permits()``
        dispatches a RedirectGoto to ``permits_redirect_goto``. Nothing in the
        dispatch table can reach ``permits_dead_block_terminator_redirect``, so
        the extra caller-supplied inputs it needs (projected graph, dispatcher
        and stop serials) can never be supplied by this consumer.

        Asserted by reflection over the dispatch table rather than by calling
        it, so adding a route to the method fails this test.
        """
        dispatched = _permits_methods_dispatched_by_permits()
        assert "permits_dead_block_terminator_redirect" not in dispatched
        assert "permits_redirect_goto" in dispatched

        authority = self._gap_authority()
        mod = RedirectGoto(from_serial=42, old_target=2, new_target=99)
        assert redirect_source(mod) == 42

        decision = authority.permits(mod)
        assert "dead_block_terminator" not in decision.reason
        assert decision.reason == "DAG_GAP:unknown_source"

    # -- consumer 2: apply_dag_conformance_gate ----------------------------

    @staticmethod
    def _fragment(modifications: list) -> PlanFragment:
        return PlanFragment(
            strategy_name="test",
            family="direct",
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
            metadata={},
            modifications=modifications,
        )

    def test_consumer_2_conformance_gate_records_no_audit_row_for_a_gap(
        self,
    ) -> None:
        authority = self._gap_authority()
        gap_mod = RedirectGoto(from_serial=77, old_target=2, new_target=88)
        fragment = self._fragment([gap_mod])

        gated = apply_dag_conformance_gate(fragment, _view(authority))

        # No records => the fragment is returned untouched; crucially the gap
        # produced no DAG_AUDIT row that a downstream reader could mistake for
        # an authorisation.
        assert gated is fragment
        assert gated.metadata.get(DAG_AUDIT_METADATA_KEY) is None
        assert [id(m) for m in gated.modifications] == [id(gap_mod)]

    def test_consumer_2_conformance_gate_still_drops_a_disagreement(self) -> None:
        """The gate is not softened: a real disagreement is still removed."""
        authority = self._gap_authority()
        gap_mod = RedirectGoto(from_serial=77, old_target=2, new_target=88)
        refused = RedirectGoto(from_serial=10, old_target=2, new_target=99)
        fragment = self._fragment([gap_mod, refused])

        gated = apply_dag_conformance_gate(fragment, _view(authority))

        assert [id(m) for m in gated.modifications] == [id(gap_mod)]
        records = gated.metadata[DAG_AUDIT_METADATA_KEY]
        assert len(records) == 1

    # -- consumer 3: finalize_reconstruction_fragment ----------------------

    @staticmethod
    def _finalize(modifications: list, view: CumulativePlannerView) -> PlanFragment:
        return finalize_reconstruction_fragment(
            strategy_name="test",
            modifications=modifications,
            owned_blocks=set(),
            owned_edges=set(),
            accepted_metadata=[],
            rejected_metadata=[],
            allow_post_apply_condition_chain_cleanup=False,
            post_apply_condition_chain_cleanup_reason=None,
            residual_dispatcher_preds=(),
            cumulative_planner_view=view,
        )

    def test_consumer_3_gap_does_not_shield_a_mod_from_the_legacy_filter(
        self,
    ) -> None:
        """The decisive fail-closed property for the terminal finaliser.

        Block 77 is a DAG gap region, so the arbiter has no opinion. The gap
        must NOT act as a pass: the legacy first-fragment-wins filter still
        owns the mod and still drops it for contradicting a prior
        linearization.
        """
        authority = self._gap_authority()
        gap_mod = RedirectGoto(from_serial=77, old_target=2, new_target=88)
        assert authority.permits(gap_mod).is_gap

        view = dataclasses.replace(
            CumulativePlannerView.empty(dag_authority=authority),
            linearization_decisions=frozenset(
                {
                    LinearizationDecision(
                        src=77,
                        tgt=1234,
                        reason="prior",
                        strategy="other",
                        round_index=0,
                    )
                }
            ),
        )

        fragment = self._finalize([gap_mod], view)

        assert fragment.modifications == [], (
            "a DAG_GAP verdict let a mod past the legacy filter that owns it"
        )
        assert fragment.metadata[DAG_AUDIT_METADATA_KEY] == ()

    def test_consumer_3_gap_synthesises_nothing(self) -> None:
        authority = self._gap_authority()
        gap_mod = RedirectGoto(from_serial=77, old_target=2, new_target=88)
        view = CumulativePlannerView.empty(dag_authority=authority)

        fragment = self._finalize([gap_mod], view)

        assert all(any(m is p for p in [gap_mod]) for m in fragment.modifications)
        assert len(fragment.modifications) <= 1
        assert fragment.metadata[DAG_AUDIT_METADATA_KEY] == ()

    def test_consumer_3_still_drops_a_dag_disagreement(self) -> None:
        authority = self._gap_authority()
        refused = RedirectGoto(from_serial=10, old_target=2, new_target=99)
        view = CumulativePlannerView.empty(dag_authority=authority)

        fragment = self._finalize([refused], view)

        assert fragment.modifications == []
        assert len(fragment.metadata[DAG_AUDIT_METADATA_KEY]) == 1


# --------------------------------------------------------------------------
# The ALLOW ban must survive aliasing (review round 2, R3)
# --------------------------------------------------------------------------


def _allow_reference_sites(source: str) -> tuple[tuple[str, str], ...]:
    """Every reference to ``DagDecision.allow``, however it is spelled.

    ``_allow_call_site_functions`` only recognised a literal
    ``DagDecision.allow(...)`` call with ``DagDecision`` as a bare ``ast.Name``.
    Three shapes evaded it (and the ast-grep rule, which matched the same
    attribute text):

    * ``A = DagDecision.allow`` followed by ``A(...)``;
    * ``from ... import DagDecision as D`` followed by ``D.allow(...)``;
    * ``getattr(DagDecision, "allow")(...)``.

    Names are resolved through module-level (and local) assignments and import
    aliases to a fixpoint, so the returned sites name the enclosing function of
    every reference regardless of spelling.  Returns ``(function, shape)``
    pairs.
    """
    tree = ast.parse(source)

    class_aliases = {"DagDecision"}
    module_aliases: set[str] = set()
    allow_aliases: set[str] = set()

    def _is_class_ref(node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in class_aliases
        if isinstance(node, ast.Attribute):
            return node.attr == "DagDecision" and (
                isinstance(node.value, ast.Name) and node.value.id in module_aliases
            )
        return False

    def _is_allow_ref(node: ast.expr) -> bool:
        if isinstance(node, ast.Attribute):
            return node.attr == "allow" and _is_class_ref(node.value)
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "getattr":
                return (
                    len(node.args) >= 2
                    and _is_class_ref(node.args[0])
                    and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value == "allow"
                )
        return False

    # Resolve aliases to a fixpoint: an alias may be defined after its use, or
    # chained through another alias.
    for _ in range(8):
        before = (len(class_aliases), len(module_aliases), len(allow_aliases))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "DagDecision" and alias.asname:
                        class_aliases.add(alias.asname)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        module_aliases.add(alias.asname)
                    else:
                        module_aliases.add(alias.name.split(".")[0])
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if _is_class_ref(node.value):
                        class_aliases.add(target.id)
                    elif _is_allow_ref(node.value):
                        allow_aliases.add(target.id)
        if (len(class_aliases), len(module_aliases), len(allow_aliases)) == before:
            break

    sites: list[tuple[str, str]] = []
    stack: list[str] = []

    class _Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

        def _record(self, shape: str) -> None:
            sites.append((stack[-1] if stack else "<module>", shape))

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if _is_allow_ref(node):
                self._record("attribute")
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if _is_allow_ref(node):
                self._record("getattr")
            self.generic_visit(node)

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Load) and node.id in allow_aliases:
                self._record("alias")
            self.generic_visit(node)

    _Visitor().visit(tree)
    return tuple(sites)


class TestAllowBanSurvivesAliasing:
    """The one-construction-site invariant must not be spelling-deep.

    Round-2 review: the guard matched the literal text ``DagDecision.allow``
    with ``DagDecision`` as a bare name, so three trivial rewrites walked past
    both the ast-grep rule and the AST test.
    """

    ALIAS_EVASIONS = {
        "bound method alias": """
            def sneaky(self, edge):
                _A = DagDecision.allow
                return _A(target_entry_anchor=1)
        """,
        "class alias": """
            def sneaky(self, edge):
                D = DagDecision
                return D.allow(target_entry_anchor=1)
        """,
        "aliased import": """
            from d810.transforms.dag_authority import DagDecision as D

            def sneaky(self, edge):
                return D.allow(target_entry_anchor=1)
        """,
        "module-qualified": """
            import d810.transforms.dag_authority as da

            def sneaky(self, edge):
                return da.DagDecision.allow(target_entry_anchor=1)
        """,
        "getattr literal": """
            def sneaky(self, edge):
                return getattr(DagDecision, "allow")(target_entry_anchor=1)
        """,
        "attribute without call": """
            def sneaky(self, edge):
                return DagDecision.allow
        """,
    }

    @pytest.mark.parametrize("label", sorted(ALIAS_EVASIONS))
    def test_every_alias_shape_is_detected(self, label: str) -> None:
        source = textwrap.dedent(self.ALIAS_EVASIONS[label]).strip()
        sites = _allow_reference_sites(source)
        assert sites, f"{label} evaded the ALLOW-reference detector"
        assert {name for name, _ in sites} == {"sneaky"}

    def test_the_helper_itself_is_still_the_only_real_site(self) -> None:
        sites = _allow_reference_sites(_dag_authority_source())
        assert {name for name, _ in sites} == {ALLOW_HELPER_NAME}

    def test_no_other_module_references_allow(self) -> None:
        """The ban is repo-wide, not scoped to two files."""
        root = pathlib.Path(inspect.getsourcefile(DagAuthority)).resolve()
        src_root = root.parents[1]
        assert src_root.name == "d810", src_root
        offenders: list[str] = []
        for path in sorted(src_root.rglob("*.py")):
            if "_vendor" in path.parts:
                continue
            for name, shape in _allow_reference_sites(path.read_text()):
                if path == root and name == ALLOW_HELPER_NAME:
                    continue
                offenders.append(f"{path}:{name}:{shape}")
        assert offenders == [], (
            f"DagDecision.allow is referenced outside {ALLOW_HELPER_NAME}: "
            f"{offenders}"
        )


class TestAllowRequiresAnEdgeTheDagOwns:
    """Holding *an* edge is not evidence; holding *this DAG's* edge is.

    ``_allow_from_dag_edge`` was a ``staticmethod``: it accepted any
    ``StateDagEdge``-shaped object and derived a ``proof_edge_key`` from it,
    so a fabricated edge produced an ALLOW naming an edge that exists in no
    DAG at all -- exactly the "proposal is its own proof" shape the three
    retired grants had.
    """

    @staticmethod
    def _fabricated_edge() -> StateDagEdge:
        return _edge(source_block=999, target_entry_anchor=1234)

    def test_the_helper_is_bound_to_the_authority(self) -> None:
        raw = inspect.getattr_static(DagAuthority, ALLOW_HELPER_NAME)
        assert not isinstance(raw, staticmethod), (
            f"{ALLOW_HELPER_NAME} is a staticmethod, so it cannot check that "
            "the edge belongs to this authority's DAG"
        )

    def test_a_fabricated_edge_is_refused(self) -> None:
        authority = _empty_authority()
        decision = getattr(authority, ALLOW_HELPER_NAME)(
            self._fabricated_edge(), mod_kind="RedirectGoto"
        )
        assert not decision.allowed
        assert decision.target_entry_anchor is None
        assert decision.proof_edge_key is None
        assert "edge_not_in_dag" in decision.reason

    def test_an_edge_from_another_dag_is_refused(self) -> None:
        foreign_edge = _edge(source_block=10, target_entry_anchor=20)
        DagAuthority(_dag(edges=(foreign_edge,)))
        authority = DagAuthority(
            _dag(edges=(_edge(source_block=10, target_entry_anchor=20),))
        )
        decision = getattr(authority, ALLOW_HELPER_NAME)(
            foreign_edge, mod_kind="RedirectGoto"
        )
        assert not decision.allowed, (
            "an equal-valued edge from a different DAG is not this DAG's "
            "evidence"
        )

    def test_an_edge_the_dag_owns_still_allows(self) -> None:
        edge = _edge(source_block=10, target_entry_anchor=20)
        authority = DagAuthority(_dag(edges=(edge,)))
        decision = getattr(authority, ALLOW_HELPER_NAME)(
            edge, mod_kind="RedirectGoto"
        )
        assert decision.allowed
        _assert_allow_is_edge_backed(authority, decision)

    def test_the_production_path_still_allows(self) -> None:
        authority = DagAuthority(
            _dag(edges=(_edge(source_block=10, target_entry_anchor=20),))
        )
        decision = authority.permits(
            RedirectGoto(from_serial=10, old_target=2, new_target=20)
        )
        assert decision.allowed
        _assert_allow_is_edge_backed(authority, decision)
