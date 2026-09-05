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

import inspect

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
from d810.transforms.fragment_arbitration import filter_dag_disagreements
from d810.transforms.graph_modification import (
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.transforms.planner_context import CumulativePlannerView

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


#: Every modification kind ``DagAuthority.permits`` dispatches on, plus one
#: unregistered kind. Each entry is (label, factory).
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
