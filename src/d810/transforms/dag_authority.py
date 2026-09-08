'DagAuthority \u2014 preanalysis DAG arbiter for emitted graph modifications.\n\nPhase 1 of the DAG-as-arbiter epic (uee-jrgq).\n\nCurrently every Hodur planner re-derives "what should block X do?" from the\nCFG and emits a graph modification independently. The downstream conflict\nfilter ("first-fragment-wins" in :func:`_drop_conflicting_redirects`) tries\nto reconcile disagreement after the fact. That\'s an architectural inversion:\nthe preanalysis-built :class:`LinearizedStateDag` already encodes the canonical\nanswer, but no consumer queries it as a single source of truth.\n\n:class:`DagAuthority` flips the relationship. It wraps a finalized\n``LinearizedStateDag`` and exposes a queryable interface every planner\nconsults *before* emitting a mod. When the DAG has an answer that disagrees\nwith the planner\'s intent, the mod is *refused*; when the DAG has no answer\n(``DAG_GAP``), the mod is *strictly refused* and a follow-up ticket has to\nclose the gap before the planner can emit there. This is the single conflict\nresolution rule that supersedes Mode 1 / Mode 2 / Mode 3 / Mode 4 per the\nsynthesis at ``.claude/notes/investigations/2026-04-25-uee-dag-phase0-synthesis.md``.\n\nPhase 1 (this module) ships:\n\n* :func:`DagAuthority.canonical_target_for` \u2014 the centralised "what\n  entry-anchor does the DAG commit src/arm to?" lookup. Replaces every\n  ad-hoc scan of ``dag.edges``.\n* :func:`DagAuthority.conflicts_for_source` \u2014 DAG-internal conflict\n  detection (when two DAG edges target different anchors for the same\n  source/arm).\n* :func:`DagAuthority.permits_redirect_goto` and\n  :func:`DagAuthority.permits_convert_to_goto` \u2014 the two arbiter methods\n  whose underlying queries are fully covered by the existing DAG.\n* :func:`DagAuthority.permits_zero_state_write` \u2014 returns a named\n  ``DAG_GAP``: ZSW legality depends on a state-write def-site index\n  the DAG does not carry (aa-v8et).\n\nPer the deferral decision recorded in semantic memory (mem_52073043),\nthe authority is built **once per pipeline run**. Per-round rederivation\nis more accurate but slower; the build-once choice is deliberate and\nrevisitable when measured drift on real corpus matters. Construction\ncaches all derived indexes so query methods are O(1) lookups.\n\nStrict ``DAG_GAP`` policy: when the DAG cannot answer a question\nauthoritatively, the mod is refused. Callers must NOT permit the mod\nwith a warning \u2014 that would defer the architectural fix and let\nsilent emission errors accumulate. Closing each ``DAG_GAP:<name>``\nrequires the corresponding extension ticket.\n'

from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.graph_modification import (
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.ir.state_dag_key import StateDagNodeKey
from d810.analyses.control_flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
)


__all__ = (
    "AnchorKey",
    "DagAuthority",
    "DagDecision",
)


# Composite key for a redirect anchor: (block_serial, branch_arm).
# branch_arm is ``None`` for unconditional gotos; ``0`` or ``1`` for
# conditional-branch arm-specific anchors.  Two distinct edges with the
# same block_serial but different branch_arm values are NOT a conflict
# (they're independent decisions about different arms).
AnchorKey = tuple[int, int | None]


@dataclass(frozen=True, slots=True)
class DagDecision:
    """Result of asking the DAG whether a graph modification is allowed.

    The decision is one of:

    * ``allow`` — the mod conforms to the DAG; the planner may emit it.
      ``target_entry_anchor`` is the DAG-canonical target (mods that
      disagree with this will be refused). ``proof_edge_key`` identifies
      the DAG edge that authorised the decision (for diagnostics).

    * ``refuse(reason)`` — the mod is rejected. ``reason`` follows one of
      these conventions:

      - ``"DAG_DISAGREEMENT:<src>->{planner=<T1>,dag=<T2>}"`` —
        the DAG has a canonical decision and the mod proposes a different
        target. Logged as DAG_DISAGREEMENT diagnostic by Phase 5.
      - ``"DAG_GAP:<gap_name>"`` — the DAG can't answer (no edge for
        this source/arm). The named gap must be closed by an extension
        ticket before the planner can emit here.
      - ``"REFUSE:<other_reason>"`` — escape hatch for shape-specific
        rejections (e.g. malformed mod, unknown source block).

    Diagnostic helpers (Phase 5) read ``reason`` to surface
    actionable per-planner statistics.
    """

    allowed: bool
    reason: str
    target_entry_anchor: int | None = None
    proof_edge_key: tuple | None = None

    @classmethod
    def allow(
        cls,
        target_entry_anchor: int | None,
        *,
        proof_edge_key: tuple | None = None,
    ) -> "DagDecision":
        return cls(
            allowed=True,
            reason="ALLOW",
            target_entry_anchor=target_entry_anchor,
            proof_edge_key=proof_edge_key,
        )

    @classmethod
    def refuse(cls, reason: str) -> "DagDecision":
        if not reason:
            raise ValueError("refuse() requires a non-empty reason")
        return cls(allowed=False, reason=reason)

    @classmethod
    def gap(cls, gap_name: str) -> "DagDecision":
        """Convenience constructor for the strict DAG_GAP refusal pattern."""
        return cls.refuse(f"DAG_GAP:{gap_name}")

    @property
    def is_gap(self) -> bool:
        return (not self.allowed) and self.reason.startswith("DAG_GAP:")

    @property
    def is_disagreement(self) -> bool:
        return (not self.allowed) and self.reason.startswith("DAG_DISAGREEMENT:")


@dataclass(frozen=True, slots=True)
class _AnchorRecord:
    """Internal record for one resolved anchor → target mapping.

    Carries the resolved target_entry_anchor and back-pointers to the
    edge(s) that committed it. When more than one edge points the same
    anchor at *different* targets, we record all of them and surface
    via :meth:`DagAuthority.conflicts_for_source` — that's a DAG-
    internal inconsistency the planner shouldn't paper over.
    """

    target_entry_anchor: int
    edges: tuple[StateDagEdge, ...]


class DagAuthority:
    """Single arbiter every planner must consult before emitting a mod.

    Constructed once from a finalised :class:`LinearizedStateDag`. Build
    cost is O(|dag.edges|); all subsequent queries are O(1) dict lookups
    plus small list scans.

    The authority is **immutable** — it never mutates the underlying DAG
    nor accepts amendments mid-run. Mutation across pipeline rounds is
    deliberately deferred (mem_52073043); revisit if measured drift
    matters.
    """

    __slots__ = (
        "_dag",
        "_dag_edge_identities",
        "_canonical_by_anchor",
        "_dag_internal_conflicts",
        "_outgoing_by_source_key",
        "_node_by_handler",
        "_node_by_entry_anchor",
        "_planner_scope_edge_kinds",
    )

    # Edge kinds the planner currently emits modifications for.  Other
    # kinds (CONDITIONAL_RETURN, EXIT_ROUTINE, UNKNOWN) are out of
    # planner scope and yield DAG_GAP refusals — tracked under
    # uee-jrgq Phase-followup work.
    _PLANNER_SCOPE_EDGE_KINDS: frozenset[SemanticEdgeKind] = frozenset(
        {SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION}
    )

    def __init__(self, dag: LinearizedStateDag) -> None:
        self._dag = dag
        self._planner_scope_edge_kinds = self._PLANNER_SCOPE_EDGE_KINDS
        # Object identities of the edges this authority arbitrates over.  An
        # ALLOW must name one of *these* edges, not merely an edge-shaped
        # value (aa-v8et / d81-9q6e review round 2).  ``self._dag`` keeps every
        # edge alive for the authority's lifetime, so the ids cannot be reused
        # by a later object.  Equality is deliberately not used: two DAGs can
        # hold equal-valued edges, and only this DAG's commitment is evidence.
        self._dag_edge_identities: frozenset[int] = frozenset(
            id(edge) for edge in dag.edges
        )

        # Build the (src_block, branch_arm) -> target_entry_anchor index.
        # When two edges in scope agree on a target, collapse them into a
        # single record. When they disagree, record all of them so
        # conflicts_for_source() can surface the DAG-internal mismatch.
        edges_by_anchor: dict[AnchorKey, list[StateDagEdge]] = {}
        for edge in dag.edges:
            if edge.kind not in self._planner_scope_edge_kinds:
                continue
            if edge.target_entry_anchor is None:
                continue
            anchor = edge.source_anchor
            key: AnchorKey = (
                int(anchor.block_serial),
                None if anchor.branch_arm is None else int(anchor.branch_arm),
            )
            edges_by_anchor.setdefault(key, []).append(edge)

        canonical: dict[AnchorKey, _AnchorRecord] = {}
        conflicts: dict[AnchorKey, tuple[StateDagEdge, ...]] = {}
        for key, edges in edges_by_anchor.items():
            distinct_targets = {int(e.target_entry_anchor) for e in edges}  # type: ignore[arg-type]
            if len(distinct_targets) > 1:
                # Multiple edges committing different targets for the same
                # anchor — DAG-internal disagreement.  Don't pick a winner;
                # surface the conflict so it shows up in diagnostics, and
                # leave the anchor without a canonical record (queries
                # return DAG_GAP:dag_internal_conflict).
                conflicts[key] = tuple(edges)
                continue
            (target,) = distinct_targets
            canonical[key] = _AnchorRecord(
                target_entry_anchor=target,
                edges=tuple(edges),
            )
        self._canonical_by_anchor = canonical
        self._dag_internal_conflicts = conflicts

        # Pre-index node lookups so the future permits_* methods (and
        # consumers reaching into dag handlers) don't have to re-scan.
        self._node_by_handler: dict[int, StateDagNode] = {}
        self._node_by_entry_anchor: dict[int, StateDagNode] = {}
        outgoing: dict[StateDagNodeKey, list[StateDagEdge]] = {}
        for node in dag.nodes:
            self._node_by_handler[int(node.handler_serial)] = node
            self._node_by_entry_anchor[int(node.entry_anchor)] = node
        for edge in dag.edges:
            outgoing.setdefault(edge.source_key, []).append(edge)
        self._outgoing_by_source_key = {k: tuple(v) for k, v in outgoing.items()}

    # ------------------------------------------------------------------
    # Identity / canonical lookups
    # ------------------------------------------------------------------

    def canonical_target_for(
        self, src_block: int, branch_arm: int | None = None
    ) -> int | None:
        """Return the unique entry-anchor the DAG commits to for src/arm.

        Returns ``None`` when the DAG has no scoped edge originating from
        ``(src_block, branch_arm)`` OR when multiple edges disagree on the
        target (DAG-internal conflict — surface via
        :meth:`conflicts_for_source`).

        This is the highest-volume duplication consolidator: every
        legacy planner reaches into ``dag.edges`` and linear-scans for
        the matching source anchor. Centralising the lookup here means
        each planner becomes a thin wrapper around an O(1) dict access.
        """
        key: AnchorKey = (
            int(src_block),
            None if branch_arm is None else int(branch_arm),
        )
        record = self._canonical_by_anchor.get(key)
        return None if record is None else record.target_entry_anchor

    def conflicts_for_source(
        self, src_block: int, branch_arm: int | None = None
    ) -> tuple[StateDagEdge, ...]:
        """Return the conflicting DAG edges for an anchor, or empty tuple.

        Non-empty result indicates the DAG itself has multiple in-scope
        edges originating from ``(src_block, branch_arm)`` that target
        different entry-anchors. The arbiter does not pick a winner;
        callers should treat this as a DAG-build bug and surface it as
        a diagnostic (Phase 5).
        """
        key: AnchorKey = (
            int(src_block),
            None if branch_arm is None else int(branch_arm),
        )
        return self._dag_internal_conflicts.get(key, ())

    def is_known_anchor(self, src_block: int, branch_arm: int | None = None) -> bool:
        """``True`` iff the DAG has a planner-scoped edge from src/arm."""
        return self.canonical_target_for(src_block, branch_arm) is not None

    def node_for_handler(self, handler_serial: int) -> StateDagNode | None:
        return self._node_by_handler.get(int(handler_serial))

    def node_for_entry_anchor(self, entry_anchor: int) -> StateDagNode | None:
        return self._node_by_entry_anchor.get(int(entry_anchor))

    def edges_from(self, source_key: StateDagNodeKey) -> tuple[StateDagEdge, ...]:
        return self._outgoing_by_source_key.get(source_key, ())

    @property
    def dag(self) -> LinearizedStateDag:
        return self._dag

    # ------------------------------------------------------------------
    # Modification arbiters
    #
    # Each permits_<mod_kind> returns a DagDecision.  Phase 3 wires
    # the existing _drop_conflicting_redirects filter to call these
    # instead of "first-fragment-wins" semantics.
    # ------------------------------------------------------------------

    def permits_redirect_goto(self, mod: RedirectGoto) -> DagDecision:
        """Validate a RedirectGoto against the DAG.

        Decision rules:
          * canonical target == mod.new_target → ALLOW
          * canonical target != mod.new_target → DAG_DISAGREEMENT
          * canonical target unknown but DAG-internal conflict exists →
            DAG_GAP:dag_internal_conflict
          * canonical target unknown and no conflict → DAG_GAP:unknown_source
        """
        src = int(mod.from_serial)
        return self._validate_unconditional_redirect(
            src=src,
            proposed_target=int(mod.new_target),
            mod_kind="RedirectGoto",
        )

    def permits_convert_to_goto(self, mod: ConvertToGoto) -> DagDecision:
        """Validate a ConvertToGoto against the DAG.

        ConvertToGoto changes a 2-way block's tail to an unconditional
        goto. From the DAG's perspective it's the same decision as a
        RedirectGoto on the same source: "what unconditional target
        should the source block commit to?"
        """
        src = int(mod.block_serial)
        return self._validate_unconditional_redirect(
            src=src,
            proposed_target=int(mod.goto_target),
            mod_kind="ConvertToGoto",
        )

    def permits_zero_state_write(self, mod: ZeroStateWrite) -> DagDecision:
        """Refuse a ZeroStateWrite: its legality is not a DAG fact (aa-v8et).

        Phase 4 (uee-rjo8) consolidated the three legacy ZSW collectors into a
        single emitter at
        :func:`d810.transforms.zero_state_write_emission.collect_zero_state_writes`,
        and this method used to return an unconditional ``ALLOW`` justified by
        that consolidation's single-emitter invariant.

        The audit at ``.tmp/audit/2026-09-05-dag-authority-audit.md`` section
        3.3 rejected that justification: the single-emitter property is real,
        but it is enforced in a *different* module and ``DagAuthority`` cannot
        observe it. The ALLOW read no DAG state at all — an authority built
        over an empty DAG granted it, and the ``proof_edge_key`` was
        synthesised from the mod's own fields, i.e. the proposal was its own
        proof. That is an independent grant, which contradicts both this
        module's strict ``DAG_GAP`` policy and the standing invariant
        "``DagAuthority`` may restrict which proposals are emitted; it must
        never independently grant final mutation or semantic-loss permission."

        The verdict is therefore ``DAG_GAP:zero_state_write_not_dag_derivable``.
        Closing the gap requires the DAG to carry state-write def-sites (the
        missing ``def_sites_for_state`` index), not a cross-module appeal.
        """
        return DagDecision.gap("zero_state_write_not_dag_derivable")

    def permits_edge_redirect_via_pred_split(
        self, mod: EdgeRedirectViaPredSplit
    ) -> DagDecision:
        """Validate an EdgeRedirectViaPredSplit against the DAG (uee-7wcd).

        The mod represents a corridor clone splice: a predecessor
        ``mod.via_pred`` is rewired through a freshly-cloned corridor
        ``mod.src_block .. mod.clone_until`` whose tail retargets to
        ``mod.new_target``.

        Evidence policy (aa-v8et)
        -------------------------
        This method used to ALLOW when the mod matched a
        :class:`CorridorSpliceData` record seeded at construction time from a
        hardcoded per-function registry in the planner. That seed was not
        DAG-derived — it was a literal (``shared_block=45, base_target=126,
        clone_source=122, clone_target=180``) registered for one entry EA —
        and the resulting ``proof_edge_key`` named no DAG edge at all. Both
        the seed registry and the match branch are gone; the seeding channel
        went with them so it cannot be re-supplied by a future caller.

        The only evidence the arbiter accepts now is the DAG's own
        commitment for the corridor source:

        * DAG canonically commits ``mod.src_block`` to ``mod.new_target``
          → ALLOW, proved by that edge.
        * DAG commits ``mod.src_block`` somewhere else →
          ``DAG_DISAGREEMENT``.
        * DAG has no in-scope edge from ``mod.src_block`` →
          ``DAG_GAP:edge_redirect_via_pred_split_no_dag_evidence``.
        * DAG contradicts itself about ``mod.src_block`` →
          ``DAG_GAP:dag_internal_conflict``.

        The splice *topology* (``via_pred``, ``clone_until``) remains outside
        anything the DAG models; the ALLOW speaks only to the corridor's
        destination, which is safe because the verdict can never do more than
        keep a modification the planner already proposed.

        The shared fragment-level filter (``filter_dag_disagreements``)
        currently only reaches ``permits()`` for RedirectGoto / ConvertToGoto,
        so this method has no production consumer today.
        """
        return self._validate_unconditional_redirect(
            src=int(mod.src_block),
            proposed_target=int(mod.new_target),
            mod_kind="EdgeRedirectViaPredSplit",
            unknown_source_gap="edge_redirect_via_pred_split_no_dag_evidence",
        )

    def permits_dead_block_terminator_redirect(
        self,
        mod: RedirectGoto,
        *,
        projected_flow_graph: object | None = None,
        dispatcher_serial: int | None = None,
        original_stop_serial: int | None = None,
    ) -> DagDecision:
        "Validate a dead-block terminator redirect (uee-7snc).\n\n        The dead-dispatcher-root cleanup pass emits ``RedirectGoto``s\n        that retarget orphaned dispatcher-feeders at the function's\n        STOP block.  These mods can't be derived from the preanalysis\n        ``LinearizedStateDag`` directly because they depend on\n        reachability of the *projected post-mod* CFG \u2014 a graph the\n        DAG (built once per pipeline run, mem_52073043) doesn't model.\n\n        Decision rules (when caller supplies the projected graph + the\n        dispatcher / stop serials):\n\n        * ``mod.from_serial`` block must be in the projected graph,\n          have empty predset, have exactly one successor =\n          ``dispatcher_serial``, and ``mod.new_target`` must equal\n          ``original_stop_serial`` \u2192 ``DAG_GAP:dead_block_terminator_caller_derived``\n          (the predicate held, but on caller-supplied state, not on a DAG\n          edge \u2014 aa-v8et).\n        * Any constraint violation \u2192 ``DAG_DISAGREEMENT:dead_block_terminator``\n          with a per-reason payload (block missing / has preds /\n          succ-not-dispatcher / target-not-stop).\n        * Caller didn't pass projected_flow_graph / serials \u2192\n          ``DAG_GAP:dead_block_terminator_no_projected_graph``.\n\n        Mirrors the predicate ``_collect_dead_dispatcher_root_cleanup_modifications``\n        already uses inline (``linearized_flow_graph.py:1135``); the\n        method exists so the consumer can consult the arbiter and\n        record an audit trail rather than re-deriving the predicate.\n"
        if (
            projected_flow_graph is None
            or dispatcher_serial is None
            or original_stop_serial is None
        ):
            return DagDecision.gap("dead_block_terminator_no_projected_graph")
        try:
            blocks = getattr(projected_flow_graph, "blocks", None)
            if blocks is None or int(mod.from_serial) not in blocks:
                return DagDecision.refuse(
                    f"DAG_DISAGREEMENT:dead_block_terminator@{mod.from_serial}"
                    "->{reason=block_not_in_projected_graph}"
                )
            block = projected_flow_graph.get_block(int(mod.from_serial))
            if block is None:
                return DagDecision.refuse(
                    f"DAG_DISAGREEMENT:dead_block_terminator@{mod.from_serial}"
                    "->{reason=block_lookup_returned_none}"
                )
            preds = tuple(getattr(block, "preds", ()))
            if preds:
                return DagDecision.refuse(
                    f"DAG_DISAGREEMENT:dead_block_terminator@{mod.from_serial}"
                    f"->{{reason=block_has_preds,preds={list(preds)}}}"
                )
            succs = tuple(getattr(block, "succs", ()))
            if len(succs) != 1 or int(succs[0]) != int(dispatcher_serial):
                return DagDecision.refuse(
                    f"DAG_DISAGREEMENT:dead_block_terminator@{mod.from_serial}"
                    f"->{{reason=succ_not_dispatcher,succs={list(succs)},"
                    f"dispatcher={dispatcher_serial}}}"
                )
            if int(mod.new_target) != int(original_stop_serial):
                return DagDecision.refuse(
                    f"DAG_DISAGREEMENT:dead_block_terminator@{mod.from_serial}"
                    f"->{{planner_target={mod.new_target},"
                    f"expected_stop={original_stop_serial}}}"
                )
        except Exception as exc:  # noqa: BLE001
            return DagDecision.refuse(
                f"REFUSE:dead_block_terminator_validation_error:{exc!r}"
            )
        # Every refusal branch above is preserved: a malformed shape is still
        # a hard DAG_DISAGREEMENT.  What cannot survive is the terminal ALLOW.
        # Its three inputs -- projected_flow_graph, dispatcher_serial and
        # original_stop_serial -- are all supplied by the caller, and the
        # projected post-mod CFG is (per this method's own docstring) a graph
        # the DAG does not model.  Granting on it would make the arbiter
        # vouch for the consumer's own belief, i.e. an independent grant
        # (aa-v8et, audit section 3.4).  The conforming shape is therefore a
        # named gap: the predicate held, but the DAG did not supply it.
        return DagDecision.gap("dead_block_terminator_caller_derived")

    def permits(self, mod: object) -> DagDecision:
        """Dispatch by mod type. Unknown mod types yield DAG_GAP.

        Uses class-name dispatch instead of ``isinstance`` to stay
        hot-reload safe per ``rules/no-concrete-isinstance.yml``: after a
        module reload the class object's identity changes, so
        ``isinstance(x, RedirectGoto)`` may erroneously return False on
        a value created from the prior generation of the class.
        Comparing ``mod.__class__.__name__`` against a string sidesteps
        that.
        """
        kind = type(mod).__name__
        if kind == "RedirectGoto":
            return self.permits_redirect_goto(mod)  # type: ignore[arg-type]
        if kind == "ConvertToGoto":
            return self.permits_convert_to_goto(mod)  # type: ignore[arg-type]
        if kind == "ZeroStateWrite":
            return self.permits_zero_state_write(mod)  # type: ignore[arg-type]
        if kind == "EdgeRedirectViaPredSplit":
            # uee-7wcd / aa-v8et: EdgeRedirectViaPredSplit goes through the
            # DAG-evidence validator.  When the DAG has no in-scope edge from
            # the corridor source this returns
            # DAG_GAP:edge_redirect_via_pred_split_no_dag_evidence, which is a
            # strict improvement over the prior
            # DAG_GAP:unknown_mod_kind:EdgeRedirectViaPredSplit.
            return self.permits_edge_redirect_via_pred_split(mod)  # type: ignore[arg-type]
        return DagDecision.gap(f"unknown_mod_kind:{kind}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_unconditional_redirect(
        self,
        *,
        src: int,
        proposed_target: int,
        mod_kind: str,
        unknown_source_gap: str = "unknown_source",
    ) -> DagDecision:
        """Shared validation core for RedirectGoto / ConvertToGoto.

        Both mod kinds answer the same DAG question: "what unconditional
        target does src commit to?" The branch_arm is None for both,
        regardless of source-block shape (a 2-way ConvertToGoto coerces
        the block to a 1-way unconditional goto, so the branch arm is
        no longer meaningful at the post-mod CFG).
        """
        record = self._canonical_by_anchor.get((int(src), None))
        if record is None:
            # Distinguish "no DAG edge for this source" (DAG silent) from
            # "DAG has multiple edges disagreeing on target" (internal
            # conflict). Both yield DAG_GAP refusals but with different
            # gap names so diagnostics can route them.
            if self.conflicts_for_source(src, branch_arm=None):
                return DagDecision.gap("dag_internal_conflict")
            return DagDecision.gap(unknown_source_gap)
        canonical = record.target_entry_anchor
        if proposed_target == canonical:
            # Hand the authorising edge itself to the ALLOW constructor. Every
            # edge in a canonical record agrees on the target by construction
            # (see __init__), so any one of them is the proof.
            return self._allow_from_dag_edge(record.edges[0], mod_kind=mod_kind)
        return DagDecision.refuse(
            f"DAG_DISAGREEMENT:{src}->{{planner={proposed_target},dag={canonical}}}"
        )

    def _allow_from_dag_edge(
        self, edge: StateDagEdge, *, mod_kind: str
    ) -> DagDecision:
        """The single construction site of an ``ALLOW`` verdict (aa-v8et).

        ``DagAuthority`` may restrict which proposals are emitted; it must
        never independently grant. The way that invariant is *pinned* -- rather
        than merely documented -- is that an ALLOW cannot be built without a
        :class:`StateDagEdge` in hand: the evidence is a parameter, not a
        convention. ``rules/no-dag-authority-mutation-grant.yml`` statically
        rejects any other ``DagDecision.allow(...)`` call in this module, and
        ``tests/unit/transforms/test_dag_authority_grant_invariant.py``
        discovers every ``permits_*`` method by reflection and asserts it
        either refuses or routes through here.

        The ``proof_edge_key`` is derived from the edge, so it always names an
        edge that is really in the DAG -- unlike the three retired grants,
        whose keys were synthesised from the proposal's own fields, a
        hardcoded corridor literal, and caller-supplied CFG serials
        respectively.

        Returns a ``DAG_GAP`` when the edge carries no target entry anchor;
        such an edge is never indexed as canonical, so this is defence in
        depth rather than a reachable branch.

        The helper is an *instance* method, not a ``staticmethod``, because
        holding an edge is not the invariant -- holding **this DAG's** edge is.
        As a staticmethod it accepted any edge-shaped value and derived the
        ``proof_edge_key`` from it, so a fabricated edge yielded an ALLOW
        naming an edge present in no DAG: the same "proposal is its own proof"
        shape as the three retired grants (d81-9q6e review round 2). An edge
        this authority does not own is refused outright.
        """
        if id(edge) not in self._dag_edge_identities:
            return DagDecision.refuse(f"REFUSE:{mod_kind}_allow_edge_not_in_dag")
        target = edge.target_entry_anchor
        if target is None:
            return DagDecision.gap(f"{mod_kind}_edge_without_target_anchor")
        anchor = edge.source_anchor
        return DagDecision.allow(
            target_entry_anchor=int(target),
            proof_edge_key=(
                int(anchor.block_serial),
                None if anchor.branch_arm is None else int(anchor.branch_arm),
                int(target),
                mod_kind,
            ),
        )
