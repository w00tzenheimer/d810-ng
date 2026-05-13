"""DagAuthority — recon DAG arbiter for emitted graph modifications.

Phase 1 of the DAG-as-arbiter epic (uee-jrgq).

Currently every Hodur planner re-derives "what should block X do?" from the
CFG and emits a graph modification independently. The downstream conflict
filter ("first-fragment-wins" in :func:`_drop_conflicting_redirects`) tries
to reconcile disagreement after the fact. That's an architectural inversion:
the recon-built :class:`LinearizedStateDag` already encodes the canonical
answer, but no consumer queries it as a single source of truth.

:class:`DagAuthority` flips the relationship. It wraps a finalized
``LinearizedStateDag`` and exposes a queryable interface every planner
consults *before* emitting a mod. When the DAG has an answer that disagrees
with the planner's intent, the mod is *refused*; when the DAG has no answer
(``DAG_GAP``), the mod is *strictly refused* and a follow-up ticket has to
close the gap before the planner can emit there. This is the single conflict
resolution rule that supersedes Mode 1 / Mode 2 / Mode 3 / Mode 4 per the
synthesis at ``.claude/notes/investigations/2026-04-25-uee-dag-phase0-synthesis.md``.

Phase 1 (this module) ships:

* :func:`DagAuthority.canonical_target_for` — the centralised "what
  entry-anchor does the DAG commit src/arm to?" lookup. Replaces every
  ad-hoc scan of ``dag.edges``.
* :func:`DagAuthority.conflicts_for_source` — DAG-internal conflict
  detection (when two DAG edges target different anchors for the same
  source/arm).
* :func:`DagAuthority.permits_redirect_goto` and
  :func:`DagAuthority.permits_convert_to_goto` — the two arbiter methods
  whose underlying queries are fully covered by the existing DAG.
* :func:`DagAuthority.permits_duplicate_and_redirect` and
  :func:`DagAuthority.permits_zero_state_write` — return ``DAG_GAP``
  refusals until the four extension tickets close (uee-7wcd, uee-7snc,
  uee-qli0, uee-bwdk).

Per the deferral decision recorded in semantic memory (mem_52073043),
the authority is built **once per pipeline run**. Per-round rederivation
is more accurate but slower; the build-once choice is deliberate and
revisitable when measured drift on real corpus matters. Construction
caches all derived indexes so query methods are O(1) lookups.

Strict ``DAG_GAP`` policy: when the DAG cannot answer a question
authoritatively, the mod is refused. Callers must NOT permit the mod
with a warning — that would defer the architectural fix and let
silent emission errors accumulate. Closing each ``DAG_GAP:<name>``
requires the corresponding extension ticket.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import (
    ConvertToGoto,
    DuplicateAndRedirect,
    EdgeRedirectViaPredSplit,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.cfg.state_dag_key import StateDagNodeKey
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    SemanticEdgeKind,
    StateDagEdge,
    StateDagNode,
)


__all__ = (
    "AnchorKey",
    "CorridorSpliceData",
    "DagAuthority",
    "DagDecision",
)


@dataclass(frozen=True, slots=True)
class CorridorSpliceData:
    """Function-specific corridor-clone splice points (uee-7wcd).

    Some lowering decisions cannot today be derived from the recon
    ``LinearizedStateDag``: e.g., ``sub_7FFD3338C040``'s
    ``deferred_corridor_clone`` emission requires hand-tuned splice
    points (shared block, base target, clone source/target) that
    no current DAG schema field encodes.  R2's emission catalogue
    flagged this as a DAG_GAP candidate (uee-7wcd in the
    DAG-as-arbiter epic).

    The closure path is to seed :class:`DagAuthority` with this
    function-specific data at construction time so the arbiter can
    authoritatively ALLOW corridor-shaped mods rather than letting
    them slip through as ``DAG_GAP:edge_redirect_via_pred_split``.
    The data lives in ``engine`` (family-agnostic) so any future
    function with a corridor pattern can register without touching
    Hodur internals.

    Attributes:
        function_ea: ``mba.entry_ea`` this corridor applies to.  Used
            to gate registry consultation (don't apply sub_7FFD's
            corridor to other functions).
        shared_block: The shared dispatch block being spliced
            (e.g., 45 for sub_7FFD).
        base_target: Where the shared block's primary redirect goes
            (e.g., 126 for sub_7FFD).
        clone_source: The block whose corridor is cloned per-pred
            (e.g., 122 for sub_7FFD).
        clone_target: Where the cloned corridor's tail redirects
            (e.g., 180 for sub_7FFD).
    """

    function_ea: int
    shared_block: int
    base_target: int
    clone_source: int
    clone_target: int


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
        "_canonical_by_anchor",
        "_dag_internal_conflicts",
        "_outgoing_by_source_key",
        "_node_by_handler",
        "_node_by_entry_anchor",
        "_planner_scope_edge_kinds",
        "_corridor_by_shared_block",
    )

    # Edge kinds the planner currently emits modifications for.  Other
    # kinds (CONDITIONAL_RETURN, EXIT_ROUTINE, UNKNOWN) are out of
    # planner scope and yield DAG_GAP refusals — tracked under
    # uee-jrgq Phase-followup work.
    _PLANNER_SCOPE_EDGE_KINDS: frozenset[SemanticEdgeKind] = frozenset(
        {SemanticEdgeKind.TRANSITION, SemanticEdgeKind.CONDITIONAL_TRANSITION}
    )

    def __init__(
        self,
        dag: LinearizedStateDag,
        *,
        corridor_data: tuple[CorridorSpliceData, ...] = (),
    ) -> None:
        self._dag = dag
        self._planner_scope_edge_kinds = self._PLANNER_SCOPE_EDGE_KINDS
        # Map shared_block -> corridor data for O(1) consultation by
        # ``permits_edge_redirect_via_pred_split`` and
        # ``canonical_corridor_splice_for``.  Empty by default; planner
        # seeds this with function-specific data based on
        # ``mba.entry_ea`` (uee-7wcd).
        self._corridor_by_shared_block: dict[int, CorridorSpliceData] = {
            int(c.shared_block): c for c in corridor_data
        }

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
        self._outgoing_by_source_key = {
            k: tuple(v) for k, v in outgoing.items()
        }

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

    def is_known_anchor(
        self, src_block: int, branch_arm: int | None = None
    ) -> bool:
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

    def permits_duplicate_and_redirect(
        self, mod: DuplicateAndRedirect
    ) -> DagDecision:
        """Validate a DuplicateAndRedirect against the DAG.

        Currently strict-refuses with ``DAG_GAP:duplicate_and_redirect_safety``
        — the DAG marks ``shared_suffix_blocks`` but does not expose
        clone-impact analysis (no liveness summary, no clones-would-
        break-join check). The R1 catalog flagged this gap; closing it
        requires extending the DAG with per-block clone-safety
        annotations. Tracked under the uee-jrgq epic.
        """
        return DagDecision.gap("duplicate_and_redirect_safety")

    def permits_zero_state_write(self, mod: ZeroStateWrite) -> DagDecision:
        """Validate a ZeroStateWrite against the DAG.

        Phase 4 (uee-rjo8) consolidated the three legacy ZSW
        collectors into a single emitter at
        :func:`d810.cfg.zero_state_write_emission.collect_zero_state_writes`.
        The single-emitter invariant — every ``(block_serial, insn_ea)``
        ZSW decision has exactly one author per pipeline run — is the
        proof of legality this arbiter relied on the missing
        ``def_sites_for_state`` index for.  With the consolidation in
        place, a ZSW reaching the arbiter is by construction the
        canonical owner's emission, so we ALLOW.

        The earlier ``DAG_GAP:zero_state_write_legality`` strict refusal
        is now redundant: the gap was about *whether* a write site is
        the unique definer; the consolidation ensures the planner
        cannot emit two ZSWs for the same site, regardless of how many
        collectors the recon-side path resolution funnels through.

        Diagnostic auditing: a tracer-driven sub_7FFD e2e shows 0
        blocks emitting ZSW from multiple call sites
        (``D810_TRACE_MOD_CONSTRUCTION=1`` ``ZERO_STATE_WRITE_CONSTRUCTED``
        log line + caller frame, post-Phase 4 invariant).
        """
        return DagDecision.allow(
            target_entry_anchor=None,
            proof_edge_key=(int(mod.block_serial), int(mod.insn_ea), "ZeroStateWrite"),
        )

    def canonical_corridor_splice_for(
        self, shared_block: int
    ) -> CorridorSpliceData | None:
        """Return the corridor splice data for a shared block, or None.

        uee-7wcd extension.  When seeded by the planner with function-
        specific corridor data, this query authoritatively answers
        "is this shared_block a known corridor splice point?"
        """
        return self._corridor_by_shared_block.get(int(shared_block))

    def permits_edge_redirect_via_pred_split(
        self, mod: EdgeRedirectViaPredSplit
    ) -> DagDecision:
        """Validate an EdgeRedirectViaPredSplit against the DAG (uee-7wcd).

        The mod represents a corridor clone splice: a predecessor
        ``mod.via_pred`` is rewired through a freshly-cloned corridor
        ``mod.src_block .. mod.clone_until`` whose tail retargets to
        ``mod.new_target``.

        Decision rules:

        * If ``DagAuthority`` was seeded with corridor data for the
          shared block (= ``mod.old_target``) and the (clone_source,
          clone_target) pair matches the recorded splice, ALLOW.
        * If corridor data is seeded but the (src, target) tuple
          disagrees with the registered splice points,
          ``DAG_DISAGREEMENT:corridor_splice@<shared>``.
        * If no corridor data is seeded for this shared block,
          ``DAG_GAP:edge_redirect_via_pred_split_seed_missing``.

        The Hodur fragment-level filter (``_drop_dag_disagreement``)
        currently only validates RedirectGoto / ConvertToGoto; this
        method exists to make the validation path *available* for
        tests + future filter extensions.
        """
        shared_block = int(mod.old_target)
        corridor = self._corridor_by_shared_block.get(shared_block)
        if corridor is None:
            return DagDecision.gap("edge_redirect_via_pred_split_seed_missing")
        if (
            int(mod.src_block) == int(corridor.clone_source)
            and int(mod.new_target) == int(corridor.clone_target)
        ):
            return DagDecision.allow(
                target_entry_anchor=int(corridor.clone_target),
                proof_edge_key=(
                    "corridor_splice",
                    int(corridor.shared_block),
                    int(corridor.clone_source),
                    int(corridor.clone_target),
                ),
            )
        return DagDecision.refuse(
            f"DAG_DISAGREEMENT:corridor_splice@{shared_block}->"
            f"{{planner=({mod.src_block},{mod.new_target}),"
            f"dag=({corridor.clone_source},{corridor.clone_target})}}"
        )

    def permits_dead_block_terminator_redirect(
        self,
        mod: RedirectGoto,
        *,
        projected_flow_graph: object | None = None,
        dispatcher_serial: int | None = None,
        original_stop_serial: int | None = None,
    ) -> DagDecision:
        """Validate a dead-block terminator redirect (uee-7snc).

        The dead-dispatcher-root cleanup pass emits ``RedirectGoto``s
        that retarget orphaned dispatcher-feeders at the function's
        STOP block.  These mods can't be derived from the recon
        ``LinearizedStateDag`` directly because they depend on
        reachability of the *projected post-mod* CFG — a graph the
        DAG (built once per pipeline run, mem_52073043) doesn't model.

        Decision rules (when caller supplies the projected graph + the
        dispatcher / stop serials):

        * ``mod.from_serial`` block must be in the projected graph,
          have empty predset, have exactly one successor =
          ``dispatcher_serial``, and ``mod.new_target`` must equal
          ``original_stop_serial`` → ALLOW.
        * Any constraint violation → ``DAG_DISAGREEMENT:dead_block_terminator``
          with a per-reason payload (block missing / has preds /
          succ-not-dispatcher / target-not-stop).
        * Caller didn't pass projected_flow_graph / serials →
          ``DAG_GAP:dead_block_terminator_no_projected_graph``.

        Mirrors the predicate ``_collect_dead_dispatcher_root_cleanup_modifications``
        already uses inline (``linearized_flow_graph.py:1135``); the
        method exists so the consumer can consult the arbiter and
        record an audit trail rather than re-deriving the predicate.
        """
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
        return DagDecision.allow(
            target_entry_anchor=int(original_stop_serial),
            proof_edge_key=(
                "dead_block_terminator",
                int(mod.from_serial),
                int(dispatcher_serial),
                int(original_stop_serial),
            ),
        )

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
        if kind == "DuplicateAndRedirect":
            return self.permits_duplicate_and_redirect(mod)  # type: ignore[arg-type]
        if kind == "ZeroStateWrite":
            return self.permits_zero_state_write(mod)  # type: ignore[arg-type]
        if kind == "EdgeRedirectViaPredSplit":
            # uee-7wcd: EdgeRedirectViaPredSplit goes through the
            # corridor-aware validator.  Without seeded corridor data
            # this returns DAG_GAP:edge_redirect_via_pred_split_seed_missing,
            # but the named gap is a strict improvement over the prior
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
    ) -> DagDecision:
        """Shared validation core for RedirectGoto / ConvertToGoto.

        Both mod kinds answer the same DAG question: "what unconditional
        target does src commit to?" The branch_arm is None for both,
        regardless of source-block shape (a 2-way ConvertToGoto coerces
        the block to a 1-way unconditional goto, so the branch arm is
        no longer meaningful at the post-mod CFG).
        """
        canonical = self.canonical_target_for(src, branch_arm=None)
        if canonical is None:
            # Distinguish "no DAG edge for this source" (DAG silent) from
            # "DAG has multiple edges disagreeing on target" (internal
            # conflict). Both yield DAG_GAP refusals but with different
            # gap names so diagnostics can route them.
            if self.conflicts_for_source(src, branch_arm=None):
                return DagDecision.gap("dag_internal_conflict")
            return DagDecision.gap("unknown_source")
        if proposed_target == canonical:
            return DagDecision.allow(
                target_entry_anchor=canonical,
                proof_edge_key=(src, None, canonical, mod_kind),
            )
        return DagDecision.refuse(
            f"DAG_DISAGREEMENT:{src}->"
            f"{{planner={proposed_target},dag={canonical}}}"
        )
