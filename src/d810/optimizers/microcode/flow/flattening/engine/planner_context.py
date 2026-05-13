"""Cumulative planner-context types shared across unflattening strategies.

Problem this solves
-------------------
Multiple strategies run sequentially in the same unflattening pipeline
(SSR, SRW, their postprocess phases, cleanup strategies, etc.). Each
strategy inspects the projected CFG to decide what to do, but the
projected CFG alone does not tell a strategy *why* a block looks the
way it does. A concrete failure this causes is the "Mode 1" pattern
observed on ``sub_7FFD3338C040``:

  mod[26]: BLOCK_GOTO_CHANGE src=76 tgt=11 old=2   (SRW linearizes)
  mod[27]: ZeroStateWrite   src=76                (SRW neutralizes state)
  mod[75]: BLOCK_GOTO_CHANGE src=76 tgt=2  old=11  (*second* planner reverts)

A later planner observed blk[76] with a zeroed state write and a goto
into a handler, decided the routing was "ambiguous", and routed it
back through the dispatcher as a safety fallback. The fallback undoes
the earlier linearization. The two planners had no way to communicate.

How this module solves it
-------------------------
Strategies emit structured intent alongside their modifications:

* :class:`LinearizationDecision` records "I routed src -> tgt for reason
  R on behalf of strategy S during round N".
* :class:`StateWriteNeutralization` records "I zeroed the state write
  on src; the original constant was C".

Each strategy's ``PlanFragment.metadata`` carries a
:class:`PlannerContextContribution` under the ``"planner_ctx"`` key with
those records. The engine aggregates contributions across all fragments
emitted this pipeline into a read-only :class:`CumulativePlannerView`
and surfaces it on the next strategy's :class:`AnalysisSnapshot`.

Subsequent strategies query the view — e.g. ``view.is_linearized(76)``
— and skip or adjust their plans instead of fighting prior decisions.

Layering
--------
This module lives in ``engine`` (family-agnostic). Hodur and any future
strategy family gets the cumulative view for free; none of the types
here are tied to a specific state-machine recovery approach.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:  # pragma: no cover — type hints only
    from d810.optimizers.microcode.flow.flattening.engine.dag_authority import (
        DagAuthority,
    )

__all__ = [
    "LinearizationDecision",
    "StateWriteNeutralization",
    "PlannerContextContribution",
    "CumulativePlannerView",
    "PLANNER_CTX_METADATA_KEY",
]


# Canonical key under which strategies should attach their contribution
# to ``PlanFragment.metadata``. Using a module-level constant avoids
# stringly-typed typos across the codebase.
PLANNER_CTX_METADATA_KEY: str = "planner_ctx"


@dataclass(frozen=True, slots=True)
class LinearizationDecision:
    """One strategy's commitment to route *src* to *tgt*.

    Emitted alongside graph-mutation modifications so downstream strategies
    can observe the routing intent even if the graph has not yet been
    mutated (planning simulates modifications; the live MBA is not touched
    until :meth:`DeferredGraphModifier.apply`).

    Attributes:
        src: The source block serial whose outgoing edge is being rewritten.
        tgt: The new target block serial.
        reason: Emission-site label (e.g. ``"residual_handoff"``,
            ``"lfg_preheader"``, ``"dag_bridge"``). Pure annotation.
        strategy: Short name of the strategy that made this decision
            (e.g. ``"state_write_reconstruction"``).
        round_index: Zero-indexed pipeline round. A strategy may run
            multiple times across rounds; this disambiguates recurrences.
    """

    src: int
    tgt: int
    reason: str
    strategy: str
    round_index: int


@dataclass(frozen=True, slots=True)
class StateWriteNeutralization:
    """A record that a strategy zeroed the state-variable write on *src*.

    The original constant is preserved so later strategies can reason
    about what the state write *originally* was, even though the current
    (zeroed) write would make the block look stateless.

    Attributes:
        src: Block serial where the state write lives.
        original_state_constant: The state constant before
            ``ZeroStateWrite`` replaced it with ``#0``. Zero-padded to
            whichever machine width the state variable uses.
        strategy: Short name of the strategy that neutralized the write.
        round_index: Zero-indexed pipeline round.
    """

    src: int
    original_state_constant: int
    strategy: str
    round_index: int


@dataclass(frozen=True, slots=True)
class PlannerContextContribution:
    """Per-fragment contribution that a strategy attaches to its metadata.

    Strategies produce one of these and put it on
    ``PlanFragment.metadata[PLANNER_CTX_METADATA_KEY]``. The engine
    aggregates all contributions into a :class:`CumulativePlannerView`
    before invoking the next strategy.

    All collections are tuples/frozensets so this value is immutable and
    hashable — safe to store in sets, caches, and diagnostic snapshots.

    Attributes:
        linearizations: Linearization decisions emitted this fragment.
        neutralizations: State-write neutralizations emitted this fragment.
        claimed_sources: Source-block serials the strategy claims exclusive
            responsibility for this fragment. Later strategies should treat
            the block as off-limits for edge rewrites unless they have a
            concrete reason to override (which they should log).
        direct_use_def_veto_sources: Source-block serials where the strategy
            considered a direct redirect and rejected it because it would
            sever a non-state stack-var use. Cleanup strategies may use this
            narrower set to avoid resurrecting a specifically rejected
            redirect without treating every claimed source as unavailable.
    """

    linearizations: tuple[LinearizationDecision, ...] = ()
    neutralizations: tuple[StateWriteNeutralization, ...] = ()
    claimed_sources: frozenset[int] = field(default_factory=frozenset)
    direct_use_def_veto_sources: frozenset[int] = field(
        default_factory=frozenset
    )


@dataclass(frozen=True, slots=True)
class CumulativePlannerView:
    """Read-only aggregate of every strategy's contributions this pipeline.

    The engine builds one of these before calling each strategy's
    ``plan()``, accumulating contributions from all prior fragments in the
    current pipeline run. Strategies read from it via the query helpers
    (``is_linearized``, ``linearization_target_for``, ``original_state_for``)
    to avoid stepping on prior planners' decisions.

    Instances are cheap to construct via :meth:`compile`. They are NOT
    cumulative across pipeline runs — each run starts with an empty
    view. This matches the semantics callers expect: a pipeline is the
    unit of planning, and strategies in round N should see decisions
    made in rounds 0..N-1 of the same pipeline, not decisions from some
    unrelated previous decompilation.

    DAG-as-arbiter (Phase 2 of uee-jrgq)
    ------------------------------------
    The optional ``dag_authority`` field carries the canonical answer
    for "what does the recon DAG commit src/arm to?". Strategies and
    fragment-finalisers query it BEFORE emitting redirects; mods that
    disagree with the DAG are dropped (Phase 3).  ``dag_authority`` is
    None when no DAG is available for the current pipeline (e.g. a
    family that hasn't built one yet) — callers MUST tolerate None and
    fall through to the legacy ``LinearizationDecision``-based filter.

    Per the deferral decision (mem_52073043), the authority is built
    once per pipeline run; per-round rederivation is intentionally
    deferred. The view is rebuilt every iteration to absorb new
    fragment contributions, but it carries the same DagAuthority across
    iterations.
    """

    linearization_decisions: frozenset[LinearizationDecision]
    neutralized_state_writes: frozenset[StateWriteNeutralization]
    claimed_sources: frozenset[int]
    direct_use_def_veto_sources: frozenset[int] = field(
        default_factory=frozenset
    )
    # ``DagAuthority`` is forward-typed via string-quoted annotation to
    # avoid an upward import (this module is structurally below
    # ``dag_authority``).  Runtime callers pass an instance; tests may
    # leave it None.  See ``engine.dag_authority.DagAuthority``.
    dag_authority: "DagAuthority | None" = None

    # Query helpers — keep the hot path tight (linear scan is fine at
    # the scale of "a few hundred decisions per pipeline"; if that grows
    # we can add a src-indexed cache here without changing the API).

    def is_linearized(self, src: int) -> bool:
        """Return True if any prior strategy linearized *src*."""
        src_int = int(src)
        return any(d.src == src_int for d in self.linearization_decisions)

    def linearization_target_for(self, src: int) -> int | None:
        """Return the target a prior strategy routed *src* to, if any.

        When multiple strategies linearized the same source, this returns
        the target from the *first* recorded decision (by round_index,
        then insertion order). In practice the view is used to detect
        "already linearized, don't touch" — the specific target matters
        less than the existence of a decision.
        """
        src_int = int(src)
        best: LinearizationDecision | None = None
        for decision in self.linearization_decisions:
            if decision.src != src_int:
                continue
            if best is None or decision.round_index < best.round_index:
                best = decision
        return best.tgt if best is not None else None

    def original_state_for(self, src: int) -> int | None:
        """Return the pre-neutralization state constant written by *src*.

        Useful for a later strategy that wants to reason about "what was
        the handler-exit state this block originally wrote" without being
        fooled by a zeroing ``ZeroStateWrite`` emitted by an earlier
        strategy.
        """
        src_int = int(src)
        for neut in self.neutralized_state_writes:
            if neut.src == src_int:
                return neut.original_state_constant
        return None

    def is_claimed(self, src: int) -> bool:
        """Return True if *src* is in any prior strategy's claimed set."""
        return int(src) in self.claimed_sources

    def is_direct_use_def_vetoed(self, src: int) -> bool:
        """Return True if a prior strategy directly vetoed *src*."""
        return int(src) in self.direct_use_def_veto_sources

    @classmethod
    def compile(
        cls,
        fragments: "Iterable[object]",
        *,
        dag_authority: "DagAuthority | None" = None,
    ) -> "CumulativePlannerView":
        """Aggregate contributions across *fragments* into a new view.

        *fragments* is typed as ``Iterable[object]`` rather than
        ``Iterable[PlanFragment]`` to avoid a circular import: this module
        is imported by ``engine.strategy`` for its ``PlanFragmentMetadata``
        TypedDict. At runtime, elements are duck-typed — we look for
        ``.metadata`` and ``.metadata[PLANNER_CTX_METADATA_KEY]``. Missing
        or empty contributions are silently skipped, so strategies that
        do not opt in incur zero cost.

        ``dag_authority`` carries the per-pipeline-run DAG-as-arbiter
        instance. The same authority is threaded through every
        iteration of the planner loop (built once per pipeline per
        memory mem_52073043). Pass ``None`` for legacy / DAG-less
        runs; consumers MUST tolerate that.
        """
        linearizations: list[LinearizationDecision] = []
        neutralizations: list[StateWriteNeutralization] = []
        claimed: set[int] = set()
        direct_use_def_vetoed: set[int] = set()

        for fragment in fragments:
            metadata = getattr(fragment, "metadata", None)
            if metadata is None:
                continue
            contribution = metadata.get(PLANNER_CTX_METADATA_KEY)
            if not isinstance(contribution, PlannerContextContribution):
                continue
            linearizations.extend(contribution.linearizations)
            neutralizations.extend(contribution.neutralizations)
            claimed.update(int(src) for src in contribution.claimed_sources)
            direct_use_def_vetoed.update(
                int(src) for src in contribution.direct_use_def_veto_sources
            )

        return cls(
            linearization_decisions=frozenset(linearizations),
            neutralized_state_writes=frozenset(neutralizations),
            claimed_sources=frozenset(claimed),
            direct_use_def_veto_sources=frozenset(direct_use_def_vetoed),
            dag_authority=dag_authority,
        )

    @classmethod
    def empty(
        cls,
        *,
        dag_authority: "DagAuthority | None" = None,
    ) -> "CumulativePlannerView":
        """Return an empty view — the correct starting point for a pipeline.

        ``dag_authority`` may be passed when the empty view is the
        first iteration of a pipeline that already has a DagAuthority
        available; subsequent iterations pass it through ``compile()``.
        """
        return cls(
            linearization_decisions=frozenset(),
            neutralized_state_writes=frozenset(),
            claimed_sources=frozenset(),
            direct_use_def_veto_sources=frozenset(),
            dag_authority=dag_authority,
        )
