"""Unified ZeroStateWrite (ZSW) collection — single-emitter consolidation.

Phase 4 of the DAG-as-arbiter epic (uee-jrgq → uee-rjo8).

Before this module, three near-identical collectors emitted ``ZeroStateWrite``
mods from different points of the planning pipeline:

1. ``cfg.reconstruction_emission._collect_zero_state_write_modifications``
   — canonical. Walks reconstruction candidates whose ``.site`` is already
   resolved by the planner.
2. ``hodur.strategies.linearized_flow_graph._collect_structured_region_zero_state_write_modifications``
   — LFG-local. Walks accepted candidates and resolves the deepest state
   write site by walking ``ordered_path`` block-by-block via
   :func:`recon.flow.state_machine_analysis.find_last_state_write_site_on_path_snapshot`.
3. ``hodur.strategies.linearized_flow_graph._collect_trivial_redirect_tail_zero_state_write_modifications``
   — LFG-local. Walks already-emitted ``RedirectGoto`` mods whose
   ``old_target`` is the dispatcher and resolves the source block's last
   state write via :func:`recon.flow.state_machine_analysis.find_last_state_write_site_snapshot`.

Tracer evidence on sub_7FFD: 47 blocks emitted ZSW from 2-3 of these
collectors. The mods coalesced at builder level via the
``existing_modifications`` dedup seed (commit ``6e6a88ca``), but the
ownership smell remained — a planner-level invariant violation hiding
behind a coalescer.

This module re-expresses all three collectors as a single function
:func:`collect_zero_state_writes` taking a tagged-union :class:`ZsvSource`
input.  Each collector's caller resolves its inputs into a uniform list
of :class:`ZsvSiteRequest` records (an already-resolved tuple of
``(block_serial, insn_ea, site_state, target_states)``) and dispatches
through the single emitter, which performs the dedup pass once.

The architectural payoff:

* **Single dedup pass** across all callers — no more cross-collector
  duplication. Tracer audit on sub_7FFD will show 0 blocks with ZSW
  from multiple call sites.
* **Single dedup-key invariant** — every ``(block_serial, insn_ea)``
  ZSW decision is keyed identically across all 3 inputs.
* **Layering preserved** — this module lives in :mod:`d810.cfg` (below
  :mod:`d810.recon`); recon-level path resolution stays at the call
  site. The unified function only sees already-resolved sites.

The DagAuthority is consulted at the planner gateway in Phase 1; the
single-emitter invariant established here is the proof of the
``permits_zero_state_write`` arbiter's safety: the mod the planner
proposes is the unique decision for a given site.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import RedirectGoto, ZeroStateWrite
from d810.core.typing import Iterable, Sequence


__all__ = (
    "ZsvSiteRequest",
    "ZsvSource",
    "candidate_to_site_request",
    "collect_zero_state_writes",
)


@dataclass(frozen=True, slots=True)
class ZsvSiteRequest:
    """An already-resolved request to emit a ZSW for a single site.

    All three legacy collectors converged on the same essential
    contract before emitting. We capture that contract here as the
    single shape the unified emitter accepts:

    Attributes:
        block_serial: Block holding the state write.
        insn_ea: Effective address of the ``m_mov`` (or equivalent)
            instruction whose source operand will be zeroed.  Must be
            non-zero — sites without an EA are pre-filtered.
        site_state: The constant value the resolved site writes (or
            ``None`` if unknown). When ``target_states`` is non-empty
            and ``site_state`` is set, the emitter checks that the
            resolved state matches at least one accepted target state.
        target_states: The set of state values for which this
            ZSW emission is intended (deduplicated, masked to 32 bits).
            When empty, the site_state check is skipped (used for
            sources that are pre-filtered by the caller, like the
            trivial-redirect-tail collector which has no target-state
            handle).
        provenance: Free-form tag identifying which legacy collector
            requested this emission. Reserved for diagnostics.
    """

    block_serial: int
    insn_ea: int
    site_state: int | None = None
    target_states: frozenset[int] = frozenset()
    provenance: str = ""


@dataclass(frozen=True, slots=True)
class ZsvSource:
    """Tagged-union input to :func:`collect_zero_state_writes`.

    The three legacy collectors map onto three constructors:

    * :meth:`from_candidates` — wraps reconstruction candidates whose
      ``.site`` is already resolved by the planner. Replaces the
      canonical ``cfg.reconstruction_emission._collect_zero_state_write_modifications``.
    * :meth:`from_resolved_sites` — wraps already-resolved
      ``ZsvSiteRequest`` tuples directly. Replaces the two LFG-local
      collectors after they perform their own recon-layer path/block
      resolution.

    A union with explicit constructors keeps the call surface narrow
    while letting each caller provide the inputs in its native shape.
    """

    requests: tuple[ZsvSiteRequest, ...]

    @classmethod
    def from_candidates(
        cls,
        candidates: Iterable[object],
        *,
        provenance: str = "candidates",
    ) -> "ZsvSource":
        """Build from reconstruction candidates with pre-resolved ``.site``.

        Mirrors the input contract of the original
        ``_collect_zero_state_write_modifications``:

        * ``candidate.site.{block_serial, insn_ea, state_value}``
        * ``candidate.edge.{target_state, observed_target_state, ordered_path}``
        * ``candidate.horizon_block``

        The ordered_path/horizon-position check is enforced by
        :func:`collect_zero_state_writes` against the per-request data
        captured here (we capture the path so the emitter can do the
        sub-horizon prune in one place).
        """
        requests: list[ZsvSiteRequest] = []
        for candidate in candidates:
            request = candidate_to_site_request(
                candidate,
                provenance=provenance,
            )
            if request is not None:
                requests.append(request)
        return cls(requests=tuple(requests))

    @classmethod
    def from_resolved_sites(
        cls,
        sites: Iterable[ZsvSiteRequest],
    ) -> "ZsvSource":
        """Build from already-resolved :class:`ZsvSiteRequest` records.

        Used by callers that perform their own recon-layer path/block
        resolution (the two LFG-local collectors). Each caller
        resolves its sites via :mod:`d810.recon.flow.state_machine_analysis`
        helpers and forwards the resulting tuples here.
        """
        return cls(requests=tuple(sites))


def candidate_to_site_request(
    candidate: object,
    *,
    provenance: str = "candidates",
) -> ZsvSiteRequest | None:
    """Project a reconstruction candidate into a :class:`ZsvSiteRequest`.

    Returns ``None`` if any of the required fields are missing or if the
    candidate's site lies before the horizon block on the ordered_path
    (mirrors the original prune in
    ``_collect_zero_state_write_modifications``).
    """

    site = getattr(candidate, "site", None)
    if site is None:
        return None
    block_serial = getattr(site, "block_serial", None)
    insn_ea = getattr(site, "insn_ea", None)
    site_state = getattr(site, "state_value", None)
    if (
        block_serial is None
        or insn_ea is None
        or int(insn_ea) == 0
        or site_state is None
    ):
        return None

    edge = getattr(candidate, "edge", None)
    target_state = getattr(edge, "target_state", None)
    observed_target_state = getattr(edge, "observed_target_state", None)
    horizon_block = getattr(candidate, "horizon_block", None)
    if target_state is None or horizon_block is None:
        return None

    ordered_path = tuple(
        int(serial)
        for serial in getattr(edge, "ordered_path", ()) or ()
    )

    # Sub-horizon prune: site must lie at or after the horizon on the
    # ordered_path.  Single-block candidates (block_serial == horizon)
    # bypass the path check.
    if int(block_serial) != int(horizon_block):
        if not ordered_path:
            return None
        try:
            horizon_index = ordered_path.index(int(horizon_block))
            site_index = ordered_path.index(int(block_serial))
        except ValueError:
            return None
        if int(site_index) < int(horizon_index):
            return None

    target_states = frozenset(
        int(state_value) & 0xFFFFFFFF
        for state_value in (target_state, observed_target_state)
        if state_value is not None
    )

    return ZsvSiteRequest(
        block_serial=int(block_serial),
        insn_ea=int(insn_ea),
        site_state=int(site_state),
        target_states=target_states,
        provenance=str(provenance),
    )


def collect_zero_state_writes(
    *,
    source: ZsvSource,
    existing_modifications: Sequence[object] = (),
) -> tuple[ZeroStateWrite, ...]:
    """Single-emitter ZSW collector.

    Performs one dedup pass over ``source.requests`` against
    ``existing_modifications`` (any ZSW already in the running modifications
    list seeds the ``seen`` set, so the same ``(block_serial, insn_ea)``
    cannot be emitted twice across multiple invocations).

    The emission rule is the unified contract from R3's audit:

    * Drop requests with ``insn_ea == 0`` (already filtered by
      ``candidate_to_site_request`` for the candidate path; the
      LFG callers must filter before forwarding).
    * If ``target_states`` is non-empty and ``site_state`` is set,
      require ``site_state & 0xFFFFFFFF`` to match at least one
      accepted target state.
    * Skip duplicates: every ``(block_serial, insn_ea)`` is emitted
      at most once across all sources sharing the same
      ``existing_modifications`` accumulator.

    The single-emitter invariant: every block→insn_ea ZSW decision
    has exactly one author per pipeline run. Phase 5 diagnostics
    surface any future regressions via the ``D810_TRACE_MOD_CONSTRUCTION``
    tracer (auditable through the ``ZERO_STATE_WRITE_CONSTRUCTED``
    log line + caller frame).
    """

    seen: set[tuple[int, int]] = {
        (int(mod.block_serial), int(mod.insn_ea))
        for mod in existing_modifications
        if isinstance(mod, ZeroStateWrite)
    }
    mods: list[ZeroStateWrite] = []
    for request in source.requests:
        if int(request.insn_ea) == 0:
            continue
        if request.target_states and request.site_state is not None:
            if (int(request.site_state) & 0xFFFFFFFF) not in request.target_states:
                continue
        key = (int(request.block_serial), int(request.insn_ea))
        if key in seen:
            continue
        seen.add(key)
        mods.append(
            ZeroStateWrite(
                block_serial=int(request.block_serial),
                insn_ea=int(request.insn_ea),
            )
        )
    return tuple(mods)
