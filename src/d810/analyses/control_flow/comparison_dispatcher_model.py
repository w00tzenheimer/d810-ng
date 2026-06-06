"""The shared comparison ``DispatcherModel`` (S2 — the 28-orphan fix).

The four comparison dispatcher kinds (``BST`` / ``SWITCH`` / ``EQUALITY_CHAIN`` /
``CONDITION_CHAIN``) differ only in *recovery*; once recovered they route a
concrete state value identically: exact row first, then interval rows.  This
collapses their divergent ``resolve_target`` bodies into ONE ``route``.

The disease (``docs/plans/dispatcher-model-consolidation.md`` §0): the §1a
``RecoverStateTransitions`` resolved next-states through the exact-only
``StateDispatcherMap.resolve_target`` (``state_to_handler().get``), so an
interval-routed next-state (e.g. ``0x79F598F7 ∈ [0x737189d6, 0x7c2c0220] → blk
52``) returned ``None`` → ``"state_not_in_dispatcher_map"`` → the edge was
dropped, orphaning blk 52 and its 12-block component.  ``route`` consults the
interval rows via :meth:`WrappedInterval.contains`, reconnecting them.

The interval body intentionally MIRRORS the existing
:func:`d810.analyses.control_flow.bst_model.resolve_target_via_bst` (exact map
first, then ``handler_range_map`` lo/hi with the ``>= 0xFFFF0000`` degenerate-arc
guard, then default), so the comparison model and the BST resolver agree.

Pure analyses-layer: no IDA, no Hex-Rays.  Structural match for the
``transforms.state_machine_unflatten.DispatcherModel`` Protocol (it does NOT
import that Protocol — ``analyses`` is below ``transforms``).  STANDING RULE:
:class:`Block` route results carry the block EA alongside the serial when an
``block_ea`` map is supplied.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import TYPE_CHECKING, Mapping, Optional

from d810.analyses.abstract_domains.interval_set import Interval, IntervalSet
from d810.analyses.data_flow.abstract_value import Block, RouteResult, Unknown

if TYPE_CHECKING:
    # Annotation-only: importing it at runtime would cycle with
    # ``dispatcher_resolution`` (which imports the route helper below).  The
    # model reads ``StateDispatcherMap`` purely structurally
    # (``state_to_handler`` / ``state_var_stkoff`` / ``dispatcher_*``).
    from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap

__all__ = [
    "ComparisonDispatcherModel",
    "build_partition",
    "build_partition_from_dispatcher",
    "route_via_interval_sets",
    "intervals_from_range_map",
]

#: The degenerate "range covers (almost) the whole word" guard, copied from
#: ``bst_model.resolve_target_via_bst``: a span this wide is the dispatcher's
#: default/catch-all interval, not a real handler range.
_DEGENERATE_RANGE_SPAN = 0xFFFF0000

#: Mask state values to the 64-bit word the rows are stored in.
_U64_MASK = 0xFFFFFFFFFFFFFFFF

#: Bit width of the dispatcher state variable.  The recovered state constants
#: are 32-bit (the ``IntervalDispatcher`` rows and the ``>= 0xFFFF0000``
#: degenerate-span guard are both sized to it), so the abstract-domain
#: :class:`IntervalSet` partition is built over ``[0, 2**32)``.
_STATE_WIDTH = 32


def build_partition_from_dispatcher(dispatcher: object | None) -> "dict[int, IntervalSet]":
    """Complete per-handler :class:`IntervalSet` partition from an ``IntervalDispatcher``.

    Sources the FULL interval rows from the :class:`IntervalDispatcher` (which
    carries every ``(lo, hi)`` row, not just one per handler) and unions each
    handler's disjoint ranges into one :class:`IntervalSet`, so a split-range
    handler keeps ALL its ranges -- unlike :func:`intervals_from_range_map`,
    which only retains the single ``(lo, hi)`` the lossy ``handler_range_map``
    kept.  The dispatcher's default / catch-all target (``default_target``, the
    max-width arm) is excluded so gap states still fall through to the surfaced
    ``Unknown`` rather than being swallowed by the default arm.

    Returns an empty map when no ``IntervalDispatcher`` (or its rows) is
    available, so callers fall back to the single-interval source.
    """
    rows = getattr(dispatcher, "_rows", None)
    if not rows:
        return {}
    default_target = getattr(dispatcher, "default_target", None)
    per_target: dict[int, list[Interval]] = {}
    for row in rows:
        target = getattr(row, "target", None)
        if target is None or target == default_target:
            continue
        # ``IntervalRow`` uses an EXCLUSIVE hi; ``Interval`` is inclusive.
        per_target.setdefault(int(target), []).append(
            Interval(int(row.lo), int(row.hi) - 1)
        )
    return {
        target: IntervalSet(_STATE_WIDTH, ivs) for target, ivs in per_target.items()
    }


def _target_intervals_from_decision_dag(dag: object) -> "dict[int, IntervalSet]":
    """Per-leaf :class:`IntervalSet` partition from a :class:`DecisionDag`.

    ``DecisionDag.resolve_paths`` partitions the whole state space into disjoint
    ``(domain, target)`` cells with per-comparison signedness handled correctly
    (the sign-bit-XOR reduction in ``route_predicate.satisfying_set``). This is
    the complete, signed-correct routing substrate -- unlike the legacy unsigned
    :class:`IntervalDispatcher`, which is blind to signed (``jle``/``jg``) BSTs.
    """
    partition: dict[int, IntervalSet] = {}
    for cell in dag.resolve_paths():
        h = int(cell.target)
        partition[h] = partition.get(h, IntervalSet.empty(_STATE_WIDTH)).union(
            cell.domain
        )
    return partition


def _build_target_intervals(bst_evidence: object | None) -> "dict[int, IntervalSet]":
    """Complete per-handler partition for the :class:`ComparisonDispatcherModel`.

    Prefers the signedness-aware :class:`DecisionDag` (``route_predicate``
    :class:`IntervalSet`) when the recovery attached one with comparison nodes;
    falls back to the legacy unsigned :class:`IntervalDispatcher`
    (``bst_evidence.dispatcher``) only when no decision-DAG is available.
    """
    dag = getattr(bst_evidence, "decision_dag", None)
    if dag is not None and getattr(dag, "nodes", None):
        return _target_intervals_from_decision_dag(dag)
    return build_partition_from_dispatcher(getattr(bst_evidence, "dispatcher", None))


def _range_to_intervals(
    lo: Optional[int], hi: Optional[int]
) -> "list[Interval]":
    """Lower one ``(lo, hi)`` handler-range row to closed :class:`Interval`s.

    Preserves the exact semantics of the retired ``route_comparison_target``
    body: a two-sided range wider than the ``>= 0xFFFF0000`` degenerate span is
    the catch-all arm (dropped); a one-sided bound (``lo``/``hi`` ``None``) is
    the half-line ``>= lo`` / ``<= hi`` over ``[0, 2**32)``; ``(None, None)``
    matches nothing.
    """
    if lo is not None and hi is not None:
        if (hi - lo) >= _DEGENERATE_RANGE_SPAN:
            return []
        return [Interval(int(lo), int(hi))]
    top = (1 << _STATE_WIDTH) - 1
    if lo is not None:
        return [Interval(int(lo), top)]
    if hi is not None:
        return [Interval(0, int(hi))]
    return []


def intervals_from_range_map(
    handler_range_map: Mapping[int, tuple[Optional[int], Optional[int]]] | None,
) -> "dict[int, IntervalSet]":
    """Adapt a single-``(lo, hi)``-per-handler range map to the IntervalSet domain.

    The lossy fallback source: callers that only carry the legacy
    ``handler_range_map`` (no full :class:`IntervalDispatcher`) get one
    :class:`IntervalSet` per handler so they route through the SAME
    abstract-domain path as :func:`route_via_interval_sets`.
    """
    out: dict[int, IntervalSet] = {}
    for handler_serial, (lo, hi) in (handler_range_map or {}).items():
        ivs = _range_to_intervals(lo, hi)
        if ivs:
            out[int(handler_serial)] = IntervalSet(_STATE_WIDTH, ivs)
    return out


def build_partition(
    state_to_handler: Mapping[int, int],
    range_intervals: Mapping[int, IntervalSet] | None = None,
) -> "dict[int, IntervalSet]":
    """Build the complete, disjoint per-handler :class:`IntervalSet` partition.

    The single source of truth for routing: EVERY handler -- exact and ranged --
    is one :class:`IntervalSet`, so a concrete state is resolved by membership
    alone (there is no separate exact ``dict.get`` resolution path).

    * each exact row ``state -> handler`` contributes the singleton ``{state}``;
    * each range handler (one NOT already claimed by an exact row -- mirrors the
      legacy ``skip-exact-claimed`` guard) contributes its ranges MINUS every
      exact state, so an exact state always wins over an overlapping range
      (the membership equivalent of "exact first").
    """
    mask = (1 << _STATE_WIDTH) - 1
    exact_states = IntervalSet(
        _STATE_WIDTH,
        [Interval(int(s) & mask, int(s) & mask) for s in state_to_handler],
    )
    partition: dict[int, IntervalSet] = {}
    for state, handler in state_to_handler.items():
        singleton = IntervalSet(_STATE_WIDTH, [Interval(int(state) & mask, int(state) & mask)])
        h = int(handler)
        partition[h] = partition.get(h, IntervalSet.empty(_STATE_WIDTH)).union(singleton)
    exact_handlers = {int(h) for h in state_to_handler.values()}
    for handler, iset in (range_intervals or {}).items():
        h = int(handler)
        if h in exact_handlers:
            continue  # exact-claimed: routes via its exact rows only
        net = iset.difference(exact_states)  # exact states win over the range
        if not net.is_empty():
            partition[h] = partition.get(h, IntervalSet.empty(_STATE_WIDTH)).union(net)
    return partition


def route_via_interval_sets(
    value: int,
    *,
    target_intervals: Mapping[int, IntervalSet],
    default_target_block: Optional[int] = None,
) -> Optional[int]:
    """The single dispatcher-routing implementation: abstract-domain membership.

    Routes a concrete state ``value`` to its handler serial purely by
    :class:`IntervalSet` membership over the complete partition
    (:func:`build_partition` -- exact singletons AND ranges, so there is no
    separate ``dict.get`` resolution path), falling through to the default arm
    (or ``None`` -- the surfaced gap) on a miss.  THE one way to route.
    """
    v = int(value) & _U64_MASK
    for handler_serial, iset in target_intervals.items():
        if iset.contains(v):
            return int(handler_serial)
    if default_target_block is not None:
        return int(default_target_block)
    return None


@dataclass(frozen=True, slots=True)
class ComparisonDispatcherModel:
    """One ``route`` body shared by the four comparison dispatcher kinds.

    Args:
        dispatch_map: exact ``state_const -> handler`` rows (the substance kept
            from :class:`StateDispatcherMap`).
        handler_range_map: optional ``handler_serial -> (lo, hi)`` inclusive
            interval rows (the BST/interval evidence).  Mirrors
            ``BSTAnalysisResult.handler_range_map``.
        default_target_block: optional catch-all handler when nothing else
            matches (the dispatcher's default arm).
        block_ea: optional ``serial -> start_ea`` so :class:`Block` route results
            carry their EA (standing rule).
    """

    dispatch_map: StateDispatcherMap
    handler_range_map: Mapping[int, tuple[Optional[int], Optional[int]]] = field(
        default_factory=dict
    )
    default_target_block: Optional[int] = None
    block_ea: Mapping[int, int] = field(default_factory=dict)
    #: Abstract-domain routing substrate: each handler -> the EXACT disjoint
    #: union of every interval that routes to it (an
    #: :class:`d810.analyses.control_flow.route_predicate.IntervalSet`).  This
    #: replaces the lossy one-``(lo, hi)``-per-handler ``handler_range_map``,
    #: which silently drops the extra ranges of a multi-interval (split-range)
    #: handler.  When populated, :meth:`route_one` routes through it (complete);
    #: otherwise it falls back to ``handler_range_map`` (single-interval).
    target_intervals: Mapping[int, IntervalSet] = field(default_factory=dict)
    #: Lazily-built cache of the complete exact-singleton ∪ range partition
    #: (see :meth:`_partition`); not part of identity/equality.
    _partition_cache: "Optional[Mapping[int, IntervalSet]]" = field(
        default=None, init=False, compare=False, repr=False
    )

    # -- DispatcherModel metadata (Protocol surface) -----------------------
    def state_var(self) -> int | None:
        return self.dispatch_map.state_var_stkoff

    @property
    def entry(self) -> int | None:
        return self.dispatch_map.dispatcher_entry_block

    def is_dispatcher(self, block_serial: int) -> bool:
        return int(block_serial) in self.dispatch_map.dispatcher_blocks

    def region(self) -> frozenset[int]:
        return frozenset(self.dispatch_map.dispatcher_blocks)

    # -- the consolidated route --------------------------------------------
    def _block(self, serial: int) -> Block:
        ea = self.block_ea.get(int(serial))
        return Block(int(serial), None if ea is None else int(ea))

    def route_one(self, value: int) -> RouteResult:
        """Route a single concrete state ``value`` -> :class:`RouteResult`.

        Routing order is exact -> interval -> default, lifting the result: a
        target serial -> :class:`Block` (with EA when known); a miss ->
        :class:`Unknown` (the explicit, surfaced gap that S2 substitutes for the
        silently dropped edge).  The interval step routes through the
        abstract-domain :class:`IntervalSet` in :attr:`target_intervals` (the
        complete disjoint union per handler) when populated, so multi-interval
        (split-range) handlers resolve every range -- not just the single
        ``(lo, hi)`` the lossy ``handler_range_map`` retained.
        """
        target = self._route_target(value)
        if target is None:
            return Unknown("state_not_in_dispatcher_map")
        return self._block(target)

    def _route_target(self, value: int) -> Optional[int]:
        """Resolve *value* to a handler serial (or ``None`` for the surfaced gap).

        Pure :class:`IntervalSet` membership over the complete partition
        (exact singletons AND ranges, :func:`build_partition`) -- the one routing
        mechanism, with no separate exact ``dict.get`` path.
        """
        return route_via_interval_sets(
            value,
            target_intervals=self._partition(),
            default_target_block=self.default_target_block,
        )

    def _partition(self) -> Mapping[int, IntervalSet]:
        """The complete exact-singleton ∪ range partition (built lazily, cached)."""
        cached = self._partition_cache
        if cached is not None:
            return cached
        range_intervals = self.target_intervals or intervals_from_range_map(
            self.handler_range_map
        )
        partition = build_partition(
            self.dispatch_map.state_to_handler(), range_intervals
        )
        object.__setattr__(self, "_partition_cache", partition)
        return partition

    def route(self, value: int) -> RouteResult:
        """Public Protocol entry point (single concrete value -> route)."""
        return self.route_one(value)

    def resolve_target(self, state_value: int) -> Optional[int]:
        """DEPRECATED exact-unwrap shim: route then unwrap a :class:`Block`."""
        rr = self.route_one(int(state_value))
        return rr.serial if isinstance(rr, Block) else None

    # -- constructors -------------------------------------------------------
    @classmethod
    def from_recovery(
        cls,
        dispatch_map: StateDispatcherMap,
        *,
        bst_evidence: object | None = None,
        block_ea: Mapping[int, int] | None = None,
    ) -> "ComparisonDispatcherModel":
        """Build from a :class:`StateDispatcherMap` plus optional BST/interval evidence.

        ``bst_evidence`` is duck-typed on ``BSTAnalysisResult`` (``handler_range_map``
        / ``default_block_serial``) so this stays portable (no live-IDA import).
        Absent the evidence the model is exact-only — byte-identical to the old
        ``resolve_target`` behaviour, so legacy callers see no change.
        """
        handler_range_map: Mapping[int, tuple[Optional[int], Optional[int]]] = (
            getattr(bst_evidence, "handler_range_map", None) or {}
        )
        default_target = (
            getattr(bst_evidence, "default_block_serial", None)
            if bst_evidence is not None
            else dispatch_map.default_target_block
        )
        return cls(
            dispatch_map=dispatch_map,
            handler_range_map=dict(handler_range_map),
            default_target_block=default_target,
            block_ea=dict(block_ea or {}),
            target_intervals=_build_target_intervals(bst_evidence),
        )
