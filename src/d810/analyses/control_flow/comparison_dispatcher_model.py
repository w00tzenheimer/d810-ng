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

from d810.analyses.abstract_domains.wrapped_interval import WrappedInterval
from d810.analyses.data_flow.abstract_value import Block, RouteResult, Unknown

if TYPE_CHECKING:
    # Annotation-only: importing it at runtime would cycle with
    # ``dispatcher_resolution`` (which imports the route helper below).  The
    # model reads ``StateDispatcherMap`` purely structurally
    # (``state_to_handler`` / ``state_var_stkoff`` / ``dispatcher_*``).
    from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap

__all__ = ["ComparisonDispatcherModel", "route_comparison_target"]

#: The degenerate "range covers (almost) the whole word" guard, copied from
#: ``bst_model.resolve_target_via_bst``: a span this wide is the dispatcher's
#: default/catch-all interval, not a real handler range.
_DEGENERATE_RANGE_SPAN = 0xFFFF0000

#: Mask state values to the 64-bit word the rows are stored in.
_U64_MASK = 0xFFFFFFFFFFFFFFFF


def _interval(lo: Optional[int], hi: Optional[int]) -> WrappedInterval | None:
    """A 64-bit :class:`WrappedInterval` for a two-sided inclusive ``[lo, hi]``."""
    if lo is None or hi is None:
        return None
    return WrappedInterval(64, int(lo) & _U64_MASK, int(hi) & _U64_MASK, "range")


def _bound_contains(lo: Optional[int], hi: Optional[int], v: int) -> bool:
    """One-sided membership matching ``resolve_target_via_bst`` (``< lo`` / ``> hi``)."""
    if lo is None and hi is None:
        return False
    if lo is not None and v < lo:
        return False
    if hi is not None and v > hi:
        return False
    return True


def route_comparison_target(
    value: int,
    *,
    state_to_handler: Mapping[int, int],
    handler_range_map: Mapping[int, tuple[Optional[int], Optional[int]]] | None = None,
    default_target_block: Optional[int] = None,
) -> Optional[int]:
    """Pure comparison-dispatcher routing (exact -> interval -> default), no ADT.

    The shared substance both :class:`ComparisonDispatcherModel` and the
    deprecated :meth:`StateDispatcherMap.resolve_target` delegate to, so the two
    can never diverge again.  Returns the target block serial or ``None``.
    Mirrors :func:`d810.analyses.control_flow.bst_model.resolve_target_via_bst`:
    exact map first, then ``handler_range_map`` lo/hi (skipping the degenerate
    ``>= 0xFFFF0000`` catch-all span and rows already claimed exactly), then the
    default arm.
    """
    v = int(value) & _U64_MASK
    exact = state_to_handler.get(v)
    if exact is not None:
        return int(exact)
    exact_handlers = set(state_to_handler.values())
    for handler_serial, (lo, hi) in (handler_range_map or {}).items():
        if int(handler_serial) in exact_handlers:
            continue
        if lo is not None and hi is not None and (hi - lo) >= _DEGENERATE_RANGE_SPAN:
            continue
        wi = _interval(lo, hi)
        if wi is not None and wi.contains(v):
            return int(handler_serial)
        if wi is None and _bound_contains(lo, hi, v):
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

        Delegates to :func:`route_comparison_target` (exact -> interval -> default)
        and lifts the result: a target serial -> :class:`Block` (with EA when
        known); a miss -> :class:`Unknown` (the explicit, surfaced gap that S2
        substitutes for the silently dropped edge).
        """
        target = route_comparison_target(
            value,
            state_to_handler=self.dispatch_map.state_to_handler(),
            handler_range_map=self.handler_range_map,
            default_target_block=self.default_target_block,
        )
        if target is None:
            return Unknown("state_not_in_dispatcher_map")
        return self._block(target)

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
        )
