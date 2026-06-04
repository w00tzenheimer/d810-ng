"""S5a isolation tests: ``explore()`` over the validated sub_7FFD corpus.

No IDA: a fake ``model`` (``route`` delegates to ``route_via_interval_sets`` over
the sub_7FFD routing — exact ∪ interval) and a fake ``resolve_state`` (returns
the solved next-states) are injected, so the verb is exercised as a pure
function.  The asserted edge set is the sub_7FFD corpus:

* ``resolve_state(blk195) -> Const(0x41FB8FBB)``; ``route -> Block(90)``
  (exact row) -> edge **195 -> 90**.
* a producer of ``0x1864829A`` -> routes via the interval rows to **152**
  (entry intervals ``[0x149f5a99..0x16f7ff74] ∪ [..0x1a9a9dd9]``; 0x1864829A is
  interior) -> edge **<h> -> 152**.
* ``resolve_state(blk152) -> Const(0x6D207773)``; ``route -> Block(48)``
  (exact row) -> edge **152 -> 48**.
* an MBA-equation site ``(var_B0 ^ var_A8) - var_A0`` whose fold the resolver
  returns as a ``Const`` -> ``explore`` routes the folded value.
* a shared ``OneOf{0x41FB8FBB, 0x71E22BF3}`` sink -> BOTH edges emitted
  (to 90 and to the 0x71E22BF3 handler).
* ``⊤`` -> one ``UNRESOLVED`` edge (no invented target).
* ``Guarded[(g, c)]`` -> the emitted edge carries the guard ``g``.
"""
from __future__ import annotations

from d810.analyses.control_flow.comparison_dispatcher_model import (
    build_partition,
    intervals_from_range_map,
    route_via_interval_sets,
)
from d810.analyses.control_flow.explore import (
    Resolution,
    StateTransitionEdge,
    StateTransitionView,
    WriteSite,
    explore,
)
from d810.analyses.data_flow.abstract_value import (
    TOP,
    Block,
    Const,
    Guarded,
    OneOf,
    RouteOneOf,
    Unknown,
)

# --- the validated sub_7FFD routing corpus --------------------------------
#
# Exact rows (state_const -> handler block serial) and interval rows
# (handler_serial -> [lo, hi]) drawn from the recovered sub_7FFD dispatcher.

_U64_MASK = 0xFFFFFFFFFFFFFFFF

# State constants and their concrete next-state handler block serials.
_STATE_41FB = 0x41FB8FBB  # blk195's next-state; exact -> block 90
_BLK90 = 90
_BLK90_EA = 0x180014D34

_STATE_6D20 = 0x6D207773  # blk152's next-state; exact -> block 48
_BLK48 = 48
_BLK48_EA = 0x18001443D

_STATE_71E2 = 0x71E22BF3  # shared sink peer; exact -> handler block 39
_BLK39 = 39
_BLK39_EA = 0x180014255

# Interval-routed: 0x1864829A is interior to block 152's entry interval(s).
_STATE_1864 = 0x1864829A
_BLK152 = 152
_BLK152_EA = 0x180016512
_BLK152_LO, _BLK152_HI = 0x149F5A99, 0x1A9A9DD9  # spanning union -> [lo..hi]

# Exact dispatcher rows.
_EXACT = {
    _STATE_41FB: _BLK90,
    _STATE_6D20: _BLK48,
    _STATE_71E2: _BLK39,
}
# Interval rows: handler 152 covers the 0x1864829A interior value.
_RANGES = {_BLK152: (_BLK152_LO, _BLK152_HI)}
_BLOCK_EA = {
    _BLK90: _BLK90_EA,
    _BLK48: _BLK48_EA,
    _BLK39: _BLK39_EA,
    _BLK152: _BLK152_EA,
}


class _FakeModel:
    """A fake :class:`DispatcherModel`: ``route`` via ``route_via_interval_sets``.

    Routes exact-first then by interval over the sub_7FFD corpus and lifts the
    target serial to a :class:`Block` (carrying its EA), matching
    :class:`ComparisonDispatcherModel.route` without importing the live recovery.
    """

    def route(self, value: int) -> Block | Unknown:
        target = route_via_interval_sets(
            value,
            target_intervals=build_partition(_EXACT, intervals_from_range_map(_RANGES)),
        )
        if target is None:
            return Unknown("state_not_in_dispatcher_map")
        return Block(int(target), _BLOCK_EA.get(int(target)))


def _resolver(table):
    """Build a fake ``resolve_state`` from a ``{(state_var, site): AbstractValue}``."""

    def resolve_state(state_var, site):
        return table[(state_var, site)]

    return resolve_state


def _site(from_handler, state_var, site, from_ea=None) -> WriteSite:
    return WriteSite(
        from_handler=from_handler, state_var=state_var, site=site, from_ea=from_ea
    )


# --- corpus edge assertions ------------------------------------------------


def test_blk195_const_routes_exact_to_90():
    # resolve_state(blk195) -> Const(0x41FB8FBB); route -> Block(90); 195 -> 90.
    sv, st = "s", "blk195"
    view = explore(
        [_site(195, sv, st)],
        model=_FakeModel(),
        resolve_state=_resolver({(sv, st): Const(_STATE_41FB, 4)}),
    )
    assert isinstance(view, StateTransitionView)
    assert len(view.resolved) == 1 and not view.unresolved
    edge = view.resolved[0]
    assert edge.from_serial == 195 and edge.to_serial == _BLK90
    assert edge.resolution is Resolution.RESOLVED
    assert edge.to_ea == _BLK90_EA  # standing rule: serial carries EA


def test_interval_routed_const_reaches_152():
    # producer of 0x1864829A -> interval rows route to block 152 (interior).
    sv, st = "s", "blk_producer_1864"
    view = explore(
        [_site(80, sv, st)],
        model=_FakeModel(),
        resolve_state=_resolver({(sv, st): Const(_STATE_1864, 4)}),
    )
    assert len(view.resolved) == 1
    edge = view.resolved[0]
    assert edge.from_serial == 80 and edge.to_serial == _BLK152
    assert _BLK152_LO <= _STATE_1864 <= _BLK152_HI  # interior, not exact
    assert edge.resolution is Resolution.RESOLVED


def test_blk152_const_routes_exact_to_48():
    # resolve_state(blk152) -> Const(0x6D207773); route -> Block(48); 152 -> 48.
    sv, st = "s", "blk152"
    view = explore(
        [_site(152, sv, st)],
        model=_FakeModel(),
        resolve_state=_resolver({(sv, st): Const(_STATE_6D20, 4)}),
    )
    assert len(view.resolved) == 1
    edge = view.resolved[0]
    assert edge.from_serial == 152 and edge.to_serial == _BLK48


def test_mba_equation_site_routes_the_folded_value():
    # blk10 shape (var_B0 ^ var_A8) - var_A0; the resolver returns the fold.
    var_b0, var_a8, var_a0 = 0x55AA55AA, 0x12345678, 0x0000FFFF
    folded = ((var_b0 ^ var_a8) - var_a0) & _U64_MASK
    sv, st = "s", "blk10"
    # Point the corpus's exact map at the folded value so we assert the routed
    # target IS the fold (not some accidental constant).
    target_for_fold = 77
    model = _FakeModelWith({folded: target_for_fold}, ea={target_for_fold: 0x180010A00})
    view = explore(
        [_site(10, sv, st)],
        model=model,
        resolve_state=_resolver({(sv, st): Const(folded, 8)}),
    )
    assert len(view.resolved) == 1
    edge = view.resolved[0]
    assert edge.from_serial == 10 and edge.to_serial == target_for_fold


def test_shared_oneof_sink_emits_both_edges():
    # OneOf{0x41FB8FBB, 0x71E22BF3} (shared i=v15 sink) -> BOTH edges.
    sv, st = "s", "shared_sink"
    view = explore(
        [_site(60, sv, st)],
        model=_FakeModel(),
        resolve_state=_resolver(
            {(sv, st): OneOf.of([_STATE_41FB, _STATE_71E2])}
        ),
    )
    assert len(view.resolved) == 2 and not view.unresolved
    targets = {e.to_serial for e in view.resolved}
    assert targets == {_BLK90, _BLK39}  # to 90 and to handler(0x71E22BF3)
    assert all(e.from_serial == 60 for e in view.resolved)


def test_top_emits_one_unresolved_edge_no_invented_target():
    sv, st = "s", "unknown_write"
    view = explore(
        [_site(99, sv, st)],
        model=_FakeModel(),
        resolve_state=_resolver({(sv, st): TOP}),
    )
    assert not view.resolved and len(view.unresolved) == 1
    edge = view.unresolved[0]
    assert edge.from_serial == 99
    assert edge.resolution is Resolution.UNRESOLVED
    assert edge.reason == "top_unresolved_state"
    assert edge.to_serial == -1  # no invented target


def test_guarded_case_carries_the_guard():
    sv, st = "s", "guarded_write"
    guard = object()
    view = explore(
        [_site(120, sv, st)],
        model=_FakeModel(),
        resolve_state=_resolver(
            {(sv, st): Guarded(((guard, Const(_STATE_41FB, 4)),))}
        ),
    )
    assert len(view.resolved) == 1
    edge = view.resolved[0]
    assert edge.guard is guard
    assert edge.to_serial == _BLK90


def test_route_unknown_surfaces_reason_as_unresolved_edge():
    # A const not in any row -> the model's Unknown is surfaced, not dropped.
    sv, st = "s", "orphan_state"
    view = explore(
        [_site(42, sv, st)],
        model=_FakeModel(),
        resolve_state=_resolver({(sv, st): Const(0xDEADBEEF, 4)}),
    )
    assert not view.resolved and len(view.unresolved) == 1
    assert view.unresolved[0].reason == "state_not_in_dispatcher_map"


def test_route_oneof_fans_out_to_every_target():
    # A RouteOneOf route result emits one edge per fan-out Block.
    sv, st = "s", "fanout"

    class _FanModel:
        def route(self, value):
            return RouteOneOf((Block(_BLK90, _BLK90_EA), Block(_BLK48, _BLK48_EA)))

    view = explore(
        [_site(7, sv, st)],
        model=_FanModel(),
        resolve_state=_resolver({(sv, st): Const(0x1, 4)}),
    )
    assert len(view.resolved) == 2
    assert {e.to_serial for e in view.resolved} == {_BLK90, _BLK48}


def test_full_corpus_edge_set_in_one_pass():
    # All sites together: the union edge set is exactly the corpus.
    sv = "s"
    sites = [
        _site(195, sv, "blk195"),
        _site(152, sv, "blk152"),
        _site(80, sv, "blk_producer_1864"),
        _site(60, sv, "shared_sink"),
        _site(99, sv, "unknown_write"),
    ]
    table = {
        (sv, "blk195"): Const(_STATE_41FB, 4),
        (sv, "blk152"): Const(_STATE_6D20, 4),
        (sv, "blk_producer_1864"): Const(_STATE_1864, 4),
        (sv, "shared_sink"): OneOf.of([_STATE_41FB, _STATE_71E2]),
        (sv, "unknown_write"): TOP,
    }
    view = explore([*sites], model=_FakeModel(), resolve_state=_resolver(table))
    resolved_pairs = {(e.from_serial, e.to_serial) for e in view.resolved}
    assert resolved_pairs == {
        (195, _BLK90),
        (152, _BLK48),
        (80, _BLK152),
        (60, _BLK90),
        (60, _BLK39),
    }
    assert len(view.unresolved) == 1 and view.unresolved[0].from_serial == 99
    # edges() yields the deterministic union (resolved then unresolved).
    assert view.edges() == view.resolved + view.unresolved
    assert all(isinstance(e, StateTransitionEdge) for e in view.edges())


class _FakeModelWith:
    """A fake model with caller-supplied exact rows (for the MBA-fold test)."""

    def __init__(self, exact, *, ea=None):
        self._exact = dict(exact)
        self._ea = dict(ea or {})

    def route(self, value):
        target = self._exact.get(int(value) & _U64_MASK)
        if target is None:
            return Unknown("state_not_in_dispatcher_map")
        return Block(int(target), self._ea.get(int(target)))
