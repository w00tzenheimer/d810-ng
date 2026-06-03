"""S3 unit tests: the ``resolve`` ladder facade (no IDA).

The facade is pure: it walks the injected tier stack cheapest-first and returns
the first non-``⊤`` answer, escalating on ``⊤`` (or an empty ``OneOf`` = ``⊥``).
The IDA-coupled tiers (T1 local fold, T3 escalation) are injected as callables,
so these tests drive deterministic stubs and exercise the orchestration only.
The T2 stub projects a real :class:`StateValue`, proving the value-set tier's
``Const | OneOf | Top`` projection flows through unchanged.
"""
from __future__ import annotations

from d810.analyses.control_flow.state_transition_domain import StateValue
from d810.analyses.data_flow import (
    TOP,
    Const,
    OneOf,
    ResolveContext,
    ResolvePoint,
    resolve,
)

_VAR = ("S", 0x64)  # opaque var token (stack offset) — facade never reads it
_PT = ResolvePoint(serial=52, ea=0x18001450D)


def _const_tier(value: int):
    return lambda var, point: Const(value, 4)


def _top_tier():
    return lambda var, point: TOP


def _record_tier(value, log: list[str], name: str):
    def tier(var, point):
        log.append(name)
        return value

    return tier


# --- ResolvePoint carries EA (standing rule) -------------------------------


def test_resolve_point_repr_carries_ea():
    assert repr(ResolvePoint(52, 0x18001450D)) == "ResolvePoint(52@0x18001450d)"
    assert repr(ResolvePoint(52)) == "ResolvePoint(52)"
    assert (
        repr(ResolvePoint(52, 0x1450D, 0x1451A))
        == "ResolvePoint(52@0x1450d#0x1451a)"
    )


# --- tier ordering / short-circuit -----------------------------------------


def test_t1_const_wins_and_short_circuits():
    log: list[str] = []
    ctx = ResolveContext(
        t1_local_fold=_record_tier(Const(0x2A5E29F6, 4), log, "t1"),
        t2_value_set=_record_tier(Const(0xDEAD, 4), log, "t2"),
        t3_escalation=_record_tier(Const(0xBEEF, 4), log, "t3"),
    )
    out = resolve(_VAR, _PT, ctx)
    assert out == Const(0x2A5E29F6, 4)
    assert log == ["t1"]  # later tiers never consulted


def test_t1_escalates_to_t2_value_set():
    log: list[str] = []
    ctx = ResolveContext(
        t1_local_fold=_record_tier(TOP, log, "t1"),
        t2_value_set=_record_tier(OneOf.of([0x10, 0x20]), log, "t2"),
        t3_escalation=_record_tier(Const(0x30, 4), log, "t3"),
    )
    out = resolve(_VAR, _PT, ctx)
    assert out == OneOf.of([0x10, 0x20])
    assert log == ["t1", "t2"]


def test_escalates_through_to_t3():
    log: list[str] = []
    ctx = ResolveContext(
        t1_local_fold=_record_tier(TOP, log, "t1"),
        t2_value_set=_record_tier(TOP, log, "t2"),
        t3_escalation=_record_tier(Const(0x99, 4), log, "t3"),
        t4_guard_solver=_record_tier(Const(0xAA, 4), log, "t4"),
    )
    out = resolve(_VAR, _PT, ctx)
    assert out == Const(0x99, 4)
    assert log == ["t1", "t2", "t3"]


def test_all_tiers_escalate_yields_top():
    log: list[str] = []
    ctx = ResolveContext(
        t1_local_fold=_record_tier(TOP, log, "t1"),
        t2_value_set=_record_tier(TOP, log, "t2"),
        t3_escalation=_record_tier(TOP, log, "t3"),
        t4_guard_solver=_record_tier(TOP, log, "t4"),
    )
    assert resolve(_VAR, _PT, ctx) is TOP
    assert log == ["t1", "t2", "t3", "t4"]


# --- absent tiers skipped ---------------------------------------------------


def test_none_tiers_are_skipped():
    # Only T2 wired; T1/T3/T4 absent -> skipped, not treated as resolved.
    ctx = ResolveContext(t2_value_set=_const_tier(0x7C2C0220))
    assert resolve(_VAR, _PT, ctx) == Const(0x7C2C0220, 4)


def test_empty_context_yields_top():
    assert resolve(_VAR, _PT, ResolveContext()) is TOP


# --- empty OneOf (⊥ projection) escalates -----------------------------------


def test_empty_oneof_escalates_like_top():
    log: list[str] = []
    ctx = ResolveContext(
        t1_local_fold=_record_tier(OneOf.of([]), log, "t1"),
        t2_value_set=_record_tier(Const(0x55, 4), log, "t2"),
    )
    out = resolve(_VAR, _PT, ctx)
    assert out == Const(0x55, 4)
    assert log == ["t1", "t2"]


def test_empty_oneof_only_yields_top():
    ctx = ResolveContext(t1_local_fold=lambda v, p: OneOf.of([]))
    assert resolve(_VAR, _PT, ctx) is TOP


# --- T2 StateValue projection flows through unchanged ------------------------


def test_t2_projects_state_value_singleton_to_const():
    # A T2 tier backed by the real StateValue.project(): singleton -> Const.
    def t2(var, point):
        return StateValue.of(0x79F598F7).project()

    out = resolve(_VAR, _PT, ResolveContext(t2_value_set=t2))
    assert out == Const(0x79F598F7, StateValue._PROJECT_CONST_SIZE)


def test_t2_projects_state_value_powerset_to_oneof():
    def t2(var, point):
        return StateValue.of_many([0x10, 0x20, 0x30]).project()

    out = resolve(_VAR, _PT, ResolveContext(t2_value_set=t2))
    assert isinstance(out, OneOf)
    assert out.values == frozenset({0x10, 0x20, 0x30})


def test_t2_projects_state_value_top_escalates():
    log: list[str] = []

    def t2(var, point):
        log.append("t2")
        return StateValue.top().project()  # ⊤

    def t3(var, point):
        log.append("t3")
        return Const(0x1, 4)

    ctx = ResolveContext(t2_value_set=t2, t3_escalation=t3)
    assert resolve(_VAR, _PT, ctx) == Const(0x1, 4)
    assert log == ["t2", "t3"]


def test_t2_projects_state_value_bottom_escalates():
    # ⊥ projects to an empty OneOf -> escalation (cannot route nothing).
    log: list[str] = []

    def t2(var, point):
        log.append("t2")
        return StateValue.bottom().project()  # empty OneOf

    ctx = ResolveContext(
        t2_value_set=t2,
        t3_escalation=_record_tier(Const(0x2, 4), log, "t3"),
    )
    assert resolve(_VAR, _PT, ctx) == Const(0x2, 4)
    assert log == ["t2", "t3"]
