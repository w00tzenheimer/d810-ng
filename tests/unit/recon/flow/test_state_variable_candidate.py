"""Unit cover for ``StateVariableCandidate`` (E3-schema).

Pure-Python tests -- ``StateVariableCandidate`` now lives in
``d810.analyses.control_flow.dispatcher_facts`` with portable ``MopSnapshot``
instead of live ``ida_hexrays.mop_t``.

These tests don't import ``d810.hexrays.*`` -- the
``unit-tests-no-hexrays`` import-linter contract forbids that for
``tests/unit/``.
"""

from __future__ import annotations

from d810.ir.flowgraph import MopSnapshot, OperandKind
from d810.analyses.control_flow.dispatcher_facts import StateVariableCandidate


class TestStateVariableCandidateConstruction:
    """Constructor accepts a portable ``MopSnapshot`` -- not a live
    ``ida_hexrays.mop_t`` -- as the operand identity."""

    def test_stack_candidate_holds_portable_snapshot(self) -> None:
        snap = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        cand = StateVariableCandidate(
            mop=snap, mop_type=4, mop_offset=0x40, mop_size=4
        )
        assert cand.mop is snap
        assert cand.mop.kind is OperandKind.STACK
        assert cand.mop.stkoff == 0x40

    def test_register_candidate_holds_portable_snapshot(self) -> None:
        snap = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        cand = StateVariableCandidate(
            mop=snap, mop_type=2, mop_offset=3, mop_size=4
        )
        assert cand.mop.kind is OperandKind.REGISTER
        assert cand.mop.reg == 3

    def test_default_field_values(self) -> None:
        """Backward-compat default values pin the contract for
        existing consumers (init_value=None, score=0.0,
        empty collections)."""
        snap = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        cand = StateVariableCandidate(mop=snap)
        assert cand.mop_type == 0
        assert cand.mop_offset == 0
        assert cand.mop_size == 4
        assert cand.init_value is None
        assert cand.comparison_count == 0
        assert cand.assignment_count == 0
        assert cand.unique_constants == set()
        assert cand.comparison_blocks == []
        assert cand.assignment_blocks == []
        assert cand.score == 0.0


class TestGetNativeStackOffset:
    """``get_native_stack_offset`` keys off ``OperandKind.STACK``,
    NOT a vendor ``mop_S`` integer.  This is the visible portability
    change in the method body."""

    def test_stack_kind_returns_negated_display_offset(self) -> None:
        """Native offset = -(frame_size - stkoff).  Mirrors the
        legacy live-IDA implementation."""
        snap = MopSnapshot(t=4, size=4, stkoff=0x40, kind=OperandKind.STACK)
        cand = StateVariableCandidate(mop=snap)
        # frame_size=0x80 -> display=0x80-0x40=0x40 -> native=-0x40
        assert cand.get_native_stack_offset(frame_size=0x80) == -0x40

    def test_register_kind_returns_none(self) -> None:
        snap = MopSnapshot(t=2, size=4, reg=3, kind=OperandKind.REGISTER)
        cand = StateVariableCandidate(mop=snap)
        assert cand.get_native_stack_offset(frame_size=0x80) is None

    def test_global_kind_returns_none(self) -> None:
        snap = MopSnapshot(
            t=8, size=8, gaddr=0x140002000, kind=OperandKind.GLOBAL
        )
        cand = StateVariableCandidate(mop=snap)
        assert cand.get_native_stack_offset(frame_size=0x80) is None

    def test_stack_kind_without_stkoff_returns_none(self) -> None:
        """Defensive: if the snapshot has ``STACK`` kind but
        ``stkoff`` was never populated (a buggy lifter would have
        to do this), the method returns ``None`` rather than
        computing nonsense."""
        snap = MopSnapshot(t=4, size=4, kind=OperandKind.STACK)
        cand = StateVariableCandidate(mop=snap)
        assert cand.get_native_stack_offset(frame_size=0x80) is None

    def test_native_offset_at_frame_top(self) -> None:
        """Sanity check: a stkoff equal to the frame size lands at
        offset 0 from the frame base."""
        snap = MopSnapshot(t=4, size=4, stkoff=0x100, kind=OperandKind.STACK)
        cand = StateVariableCandidate(mop=snap)
        assert cand.get_native_stack_offset(frame_size=0x100) == 0


class TestPureModuleBoundary:
    """``dispatcher_facts`` is the pure home: importing
    ``StateVariableCandidate`` MUST NOT pull in ``d810.hexrays.*``.
    The architectural pin lives here -- if a future edit
    re-introduces a live ``mop_t`` field annotation or an
    ``ida_hexrays`` import, this test fails."""

    def test_dispatcher_facts_has_no_hexrays_imports(self) -> None:
        """Read the module source and assert no hexrays / idaapi
        imports.  String search is sufficient because the contract
        is "the module text mentions no hexrays imports", not "no
        symbol resolution"."""
        import d810.analyses.control_flow.dispatcher_facts as facts_mod
        import inspect

        src = inspect.getsource(facts_mod)
        # Forbidden import shapes.
        assert "import ida_hexrays" not in src, (
            "dispatcher_facts must not import ida_hexrays -- it is "
            "the pure home for StateVariableCandidate"
        )
        assert "import idaapi" not in src
        assert "from d810.hexrays" not in src
        # Allowed: pure flowgraph snapshot symbols only. Post-dissolution the
        # canonical pure home is ``d810.ir.flowgraph`` (the cfg.flowgraph path
        # is a migration shim onto it).
        assert (
            "from d810.ir.flowgraph import" in src
            or "from d810.ir.flowgraph import" in src
        )
