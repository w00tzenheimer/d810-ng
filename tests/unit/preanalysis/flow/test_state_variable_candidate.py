"""Unit cover for ``StateVariableCandidate`` (E3-schema).

Pure-Python tests -- ``StateVariableCandidate`` now lives in
``d810.analyses.control_flow.dispatcher_facts`` and carries a portable
``StorageIdentity`` (size-agnostic ``(kind, offset)``) as its operand identity,
not a backend operand snapshot or a live ``ida_hexrays.mop_t``.

These tests don't import ``d810.hexrays.*`` -- the
``unit-tests-no-hexrays`` import-linter contract forbids that for
``tests/unit/``.
"""

from __future__ import annotations

from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.analyses.control_flow.dispatcher_facts import StateVariableCandidate


class TestStateVariableCandidateConstruction:
    """Constructor carries a portable ``StorageIdentity`` -- not a live
    ``ida_hexrays.mop_t`` or a backend operand snapshot -- as the operand
    identity."""

    def test_stack_candidate_holds_storage_identity(self) -> None:
        identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
        cand = StateVariableCandidate(
            storage_identity=identity, mop_type=4, mop_offset=0x40, mop_size=4
        )
        assert cand.storage_identity is identity
        assert cand.storage_identity.kind is StorageIdentityKind.STACK
        assert cand.storage_identity.offset == 0x40

    def test_register_candidate_holds_storage_identity(self) -> None:
        identity = StorageIdentity(StorageIdentityKind.REGISTER, 3)
        cand = StateVariableCandidate(
            storage_identity=identity, mop_type=2, mop_offset=3, mop_size=4
        )
        assert cand.storage_identity.kind is StorageIdentityKind.REGISTER
        assert cand.storage_identity.offset == 3

    def test_default_field_values(self) -> None:
        """Backward-compat default values pin the contract for
        existing consumers (init_value=None, score=0.0,
        empty collections)."""
        identity = StorageIdentity(StorageIdentityKind.REGISTER, 3)
        cand = StateVariableCandidate(storage_identity=identity)
        assert cand.storage_identity == StorageIdentity(StorageIdentityKind.REGISTER, 3)
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

    def test_lvar_candidate_holds_storage_identity(self) -> None:
        identity = StorageIdentity(StorageIdentityKind.LVAR, 0x8)
        cand = StateVariableCandidate(storage_identity=identity)
        assert cand.storage_identity.kind is StorageIdentityKind.LVAR
        assert cand.storage_identity.offset == 0x8

    def test_explicit_mirror_fields_are_preserved(self) -> None:
        """The diagnostic mirror fields (``mop_type`` / ``mop_offset`` /
        ``mop_size``) are stored verbatim when supplied by the caller."""
        identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
        cand = StateVariableCandidate(
            storage_identity=identity, mop_type=5, mop_offset=0x40, mop_size=1
        )
        assert cand.mop_type == 5
        assert cand.mop_offset == 0x40
        assert cand.mop_size == 1


class TestGetNativeStackOffset:
    """``get_native_stack_offset`` keys off ``StorageIdentityKind.STACK``,
    NOT a vendor ``mop_S`` integer.  This is the visible portability
    change in the method body."""

    def test_stack_kind_returns_negated_display_offset(self) -> None:
        """Native offset = -(frame_size - stkoff).  Mirrors the
        legacy live-IDA implementation."""
        identity = StorageIdentity(StorageIdentityKind.STACK, 0x40)
        cand = StateVariableCandidate(storage_identity=identity)
        # frame_size=0x80 -> display=0x80-0x40=0x40 -> native=-0x40
        assert cand.get_native_stack_offset(frame_size=0x80) == -0x40

    def test_register_kind_returns_none(self) -> None:
        identity = StorageIdentity(StorageIdentityKind.REGISTER, 3)
        cand = StateVariableCandidate(storage_identity=identity)
        assert cand.get_native_stack_offset(frame_size=0x80) is None

    def test_global_kind_returns_none(self) -> None:
        identity = StorageIdentity(StorageIdentityKind.GLOBAL, 0x140002000)
        cand = StateVariableCandidate(storage_identity=identity)
        assert cand.get_native_stack_offset(frame_size=0x80) is None

    def test_native_offset_at_frame_top(self) -> None:
        """Sanity check: a stkoff equal to the frame size lands at
        offset 0 from the frame base."""
        identity = StorageIdentity(StorageIdentityKind.STACK, 0x100)
        cand = StateVariableCandidate(storage_identity=identity)
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
        # Allowed: pure portable identity symbols only. The state-variable
        # identity is held as ``d810.ir.storage_identity.StorageIdentity``;
        # ``dispatcher_facts`` no longer depends on the operand-snapshot layer.
        assert "from d810.ir.storage_identity import" in src
        assert "MopSnapshot" not in src
