"""System-runtime tests for the Hex-Rays semantic-IR adapter.

Lives in ``tests/system/runtime/`` because the adapter resolves
opcode names to ints via live ``ida_hexrays`` attribute reads; the
``unit-tests-no-hexrays`` import-linter contract forbids
``tests/unit/`` from importing ``d810.hexrays``.  These tests
exercise the *mapping behaviour* of
``classify_branch_predicate`` / ``classify_control_transfer``;
the enum surface itself is unit-tested in
``tests/unit/ir/test_semantics.py``.

Regression-cover for the P1 review finding on commit ``330c03bd1``:
``m_setz`` (byte-materialized predicate) must NOT be classified as
``ControlTransferKind.CONDITIONAL_BRANCH`` -- only ``m_jX`` branch
opcodes are control transfers.  ``classify_branch_predicate``
returns ``PredicateKind.EQ`` for both ``m_jz`` and ``m_setz``
because they share the predicate semantic; only the
``classify_control_transfer`` half discriminates between branch and
materialization.
"""

from __future__ import annotations

import ida_hexrays
import pytest

from d810.hexrays.mutation.ir_translator import (
    classify_branch_predicate,
    classify_call_kind,
    classify_control_transfer,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.semantics import CallKind, ControlTransferKind, PredicateKind


class _StubInsn:
    """Minimal stand-in for ``ida_hexrays.minsn_t`` that only carries
    an opcode int -- enough for the adapter's ``getattr(insn, 'opcode')``
    duck-typing.  Avoids constructing a real microcode instruction
    just to test opcode classification."""

    def __init__(self, opcode: int) -> None:
        self.opcode = int(opcode)


def _required(name: str) -> int:
    """Return the int value of an ``ida_hexrays.m_X`` constant, or
    skip the test if the running Hex-Rays SDK does not expose it.
    Defensive: the adapter is designed to tolerate missing opcode
    names; the tests should not crash if a future SDK drops one."""
    value = getattr(ida_hexrays, name, None)
    if value is None:
        pytest.skip(f"ida_hexrays.{name} not present in this SDK")
    return int(value)


# ---------------------------------------------------------------------------
# classify_branch_predicate
# ---------------------------------------------------------------------------


class TestClassifyBranchPredicate:
    """Branch + set opcodes both produce a portable ``PredicateKind``."""

    @pytest.mark.parametrize(
        ("opcode_name", "expected"),
        [
            # Conditional branches
            ("m_jz", PredicateKind.EQ),
            ("m_jnz", PredicateKind.NE),
            ("m_jae", PredicateKind.UGE),
            ("m_ja", PredicateKind.UGT),
            ("m_jbe", PredicateKind.ULE),
            ("m_jb", PredicateKind.ULT),
            ("m_jge", PredicateKind.SGE),
            ("m_jg", PredicateKind.SGT),
            ("m_jle", PredicateKind.SLE),
            ("m_jl", PredicateKind.SLT),
            ("m_jcnd", PredicateKind.TRUTHY),
            # Byte-materialized predicates ("set*") share the
            # predicate semantic; only the transfer-kind dispatch
            # discriminates.  This is the P1 regression cover.
            ("m_setz", PredicateKind.EQ),
            ("m_setnz", PredicateKind.NE),
            ("m_setae", PredicateKind.UGE),
            ("m_seta", PredicateKind.UGT),
            ("m_setbe", PredicateKind.ULE),
            ("m_setb", PredicateKind.ULT),
            ("m_setge", PredicateKind.SGE),
            ("m_setg", PredicateKind.SGT),
            ("m_setle", PredicateKind.SLE),
            ("m_setl", PredicateKind.SLT),
        ],
    )
    def test_predicate_mapping(self, opcode_name: str, expected: PredicateKind) -> None:
        insn = _StubInsn(_required(opcode_name))
        assert classify_branch_predicate(insn) is expected

    @pytest.mark.parametrize("opcode_name", ["m_goto", "m_call", "m_icall", "m_ret", "m_mov", "m_add"])
    def test_non_predicate_opcodes_return_none(self, opcode_name: str) -> None:
        """Non-predicate opcodes carry no PredicateKind."""
        insn = _StubInsn(_required(opcode_name))
        assert classify_branch_predicate(insn) is None


# ---------------------------------------------------------------------------
# classify_control_transfer
# ---------------------------------------------------------------------------


class TestClassifyControlTransfer:
    """Transfer kinds: goto, conditional branch, table, indirect, return.
    ``m_set*`` materializations and calls are deliberately unmapped."""

    @pytest.mark.parametrize(
        ("opcode_name", "expected"),
        [
            ("m_goto", ControlTransferKind.GOTO),
            ("m_jtbl", ControlTransferKind.TABLE_BRANCH),
            ("m_ijmp", ControlTransferKind.INDIRECT_BRANCH),
            ("m_ret", ControlTransferKind.RETURN),
            # All m_jX branch opcodes -> CONDITIONAL_BRANCH
            ("m_jz", ControlTransferKind.CONDITIONAL_BRANCH),
            ("m_jnz", ControlTransferKind.CONDITIONAL_BRANCH),
            ("m_jae", ControlTransferKind.CONDITIONAL_BRANCH),
            ("m_jb", ControlTransferKind.CONDITIONAL_BRANCH),
            ("m_jcnd", ControlTransferKind.CONDITIONAL_BRANCH),
        ],
    )
    def test_transfer_mapping(
        self, opcode_name: str, expected: ControlTransferKind
    ) -> None:
        insn = _StubInsn(_required(opcode_name))
        assert classify_control_transfer(insn) is expected

    @pytest.mark.parametrize(
        "opcode_name",
        [
            # The P1 regression: m_set* opcodes carry a predicate but
            # do NOT transfer control.  Before the fix in the adapter,
            # classify_control_transfer would have returned
            # CONDITIONAL_BRANCH here because the inner dispatch
            # used the broad predicate mapper instead of the
            # branch-only one.
            "m_setz",
            "m_setnz",
            "m_setb",
            "m_setae",
            "m_seta",
            "m_setbe",
            "m_setge",
            "m_setg",
            "m_setle",
            "m_setl",
            # Calls are deliberately mapped through the sibling CallKind family.
            "m_call",
            "m_icall",
            # Plain value ops have no transfer.
            "m_mov",
            "m_add",
        ],
    )
    def test_non_transfer_opcodes_return_none(self, opcode_name: str) -> None:
        insn = _StubInsn(_required(opcode_name))
        assert classify_control_transfer(insn) is None


# ---------------------------------------------------------------------------
# classify_call_kind
# ---------------------------------------------------------------------------


class TestClassifyCallKind:
    """Direct and indirect calls use a sibling call vocabulary."""

    @pytest.mark.parametrize(
        ("opcode_name", "expected"),
        [
            ("m_call", CallKind.DIRECT),
            ("m_icall", CallKind.INDIRECT),
        ],
    )
    def test_call_mapping(self, opcode_name: str, expected: CallKind) -> None:
        insn = _StubInsn(_required(opcode_name))
        assert classify_call_kind(insn) is expected

    @pytest.mark.parametrize("opcode_name", ["m_jz", "m_goto", "m_ret", "m_mov", "m_add"])
    def test_non_call_opcodes_return_none(self, opcode_name: str) -> None:
        insn = _StubInsn(_required(opcode_name))
        assert classify_call_kind(insn) is None


# ---------------------------------------------------------------------------
# backend opcode lift
# ---------------------------------------------------------------------------


class TestHexraysOpcodeLift:
    def test_value_opcode_mapping(self) -> None:
        from d810.backends.hexrays.opcode_lift import lift_opcode

        lifted = lift_opcode(_required("m_add"))

        assert lifted.kind is ValueOpKind.ADD
        assert lifted.attrs["backend"] == "hexrays"
        assert lifted.attrs["raw_opcode_int"] == _required("m_add")
        assert lifted.attrs["raw_opcode_name"] == "m_add"

    def test_call_opcode_mapping(self) -> None:
        from d810.backends.hexrays.opcode_lift import lift_opcode

        assert lift_opcode(_required("m_call")).kind is CallKind.DIRECT
        assert lift_opcode(_required("m_icall")).kind is CallKind.INDIRECT

    def test_branch_opcode_lifts_to_transfer_and_keeps_predicate_query_separate(
        self,
    ) -> None:
        from d810.backends.hexrays.opcode_lift import (
            branch_predicate_from_opcode,
            lift_opcode,
        )

        opcode = _required("m_jz")

        assert lift_opcode(opcode).kind is ControlTransferKind.CONDITIONAL_BRANCH
        assert branch_predicate_from_opcode(opcode) is PredicateKind.EQ

    def test_unknown_opcode_uses_vendor_escape_without_fabricated_name(self) -> None:
        from d810.backends.hexrays.opcode_lift import lift_opcode

        lifted = lift_opcode(0x7FFFFFFE)

        assert lifted.kind is ValueOpKind.VENDOR
        assert lifted.attrs["raw_opcode_int"] == 0x7FFFFFFE
        assert "raw_opcode_name" not in lifted.attrs
        assert all(
            not (isinstance(value, str) and value.startswith("op_"))
            for value in lifted.attrs.values()
        )


# ---------------------------------------------------------------------------
# Cross-function consistency
# ---------------------------------------------------------------------------


class TestPredicateAndTransferConsistency:
    """For any predicate-carrying opcode, ``classify_branch_predicate``
    returns a non-None ``PredicateKind``.  For the *branch* subset of
    those, ``classify_control_transfer`` ALSO returns
    ``CONDITIONAL_BRANCH``.  For the *set* subset, it returns
    ``None``.  These invariants together guarantee no
    misclassification across the predicate/transfer split."""

    def test_branch_opcode_has_both_predicate_and_transfer(self) -> None:
        opcode = _required("m_jz")
        insn = _StubInsn(opcode)
        assert classify_branch_predicate(insn) is PredicateKind.EQ
        assert classify_control_transfer(insn) is ControlTransferKind.CONDITIONAL_BRANCH

    def test_set_opcode_has_predicate_but_no_transfer(self) -> None:
        opcode = _required("m_setz")
        insn = _StubInsn(opcode)
        assert classify_branch_predicate(insn) is PredicateKind.EQ
        assert classify_control_transfer(insn) is None
