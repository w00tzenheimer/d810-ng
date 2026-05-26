"""Unit tests for the portable semantic-IR enums.

These tests live in ``tests/unit/`` because ``d810.ir.semantics`` is a
pure-Python module with no IDA / Hex-Rays dependency.  The behaviour
of the *adapter* functions
(``classify_branch_predicate`` / ``classify_control_transfer`` in
``d810.hexrays.mutation.ir_translator``) is exercised in the
system-runtime suite, because the adapter resolves opcode names to
ints via live ``ida_hexrays`` attribute reads.  Importing the
adapter from ``tests/unit/`` would violate the
``unit-tests-no-hexrays`` import-linter contract.
"""

from __future__ import annotations

from d810.ir.semantics import ControlTransferKind, PredicateKind


class TestPredicateKind:
    def test_full_predicate_membership(self) -> None:
        """The minimum-viable PredicateKind covers EQ/NE, the 4 unsigned
        comparisons, the 4 signed comparisons, and TRUTHY (m_jcnd)."""
        names = {member.name for member in PredicateKind}
        assert names == {
            "EQ",
            "NE",
            "UGE",
            "UGT",
            "ULE",
            "ULT",
            "SGE",
            "SGT",
            "SLE",
            "SLT",
            "TRUTHY",
        }

    def test_members_are_distinct(self) -> None:
        """Each PredicateKind value is unique so callers can use
        identity comparison (`is PredicateKind.EQ`) safely."""
        values = [member.value for member in PredicateKind]
        assert len(values) == len(set(values))


class TestControlTransferKind:
    def test_transfer_kinds(self) -> None:
        """Five transfer kinds cover the recon-side dispatch shapes
        the adapter needs today: gotos, conditional branches, jump
        tables, indirect jumps, and returns.  Calls have their own
        future ``CallKind`` family."""
        names = {member.name for member in ControlTransferKind}
        assert names == {
            "GOTO",
            "CONDITIONAL_BRANCH",
            "TABLE_BRANCH",
            "INDIRECT_BRANCH",
            "RETURN",
        }


class TestNotFlatOpcodeEnum:
    """Architectural test: PredicateKind + ControlTransferKind must NOT
    mirror Hex-Rays mcode_t as one flat enum.  The discipline (per the
    axis-C2 split-queue plan) is that semantic families separate
    distinct concerns; a flat enum like ``InsnKind.M_JBE`` just
    recreates IDA under a portable name.

    These tests ensure no member name carries the vendor ``m_`` prefix
    or hex-rays internal opcode names directly.
    """

    def test_predicate_kind_has_no_mcode_naming(self) -> None:
        for member in PredicateKind:
            assert not member.name.startswith("M_"), (
                f"PredicateKind.{member.name} looks like a Hex-Rays mcode_t name; "
                "predicates should use LLVM-style short forms (EQ, ULT, ...) "
                "not vendor opcode names."
            )

    def test_control_transfer_kind_has_no_mcode_naming(self) -> None:
        for member in ControlTransferKind:
            assert not member.name.startswith("M_"), (
                f"ControlTransferKind.{member.name} looks like a Hex-Rays mcode_t "
                "name; transfer kinds describe semantics, not opcodes."
            )
