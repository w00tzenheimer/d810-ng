"""Focused unit cover for ``_is_corridor_control_flow_insn`` (E2d/terminal-corridor).

Pins the *exact* corridor control-flow set {m_goto, m_jnz, m_ijmp, m_jtbl}
expressed in portable kinds, so the parity is protected without distorting
the generic ``InsnKind`` / ``BranchPredicate`` helpers:

* ``m_jnz`` (EQUALITY_JUMP + NOT_EQUAL) is control flow -> accepted.
* ``m_jz``  (EQUALITY_JUMP + EQUAL) is NOT in the original set -> rejected.
* ``m_ijmp`` (INDIRECT_JUMP) and ``m_jtbl`` (TABLE_JUMP) -> accepted.
* Everything else (CALL, MOV, COND_JUMP, ...) counts as a carrier -> rejected.

Pure recon -- no IDA / Hex-Rays imports.
"""
from __future__ import annotations

import pytest

from d810.ir.flowgraph import BranchPredicate, InsnKind, InsnSnapshot
from d810.analyses.control_flow.terminal_corridor_discovery import (
    _is_corridor_control_flow_insn,
)


def _insn(
    kind: InsnKind,
    branch_predicate: BranchPredicate | None = None,
) -> InsnSnapshot:
    return InsnSnapshot(
        opcode=1,
        ea=0,
        operands=(),
        kind=kind,
        branch_predicate=branch_predicate,
    )


@pytest.mark.parametrize(
    "kind, predicate, expected, label",
    [
        (InsnKind.GOTO, None, True, "m_goto"),
        (InsnKind.EQUALITY_JUMP, BranchPredicate.NOT_EQUAL, True, "m_jnz"),
        (InsnKind.EQUALITY_JUMP, BranchPredicate.EQUAL, False, "m_jz"),
        (InsnKind.INDIRECT_JUMP, None, True, "m_ijmp"),
        (InsnKind.TABLE_JUMP, None, True, "m_jtbl"),
        (InsnKind.CALL, None, False, "m_call"),
        (InsnKind.MOV, None, False, "m_mov (carrier)"),
        (InsnKind.COND_JUMP, None, False, "other conditional jump"),
    ],
)
def test_corridor_control_flow_membership(
    kind: InsnKind,
    predicate: BranchPredicate | None,
    expected: bool,
    label: str,
) -> None:
    assert _is_corridor_control_flow_insn(_insn(kind, predicate)) is expected, label


def test_equality_jump_without_predicate_is_rejected() -> None:
    """An EQUALITY_JUMP whose predicate was never populated must NOT be
    accepted -- only ``NOT_EQUAL`` (m_jnz) qualifies, never a bare/None
    predicate (which would let m_jz-shaped snapshots slip through)."""
    assert _is_corridor_control_flow_insn(_insn(InsnKind.EQUALITY_JUMP, None)) is False
