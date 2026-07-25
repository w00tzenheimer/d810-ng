"""Unit pins for ``InsnSnapshot.__post_init__`` control-transfer inference.

Covers the d81-qlal IR fix (``ir/flowgraph.py``): a predicate-identified
conditional jump whose ``kind`` supplies no transfer (e.g. a semantically
recovered branch lifted with ``kind=UNKNOWN`` but a known ``branch_predicate``)
is still a conditional branch, so ``control_transfer_kind`` is inferred
``CONDITIONAL_BRANCH``.  This lets the canonical projection populate
``Instruction.control.target`` for it, matching the legacy ``insn.d.block_ref``
jump-target read that the operand-slot typed-port replaced (selector_shell /
side_effect_select_loop, commit 0a0a78ea3).
"""

from __future__ import annotations

from d810.ir.flowgraph import InsnKind, InsnSnapshot
from d810.ir.semantics import ControlTransferKind, PredicateKind


def test_predicate_only_jump_infers_conditional_branch_transfer():
    """kind=UNKNOWN + branch_predicate => conditional branch w/ inferred transfer."""
    insn = InsnSnapshot(
        opcode=0,
        ea=0,
        operands=(),
        kind=InsnKind.UNKNOWN,
        branch_predicate=PredicateKind.SLT,
    )
    # branch_predicate marks it a conditional jump; kind=UNKNOWN supplied no
    # transfer, so the d81-qlal clause infers CONDITIONAL_BRANCH.
    assert insn.is_conditional_jump is True
    assert insn.control_transfer_kind is ControlTransferKind.CONDITIONAL_BRANCH


def test_explicit_transfer_not_overridden():
    """A kind that already maps to a transfer is left untouched by the clause."""
    insn = InsnSnapshot(opcode=0, ea=0, operands=(), kind=InsnKind.GOTO)
    assert insn.control_transfer_kind is ControlTransferKind.GOTO


def test_non_branch_leaves_transfer_none():
    """A non-jump with no predicate stays a non-branch (clause must not fire)."""
    insn = InsnSnapshot(opcode=0, ea=0, operands=(), kind=InsnKind.MOV)
    assert insn.is_conditional_jump is False
    assert insn.control_transfer_kind is None
