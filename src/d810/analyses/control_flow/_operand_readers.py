"""Shared canonical operand readers for selector / select-loop discovery.

d81-qlal -- canonical Instruction port.  ``selector_shell`` and
``side_effect_select_loop`` simulate small constant-propagation state machines
over pure dispatch shells.  Both used to read operand slots through the
``_operand(insn, slot)`` shim (``operand_slots`` provenance + a raw
``getattr(insn, slot)`` fallback) and then adapt the raw ``MopSnapshot`` with
duplicated ``_varnode`` / ``_const_value`` / ``_block_ref`` / ``_var_id``
helpers.  This module is the single typed home for those readers; both analyses
import from it.

Operand reads now go through the canonical projection
(:func:`~d810.ir.insn_projection.project_instruction` /
:func:`~d810.ir.insn_projection.operand_storages`):

* the slot-aligned source/dest storage views come from ``operand_storages`` (an
  absent operand is ``None``, never positionally collapsed; an unknown-offset
  stack slot is an explicit :class:`~d810.ir.locations.WeakStackSlot`);
* a numeric constant is read off the storage view with
  :func:`~d810.analyses.value_flow.induction_carrier._const_value_from_varnode`;
* a storage identity ``(label, offset)`` is derived with
  :func:`~d810.ir.storage_identity.storage_identity_from_varnode`;
* the conditional/goto jump target (was ``tail.d.block_ref`` /
  ``tail.l.block_ref``) is read off ``Instruction.control.target`` (populated by
  the projection's ``_block_target_from``).

No raw ``insn.l`` / ``insn.r`` / ``insn.d`` slot read, no ``operand_slots``
provenance walk, and no ``getattr`` on a snapshot remains.

``_const_value`` / ``_var_id`` accept either the canonical storage view
(``Varnode`` / ``WeakStackSlot``) produced by ``operand_storages`` or a raw
``MopSnapshot``-shaped operand; a raw operand is normalized through
:func:`~d810.ir.varnode.varnode_from_mop_snapshot` first, so the operand-identity
unit tests that call these helpers with a duck-typed mop keep their behavior.
"""
from __future__ import annotations

from d810.analyses.control_flow.instruction_semantics import (
    branch_predicate,
    comparison_width,
    evaluate_branch_predicate,
    is_branch,
)
from d810.analyses.value_flow.induction_carrier import _const_value_from_varnode
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockSnapshot, InsnSnapshot
from d810.ir.insn_projection import operand_storages, project_instruction
from d810.ir.locations import WeakStackSlot
from d810.ir.storage_identity import (
    StorageIdentityKind,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot

VarId = tuple[str, int]
Env = dict[VarId, int]

_VAR_ID_KIND_LABELS: dict[StorageIdentityKind, str] = {
    StorageIdentityKind.REGISTER: "reg",
    StorageIdentityKind.STACK: "stack",
    StorageIdentityKind.LVAR: "lvar",
}


def _as_varnode(operand: Varnode | WeakStackSlot | object | None) -> Varnode | None:
    """Normalize an operand to a canonical ``Varnode``, else ``None``.

    Accepts the canonical storage views produced by ``operand_storages``
    (``Varnode`` is returned as-is; an unknown-offset ``WeakStackSlot`` carries
    no comparable scalar identity, so it normalizes to ``None``) and raw
    ``MopSnapshot``-shaped operands (adapted through
    :func:`varnode_from_mop_snapshot`).  ``None`` propagates ``None``.
    """
    if operand is None or isinstance(operand, WeakStackSlot):
        return None
    if isinstance(operand, Varnode):
        return operand
    try:
        return varnode_from_mop_snapshot(operand)
    except (AttributeError, TypeError, ValueError):
        return None


def _const_value(operand: Varnode | WeakStackSlot | object | None) -> int | None:
    """Return the numeric constant for a CONST operand, masked to 64 bits."""
    varnode = _as_varnode(operand)
    value = _const_value_from_varnode(varnode)
    if value is None:
        return None
    try:
        return int(value) & 0xFFFFFFFFFFFFFFFF
    except (TypeError, ValueError):
        return None


def _var_id(operand: Varnode | WeakStackSlot | object | None) -> VarId | None:
    """Return the size-agnostic storage identity ``(label, offset)``, else ``None``."""
    identity = storage_identity_from_varnode(_as_varnode(operand))
    if identity is None:
        return None
    label = _VAR_ID_KIND_LABELS.get(identity.kind)
    if label is None:
        return None
    return (label, int(identity.offset))


def _last_insn(block: BlockSnapshot) -> InsnSnapshot | None:
    """Return the block's tail instruction snapshot, or ``None`` when empty."""
    return block.insn_snapshots[-1] if block.insn_snapshots else None


def _jump_target_from_snapshot(insn: InsnSnapshot | None) -> int | None:
    """Return the (conditional/goto) jump target block serial, else ``None``.

    Read off the canonical ``Instruction.control.target`` (the projection
    populates it from the branch's block operand ``block_ref``), never from the
    raw ``insn.d`` / ``insn.l`` operand slot.
    """
    if insn is None:
        return None
    control = project_instruction(insn).control
    if control is None or control.target is None:
        return None
    return int(control.target)


def _is_simple_assign(insn: InsnSnapshot | None) -> bool:
    """Return whether ``insn`` is a constant/var MOV-or-ZEXT into a known dest.

    The original guard accepted both ``InsnKind.MOV`` and ``InsnKind.XDU``;
    those project to ``ValueOpKind.MOVE`` / ``ValueOpKind.ZEXT`` respectively, so
    the canonical operation test admits exactly the same instructions.
    """
    if insn is None:
        return False
    instruction = project_instruction(insn)
    if instruction.operation not in (ValueOpKind.MOVE, ValueOpKind.ZEXT):
        return False
    _left, _right, dest = operand_storages(insn)
    if _var_id(dest) is None:
        return False
    return _const_value(_left) is not None or _var_id(_left) is not None


def _exec_simple_assignments(block: BlockSnapshot, env: Env) -> Env:
    """Constant-fold the block's simple assignments over ``env``."""
    result = dict(env)
    for insn in block.insn_snapshots:
        if not _is_simple_assign(insn):
            continue
        left, _right, dest_storage = operand_storages(insn)
        dst = _var_id(dest_storage)
        if dst is None:
            continue
        value = _const_value(left)
        if value is None:
            src_id = _var_id(left)
            value = result.get(src_id) if src_id is not None else None
        if value is None:
            result.pop(dst, None)
        else:
            result[dst] = int(value)
    return result


def _eval_branch(block: BlockSnapshot, env: Env) -> bool | None:
    """Evaluate the block's tail branch under ``env``, else ``None``."""
    tail = _last_insn(block)
    if tail is None or not is_branch(tail):
        return None
    left_storage, right_storage, _dest = operand_storages(tail)
    left_value = _const_value(left_storage)
    if left_value is None:
        left_id = _var_id(left_storage)
        left_value = env.get(left_id) if left_id is not None else None
    right_value = _const_value(right_storage)
    if right_value is None:
        right_id = _var_id(right_storage)
        right_value = env.get(right_id) if right_id is not None else None
    return evaluate_branch_predicate(
        branch_predicate(tail),
        left_value,
        right_value,
        comparison_width(tail),
    )


def _branch_targets(block: BlockSnapshot) -> tuple[int, int] | None:
    """Return ``(taken, fallthrough)`` for a two-way branch tail, else ``None``."""
    tail = _last_insn(block)
    taken = _jump_target_from_snapshot(tail)
    if taken is None or taken not in block.succs:
        return None
    fallthrough = tuple(int(succ) for succ in block.succs if int(succ) != int(taken))
    if len(fallthrough) != 1:
        return None
    return int(taken), fallthrough[0]


def _next_successors(block: BlockSnapshot, env: Env) -> tuple[int, ...] | None:
    """Resolve the block's single live successor under ``env``, else ``None``."""
    if block.nsucc == 0:
        return ()
    if block.nsucc == 1:
        return (int(block.succs[0]),)
    if block.nsucc != 2:
        return None
    targets = _branch_targets(block)
    if targets is None:
        return None
    taken, fallthrough = targets
    decision = _eval_branch(block, env)
    if decision is None:
        return None
    return (taken if decision else fallthrough,)


__all__ = [
    "Env",
    "VarId",
    "_branch_targets",
    "_const_value",
    "_eval_branch",
    "_exec_simple_assignments",
    "_is_simple_assign",
    "_jump_target_from_snapshot",
    "_last_insn",
    "_next_successors",
    "_var_id",
]
