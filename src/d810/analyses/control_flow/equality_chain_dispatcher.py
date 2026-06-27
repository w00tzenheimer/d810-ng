"""Recover exact dispatcher rows from equality/inequality chains.

d81-qlal -- canonical Instruction port.  The compared-operand and state-write
reads no longer touch backend-shaped ``InsnSnapshot`` operand slots (``.l`` /
``.r`` / ``.d``).  Each tail / move :class:`~d810.ir.flowgraph.InsnSnapshot` is
read through the canonical projection:

* the compared operands (was ``tail.l`` / ``tail.r``) come from the slot-aligned
  canonical storage views (:func:`~d810.ir.insn_projection.operand_storages` ->
  ``l`` / ``r``): a ``NUMBER`` operand projects to a ``Varnode(Space.CONST,
  value, size)`` and a stack/lvar operand to a stack/lvar identity ``Varnode``;
* the conditional jump target (was ``tail.d.block_ref``) is read off
  ``Instruction.control.target`` (populated by the projection's
  ``_block_target_from`` for a CONDITIONAL_BRANCH), and the branch predicate off
  ``Instruction.control.predicate``;
* the move source/dest of a state-var alias (was ``insn.l`` / ``insn.d``) come
  from the move instruction's slot-aligned ``operand_storages`` (``l`` source /
  ``d`` dest).

STRUCTURAL block topology stays direct: ``mba.qty`` / ``get_mblock`` and the
block's ``serial`` / ``succs`` / ``tail`` / ``insns`` are model surfaces, not
operand slots.  The live Hex-Rays adapter
(:mod:`d810.backends.hexrays.evidence.dispatcher.equality_chain`) normalizes the
raw microcode into these portable ``InsnSnapshot`` / ``BlockSnapshot`` shapes
before this extractor runs.
"""
from __future__ import annotations

from d810.core import logging
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_resolution import (
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.ir.flowgraph import InsnKind, InsnSnapshot
from d810.ir.insn_projection import operand_storages, project_instruction
from d810.ir.semantics import PredicateKind
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space, Varnode

logger = logging.getLogger("D810.analyses.control_flow.equality_chain_dispatcher", logging.INFO)


def extract_state_dispatcher_map_from_mba(
    mba: object,
    *,
    dispatcher_entry_block: int | None = None,
    max_depth: int | None = None,
) -> StateDispatcherMap | None:
    """Extract exact ``state_const -> handler`` rows from a normalized mba view."""
    qty = int(getattr(mba, "qty", 0) or 0)
    if qty <= 0:
        return None
    if max_depth is None:
        max_depth = max(qty * 2, 1)

    compare_blocks: set[int] = set()
    two_way_count = 0
    compare_count = 0
    sample_two_way: list[tuple[int, object, object, object, int | None, tuple[int | None, int | None]]] = []
    for serial, blk in _iter_blocks(mba, qty):
        if not _is_two_way_block(blk):
            continue
        two_way_count += 1
        tail = _block_tail(blk)
        predicate = _branch_predicate(tail)
        left, right = _compare_operands(tail)
        extracted = _extract_compare(blk)
        jump_and_fallthrough = _jump_and_fallthrough(blk)
        if len(sample_two_way) < 8:
            sample_two_way.append(
                (
                    int(getattr(blk, "serial", serial)),
                    predicate,
                    _operand_space(left),
                    _operand_space(right),
                    _const_value(right),
                    jump_and_fallthrough,
                )
            )
        if extracted is None:
            continue
        compare_count += 1
        if jump_and_fallthrough == (None, None):
            continue
        compare_blocks.add(int(getattr(blk, "serial", serial)))
    if not compare_blocks:
        logger.debug(
            "No equality-chain dispatcher compare blocks found: qty=%d two_way=%d "
            "compare=%d sample=%s",
            qty,
            two_way_count,
            compare_count,
            tuple(sample_two_way),
        )
        return None

    if dispatcher_entry_block is None:
        entry = min(compare_blocks)
        ordered_blocks = sorted(compare_blocks)
    else:
        entry = int(dispatcher_entry_block)
        ordered_blocks = _walk_chain(mba, entry, compare_blocks, max_depth)
        if not ordered_blocks:
            logger.debug(
                "No equality-chain dispatcher walk from entry blk[%d]; compare_blocks=%s",
                int(entry),
                tuple(sorted(compare_blocks))[:32],
            )
            return None

    rows: list[StateDispatcherRow] = []
    seen: dict[int, int] = {}
    state_var: StorageIdentity | None = None
    state_aliases = _state_var_aliases(mba, ordered_blocks)
    dispatcher_blocks: set[int] = set()
    ordered_dispatcher_blocks = set(int(block) for block in ordered_blocks)
    logger.debug(
        "Walking equality-chain dispatcher entry blk[%d]: ordered=%s aliases=%s",
        int(entry),
        tuple(ordered_blocks),
        state_aliases,
    )

    for serial in ordered_blocks:
        blk = _get_block(mba, serial)
        if blk is None:
            continue
        extracted = _extract_compare(blk)
        if extracted is None:
            continue
        var, const, predicate = extracted
        var = _canonical_state_var(var, state_aliases)
        if state_var is None:
            state_var = var
        elif var != state_var:
            logger.debug(
                "Rejected equality-chain dispatcher entry blk[%d]: mixed state variable "
                "at blk[%d] expected=%s actual=%s raw=%s aliases=%s",
                int(entry),
                int(serial),
                state_var,
                var,
                extracted[0],
                state_aliases,
            )
            return None

        jump_target, fallthrough = _jump_and_fallthrough(blk)
        if jump_target is None or fallthrough is None:
            continue
        if _is_eq(predicate):
            target = jump_target
            branch_kind = "jz_taken"
        elif _is_ne(predicate):
            target = fallthrough
            branch_kind = "jnz_fallthrough"
        else:
            continue
        # A handler may itself start with a normal semantic conditional
        # compare. The broad ``compare_blocks`` set includes those blocks too,
        # so using it here silently drops exact rows such as OLLVM
        # ``state == K -> handler_that_starts_with_if``. Only suppress rows
        # whose target is another block in this dispatcher chain.
        if int(target) in ordered_dispatcher_blocks:
            continue
        existing = seen.get(int(const))
        if existing is not None:
            if existing != int(target):
                logger.debug(
                    "Rejected equality-chain dispatcher entry blk[%d]: duplicate "
                    "state 0x%X targets blk[%d] and blk[%d]",
                    int(entry),
                    int(const),
                    int(existing),
                    int(target),
                )
                return None
            continue
        seen[int(const)] = int(target)
        dispatcher_blocks.add(int(serial))
        rows.append(
            StateDispatcherRow(
                state_const=int(const) & 0xFFFFFFFFFFFFFFFF,
                target_block=int(target),
                dispatcher_block=int(entry),
                compare_block=int(serial),
                branch_kind=branch_kind,
                router_kind=RouterKind.CONDITION_CHAIN,
                confidence=1.0,
            )
        )

    if not rows or state_var is None:
        logger.debug(
            "Rejected equality-chain dispatcher entry blk[%d]: rows=%d state_var=%s",
            int(entry),
            len(rows),
            state_var,
        )
        return None
    dispatcher_blocks.add(int(entry))
    dispatch_map = StateDispatcherMap(
        rows=tuple(rows),
        dispatcher_entry_block=int(entry),
        dispatcher_blocks=frozenset(dispatcher_blocks),
        state_var_stkoff=(
            state_var.offset
            if state_var.kind is StorageIdentityKind.STACK
            else None
        ),
        state_var_lvar_idx=(
            state_var.offset
            if state_var.kind is StorageIdentityKind.LVAR
            else None
        ),
        router_kind=RouterKind.CONDITION_CHAIN,
    )
    return dispatch_map


def _iter_blocks(mba: object, qty: int):
    for serial in range(qty):
        blk = _get_block(mba, serial)
        if blk is not None:
            yield serial, blk


def _get_block(mba: object, serial: int):
    getter = getattr(mba, "get_mblock", None)
    if callable(getter):
        return getter(int(serial))
    blocks = getattr(mba, "blocks", None)
    if isinstance(blocks, dict):
        return blocks.get(int(serial))
    return None


def _is_two_way_block(blk: object) -> bool:
    block_type = getattr(blk, "block_type", getattr(blk, "type", None))
    type_name = str(getattr(blk, "type_name", ""))
    nsucc = getattr(blk, "nsucc", None)
    if callable(nsucc):
        try:
            nsucc = int(nsucc())
        except Exception:
            nsucc = None
    if nsucc is None:
        succs = _successors(blk)
        nsucc = len(succs)
    try:
        numeric_type = int(block_type)
    except (TypeError, ValueError):
        numeric_type = -1
    return (
        str(block_type) == "BLT_2WAY"
        or type_name == "BLT_2WAY"
        or numeric_type == 4
        or int(nsucc or 0) == 2
    )


def _successors(blk: object) -> tuple[int, ...]:
    succs = getattr(blk, "succset", None)
    if succs is None:
        succs = getattr(blk, "succs", ())
    try:
        return tuple(int(s) for s in succs)
    except TypeError:
        pass
    nsucc = getattr(blk, "nsucc", None)
    succ = getattr(blk, "succ", None)
    if callable(nsucc) and callable(succ):
        try:
            return tuple(int(succ(i)) for i in range(int(nsucc())))
        except Exception:
            return ()
    return ()


def _block_tail(blk: object) -> InsnSnapshot | None:
    """Return the block's tail instruction snapshot, else ``None``.

    ``tail`` is a model surface (the block's last instruction), not an operand
    slot.  Accepts either a ``BlockSnapshot`` (``.tail`` property) or the live
    Hex-Rays adapter's block view (``.tail`` attribute).
    """
    return getattr(blk, "tail", None)


def _walk_chain(
    mba: object,
    entry: int,
    compare_blocks: set[int],
    max_depth: int,
) -> list[int]:
    current = int(entry)
    visited: set[int] = set()
    ordered: list[int] = []
    for _ in range(max_depth):
        if current in visited or current not in compare_blocks:
            break
        visited.add(current)
        ordered.append(current)
        blk = _get_block(mba, current)
        if blk is None:
            break
        extracted = _extract_compare(blk)
        jump_target, fallthrough = _jump_and_fallthrough(blk)
        if extracted is None or jump_target is None or fallthrough is None:
            break
        _var, _const, predicate = extracted
        if _is_eq(predicate):
            next_serial = fallthrough
        elif _is_ne(predicate):
            next_serial = jump_target
        else:
            break
        if int(next_serial) not in compare_blocks:
            break
        current = int(next_serial)
    return ordered


def _state_var_aliases(
    mba: object,
    ordered_blocks: list[int],
) -> dict[StorageIdentity, StorageIdentity]:
    aliases: dict[StorageIdentity, StorageIdentity] = {}
    for serial in ordered_blocks:
        blk = _get_block(mba, serial)
        if blk is None:
            continue
        for insn in _iter_block_insns(blk):
            if not _is_mov(insn):
                continue
            src_storage, _r, dst_storage = operand_storages(insn)
            dst = _state_var_identity(dst_storage)
            src = _state_var_identity(src_storage)
            if dst is None or src is None or dst == src:
                continue
            aliases[dst] = src
    return aliases


def _canonical_state_var(
    var: StorageIdentity,
    aliases: dict[StorageIdentity, StorageIdentity],
) -> StorageIdentity:
    current = var
    seen: set[StorageIdentity] = set()
    while current in aliases and current not in seen:
        seen.add(current)
        current = aliases[current]
    return current


def _iter_block_insns(blk: object):
    insns = getattr(blk, "insn_snapshots", None)
    if insns is None:
        insns = getattr(blk, "insns", None)
    if insns is not None:
        try:
            yield from tuple(insns)
            return
        except TypeError:
            pass

    head = getattr(blk, "head", None)
    tail = _block_tail(blk)
    if head is None:
        return
    current = head
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        if current is tail:
            break
        current = getattr(current, "next", None)


def _compare_operands(
    tail: InsnSnapshot | None,
) -> tuple[Varnode | None, Varnode | None]:
    """Return the slot-aligned ``(left, right)`` compared-operand storage views.

    Reads the canonical slot-aligned ``operand_storages`` (``l`` / ``r``), so a
    ``NUMBER`` operand surfaces as a ``Varnode(Space.CONST, ...)`` and a
    stack/lvar operand as its identity ``Varnode`` -- never a raw ``tail.l`` /
    ``tail.r`` operand slot.  A ``WeakStackSlot`` (unknown stack offset) or
    absent operand normalizes to ``None`` for the scalar reads below.
    """
    if tail is None:
        return None, None
    left, right, _dest = operand_storages(tail)
    return (
        left if isinstance(left, Varnode) else None,
        right if isinstance(right, Varnode) else None,
    )


def _extract_compare(
    blk: object,
) -> tuple[StorageIdentity, int, PredicateKind] | None:
    tail = _block_tail(blk)
    if tail is None:
        return None
    predicate = _branch_predicate(tail)
    if not (_is_eq(predicate) or _is_ne(predicate)):
        return None
    left, right = _compare_operands(tail)
    left_const = _const_value(left)
    right_const = _const_value(right)
    left_var = _state_var_identity(left)
    right_var = _state_var_identity(right)
    if left_var is not None and right_const is not None:
        return left_var, int(right_const), predicate
    if right_var is not None and left_const is not None:
        return right_var, int(left_const), predicate
    return None


def _jump_and_fallthrough(blk: object) -> tuple[int | None, int | None]:
    jump_target = _jump_target(_block_tail(blk))
    succs = _successors(blk)
    if jump_target is None and len(succs) == 2:
        jump_target = int(succs[1])
    if jump_target is None:
        return None, None
    fallthrough = None
    for succ in succs:
        if int(succ) != int(jump_target):
            fallthrough = int(succ)
            break
    return int(jump_target), fallthrough


def _jump_target(tail: InsnSnapshot | None) -> int | None:
    """Return the conditional jump target block serial, else ``None``.

    Read off the canonical ``Instruction.control.target`` (the projection
    populates it from ``insn.d.block_ref`` for a CONDITIONAL_BRANCH), never from
    the raw ``tail.d`` operand slot.
    """
    if tail is None:
        return None
    control = project_instruction(tail).control
    if control is None or control.target is None:
        return None
    return int(control.target)


def _const_value(operand: Varnode | None) -> int | None:
    if operand is None or operand.space is not Space.CONST:
        return None
    return int(operand.offset)


def _state_var_identity(
    operand: Varnode | None,
) -> StorageIdentity | None:
    identity = storage_identity_from_varnode(operand)
    if identity is None:
        return None
    if identity.kind not in {
        StorageIdentityKind.STACK,
        StorageIdentityKind.LVAR,
    }:
        return None
    return identity


def _operand_space(operand: Varnode | None) -> str | None:
    if operand is None:
        return None
    return operand.space.name.lower()


def _branch_predicate(tail: InsnSnapshot | None) -> PredicateKind | None:
    """Return the tail branch predicate, else ``None``.

    Read off the canonical ``Instruction.control.predicate`` (populated from the
    snapshot's ``predicate_kind`` for a CONDITIONAL_BRANCH), never from a raw
    operand slot.
    """
    if tail is None:
        return None
    control = project_instruction(tail).control
    if control is None:
        return None
    return control.predicate


def _is_eq(predicate: PredicateKind | None) -> bool:
    return predicate is PredicateKind.EQ


def _is_ne(predicate: PredicateKind | None) -> bool:
    return predicate is PredicateKind.NE


def _is_mov(insn: object) -> bool:
    return getattr(insn, "kind", None) is InsnKind.MOV


__all__ = ["extract_state_dispatcher_map_from_mba"]
