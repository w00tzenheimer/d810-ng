"""Recover exact dispatcher rows from equality/inequality chains."""
from __future__ import annotations

from dataclasses import dataclass

from d810.core import logging
from d810.recon.flow.dispatcher_kind import DispatcherType
from d810.recon.flow.dispatcher_map import (
    StateDispatcherMap,
    StateDispatcherRow,
)

logger = logging.getLogger("D810.recon.flow.equality_chain_dispatcher", logging.INFO)


@dataclass(frozen=True, slots=True)
class _StateVarIdentity:
    kind: str
    identifier: int
    size: int


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
        tail = getattr(blk, "tail", None)
        opcode = getattr(tail, "opcode", getattr(blk, "tail_opcode", None))
        left = getattr(tail, "l", None)
        right = getattr(tail, "r", None)
        extracted = _extract_compare(blk)
        jump_and_fallthrough = _jump_and_fallthrough(blk)
        if len(sample_two_way) < 8:
            sample_two_way.append(
                (
                    int(getattr(blk, "serial", serial)),
                    opcode,
                    getattr(left, "t", None),
                    getattr(right, "t", None),
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
    state_var: _StateVarIdentity | None = None
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
        var, const, opcode = extracted
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
        if _is_jz(opcode):
            target = jump_target
            branch_kind = "jz_taken"
        elif _is_jnz(opcode):
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
                source=DispatcherType.CONDITIONAL_CHAIN,
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
            state_var.identifier if state_var.kind == "stack" else None
        ),
        state_var_lvar_idx=(
            state_var.identifier if state_var.kind == "lvar" else None
        ),
        source=DispatcherType.CONDITIONAL_CHAIN,
    )
    _observe_state_dispatcher_map(mba, dispatch_map)
    return dispatch_map


def _observe_state_dispatcher_map(
    mba: object,
    dispatch_map: StateDispatcherMap,
) -> None:
    """Publish equality-chain rows for the diag DB when observability is on."""
    try:
        from d810.recon.observability import observe_state_dispatcher_rows

        observe_state_dispatcher_rows(
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
            maturity=_maturity_name(int(getattr(mba, "maturity", -1) or -1)),
            dispatcher_entry_block=int(dispatch_map.dispatcher_entry_block),
            dispatcher_kind=dispatch_map.source.name,
            rows=dispatch_map.rows,
        )
    except Exception:
        return


def _maturity_name(maturity: int) -> str:
    names = {
        0: "MMAT_GENERATED",
        1: "MMAT_PREOPTIMIZED",
        2: "MMAT_LOCOPT",
        3: "MMAT_CALLS",
        4: "MMAT_GLBOPT1",
        5: "MMAT_GLBOPT2",
        6: "MMAT_GLBOPT3",
        7: "MMAT_LVARS",
    }
    return names.get(int(maturity), f"MMAT_{int(maturity)}")


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
        _var, _const, opcode = extracted
        if _is_jz(opcode):
            next_serial = fallthrough
        elif _is_jnz(opcode):
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
) -> dict[_StateVarIdentity, _StateVarIdentity]:
    aliases: dict[_StateVarIdentity, _StateVarIdentity] = {}
    for serial in ordered_blocks:
        blk = _get_block(mba, serial)
        if blk is None:
            continue
        for insn in _iter_block_insns(blk):
            if not _is_mov(getattr(insn, "opcode", None)):
                continue
            dst = _state_var_identity(getattr(insn, "d", None))
            src = _state_var_identity(getattr(insn, "l", None))
            if dst is None or src is None or dst == src:
                continue
            aliases[dst] = src
    return aliases


def _canonical_state_var(
    var: _StateVarIdentity,
    aliases: dict[_StateVarIdentity, _StateVarIdentity],
) -> _StateVarIdentity:
    current = var
    seen: set[_StateVarIdentity] = set()
    while current in aliases and current not in seen:
        seen.add(current)
        current = aliases[current]
    return current


def _iter_block_insns(blk: object):
    insns = getattr(blk, "insns", None)
    if insns is not None:
        try:
            yield from tuple(insns)
            return
        except TypeError:
            pass

    head = getattr(blk, "head", None)
    tail = getattr(blk, "tail", None)
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


def _extract_compare(
    blk: object,
) -> tuple[_StateVarIdentity, int, object] | None:
    tail = getattr(blk, "tail", None)
    if tail is None:
        return None
    opcode = getattr(tail, "opcode", getattr(blk, "tail_opcode", None))
    if not (_is_jz(opcode) or _is_jnz(opcode)):
        return None
    left = getattr(tail, "l", None)
    right = getattr(tail, "r", None)
    left_const = _const_value(left)
    right_const = _const_value(right)
    left_var = _state_var_identity(left)
    right_var = _state_var_identity(right)
    if left_var is not None and right_const is not None:
        return left_var, int(right_const), opcode
    if right_var is not None and left_const is not None:
        return right_var, int(left_const), opcode
    return None


def _jump_and_fallthrough(blk: object) -> tuple[int | None, int | None]:
    tail = getattr(blk, "tail", None)
    jump_target = None
    if tail is not None:
        dest = getattr(tail, "d", None)
        jump_target = _block_ref(dest)
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


def _block_ref(mop: object | None) -> int | None:
    if mop is None:
        return None
    for attr in ("block_ref", "block_num", "b"):
        value = getattr(mop, attr, None)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
    return None


def _const_value(mop: object | None) -> int | None:
    if mop is None or not _is_mop(mop, "mop_n"):
        return None
    nnn = getattr(mop, "nnn", None)
    candidates = (
        getattr(mop, "nnn_value", None),
        getattr(nnn, "value", None),
        getattr(mop, "value", None),
    )
    for value in candidates:
        if callable(value):
            try:
                value = value()
            except Exception:
                value = None
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _state_var_identity(
    mop: object | None,
) -> _StateVarIdentity | None:
    if mop is None:
        return None
    size = int(getattr(mop, "size", 0) or 0)
    if _is_mop(mop, "mop_S"):
        s = getattr(mop, "s", None)
        off = getattr(s, "off", getattr(mop, "stkoff", None))
        if off is None:
            return None
        return _StateVarIdentity("stack", int(off), size)
    if _is_mop(mop, "mop_l"):
        lv = getattr(mop, "l", None)
        idx = getattr(lv, "idx", getattr(mop, "idx", None))
        if idx is None:
            var = getattr(lv, "var", None)
            if callable(var):
                v = var()
                idx = getattr(v, "idx", None)
        if idx is None:
            return None
        return _StateVarIdentity("lvar", int(idx), size)
    return None


def _is_mop(
    mop: object,
    name: str,
) -> bool:
    t = getattr(mop, "t", None)
    return t == name or str(t) == name


def _is_jz(opcode: object) -> bool:
    return _is_opcode(opcode, "m_jz")


def _is_jnz(opcode: object) -> bool:
    return _is_opcode(opcode, "m_jnz")


def _is_mov(opcode: object) -> bool:
    return _is_opcode(opcode, "m_mov")


def _is_opcode(
    opcode: object,
    name: str,
) -> bool:
    return opcode == name or str(opcode) == name


__all__ = ["extract_state_dispatcher_map_from_mba"]
