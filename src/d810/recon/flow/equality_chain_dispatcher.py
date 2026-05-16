"""Recover exact dispatcher rows from equality/inequality chains."""
from __future__ import annotations

from dataclasses import dataclass

from d810.recon.flow.dispatcher_detection import DispatcherType
from d810.recon.flow.dispatcher_map import (
    StateDispatcherMap,
    StateDispatcherRow,
)


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
    """Extract exact ``state_const -> handler`` rows from a live-like mba."""
    qty = int(getattr(mba, "qty", 0) or 0)
    if qty <= 0:
        return None
    if max_depth is None:
        max_depth = max(qty * 2, 1)

    compare_blocks = {
        int(getattr(blk, "serial", serial))
        for serial, blk in _iter_blocks(mba, qty)
        if _is_two_way_block(blk)
        and _extract_compare(blk) is not None
        and _jump_and_fallthrough(blk) != (None, None)
    }
    if not compare_blocks:
        return None

    if dispatcher_entry_block is None:
        entry = min(compare_blocks)
        ordered_blocks = sorted(compare_blocks)
    else:
        entry = int(dispatcher_entry_block)
        ordered_blocks = _walk_chain(mba, entry, compare_blocks, max_depth)
        if not ordered_blocks:
            return None

    rows: list[StateDispatcherRow] = []
    seen: dict[int, int] = {}
    state_var: _StateVarIdentity | None = None
    dispatcher_blocks: set[int] = set()

    for serial in ordered_blocks:
        blk = _get_block(mba, serial)
        if blk is None:
            continue
        extracted = _extract_compare(blk)
        if extracted is None:
            continue
        var, const, opcode = extracted
        if state_var is None:
            state_var = var
        elif var != state_var:
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
        if int(target) in compare_blocks:
            continue
        existing = seen.get(int(const))
        if existing is not None:
            if existing != int(target):
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
        return None
    dispatcher_blocks.add(int(entry))
    return StateDispatcherMap(
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
    try:
        import ida_hexrays  # type: ignore[import-untyped]

        if int(getattr(blk, "type", -1)) == int(ida_hexrays.BLT_2WAY):
            return True
    except Exception:
        pass
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
    if mop is None or not _is_mop(mop, "mop_n", {2}):
        return None
    value = getattr(mop, "value", None)
    if value is None:
        nnn = getattr(mop, "nnn", None)
        value = getattr(nnn, "value", None)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _state_var_identity(mop: object | None) -> _StateVarIdentity | None:
    if mop is None:
        return None
    size = int(getattr(mop, "size", 0) or 0)
    if _is_mop(mop, "mop_S", {3, 5}):
        s = getattr(mop, "s", None)
        off = getattr(s, "off", getattr(mop, "stkoff", None))
        if off is None:
            return None
        return _StateVarIdentity("stack", int(off), size)
    if _is_mop(mop, "mop_l", {9, 10}):
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


def _is_mop(mop: object, name: str, fallback_values: set[int]) -> bool:
    t = getattr(mop, "t", None)
    if t == name or str(t) == name:
        return True
    try:
        import ida_hexrays  # type: ignore[import-untyped]

        expected = getattr(ida_hexrays, name)
        return int(t) == int(expected)
    except Exception:
        try:
            return int(t) in fallback_values
        except Exception:
            return False


def _is_jz(opcode: object) -> bool:
    return _is_opcode(opcode, "m_jz", fallback_values={24})


def _is_jnz(opcode: object) -> bool:
    return _is_opcode(opcode, "m_jnz", fallback_values={25})


def _is_opcode(
    opcode: object,
    name: str,
    *,
    fallback_values: set[int],
) -> bool:
    if opcode == name or str(opcode) == name:
        return True
    try:
        import ida_hexrays  # type: ignore[import-untyped]

        expected = getattr(ida_hexrays, name)
        return int(opcode) == int(expected)
    except Exception:
        try:
            return int(opcode) in fallback_values
        except Exception:
            return False


__all__ = ["extract_state_dispatcher_map_from_mba"]
