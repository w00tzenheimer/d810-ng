"""Live Hex-Rays adapter for the immutable SCCP program model.

This module is deliberately the only SCCP layer that walks ``mba_t`` and
``mop_t`` objects.  The solver and public facade consume the detached model
produced here, so no SWIG object can cross into a cached result.
"""

from __future__ import annotations

import importlib
import operator
from collections.abc import Mapping

from d810.evaluator.hexrays_microcode.sccp_model import (
    OperandKind,
    SccpBlock,
    SccpInstruction,
    SccpOperand,
    SccpProgram,
)


class SccpSnapshotError(RuntimeError):
    """Raised when live MBA data cannot be represented safely."""


_MISSING = object()
_OPCODE_NAMES = (
    "mov",
    "neg",
    "lnot",
    "bnot",
    "xds",
    "xdu",
    "low",
    "high",
    "add",
    "sub",
    "mul",
    "udiv",
    "sdiv",
    "umod",
    "smod",
    "or",
    "and",
    "xor",
    "shl",
    "shr",
    "sar",
    "setz",
    "setnz",
    "setae",
    "setb",
    "seta",
    "setbe",
    "setg",
    "setge",
    "setl",
    "setle",
    "goto",
    "jcnd",
    "jz",
    "jnz",
    "jae",
    "jb",
    "ja",
    "jbe",
    "jg",
    "jge",
    "jl",
    "jle",
)


def _read(obj: object, name: str, path: str) -> object:
    try:
        value = getattr(obj, name)
    except AttributeError as exc:
        raise SccpSnapshotError(f"{path} is missing {name}") from exc
    if value is None:
        raise SccpSnapshotError(f"{path}.{name} is missing")
    return value


def _as_index(value: object, path: str) -> int:
    if isinstance(value, bool):
        raise SccpSnapshotError(f"{path} must be an integer")
    try:
        return operator.index(value)
    except TypeError as exc:
        raise SccpSnapshotError(f"{path} must be an integer") from exc


def _operand_size(value: object, path: str, *, supported: bool = False) -> int:
    size = _as_index(value, path)
    if supported and size <= 0:
        raise SccpSnapshotError(f"{path} must be positive for a supported operand")
    # Hex-Rays uses negative sizes for a few unsupported/helper operands.  A
    # zero size is the model's conservative representation for those values.
    return max(0, size)


def _mop_type(mop: object, path: str) -> int:
    return _as_index(_read(mop, "t", path), f"{path}.t")


def _primitive(value: object, path: str) -> object:
    """Validate and detach a key before it enters the value-ID map."""

    if value is None or isinstance(value, (str, int, float, bool, bytes)):
        return value
    if isinstance(value, (tuple, list)):
        return tuple(_primitive(item, f"{path}[]") for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_primitive(item, f"{path}[]") for item in value)
    if isinstance(value, Mapping):
        items = {
            _primitive(key, f"{path}.key"): _primitive(item, f"{path}[key]")
            for key, item in value.items()
        }
        return items
    raise SccpSnapshotError(f"{path} contains live data of type {type(value).__name__}")


class _ValueIds:
    """Assign encounter-stable IDs while retaining detached result keys."""

    def __init__(self, get_mop_key: object) -> None:
        self._get_mop_key = get_mop_key
        self._ids: dict[object, int] = {}
        self.keys: dict[int, object] = {}

    def for_mop(self, mop: object, path: str) -> int:
        # These are the malformed/missing SWIG attribute and indexing errors
        # the live-key helper can raise.  RuntimeError and other exceptions
        # remain programming failures and must reach the caller unchanged.
        try:
            key = self._get_mop_key(mop)  # type: ignore[operator]
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            raise SccpSnapshotError(f"cannot identify {path}") from exc
        key = _primitive(key, f"{path}.key")
        try:
            value_id = self._ids.get(key)
        except TypeError as exc:
            raise SccpSnapshotError(f"{path}.key is not hashable") from exc
        if value_id is None:
            value_id = len(self._ids)
            self._ids[key] = value_id
            self.keys[value_id] = key
        return value_id


def _normalize_opcode(opcode: object, hx: object, path: str) -> str:
    if isinstance(opcode, str):
        name = opcode.strip().lower()
        return name[2:] if name.startswith("m_") else name
    number = _as_index(opcode, path)
    for name in _OPCODE_NAMES:
        candidate = getattr(hx, f"m_{name}", _MISSING)
        if candidate is not _MISSING:
            try:
                if _as_index(candidate, f"ida_hexrays.m_{name}") == number:
                    return name
            except SccpSnapshotError:
                continue
    # Unknown operations remain representable and are conservatively treated
    # as overdefined by the pure solver.
    return f"opcode_{number}"


def _snapshot_operand(
    mop: object | None,
    hx: object,
    value_ids: _ValueIds,
    path: str,
) -> SccpOperand | None:
    if mop is None:
        return None
    mop_type = _mop_type(mop, path)
    mop_z = _as_index(_read(hx, "mop_z", "ida_hexrays"), "ida_hexrays.mop_z")
    if mop_type == mop_z:
        return None
    mop_n = _as_index(_read(hx, "mop_n", "ida_hexrays"), "ida_hexrays.mop_n")
    mop_r = _as_index(_read(hx, "mop_r", "ida_hexrays"), "ida_hexrays.mop_r")
    mop_s = _as_index(_read(hx, "mop_S", "ida_hexrays"), "ida_hexrays.mop_S")
    size = _operand_size(
        _read(mop, "size", path),
        f"{path}.size",
        supported=mop_type in (mop_n, mop_r, mop_s),
    )

    if mop_type == mop_n:
        number = _read(mop, "nnn", path)
        value = _as_index(_read(number, "value", f"{path}.nnn"), f"{path}.nnn.value")
        return SccpOperand(kind=OperandKind.CONSTANT, size=size, constant=value)
    if mop_type in (mop_r, mop_s):
        value_id = value_ids.for_mop(mop, path)
        return SccpOperand(kind=OperandKind.VALUE, size=size, value_id=value_id)
    # mop_d/mop_f are intentionally not recursively traversed.  This keeps
    # the adapter's supported source surface at the existing one level and
    # makes nested/live objects proof-opaque.
    return SccpOperand(kind=OperandKind.UNSUPPORTED, size=size)


def _destination_value_id(
    mop: object | None,
    hx: object,
    value_ids: _ValueIds,
    path: str,
) -> int | None:
    if mop is None:
        return None
    mop_type = _mop_type(mop, path)
    mop_z = _as_index(_read(hx, "mop_z", "ida_hexrays"), "ida_hexrays.mop_z")
    if mop_type == mop_z:
        return None
    mop_r = _as_index(_read(hx, "mop_r", "ida_hexrays"), "ida_hexrays.mop_r")
    mop_s = _as_index(_read(hx, "mop_S", "ida_hexrays"), "ida_hexrays.mop_S")
    if mop_type not in (mop_r, mop_s):
        return None
    return value_ids.for_mop(mop, path)


def _block_serial(block: object, position: int) -> int:
    path = f"mba.block[{position}].serial"
    serial = _as_index(_read(block, "serial", f"mba.block[{position}]"), path)
    if serial < 0:
        raise SccpSnapshotError(f"{path} must be non-negative")
    return serial


def _successors(block: object, index: int, serials: frozenset[int]) -> tuple[int, ...]:
    raw = _read(block, "succset", f"mba.block[{index}]")
    try:
        values = list(raw)  # type: ignore[arg-type]
    except TypeError:
        size = _read(raw, "size", f"mba.block[{index}].succset")
        count = _as_index(size() if callable(size) else size, f"mba.block[{index}].succset.size")
        try:
            values = [raw[pos] for pos in range(count)]  # type: ignore[index]
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            raise SccpSnapshotError(f"cannot read successors for block {index}") from exc
    result: list[int] = []
    for pos, successor in enumerate(values):
        target = _as_index(successor, f"mba.block[{index}].succset[{pos}]")
        if target < 0 or target not in serials:
            raise SccpSnapshotError(
                f"block {index} has invalid successor {target} (known serials={sorted(serials)})"
            )
        result.append(target)
    return tuple(result)


def _size_for_mop(mop: object, hx: object, path: str) -> int:
    mop_type = _mop_type(mop, path)
    mop_n = _as_index(_read(hx, "mop_n", "ida_hexrays"), "ida_hexrays.mop_n")
    mop_r = _as_index(_read(hx, "mop_r", "ida_hexrays"), "ida_hexrays.mop_r")
    mop_s = _as_index(_read(hx, "mop_S", "ida_hexrays"), "ida_hexrays.mop_S")
    return _operand_size(
        _read(mop, "size", path),
        f"{path}.size",
        supported=mop_type in (mop_n, mop_r, mop_s),
    )


def _instructions(
    block: object,
    block_index: int,
    hx: object,
    value_ids: _ValueIds,
    start_index: int,
) -> tuple[list[SccpInstruction], tuple[int, ...]]:
    try:
        head = getattr(block, "head")
    except AttributeError as exc:
        raise SccpSnapshotError(f"mba.block[{block_index}] is missing head") from exc
    current = None if head is None else head
    seen: set[int] = set()
    instructions: list[SccpInstruction] = []
    indices: list[int] = []
    while current is not None:
        identity = id(current)
        if identity in seen:
            raise SccpSnapshotError(f"instruction list cycles in block {block_index}")
        seen.add(identity)
        path = f"mba.block[{block_index}].insn[{len(instructions)}]"
        opcode = _normalize_opcode(_read(current, "opcode", path), hx, f"{path}.opcode")
        ea = _as_index(_read(current, "ea", path), f"{path}.ea")
        left_mop = getattr(current, "l", None)
        right_mop = getattr(current, "r", None)
        destination_mop = getattr(current, "d", None)
        left = _snapshot_operand(left_mop, hx, value_ids, f"{path}.l")
        right = _snapshot_operand(right_mop, hx, value_ids, f"{path}.r")
        destination_value_id = _destination_value_id(
            destination_mop,
            hx,
            value_ids,
            f"{path}.d",
        )
        destination_size = 0
        if destination_mop is not None:
            destination_size = _size_for_mop(destination_mop, hx, f"{path}.d")
        if destination_size == 0:
            for operand in (left_mop, right_mop):
                if operand is not None:
                    destination_size = _operand_size(
                        _read(operand, "size", f"{path}.operand"),
                        f"{path}.operand.size",
                    )
                    if destination_size:
                        break
        try:
            instruction = SccpInstruction(
                index=start_index + len(instructions),
                block_index=block_index,
                opcode=opcode,
                ea=ea,
                size=destination_size,
                left=left,
                right=right,
                destination_value_id=destination_value_id,
            )
        except (TypeError, ValueError) as exc:
            raise SccpSnapshotError(f"malformed {path}") from exc
        instructions.append(instruction)
        indices.append(instruction.index)
        try:
            current = current.next
        except AttributeError as exc:
            raise SccpSnapshotError(f"{path} is missing next") from exc
    return instructions, tuple(indices)


def snapshot_from_mba(mba: object) -> SccpProgram:
    """Detach a live ``mba_t`` into a primitive :class:`SccpProgram`."""

    # Keep IDA and the compatibility key helper inside the live adapter.  The
    # rest of the SCCP stack remains importable and testable without IDA.
    import ida_hexrays

    get_mop_key = importlib.import_module("d810.hexrays.expr.p_ast").get_mop_key

    qty = _as_index(_read(mba, "qty", "mba"), "mba.qty")
    if qty <= 0:
        raise SccpSnapshotError(f"mba.qty must be positive, got {qty}")
    value_ids = _ValueIds(get_mop_key)
    ordered_blocks: list[tuple[int, object, int]] = []
    blocks_by_serial: dict[int, object] = {}
    for position in range(qty):
        try:
            block = mba.get_mblock(position)
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            raise SccpSnapshotError(f"cannot read mba.block[{position}]") from exc
        if block is None:
            raise SccpSnapshotError(f"mba.block[{position}] is missing")
        serial = _block_serial(block, position)
        if serial in blocks_by_serial:
            raise SccpSnapshotError(f"duplicate block serial {serial}")
        blocks_by_serial[serial] = block
        ordered_blocks.append((position, block, serial))

    serials = frozenset(blocks_by_serial)
    blocks: list[SccpBlock] = []
    instructions: list[SccpInstruction] = []
    for _position, block, serial in ordered_blocks:
        successors = _successors(block, serial, serials)
        block_instructions, indices = _instructions(
            block,
            serial,
            ida_hexrays,
            value_ids,
            len(instructions),
        )
        instructions.extend(block_instructions)
        blocks.append(
            SccpBlock(
                index=serial,
                successors=successors,
                instruction_indices=indices,
            )
        )
    try:
        return SccpProgram.from_parts(
            blocks=tuple(blocks),
            instructions=tuple(instructions),
            mop_keys_by_value=value_ids.keys,
            fingerprint_seed="sccp-snapshot-v1",
        )
    except (TypeError, ValueError) as exc:
        raise SccpSnapshotError("snapshot contains unsupported live data") from exc


__all__ = ["SccpSnapshotError", "snapshot_from_mba"]
