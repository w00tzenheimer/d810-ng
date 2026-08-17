"""Checked instruction-level materialization for fixed-width rotate helpers.

Rotate helpers are Hex-Rays call instructions, not ordinary expression nodes.
This backend owns their construction so every caller supplies the active MBA
and destination context explicitly.  No IDB-local type handle or native
allocator state is retained between calls.
"""

from __future__ import annotations

import ida_hexrays
import ida_typeinf

from d810.core.typing import Any
from d810.mba.typed_term import TypedBvTerm


_ROTATE_WIDTHS = {1: 8, 2: 16, 4: 32, 8: 64}
_ROTATE_HELPERS = {
    f"__{direction}{size}__": (direction.lower(), size * 8)
    for direction in ("ROL", "ROR")
    for size in _ROTATE_WIDTHS
}


def _dup_mop(source: ida_hexrays.mop_t) -> ida_hexrays.mop_t:
    """Detach one live operand without importing the Hex-Rays utility layer."""

    result = ida_hexrays.mop_t()
    result.assign(source)
    return result


def _fresh_uint_type(declaration: int) -> ida_typeinf.tinfo_t:
    """Create a type handle owned by the currently active IDB."""

    type_info = ida_typeinf.tinfo_t()
    type_info.create_simple_type(declaration)
    return type_info


def _width_of(mop: Any | None) -> int:
    try:
        return 0 if mop is None else int(mop.size) * 8
    except (AttributeError, TypeError, ValueError):
        return 0


def _helper_spec(helper: object) -> tuple[str, int] | None:
    if type(helper) is not str:
        return None
    return _ROTATE_HELPERS.get(helper)


def _native_mop(value: Any) -> Any | None:
    """Clone one live mop or reconstruct one owned snapshot operand."""

    if isinstance(value, ida_hexrays.mop_t):
        return _dup_mop(value)
    to_mop = getattr(value, "to_mop", None)
    if callable(to_mop):
        try:
            return to_mop()
        except Exception:
            return None
    mop = getattr(value, "mop", None)
    if mop is not None:
        to_mop = getattr(mop, "to_mop", None)
        if callable(to_mop):
            try:
                return to_mop()
            except Exception:
                return None
        if isinstance(mop, ida_hexrays.mop_t):
            return _dup_mop(mop)
    return None


def _native_ea(lowering: Any, block: Any, destination: Any) -> int:
    """Choose an instruction EA from preserved native/source context."""

    candidates: list[Any] = []
    for nodes in (
        getattr(lowering, "raw_native_nodes_by_path", None),
        getattr(lowering, "native_nodes_by_path", None),
    ):
        if nodes is not None:
            try:
                candidates.append(nodes.get((), None))
            except (AttributeError, TypeError):
                pass
    if block is not None:
        candidates.extend(
            (
                getattr(block, "head", None),
                getattr(block, "tail", None),
            )
        )
    # A live destination may carry an EA in some IDA builds.  Keep it as a
    # last resort only; mop_t normally has no meaningful EA of its own.
    candidates.append(destination)
    for candidate in candidates:
        try:
            value = getattr(candidate, "ea", None)
        except Exception:
            continue
        if type(value) is int:
            return value
    return 0


def _number_mop(value: int, size: int, ea: int) -> ida_hexrays.mop_t | None:
    try:
        result = ida_hexrays.mop_t()
        result.make_number(value & ((1 << (size * 8)) - 1), size, ea)
        return result
    except Exception:
        return None


def make_rotate_helper_call(
    block: ida_hexrays.mblock_t,
    *,
    ea: int,
    helper: str,
    base: Any,
    rotation: int,
    output: Any,
) -> ida_hexrays.minsn_t | None:
    """Build a value-producing fixed-width rotate helper instruction.

    All admission checks occur before creating types, allocating arguments, or
    asking the active MBA to construct an instruction.
    """

    spec = _helper_spec(helper)
    if spec is None:
        return None
    _, width = spec
    if (
        block is None
        or type(rotation) is not int
        or not 0 <= rotation < width
        or _width_of(base) != width
        or _width_of(output) != width
    ):
        return None
    try:
        uint_type = _fresh_uint_type(
            getattr(ida_typeinf, f"BTF_UINT{width}")
        )
        uint8_type = _fresh_uint_type(ida_typeinf.BTF_UINT8)
        value_arg = ida_hexrays.mcallarg_t()
        value_arg.copy_mop(_dup_mop(base))
        value_arg.type = uint_type
        count_arg = ida_hexrays.mcallarg_t()
        count_arg.make_number(rotation, 1, ea)
        count_arg.type = uint8_type
        args = ida_hexrays.mcallargs_t()
        args.push_back(value_arg)
        args.push_back(count_arg)
        return block.mba.create_helper_call(
            ea,
            helper,
            uint_type,
            args,
            _dup_mop(output),
        )
    except Exception:
        return None


def make_rol8_helper_call(
    block: ida_hexrays.mblock_t,
    *,
    ea: int,
    base: Any,
    rotation: int,
    output: Any,
) -> ida_hexrays.minsn_t | None:
    """Compatibility wrapper preserving the direct pass's 64-bit contract."""

    if type(rotation) is not int or not 1 <= rotation < 64:
        return None
    return make_rotate_helper_call(
        block,
        ea=ea,
        helper="__ROL8__",
        base=base,
        rotation=rotation,
        output=output,
    )


def materialize_rotate_term(
    term: TypedBvTerm,
    *,
    lowering: Any,
    block: ida_hexrays.mblock_t,
    destination: Any,
) -> ida_hexrays.minsn_t | None:
    """Materialize one admitted rotate term using the active native context."""

    if not isinstance(term, TypedBvTerm) or term.operation not in {"rol", "ror"}:
        return None
    if len(term.children) != 1 or type(term.shift_count) is not int:
        return None
    size = term.width // 8
    helper = f"__{term.operation.upper()}{size}__"
    spec = _helper_spec(helper)
    if spec is None or spec[1] != term.width:
        return None
    if not 0 <= term.shift_count < term.width:
        return None
    if block is None or _width_of(destination) != term.width:
        return None
    ea = _native_ea(lowering, block, destination)
    child = term.children[0]
    if child.operation is not None:
        return None
    if child.value is not None:
        base = _number_mop(child.value, size, ea)
    else:
        source = (
            lowering.leafs.get(child.leaf_key)
            if child.leaf_key is not None
            else None
        )
        base = _native_mop(source) if source is not None else None
    if base is None:
        return None
    return make_rotate_helper_call(
        block,
        ea=ea,
        helper=helper,
        base=base,
        rotation=term.shift_count,
        output=destination,
    )


__all__ = [
    "make_rol8_helper_call",
    "make_rotate_helper_call",
    "materialize_rotate_term",
]
