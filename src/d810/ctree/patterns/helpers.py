"""Convenience pattern constructors for common matching scenarios.

Provides ``IntPat``, ``StringPat``, ``StructFieldAccessPat``,
``CallInsnPat``, and ``AsgInsnPat``.

Ported from herast (herast/tree/patterns/helpers.py).
"""
from __future__ import annotations

from d810.core import typing
from d810.core import getLogger
from d810.ctree.patterns.base_pattern import BasePat
from d810.ctree.match_context import MatchContext
from d810.ctree.patterns.expressions import AsgPat, CallPat
from d810.ctree.patterns.instructions import ExprInsPat

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import idaapi
    import ida_bytes
    import ida_nalt
except ImportError:
    idaapi = None  # type: ignore[assignment]
    ida_bytes = None  # type: ignore[assignment]
    ida_nalt = None  # type: ignore[assignment]


class IntPat(BasePat):
    """Pattern for expression that could be interpreted as integer."""

    def __init__(self, value: int | None = None, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.value = value

    @BasePat.base_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        if idaapi is None:
            return False
        if item.op not in (idaapi.cot_num, idaapi.cot_obj):
            return False
        if self.value is None:
            return True
        if item.op == idaapi.cot_num:
            check_value = item.n._value
        else:
            check_value = item.obj_ea
        return self.value == check_value


class StringPat(BasePat):
    """Pattern for expression that could be interpreted as string."""

    def __init__(
        self, str_value: str | None = None, minlen: int = 5, **kwargs: typing.Any
    ) -> None:
        super().__init__(**kwargs)
        self.str_value = str_value
        self.minlen = minlen

    @BasePat.base_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        if idaapi is None:
            return False
        if item.op == idaapi.cot_obj and item.is_cstr():
            ea = item.obj_ea
            if ea == idaapi.BADADDR:
                return False
            try:
                name = ida_bytes.get_strlit_contents(
                    ea, -1, ida_nalt.get_str_type(ea)
                ).decode()
            except TypeError:
                return False
        elif item.op == idaapi.cot_str:
            name = item.string
        else:
            return False

        if self.str_value is None:
            return len(name) >= self.minlen
        else:
            return self.str_value == name


class StructFieldAccessPat(BasePat):
    """Pattern for structure field access (by pointer or reference)."""

    def __init__(
        self,
        struct_type: typing.Any = None,
        member_offset: int | None = None,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)
        self.struct_type = struct_type
        self.member_offset = member_offset

    @BasePat.base_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        if idaapi is None:
            return False
        if item.op != idaapi.cot_memptr and item.op != idaapi.cot_memref:
            return False
        stype = item.x.type
        if stype.is_ptr():
            stype = stype.get_pointed_object()
        if not stype.is_struct():
            return False
        if self.member_offset is not None and self.member_offset != item.m:
            return False
        if self.struct_type is None:
            return True
        if isinstance(self.struct_type, str) and self.struct_type == str(stype):
            return True
        return self.struct_type == stype


def CallInsnPat(*args: typing.Any, **kwargs: typing.Any) -> ExprInsPat:
    """Convenience: ExprInsPat wrapping a CallPat."""
    return ExprInsPat(CallPat(*args, **kwargs))


def AsgInsnPat(x: BasePat, y: BasePat, **kwargs: typing.Any) -> ExprInsPat:
    """Convenience: ExprInsPat wrapping an AsgPat."""
    return ExprInsPat(AsgPat(x, y, **kwargs))
