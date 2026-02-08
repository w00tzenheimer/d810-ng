"""Expression patterns for ctree matching.

Contains patterns for matching ctree expression nodes (``cexpr_t``):
function calls, objects, numbers, variables, binary/unary operators,
casts, ternary, and more. Auto-generates named patterns for all
binary and unary ops.

Ported from herast (herast/tree/patterns/expressions.py).
"""
from __future__ import annotations

import sys
import typing

from d810.core import getLogger
from d810.ctree.patterns.base_pattern import BasePat
from d810.ctree.match_context import MatchContext

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import idaapi
except ImportError:
    idaapi = None  # type: ignore[assignment]


class ExpressionPat(BasePat):
    """Base class for expression item patterns."""

    op: int | None = None

    def __init__(
        self,
        check_op: int | None = None,
        skip_casts: bool = True,
        **kwargs: typing.Any,
    ) -> None:
        """
        :param skip_casts: should skip type casting
        """
        super().__init__(check_op=self.op, **kwargs)
        self.skip_casts = skip_casts

    @staticmethod
    def expr_check(func: typing.Callable) -> typing.Callable:
        """Decorator that unwraps casts before applying base_check."""
        base_check = BasePat.base_check(func)

        def __perform_expr_check(
            self: ExpressionPat, item: typing.Any, *args: typing.Any, **kwargs: typing.Any
        ) -> bool:
            if idaapi is not None and self.skip_casts and item.op == idaapi.cot_cast:
                item = item.x
            return base_check(self, item, *args, **kwargs)

        return __perform_expr_check


class CallPat(ExpressionPat):
    """Pattern for matching function calls."""

    op = idaapi.cot_call if idaapi is not None else None

    def __init__(
        self,
        calling_function: typing.Any,
        *arguments: BasePat,
        ignore_arguments: bool = False,
        skip_missing: bool = False,
        **kwargs: typing.Any,
    ) -> None:
        """
        :param calling_function: what function is called.
        :param arguments: call arguments.
        :param ignore_arguments: whether or not should match arguments.
        :param skip_missing: skip missing arguments/patterns.
        """
        super().__init__(**kwargs)
        if isinstance(calling_function, str):
            calling_function = ObjPat(calling_function)
        if isinstance(calling_function, int):
            calling_function = ObjPat(calling_function)
        self.calling_function = calling_function
        self.arguments: tuple[BasePat, ...] = arguments
        self.ignore_arguments = ignore_arguments
        self.skip_missing = skip_missing

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        if self.calling_function is not None and not self.calling_function.check(
            expression.x, ctx
        ):
            return False
        if self.ignore_arguments:
            return True
        if len(self.arguments) != len(expression.a) and not self.skip_missing:
            return False
        min_l = min(len(self.arguments), len(expression.a))
        for arg_id in range(min_l):
            if not self.arguments[arg_id].check(expression.a[arg_id], ctx):
                return False
        return True

    @property
    def children(self) -> tuple:
        return (self.calling_function, *self.arguments)


class HelperPat(ExpressionPat):
    """Pattern for matching helper objects."""

    op = idaapi.cot_helper if idaapi is not None else None

    def __init__(self, helper_name: str | None = None, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.helper_name = helper_name

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return (
            self.helper_name == expression.helper
            if self.helper_name is not None
            else True
        )

    @property
    def children(self) -> tuple:
        return ()


class NumPat(ExpressionPat):
    """Pattern for matching numbers."""

    op = idaapi.cot_num if idaapi is not None else None

    def __init__(self, num: int | None = None, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.num = num

    @ExpressionPat.expr_check
    def check(self, expr: typing.Any, ctx: MatchContext) -> bool:
        if self.num is None:
            return True
        return self.num == expr.n._value


class CastPat(ExpressionPat):
    """Pattern for implicit cast matching."""

    op = idaapi.cot_cast if idaapi is not None else None

    def __init__(self, pat: BasePat, skip_casts: bool = False, **kwargs: typing.Any) -> None:
        super().__init__(skip_casts=False, **kwargs)
        self.pat = pat

    @ExpressionPat.expr_check
    def check(self, item: typing.Any, ctx: MatchContext, *args: typing.Any, **kwargs: typing.Any) -> bool:
        return self.pat.check(item.x, ctx)


class ObjPat(ExpressionPat):
    """Pattern for matching objects with addresses."""

    op = idaapi.cot_obj if idaapi is not None else None

    def __init__(self, *objects: typing.Any, **kwargs: typing.Any) -> None:
        """
        :param objects: int addresses or str names to match.
        """
        super().__init__(**kwargs)
        self.addrs: set[int] = set()
        self.names: set[str] = set()

        for obj_info in objects:
            if isinstance(obj_info, int):
                self.addrs.add(obj_info)
                if idaapi is not None and not idaapi.is_mapped(obj_info):
                    logger.warning(
                        "object with address %s is not mapped. Will still try to match it",
                        hex(obj_info),
                    )
                    continue
                if idaapi is not None:
                    name = idaapi.get_name(obj_info)
                    if name != "":
                        self.names.add(name)
            elif isinstance(obj_info, str):
                self.names.add(obj_info)
                if idaapi is not None:
                    from d810.ctree.utils import resolve_name_address
                    addr = resolve_name_address(obj_info)
                    if addr == idaapi.BADADDR:
                        logger.warning(
                            "object with name %s does not exist. Will still try to match it",
                            obj_info,
                        )
                        continue
                    self.addrs.add(addr)
            else:
                raise TypeError("Object info should be int|str")

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        # if no object was given aka any object, that passes expr_check
        if len(self.addrs) == 0 and len(self.names) == 0:
            return True
        if len(self.addrs) != 0 and expression.obj_ea in self.addrs:
            return True
        if len(self.names) == 0:
            return False
        if idaapi is None:
            return False
        ea_name = idaapi.get_name(expression.obj_ea)
        if ea_name in self.names:
            return True
        demangled_ea_name = idaapi.demangle_name(
            ea_name, idaapi.MNG_NODEFINIT | idaapi.MNG_NORETTYPE
        )
        return demangled_ea_name in self.names


class RefPat(ExpressionPat):
    """Pattern for matching references."""

    op = idaapi.cot_ref if idaapi is not None else None

    def __init__(self, referenced_object: BasePat, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.referenced_object = referenced_object

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return self.referenced_object.check(expression.x, ctx)


class MemrefPat(ExpressionPat):
    """Pattern for matching memory references."""

    op = idaapi.cot_memref if idaapi is not None else None

    def __init__(
        self, referenced_object: BasePat, field: int | None = None, **kwargs: typing.Any
    ) -> None:
        super().__init__(**kwargs)
        self.referenced_object = referenced_object
        self.field = field

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return (
            self.field is None or self.field == expression.m
        ) and self.referenced_object.check(expression.x, ctx)


class PtrPat(ExpressionPat):
    """Pattern for matching pointer dereferences."""

    op = idaapi.cot_ptr if idaapi is not None else None

    def __init__(self, pointed_object: BasePat, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.pointed_object = pointed_object

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return self.pointed_object.check(expression.x, ctx)


class MemptrPat(ExpressionPat):
    """Pattern for matching memory pointers."""

    op = idaapi.cot_memptr if idaapi is not None else None

    def __init__(
        self, pointed_object: BasePat, field: int | None = None, **kwargs: typing.Any
    ) -> None:
        super().__init__(**kwargs)
        self.pointed_object = pointed_object
        self.field = field

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return (
            self.field is None or self.field == expression.m
        ) and self.pointed_object.check(expression.x, ctx)


class IdxPat(ExpressionPat):
    """Pattern for matching array index operations."""

    op = idaapi.cot_idx if idaapi is not None else None

    def __init__(
        self, pointed_object: BasePat, indx: BasePat | int, **kwargs: typing.Any
    ) -> None:
        super().__init__(**kwargs)
        self.pointed_object = pointed_object
        if isinstance(indx, int):
            indx = NumPat(indx)
        self.indx: BasePat = indx

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return self.pointed_object.check(expression.x, ctx) and self.indx.check(
            expression.y, ctx
        )


class TernPat(ExpressionPat):
    """Pattern for C's ternary operator."""

    op = idaapi.cot_tern if idaapi is not None else None

    def __init__(
        self,
        condition: BasePat,
        positive_expression: BasePat,
        negative_expression: BasePat,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)
        self.condition = condition
        self.positive_expression = positive_expression
        self.negative_expression = negative_expression

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return (
            self.condition.check(expression.x, ctx)
            and self.positive_expression.check(expression.y, ctx)
            and self.negative_expression.check(expression.z, ctx)
        )


class VarPat(ExpressionPat):
    """Pattern for matching variables."""

    op = idaapi.cot_var if idaapi is not None else None

    def __init__(self, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return True


class AbstractUnaryOpPat(ExpressionPat):
    """Abstract class for C's unary operators."""

    def __init__(self, operand: BasePat, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.operand = operand

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        return self.operand.check(expression.x, ctx)

    @property
    def children(self) -> tuple[BasePat]:
        return (self.operand,)


class AbstractBinaryOpPat(ExpressionPat):
    """Abstract class for C's binary operators."""

    def __init__(
        self,
        first_operand: BasePat,
        second_operand: BasePat,
        symmetric: bool = False,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)
        self.first_operand = first_operand
        self.second_operand = second_operand
        self.symmetric = symmetric

    @ExpressionPat.expr_check
    def check(self, expression: typing.Any, ctx: MatchContext) -> bool:
        first_op_second = self.first_operand.check(
            expression.x, ctx
        ) and self.second_operand.check(expression.y, ctx)
        if self.symmetric:
            second_op_first = self.first_operand.check(
                expression.y, ctx
            ) and self.second_operand.check(expression.x, ctx)
            return first_op_second or second_op_first
        else:
            return first_op_second

    @property
    def children(self) -> tuple[BasePat, BasePat]:
        return (self.first_operand, self.second_operand)


class AsgPat(ExpressionPat):
    """Pattern for assignment expression."""

    op = idaapi.cot_asg if idaapi is not None else None

    def __init__(self, lhs: BasePat, rhs: BasePat, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.lhs = lhs
        self.rhs = rhs

    @ExpressionPat.expr_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        if not self.lhs.check(item.x, ctx):
            return False
        return self.rhs.check(item.y, ctx)


class FnumPat(ExpressionPat):
    """Pattern for floating-point number constants."""

    op = idaapi.cot_fnum if idaapi is not None else None

    def __init__(self, value: typing.Any = None, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.value = value

    @ExpressionPat.expr_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        if self.value is not None and self.value != item.fpc.fnum:
            return False
        return True


class StrPat(ExpressionPat):
    """Pattern for string constants."""

    op = idaapi.cot_str if idaapi is not None else None

    def __init__(self, value: str | None = None, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.value = value

    @ExpressionPat.expr_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        if self.value is not None and self.value != item.string:
            return False
        return True


class TypePat(ExpressionPat):
    """Pattern for type expressions."""

    op = idaapi.cot_type if idaapi is not None else None

    def __init__(self, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)

    @ExpressionPat.expr_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        return True


# ---------------------------------------------------------------------------
# Auto-generate named patterns for all binary and unary ops
# ---------------------------------------------------------------------------
def _generate_expression_patterns() -> None:
    """Dynamically create pattern classes for each unary/binary op."""
    module = sys.modules[__name__]
    from d810.ctree.consts import binary_expressions_ops, unary_expressions_ops, op2str

    for op_val in unary_expressions_ops:
        name = "%sPat" % op2str[op_val].replace("cot_", "").capitalize()
        # pattern was already added explicitly
        if name in vars(module):
            continue
        vars(module)[name] = type(name, (AbstractUnaryOpPat,), {"op": op_val})

    for op_val in binary_expressions_ops:
        name = "%sPat" % op2str[op_val].replace("cot_", "").capitalize()
        # pattern was already added explicitly
        if name in vars(module):
            continue
        vars(module)[name] = type(name, (AbstractBinaryOpPat,), {"op": op_val})


# Only generate when IDA is available
if idaapi is not None:
    _generate_expression_patterns()
