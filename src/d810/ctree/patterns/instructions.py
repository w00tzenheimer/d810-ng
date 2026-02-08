"""Instruction (statement) patterns for ctree matching.

Contains patterns for matching ctree statement nodes (``cinsn_t``):
``IfPat``, ``SwitchPat``, ``WhilePat``, ``ForPat``, ``RetPat``,
``GotoPat``, ``BlockPat``, ``BreakPat``, ``DoPat``, etc.

Ported from herast (herast/tree/patterns/instructions.py).
"""
from __future__ import annotations

import typing

from d810.core import getLogger
from d810.ctree.patterns.abstracts import AnyPat
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


class InstructionPat(BasePat):
    """Base pattern for instruction (statement) patterns."""

    SKIP_LABEL_CHECK: int = -3
    HAS_SOME_LABEL: int = -2
    HAS_NO_LABEL: int = -1

    def __init__(
        self, check_op: int | None = None, label_num: int = -3, **kwargs: typing.Any
    ) -> None:
        """
        :param label_num: is instr labeled? -3 means anything, -1 means not labeled,
                          -2 means is labeled, >=0 means label num
        """
        super().__init__(check_op=self.op, **kwargs)
        assert label_num >= -3
        self.label_num = label_num

    @staticmethod
    def instr_check(func: typing.Callable) -> typing.Callable:
        """Decorator for instruction pattern checking with label validation."""
        base_check = BasePat.base_check(func)

        def __perform_instr_check(
            self: InstructionPat, item: typing.Any, *args: typing.Any, **kwargs: typing.Any
        ) -> bool:
            # item.label_num == -1, if it has no label, otherwise item.label_num >= 0
            if self.label_num == self.SKIP_LABEL_CHECK:
                is_label_ok = True
            elif self.label_num == self.HAS_SOME_LABEL:
                is_label_ok = item.label_num != -1
            elif self.label_num == self.HAS_NO_LABEL:
                is_label_ok = item.label_num == -1
            else:
                is_label_ok = self.label_num == item.label_num

            if not is_label_ok:
                return False
            return base_check(self, item, *args, **kwargs)

        return __perform_instr_check


class BlockPat(InstructionPat):
    """Pattern for block instruction (curly braces)."""

    op = idaapi.cit_block if idaapi is not None else None

    def __init__(self, *patterns: BasePat, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.sequence: tuple[BasePat, ...] = patterns

    @InstructionPat.instr_check
    def check(self, instruction: typing.Any, ctx: MatchContext) -> bool:
        block = instruction.cblock
        if len(block) != len(self.sequence):
            return False
        for i, pat in enumerate(self.sequence):
            if not pat.check(block[i], ctx):
                return False
        return True

    @property
    def children(self) -> tuple:
        return (self.sequence,)


class ExprInsPat(InstructionPat):
    """Pattern for expression instruction (``...;``)."""

    op = idaapi.cit_expr if idaapi is not None else None

    def __init__(self, expr: BasePat | None = None, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.expr: BasePat = expr or AnyPat()

    @InstructionPat.instr_check
    def check(self, instruction: typing.Any, ctx: MatchContext) -> bool:
        return self.expr.check(instruction.cexpr, ctx)

    @property
    def children(self) -> tuple[BasePat]:
        return (self.expr,)


class IfPat(InstructionPat):
    """Pattern for if instruction."""

    op = idaapi.cit_if if idaapi is not None else None

    def __init__(
        self,
        condition: BasePat | None = None,
        then_branch: BasePat | None = None,
        else_branch: BasePat | None = None,
        should_wrap_in_block: bool = True,
        no_else: bool = False,
        **kwargs: typing.Any,
    ) -> None:
        """
        :param condition: if condition
        :param then_branch: if then block
        :param else_branch: if else block
        :param should_wrap_in_block: whether to wrap then/else in BlockPat
        """
        super().__init__(**kwargs)

        def wrap_pattern(pat: BasePat | None) -> BasePat:
            if pat is None:
                return AnyPat()
            if not should_wrap_in_block or isinstance(pat, AnyPat):
                return pat
            if idaapi is not None and pat.op == idaapi.cit_block:
                return pat
            # do not wrap expressions and abstracts
            if not isinstance(pat, InstructionPat):
                return pat
            return BlockPat(pat)

        self.condition: BasePat = condition or AnyPat()
        self.then_branch: BasePat = wrap_pattern(then_branch)
        self.else_branch: BasePat = wrap_pattern(else_branch)
        self.no_else = no_else

    @InstructionPat.instr_check
    def check(self, instruction: typing.Any, ctx: MatchContext) -> bool:
        cif = instruction.cif
        if self.no_else and cif.ielse is not None:
            return False
        rv = self.condition.check(cif.expr, ctx)
        if not rv:
            return False
        rv = self.then_branch.check(cif.ithen, ctx)
        if not rv:
            return False
        return self.else_branch.check(cif.ielse, ctx)

    @property
    def children(self) -> tuple[BasePat, BasePat, BasePat]:
        return (self.condition, self.then_branch, self.else_branch)


class ForPat(InstructionPat):
    """Pattern for for cycle instruction."""

    op = idaapi.cit_for if idaapi is not None else None

    def __init__(
        self,
        init: BasePat | None = None,
        expr: BasePat | None = None,
        step: BasePat | None = None,
        body: BasePat | None = None,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)
        self.init: BasePat = init or AnyPat()
        self.expr: BasePat = expr or AnyPat()
        self.step: BasePat = step or AnyPat()
        self.body: BasePat = body or AnyPat()

    @InstructionPat.instr_check
    def check(self, instruction: typing.Any, ctx: MatchContext) -> bool:
        cfor = instruction.cfor
        return (
            self.init.check(cfor.init, ctx)
            and self.expr.check(cfor.expr, ctx)
            and self.step.check(cfor.step, ctx)
            and self.body.check(cfor.body, ctx)
        )

    @property
    def children(self) -> tuple[BasePat, BasePat, BasePat, BasePat]:
        return (self.init, self.expr, self.step, self.body)


class RetPat(InstructionPat):
    """Pattern for return instruction."""

    op = idaapi.cit_return if idaapi is not None else None

    def __init__(self, expr: BasePat | None = None, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)
        self.expr: BasePat = expr or AnyPat()

    @InstructionPat.instr_check
    def check(self, instruction: typing.Any, ctx: MatchContext) -> bool:
        creturn = instruction.creturn
        return self.expr.check(creturn.expr, ctx)

    @property
    def children(self) -> tuple[BasePat]:
        return (self.expr,)


class WhilePat(InstructionPat):
    """Pattern for while cycle instruction."""

    op = idaapi.cit_while if idaapi is not None else None

    def __init__(
        self, expr: BasePat | None = None, body: BasePat | None = None, **kwargs: typing.Any
    ) -> None:
        super().__init__(**kwargs)
        self.expr: BasePat = expr or AnyPat()
        self.body: BasePat = body or AnyPat()

    @InstructionPat.instr_check
    def check(self, instruction: typing.Any, ctx: MatchContext) -> bool:
        cwhile = instruction.cwhile
        return self.expr.check(cwhile.expr, ctx) and self.body.check(cwhile.body, ctx)

    @property
    def children(self) -> tuple[BasePat, BasePat]:
        return (self.expr, self.body)


class DoPat(InstructionPat):
    """Pattern for do-while cycle instruction."""

    op = idaapi.cit_do if idaapi is not None else None

    def __init__(
        self, expr: BasePat | None = None, body: BasePat | None = None, **kwargs: typing.Any
    ) -> None:
        super().__init__(**kwargs)
        self.expr: BasePat = expr or AnyPat()
        self.body: BasePat = body or AnyPat()

    @InstructionPat.instr_check
    def check(self, instruction: typing.Any, ctx: MatchContext) -> bool:
        cdo = instruction.cdo
        return self.body.check(cdo.body, ctx) and self.expr.check(cdo.expr, ctx)

    @property
    def children(self) -> tuple[BasePat, BasePat]:
        return (self.expr, self.body)


class GotoPat(InstructionPat):
    """Pattern for goto instruction."""

    op = idaapi.cit_goto if idaapi is not None else None

    def __init__(self, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)

    @InstructionPat.instr_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        return True


class ContPat(InstructionPat):
    """Pattern for continue instruction."""

    op = idaapi.cit_continue if idaapi is not None else None

    def __init__(self, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)

    @InstructionPat.instr_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        return True


class BreakPat(InstructionPat):
    """Pattern for break instruction."""

    op = idaapi.cit_break if idaapi is not None else None

    def __init__(self, **kwargs: typing.Any) -> None:
        super().__init__(**kwargs)

    @InstructionPat.instr_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        return True


class SwitchPat(InstructionPat):
    """Pattern for switch instruction."""

    op = idaapi.cit_switch if idaapi is not None else None

    def __init__(
        self, expr: BasePat | None = None, *cases: typing.Any, **kwargs: typing.Any
    ) -> None:
        super().__init__(**kwargs)
        self.expr = expr
        self.cases: list[BasePat] = []
        self.valued_cases: dict[int, BasePat] = {}
        for case in cases:
            if isinstance(case, BasePat):
                self.cases.append(case)
            elif (
                isinstance(case, tuple)
                and len(case) == 2
                and isinstance(case[0], int)
                and isinstance(case[1], BasePat)
            ):
                if case[0] in self.valued_cases:
                    raise ValueError("Duplicate numbered case in switch")
                self.valued_cases[case[0]] = case[1]
            else:
                raise ValueError("Invalid case in switch")

    @InstructionPat.instr_check
    def check(self, item: typing.Any, ctx: MatchContext) -> bool:
        if self.expr is not None and not self.expr.check(item.cswitch.expr, ctx):
            return False
        for case in item.cswitch.cases:
            value = case.value()
            if value in self.valued_cases:
                if not self.valued_cases[value].check(case, ctx):
                    return False
            for check_case in self.cases:
                if check_case.check(case, ctx):
                    break
            else:
                return False
        return True
