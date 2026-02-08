"""Block search patterns for matching instruction sequences.

``SeqPat`` matches a sequence of consecutive instructions inside a
``cblock_t``.

Ported from herast (herast/tree/patterns/block_searches.py).
"""
from __future__ import annotations

import typing

from d810.core import getLogger
from d810.ctree.patterns.instructions import InstructionPat
from d810.ctree.match_context import MatchContext

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import idaapi
except ImportError:
    idaapi = None  # type: ignore[assignment]


class SeqPat(InstructionPat):
    """Pattern for matching a sequence of instructions inside a Block."""

    op = idaapi.cit_block if idaapi is not None else None

    def __init__(self, *pats: typing.Any, skip_missing: bool = True, **kwargs: typing.Any) -> None:
        """
        :param pats: instruction patterns
        :param skip_missing: whether should skip missing instructions
        """
        super().__init__(**kwargs)
        self.skip_missing = skip_missing

        if len(pats) == 1 and isinstance(pats[0], list):
            pats = tuple(pats[0])

        from d810.ctree.consts import cinsn_op2str
        for p in pats:
            if p.op is not None and cinsn_op2str.get(p.op) is None:
                logger.warning("SeqPat expects instructions, not expression")

        self.seq: tuple = tuple(pats)
        self.length: int = len(pats)

    @InstructionPat.instr_check
    def check(self, instruction: typing.Any, ctx: MatchContext) -> bool:
        container = instruction.cblock
        start_from = container.index(instruction)
        if start_from + self.length > len(container):
            return False
        if not self.skip_missing and len(container) != self.length + start_from:
            return False
        for i in range(self.length):
            if not self.seq[i].check(container[start_from + i], ctx):
                return False
        return True

    @property
    def children(self) -> tuple:
        return tuple(self.seq)
