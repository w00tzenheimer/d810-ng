"""AST context for ctree manipulation.

Wraps a ``cfunc_t`` and tracks which labels are referenced by gotos,
which is needed for safe instruction removal.

Ported from herast (herast/tree/ast_context.py).
"""
from __future__ import annotations

from d810.core import typing
from d810.core import getLogger
from d810.ctree.ast_iteration import collect_gotos, collect_labels

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import idaapi
except ImportError:
    idaapi = None  # type: ignore[assignment]


class ASTContext:
    """AST context, contains additional logic for information
    not present in the AST. Also has code for modifying the AST
    during pattern matching.
    """

    def __init__(self, cfunc: typing.Any) -> None:
        self.cfunc = cfunc
        self.label2gotos: dict[int, list] = {}
        self.label2instr: dict[int, typing.Any] = {}
        self.rebuild()
        self.is_modified: bool = False

    def rebuild(self) -> None:
        """Rebuild label-to-goto mappings from the cfunc body."""
        self.label2gotos.clear()
        self.label2instr.clear()
        gotos = collect_gotos(self.cfunc.body)
        labels = collect_labels(self.cfunc.body)
        for lbl in labels:
            self.label2gotos[lbl.label_num] = []
            self.label2instr[lbl.label_num] = lbl
        for g in gotos:
            label_num = g.cgoto.label_num
            if label_num in self.label2gotos:
                self.label2gotos[label_num].append(g)

    @property
    def func_addr(self) -> int:
        """Return the entry address of the function."""
        return self.cfunc.entry_ea

    @property
    def root(self) -> typing.Any:
        """Return the root cinsn_t (function body)."""
        return self.cfunc.body

    @property
    def func_name(self) -> str:
        """Return the name of the function."""
        if idaapi is not None:
            return idaapi.get_name(self.func_addr)
        return ""

    def get_parent_block(self, item: typing.Any) -> typing.Any | None:
        """Find the parent block of *item*."""
        parent = self.cfunc.body.find_parent_of(item)
        if parent is None:
            return None
        if idaapi is not None and parent.op != idaapi.cit_block:
            return None
        return parent
