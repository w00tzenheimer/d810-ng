"""High-level pattern matcher for ctree.

``Matcher`` combines schemes (pattern + handler pairs) with an
``ASTProcessor`` to walk a ``cfunc_t`` and collect/apply all matches.

Ported from herast (herast/tree/matcher.py).
"""
from __future__ import annotations

import traceback
import typing

from d810.core import getLogger
from d810.ctree.ast_context import ASTContext
from d810.ctree.ast_patch import ASTPatch
from d810.ctree.ast_processor import ASTProcessor
from d810.ctree.match_context import MatchContext
from d810.ctree.scheme import Scheme
from d810.ctree import utils

logger = getLogger("D810.ctree")

# ---------------------------------------------------------------------------
# IDA imports are optional for testing.
# ---------------------------------------------------------------------------
try:
    import idaapi
    import idc
except ImportError:
    idaapi = None  # type: ignore[assignment]
    idc = None  # type: ignore[assignment]


class Matcher:
    """High-level API combining patterns + processor + context.

    Walks a ``cfunc_t`` and applies schemes (pattern/handler pairs).
    """

    def __init__(self, *schemes: Scheme) -> None:
        self.schemes: dict[str, Scheme] = {
            "scheme" + str(i): s for i, s in enumerate(schemes)
        }

    def get_scheme(self, scheme_name: str) -> Scheme | None:
        """Look up a scheme by name."""
        return self.schemes.get(scheme_name)

    def add_scheme(self, name: str, scheme: Scheme) -> None:
        """Add a scheme with the given name."""
        self.schemes[name] = scheme

    def remove_scheme(self, scheme_name: str) -> None:
        """Remove a scheme by name."""
        self.schemes.pop(scheme_name, None)

    def match(self, *functions: typing.Any) -> None:
        """Match schemes for function body.

        :param functions: matched functions. Can be decompiled cfuncs,
                          function addresses, or function names.
        """
        for func in functions:
            if idaapi is not None and isinstance(func, idaapi.cfunc_t):
                self.match_cfunc(func)
            elif isinstance(func, str):
                if idc is None:
                    continue
                addr = idc.get_name_ea_simple(func)
                cfunc = utils.get_cfunc(addr)
                if cfunc is None:
                    continue
                self.match_cfunc(cfunc)
            elif isinstance(func, int):
                cfunc = utils.get_cfunc(func)
                if cfunc is None:
                    continue
                self.match_cfunc(cfunc)
            else:
                raise TypeError("Invalid function type")

    def match_cfunc(self, cfunc: typing.Any) -> None:
        """Match schemes in a decompiled function."""
        ast_tree = cfunc.body
        ast_ctx = ASTContext(cfunc)

        schemes = [s for s in self.schemes.values() if s.stype is s.SchemeType.GENERIC]
        self.match_ast_tree(ast_tree, ast_ctx, schemes)

        singulars = [
            s for s in self.schemes.values() if s.stype is s.SchemeType.SINGULAR
        ]
        for s in singulars:
            self.match_ast_tree(ast_tree, ast_ctx, [s])

        schemes = [
            s for s in self.schemes.values() if s.stype is s.SchemeType.READONLY
        ]
        self.match_ast_tree(ast_tree, ast_ctx, schemes)

    def match_ast_tree(
        self,
        ast_tree: typing.Any,
        ast_ctx: ASTContext,
        schemes: list[Scheme],
    ) -> None:
        """Walk the AST and apply schemes."""
        for scheme in schemes:
            scheme.on_tree_iteration_start()

        ast_proc = ASTProcessor(ast_tree)
        while (subitem := ast_proc.get_current()) is not None:
            ast_patch = self.check_schemes(subitem, ast_ctx, schemes)
            if ast_patch is None:
                ast_proc.pop_current()
                continue

            if not ast_proc.apply_patch(ast_patch, ast_ctx):
                ast_proc.pop_current()
                continue

            # check if patch restarted iteration
            if ast_proc.is_iteration_started():
                for scheme in schemes:
                    scheme.on_tree_iteration_start()

        for scheme in schemes:
            scheme.on_tree_iteration_end()

    def check_schemes(
        self,
        item: typing.Any,
        ast_ctx: ASTContext,
        schemes: list[Scheme],
    ) -> ASTPatch | None:
        """Check item against all schemes."""
        for scheme in schemes:
            ast_patch = self.check_scheme(scheme, item, ast_ctx)
            if ast_patch is not None:
                return ast_patch
        return None

    def check_scheme(
        self, scheme: Scheme, item: typing.Any, ast_ctx: ASTContext
    ) -> ASTPatch | None:
        """Check item against a single scheme with exception handling."""
        try:
            return self._check_scheme(scheme, item, ast_ctx)
        except Exception as e:
            logger.error("Got an exception during scheme checking: %s", e)
            logger.debug(traceback.format_exc())
            return None

    def _check_scheme(
        self, scheme: Scheme, item: typing.Any, ast_ctx: ASTContext
    ) -> ASTPatch | None:
        """Internal: check item against scheme patterns."""
        for pat in scheme.patterns:
            mctx = MatchContext(ast_ctx, pat)
            # check that pattern matches AST item
            if not pat.check(item, mctx):
                continue

            # handle user's scheme callback
            ast_patch = scheme.on_matched_item(item, mctx)
            if ast_patch is None:
                continue

            # validate return type
            if not isinstance(ast_patch, ASTPatch):
                raise TypeError(
                    "Handler returned invalid return type, should be ASTPatch or None"
                )
            return ast_patch

        return None
