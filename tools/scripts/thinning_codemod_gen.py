#!/usr/bin/env python3
"""Staged libcst->regex codemod primitives for one thinning slice.

Mirrors the canonical project template ``tools/scripts/codemod_rename_mba_backends.py``:

* ``rewrite_imports`` -- libcst pass: rewrites ``ImportFrom`` module nodes by WHOLE dotted
  module match (immune to prefix collisions like ``branch_ownership`` vs
  ``branch_ownership_oracle``); falls back to ``rewrite_text`` if the file fails to parse.
* ``rewrite_text`` -- boundary-aware regex pass: catches docstrings, comments,
  ``importlib`` / ``RuntimeError`` string literals, and fully-qualified attribute access
  that libcst leaves verbatim.
* ``make_alias_shim`` -- sys.modules-alias shim re-exporting PUBLIC and PRIVATE names
  (avoids the ``_unresolved_fact`` ImportError trap).
"""
from __future__ import annotations

import re

import libcst as cst


def _dotted(node) -> str:
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        return _dotted(node.value) + "." + node.attr.value
    return ""


def _parse_dotted(dotted: str):
    parts = dotted.split(".")
    out = cst.Name(parts[0])
    for p in parts[1:]:
        out = cst.Attribute(value=out, attr=cst.Name(p))
    return out


class _ImportRewriter(cst.CSTTransformer):
    def __init__(self, old: str, new: str):
        self.old = old
        self.new = new

    def leave_ImportFrom(self, original, updated):
        if updated.module is None:
            return updated
        mod = _dotted(updated.module)
        if mod == self.old or mod.startswith(self.old + "."):
            tail = mod[len(self.old):]
            return updated.with_changes(module=_parse_dotted(self.new + tail))
        return updated


def rewrite_imports(src: str, *, old: str, new: str) -> str:
    """libcst ImportFrom rewrite; regex fallback on parse failure."""
    try:
        tree = cst.parse_module(src)
    except cst.ParserSyntaxError:
        return rewrite_text(src, old=old, new=new)
    return tree.visit(_ImportRewriter(old, new)).code


def rewrite_text(src: str, *, old: str, new: str) -> str:
    """Boundary-aware textual rename: ``old`` not followed by an identifier char."""
    return re.sub(re.escape(old) + r"(?![\w])", new, src)


def make_alias_shim(old: str, new: str) -> str:
    """sys.modules-alias shim re-exporting public AND private names."""
    return (
        f"# auto-generated thinning shim: {old} -> {new}\n"
        f"import sys as _sys\n"
        f"from {new} import *  # noqa: F401,F403\n"
        f"import {new} as _t\n"
        f"_sys.modules[__name__] = _t  # re-export public AND private names\n"
    )
