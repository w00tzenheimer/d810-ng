"""Portability gates for the relocated expression DSL (d810.ir.expr) — ticket llr-n2so.

Three guarantees:
1. No dynamic imports in ir/expr (the static `portable-core-no-ida` contract cannot
   see `importlib.import_module(...)`, which is exactly how the old hexrays_helpers
   leak hid).
2. ir/expr imports + evaluates with `ida_hexrays`/`idaapi` masked (the airtight
   proof: execution, not static analysis).
3. The sealed matching-time checks route through the injected MopOpsProvider (the
   seal is real, not dead code) and degrade conservatively with no provider.
"""
from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

import d810.ir.expr as E


def test_no_dynamic_imports_in_ir_expr() -> None:
    pkg = pathlib.Path(E.__file__).parent
    offenders: list[str] = []
    for py in sorted(pkg.glob("*.py")):
        tree = ast.parse(py.read_text(), filename=str(py))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr in {"import_module", "__import__"}:
                offenders.append(f"{py.name}:{node.lineno} importlib.{fn.attr}")
            if isinstance(fn, ast.Name) and fn.id == "__import__":
                offenders.append(f"{py.name}:{node.lineno} __import__")
    assert not offenders, (
        "dynamic imports are banned in d810.ir.expr (they bypass the static "
        f"portability contract): {offenders}"
    )


def test_ir_expr_loads_and_evaluates_without_ida() -> None:
    # Subprocess so the import graph is clean; mask the IDA modules so any reach
    # raises ImportError. Inherits PYTHONPATH=src:tests from the test invocation.
    script = (
        "import sys\n"
        "sys.modules['ida_hexrays'] = None\n"
        "sys.modules['idaapi'] = None\n"
        "import d810.ir.expr as E\n"
        "x, y = E.Var('x'), E.Var('y')\n"
        "_ = (x | y) - (x & y)\n"        # full BV operator surface
        "_ = (x == y)\n"                  # comparison -> ConstraintExpr
        "assert E.get_mop_ops() is None\n"
        "assert E.when.is_bnot('a', 'b')({}) is False\n"  # sealed check, no-provider fallback
        "assert 'ida_hexrays' not in [m for m, v in sys.modules.items() if v is not None]\n"
        "print('PORTABLE_OK')\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True
    )
    assert r.returncode == 0, f"rc={r.returncode}\nstderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    assert "PORTABLE_OK" in r.stdout, r.stdout


def test_sealed_check_routes_through_injected_provider() -> None:
    class _FakeMopOps:
        def equal_mops_ignore_size(self, lo, ro):
            return lo == ro

        def equal_bnot_mop(self, lo, ro):
            return True  # distinct from the no-provider default (False)

    class _Bound:
        def __init__(self, mop):
            self.mop = mop

    try:
        E.register_mop_ops(_FakeMopOps())
        check = E.when.is_bnot("a", "b")
        # With a provider, is_bnot delegates to equal_bnot_mop -> True (vs False default)
        assert check({"a": _Bound(1), "b": _Bound(2)}) is True
    finally:
        E.register_mop_ops(None)
    # After clearing, the conservative default returns
    assert E.when.is_bnot("a", "b")({"a": _Bound(1), "b": _Bound(2)}) is False
