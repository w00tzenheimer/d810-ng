"""Self-maintaining ownership for the Python/Cython runtime parity slice."""

from __future__ import annotations

import ast
from pathlib import Path


# These exercise a compiled seam indirectly and therefore cannot be inferred
# from imports alone. Direct speedup/CythonMode imports are discovered below.
_INDIRECT_RUNTIME_BOUNDARIES = frozenset(
    {
        "tests/system/hexrays/contracts/test_parity_differential.py",
        "tests/system/runtime/hexrays/test_callback_mutation_diagnostics.py",
        "tests/system/runtime/hexrays/test_detached_snippet_companion_regression.py",
        "tests/system/runtime/hexrays/test_mop_ast_cache_scope.py",
        "tests/system/runtime/support/test_mutation_witness.py",
        "tests/system/runtime/test_bindings_proxy.py",
        "tests/system/runtime/test_block_optimizer_perf_counters.py",
        "tests/system/runtime/test_ctree_hooks.py",
        "tests/system/runtime/test_cython_optimizer_parity.py",
        "tests/system/runtime/test_pattern_speedups.py",
        "tests/system/runtime/test_z3_astproxy_regression.py",
    }
)


def _imports_speedup_boundary(path: Path) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module == "d810.core.cymode" or node.module.startswith(
                "d810.speedups"
            ):
                return True
        if isinstance(node, ast.Import):
            if any(alias.name.startswith("d810.speedups") for alias in node.names):
                return True
    return False


def speedup_parity_modules(repository_root: Path) -> frozenset[str]:
    """Return reviewed indirect seams plus every directly imported speedup seam."""
    root = Path(repository_root)
    system_root = root / "tests" / "system"
    discovered = {
        path.relative_to(root).as_posix()
        for path in system_root.rglob("test_*.py")
        if _imports_speedup_boundary(path)
    }
    existing_indirect = {
        module for module in _INDIRECT_RUNTIME_BOUNDARIES if (root / module).is_file()
    }
    return frozenset(existing_indirect | discovered)


__all__ = ["speedup_parity_modules"]
