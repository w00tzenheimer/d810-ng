#!/usr/bin/env python3
"""Phase 8 codemod: flatten evaluator concrete/symbolic/dataflow into evaluators.py.

Default mode is dry-run. Use --apply to write changes.
Use --delete-legacy to remove concrete.py/symbolic.py/dataflow.py after rewrite.
Run with: pyenv exec python tools/scripts/codemod_phase8_flatten_evaluator.py --dry-run
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path

import libcst as cst


MODULE_RENAMES: dict[str, str] = {
    "d810.evaluator.concrete": "d810.evaluator.evaluators",
    "d810.evaluator.symbolic": "d810.evaluator.evaluators",
    "d810.evaluator.dataflow": "d810.evaluator.evaluators",
}

EVALUATORS_TEMPLATE = '''"""Unified evaluator entrypoints and helper abstractions."""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import TypeAlias
from d810.errors import AstEvaluationException
from d810.evaluator.backend_registry import get_concrete_provider

_provider = get_concrete_provider("concrete")
ConcreteEvaluator = _provider.evaluator_type()
_default_evaluator = _provider.default_evaluator()


def evaluate_concrete(
    node: object,
    env: dict[int, int],
    *,
    evaluator: object | None = None,
) -> int:
    """Evaluate AST node using the configured concrete evaluator backend."""
    ev = evaluator if evaluator is not None else _default_evaluator
    return ev.evaluate(node, env)  # type: ignore[union-attr]


# Abstract interpreter state alias.
ConstMap: TypeAlias = dict[str, tuple[int, int]]

logger = getLogger(__name__)


def probe_is_constant(
    node: object,
    leaf_info_list: list,
    probe_values: list[int] | None = None,
) -> tuple[bool, int | None]:
    """Heuristic pre-filter: determine whether *node* evaluates to a constant."""
    if probe_values is None:
        probe_values = [0, 0xFFFFFFFF]

    results: set[int] = set()
    try:
        for probe in probe_values:
            env: dict[int, int] = {
                li.ast.ast_index: probe
                for li in leaf_info_list
                if li.ast.ast_index is not None
            }
            val = evaluate_concrete(node, env)
            if val is None:
                return False, None
            results.add(val)
    except (AstEvaluationException, ZeroDivisionError):
        logger.debug(
            "probe_is_constant: evaluation error for node=%r", node, exc_info=True
        )
        return False, None

    if len(results) == 1:
        return True, results.pop()
    return False, None


__all__ = [
    "ConcreteEvaluator",
    "_default_evaluator",
    "evaluate_concrete",
    "ConstMap",
    "probe_is_constant",
]
'''


def _ordered_module_renames() -> list[tuple[str, str]]:
    return sorted(MODULE_RENAMES.items(), key=lambda kv: len(kv[0]), reverse=True)


def rewrite_dotted_name(name: str) -> str:
    for old, new in _ordered_module_renames():
        if name == old or name.startswith(old + "."):
            return new + name[len(old) :]
    return name


class RenameTransformer(cst.CSTTransformer):
    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        name_code = cst.Module([]).code_for_node(updated_node.name)
        new_name = rewrite_dotted_name(name_code)
        if new_name != name_code:
            return updated_node.with_changes(name=cst.parse_expression(new_name))
        return updated_node

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom:
        module = updated_node.module
        if module is None:
            return updated_node
        module_code = cst.Module([]).code_for_node(module)
        new_module_code = rewrite_dotted_name(module_code)
        if new_module_code != module_code:
            return updated_node.with_changes(module=cst.parse_expression(new_module_code))
        return updated_node


def rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    transformed = module.visit(RenameTransformer())
    out = transformed.code
    for old, new in _ordered_module_renames():
        out = out.replace(old, new)
    return out


def iter_python_files(root: Path) -> list[Path]:
    self_path = Path(__file__).resolve()
    return sorted(
        p
        for p in root.rglob("*.py")
        if p.resolve() != self_path
        if ".git/" not in str(p)
        and ".venv/" not in str(p)
        and "__pycache__/" not in str(p)
        and "/build/" not in str(p)
        and "/dist/" not in str(p)
    )


def rewrite_files(root: Path, apply: bool) -> int:
    changed = 0
    for path in iter_python_files(root):
        src = path.read_text(encoding="utf-8")
        if "d810.evaluator.concrete" not in src and "d810.evaluator.symbolic" not in src and "d810.evaluator.dataflow" not in src:
            continue
        out = rewrite_text(src)
        if out == src:
            continue
        changed += 1
        if apply:
            path.write_text(out, encoding="utf-8")
            print(f"rewrote {path}")
        else:
            print(f"would rewrite {path}")
            diff = difflib.unified_diff(
                src.splitlines(),
                out.splitlines(),
                fromfile=str(path),
                tofile=str(path),
                lineterm="",
            )
            for line in diff:
                print(line)
    return changed


def write_evaluators_module(root: Path, apply: bool) -> None:
    path = root / "src/d810/evaluator/evaluators.py"
    if path.exists():
        return
    if apply:
        path.write_text(EVALUATORS_TEMPLATE, encoding="utf-8")
        print(f"created {path}")
    else:
        print(f"would create {path}")


def maybe_delete_legacy(root: Path, apply: bool, delete_legacy: bool) -> None:
    if not delete_legacy:
        return
    for rel in (
        "src/d810/evaluator/concrete.py",
        "src/d810/evaluator/symbolic.py",
        "src/d810/evaluator/dataflow.py",
    ):
        path = root / rel
        if not path.exists():
            continue
        if apply:
            path.unlink()
            print(f"deleted {path}")
        else:
            print(f"would delete {path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."), help="Repository root")
    parser.add_argument("--apply", action="store_true", help="Apply changes")
    parser.add_argument(
        "--delete-legacy",
        action="store_true",
        help="Delete concrete.py/symbolic.py/dataflow.py after rewrite",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    apply = args.apply
    write_evaluators_module(root, apply)
    changed = rewrite_files(root, apply)
    maybe_delete_legacy(root, apply, args.delete_legacy)
    mode = "applied" if apply else "dry-run"
    print(f"{mode}: rewrote {changed} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
