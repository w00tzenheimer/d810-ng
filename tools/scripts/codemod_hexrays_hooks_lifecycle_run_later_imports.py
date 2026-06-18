#!/usr/bin/env python3
"""Relocate hexrays_hooks lifecycle/run_later import owners.

Default mode is dry-run. Use ``--apply`` to write changes.

This codemod only rewrites import consumers for the mechanical class/helper
moves in the Hex-Rays hooks lifecycle/run_later plan. It does not create
compatibility re-exports or move production code.
"""

from __future__ import annotations

import argparse
import difflib
import re
from dataclasses import dataclass
from pathlib import Path

import libcst as cst


OLD_MODULE = "d810.hexrays.hooks.hexrays_hooks"
HOOKS_MODULE = "d810.hexrays.hooks"
HOOKS_ALIAS_NAME = "hexrays_hooks"

SYMBOL_OWNERS: dict[str, str] = {
    "InstructionOptimizerManager": "d810.hexrays.hooks.optinsn_adapter",
    "BlockOptimizerManager": "d810.hexrays.hooks.optblock_adapter",
    "DecompilationEvent": "d810.hexrays.lifecycle",
    "_emit_flowgraph_ready_event": "d810.hexrays.lifecycle",
    "HexraysDecompilationHook": OLD_MODULE,
}

DEFAULT_SCOPES = ("src", "tests")
SELF_TEST_FILE = f"test_{Path(__file__).stem}.py"
SKIP_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".venv",
        "__pycache__",
        "build",
        "dist",
    }
)


@dataclass(frozen=True)
class RewriteResult:
    text: str
    changed: bool


@dataclass(frozen=True)
class AliasContext:
    aliases: frozenset[str]
    moved_by_alias: dict[str, tuple[str, ...]]


def _module_code(node: cst.CSTNode) -> str:
    return cst.Module([]).code_for_node(node)


def _parse_module(module: str) -> cst.BaseExpression:
    return cst.parse_expression(module)


def _clone_alias(alias: cst.ImportAlias) -> cst.ImportAlias:
    return cst.ImportAlias(name=alias.name, asname=alias.asname)


def _target_for_alias(alias: cst.ImportAlias) -> str:
    return SYMBOL_OWNERS.get(_module_code(alias.name), OLD_MODULE)


def _binding_name(alias: cst.ImportAlias) -> str:
    if alias.asname is not None and isinstance(alias.asname.name, cst.Name):
        return alias.asname.name.value
    return _module_code(alias.name)


def _is_hooks_module_alias(alias: cst.ImportAlias) -> bool:
    return _module_code(alias.name) == HOOKS_ALIAS_NAME


def split_hexrays_hooks_import(
    node: cst.ImportFrom,
) -> tuple[cst.ImportFrom, ...] | None:
    """Split moved hexrays_hooks symbols into their new owner modules."""

    if node.module is None or isinstance(node.names, cst.ImportStar):
        return None

    if _module_code(node.module) != OLD_MODULE:
        return None

    groups: dict[str, list[cst.ImportAlias]] = {}
    order: list[str] = []
    for alias in node.names:
        target = _target_for_alias(alias)
        if target not in groups:
            groups[target] = []
            order.append(target)
        groups[target].append(_clone_alias(alias))

    if order == [OLD_MODULE]:
        return None

    return tuple(
        cst.ImportFrom(
            module=_parse_module(target),
            names=tuple(groups[target]),
        )
        for target in order
    )


class _AliasImportCollector(cst.CSTVisitor):
    def __init__(self) -> None:
        self.aliases: set[str] = set()

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        if node.module is None or isinstance(node.names, cst.ImportStar):
            return
        if _module_code(node.module) != HOOKS_MODULE:
            return
        for alias in node.names:
            if _is_hooks_module_alias(alias):
                self.aliases.add(_binding_name(alias))


class _AliasUsageCollector(cst.CSTVisitor):
    def __init__(self, aliases: set[str]) -> None:
        self.aliases = aliases
        self.moved_by_alias: dict[str, list[str]] = {}

    def visit_Attribute(self, node: cst.Attribute) -> None:
        if not isinstance(node.value, cst.Name):
            return
        alias = node.value.value
        symbol = node.attr.value
        if alias not in self.aliases:
            return
        if SYMBOL_OWNERS.get(symbol, OLD_MODULE) == OLD_MODULE:
            return
        symbols = self.moved_by_alias.setdefault(alias, [])
        if symbol not in symbols:
            symbols.append(symbol)


def _collect_alias_context(node: cst.CSTNode) -> AliasContext:
    import_collector = _AliasImportCollector()
    node.visit(import_collector)
    usage_collector = _AliasUsageCollector(import_collector.aliases)
    node.visit(usage_collector)
    return AliasContext(
        aliases=frozenset(import_collector.aliases),
        moved_by_alias={
            alias: tuple(symbols)
            for alias, symbols in usage_collector.moved_by_alias.items()
        },
    )


def split_hooks_module_alias_import(
    node: cst.ImportFrom,
    context: AliasContext,
) -> tuple[cst.ImportFrom, ...]:
    if node.module is None or isinstance(node.names, cst.ImportStar):
        return ()
    if _module_code(node.module) != HOOKS_MODULE:
        return ()

    symbols: list[str] = []
    for alias in node.names:
        if not _is_hooks_module_alias(alias):
            continue
        for symbol in context.moved_by_alias.get(_binding_name(alias), ()):
            if symbol not in symbols:
                symbols.append(symbol)

    return _direct_imports_for_symbols(tuple(symbols))


def _direct_imports_for_symbols(symbols: tuple[str, ...]) -> tuple[cst.ImportFrom, ...]:
    groups: dict[str, list[cst.ImportAlias]] = {}
    order: list[str] = []
    for symbol in symbols:
        target = SYMBOL_OWNERS[symbol]
        if target == OLD_MODULE:
            continue
        if target not in groups:
            groups[target] = []
            order.append(target)
        groups[target].append(cst.ImportAlias(name=cst.Name(symbol)))

    return tuple(
        cst.ImportFrom(module=_parse_module(target), names=tuple(groups[target]))
        for target in order
    )


class HexraysHooksImportTransformer(cst.CSTTransformer):
    def __init__(self) -> None:
        self._alias_context_stack: list[AliasContext] = []

    @property
    def _alias_context(self) -> AliasContext:
        if not self._alias_context_stack:
            return AliasContext(aliases=frozenset(), moved_by_alias={})
        return self._alias_context_stack[-1]

    def visit_Module(self, node: cst.Module) -> bool:
        self._alias_context_stack.append(_collect_alias_context(node))
        return True

    def leave_Module(
        self,
        original_node: cst.Module,
        updated_node: cst.Module,
    ) -> cst.Module:
        self._alias_context_stack.pop()
        return updated_node

    def visit_IndentedBlock(self, node: cst.IndentedBlock) -> bool:
        self._alias_context_stack.append(_collect_alias_context(node))
        return True

    def leave_IndentedBlock(
        self,
        original_node: cst.IndentedBlock,
        updated_node: cst.IndentedBlock,
    ) -> cst.IndentedBlock:
        self._alias_context_stack.pop()
        return updated_node

    def leave_Attribute(
        self,
        original_node: cst.Attribute,
        updated_node: cst.Attribute,
    ) -> cst.BaseExpression:
        if not isinstance(updated_node.value, cst.Name):
            return updated_node
        alias = updated_node.value.value
        symbol = updated_node.attr.value
        if symbol in self._alias_context.moved_by_alias.get(alias, ()):
            return cst.Name(symbol)
        return updated_node

    def leave_SimpleStatementLine(
        self,
        original_node: cst.SimpleStatementLine,
        updated_node: cst.SimpleStatementLine,
    ) -> cst.BaseStatement | cst.FlattenSentinel[cst.BaseStatement]:
        new_body: list[cst.BaseSmallStatement] = []
        changed = False

        for statement in updated_node.body:
            if isinstance(statement, cst.ImportFrom):
                split = split_hexrays_hooks_import(statement)
                if split is not None:
                    new_body.extend(split)
                    changed = True
                    continue
                alias_imports = split_hooks_module_alias_import(
                    statement,
                    self._alias_context,
                )
                if alias_imports:
                    new_body.append(statement)
                    new_body.extend(alias_imports)
                    changed = True
                    continue
            new_body.append(statement)

        if not changed:
            return updated_node

        if len(updated_node.body) == 1:
            lines: list[cst.SimpleStatementLine] = []
            for index, statement in enumerate(new_body):
                if index == 0:
                    lines.append(updated_node.with_changes(body=(statement,)))
                else:
                    lines.append(cst.SimpleStatementLine(body=(statement,)))
            return cst.FlattenSentinel(lines)

        return updated_node.with_changes(body=tuple(new_body))


def _symbol_patterns() -> tuple[tuple[re.Pattern[str], str], ...]:
    patterns: list[tuple[re.Pattern[str], str]] = []
    for symbol, target in SYMBOL_OWNERS.items():
        if target == OLD_MODULE:
            continue
        old = f"{OLD_MODULE}.{symbol}"
        new = f"{target}.{symbol}"
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])" + re.escape(old) + r"(?![A-Za-z0-9_])"
        )
        patterns.append((pattern, new))
    return tuple(patterns)


SYMBOL_PATTERNS = _symbol_patterns()


def rewrite_fully_qualified_symbol_text(text: str) -> str:
    out = text
    for pattern, replacement in SYMBOL_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def rewrite_text(text: str) -> RewriteResult:
    try:
        module = cst.parse_module(text)
        rewritten = module.visit(HexraysHooksImportTransformer()).code
    except cst.ParserSyntaxError:
        rewritten = text

    rewritten = rewrite_fully_qualified_symbol_text(rewritten)
    return RewriteResult(text=rewritten, changed=rewritten != text)


def _relative_path(root: Path, path: Path) -> Path:
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return path


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_PARTS for part in path.parts)


def iter_python_files(root: Path, explicit_paths: tuple[str, ...] = ()) -> list[Path]:
    if explicit_paths:
        out: list[Path] = []
        for raw in explicit_paths:
            path = Path(raw)
            if not path.is_absolute():
                path = root / path
            if path.is_file() and path.suffix == ".py":
                out.append(path.resolve())
        return sorted(out)

    self_path = Path(__file__).resolve()
    out = []
    for scope in DEFAULT_SCOPES:
        base = root / scope
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            rel = _relative_path(root, path)
            if (
                path.resolve() == self_path
                or rel.as_posix() == f"tests/unit/tools/{SELF_TEST_FILE}"
                or _should_skip(rel)
            ):
                continue
            out.append(path.resolve())
    return sorted(out)


def rewrite_files(root: Path, *, apply: bool, paths: tuple[str, ...] = ()) -> int:
    rewritten = 0
    for path in iter_python_files(root, paths):
        source = path.read_text(encoding="utf-8")
        if OLD_MODULE not in source and HOOKS_MODULE not in source:
            continue

        result = rewrite_text(source)
        if not result.changed:
            continue

        rewritten += 1
        rel = _relative_path(root, path).as_posix()
        if apply:
            path.write_text(result.text, encoding="utf-8")
            print(f"rewrote {rel}")
            continue

        print(f"would rewrite {rel}")
        diff = difflib.unified_diff(
            source.splitlines(),
            result.text.splitlines(),
            fromfile=rel,
            tofile=rel,
            lineterm="",
        )
        for line in diff:
            print(line)

    return rewritten


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", help="Repo root to scan")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Write changes")
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without writing (default)",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional Python files to rewrite instead of scanning src/ and tests/",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    count = rewrite_files(root, apply=args.apply, paths=tuple(args.paths))
    mode_name = "applied" if args.apply else "dry-run"
    print(f"{mode_name}: rewritten={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
