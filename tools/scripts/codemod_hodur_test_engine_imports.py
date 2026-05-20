#!/usr/bin/env python3
"""Rewrite test imports from Hodur runtime shims to canonical engine modules.

Default mode is dry-run. Use --apply to write changes.
The codemod intentionally scans tests only and leaves Hodur strategy-specific
coverage in place.
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path

import libcst as cst


HODUR_PACKAGE = "d810.optimizers.microcode.flow.flattening.hodur"
ENGINE_PACKAGE = "d810.optimizers.microcode.flow.flattening.engine"

MODULE_RENAMES: dict[str, str] = {
    f"{HODUR_PACKAGE}.strategy": f"{ENGINE_PACKAGE}.strategy",
    f"{HODUR_PACKAGE}.planner": f"{ENGINE_PACKAGE}.planner",
    f"{HODUR_PACKAGE}.provenance": f"{ENGINE_PACKAGE}.provenance",
    f"{HODUR_PACKAGE}.executor": f"{ENGINE_PACKAGE}.executor",
    f"{HODUR_PACKAGE}.snapshot": f"{ENGINE_PACKAGE}.snapshot",
    f"{HODUR_PACKAGE}.metrics": f"{ENGINE_PACKAGE}.metrics",
}

SUBMODULE_RENAMES: dict[str, str] = {
    old.rsplit(".", 1)[-1]: new.rsplit(".", 1)[-1]
    for old, new in MODULE_RENAMES.items()
}

EXCLUDED_PATH_MARKERS = (
    "/hodur/strategies/",
    "recon_artifacts",
    "return_sites",
    "linearized_flow_graph",
    "exact_node_frontier_bypass",
)


def _node_code(node: cst.CSTNode) -> str:
    return cst.Module([]).code_for_node(node)


class DirectTargetImportVisitor(cst.CSTVisitor):
    """Detect real imports from the exact Hodur compatibility modules."""

    def __init__(self) -> None:
        self.found = False

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        if node.module is not None and _node_code(node.module) in MODULE_RENAMES:
            self.found = True

    def visit_ImportAlias(self, node: cst.ImportAlias) -> None:
        if _node_code(node.name) in MODULE_RENAMES:
            self.found = True


class HodurTestImportTransformer(cst.CSTTransformer):
    def __init__(self, *, rewrite_package_level_aliases: bool) -> None:
        self.rewrite_package_level_aliases = rewrite_package_level_aliases

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.BaseSmallStatement | cst.FlattenSentinel[cst.BaseSmallStatement]:
        module = updated_node.module
        if module is None:
            return updated_node

        module_code = _node_code(module)
        new_module = MODULE_RENAMES.get(module_code)
        if new_module is not None:
            return updated_node.with_changes(module=cst.parse_expression(new_module))

        if (
            not self.rewrite_package_level_aliases
            or module_code != HODUR_PACKAGE
            or isinstance(updated_node.names, cst.ImportStar)
        ):
            return updated_node

        hodur_aliases: list[cst.ImportAlias] = []
        engine_aliases: list[cst.ImportAlias] = []
        for alias in updated_node.names:
            alias_name = _node_code(alias.name)
            if alias_name in SUBMODULE_RENAMES:
                engine_aliases.append(
                    alias.with_changes(
                        name=cst.Name(SUBMODULE_RENAMES[alias_name])
                    )
                )
            else:
                hodur_aliases.append(alias)

        if not engine_aliases:
            return updated_node

        new_nodes: list[cst.ImportFrom] = []
        if hodur_aliases:
            new_nodes.append(updated_node.with_changes(names=tuple(hodur_aliases)))
        new_nodes.append(
            updated_node.with_changes(
                module=cst.parse_expression(ENGINE_PACKAGE),
                names=tuple(engine_aliases),
            )
        )

        if len(new_nodes) == 1:
            return new_nodes[0]
        return cst.FlattenSentinel(new_nodes)

    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        name_code = _node_code(updated_node.name)
        new_name = MODULE_RENAMES.get(name_code)
        if new_name is not None:
            return updated_node.with_changes(name=cst.parse_expression(new_name))
        return updated_node


def _has_direct_target_import(module: cst.Module) -> bool:
    visitor = DirectTargetImportVisitor()
    module.visit(visitor)
    return visitor.found


def rewrite_text(text: str) -> str:
    module = cst.parse_module(text)
    transformer = HodurTestImportTransformer(
        rewrite_package_level_aliases=_has_direct_target_import(module)
    )
    return module.visit(transformer).code


def should_skip_path(path: Path, root: Path) -> bool:
    rel = path.relative_to(root).as_posix()
    return any(marker in rel for marker in EXCLUDED_PATH_MARKERS)


def iter_test_files(root: Path, explicit_paths: list[str]) -> list[Path]:
    if explicit_paths:
        return sorted((root / path).resolve() for path in explicit_paths)

    tests_root = root / "tests"
    if not tests_root.exists():
        return []
    return sorted(
        path
        for path in tests_root.rglob("*.py")
        if "__pycache__" not in path.parts
        and not should_skip_path(path, root)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional test paths relative to the repository root",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    changed = 0
    for path in iter_test_files(root, args.paths):
        if not path.is_file() or path.suffix != ".py":
            continue
        if root / "tests" not in path.parents:
            raise SystemExit(f"refusing to rewrite non-test path: {path}")
        if should_skip_path(path, root):
            continue

        src = path.read_text(encoding="utf-8")
        if HODUR_PACKAGE not in src:
            continue
        out = rewrite_text(src)
        if out == src:
            continue

        changed += 1
        rel = path.relative_to(root)
        if args.apply:
            path.write_text(out, encoding="utf-8")
            print(f"rewrote {rel}")
        else:
            print(f"would rewrite {rel}")
            for line in difflib.unified_diff(
                src.splitlines(),
                out.splitlines(),
                fromfile=str(rel),
                tofile=str(rel),
                lineterm="",
            ):
                print(line)

    mode = "applied" if args.apply else "dry-run"
    print(f"{mode}: rewritten={changed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
