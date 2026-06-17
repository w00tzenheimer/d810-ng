#!/usr/bin/env python3
"""Manager-thinning helper codemod for the LLVM-for-deobfuscation plan.

This tool intentionally handles only mechanical follow-up work after a manual
manager.py slice has proven the boundary:

* longest-prefix module import rewrites;
* canonical moved-symbol imports such as ``from d810.manager import X``;
* optional, allowlist-guarded public manager re-export blocks;
* remaining-reference reporting.

Default mode is dry-run. Pass ``--apply`` to write changes. The built-in
manifest is a no-op so phase manifests are isolated; pass ``--manifest`` with
JSON to drive a specific slice, or ``--use-default-manager-map`` to opt into
the conservative manager moved-symbol map. Example shape:

{
  "module_renames": {
    "d810.manager_old_home": "d810.manager.new_home"
  },
  "symbol_imports": {
    "d810.manager": {
      "CProfileWrapper": "d810.manager.profiling"
    }
  },
  "manager_reexports": {
    "D810State": "d810.manager.state"
  },
  "public_api_allowlist": ["D810State", "D810Manager", "d810_hooks_suppressed"]
}
"""
from __future__ import annotations

import argparse
import dataclasses
import difflib
import json
import re
import tempfile
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any

import libcst as cst


DEFAULT_MANIFEST: dict[str, Any] = {
    "module_renames": {},
    "symbol_imports": {},
    "manager_reexports": {},
    "public_api_allowlist": [
        "D810State",
        "D810Manager",
        "d810_hooks_suppressed",
    ],
}

DEFAULT_MANAGER_MAP: dict[str, Any] = {
    "symbol_imports": {
        "d810.manager": {
            "CProfileWrapper": "d810.manager.profiling",
            "PostD810ProtectedBundleSpec": "d810.diagnostics.post_d810_handoff",
            "PostD810HandoffViolation": "d810.diagnostics.post_d810_handoff",
            "detect_post_d810_handoff_violations": (
                "d810.diagnostics.post_d810_handoff"
            ),
        },
    },
}

REEXPORT_BEGIN = "# BEGIN manager-thinning public compatibility reexports"
REEXPORT_END = "# END manager-thinning public compatibility reexports"

SKIP_PARTS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}


@dataclasses.dataclass(frozen=True)
class Manifest:
    module_renames: dict[str, str]
    symbol_imports: dict[str, dict[str, str]]
    manager_reexports: dict[str, str]
    public_api_allowlist: frozenset[str]


@dataclasses.dataclass(frozen=True)
class RewriteResult:
    changed: bool
    text: str
    parse_failed: bool = False


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            nested = dict(merged[key])
            for nested_key, nested_value in value.items():
                if (
                    isinstance(nested_value, dict)
                    and isinstance(nested.get(nested_key), dict)
                ):
                    sub = dict(nested[nested_key])
                    sub.update(nested_value)
                    nested[nested_key] = sub
                else:
                    nested[nested_key] = nested_value
            merged[key] = nested
        else:
            merged[key] = value
    return merged


def load_manifest(
    path: Path | None,
    only_source: set[str] | None,
    *,
    use_default_manager_map: bool,
) -> Manifest:
    raw = dict(DEFAULT_MANIFEST)
    if use_default_manager_map:
        raw = _deep_merge(raw, DEFAULT_MANAGER_MAP)
    if path is not None:
        raw = _deep_merge(raw, json.loads(path.read_text(encoding="utf-8")))

    module_renames = {
        str(old): str(new)
        for old, new in dict(raw.get("module_renames", {})).items()
    }
    symbol_imports = {
        str(module): {str(sym): str(dest) for sym, dest in dict(symbols).items()}
        for module, symbols in dict(raw.get("symbol_imports", {})).items()
    }
    manager_reexports = {
        str(sym): str(dest)
        for sym, dest in dict(raw.get("manager_reexports", {})).items()
    }
    allowlist = frozenset(str(sym) for sym in raw.get("public_api_allowlist", ()))

    if only_source:
        module_renames = {
            old: new for old, new in module_renames.items() if old in only_source
        }
        symbol_imports = {
            module: symbols
            for module, symbols in symbol_imports.items()
            if module in only_source
        }

    return Manifest(
        module_renames=module_renames,
        symbol_imports=symbol_imports,
        manager_reexports=manager_reexports,
        public_api_allowlist=allowlist,
    )


def _ordered_module_renames(manifest: Manifest) -> list[tuple[str, str]]:
    return sorted(manifest.module_renames.items(), key=lambda item: len(item[0]), reverse=True)


def _configured_destinations(manifest: Manifest) -> set[str]:
    destinations = set(manifest.module_renames.values())
    for moved_symbols in manifest.symbol_imports.values():
        destinations.update(moved_symbols.values())
    destinations.update(manifest.manager_reexports.values())
    return destinations


def _destination_exists(root: Path, dotted: str) -> bool:
    """Return True when dotted resolves to a source module or package."""
    parts = dotted.split(".")
    if not parts or parts[0] != "d810":
        return False
    module_path = root / "src" / Path(*parts)
    return module_path.with_suffix(".py").is_file() or (
        module_path / "__init__.py"
    ).is_file()


def missing_destinations(root: Path, manifest: Manifest) -> list[str]:
    return sorted(
        destination
        for destination in _configured_destinations(manifest)
        if not _destination_exists(root, destination)
    )


def _rewrite_dotted_name(name: str, manifest: Manifest) -> str:
    for old, new in _ordered_module_renames(manifest):
        if name == old or name.startswith(old + "."):
            return new + name[len(old):]
    return name


def _parse_dotted(dotted: str) -> cst.BaseExpression:
    return cst.parse_expression(dotted)


class ModuleRenameTransformer(cst.CSTTransformer):
    def __init__(self, manifest: Manifest) -> None:
        self._manifest = manifest

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom:
        if updated_node.module is None:
            return updated_node
        old = cst.Module([]).code_for_node(updated_node.module)
        new = _rewrite_dotted_name(old, self._manifest)
        if new == old:
            return updated_node
        return updated_node.with_changes(module=_parse_dotted(new))

    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        old = cst.Module([]).code_for_node(updated_node.name)
        new = _rewrite_dotted_name(old, self._manifest)
        if new == old:
            return updated_node
        return updated_node.with_changes(name=_parse_dotted(new))


def _alias_to_code(alias: cst.ImportAlias) -> str:
    code = cst.Module([]).code_for_node(alias.name)
    if alias.asname is not None:
        code += " as " + cst.Module([]).code_for_node(alias.asname.name)
    return code


class MovedSymbolImportTransformer(cst.CSTTransformer):
    def __init__(self, manifest: Manifest) -> None:
        self._manifest = manifest

    def leave_SimpleStatementLine(
        self,
        original_node: cst.SimpleStatementLine,
        updated_node: cst.SimpleStatementLine,
    ) -> cst.BaseStatement | cst.FlattenSentinel[cst.BaseStatement]:
        if len(updated_node.body) != 1:
            return updated_node
        stmt = updated_node.body[0]
        if not isinstance(stmt, cst.ImportFrom) or stmt.module is None:
            return updated_node
        if isinstance(stmt.names, cst.ImportStar):
            return updated_node

        module = cst.Module([]).code_for_node(stmt.module)
        symbol_map = self._manifest.symbol_imports.get(module)
        if not symbol_map:
            return updated_node

        groups: OrderedDict[str, list[str]] = OrderedDict()
        changed = False
        for alias in stmt.names:
            if not isinstance(alias, cst.ImportAlias):
                return updated_node
            imported_name = cst.Module([]).code_for_node(alias.name)
            dest = symbol_map.get(imported_name, module)
            if dest != module:
                changed = True
            groups.setdefault(dest, []).append(_alias_to_code(alias))

        if not changed:
            return updated_node

        text = "".join(
            f"from {dest} import {', '.join(aliases)}\n"
            for dest, aliases in groups.items()
        )
        parsed = list(cst.parse_module(text).body)
        if not parsed:
            return updated_node

        first = parsed[0].with_changes(leading_lines=updated_node.leading_lines)
        parsed[0] = first
        parsed[-1] = parsed[-1].with_changes(
            trailing_whitespace=updated_node.trailing_whitespace
        )
        return cst.FlattenSentinel(parsed)


def _dotted_pattern(dotted: str) -> re.Pattern[str]:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(dotted) + r"(?![A-Za-z0-9_])")


def rewrite_text(
    text: str,
    manifest: Manifest,
    *,
    rewrite_text_refs: bool,
) -> RewriteResult:
    original = text
    parse_failed = False
    try:
        module = cst.parse_module(text)
        module = module.visit(ModuleRenameTransformer(manifest))
        module = module.visit(MovedSymbolImportTransformer(manifest))
        text = module.code
    except cst.ParserSyntaxError:
        parse_failed = True

    if rewrite_text_refs:
        for old, new in _ordered_module_renames(manifest):
            text = _dotted_pattern(old).sub(new, text)

    return RewriteResult(changed=text != original, text=text, parse_failed=parse_failed)


def _is_skipped_path(path: Path) -> bool:
    return any(part in SKIP_PARTS or part.endswith(".egg-info") for part in path.parts)


def iter_python_files(root: Path, roots: tuple[str, ...]) -> list[Path]:
    self_path = Path(__file__).resolve()
    files: list[Path] = []
    for rel_root in roots:
        base = root / rel_root
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if path.resolve() == self_path:
                continue
            if _is_skipped_path(path.relative_to(root)):
                continue
            files.append(path)
    return files


def rewrite_files(
    root: Path,
    roots: tuple[str, ...],
    manifest: Manifest,
    *,
    apply: bool,
    show_diff: bool,
    rewrite_text_refs: bool,
) -> tuple[int, int]:
    changed = 0
    parse_failed = 0
    for path in iter_python_files(root, roots):
        src = path.read_text(encoding="utf-8")
        result = rewrite_text(src, manifest, rewrite_text_refs=rewrite_text_refs)
        if result.parse_failed:
            parse_failed += 1
        if not result.changed:
            continue
        changed += 1
        rel = path.relative_to(root)
        if apply:
            path.write_text(result.text, encoding="utf-8")
            print(f"rewrote {rel}")
        else:
            print(f"would rewrite {rel}")
            if show_diff:
                for line in difflib.unified_diff(
                    src.splitlines(),
                    result.text.splitlines(),
                    fromfile=str(rel),
                    tofile=str(rel),
                    lineterm="",
                ):
                    print(line)
    return changed, parse_failed


def _manager_reexport_block(manager_reexports: dict[str, str]) -> str:
    by_module: dict[str, list[str]] = defaultdict(list)
    for symbol, module in sorted(manager_reexports.items()):
        by_module[module].append(symbol)
    lines = [REEXPORT_BEGIN]
    for module, symbols in sorted(by_module.items()):
        lines.append(f"from {module} import {', '.join(sorted(symbols))}")
    lines.append(REEXPORT_END)
    return "\n".join(lines) + "\n"


def refresh_manager_reexports(
    root: Path,
    manager_path: Path,
    manifest: Manifest,
    *,
    apply: bool,
) -> int:
    invalid = sorted(set(manifest.manager_reexports) - manifest.public_api_allowlist)
    if invalid:
        print(
            "FATAL: manager_reexports contains non-allowlisted symbols: "
            + ", ".join(invalid)
        )
        return 2
    if not manifest.manager_reexports:
        print("manager reexports: no configured reexports")
        return 0

    path = root / manager_path
    src = path.read_text(encoding="utf-8")
    block = _manager_reexport_block(manifest.manager_reexports)
    pattern = re.compile(
        re.escape(REEXPORT_BEGIN) + r".*?" + re.escape(REEXPORT_END) + r"\n?",
        re.DOTALL,
    )
    if pattern.search(src):
        out = pattern.sub(block, src)
    else:
        lines = src.splitlines(keepends=True)
        insert_at = 0
        for idx, line in enumerate(lines):
            if line.startswith("from __future__ import "):
                insert_at = idx + 1
        lines.insert(insert_at, "\n" + block)
        out = "".join(lines)

    if out == src:
        print("manager reexports: already current")
        return 0
    rel = path.relative_to(root)
    if apply:
        path.write_text(out, encoding="utf-8")
        print(f"refreshed {rel}")
    else:
        print(f"would refresh {rel}")
    return 0


@dataclasses.dataclass(frozen=True)
class ReferenceHit:
    path: Path
    line_no: int
    kind: str
    text: str


def _report_symbol_names(
    manifest: Manifest,
    *,
    report_preserved_public_api: bool,
) -> dict[str, set[str]]:
    symbols: dict[str, set[str]] = defaultdict(set)
    for module, moved in manifest.symbol_imports.items():
        symbols[module].update(moved)
    if manifest.manager_reexports:
        symbols["d810.manager"].update(manifest.manager_reexports)
    if report_preserved_public_api and manifest.public_api_allowlist:
        symbols["d810.manager"].update(manifest.public_api_allowlist)
    return symbols


def collect_reference_hits(
    root: Path,
    roots: tuple[str, ...],
    manifest: Manifest,
    *,
    report_preserved_public_api: bool,
) -> list[ReferenceHit]:
    module_patterns = {
        old: _dotted_pattern(old)
        for old in manifest.module_renames
    }
    import_symbol_patterns = {
        module: re.compile(
            r"\bfrom\s+"
            + re.escape(module)
            + r"\s+import\s+.*\b("
            + "|".join(re.escape(symbol) for symbol in sorted(symbols))
            + r")\b"
        )
        for module, symbols in _report_symbol_names(
            manifest,
            report_preserved_public_api=report_preserved_public_api,
        ).items()
        if symbols
    }

    hits: list[ReferenceHit] = []
    for path in iter_python_files(root, roots):
        rel = path.relative_to(root)
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            for old, pattern in module_patterns.items():
                if pattern.search(line):
                    hits.append(ReferenceHit(rel, line_no, f"module:{old}", stripped))
            for module, pattern in import_symbol_patterns.items():
                if pattern.search(line):
                    hits.append(
                        ReferenceHit(rel, line_no, f"import-from:{module}", stripped)
                    )
    return hits


def print_reference_report(hits: list[ReferenceHit], *, limit: int) -> None:
    print("\nremaining reference report:")
    if not hits:
        print("  no configured references found")
        return
    for hit in hits[:limit]:
        print(f"  {hit.path}:{hit.line_no}: {hit.kind}: {hit.text}")
    if len(hits) > limit:
        print(f"  ... {len(hits) - limit} more hit(s)")


def run_selftest() -> int:
    ok = True

    default_manifest = load_manifest(
        None,
        None,
        use_default_manager_map=False,
    )
    good = not _configured_destinations(default_manifest)
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] default manifest is no-op")

    manager_map_manifest = load_manifest(
        None,
        None,
        use_default_manager_map=True,
    )
    good = "d810.manager.profiling" in _configured_destinations(manager_map_manifest)
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] default manager map opt-in")

    manifest = Manifest(
        module_renames={
            "d810.manager.deep": "d810.manager.deep",
            "d810.manager": "d810.driver.manager",
        },
        symbol_imports={
            "d810.driver.manager": {
                "Moved": "d810.manager.moved",
            },
        },
        manager_reexports={},
        public_api_allowlist=frozenset(),
    )
    cases = [
        (
            "from d810.manager.deep.child import X\n",
            "from d810.manager.deep.child import X\n",
        ),
        (
            "import d810.manager.deep as deep\n",
            "import d810.manager.deep as deep\n",
        ),
        (
            "from d810.manager import Moved, Kept\n",
            "from d810.manager.moved import Moved\n"
            "from d810.driver.manager import Kept\n",
        ),
        (
            "from d810.manager.deep import Moved, Kept\n",
            "from d810.manager.deep import Moved, Kept\n",
        ),
    ]
    for src, expected in cases:
        got = rewrite_text(src, manifest, rewrite_text_refs=False).text
        good = got == expected
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] {src.strip()} -> {got.strip()}")

    split_manifest = Manifest(
        module_renames={},
        symbol_imports={"d810.manager": {"Moved": "d810.manager.moved"}},
        manager_reexports={},
        public_api_allowlist=frozenset(),
    )
    src = "from d810.manager import Kept, Moved as Alias\n"
    expected = (
        "from d810.manager import Kept\n"
        "from d810.manager.moved import Moved as Alias\n"
    )
    got = rewrite_text(src, split_manifest, rewrite_text_refs=False).text
    good = got == expected
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] mixed import split")

    report_manifest = Manifest(
        module_renames={},
        symbol_imports={"d810.manager": {"Moved": "d810.manager.moved"}},
        manager_reexports={},
        public_api_allowlist=frozenset(
            {"D810State", "D810Manager", "d810_hooks_suppressed"}
        ),
    )
    quiet_symbols = _report_symbol_names(
        report_manifest,
        report_preserved_public_api=False,
    )
    good = (
        "Moved" in quiet_symbols.get("d810.manager", set())
        and "D810State" not in quiet_symbols.get("d810.manager", set())
    )
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] preserved public API hidden by default")

    reexport_manifest = dataclasses.replace(
        report_manifest,
        manager_reexports={"D810State": "d810.manager.state"},
    )
    reexport_symbols = _report_symbol_names(
        reexport_manifest,
        report_preserved_public_api=False,
    )
    good = "D810State" in reexport_symbols.get("d810.manager", set())
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] configured public reexport is reported")

    requested_symbols = _report_symbol_names(
        report_manifest,
        report_preserved_public_api=True,
    )
    good = "d810_hooks_suppressed" in requested_symbols.get("d810.manager", set())
    ok &= good
    print(f"[{'OK' if good else 'FAIL'}] preserved public API report opt-in")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        file_dest = root / "src/d810/manager/present_file.py"
        package_dest = root / "src/d810/manager/present_package/__init__.py"
        file_dest.parent.mkdir(parents=True)
        package_dest.parent.mkdir(parents=True)
        file_dest.write_text("# present\n", encoding="utf-8")
        package_dest.write_text("# present\n", encoding="utf-8")
        guard_manifest = Manifest(
            module_renames={
                "d810.old_file": "d810.manager.present_file",
                "d810.old_package": "d810.manager.present_package",
                "d810.old_missing": "d810.manager.missing",
            },
            symbol_imports={
                "d810.manager": {
                    "Moved": "d810.manager.present_file",
                },
            },
            manager_reexports={"D810State": "d810.manager.present_package"},
            public_api_allowlist=frozenset({"D810State"}),
        )
        missing = missing_destinations(root, guard_manifest)
        good = missing == ["d810.manager.missing"]
        ok &= good
        print(f"[{'OK' if good else 'FAIL'}] destination guard file/package")
    return 0 if ok else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--root", type=Path, default=Path("."), help="repository root")
    parser.add_argument(
        "--roots",
        nargs="*",
        default=["src", "tests"],
        help="root directories to scan",
    )
    parser.add_argument("--manifest", type=Path, help="JSON manifest overlay")
    parser.add_argument(
        "--use-default-manager-map",
        action="store_true",
        help="enable the conservative built-in d810.manager moved-symbol map",
    )
    parser.add_argument(
        "--only-source-module",
        action="append",
        help="restrict module/symbol rewrites to one old source module",
    )
    parser.add_argument("--apply", action="store_true", help="write changes")
    parser.add_argument(
        "--allow-missing-destinations",
        action="store_true",
        help="allow --apply even when configured destination modules do not exist",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="explicit no-write mode (default)",
    )
    parser.add_argument("--diff", action="store_true", help="show dry-run diffs")
    parser.add_argument(
        "--rewrite-text-refs",
        action="store_true",
        help="also rewrite configured dotted module refs in strings/comments",
    )
    parser.add_argument(
        "--refresh-manager-reexports",
        action="store_true",
        help="refresh the allowlist-guarded manager public reexport block",
    )
    parser.add_argument(
        "--manager-path",
        type=Path,
        default=Path("src/d810/manager.py"),
        help="manager facade path for --refresh-manager-reexports",
    )
    parser.add_argument(
        "--report-preserved-public-api",
        action="store_true",
        help="include intentionally preserved d810.manager public API imports",
    )
    parser.add_argument("--report-limit", type=int, default=80)
    parser.add_argument("--selftest", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.apply and args.dry_run:
        print("FATAL: choose either --apply or --dry-run, not both")
        return 2
    if args.selftest:
        return run_selftest()

    root = args.root.resolve()
    only_source = set(args.only_source_module or ()) or None
    manifest = load_manifest(
        args.manifest,
        only_source,
        use_default_manager_map=bool(args.use_default_manager_map),
    )
    roots = tuple(str(root_name) for root_name in args.roots)
    apply = bool(args.apply)

    if args.refresh_manager_reexports:
        invalid = sorted(set(manifest.manager_reexports) - manifest.public_api_allowlist)
        if invalid:
            print(
                "FATAL: manager_reexports contains non-allowlisted symbols: "
                + ", ".join(invalid)
            )
            return 2

    if apply and not args.allow_missing_destinations:
        missing = missing_destinations(root, manifest)
        if missing:
            print(
                "FATAL: refusing --apply because destination module(s) are missing "
                "under src. Pass --allow-missing-destinations to override."
            )
            for destination in missing[:40]:
                print(f"  missing: {destination}")
            if len(missing) > 40:
                print(f"  ... {len(missing) - 40} more")
            return 2

    changed, parse_failed = rewrite_files(
        root,
        roots,
        manifest,
        apply=apply,
        show_diff=bool(args.diff and not apply),
        rewrite_text_refs=bool(args.rewrite_text_refs),
    )
    if args.refresh_manager_reexports:
        rc = refresh_manager_reexports(
            root,
            args.manager_path,
            manifest,
            apply=apply,
        )
        if rc:
            return rc

    mode = "applied" if apply else "dry-run"
    print(f"\n{mode}: {changed} file(s) would change" if not apply else f"\n{mode}: {changed} file(s) changed")
    if parse_failed:
        print(f"parse fallback/skips: {parse_failed} file(s)")

    hits = collect_reference_hits(
        root,
        roots,
        manifest,
        report_preserved_public_api=bool(args.report_preserved_public_api),
    )
    print_reference_report(hits, limit=int(args.report_limit))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
