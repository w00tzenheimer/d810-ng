#!/usr/bin/env python3
"""Generate ast-grep diagnostic-storage burndown reports and safe rewrites.

Default mode is dry-run. Use ``--apply`` to write generated report files or
rewrite imports.

This codemod intentionally does not move runtime behavior. It supports the
mechanical parts of the exception burndown:

- inventory diagnostic-storage rule ignores;
- run each rule with ignores stripped in a temporary rule file;
- generate a phase manifest for remaining manual work;
- rewrite imports for modules that were already moved to diagnostics.
"""

from __future__ import annotations

import argparse
import ast
import difflib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


RULE_FILES = (
    "rules/no-cfg-diagnostic-storage-imports.yml",
    "rules/no-recon-diagnostic-storage-imports.yml",
    "rules/no-optimizers-diagnostic-storage-imports.yml",
    "rules/no-hexrays-mutation-diagnostic-storage-imports.yml",
)

DEFAULT_OUTPUT_DIR = Path(".tmp/astgrep_diagnostic_storage_burndown")
DEFAULT_SCOPES = ("src", "tests", "tools")
SKIP_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".worktrees",
        "__pycache__",
    }
)

EXACT_MODULE_RENAMES: dict[str, str] = {
    "d810.cfg.region_oracle_cli": "d810.diagnostics.region_oracle_cli",
    "d810.recon.flow.alternate_correlation": (
        "d810.diagnostics.alternate_correlation"
    ),
    "d810.recon.flow.alternate_selection": "d810.diagnostics.alternate_selection",
    "d810.recon.flow.bst_resolution": "d810.diagnostics.bst_resolution",
    "d810.recon.flow.edge_diagnostics": "d810.diagnostics.edge_diagnostics",
}

MOVED_SYMBOL_RENAMES: dict[tuple[str, str], str] = {
    (
        "d810.cfg.ref_region_oracle",
        "collect_block_views_for_snapshot",
    ): "d810.diagnostics.ref_region_oracle_db",
    (
        "d810.recon.flow.selected_alternate_edge_override",
        "apply_selected_alternate_edge_overrides_from_diag",
    ): "d810.diagnostics.selected_alternate_edge_override",
}

HIT_RE = re.compile(
    r"^(?P<path>[^:\n]+):(?P<line>\d+):(?P<col>\d+): "
    r"(?P<severity>\w+)\[(?P<rule>[^\]]+)\]: (?P<message>.+)$"
)


@dataclass(frozen=True)
class SgHit:
    path: str
    line: int
    col: int
    severity: str
    rule: str
    message: str


@dataclass(frozen=True)
class RuleInventory:
    rule_path: str
    rule_id: str
    ignores: tuple[str, ...]
    no_ignore_returncode: int
    hits: tuple[SgHit, ...]
    raw_output: str


@dataclass(frozen=True)
class RewriteChange:
    path: Path
    line: int
    old: str
    new: str


@dataclass(frozen=True)
class RewriteResult:
    text: str
    changes: tuple[RewriteChange, ...]
    warnings: tuple[str, ...]


def _resolve(root: Path, value: str | Path | None, default: Path | None = None) -> Path:
    if value is None:
        if default is None:
            raise ValueError("missing path")
        path = default
    else:
        path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _relative_path(root: Path, path: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def _should_skip(path: Path) -> bool:
    return any(part in SKIP_PARTS for part in path.parts)


def iter_python_files(root: Path, explicit_paths: tuple[str, ...] = ()) -> list[Path]:
    if explicit_paths:
        files: list[Path] = []
        for raw in explicit_paths:
            path = Path(raw)
            if not path.is_absolute():
                path = root / path
            if path.is_file() and path.suffix == ".py":
                files.append(path.resolve())
        return sorted(files)

    files = []
    for scope in DEFAULT_SCOPES:
        base = root / scope
        if not base.exists():
            continue
        files.extend(
            path
            for path in base.rglob("*.py")
            if path.is_file() and not _should_skip(_relative_path(root, path))
        )
    return sorted(files)


def parse_rule_id(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("id:"):
            return line.split(":", 1)[1].strip()
    return "<unknown>"


def parse_ignores(text: str) -> tuple[str, ...]:
    ignores: list[str] = []
    in_ignores = False
    for line in text.splitlines():
        if line.startswith("ignores:"):
            in_ignores = True
            continue
        if in_ignores and line and not line.startswith((" ", "\t", "#")):
            break
        if not in_ignores:
            continue
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        raw = stripped[2:].strip()
        if (
            len(raw) >= 2
            and raw[0] in {"'", '"'}
            and raw[-1] == raw[0]
        ):
            raw = raw[1:-1]
        ignores.append(raw)
    return tuple(ignores)


def strip_ignores_block(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    skipping = False
    for line in lines:
        if line.startswith("ignores:"):
            skipping = True
            continue
        if skipping and line and not line.startswith((" ", "\t", "#", "\n", "\r")):
            skipping = False
        if not skipping:
            out.append(line)
    return "".join(out)


def parse_sg_hits(output: str) -> tuple[SgHit, ...]:
    hits: list[SgHit] = []
    for line in output.splitlines():
        match = HIT_RE.match(line)
        if match is None:
            continue
        hits.append(
            SgHit(
                path=match.group("path"),
                line=int(match.group("line")),
                col=int(match.group("col")),
                severity=match.group("severity"),
                rule=match.group("rule"),
                message=match.group("message"),
            )
        )
    return tuple(hits)


def scan_rule_without_ignores(root: Path, rule_path: Path) -> RuleInventory:
    source = rule_path.read_text(encoding="utf-8")
    stripped = strip_ignores_block(source)
    with tempfile.TemporaryDirectory(prefix="diag-storage-rule-") as tmp:
        temp_rule = Path(tmp) / rule_path.name
        temp_rule.write_text(stripped, encoding="utf-8")
        proc = subprocess.run(
            [
                "sg",
                "scan",
                "--rule",
                str(temp_rule),
                "--report-style",
                "short",
                "--color",
                "never",
            ],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=60,
        )
    raw = (proc.stdout or "") + (proc.stderr or "")
    return RuleInventory(
        rule_path=_relative_path(root, rule_path).as_posix(),
        rule_id=parse_rule_id(source),
        ignores=parse_ignores(source),
        no_ignore_returncode=int(proc.returncode),
        hits=parse_sg_hits(raw),
        raw_output=raw,
    )


def collect_inventories(root: Path) -> tuple[RuleInventory, ...]:
    inventories: list[RuleInventory] = []
    for rule in RULE_FILES:
        path = root / rule
        if not path.exists():
            continue
        inventories.append(scan_rule_without_ignores(root, path))
    return tuple(inventories)


def candidate_phases() -> list[dict[str, Any]]:
    return [
        {
            "phase": "phase1-import-cleanup",
            "automation": "safe-import-rewrite",
            "supported_by": "rewrite-imports",
            "scope": sorted(
                set(EXACT_MODULE_RENAMES)
                | {module for module, _name in MOVED_SYMBOL_RENAMES}
            ),
            "notes": [
                "Only rewrites imports for modules already moved to diagnostics.",
                "Does not move code or change runtime behavior.",
            ],
        },
        {
            "phase": "phase2-optimizer-hcc-diagnostic-query",
            "automation": "completed-query-moved",
            "rule": "no-optimizers-diagnostic-storage-imports",
            "candidate_files": [],
            "notes": [
                "Read-only HCC anchor snapshot SQLite lookup lives in "
                "d810.diagnostics.hcc_anchor_snapshot_context.",
                "The optimizer rule has no HCC ignore; new storage imports "
                "should be treated as regressions.",
            ],
        },
        {
            "phase": "phase3-hexrays-byte-tail-runtime-diagnostic-coupling",
            "automation": "manifest-and-audit-only",
            "rule": "no-hexrays-mutation-diagnostic-storage-imports",
            "candidate_files": [
                "src/d810/hexrays/mutation/byte_emit_tail_isolation_runtime.py"
            ],
            "notes": [
                "DiagDbFactView and planner/DAG loaders read SQLite inside "
                "mutation runtime.",
                "Behavior is entangled with active diag snapshots; do not codemod "
                "without a validated adapter boundary.",
            ],
        },
        {
            "phase": "protected-recon-store-review",
            "automation": "manual-review-only",
            "rule": "no-recon-diagnostic-storage-imports",
            "candidate_files": [
                "src/d810/recon/store.py",
                "src/d810/recon/artifacts.py",
            ],
            "notes": [
                "Rule comments classify these as recon-local behavior/data stores.",
                "Do not move unless a separate audit proves diagnostic DB behavior.",
            ],
        },
    ]


def build_manifest(
    root: Path, inventories: tuple[RuleInventory, ...],
) -> dict[str, Any]:
    return {
        "generated_by": (
            "tools/scripts/codemod_astgrep_diagnostic_storage_burndown.py"
        ),
        "root": root.as_posix(),
        "rules": [
            {
                "rule_path": item.rule_path,
                "rule_id": item.rule_id,
                "ignores": list(item.ignores),
                "no_ignore_returncode": item.no_ignore_returncode,
                "hits": [
                    {
                        "path": hit.path,
                        "line": hit.line,
                        "col": hit.col,
                        "severity": hit.severity,
                        "rule": hit.rule,
                    }
                    for hit in item.hits
                ],
            }
            for item in inventories
        ],
        "moved_imports": {
            "module_renames": EXACT_MODULE_RENAMES,
            "symbol_renames": [
                {
                    "from_module": module,
                    "name": name,
                    "to_module": to_module,
                }
                for (module, name), to_module in sorted(
                    MOVED_SYMBOL_RENAMES.items()
                )
            ],
        },
        "candidate_phases": candidate_phases(),
        "validation": [
            "python3 -m py_compile "
            "tools/scripts/codemod_astgrep_diagnostic_storage_burndown.py",
            "python3 tools/scripts/codemod_astgrep_diagnostic_storage_burndown.py "
            "report",
            "python3 tools/scripts/codemod_astgrep_diagnostic_storage_burndown.py "
            "rewrite-imports",
            "sg scan --config sgconfig.yml --filter "
            "no-cfg-diagnostic-storage-imports --report-style short",
            "sg scan --config sgconfig.yml --filter "
            "no-recon-diagnostic-storage-imports --report-style short",
            "sg scan --config sgconfig.yml --filter "
            "no-optimizers-diagnostic-storage-imports --report-style short",
            "sg scan --config sgconfig.yml --filter "
            "no-hexrays-mutation-diagnostic-storage-imports --report-style short",
            "PYTHONPATH=src lint-imports --config .importlinter",
        ],
    }


def render_report(inventories: tuple[RuleInventory, ...]) -> str:
    lines = [
        "# Ast-Grep Diagnostic-Storage Burndown Report",
        "",
        "Generated by "
        "`tools/scripts/codemod_astgrep_diagnostic_storage_burndown.py`.",
        "",
        "This report is an audit aid. It removes rule ignores only in temporary",
        "rule files and does not edit runtime code.",
        "",
        "## Rule Inventories",
        "",
    ]
    for item in inventories:
        lines.extend(
            [
                f"### `{item.rule_id}`",
                "",
                f"- Rule file: `{item.rule_path}`",
                f"- Ignored path count: {len(item.ignores)}",
            ]
        )
        if item.ignores:
            lines.append("- Ignored paths:")
            for ignore in item.ignores:
                lines.append(f"  - `{ignore}`")
        else:
            lines.append("- Ignored paths: none")
        lines.append(f"- No-ignore sg return code: {item.no_ignore_returncode}")
        if item.hits:
            lines.append("- No-ignore hits:")
            for hit in item.hits:
                lines.append(
                    f"  - `{hit.path}:{hit.line}:{hit.col}` "
                    f"`{hit.severity}[{hit.rule}]`"
                )
        else:
            lines.append("- No-ignore hits: none")
        lines.append("")

    lines.extend(["## Candidate Phases", ""])
    for phase in candidate_phases():
        lines.append(f"### `{phase['phase']}`")
        lines.append("")
        lines.append(f"- Automation: `{phase['automation']}`")
        if "supported_by" in phase:
            lines.append(f"- Supported by: `{phase['supported_by']}`")
        if "rule" in phase:
            lines.append(f"- Rule: `{phase['rule']}`")
        if "candidate_files" in phase:
            if phase["candidate_files"]:
                lines.append("- Candidate files:")
                for path in phase["candidate_files"]:
                    lines.append(f"  - `{path}`")
            else:
                lines.append("- Candidate files: none")
        if "scope" in phase:
            lines.append("- Import rewrite scope:")
            for module in phase["scope"]:
                lines.append(f"  - `{module}`")
        lines.append("- Notes:")
        for note in phase["notes"]:
            lines.append(f"  - {note}")
        lines.append("")

    return "\n".join(lines)


def _print_diff(path: Path, existing: str, generated: str) -> None:
    for line in difflib.unified_diff(
        existing.splitlines(),
        generated.splitlines(),
        fromfile=str(path),
        tofile=str(path),
        lineterm="",
    ):
        print(line)


def _alias_text(alias: ast.alias) -> str:
    if alias.asname:
        return f"{alias.name} as {alias.asname}"
    return alias.name


def _line_ending(line: str) -> str:
    if line.endswith("\r\n"):
        return "\r\n"
    if line.endswith("\n"):
        return "\n"
    return ""


def rewrite_import_text(text: str, *, path: Path = Path("<memory>")) -> RewriteResult:
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError as exc:
        return RewriteResult(text=text, changes=(), warnings=(f"{path}: {exc}",))

    lines = text.splitlines(keepends=True)
    replacements: dict[int, str] = {}
    changes: list[RewriteChange] = []
    warnings: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        lineno = int(getattr(node, "lineno", 0) or 0)
        end_lineno = int(getattr(node, "end_lineno", lineno) or lineno)
        if lineno <= 0 or lineno > len(lines):
            continue
        old_line = replacements.get(lineno, lines[lineno - 1])
        new_line = old_line
        if isinstance(node, ast.Import):
            if end_lineno != lineno:
                if any(alias.name in EXACT_MODULE_RENAMES for alias in node.names):
                    warnings.append(
                        f"{path}:{lineno}: manual review for multiline import"
                    )
                continue
            for alias in node.names:
                target = EXACT_MODULE_RENAMES.get(alias.name)
                if target is not None:
                    new_line = new_line.replace(alias.name, target, 1)

        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            module = node.module or ""
            if end_lineno != lineno:
                has_moved_symbol = any(
                    alias.name != "*"
                    and (module, alias.name) in MOVED_SYMBOL_RENAMES
                    for alias in node.names
                )
                if module in EXACT_MODULE_RENAMES or has_moved_symbol:
                    warnings.append(
                        f"{path}:{lineno}: manual review for multiline import"
                    )
                continue
            target = EXACT_MODULE_RENAMES.get(module)
            if target is not None:
                new_line = new_line.replace(f"from {module} import", f"from {target} import", 1)
            else:
                moved: dict[str, list[ast.alias]] = {}
                kept: list[ast.alias] = []
                star_import = False
                for alias in node.names:
                    if alias.name == "*":
                        star_import = True
                        kept.append(alias)
                        continue
                    target_module = MOVED_SYMBOL_RENAMES.get((module, alias.name))
                    if target_module is None:
                        kept.append(alias)
                    else:
                        moved.setdefault(target_module, []).append(alias)
                if star_import and moved:
                    warnings.append(
                        f"{path}:{lineno}: manual review for star import"
                    )
                    continue
                if moved:
                    if "#" in old_line and kept:
                        warnings.append(
                            f"{path}:{lineno}: manual review for split import with comment"
                        )
                        continue
                    indent = old_line[: len(old_line) - len(old_line.lstrip())]
                    ending = _line_ending(old_line)
                    rendered: list[str] = []
                    if kept:
                        rendered.append(
                            f"{indent}from {module} import "
                            f"{', '.join(_alias_text(alias) for alias in kept)}"
                            f"{ending}"
                        )
                    for target_module in sorted(moved):
                        rendered.append(
                            f"{indent}from {target_module} import "
                            f"{', '.join(_alias_text(alias) for alias in moved[target_module])}"
                            f"{ending}"
                        )
                    new_line = "".join(rendered)

        if new_line != old_line:
            replacements[lineno] = new_line
            changes.append(
                RewriteChange(
                    path=path,
                    line=lineno,
                    old=old_line.rstrip("\r\n"),
                    new=new_line.rstrip("\r\n"),
                )
            )

    if replacements:
        for lineno, new_line in sorted(replacements.items(), reverse=True):
            lines[lineno - 1] = new_line
    return RewriteResult(
        text="".join(lines),
        changes=tuple(changes),
        warnings=tuple(warnings),
    )


def rewrite_import_files(
    root: Path,
    paths: tuple[str, ...],
    *,
    apply: bool,
) -> tuple[int, int]:
    changed = 0
    warnings = 0
    for path in iter_python_files(root, paths):
        source = path.read_text(encoding="utf-8")
        result = rewrite_import_text(source, path=_relative_path(root, path))
        warnings += len(result.warnings)
        for warning in result.warnings:
            print(f"warning: {warning}")
        if result.text == source:
            continue
        changed += 1
        rel = _relative_path(root, path)
        if apply:
            path.write_text(result.text, encoding="utf-8")
            print(f"rewrote {rel}")
        else:
            print(f"would rewrite {rel}")
            _print_diff(rel, source, result.text)
    mode = "applied" if apply else "dry-run"
    print(f"{mode}: rewritten={changed} warnings={warnings}")
    return changed, warnings


def cmd_report(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    output_dir = _resolve(root, args.output_dir)
    report_path = output_dir / "report.md"
    manifest_path = output_dir / "manifest.json"
    inventories = collect_inventories(root)
    files = {
        report_path: render_report(inventories),
        manifest_path: json.dumps(build_manifest(root, inventories), indent=2) + "\n",
    }

    changed = 0
    for path, generated in sorted(files.items()):
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if existing == generated:
            print(f"no changes for {path}")
            continue
        changed += 1
        if args.apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(generated, encoding="utf-8")
            print(f"wrote {path}")
        else:
            print(f"would write {path}")
            _print_diff(path, existing, generated)

    if changed == 0:
        print("no files needed rewriting")
    else:
        mode = "applied" if args.apply else "dry-run"
        print(f"{mode}: {changed} file(s)")
    return 0


def cmd_rewrite_imports(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    rewrite_import_files(root, tuple(args.paths), apply=bool(args.apply))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_report = sub.add_parser("report", help="Generate rule inventory report")
    p_report.add_argument("--root", default=".", help="Repository root")
    p_report.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Artifact directory, relative to root unless absolute",
    )
    p_report.add_argument("--apply", action="store_true", help="Write files")
    p_report.set_defaults(func=cmd_report)

    p_rewrite = sub.add_parser(
        "rewrite-imports",
        help="Rewrite imports for modules already moved to diagnostics",
    )
    p_rewrite.add_argument("--root", default=".", help="Repository root")
    p_rewrite.add_argument("--apply", action="store_true", help="Write changes")
    p_rewrite.add_argument("paths", nargs="*", help="Optional Python files")
    p_rewrite.set_defaults(func=cmd_rewrite_imports)

    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
