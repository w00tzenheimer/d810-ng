#!/usr/bin/env python3
"""Report and mechanically rename the safe lifecycle-consolidation residue.

The B0 lifecycle migration deliberately has two classes of work:

* exact spelling/module substitutions that LibCST can preserve safely; and
* ownership changes (adapter runtime calls, event subscribers, resolver
  registries) that require an architectural edit and must not be guessed.

Default mode only reports candidates.  ``--apply`` is atomic and refuses to
write when the selected paths contain any manual-migration candidate.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

import libcst as cst


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCOPES = ("src", "tests")
SCAN_SUFFIXES = frozenset({".py", ".json"})
SELF_TEST_FILE = f"test_{Path(__file__).stem}.py"
SKIP_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".venv",
        "graphify-out",
        "__pycache__",
        "build",
        "dist",
    }
)

MODULE_RENAMES = {
    "d810.passes.recon_runtime_factory": "d810.passes.analysis_runtime_factory",
}
NAME_RENAMES = {
    "ReconPhase": "PreanalysisPhase",
    "FactLifecycleRuntime": "PreanalysisFactRuntime",
    "ReconAnalysisRuntime": "DecompilationAnalysisRuntime",
    "ReconRuntimeBundle": "AnalysisRuntimeBundle",
    "build_recon_phase": "build_preanalysis_phase",
    "build_recon_runtime_bundle": "build_analysis_runtime_bundle",
    "register_default_recon_collectors": "register_default_preanalysis_collectors",
    "register_default_fact_collectors": "register_default_preanalysis_fact_collectors",
    "recon_phase": "preanalysis_phase",
    "_recon_phase": "_preanalysis_phase",
    "recon_runtime": "analysis_runtime",
    "_recon_runtime": "_analysis_runtime",
    "_recon_bundle": "_analysis_bundle",
    "recon_db": "analysis_db",
    "enable_recon_pipeline": "enable_analysis_pipeline",
    "recon_fact_profile_modules": "preanalysis_profile_modules",
    "_load_recon_fact_profile_modules": "_load_preanalysis_profile_modules",
}
LITERAL_RENAMES = {
    **NAME_RENAMES,
    "D810.recon.flowgraph_ready": "D810.preanalysis.flowgraph_ready",
}
EVENT_RENAMES = {
    "STARTED": "SESSION_STARTED",
    "FINISHED": "SESSION_FINISHED",
}
RESOLVER_GLOBALS = frozenset(
    {
        "_MATERIALIZATION_SESSIONS",
        "_RESOLUTIONS_BY_EA",
        "_PREPATCH_PREOPT_UNION_SOURCES",
        "_PREOPT_UNION_PREPARATIONS",
    }
)
MANUAL_NAMES = frozenset({"FlowGraphReadySubscriber"})
MANUAL_RUNTIME_METHODS = frozenset({"reset_for_func", "analyze_and_persist"})
EVENT_SUBSCRIBER_METHODS = frozenset({"on", "subscribe", "emit"})


@dataclass(frozen=True, slots=True)
class Candidate:
    path: str
    line: int
    column: int
    kind: str
    detail: str
    rewriteable: bool


@dataclass(frozen=True, slots=True)
class RewriteResult:
    text: str
    changed: bool


def _node_code(node: cst.CSTNode) -> str:
    return cst.Module([]).code_for_node(node)


class _LifecycleRenameTransformer(cst.CSTTransformer):
    """Apply only substitutions whose target spelling is already specified."""

    def leave_Name(
        self,
        original_node: cst.Name,
        updated_node: cst.Name,
    ) -> cst.Name:
        replacement = NAME_RENAMES.get(updated_node.value)
        if replacement is None:
            return updated_node
        return updated_node.with_changes(value=replacement)

    def leave_Import(
        self,
        original_node: cst.Import,
        updated_node: cst.Import,
    ) -> cst.Import:
        aliases = []
        changed = False
        for alias in updated_node.names:
            replacement = MODULE_RENAMES.get(_node_code(alias.name))
            if replacement is None:
                aliases.append(alias)
                continue
            aliases.append(alias.with_changes(name=cst.parse_expression(replacement)))
            changed = True
        return updated_node.with_changes(names=tuple(aliases)) if changed else updated_node

    def leave_ImportFrom(
        self,
        original_node: cst.ImportFrom,
        updated_node: cst.ImportFrom,
    ) -> cst.ImportFrom:
        if updated_node.module is None:
            return updated_node
        replacement = MODULE_RENAMES.get(_node_code(updated_node.module))
        if replacement is None:
            return updated_node
        return updated_node.with_changes(module=cst.parse_expression(replacement))

    def leave_Attribute(
        self,
        original_node: cst.Attribute,
        updated_node: cst.Attribute,
    ) -> cst.Attribute:
        if (
            isinstance(updated_node.value, cst.Name)
            and updated_node.value.value == "DecompilationEvent"
            and updated_node.attr.value in EVENT_RENAMES
        ):
            return updated_node.with_changes(
                attr=cst.Name(EVENT_RENAMES[updated_node.attr.value])
            )
        return updated_node

    def leave_SimpleString(
        self,
        original_node: cst.SimpleString,
        updated_node: cst.SimpleString,
    ) -> cst.SimpleString:
        try:
            value = ast.literal_eval(updated_node.value)
        except (SyntaxError, ValueError):
            return updated_node
        if not isinstance(value, str):
            return updated_node
        replacement = LITERAL_RENAMES.get(value)
        if replacement is None:
            return updated_node
        return cst.SimpleString(json.dumps(replacement))


def rewrite_text(source: str) -> RewriteResult:
    """Return a formatting-preserving rewrite for declared safe substitutions."""
    module = cst.parse_module(source)
    rewritten = module.visit(_LifecycleRenameTransformer()).code
    return RewriteResult(text=rewritten, changed=rewritten != source)


def _event_name(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Attribute):
        return None
    if not isinstance(node.value, ast.Name):
        return None
    if node.value.id != "DecompilationEvent" or node.attr not in EVENT_RENAMES:
        return None
    return node.attr


class _CandidateVisitor(ast.NodeVisitor):
    def __init__(self, relative_path: str) -> None:
        self._relative_path = relative_path
        self.candidates: list[Candidate] = []

    def _add(
        self,
        node: ast.AST,
        *,
        kind: str,
        detail: str,
        rewriteable: bool,
    ) -> None:
        self.candidates.append(
            Candidate(
                path=self._relative_path,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0),
                kind=kind,
                detail=detail,
                rewriteable=rewriteable,
            )
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name in NAME_RENAMES or module in MODULE_RENAMES:
                self._add(
                    node,
                    kind="legacy-import",
                    detail=f"from {module} import {alias.name}",
                    rewriteable=True,
                )
            elif alias.name in MANUAL_NAMES:
                self._add(
                    node,
                    kind="manual-lifecycle-owner",
                    detail=f"from {module} import {alias.name}",
                    rewriteable=False,
                )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in MODULE_RENAMES:
                self._add(
                    node,
                    kind="legacy-import",
                    detail=f"import {alias.name}",
                    rewriteable=True,
                )

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in NAME_RENAMES:
            self._add(
                node,
                kind="legacy-symbol",
                detail=node.id,
                rewriteable=True,
            )
        elif node.id in RESOLVER_GLOBALS:
            self._add(
                node,
                kind="resolver-global-access",
                detail=node.id,
                rewriteable=False,
            )
        elif node.id in MANUAL_NAMES:
            self._add(
                node,
                kind="manual-lifecycle-owner",
                detail=node.id,
                rewriteable=False,
            )

    def visit_Attribute(self, node: ast.Attribute) -> None:
        event_name = _event_name(node)
        if event_name is not None:
            self._add(
                node,
                kind="legacy-event",
                detail=f"DecompilationEvent.{event_name}",
                rewriteable=True,
            )
        elif node.attr in NAME_RENAMES:
            self._add(
                node,
                kind="legacy-attribute",
                detail=node.attr,
                rewriteable=True,
            )
        elif node.attr in RESOLVER_GLOBALS:
            self._add(
                node,
                kind="resolver-global-access",
                detail=node.attr,
                rewriteable=False,
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in MANUAL_RUNTIME_METHODS:
                self._add(
                    node,
                    kind="direct-runtime-call",
                    detail=node.func.attr,
                    rewriteable=False,
                )
            elif node.func.attr in EVENT_SUBSCRIBER_METHODS:
                for argument in node.args:
                    event_name = _event_name(argument)
                    if event_name is not None:
                        self._add(
                            argument,
                            kind="event-subscription",
                            detail=(
                                f"{node.func.attr}("
                                f"DecompilationEvent.{event_name}, ...)"
                            ),
                            rewriteable=False,
                        )
        for keyword in node.keywords:
            if keyword.arg in NAME_RENAMES:
                self._add(
                    keyword.value,
                    kind="constructor-injection",
                    detail=keyword.arg,
                    rewriteable=True,
                )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and node.value in LITERAL_RENAMES:
            self._add(
                node,
                kind=(
                    "legacy-log-prefix"
                    if node.value.startswith("D810.recon.")
                    else "legacy-config-key"
                ),
                detail=node.value,
                rewriteable=True,
            )


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _scan_json_config(path: Path, *, root: Path) -> list[Candidate]:
    """Report configuration keys without reformatting or rewriting JSON."""
    try:
        source = path.read_text(encoding="utf-8")
        json.loads(source)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [
            Candidate(
                path=_relative_path(path, root),
                line=getattr(error, "lineno", 0) or 0,
                column=getattr(error, "colno", 0) or 0,
                kind="unparseable-source",
                detail=str(error),
                rewriteable=False,
            )
        ]

    candidates: list[Candidate] = []
    for legacy_name in NAME_RENAMES:
        token = json.dumps(legacy_name)
        offset = 0
        while True:
            index = source.find(token, offset)
            if index < 0:
                break
            line = source.count("\n", 0, index) + 1
            column = index - source.rfind("\n", 0, index) - 1
            candidates.append(
                Candidate(
                    path=_relative_path(path, root),
                    line=line,
                    column=column,
                    kind="manual-config-key",
                    detail=legacy_name,
                    rewriteable=False,
                )
            )
            offset = index + len(token)
    return candidates


def scan_paths(paths: Sequence[Path], *, root: Path) -> list[Candidate]:
    """Classify every requested migration candidate without mutating a file."""
    candidates: list[Candidate] = []
    for path in paths:
        if path.suffix == ".json":
            candidates.extend(_scan_json_config(path, root=root))
            continue
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError) as error:
            candidates.append(
                Candidate(
                    path=_relative_path(path, root),
                    line=getattr(error, "lineno", 0) or 0,
                    column=getattr(error, "offset", 0) or 0,
                    kind="unparseable-source",
                    detail=str(error),
                    rewriteable=False,
                )
            )
            continue
        visitor = _CandidateVisitor(_relative_path(path, root))
        visitor.visit(tree)
        candidates.extend(visitor.candidates)
    return sorted(
        candidates,
        key=lambda item: (item.path, item.line, item.column, item.kind, item.detail),
    )


def _iter_scan_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        if path.suffix in SCAN_SUFFIXES:
            yield path
        return
    if not path.is_dir():
        return
    for child in sorted(path.rglob("*")):
        if not any(part in SKIP_PARTS for part in child.parts):
            if child.is_file() and child.suffix in SCAN_SUFFIXES:
                yield child


def discover_paths(root: Path, requested: Sequence[str]) -> list[Path]:
    """Return a stable, de-duplicated set of Python files to inspect."""
    roots = [root / item for item in DEFAULT_SCOPES] if not requested else [
        Path(item).resolve() for item in requested
    ]
    discovered = {
        path.resolve()
        for item in roots
        for path in _iter_scan_files(item)
        if path.name != SELF_TEST_FILE
    }
    return sorted(discovered)


def _report_payload(root: Path, candidates: Sequence[Candidate]) -> dict[str, object]:
    unknown = sum(not candidate.rewriteable for candidate in candidates)
    return {
        "schema_version": 1,
        "root": str(root),
        "summary": {
            "candidates": len(candidates),
            "rewritable": len(candidates) - unknown,
            "unknown": unknown,
        },
        "candidates": [asdict(candidate) for candidate in candidates],
    }


def _write_report(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _manual_candidate_dicts(payload: dict[str, object]) -> list[dict[str, object]]:
    candidates = payload.get("candidates", [])
    if not isinstance(candidates, list):
        return []
    return [
        candidate
        for candidate in candidates
        if isinstance(candidate, dict) and not bool(candidate.get("rewriteable"))
    ]


def _candidate_fingerprint(candidate: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(candidate.get("path", "")),
        str(candidate.get("kind", "")),
        str(candidate.get("detail", "")),
    )


def _counter_for_candidates(
    candidates: Iterable[dict[str, object]],
) -> dict[tuple[str, str, str], int]:
    counts: dict[tuple[str, str, str], int] = {}
    for candidate in candidates:
        fingerprint = _candidate_fingerprint(candidate)
        counts[fingerprint] = counts.get(fingerprint, 0) + 1
    return counts


def verify_manifest(
    payload: dict[str, object],
    manifest: dict[str, object],
    *,
    root: Path,
) -> list[str]:
    """Return lifecycle-manifest violations for one freshly scanned report.

    The manifest deliberately derives the non-runtime allowlist from a checked
    baseline report.  That makes each existing manual candidate explicit while
    still allowing a candidate to disappear as its migration batch lands.
    Direct runtime calls are stricter: tests may exercise the runtime API, but
    production calls require an exact declared coordinator/internal allowance.
    """
    errors: list[str] = []
    if manifest.get("schema_version") != 1:
        return ["manifest schema_version must be 1"]
    baseline_name = manifest.get("baseline_report")
    if not isinstance(baseline_name, str) or not baseline_name:
        return ["manifest baseline_report must be a non-empty path"]
    baseline_path = root / baseline_name
    try:
        baseline_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [f"could not read manifest baseline report {baseline_path}: {error}"]
    if not isinstance(baseline_payload, dict):
        return [f"manifest baseline report is not an object: {baseline_path}"]

    current_manual = _manual_candidate_dicts(payload)
    baseline_manual = _manual_candidate_dicts(baseline_payload)
    retired_kinds = {
        str(kind)
        for kind in manifest.get("retired_manual_kinds", [])
        if isinstance(kind, str)
    }
    for candidate in current_manual:
        kind = str(candidate.get("kind", ""))
        if kind in retired_kinds:
            errors.append(
                "retired manual candidate remains: "
                f"{candidate.get('path')}:{candidate.get('line')} "
                f"{kind} {candidate.get('detail')}"
            )

    current_non_runtime = [
        candidate
        for candidate in current_manual
        if str(candidate.get("kind", "")) != "direct-runtime-call"
    ]
    baseline_non_runtime = [
        candidate
        for candidate in baseline_manual
        if str(candidate.get("kind", "")) != "direct-runtime-call"
    ]
    current_counts = _counter_for_candidates(current_non_runtime)
    baseline_counts = _counter_for_candidates(baseline_non_runtime)
    for fingerprint, count in sorted(current_counts.items()):
        baseline_count = baseline_counts.get(fingerprint, 0)
        if count > baseline_count:
            path, kind, detail = fingerprint
            errors.append(
                "manual candidate is not baseline-allowlisted: "
                f"{path} {kind} {detail} ({count}>{baseline_count})"
            )

    direct_config = manifest.get("direct_runtime", {})
    if not isinstance(direct_config, dict):
        errors.append("manifest direct_runtime must be an object")
        direct_config = {}
    direct_candidates = [
        candidate
        for candidate in current_manual
        if str(candidate.get("kind", "")) == "direct-runtime-call"
    ]
    checkpoint_count = direct_config.get("checkpoint_count")
    if not isinstance(checkpoint_count, int):
        errors.append("manifest direct_runtime.checkpoint_count must be an integer")
    elif len(direct_candidates) > checkpoint_count:
        errors.append(
            "direct-runtime-call count increased beyond migration checkpoint: "
            f"{len(direct_candidates)}>{checkpoint_count}"
        )

    baseline_test_counts = _counter_for_candidates(
        candidate
        for candidate in baseline_manual
        if str(candidate.get("kind", "")) == "direct-runtime-call"
        and str(candidate.get("path", "")).startswith("tests/")
    )
    allowed_production: dict[tuple[str, str], int] = {}
    for item in direct_config.get("allowed_production", []):
        if not isinstance(item, dict):
            errors.append("direct_runtime.allowed_production entries must be objects")
            continue
        path = item.get("path")
        detail = item.get("detail")
        maximum = item.get("maximum")
        if not isinstance(path, str) or not isinstance(detail, str) or not isinstance(
            maximum, int
        ):
            errors.append(
                "direct_runtime allowed production entry needs path/detail/maximum"
            )
            continue
        allowed_production[(path, detail)] = maximum
    production_counts: dict[tuple[str, str], int] = {}
    test_counts: dict[tuple[str, str, str], int] = {}
    for candidate in direct_candidates:
        path = str(candidate.get("path", ""))
        detail = str(candidate.get("detail", ""))
        if path.startswith("tests/"):
            fingerprint = _candidate_fingerprint(candidate)
            test_counts[fingerprint] = test_counts.get(fingerprint, 0) + 1
            continue
        key = (path, detail)
        production_counts[key] = production_counts.get(key, 0) + 1
    for fingerprint, count in sorted(test_counts.items()):
        baseline_count = baseline_test_counts.get(fingerprint, 0)
        if count > baseline_count:
            path, _kind, detail = fingerprint
            errors.append(
                "test direct-runtime-call is not baseline-allowlisted: "
                f"{path} {detail} ({count}>{baseline_count})"
            )
    for key, count in sorted(production_counts.items()):
        maximum = allowed_production.get(key, 0)
        if count > maximum:
            path, detail = key
            errors.append(
                "production direct-runtime-call is not manifest-allowlisted: "
                f"{path} {detail} ({count}>{maximum})"
            )

    bridges = manifest.get("bridges", [])
    if not isinstance(bridges, list):
        errors.append("manifest bridges must be a list")
        bridges = []
    for bridge in bridges:
        if not isinstance(bridge, dict):
            errors.append("manifest bridge entries must be objects")
            continue
        path = bridge.get("path")
        kind = bridge.get("kind")
        details = bridge.get("details")
        if not isinstance(path, str) or not isinstance(kind, str) or not isinstance(
            details, list
        ):
            errors.append("manifest bridge requires path, kind, and details")
            continue
        detail_set = {str(detail) for detail in details}
        bridge_count = sum(
            1
            for candidate in current_manual
            if str(candidate.get("path", "")) == path
            and str(candidate.get("kind", "")) == kind
            and str(candidate.get("detail", "")) in detail_set
        )
        if bridge_count == 0 and (root / path).exists():
            errors.append(
                "bridge has no remaining legacy candidates and must be removed: "
                f"{path}"
            )
    return errors


def _rewrite_candidates(paths: Sequence[Path]) -> list[tuple[Path, RewriteResult]]:
    rewrites: list[tuple[Path, RewriteResult]] = []
    for path in paths:
        if path.suffix != ".py":
            continue
        source = path.read_text(encoding="utf-8")
        result = rewrite_text(source)
        if result.changed:
            rewrites.append((path, result))
    return rewrites


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="Python files or directories to inspect")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--report", type=Path, help="Write JSON inventory to this path")
    parser.add_argument(
        "--manifest",
        type=Path,
        help="Verify the report against a lifecycle migration manifest",
    )
    parser.add_argument("--apply", action="store_true", help="Write only safe substitutions")
    parser.add_argument(
        "--test-update",
        action="append",
        type=Path,
        default=[],
        help="Updated test file that covers this apply batch; required with --apply",
    )
    return parser.parse_args(argv)


def _validate_test_updates(root: Path, test_updates: Sequence[Path]) -> str | None:
    if not test_updates:
        return "pass at least one --test-update <tests/test_*.py> path"
    for test_update in test_updates:
        path = test_update.resolve()
        try:
            relative = path.relative_to(root)
        except ValueError:
            return f"test update is outside --root: {test_update}"
        if not path.is_file() or path.suffix != ".py" or not relative.parts[:1] == ("tests",):
            return f"test update must be an existing Python file under tests/: {test_update}"
    return None


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.root.resolve()
    paths = discover_paths(root, args.paths)
    candidates = scan_paths(paths, root=root)
    payload = _report_payload(root, candidates)
    if args.report is not None:
        _write_report(args.report.resolve(), payload)

    manifest_errors: list[str] = []
    if args.manifest is not None:
        try:
            manifest_payload = json.loads(args.manifest.resolve().read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as error:
            manifest_errors = [f"could not read manifest {args.manifest}: {error}"]
        else:
            if not isinstance(manifest_payload, dict):
                manifest_errors = [f"manifest is not an object: {args.manifest}"]
            else:
                manifest_errors = verify_manifest(payload, manifest_payload, root=root)

    for candidate in candidates:
        mode = "rewrite" if candidate.rewriteable else "manual"
        print(
            f"candidate [{mode}:{candidate.kind}] "
            f"{candidate.path}:{candidate.line}:{candidate.column} {candidate.detail}"
        )

    if manifest_errors:
        for error in manifest_errors:
            print(f"manifest violation: {error}", file=sys.stderr)
        return 2

    unknown = payload["summary"]["unknown"]
    if args.apply and unknown:
        print(
            f"refusing --apply: {unknown} manual migration candidate(s) remain; "
            "no files were written",
            file=sys.stderr,
        )
        return 2

    if args.apply:
        test_update_error = _validate_test_updates(root, args.test_update)
        if test_update_error is not None:
            print(f"refusing --apply: {test_update_error}; no files were written", file=sys.stderr)
            return 2

    rewrites = _rewrite_candidates(paths)
    if args.apply:
        for path, result in rewrites:
            path.write_text(result.text, encoding="utf-8")
            print(f"rewrote {_relative_path(path, root)}")
        print(f"apply: rewritten={len(rewrites)} candidates={len(candidates)}")
        return 0

    for path, _ in rewrites:
        print(f"would rewrite {_relative_path(path, root)}")
    print(
        "dry-run: "
        f"candidates={len(candidates)} rewritten={len(rewrites)} unknown={unknown}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
