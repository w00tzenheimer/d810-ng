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
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

import libcst as cst


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCOPES = ("src", "tests", "tools")
SCAN_SUFFIXES = frozenset({".py", ".json", ".toml"})
SELF_TEST_FILE = f"test_{Path(__file__).stem}.py"
SELF_SCRIPT = Path(__file__).resolve()
SKIP_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".venv",
        "graphify-out",
        "codemod_reports",
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
    "ReconCollectionContext": "PreanalysisCollectionContext",
    "ReconCollector": "PreanalysisCollector",
    "ReconOutcome": "AnalysisOutcome",
    "ReconOutcomeLog": "AnalysisOutcomeLog",
    "ReconResult": "PreanalysisResult",
    "ReconRoundDiscoveryContext": "PreanalysisRoundDiscoveryContext",
    "ReconStore": "PreanalysisStore",
    "ReconStoreWriter": "PreanalysisStoreWriter",
    "DEFAULT_RECON_COLLECTOR_FACTORIES": "DEFAULT_PREANALYSIS_COLLECTOR_FACTORIES",
    "DEFAULT_RECON_COLLECTOR_NAMES": "DEFAULT_PREANALYSIS_COLLECTOR_NAMES",
    "_create_default_recon_phase": "_create_default_preanalysis_phase",
    "build_recon_phase": "build_preanalysis_phase",
    "build_recon_runtime_bundle": "build_analysis_runtime_bundle",
    "coerce_recon_collection_context": "coerce_preanalysis_collection_context",
    "get_recon_writer": "get_preanalysis_writer",
    "load_all_recon_results": "load_all_preanalysis_results",
    "load_latest_recon_result": "load_latest_preanalysis_result",
    "load_recon_results": "load_preanalysis_results",
    "register_default_recon_collectors": "register_default_preanalysis_collectors",
    "register_default_fact_collectors": "register_default_preanalysis_fact_collectors",
    "save_recon_result": "save_preanalysis_result",
    "recon_phase": "preanalysis_phase",
    "_recon_phase": "_preanalysis_phase",
    "recon_runtime": "analysis_runtime",
    "_recon_runtime": "_analysis_runtime",
    "_recon_bundle": "_analysis_bundle",
    "recon_db": "analysis_db",
    "recon_db_path": "analysis_db_path",
    "recon_store_path": "analysis_store_path",
    "recon_store_session": "analysis_store_session",
    "_recon": "_preanalysis",
    "_recon_diagnostics_enabled": "_preanalysis_diagnostics_enabled",
    "_recon_fact_collector_registration_handlers": (
        "_preanalysis_fact_collector_registration_handlers"
    ),
    "emit_recon_fact_collector_registration": (
        "emit_preanalysis_fact_collector_registration"
    ),
    "find_latest_recon_db": "find_latest_analysis_db",
    "register_recon_fact_collector_registration_handler": (
        "register_preanalysis_fact_collector_registration_handler"
    ),
    "unregister_recon_fact_collector_registration_handler": (
        "unregister_preanalysis_fact_collector_registration_handler"
    ),
    "enable_recon_pipeline": "enable_analysis_pipeline",
    "recon_fact_profiles": "preanalysis_fact_profiles",
    "recon_fact_profile_modules": "preanalysis_profile_modules",
    "_load_recon_fact_profile_modules": "_load_preanalysis_profile_modules",
}
CLI_RENAMES = {
    "d810-recon": "d810-preanalysis",
    "--recon-db": "--analysis-db",
}
LITERAL_RENAMES = {
    **NAME_RENAMES,
    **CLI_RENAMES,
    "D810.recon.flowgraph_ready": "D810.preanalysis.flowgraph_ready",
}
EVENT_RENAMES = {
    "STARTED": "SESSION_STARTED",
    "FINISHED": "SESSION_FINISHED",
}
RESOLVER_GLOBALS = frozenset(
    {
        "_MATERIALIZED_EAS",
        "_MATERIALIZATION_SESSIONS",
        "_PROVEN_CALL_ABI_BY_EA",
        "_RESOLUTIONS_BY_EA",
        "_PREPATCH_PREOPT_UNION_SOURCES",
        "_PREOPT_UNION_PREPARATIONS",
        "_MATERIALIZED_INDIRECT_TRANSFERS",
        "_TERMINAL_RETURN_CARRIER_REQUESTS",
        "_INDIRECT_MATERIALIZED_FUNCTION_EAS",
        "_INDIRECT_DISPATCHER_FUNCTION_EAS",
    }
)
LEGACY_RESOLVER_APIS = frozenset(
    {
        "get_materialized_indirect_transfers",
        "get_terminal_return_carrier_requests",
        "record_materialized_indirect_transfers",
        "record_terminal_return_carrier_requests",
        "clear_materialized_indirect_dispatcher_evidence",
    }
)
ADDRESS_KEYED_RESOLVER_APIS = frozenset(
    {"mark_indirect_dispatcher", "is_materialized_indirect_dispatcher"}
)
MANUAL_NAMES = frozenset({"FlowGraphReadySubscriber"})
MANUAL_RUNTIME_METHODS = frozenset({"reset_for_func", "analyze_and_persist"})
EVENT_SUBSCRIBER_METHODS = frozenset({"on", "subscribe", "emit"})
CLI_DECLARATION_METHODS = frozenset({"add_argument", "add_parser"})
TEMPORARY_INTERNAL_PORTS = frozenset({"template_maturity"})
_RECON_API_NAME = re.compile(r"^_?recon(?:_|$)|^Recon(?:_|[A-Z]|$)")


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


def _rewrite_dotted_symbol_literal(value: str) -> str:
    """Rewrite declared module/symbol spellings in an import or mock target."""
    whole_module = MODULE_RENAMES.get(value)
    if whole_module is not None:
        return whole_module
    if "." not in value:
        return value
    return ".".join(NAME_RENAMES.get(part, part) for part in value.split("."))


def _rewrite_literal(value: str) -> str:
    """Return the declared replacement for one string literal, if any."""
    direct = LITERAL_RENAMES.get(value)
    return direct if direct is not None else _rewrite_dotted_symbol_literal(value)


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
        replacement = _rewrite_literal(value)
        if replacement == value:
            return updated_node
        return cst.SimpleString(json.dumps(replacement))

    def leave_FormattedStringText(
        self,
        original_node: cst.FormattedStringText,
        updated_node: cst.FormattedStringText,
    ) -> cst.FormattedStringText:
        replacement = _rewrite_literal(updated_node.value)
        if replacement == updated_node.value:
            return updated_node
        return updated_node.with_changes(value=replacement)


def rewrite_text(source: str) -> RewriteResult:
    """Return a formatting-preserving rewrite for declared safe substitutions."""
    module = cst.parse_module(source)
    rewritten = module.visit(_LifecycleRenameTransformer()).code
    return RewriteResult(text=rewritten, changed=rewritten != source)


def rewrite_json_text(source: str) -> RewriteResult:
    """Rewrite declared JSON keys without reformatting the file."""
    rewritten = source
    for original, replacement in NAME_RENAMES.items():
        rewritten = re.sub(
            rf"{re.escape(json.dumps(original))}(?=\s*:)",
            json.dumps(replacement),
            rewritten,
        )
    return RewriteResult(text=rewritten, changed=rewritten != source)


def rewrite_toml_text(source: str) -> RewriteResult:
    """Rewrite declared project-script names without reformatting TOML."""
    rewritten = source
    for original, replacement in CLI_RENAMES.items():
        rewritten = re.sub(
            rf"(?m)^(?P<indent>\s*){re.escape(original)}(?=\s*=)",
            rf"\g<indent>{replacement}",
            rewritten,
        )
    return RewriteResult(text=rewritten, changed=rewritten != source)


def _event_name(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Attribute):
        return None
    if not isinstance(node.value, ast.Name):
        return None
    if node.value.id != "DecompilationEvent" or node.attr not in EVENT_RENAMES:
        return None
    return node.attr


def _is_analysis_runtime_receiver(node: ast.AST) -> bool:
    """Return whether a call receiver denotes the injected analysis runtime.

    The fact-capture and outcome-log internals intentionally expose a method
    named ``reset_for_func`` too.  Those are implementation details, not
    adapter-owned calls into the decompilation runtime and must not block a
    terminology-only codemod batch.
    """
    if isinstance(node, ast.Name):
        return node.id in {"runtime", "analysis_runtime", "recon_runtime"}
    return isinstance(node, ast.Attribute) and node.attr in {
        "analysis_runtime",
        "_analysis_runtime",
        "recon_runtime",
        "_recon_runtime",
    }


def _is_function_ea_argument(node: ast.AST) -> bool:
    """Recognize the former function-EA facade without flagging session calls."""
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return True
    return (
        isinstance(node, ast.Name)
        and node.id.lstrip("_").lower() in {"function_ea", "func_ea"}
    )


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
        elif node.id in RESOLVER_GLOBALS | LEGACY_RESOLVER_APIS:
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
        elif _RECON_API_NAME.match(node.id):
            self._add(
                node,
                kind="residual-recon-api",
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
        elif node.attr in RESOLVER_GLOBALS | LEGACY_RESOLVER_APIS:
            self._add(
                node,
                kind="resolver-global-access",
                detail=node.attr,
                rewriteable=False,
            )
        elif _RECON_API_NAME.match(node.attr):
            self._add(
                node,
                kind="residual-recon-api",
                detail=node.attr,
                rewriteable=False,
            )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name in NAME_RENAMES:
            self._add(
                node,
                kind="legacy-symbol",
                detail=node.name,
                rewriteable=True,
            )
        elif _RECON_API_NAME.match(node.name):
            self._add(
                node,
                kind="residual-recon-api",
                detail=node.name,
                rewriteable=False,
            )
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ):
            if argument.arg in TEMPORARY_INTERNAL_PORTS:
                self._add(
                    argument,
                    kind="temporary-internal-port",
                    detail=argument.arg,
                    rewriteable=False,
                )
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if node.name in NAME_RENAMES:
            self._add(
                node,
                kind="legacy-symbol",
                detail=node.name,
                rewriteable=True,
            )
        elif _RECON_API_NAME.match(node.name):
            self._add(
                node,
                kind="residual-recon-api",
                detail=node.name,
                rewriteable=False,
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            if (
                node.func.attr in MANUAL_RUNTIME_METHODS
                and _is_analysis_runtime_receiver(node.func.value)
            ):
                self._add(
                    node,
                    kind="direct-runtime-call",
                    detail=node.func.attr,
                    rewriteable=False,
                )
            elif (
                node.func.attr in ADDRESS_KEYED_RESOLVER_APIS
                and node.args
                and _is_function_ea_argument(node.args[0])
            ):
                self._add(
                    node,
                    kind="resolver-global-access",
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
            if node.func.attr in CLI_DECLARATION_METHODS:
                for argument in node.args:
                    if not (
                        isinstance(argument, ast.Constant)
                        and isinstance(argument.value, str)
                    ):
                        continue
                    if argument.value in CLI_RENAMES:
                        self._add(
                            argument,
                            kind="legacy-cli-name",
                            detail=argument.value,
                            rewriteable=True,
                        )
                    elif argument.value.startswith("--recon"):
                        self._add(
                            argument,
                            kind="legacy-cli-name",
                            detail=argument.value,
                            rewriteable=False,
                        )
                    elif (
                        node.func.attr == "add_parser"
                        and argument.value in CLI_RENAMES
                    ):
                        self._add(
                            argument,
                            kind="legacy-cli-name",
                            detail=argument.value,
                            rewriteable=True,
                        )
        for keyword in node.keywords:
            if keyword.arg in NAME_RENAMES:
                self._add(
                    keyword.value,
                    kind="constructor-injection",
                    detail=keyword.arg,
                    rewriteable=True,
                )
            elif keyword.arg in TEMPORARY_INTERNAL_PORTS:
                self._add(
                    keyword.value,
                    kind="temporary-internal-port",
                    detail=keyword.arg,
                    rewriteable=False,
                )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if not isinstance(node.value, str):
            return
        if node.value in CLI_RENAMES:
            return
        if node.value in LITERAL_RENAMES:
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
        elif _rewrite_dotted_symbol_literal(node.value) != node.value:
            self._add(
                node,
                kind="legacy-symbol",
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
        pattern = re.compile(rf"{re.escape(json.dumps(legacy_name))}(?=\s*:)")
        for match in pattern.finditer(source):
            index = match.start()
            line = source.count("\n", 0, index) + 1
            column = index - source.rfind("\n", 0, index) - 1
            candidates.append(
                Candidate(
                    path=_relative_path(path, root),
                    line=line,
                    column=column,
                    kind="legacy-config-key",
                    detail=legacy_name,
                    rewriteable=True,
                )
            )
    return candidates


def _scan_toml_config(path: Path, *, root: Path) -> list[Candidate]:
    """Inventory legacy console-script names without changing TOML parsing."""
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        return [
            Candidate(
                path=_relative_path(path, root),
                line=0,
                column=0,
                kind="unparseable-source",
                detail=str(error),
                rewriteable=False,
            )
        ]
    candidates: list[Candidate] = []
    for legacy_name in CLI_RENAMES:
        pattern = re.compile(rf"(?m)^\s*{re.escape(legacy_name)}(?=\s*=)")
        for match in pattern.finditer(source):
            index = match.start() + len(match.group()) - len(legacy_name)
            candidates.append(
                Candidate(
                    path=_relative_path(path, root),
                    line=source.count("\n", 0, index) + 1,
                    column=index - source.rfind("\n", 0, index) - 1,
                    kind="legacy-cli-name",
                    detail=legacy_name,
                    rewriteable=True,
                )
            )
    return candidates


def scan_paths(paths: Sequence[Path], *, root: Path) -> list[Candidate]:
    """Classify every requested migration candidate without mutating a file."""
    candidates: list[Candidate] = []
    for path in paths:
        if path.suffix == ".json":
            candidates.extend(_scan_json_config(path, root=root))
            continue
        if path.suffix == ".toml":
            candidates.extend(_scan_toml_config(path, root=root))
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
    """Return a stable, de-duplicated set of source and config files to inspect."""
    roots = (
        [*(root / item for item in DEFAULT_SCOPES), root / "pyproject.toml"]
        if not requested
        else [Path(item).resolve() for item in requested]
    )
    discovered = {
        path.resolve()
        for item in roots
        for path in _iter_scan_files(item)
        if path.name != SELF_TEST_FILE and path.resolve() != SELF_SCRIPT
    }
    return sorted(discovered)


def _summary(candidates: Sequence[Candidate]) -> dict[str, object]:
    unknown = sum(not candidate.rewriteable for candidate in candidates)
    by_kind: dict[str, int] = {}
    for candidate in candidates:
        by_kind[candidate.kind] = by_kind.get(candidate.kind, 0) + 1
    return {
        "candidates": len(candidates),
        "rewritable": len(candidates) - unknown,
        "unknown": unknown,
        "by_kind": dict(sorted(by_kind.items())),
    }


def _report_payload(root: Path, candidates: Sequence[Candidate]) -> dict[str, object]:
    production_candidates = [
        candidate for candidate in candidates if not candidate.path.startswith("tests/")
    ]
    tool_candidates = [
        candidate for candidate in candidates if candidate.path.startswith("tools/")
    ]
    return {
        "schema_version": 1,
        "root": str(root),
        "summary": {
            **_summary(candidates),
            "production": _summary(production_candidates),
            "tools": _summary(tool_candidates),
        },
        "candidates": [asdict(candidate) for candidate in candidates],
    }


def _stage_text(path: Path, text: str) -> Path:
    """Write one same-directory temporary file with the destination's mode."""
    path.parent.mkdir(parents=True, exist_ok=True)
    destination_mode = (
        path.stat().st_mode & 0o7777 if path.exists() else None
    )
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.codemod-",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        if destination_mode is not None:
            os.chmod(temporary, destination_mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _write_report(path: Path, payload: dict[str, object]) -> None:
    temporary = _stage_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


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
        if str(candidate.get("kind", ""))
        not in {"direct-runtime-call", "temporary-internal-port"}
    ]
    baseline_non_runtime = [
        candidate
        for candidate in baseline_manual
        if str(candidate.get("kind", ""))
        not in {"direct-runtime-call", "temporary-internal-port"}
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

    temporary_candidates = [
        candidate
        for candidate in current_manual
        if str(candidate.get("kind", "")) == "temporary-internal-port"
    ]
    temporary_ports = manifest.get("temporary_internal_ports", [])
    if not isinstance(temporary_ports, list):
        errors.append("manifest temporary_internal_ports must be a list")
        temporary_ports = []
    allowed_temporary: dict[tuple[str, str], tuple[str, int]] = {}
    declared_ports: list[tuple[str, list[dict[str, object]]]] = []
    for port in temporary_ports:
        if not isinstance(port, dict):
            errors.append("temporary_internal_ports entries must be objects")
            continue
        detail = port.get("detail")
        locations = port.get("locations")
        removal_condition = port.get("removal_condition")
        if (
            not isinstance(detail, str)
            or not isinstance(locations, list)
            or not isinstance(removal_condition, str)
            or not removal_condition.strip()
        ):
            errors.append(
                "temporary internal port requires detail, locations, and "
                "removal_condition"
            )
            continue
        valid_locations: list[dict[str, object]] = []
        for location in locations:
            if not isinstance(location, dict):
                errors.append("temporary internal port locations must be objects")
                continue
            path = location.get("path")
            role = location.get("role")
            maximum = location.get("maximum")
            if (
                not isinstance(path, str)
                or role not in {"definition", "consumer"}
                or not isinstance(maximum, int)
                or maximum < 1
            ):
                errors.append(
                    "temporary internal port location requires path, "
                    "definition/consumer role, and positive maximum"
                )
                continue
            key = (path, detail)
            if key in allowed_temporary:
                errors.append(
                    f"duplicate temporary internal port location: {path} {detail}"
                )
                continue
            allowed_temporary[key] = (str(role), maximum)
            valid_locations.append(location)
        declared_ports.append((detail, valid_locations))

    temporary_counts: dict[tuple[str, str], int] = {}
    for candidate in temporary_candidates:
        key = (str(candidate.get("path", "")), str(candidate.get("detail", "")))
        temporary_counts[key] = temporary_counts.get(key, 0) + 1
        allowance = allowed_temporary.get(key)
        if allowance is None:
            errors.append(
                "temporary internal port is not manifest-allowlisted: "
                f"{key[0]} {key[1]}"
            )
            continue
        _role, maximum = allowance
        if temporary_counts[key] > maximum:
            errors.append(
                "temporary internal port count exceeds manifest maximum: "
                f"{key[0]} {key[1]} "
                f"({temporary_counts[key]}>{maximum})"
            )

    for detail, locations in declared_ports:
        definition_count = sum(
            temporary_counts.get((str(location["path"]), detail), 0)
            for location in locations
            if location.get("role") == "definition"
        )
        consumer_count = sum(
            temporary_counts.get((str(location["path"]), detail), 0)
            for location in locations
            if location.get("role") == "consumer"
        )
        if consumer_count and definition_count != 1:
            errors.append(
                "temporary internal port consumers require exactly one definition: "
                f"{detail} definitions={definition_count} consumers={consumer_count}"
            )
        if definition_count and consumer_count == 0:
            errors.append(
                "temporary internal port has no remaining consumers and must be "
                f"removed: {detail}"
            )
        if definition_count == 0 and consumer_count == 0:
            errors.append(
                "temporary internal port manifest entry has retired and must be "
                f"removed: {detail}"
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
        if path.suffix not in SCAN_SUFFIXES:
            continue
        source = path.read_text(encoding="utf-8")
        if path.suffix == ".py":
            result = rewrite_text(source)
        elif path.suffix == ".json":
            result = rewrite_json_text(source)
        else:
            result = rewrite_toml_text(source)
        if result.changed:
            rewrites.append((path, result))
    return rewrites


def apply_rewrites(rewrites: Sequence[tuple[Path, RewriteResult]]) -> None:
    """Commit a batch atomically, restoring every prior file on failure.

    All replacement and rollback files are staged before the first destination
    changes.  A failed destination replace restores already-committed files
    from their staged original bytes, so an ``--apply`` run cannot leave a
    prefix of its intended edits behind.
    """
    staged: list[tuple[Path, Path, Path]] = []
    try:
        for path, result in rewrites:
            original = path.read_text(encoding="utf-8")
            staged.append((path, _stage_text(path, result.text), _stage_text(path, original)))
    except Exception:
        for _path, replacement, backup in staged:
            replacement.unlink(missing_ok=True)
            backup.unlink(missing_ok=True)
        raise

    committed: list[tuple[Path, Path, Path]] = []
    try:
        for row in staged:
            path, replacement, _backup = row
            os.replace(replacement, path)
            committed.append(row)
    except Exception:
        rollback_error: Exception | None = None
        for path, _replacement, backup in reversed(committed):
            try:
                os.replace(backup, path)
            except Exception as error:  # pragma: no cover - filesystem catastrophe
                rollback_error = error
        if rollback_error is not None:
            raise RuntimeError("codemod rollback failed") from rollback_error
        raise
    finally:
        for _path, replacement, backup in staged:
            replacement.unlink(missing_ok=True)
            backup.unlink(missing_ok=True)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        help="Python, JSON, or TOML paths to inspect",
    )
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
        apply_rewrites(rewrites)
        for path, _result in rewrites:
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
