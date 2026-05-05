"""CLI for the Hex-Rays structuring lab."""
from __future__ import annotations

import argparse
import json
import shlex
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path


LAB_DIR = Path(__file__).resolve().parent
REPO_ROOT = LAB_DIR.parents[1]
SRC_DIR = REPO_ROOT / "src"
REGISTRY_PATH = LAB_DIR / "registry.json"
DEFAULT_OUTPUT_SUBDIR = "hexrays_structuring_lab"
DEFAULT_FROM_LABEL = "state_write_reconstruction_post_apply"
DEFAULT_TO_LABEL = "maturity_MMAT_GLBOPT1_post_d810"
CFG_VALIDATION_OUTPUT_SUBDIR = "hexrays_structuring_lab/cfg_validation"
ALLOWED_CASE_STATUSES = frozenset({
    "planned",
    "compiled_cfg_validated",
    "observed",
    "invalid_compiled_cfg",
})
ALLOWED_CFG_VALIDATION_STATUSES = frozenset({
    "not_run",
    "passed",
    "failed",
    "not_provided",
})


class LabError(Exception):
    """User-facing lab CLI error."""


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, object]:
    """Load and validate the lab registry."""
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise LabError(f"registry not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise LabError(f"registry is not valid JSON: {path}: {exc}") from exc

    cases = data.get("cases")
    if not isinstance(cases, list):
        raise LabError("registry must contain a 'cases' list")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict):
            raise LabError("registry case entries must be objects")
        case_id = case.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise LabError("registry case is missing a non-empty string id")
        if case_id in seen:
            raise LabError(f"duplicate registry case id: {case_id}")
        status = case.get("status")
        if status not in ALLOWED_CASE_STATUSES:
            allowed = ", ".join(sorted(ALLOWED_CASE_STATUSES))
            raise LabError(
                f"case '{case_id}' has invalid status {status!r}; "
                f"expected one of: {allowed}"
            )
        cfg_validation = case.get("cfg_validation")
        if not isinstance(cfg_validation, dict):
            raise LabError(f"case '{case_id}' is missing cfg_validation object")
        validation_status = cfg_validation.get("status")
        if validation_status not in ALLOWED_CFG_VALIDATION_STATUSES:
            allowed = ", ".join(sorted(ALLOWED_CFG_VALIDATION_STATUSES))
            raise LabError(
                f"case '{case_id}' has invalid cfg_validation.status "
                f"{validation_status!r}; expected one of: {allowed}"
            )
        seen.add(case_id)
    return data


def _cases(registry: dict[str, object]) -> list[dict[str, object]]:
    return list(registry.get("cases", []))  # type: ignore[arg-type]


def _case_by_id(registry: dict[str, object], case_id: str) -> dict[str, object]:
    for case in _cases(registry):
        if case.get("id") == case_id:
            return case
    available = ", ".join(str(case.get("id")) for case in _cases(registry))
    raise LabError(f"unknown case '{case_id}'. Available cases: {available}")


def _string_field(case: dict[str, object], key: str, *, default: str = "") -> str:
    value = case.get(key, default)
    return value if isinstance(value, str) else default


def _string_list_field(case: dict[str, object], key: str) -> list[str]:
    value = case.get(key, [])
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _env_field(case: dict[str, object]) -> dict[str, str]:
    value = case.get("env", {})
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


def render_case_command(
    case: dict[str, object],
    *,
    output_subdir: str = DEFAULT_OUTPUT_SUBDIR,
    worktree: str | None = None,
) -> str:
    """Render the Docker dump command for one lab case."""
    case_id = _string_field(case, "id")
    function = _string_field(case, "function")
    project = _string_field(case, "project")
    if not case_id or not function or not project:
        raise LabError(f"case {case_id or '<unknown>'} is missing function/project")

    mkdir_cmd = shlex.join(["mkdir", "-p", f".tmp/{output_subdir}"])
    docker_cmd = [
        "./tools/scripts/run_system_tests_docker.sh",
        "dump",
    ]
    if worktree:
        docker_cmd.extend(["-w", worktree])
    docker_cmd.extend([
        "-f",
        function,
        "-p",
        project,
        "-o",
        f"{output_subdir}/{case_id}.txt",
        "-l",
        "--enable-debug-logging",
    ])
    maturity = _string_field(case, "maturity")
    if maturity:
        docker_cmd.extend(["-m", maturity])
    extra_pytest = _string_list_field(case, "extra_pytest")
    if extra_pytest:
        docker_cmd.append("--")
        docker_cmd.extend(extra_pytest)

    env = _env_field(case)
    binary = _string_field(case, "binary")
    if binary:
        env.setdefault("D810_TEST_BINARY", binary)
    env_prefix = " ".join(
        f"{key}={shlex.quote(value)}" for key, value in sorted(env.items())
    )
    rendered = f"{mkdir_cmd} && "
    if env_prefix:
        rendered += f"{env_prefix} "
    rendered += shlex.join(docker_cmd)
    return rendered


def render_validate_cfg_command(
    case: dict[str, object],
    *,
    output_subdir: str = CFG_VALIDATION_OUTPUT_SUBDIR,
    worktree: str | None = None,
) -> str:
    """Render the compiled-CFG validation command for one lab case."""
    case_id = _string_field(case, "id")
    function = _string_field(case, "function")
    if not case_id or not function:
        raise LabError(f"case {case_id or '<unknown>'} is missing function")
    command = [
        "./tools/scripts/run_system_tests_docker.sh",
        "test",
    ]
    if worktree:
        command.extend(["-w", worktree])
    command.extend([
        "-o",
        f"{output_subdir}/{case_id}.txt",
        "--enable-debug-logging",
        "--",
        "tests/system/runtime/hexrays/test_structuring_lab_cfg_validation.py",
        "-q",
        "--hexrays-lab-case",
        case_id,
        "--hexrays-lab-function",
        function,
        "--hexrays-lab-output-json",
        f".tmp/{output_subdir}/{case_id}.json",
    ])
    binary = _string_field(case, "binary")
    env = _env_field(case)
    if binary:
        env.setdefault("D810_TEST_BINARY", binary)
    env_prefix = " ".join(
        f"{key}={shlex.quote(value)}" for key, value in sorted(env.items())
    )
    mkdir_cmd = shlex.join(["mkdir", "-p", f".tmp/{output_subdir}"])
    rendered = f"{mkdir_cmd} && "
    if env_prefix:
        rendered += f"{env_prefix} "
    rendered += shlex.join(command)
    return rendered


def _resolve_snapshot_id(conn: sqlite3.Connection, label: str) -> int:
    row = conn.execute(
        "SELECT id FROM snapshots WHERE label=? ORDER BY id DESC LIMIT 1",
        (label,),
    ).fetchone()
    if row is None:
        raise LabError(f"no snapshot with label: {label}")
    return int(row[0])


def _default_cfg_validation() -> dict[str, object]:
    return {
        "status": "not_provided",
        "compiler_flags": [],
        "binary_hash": None,
        "artifact_path": None,
        "expected": {},
        "observed": {},
    }


def load_cfg_validation_result(path: Path) -> dict[str, object]:
    """Load a compiled-CFG validation result artifact."""
    if not path.is_file():
        raise LabError(f"compiled-CFG validation result not found: {path}")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise LabError(f"compiled-CFG validation JSON is invalid: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise LabError("compiled-CFG validation result must be a JSON object")
    status = data.get("status")
    if status not in ALLOWED_CFG_VALIDATION_STATUSES:
        allowed = ", ".join(sorted(ALLOWED_CFG_VALIDATION_STATUSES))
        raise LabError(
            f"compiled-CFG validation status {status!r} is invalid; "
            f"expected one of: {allowed}"
        )
    data.setdefault("compiler_flags", [])
    data.setdefault("binary_hash", None)
    data.setdefault("artifact_path", str(path))
    data.setdefault("expected", {})
    data.setdefault("observed", {})
    return data


def _enforce_cfg_validation_gate(cfg_validation: dict[str, object]) -> None:
    status = cfg_validation.get("status")
    if status != "passed":
        raise LabError(
            "compiled-CFG validation is required before structuring summary; "
            f"status={status!r}"
        )


def build_summary(
    db_path: Path,
    *,
    from_label: str = DEFAULT_FROM_LABEL,
    to_label: str = DEFAULT_TO_LABEL,
    cfg_validation_path: Path | None = None,
    require_cfg_validation: bool = False,
) -> dict[str, object]:
    """Build a compact post-apply to post-d810 merge summary."""
    cfg_validation = (
        load_cfg_validation_result(cfg_validation_path)
        if cfg_validation_path is not None
        else _default_cfg_validation()
    )
    if require_cfg_validation:
        _enforce_cfg_validation_gate(cfg_validation)

    if not db_path.is_file():
        raise LabError(f"diagnostic DB not found: {db_path}")
    if SRC_DIR.is_dir() and str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))
    from d810.core.diag.query import merge_causality

    conn = sqlite3.connect(str(db_path))
    try:
        try:
            from_snapshot_id = _resolve_snapshot_id(conn, from_label)
            to_snapshot_id = _resolve_snapshot_id(conn, to_label)
            result = merge_causality(conn, from_snapshot_id, to_snapshot_id)
        except sqlite3.Error as exc:
            raise LabError(f"failed to read diagnostic DB {db_path}: {exc}") from exc
    finally:
        conn.close()

    vanished = list(result.get("vanished", []))
    disposition_counts = Counter(str(row.get("disposition")) for row in vanished)
    content_counts = Counter(str(row.get("content_class")) for row in vanished)
    cross_tab: dict[str, dict[str, int]] = defaultdict(dict)
    for row in vanished:
        content = str(row.get("content_class"))
        disposition = str(row.get("disposition"))
        cross_tab[content][disposition] = cross_tab[content].get(disposition, 0) + 1

    return {
        "db": str(db_path),
        "from_label": from_label,
        "to_label": to_label,
        "cfg_validation": cfg_validation,
        "from_snapshot_id": from_snapshot_id,
        "to_snapshot_id": to_snapshot_id,
        "from_block_count": result.get("from_block_count", 0),
        "to_block_count": result.get("to_block_count", 0),
        "vanished_count": result.get("vanished_count", 0),
        "disposition_counts": dict(sorted(disposition_counts.items())),
        "content_counts": dict(sorted(content_counts.items())),
        "cross_tab": {
            content: dict(sorted(dispositions.items()))
            for content, dispositions in sorted(cross_tab.items())
        },
        "vanished": vanished,
    }


def format_summary_text(summary: dict[str, object], *, limit: int = 10) -> str:
    """Format a summary as compact text."""
    cfg_validation = dict(summary.get("cfg_validation", {}))
    lines = [
        f"DB: {summary['db']}",
        (
            "CFG validation: "
            f"{cfg_validation.get('status', 'not_provided')} "
            f"binary_hash={cfg_validation.get('binary_hash')}"
        ),
        (
            f"Snapshots: {summary['from_snapshot_id']} ({summary['from_label']})"
            f" -> {summary['to_snapshot_id']} ({summary['to_label']})"
        ),
        (
            f"Blocks: {summary['from_block_count']} -> {summary['to_block_count']} "
            f"vanished={summary['vanished_count']}"
        ),
        "",
        "Disposition counts:",
    ]
    for key, value in dict(summary["disposition_counts"]).items():
        lines.append(f"  {key}: {value}")
    lines.extend(["", "Content counts:"])
    for key, value in dict(summary["content_counts"]).items():
        lines.append(f"  {key}: {value}")
    lines.extend(["", "Cross-tab:"])
    for content, dispositions in dict(summary["cross_tab"]).items():
        parts = " ".join(
            f"{name}={count}" for name, count in dict(dispositions).items()
        )
        lines.append(f"  {content}: {parts}")

    vanished = list(summary["vanished"])
    if limit > 0 and vanished:
        lines.extend(["", f"First {min(limit, len(vanished))} vanished blocks:"])
        for row in vanished[:limit]:
            absorber = row.get("absorber")
            absorber_text = "-"
            if isinstance(absorber, dict):
                absorber_text = f"blk[{absorber.get('serial')}]"
            lines.append(
                "  "
                f"blk[{row.get('serial')}] "
                f"{row.get('type_name')} "
                f"preds={row.get('preds')} succs={row.get('succs')} "
                f"content={row.get('content_class')} "
                f"disposition={row.get('disposition')} "
                f"absorber={absorber_text}"
            )
    return "\n".join(lines)


def format_summary_markdown(summary: dict[str, object], *, limit: int = 10) -> str:
    """Format a summary as Markdown."""
    cfg_validation = dict(summary.get("cfg_validation", {}))
    lines = [
        "# Hex-Rays Structuring Lab Summary",
        "",
        f"- DB: `{summary['db']}`",
        f"- CFG validation: `{cfg_validation.get('status', 'not_provided')}`",
        f"- Compiler flags: `{cfg_validation.get('compiler_flags', [])}`",
        f"- Binary hash: `{cfg_validation.get('binary_hash')}`",
        (
            f"- Snapshots: `{summary['from_snapshot_id']}` "
            f"(`{summary['from_label']}`) -> `{summary['to_snapshot_id']}` "
            f"(`{summary['to_label']}`)"
        ),
        (
            f"- Blocks: `{summary['from_block_count']}` -> "
            f"`{summary['to_block_count']}`"
        ),
        f"- Vanished blocks: `{summary['vanished_count']}`",
        "",
        "## Cross-Tab",
        "",
        "| content_class | dispositions |",
        "|-|-|",
    ]
    for content, dispositions in dict(summary["cross_tab"]).items():
        parts = ", ".join(
            f"`{name}`={count}" for name, count in dict(dispositions).items()
        )
        lines.append(f"| `{content}` | {parts} |")

    vanished = list(summary["vanished"])
    if limit > 0 and vanished:
        lines.extend([
            "",
            "## Vanished Blocks",
            "",
            "| block | type | content | disposition | absorber |",
            "|-|-|-|-|-|",
        ])
        for row in vanished[:limit]:
            absorber = row.get("absorber")
            absorber_text = "-"
            if isinstance(absorber, dict):
                absorber_text = f"`blk[{absorber.get('serial')}]`"
            lines.append(
                f"| `blk[{row.get('serial')}]` | `{row.get('type_name')}` | "
                f"`{row.get('content_class')}` | `{row.get('disposition')}` | "
                f"{absorber_text} |"
            )
    return "\n".join(lines)


def _write_or_print(text: str, output: Path | None) -> None:
    if output is None:
        print(text)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text + "\n")


def _cmd_list(args: argparse.Namespace) -> int:
    registry = load_registry(Path(args.registry))
    for case in _cases(registry):
        print(
            f"{case.get('id')}\t{case.get('status')}\t"
            f"{case.get('fixture_kind')}\t{case.get('function')}"
        )
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    registry = load_registry(Path(args.registry))
    case = _case_by_id(registry, args.case_id)
    print(json.dumps(case, indent=2, sort_keys=True))
    return 0


def _cmd_command(args: argparse.Namespace) -> int:
    registry = load_registry(Path(args.registry))
    case = _case_by_id(registry, args.case_id)
    if case.get("status") not in {"compiled_cfg_validated", "observed"} and not args.quiet:
        print(
            f"warning: case '{args.case_id}' status is {case.get('status')}; "
            "run validate-cfg and record a passed result before treating this "
            "as executable evidence",
            file=sys.stderr,
        )
    print(
        render_case_command(
            case,
            output_subdir=args.output_subdir,
            worktree=args.worktree,
        )
    )
    return 0


def _cmd_validate_cfg(args: argparse.Namespace) -> int:
    registry = load_registry(Path(args.registry))
    case = _case_by_id(registry, args.case_id)
    print(
        render_validate_cfg_command(
            case,
            output_subdir=args.output_subdir,
            worktree=args.worktree,
        )
    )
    return 0


def _cmd_summarize(args: argparse.Namespace) -> int:
    summary = build_summary(
        Path(args.db),
        from_label=args.from_label,
        to_label=args.to_label,
        cfg_validation_path=(
            Path(args.cfg_validation) if args.cfg_validation is not None else None
        ),
        require_cfg_validation=args.require_cfg_validation,
    )
    if args.format == "json":
        text = json.dumps(summary, indent=2, sort_keys=True)
    elif args.format == "markdown":
        text = format_summary_markdown(summary, limit=args.limit)
    else:
        text = format_summary_text(summary, limit=args.limit)
    _write_or_print(text, Path(args.output) if args.output else None)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.hexrays_structuring_lab",
        description="Run and summarize Hex-Rays structuring lab cases.",
    )
    parser.add_argument(
        "--registry",
        default=str(REGISTRY_PATH),
        help=f"Registry JSON path (default: {REGISTRY_PATH})",
    )
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="List registered lab cases")
    p_list.set_defaults(func=_cmd_list)

    p_show = sub.add_parser("show", help="Show one registry case as JSON")
    p_show.add_argument("case_id")
    p_show.set_defaults(func=_cmd_show)

    p_command = sub.add_parser(
        "command",
        help="Render the Docker dump command for one case",
    )
    p_command.add_argument("case_id")
    p_command.add_argument(
        "--output-subdir",
        default=DEFAULT_OUTPUT_SUBDIR,
        help="Subdirectory under .tmp for dump output",
    )
    p_command.add_argument(
        "--worktree",
        default=None,
        help="Optional run_system_tests_docker.sh --worktree value",
    )
    p_command.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress planned-fixture warning",
    )
    p_command.set_defaults(func=_cmd_command)

    p_validate = sub.add_parser(
        "validate-cfg",
        help="Render the compiled-CFG validation command for one case",
    )
    p_validate.add_argument("case_id")
    p_validate.add_argument(
        "--output-subdir",
        default=CFG_VALIDATION_OUTPUT_SUBDIR,
        help="Subdirectory under .tmp for validation output",
    )
    p_validate.add_argument(
        "--worktree",
        default=None,
        help="Optional run_system_tests_docker.sh --worktree value",
    )
    p_validate.set_defaults(func=_cmd_validate_cfg)

    p_summary = sub.add_parser(
        "summarize",
        help="Summarize post-apply to post-d810 merge causality for a diag DB",
    )
    p_summary.add_argument("--db", required=True, help="Diagnostic SQLite DB")
    p_summary.add_argument(
        "--from-label",
        default=DEFAULT_FROM_LABEL,
        help=f"FROM snapshot label (default: {DEFAULT_FROM_LABEL})",
    )
    p_summary.add_argument(
        "--to-label",
        default=DEFAULT_TO_LABEL,
        help=f"TO snapshot label (default: {DEFAULT_TO_LABEL})",
    )
    p_summary.add_argument(
        "--format",
        choices=("text", "json", "markdown"),
        default="text",
    )
    p_summary.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Number of vanished block detail rows to include",
    )
    p_summary.add_argument(
        "--cfg-validation",
        default=None,
        help=(
            "Compiled-CFG validation result JSON. Include this when producing "
            "a lab run summary."
        ),
    )
    p_summary.add_argument(
        "--require-cfg-validation",
        action="store_true",
        help="Hard-fail unless --cfg-validation has status=passed.",
    )
    p_summary.add_argument(
        "--output",
        default=None,
        help="Optional output file. Parent directories are created.",
    )
    p_summary.set_defaults(func=_cmd_summarize)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return 1
    try:
        return int(args.func(args))
    except LabError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
