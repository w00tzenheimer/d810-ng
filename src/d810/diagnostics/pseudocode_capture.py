from __future__ import annotations

import difflib
import json
import os
import platform
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from d810.core.typing import Any, Callable, Iterable, Mapping, Optional


# Default capture DB location can be overridden via D810_CAPTURE_DB.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CAPTURE_DB_NAME = ".d810_capture.db"
BEFORE_MARKER = "--- BEFORE ---"
AFTER_MARKER = "--- AFTER ---"
STATS_MARKER_PREFIX = "=== STATS:"


@dataclass(frozen=True)
class ParsedPseudocodeDump:
    function_name: str
    function_address: str | None
    code_before: str
    code_after: str
    code_changed: bool
    rules_fired: tuple[str, ...]
    project_config: str | None
    binary_name: str | None


def resolve_capture_db_path(db_arg: str | os.PathLike[str] | None = None) -> Path:
    """
    Resolve the path to the pseudocode_capture SQLite database.

    Resolution order:
    1. Explicit CLI argument (db_arg)
    2. Environment variable D810_CAPTURE_DB
    3. Project root /.d810_capture.db
    """
    if db_arg:
        return Path(db_arg)

    env_path = os.environ.get("D810_CAPTURE_DB")
    if env_path:
        return Path(env_path)

    return _PROJECT_ROOT / DEFAULT_CAPTURE_DB_NAME


def init_capture_db(db_path: Path | str) -> sqlite3.Connection:
    """
    Initialize the pseudocode_capture database and return a connection.

    Schema matches the historic tests/system capture scripts/tests:

        CREATE TABLE IF NOT EXISTS pseudocode_capture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            function_name TEXT NOT NULL,
            function_address TEXT,
            code_before TEXT,
            code_after TEXT,
            code_changed BOOLEAN,
            rules_fired TEXT,
            project_config TEXT,
            binary_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pseudocode_capture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            function_name TEXT NOT NULL,
            function_address TEXT,
            code_before TEXT,
            code_after TEXT,
            code_changed BOOLEAN,
            rules_fired TEXT,
            project_config TEXT,
            binary_name TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_func_name "
        "ON pseudocode_capture(function_name)"
    )
    conn.commit()
    return conn


def get_default_binary_name() -> str:
    """
    Get the default test binary name, respecting D810_TEST_BINARY when set.
    """
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


def get_func_ea(name_or_ea: str) -> int:
    """
    Resolve a function effective address from a name or hex EA string.

    Supports:
    - Named symbols (e.g. "test_xor")
    - macOS underscore-prefixed names ("test_xor" -> "_test_xor")
    - Hex addresses like "0x180012B60" (only if idaapi.get_func confirms)
    """
    import idaapi
    import idc

    if not name_or_ea:
        return idc.get_screen_ea()

    # First try as plain name.
    ea = idc.get_name_ea_simple(name_or_ea)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name_or_ea)

    # Hex EA form for functions without a named export.
    if ea == idaapi.BADADDR and isinstance(name_or_ea, str) and name_or_ea.startswith(
        "0x"
    ):
        try:
            cand = int(name_or_ea, 16)
        except ValueError:
            cand = None
        if cand is not None and idaapi.get_func(cand):
            ea = cand

    return ea


def pseudocode_to_string(pseudocode: Any) -> str:
    """
    Convert IDA Hex-Rays pseudocode to a plain string.

    Accepts a cfunc_t.get_pseudocode() result (vector of citem line objects).
    """
    # Late import to avoid binding IDA modules when not needed.
    import idaapi

    lines: list[str] = []
    for i in range(pseudocode.size()):
        line = pseudocode[i]
        # Use tag_remove to drop color/formatting tags.
        lines.append(idaapi.tag_remove(line.line))
    return "\n".join(lines)


def strip_colors(text: str | None) -> str:
    """
    Remove IDA color tags from pseudocode.
    """
    if not text:
        return ""
    # IDA uses \x01X / \x02X for color tags.
    text = re.sub(r"\x01.", "", text)
    text = re.sub(r"\x02.", "", text)
    return text


def unified_diff(before: str, after: str, func_name: str) -> str:
    """
    Unified diff between before and after pseudocode for a function.
    """
    before_lines = strip_colors(before).splitlines(keepends=True)
    after_lines = strip_colors(after).splitlines(keepends=True)
    diff = difflib.unified_diff(
        before_lines,
        after_lines,
        fromfile=f"{func_name} (OBFUSCATED)",
        tofile=f"{func_name} (DEOBFUSCATED)",
        lineterm="",
    )
    return "".join(diff)


def side_by_side_diff(before: str, after: str, width: int = 60) -> str:
    """
    Produce a simple side-by-side diff view.
    """
    before_lines = strip_colors(before).splitlines()
    after_lines = strip_colors(after).splitlines()

    header = f"{'BEFORE (Obfuscated)':<{width}} | {'AFTER (Deobfuscated)':<{width}}"
    sep = "-" * (width * 2 + 3)
    result: list[str] = [header, sep]

    max_lines = max(len(before_lines), len(after_lines))
    for i in range(max_lines):
        left = before_lines[i] if i < len(before_lines) else ""
        right = after_lines[i] if i < len(after_lines) else ""
        if len(left) > width:
            left = left[: width - 3] + "..."
        if len(right) > width:
            right = right[: width - 3] + "..."
        marker = " " if left.strip() == right.strip() else "*"
        result.append(f"{left:<{width}} {marker} {right:<{width}}")

    return "\n".join(result)


def _is_section_rule(raw: str) -> bool:
    stripped = raw.strip()
    return stripped.startswith("RULES_FIRED")


def _is_separator(raw: str) -> bool:
    stripped = raw.strip()
    return len(stripped) >= 20 and set(stripped) == {"="}


def _extract_section(
    lines: list[str],
    marker: str,
    *,
    stop_at_markers: tuple[str, ...],
) -> str:
    start: int | None = None
    end: int | None = None
    for index, raw in enumerate(lines):
        if raw.strip() == marker:
            start = index + 1
            end = None
            continue
        if start is None:
            continue
        stripped = raw.strip()
        if stripped in stop_at_markers:
            end = index
            break
        if raw.startswith(STATS_MARKER_PREFIX) or _is_separator(raw):
            end = index
            break
    if start is None:
        raise ValueError(f"missing pseudocode section marker: {marker!r}")
    if end is None:
        end = len(lines)
    return "\n".join(lines[start:end]).strip("\n")


def _parse_capture_metadata(lines: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for raw in lines:
        if raw.startswith("FUNCTION:"):
            value = raw.removeprefix("FUNCTION:").strip()
            match = re.match(r"(?P<name>.+?)(?:\s+@\s+(?P<ea>0x[0-9A-Fa-f]+))?$", value)
            if match:
                metadata["function_name"] = match.group("name").strip()
                if match.group("ea"):
                    metadata["function_address"] = match.group("ea")
        elif raw.startswith("BINARY:"):
            metadata["binary_name"] = raw.removeprefix("BINARY:").strip()
        elif raw.startswith("PROJECT:"):
            project = raw.removeprefix("PROJECT:").strip()
            metadata["project_config"] = "" if project == "<none>" else project
        elif raw.startswith("CODE_CHANGED:"):
            metadata["code_changed"] = raw.removeprefix("CODE_CHANGED:").strip()
    return metadata


def _parse_rules_fired(lines: list[str]) -> list[str]:
    rules: list[str] = []
    in_rules = False
    for raw in lines:
        stripped = raw.strip()
        if _is_section_rule(raw):
            in_rules = "<none>" not in raw
            continue
        if not in_rules:
            continue
        if not raw.startswith("  ") or stripped.startswith(("-", "=")):
            in_rules = False
            continue
        if not stripped or stripped == "<none>":
            continue
        rules.append(re.sub(r"\s+\[[^]]+\]$", "", stripped))
    return rules


def _parse_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "changed"}


def parse_capture_dump(
    text: str,
    *,
    function_name: str | None = None,
    project_config: str | None = None,
    binary_name: str | None = None,
) -> ParsedPseudocodeDump:
    """Parse a Docker pseudocode dump into DB-ready capture fields.

    The dump format is produced by
    ``tests/system/e2e/test_dump_function_pseudocode.py`` and contains
    metadata lines followed by ``--- BEFORE ---`` and ``--- AFTER ---``
    pseudocode sections. The parser stays text-only so it can run in normal
    unit tests without IDA or Docker.
    """
    lines = text.splitlines()
    metadata = _parse_capture_metadata(lines)
    code_before = _extract_section(
        lines,
        BEFORE_MARKER,
        stop_at_markers=(AFTER_MARKER,),
    )
    code_after = _extract_section(
        lines,
        AFTER_MARKER,
        stop_at_markers=(BEFORE_MARKER,),
    )
    parsed_function = function_name or metadata.get("function_name")
    if not parsed_function:
        raise ValueError("capture dump has no FUNCTION line and no function override")
    changed_default = code_before != code_after
    return ParsedPseudocodeDump(
        function_name=parsed_function,
        function_address=metadata.get("function_address"),
        code_before=code_before,
        code_after=code_after,
        code_changed=_parse_bool(metadata.get("code_changed"), default=changed_default),
        rules_fired=tuple(_parse_rules_fired(lines)),
        project_config=(
            project_config
            if project_config is not None
            else metadata.get("project_config") or None
        ),
        binary_name=(
            binary_name
            if binary_name is not None
            else metadata.get("binary_name") or None
        ),
    )


def insert_capture_row(
    conn: sqlite3.Connection,
    *,
    function_name: str,
    function_address: str | None,
    code_before: str,
    code_after: str,
    code_changed: bool | None = None,
    rules_fired: Iterable[str] = (),
    project_config: str | None,
    binary_name: str | None,
) -> Mapping[str, Any]:
    """Insert one parsed before/after pseudocode capture row."""
    rules_fired_list = list(rules_fired)
    changed = code_before != code_after if code_changed is None else code_changed
    conn.execute(
        """
        INSERT INTO pseudocode_capture
        (function_name, function_address, code_before, code_after, code_changed,
         rules_fired, project_config, binary_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            function_name,
            function_address,
            code_before,
            code_after,
            changed,
            json.dumps(rules_fired_list),
            project_config,
            binary_name,
        ),
    )
    conn.commit()
    return {
        "function_name": function_name,
        "function_address": function_address,
        "code_before": code_before,
        "code_after": code_after,
        "code_changed": changed,
        "rules_fired": rules_fired_list,
        "project_config": project_config,
        "binary_name": binary_name,
    }


def capture_dump_text_to_db(
    conn: sqlite3.Connection,
    text: str,
    *,
    function_name: str | None = None,
    project_config: str | None = None,
    binary_name: str | None = None,
) -> Mapping[str, Any]:
    """Parse dump text and insert its pseudocode capture into ``conn``."""
    parsed = parse_capture_dump(
        text,
        function_name=function_name,
        project_config=project_config,
        binary_name=binary_name,
    )
    return insert_capture_row(
        conn,
        function_name=parsed.function_name,
        function_address=parsed.function_address,
        code_before=parsed.code_before,
        code_after=parsed.code_after,
        code_changed=parsed.code_changed,
        rules_fired=parsed.rules_fired,
        project_config=parsed.project_config,
        binary_name=parsed.binary_name,
    )


def capture_dump_file_to_db(
    *,
    dump_path: Path | str,
    db_path: Path | str,
    function_name: str | None = None,
    project_config: str | None = None,
    binary_name: str | None = None,
) -> Mapping[str, Any]:
    """Parse a dump file and append one row to the capture DB."""
    dump = Path(dump_path)
    conn = init_capture_db(db_path)
    try:
        row = capture_dump_text_to_db(
            conn,
            dump.read_text(errors="replace"),
            function_name=function_name,
            project_config=project_config,
            binary_name=binary_name,
        )
    finally:
        conn.close()
    return {**row, "db_path": str(db_path), "dump_path": str(dump)}


def render_capture_summary(row: Mapping[str, Any]) -> str:
    """Render a concise human summary for a captured pseudocode row."""
    rules = row.get("rules_fired") or []
    if isinstance(rules, str):
        try:
            rules = json.loads(rules)
        except json.JSONDecodeError:
            rules = [rules]
    rule_text = ", ".join(str(rule) for rule in rules) if rules else "<none>"
    return "\n".join(
        [
            f"FUNCTION={row.get('function_name')}",
            f"PROJECT={row.get('project_config') or '<none>'}",
            f"BINARY={row.get('binary_name') or '<unknown>'}",
            f"CODE_CHANGED={bool(row.get('code_changed'))}",
            f"RULES_FIRED={rule_text}",
        ]
    )


def capture_one_function(
    *,
    state: Any,
    func_name: str,
    func_ea: int,
    project_config: str | None,
    conn: sqlite3.Connection,
    binary_name: str,
    pseudo_to_str: Optional[Callable[[Any], str]] = None,
) -> Mapping[str, Any]:
    """
    Capture before/after pseudocode for a single function and write to DB.

    This helper assumes:
    - The binary is already open in IDA.
    - Any desired project configuration has been loaded on `state` by the caller.
    - `state` exposes stop_d810(), start_d810(), and a stats object with:
        - reset()
        - get_fired_rule_names()
    """
    import idaapi

    if func_ea == idaapi.BADADDR:
        raise ValueError(f"Function '{func_name}' not found")

    if pseudo_to_str is None:
        pseudo_to_str = pseudocode_to_string

    # Baseline (no D810).
    state.stop_d810()
    cfunc_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    if cfunc_before is None:
        raise RuntimeError(f"Decompilation failed for '{func_name}' without D810")
    code_before = pseudo_to_str(cfunc_before.get_pseudocode())

    # With D810 enabled.
    state.stats.reset()
    state.start_d810()
    cfunc_after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    if cfunc_after is None:
        raise RuntimeError(f"Decompilation failed for '{func_name}' with D810")
    code_after = pseudo_to_str(cfunc_after.get_pseudocode())

    rules_fired: Iterable[str] = getattr(
        state.stats, "get_fired_rule_names", lambda: []
    )()
    rules_fired_list = list(rules_fired)
    changed = code_before != code_after

    conn.execute(
        """
        INSERT INTO pseudocode_capture
        (function_name, function_address, code_before, code_after, code_changed,
         rules_fired, project_config, binary_name)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            func_name,
            hex(func_ea),
            code_before,
            code_after,
            changed,
            json.dumps(rules_fired_list),
            project_config,
            binary_name,
        ),
    )
    conn.commit()

    return {
        "function_name": func_name,
        "function_address": hex(func_ea),
        "code_before": code_before,
        "code_after": code_after,
        "code_changed": changed,
        "rules_fired": rules_fired_list,
        "project_config": project_config,
        "binary_name": binary_name,
    }


# Shared function/test metadata -------------------------------------------------

# Overlapping test functions used by capture scripts and CLI.
_DEFAULT_PROJECT = "example_libobfuscated.json"

OVERLAPPING_FUNCTIONS: list[tuple[str, Optional[str]]] = [
    ("test_chained_add", _DEFAULT_PROJECT),
    ("test_cst_simplification", _DEFAULT_PROJECT),
    ("test_opaque_predicate", _DEFAULT_PROJECT),
    ("test_xor", _DEFAULT_PROJECT),
    ("test_or", _DEFAULT_PROJECT),
    ("test_and", _DEFAULT_PROJECT),
    ("test_neg", None),
    ("tigress_minmaxarray", _DEFAULT_PROJECT),
    ("unwrap_loops", _DEFAULT_PROJECT),
    ("unwrap_loops_2", _DEFAULT_PROJECT),
    ("unwrap_loops_3", _DEFAULT_PROJECT),
    ("while_switch_flattened", _DEFAULT_PROJECT),
    ("test_function_ollvm_fla_bcf_sub", _DEFAULT_PROJECT),
]


# Mapping from function name to DSL test classes, used by summary/diff views.
FUNCTION_TO_DSL_TESTS: dict[str, list[str]] = {
    "test_chained_add": [
        "TestMBASimplification",
    ],
    "test_cst_simplification": [
        "TestMBASimplification",
    ],
    "test_opaque_predicate": [
        "TestMBASimplification",
    ],
    "test_xor": [
        "TestMBASimplification",
    ],
    "test_or": [
        "TestMBASimplification",
    ],
    "test_and": [
        "TestMBASimplification",
    ],
    "test_neg": [
        "TestMBASimplification",
    ],
    "tigress_minmaxarray": [
        "TestTigressPatterns",
    ],
    "unwrap_loops": [
        "TestLoopPatterns",
    ],
    "unwrap_loops_2": [
        "TestLoopPatterns",
    ],
    "unwrap_loops_3": [
        "TestLoopPatterns",
    ],
    "while_switch_flattened": [
        "TestLoopPatterns",
    ],
    "test_function_ollvm_fla_bcf_sub": [
        "TestOLLVMPatterns",
    ],
}


__all__ = [
    "AFTER_MARKER",
    "BEFORE_MARKER",
    "DEFAULT_CAPTURE_DB_NAME",
    "FUNCTION_TO_DSL_TESTS",
    "OVERLAPPING_FUNCTIONS",
    "ParsedPseudocodeDump",
    "STATS_MARKER_PREFIX",
    "capture_dump_file_to_db",
    "capture_dump_text_to_db",
    "capture_one_function",
    "get_default_binary_name",
    "get_func_ea",
    "init_capture_db",
    "insert_capture_row",
    "parse_capture_dump",
    "pseudocode_to_string",
    "render_capture_summary",
    "resolve_capture_db_path",
    "side_by_side_diff",
    "strip_colors",
    "unified_diff",
]
