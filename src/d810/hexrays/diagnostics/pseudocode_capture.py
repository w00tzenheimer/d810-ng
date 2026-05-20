"""Live IDA/Hex-Rays pseudocode capture helpers."""
from __future__ import annotations

import json
import sqlite3

from d810.core.typing import Any, Callable, Iterable, Mapping, Optional


def _insert_capture_row(
    conn: sqlite3.Connection,
    *,
    function_name: str,
    function_address: str | None,
    code_before: str,
    code_after: str,
    code_changed: bool,
    rules_fired: Iterable[str] = (),
    project_config: str | None,
    binary_name: str | None,
) -> Mapping[str, Any]:
    rules_fired_list = list(rules_fired)
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
            code_changed,
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
        "code_changed": code_changed,
        "rules_fired": rules_fired_list,
        "project_config": project_config,
        "binary_name": binary_name,
    }


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

    ea = idc.get_name_ea_simple(name_or_ea)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name_or_ea)

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
    import idaapi

    lines: list[str] = []
    for i in range(pseudocode.size()):
        line = pseudocode[i]
        lines.append(idaapi.tag_remove(line.line))
    return "\n".join(lines)


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

    state.stop_d810()
    cfunc_before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    if cfunc_before is None:
        raise RuntimeError(f"Decompilation failed for '{func_name}' without D810")
    code_before = pseudo_to_str(cfunc_before.get_pseudocode())

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

    return _insert_capture_row(
        conn,
        function_name=func_name,
        function_address=hex(func_ea),
        code_before=code_before,
        code_after=code_after,
        code_changed=code_before != code_after,
        rules_fired=rules_fired_list,
        project_config=project_config,
        binary_name=binary_name,
    )


__all__ = [
    "capture_one_function",
    "get_func_ea",
    "pseudocode_to_string",
]
