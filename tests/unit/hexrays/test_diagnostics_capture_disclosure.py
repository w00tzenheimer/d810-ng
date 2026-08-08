from __future__ import annotations

import ast
from pathlib import Path


HOOKS = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "d810"
    / "hexrays"
    / "hooks"
    / "hexrays_hooks.py"
)


def test_prolog_discloses_enabled_diagnostics_capture_before_opening_session() -> None:
    tree = ast.parse(HOOKS.read_text(encoding="utf-8"), filename=str(HOOKS))
    prolog = next(
        item
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "HexraysDecompilationHook"
        for item in node.body
        if isinstance(item, ast.FunctionDef) and item.name == "prolog"
    )
    source = ast.get_source_segment(HOOKS.read_text(encoding="utf-8"), prolog)
    assert source is not None

    assert "get_settings().diag_snapshots" in source
    assert "D810 diagnostics capture is on for this decompilation." in source
    assert source.index("D810 diagnostics capture is on") < source.index(
        "open_observability_session(diagnostic_owner_ea)"
    )


def test_prolog_traces_the_decompilation_requester() -> None:
    """``prolog`` must record who asked, next to the line that announces it.

    ``hxe_prolog`` fires once per microcode-generation pass, so this is the
    one place that can distinguish "IDA decompiled this function twice" from
    "d810 re-entered its own retry loop". The trace is opt-in, so the call
    sits directly after the announcement and is gated inside the helper.
    """
    text = HOOKS.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(HOOKS))
    prolog = next(
        item
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "HexraysDecompilationHook"
        for item in node.body
        if isinstance(item, ast.FunctionDef) and item.name == "prolog"
    )
    source = ast.get_source_segment(text, prolog)
    assert source is not None
    assert "_log_decompile_requester(function_ea)" in source
    assert source.index("Starting decompilation of function") < source.index(
        "_log_decompile_requester(function_ea)"
    )


def test_decompile_requester_trace_is_opt_in_and_cannot_fail_decompilation() -> None:
    """The helper must be gated on the setting and must swallow everything.

    A diagnostic that can raise inside an IDA callback turns an observability
    question into a decompilation failure.
    """
    text = HOOKS.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(HOOKS))
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_log_decompile_requester"
    )
    source = ast.get_source_segment(text, helper)
    assert source is not None

    # Gated: returns early unless the opt-in setting is on.
    assert "get_settings().trace_decompile_callers" in source
    assert "return" in source.split("get_settings().trace_decompile_callers")[1][:120]

    # Total: every statement that can raise sits under a bare ``except``.
    handlers = [n for n in ast.walk(helper) if isinstance(n, ast.ExceptHandler)]
    assert handlers, "requester trace must not propagate out of an IDA callback"
    assert any(h.type is None or getattr(h.type, "id", "") == "Exception" for h in handlers)
