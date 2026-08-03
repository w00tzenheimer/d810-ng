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
