from __future__ import annotations

from d810.hexrays.utils.pseudocode_render import _format_memory_expr


def test_format_memory_expr_elides_default_ds_segment() -> None:
    assert _format_memory_expr("ds", "v210") == "*v210"
    assert _format_memory_expr("", "v210") == "*v210"
    assert _format_memory_expr("", "v102 + a3") == "*(v102 + a3)"


def test_format_memory_expr_preserves_nondefault_segments() -> None:
    assert _format_memory_expr("fs", "v210") == "*(fs:v210)"
