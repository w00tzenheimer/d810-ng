"""Portable BadWhileLoop dependency-diagnostics metadata (no live backend).

The *building* of a diagnostic (``build_bad_while_loop_dependency_diagnostic``) reads a live
Hex-Rays ``mba`` / definition-rescue backend and therefore lives in
``d810.backends.hexrays.evidence.bad_while_loop_dependency_diagnostics``. The pieces here are pure
data: the metadata key, the JSON-shaped diagnostic alias, and the serialize/extract helpers that
move those dicts on and off a portable ``FlowGraph``'s ``metadata``. Splitting them out lets
``d810.passes`` / ``d810.transforms`` consume the metadata WITHOUT transitively importing
``ida_hexrays`` (ticket llr-1330 follow-up: a portable ``passes`` module must import cleanly with no
IDA present).
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from d810.core.typing import Any

BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY = (
    "bad_while_loop_dependency_diagnostics"
)

BadWhileLoopDependencyDiagnostic = dict[str, object]


def _json_sanitize(value: object) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_sanitize(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_sanitize(item) for item in value]
    return repr(value)


def serialize_bad_while_loop_dependency_diagnostics(
    diagnostics: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Return JSON-friendly diagnostic metadata rows."""
    return [
        _json_sanitize(dict(row))
        for row in diagnostics
        if isinstance(row, Mapping)
    ]


def extract_bad_while_loop_dependency_diagnostics(
    flow_graph: object | None,
) -> tuple[BadWhileLoopDependencyDiagnostic, ...]:
    """Read BadWhileLoop dependency diagnostics from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    metadata = getattr(flow_graph, "metadata", None)
    if not isinstance(metadata, Mapping):
        return ()
    raw = metadata.get(BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    return tuple(
        _json_sanitize(dict(row))
        for row in raw
        if isinstance(row, Mapping)
    )


__all__ = [
    "BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY",
    "BadWhileLoopDependencyDiagnostic",
    "extract_bad_while_loop_dependency_diagnostics",
    "serialize_bad_while_loop_dependency_diagnostics",
]
