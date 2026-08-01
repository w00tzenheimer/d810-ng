"""IDA-specific assembly for the Diagnostics Explorer graph companion."""

from __future__ import annotations

from d810.diagnostics.workbench_graph_controller import DiagnosticGraphController
from d810.ui.workbench_diagnostic_graph import IdaDiagnosticGraphView


def create_ida_diagnostic_graph_controller(
    adapter: object,
) -> DiagnosticGraphController:
    """Bind the existing diagnostics adapter to its native graph renderer."""
    graph_view = IdaDiagnosticGraphView()
    return DiagnosticGraphController(adapter, adapter, graph_view)  # type: ignore[arg-type]


__all__ = ["create_ida_diagnostic_graph_controller"]
