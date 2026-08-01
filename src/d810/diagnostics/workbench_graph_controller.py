"""Pure action logic for the Diagnostics Explorer native graph companion."""

from __future__ import annotations

from d810.core.deobfuscation_case import DeobfuscationCaseEvidence
from d810.core.logging import getLogger
from d810.core.typing import Callable, Protocol
from d810.diagnostics.workbench_graph_models import (
    DiagnosticGraph,
    DiagnosticGraphContext,
    DiagnosticGraphKind,
    DiagnosticGraphProjectionRequest,
    node_ids_for_record,
    record_ref,
)
from d810.diagnostics.workbench_graph_projection import project_diagnostic_graph
from d810.diagnostics.workbench_models import DiagnosticRecord


logger = getLogger("D810.diagnostics.graph")


class DiagnosticGraphRecordPort(Protocol):
    """Allowlisted read interface supplied by the existing diagnostics adapter."""

    def records(
        self,
        path: str,
        snapshot_id: int,
        kind: str,
    ) -> tuple[DiagnosticRecord, ...]: ...

    def case(
        self,
        path: str,
        function_ea: int,
    ) -> DeobfuscationCaseEvidence | None: ...


class DiagnosticGraphNavigationPort(Protocol):
    """IDA navigation interface supplied by the existing diagnostics adapter."""

    def navigate(self, ea: int) -> None: ...


class DiagnosticGraphViewPort(Protocol):
    """UI adapter surface used by pure controller actions."""

    def bind_actions(
        self,
        *,
        toggle_state: Callable[[str], None],
        jump_node: Callable[[str], None],
    ) -> None: ...

    def show_or_focus(self) -> None: ...

    def render(self, graph: DiagnosticGraph) -> None: ...

    def clear(self, message: str) -> None: ...

    def select_node(self, model_id: str) -> bool: ...

    def close(self) -> None: ...


class DiagnosticGraphController:
    """Coordinate graph evidence context without interpreting UI widgets."""

    def __init__(
        self,
        records: DiagnosticGraphRecordPort,
        navigation: DiagnosticGraphNavigationPort,
        view: DiagnosticGraphViewPort,
    ) -> None:
        self._records = records
        self._navigation = navigation
        self._view = view
        self._active = False
        self._context: DiagnosticGraphContext | None = None
        self._graph: DiagnosticGraph | None = None
        self._expanded_state_model_id: str | None = None
        self._view.bind_actions(
            toggle_state=self.toggle_state,
            jump_node=self.jump_node,
        )

    @staticmethod
    def context_for_explorer(
        *,
        database_path: str,
        snapshot_id: int,
        function_ea: int,
        function_name: str | None,
        view_value: str,
    ) -> DiagnosticGraphContext | None:
        """Translate the two supported Explorer values into a typed context."""

        kinds = {
            "blocks": DiagnosticGraphKind.BLOCK_CFG,
            "state_machine": DiagnosticGraphKind.STATE_MACHINE,
            "case": DiagnosticGraphKind.CASE_LINEAGE,
        }
        kind = kinds.get(view_value)
        if kind is None:
            return None
        return DiagnosticGraphContext(
            database_path=database_path,
            snapshot_id=int(snapshot_id),
            function_ea=int(function_ea),
            function_name=function_name,
            kind=kind,
        )

    def open(self, context: DiagnosticGraphContext) -> None:
        """Open or focus the reusable graph view and render this context."""

        self._reset_expansion_if_context_changed(context)
        self._active = True
        self._context = context
        self._view.show_or_focus()
        self._rebuild(context)

    def update_context(self, context: DiagnosticGraphContext) -> None:
        """Refresh the open graph only after Explorer evidence context changes."""

        if not self._active:
            return
        self._reset_expansion_if_context_changed(context)
        self._context = context
        self._rebuild(context)

    def clear_for_unsupported_view(self) -> None:
        """Clear stale topology when Explorer leaves the supported graph views."""

        self._context = None
        self._graph = None
        self._expanded_state_model_id = None
        if self._active:
            self._view.clear("No graph for this view")

    def select_record(self, record: DiagnosticRecord | None) -> bool:
        """Center the first graph node sourced from an Explorer record."""

        if record is None or self._graph is None:
            return False
        node_ids = node_ids_for_record(self._graph, record_ref(record))
        return bool(node_ids) and self._view.select_node(node_ids[0])

    def toggle_state(self, state_model_id: str) -> None:
        """Expand or collapse the one selected state in the current graph."""

        context = self._context
        graph = self._graph
        if (
            context is None
            or graph is None
            or context.kind is not DiagnosticGraphKind.STATE_MACHINE
        ):
            return
        node = next(
            (item for item in graph.nodes if item.model_id == state_model_id),
            None,
        )
        if node is None or not node.expandable:
            return
        self._expanded_state_model_id = (
            None
            if state_model_id == self._expanded_state_model_id
            else state_model_id
        )
        self._rebuild(context)

    def jump_node(self, model_id: str) -> None:
        """Navigate only when the current model node provides an EA anchor."""

        graph = self._graph
        if graph is None:
            return
        node = next((item for item in graph.nodes if item.model_id == model_id), None)
        if node is not None and node.anchor_ea is not None:
            self._navigation.navigate(node.anchor_ea)

    def close(self) -> None:
        """Close the companion view and discard graph-local context."""

        self._active = False
        self._context = None
        self._graph = None
        self._expanded_state_model_id = None
        self._view.close()

    def _reset_expansion_if_context_changed(
        self, context: DiagnosticGraphContext
    ) -> None:
        previous = self._context
        if previous is None:
            return
        if (
            previous.database_path,
            previous.snapshot_id,
            previous.function_ea,
            previous.kind,
        ) != (
            context.database_path,
            context.snapshot_id,
            context.function_ea,
            context.kind,
        ):
            self._expanded_state_model_id = None

    def _request_for_context(
        self, context: DiagnosticGraphContext
    ) -> DiagnosticGraphProjectionRequest:
        if context.kind is DiagnosticGraphKind.BLOCK_CFG:
            return DiagnosticGraphProjectionRequest(
                context=context,
                primary_records=self._records.records(
                    context.database_path,
                    context.snapshot_id,
                    "blocks",
                ),
                expanded_state_model_id=self._expanded_state_model_id,
            )
        if context.kind is DiagnosticGraphKind.STATE_MACHINE:
            return DiagnosticGraphProjectionRequest(
                context=context,
                primary_records=self._records.records(
                    context.database_path,
                    context.snapshot_id,
                    "state_machine",
                ),
                block_records=self._records.records(
                    context.database_path,
                    context.snapshot_id,
                    "blocks",
                ),
                expanded_state_model_id=self._expanded_state_model_id,
            )
        if context.kind is DiagnosticGraphKind.CASE_LINEAGE:
            return DiagnosticGraphProjectionRequest(
                context=context,
                primary_records=(),
                expanded_state_model_id=self._expanded_state_model_id,
                case_evidence=self._records.case(
                    context.database_path,
                    context.function_ea,
                ),
            )
        raise ValueError("No graph for this view")

    def _rebuild(self, context: DiagnosticGraphContext) -> None:
        try:
            graph = project_diagnostic_graph(self._request_for_context(context))
        except Exception as error:
            self._graph = None
            self._view.clear(f"Graph unavailable: {error}")
            logger.warning(
                "Diagnostic graph unavailable kind=%s database=%s snapshot=%s "
                "function=0x%X: %s",
                context.kind.value,
                context.database_path,
                context.snapshot_id,
                context.function_ea,
                error,
            )
            return
        self._graph = graph
        self._view.render(graph)


__all__ = [
    "DiagnosticGraphController",
    "DiagnosticGraphNavigationPort",
    "DiagnosticGraphRecordPort",
    "DiagnosticGraphViewPort",
]
