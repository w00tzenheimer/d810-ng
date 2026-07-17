"""Thin native IDA graph rendering for diagnostic graph models."""

from __future__ import annotations

import ida_graph
import ida_kernwin

from d810.core.typing import Callable
from d810.diagnostics.workbench_graph_models import (
    DiagnosticGraph,
    DiagnosticGraphNode,
)


class _ToggleStateAction(ida_kernwin.action_handler_t):
    """One popup action that delegates state expansion to the pure controller."""

    def __init__(self, owner: "IdaDiagnosticGraphView", model_id: str) -> None:
        super().__init__()
        self._owner = owner
        self._model_id = model_id

    def activate(self, context: object) -> int:
        del context
        self._owner.toggle_model_state(self._model_id)
        return 1

    def update(self, context: object) -> int:
        del context
        return ida_kernwin.AST_ENABLE_FOR_WIDGET


class _DiagnosticGraphViewer(ida_graph.GraphViewer):
    """IDA node IDs and callbacks layered over one immutable graph model."""

    TITLE = "d810-ng Diagnostics Graph"

    def __init__(self, owner: "IdaDiagnosticGraphView") -> None:
        super().__init__(self.TITLE, False)
        self._owner = owner
        self._model_to_id: dict[str, int] = {}
        self._id_to_model: dict[int, str] = {}

    def OnRefresh(self) -> bool:
        self.Clear()
        self._model_to_id.clear()
        self._id_to_model.clear()
        self._owner.begin_refresh()

        status_id = self.AddNode(self._owner.status_text())
        self._id_to_model[status_id] = "__status__"
        graph = self._owner.graph
        if graph is None:
            return True

        for node in graph.nodes:
            node_id = self.AddNode(node.label)
            self._model_to_id[node.model_id] = node_id
            self._id_to_model[node_id] = node.model_id
        for edge in graph.edges:
            self.AddEdge(
                self._model_to_id[edge.source_model_id],
                self._model_to_id[edge.target_model_id],
            )
        self._owner.realize_group(self)
        if self._owner.native_group_warning:
            warning_id = self.AddNode(self._owner.native_group_warning)
            self._id_to_model[warning_id] = "__status__"
        return True

    def OnGetText(self, node_id: int) -> str:
        """Return the text stored for the IDA GraphViewer node."""
        return str(self[node_id])

    def OnHint(self, node_id: int) -> tuple[int, str] | None:
        model_id = self._id_to_model.get(int(node_id))
        if model_id is None:
            return None
        return self._owner.hint_for(model_id)

    def OnDblClick(self, node_id: int) -> bool:
        model_id = self._id_to_model.get(int(node_id))
        if model_id is not None:
            self._owner.jump_model_node(model_id)
        return True

    def OnPopup(self, form: object, popup_handle: object) -> None:
        graph_viewer = ida_graph.get_graph_viewer(self.GetWidget())
        node_id = ida_graph.viewer_get_curnode(graph_viewer)
        model_id = self._id_to_model.get(int(node_id))
        if model_id is None or not self._owner.can_toggle_state(model_id):
            return
        label = (
            "Collapse owned blocks"
            if self._owner.is_expanded(model_id)
            else "Expand owned blocks"
        )
        description = ida_kernwin.action_desc_t(
            None,
            label,
            _ToggleStateAction(self._owner, model_id),
            None,
            label,
            -1,
        )
        ida_kernwin.attach_dynamic_action_to_popup(form, popup_handle, description)

    def node_id_for(self, model_id: str) -> int | None:
        return self._model_to_id.get(model_id)


class IdaDiagnosticGraphView:
    """Native implementation of the diagnostics graph view port."""

    def __init__(self) -> None:
        self.graph: DiagnosticGraph | None = None
        self._message: str | None = None
        self._viewer: _DiagnosticGraphViewer | None = None
        self._toggle_state: Callable[[str], None] | None = None
        self._jump_node: Callable[[str], None] | None = None
        self.native_group_warning: str | None = None

    def bind_actions(
        self,
        *,
        toggle_state: Callable[[str], None],
        jump_node: Callable[[str], None],
    ) -> None:
        self._toggle_state = toggle_state
        self._jump_node = jump_node

    def show_or_focus(self) -> None:
        viewer = self._ensure_viewer()
        viewer.Show()
        widget = viewer.GetWidget()
        if widget is not None:
            ida_kernwin.activate_widget(widget, True)

    def render(self, graph: DiagnosticGraph) -> None:
        self.graph = graph
        self._message = None
        self.show_or_focus()
        self._ensure_viewer().Refresh()

    def clear(self, message: str) -> None:
        self.graph = None
        self._message = message
        self.show_or_focus()
        self._ensure_viewer().Refresh()

    def select_node(self, model_id: str) -> bool:
        viewer = self._viewer
        if viewer is None:
            return False
        node_id = viewer.node_id_for(model_id)
        if node_id is None:
            return False
        viewer.Select(node_id)
        self.show_or_focus()
        return True

    def close(self) -> None:
        if self._viewer is not None:
            self._viewer.Close()
        self._viewer = None
        self.graph = None
        self._message = None
        self.native_group_warning = None

    def begin_refresh(self) -> None:
        self.native_group_warning = None

    def status_text(self) -> str:
        if self.graph is None:
            return self._message or "No diagnostic graph"
        lines = [self.graph.status]
        lines.extend(f"Warning: {warning}" for warning in self.graph.warnings)
        if self.native_group_warning:
            lines.append(self.native_group_warning)
        return "\n".join(lines)

    def hint_for(self, model_id: str) -> tuple[int, str] | None:
        if model_id == "__status__":
            return 1, self.status_text()
        node = self._node_for(model_id)
        if node is None:
            return None
        fields = "\n".join(f"{name}: {value}" for name, value in node.hint_fields)
        references = "\n".join(
            f"source: {reference.source_table}#{reference.ordinal} "
            f"(snapshot {reference.snapshot_id})"
            for reference in node.record_refs
        )
        return 1, "\n".join(part for part in (node.label, fields, references) if part)

    def can_toggle_state(self, model_id: str) -> bool:
        node = self._node_for(model_id)
        return node is not None and node.expandable

    def is_expanded(self, model_id: str) -> bool:
        group = None if self.graph is None else self.graph.expanded_group
        return group is not None and group.model_id == f"group:{model_id}"

    def toggle_model_state(self, model_id: str) -> None:
        if self._toggle_state is not None:
            self._toggle_state(model_id)

    def jump_model_node(self, model_id: str) -> None:
        if self._jump_node is not None:
            self._jump_node(model_id)

    def realize_group(self, viewer: _DiagnosticGraphViewer) -> None:
        graph = self.graph
        group = None if graph is None else graph.expanded_group
        if group is None:
            return
        member_ids = [
            viewer.node_id_for(model_id)
            for model_id in group.member_node_ids
        ]
        if any(node_id is None for node_id in member_ids):
            self.native_group_warning = "Native group unavailable: member node missing"
            return
        try:
            handles = viewer.CreateGroups(
                [{"nodes": member_ids, "text": group.label}]
            )
            if not handles:
                self.native_group_warning = "Native group unavailable: IDA rejected group"
                return
            viewer.SetGroupsVisibility(handles, True)
        except Exception as error:
            self.native_group_warning = f"Native group unavailable: {error}"

    def _ensure_viewer(self) -> _DiagnosticGraphViewer:
        if self._viewer is None:
            self._viewer = _DiagnosticGraphViewer(self)
        return self._viewer

    def _node_for(self, model_id: str) -> DiagnosticGraphNode | None:
        graph = self.graph
        if graph is None:
            return None
        return next((node for node in graph.nodes if node.model_id == model_id), None)


__all__ = ["IdaDiagnosticGraphView"]
