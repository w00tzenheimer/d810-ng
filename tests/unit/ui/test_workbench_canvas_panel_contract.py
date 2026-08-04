from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

from d810.ui.workbench_canvas_models import (
    CanvasEdge,
    CanvasMaturity,
    CanvasNode,
    CanvasPort,
    MaturityCanvasProjection,
)


ROOT = Path(__file__).resolve().parents[3]
RENDERER = ROOT / "src" / "d810" / "ui" / "workbench_canvas_renderer.py"
PANEL = ROOT / "src" / "d810" / "ui" / "workbench_canvas_panel.py"


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _method(path: Path, class_name: str, method_name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return item
    raise AssertionError(f"{class_name}.{method_name} not found")


def _method_source(path: Path, class_name: str, method_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    segment = ast.get_source_segment(
        source,
        _method(path, class_name, method_name),
    )
    assert segment is not None
    return segment


def _imports(path: Path) -> set[str]:
    imports: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


def _node(
    node_id: str,
    maturity: CanvasMaturity,
    *,
    inputs: tuple[CanvasPort, ...] = (),
    outputs: tuple[CanvasPort, ...] = (),
) -> CanvasNode:
    return CanvasNode(
        node_id=node_id,
        pass_id=node_id,
        label=node_id,
        maturity=maturity,
        inputs=inputs,
        outputs=outputs,
        state="ready",
        detail="{}",
    )


def test_canvas_modules_are_headless_safe_and_use_only_the_qt_shim() -> None:
    for path in (RENDERER, PANEL):
        source = path.read_text(encoding="utf-8")
        imports = _imports(path)

        assert "d810.qt_shim" in imports
        assert "QT_GRAPHICS_AVAILABLE" in source
        assert "PyQt5" not in source
        assert "PySide6" not in source

    for module_name in (
        "d810.ui.workbench_canvas_renderer",
        "d810.ui.workbench_canvas_panel",
    ):
        sys.modules.pop(module_name, None)
        importlib.import_module(module_name)


def test_canvas_panel_uses_popup_then_preserves_renderer_add_intent() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert "CanvasPassPickerPopup" in source
    assert "_show_add_palette" in source
    assert "renderer.request_add_pass(stage_id, pass_id)" in source
    assert "_show_add_menu" not in source
    assert "palette.dispose()" in source
    assert "IDA_AVAILABLE and QT_GRAPHICS_AVAILABLE" in source


def test_renderer_draws_projection_as_one_vertical_read_only_workspace() -> None:
    source = RENDERER.read_text(encoding="utf-8")
    render_source = _method_source(RENDERER, "MaturityCanvasRenderer", "render")

    assert "QGraphicsScene" in source
    assert "addText" in render_source
    assert "addRect" in render_source
    assert "addEllipse" in render_source
    assert "addLine" in render_source
    assert "stage_y" in render_source
    assert "_layout_projection(projection" in render_source
    assert "layout.stages" in render_source
    assert "layout.edges" in render_source
    assert "adapter" not in render_source
    assert "drag" not in source.lower()
    assert "connect_nodes" not in source


def test_carrier_edges_use_distinct_direction_aware_port_positions() -> None:
    renderer_module = importlib.import_module("d810.ui.workbench_canvas_renderer")
    layout_projection = getattr(renderer_module, "_layout_projection", None)
    assert callable(layout_projection), "renderer must expose its pure layout step"
    early = CanvasMaturity("ir.canonical", "Canonical", 1)
    late = CanvasMaturity("ir.global", "Global", 2)
    fact_in = CanvasPort("fact:value", "value", "fact", "input")
    fact_out = CanvasPort("fact:value", "value", "fact", "output")
    source = _node("source", early, outputs=(fact_out,))
    carrier = _node("carrier", late, inputs=(fact_in,), outputs=(fact_out,))
    target = _node("target", late, inputs=(fact_in,))
    projection = MaturityCanvasProjection(
        maturities=(early, late),
        nodes=(source, carrier, target),
        edges=(
            CanvasEdge("source", "fact:value", "carrier", "fact:value", "fact"),
            CanvasEdge("carrier", "fact:value", "target", "fact:value", "fact"),
        ),
        diagnostics=(),
    )

    layout = layout_projection(projection, ())

    carrier_input = layout.port_positions[("carrier", "fact:value", "input")]
    carrier_output = layout.port_positions[("carrier", "fact:value", "output")]
    assert carrier_input != carrier_output
    incoming, outgoing = layout.edges
    assert incoming.target == carrier_input
    assert outgoing.source == carrier_output


def test_nine_node_stage_expands_to_contain_every_node() -> None:
    renderer_module = importlib.import_module("d810.ui.workbench_canvas_renderer")
    layout_projection = renderer_module._layout_projection
    stage = CanvasMaturity("any", "Any maturity", -1)
    nodes = tuple(_node(f"node-{index}", stage) for index in range(9))
    projection = MaturityCanvasProjection(
        maturities=(stage,),
        nodes=nodes,
        edges=(),
        diagnostics=(),
    )

    layout = layout_projection(projection, ())

    stage_geometry = layout.stages[0]
    assert len(stage_geometry.nodes) == 9
    assert stage_geometry.width > 980.0
    assert all(
        node.x >= stage_geometry.x
        and node.x + node.width <= stage_geometry.x + stage_geometry.width
        for node in stage_geometry.nodes
    )


def test_renderer_binds_only_selection_and_recipe_intents() -> None:
    bind_source = _method_source(
        RENDERER,
        "MaturityCanvasRenderer",
        "bind_actions",
    )

    for intent in ("select_node", "add_pass", "edit_options", "save_recipe"):
        assert intent in bind_source
    for forbidden in ("persist", "idb", "connect_edge", "add_workbench_recipe_pass"):
        assert forbidden not in bind_source


def test_panel_owns_three_panes_manual_collapse_and_compact_add_action() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_source = _method_source(PANEL, "WorkbenchCanvasPanel", "__init__")
    create_source = _method_source(PANEL, "WorkbenchCanvasPanel", "OnCreate")

    assert "QGraphicsScene" in init_source
    assert "QGraphicsView" in init_source
    assert "self._collapsed_stages" in init_source
    assert "Add registered node" in init_source
    assert "evidence_summary" in init_source
    assert "node_inspector" in init_source
    assert "QSplitter" in create_source
    assert "Save for Deobfuscate This" in init_source
    assert "self.evidence_summary" in create_source
    assert "self.canvas_view" in create_source
    assert "self.node_inspector" in create_source
    assert "_toggle_stage" in source
    assert "auto_collapse" not in source


def test_panel_reprojects_after_adapter_owned_add_and_edit_then_reuses_save() -> None:
    source = PANEL.read_text(encoding="utf-8")
    add_source = _method_source(PANEL, "WorkbenchCanvasPanel", "_add_pass")
    edit_source = _method_source(PANEL, "WorkbenchCanvasPanel", "_edit_options")
    save_source = _method_source(PANEL, "WorkbenchCanvasPanel", "_save_recipe")

    assert "canvas_add_candidates" not in source
    assert "project_maturity_canvas" in source
    assert "self._adapter.add_canvas_pass" in add_source
    assert "self._adapter.replace_options" in edit_source
    assert "self._adapter.save_function" in save_source
    assert "self._render_projection" in add_source
    assert "self._render_projection" in edit_source
    for forbidden in (
        "sqlite3",
        "ida_bytes",
        "ida_funcs",
        "open(",
        "set_workbench_function_recipe",
        "FunctionPipelineOverride",
    ):
        assert forbidden not in source


def test_selected_node_inspector_includes_contract_options_prerequisites_and_evidence() -> (
    None
):
    source = _method_source(PANEL, "WorkbenchCanvasPanel", "_select_node")

    assert "Contract" in source
    assert "Options" in source
    assert "Prerequisites" in source
    assert "Evidence references" in source


def test_selected_evidence_node_delegates_opening_without_owning_diagnostics() -> None:
    panel_source = PANEL.read_text(encoding="utf-8")
    init_source = _method_source(PANEL, "WorkbenchCanvasPanel", "__init__")
    select_source = _method_source(PANEL, "WorkbenchCanvasPanel", "_select_node")
    open_source = _method_source(
        PANEL,
        "WorkbenchCanvasPanel",
        "_open_selected_diagnostic",
    )

    assert "open_diagnostic_record" in init_source
    assert "Open linked diagnostic" in init_source
    assert "linked_case_findings" in select_source
    assert "self._selected_finding" in select_source
    assert "self._open_diagnostic_record" in open_source
    assert "finding.finding_id" in open_source
    assert "finding.native_ea" in open_source
    for forbidden in (
        "sqlite3",
        "WorkbenchDiagnosticsPanel",
        "WorkbenchDiagnosticsAdapter",
    ):
        assert forbidden not in panel_source
