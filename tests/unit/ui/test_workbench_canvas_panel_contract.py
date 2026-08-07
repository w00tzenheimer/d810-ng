from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

from d810.ui.workbench_canvas_models import (
    CanvasEdge,
    CanvasMaturity,
    CanvasNode,
    CanvasPort,
    CanvasSubgraph,
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


def test_reset_canvas_view_origin_returns_both_scrollbars_to_the_scene_start() -> None:
    """A wider canvas must open at its first stage, not the viewport center."""

    panel = importlib.import_module("d810.ui.workbench_canvas_panel")
    reset_origin = getattr(panel, "reset_canvas_view_origin", None)

    class _ScrollBar:
        def __init__(self, minimum: int, value: int) -> None:
            self._minimum = minimum
            self.value = value

        def minimum(self) -> int:
            return self._minimum

        def setValue(self, value: int) -> None:
            self.value = value

    class _View:
        def __init__(self) -> None:
            self.horizontal = _ScrollBar(-4, 277)
            self.vertical = _ScrollBar(-1, 83)

        def horizontalScrollBar(self) -> _ScrollBar:
            return self.horizontal

        def verticalScrollBar(self) -> _ScrollBar:
            return self.vertical

    view = _View()

    assert callable(reset_origin)
    reset_origin(view)

    assert view.horizontal.value == -4
    assert view.vertical.value == -1


def test_single_any_maturity_stage_is_presented_as_an_explanatory_static_state() -> None:
    panel = importlib.import_module("d810.ui.workbench_canvas_panel")
    presentation = getattr(panel, "stage_selector_presentation", None)
    stage = CanvasMaturity("any", "Any maturity", -1)

    assert callable(presentation)
    label, tooltip, has_choices = presentation((stage,), stage.stage_id)

    assert label == "Any maturity - all active passes"
    assert tooltip == "All active recipe nodes support Any maturity."
    assert has_choices is False


def test_receipted_evidence_nodes_have_a_distinct_canvas_state_color() -> None:
    renderer = importlib.import_module("d810.ui.workbench_canvas_renderer")

    node_fill = getattr(renderer, "_node_fill", None)
    assert callable(node_fill)
    assert node_fill("evidence_produced") != node_fill("ready")
    assert node_fill("evidence_produced") != node_fill("blocked")


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

    assert "ReadOnlyDataflowScene" in source
    assert "ReadOnlyCanvasNodeItem" in source
    assert "ReadOnlyCanvasConnectionItem" in source
    assert "addText" in render_source
    assert "addRect" in render_source
    assert "addEllipse" not in render_source
    assert "addLine" not in render_source
    assert "stage_y" in render_source
    assert "_layout_projection(projection" in render_source
    assert "layout.stages" in render_source
    assert "layout.edges" in render_source
    assert "projection.subgraphs" in source
    assert "subgraph.label" in render_source
    assert "stage_geometry.subgraphs" in render_source
    assert "adapter" not in render_source
    assert "drag" not in source.lower()
    assert "connect_nodes" not in source


def test_renderer_places_self_painting_node_items_at_their_scene_geometry() -> (
    None
):
    render_source = _method_source(RENDERER, "MaturityCanvasRenderer", "render")

    assert "item = ReadOnlyCanvasNodeItem(" in render_source
    assert "item.setPos(node_geometry.x, node_geometry.y)" in render_source
    assert "self.scene.addItem(item)" in render_source
    assert "label.setParentItem(item)" not in render_source


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
    assert len({node.y for node in stage_geometry.nodes}) == 3
    assert stage_geometry.height > 300.0
    assert all(
        node.x >= stage_geometry.x
        and node.x + node.width <= stage_geometry.x + stage_geometry.width
        for node in stage_geometry.nodes
    )


def test_stage_layout_wraps_dense_cards_without_losing_declared_order() -> None:
    renderer_module = importlib.import_module("d810.ui.workbench_canvas_renderer")
    stage = CanvasMaturity("any", "Any maturity", -1)
    nodes = tuple(_node(f"node-{index}", stage) for index in range(7))
    projection = MaturityCanvasProjection(
        maturities=(stage,),
        nodes=nodes,
        edges=(),
        diagnostics=(),
    )

    layout = renderer_module._layout_projection(projection, ())
    geometries = layout.stages[0].nodes

    assert [geometry.node.node_id for geometry in geometries] == [
        f"node-{index}" for index in range(7)
    ]
    assert len({geometry.y for geometry in geometries}) == 2
    assert all(
        geometry.x >= layout.stages[0].x
        and geometry.x + geometry.width <= layout.stages[0].x + layout.stages[0].width
        for geometry in geometries
    )


def test_projection_defaults_keep_existing_direct_canvas_fixtures_compatible() -> None:
    stage = CanvasMaturity("any", "Any maturity", -1)
    projection = MaturityCanvasProjection(
        maturities=(stage,),
        nodes=(_node("node", stage),),
        edges=(),
        diagnostics=(),
    )

    assert projection.subgraphs == ()
    assert projection.nodes[0].workflow_stage_id == ""
    assert projection.nodes[0].workflow_stage_label == ""


def test_renderer_lays_out_projected_strategy_subgraphs_in_declared_order() -> None:
    renderer_module = importlib.import_module("d810.ui.workbench_canvas_renderer")
    stage = CanvasMaturity("ir.local.optimized", "Local", 1)
    analysis = _node("analysis", stage)
    transform = _node("transform", stage)
    projection = MaturityCanvasProjection(
        maturities=(stage,),
        nodes=(analysis, transform),
        edges=(),
        diagnostics=(),
        subgraphs=(
            CanvasSubgraph(
                "ir.local.optimized:canonical_analysis",
                "ir.local.optimized",
                "canonical_analysis",
                "Canonical analysis",
                ("analysis",),
            ),
            CanvasSubgraph(
                "ir.local.optimized:canonical_transform",
                "ir.local.optimized",
                "canonical_transform",
                "Canonical transform",
                ("transform",),
            ),
        ),
    )

    layout = renderer_module._layout_projection(projection, ())
    subgraphs = layout.stages[0].subgraphs

    assert [group.subgraph.label for group in subgraphs] == [
        "Canonical analysis",
        "Canonical transform",
    ]
    assert subgraphs[0].nodes[0].node.node_id == "analysis"
    assert subgraphs[1].nodes[0].node.node_id == "transform"
    assert subgraphs[0].y < subgraphs[1].y


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

    assert "ReadOnlyDataflowScene" in init_source
    assert "ReadOnlyDataflowView" in init_source
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


def test_panel_uses_a_native_maturity_menu_and_top_left_canvas_alignment() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_source = _method_source(PANEL, "WorkbenchCanvasPanel", "__init__")
    create_source = _method_source(PANEL, "WorkbenchCanvasPanel", "OnCreate")

    assert "QtWidgets.QMenu" in init_source
    assert "QComboBox" not in source
    assert "setMenu" in init_source
    assert "setPopupMode" in init_source
    assert "_select_stage" in source
    assert "setAlignment" in create_source
    assert "AlignLeft" in source
    assert "AlignTop" in source


def test_panel_uses_dataflow_navigation_without_resetting_each_projection() -> None:
    source = PANEL.read_text(encoding="utf-8")
    init_source = _method_source(PANEL, "WorkbenchCanvasPanel", "__init__")
    create_source = _method_source(PANEL, "WorkbenchCanvasPanel", "OnCreate")
    render_source = _method_source(PANEL, "WorkbenchCanvasPanel", "_render_projection")

    assert "ReadOnlyDataflowScene" in source
    assert "ReadOnlyDataflowView" in source
    assert '"Fit workspace"' in init_source
    assert '"100%"' in init_source
    assert "fit_workspace_button" in create_source
    assert "reset_zoom_button" in create_source
    assert "reset_canvas_view_origin(self.canvas_view)" not in render_source


def test_canvas_controls_are_owned_by_side_rails_not_a_top_toolbar() -> None:
    create_source = _method_source(PANEL, "WorkbenchCanvasPanel", "OnCreate")

    assert "navigation_controls = QtWidgets.QVBoxLayout()" in create_source
    assert "navigation_controls.addWidget(self.stage_selector)" in create_source
    assert "navigation_controls.addWidget(self.add_registered_node_button)" in create_source
    assert "inspector_controls = QtWidgets.QHBoxLayout()" in create_source
    assert "inspector_controls.addWidget(self.edit_options_button)" in create_source
    assert "inspector_controls.addWidget(self.open_diagnostic_button)" in create_source
    assert "inspector_layout.addWidget(self.save_recipe_button)" in create_source
    assert "layout.addLayout(controls)" not in create_source


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


def test_selected_node_inspector_is_structured_with_read_only_contract_opt_in() -> None:
    source = _method_source(PANEL, "WorkbenchCanvasPanel", "_select_node")
    panel_source = PANEL.read_text(encoding="utf-8")

    assert "build_node_sections" in source
    assert "self.node_inspector.show_node" in source
    assert "View pass contract" in panel_source
    assert "node.detail" in source


def test_generic_pipeline_evidence_summary_makes_absent_case_evidence_explicit() -> None:
    panel = importlib.import_module("d810.ui.workbench_canvas_panel")
    summary_lines = getattr(panel, "evidence_summary_lines", None)

    assert callable(summary_lines)
    lines = summary_lines(SimpleNamespace(case=None), ())

    assert "Generic cleanup pipeline" in "\n".join(lines)
    assert "No protection-specific case evidence captured yet." in lines


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
