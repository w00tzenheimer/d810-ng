"""Qt-free behavior tests for the native maturity dataflow canvas."""

from __future__ import annotations

from d810.ui.workbench_canvas_models import CanvasMaturity, CanvasNode, CanvasPort


def _node(
    node_id: str,
    *,
    inputs: tuple[CanvasPort, ...] = (),
    outputs: tuple[CanvasPort, ...] = (),
) -> CanvasNode:
    return CanvasNode(
        node_id=node_id,
        pass_id="constant-simplification",
        label="Simplify constants",
        maturity=CanvasMaturity("any", "Any maturity", -1),
        inputs=inputs,
        outputs=outputs,
        state="ready",
        detail='{"contract": "intentionally hidden"}',
    )


def test_node_card_lines_are_dense_and_never_raw_contract_json() -> None:
    from d810.ui.workbench_canvas_graphics_logic import node_card_lines

    fact_input = CanvasPort("fact:input", "input", "fact", "input")
    fact_output = CanvasPort("fact:output", "output", "fact", "output")

    lines = node_card_lines(_node("simplify", inputs=(fact_input,), outputs=(fact_output,)))

    assert lines == (
        "Simplify constants",
        "constant-simplification",
        "ready | Any maturity",
        "in 1 | out 1",
    )
    assert "{" not in "\n".join(lines)


def test_canvas_scale_is_clamped_at_both_bounds() -> None:
    from d810.ui.workbench_canvas_graphics_logic import clamp_canvas_scale

    assert clamp_canvas_scale(0.30, 0.5) == 0.30
    assert clamp_canvas_scale(1.00, 1.15) == 1.15
    assert clamp_canvas_scale(3.20, 1.15) == 3.20


def test_contract_bezier_leaves_the_output_and_enters_the_input() -> None:
    from d810.ui.workbench_canvas_graphics_logic import contract_bezier

    curve = contract_bezier(source=(100.0, 20.0), target=(300.0, 140.0))

    assert curve.start == (100.0, 20.0)
    assert curve.end == (300.0, 140.0)
    assert curve.control_1[0] > curve.start[0]
    assert curve.control_2[0] < curve.end[0]


def test_node_presentation_labels_recipe_system_and_evidence_without_qss() -> None:
    from d810.ui.workbench_canvas_graphics_logic import node_presentation

    assert node_presentation("recipe").badge == "Recipe"
    assert node_presentation("system").badge == "Observed"
    assert node_presentation("evidence").badge == "Evidence"
    assert node_presentation("system").read_only is True
    assert node_presentation("evidence").read_only is True
    assert node_presentation("recipe").read_only is False


def test_sequence_edge_has_a_distinct_presentation_from_contract_data_flow() -> None:
    from d810.ui.workbench_canvas_graphics_logic import edge_presentation

    assert edge_presentation("contract") != edge_presentation("sequence")
    assert edge_presentation("contract").uses_ports is True
    assert edge_presentation("sequence").uses_ports is False
