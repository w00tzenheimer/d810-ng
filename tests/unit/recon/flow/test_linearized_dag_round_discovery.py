from __future__ import annotations

from types import SimpleNamespace

from d810.analyses.control_flow import linearized_dag_round_discovery as discovery
from d810.analyses.control_flow.linearized_state_dag import SemanticEdgeKind
from d810.analyses.control_flow.linearized_state_dag import (
    RenderedProgramLine,
    RenderedProgramNode,
)


class _FakeKey:
    def __init__(self, handler_serial: int):
        self.handler_serial = int(handler_serial)


class _FakeAnchor:
    def __init__(self, block_serial: int):
        self.block_serial = int(block_serial)


class _FakeEdge:
    def __init__(
        self,
        *,
        kind,
        handler_serial: int,
        ordered_path: tuple[int, ...],
        target_entry_anchor: int | None = None,
    ):
        self.kind = kind
        self.source_key = _FakeKey(handler_serial)
        self.source_anchor = _FakeAnchor(ordered_path[0])
        self.ordered_path = ordered_path
        self.target_entry_anchor = target_entry_anchor


class _FakeHandler:
    def __init__(self, check_block: int, handler_blocks: tuple[int, ...]):
        self.check_block = int(check_block)
        self.handler_blocks = tuple(int(block) for block in handler_blocks)


class _FakeStateKey:
    def __init__(self, state_const: int, handler_serial: int = 0):
        self.state_const = int(state_const)
        self.handler_serial = int(handler_serial)


class _FakeStateEdge:
    def __init__(self, source_state: int, target_state: int):
        self.kind = SemanticEdgeKind.TRANSITION
        self.source_key = _FakeStateKey(source_state)
        self.target_state = int(target_state)


class _FakeProgramNode:
    def __init__(
        self,
        label_text: str,
        *,
        line_start: int = 0,
        line_end: int = 0,
    ):
        self.label_text = label_text
        self.line_start = int(line_start)
        self.line_end = int(line_end)


class _FakeProgramLine:
    def __init__(self, target_label: str | None, *, line_no: int = 0):
        self.target_label = target_label
        self.line_no = int(line_no)


class _FakeDagNode:
    def __init__(
        self,
        state_const: int,
        *,
        state_label: str,
        entry_anchor: int,
        exclusive_blocks: tuple[int, ...] = (),
        owned_blocks: tuple[int, ...] = (),
        local_segments: tuple[tuple[int, ...], ...] = (),
    ):
        self.key = _FakeStateKey(state_const)
        self.state_label = state_label
        self.entry_anchor = int(entry_anchor)
        self.exclusive_blocks = tuple(int(block) for block in exclusive_blocks)
        self.owned_blocks = tuple(int(block) for block in owned_blocks)
        self.local_segments = tuple(
            SimpleNamespace(blocks=tuple(int(block) for block in segment))
            for segment in local_segments
        )


def test_build_linearized_dag_round_summary_collects_exit_and_terminal_facts(monkeypatch):
    transition_edge = _FakeEdge(
        kind=SemanticEdgeKind.TRANSITION,
        handler_serial=10,
        ordered_path=(100, 101),
        target_entry_anchor=200,
    )
    return_edge = _FakeEdge(
        kind=SemanticEdgeKind.CONDITIONAL_RETURN,
        handler_serial=20,
        ordered_path=(300, 301),
    )
    unknown_edge = _FakeEdge(
        kind=SemanticEdgeKind.UNKNOWN,
        handler_serial=30,
        ordered_path=(400,),
    )
    dag = SimpleNamespace(
        edges=(transition_edge, return_edge, unknown_edge),
        nodes=(
            SimpleNamespace(handler_serial=20, owned_blocks=(20, 21)),
            SimpleNamespace(handler_serial=30, owned_blocks=(30,)),
        ),
    )

    monkeypatch.setattr(
        discovery,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )
    monkeypatch.setattr(
        discovery,
        "build_dispatcher_transition_report_from_graph",
        lambda *args, **kwargs: SimpleNamespace(
            rows=(
                SimpleNamespace(handler_serial=10, kind=discovery.TransitionKind.EXIT),
                SimpleNamespace(handler_serial=40, kind=discovery.TransitionKind.EXIT),
            )
        ),
    )
    monkeypatch.setattr(
        discovery,
        "select_plannable_dag_edges",
        lambda dag_obj: (transition_edge,),
    )
    monkeypatch.setattr(
        discovery,
        "build_linearized_state_program",
        lambda *args, **kwargs: SimpleNamespace(nodes=()),
    )

    result = discovery.build_linearized_dag_round_summary(
        current_flow_graph=object(),
        transition_result=object(),
        dispatcher_serial=2,
        state_var_stkoff=None,
        pre_header_serial=1,
        initial_state=0x10,
        handler_range_map={},
        bst_node_blocks=(2,),
        diagnostics=(),
        dispatcher=None,
        mba=None,
        handlers={
            10: _FakeHandler(10, (11,)),
            40: _FakeHandler(40, (41, 42)),
        },
    )

    assert result.dag is dag
    assert result.report_exit_handlers == frozenset({40})
    assert result.report_exit_owned_blocks == frozenset({40, 41, 42})
    assert result.terminal_source_handlers == frozenset({20, 30})
    assert result.terminal_source_owned_blocks == frozenset({20, 21, 30})
    assert result.terminal_protected_blocks == frozenset({300, 301, 400})
    assert result.terminal_skipped == 1
    assert result.unknown_skipped == 1
    assert len(result.plannable_edges) == 1
    assert result.plannable_edges[0].source_anchor_block == 100
    assert result.plannable_edges[0].ordered_path == (100, 101)
    assert result.plannable_edges[0].target_entry_anchor == 200
    assert result.plannable_edges[0].requires_safe_target_resolution


def test_build_linearized_dag_round_summary_uses_non_inlining_semantic_program(monkeypatch):
    captured: dict[str, object] = {}
    dag = SimpleNamespace(edges=(), nodes=())

    monkeypatch.setattr(
        discovery,
        "build_live_linearized_state_dag_from_graph",
        lambda *args, **kwargs: dag,
    )
    monkeypatch.setattr(
        discovery,
        "build_dispatcher_transition_report_from_graph",
        lambda *args, **kwargs: SimpleNamespace(rows=()),
    )
    monkeypatch.setattr(
        discovery,
        "select_plannable_dag_edges",
        lambda dag_obj: (),
    )

    def _capture_build_program(*args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(nodes=(), lines=())

    monkeypatch.setattr(
        discovery,
        "build_linearized_state_program",
        _capture_build_program,
    )

    discovery.build_linearized_dag_round_summary(
        current_flow_graph=object(),
        transition_result=object(),
        dispatcher_serial=2,
        state_var_stkoff=None,
        pre_header_serial=1,
        initial_state=0x10,
        handler_range_map={},
        bst_node_blocks=(2,),
        diagnostics=(),
        dispatcher=None,
        mba=None,
        handlers={},
    )

    assert captured["order_strategy"] == discovery.RenderOrderStrategy.SEMANTIC
    assert (
        captured["program_strategy"]
        == discovery.ProgramRenderStrategy.LOCAL_SEGMENT_COLLAPSING
    )
    assert captured["label_render_mode"] == discovery.LabelRenderMode.STATE_FAMILY
    assert captured["boundary_inline_mode"] == discovery.BoundaryInlineMode.LABELS_ONLY
    assert captured["comment_mode"] == discovery.ProgramCommentMode.MINIMAL


def test_discover_structured_regions_keeps_secondary_regions_when_initial_labels_are_gone():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        edges=(
            _FakeStateEdge(0x32FCD904, 0x2E6C61F3),
            _FakeStateEdge(0x2E6C61F3, 0x652D7A98),
            _FakeStateEdge(0x2315233C, 0x7D9C16EC),
            _FakeStateEdge(0x7D9C16EC, 0x72AFE1BC),
            _FakeStateEdge(0x72AFE1BC, 0x737189D5),
            _FakeStateEdge(0x737189D5, 0x71E22BF3),
            _FakeStateEdge(0x71E22BF3, 0x11CD1DA3),
            _FakeStateEdge(0x4E69F350, 0x2A5ADB57),
            _FakeStateEdge(0x2A5ADB57, 0x1AB9946F),
            _FakeStateEdge(0x1AB9946F, 0x7C2C0220),
            _FakeStateEdge(0x7C2C0220, 0x385BBE2D),
            _FakeStateEdge(0x385BBE2D, 0x10743C4C),
            _FakeStateEdge(0x10743C4C, 0x6107F8EC),
            _FakeStateEdge(0x6107F8EC, 0x4C77464F),
        ),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            _FakeProgramNode("STATE_32FCD904"),
            _FakeProgramNode("STATE_2E6C61F3"),
            _FakeProgramNode("STATE_652D7A98"),
            _FakeProgramNode("STATE_2315233C"),
            _FakeProgramNode("STATE_7D9C16EC"),
            _FakeProgramNode("STATE_72AFE1BC"),
            _FakeProgramNode("STATE_737189D5"),
            _FakeProgramNode("STATE_71E22BF3"),
            _FakeProgramNode("STATE_11CD1DA3"),
            _FakeProgramNode("STATE_4E69F350"),
            _FakeProgramNode("STATE_2A5ADB57"),
            _FakeProgramNode("STATE_1AB9946F"),
            _FakeProgramNode("STATE_7C2C0220"),
            _FakeProgramNode("STATE_385BBE2D"),
            _FakeProgramNode("STATE_10743C4C"),
            _FakeProgramNode("STATE_6107F8EC"),
            _FakeProgramNode("STATE_4C77464F"),
        )
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    assert [region.region_name for region in regions] == [
        "sub7ffd_downstream_chain_region",
        "sub7ffd_7c2c0220_corridor_region",
        "sub7ffd_10743c4c_branch_region",
    ]


def test_discover_structured_regions_accepts_branch_region_from_semantic_target_labels():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        edges=(
            _FakeStateEdge(0x4E69F350, 0x2A5ADB57),
            _FakeStateEdge(0x2A5ADB57, 0x1AB9946F),
            _FakeStateEdge(0x1AB9946F, 0x7C2C0220),
            _FakeStateEdge(0x7C2C0220, 0x385BBE2D),
            _FakeStateEdge(0x385BBE2D, 0x10743C4C),
            _FakeStateEdge(0x10743C4C, 0x6107F8EC),
            _FakeStateEdge(0x6107F8EC, 0x4C77464F),
        ),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            _FakeProgramNode("STATE_4E69F350"),
            _FakeProgramNode("STATE_2A5ADB57"),
            _FakeProgramNode("STATE_1AB9946F"),
            _FakeProgramNode("STATE_7C2C0220"),
            _FakeProgramNode("STATE_385BBE2D"),
            _FakeProgramNode("STATE_10743C4C"),
            _FakeProgramNode("STATE_4C77464F"),
        ),
        lines=(
            _FakeProgramLine("STATE_2A5ADB57"),
            _FakeProgramLine("STATE_1AB9946F"),
            _FakeProgramLine("STATE_7C2C0220"),
            _FakeProgramLine("STATE_385BBE2D"),
            _FakeProgramLine("STATE_10743C4C"),
            _FakeProgramLine("STATE_6107F8EC"),
            _FakeProgramLine("STATE_4C77464F"),
            _FakeProgramLine("STATE_296F2452"),
            _FakeProgramLine("STATE_12ACFB20"),
            _FakeProgramLine("STATE_32FCD904"),
        ),
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    assert any(
        region.region_name == "sub7ffd_10743c4c_branch_region"
        for region in regions
    )


def test_discover_structured_regions_derives_branch_internal_edge_from_semantic_lines():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        edges=(),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            _FakeProgramNode("STATE_4E69F350", line_start=1, line_end=1),
            _FakeProgramNode("STATE_2A5ADB57", line_start=2, line_end=2),
            _FakeProgramNode("STATE_1AB9946F", line_start=3, line_end=3),
            _FakeProgramNode("STATE_7C2C0220", line_start=4, line_end=4),
            _FakeProgramNode("STATE_385BBE2D", line_start=5, line_end=6),
            _FakeProgramNode("STATE_10743C4C", line_start=7, line_end=7),
            _FakeProgramNode("STATE_6107F8EC", line_start=8, line_end=9),
            _FakeProgramNode("STATE_4C77464F", line_start=10, line_end=11),
        ),
        lines=(
            _FakeProgramLine("STATE_2A5ADB57", line_no=1),
            _FakeProgramLine("STATE_1AB9946F", line_no=2),
            _FakeProgramLine("STATE_7C2C0220", line_no=3),
            _FakeProgramLine("STATE_385BBE2D", line_no=4),
            _FakeProgramLine("STATE_10743C4C", line_no=5),
            _FakeProgramLine("STATE_6B588049", line_no=6),
            _FakeProgramLine("STATE_6107F8EC", line_no=7),
            _FakeProgramLine("STATE_296F2452", line_no=8),
            _FakeProgramLine("STATE_4C77464F", line_no=9),
            _FakeProgramLine("STATE_12ACFB20", line_no=10),
            _FakeProgramLine("STATE_32FCD904", line_no=11),
        ),
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    branch_region = next(
        region
        for region in regions
        if region.region_name == "sub7ffd_10743c4c_branch_region"
    )
    assert branch_region.internal_state_edges == (
        (0x10743C4C, 0x6107F8EC),
        (0x1AB9946F, 0x7C2C0220),
        (0x2A5ADB57, 0x1AB9946F),
        (0x385BBE2D, 0x10743C4C),
        (0x4E69F350, 0x2A5ADB57),
        (0x7C2C0220, 0x385BBE2D),
    )
    assert branch_region.state_values == (
        0x4E69F350,
        0x2A5ADB57,
        0x1AB9946F,
        0x7C2C0220,
        0x385BBE2D,
        0x10743C4C,
        0x6107F8EC,
    )
    assert branch_region.exit_state_values == (0x4C77464F, 0x296F2452)


def test_discover_structured_regions_accepts_branch_region_from_live_dag_states():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        nodes=(
            SimpleNamespace(key=_FakeStateKey(0x4E69F350)),
            SimpleNamespace(key=_FakeStateKey(0x2A5ADB57)),
            SimpleNamespace(key=_FakeStateKey(0x1AB9946F)),
            SimpleNamespace(key=_FakeStateKey(0x7C2C0220)),
            SimpleNamespace(key=_FakeStateKey(0x385BBE2D)),
            SimpleNamespace(key=_FakeStateKey(0x10743C4C)),
            SimpleNamespace(key=_FakeStateKey(0x6107F8EC)),
            SimpleNamespace(key=_FakeStateKey(0x4C77464F)),
        ),
        edges=(
            _FakeStateEdge(0x4E69F350, 0x2A5ADB57),
            _FakeStateEdge(0x2A5ADB57, 0x1AB9946F),
            _FakeStateEdge(0x1AB9946F, 0x7C2C0220),
            _FakeStateEdge(0x7C2C0220, 0x385BBE2D),
            _FakeStateEdge(0x385BBE2D, 0x10743C4C),
            _FakeStateEdge(0x10743C4C, 0x6107F8EC),
            _FakeStateEdge(0x6107F8EC, 0x4C77464F),
        ),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(),
        lines=(),
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    assert any(
        region.region_name == "sub7ffd_10743c4c_branch_region"
        for region in regions
    )


def test_discover_structured_regions_synthesizes_child_regions_for_exit_states_with_bodies():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        nodes=(
            SimpleNamespace(key=_FakeStateKey(0x4E69F350)),
            SimpleNamespace(key=_FakeStateKey(0x2A5ADB57)),
            SimpleNamespace(key=_FakeStateKey(0x1AB9946F)),
            SimpleNamespace(key=_FakeStateKey(0x7C2C0220)),
            SimpleNamespace(key=_FakeStateKey(0x385BBE2D)),
            SimpleNamespace(key=_FakeStateKey(0x10743C4C)),
            SimpleNamespace(key=_FakeStateKey(0x6107F8EC)),
            SimpleNamespace(key=_FakeStateKey(0x4C77464F)),
            SimpleNamespace(key=_FakeStateKey(0x296F2452)),
            SimpleNamespace(key=_FakeStateKey(0x12ACFB20)),
            SimpleNamespace(key=_FakeStateKey(0x32FCD904)),
            SimpleNamespace(key=_FakeStateKey(0x1A9A9DD9)),
        ),
        edges=(
            _FakeStateEdge(0x4E69F350, 0x2A5ADB57),
            _FakeStateEdge(0x2A5ADB57, 0x1AB9946F),
            _FakeStateEdge(0x1AB9946F, 0x7C2C0220),
            _FakeStateEdge(0x7C2C0220, 0x385BBE2D),
            _FakeStateEdge(0x385BBE2D, 0x10743C4C),
            _FakeStateEdge(0x10743C4C, 0x6107F8EC),
            _FakeStateEdge(0x6107F8EC, 0x4C77464F),
            _FakeStateEdge(0x6107F8EC, 0x296F2452),
            _FakeStateEdge(0x4C77464F, 0x12ACFB20),
            _FakeStateEdge(0x4C77464F, 0x32FCD904),
            _FakeStateEdge(0x296F2452, 0x1A9A9DD9),
        ),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            _FakeProgramNode("STATE_4E69F350", line_start=1, line_end=1),
            _FakeProgramNode("STATE_2A5ADB57", line_start=2, line_end=2),
            _FakeProgramNode("STATE_1AB9946F", line_start=3, line_end=3),
            _FakeProgramNode("STATE_7C2C0220", line_start=4, line_end=4),
            _FakeProgramNode("STATE_385BBE2D", line_start=5, line_end=5),
            _FakeProgramNode("STATE_10743C4C", line_start=6, line_end=6),
            _FakeProgramNode("STATE_6107F8EC", line_start=7, line_end=8),
            _FakeProgramNode("STATE_4C77464F", line_start=9, line_end=10),
            _FakeProgramNode("STATE_296F2452", line_start=11, line_end=11),
        ),
        lines=(
            _FakeProgramLine("STATE_2A5ADB57", line_no=1),
            _FakeProgramLine("STATE_1AB9946F", line_no=2),
            _FakeProgramLine("STATE_7C2C0220", line_no=3),
            _FakeProgramLine("STATE_385BBE2D", line_no=4),
            _FakeProgramLine("STATE_10743C4C", line_no=5),
            _FakeProgramLine("STATE_6107F8EC", line_no=6),
            _FakeProgramLine("STATE_4C77464F", line_no=7),
            _FakeProgramLine("STATE_296F2452", line_no=8),
            _FakeProgramLine("STATE_12ACFB20", line_no=9),
            _FakeProgramLine("STATE_32FCD904", line_no=10),
            _FakeProgramLine("STATE_1A9A9DD9", line_no=11),
        ),
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    region_by_name = {region.region_name: region for region in regions}
    assert "sub7ffd_exit_state_region_4c77464f" in region_by_name
    assert region_by_name["sub7ffd_exit_state_region_4c77464f"].state_values == (
        0x4C77464F,
    )
    assert region_by_name["sub7ffd_exit_state_region_4c77464f"].exit_state_values == (
        0x12ACFB20,
        0x32FCD904,
    )
    assert "sub7ffd_exit_state_region_296f2452" in region_by_name
    assert region_by_name["sub7ffd_exit_state_region_296f2452"].exit_state_values == (
        0x1A9A9DD9,
    )


def test_discover_structured_regions_normalizes_raw_alias_exit_state_to_semantic_family():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        supplemental_selected_entries=((0x4C77464F, 66),),
        nodes=(
            _FakeDagNode(0x4E69F350, state_label="STATE_4E69F350", entry_anchor=71),
            _FakeDagNode(0x2A5ADB57, state_label="STATE_2A5ADB57", entry_anchor=177),
            _FakeDagNode(0x1AB9946F, state_label="STATE_1AB9946F", entry_anchor=214),
            _FakeDagNode(0x7C2C0220, state_label="STATE_7C2C0220", entry_anchor=52),
            _FakeDagNode(0x385BBE2D, state_label="STATE_385BBE2D", entry_anchor=160),
            _FakeDagNode(0x10743C4C, state_label="STATE_10743C4C", entry_anchor=158),
            _FakeDagNode(0x6107F8EC, state_label="STATE_6107F8EC", entry_anchor=160),
            _FakeDagNode(
                0x4C77464F,
                state_label="0x4C77464F",
                entry_anchor=66,
                exclusive_blocks=(66,),
            ),
            _FakeDagNode(
                0x474EEEBB,
                state_label="STATE_474EEEBB",
                entry_anchor=66,
                exclusive_blocks=(66,),
                owned_blocks=(67, 68, 69),
            ),
            _FakeDagNode(0x296F2452, state_label="STATE_296F2452", entry_anchor=202),
            _FakeDagNode(0x12ACFB20, state_label="STATE_12ACFB20", entry_anchor=181),
            _FakeDagNode(0x32FCD904, state_label="STATE_32FCD904", entry_anchor=189),
            _FakeDagNode(0x1A9A9DD9, state_label="STATE_1A9A9DD9", entry_anchor=217),
        ),
        edges=(
            _FakeStateEdge(0x4E69F350, 0x2A5ADB57),
            _FakeStateEdge(0x2A5ADB57, 0x1AB9946F),
            _FakeStateEdge(0x1AB9946F, 0x7C2C0220),
            _FakeStateEdge(0x7C2C0220, 0x385BBE2D),
            _FakeStateEdge(0x385BBE2D, 0x10743C4C),
            _FakeStateEdge(0x10743C4C, 0x6107F8EC),
            _FakeStateEdge(0x6107F8EC, 0x4C77464F),
            _FakeStateEdge(0x6107F8EC, 0x296F2452),
            _FakeStateEdge(0x4C77464F, 0x12ACFB20),
            _FakeStateEdge(0x4C77464F, 0x32FCD904),
            _FakeStateEdge(0x474EEEBB, 0x12ACFB20),
            _FakeStateEdge(0x474EEEBB, 0x32FCD904),
            _FakeStateEdge(0x296F2452, 0x1A9A9DD9),
        ),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            _FakeProgramNode("STATE_4E69F350", line_start=1, line_end=1),
            _FakeProgramNode("STATE_2A5ADB57", line_start=2, line_end=2),
            _FakeProgramNode("STATE_1AB9946F", line_start=3, line_end=3),
            _FakeProgramNode("STATE_7C2C0220", line_start=4, line_end=4),
            _FakeProgramNode("STATE_385BBE2D", line_start=5, line_end=5),
            _FakeProgramNode("STATE_10743C4C", line_start=6, line_end=6),
            _FakeProgramNode("STATE_6107F8EC", line_start=7, line_end=8),
            _FakeProgramNode("STATE_474EEEBB", line_start=9, line_end=10),
            _FakeProgramNode("STATE_296F2452", line_start=11, line_end=11),
        ),
        lines=(
            _FakeProgramLine("STATE_2A5ADB57", line_no=1),
            _FakeProgramLine("STATE_1AB9946F", line_no=2),
            _FakeProgramLine("STATE_7C2C0220", line_no=3),
            _FakeProgramLine("STATE_385BBE2D", line_no=4),
            _FakeProgramLine("STATE_10743C4C", line_no=5),
            _FakeProgramLine("STATE_6107F8EC", line_no=6),
            _FakeProgramLine("STATE_474EEEBB", line_no=7),
            _FakeProgramLine("STATE_296F2452", line_no=8),
            _FakeProgramLine("STATE_12ACFB20", line_no=9),
            _FakeProgramLine("STATE_32FCD904", line_no=10),
            _FakeProgramLine("STATE_1A9A9DD9", line_no=11),
        ),
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    region_by_name = {region.region_name: region for region in regions}
    branch_region = region_by_name["sub7ffd_10743c4c_branch_region"]
    assert branch_region.exit_state_values == (0x474EEEBB, 0x296F2452)
    assert "sub7ffd_exit_state_region_4c77464f" not in region_by_name
    assert "sub7ffd_exit_state_region_474eeebb" in region_by_name
    assert region_by_name["sub7ffd_exit_state_region_474eeebb"].exit_state_values == (
        0x12ACFB20,
        0x32FCD904,
    )


def test_normalize_semantic_reference_program_aliases_rewrites_raw_branch_artifact_state():
    dag = SimpleNamespace(
        supplemental_selected_entries=((0x4C77464F, 68),),
        nodes=(
            _FakeDagNode(
                0x4C77464F,
                state_label="STATE_4C77464F",
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
            ),
            _FakeDagNode(
                0x474EEEBB,
                state_label="STATE_474EEEBB",
                entry_anchor=66,
                owned_blocks=(66, 67, 68, 69),
            ),
        ),
        edges=(
            _FakeStateEdge(0x474EEEBB, 0x12ACFB20),
            _FakeStateEdge(0x474EEEBB, 0x32FCD904),
        ),
    )
    semantic_reference_program = discovery.RenderedProgramSnapshot(
        variant_name="semantic",
        order_strategy="semantic",
        program_strategy="local",
        label_render_mode="family",
        boundary_inline_mode="labels_only",
        comment_mode="minimal",
        nodes=(
            RenderedProgramNode(
                node_index=0,
                label_text="STATE_6107F8EC",
                node_kind="exact",
                line_start=1,
                line_end=2,
                state_label="STATE_6107F8EC",
                handler_serial=15,
                entry_anchor=15,
                label_num=None,
            ),
            RenderedProgramNode(
                node_index=1,
                label_text="STATE_4C77464F",
                node_kind="exact",
                line_start=3,
                line_end=4,
                state_label="STATE_4C77464F",
                handler_serial=66,
                entry_anchor=66,
                label_num=None,
            ),
        ),
        lines=(
            RenderedProgramLine(
                line_no=1,
                text="    goto STATE_4C77464F;",
                node_index=0,
                indent_level=1,
                line_kind="goto",
                target_label="STATE_4C77464F",
            ),
            RenderedProgramLine(
                line_no=2,
                text="    goto STATE_296F2452;",
                node_index=0,
                indent_level=1,
                line_kind="goto",
                target_label="STATE_296F2452",
            ),
            RenderedProgramLine(
                line_no=3,
                text="STATE_4C77464F:",
                node_index=1,
                indent_level=0,
                line_kind="label",
                target_label=None,
            ),
            RenderedProgramLine(
                line_no=4,
                text="    goto STATE_12ACFB20;",
                node_index=1,
                indent_level=1,
                line_kind="goto",
                target_label="STATE_12ACFB20",
            ),
        ),
    )

    normalized = discovery._normalize_semantic_reference_program_aliases(
        dag,
        semantic_reference_program,
    )

    assert normalized.nodes[1].label_text == "STATE_474EEEBB"
    assert normalized.lines[0].target_label == "STATE_474EEEBB"
    assert "STATE_474EEEBB" in normalized.lines[0].text


def test_discover_structured_regions_does_not_synthesize_child_for_state_already_covered_by_region():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        nodes=(
            SimpleNamespace(key=_FakeStateKey(0x4E69F350)),
            SimpleNamespace(key=_FakeStateKey(0x2A5ADB57)),
            SimpleNamespace(key=_FakeStateKey(0x1AB9946F)),
            SimpleNamespace(key=_FakeStateKey(0x7C2C0220)),
            SimpleNamespace(key=_FakeStateKey(0x385BBE2D)),
            SimpleNamespace(key=_FakeStateKey(0x10743C4C)),
            SimpleNamespace(key=_FakeStateKey(0x6107F8EC)),
            SimpleNamespace(key=_FakeStateKey(0x4C77464F)),
        ),
        edges=(
            _FakeStateEdge(0x4E69F350, 0x2A5ADB57),
            _FakeStateEdge(0x2A5ADB57, 0x1AB9946F),
            _FakeStateEdge(0x1AB9946F, 0x7C2C0220),
            _FakeStateEdge(0x7C2C0220, 0x385BBE2D),
            _FakeStateEdge(0x385BBE2D, 0x10743C4C),
            _FakeStateEdge(0x10743C4C, 0x6107F8EC),
            _FakeStateEdge(0x6107F8EC, 0x4C77464F),
            _FakeStateEdge(0x4C77464F, 0x6107F8EC),
        ),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            _FakeProgramNode("STATE_4E69F350", line_start=1, line_end=1),
            _FakeProgramNode("STATE_2A5ADB57", line_start=2, line_end=2),
            _FakeProgramNode("STATE_1AB9946F", line_start=3, line_end=3),
            _FakeProgramNode("STATE_7C2C0220", line_start=4, line_end=4),
            _FakeProgramNode("STATE_385BBE2D", line_start=5, line_end=5),
            _FakeProgramNode("STATE_10743C4C", line_start=6, line_end=6),
            _FakeProgramNode("STATE_6107F8EC", line_start=7, line_end=7),
            _FakeProgramNode("STATE_4C77464F", line_start=8, line_end=8),
        ),
        lines=(
            _FakeProgramLine("STATE_2A5ADB57", line_no=1),
            _FakeProgramLine("STATE_1AB9946F", line_no=2),
            _FakeProgramLine("STATE_7C2C0220", line_no=3),
            _FakeProgramLine("STATE_385BBE2D", line_no=4),
            _FakeProgramLine("STATE_10743C4C", line_no=5),
            _FakeProgramLine("STATE_6107F8EC", line_no=6),
            _FakeProgramLine("STATE_4C77464F", line_no=7),
            _FakeProgramLine("STATE_6107F8EC", line_no=8),
        ),
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    region_names = {region.region_name for region in regions}
    assert "sub7ffd_exit_state_region_4c77464f" in region_names
    assert "sub7ffd_exit_state_region_6107f8ec" not in region_names


def test_discover_structured_regions_skips_zero_state_child_regions():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        nodes=(
            SimpleNamespace(key=_FakeStateKey(0x4E69F350)),
            SimpleNamespace(key=_FakeStateKey(0x2A5ADB57)),
            SimpleNamespace(key=_FakeStateKey(0x1AB9946F)),
            SimpleNamespace(key=_FakeStateKey(0x7C2C0220)),
            SimpleNamespace(key=_FakeStateKey(0x385BBE2D)),
            SimpleNamespace(key=_FakeStateKey(0x10743C4C)),
            SimpleNamespace(key=_FakeStateKey(0x6107F8EC)),
        ),
        edges=(
            _FakeStateEdge(0x4E69F350, 0x2A5ADB57),
            _FakeStateEdge(0x2A5ADB57, 0x1AB9946F),
            _FakeStateEdge(0x1AB9946F, 0x7C2C0220),
            _FakeStateEdge(0x7C2C0220, 0x385BBE2D),
            _FakeStateEdge(0x385BBE2D, 0x10743C4C),
            _FakeStateEdge(0x10743C4C, 0x6107F8EC),
            _FakeStateEdge(0x6107F8EC, 0x00000000),
        ),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            _FakeProgramNode("STATE_4E69F350", line_start=1, line_end=1),
            _FakeProgramNode("STATE_2A5ADB57", line_start=2, line_end=2),
            _FakeProgramNode("STATE_1AB9946F", line_start=3, line_end=3),
            _FakeProgramNode("STATE_7C2C0220", line_start=4, line_end=4),
            _FakeProgramNode("STATE_385BBE2D", line_start=5, line_end=5),
            _FakeProgramNode("STATE_10743C4C", line_start=6, line_end=6),
            _FakeProgramNode("STATE_6107F8EC", line_start=7, line_end=7),
        ),
        lines=(
            _FakeProgramLine("STATE_2A5ADB57", line_no=1),
            _FakeProgramLine("STATE_1AB9946F", line_no=2),
            _FakeProgramLine("STATE_7C2C0220", line_no=3),
            _FakeProgramLine("STATE_385BBE2D", line_no=4),
            _FakeProgramLine("STATE_10743C4C", line_no=5),
            _FakeProgramLine("STATE_6107F8EC", line_no=6),
            _FakeProgramLine("STATE_00000000", line_no=7),
        ),
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    region_names = {region.region_name for region in regions}
    assert "sub7ffd_exit_state_region_00000000" not in region_names


def test_discover_structured_regions_falls_back_to_declared_region_order_when_semantic_edges_are_missing():
    dag = SimpleNamespace(
        initial_state=0x5D0AEBD3,
        nodes=(
            SimpleNamespace(key=_FakeStateKey(0x4E69F350)),
        ),
        edges=(),
    )
    semantic_reference_program = SimpleNamespace(
        nodes=(
            _FakeProgramNode("STATE_4E69F350"),
        ),
        lines=(),
    )

    regions = discovery.discover_structured_dag_regions(
        dag,
        semantic_reference_program=semantic_reference_program,
    )

    branch_region = next(
        region
        for region in regions
        if region.region_name == "sub7ffd_10743c4c_branch_region"
    )
    assert branch_region.internal_state_edges == (
        (0x4E69F350, 0x2A5ADB57),
        (0x2A5ADB57, 0x1AB9946F),
        (0x1AB9946F, 0x7C2C0220),
        (0x7C2C0220, 0x385BBE2D),
        (0x385BBE2D, 0x10743C4C),
        (0x10743C4C, 0x6107F8EC),
    )
