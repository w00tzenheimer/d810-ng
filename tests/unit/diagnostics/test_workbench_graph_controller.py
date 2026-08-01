from __future__ import annotations

from d810.diagnostics.workbench_graph_controller import DiagnosticGraphController
from d810.diagnostics.workbench_graph_models import (
    DiagnosticGraph,
    DiagnosticGraphContext,
    DiagnosticGraphKind,
)
from d810.diagnostics.workbench_models import (
    DiagnosticField,
    DiagnosticRecord,
    DiagnosticViewKind,
)
from d810.core.deobfuscation_case import (
    CaseEvidenceLevel,
    CaseFinding,
    CaseFindingKind,
    CaseVerdict,
    DeobfuscationCaseEvidence,
)


def _context(kind: DiagnosticGraphKind) -> DiagnosticGraphContext:
    return DiagnosticGraphContext(
        database_path="/tmp/diag.sqlite3",
        snapshot_id=17,
        function_ea=0x180012B60,
        function_name="target",
        kind=kind,
    )


def _block(ordinal: int, serial: str, succs: str = "") -> DiagnosticRecord:
    anchor_ea = int(serial.rsplit("@", 1)[1], 16)
    return DiagnosticRecord(
        kind=DiagnosticViewKind.BLOCKS,
        source_table="blocks",
        snapshot_id=17,
        ordinal=ordinal,
        fields=(
            DiagnosticField("serial", serial, serial, anchor_ea),
            DiagnosticField("succs", succs, succs),
        ),
        warnings=(),
        anchor_ea=anchor_ea,
    )


def _state_records() -> tuple[DiagnosticRecord, ...]:
    return (
        DiagnosticRecord(
            kind=DiagnosticViewKind.STATE_MACHINE,
            source_table="state_cfg_nodes",
            snapshot_id=17,
            ordinal=1,
            fields=(
                DiagnosticField("state_hex", "0x12", "0x12"),
                DiagnosticField("state_i64", 18, "18"),
                DiagnosticField(
                    "entry_block",
                    "blk7@0x180012C9F",
                    "blk7@0x180012C9F",
                    0x180012C9F,
                ),
                DiagnosticField("classification", "dispatcher", "dispatcher"),
            ),
            warnings=(),
            anchor_ea=0x180012C9F,
        ),
        DiagnosticRecord(
            kind=DiagnosticViewKind.STATE_MACHINE,
            source_table="state_cfg_node_blocks",
            snapshot_id=17,
            ordinal=2,
            fields=(
                DiagnosticField("state_hex", "0x12", "0x12"),
                DiagnosticField(
                    "block_serial",
                    "blk7@0x180012C9F",
                    "blk7@0x180012C9F",
                    0x180012C9F,
                ),
                DiagnosticField("role", "owned", "owned"),
            ),
            warnings=(),
            anchor_ea=0x180012C9F,
        ),
        DiagnosticRecord(
            kind=DiagnosticViewKind.STATE_MACHINE,
            source_table="state_cfg_nodes",
            snapshot_id=17,
            ordinal=3,
            fields=(
                DiagnosticField("state_hex", "0x34", "0x34"),
                DiagnosticField("state_i64", 52, "52"),
                DiagnosticField(
                    "entry_block",
                    "blk8@0x180012D10",
                    "blk8@0x180012D10",
                    0x180012D10,
                ),
                DiagnosticField("classification", "payload", "payload"),
            ),
            warnings=(),
            anchor_ea=0x180012D10,
        ),
        DiagnosticRecord(
            kind=DiagnosticViewKind.STATE_MACHINE,
            source_table="state_cfg_node_blocks",
            snapshot_id=17,
            ordinal=4,
            fields=(
                DiagnosticField("state_hex", "0x34", "0x34"),
                DiagnosticField(
                    "block_serial",
                    "blk8@0x180012D10",
                    "blk8@0x180012D10",
                    0x180012D10,
                ),
                DiagnosticField("role", "owned", "owned"),
            ),
            warnings=(),
            anchor_ea=0x180012D10,
        ),
    )


class _Records:
    def __init__(self, values: dict[str, tuple[DiagnosticRecord, ...]]) -> None:
        self.values = values
        self.calls: list[tuple[str, int, str]] = []
        self.error: Exception | None = None

    def records(
        self,
        path: str,
        snapshot_id: int,
        kind: str,
    ) -> tuple[DiagnosticRecord, ...]:
        self.calls.append((path, snapshot_id, kind))
        if self.error is not None:
            raise self.error
        return self.values[kind]

    def case(self, path: str, function_ea: int) -> DeobfuscationCaseEvidence | None:
        del path, function_ea
        return DeobfuscationCaseEvidence(
            schema_version=1,
            function_fingerprint="target",
            runtime_identity="diagnostic-runtime",
            run_identity="diagnostic-session:17",
            findings=(
                CaseFinding(
                    finding_id="receipt:0x180012C9F",
                    kind=CaseFindingKind.RECEIPT,
                    summary="receipt",
                    detail="publication receipt",
                    native_ea=0x180012C9F,
                    confidence=1.0,
                    provenance=("diagnostic-session:17",),
                ),
            ),
            verdict=CaseVerdict(
                level=CaseEvidenceLevel.C5_PUBLICATION,
                summary="publication",
                first_blocked_obligation="semantic witness required",
            ),
        )


class _Navigation:
    def __init__(self) -> None:
        self.eas: list[int] = []

    def navigate(self, ea: int) -> None:
        self.eas.append(ea)


class _View:
    def __init__(self) -> None:
        self.actions: dict[str, object] = {}
        self.rendered: list[DiagnosticGraph] = []
        self.cleared: list[str] = []
        self.selected: list[str] = []
        self.focus_count = 0
        self.closed = False

    def bind_actions(self, **actions: object) -> None:
        self.actions = actions

    def show_or_focus(self) -> None:
        self.focus_count += 1

    def render(self, graph: DiagnosticGraph) -> None:
        self.rendered.append(graph)

    def clear(self, message: str) -> None:
        self.cleared.append(message)

    def select_node(self, model_id: str) -> bool:
        self.selected.append(model_id)
        return True

    def close(self) -> None:
        self.closed = True


def _controller() -> tuple[DiagnosticGraphController, _Records, _Navigation, _View]:
    records = _Records(
        {
            "blocks": (
                _block(1, "blk7@0x180012C9F"),
                _block(2, "blk8@0x180012D10"),
            ),
            "state_machine": _state_records(),
        }
    )
    navigation = _Navigation()
    view = _View()
    return DiagnosticGraphController(records, navigation, view), records, navigation, view


def test_controller_maps_explorer_context_and_reuses_one_view() -> None:
    controller, records, _, view = _controller()

    context = controller.context_for_explorer(
        database_path="/tmp/diag.sqlite3",
        snapshot_id=17,
        function_ea=0x180012B60,
        function_name="target",
        view_value="blocks",
    )
    assert context == _context(DiagnosticGraphKind.BLOCK_CFG)
    assert controller.context_for_explorer(
        database_path="/tmp/diag.sqlite3",
        snapshot_id=17,
        function_ea=0x180012B60,
        function_name="target",
        view_value="facts",
    ) is None

    controller.open(context)
    controller.open(context)

    assert records.calls == [
        ("/tmp/diag.sqlite3", 17, "blocks"),
        ("/tmp/diag.sqlite3", 17, "blocks"),
    ]
    assert view.focus_count == 2
    assert len(view.rendered) == 2


def test_controller_projects_a_case_lineage_only_when_case_evidence_exists() -> None:
    controller, _, _, view = _controller()
    context = controller.context_for_explorer(
        database_path="/tmp/diag.sqlite3",
        snapshot_id=17,
        function_ea=0x180012B60,
        function_name="target",
        view_value="case",
    )

    assert context is not None
    assert context.kind is DiagnosticGraphKind.CASE_LINEAGE
    controller.open(context)
    assert view.rendered[-1].nodes[0].category == "case_function"


def test_controller_centers_selected_record_without_reprojecting_and_jumps_anchor() -> None:
    controller, _, navigation, view = _controller()
    context = _context(DiagnosticGraphKind.BLOCK_CFG)
    controller.open(context)
    record = _block(1, "blk7@0x180012C9F")

    assert controller.select_record(record) is True
    assert view.selected == ["block:blk7@0x180012C9F"]
    assert len(view.rendered) == 1

    controller.jump_node("block:blk7@0x180012C9F")
    controller.jump_node("missing")
    assert navigation.eas == [0x180012C9F]


def test_controller_replaces_one_expanded_state_and_clears_for_context_change() -> None:
    controller, records, _, view = _controller()
    controller.open(_context(DiagnosticGraphKind.STATE_MACHINE))
    assert records.calls == [
        ("/tmp/diag.sqlite3", 17, "state_machine"),
        ("/tmp/diag.sqlite3", 17, "blocks"),
    ]

    controller.toggle_state("state:0x12")
    assert view.rendered[-1].expanded_group is not None
    assert view.rendered[-1].expanded_group.member_node_ids == (
        "block:blk7@0x180012C9F",
    )

    controller.toggle_state("state:0x34")
    assert view.rendered[-1].expanded_group is not None
    assert view.rendered[-1].expanded_group.member_node_ids == (
        "block:blk8@0x180012D10",
    )

    controller.update_context(_context(DiagnosticGraphKind.BLOCK_CFG))
    assert view.rendered[-1].expanded_group is None


def test_controller_clears_stale_graph_for_unsupported_and_read_failures() -> None:
    controller, records, _, view = _controller()
    controller.open(_context(DiagnosticGraphKind.BLOCK_CFG))
    records.error = RuntimeError("read failed")
    controller.update_context(_context(DiagnosticGraphKind.BLOCK_CFG))
    controller.clear_for_unsupported_view()

    assert view.cleared == ["Graph unavailable: read failed", "No graph for this view"]
    controller.close()
    assert view.closed is True
