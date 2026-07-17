# Diagnostics Native Graphs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add one live-linked native IDA graph tab for the Diagnostics Explorer's Block CFG and State Machine evidence.

**Architecture:** Existing normalized DiagnosticRecord values are converted by pure projectors into immutable graph models. A pure controller coordinates evidence context, one-way selection centering, expansion, and navigation through ports. A thin ida_graph.GraphViewer adapter renders models and implements only IDA callbacks.

**Tech Stack:** Python 3.10+, dataclasses, pytest, existing diagnostics inventory, ida_graph.GraphViewer, ida_kernwin CustomIDAMemo groups, IDA 9.3, Docker/XQuartz, ast-grep, import-linter, graphify.

## Global Constraints

- Implement exactly two graph kinds: Block CFG and State Machine. Do not graph other Diagnostics Explorer views.
- Diagnostics model, projectors, and controller import neither Qt, ida_* modules, SQLite, manager state, nor optimizer/runtime code.
- Projectors consume normalized DiagnosticRecord values only; they never open databases or run SQL.
- A block serial must never appear by itself in a label, hint, warning, or log. Render it only as blk<serial>@0x<EA>. Omit unanchored blocks and warn; never guess an EA.
- Edges, state ownership, terminal states, and transitions require explicit evidence. Omit dangling/incomplete evidence with warnings rather than synthesizing it.
- Models and output ordering are deterministic; every graph edge endpoint is an output node.
- State Machine accepts at most one expanded state. Changing database, snapshot, function, or kind clears expansion.
- Explorer record selection centers an already projected node without rebuild. Record filters never change graph topology.
- One stable title, d810-ng Diagnostics Graph, is reused. A visible status card names kind, database basename, snapshot, function name when known, function EA, and warnings.
- Graph selection is local. Double-click navigates only an explicit node anchor. No graph event changes structured-record selection.
- Retain WorkbenchDiagnosticsAdapter as the allowlisted reader/navigation seam. Do not add manager facades, raw SQL, graph writes, dependencies, or architecture-rule ignores.
- Graph work must not alter inventory/cleaner behavior, persisted overrides, diagnostic SQLite data, WAL, or SHM.
- Run architecture checks in /Users/mahmoud/src/idapro/d810/.worktrees/truthful-config-v2-project-ui and run graphify update . after code changes.
- Live acceptance uses /samples/bins/libobfuscated.dll.2026-06-03.i64 only through the audited launcher copy mechanism; its source SHA-256 must not change.

## File Structure

| Path | Responsibility |
| --- | --- |
| src/d810/diagnostics/workbench_graph_models.py | Immutable graph/context/source-reference types; graph invariants; record-to-node lookup; canonical anchored block IDs. |
| src/d810/diagnostics/workbench_graph_projection.py | Pure Block CFG and State Machine graph projection from normalized records. |
| src/d810/diagnostics/workbench_graph_controller.py | Pure ports and action logic for context, reusable view, selection, expansion, errors, and anchors. |
| src/d810/ui/workbench_diagnostic_graph.py | Thin ida_graph adapter: tab reuse, AddNode/AddEdge, status card, hints, popups, grouping, select, double-click. |
| src/d810/ui/workbench_diagnostics_panel.py | Open graph action, context publishing, record centering, graph companion teardown. |
| src/d810/ui/workbench_panel.py | Construct/inject the graph controller beside WorkbenchDiagnosticsAdapter. |
| tests/unit/diagnostics/test_workbench_graph_models.py | Graph model/source identity tests. |
| tests/unit/diagnostics/test_workbench_graph_projection.py | Pure evidence projector tests. |
| tests/unit/diagnostics/test_workbench_graph_controller.py | Fake-port action/lifecycle tests. |
| tests/unit/ui/test_workbench_diagnostic_graph_contract.py | AST/source contracts for IDA adapter without IDA imports in unit tests. |
| tests/unit/ui/test_workbench_diagnostics_panel_contract.py | Thin Explorer/integration contract. |
| tests/unit/ui/test_workbench_panel_contract.py | Workbench controller construction/injection contract. |

## Locked Interfaces

~~~python
# src/d810/diagnostics/workbench_graph_models.py
class DiagnosticGraphKind(str, enum.Enum):
    BLOCK_CFG = "block_cfg"
    STATE_MACHINE = "state_machine"

@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticRecordRef:
    source_table: str
    snapshot_id: int
    ordinal: int

@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphContext:
    database_path: str
    snapshot_id: int
    function_ea: int
    function_name: str | None
    kind: DiagnosticGraphKind

@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphNode:
    model_id: str
    label: str
    category: str
    anchor_ea: int | None
    hint_fields: tuple[tuple[str, str], ...]
    record_refs: tuple[DiagnosticRecordRef, ...]
    expandable: bool = False

@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphEdge:
    model_id: str
    source_model_id: str
    target_model_id: str
    category: str
    label: str | None
    hint_fields: tuple[tuple[str, str], ...]
    record_refs: tuple[DiagnosticRecordRef, ...]

@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphGroup:
    model_id: str
    label: str
    member_node_ids: tuple[str, ...]
    record_refs: tuple[DiagnosticRecordRef, ...]
    anchor_ea: int | None

@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraph:
    context: DiagnosticGraphContext
    nodes: tuple[DiagnosticGraphNode, ...]
    edges: tuple[DiagnosticGraphEdge, ...]
    expanded_group: DiagnosticGraphGroup | None
    warnings: tuple[str, ...]
    status: str

@dataclasses.dataclass(frozen=True, slots=True)
class DiagnosticGraphProjectionRequest:
    context: DiagnosticGraphContext
    primary_records: tuple[DiagnosticRecord, ...]
    block_records: tuple[DiagnosticRecord, ...] = ()
    expanded_state_model_id: str | None = None

def record_ref(record: DiagnosticRecord) -> DiagnosticRecordRef: ...
def anchored_block_model_id(serial: int, anchor_ea: int) -> str: ...
def node_ids_for_record(
    graph: DiagnosticGraph, reference: DiagnosticRecordRef
) -> tuple[str, ...]: ...
~~~

~~~python
# src/d810/diagnostics/workbench_graph_projection.py
def project_block_cfg(request: DiagnosticGraphProjectionRequest) -> DiagnosticGraph: ...
def project_state_machine(request: DiagnosticGraphProjectionRequest) -> DiagnosticGraph: ...
def project_diagnostic_graph(request: DiagnosticGraphProjectionRequest) -> DiagnosticGraph: ...
~~~

~~~python
# src/d810/diagnostics/workbench_graph_controller.py
class DiagnosticGraphRecordPort(Protocol):
    def records(
        self, path: str, snapshot_id: int, kind: str
    ) -> tuple[DiagnosticRecord, ...]: ...

class DiagnosticGraphNavigationPort(Protocol):
    def navigate(self, ea: int) -> None: ...

class DiagnosticGraphViewPort(Protocol):
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
    def __init__(
        self,
        records: DiagnosticGraphRecordPort,
        navigation: DiagnosticGraphNavigationPort,
        view: DiagnosticGraphViewPort,
    ) -> None: ...
    def context_for_explorer(
        self,
        *,
        database_path: str,
        snapshot_id: int,
        function_ea: int,
        function_name: str | None,
        view_value: str,
    ) -> DiagnosticGraphContext | None: ...
    def open(self, context: DiagnosticGraphContext) -> None: ...
    def update_context(self, context: DiagnosticGraphContext) -> None: ...
    def clear_for_unsupported_view(self) -> None: ...
    def select_record(self, record: DiagnosticRecord | None) -> bool: ...
    def toggle_state(self, state_model_id: str) -> None: ...
    def jump_node(self, model_id: str) -> None: ...
    def close(self) -> None: ...
~~~

The existing WorkbenchDiagnosticsAdapter satisfies both controller ports after its existing records() result annotation is narrowed to tuple[DiagnosticRecord, ...]. Do not add methods to the adapter.

---

### Task 1: Establish immutable graph data and canonical source identities

**Files:**
- Create: src/d810/diagnostics/workbench_graph_models.py
- Create: tests/unit/diagnostics/test_workbench_graph_models.py
- Modify: src/d810/ui/workbench_diagnostics_commands.py
- Modify: tests/unit/ui/test_workbench_diagnostics_commands.py

**Interfaces:**
- Consumes: DiagnosticRecord, DiagnosticField, DiagnosticViewKind from d810.diagnostics.workbench_models.
- Produces: every locked model and helper used by Tasks 2-6.

- [ ] **Step 1: Write failing pure-model tests**

~~~python
def test_anchored_block_identity_and_record_lookup_are_deterministic() -> None:
    context = DiagnosticGraphContext(
        database_path="/tmp/diag.sqlite3",
        snapshot_id=17,
        function_ea=0x180012B60,
        function_name="target",
        kind=DiagnosticGraphKind.BLOCK_CFG,
    )
    ref = DiagnosticRecordRef("blocks", 17, 7)
    graph = DiagnosticGraph(
        context=context,
        nodes=(
            DiagnosticGraphNode(
                model_id=anchored_block_model_id(7, 0x180012C9F),
                label="blk7@0x180012C9F",
                category="block",
                anchor_ea=0x180012C9F,
                hint_fields=(),
                record_refs=(ref,),
            ),
        ),
        edges=(),
        expanded_group=None,
        warnings=(),
        status="Block CFG | diag.sqlite3 | snapshot 17 | target@0x180012B60",
    )
    assert anchored_block_model_id(7, 0x180012C9F) == "block:blk7@0x180012C9F"
    assert node_ids_for_record(graph, ref) == ("block:blk7@0x180012C9F",)
~~~

Add tests that two nodes containing the same record reference return in model order, duplicate node/edge IDs raise ValueError, and an edge with a missing endpoint raises ValueError.

- [ ] **Step 2: Run the new tests before implementation**

Run: pytest tests/unit/diagnostics/test_workbench_graph_models.py -q

Expected: collection fails because workbench_graph_models does not exist.

- [ ] **Step 3: Implement models and invariants**

~~~python
def record_ref(record: DiagnosticRecord) -> DiagnosticRecordRef:
    return DiagnosticRecordRef(
        source_table=record.source_table,
        snapshot_id=int(record.snapshot_id),
        ordinal=int(record.ordinal),
    )

def anchored_block_model_id(serial: int, anchor_ea: int) -> str:
    return f"block:blk{int(serial)}@0x{int(anchor_ea):X}"

def node_ids_for_record(
    graph: DiagnosticGraph, reference: DiagnosticRecordRef
) -> tuple[str, ...]:
    return tuple(
        node.model_id for node in graph.nodes if reference in node.record_refs
    )
~~~

Use frozen/slotted dataclasses. In DiagnosticGraph.__post_init__, reject duplicate node IDs, duplicate edge IDs, missing edge endpoints, and an expanded group with duplicated/missing members. The module imports only dataclasses, enum, collections.abc, d810.core.typing, and d810.diagnostics.workbench_models.

Narrow WorkbenchDiagnosticsAdapter.records() to return tuple[DiagnosticRecord, ...] while retaining its current allowlisted DiagnosticViewKind lookup.

- [ ] **Step 4: Run model and adapter tests**

Run: pytest tests/unit/diagnostics/test_workbench_graph_models.py tests/unit/ui/test_workbench_diagnostics_commands.py -q

Expected: PASS; the existing adapter test still sees DiagnosticViewKind.BLOCKS at the state facade.

- [ ] **Step 5: Commit**

~~~bash
git add src/d810/diagnostics/workbench_graph_models.py \
  src/d810/ui/workbench_diagnostics_commands.py \
  tests/unit/diagnostics/test_workbench_graph_models.py \
  tests/unit/ui/test_workbench_diagnostics_commands.py
git commit -m "feat(diagnostics): add immutable graph models"
~~~

### Task 2: Project complete anchored Block CFG evidence

**Files:**
- Create: src/d810/diagnostics/workbench_graph_projection.py
- Create: tests/unit/diagnostics/test_workbench_graph_projection.py

**Interfaces:**
- Consumes: Task 1 models plus normalized block DiagnosticRecord values.
- Produces: project_block_cfg() and project_diagnostic_graph() for Block CFG.

- [ ] **Step 1: Write failing Block CFG tests from normalized records**

~~~python
def test_block_cfg_projects_anchored_nodes_and_only_evidenced_edges() -> None:
    graph = project_block_cfg(
        DiagnosticGraphProjectionRequest(
            context=_context(DiagnosticGraphKind.BLOCK_CFG),
            primary_records=(
                _block("blocks", 1, serial="blk7@0x180012C9F",
                       succs="blk8@0x180012D10"),
                _block("blocks", 2, serial="blk8@0x180012D10", succs=""),
            ),
        )
    )
    assert [node.label for node in graph.nodes] == [
        "blk7@0x180012C9F", "blk8@0x180012D10"
    ]
    assert [(edge.source_model_id, edge.target_model_id) for edge in graph.edges] == [
        ("block:blk7@0x180012C9F", "block:blk8@0x180012D10")
    ]
~~~

The _block fixture constructs a DiagnosticRecord with kind BLOCKS, snapshot 17, and DiagnosticField(name, value, str(value)) fields.

Add tests:
- successor block absent: no edge and warning exactly Dangling CFG edge omitted: blk7@0x180012C9F -> blk8@0x180012D10;
- serial field has no anchored reference: no node and a warning that contains EA anchor unavailable but does not display bare blk7;
- reversed source order still returns sorted anchored node/edge output;
- snapshot mismatch is omitted with Record snapshot mismatch: blocks#<ordinal>;
- no trustworthy nodes returns empty graph with No trustworthy Block CFG records for this context.

- [ ] **Step 2: Run the Block CFG tests before implementation**

Run: pytest tests/unit/diagnostics/test_workbench_graph_projection.py -k block_cfg -q

Expected: FAIL because project_block_cfg is not defined.

- [ ] **Step 3: Implement normalized field decoding and strict projection**

~~~python
_BLOCK_REF = re.compile(r"\bblk(?P<serial>\d+)@(?P<ea>0[xX][0-9A-Fa-f]+)\b")

def _block_refs(value: object) -> tuple[tuple[int, int], ...]:
    return tuple(
        (int(match.group("serial")), int(match.group("ea"), 16))
        for match in _BLOCK_REF.finditer(str(value or ""))
    )
~~~

Implement _field_map(record) keyed by DiagnosticField.name. project_block_cfg:
1. requires BLOCK_CFG context;
2. considers only snapshot-matching records from source_table blocks;
3. creates exactly one anchored node per serial field with record_ref(record);
4. adds only unique successor relationships whose endpoints are projected nodes;
5. carries all original fields and source-table/snapshot/ordinal in node/edge hints;
6. sorts nodes by anchored model ID, edges by source/target/model ID;
7. status is Block CFG | <database basename> | snapshot <id> | <function-name-or-0xEA>, with | warnings: <count> when needed.

Do not synthesize a block for a dangling successor. project_diagnostic_graph dispatches BLOCK_CFG and raises ValueError for STATE_MACHINE until Task 3.

- [ ] **Step 4: Run projection tests**

Run: pytest tests/unit/diagnostics/test_workbench_graph_projection.py -q

Expected: PASS with only Block CFG cases present.

- [ ] **Step 5: Commit**

~~~bash
git add src/d810/diagnostics/workbench_graph_projection.py \
  tests/unit/diagnostics/test_workbench_graph_projection.py
git commit -m "feat(diagnostics): project anchored block cfg graphs"
~~~

### Task 3: Project State Machine evidence and enforce one expansion in pure logic

**Files:**
- Modify: src/d810/diagnostics/workbench_graph_projection.py
- Modify: tests/unit/diagnostics/test_workbench_graph_projection.py

**Interfaces:**
- Consumes: State Machine primary records and complete Block CFG records passed through DiagnosticGraphProjectionRequest.
- Produces: project_state_machine(), state-transition nodes/edges, one optional group, and dispatch for both graph kinds.

- [ ] **Step 1: Write failing State Machine evidence tests**

Construct normalized records for:
- state_cfg_nodes: state_hex, state_i64, entry_block, classification;
- state_cfg_node_blocks: state_hex, entry_block, block_serial, block_index, role;
- state_cfg_edges: edge_id, source_state_hex, target_state_hex, edge_kind, source_block, target_entry;
- blocks: anchored serial and succs fields.

~~~python
graph = project_state_machine(
    DiagnosticGraphProjectionRequest(
        context=_context(DiagnosticGraphKind.STATE_MACHINE),
        primary_records=(state_12, state_34, own_12, own_34, transition),
        block_records=(block_7, block_8),
    )
)
assert [node.category for node in graph.nodes] == ["state", "state"]
assert graph.nodes[0].expandable is True
assert graph.edges[0].category == "state_transition"
assert graph.expanded_group is None

expanded = project_state_machine(
    dataclasses.replace(
        request, expanded_state_model_id="state:0x12"
    )
)
assert expanded.expanded_group.member_node_ids == ("block:blk7@0x180012C9F",)
assert "block:blk7@0x180012C9F" in {node.model_id for node in expanded.nodes}
~~~

Add cases for unknown expanded state, role exclusive/shared_suffix (never owned), owned record referencing unavailable block, transition with a missing state, terminal CONDITIONAL_RETURN/EXIT_ROUTINE with no target, and an input attempting to represent a second expansion. Assert warnings and no invented state/block edge.

- [ ] **Step 2: Run State Machine tests before implementation**

Run: pytest tests/unit/diagnostics/test_workbench_graph_projection.py -k state_machine -q

Expected: FAIL because project_state_machine is not defined.

- [ ] **Step 3: Implement canonical states and collapsed evidence**

~~~python
def _state_model_id(fields: Mapping[str, DiagnosticField]) -> str | None:
    value = fields.get("state_i64")
    if value is not None and value.value is not None:
        return f"state:0x{int(value.value):X}"
    value = fields.get("state_hex")
    if value is not None and str(value.value).strip():
        return f"state:{str(value.value).strip().upper()}"
    return None
~~~

Only state_cfg_nodes creates state nodes. state_cfg_node_blocks attaches role == owned anchored block identities to state hint fields and record refs; exclusive and shared_suffix never become group members. state_cfg_edges creates a state_transition only after both endpoint state nodes resolve. A targetless CONDITIONAL_RETURN or EXIT_ROUTINE may create terminal:<edge_id> only because the edge kind explicitly evidences a terminal; it has no guessed EA.

- [ ] **Step 4: Implement progressive native-ready group output**

For an expanded_state_model_id, require a current expandable state. Keep its state node and state transition edges, add its owned anchored block nodes from block_records, add only their internal evidenced CFG edges, and return:

~~~python
group = DiagnosticGraphGroup(
    model_id=f"group:{expanded_state_id}",
    label=f"{expanded_state.label} owned blocks",
    member_node_ids=tuple(sorted(owned_block_node_ids)),
    record_refs=tuple(sorted(ownership_refs, key=_record_ref_sort_key)),
    anchor_ea=expanded_state.anchor_ea,
)
~~~

A bad requested expansion returns collapsed graph plus Expanded state unavailable: <id>. There is one request field and one graph expanded_group, so the model makes multiple expansion unrepresentable.

Finish project_diagnostic_graph dispatch for both enum values.

- [ ] **Step 5: Run all projector tests**

Run: pytest tests/unit/diagnostics/test_workbench_graph_projection.py -q

Expected: PASS. Verify no assertion observes a bare block serial in labels, warnings, or hints.

- [ ] **Step 6: Commit**

~~~bash
git add src/d810/diagnostics/workbench_graph_projection.py \
  tests/unit/diagnostics/test_workbench_graph_projection.py
git commit -m "feat(diagnostics): project progressive state machine graphs"
~~~

### Task 4: Implement pure controller actions and one-way synchronization

**Files:**
- Create: src/d810/diagnostics/workbench_graph_controller.py
- Create: tests/unit/diagnostics/test_workbench_graph_controller.py

**Interfaces:**
- Consumes: Task 1 models, Task 3 projector, record/navigation/view ports.
- Produces: locked port protocols and DiagnosticGraphController.

- [ ] **Step 1: Write controller tests with fakes**

~~~python
class _Records:
    def __init__(self, values: dict[str, tuple[DiagnosticRecord, ...]]) -> None:
        self.values = values
        self.calls: list[tuple[str, int, str]] = []

    def records(self, path: str, snapshot_id: int, kind: str) -> tuple[DiagnosticRecord, ...]:
        self.calls.append((path, snapshot_id, kind))
        return self.values[kind]

class _View:
    def __init__(self) -> None:
        self.rendered: list[DiagnosticGraph] = []
        self.cleared: list[str] = []
        self.selected: list[str] = []
        self.focus_count = 0

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
~~~

Test:
1. opening Block CFG reads blocks only and renders/focuses one reusable fake view;
2. opening same context again focuses, not a new fake view;
3. select_record maps only existing output node and does not append render;
4. toggling state:0x12 then state:0x34 replaces one group; changing context clears expansion;
5. clear_for_unsupported_view clears No graph for this view;
6. reader/projector errors clear Graph unavailable: ... before retaining no stale graph;
7. jump_node navigates only an anchor-bearing model node;
8. controller has no record-selection output port, proving graph events cannot select Explorer rows.

- [ ] **Step 2: Run controller tests before implementation**

Run: pytest tests/unit/diagnostics/test_workbench_graph_controller.py -q

Expected: collection fails because workbench_graph_controller does not exist.

- [ ] **Step 3: Implement ports, controlled reads, and robust rebuild**

Implement context_for_explorer() as the sole mapping from Explorer values to a
typed context. It returns None unless view_value is blocks or state_machine;
otherwise it creates DiagnosticGraphContext with BLOCK_CFG or STATE_MACHINE,
respectively. The Explorer passes only primitives, so it stays free of direct
diagnostics model imports.

~~~python
def _records_for_context(
    self, context: DiagnosticGraphContext
) -> tuple[tuple[DiagnosticRecord, ...], tuple[DiagnosticRecord, ...]]:
    if context.kind is DiagnosticGraphKind.BLOCK_CFG:
        return self._records.records(
            context.database_path, context.snapshot_id, "blocks"
        ), ()
    if context.kind is DiagnosticGraphKind.STATE_MACHINE:
        return (
            self._records.records(context.database_path, context.snapshot_id, "state_machine"),
            self._records.records(context.database_path, context.snapshot_id, "blocks"),
        )
    raise ValueError("No graph for this view")
~~~

In __init__, bind only controller callbacks:

~~~python
self._view.bind_actions(
    toggle_state=self.toggle_state,
    jump_node=self.jump_node,
)
~~~

open() calls show_or_focus(), marks view active, stores context, resets expansion when evidence identity differs, and rebuilds. update_context() rebuilds only while active. clear_for_unsupported_view() resets graph/expansion and calls view.clear("No graph for this view").

- [ ] **Step 4: Implement selection, expansion, errors, navigation**

~~~python
try:
    primary_records, block_records = self._records_for_context(context)
    graph = project_diagnostic_graph(
        DiagnosticGraphProjectionRequest(
            context=context,
            primary_records=primary_records,
            block_records=block_records,
            expanded_state_model_id=self._expanded_state_model_id,
        )
    )
except Exception as exc:
    self._graph = None
    self._view.clear(f"Graph unavailable: {exc}")
    logger.warning(
        "Diagnostic graph unavailable kind=%s database=%s snapshot=%s function=0x%X: %s",
        context.kind.value, context.database_path, context.snapshot_id,
        context.function_ea, exc,
    )
    return
self._graph = graph
self._view.render(graph)
~~~

select_record() uses node_ids_for_record(graph, record_ref(record)) and selects only the first deterministic result. toggle_state() accepts only a current expandable State Machine node and toggles/replaces the one stored ID before rebuild. jump_node() looks up graph node by model_id and calls navigation.navigate() only if anchor_ea is not None.

- [ ] **Step 5: Run controller and projector tests**

Run: pytest tests/unit/diagnostics/test_workbench_graph_controller.py tests/unit/diagnostics/test_workbench_graph_projection.py -q

Expected: PASS.

- [ ] **Step 6: Commit**

~~~bash
git add src/d810/diagnostics/workbench_graph_controller.py \
  tests/unit/diagnostics/test_workbench_graph_controller.py
git commit -m "feat(diagnostics): add graph controller actions"
~~~

### Task 5: Implement a reusable thin native GraphViewer adapter

**Files:**
- Create: src/d810/ui/workbench_diagnostic_graph.py
- Create: tests/unit/ui/test_workbench_diagnostic_graph_contract.py

**Interfaces:**
- Consumes: DiagnosticGraph and Task 4 view port.
- Produces: IdaDiagnosticGraphView, the sole IDA rendering implementation.

- [ ] **Step 1: Write source-contract tests without importing IDA**

Parse the source with ast, like test_workbench_diagnostics_panel_contract.py.

~~~python
def test_native_graph_adapter_uses_only_the_ida_rendering_boundary() -> None:
    source = GRAPH.read_text(encoding="utf-8")
    assert "import ida_graph" in source
    assert "import ida_kernwin" in source
    assert "GraphViewer" in source
    assert "import sqlite3" not in source
    assert "d810.diagnostics.workbench_inventory" not in source
    assert "get_diagnostic_records" not in source

def test_adapter_has_refresh_hints_double_click_popup_and_groups() -> None:
    source = GRAPH.read_text(encoding="utf-8")
    for required in (
        "def OnRefresh", "def OnHint", "def OnDblClick", "def OnPopup",
        "AddNode", "AddEdge", "CreateGroups", "SetGroupsVisibility",
        "attach_dynamic_action_to_popup", "select_node", "show_or_focus",
    ):
        assert required in source
~~~

AST-assert OnHint uses .get() for its node map and returns None for unknown node IDs. This is the stale-callback defense used by the graphwork GraphViewer examples.

- [ ] **Step 2: Run contracts before implementation**

Run: pytest tests/unit/ui/test_workbench_diagnostic_graph_contract.py -q

Expected: FAIL because workbench_diagnostic_graph.py does not exist.

- [ ] **Step 3: Implement GraphViewer refresh and context card**

Use the GraphViewer lifecycle demonstrated by /Volumes/code/re/idapro/graphwork/PhatDatPQ__NoVmpy/novmpy/views/vtil_graph.py: retain maps, Clear(), AddNode(), AddEdge(), OnHint(), dynamic popup actions, and in-place refresh. Do not copy source or dependencies.

~~~python
class _DiagnosticGraphViewer(ida_graph.GraphViewer):
    TITLE = "d810-ng Diagnostics Graph"

    def __init__(self, owner: "IdaDiagnosticGraphView") -> None:
        super().__init__(self.TITLE, True)
        self._owner = owner
        self._model_to_id: dict[str, int] = {}
        self._id_to_model: dict[int, str] = {}

    def OnRefresh(self) -> bool:
        self.Clear()
        self._model_to_id.clear()
        self._id_to_model.clear()
        graph = self._owner.graph
        status_id = self.AddNode(self._owner.status_text())
        self._id_to_model[status_id] = "__status__"
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
        return True
~~~

IdaDiagnosticGraphView owns graph/message/viewer/callbacks. render() sets graph, clears message, show_or_focus(), then Refresh(). clear() sets graph None, stores visible message, ensures same viewer, Refresh(). status_text() returns graph.status plus each warning, or the clear message.

- [ ] **Step 4: Add safe hints, local selection, navigation callbacks, and popup action**

~~~python
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
~~~

hint_for("__status__") returns status. Other hints join immutable hint_fields and record references. select_node() uses model-to-IDA mapping plus IDA 9.3 GraphViewer selection/focus, returns False if missing, and never reaches Explorer code. OnPopup() attaches exactly one dynamic Expand owned blocks or Collapse owned blocks action only for an expandable selected model node. The action invokes the bound toggle_state(model_id) callback only.

- [ ] **Step 5: Implement native group realization**

~~~python
group_handles = viewer.CreateGroups(
    [{"nodes": member_ids, "text": graph.expanded_group.label}]
)
viewer.SetGroupsVisibility(group_handles, True)
~~~

member_ids must be mapped IDA node IDs corresponding to the single immutable group member_node_ids. If native grouping rejects its inputs, retain flat block nodes, append visible warning Native group unavailable: <error>, and do not add a second group or alter pure graph semantics. The exact IDA 9.3 return shape is proven in Task 7 before treating groups as complete.

- [ ] **Step 6: Run source contracts and commit**

Run: pytest tests/unit/ui/test_workbench_diagnostic_graph_contract.py -q

Expected: PASS without IDA, Qt, or IDAPython.

~~~bash
git add src/d810/ui/workbench_diagnostic_graph.py \
  tests/unit/ui/test_workbench_diagnostic_graph_contract.py
git commit -m "feat(ui): render diagnostics graphs in ida"
~~~

### Task 6: Wire Explorer context, action, one-way record centering, and teardown

**Files:**
- Modify: src/d810/ui/workbench_diagnostics_panel.py
- Modify: src/d810/ui/workbench_panel.py
- Modify: tests/unit/ui/test_workbench_diagnostics_panel_contract.py
- Create: tests/unit/ui/test_workbench_panel_contract.py
- Modify: Task 4 controller/test only to expose clear_for_unsupported_view().

**Interfaces:**
- Consumes: Task 4 controller and Task 5 adapter.
- Produces: one controller per Explorer, Open graph, context lifecycle, record centering, and companion closure.

- [ ] **Step 1: Write failing UI contracts**

In test_workbench_diagnostics_panel_contract.py assert:
- Open graph occurs in structured-record actions;
- methods _open_graph, _graph_context, _publish_graph_context, and _record_changed exist;
- panel calls .open, .update_context, .select_record, .clear_for_unsupported_view, and .close only on injected controller;
- panel source does not contain project_diagnostic_graph, sqlite3, d810.diagnostics.workbench_models, or d810.diagnostics.workbench_inventory;
- _refilter_records does not mention graph controller.

In test_workbench_panel_contract.py assert _show_diagnostics imports DiagnosticGraphController and IdaDiagnosticGraphView and passes graph_controller=controller to WorkbenchDiagnosticsPanel.

- [ ] **Step 2: Run UI contracts before implementation**

Run: pytest tests/unit/ui/test_workbench_diagnostics_panel_contract.py tests/unit/ui/test_workbench_panel_contract.py -q

Expected: FAIL because no graph wiring exists.

- [ ] **Step 3: Construct/inject exactly one controller**

~~~python
from d810.diagnostics.workbench_graph_controller import DiagnosticGraphController
from d810.ui.workbench_diagnostic_graph import IdaDiagnosticGraphView

graph_view = IdaDiagnosticGraphView()
controller = DiagnosticGraphController(adapter, adapter, graph_view)
panel = WorkbenchDiagnosticsPanel(
    adapter,
    function_ea=self._func_ea,
    function_name=self._func_name or None,
    graph_controller=controller,
)
~~~

Place this in DeobfuscationWorkbenchPanel._show_diagnostics after constructing the existing adapter. Preserve closing the previous Diagnostics panel first.

- [ ] **Step 4: Add compact Open graph and complete-context builder**

Add optional keyword-only function_name: str | None = None and graph_controller: typing.Any = None to WorkbenchDiagnosticsPanel. Add self.open_graph_button = QtWidgets.QPushButton("Open graph"), connect it to _open_graph, and place it beside the existing two jump buttons.

_graph_context() returns None unless current database is readable and current snapshot exists. It delegates graph-kind mapping to its injected controller:

~~~python
return self._graph_controller.context_for_explorer(
    database_path=str(database.path),
    snapshot_id=int(snapshot.snapshot_id),
    function_ea=int(snapshot.function_ea),
    function_name=self._function_name,
    view_value=view_value,
)
~~~

_open_graph opens only a non-None context; otherwise disable button and set record_detail to Select a readable database, snapshot, and supported view before opening a graph.

- [ ] **Step 5: Publish context only after new evidence and center only selection**

_publish_graph_context() runs at the end of _load_records after the current database/snapshot/view identity has changed. It calls update_context(context) when valid; when graph is active and current view unsupported, calls clear_for_unsupported_view(). It never runs from _refilter_records.

In _record_changed():

~~~python
if self._graph_controller is not None:
    self._graph_controller.select_record(
        None if row is None else row.record
    )
~~~

OnClose() calls self._graph_controller.close() before clearing references. Do not add graph callbacks that set record_tree selection.

- [ ] **Step 6: Run UI/Diagnostics regression selection**

Run:
~~~bash
pytest \
  tests/unit/ui/test_workbench_diagnostics_panel_contract.py \
  tests/unit/ui/test_workbench_panel_contract.py \
  tests/unit/diagnostics/test_workbench_graph_controller.py \
  tests/unit/ui/test_workbench_diagnostics_logic.py \
  tests/unit/ui/test_workbench_diagnostics_commands.py \
  tests/unit/diagnostics/test_workbench_inventory.py -q
~~~

Expected: PASS; existing inventory, sorting, cleaner, and command adapter behavior stays unchanged.

- [ ] **Step 7: Commit**

~~~bash
git add src/d810/ui/workbench_diagnostics_panel.py \
  src/d810/ui/workbench_panel.py \
  src/d810/diagnostics/workbench_graph_controller.py \
  tests/unit/diagnostics/test_workbench_graph_controller.py \
  tests/unit/ui/test_workbench_diagnostics_panel_contract.py \
  tests/unit/ui/test_workbench_panel_contract.py
git commit -m "feat(ui): link diagnostics explorer to graph tab"
~~~

### Task 7: Verify grouping and complete live Docker/XQuartz acceptance

**Files:**
- Modify only if IDA 9.3 proves a real binding mismatch: src/d810/ui/workbench_diagnostic_graph.py
- Modify source contract only when such a correction needs pinning: tests/unit/ui/test_workbench_diagnostic_graph_contract.py
- Do not modify the launcher, samples, source diagnostic databases, or function override saves.

**Interfaces:**
- Consumes: Tasks 1-6, audited Docker/XQuartz launcher, mounted worktree.
- Produces: direct IDA evidence that rendering, grouping, one-way sync, failure clearing, and copy safety work.

- [ ] **Step 1: Run focused graph and Diagnostics tests**

~~~bash
pytest \
  tests/unit/diagnostics/test_workbench_graph_models.py \
  tests/unit/diagnostics/test_workbench_graph_projection.py \
  tests/unit/diagnostics/test_workbench_graph_controller.py \
  tests/unit/ui/test_workbench_diagnostic_graph_contract.py \
  tests/unit/ui/test_workbench_diagnostics_panel_contract.py \
  tests/unit/ui/test_workbench_panel_contract.py \
  tests/unit/ui/test_workbench_diagnostics_logic.py \
  tests/unit/ui/test_workbench_diagnostics_commands.py \
  tests/unit/diagnostics/test_workbench_inventory.py -q
~~~

Expected: PASS with no skipped graph semantics.

- [ ] **Step 2: Run static and architecture gates**

~~~bash
ruff check src/d810/diagnostics/workbench_graph_models.py \
  src/d810/diagnostics/workbench_graph_projection.py \
  src/d810/diagnostics/workbench_graph_controller.py \
  src/d810/ui/workbench_diagnostic_graph.py \
  src/d810/ui/workbench_diagnostics_panel.py \
  src/d810/ui/workbench_panel.py
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
graphify update .
~~~

Expected: every command exits 0. Resolve failures at the appropriate layer; do not add ignores.

- [ ] **Step 3: Record source sample integrity then launch the audited disposable session**

~~~bash
shasum -a 256 samples/bins/libobfuscated.dll.2026-06-03.i64
open -a XQuartz
/opt/X11/bin/xhost +localhost
tools/scripts/run_ida_gui_docker.sh \
  -w truthful-config-v2-project-ui \
  --open-workbench \
  --function 0x180012B60 \
  --mcp \
  -- /samples/bins/libobfuscated.dll.2026-06-03.i64
~~~

Expected: launcher audit names a .tmp/ida-gui copy, image label is org.d810.gui-runtime=x11-dev-emulation-z3-v1, D810 initializes, and source witness stays read-only.

- [ ] **Step 4: Prove the real IDA 9.3 group binding before trusting it**

After State Machine renders, use IDA Console or the existing loopback MCP py_eval capability to inspect the actual Python GraphViewer class:

~~~python
from d810.ui.workbench_diagnostic_graph import _DiagnosticGraphViewer
print(
    _DiagnosticGraphViewer.__mro__,
    hasattr(_DiagnosticGraphViewer, "CreateGroups"),
    hasattr(_DiagnosticGraphViewer, "SetGroupsVisibility"),
)
~~~

Expected: both capabilities are present. Trigger Expand owned blocks using the popup. If CreateGroups returns a handle form different from the IDAPython declaration, change only IdaDiagnosticGraphView.realize_group() to feed that actual handle form to SetGroupsVisibility; preserve the pure DiagnosticGraphGroup and add a source-contract assertion.

- [ ] **Step 5: Execute and capture the acceptance matrix**

| Action | Required result |
| --- | --- |
| Select Blocks then Open graph | One d810-ng Diagnostics Graph tab; status names Block CFG, database basename, snapshot, function EA. |
| Inspect Block CFG | Every block node has blk<serial>@0x<EA>; every edge is selected-snapshot evidence. |
| Select a block record | Existing graph centers/selects matching node without rebuild or new tab. |
| Change record filter | Explorer rows change; graph topology does not. |
| Select State machine | Same tab shows collapsed states/transitions and visible warnings. |
| Expand state, then another state | Exactly one labeled owned-block group is visible; first expansion collapses. |
| Double-click anchored node | IDA jumps to its explicit EA; terminal/status node does not jump. |
| Click graph node/edge | Graph-local hint/selection changes; Explorer row remains unchanged. |
| Change database/snapshot | Same tab changes context/topology and expansion clears. |
| Select Facts/other unsupported view | Topology clears, status visibly says No graph for this view. |
| Induce disposable read/projection failure | Old graph clears before Graph unavailable: ...; database remains untouched. |

Use D810.reload() for code reloads in the current process rather than starting a second plugin instance. Save Block CFG, collapsed State Machine, expanded State Machine, and cleared-unsupported screenshots under .tmp/ida-gui/.

- [ ] **Step 6: Recheck integrity, full unit suite, and final static gates**

~~~bash
shasum -a 256 samples/bins/libobfuscated.dll.2026-06-03.i64
pytest tests/unit -q
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
git diff --check
graphify update .
git status --short
~~~

Expected: final SHA-256 equals the Step 3 value; all tests/gates pass; only ignored .tmp/ida-gui artifacts are generated. If Task 7 needs no correction, preserve the task commits from Tasks 1-6 without an empty verification commit.

## Plan Self-Review

### Spec coverage

| Approved requirement | Tasks |
| --- | --- |
| Two supported graph kinds | 2, 3, 6, 7 |
| Pure model/projector/controller seam | 1, 2, 3, 4 |
| Anchored blocks and evidence-only topology | 1, 2, 3, 7 |
| One reusable native graph tab/status | 4, 5, 6, 7 |
| Explorer-driven one-way synchronization | 4, 6, 7 |
| Record centering without rebuild/filter topology change | 4, 6, 7 |
| Local graph interaction and anchor jump | 4, 5, 7 |
| Single progressive State Machine expansion | 3, 4, 5, 7 |
| Cleaner/inventory unchanged | 6, 7 |
| Docker/XQuartz disposable witness | 7 |
| Future full two-way sync excluded | Global constraints, controller ports, 6 |

### Placeholder scan

Every task names exact paths, public interfaces, test cases, commands, expected outcomes, and commit contents. The sole runtime conditional is the documented IDA 9.3 CreateGroups return shape; it permits a correction only in IdaDiagnosticGraphView.realize_group() and preserves the pure model contract.

### Type consistency

- record_ref() creates DiagnosticRecordRef in Task 1; Tasks 2-4 consume that same type.
- Task 4 loads DiagnosticGraphProjectionRequest.primary_records/block_records and Tasks 2-3 project them.
- Task 4 binds the exact callbacks Task 5 implements through DiagnosticGraphViewPort.
- Task 6 injects one IdaDiagnosticGraphView and DiagnosticGraphController built from the existing WorkbenchDiagnosticsAdapter.
- No IDA object crosses into diagnostics; no raw record/database query crosses into the UI adapter.
