# Diagnostics Native Graphs Design

**Status:** Approved design | **Date:** 2026-07-17

## 1. Executive decision

The Diagnostics Explorer will render two existing structured diagnostic views
as native IDA graphs:

1. Block CFG
2. State Machine

The feature uses one reusable, live-linked `ida_graph.GraphViewer` tab. The
Diagnostics Explorer controls the graph context. Structured-record selection
can center the corresponding graph node, graph selection remains local to
the graph, and double-click jumps to an available EA anchor.

Graph construction will not live in Qt or the IDA adapter. Pure projectors
convert normalized diagnostic records into an IDA-independent graph model. A
thin adapter renders that model and forwards graph actions. This follows the
existing D810 action-logic pattern and keeps graph semantics directly
unit-testable outside IDA.

## 2. Goal

Let a reverse engineer move from structured diagnostic records to the topology
those records describe without leaving IDA or querying SQLite manually.

The graph must remain visibly bound to its evidence context: database,
snapshot, function, and graph kind. It must not infer missing evidence or leave
a stale graph visible after a context or projection failure.

## 3. Scope

### 3.1 Included

- A native Block CFG projected from normalized block diagnostic records.
- A native State Machine graph projected from state, transition, ownership,
  and related block records.
- Progressive State Machine expansion: state-centric by default, with one
  state expanded into its owned block subgraph at a time.
- One reusable native graph tab that switches graph kind and context in place.
- Live, explorer-driven synchronization.
- Record-to-graph centering where a structured record maps to a projected node.
- Local graph hints and context actions.
- Double-click jump to an explicit EA anchor.
- Pure model, projector, and controller tests plus Docker/XQuartz acceptance
  testing in IDA 9.3.

### 3.2 Excluded

- Graphs for Modifications, Facts, Conflicts, Provenance, Instructions, or
  Rendered Programs.
- A general SQL console or arbitrary table graphing.
- Graph editing or mutation of diagnostic data.
- Graph-to-explorer record selection.
- Multiple native graph tabs or a new tab per snapshot.
- More than one expanded state at a time.
- Authoring passes, transforms, or Python implementations in IDA.

## 4. Approved product behavior

### 4.1 Graph kinds

The first release supports exactly two graph kinds.

#### Block CFG

The graph shows the complete projected control-flow topology for the selected
function and snapshot. Each block node includes both its snapshot-local block
serial and stable EA anchor, for example `blk77@0x40ADE6`. A block serial is
never displayed by itself.

Node hints expose relevant structured fields and source-record identity. Edges
represent only control-flow relationships present in the selected diagnostic
evidence.

#### State Machine

The default view is state-centric: recovered states are nodes and recovered
state transitions are edges. State labels and hints summarize owned blocks and
available anchors without showing every block by default.

Any block identity included in a state label or hint includes both serial and
EA anchor. The stable-anchor rule applies to summaries as well as block nodes.

A graph context action expands the locally selected state into its owned block
subgraph. The expanded state is presented as a labeled group containing its
owned, anchored block nodes and their evidenced CFG relationships. Other states
remain collapsed. Expanding another state collapses the previous state; using
the action on the expanded state collapses it.

State expansion is cleared whenever database, snapshot, function, or graph kind
changes.

### 4.2 One reusable graph tab

The Diagnostics Explorer exposes an **Open graph** action for the Block CFG and
State Machine views. The action creates or focuses one reusable native IDA tab.
The tab updates in place instead of creating parallel tabs for each graph kind
or evidence context.

The tab title is stable so IDA can find and reuse it. Visible graph status must
identify:

- graph kind;
- diagnostic database;
- snapshot ID;
- function name when available;
- function entry EA; and
- projection warnings, if any.

The user must never need to infer which snapshot a displayed graph represents.

### 4.3 Explorer-driven synchronization

Synchronization is intentionally one-way in the initial implementation:

- Changing database, snapshot, function, or supported diagnostics view rebuilds
  the graph while its tab is open.
- Selecting a structured record centers and locally selects its corresponding
  graph node when the record has a node mapping.
- Selecting a graph node changes only graph-local focus and displays its hint.
- Selecting a graph edge changes only graph-local focus and displays its hint
  when the IDA binding exposes that interaction.
- Double-clicking an anchored graph node jumps to the anchor in IDA.
- Graph selection never changes the structured-record selection.

Changing only the structured-record text filter does not change graph topology.
Filters are discovery aids; the graph represents the complete normalized
evidence set for the selected database, snapshot, function, and graph kind.

When the explorer moves to an unsupported diagnostics view, the open graph tab
clears the previous graph and displays an explicit `No graph for this view`
state. It must not retain the last supported graph.

## 5. Architecture

### 5.1 Selected approach

The selected pipeline is:

```text
normalized DiagnosticRecord sets
    -> pure BlockCfgProjector or StateMachineProjector
    -> immutable DiagnosticGraph
    -> thin ida_graph.GraphViewer adapter
```

This separates diagnostics semantics from rendering and makes graph behavior
testable without Qt, SQLite, or IDA.

### 5.2 Rejected alternatives

#### Return UI-ready graphs from the diagnostics inventory

This would centralize data access, but it would make the read-only inventory
responsible for a particular UI representation. The inventory should continue
to normalize and expose records; graph projection is a separate consumer.

#### Infer topology inside `GraphViewer`

This initially requires fewer types, but it couples diagnostic table schemas,
record interpretation, IDA node IDs, rendering, and callbacks. It would be
difficult to unit-test and would recreate the UI-logic coupling this project is
already removing.

## 6. Pure graph model

The pure graph layer contains no imports from Qt, `ida_graph`, `ida_kernwin`, or
SQLite. Its public concepts are:

### 6.1 `DiagnosticGraphContext`

Identifies the exact evidence boundary:

- canonical diagnostic database identity;
- snapshot ID;
- function EA;
- optional function name; and
- graph kind.

### 6.2 `DiagnosticGraphNode`

Contains:

- stable model ID within the graph context;
- display label;
- semantic category;
- optional EA anchor;
- structured hint fields;
- zero or more source-record references; and
- whether the node represents an expandable state.

A source-record reference identifies the source table and record within the
selected context. It supports current record-to-graph centering and leaves a
clean model seam for possible future reverse synchronization.

### 6.3 `DiagnosticGraphEdge`

Contains:

- stable model ID;
- source and destination model IDs;
- semantic category;
- optional label;
- structured hint fields; and
- zero or more source-record references.

An edge whose endpoint is not present is not valid graph output.

### 6.4 `DiagnosticGraphGroup`

Describes an expanded state group independently of IDA:

- group model ID;
- state label;
- member node IDs;
- source-record references; and
- optional state anchor.

The IDA adapter may realize this through native graph grouping, but all
ownership decisions and group membership come from the pure projector.

### 6.5 `DiagnosticGraph`

Contains the context, ordered nodes, ordered edges, optional expanded group,
warnings, and a human-readable status summary. Ordering is deterministic so
tests and refreshes are stable.

## 7. Projection

### 7.1 Projection request

A projection request contains:

- one `DiagnosticGraphContext`;
- the complete normalized records required for that graph kind; and
- an optional expanded state model ID.

The controller obtains records through the existing read-only diagnostics
inventory. Projectors do not open database connections and do not know file
paths beyond the context identity they receive.

### 7.2 Block CFG projector

The Block CFG projector:

1. admits only records belonging to the selected snapshot and function;
2. derives block nodes only from records with sufficient block identity;
3. formats every block identity with its EA anchor;
4. derives only evidenced control-flow edges;
5. attaches source-record references to projected elements;
6. produces deterministic node and edge ordering; and
7. reports incomplete or contradictory records as warnings.

It does not synthesize a missing block to satisfy a dangling edge.

### 7.3 State Machine projector

The State Machine projector:

1. derives collapsed state nodes from recovered state records;
2. derives state edges from recovered transition records;
3. associates ownership records with states and blocks;
4. summarizes owned blocks in collapsed state hints;
5. replaces the requested expanded state presentation with a labeled group of
   its evidenced block nodes and internal CFG edges;
6. preserves state-level transitions to and from the expanded presentation;
7. rejects an expanded state ID that does not belong to the current context;
   and
8. reports incomplete ownership or transition evidence without inventing it.

The projector accepts at most one expanded state ID. Single-expansion behavior
is therefore enforced in pure logic rather than only by a UI callback.

## 8. Controller and IDA adapter

### 8.1 Pure controller/action logic

Controller logic owns state transitions, not widgets. It receives abstract
inventory and graph-view ports and decides when to:

- open or focus the reusable graph;
- choose a projector;
- rebuild after an evidence-context change;
- center a graph node after explorer record selection;
- expand or collapse one state;
- clear the graph for unsupported or failed contexts; and
- request an anchored IDA jump.

Record selection centers existing graph output without reprojecting the graph.
Context and expansion changes reproject it.

### 8.2 Thin `ida_graph.GraphViewer` adapter

The native adapter owns only IDA-specific behavior:

- model-ID to IDA-node-ID mapping;
- `AddNode` and `AddEdge` calls;
- native group creation or visibility;
- refresh and focus operations;
- node and edge text and hints;
- graph popup command forwarding;
- local selection tracking; and
- double-click callback forwarding.

It must not inspect SQLite rows, decide block ownership, infer transitions, or
format evidence identities from raw database fields.

The adapter uses `ida_graph.GraphViewer` rather than drawing a graph in Qt.

### 8.3 Explorer integration

The existing Diagnostics Explorer remains responsible for database, snapshot,
function, view, and record selection. It publishes a normalized graph context
to the graph controller while the graph tab is open.

The graph feature does not change cleaner behavior, cleanup plans, database
sorting, snapshot sorting, or read-only inventory behavior.

## 9. Failure and evidence safety

The graph is explanatory evidence, so ambiguous failure must be visible.

- Missing optional records produce a partial graph with visible warnings.
- An individual record with insufficient node identity is omitted and reported.
- A missing required source set, or a context with no trustworthy node
  identity, produces an explicit unavailable state.
- Dangling edges are omitted and reported.
- A block record without an EA anchor is omitted and reported because block
  serials cannot stand alone. Other unanchored node kinds remain visible but
  disable jumping; no address is guessed.
- Read or projection failures clear the previous graph before showing the
  current error.
- Unsupported views clear stale topology and show an explicit empty state.
- An invalid expanded state is cleared and reported.
- If native graph support is unavailable, the action fails visibly without
  repeated modal dialogs.
- Graph operations never mutate the diagnostic database or its WAL files.

The controller logs enough context to diagnose a failure: graph kind, database,
snapshot, and function EA. It must not report a block serial without its EA
anchor.

## 10. Testing strategy

### 10.1 Pure model and projector tests

Tests cover:

- deterministic model IDs and ordering;
- anchored block labels;
- Block CFG nodes and edges;
- state nodes and transitions;
- state ownership summaries;
- collapsed and expanded State Machine output;
- exactly one expanded state;
- source-record references;
- record-to-node lookup;
- missing anchors;
- dangling edges;
- incomplete ownership;
- invalid expanded-state requests; and
- warning and unavailable-state behavior.

Fixtures use normalized diagnostic records, not Qt widgets or live SQLite
connections.

### 10.2 Pure controller/action tests

Fake inventory and graph-view ports verify:

- one graph instance is reused;
- open focuses an existing tab;
- supported context changes rebuild;
- record selection centers without rebuilding;
- graph-local selection does not alter explorer selection;
- expansion replaces the previous expanded state;
- context changes clear expansion;
- unsupported views clear stale graphs;
- read and projection errors clear stale graphs; and
- anchored jumps are requested only when an anchor exists.

These tests follow the same pure action-logic boundary used by the other new
D810 UI surfaces.

### 10.3 IDA adapter tests

Adapter-focused tests or source contracts cover:

- model-to-IDA node mapping;
- edge mapping;
- hint rendering;
- reusable-tab behavior;
- group command forwarding;
- refresh and centering calls; and
- double-click forwarding.

They do not duplicate projector semantics.

### 10.4 Live Docker/XQuartz acceptance

The final acceptance pass uses the dependency-complete IDA 9.3 X11 image, the
mounted target worktree, and a disposable copy of
`samples/bins/libobfuscated.dll.i64`. The source sample and its database are not
modified.

The live pass verifies:

1. D810 initializes and can be refreshed with `D810.reload()`.
2. Diagnostics opens against generated SQLite evidence.
3. Open graph creates one native tab.
4. Block CFG renders anchored nodes and evidenced edges.
5. State Machine renders collapsed states and transitions.
6. One state expands into owned blocks; expanding a second collapses the first.
7. Explorer context changes update the same tab.
8. Explorer selection of a node-backed record centers the matching graph node.
9. Graph selection does not alter the structured-record selection.
10. Double-click jumps to the explicit EA anchor.
11. Unsupported views and errors do not leave stale topology visible.

## 11. Acceptance criteria

The feature is complete when:

- both approved graph kinds render from normalized diagnostic evidence;
- graph semantics are implemented in pure, directly tested projectors;
- one reusable native IDA graph tab is live-linked to explorer context;
- one-way explorer-driven synchronization behaves as specified;
- progressive State Machine expansion enforces one expanded state;
- every displayed block serial includes an EA anchor;
- missing evidence is warned about rather than inferred;
- stale topology is cleared on unsupported or failed contexts;
- existing diagnostics and cleaner tests remain green;
- architecture boundary checks remain green; and
- the Docker/XQuartz acceptance pass succeeds on the disposable sample copy.

## 12. Future exploration: full two-way synchronization

A later design may upgrade synchronization to full two-way behavior:

- diagnostics selection rebuilds or centers the graph;
- graph selection highlights the corresponding structured record; and
- double-click continues to jump to the anchored EA.

The pure model includes source-record references so this can be explored
without moving topology inference into the IDA adapter. This section is not an
initial-release requirement. The current implementation must remain
explorer-driven and must not change structured-record selection from graph
clicks.
