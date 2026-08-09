# D810 UI worklist

## Direction: Designer-authored Qt shell

Use a Qt Designer `.ui` file for stable D810 screens rather than constructing
the entire visual hierarchy imperatively in Python.  This is compatible with
IDA: IdaClu demonstrates the relevant shape -- a `.ui`-defined Qt widget tree,
generated Python `Ui_*` class, custom-widget placeholders, and a Python
controller that owns IDA actions and data binding.

This is a native Qt solution, not an embedded React application.  It gives us
the practical benefits we want from a component-oriented UI: a visual layout
tool, named regions, predictable spacing, and a stable composition boundary.

## First migration target: Deobfuscation Workbench

Define a static `deobfuscation_workbench.ui` shell with these named regions:

- Header/action row: function, protection classification, Deobfuscate Function,
  Build Deobfuscator, Diagnostics, and workspace controls.
- Collapsible left dossier: function identity, protection shape, case evidence,
  and diagnostic summary.
- Central workspace: stacked/collapsible maturity timeline regions with a
  `QGraphicsView` placeholder for the canvas.
- Collapsible right inspector: typed node/pass details, inputs/outputs,
  options, contract summary, evidence references, and raw-audit action.
- Compact footer: diagnostics-capture state, active maturity/counts, selected
  config, and engine state.

The `.ui` owns dimensions, splitters, margins, stretch factors, section shells,
and stable labels.  Python owns all data, state transitions, callback wiring,
and construction of runtime-only child widgets.

## Config-v2 editor shell

Move the fixed Config-v2 Builder / Pass Inspector shell into its own `.ui`
file after the Workbench shell is established:

- compact pipeline list and header actions;
- typed-options host populated from `PassEditorSpec`;
- transform-catalog host populated from the explicit pass-owned family tree;
- read-only contract/structured-JSON audit hosts;
- compact save/status footer.

Do not put pass behavior into Designer files.  A pass still supplies only its
closed `PassEditorSpec`; the Python renderer chooses from the small supported
control set.  No pass may inject arbitrary Qt code or define a user-authored
dialog.

## Static versus dynamic boundary

| Designer-owned | Python-owned |
| --- | --- |
| panes, splitters, headers, fixed controls, spacing, size policies | projections, IDA calls, actions, validation, save/reload |
| placeholder widgets and object names | `PassEditorSpec` typed controls |
| `QGraphicsView`/scroll-area containers | maturity canvas scene/nodes/edges |
| inspector section containers | transform family/subfamily tree and selection state |

Keep state and mutations Qt-free at the boundary: projections feed widgets;
widgets dispatch one explicit manager/adapter action; the manager remains the
only configuration authority.

## Generation and compatibility rules

- Commit both the human-authored `.ui` source and generated `ui_*.py` output.
  Treat the generated file as derived; edit the `.ui`, then regenerate.
- Use a project-owned generation/normalization step so imports go through
  `d810.qt_shim`, not a hard-coded `PyQt5` or `PySide6` import.
- Do not assume a runtime `QUiLoader`, Qt Designer executable, or one binding's
  generated code exists inside IDA.  Generate in development and ship the
  resulting Python source.
- Verify on IDA 9.1/PyQt5 and IDA 9.3/PySide6.  The same `.ui` shell must load
  and preserve splitter/collapse behavior under both bindings.
- Preserve a no-Qt import path for unit tests.  Test screen projections and
  actions outside Qt; use focused UI contract tests plus native IDA smoke tests
  for the generated shell.

## Canvas and node-editor work

- Use a native `QGraphicsScene`/`QGraphicsView` canvas for maturity timelines,
  node cards, ports, edges, pan/zoom, selection, and inspector focus.
- Continue evaluating NodeDataFlowEditor as a source of native Qt interaction
  patterns and reusable code under the author-granted permission.  Its C++ Qt
  implementation is not a drop-in Python dependency; wrap it deliberately or
  port the minimal needed behavior behind D810's own canvas model.
- Keep the canvas model independent of the renderer: maturity stages, node
  contracts, port types, edges, and selection should remain serializable pure
  records.

## React/browser exploration (not the current embedded plan)

React can still become an optional external Workbench client served from an
authenticated localhost endpoint.  It is not the embedded-IDA default:
our verified IDA 9.1/PyQt5 and 9.3/PySide6 runtimes do not ship a usable
QtWebEngine module.  Do not make an embedded browser a D810 requirement.

If revisited, the browser client must be read/write only through explicit
adapter actions, bind loopback only, use a per-session capability token, ship
local assets, and leave IDA/Python as the authority for decompilation and
mutation.

## Acceptance checklist

- [ ] Workbench `.ui` shell loads docked, floating, and detached in IDA 9.1
      and 9.3.
- [ ] Left/right panes collapse, restore, and retain splitter sizes across
      D810 reload.
- [ ] Maturity canvas remains usable at narrow and wide dock widths.
- [ ] Config-v2 typed editor has no raw free-form option editor as its primary
      interface.
- [ ] Every pass option is presented only through its declared
      `PassEditorSpec` control.
- [ ] Qt-free projection/action tests, UI contract tests, and native IDA
      smoke tests all pass before replacing an existing screen.
