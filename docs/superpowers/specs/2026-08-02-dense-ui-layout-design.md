# Dense D810 Configuration UI Layout Design

## Goal

Make the D-810 Configuration and Config-v2 Project Editor information-dense and readable at the dock sizes used by IDA on Windows, without changing any action, persistence, or editing behavior.

## Current problems

- The main configuration panel uses a fixed `450/750` rule/detail splitter. In a narrow dock, the rule tree and rule detail form both become too narrow.
- The Config-v2 editor gives the structured group and preserved document fixed vertical stretch ratios. The user cannot resize the two regions, and the nested manifest/pipeline/routing panes have no explicit initial sizes.
- Long metadata and action rows compete with the dense rule/pass content instead of being compact, bounded sections.

## Design

### Main D-810 Configuration

- Keep the project summary, rules, and engine sections in the existing vertical order.
- Give the project summary compact, explicit margins and minimum sizing so it does not grow when the dock grows.
- Make the rule tree/detail splitter user-resizable with minimum widths and a default 40/60 split. The detail pane receives the larger share because its option editors contain longer labels and controls.
- Keep the engine row compact and at the bottom; do not add a second status area or duplicate actions.

### Config-v2 Project Editor

- Keep the identity summary at the top and the final action row at the bottom.
- Replace the rigid structured/raw sibling stretch with a vertical splitter. Its initial sizes favor preserved-document reading space slightly (45% structured, 55% preserved), while allowing users to resize it.
- Give the typed structured splitter explicit 20/40/40 initial proportions for serializer manifest, ordered pipeline, and routing details. Apply minimum widths so the three columns do not collapse into unreadable strips.
- Keep description and pass controls compact: bounded description height, a stretchable catalog selector, and non-stretching action buttons.
- Preserve the existing read-only document tabs, status visibility behavior, adapter calls, signal connections, and save/validation semantics.

## Compatibility and safety

- Use only Qt APIs already available through `d810.qt_shim`, including PyQt5 and PyQt6 enum compatibility branches where needed.
- Do not add new dependencies or move policy out of the existing pure logic/adapter layers.
- The initial splitter sizes are hints only; users can resize them during a session and IDA may persist the dock geometry.

## Verification

- Extend source-level UI contract tests to assert the splitter hierarchy, stretch factors, minimum sizing, and explicit initial sizes.
- Run the targeted UI contract tests with `pyenv exec python -m pytest`.
- Run `sg scan --config sgconfig.yml --report-style short` and `PYTHONPATH=src lint-imports --config .importlinter` from this worktree.
