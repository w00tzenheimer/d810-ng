---
id: tcvpu-313q
status: closed
deps: []
links: []
created: 2026-07-17T21:26:05Z
type: feature
priority: 2
assignee: w00tzenheimer
tags: [ui, configuration]
---
# Make D-810 configuration selection scalable

Replace the flat project-name combobox with a scalable configuration picker that supports fast filtering and makes source/runtime config-v2 routing understandable. Preserve current selection, all project operations, and index-based state loading.

## Acceptance Criteria

Large configuration inventories are searchable without opening a full flat menu; config-v2 source/runtime relationships are legible; selecting an item still loads the exact ProjectManager project; unit/UI contract tests and native IDA/X11 presentation are checked.


## Notes

**2026-07-17T21:28:09Z**

Decision: every JSON project discovered in the configured folder remains directly selectable. The redesign must improve discovery and make source/runtime relationships legible, not hide or exclude generated config-v2 canaries.

**2026-07-17T21:53:49Z**

User approved the searchable-picker design and explicitly requested direct implementation plus inspection in the native IDA/XQuartz GUI. Design and implementation plan were written; proceeding inline under the approved scope.

**2026-07-17T22:22:52Z**

Implemented searchable D-810 configuration picker. All 80 discovered JSON configurations are selectable; v2 source/runtime pairs are labeled but not hidden. Native XQuartz validation captured full catalog and filtered O-LLVM source/runtime pair. Focused picker tests pass; full unit suite was green before the final column-width-only polish; ast-grep, import contracts, diff check, and graphify update are green.

**2026-07-17T22:28:20Z**

Follow-up native validation after D810.reload() found parentless PluginForm placement could put modal picker off-screen under XQuartz. Picker now falls back to QApplication.activeWindow(); exact configuration-button route opens visibly at 1080x662+350+233.
