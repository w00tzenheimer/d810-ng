---
id: tcvpu-reh7
status: closed
deps: []
links: []
created: 2026-07-17T22:34:11Z
type: feature
priority: 2
assignee: w00tzenheimer
tags: [ui, config]
---
# Replace configuration dialog with anchored searchable dropdown

Replace the modal D-810 configuration picker with an anchored search popup modeled on a standard searchable select. Preserve stable project-index activation and all discovered JSON files.

## Acceptance Criteria

Current config control opens an anchored popup with a focused search field; filtering never loads a project; every discovered JSON remains selectable; selecting a visible entry loads its original manager index; native XQuartz validation covers the real configuration form.


## Notes

**2026-07-17T22:45:10Z**

Replaced the modal picker with ProjectPickerPopup, an anchored Qt.Popup with focused text search, filename-first results, routing hints, result count, stable original-index selection, and direct _load_config callback. Native XQuartz validated the real 80-item configuration form, filtered O-LLVM source/runtime pair (2 of 80), source selection closure, and visual dropdown affordance.
