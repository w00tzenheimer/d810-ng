---
id: tcvpu-qzth
status: closed
deps: [tcvpu-004o]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 2
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, config-v2, editing]
---
# Slice 5: v2-aware advanced project editing

Add structured serializers for explicitly supported config-v2 fields, pass/rule selection editing, routing overrides, and atomic validated save/reload.

## Acceptance Criteria

Only fields with declared serializers are editable; unsupported fields remain read-only; edits preserve the complete document, validate the full pass pipeline and routing policy, write atomically, and reload through the manager; no flat-rule semantic downgrade is possible.

## Implementation status (2026-07-16)

Complete through live Docker/XQuartz acceptance. A thin native editor exposes
only the declared description, ordered pass, pass-rule/options, and routing
serializers. The complete and unsupported document projections remain
read-only. Both D-810 Configuration and Recipe Composer own the editor, and
project-profile save is enabled only for a current valid recipe.

Live acceptance proved a six-pass configuration edit, a one-pass
`jump-fixer` recipe seed, deterministic `approov` to `tigress` routing, exact
Reset restoration, atomic validated save/reload, unchanged unsupported fields,
manager-start preservation, and complete disposable-file/project cleanup. The
description is a wrapped scrollable multiline editor, and all three docks use
compact grouped layouts.

Fresh verification: `156 passed` focused; `6143 passed, 29 skipped, 9 warnings,
162 subtests passed` full unit suite; no import cycles; ast-grep clean; 13 import
contracts kept; `git diff --check` clean.
