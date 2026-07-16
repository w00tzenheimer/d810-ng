---
id: tcvpu-qzth
status: open
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

## Implementation status (2026-07-15)

Headless acceptance is implemented, including lossless rule metadata, bundled
overwrite protection, atomic validated save/reload, and live propagation of
project-level `router_resolution` into family selection. Fresh focused coverage
reported `164 passed`; the full unit suite reported `5891 passed, 29 skipped, 9
warnings, 162 subtests passed`. The ticket remains open for the deferred Qt
editors and live IDA acceptance.
