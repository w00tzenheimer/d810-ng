# 2026-02-12 Rule Scope Cache Status

## Snapshot

Status relative to `2026-02-12-rule-scope-cache-plan.md`:

- Phase 1 (foundation): implemented.
- Phase 2 (hot-path flow integration): implemented for flow optimizer path.
- Phase 3 (overlay + persistence bridge): implemented with sqlite/netnode backends and function override invalidation.
- Phase 4 (UI analyst interaction): in progress, with function-scoped rules editor action now implemented.

## Implemented

1. Core rule scope service and cache structs.
- `src/d810/core/rule_scope.py`

2. Manager integration and compile lifecycle.
- `src/d810/manager.py`

3. Flow optimizer scoped lookup + perf counters.
- `src/d810/hexrays/hexrays_hooks.py`
- `tests/system/runtime/test_block_optimizer_perf_counters.py`

4. Function override persistence bridge and targeted invalidation.
- `src/d810/manager.py`
- `src/d810/ui/stats_dialog.py`

5. Netnode + sqlite persistence backends.
- `src/d810/core/persistence.py`
- `tests/system/runtime/test_netnode_wrapper.py`

6. Regression rules and CI enforcement for ast-grep.
- `rules/no-ui-direct-function-rule-storage.yml`
- `rules/no-legacy-optimizationstorage.yml`
- `.github/workflows/python.yml`

## Divergences Fixed In This Pass

1. Project-level invalidation emission on project load.
- Emits `RuleScopeEvent.PROJECT_RULES_RELOADED` in `D810State.load_project`.

2. IDB overlay reload invalidation emission.
- Emits `RuleScopeEvent.IDB_OVERLAY_RELOADED` when storage backend is initialized/reinitialized.

3. Phase 4 function-rules UI action (no longer stub).
- `src/d810/ui/actions/function_rules.py` now opens a rule editor dialog for the current function and saves overrides through manager APIs.

## Remaining Gaps

1. Instruction pipeline still does not consume `RuleScopeService` active bundles.
- Flow pipeline is scoped; instruction pipeline remains optimizer-internal.

2. Recipe/tag policy layer is defined in events but not yet fully wired to UI/persistence.
- `FUNCTION_TAGS_UPDATED`, `RECIPE_APPLIED`, `RECIPE_CLEARED` are defined but not actively emitted by analyst workflows yet.

3. Dedicated `idb_scope_store.py` module from design was replaced by persistence backends in `core/persistence.py`.
- Functionally covered, but architecture differs from the original file split.
