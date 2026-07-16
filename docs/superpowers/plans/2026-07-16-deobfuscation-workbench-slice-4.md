# Deobfuscation Workbench - Slice 4 Headless Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` and
> `superpowers:test-driven-development`.

**Goal:** Provide a truthful, IDA-independent Recipe Composer backend for
ordered registered passes, complete function recipe saves, pure validation,
and existing-lifecycle apply commands while deferring Qt widgets and live IDA
acceptance.

**Architecture:** The operational registry exposes stable pass IDs plus
canonical `PipelineConfig` templates. `RecipeService` owns immutable catalog,
draft, validation, and command records. Draft operations always return a new
record, retain execution order, and rebuild `PassSpec` objects through the
registry before static contract preflight. A sibling `function_recipes`
persistence record stores the complete pipeline and provenance; it never
modifies `function_rules`, tags, or notes. Manager/state facades own persistence,
function-scoped invalidation, and one-shot lifecycle submission. Pure UI logic
projects/filter catalog and draft records without importing registries or Qt.

## Constraints

- Only registered stable pass IDs are addable. Transform names are explanatory
  children and never independent draft operations.
- Unknown pass IDs, invalid structured options, duplicate draft item IDs, and
  failed contract preflight block apply/save.
- Draft order is execution order. Search/sort affect catalog presentation only.
- A function recipe is a full pipeline with schema version and source/runtime
  provenance, not a project delta.
- Existing function rules, tags, notes, inference overlays, and their storage
  rows remain untouched and are applied inside the selected recipe.
- Project-profile save remains disabled; lossless config-v2 project serialization
  is Slice 5.
- Qt composition widgets and live IDA execution remain deferred by user direction.

### Task 1: Define immutable recipe records

Add `PassCatalogEntry`, `RecipePass`, `PipelineRecipeDraft`,
`RecipeValidation`, `RecipeDiagnostic`, `FunctionPipelineOverride`, and
generation-safe recipe command/result records under `d810.manager` with exact,
canonical JSON payloads and frozen collections.

### Task 2: Expose a truthful operational pass catalog

Extend `PassRegistry` with deterministic read-only ID/template discovery.
Register canonical templates for configured adapters and native state-machine
passes. Catalog records include the full contract manifest, structured option
payload, backend/safety metadata, owned legacy rules, and explanatory transform
children when declared.

### Task 3: Build the pure RecipeService

Create drafts from the effective runtime pipeline; add, remove, enable, disable,
reorder, and replace structured options immutably; rebuild all enabled specs
through the registry; run ordered contract preflight after every operation; and
serialize the complete recipe deterministically. Never auto-insert or reorder.

### Task 4: Add sibling persistence and manager ownership

Add function-recipe get/set/clear methods to the storage protocol, SQLite, and
netnode backends. Persist the full recipe in a dedicated table/key. Add manager
and state facades that preserve existing function-rule records and emit a
function-scoped invalidation event after recipe save/clear.

### Task 5: Add apply-once and save command boundaries

Validate generation/function identity before and after callbacks. Apply once
invokes the existing deobfuscation lifecycle exactly once with the immutable
validated recipe. Save persists once, invalidates once, and requests one queued
refresh. Stale results cannot replace current workbench state.

### Task 6: Add pure recipe presentation logic

Project/filter/sort the catalog separately from ordered draft rows. Expose
selection detail, validation summaries, transform child labels, and action
enablement. Project-profile save remains explicitly disabled.

### Task 7: Verify

Run focused recipe/registry/persistence/action tests, full unit tests,
architecture gates, `git diff --check`, and `graphify update .`. Record exact
automated evidence and leave Qt/live acceptance open.
