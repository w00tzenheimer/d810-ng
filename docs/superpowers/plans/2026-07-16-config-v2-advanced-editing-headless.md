# Config-v2 Advanced Editing - Slice 5 Headless Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` and
> `superpowers:test-driven-development`.

**Goal:** Finish the non-Qt project-profile workflow with lossless, explicitly
typed config-v2 edits, complete validation, atomic persistence, and state-owned
reload.

**Architecture:** A manager-owned `ConfigV2EditingService` reads the complete
runtime JSON document into an immutable revisioned draft. Its serializer
manifest exposes only description, ordered pipeline selection, per-pass rule
selection, and `router_resolution` policy. Every operation returns a new draft
and revalidates the complete pipeline through the operational pass registry,
the live hook bridge, and strict routing-policy validation. Persistence writes
a sibling temporary file, reloads and fully validates it, then atomically
replaces the destination. State registers the saved project and reloads it
through the normal project lifecycle. Pure UI logic only projects fields and
action enablement; Qt remains deferred.

## Constraints

- Every mutation starts from the complete runtime document; unknown top-level,
  additional-configuration, migration, contract, and option fields survive.
- Generic edits outside the declared serializer manifest are refused.
- Pass selection accepts registered pass IDs only and preserves explicit order.
- Rule include/exclude/options edits are scoped to one exact pass occurrence.
- Routing policy has exact `prefer`, `require`, and `deny` shapes and registered
  family names; conflicts fail validation.
- The document must remain `pipeline_v2_mode='config-v2'`, parse every pass,
  build every pass through the operational registry, and derive a valid live
  hook activation. No flat `ins_rules`/`blk_rules` downgrade is permitted.
- Save rejects stale draft/validation identity, validates the temporary reload,
  uses `os.replace`, and never damages the existing destination on failure.
- Qt widgets and live IDA interaction remain deferred by user direction.

### Task 1: Define immutable draft, serializer, validation, and result records

### Task 2: Implement complete-document structured edit operations

### Task 3: Validate registry, hook expansion, routing policy, and no downgrade

### Task 4: Add atomic validated persistence and recipe materialization

### Task 5: Add manager/state ownership and normal project reload

### Task 6: Enable project-profile action through pure UI logic

### Task 7: Run focused/full tests, architecture gates, and graph refresh
