# L11: Operand / alias fixups

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L11). Harness: Phases 1-3.

## Goal
Lab-validate operand/alias lowering: when a reconstructed block references a value
through a stack alias or a non-scalar operand that Hex-Rays renders poorly,
promote/scalarize it so the render is clean.

## What d810 already has
`PromoteOperandToScalar` (`graph_modification.py:429`), `ScalarizeLocalAliasAccess`
(`:615`); `queue_promote_operand_to_scalar`,
`queue_scalarize_local_alias_access`.

## Gap
Our fixtures use plain scalars; the alias/operand ops are unvalidated in the lab.

## Approach
A fixture whose handler accesses a value via a stack alias / overlapping local;
apply `ScalarizeLocalAliasAccess` / `PromoteOperandToScalar` during the optblock
stage; assert the render uses a clean scalar (no `*(_DWORD *)&v` alias artifact).

## Fixture
`c/lab_flat_alias.c`: a handler that reads/writes through an aliased stack slot
(e.g. a `union`-style or pointer-to-local access) inside the flattened body.

## Success criteria
`mba.verify()` clean; render shows a scalar variable (no alias/memory-cast
artifact); semantics preserved. Observation recorded.

## Risks / IR-dump unknowns
Forcing the alias shape to survive to GLBOPT1 in C; the ops' exact applicability
conditions; may interact with lvar allocation maturity.

## Dependencies
P1. Lower priority (polish).
