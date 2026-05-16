#!/usr/bin/env python3
"""Generate the unflattening engine extension guide.

Default mode is dry-run. Use ``--apply`` to write the generated guide.
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path


GUIDE_PATH = Path(
    "src/d810/optimizers/microcode/flow/flattening/engine/EXTENSION_GUIDE.md"
)

GUIDE_TEXT = """# Unflattening Engine Extension Guide

This guide is the implementer contract for adding or migrating an unflattening
family into the shared engine. The architecture rationale lives in
`docs/unflattening-profile-architecture.md`; this file is the operational
checklist.

Generated and refreshed by:

```bash
python tools/scripts/codemod_unflattening_engine_extension_guide.py --apply
```

## Stable Shape

The shared engine is organized around this lifecycle:

```text
detect -> snapshot -> plan -> execute -> provenance
```

- `detect` is family-owned and read-only. It finds evidence, chooses a profile,
  and returns a detection result.
- `snapshot` converts detection evidence into immutable planner input.
- `plan` asks ordered strategies for `PlanFragment` instances and arbitrates
  conflicts.
- `execute` lowers accepted fragments through the shared executor and cfg
  modification pipeline.
- `provenance` records why each strategy was accepted, rejected, bypassed, or
  applied.

The lifecycle is deliberately narrower than the old generic dispatcher rule.
New behavior should enter as evidence, a profile, a strategy, a cfg primitive,
or a backend/materialization adapter. It should not add another direct live CFG
mutation path inside strategy code.

## Layer Contract

Use the lowest layer that owns the concept:

- `d810.recon` owns read-only analysis, source facts, transition facts, and
  observations. Recon code may emit observations; diagnostics subscribers
  persist them. Recon and behavior code must not directly read or write
  diagnostic SQLite.
- `d810.cfg` owns backend-neutral graph modifications, materialization payloads,
  planning fragments, and validation helpers. Add a cfg primitive when more
  than one family needs the same shape of edit.
- `d810.hexrays` owns Hex-Rays-specific materialization and verifier details.
  Engine strategies should not encode Hex-Rays mutation mechanics directly.
- `d810.optimizers.microcode.flow.flattening.engine` owns family orchestration,
  planning, execution, provenance, and shared strategy contracts.
- `d810.optimizers.microcode.flow.flattening.<family>` owns profile policy,
  detection details, and family-local heuristics that are not reusable yet.

## Adding A Family Or Profile

1. Define the detection result.
   - It should be explicit enough to explain why the family detected.
   - It should carry stable evidence identifiers, not rendered pseudocode text.
2. Build an immutable snapshot.
   - Include the microcode handle, handler count, source facts, transition
     facts, and profile evidence needed by strategies.
   - Do not let strategies reach back into collectors for hidden mutable state.
3. Define profile policy.
   - A profile chooses strategy ordering, feature gates, and family-specific
     thresholds.
   - Keep obfuscator-specific policy in the profile rather than branching inside
     shared engine code.
4. Implement strategies.
   - Strategies consume a snapshot and emit `PlanFragment` objects.
   - Strategies should abstain when proof is missing.
   - Strategies should not mutate CFG directly, scrape logs, or query
     diagnostic SQLite.
5. Lower through cfg modifications.
   - Reuse existing graph modifications before adding new ones.
   - Add a new modification only when the edit shape is a real shared primitive
     and can be validated independently.
6. Execute through the shared runtime.
   - Use `plan_family_pipeline(...)` and `execute_family_pipeline(...)` unless
     the rule is still an intentional compatibility bridge.
   - Let executor/preflight/semantic gates own transaction safety.
7. Record provenance and diagnostics.
   - Planner provenance should explain accepted and rejected fragments.
   - Observability should flow through emitted events and subscribers, not
     direct persistence from recon or strategy code.

## What Belongs In A Strategy

A strategy may:

- inspect the immutable snapshot;
- combine recon/cfg facts into a proposed edit;
- emit one or more `PlanFragment` objects;
- attach proof metadata used by preflight, gates, or diagnostics.

A strategy must not:

- call Hex-Rays mutation APIs directly;
- own a transaction;
- read or write diagnostic SQLite;
- scrape rendered pseudocode or debug logs as its proof source;
- silently fall back to legacy mutation after emitting a modern fragment.

If a strategy cannot prove safety, it should abstain with enough metadata for a
gap card or diagnostic row to explain what evidence is missing.

## When To Add A Recon Helper

Add recon code when the missing piece is read-only evidence:

- branch ownership;
- state transition facts;
- dispatcher row extraction;
- source-byte or value-flow facts;
- return-carrier or terminal-byte facts;
- structural observations that diagnostics should persist.

Recon helpers should return structured objects or emit observations. Behavior
code should consume the in-memory result, not a diagnostic database row.

## When To Add A Cfg Primitive

Add a cfg primitive when the missing piece is an edit shape:

- duplicate a block;
- redirect a conditional edge;
- isolate an empty trampoline;
- insert captured block bodies;
- materialize a backend-neutral payload.

The cfg layer should own validation for the primitive. A family strategy should
only choose the primitive and provide proof metadata.

## Validation Ladder

Use the smallest gate that proves the contract, then climb:

1. Unit-test the recon fact or cfg primitive in isolation.
2. Unit-test the family profile, strategy ordering, and abstention reasons.
3. Unit-test `PlanFragment` output and planner/provenance rows.
4. Run focused dump/diagnostic checks for one representative function.
5. Compare legacy-on, engine-only, current-default, and no-project baseline
   outputs when retiring a legacy rule.
6. Run import and architecture boundary checks:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

Only retire a legacy path when the engine-only run proves equal or better
behavior, the old blocker disappears, and any remaining delta is classified as
an intentional abstention rather than an unexamined fallback.

## Current Reference Families

- Hodur is the rich state-machine reference. It demonstrates profile-owned
  strategy ordering, multi-strategy planning, and shared execution.
- `SimpleFlatteningCleanupUnflattener` is the small cleanup-family reference.
  It shows how narrow cleanup lanes can use the engine without becoming a new
  dispatcher framework.
- `EmulatedDispatcherUnflattener` is the dispatcher-profile migration target
  for OLLVM and Tigress. Profiles should provide exact state-transition
  evidence when possible before falling back to broader dispatcher analysis.

## Review Checklist

Before accepting a new family/profile migration:

- detection is read-only;
- snapshot input is explicit and immutable;
- profile policy is not hidden in shared engine branches;
- strategies emit fragments and abstain on proof gaps;
- mutation goes through cfg/materialization/executor contracts;
- diagnostics are observations/subscribers, not behavior dependencies;
- legacy fallback is either removed after parity or explicitly recorded as an
  abstention contract;
- focused tests cover the proof source, emitted fragment, rejection case, and
  config/profile wiring.
"""


def render_extension_guide() -> str:
    return GUIDE_TEXT


def _resolve(root: Path, value: str | None) -> Path:
    path = Path(value) if value else GUIDE_PATH
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _print_diff(path: Path, existing: str, generated: str) -> None:
    for line in difflib.unified_diff(
        existing.splitlines(),
        generated.splitlines(),
        fromfile=str(path),
        tofile=str(path),
        lineterm="",
    ):
        print(line)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="Repository root")
    parser.add_argument(
        "--output",
        default=None,
        help="Guide output path, relative to root unless absolute",
    )
    parser.add_argument("--apply", action="store_true", help="Write the guide")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    output = _resolve(root, args.output)
    generated = render_extension_guide()
    existing = output.read_text(encoding="utf-8") if output.exists() else ""

    if existing == generated:
        print(f"no changes for {output}")
        return 0

    if args.apply:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(generated, encoding="utf-8")
        print(f"wrote {output}")
    else:
        print(f"would write {output}")
        _print_diff(output, existing, generated)
        print("dry-run: 1 file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
