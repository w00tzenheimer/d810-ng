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

GUIDE_TEXT = "# Unflattening Engine Extension Guide\n\nThis guide is the implementer contract for adding or migrating an unflattening\nfamily into the shared engine. The architecture rationale lives in\n`docs/unflattening-profile-architecture.md`; this file is the operational\nchecklist.\n\nGenerated and refreshed by:\n\n```bash\npython tools/scripts/codemod_unflattening_engine_extension_guide.py --apply\n```\n\n## Stable Shape\n\nThe shared engine is organized around this lifecycle:\n\n```text\ndetect -> snapshot -> plan -> execute -> provenance\n```\n\n- `detect` is family-owned and read-only. It finds evidence, chooses a profile,\n  and returns a detection result.\n- `snapshot` converts detection evidence into immutable planner input.\n- `plan` asks ordered strategies for `PlanFragment` instances and arbitrates\n  conflicts.\n- `execute` lowers accepted fragments through the shared executor and cfg\n  modification pipeline.\n- `provenance` records why each strategy was accepted, rejected, bypassed, or\n  applied.\n\nThe lifecycle is deliberately narrower than the old generic dispatcher rule.\nNew behavior should enter as evidence, a profile, a strategy, a cfg primitive,\nor a backend/materialization adapter. It should not add another direct live CFG\nmutation path inside strategy code.\n\n## Layer Contract\n\nUse the lowest layer that owns the concept:\n\n- `d810.preanalysis` owns read-only analysis, source facts, transition facts, and\n  observations. Preanalysis code may emit observations; diagnostics subscribers\n  persist them. Preanalysis and behavior code must not directly read or write\n  diagnostic SQLite.\n- `d810.cfg` owns backend-neutral graph modifications, materialization payloads,\n  planning fragments, and validation helpers. Add a cfg primitive when more\n  than one family needs the same shape of edit.\n- `d810.hexrays` owns Hex-Rays-specific materialization and verifier details.\n  Engine strategies should not encode Hex-Rays mutation mechanics directly.\n- `d810.optimizers.microcode.flow.flattening.engine` owns family orchestration,\n  planning, execution, provenance, and shared strategy contracts.\n- `d810.optimizers.microcode.flow.flattening.<family>` owns profile policy,\n  detection details, and family-local heuristics that are not reusable yet.\n\n## Adding A Family Or Profile\n\n1. Define the detection result.\n   - It should be explicit enough to explain why the family detected.\n   - It should carry stable evidence identifiers, not rendered pseudocode text.\n2. Build an immutable snapshot.\n   - Include the microcode handle, handler count, source facts, transition\n     facts, and profile evidence needed by strategies.\n   - Do not let strategies reach back into collectors for hidden mutable state.\n3. Define profile policy.\n   - A profile chooses strategy ordering, feature gates, and family-specific\n     thresholds.\n   - Keep obfuscator-specific policy in the profile rather than branching inside\n     shared engine code.\n4. Implement strategies.\n   - Strategies consume a snapshot and emit `PlanFragment` objects.\n   - Strategies should abstain when proof is missing.\n   - Strategies should not mutate CFG directly, scrape logs, or query\n     diagnostic SQLite.\n5. Lower through cfg modifications.\n   - Reuse existing graph modifications before adding new ones.\n   - Add a new modification only when the edit shape is a real shared primitive\n     and can be validated independently.\n6. Execute through the shared runtime.\n   - Use `plan_family_pipeline(...)` and `execute_family_pipeline(...)` unless\n     the rule is still an intentional compatibility bridge.\n   - Let executor/preflight/semantic gates own transaction safety.\n7. Record provenance and diagnostics.\n   - Planner provenance should explain accepted and rejected fragments.\n   - Observability should flow through emitted events and subscribers, not\n     direct persistence from preanalysis or strategy code.\n\n## What Belongs In A Strategy\n\nA strategy may:\n\n- inspect the immutable snapshot;\n- combine preanalysis/cfg facts into a proposed edit;\n- emit one or more `PlanFragment` objects;\n- attach proof metadata used by preflight, gates, or diagnostics.\n\nA strategy must not:\n\n- call Hex-Rays mutation APIs directly;\n- own a transaction;\n- read or write diagnostic SQLite;\n- scrape rendered pseudocode or debug logs as its proof source;\n- silently fall back to legacy mutation after emitting a modern fragment.\n\nIf a strategy cannot prove safety, it should abstain with enough metadata for a\ngap card or diagnostic row to explain what evidence is missing.\n\n## When To Add A Preanalysis Helper\n\nAdd preanalysis code when the missing piece is read-only evidence:\n\n- branch ownership;\n- state transition facts;\n- dispatcher row extraction;\n- source-byte or value-flow facts;\n- return-carrier or terminal-byte facts;\n- structural observations that diagnostics should persist.\n\nPreanalysis helpers should return structured objects or emit observations. Behavior\ncode should consume the in-memory result, not a diagnostic database row.\n\n## When To Add A Cfg Primitive\n\nAdd a cfg primitive when the missing piece is an edit shape:\n\n- duplicate a block;\n- redirect a conditional edge;\n- isolate an empty trampoline;\n- insert captured block bodies;\n- materialize a backend-neutral payload.\n\nThe cfg layer should own validation for the primitive. A family strategy should\nonly choose the primitive and provide proof metadata.\n\n## Validation Ladder\n\nUse the smallest gate that proves the contract, then climb:\n\n1. Unit-test the preanalysis fact or cfg primitive in isolation.\n2. Unit-test the family profile, strategy ordering, and abstention reasons.\n3. Unit-test `PlanFragment` output and planner/provenance rows.\n4. Run focused dump/diagnostic checks for one representative function.\n5. Compare legacy-on, engine-only, current-default, and no-project baseline\n   outputs when retiring a legacy rule.\n6. Run import and architecture boundary checks:\n\n```bash\nsg scan --config sgconfig.yml --report-style short\nPYTHONPATH=src lint-imports --config .importlinter\n```\n\nOnly retire a legacy path when the engine-only run proves equal or better\nbehavior, the old blocker disappears, and any remaining delta is classified as\nan intentional abstention rather than an unexamined fallback.\n\n## Current Reference Families\n\n- Hodur is the rich state-machine reference. It demonstrates profile-owned\n  strategy ordering, multi-strategy planning, and shared execution.\n- `SimpleFlatteningCleanupUnflattener` is the small cleanup-family reference.\n  It shows how narrow cleanup lanes can use the engine without becoming a new\n  dispatcher framework.\n- `EmulatedDispatcherUnflattener` is the dispatcher-profile migration target\n  for OLLVM and Tigress. Profiles should provide exact state-transition\n  evidence when possible before falling back to broader dispatcher analysis.\n\n## Review Checklist\n\nBefore accepting a new family/profile migration:\n\n- detection is read-only;\n- snapshot input is explicit and immutable;\n- profile policy is not hidden in shared engine branches;\n- strategies emit fragments and abstain on proof gaps;\n- mutation goes through cfg/materialization/executor contracts;\n- diagnostics are observations/subscribers, not behavior dependencies;\n- legacy fallback is either removed after parity or explicitly recorded as an\n  abstention contract;\n- focused tests cover the proof source, emitted fragment, rejection case, and\n  config/profile wiring.\n"


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
