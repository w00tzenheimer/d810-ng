#!/usr/bin/env python3
"""Mechanical OLLVM carrier profile-scope codemod.

This script intentionally performs only symbol/import cleanup. It does not move
projection semantics or decide architecture boundaries.
"""
from __future__ import annotations

import argparse
from pathlib import Path

REPLACEMENTS = {
    "d810.analyses.value_flow.ollvm_semantic_carrier": (
        "d810.families.state_machine_cff.ollvm_carrier_profile"
    ),
    "d810.backends.hexrays.evidence.ollvm_carrier_backend": (
        "d810.families.state_machine_cff.ollvm_carrier_profile"
    ),
    "ollvm_semantic_carrier": "ollvm_carrier_profile",
    "ollvm_carrier_backend": "ollvm_carrier_profile",
    "OllvmValueFlowEvidenceCollector": "OllvmCarrierRawEvidenceCollector",
}


def _iter_python_files(root: Path) -> tuple[Path, ...]:
    candidates = []
    for dirname in ("src/d810", "tests", "tools"):
        base = root / dirname
        if not base.exists():
            continue
        candidates.extend(path for path in base.rglob("*.py") if path.is_file())
    return tuple(sorted(candidates))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository/worktree root. Defaults to cwd.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report files that would change without writing them.",
    )
    args = parser.parse_args()

    changed = []
    for path in _iter_python_files(args.root):
        original = path.read_text(encoding="utf-8")
        updated = original
        for old, new in REPLACEMENTS.items():
            updated = updated.replace(old, new)
        if updated != original:
            changed.append(path)
            if not args.check:
                path.write_text(updated, encoding="utf-8")

    for path in changed:
        print(path)
    return 1 if args.check and changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
