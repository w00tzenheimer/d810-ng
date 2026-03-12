#!/usr/bin/env python3
"""Phase 14: Update hodur re-exports to use extracted base types.

This codemod updates hodur package to re-export from the new base locations:
1. hodur/strategy.py → re-exports from base_strategy
2. hodur/provenance.py → re-exports from core.pipeline
3. hodur/planner.py → imports from new locations

Default mode is dry-run. Use --apply to write changes.
Run with `pyenv exec` to use the project interpreter.
"""
from __future__ import annotations

import argparse
import difflib
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ─────────────────────────────────────────────────────────────────────────────
# File Contents
# ─────────────────────────────────────────────────────────────────────────────

HODUR_STRATEGY_INIT = '''#!/usr/bin/env python3
"""Hodur strategy module — re-exports from base_strategy for backward compatibility.

This module re-exports the strategy pattern types from the canonical location
to maintain backward compatibility with existing code.

All types are now defined in:
    d810.optimizers.microcode.flow.flattening.base_strategy

This module exists solely for backward compatibility during the migration period.
"""
from d810.optimizers.microcode.flow.flattening.base_strategy import (
    FAMILY_DIRECT,
    FAMILY_FALLBACK,
    FAMILY_CLEANUP,
    OwnershipScope,
    BenefitMetrics,
    PlanFragment,
    UnflatteningStrategy,
    StageResult,
    VerificationGate,
    SemanticGate,
)

# Re-export everything for backward compatibility
__all__ = [
    "FAMILY_DIRECT",
    "FAMILY_FALLBACK",
    "FAMILY_CLEANUP",
    "OwnershipScope",
    "BenefitMetrics",
    "PlanFragment",
    "UnflatteningStrategy",
    "StageResult",
    "VerificationGate",
    "SemanticGate",
]
'''

HODUR_PROVENANCE_INIT = '''#!/usr/bin/env python3
"""Hodur provenance module — re-exports from core.pipeline for backward compatibility.

This module re-exports the pipeline provenance types from the canonical location
to maintain backward compatibility with existing code.

All types are now defined in:
    d810.core.pipeline

This module exists solely for backward compatibility during the migration period.
"""
from d810.core.pipeline import (
    DecisionPhase,
    DecisionReasonCode,
    GateVerdict,
    GateDecision,
    GateAccounting,
    DecisionInputSummary,
    PlannerInputs,
    DecisionRecord,
    PipelineProvenance,
)

# Re-export everything for backward compatibility
__all__ = [
    "DecisionPhase",
    "DecisionReasonCode",
    "GateVerdict",
    "GateDecision",
    "GateAccounting",
    "DecisionInputSummary",
    "PlannerInputs",
    "DecisionRecord",
    "PipelineProvenance",
]
'''

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────


def create_or_update_file(path: Path, content: str, dry_run: bool = True) -> bool:
    """Create or update a file with the given content."""
    if path.exists():
        old_content = path.read_text(encoding="utf-8")
        if old_content == content:
            print(f"Skip (no change): {path}")
            return False
        else:
            if dry_run:
                print(f"Would update: {path}")
                diff = difflib.unified_diff(
                    old_content.splitlines(),
                    content.splitlines(),
                    fromfile=str(path),
                    tofile=str(path),
                    lineterm="",
                )
                for line in diff:
                    print(line)
            else:
                path.write_text(content, encoding="utf-8")
                print(f"Updated: {path}")
            return True
    else:
        if dry_run:
            print(f"Would create: {path}")
            print(f"  Content: {len(content)} bytes")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(f"Created: {path}")
        return True


def update_imports_in_file(
    path: Path, old_import: str, new_import: str, dry_run: bool = True
) -> bool:
    """Update an import statement in a file."""
    if not path.exists():
        print(f"Skip (not found): {path}")
        return False

    content = path.read_text(encoding="utf-8")

    if old_import not in content:
        print(f"Skip (import not found): {path}")
        return False

    new_content = content.replace(old_import, new_import)

    if dry_run:
        print(f"Would update imports in: {path}")
        print(f"  Old: {old_import}")
        print(f"  New: {new_import}")
    else:
        path.write_text(new_content, encoding="utf-8")
        print(f"Updated imports in: {path}")

    return True


# ─────────────────────────────────────────────────────────────────────────────
# Main Codemod Logic
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 14: Update hodur re-exports to use extracted base types"
    )
    parser.add_argument("--root", default=".", help="Repo root")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    dry_run = not args.apply

    print(f"Phase 14: Update hodur re-exports")
    print(f"Root: {root}")
    print(f"Mode: {'DRY RUN' if dry_run else 'APPLY'}")
    print("-" * 60)

    # Step 1: Update hodur/strategy.py
    print("\nStep 1: Update hodur/strategy.py")
    strategy_path = root / "src/d810/optimizers/microcode/flow/flattening/hodur/strategy.py"
    create_or_update_file(strategy_path, HODUR_STRATEGY_INIT, dry_run)

    # Step 2: Update hodur/provenance.py
    print("\nStep 2: Update hodur/provenance.py")
    provenance_path = (
        root / "src/d810/optimizers/microcode/flow/flattening/hodur/provenance.py"
    )
    create_or_update_file(provenance_path, HODUR_PROVENANCE_INIT, dry_run)

    # Step 3: Update hodur/planner.py imports
    print("\nStep 3: Update hodur/planner.py imports")
    planner_path = root / "src/d810/optimizers/microcode/flow/flattening/hodur/planner.py"
    update_imports_in_file(
        planner_path,
        "from d810.optimizers.microcode.flow.flattening.hodur.provenance import",
        "from d810.core.pipeline import",
        dry_run,
    )

    print("-" * 60)
    if dry_run:
        print("Dry run complete. Use --apply to write changes.")
    else:
        print("Codemod complete!")
        print("\nNext: Run tests to verify imports work correctly")
        print("  pytest tests/unit/optimizers/microcode/flow/flattening/ -v")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
