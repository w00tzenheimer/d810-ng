#!/usr/bin/env python3
"""Phase 12 codemod: Delete unused files and update imports.

This codemod:
1. Deletes services.py (unused, duplicates dispatcher_detection.py)
2. Deletes unflattener_refactored.py (demo code, never wired)
3. Deletes test_services_integration.py (tests unused code)
4. Updates ARCHITECTURE.md with deprecation notices
5. Updates __init__.py exports

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

# Files to delete
FILES_TO_DELETE = [
    "src/d810/optimizers/microcode/flow/flattening/services.py",
    "src/d810/optimizers/microcode/flow/flattening/unflattener_refactored.py",
    "tests/system/runtime/optimizers/microcode/flow/flattening/test_services_integration.py",
]

# Files to update
ARCHITECTURE_MD_PATH = (
    "src/d810/optimizers/microcode/flow/flattening/ARCHITECTURE.md"
)
FLATTENING_INIT_PATH = (
    "src/d810/optimizers/microcode/flow/flattening/__init__.py"
)

# Text to add to ARCHITECTURE.md
ARCHITECTURE_ADDENDUM = """
## Deprecated Components (v2.0+)

The following components have been removed as part of the strategy pattern migration:

- `services.py` - Superseded by strategy pattern in `base_strategy.py`
- `unflattener_refactored.py` - Demo code, never wired into production
- `test_services_integration.py` - Tested unused code

### Migration Guide

**Old code (services.py pattern):**
```python
from d810.optimizers.microcode.flow.flattening.services import (
    CFGPatcher,
    Dispatcher,
    OLLVMDispatcherFinder,
    PathEmulator,
)

finder = OLLVMDispatcherFinder()
emulator = PathEmulator()
patcher = CFGPatcher()
```

**New code (strategy pattern):**
```python
from d810.optimizers.microcode.flow.flattening.base_strategy import (
    UnflatteningStrategy,
    PlanFragment,
    FAMILY_DIRECT,
)
from d810.optimizers.microcode.flow.flattening.strategies import (
    OLLVMLinearizationStrategy,
)
from d810.recon.flow.dispatcher_detection import DispatcherCache

# Use strategy pattern
strategy = OLLVMLinearizationStrategy()
# Use DispatcherCache for detection (canonical)
cache = DispatcherCache.get_or_create(mba)
analysis = cache.analyze()
```

### Why Deprecated?

1. **Duplication**: `services.py` duplicated detection logic already in `dispatcher_detection.py`
2. **Not wired**: `unflattener_refactored.py` was never integrated into production
3. **Better pattern**: Strategy pattern provides better testability and composition
4. **Clear layering**: Recon (detection) → Strategies (implementation) → Planner (orchestration)

See `docs/ARCHITECTURE_PLAN.md` for the full migration plan.
"""


def delete_file(path: Path, dry_run: bool = True) -> bool:
    """Delete a file if it exists."""
    if not path.exists():
        print(f"Skip (not found): {path}")
        return False

    if dry_run:
        print(f"Would delete: {path}")
        return True

    path.unlink()
    print(f"Deleted: {path}")
    return True


def update_architecture_md(path: Path, dry_run: bool = True) -> bool:
    """Add deprecation notice to ARCHITECTURE.md."""
    if not path.exists():
        print(f"Skip (not found): {path}")
        return False

    content = path.read_text(encoding="utf-8")

    # Check if already has deprecation section
    if "Deprecated Components" in content:
        print(f"Skip (already has deprecation): {path}")
        return False

    # Add deprecation section
    new_content = content + "\n" + ARCHITECTURE_ADDENDUM

    if dry_run:
        print(f"Would update: {path}")
        print(f"  Adding: {len(ARCHITECTURE_ADDENDUM)} bytes")
        # Show diff
        diff = difflib.unified_diff(
            content.splitlines(),
            new_content.splitlines(),
            fromfile=str(path),
            tofile=str(path),
            lineterm="",
        )
        for line in diff:
            print(line)
        return True

    path.write_text(new_content, encoding="utf-8")
    print(f"Updated: {path}")
    return True


def update_init_py(path: Path, dry_run: bool = True) -> bool:
    """Update __init__.py to remove deprecated exports."""
    if not path.exists():
        print(f"Skip (not found): {path}")
        return False

    content = path.read_text(encoding="utf-8")

    # Check if already updated
    if "base_strategy" in content:
        print(f"Skip (already updated): {path}")
        return False

    # Add new exports
    lines = content.splitlines()

    # Add imports after existing imports
    new_imports = [
        "",
        "# Base strategy types (strategy pattern)",
        "from d810.optimizers.microcode.flow.flattening.base_strategy import (",
        "    FAMILY_DIRECT,",
        "    FAMILY_FALLBACK,",
        "    FAMILY_CLEANUP,",
        "    OwnershipScope,",
        "    BenefitMetrics,",
        "    PlanFragment,",
        "    UnflatteningStrategy,",
        "    StageResult,",
        "    VerificationGate,",
        "    SemanticGate,",
        ")",
        "",
        "__all__ = [",
        '    "FAMILY_DIRECT",',
        '    "FAMILY_FALLBACK",',
        '    "FAMILY_CLEANUP",',
        '    "OwnershipScope",',
        '    "BenefitMetrics",',
        '    "PlanFragment",',
        '    "UnflatteningStrategy",',
        '    "StageResult",',
        '    "VerificationGate",',
        '    "SemanticGate",',
        "]",
        "",
    ]

    # Insert new imports after existing code
    new_content = content + "\n".join(new_imports) + "\n"

    if dry_run:
        print(f"Would update: {path}")
        print(f"  Adding: {len(new_imports)} lines")
        return True

    path.write_text(new_content, encoding="utf-8")
    print(f"Updated: {path}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 12: Delete unused files and update imports"
    )
    parser.add_argument("--root", default=".", help="Repo root")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    dry_run = not args.apply

    print(f"Phase 12: Cleanup unused files")
    print(f"Root: {root}")
    print(f"Mode: {'DRY RUN' if dry_run else 'APPLY'}")
    print("-" * 60)

    deleted_count = 0

    # Step 1: Delete files
    print("\nStep 1: Delete unused files")
    for rel_path in FILES_TO_DELETE:
        path = root / rel_path
        if delete_file(path, dry_run):
            deleted_count += 1

    # Step 2: Update ARCHITECTURE.md
    print("\nStep 2: Update ARCHITECTURE.md")
    arch_path = root / ARCHITECTURE_MD_PATH
    update_architecture_md(arch_path, dry_run)

    # Step 3: Update __init__.py
    print("\nStep 3: Update __init__.py")
    init_path = root / FLATTENING_INIT_PATH
    update_init_py(init_path, dry_run)

    print("-" * 60)
    print(f"Deleted {deleted_count} file(s)")
    if dry_run:
        print("Dry run complete. Use --apply to write changes.")
    else:
        print("Codemod complete!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
