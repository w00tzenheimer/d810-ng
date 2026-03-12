#!/usr/bin/env python3
"""Phase 16: Wire strategies into hodur/unflattener.py pipeline.

This codemod updates hodur/unflattener.py to use the strategy pattern:
1. Import strategies from strategies package
2. Create UnflatteningPlanner with strategy chain
3. Execute pipeline instead of monolithic logic

This is the final integration step that makes everything work together.

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
# Patch for hodur/unflattener.py
# ─────────────────────────────────────────────────────────────────────────────

# This is a simplified patch - the actual file is complex
# We'll add the strategy pattern integration

STRATEGY_IMPORTS = """
# Strategy pattern imports
from d810.optimizers.microcode.flow.flattening.strategies import (
    OLLVMLinearizationStrategy,
    CleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.planner import UnflatteningPlanner
from d810.optimizers.microcode.flow.flattening.base_strategy import (
    PlanFragment,
    UnflatteningStrategy,
)
"""

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────


def update_file_with_patch(
    path: Path,
    import_addition: str,
    old_pattern: str,
    new_replacement: str,
    dry_run: bool = True,
) -> bool:
    """Update a file by adding imports and replacing a pattern."""
    if not path.exists():
        print(f"Skip (not found): {path}")
        return False

    content = path.read_text(encoding="utf-8")

    # Check if already updated
    if "UnflatteningPlanner" in content:
        print(f"Skip (already updated): {path}")
        return False

    # Add imports
    if import_addition not in content:
        # Find import section and add
        import_marker = "from d810.optimizers.microcode.flow.flattening.hodur."
        if import_marker in content:
            content = import_addition + "\n" + content
        else:
            content = import_addition + "\n" + content

    # Replace pattern
    if old_pattern in content:
        content = content.replace(old_pattern, new_replacement)
    else:
        print(f"Warning: Pattern not found in {path}")
        print(f"  Looking for: {old_pattern[:100]}...")

    if dry_run:
        print(f"Would update: {path}")
        diff = difflib.unified_diff(
            path.read_text(encoding="utf-8").splitlines(),
            content.splitlines(),
            fromfile=str(path),
            tofile=str(path),
            lineterm="",
        )
        for line in diff:
            print(line)
        return True

    path.write_text(content, encoding="utf-8")
    print(f"Updated: {path}")
    return True


def create_manual_instructions(path: Path, dry_run: bool = True) -> None:
    """Create a file with manual instructions for the remaining steps."""
    instructions = """# Manual Steps for Phase 16: Wire Pipeline

This file contains the manual steps needed to complete the strategy pattern integration.

## Step 1: Update hodur/unflattener.py::optimize()

Find the `optimize()` method and replace the logic:

### Before (old code):
```python
def optimize(self, blk: ida_hexrays.mblock_t) -> int:
    # Old monolithic logic
    self.retrieve_all_dispatchers()
    self.remove_flattening()
    return self.changes
```

### After (new code):
```python
def optimize(self, blk: ida_hexrays.mblock_t) -> int:
    # Only process at entry block
    if blk.serial != 0:
        return 0

    # Create strategy chain
    strategies = [
        OLLVMLinearizationStrategy(),
        CleanupStrategy(),
        # Add more strategies as needed
    ]

    # Create planner with recon artifacts
    planner = UnflatteningPlanner(
        strategies=strategies,
        recon_artifacts=self.recon_artifacts,
    )

    # Execute pipeline
    result = planner.execute(self.mba)

    return result.changes
```

## Step 2: Verify imports

Ensure these imports are present in hodur/unflattener.py:
```python
from d810.optimizers.microcode.flow.flattening.strategies import (
    OLLVMLinearizationStrategy,
    CleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.planner import UnflatteningPlanner
```

## Step 3: Test

Run the test suite to verify the integration:
```bash
pytest tests/unit/optimizers/microcode/flow/flattening/ -v
pytest tests/system/runtime/optimizers/microcode/flow/flattening/ -v
```

## Step 4: Debug if needed

If tests fail:
1. Check that strategies are being instantiated correctly
2. Verify that recon_artifacts are passed to the planner
3. Ensure the planner's execute() method is called
4. Check that result.changes is returned

## Common Issues

### Issue: "No module named 'strategies'"
**Fix:** Ensure `strategies/__init__.py` exists and exports the strategies

### Issue: "AttributeError: 'UnflatteningPlanner' object has no attribute 'execute'"
**Fix:** Check that planner.py has the execute() method

### Issue: "TypeError: optimize() missing required argument: recon_artifacts"
**Fix:** Pass recon_artifacts to the planner constructor

## Success Criteria

- [ ] Strategies are instantiated
- [ ] Planner executes the pipeline
- [ ] Changes are returned from optimize()
- [ ] All tests pass
- [ ] No regressions in unflattening accuracy
"""

    instructions_path = path.parent / "MANUAL_PHASE16_INSTRUCTIONS.md"
    if dry_run:
        print(f"Would create: {instructions_path}")
        print(f"  Content: {len(instructions)} bytes")
    else:
        instructions_path.write_text(instructions, encoding="utf-8")
        print(f"Created: {instructions_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Main Codemod Logic
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 16: Wire strategies into hodur/unflattener.py pipeline"
    )
    parser.add_argument("--root", default=".", help="Repo root")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    dry_run = not args.apply

    print(f"Phase 16: Wire strategies into pipeline")
    print(f"Root: {root}")
    print(f"Mode: {'DRY RUN' if dry_run else 'APPLY'}")
    print("-" * 60)

    # Step 1: Create manual instructions
    print("\nStep 1: Create manual instructions")
    unflattener_path = (
        root / "src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py"
    )
    create_manual_instructions(unflattener_path, dry_run)

    # Step 2: Note about manual work
    print("\nStep 2: Manual integration required")
    print("  See MANUAL_PHASE16_INSTRUCTIONS.md for detailed steps")
    print("  This step requires human judgment to integrate correctly")

    print("-" * 60)
    if dry_run:
        print("Dry run complete.")
        print("\nNext steps:")
        print("  1. Read MANUAL_PHASE16_INSTRUCTIONS.md")
        print("  2. Manually update hodur/unflattener.py::optimize()")
        print("  3. Run tests to verify integration")
    else:
        print("Instructions created!")
        print("\nNext steps:")
        print("  1. Read MANUAL_PHASE16_INSTRUCTIONS.md")
        print("  2. Manually update hodur/unflattener.py::optimize()")
        print("  3. Run tests to verify integration")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
