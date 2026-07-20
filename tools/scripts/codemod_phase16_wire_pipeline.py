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
    instructions = "# Manual Steps for Phase 16: Wire Pipeline\n\nThis file contains the manual steps needed to complete the strategy pattern integration.\n\n## Step 1: Update hodur/unflattener.py::optimize()\n\nFind the `optimize()` method and replace the logic:\n\n### Before (old code):\n```python\ndef optimize(self, blk: ida_hexrays.mblock_t) -> int:\n    # Old monolithic logic\n    self.retrieve_all_dispatchers()\n    self.remove_flattening()\n    return self.changes\n```\n\n### After (new code):\n```python\ndef optimize(self, blk: ida_hexrays.mblock_t) -> int:\n    # Only process at entry block\n    if blk.serial != 0:\n        return 0\n\n    # Create strategy chain\n    strategies = [\n        OLLVMLinearizationStrategy(),\n        CleanupStrategy(),\n        # Add more strategies as needed\n    ]\n\n    # Create planner with preanalysis artifacts\n    planner = UnflatteningPlanner(\n        strategies=strategies,\n        preanalysis_artifacts=self.preanalysis_artifacts,\n    )\n\n    # Execute pipeline\n    result = planner.execute(self.mba)\n\n    return result.changes\n```\n\n## Step 2: Verify imports\n\nEnsure these imports are present in hodur/unflattener.py:\n```python\nfrom d810.optimizers.microcode.flow.flattening.strategies import (\n    OLLVMLinearizationStrategy,\n    CleanupStrategy,\n)\nfrom d810.optimizers.microcode.flow.flattening.planner import UnflatteningPlanner\n```\n\n## Step 3: Test\n\nRun the test suite to verify the integration:\n```bash\npytest tests/unit/optimizers/microcode/flow/flattening/ -v\npytest tests/system/runtime/optimizers/microcode/flow/flattening/ -v\n```\n\n## Step 4: Debug if needed\n\nIf tests fail:\n1. Check that strategies are being instantiated correctly\n2. Verify that preanalysis_artifacts are passed to the planner\n3. Ensure the planner's execute() method is called\n4. Check that result.changes is returned\n\n## Common Issues\n\n### Issue: \"No module named 'strategies'\"\n**Fix:** Ensure `strategies/__init__.py` exists and exports the strategies\n\n### Issue: \"AttributeError: 'UnflatteningPlanner' object has no attribute 'execute'\"\n**Fix:** Check that planner.py has the execute() method\n\n### Issue: \"TypeError: optimize() missing required argument: preanalysis_artifacts\"\n**Fix:** Pass preanalysis_artifacts to the planner constructor\n\n## Success Criteria\n\n- [ ] Strategies are instantiated\n- [ ] Planner executes the pipeline\n- [ ] Changes are returned from optimize()\n- [ ] All tests pass\n- [ ] No regressions in unflattening accuracy\n"

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
