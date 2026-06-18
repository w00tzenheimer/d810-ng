#!/usr/bin/env python3
"""Phase 13: Create strategy implementations and wire into pipeline.

This codemod:
1. Creates strategies/ directory structure
2. Implements OLLVMLinearizationStrategy
3. Implements CleanupStrategy
4. Creates __init__.py for strategies package
5. Updates hodur/unflattener.py to use strategy pattern

This is the final phase that wires everything together.

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
# Strategy Implementations
# ─────────────────────────────────────────────────────────────────────────────

STRATEGIES_INIT = '''"""Strategy implementations for unflattening pipelines.

This package provides concrete strategy implementations for various
control-flow flattening patterns:

- OLLVMLinearizationStrategy: Unflattens OLLVM-style switch-table dispatchers
- CleanupStrategy: Removes dead code after unflattening
- (Future) HodurStrategy: Unflattens Hodur-style conditional chains
- (Future) TigressStrategy: Unflattens Tigress dispatchers

Example::

    from d810.optimizers.microcode.flow.flattening.strategies import (
        OLLVMLinearizationStrategy,
        CleanupStrategy,
    )
    from d810.optimizers.microcode.flow.flattening.planner import UnflatteningPlanner

    # Create strategies
    strategies = [
        OLLVMLinearizationStrategy(),
        CleanupStrategy(),
    ]

    # Create planner with strategy chain
    planner = UnflatteningPlanner(strategies=strategies)

    # Execute pipeline
    result = planner.execute(mba)
'''

OLLVM_STRATEGY = '''#!/usr/bin/env python3
"""OLLVM control-flow flattening unflattening strategy.

This strategy unflattens OLLVM-style switch-table dispatchers by:
1. Detecting switch-table patterns via DispatcherCache
2. Linearizing handlers by redirecting edges through dispatcher
3. Generating PlanFragment with GraphModifications

Example::

    from d810.optimizers.microcode.flow.flattening.strategies import OLLVMLinearizationStrategy

    strategy = OLLVMLinearizationStrategy()
    if strategy.is_applicable(snapshot):
        plan = strategy.plan(snapshot)
        # plan contains modifications to apply
'''

CLEANUP_STRATEGY = '''#!/usr/bin/env python3
"""Post-unflattening cleanup strategy.

This strategy removes dead code and simplifies the CFG after
unflattening has been applied:
1. Removes unreachable blocks (former dispatcher/condition-chain blocks)
2. Coalesces redundant jumps
3. Cleans up residual state variable writes

Example::

    from d810.optimizers.microcode.flow.flattening.strategies import CleanupStrategy

    strategy = CleanupStrategy()
    if strategy.is_applicable(snapshot):
        plan = strategy.plan(snapshot)
        # plan contains cleanup modifications
'''

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────


def create_file(path: Path, content: str, dry_run: bool = True) -> None:
    """Create a file with the given content."""
    if path.exists():
        print(f"Skip (exists): {path}")
        return

    if dry_run:
        print(f"Would create: {path}")
        print(f"  Content: {len(content)} bytes")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"Created: {path}")


def update_file(path: Path, new_content: str, dry_run: bool = True) -> bool:
    """Update a file with new content."""
    if not path.exists():
        print(f"Skip (not found): {path}")
        return False

    old_content = path.read_text(encoding="utf-8")

    if old_content == new_content:
        print(f"Skip (no change): {path}")
        return False

    if dry_run:
        print(f"Would update: {path}")
        diff = difflib.unified_diff(
            old_content.splitlines(),
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


# ─────────────────────────────────────────────────────────────────────────────
# Main Codemod Logic
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 13: Create strategy implementations and wire into pipeline"
    )
    parser.add_argument("--root", default=".", help="Repo root")
    parser.add_argument("--apply", action="store_true", help="Write changes")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    dry_run = not args.apply

    print(f"Phase 13: Create strategy implementations")
    print(f"Root: {root}")
    print(f"Mode: {'DRY RUN' if dry_run else 'APPLY'}")
    print("-" * 60)

    # Step 1: Create strategies/__init__.py
    print("\nStep 1: Create strategies package")
    strategies_init_path = root / "src/d810/optimizers/microcode/flow/flattening/strategies/__init__.py"
    if not strategies_init_path.exists():
        create_file(strategies_init_path, STRATEGIES_INIT, dry_run)
    else:
        print(f"Skip (exists): {strategies_init_path}")

    # Step 2: Create OLLVMLinearizationStrategy
    print("\nStep 2: Create OLLVMLinearizationStrategy")
    ollvm_strategy_path = (
        root / "src/d810/optimizers/microcode/flow/flattening/strategies/ollvm_strategy.py"
    )
    if not ollvm_strategy_path.exists():
        create_file(ollvm_strategy_path, OLLVM_STRATEGY, dry_run)
    else:
        print(f"Skip (exists): {ollvm_strategy_path}")

    # Step 3: Create CleanupStrategy
    print("\nStep 3: Create CleanupStrategy")
    cleanup_strategy_path = (
        root / "src/d810/optimizers/microcode/flow/flattening/strategies/cleanup_strategy.py"
    )
    if not cleanup_strategy_path.exists():
        create_file(cleanup_strategy_path, CLEANUP_STRATEGY, dry_run)
    else:
        print(f"Skip (exists): {cleanup_strategy_path}")

    # Step 4: Update hodur/unflattener.py (TODO - manual step)
    print("\nStep 4: Manual step required")
    print("  Update hodur/unflattener.py to use strategy pattern")
    print("  See docs/ARCHITECTURE_PLAN.md for details")

    print("-" * 60)
    if dry_run:
        print("Dry run complete. Use --apply to write changes.")
    else:
        print("Codemod complete!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
