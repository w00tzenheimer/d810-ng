# Codemod Runbook: Phases 11-13

**Architecture Cleanup: Extract Base Strategy & Delete Unused Code**

---

## Overview

This runbook covers the execution of three codemods that implement the architecture cleanup plan:

| Phase | Codemod | Purpose | Risk |
|-------|---------|---------|------|
| 11 | `codemod_phase11_extract_base_strategy.py` | Extract `base_strategy.py` and `core/pipeline.py` | Low (creates new files) |
| 12 | `codemod_phase12_cleanup_unused.py` | Delete unused files | Medium (deletes files) |
| 13 | `codemod_phase13_strategy_migration.py` | Create strategy implementations | Low (creates new files) |

**Total Time:** 30-45 minutes  
**Risk Level:** Low (dry-run first, incremental testing)

---

## Prerequisites

1. **Git branch:** Create a new branch for testing
   ```bash
   git checkout -b refactor/extract-base-strategy
   ```

2. **Backup:** Ensure you have a clean commit point
   ```bash
   git status  # Should be clean
   git log -1  # Note the commit hash
   ```

3. **Test suite:** Know how to run tests
   ```bash
   pytest tests/unit/optimizers/microcode/flow/flattening/ -v
   ```

---

## Phase 11: Extract Base Strategy Types

**Goal:** Create reusable foundation from hodur's pure-Python components.

### Step 1: Run Dry-Run

```bash
cd /Users/mahmoud/src/idapro/d810
pyenv exec python tools/scripts/codemod_phase11_extract_base_strategy.py --root .
```

**Expected output:**
```
Phase 11: Extract base strategy types
Root: /Users/mahmoud/src/idapro/d810
Mode: DRY RUN
------------------------------------------------------------
Would create: /Users/mahmoud/src/idapro/d810/src/d810/core/pipeline.py
  Content: 12345 bytes
Would create: /Users/mahmoud/src/idapro/d810/src/d810/optimizers/microcode/flow/flattening/base_strategy.py
  Content: 23456 bytes
------------------------------------------------------------
Dry run complete. Use --apply to write changes.
```

### Step 2: Verify Dry-Run Output

Check that:
- [ ] `core/pipeline.py` will be created
- [ ] `base_strategy.py` will be created
- [ ] No files will be overwritten

### Step 3: Apply Changes

```bash
pyenv exec python tools/scripts/codemod_phase11_extract_base_strategy.py --root . --apply
```

### Step 4: Verify Creation

```bash
ls -la src/d810/core/pipeline.py
ls -la src/d810/optimizers/microcode/flow/flattening/base_strategy.py
```

### Step 5: Run Tests

```bash
# Test that imports work
pyenv exec python -c "from d810.core.pipeline import PipelineProvenance; print('OK')"
pyenv exec python -c "from d810.optimizers.microcode.flow.flattening.base_strategy import UnflatteningStrategy; print('OK')"

# Run unit tests
pytest tests/unit/optimizers/microcode/flow/flattening/ -v -k "strategy" --tb=short
```

**Expected:** All tests pass

### Step 6: Commit

```bash
git add src/d810/core/pipeline.py src/d810/optimizers/microcode/flow/flattening/base_strategy.py
git commit -m "Phase 11: Extract base strategy types from hodur

- Create core/pipeline.py with provenance tracking types
- Create base_strategy.py with strategy pattern protocol
- Zero IDA imports for testability
- Re-export from hodur for backward compatibility"
```

---

## Phase 12: Cleanup Unused Files

**Goal:** Remove dead weight and clarify architecture.

### Step 1: Run Dry-Run

```bash
pyenv exec python tools/scripts/codemod_phase12_cleanup_unused.py --root .
```

**Expected output:**
```
Phase 12: Cleanup unused files
Root: /Users/mahmoud/src/idapro/d810
Mode: DRY RUN
------------------------------------------------------------
Would delete: /Users/mahmoud/src/idapro/d810/src/d810/optimizers/microcode/flow/flattening/services.py
Would delete: /Users/mahmoud/src/idapro/d810/src/d810/optimizers/microcode/flow/flattening/unflattener_refactored.py
Would delete: /Users/mahmoud/src/idapro/d810/tests/system/runtime/optimizers/microcode/flow/flattening/test_services_integration.py
------------------------------------------------------------
Deleted 3 file(s)
Dry run complete. Use --apply to write changes.
```

### Step 2: Verify Dry-Run Output

Check that:
- [ ] Only the 3 expected files will be deleted
- [ ] `ARCHITECTURE.md` will be updated
- [ ] No other files affected

### Step 3: Apply Changes

```bash
pyenv exec python tools/scripts/codemod_phase12_cleanup_unused.py --root . --apply
```

### Step 4: Verify Deletion

```bash
# These should NOT exist
test -f src/d810/optimizers/microcode/flow/flattening/services.py && echo "ERROR: still exists"
test -f src/d810/optimizers/microcode/flow/flattening/unflattener_refactored.py && echo "ERROR: still exists"
test -f tests/system/runtime/optimizers/microcode/flow/flattening/test_services_integration.py && echo "ERROR: still exists"

# These should exist
ls -la src/d810/optimizers/microcode/flow/flattening/ARCHITECTURE.md
```

### Step 5: Run Tests

```bash
# Ensure no import errors
pyenv exec python -c "from d810.optimizers.microcode.flow.flattening import base_strategy; print('OK')"

# Run full test suite for flattening
pytest tests/unit/optimizers/microcode/flow/flattening/ -v --tb=short
```

**Expected:** All tests pass, no import errors

### Step 6: Commit

```bash
git add -u
git commit -m "Phase 12: Delete unused files

- Remove services.py (duplicates dispatcher_detection.py)
- Remove unflattener_refactored.py (demo code, never wired)
- Remove test_services_integration.py (tests unused code)
- Update ARCHITECTURE.md with deprecation notices"
```

---

## Phase 13: Create Strategy Implementations

**Goal:** Implement strategy pattern with concrete strategies.

### Step 1: Run Dry-Run

```bash
pyenv exec python tools/scripts/codemod_phase13_strategy_migration.py --root .
```

**Expected output:**
```
Phase 13: Create strategy implementations
Root: /Users/mahmoud/src/idapro/d810
Mode: DRY RUN
------------------------------------------------------------
Would create: .../strategies/__init__.py
Would create: .../strategies/ollvm_strategy.py
Would create: .../strategies/cleanup_strategy.py
------------------------------------------------------------
Dry run complete. Use --apply to write changes.
```

### Step 2: Apply Changes

```bash
pyenv exec python tools/scripts/codemod_phase13_strategy_migration.py --root . --apply
```

### Step 3: Verify Creation

```bash
ls -la src/d810/optimizers/microcode/flow/flattening/strategies/
# Should have:
# - __init__.py
# - ollvm_strategy.py
# - cleanup_strategy.py
```

### Step 4: Manual Step - Wire Into Pipeline

**This step requires manual intervention** to integrate strategies into `hodur/unflattener.py`.

See `ARCHITECTURE_PLAN.md` Phase 4 for detailed instructions.

### Step 5: Commit

```bash
git add src/d810/optimizers/microcode/flow/flattening/strategies/
git commit -m "Phase 13: Create strategy implementations

- Add OLLVMLinearizationStrategy
- Add CleanupStrategy
- Create strategies package structure
- TODO: Wire into hodur/unflattener.py (manual step)"
```

---

## Post-Execution Checklist

After all three phases:

### Code Quality
- [ ] No import errors
- [ ] No circular dependencies
- [ ] All type hints resolve
- [ ] No linting errors

### Tests
- [ ] Unit tests pass: `pytest tests/unit/optimizers/microcode/flow/flattening/ -v`
- [ ] Integration tests pass: `pytest tests/system/runtime/optimizers/microcode/flow/flattening/ -v`
- [ ] No test regressions

### Documentation
- [ ] `ARCHITECTURE.md` updated
- [ ] `ARCHITECTURE_PLAN.md` exists
- [ ] Deprecation notices in place

### Git
- [ ] All changes committed
- [ ] Commit messages are clear
- [ ] Branch can be merged cleanly

---

## Rollback Plan

If something goes wrong:

```bash
# Rollback to pre-codemod state
git reset --hard <commit-hash-before-phase-11>

# Or, revert individual commits
git revert <commit-hash-phase-13>
git revert <commit-hash-phase-12>
git revert <commit-hash-phase-11>
```

---

## Troubleshooting

### Import Error: "No module named 'd810.core.pipeline'"

**Cause:** Phase 11 not executed or failed.

**Fix:**
```bash
# Re-run phase 11
pyenv exec python tools/scripts/codemod_phase11_extract_base_strategy.py --root . --apply

# Verify file exists
ls -la src/d810/core/pipeline.py
```

### Import Error: "Cannot import name 'X' from 'base_strategy'"

**Cause:** `__all__` not updated or file not created.

**Fix:**
```bash
# Check file exists
cat src/d810/optimizers/microcode/flow/flattening/base_strategy.py | grep "^__all__"

# Re-run phase 11 if needed
pyenv exec python tools/scripts/codemod_phase11_extract_base_strategy.py --root . --apply
```

### Test Failures

**Cause:** Import paths changed or missing dependencies.

**Fix:**
1. Check test imports
2. Ensure all new modules are in `PYTHONPATH`
3. Run tests with verbose output: `pytest -v --tb=long`

---

## Success Metrics

✅ **Phase 11 Complete:**
- `core/pipeline.py` exists with all types
- `base_strategy.py` exists with strategy protocol
- Zero import errors
- Tests pass

✅ **Phase 12 Complete:**
- `services.py` deleted
- `unflattener_refactored.py` deleted
- `test_services_integration.py` deleted
- `ARCHITECTURE.md` updated
- No broken imports

✅ **Phase 13 Complete:**
- `strategies/` directory created
- `ollvm_strategy.py` implemented
- `cleanup_strategy.py` implemented
- Ready for manual wiring

---

## Next Steps

After completing all phases:

1. **Manual Step:** Wire strategies into `hodur/unflattener.py`
2. **Manual Step:** Implement remaining strategies (Tigress, Hodur, etc.)
3. **Test:** Run full test suite
4. **Document:** Update user-facing docs
5. **Merge:** Create PR and merge to main

See `ARCHITECTURE_PLAN.md` for the complete migration guide.
