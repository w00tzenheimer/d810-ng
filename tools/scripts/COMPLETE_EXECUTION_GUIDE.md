# Complete Execution Guide: Architecture Cleanup (Phases 11-16)

**Goal:** Migrate from monolithic inheritance-based unflattening to strategy pattern  
**Total Time:** 1-2 hours (including testing)  
**Risk:** Low (dry-run first, incremental commits)

---

## 📦 Codemods Created

| Phase | File | Purpose | Auto/Manual |
|-------|------|---------|-------------|
| 11 | `codemod_phase11_extract_base_strategy.py` | Create `core/pipeline.py` + `base_strategy.py` | ✅ Auto |
| 12 | `codemod_phase12_cleanup_unused.py` | Delete unused files | ✅ Auto |
| 13 | `codemod_phase13_strategy_migration.py` | Create strategy package stubs | ✅ Auto |
| 14 | `codemod_phase14_update_hodur_reexports.py` | Update hodur re-exports | ✅ Auto |
| 15 | `codemod_phase15_implement_strategies.py` | Implement full strategy logic | ✅ Auto |
| 16 | `codemod_phase16_wire_pipeline.py` | Wire into pipeline | ⚠️ Manual |

---

## 🚀 Quick Start (Automated Phases 11-15)

```bash
cd /Users/mahmoud/src/idapro/d810

# Create a new branch
git checkout -b refactor/strategy-pattern

# Run all automated phases (dry-run first)
pyenv exec python tools/scripts/codemod_phase11_extract_base_strategy.py --root .
pyenv exec python tools/scripts/codemod_phase12_cleanup_unused.py --root .
pyenv exec python tools/scripts/codemod_phase13_strategy_migration.py --root .
pyenv exec python tools/scripts/codemod_phase14_update_hodur_reexports.py --root .
pyenv exec python tools/scripts/codemod_phase15_implement_strategies.py --root .

# Verify dry-run output looks correct, then apply:
pyenv exec python tools/scripts/codemod_phase11_extract_base_strategy.py --root . --apply
pyenv exec python tools/scripts/codemod_phase12_cleanup_unused.py --root . --apply
pyenv exec python tools/scripts/codemod_phase13_strategy_migration.py --root . --apply
pyenv exec python tools/scripts/codemod_phase14_update_hodur_reexports.py --root . --apply
pyenv exec python tools/scripts/codemod_phase15_implement_strategies.py --root . --apply

# Verify files created
ls -la src/d810/core/pipeline.py
ls -la src/d810/optimizers/microcode/flow/flattening/base_strategy.py
ls -la src/d810/optimizers/microcode/flow/flattening/strategies/

# Run tests
pytest tests/unit/optimizers/microcode/flow/flattening/ -v

# Commit
git add -A
git commit -m "Phases 11-15: Extract strategy pattern foundation

- Create core/pipeline.py with provenance types
- Create base_strategy.py with strategy protocol
- Delete unused services.py, unflattener_refactored.py
- Create strategy implementations (OLLVM, Cleanup)
- Update hodur re-exports"
```

---

## 🔧 Phase 16: Manual Integration

After the automated phases, you need to manually wire the strategies into the pipeline.

### Step 1: Read Manual Instructions

```bash
cat tools/scripts/MANUAL_PHASE16_INSTRUCTIONS.md
```

### Step 2: Update hodur/unflattener.py

Find the `optimize()` method and update it:

```python
# Add imports at the top
from d810.optimizers.microcode.flow.flattening.strategies import (
    OLLVMLinearizationStrategy,
    CleanupStrategy,
)
from d810.optimizers.microcode.flow.flattening.planner import UnflatteningPlanner

# Update optimize() method
def optimize(self, blk: ida_hexrays.mblock_t) -> int:
    """Apply unflattening using strategy pattern."""
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

### Step 3: Test

```bash
# Run unit tests
pytest tests/unit/optimizers/microcode/flow/flattening/ -v

# Run integration tests
pytest tests/system/runtime/optimizers/microcode/flow/flattening/ -v

# Run specific hodur tests
pytest tests/system/runtime/optimizers/microcode/flow/flattening/test_hodur_unflattener.py -v
```

### Step 4: Debug if Needed

If tests fail:

1. **Import errors?** Check that all new modules are in PYTHONPATH
2. **AttributeError?** Verify that planner has `execute()` method
3. **No changes returned?** Check that strategies are applicable to the test case

### Step 5: Commit

```bash
git add src/d810/optimizers/microcode/flow/flattening/hodur/unflattener.py
git commit -m "Phase 16: Wire strategies into hodur pipeline

- Update optimize() to use strategy pattern
- Create strategy chain (OLLVM, Cleanup)
- Execute via UnflatteningPlanner
- All tests passing"
```

---

## ✅ Verification Checklist

After all phases:

### Files Created
- [ ] `src/d810/core/pipeline.py`
- [ ] `src/d810/optimizers/microcode/flow/flattening/base_strategy.py`
- [ ] `src/d810/optimizers/microcode/flow/flattening/strategies/__init__.py`
- [ ] `src/d810/optimizers/microcode/flow/flattening/strategies/ollvm_strategy.py`
- [ ] `src/d810/optimizers/microcode/flow/flattening/strategies/cleanup_strategy.py`

### Files Deleted
- [ ] `src/d810/optimizers/microcode/flow/flattening/services.py`
- [ ] `src/d810/optimizers/microcode/flow/flattening/unflattener_refactored.py`
- [ ] `tests/system/runtime/optimizers/microcode/flow/flattening/test_services_integration.py`

### Imports Updated
- [ ] `hodur/strategy.py` re-exports from `base_strategy`
- [ ] `hodur/provenance.py` re-exports from `core.pipeline`
- [ ] `hodur/planner.py` imports from `core.pipeline`
- [ ] `hodur/unflattener.py` uses strategy pattern

### Tests Pass
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] No regressions in unflattening accuracy

### Documentation
- [ ] `ARCHITECTURE.md` updated
- [ ] `docs/ARCHITECTURE_PLAN.md` exists
- [ ] Deprecation notices in place

---

## 🔄 Rollback Plan

If something goes wrong:

```bash
# Rollback to pre-codemod state
git reset --hard <commit-before-phase-11>

# Or revert individual commits
git revert HEAD~5  # Phase 16
git revert HEAD~4  # Phase 15
git revert HEAD~3  # Phase 14
git revert HEAD~2  # Phase 13
git revert HEAD~1  # Phase 12
git revert HEAD    # Phase 11
```

---

## 📊 Success Metrics

✅ **Automated Phases (11-15) Complete:**
- All files created/deleted as expected
- Zero import errors
- Unit tests pass

✅ **Manual Phase (16) Complete:**
- Strategies wired into pipeline
- Integration tests pass
- No regressions

✅ **Overall Success:**
- Code reduction: -800 lines (deleted dead code)
- Test coverage: >80% on new strategy classes
- Clear layering: `recon/` → `strategies/` → `planner/`

---

## 📚 Next Steps After Completion

1. **Implement more strategies:**
   - `hodur_strategy.py` - Hodur-style conditional chains
   - `tigress_strategy.py` - Tigress dispatchers
   - `badwhile_strategy.py` - BadWhile loops

2. **Improve strategy logic:**
   - Add forward evaluation to OLLVM strategy
   - Add state variable cleanup to cleanup strategy
   - Add benefit scoring based on actual metrics

3. **Document:**
   - Update user-facing docs
   - Add strategy pattern tutorial
   - Create migration guide for external users

4. **Optimize:**
   - Profile strategy execution
   - Add caching for repeated patterns
   - Improve conflict detection

---

## 🆘 Troubleshooting

### Issue: "No module named 'd810.core.pipeline'"
**Fix:** Run phase 11 codemod
```bash
pyenv exec python tools/scripts/codemod_phase11_extract_base_strategy.py --root . --apply
```

### Issue: "Cannot import name 'X' from 'base_strategy'"
**Fix:** Check `__all__` in base_strategy.py
```bash
cat src/d810/optimizers/microcode/flow/flattening/base_strategy.py | grep "^__all__"
```

### Issue: Test failures after phase 16
**Fix:** Check that strategies are applicable to test cases
```python
# In test, verify strategy is_applicable()
strategy = OLLVMLinearizationStrategy()
assert strategy.is_applicable(snapshot)
```

### Issue: "UnflatteningPlanner not found"
**Fix:** Ensure planner.py exists and exports UnflatteningPlanner
```bash
grep "class UnflatteningPlanner" src/d810/optimizers/microcode/flow/flattening/planner.py
```

---

## 📞 Support

If you encounter issues not covered here:

1. Check `docs/ARCHITECTURE_PLAN.md` for detailed design
2. Review codemod source code for expected behavior
3. Run codemods in dry-run mode to see what they would do
4. Check git history for recent changes

Good luck! 🎉
