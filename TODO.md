# TODO

## Resolved Issues

### INTERR 51810 in insert_nop_blk (v0.3.0)

**Fixed.** The `insert_nop_blk` function was rewritten to append blocks at the end of the MBA instead of mid-insertion (which shifted serials and corrupted references). Additionally, `create_standalone_block` was added as a safe alternative for block creation. INTERR 50856/50858 cascade was eliminated by adding `verify: bool = True` parameter to all CFG functions and having batch callers pass `verify=False`.

### FoldPureConstantRule collapsing call instructions

**Mitigated.** The rule class is disabled (parent class commented out). `FoldReadonlyDataRule` is the active, safer replacement that specifically handles `ldx` from read-only data segments with guards against folding function pointers and IAT entries.

### INTERR 50863 prevention (v0.3.1)

**Fixed.** Synthesized microcode instructions (gotos, nops, block fillers) now use `mba.entry_ea` instead of inheriting potentially stale addresses from template blocks via `copy_block`. Three previously-segfaulting characterization tests un-skipped (`test_nested_shared_blocks`, `test_deep_duplication_path`, `test_loop_dependent_state`).

### Worktree .env discovery (v0.3.1)

**Fixed.** The `env()` fixture in `tests/conftest.py` now searches `git rev-parse --git-common-dir` as fallback, so `.env` is found even when running from a git worktree with a 0-byte shadow `.env`.

## Open Items

- Wire `OptimizationRule` Protocol as primary dispatch path in `hexrays_hooks.py`
- Make `UnflattenerRule` coordinator the primary unflattening path (currently parallel to legacy)
- Re-enable `CstSimplificationRule2` with proper Z3 constraint (`c1 | c2 == MAX_VAL`)
- Evaluate whether `FoldPureConstantRule` should be re-enabled behind a feature flag
- Clean up `canonicalizer.py` (dead code with useful AST normalization utils)
- Investigate `tigress_minmaxarray` segfault in `decompile_func` (only segfault in test suite)
- Fix 4 DSL test regressions: `test_xor`, `test_or`, `test_and`, `constant_folding_test1` (likely MBA rule gaps after legacy removal)
- Investigate 2 known test failures: `hardened_cond_chain_simple`, `sub_7FFC1EB47830` (`FixPredecessorOfConditionalJumpBlock` does not fire)
