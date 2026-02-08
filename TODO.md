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

### DSL test regressions (v0.3.2)

**Fixed.** Two root causes: (1) `manager.py` was not calling `resolve_arch_config()` before passing config to `rule.configure()`, so arch-specific settings like `allow_executable_readonly` under `"macho"` key never reached `FoldReadonlyDataRule` — fixed `constant_folding_test1`. (2) `test_xor`, `test_or`, `test_and` expected Windows type signatures (`int`) but macOS produces `__int64` — initially mitigated with `acceptable_patterns`, then properly fixed with type-agnostic AST comparison (v0.3.3).

### CstSimplificationRule2 re-enabled (v0.3.3)

**Fixed.** Rule `((x ^ c_1_1) & c_2_1) | ((x ^ c_1_2) & c_2_2) => x ^ c_res` re-enabled with Z3 constraint `c_2_1 == ~c_2_2`. Verified at 8/16/32/64-bit widths. 56 unit tests pass.

### Type-agnostic AST comparison (v0.3.3)

**Fixed.** `CodeComparator` in `tests/system/conftest.py` now uses libclang for structural comparison with 3 tiers: (1) IDA typedef preamble resolves `_DWORD`, `__int64`, etc. (2) TypeKind width-bucket equivalence maps `int`/`unsigned int`/`__int64` to bit-width classes. (3) Trivial integer cast stripping + `UNEXPOSED_EXPR` unwrapping. The `acceptable_patterns` workaround removed from `test_xor`, `test_or`, `test_and`. 18 AST comparison tests added in `test_ast_comparison.py`.

### tigress_minmaxarray segfault prevention (v0.3.3)

**Fixed.** `insert_nop_blk` now updates `m_jtbl` case targets (`mcases_t.targets[]`) in addition to `m_goto` and `jcc` targets. Added `_update_jtbl_case_targets()` helper in `cfg_utils.py`. Stale pointer dedup via `_processed_dispatcher_fathers` tracking was already present from earlier port. 16 non-contiguous Tigress switch cases no longer cause stale serial references during CFG modifications.

### convert_jtbl_to_goto helper (v0.3.4)

**Added.** Ported copycat's `convert_jtbl_to_goto()` (deflatten.cpp:2063-2126) as a reusable helper in `cfg_utils.py`. Safely converts an `m_jtbl` tail to `m_goto` by collecting old case targets from `mcases_t.targets`, rewiring succset/predset using codebase conventions (`_del`/`push_back`), and setting `BLT_1WAY`. Includes `_serial_in_predset()` helper for duplicate-safe predset insertion.

## Open Items

- Wire `OptimizationRule` Protocol as primary dispatch path in `hexrays_hooks.py`
- Make `UnflattenerRule` coordinator the primary unflattening path (currently parallel to legacy)
- Evaluate whether `FoldPureConstantRule` should be re-enabled behind a feature flag
- Clean up `canonicalizer.py` (dead code with useful AST normalization utils)
- Investigate 2 known test failures: `hardened_cond_chain_simple`, `sub_7FFC1EB47830` (`FixPredecessorOfConditionalJumpBlock` does not fire)
- Add config schema validation at `rule.configure()` boundary to reject arch-structured dicts (prevent silent `resolve_arch_config` bypass)
