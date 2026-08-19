# Task 7 implementation report

## Scope

Task 7 migrates the bundled `constant-simplification` config-v2 entries to the
canonical `preparation` plus `stages` shape, while retaining a fail-closed
legacy compatibility boundary for external projects.

The repository contains 13 such config-v2 entries. All 13 now declare the three
stages with their registration-owned full maturity sets. The two EID-prefixed
profiles retain `aggressive_no_direct_writes` and `rva_guard: false`; the other
readonly policies and the pass-level `maturity_gates` values are preserved.

## Compatibility boundary

`pipeline_configs_from_project_config()` canonicalizes a legacy constant bundle
before it reaches the public registry. This is deliberate: the registry's
editor contract is canonical-only, so allowing legacy data to reach it would
reject otherwise supported external projects as editor-invisible. The
canonicalizer calls the same portable schedule compiler used by runtime
activation, serializes requested stage maturities (not gate-intersected
effective maturities), and preserves pass metadata including `maturity_gates`
semantically (the normal `PipelineConfig` serializer may normalize maturity
spelling). Therefore legacy runtime behavior is unchanged while all downstream
consumers see one canonical schedule. The compiler rejects any mixed
canonical/legacy input before projection; there is no precedence rule.

The config-v2 editing service applies the same projection when creating a draft,
replacing a document, setting constant-bundle options, and saving. An accepted
legacy source is therefore written canonically on the next save. The editor
already consumes the canonical fields introduced by Task 4; no duplicate UI
schema was added.

## TDD and verification evidence

- Genuine pre-migration RED: an archived `63d4eb393` tree with only the new
  migration test applied produced 5 failures. The retained output is
  `.tmp/task7-red-before-migration.txt`.
- Focused migration/compiler/editor command:
  `150 passed`:

  ```text
  PYTHONPATH=src pytest -q \
    tests/unit/passes/test_constant_simplification_profile_migration.py \
    tests/unit/core/test_config_v2_defaults.py \
    tests/unit/passes/test_operational_config_v2.py \
    tests/unit/ui/test_config_v2_editing_logic.py
  ```

- Every JSON under `src/d810/conf` was parsed and passed through the project
  config parser and operational registry: `68` JSON files, `68` projects, and
  `171` pipeline configs.
- Adjacent compiler/editor command: `235 passed`; one pre-existing failure
  remains in
  `test_tigress_switch_legacy_configs_remain_runtime_source[...]`, which also
  fails on clean base `63d4eb393` because the unchanged legacy source contains
  3 activated instruction rules while the test expects 4.
- `ruff check`, `python3 -m py_compile`, `git diff --check`, `sg scan`, and
  `PYTHONPATH=src lint-imports --config .importlinter` passed.
- No Docker/system tests were run; Task 7 is config/parser/editor-only and the
  task brief explicitly defers system acceptance to Task 8.

## Product commit

`ea064b829 chore(config): migrate constant stage controls`

The separate progress/report documentation commit follows this report.
