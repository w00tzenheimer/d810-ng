# Task 4 Implementation Report

## Scope

Task 4 enforces complete section coverage at the operational config-v2 editor
boundary and prevents pass-specific branching in the config-v2 Qt adapter.
Review repairs are limited to the approved fake-Qt test fixture, the local
ast-grep rule and fixture, and this report.

## SHAs

- Reviewed Task 4 base: `60a374e64`
- Initial Task 4 implementation: `9700a5324`

## Initial implementation result

The focused registry coverage and contract tests were run with:

```text
PYTHONPATH=src pyenv exec python -m pytest -q \
  tests/unit/passes/test_pass_editor_section_coverage.py \
  tests/unit/passes/test_config_v2_editor_contracts.py
```

Result: `18 passed`.

The requested RED could not be reproduced because Tasks 1-3 were already
present at the reviewed base.

The initial cumulative UI gate reported `2 failed, 769 passed`; both failures
were the routing/removal tests failing during panel construction because the
fake Qt namespace lacked `QScrollArea`.

The initial ast-grep fixture reported `1 passed, 0 failed`, but the review
identified that it did not cover local `pass_id` equality or unrelated
membership precision.

## Review RED/GREEN

UI RED command:

```text
PYTHONPATH=src pyenv exec python -m pytest -q \
  tests/unit/ui/test_project_config_adapter_contract.py::test_routes_focus_duplicate_by_exact_row_and_share_draft_across_screens \
  tests/unit/ui/test_project_config_adapter_contract.py::test_remove_pass_keeps_rendering_remaining_rows_when_draft_is_invalid
```

Result: `2 failed`; both failed with
`AttributeError: 'types.SimpleNamespace' object has no attribute 'QScrollArea'`.

Ast-grep RED after adding the review fixtures:

```text
sg test --config sgconfig.yml --test-dir rule-tests \
  --filter no-pass-specific-config-v2-qt --skip-snapshot-tests
```

Result: failed because `field_id in {...}` was incorrectly reported and local
`pass_id == "..."` was not reported.

Review fixes:

- Added reusable `_ScrollAreaWidget` behavior to the existing fake-Qt fixture.
- Restricted equality and membership patterns to local `pass_id` and
  `$OBJECT.pass_id` expressions.
- Added valid unrelated `field_id` membership and invalid local equality
  fixtures.

## Final verification

```text
PYTHONPATH=src pyenv exec python -m pytest -q \
  tests/unit/ui tests/unit/passes/test_pass_editor_section_coverage.py
771 passed in 3.25s

sg scan --config sgconfig.yml --report-style short
0 violations

sg test --config sgconfig.yml --test-dir rule-tests \
  --filter no-pass-specific-config-v2-qt --skip-snapshot-tests
1 passed, 0 failed

PYTHONPATH=src pyenv exec lint-imports --config .importlinter
Contracts: 14 kept, 0 broken

PYTHONPATH=src pyenv exec ruff check \
  tests/unit/passes/test_config_v2_editor_contracts.py \
  tests/unit/passes/test_pass_editor_section_coverage.py \
  tests/unit/ui/test_project_config_adapter_contract.py
All checks passed!

git diff --check
clean
```

## Graphify

The required attempt was:

```text
graphify update .
```

It exited 1 after reporting:

```text
Nothing to update or rebuild failed - check output above.
Re-extracting code files in . (no LLM needed)...
[graphify watch] Rebuild failed: [Errno 1] Operation not permitted
```

The alternate `graphify . --update --no-viz` form was also attempted. It was
stopped after a bounded wait while scanning the worktree; its traceback ended
in `graphify.detect` with `KeyboardInterrupt`. No graph artifacts changed and
none were staged.

## Result

Review findings are fixed. The full required UI and architecture gates pass;
Graphify remains environment-blocked as recorded above.
