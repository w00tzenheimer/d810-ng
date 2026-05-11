# Debug tooling migration

Living index of the **post-hoc diagnostic surface**. The goal is to make
`tools/cff_debug.py` the single human-facing debug front door while keeping
real parsing / report logic in `d810.diagnostics` with unit tests.

## Architecture rule (do not violate)

```text
tools/cff_debug.py = workflow orchestration + path/default convenience
d810.diagnostics   = tested diagnostic parsers, DB queries, reports
d810.core.diag     = capture-time substrate (schema, snapshot writers,
                     mba/cfg provenance serializers, session lifecycle)
tools/scripts/*.py = compatibility wrappers until migrated/deprecated
```

`d810.diagnostics` sits **above** `d810.optimizers` in the `.importlinter`
layered stack; `d810.core.diag` stays at the bottom. The post-hoc package
may import freely from any runtime layer; runtime layers may NOT import the
post-hoc package.

Invocation: `python -m d810.diagnostics ...` (the `python -m d810.core.diag`
entry point was removed in commit `9165c1b3`).

## Command map

| old script / tool | new diag command | new cff_debug wrapper | status |
|-|-|-|-|
| `tools/scripts/extract_after_pseudocode.py` | (kept; small) | `cff_debug.py after` | wrapped |
| `tools/scripts/inspect_hodur_dump.sh` | (kept; small) | `cff_debug.py inspect` | wrapped (ported to Python) |
| `tools/scripts/inspect_linearized_state_node.py` | (kept; small) | `cff_debug.py state` | wrapped |
| HCC byte-cascade tracer log | `python -m d810.diagnostics hcc-byte-cascade-trace` | `cff_debug.py trace` | done (commit `9165c1b3`) |
| `tools/scripts/terminal_tail_audit.py` | `python -m d810.diagnostics terminal-tail-audit` | `cff_debug.py byte-audit` | **TODO (next)** |
| `tools/scripts/gate_audit.py` | `python -m d810.diagnostics gate-audit` | `cff_debug.py gates` | TODO |
| `tools/scripts/reconcile_dispatcher_redirects.py` | `python -m d810.diagnostics redirect-reconcile` | `cff_debug.py reconcile` | TODO |
| `tools/scripts/return_family_ledger.py` | `python -m d810.diagnostics return-ledger` | `cff_debug.py returns` | TODO |
| `tools/scripts/region_oracle.py` | `python -m d810.diagnostics region-shape/region-diff` (already exists) | `cff_debug.py oracle` | partly done; needs wrapper |
| `tools/scripts/terminal_tail_cascade_egress_plan.py` | `python -m d810.diagnostics cascade-egress-plan` | `cff_debug.py egress-plan` | TODO |

## Migration recipe (per command)

1. Add a module under `src/d810/diagnostics/<name>.py` — keep it
   parser/query based; avoid optimizer imports so it stays unit-testable.
   If optimizer imports are unavoidable, put the tests under
   `tests/system/runtime/` instead of `tests/unit/diagnostics/`.
2. Register a subcommand in `src/d810/diagnostics/__main__.py`. Use
   `parents=[common]` so it gets `--db`, `--snapshot`, `--maturity`,
   `--phase`. Add `--json` flag where reasonable.
3. Add unit tests under `tests/unit/diagnostics/test_<name>.py`. Use
   synthetic sqlite fixtures or text inputs; do not require a real diag
   DB.
4. Add a wrapper subcommand in `tools/cff_debug.py` that resolves
   worktree paths, locates latest dump/log/DB, passes defaults like
   function/project, calls `python -m d810.diagnostics`, and prints
   paths. Wrapper must NOT contain SQL or log parsing.
5. Leave the old `tools/scripts/<name>.py` untouched, OR add a top
   comment:

   ```text
   Prefer: python -m d810.diagnostics <command>
   ```

   Do NOT delete old scripts in a migration pass.

## Acceptance criteria per migration

- `python -m d810.diagnostics --help` lists the new subcommand.
- `./tools/cff_debug.py <wrapper> --help` works.
- `tests/unit/diagnostics/test_<name>.py` runs green.
- Import-linter remains clean.
- No HCC / unflattening behaviour changes.

## Non-goals (do not absorb)

- `tools/d810_debug.py` (different runtime: in-process IDA debugger)
- `tools/scripts/run_system_tests_docker.sh` (Docker harness driver)
- `tools/scripts/codemod_*.py` (historical phase migrations)
- `tools/equivalence/` (equivalence harness)
- `tools/hexrays_structuring_lab/` (structurer experiments)
- `tools/bisect_rule*.py` / `tools/analyze_verify_failures.py` (different niches)
- `tools/vendoring/`
