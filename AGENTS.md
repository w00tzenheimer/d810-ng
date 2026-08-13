# Agent Instructions

## Architecture Boundary Failures

When fixing architecture-sensitive ast-grep or import-linter failures, treat
the local worktree configuration as the source of truth.

- Before fixing ast-grep failures, read the relevant YAML rule under `rules/`.
  Treat the rule's top comment, `message`, `note`, `files`, and `ignores` as
  authoritative.
- Do not fix ast-grep failures by adding new ignores unless explicitly asked.
  Move code to the layer indicated by the rule, or introduce the
  backend, observability, or adapter boundary described by the rule.
- Before changing imports or import-linter ignores, read `.importlinter` from
  the target worktree. Treat its contracts and `ignore_imports` entries as
  authoritative.
- Do not add `.importlinter` `ignore_imports` exceptions unless the import is a
  deliberate compatibility bridge and the dependency cannot be inverted yet.
- Run these commands from inside the target worktree before claiming the
  boundary issue is fixed:

```bash
sg scan --config sgconfig.yml --report-style short
PYTHONPATH=src lint-imports --config .importlinter
```

`lint-imports` analyzes the current working directory's `src` tree and
`.importlinter`. Running it from the root checkout does not validate a separate
`.worktrees/<name>` checkout.

## Running Tests

Unit tests run locally. IDA-dependent tests (`tests/system/**`) run in the IDA 9.4
Docker runtime via `tools/scripts/run_system_tests_docker.sh` — note
`tools/scripts/`, not the repo root.

```bash
# always from the MAIN repo root, never from inside a worktree
./tools/scripts/run_system_tests_docker.sh test   -w <worktree> -o out.txt -- tests/unit/... -q
./tools/scripts/run_system_tests_docker.sh system -w <worktree> -l -o out.txt -- -k <expr>
./tools/scripts/run_system_tests_docker.sh exec   -w <worktree> -- bash -c '$PYTHON -c "..."'
```

`system` runs `pytest tests/system -v`; `test` runs `pytest -v` so you pass your
own path. `-w REL` mounts `REPO_ROOT/.worktrees/REL` as `/work`. `-o FILE` writes
stdout+stderr to `<worktree>/.tmp/FILE` and takes a bare filename, not a path.
`-l` mounts `.tmp/logs` at `/root/.idapro/logs`. The image is
`idapro-9.4-speedups:latest` via the repo `.env`; the runner prints the override.

Four things that reliably waste time:

- **Invoke from the main repo root.** `D810_REPO_ROOT` defaults to
  `git rev-parse --show-toplevel` from the current directory, and inside a
  worktree that resolves to the worktree itself, breaking `-w`.
- **Locally, prefix worktree commands with `PYTHONPATH=src`.** Otherwise
  `import d810` resolves to the root checkout's `src/d810` and your worktree
  edits are silently not under test. This applies to `pytest` as much as to
  `lint-imports`.
- **The runtime has unicorn but not capstone, keystone, or z3.** capstone is not
  a declared dependency anywhere; unicorn is, as the `emulation` extra. A test
  guarded by `pytest.importorskip("capstone")` disappears in CI while still
  passing on a developer host, so do not let one carry a correctness guarantee
  on its own.
- **Worktrees share the root's git hooks but not its untracked files.** If a
  hook shells out to a script that is untracked and present only in the root
  checkout, it aborts by absence in every worktree and can report a misleading
  cause. This bit the pre-commit `ida-plugin.json` check until `f8acf9b15`
  tracked `tools/sync_plugin_version.py`; the hook works in worktrees now. The
  general lesson stands: when a hook fails in a worktree, check whether the file
  it needs is tracked before concluding your change is at fault, and re-check
  after any rebase rather than carrying the old conclusion forward.

## Unflattening Safety Lessons

- Never report a microcode block serial without an accompanying EA anchor
  (for example, `blk77@0x40ADE6`). Block serials are maturity- and
  snapshot-local; use the EA anchor as the stable identity when comparing
  diagnostics, logs, tests, handoffs, or results across maturities.
- Profile-specific guards must stay profile-scoped. Do not apply OLLVM
  dispatcher-entry prefix/payload vetoes to Tigress indirect or other profiles
  unless the profile explicitly opts in.
- Hard safety vetoes for state-DAG rewrite batches are fragment-atomic. If an
  actionable non-state use-def severance is found, reject the whole fragment;
  do not drop one redirect and apply the remaining sibling redirects.
- Dispatcher state-slot use-def changes are expected plumbing during state-DAG
  lowering. Non-state severance is the safety boundary.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
