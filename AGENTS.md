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
