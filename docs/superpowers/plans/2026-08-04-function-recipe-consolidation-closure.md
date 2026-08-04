# Function-recipe consolidation closure record

Status: completed, then tightened by the strict pass/execution-configuration
implementation on 2026-08-04.

The completed system has one public model:

1. Projects and function recipes contain ordered strict config-v2 pass entries.
2. Passes own typed options and stable transforms.
3. Passes expand to stable execution stages for scheduling and diagnostics.
4. `ExecutionScopeService` evaluates stage eligibility for both hooks and the
   Workbench.
5. Function recipes and tags are keyed by database identity, project, and EA.
6. Netnode is the default. SQLite is selected only by the typed
   `function_recipe_storage` application setting with an explicit safe path.
7. Saved recipes execute only through the atomic `Deobfuscate This` path.

The implementation deliberately removed the separate private-implementation
editor, persisted implementation overrides, compatibility aliases, inferred
storage locations, and public implementation-class diagnostics. Former data is
not migrated because its ownership and semantics cannot be established safely.

Verification is recorded by the strict plan in
`docs/superpowers/plans/2026-08-04-strict-pass-execution-configuration.md`.
