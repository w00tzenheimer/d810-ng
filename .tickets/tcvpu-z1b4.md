---
id: tcvpu-z1b4
status: closed
deps: [tcvpu-nyvc]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, workbench, actions]
---
# Slice 2: scoped workbench interaction

Add read-only Analyze, lifecycle-safe Deobfuscate, existing function-override integration, generation-aware refresh, and stale-result rejection.

## Acceptance Criteria

Analyze cannot invoke mutation; Deobfuscate delegates to the existing manager lifecycle exactly once; existing function rule/tag/note persistence and invalidation remain authoritative; async results are generation checked; pure action tests and runtime adapter contracts pass.


## Notes

**2026-07-16T00:17:19Z**

Implementation plan saved at docs/superpowers/plans/2026-07-16-deobfuscation-workbench-slice-2.md. It defines immutable generation-bound commands, direct recon-only Analyze, exact-once reuse of existing Deobfuscate and FunctionRules actions, pure stale-result rejection, thin context adaptation, and deferred live Qt acceptance.

**2026-07-16T00:27:41Z**

Terminal-only Slice 2 implementation completed through ea212f738. Focused workbench/action gate: 55 passed; FunctionRules regression: 7 passed; full unit gate: 5776 passed, 29 skipped, 9 unchanged contract-vocabulary warnings, 162 subtests in 64.74s. ast-grep/import-linter/diff clean. Analyze is direct recon collect_and_analyze(persist_hints=True) with source tests excluding refresh/decompile/optimizer/mutation/apply_hints; existing Deobfuscate and FunctionRules lifecycles are invoked exactly once; generation mismatch rejects stale completions. Live Qt/IDA command acceptance remains deferred, so ticket stays in_progress.

**2026-07-16T22:28:00Z**

Live Docker/XQuartz command acceptance completed on `abc_f6_add_dispatch @ 0x180001000` in a fresh copied sample IDB. The live session exposed and fixed two terminal-only blind spots: the stored IDA action context expired after the Stats action returned, so the command adapter now captures the stable pseudocode `TWidget` and reacquires/validates its current `vdui` for each command; and fresh direct plugin loading left optimizer registries empty, so manager startup now scans the optimizer tree before constructing hooks. Fresh-start evidence went from 0 to 8 registered instruction optimizers and `manager_started=true` without a preceding reload. Analyze completed at maturity 8, classified `ollvm_flat` with confidence 1.00, advanced the workbench generation, and left optimizer statistics unchanged. A forced in-flight generation advance produced `Analyze completed for an older workbench generation`, kept generation 3 rendered stale while service generation reached 4, and returned current only after refresh to generation 5. Deobfuscate invoked the established `DeobfuscateThisFunction.execute()` exactly once and refreshed generation 6 to 7. Function override opened the real modal dialog, then the existing action/save path persisted one disabled rule, tag `codex-slice2-live`, and note `Slice 2 live persistence proof` in the existing function-rules store; all three survived `D810.reload()` and appeared in the workbench. The test function was restored to its original absent override and empty tags afterward. Fresh automation audit: `.tmp/ida-gui/automation-0996e0bb2715d3ff5ac712f5bb8f0d4f.json`; post-reload audit: `.tmp/ida-gui/automation-ae7c3915d2921b471c5efdb28214b4ef.json`.
