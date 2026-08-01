---
id: tcvpu-9q3g
status: closed
deps: [tcvpu-v3qt]
links: []
created: 2026-07-18T00:00:00Z
type: task
priority: 1
assignee: w00tzenheimer
---
# Verify the guided Workbench attack flow in IDA 9.3/PyQt6

Launch the existing XQuartz-capable ARM64 IDA 9.3 image through the audited
worktree-aware launcher, open a disposable copied input, and verify the
Workbench's ready card plus its direct deobfuscation/automatic-comparison
transition. Do not save or modify the source binary or source database.

## Evidence

- Image: `idapro-9.3-speedups:x11-arm64`, labelled
  `org.d810.gui-runtime=x11-dev-emulation-z3-v1`.
- Fresh audited launch: `.tmp/ida-gui/automation-16d7bf546a65ecc3c54186d0b9199487.json`.
  It opened `test_function_ollvm_fla_bcf_sub` at `0x18000E790` and focused the
  `d810-ng Deobfuscation Workbench`.
- The live PyQt6 form initially showed `Ready to deobfuscate …` with the
  enabled `Deobfuscate this function` action. Invoking that exact action through
  the loopback MCP panel reference returned an accepted, successful, refresh-
  requesting `deobfuscate` result. The refreshed form showed `Pseudocode text
  differs` and the primary action changed to `View comparison`.
- Both comparison artifacts were current. The native-vs-D810 evidence was
  1,037 -> 595 lines (delta -442) and 55,940 -> 17,802 characters (delta
  -38,138). This is comparison evidence, not a semantic-correctness claim.
- Captures: `.tmp/ida-gui/task9-ida93-direct-action.png` and
  `.tmp/ida-gui/task9-ida93-workbench-result.png`.
- The source `.i64` and disposable copy both retained SHA-256
  `7ca01821ea10e81dba2bc95ba8b4a20d45d6fbe76ad423b7464e3533b867a221`
  after the container was stopped without saving.
