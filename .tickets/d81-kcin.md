---
id: d81-kcin
status: in_progress
deps: []
links: []
created: 2026-07-15T23:04:05Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, config-v2]
---
# Slice 0: truthful config-v2 project UI

Expose source and effective runtime project identity, make configuration duplication lossless, refuse unsafe config-v2 edits, show effective pass and expanded-rule counts, and lock the OLLVM routing behavior with a regression test.

## Acceptance Criteria

The current configuration UI distinguishes legacy and config-v2 projects; routed bundled defaults show source and runtime identities; config-v2 editing is read-only; duplication materializes the effective runtime document without dropping unknown or additional fields; the UI shows effective configured pass IDs and expanded instruction/block rule counts; the OLLVM bundled-default witness is covered; pure UI decisions are unit-tested in tests/unit/ui/test_*_logic.py.


## Notes

**2026-07-15T23:21:51Z**

Implementation plan saved at docs/superpowers/plans/2026-07-15-truthful-config-v2-project-ui.md. It defines lossless atomic core persistence, a manager-owned immutable snapshot and guarded command facade, pure project_config_logic action tests, thin ida_ui wiring, and the exact OLLVM 11-pass/180-instruction-rule/6-block-rule regression.

**2026-07-15T23:52:40Z**

Automated Slice 0 gates passed in diff/truthful-config-v2-project-ui through f31191d24: 127 focused tests; 5728 unit tests passed, 29 skipped, 9 baseline warnings, 162 subtests; ast-grep/import-linter/diff gates clean; OLLVM probe is exact 11/180/6; graph refreshed. Live IDA/Qt acceptance is intentionally deferred after the wrong IDA process was targeted; ticket remains open.

**2026-07-16T17:05:00Z**

Added and live-tested `tools/scripts/run_ida_gui_docker.sh` for worktree-aware XQuartz acceptance. The launcher preserves the image-owned Linux IDA registry, reuses host `cfg/d810`, `d810_function_rules.db`, and diagnostic logs through scoped mounts, mounts canonical samples read-only, and opens a byte-verified copy under the selected worktree. Eleven launcher contract tests pass. Live IDA 9.3 opened `/work/.tmp/ida-gui/libobfuscated.dll.2026-06-03.docker.on4e5h.i64` from `idapro-9.3:x11-arm64` with D810 loaded from `/root/.idapro/plugins/d810`; Docker reported the source sample mount `rw=false`, and the canonical database SHA-256 remained `61678430e3fe08f6bb23f41752faa22b57c805e8261277660933d01e3c046dab` before and after. This establishes the GUI test lane; the original truthful-config-v2 visual behavior still requires explicit workbench inspection, so the ticket remains open.

**2026-07-16T17:40:00Z**

The initial X11 base image mounted the selected plugin correctly but lacked the
Python Z3 layer required during D810 import. Added
`idapro-9.3-speedups:x11-arm64`, built from the X11 base through
`docker/Dockerfile.test-runtime`, with the virtualenv dependencies and isolated
`/root/.d810-speedups` Z3 installation. The launcher now defaults to this image
and refuses images missing
`org.d810.gui-runtime=x11-dev-emulation-z3-v1`. Fourteen launcher contracts
pass. Live IDA output reports `D810 initialized (version 0.6.6)` from the
selected worktree without the prior traceback, and the opened worktree copy
still matches the canonical source SHA-256. The ticket remains open for visual
workbench acceptance.

**2026-07-16T18:10:32Z**

Live config-window acceptance exposed a virtualenv-specific Qt detection bug:
IDAPython reported `sys.executable=/app/ida/.venv/bin/python3`, so `qt_shim`
misclassified GUI IDA as headless and substituted its proxy layouts. The first
real nested layout call then failed with `AttributeError: 'QVBoxLayout' object
has no attribute 'addLayout'`. Replaced the executable-name heuristic with
IDA's own `idaapi.is_idaq()` oracle and added a regression for virtualenv-backed
IDAPython. The live post-fix probe reports `qt_available=true`, binding
`PySide6`, layout module `PySide6.QtWidgets`, and `addLayout=true`. The D-810
Configuration dock now renders the routed OLLVM source/runtime identities, 11
effective passes, and 180 instruction / 6 block expanded rules without the
callback traceback. Verification: 5906 unit tests passed, 29 skipped, 9
unchanged contract-vocabulary warnings, and 162 subtests; ast-grep, all 13
import contracts, and diff checks are clean.

**2026-07-16T18:27:02Z**

Persisted the complete live-session checkpoint and remaining GUI acceptance
work in
`docs/superpowers/plans/2026-07-16-d810-gui-session-worklist.md`. The approved
automation contract supports both deterministic fresh-launch actions
(`--open-config` and `--open-workbench`) and explicit control of an existing
MCP-enabled IDA session with `--connect`. Fresh actions do not require MCP;
fresh-session MCP is opt-in, and every Docker MCP publication is restricted to
host loopback. The worklist also records the safe copied-DLL lane, Qt root
cause and live proof, current ticket boundaries, structured audit schema,
function-override reuse, and the remaining workbench/recipe/config-v2/SQLite
live gates.
