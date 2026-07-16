---
id: tcvpu-guv6
status: closed
deps: [tcvpu-z1b4]
links: []
created: 2026-07-15T23:52:25Z
type: feature
priority: 1
assignee: w00tzenheimer
parent: d81-38ha
tags: [ui, workbench, oracle]
---
# Slice 3: native decompile comparison

Capture an isolated native-decompile baseline and compare it with the latest D810 output using fingerprint and generation freshness metadata.

## Acceptance Criteria

Native capture suppresses D810 hooks for one decompilation without changing persistent engine state; baseline and D810 references carry fingerprint, IDB, type, Hex-Rays, runtime, and generation identity; stale output is never labeled current; pure freshness tests pass.


## Notes

**2026-07-16T00:29:34Z**

Implementation plan saved at docs/superpowers/plans/2026-07-16-deobfuscation-workbench-slice-3.md. It defines identity-bearing native/D810 artifacts, an IDA-independent freshness/metrics service, exact one-shot hook-suppressed native capture, pure comparison projection, thin adapter wiring, and deferred live acceptance.

**2026-07-16T22:52:00Z**

Live Docker/XQuartz acceptance completed on a fresh copied `abc_f6_add_dispatch @ 0x180001000` IDB. The fresh startup exposed that `late_init()` loaded the state/UI but did not start the manager; the lifecycle now calls `start_d810()` exactly once after a successful load and skips it when already started. Compare was enabled with `manager_started=true`, opened a modeless read-only Native/D810 tab dialog, and showed both artifacts Current. An instrumented capture recorded exactly `suppress-enter`, `decompile:0x180001000`, `suppress-exit`; manager state remained started before and after. Concrete identity matched across the function, baseline, and D810 output with fingerprint `sha256:6a9e491eeb3fd043ecfef888783aa5de3a236b0aa130fb320b272629b1642976`, copied-IDB path/ctime/input SHA-256, conservative type generation `db-change:13;ordinals:191`, Hex-Rays `9.3.0.260213`, runtime project `hodur_flag2_s1a_config_v2_canary.json`, six ordered pass IDs, and generation 2. Native measured 40 lines/693 characters versus D810 7 lines/150 characters; the UI correctly said only that pseudocode text differs. A drifted type identity projected both artifacts Stale, suppressed metrics, and returned no text verdict. Fresh automation audit: `.tmp/ida-gui/automation-0aebed31038fd1918ca1110e9c4cf813.json`. Qt capture: `.tmp/ida-gui/live-comparison-slice3-final.png`.
