---
id: lrea-t5gy
status: in_progress
deps: []
links: [dsf-katd, lrea-8gml]
created: 2026-07-22T01:23:57Z
type: bug
priority: 0
assignee: w00tzenheimer
tags: [decompilation, rhad, preopt, identity, mutation, regression]
---
# Restore the exact four-function Rhad semantic matrix

Repair lifecycle-integration regressions that disconnected previously observed Rhad evidence. Treat sub_40D200 as semantically green pending oracle reconciliation; restore real semantic failures in sub_40A560, sub_40C8B0, and sub_40CDA0. This is required follow-up to dsf-katd, whose closeout did not execute its stated four-function acceptance matrix.

## Design

Represent each terminal return as one fragment-atomic mutation through MbaMutationGateway: route edge, return carrier, and terminal m_ret are planned, applied, verified, and receipted together. A disconnected synthetic m_ret is forbidden. Any identity ambiguity, non-state use-def severance, or ownership mismatch rejects the whole fragment. Diagnostic DB lifecycle events must correlate evidence generation, stable EA identities, mutation plan, and receipt. No compatibility layer and no production sample-EA guards.

## Acceptance Criteria

Fresh cache-disabled exact Docker matrix is semantically 4/4 in one run: sub_40A560 matches its established side-effect and terminal-return oracle; sub_40D200 matches native semantics after correcting only an oracle proven stale by raw native comparison; sub_40C8B0 and sub_40CDA0 recover their established full bodies without dispatcher stubs or JUMPOUT exits. The diagnostic DB records one atomic terminal fragment plan/receipt containing carrier, m_ret, and route edge, with full-fragment abstention tests. Hodur, Sub7ffd, Tigress, and Approov remain green. Focused runtime/unit suites, sg scan, all 14 import contracts, graphify update, and Docker operation pass. Work is committed logically and the worktree is clean.


## Notes

**2026-07-22T01:24:07Z**

2026-07-21 baseline audit: fresh preserved donor aa0438157 exact Docker four-function matrix was 4 failed in 475.08s. Semantic classification: sub_40D200 emitted a full structured body with zero while loops and is green; its exactly-one-while assertion is stale/overconstrained and must be reconciled against native output. Real failures: sub_40A560 recovered None; sub_40C8B0 ended JUMPOUT(0x40CD46); sub_40CDA0 ended JUMPOUT(0x40CEAB). Donor log: /Users/mahmoud/src/idapro/d810/.tmp/rhad_aa043_four_matrix_20260721.txt. Current branch at 4ace85587 has A560 nearly matching but ends JUMPOUT(0x40C898); capture-time disconnected m_ret WIP is rejected by design and will be replaced with an atomic carrier plus terminal plus route fragment.

**2026-07-22T04:22:39Z**

Reference parity audit on SHA256 244907...35e4c: unchanged ../cff/rhadamanthys-loader-deobfuscator commits 228/37/13/270 indirect-jump rewrite transactions and 93/13/5/97 flow-route transactions for A560/C8B0/CDA0/D200. D810's recorded static-fixpoint counts already match the first three indirect counts exactly, so the first-stage resolver is not the primary gap. The missing authority is per-site flow-state delivery: current evidence collapses state-to-handler mappings and later asks Hex-Rays to rediscover source-site routes. Machine-readable reference ledger: .tmp/rhad_reference_parity_ledger.json. A560 example: reference writes EBX=0xABB95547 at 0x40A5B2 and commits 0x40A5C8 -> 0x40BECC; D810 knows state 0xABB95547 -> 0x40BECC only at handler-entry source 0x40BEB2, not as portable authority for the native source site.

**2026-07-22T20:19:34Z**

2026-07-22 pivot: exact A560 at HEAD 8fd8e6b21 timed out after the 91-route fragment bound (event 2598) and its 92-item/93-operation live copy-and-swap receipt committed (event 2600), then stalled in later CALLS. This rejects large live-MBA repair on liveness even after fixing false fallthrough receipts. New design authority: lower reference state-write and entry-consumer routes into the detached template before publication; validate closed fragment ownership, reachability, original supersession, dispatcher exclusion, predicates, targets, terminal carriers, and returns; publish once at the root and receipt semantic publication, not API call count. Preserve committed identity/predicate/consumer/gateway fixes.

**2026-07-22T21:27:09Z**

Phase 1 migration checkpoint: the versioned-proxy bridge covers explicit replacement staging, transaction-local resolution, commit lineage, abort discard lineage, and deterministic native-EA ambiguity. It is not Phase 1 acceptance. Before architecture acceptance, migrate every initial binding and insert/split/clone/remove path to proxy authority, delete _stale_tokens and direct baseline-token mutation as semantic authority, and add an architecture test proving no structural mutation path bypasses proxy commit/abort. Exact A560 remains prohibited until that removal is complete.

**2026-07-22T21:38:41Z**

Phase 1 cutover update: every initial live binding now owns a logical proxy; insert, replacement, split, clone, and removal use transaction-local serial overlays plus proxy stage/commit/abort; _stale_tokens was deleted; refresh rebuilds proxy authority while preserving uniquely proved handles. Evidence: 63 local identity/gateway/architecture tests green and pinned Docker resolver/deferred runtime 133/133 green at .tmp/phase1-versioned-proxy-runtime-full2.txt. Phase 1 remains open: planned-serial resolution still exists for legacy DeferredGraphModifier callers and receipts do not yet version every semantic edge edit; Phase 2 must replace that with the single role-aware semantic-edge operation before acceptance.

**2026-07-22T22:31:00Z**

Phase 2 authoritative-operation slice: added serial-free direct, conditional-taken, and conditional-fallthrough roles over versioned logical proxies. MbaMutationGateway now owns proxy validation, batch creation, plan observations, backend dispatch, explicit abort, and receipt commit. DeferredGraphModifier alone maps the roles to zero-way materialization, one-way redirection, explicit taken-arm replacement, adjacent-helper fallthrough, or one predicate plus both destinations as a three-operation atomic group. Unsupported shapes, stale expected arms, foreign proxies, and helper failures raise and abort instead of skipping an arm. Evidence: 53 focused local tests green; pinned Docker semantic-edge, deferred-modifier, and resolver-session suites 142/142 green at .tmp/phase2-semantic-edge-runtime-full.txt; sg scan clean; all 14 import contracts kept. The legacy serial-shaped queue paths remain only for later Phase 7 deletion after canonical FragmentPlan lowering is live; they are not a fallback used by the new operation. Exact A560 remains prohibited.

**2026-07-23T17:33:52Z**

Post-success architectural hardening and cleanup is tracked separately in lrea-8gml. It enforces that gateway/mutation code may only realize and verify explicit FragmentPlan obligations, never recover or construct semantic intent, and inventories/removes temporary publication scaffolding after Rhad 4/4 and protected-family success. It depends on this ticket and is not on the current restoration critical path.

**2026-07-23T17:38:45Z**

Execution strategy superseded by /Users/mahmoud/src/idapro/d810/_gitless/RHAD_DEOBFU_STRAT_v3.1.md. It retains the v3 ownership model and adds the iterative vertical loop, continuous diagnostic A560 canaries, C0-C6 evidence levels, a one-fragment C5 milestone, restart-safe rollback semantics, and liveness/performance budgets. Exact A560 acceptance remains architecture-gated. Post-success verifier-boundary and cleanup work remains tracked in lrea-8gml.

**2026-07-23T17:51:05Z**

v3.1 restart-safe checkpoint, amending this active ticket without replaying completed work. Authoritative code state is HEAD 750bda9d21 on diff/lifecycle-resolver-evidence-authority plus the current 18-file dirty worktree (+1172/-1515). Phase 1 and Phase 2 foundations are committed, although their remaining acceptance obligations still include legacy planned-serial deletion and complete proxy/receipt coverage. Phase 7 has committed deletion of the residual byte materializer plus static and concolic portable-normalization evidence publication at 744d6ae2d, 1cbbde955, and 750bda9d21. The dirty logical slice spans Phase 5 frontend-normalization planning, Phase 3 detached native-body realization, Phase 4 rejection/lifecycle observation, Phase 7 resolver thinning, and Phase 8 typed diagnostic rejection: it splits stale native FlowChart ownership at resolver-proven semantic leaders, plans absent-source proofs through a portable FragmentPlan, records planning rejection in the diagnostic DB, accepts the real hxe_preoptimized GENERATED/PREOPTIMIZED callback window, and exposes PREOPT-template binding failures as aborted receipts. Phase 6 canonical state-transition planning and the complete Phase 3 vertical C5 fragment are not yet proved.

Latest primary evidence before the next implementation change is `.tmp/logs/d810_logs/00000001800020f0_1784828655_9.diag.sqlite3` for the generic x86_64 computed-goto fixture. The pinned image remains `sha256:360f91d9d4ace70d89e03893f1d895d94383fa0fe426ddba9d3898a7922b650a`. This generic run reaches C1: evidence generation 1 is accepted and a 26-operation frontend-normalization plan is recorded. It does not reach C2: fragment staging fails after one applied operation, rollback succeeds, and the receipt aborts. The first failed obligation is unique realization of native body `native-body:frontend-normalization:g1`: the portable block anchored at 0x1800020F0 matches both an empty topology template block and a substantive PREOPT template block, while later portable native blocks also span multiple PREOPT microblocks. No pre-publication validation outcome, root publication, post-validation, or committed receipt exists, so C3-C6 are not claimed. The current dirty frontend/resolver/maturity slice has not yet received an A560 diagnostic canary; its A560 C level is therefore unverified, not inherited from an older run. Finish and verify this logical slice, run the A560 diagnostic canary immediately, record its highest completed C level and first failed DB obligation, then continue the v3.1 vertical loop to one complete C5 real fragment before any broad 91-route publication. lrea-8gml remains outside this restoration critical path.

**2026-07-23T18:38:12Z**

The current Phase 3/5/7/8 slice now has one complete C5 vertical publication on the generic x86_64 computed-goto fixture. Its primary DB is `.tmp/logs/d810_logs/00000001800020f0_1784831724_9.diag.sqlite3`: evidence generation 1 is accepted, the frontend-normalization FragmentPlan contains 20 operations, all 20 are applied, prepublication validation passes, root publication and postvalidation complete, and event 16 records a committed receipt. The source-generation envelope remains broad, but publication membership now excludes the disconnected native prefix at 0x1800020F0 and contains only blocks forward-reachable from required missing-entry roots. This is C5, not C6: the fixture's later semantic effects assertion still fails. Focused evidence is 18/18 frontend-normalization unit tests, 9/9 pinned-Docker materializer/undefined-INT3 runtime cases, and a clean Ruff pass. The progress is secured as three logical commits: resolver mutation-authority deletion `7caefe0e4`, detached frontend-normalization planning `e6dedf31c`, and transactional PREOPT native-body materialization `b755a47f2`.

The mandatory current-WIP A560 canary completed in 16.27 seconds with no segfault or INTERR. Its primary DB is `.tmp/logs/d810_logs/000000000040a560_1784831820_10.diag.sqlite3`; output is a short body ending `JUMPOUT(0x40B6C0)`. Highest completed A560 level is C1: generation 1 records accepted PREOPT entry-bridge, terminal-return-carrier, native-fact, and bootstrap-route evidence. C2 is not reached because event 7 rejects frontend-normalization planning with the first failed obligation `proof 'native-indirect-transfer@0x40A619' detached source is not owned by the import request`. There is no mutation plan, semantic-fragment transaction, or receipt in this A560 run. Continue the v3.1 vertical loop from that import-root ownership failure; do not broaden to the 91-route publication and do not claim A560 acceptance.

**2026-07-23T18:50:55Z**

The next A560 vertical-loop canary completed in 14.32 seconds with no segfault or INTERR after commit `a0318daad` made every absent proof source a required detached root, normalized missing anchors to unique native block entries, and preserved conditional-owner disambiguation. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784832616_11.diag.sqlite3`. Highest completed level remains C1 because no mutation plan, transaction, or receipt exists. The previous `native-indirect-transfer@0x40A619` source-ownership rejection is gone. The new first failed obligation is event 7: frontend-normalization planning rejects because detached block `0x40A68C` targets an unavailable block. Continue from that exact native-EA-anchored target-ownership gap; do not broaden publication.

**2026-07-23T18:56:39Z**

The diagnostic-first refinement makes the current A560 C1 failure self-contained in the primary DB. Canary DB `.tmp/logs/d810_logs/000000000040a560_1784832878_11.diag.sqlite3` records event 7 as `detached block 0x40A68C direct_jump target 0x40A6A0 is unavailable`. Highest completed level remains C1: no FragmentPlan, transaction, or receipt exists. The next v3.1 obligation is therefore exact publication ownership for the native direct edge `0x40A68C -> 0x40A6A0`; do not infer it from logs or broaden to the 91-route publication. The diagnostic change is covered by the full frontend-normalization unit file, 20/20 green, with Ruff and diff checks clean.

**2026-07-23T19:10:04Z**

The native-leader ownership loop required two committed slices. Commit `eed296c37` promoted existing FlowChart successors to semantic leaders but its canary DB `.tmp/logs/d810_logs/000000000040a560_1784833551_11.diag.sqlite3` remained C1 at the same `0x40A68C -> 0x40A6A0` rejection because that leader appears only after native re-decode. Commit `5bf446526` revisits any previously owned native fact crossed by a decode-discovered successor; its primary canary DB is `.tmp/logs/d810_logs/000000000040a560_1784833729_11.diag.sqlite3`. The prior target-ownership rejection is gone and event 15 records an 822-operation frontend-normalization plan. Highest completed A560 level is still C1, because C2 normalization did not publish: native-body staging applied one operation, then failed with `native body 'native-body:frontend-normalization:g1' requires exactly one PREOPT union template, observed 0`; the transaction records `fragment_staged=0`, no validation or root-publication attempt, and a successful rollback with an aborted receipt. Do not solve this by publishing the full 822-operation fragment. The next v3.1 obligation is to select and carry one complete real vertical fragment through C5 before broadening fragment size.

**2026-07-23T19:31:33Z**

Commits `63a3e07ba` and `a60a3715e` introduce explicit normalization work-item scope, select one deterministic publication-root component, and keep generation-wide authority unadvanced after a committed partial receipt. The pinned focused architecture/runtime gate is 333/333 green. The mandatory A560 canary at `a60a3715e` completed in 10.42 seconds without a segfault or INTERR; primary DB: `.tmp/logs/d810_logs/000000000040a560_1784834880_12.diag.sqlite3`. Event 15 now records a 73-item mutation plan whose portable fragment has 42 blocks, one root, one owned original, 34 operations, one 33-block native body, 3 selected proof obligations, and 225 explicitly remaining obligations. This is the intended narrow real fragment, not broad 91-route publication.

Highest completed A560 level remains C1. C2 staging applied one operation, then aborted before fragment staging, validation, or root publication; rollback succeeded and event 24 records the aborted receipt. The first failed obligation is unique PREOPT-template realization: the only current candidate is the PREOPT union cached at provenance anchor `0x40A5CA`, but `_select_template_blocks` rejects it as `target_not_entry` because the selected body enters at `0x40A607` and `0x40B6C0`. The next falsifiable hypothesis is that a union cache target is provenance, not publication-entry authority: selection should require matching maturity, complete native-range ownership, and unique exact block-identity coverage, while continuing to reject zero or multiple matching templates. Do not broaden the work item.

**2026-07-23T19:34:41Z**

Commit `769419dfd` removed cache-key equality as template authority while preserving PREOPT maturity, complete range ownership, unique block-identity coverage, and zero-or-multiple-candidate rejection; the expanded pinned gate is 341/341 green. Its mandatory A560 canary completed in 11.09 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784835103_11.diag.sqlite3`. The selected fragment remains unchanged at 42 blocks, 34 operations, 3 selected proofs, and 225 remaining proofs. Highest completed level remains C1: event 24 records an aborted 73-item transaction after one applied operation, `fragment_staged=0`, no validation, no root publication, and successful rollback. The prior template-selection rejection is gone. The new first C2 obligation is typed as `PREOPT native body topology is not owned by exactly one compatible FragmentPlan operation`. Continue by identifying the exact native-EA-anchored block and operation mismatch inside this selected fragment; do not weaken the one-operation ownership rule and do not broaden the work item.

**2026-07-23T19:37:02Z**

Commit `e84303ad4` made PREOPT topology rejection self-contained and native-EA anchored in the diagnostic DB. The mandatory A560 canary completed in 14.43 seconds without a segfault or INTERR; primary DB: `.tmp/logs/d810_logs/000000000040a560_1784835379_12.diag.sqlite3`. Highest completed level remains C1. Event 24 records an aborted 73-item transaction after one applied operation, `fragment_staged=0`, no validation or root publication, and successful rollback. The exact first C2 obligation is `native[0x40A607-0x40A615]:imported@0x40A607`: the FragmentPlan owns one operation, `native-body-edge@0x40A607`, with one edge, but its matched PREOPT template block has a conditional tail. The next vertical-loop hypothesis is a capture/split topology mismatch at this native range; preserve one-operation ownership, identify why the template retains a conditional tail, and do not broaden the work item.

**2026-07-23T19:43:40Z**

Commit `b0040501c` corrected the underlying portable native evidence: native re-decode now retains both conditional arms even when IDA does not claim the fallthrough and records the exact predicate EA. Its pinned native-closure gate is 24/24 green. The mandatory A560 canary completed in 13.63 seconds without a segfault or INTERR; primary DB: `.tmp/logs/d810_logs/000000000040a560_1784835760_11.diag.sqlite3`. Highest completed level remains C1. Event 15 records a 254-item plan; event 24 records one applied operation, failed staging, successful rollback, no validation or root publication, and an aborted receipt. The prior `0x40A607` topology mismatch is gone. The first failed C2 obligation is unique PREOPT identity realization for the portable block anchored at `0x40AE3E`, which has zero matching template blocks. Restoring the missing false arms also proves that choosing the lowest-EA publication root can expand to a 254-item closure, so this is not an acceptable first real-fragment C5 candidate. Before pursuing the `0x40AE3E` realization gap, select a deterministic complete root component whose full branch and dependency closure is minimal; do not reintroduce incomplete edges or broaden toward the 91-route publication.

**2026-07-23T19:50:33Z**

Commit `b8dbd7e16` now selects a deterministic complete normalization work item by minimizing the full forward operation closure plus every flag-corridor dependency; its focused v3.1 pinned-Docker architecture gate is 342/342 green. The mandatory A560 canary completed in 11.76 seconds without a segfault or INTERR; primary DB: `.tmp/logs/d810_logs/000000000040a560_1784836012_11.diag.sqlite3`. Highest completed level remains C1. Event 15 still records a 254-item plan rooted at native EA `0x40A5F0`; event 24 records one applied operation, failed staging, successful rollback, no prepublication validation or root publication, and an aborted receipt. The first failed C2 obligation remains unique PREOPT identity realization for the portable block anchored at `0x40AE3E`, which has zero matching template blocks.

This falsifies the root-choice hypothesis for the live A560 publication graph: every currently eligible live root reaches the same large missing native closure, so root selection alone cannot furnish the required bounded real-fragment C5 milestone. Do not weaken complete-edge ownership, call the 254-item plan the small milestone, or broaden toward the 91-route publication. Prove a controlled complete real A560 fragment through C5 first, then resume the main A560 loop from the `0x40AE3E` identity-realization failure.

**2026-07-23T20:06:00Z**

Commit `ecf749c1b` makes frontend-normalization block IDs distinguish topology-only and instruction-backed blocks that share native ranges by including exact instruction EAs in the portable identity token. The focused pinned-Docker planner and manager-adapter gate is 28/28 green, and the commit-time sg scan and all 14 import contracts pass. Its mandatory A560 diagnostic canary completed in 11.61 seconds without a segfault or INTERR; primary DB: `.tmp/logs/d810_logs/000000000040a560_1784837117_11.diag.sqlite3`. The semantic result remains the short body ending `JUMPOUT(0x40B6C0)`.

Highest completed A560 level remains C1. The DB records accepted generation-1 evidence and a 254-item mutation plan rooted at native EA `0x40A5F0`; staging applies one operation, then aborts with successful rollback, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt. The first failed C2 obligation remains unique PREOPT identity realization for the portable block anchored at native EA `0x40AE3E`, which has zero matching template blocks. This proves the same-range identity collision was real but was not the main A560 blocker. Continue first to the required controlled real-Rhad C5 fragment; after that milestone, resume the main vertical loop at `0x40AE3E` without broadening to the 91-route publication.

**2026-07-23T20:20:24Z**

Commit `d6372c0f2` makes canonical semantic binding compare a supplied `StableBlockIdentity` before falling back to a unique native anchor. This disambiguates the real A560 carrier-owning block from the maturity-local taken-arm helper that shares branch EA `0x40C7F6`; the focused pinned-Docker semantic-evidence and canonical-plan gate is 14/14 green, with commit-time sg scan and all 14 import contracts passing. The required main A560 canary completed in 11.80 seconds without a segfault or INTERR; primary DB: `.tmp/logs/d810_logs/000000000040a560_1784837997_11.diag.sqlite3`.

Highest completed main-A560 level remains C1. The DB again records a 254-item plan, one applied operation, an aborted receipt with successful rollback, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt. The first failed C2 obligation remains the portable block anchored at native EA `0x40AE3E`, which has zero matching PREOPT templates. In the controlled real-terminal vertical loop, exact binding now succeeds and the next C2 obligation is distinct terminal-effect identity: route target `0x40C898` names the epilogue entry, while the native return instruction is `0x40C89F`. Carry both stable EAs in portable terminal evidence before retrying C5; do not infer semantic success or broaden publication.

**2026-07-23T20:37:10Z**

Commit `d1a415b79` makes terminal control-flow target identity and terminal return-instruction identity distinct and mandatory: the A560 epilogue route still targets native EA `0x40C898`, while portable carrier evidence, canonical planning, and terminal lowering now own the exact native `ret` at `0x40C89F`. The focused portable/canonical unit gate is 51/51 green, the pinned IDA capture/recognizer runtime gate is 6/6 green, Ruff passes for the changed production and focused test files, and commit-time sg scan plus all 14 import contracts pass.

The mandatory A560 diagnostic canary completed in 7.73 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784838961_11.diag.sqlite3`; output remains the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. The DB records a 254-item frontend-normalization plan, one applied operation, successful rollback, an aborted receipt, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt. The first failed C2 obligation is unchanged and native-EA anchored: `block@0x40AE3E` has zero matching PREOPT union-template blocks. The exact-return slice therefore caused no canary regression. Continue the controlled real-terminal loop before returning to `0x40AE3E`; its current next realization obligation is the staged zero-successor clone at route source `0x40C7F6`, whose retained conditional tail cannot yet be replaced by the one proven direct terminal successor through the authoritative semantic-edge operation.

**2026-07-23T20:50:18Z**

Commit `d5ccfc0fa` checkpoints the controlled real A560 terminal fragment without claiming C5. The gateway now rewrites the detached conditional route source at native EA `0x40C7F6` to the one proved direct target at `0x40C898`; the bounded plan also stages the carrier corridor `0x40C7E5 -> 0x40C7EA` and exact terminal return at `0x40C89F`. Published originals may expose explicitly marked opaque live-MBA boundary endpoints, while staged replacements remain graph-closed; same-EA maturity-local endpoints are distinguished as `blk<N>@0x<EA>`, and unreachable superseded originals do not impose staged fallthrough topology. Focused evidence is 37/37 projection-validation units and 13/13 pinned IDA semantic-edge runtime tests, with Ruff, ast-grep, and all 14 import contracts green. The intentionally red real-fragment C5 test is committed as the executable next obligation.

Primary controlled-fragment DB: `.tmp/rhad-real-terminal-fragment-c5-boundary.diag.sqlite3`. The transaction plans six operations, applies the five prepublication operations, stages both replacements, and rolls back successfully without attempting root publication. Every graph-closure, block-topology, predecessor/successor-symmetry, fallthrough-topology, reachability, supersession, dispatcher-absence, operation-topology, identity, and lineage outcome now passes. Highest completed real-fragment level remains C3 because prepublication validation fails; C4 is not claimed. The first failed obligation is `terminal_effect_scope:terminal-effects`, followed by missing observed carrier `return-carrier:terminal-return@0x40C7F6:0x19A7218A`, missing terminal return `terminal-return:0x40C898`, and aggregate terminal-route atomicity. Continue the v3.1 vertical loop by diagnosing why terminal effects validate immediately when materialized but disappear from the final staged projection; do not broaden the fragment or return to the 254-item main plan yet.

**2026-07-23T21:26:47Z**

Commit `385c3df3f` completes the required controlled real-Rhad vertical fragment through C5. The terminal carrier corridor `0x40C7E5 -> 0x40C7EA`, route source `0x40C7F6`, epilogue entry `0x40C898`, and exact return `0x40C89F` are staged and published atomically. Synthetic fallthrough helpers are born with verifier-safe fake ownership and an adjacent helper publishes the empty entry block's implicit one-way edge without violating Hex-Rays successor or address-range invariants. Primary DB: `.tmp/rhad-real-terminal-fragment-c5-checkpoint.diag.sqlite3`. It records a committed transaction, successful root publication without rollback, all seven planned operations applied, 32 passing prepublication outcomes, 59 passing postpublication outcomes, and accepted lifecycle evidence through `receipt_committed`. Native verification passes after staging, root publication, chain rebuild, and final publication. The focused proof is 58/58 local units and 14/14 pinned IDA runtime/E2E tests; Ruff, ast-grep, all 14 import contracts, and graphify update pass. This is C5 publication evidence only, not A560 semantic acceptance.

The mandatory full A560 diagnostic canary at `385c3df3f` completed in 9.79 seconds without a segfault or INTERR. Output remains the short body ending `JUMPOUT(0x40B6C0)`. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784841946_11.diag.sqlite3`. Highest completed main-A560 level remains C1: generation-1 evidence is accepted and event 15 records a 254-item plan, but staging applies one operation and aborts with successful rollback, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt. The first failed C2 obligation remains unique PREOPT identity realization at native EA `0x40AE3E`: `block@0x40AE3E:matches=0` within `native-body:frontend-normalization:g1:root@0x40A5F0`. The controlled C5 prerequisite is now satisfied, so resume the v3.1 main vertical loop at this exact identity-realization failure without broad 91-route publication or weakening complete-edge ownership.

**2026-07-23T21:40:04Z**

Commit `ed1677871` fixes the `0x40AE3E` identity-realization failure at its portable-native source instead of weakening PREOPT binding. Native calls now terminate one semantic closure block, publish an explicit `CALL_FALLTHROUGH` continuation, never traverse their direct callees, and fail closed when no continuation exists. The backend re-decodes every reachable FlowChart entry, so FlowChart remains reachability inventory rather than portable topology authority. Focused evidence is 81/81 unit tests and 20/20 pinned native-closure/frontend runtime tests, with Ruff, ast-grep, all 14 import contracts, and graphify update green.

The mandatory A560 diagnostic canary completed in 22.27 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784842750_12.diag.sqlite3`; output remains the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. The previous `block@0x40AE3E:matches=0` realization failure is gone, but planning now rejects before recording any mutation plan, transaction, receipt, validation outcome, or root-publication attempt. Event 7 records the first failed obligation exactly: `missing native anchor 0x40B0AB is not owned by one semantic closure block`. Continue the v3.1 vertical loop by determining whether `0x40B0AB` is a call continuation, an interior dependency anchor, or a closure-ownership omission; do not broaden publication or weaken ownership.

**2026-07-23T21:55:41Z**

Commit `c530e9bfd` resolves the `0x40B0AB` closure-ownership omission without assigning detached code to the nominal IDA function. A direct IDA probe established that the architectural continuation at `0x40B094` is executable flow with no owning function while IDA's nominal `sub_40A560` extent ends at `0x40A607`. Native call splitting now admits such resolver-scoped flow only when the continuation is code and no foreign function owns it; direct calls without flow remain fail-closed. Focused evidence is 82/82 unit tests and 20/20 pinned native-closure/frontend runtime tests, with Ruff, ast-grep, all 14 import contracts, and graphify update green.

The mandatory A560 diagnostic canary completed in 20.16 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784843539_11.diag.sqlite3`; output remains the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. The previous `0x40B0AB` planning rejection is gone: event 15 records a 260-item plan, and event 24 records one applied operation, successful rollback, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt. The first failed C2 obligation is now native-EA anchored at `0x40AE26`: operation `native-indirect-transfer@0x40AE3C` owns two semantic edges for `native[0x40AE26-0x40AE3E;exact=0x40AE26,0x40AE28,0x40AE2E]:imported`, but its matched PREOPT template reports `conditional_tail=False`, with neither template nor plan call-fallthrough topology. Continue the v3.1 vertical loop by reconciling that exact portable-proof versus PREOPT-template topology mismatch; do not weaken one-operation ownership or broaden to 91-route publication.

**2026-07-23T22:19:37Z**

Commits `a789e6360` and `70cf41855` complete the typed computed-branch-normalization slice without broad publication. Portable indirect-transfer proof now owns the exact unresolved transfer EA, typed predicate kind, producer EA, and predicate anchor; only a proof-owned imported two-arm operation may carry that normalization contract. The PREOPT materializer verifies those anchors against one live producer and one trailing unresolved `m_ijmp`, prepares every block before staging any block, replaces only the unresolved suffix with a producer-result `m_jnz`, and leaves both destinations to the semantic gateway. Focused evidence is 92/92 portable unit tests, 74/74 semantic-fragment backend runtime tests, and a post-instrumentation 1/1 pinned runtime proof. Ruff, ast-grep, all 14 import contracts, diff checks, and graphify update pass.

The mandatory A560 diagnostic canary completed in 19.11 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784844955_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-computed-branch-normalization-anchored.txt`. Output remains the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. The DB preserves all 464 fact observations and the 260-item plan; staging applies one operation, then aborts with successful rollback, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt. The prior `native-indirect-transfer@0x40AE3C` topology rejection is gone.

The first failed C2 obligation is now self-contained: operation `native-indirect-transfer@0x40B340`, source `0x40B32C`, producer `0x40B32E`, predicate anchor `0x40B334`, and unresolved transfer `0x40B340` carry portable predicate `ne`, while the live producer at `0x40B32E` is opcode 33 with predicate `eq`. The earlier unanchored receipt could not identify its failing operation, so an interim inference that `native-indirect-transfer@0x40A5E3` failed was unsupported and is superseded by this DB evidence. Continue the v3.1 vertical loop by proving whether the portable predicate polarity or the live producer interpretation is wrong at `0x40B32E`; do not accept an opposite predicate by weakening exact matching, and do not broaden to the 91-route publication.

**2026-07-23T22:28:35Z**

Commit `b1a53f7e1` resolves the `0x40B32E` mismatch as an exact polarity relation rather than a relaxed predicate match. Portable `PredicateKind` remains the semantic branch predicate. The PREOPT backend now accepts a materialized boolean only when its `m_set*` predicate is either identical to that semantic predicate or its exact portable complement, emits `m_jnz` for identical polarity and `m_jz` for complemented polarity, carries that selected sense through preflight, and still rejects unrelated predicates before staging. Native disassembly confirms the real site is `cmp ebx, 0x304E8694` at `0x40B32E`, `setne al` at `0x40B334`, and unresolved `jmp eax` at `0x40B340`, while PREOPT canonicalizes the compare result as `m_setz`; the complemented branch is therefore required to preserve the reference `JNE` arms. Evidence is 21/21 portable semantic units, 3/3 focused pinned runtime polarity cases, and 74/74 pinned semantic-fragment backend tests, with Ruff, ast-grep, all 14 import contracts, diff checks, and graphify update green.

The mandatory A560 canary completed in 11.64 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784845505_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-computed-branch-polarity.txt`. Output remains the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. The DB again records 464 fact observations, a 260-item plan, one applied operation, successful rollback, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt. The `native-indirect-transfer@0x40B340` failure is gone. The first failed C2 obligation advances to operation `native-indirect-transfer@0x40B956`, source `0x40B940`, producer `0x40B942`, predicate anchor `0x40B948`, unresolved transfer `0x40B956`, and semantic predicate `slt`: PREOPT exposes two instructions at producer EA `0x40B942` with raw opcodes 30 and 29, neither of which is an `m_set*` predicate. Continue by identifying and proving that compound signed-predicate materialization; do not collapse it to an untyped truthiness test or broaden publication.

**2026-07-23T23:02:45Z**

Commits `301118018` and `cfa3191b4` complete the next signed-predicate and restart-safe rollback slice as separate logical changes. Exact PREOPT inspection proved the portable `slt` predicate at `0x40B942 -> 0x40B948` is materialized as same-anchor `m_seto` and `m_sets`, followed by `m_xdu(SF XOR OF)`. The native-body preflight now accepts only that exact typed template for portable `slt`/`sge`, retains the `m_xdu` result, and emits the corresponding `m_jnz`/`m_jz`; malformed flag combines still abstain.

The first live retry exposed two rollback defects, both decoded from the matching SDK sources before repair. `52719` is the `mba_t::get_mblock(n)` assertion `n < qty` in `hexrays.hpp`, caused by iterative removal observing shifted block coordinates. Replacing it with low-level `remove_blocks(8, 102)` exposed `50842` from `verifier/verify.cpp`: the surviving stop block occupied `natural[8]` but retained serial `101`, violating the physical block-list endpoint invariant. Rollback now detaches the complete staged inventory, temporarily protects surviving blocks through unique native identities, clears `MBL_KEEP` only on staged blocks, invokes `remove_empty_and_unreachable_blocks()`, restores survivor flags after rebinding, checks the exact quantity delta, and requires native verification before the diagnostic receipt may record rollback success. No compatibility path to `remove_block` or `remove_blocks` remains.

The mandatory A560 diagnostic canary completed in 15.01 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784847407_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-identity-safe-rollback.txt`. Hex-Rays now completes decompilation and the semantic oracle fails only on the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. The DB records 464 fact observations, a 260-item plan, 94 applied staging operations, zero validation outcomes, no root-publication attempt, and one aborted receipt whose rollback succeeded while preserving the original reason `conditional reconstruction predicate does not match blk8@0x40A5F0`.

The first failed C2 obligation is now operation `native-indirect-transfer@0x40A605`. Its replacement source is anchored by exact native EAs `0x40A5F0`, `0x40A5F6`, `0x40A5F8`, and `0x40A5FE`; the plan expects a conditional at predicate anchor `0x40A5F6` with taken target `0x40B6C0` and fallthrough target `0x40A607`, but the live clone contains the native `cmp`/`mov`/`lea`/`cmovl` computed-target sequence and has no computed-branch-normalization contract. Continue the v3.1 vertical loop by carrying and normalizing this exact proof-owned CMOV route in detached construction; do not weaken conditional-tail matching, mutate both a live clone and imported envelope, or broaden to the 91-route publication.

Verification for this checkpoint is 6/6 focused computed-branch runtime cases, 146/146 detached-import runtime tests, 75/75 semantic-fragment backend tests, and 257/257 current resolver runtime tests. The historical 303-test resolver count included the 46-test legacy island-lowerer file intentionally removed by `835d955e0`; it is not a current test target. Ruff passes the changed production and rollback-test files, the signed-import diff adds no finding beyond three pre-existing findings present at the prior HEAD, ast-grep passes, all 14 import contracts are kept, and `graphify update .` completes.

**2026-07-23T23:44:56Z**

Commits `84a6b660f` and `020bf1a3d` complete the proof-owned live conditional-select slice without broad publication. The portable plan now owns the exact source predicate, selected-value arm, join block, and unresolved-transfer envelope; signed truthiness is accepted only when the branch expression is the exact one-byte `SF XOR OF` result of the uniquely anchored sign/overflow producers, including its exact `m_lnot` complement. The backend revalidates the published topology, clones the source, normalizes only the detached replacement, and routes its unique EA-anchored suffix replacement through `DeferredGraphModifier`. The published original remains unchanged. No compatibility path or architecture ignore was added.

The mandatory A560 diagnostic canary completed in 9.37 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784849881_10.diag.sqlite3`; log: `.tmp/rhad-a560-v31-conditional-select-exact-signed.txt`. Output remains the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. The DB records 464 fact observations and a 260-item plan. Staging applies 97 operations, then aborts with successful rollback, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt.

The prior `native-indirect-transfer@0x40A605` failure is gone: plan items 94-96 apply its fallthrough helper and both semantic arms at replacement source `0x40A5F0`, targeting `0x40B6C0` and `0x40A607`. The first unapplied item is item 97 for the next operation, `native-indirect-transfer@0x40A5E3`, whose portable source is `0x40A5CA`, producer `0x40A5CA`, predicate anchor `0x40A5D0`, unresolved transfer `0x40A5E3`, semantic predicate `eq`, and targets `0x40C898` plus `0x40A5F0`. The receipt reports only `conditional reconstruction predicate does not match blk10@0x40A560`. That physical start is not evidence of an entry-block binding: imported blocks deliberately use the verifier-safe live range `mba.entry_ea..mba.entry_ea+1`. The next v3.1 obligation is to record the imported block's stable native identity and observed tail in the DB, then reconcile the exact predicate shape or anchor at portable source `0x40A5CA`. Do not weaken predicate matching, trust a maturity-local serial or fake live EA as portable identity, or broaden publication.

Verification for this checkpoint is 52/52 portable planner/plan tests and 481/481 combined pinned runtime tests covering semantic-fragment staging, detached import, computed-goto resolution, and resolver session state. Ruff, ast-grep, all 14 import contracts, diff checks, and `graphify update .` pass.

**2026-07-23T23:54:21Z**

Commit `01e249230` closes the conditional-rejection visibility gap without changing semantic acceptance. The gateway now records the logical operation, verifier-safe physical block label, portable native source identity, expected predicate anchor, and observed live tail EA/opcode in both initial and post-staging predicate rejections. The full pinned semantic-edge gateway runtime file is 12/12 green; Ruff, ast-grep, all 14 import contracts, diff checks, and `graphify update .` pass.

The mandatory A560 diagnostic canary completed in 11.15 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784850684_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-semantic-edge-native-diag.txt`. Output remains the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. Event 15 records the 260-item plan; event 24 records 97 applied operations, successful rollback, `fragment_staged=0`, zero validation outcomes, no root-publication attempt, and an aborted receipt.

The first failed C2 obligation is now self-contained: operation `native-indirect-transfer@0x40A5E3` is bound to stable source `native@0x40A5CA` while its verifier-safe physical block label is `blk10@0x40A560`; the operation expects predicate anchor `0xF1C00018`, but the observed tail is `m_jcnd` at `0xF1C00020`. Continue the v3.1 vertical loop by proving the exact detached predicate-envelope relation for native source `0x40A5CA`; do not equate the physical `0x40A560` label with portable identity, weaken predicate matching, or broaden publication.

**2026-07-24T00:25:16Z**

Commit `945abb51e` completes the proof-owned PREOPT split-conditional normalization slice and advances the main A560 C2 frontier without broad publication. Native bytes prove the first envelope is `cmp` at `0x40A5CA`, two candidate address loads, `cmove` at `0x40A5DC`, and unresolved `jmp eax` at `0x40A5E3`. The detached PREOPT template splits that native block into a five-flag producer, selected-value arm, and join. Docker further classifies the native jump as an SDK-defined artificial tail call: `blk7@0x40A5DF` is `BLT_1WAY|MBL_TCAL`, ends in an unknown `m_icall@0x40A5E3` with no callinfo, and reaches the same-EA fake stop `blk8@0x40A5E3` containing only `m_ret@0x40A5E3`. The materializer now accepts only the complete proof-owned envelope, including exact predicate orientation, selected `m_mov`, join predecessors, and either a zero-way `m_ijmp` or that exact unanalysed tail-call plus fake-stop representation. Ordinary indirect calls, `MBL_CALL` blocks, malformed selected arms, and non-fake continuations still reject before staging. No compatibility path or architecture ignore was added.

The mandatory A560 canary completed in 9.19 seconds without a new segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784852514_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-tailcall-normalization.txt`. Output remains the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1 because the 260-item transaction aborts during C2 preflight after one applied operation, with successful rollback, `fragment_staged=0`, zero validation outcomes, and no root-publication attempt. The prior `native-indirect-transfer@0x40A5E3` obligation is gone.

The first failed C2 obligation advances to operation `native-indirect-transfer@0x40AE89`: source `0x40AE63`, condition producer `0x40AE74`, predicate anchor `0x40AE7A`, unresolved transfer `0x40AE89`, and portable predicate `slt`. Its split topology and direct `m_ijmp` join validate, but the source reports zero exact oriented `m_set*` producers, so `oriented_producer_unique`, `producer_has_result`, `producer_precedes_predicate`, and `tail_skips_semantic_true` fail atomically. Continue the v3.1 vertical loop by proving the exact signed predicate materialization at this native-EA-anchored split and reusing the typed `SF XOR OF` discipline only if the template matches it; do not lower it as untyped truthiness or broaden to the 91-route publication.

Verification is 230/230 pinned Docker detached-import and semantic-fragment backend tests, including exact abstention cases for call-like join variants. `pyenv exec ruff`, ast-grep, all 14 import contracts, diff checks, and `graphify update .` pass.

**2026-07-24T00:41:59Z**

Commit `3886ab3dd` completes the exact split signed-predicate normalization slice without broad publication. PREOPT inspection proves the portable `slt` route at native source `0x40AE63` is materialized as the five same-anchor flag results at `0x40AE74` followed by a candidate-value `m_mov@0x40AE7A`; its actual condition survives only in the split tail as `m_lnot(m_xor(SF, OF))`. The materializer accepts only that exact flag inventory, producer adjacency, typed `SLT` ownership, operand correspondence, split topology, and direct unresolved-transfer join. It clones the inner `SF XOR OF` operand, rebases it, and emits `m_jnz` while cutting the candidate-selection suffix. A malformed `m_or` combine still rejects before staging. No untyped truthiness path, compatibility path, or architecture ignore was added.

Focused verification is 8/8 split-select cases and 232/232 combined pinned Docker detached-import plus semantic-fragment backend tests. `pyenv exec ruff`, ast-grep, all 14 import contracts, diff checks, and `graphify update .` pass.

The mandatory A560 diagnostic canary then reached live operation realization and failed in 8.15 seconds. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784853358_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-signed-split.txt`; verifier artifact: `.tmp/logs/d810_logs/verify_failures/verify_fail_20260724T003600.753044Z_000000000040A560_11.json`. Highest completed main-A560 level remains C1. Event 15 records the 260-item plan; event 24 records 97 applied items, `fragment_staged=0`, no validation outcomes, no root-publication attempt, and failed rollback.

The first failed publication obligation is plan item 97, the adjacent fallthrough helper for operation `native-indirect-transfer@0x40A5E3` at stable source `native@0x40A5CA`. The preceding replacement helper and both arms for `native-indirect-transfer@0x40A605` applied as items 94-96. The second helper calls `mba.copy_block()` on the imported conditional and raises `INTERR 51812`; that API call appears to change live block inventory before raising, after which the nested unreachable sweep raises `INTERR 51769`. The outer rollback reaches `mba.verify()` with a surviving `m_ret` at fictitious EA `0xF1C00888` and raises `INTERR 50863`; `verifier/verify.cpp` defines 50863 as a mapped instruction address outside the MBA range. A repeated cleanup then resolves a shifted logical version past current `mba.qty` and raises 52719; `hexrays.hpp` defines 52719 as `mba_t::get_mblock(n)` asserting `n < qty`. This is an actual IDA API invariant failure and a failed rollback, not a process segfault.

The diagnostic DB currently preserves only the outer 50863/52719 rollback reason, not the initiating 51812 plus native source identity, so the next vertical slice must make helper creation restart-safe and receipt the first SDK failure before cleanup can replace it. Do not retry broad realization until adjacent helper construction either completes atomically or leaves `mba.qty`, logical proxies, fictitious-EA ownership, and staged inventory unchanged.

**2026-07-24T00:51:44Z**

Commit `6f00784cb` removes source-body copying from semantic fallthrough-helper construction. The gateway now asks `mba.insert_block()` for one genuinely empty block immediately after the source, records the serial insertion and synthetic handle before adding metadata or edges, rejects any non-empty SDK result, rebinds the target through portable identity, and then adds the sole verifier-safe goto. This prevents imported fictitious instruction addresses from being cloned into another logical block and closes the observed `copy_block()` 51812 plus failed-rollback chain without a compatibility fallback.

Verification is 5/5 focused helper contracts and 184/184 combined pinned Docker deferred-modifier, semantic-edge-gateway, and semantic-fragment-backend tests. The focused coverage includes two serial-shifting helper insertions, invalidated SWIG-style block proxies, and a source at stable native EA `0x40A5CA` whose body carries fictitious live instruction EAs. Ruff, ast-grep, all 14 import contracts, diff checks, and `graphify update .` pass.

The mandatory A560 canary completed in 8.87 seconds with no segfault and no INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784854122_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-empty-adjacent-helper.txt`. Hex-Rays decompiles normally and the semantic oracle fails only on the short body ending `JUMPOUT(0x40B6C0)`. Highest completed main-A560 level remains C1. Event 15 records the 260-item plan; event 24 records 138 applied items, `fragment_staged=0`, zero validation outcomes, no root-publication attempt, and successful rollback.

The prior item-97 helper failure is gone. Items 97-99 now apply the complete conditional fragment for `native-indirect-transfer@0x40A5E3`, and items 123-125 apply the newly normalized `native-indirect-transfer@0x40AE89` fragment at stable source `0x40AE63`. The first failed C2 obligation advances to item 138, operation `native-indirect-transfer@0x40B956`, at imported identity `native[0x40B940-0x40B958;exact=0x40B940,0x40B942,0x40B948]:imported`. Its retained signed-result instruction and synthesized conditional both claim native origin `0x40B948`, so `SemanticFragmentBackendState.live_instruction_ea()` rejects the predicate anchor as ambiguous before helper publication. Continue by giving the exact signed normalization one live predicate origin; do not weaken unique-origin binding or select between duplicates by serial/order.

**2026-07-24T01:02:06Z**

Commit `7d319ac54` gives the exact signed normalization one live predicate origin. The detached replacement now drops the intermediate `m_xdu@0x40B948` and branches directly on the exact typed `SF XOR OF` expression cloned from that predicate anchor, while retaining the separately anchored `m_seto` and `m_sets` producers. Unique native-origin lookup remains mandatory; no serial- or order-based disambiguation was added. Focused verification is 3/3 signed-normalization cases and 232/232 combined pinned Docker detached-import plus semantic-fragment-backend tests. Ruff, ast-grep, all 14 import contracts, diff checks, and `graphify update .` pass.

The mandatory A560 diagnostic canary completed in 8.16 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784854479_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-unique-signed-origin.txt`. Hex-Rays completes decompilation and the semantic oracle still fails on the short body ending `JUMPOUT(0x40B6C0)`.

The previous `0x40B948` ambiguity is gone and the main A560 canary advances from C1 to C4. All 260 planned operations apply, fragment staging completes, all 639 prepublication validation outcomes pass, and root publication succeeds. Postpublication validation passes 1087 of 1180 outcomes, then rejects the transaction and rolls publication back successfully. The first failed obligation is `observable_operation:native-indirect-transfer@0x40A605`, anchored at replacement source `0x40A5F0` with semantic targets `0x40B6C0` and `0x40A607`; the same failure is reported for all 93 plan operations.

This uniform failure is not evidence that 93 route topologies broke. The DB separately records every one of the 93 postpublication `operation_topology` outcomes and all 74 `fallthrough_topology` outcomes as passing, together with passing reachability, root authority, original supersession, graph closure, identity, and lineage. Continue the v3.1 vertical loop by reconciling the postpublication observation's exact operation-set/cardinality calculation with those passing live topology outcomes. Do not weaken observable semantics, bypass postvalidation, or infer C5 before a committed receipt.

**2026-07-24T01:08:40Z**

Commit `008e5764c` fixes the postpublication observation mismatch by deriving the exact required topology postconditions from each operation's semantic roles. A one-edge `CALL_FALLTHROUGH` now requires both `operation_topology` and `fallthrough_topology`, while a direct operation requires only the former and a complete conditional requires both. The observer still requires one exact outcome of every required kind and rejects duplicates or failures. The focused live-Hex-Rays call-continuation test is green, as is the full 232/232 pinned Docker detached-import plus semantic-fragment-backend gate. Ruff, ast-grep, all 14 import contracts, diff checks, and `graphify update .` pass.

The mandatory A560 canary completed in 8.29 seconds and advances the main path to C5, not C6. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784854992_10.diag.sqlite3`; log: `.tmp/rhad-a560-v31-call-observation.txt`. All 260 planned operations apply, fragment staging and root publication complete, all 639 prepublication outcomes and all 1180 postpublication outcomes pass, the receipt commits, and frontend-normalization generation 1 is published with 188 remaining obligations. No rollback occurs.

Hex-Rays then rejects later processing before pseudocode with `INTERR 50819`. The SDK source at `verifier/verify.cpp:754` defines this as an `m_jcnd` with wrong operands: `l` is empty, `r` is nonempty, or `d` is neither `mop_v` nor `mop_b`. The diagnostic DB contains no failed event after the accepted `normalization_work_item_published` event, so it does not yet identify the malformed instruction or native EA anchor; this is the first current visibility obligation. Continue the v3.1 loop by capturing the post-C5 live `m_jcnd` inventory and identifying the exact malformed native-EA-owned instruction before changing lowering. Do not infer the cause from the numeric INTERR alone, weaken postvalidation, or claim semantic acceptance.

**2026-07-24T01:20:50Z**

Commit `7ad3243f9` resolves the post-C5 `INTERR 50819` as an SDK operand-ownership defect in exact signed conditional-select normalization. A focused live probe anchored the only malformed branch at native EA `0x40A5F6`: before normalization its `m_jcnd.l` owned `m_lnot(m_xor(SF, OF))`, while afterward `l` was `mop_z`. The normalizer had called `branch.l.assign(expression.l)` where `expression.l` was a child of `branch.l`; SDK-style assignment clears the destination before copying, so the overlapping child source was destroyed. The backend now clones that child into an independently owned `mop_t`, rejects an empty clone, and only then replaces the parent. The regression test models the SDK's destructive self-overlap semantics instead of constructing unsafe standalone live microcode objects.

Focused pinned-Docker verification is 232/232 for detached snippet import and semantic-fragment backend behavior. `pyenv exec ruff`, ast-grep, all 14 worktree-local import contracts, diff checks, and `graphify update .` pass. No compatibility path or architecture ignore was added.

The mandatory A560 diagnostic canary completed in 7.63 seconds with no process segfault and no recurrence of 50819. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784855748_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-owned-nested-condition.txt`. Main A560 remains at C5, not C6: the DB again records all 260 operations applied, 639/639 prepublication outcomes passing, successful root publication, 1180/1180 postpublication outcomes passing, a committed receipt, and the generation-1 frontend-normalization work item published with 188 remaining obligations.

Hex-Rays then rejects later verification before pseudocode with `INTERR 50863`. The SDK source at `verifier/verify.cpp:479-483` maps every instruction EA through `mba->map_fict_ea(ea)` and raises 50863 when the result is outside the MBA range. The first failed post-C5 obligation is therefore that every published instruction, including detached normalized operands and synthetic instructions, has a mapped native EA within the A560 MBA range. The diagnostic DB again records only accepted publication and contains no failed event for this later SDK rejection, so address validity is also a primary-observability gap. Continue the v3.1 vertical loop by capturing the exact invalid instruction with its portable native EA anchor and mapped live EA before changing lowering; do not infer which instruction is invalid, weaken address verification, or claim A560 acceptance.

**2026-07-24T01:43:43Z**

Commit `f72a00393` resolves `INTERR 50863` by making native instruction-address ownership part of the same semantic-fragment transaction as detached body materialization. Every requested native range is merged into `mba.mbr.ranges`, `MBA2_HAS_OUTLINES` is set through the bound `mba_t` API, every fictitious instruction origin must map back into that owned range, and an aborted transaction restores the exact prior ranges and outline flag. The implementation uses `get_mba_flags2()` rather than assuming the SWIG binding exposes the C++ `flags2` field. The focused contract was red against direct field access, then green; the complete pinned detached-import plus semantic-fragment-backend gate is 232/232. Ruff, ast-grep, all 14 worktree-local import contracts, diff checks, and `graphify update .` pass. No compatibility path or architecture ignore was added.

The mandatory A560 diagnostic canary completed in 19.83 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784857178_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-native-range-ownership-fixed.txt`. Main A560 remains C5, not C6. The DB records all 260 operations applied, 639/639 prepublication outcomes passing, successful root publication, 1180/1180 postpublication outcomes passing, a committed receipt, and generation-1 publication with 40 selected and 188 remaining obligations. Hex-Rays now reaches pseudocode: the prior short `JUMPOUT(0x40B6C0)` stub expands into a substantial body, but the established oracle rejects one residual `while ( 1 )`.

The first failed lifecycle obligation recorded by the DB occurs at `MMAT_CALLS`: `state_machine_cff_unflattener` declines `resolver_session:indirect_dispatcher_materialized` with typed reason `preopt_evidence_generation_unbound`. Its payload records `evidence_generation=1`, `normalization_published_postvalidated_generation=null`, `imported_identity_ready=false`, and `indirect_dispatcher_materialized=false`; the same decline repeats at `MMAT_GLBOPT1`. Continue the v3.1 vertical loop at this lifecycle-authority discontinuity. Determine why the committed, postvalidated generation-1 receipt does not become the session generation consumed by later maturities; do not broaden the 188 remaining obligations, weaken the recovery gate, or claim C6.

**2026-07-24T01:50:04Z**

The lifecycle frontier is intentional partial authority, not a lost receipt. Production still uses the temporary one-root-component planner introduced to reach the required real-fragment C5 gate; a receipt with remaining sibling obligations must keep `normalization_published_postvalidated_generation` unset, and PREOPT has no supported maturity-restart return contract. An uncommitted pass-level experiment therefore switched to the complete generation plan now that C5 exists, ran the mandatory A560 canary, and was removed after the diagnostic DB falsified that plan shape. The worktree is back to the committed implementation.

Experimental DB: `.tmp/logs/d810_logs/000000000040a560_1784857736_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-complete-generation-publication.txt`. The canary completed without a segfault or INTERR. It planned 968 mutations, applied one, then aborted before fragment staging or root publication and rolled back successfully. The exact first broad-publication C2 obligation is `native-body:frontend-normalization:g1`: the complete plan aggregates all disconnected missing-native components into one `FragmentNativeBody`, so the materializer requires one PREOPT union template covering its full entry inventory and correctly observes zero. The semantic output consequently returns to the short `JUMPOUT(0x40B6C0)` stub; the earlier committed C5 canary remains the highest valid checkpoint.

Continue by partitioning the complete portable generation into disjoint, template-ownable native bodies within one atomic `FragmentPlan`. Each imported block must belong to exactly one native body, each body must bind exactly one compatible PREOPT template, and the generation may advance only after the whole multi-body fragment stages, validates, publishes, postvalidates, and commits. Do not loop partial live-MBA publications, collapse template uniqueness, or mark partial authority complete.

**2026-07-24T02:10:29Z**

Commit `a42a4392b` corrects the representation-boundary diagnosis from the preceding checkpoint. Compact extraction of the aborted transaction reason shows one cached PREOPT template, owned by target `0x40A5CA` at PREOPT maturity, and that template does contain a substantive block beginning at `0x40ADF2`. The apparent zero-template failure was instead `block@0x40ADF2:matches=0`: portable identity `0x40ADF2-0x40AE1A` owns exact source, producer, and predicate anchors across a native block that Hex-Rays split into source, selected-value, and join microblocks. Therefore multi-body partitioning may still be required later, but the DB does not prove it is the first obligation and it must not be implemented first.

The PREOPT selector now admits this representation only for an explicit proof-owned computed normalization with exactly both conditional roles, exact source/producer/predicate ownership, and an unresolved transfer inside the same stable native range. Admission does not authorize mutation: the existing split-envelope preflight must still prove the selected arm, join predecessors, unresolved-transfer tail, typed predicate orientation, and complete topology before any body is staged. The focused regression models one portable native block split into three PREOPT microblocks. Local semantic-fragment backend verification is 79/79, and the pinned Docker backend plus frontend-planner gate is 106/106. `pyenv exec ruff check`, ast-grep, all 14 worktree-local import contracts, diff checks, and `graphify update .` pass. No compatibility path or architecture ignore was added.

The mandatory production A560 canary completed in 18.17 seconds without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784858786_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-split-envelope-template-binding.txt`. The current one-root work item remains at C5, not C6: 40 obligations are selected, 188 remain, all 639 prepublication and 1180 postpublication outcomes pass, root publication succeeds, and one receipt commits. The semantic oracle still rejects one residual `while ( 1 )`.

An uncommitted complete-generation switch then exercised the corrected binding and was removed. Experimental DB: `.tmp/logs/d810_logs/000000000040a560_1784858858_10.diag.sqlite3`; log: `.tmp/rhad-a560-v31-complete-generation-split-binding.txt`. Template selection now completes, no root publication is attempted, rollback succeeds, and the first failed obligation advances to typed preflight of `native-indirect-transfer@0x40A792`: source `0x40A77E`, producer `0x40A780`, predicate `0x40A786`, unresolved transfer `0x40A792`, semantic predicate `sge`, observed producers `overflow_flag` plus `sign_bit`, and observed predicate `xor` plus `zext`. Continue the v3.1 vertical loop by proving that exact `SGE` signed-predicate materialization before reconsidering complete-plan partitioning. Do not weaken predicate typing, keep the complete-generation switch, or treat the changed failure alone as C6 progress.

**2026-07-24T02:30:18Z**

Commit `f3e34bfab` proves and lowers the exact PREOPT materialization of native `setge` at `0x40A786`. The detached template contains separate top-level `SF XOR OF -> reg48.1` and `XDU(LNOT(reg48.1)) -> reg8.4` instructions at the same native predicate EA. The backend now requires that exact adjacent def-use chain for portable `SGE`, requires direct `XDU(XOR-result)` for the corresponding `SLT` form, rejects wrong wrappers and wrong consumers, cuts before both materialization instructions, and synthesizes one owned `jz(SF XOR OF)` branch. Rejected typed predicates now include serial-free producer and predicate operand shapes in the transaction reason, so the diagnostic DB exposes the failed obligation without log inference. Commit `10febf1ab` separately removes three stale unused imports from the touched runtime test file.

Focused verification is 158/158 local detached-import contracts and 237/237 pinned-Docker detached-import plus semantic-fragment-backend contracts. `pyenv exec ruff check` passes for the changed files, ast-grep passes, all 14 worktree-local import contracts pass, diff checks pass, and `graphify update .` completed. No compatibility path, sample-EA production guard, architecture ignore, or complete-generation production switch was added.

The mandatory production A560 canary completed without a segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784859926_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-exact-sge-lnot.txt`. Main A560 remains C5, not C6: all 260 operations apply, all 639 prepublication and 1180 postpublication outcomes pass, root publication succeeds, the receipt commits, and generation 1 records 40 selected with 188 remaining obligations. The semantic oracle still rejects one residual `while ( 1 )`.

The controlled complete-generation switch was then applied only for one diagnostic canary and removed. Experimental DB: `.tmp/logs/d810_logs/000000000040a560_1784859965_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-complete-exact-sge-lnot.txt`. The previous `0x40A792` typed-predicate rejection is gone. The 968-operation transaction still aborts before fragment staging or root publication after one applied item, and rollback succeeds. The new first failed obligation is the split conditional-select envelope for `native-indirect-transfer@0x40AE18`: source `0x40ADF2`, producer `0x40ADF7`, portable predicate `0x40AE09`, unresolved transfer `0x40AE18`, semantic predicate `slt`. PREOPT source `blk153@0x40ADF2` has no instruction at the portable predicate EA; its selected arm is `blk154@0x40AE05`, its join is `blk155@0x40AE08`, and the failed checks are `predicate_anchor_unique`, `oriented_producer_unique`, `producer_has_result`, `producer_precedes_predicate`, and `tail_skips_semantic_true`. Continue the v3.1 vertical loop from this exact split-envelope ownership mismatch. Do not broaden publication, weaken predicate typing, or claim C6.

**2026-07-24T02:49:41Z**

Commits `4b1adeec5` and `c6d395775` separate the portable normalization cut from the synthetic predicate origin and realize the exact split signed-select envelope at `0x40AE18`. The resolver proof now carries native normalization start `0x40ADFD` separately from synthetic predicate anchor `0x40AE09`; the backend requires a unique real start, the exact contiguous `setb/seto/setz/setp/sets` producer rows at `0x40ADF7`, and the exact `LNOT(SF XOR OF)` split tail before cutting at `0x40ADFD` and emitting one branch owned by `0x40AE09`. An absent start and the wrong existing start at `0x40ADFF` both reject before staging. No compatibility path, sample-EA production guard, architecture ignore, or serial-based choice was added.

Focused verification is 91/91 portable unit tests, 161/161 local detached-import tests, 79/79 local semantic-fragment-backend tests, and 240/240 combined pinned-Docker importer/backend tests. Ruff, commit-time ast-grep, all 14 worktree-local import contracts, diff checks, and `graphify update .` pass.

The mandatory production A560 diagnostic canary completed in 17.02 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784861156_10.diag.sqlite3`; log: `.tmp/rhad-a560-v31-split-normalization-start.txt`. The selected production fragment remains C5, not C6: all 260 operations apply, all 639 prepublication and 1180 postpublication outcomes pass, root publication succeeds, the receipt commits, and generation 1 records 40 selected with 188 remaining obligations. Pseudocode remains the substantial body with one residual `while ( 1 )`.

The controlled complete-generation selector was then applied for one diagnostic run and removed explicitly; the worktree returned clean. Experimental DB: `.tmp/logs/d810_logs/000000000040a560_1784861250_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-complete-split-normalization-start.txt`. The previous `0x40AE18` split-envelope rejection is gone. The complete plan now reaches C3: it plans 968 transaction items, applies 967, stages the complete native body, runs prepublication validation, then aborts before root publication and rolls back successfully. Of 2367 prepublication outcomes, 1823 pass and 544 fail.

The first failed obligation is `internal_connectivity` for imported block `native[0x40A6B4-0x40A6C0;exact=0x40A6B4]:imported`: it is disconnected from every fragment root. The complete plan has 374 blocks, 365 operations, one native body with 365 blocks and 300 declared entry blocks, but only one publication root at native EA `0x40A5F0`; the failing block has no incoming semantic operation. Continue the v3.1 vertical loop by determining whether these detached entries require distinct publication authority or are non-actionable unreachable proofs. Do not make disconnected blocks roots merely to satisfy validation, weaken internal-connectivity validation, or claim C4/C6.

**2026-07-24T03:04:40Z**

Commits `ab0addd46` and `aa3885b2b` make non-actionable proof disposition explicit without changing the selected physical fragment. `FragmentWorkItemScope` now retains selected, pending, and root-unreachable obligation IDs as pairwise-disjoint sets, and the planner classifies a proof as root-unreachable only when it lies outside the semantic closure of every live publication root. A sibling proof reachable from another live root remains pending. No disconnected block was promoted to a publication root, and partial authority cannot silently forget either pending or unreachable evidence.

The mandatory production A560 diagnostic canary completed in 17.34 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784862019_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-root-unreachable-authority.txt`. The selected fragment remains C5, not C6: all 260 operations apply, all 639 prepublication and 1180 postpublication outcomes pass, root publication succeeds, and the mutation receipt commits. Its lifecycle scope is 40 selected, zero pending, and 188 separately retained root-unreachable obligations. Pseudocode remains substantial but still contains one residual `while ( 1 )`.

The intended generation-1 authority boundary now succeeds. DB event 27 records `normalization_published_postvalidated` accepted for frontend-normalization generation 1. Event 28 then records a real new `native_facts` evidence epoch, advancing generation 1 to generation 2. At MMAT_CALLS and again at MMAT_GLBOPT1, the fact consumer declines `resolver_session:indirect_dispatcher_materialized` with typed reason `preopt_evidence_generation_unbound`; its payload records evidence generation 2 and postvalidated publication generation 1.

The first failed obligation is therefore controller-owned restart and PREOPT rebinding for the newly discovered generation 2, not fragment publication or detached-root connectivity. Continue by proving that a postvalidated generation-1 native-facts change at CALLS stages exactly one generated restart, that the lifecycle controller consumes it, and that the follow-up PREOPT round binds generation 2. Do not coalesce generation 2 into generation 1, return `MERR_REDO` from a hook without that contract, or weaken the recovery gate.

**2026-07-24T03:17:52Z**

Commit `be02b7c6b` closes the call-info evidence restart discontinuity. Exact detached route recovery inside `hxe_build_callinfo` now stages the existing idempotent controller-owned restart only when a live profile MBA advances beyond an already postvalidated PREOPT generation. Later call-info callbacks abstain from the obsolete MBA. Detached capture and first-pass coalescing do not request a restart. The focused test proves generation 1 to generation 2 evidence advancement, one restart request, flowchart consumption, and generation-2 normalization rebinding. The pinned Docker resolver, manager-controller, and lifecycle gate is 292/292; Ruff, Graphify, commit-time ast-grep, and all 14 worktree-local import contracts pass.

The mandatory production A560 canary completed in 25.76 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784862945_11.diag.sqlite3` (7,749,632 bytes); log: `.tmp/rhad-a560-v31-callinfo-restart.txt`. A560 remains C5, not C6: both generation-1 and follow-up generation-3 frontend-normalization transactions plan and apply 260 operations, publish their root, postvalidate, and commit receipts. Pseudocode remains substantial but still contains one residual `while ( 1 )`.

The intended lifecycle boundary advances. Event 28 records native facts moving generation 1 to 2, event 29 records the generated restart request, event 30 carries that pending request forward when terminal-return carriers advance generation 2 to 3, and event 31 records one flowchart consumption. Events 50-53 then stage, validate, commit, and postvalidate generation 3. The second-round GLBOPT1 fact consumer is accepted with `recovery_round_granted`, evidence generation 3, and postvalidated normalization generation 3. The elapsed time is 1.49x the preceding 17.34-second canary, within the v3.1 2x budget.

The first new failed obligation is current-MBA handler identity completeness during canonical recovery. DB event 54 is `rebind_region_entry missing` at stable native EA `0x40C62F`; the subsequent identity inventory shows only three handler bindings and 66 missing native handler targets. The log confirms that imported native-origin ownership is empty at GLBOPT1 and the pass declines structural mutation with `handlers=3 missing=66`. Event 182 then records a secondary `dispatcher_region_identity` evidence change from generation 3 to 4, causing later callbacks to defer against an unbound generation, but that occurs after the missing-handler decisions and is not the first failure.

Continue the v3.1 loop by explaining why generation-3 PREOPT publication loses imported native-origin handler ownership before GLBOPT1 identity rebinding. Preserve the accepted controller restart and both C5 receipts. Do not add another retry to mask missing ownership, treat the late dispatcher-region generation change as the first failure, or weaken complete materialized-identity gating.

**2026-07-24T03:28:17Z**

Commit `c73e2bdd6` tested the first ownership hypothesis by binding the legacy detached-import live-origin inventory to the resolver session only after receipt-backed frontend-normalization success. Rejected publication leaves the session unbound. The focused runtime tests are 47/47 local, and the pinned-Docker resolver, manager-controller, and lifecycle gate is 298/298. Ruff, Graphify, ast-grep, all 14 worktree-local import contracts, and commit hooks pass.

The mandatory production A560 canary completed in 33.60 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784863565_11.diag.sqlite3` (7,757,824 bytes); log: `.tmp/rhad-a560-v31-live-origin-binding.txt`. A560 remains C5, not C6: both frontend-normalization receipts still commit 260/260 operations, while the semantic oracle retains one residual `while ( 1 )`. The run is 1.30x the preceding 25.76-second canary and remains inside the v3.1 2x budget.

The production canary rejects the first hypothesis and does not move the failed obligation. DB event 54 remains `current_mba_identity_index: rebind_region_entry missing` at stable native EA `0x40C62F`; canonical recovery again has three handler bindings and 66 missing targets. The reason is now localized: the receipt-backed semantic-fragment path records exact `(live fict EA, native EA)` rows only in `SemanticFragmentBackendState.instruction_origins_by_block_id`, whereas `c73e2bdd6` reads the separate legacy `_IMPORTED_INSTRUCTION_ORIGINS` registry. The semantic-fragment path never populates that registry, and transaction completion discards the backend state, so the adapter binds an empty inventory.

Continue the v3.1 vertical loop by carrying the transaction-local origin rows through the successful publication result and binding that exact committed snapshot to the current resolver session after postvalidation. Aborted publication must expose no snapshot. Do not populate or fall back to the legacy global registry, retain transaction state after completion, weaken handler-completeness gating, or add another restart.

**2026-07-24T03:39:45Z**

Commit `841a4ac68` replaces the rejected legacy-registry read with receipt-backed current-MBA ownership. `SemanticFragmentBackendState` exports its exact staged live/native instruction coordinates to the pending gateway transaction; only a committed, postvalidated fragment receipt exposes them; the Hex-Rays backend clears its prior snapshot before every publication attempt; and the manager binds only that committed receipt to the current resolver session. Aborted publication exposes no snapshot. The diagnostic DB now records a typed `current_mba_import_origins_bound` lifecycle event with stable native-EA inventory. No legacy fallback, global registry write, retained transaction state, block serial, or new restart was added.

Focused local publication/backend/adapter verification is 118/118, and the pinned-Docker receipt, semantic-backend, manager, resolver-session, and computed-goto gate is 377/377. Ruff, Graphify, ast-grep, all 14 worktree-local import contracts, diff checks, and commit hooks pass.

The mandatory production A560 canary completed in 41.46 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784864262_11.diag.sqlite3` (12,304,384 bytes); log: `.tmp/rhad-a560-v31-receipt-origin-authority.txt`. A560 remains C5, not C6: both frontend-normalization receipts commit 260/260 operations and the semantic oracle still retains one residual `while ( 1 )`. The run is 1.61x the preceding accepted 25.76-second canary and remains inside the v3.1 2x budget.

The receipt path is now proven in production. DB events 28 and 55 each bind 545 current-MBA instruction-origin rows covering 250 unique native EAs for generations 1 and 3. The first failed obligation remains event 56, `current_mba_identity_index: rebind_region_entry missing` at native EA `0x40C62F`, and that decision repeats 62 times through event 7864. The bound inventory contains surviving origins later in the same imported native block, including `0x40C64B`, but not the handler entry `0x40C62F`. `MbaBlockIdentityIndex.from_mba` therefore rebuilds imported blocks from exact point origins and loses the transaction's wider `StableBlockIdentity` range, so range-entry rebinding still cannot recognize the handler.

Continue the v3.1 vertical loop by receipting each imported block's full stable identity together with its current live instruction anchors, binding that current-only inventory to the resolver session, and teaching current-MBA index construction to reattach the full identity to the uniquely anchored live block. A merged block may combine matching identities only when ownership is unambiguous. Aborted publication must expose no block binding. Do not persist or select by block serial, widen point origins into guessed ranges, consult the legacy importer registry, or weaken handler-completeness gating.

**2026-07-24T04:03:11Z**

Commits `e4e329756` and `21a8c9044` complete the receipt-backed full imported-identity slice as two logical checkpoints. The pure IR substrate defines a serial-free current-MBA snapshot tying live instruction EAs to both exact native origins and full `StableBlockIdentity` ranges. Current-MBA indexing reattaches those ranges only through receipt-owned live anchors, preserves only actually surviving exact origins, and uses full-range containment solely as an ambiguity-safe imported-region fallback. The gateway, committed receipt, Hex-Rays backend, resolver session, and manager now carry that snapshot atomically. Aborted publication exposes no snapshot, another MBA token cannot consume it, and the old point-only receipt/session API was removed rather than retained as compatibility.

Focused verification is 205/205 affected local tests and 378/378 combined local resolver/publication tests. The pinned Docker image `sha256:360f91d9d4ace70d89e03893f1d895d94383fa0fe426ddba9d3898a7922b650a` passes the same 378/378 gate. Ruff passes the integration files; the pure-IR files add no finding beyond three pre-existing warnings on unchanged lines. Ast-grep passes, all 14 worktree-local import contracts pass, commit hooks pass, diff checks pass, and `graphify update .` completes. No compatibility path, legacy-registry read, guessed range, block serial, sample-EA production guard, or architecture ignore was added.

The mandatory production A560 diagnostic canary completed in 40.57 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784865656_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-range-identity.txt`. A560 remains C5, not C6: both frontend-normalization transactions commit 260/260 operations, and the semantic oracle still rejects one residual `while ( 1 )`. The elapsed time is 0.98x the preceding 41.46-second canary and remains within the v3.1 budget.

The intended range-authority fact is now proven, but it falsifies the prior explanation for the unchanged failed obligation. DB events 28 and 55 each bind 545 current-MBA origins covering 250 unique native EAs and 93 full imported block identities. Event 56 still reports `rebind_region_entry missing` for region `[0x40C62F,0x40C64B)`. The event-55 receipt inventory contains no full range covering `0x40C62F`: the nearest imported ranges are `[0x40C60F,0x40C615)` and `[0x40C64B,0x40C659)`. Therefore the index is not discarding a receipted owner for this boundary; the selected portable plan or native-body publication never supplied one.

Continue the v3.1 vertical loop by tracing stable handler region `0x40C62F-0x40C64B` through generation-3 resolver evidence, `FragmentWorkItemScope` disposition, `FragmentPlan` block/native-body membership, PREOPT template selection, and the committed receipt inventory. Determine whether the corridor was incorrectly classified root-unreachable, omitted during native-body construction, or whether the handler-region boundary itself is wrong. Do not widen a neighboring block across the uncovered gap, weaken complete handler gating, add another restart, revive point-only compatibility, or broaden to the 91-route publication until one proof-owned owner for this exact region reaches the committed snapshot.

**2026-07-24T04:31:13Z**

Commits `77d4d46ca` and `dce6100d5` close the missing `0x40C62F-0x40C64B` owner frontier without promoting detached imported blocks to live publication roots. Fragment validation now proves internal operation reachability from both live replacement roots and explicit `FragmentNativeBody.entry_block_ids`, while still requiring every live publication root to be reachable from function entry and still rejecting unseeded disconnected work. Frontend normalization retains imported components rooted in `NativeSemanticClosure.seed_provenance`; incidental detached proofs remain explicitly root-unreachable. The pinned Docker architecture/runtime gate is 397/397 green, and both commits passed ast-grep and all 14 worktree-local import contracts.

The mandatory A560 diagnostic canary completed in 69.84 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784866936_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-proof-owned-body-roots.txt`. A560 remains C5, not C6: generation-1 and generation-3 frontend-normalization transactions each plan 924 items over 354 semantic operations and a 354-block native body, apply and postvalidate successfully, publish the live root at `0x40A5F0`, and commit a receipt. Each scope selects 217 proof obligations, leaves zero pending, and retains 11 truly unseeded obligations as root-unreachable. The semantic oracle still rejects one residual `while ( 1 )`. The 69.84-second runtime is 1.72x the preceding 40.57-second canary and remains within the v3.1 2x budget.

The intended owner is now proven in both committed receipts. Receipt identity events 26 and 53 each contain a full imported identity anchored at `0x40C62F` with native range `[0x40C62F,0x40C64B)` and exact instruction EAs `0x40C62F`, `0x40C634`, and `0x40C63A`; the prior `rebind_region_entry missing` decision is absent.

The new first failed obligation is evidence-authority convergence after the one controlled restart. After generation 3 commits, second-round live condition-chain recovery adds exactly 72 `ResolverTransferEvidenceFact` observations and advances native facts to generation 4, but no second restart is consumed and later canonical recovery correctly defers against the unbound generation. The DB set difference between snapshots 3 and 11 classifies the 72 rows as 36 `condition_chain_handler_evidence` plus 36 `live_state_dispatcher_row_evidence`, paired over the same 36 state constants. All 36 states already have generation-2 `static_handler_entry_route` authority. Every one of the 72 late rows has its alleged handler target inside its own `dispatcher_router_eas`, and all 72 collapse to source and target EA `0x40A560`; they therefore describe dispatcher-router landings, not new handler semantics.

Continue the v3.1 vertical loop by rejecting this malformed live condition-chain snapshot at the producer boundary and preserving the existing one-restart controller contract. Add a focused regression proving that a recovered row whose target is a dispatcher router emits neither live-row nor handler-transfer authority, while a uniquely native-EA-owned non-router handler row remains admissible. Then run the focused resolver gate and the mandatory A560 diagnostic canary, recording whether generation 3 stays bound and the next DB obligation. Do not allow another restart, coalesce genuine new routes, suppress conflicting exact authority, weaken target identity, or broaden to the 91-route publication.

**2026-07-24T04:39:06Z**

Commit `744173451` rejects recovered condition-chain rows whose targets are members of the recovered dispatcher-router set before either `live_state_dispatcher_row_evidence` or `condition_chain_handler_evidence` can enter portable authority. This applies the same invariant already enforced by semantic target projection: a router landing is navigation, not a handler. A focused pinned-Docker contract was red with two emitted transfers before the change and green afterward; the existing non-router admission contract also stays green. The complete current computed-goto plus resolver-session Docker gate is 260/260 green. The production resolver file passes `pyenv exec ruff check`; the touched runtime file retains the same ten pre-existing E402/F811 findings present at HEAD. Graphify is current, and the commit gate passes ast-grep and all 14 worktree-local import contracts.

The mandatory A560 diagnostic canary completed in 117.70 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784867723_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-router-landing-rejection.txt`. Runtime is 1.69x the preceding 69.84-second canary and remains within the v3.1 2x budget. A560 remains C5, not C6: generation-1 and generation-3 transactions each commit 924/924 operations, and pseudocode still contains one residual `while ( 1 )`.

The evidence-convergence defect is closed. The DB contains no generation-4 evidence event and no `condition_chain_handler_evidence` or `live_state_dispatcher_row_evidence` inventory. One controller restart advances generation 1 through native-fact generation 2 and terminal-carrier generation 3, one restart is consumed, generation 3 stages, validates, commits, and becomes postvalidated, and snapshot 13 accepts `state_machine_cff_unflattener` recovery with `recovery_round_granted`.

The next first failed obligation is complete current-MBA handler identity. DB event 63 is `rebind_region_entry missing` for stable terminal handler range `[0x40C898,0x40C8A2)`. Canonical recovery has 53 bound handlers and 13 missing targets, so structural mutation correctly defers. Both committed receipt inventories contain the exact imported identity anchored at `0x40C898` with range `[0x40C898,0x40C8A2)`, but later current-MBA lookup has no candidate. The full missing target set is `0x40C898`, `0x40B1EA`, `0x40AA2C`, `0x40B08B`, `0x40B236`, `0x40B10C`, `0x40B3FF`, `0x40BD84`, `0x40C1A0`, `0x40BC2D`, `0x40C541`, `0x40C4B4`, and `0x40BD19`.

Continue the v3.1 vertical loop from the first stable terminal owner at `0x40C898`. Trace its receipt-backed block identity, terminal carrier and return fragment, and live instruction/origin survival from committed PREOPT publication into the accepted generation-3 recovery maturity. Determine whether later optimization removes the terminal block, merges it into an unreceipted owner, or drops its current anchor before indexing. Preserve complete-handler gating and fragment atomicity. Do not widen range matching, select by block serial, resurrect a missing block from stale receipt coordinates, or treat the other 12 missing targets as independent fixes until the common ownership transition is classified.

**2026-07-24T04:55:30Z**

Commit `ad3b5aedf` closes the terminal-identity interpretation defect without manufacturing a live block or weakening complete-handler gating. Canonical semantic evidence now projects terminal `(state, native target EA)` pairs only from a validated `TERMINAL_RETURN` proof whose exact state write, state variable, destination, terminal carrier, and native identities already agree. The unflattener obtains that evidence through `canonical_semantic_evidence_for`, so only the current postvalidated generation can discharge a terminal target after Hex-Rays canonicalizes its physical `m_ret` block away. Stale receipt coordinates, raw carrier requests, and nonterminal proofs remain inadmissible.

Focused verification is 46/46 portable semantic/session tests and 318/318 pinned-Docker unflatten/resolver tests. `pyenv exec ruff check`, ast-grep, all 14 worktree-local import contracts, diff checks, commit hooks, and `graphify update .` pass. No compatibility path, legacy fallback, guessed range, block-serial selection, sample-EA production guard, or architecture ignore was added.

The mandatory A560 diagnostic canary completed in 118.39 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784868662_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-canonical-terminal-target.txt`. A560 remains C5, not C6: generation-1 and generation-3 transactions each commit 924/924 operations, generation 3 is postvalidated, the one controlled restart is consumed, snapshot 13 accepts `recovery_round_granted`, and the semantic oracle still rejects one residual `while ( 1 )`.

The intended semantic distinction is now proven. DB event 63 still reports that physical region entry `[0x40C898,0x40C8A2)` has no current live block, which is expected after Hex-Rays converts the return into a stop edge and later folds the carrier. Current generation-3 evidence still owns the exact terminal state route and carrier. The final complete-handler computation consequently excludes `state=0x19A7218A@0x40C898`; the remaining incomplete-handler inventory starts with `state=0x22C02855@0x40B1EA` and contains 12 nonterminal targets total.

The highest reached canary level remains C5. The first failed semantic obligation is now the nonterminal handler owner at stable native EA `0x40B1EA`, recorded by DB identity event 69 after the terminal-only event 63. The DB currently persists raw identity decisions and the evidence needed to justify the terminal exemption, but not the final ordered post-exemption missing inventory as one first-class record; that is an observability gap, and the secondary log was required to verify the 12-target final list. Continue the v3.1 vertical loop by first making the final complete-handler gate decision queryable in the diagnostic DB, then classify why `[0x40B1EA,... )` lacks a live owner across snapshots before changing semantic lowering. Do not treat `0x40C898` as a live-identity regression, widen identities, bypass the complete-handler gate, or broaden to the 91-route publication.

**2026-07-24T05:07:18Z**

Commit `787b5f4f2` makes the post-exemption materialized-handler completeness decision a first-class diagnostic fact consumer. Snapshot 13 records strategy `materialized_handler_completeness`, fact `resolver_session:materialized_handler_identity`, maturity `MMAT_GLBOPT1`, the validated terminal exemption, the ordered nonterminal missing `(state, native target EA)` inventory, and the first missing target. Focused pinned-Docker resolver verification is 319/319 green; Ruff, ast-grep, all 14 worktree-local import contracts, commit hooks, and `graphify update .` pass.

The mandatory A560 diagnostic canary completed in 117.18 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784869177_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-handler-completeness-db.txt`. A560 remains C5, not C6: generation-1 and generation-3 frontend-normalization transactions each commit 924/924 operations, generation 3 is postvalidated after one controlled restart, and pseudocode still contains one residual `while ( 1 )`.

The final completeness frontier is now queryable without reconstructing it from logs. The DB records 66 resolver targets, 54 live handler owners, the single validated terminal target `state=0x19A7218A@0x40C898`, and 12 nonterminal missing owners. The first is `state=0x22C02855@0x40B1EA`. Repeated `rebind_region_entry` decisions show no current candidate for stable range `[0x40B1EA,0x40B21C)`, and neither committed receipt contains an imported identity covering that range.

The generation-3 fragment plan explains the omission. It contains the adjacent imported identities `[0x40B1E4,0x40B1EA)` and `[0x40B21C,0x40B22A)` but not the handler body `[0x40B1EA,0x40B21C)`. Its work-item scope classifies `native-indirect-transfer@0x40B21A`, the transfer terminating that body, as root-unreachable. Native disassembly proves the omitted region is not routing residue: it pushes an argument, performs the indirect call through `0x42E10C`, assigns next state `0xDEF4B7E6`, and only then re-enters the dispatcher. The portable evidence already has an exact `static_handler_entry_route` owned range `[0x40B1EA,0x40B21C)` for state `0x22C02855`, plus the incoming state-write route from `0x40C751`.

Continue the v3.1 vertical loop by tracing why this exact proof-owned handler seed does not retain its native component during semantic-closure/work-item construction. The fix must be proof-scoped to an exact `static_handler_entry_route` target and owned range connected by canonical state-route authority. Do not promote all root-unreachable components, classify a handler as routing-only merely because its body later dispatches, widen neighboring identities across the gap, or broaden to the 91-route publication.

**2026-07-24T05:23:29Z**

Commit `95bc25c62` carries unambiguous `static_handler_entry_route` targets into prepatch semantic-closure seed provenance only when one exact owned native range contains the target EA. Missing, conflicting, or non-containing ownership makes source construction abstain. The focused regression models a handler entry, native call fallthrough, and resolver-proven indirect exit. The pinned-Docker resolver/session gate is 261/261 green, the portable semantic-closure/frontend-planner gate is 48/48 green, Ruff passes the production file, ast-grep passes, all 14 worktree-local import contracts pass, commit hooks pass, and `graphify update .` completes.

The mandatory A560 diagnostic canary completed in 117.09 seconds without a process segfault or INTERR. Primary DB: `.tmp/logs/d810_logs/000000000040a560_1784870141_11.diag.sqlite3`; log: `.tmp/rhad-a560-v31-proof-owned-handler-seeds.txt`. A560 remains C5, not C6. Generation-1 and generation-2 frontend-normalization transactions each commit all 924 transaction items over 354 semantic operations, publish and postvalidate the live root, and retain 217 selected, zero pending, and the same 11 root-unreachable obligations. Pseudocode still contains one residual `while ( 1 )`.

The canary falsifies the claim that `0x40B1EA` is absent from the prepatch source. Current source diagnostics include `0x40B1EA` among computed-transfer source entries and include native CFG blocks at `0x40B1EA` and the post-call continuation `0x40B1F4`. The first-class handler-completeness row remains unchanged at 66 resolver targets, 54 live owners, one terminal exemption, and first missing `state=0x22C02855@0x40B1EA`. `native-indirect-transfer@0x40B21A` remains root-unreachable.

The refined failure is publication-entry ownership. `plan_detached_semantic_closure_import` derives required entries from missing computed-transfer anchors; `_publication_native_entry_eas` then closes forward only from those entries. For this handler, the missing exit proof owns the downstream post-call block containing transfer `0x40B21A`, while the exact handler-entry proof owns `[0x40B1EA,0x40B21C)`. Because the range-owned `static_handler_entry_route` seed at `0x40B1EA` is not itself a publication root, the call-bearing predecessor is filtered before `_select_frontend_root_component` can retain it.

Continue the v3.1 vertical loop by carrying the exact owned native range on `ResolverProvenHandlerEntry` and admitting only such range-owned handler seeds as additional detached publication roots. Prove the real shape with a focused case in which a call-bearing handler entry precedes an already-required exit block. Do not promote generic computed-source seeds, all root-unreachable components, or a range-less provenance string; do not widen identities or bypass fragment validation.

**2026-07-24T05:34:50Z**

Commit `10050536e` carries exact `owned_native_ranges` on range-owned
`ResolverProvenHandlerEntry` evidence and admits only those exact
`static_handler_entry_route` seeds as detached publication roots. Generic and
range-less computed seeds remain ineligible, every admitted target must have
one containing range, and every owned range must stay within the same native
semantic closure. The focused portable regression models a call-bearing handler
entry preceding an already-required indirect-exit block. The affected
resolver, session, native-closure, and frontend-normalization Docker gate is
335/335 green. Ruff, ast-grep, all 14 worktree-local import contracts, commit
hooks, and `graphify update .` pass. No compatibility path, sample-EA guard,
block-serial authority, architecture ignore, or widened identity was added.

The mandatory production A560 diagnostic canary completed in 9.35 seconds
without a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784871005_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-range-owned-handler-roots.txt`. The highest contiguous
canary level is C1, not C5 or C6. The transaction plans 1,394 items over 480
semantic operations, selects all 228 obligations, leaves zero pending and zero
root-unreachable obligations, then aborts before fragment staging or root
publication and rolls back successfully. The short
`JUMPOUT(0x40B6C0)` pseudocode is a consequence of that safe rollback, not a
new semantic diagnosis.

The intended ownership result is proven: all eleven formerly root-unreachable
proof-owned handler components now enter the complete plan. The newly exposed
first C2 obligation is exact predicate ownership for
`native-body-edge@0x40C4B4`. The portable operation expects native predicate
EA `0x40C4D2`, but its detached PREOPT source
`blk637@0x40A560/native@0x40C4B4` ends in synthetic conditional opcode 42 at
fictitious EA `0xF1C02B3C`. The gateway correctly rejects the mismatch before
staging.

Native semantics show why accepting the synthetic tail as the raw
`0x40C4D2` branch would be wrong. The block computes the flow state with
`cmp [esp+0x44], 5; mov ebx, 0x2B8162DC; mov eax, 0x456A4274; cmove ebx, eax`
before the dispatcher-navigation corridor and unresolved transfer at
`0x40C4DA`. Existing portable authority maps state `0x2B8162DC` to handler
`0x40ADA2` and state `0x456A4274` to handler `0x40B199`, but no conditional
state-choice evidence currently owns source `0x40C4B4`. This matches the
reference Rhad algorithm's atomic CMOV rewrite: preserve the original
condition and install both semantic handler arms together, rather than
publishing the later dispatcher-navigation predicate.

Continue the v3.1 vertical loop by recovering that exact portable conditional
state choice, then make one semantic condition-plus-both-arms operation
supersede every generic imported dispatcher/native-body operation in the same
envelope. Start with a focused red resolver contract for the
`CMP/MOV/MOV/CMOV` form and keep the gateway's exact predicate rejection.
Do not accept arbitrary synthetic tails, preserve the raw dispatcher
navigation as semantics, add a sample-EA production guard, or broaden
publication beyond the first failed obligation.

**2026-07-24T05:48:00Z**

Commit `59a9cc37e` recovers an exact ESP-relative native comparison feeding a
CMOV state choice only after the comparison instruction has one canonical
IDA-frame stack identity. The resolver records that stable stack identity,
predicate width and constant, both selected state constants, and the original
condition code before any dispatcher navigation. Missing or ambiguous stack
identity still makes discovery abstain. The focused runtime contract was red
before the change and is green afterward; Ruff, ast-grep, all 14
worktree-local import contracts, commit hooks, and `graphify update .` pass.

The mandatory production A560 diagnostic canary completed in 9.24 seconds
without a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784872053_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-stack-predicate-choice.txt`. The highest contiguous level
remains C1, not C5 or C6, and the transaction again rolls back before fragment
staging or root publication.

The intended resolver evidence is proven in production. Snapshot 1 contains
`ResolverTransferEvidenceFact` proof `d177cf26836df2ac9d1f` with source
`0x40C4B4`, select/predicate consumer `0x40C4C3`, materialized anchors
`0x40C4B4` and `0x40C4C3`, canonical stack identity `68`, width 4, compare
constant 5, true state `0x456A4274` mapped to handler `0x40B199`, and false
state `0x2B8162DC` mapped to handler `0x40ADA2`. The row is a
`static_conditional_state_choice_bridge` and preserves the original condition.

The first failed C2 obligation is unchanged because frontend normalization
still projects only computed-goto patch plans. The transaction therefore emits
the generic imported operation `native-body-edge@0x40C4B4`, expects the later
raw dispatcher predicate at `0x40C4D2`, observes the detached synthetic tail at
fictitious EA `0xF1C02B3C`, aborts before staging, and rolls back successfully.

Continue by projecting only field-complete static conditional state-choice
bridges into `NativeIndirectTransferProof`: the proof must own the original
condition producer/consumer, the complete split dispatcher envelope through
the unique unresolved transfer, and both independently mapped handler
endpoints. That proof-owned operation must replace the generic native-body
operation at the same imported source, so exactly one atomic predicate and
both semantic arms own the envelope. Do not special-case `0x40C4B4`, weaken
predicate validation, or retain both operations.

**2026-07-24T05:57:48Z**

Commit `155deb98d` projects only field-complete, non-stack-carried
`static_conditional_state_choice_bridge` evidence into one portable
`NativeIndirectTransferProof`. The projection requires an exact original
predicate, one register or canonical stack predicate identity, two distinct
state values and mapped native handler targets, the complete bounded native
envelope through one resolver-proven indirect frontier, and convergence of
every route on that frontier. The focused pure regression models the exact
source, selected-value, join, and two-handler shape. Native-preanalysis is
40/40 green, the combined native-preanalysis/frontend-normalization gate is
72/72 green, Ruff passes, ast-grep passes, all 14 worktree-local import
contracts pass, commit hooks pass, and `graphify update .` completes.

The mandatory production A560 diagnostic canary completed in 8.42 seconds
without a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784872494_10.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-state-choice-envelope.txt`. The highest contiguous level
remains C1, not C2 or C6. No semantic-fragment transaction row exists because
portable plan construction rejects the operation before transaction staging.
The short rollback pseudocode ends in `JUMPOUT(0x40B6C0)` and is not semantic
acceptance.

The intended supersession is proven: lifecycle event 8 rejects
`native-state-choice@0x40C4C3`, rather than the former generic
`native-body-edge@0x40C4B4`. The first failed C2 obligation is:
`fragment operation 'native-state-choice@0x40C4C3' computed branch anchors do
not belong to its source identity`. The semantic proof owns native envelope
`[0x40C4B4,0x40C4DC)` and unresolved transfer `0x40C4DA`, but the imported
physical source block retains its exact native block identity
`[0x40C4B4,0x40C4D4)`. The transfer belongs to the downstream join block, so
requiring every normalization anchor to belong to the physical source block
conflates semantic-envelope authority with block identity.

Continue the v3.1 vertical loop by representing the participating
conditional-select envelope explicitly and validating each anchor against its
exact owned block while retaining one atomic semantic operation. Do not widen
the imported source block identity across multiple native blocks, admit an
arbitrary downstream transfer, weaken exact predicate ownership, or reintroduce
the generic native-body operation.

**2026-07-24T06:16:19Z**

Commit `ab152917a` represents an imported conditional-select as one physical
source plus proof-only selected-value and join identities. The planner validates
the exact native source/select/join topology, excludes the consumed routing
blocks from publication, retains their ranges in the scoped native body, and
emits no generic native-body operations for them. The detached PREOPT
materializer independently binds the source and consumed identities, validates
the complete split envelope, and stages only the semantic source operation.
The pure native-preanalysis/planner gate is 99/99 green, the pinned-Docker
detached-import and semantic-backend gate is 241/241 green, and Ruff, ast-grep,
all 14 worktree-local import contracts, commit hooks, and `graphify update .`
pass.

The mandatory production A560 diagnostic canary completed in 8.56 seconds
without a process segfault or reported INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784873600_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-imported-state-choice-envelope.txt`. The highest contiguous
level remains C1, not C2 or C6. No semantic-fragment transaction or mutation
receipt exists because portable evidence planning rejects before staging. The
rollback pseudocode remains the short `JUMPOUT(0x40B6C0)` stub.

Lifecycle event 8 records the first failed C2 obligation:
`imported conditional-select routing blocks overlap transfer sources
('0x40c4d4',)`. The competing persisted resolver fact is
`resolver_transfer:generation=1:revision=1:proof=91ec0baa895b4bbd8bd8`, a
`static_fixpoint` proof with physical source `0x40C4D4`, unresolved transfer
`0x40C4DA`, and dispatcher target `0x40A607`. That lower-level proof owns the
same selected/join routing envelope as `native-state-choice@0x40C4C3`; the
overlap rejection is therefore correct, but the proof inventory has not yet
expressed semantic supersession.

Continue by filtering a lower direct patch proof only when exactly one
field-complete state-choice proof owns the same unresolved transfer and fully
contains the patch source identity. Reject ambiguous or partial overlap and
retain unrelated patch proofs. Do not permit shared mutation ownership, add an
overlap exception in the planner, or key the rule to A560 sample addresses.

**2026-07-24T06:24:21Z**

Commit `3b19a2d03` makes a field-complete conditional state-choice proof
supersede a lower direct patch proof only when both own the same unresolved
transfer, the state-choice source fully contains the patch source, and the
owner is unique. Unrelated and partial-overlap proofs remain, ambiguous
ownership rejects, and the surviving semantic proof records the superseded
proof ID as diagnostic provenance. The pure native-preanalysis gate is 100/100
green, the pinned-Docker resolver/session gate is 262/262 green, Ruff passes,
ast-grep passes, all 14 worktree-local import contracts pass, commit hooks
pass, and `graphify update .` completes.

The mandatory production A560 diagnostic canary completed in 8.03 seconds
without a process segfault or reported INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784874057_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-frontier-supersession.txt`. The highest contiguous level
remains C1, not C2 or C6. The portable plan now succeeds and records one
frontend-normalization transaction with 1,390 planned items. Its mutation plan
contains the atomic state-choice operation at source `0x40C4B4`, including the
fallthrough helper and both semantic handler arms to `0x40B199` and
`0x40ADA2`.

The transaction aborts during staging before root publication:
`fragment_staged=0`, publication is not attempted, rollback succeeds, and the
receipt records one applied operation followed by
`conditional-select normalization source has no replaced original`. This is
not INTERR 52719 or another Hex-Rays verifier failure; SDK decoding remains the
required first step for any future INTERR.

The first failed C2 obligation is backend envelope ownership. The imported
conditional-select envelope is already owned and realized by the detached
native-body materializer, but
`_normalize_conditional_select_replacement` treats it as the live replacement
envelope and requires `replaces_block_id`. Continue with an explicit
envelope-type dispatch: imported envelopes remain materializer-owned, live
replacement envelopes retain the existing replacement normalization, and
unknown ownership rejects. Prove this first with a focused red semantic-backend
contract. Do not add a compatibility fallback, manufacture a replaced original,
weaken fragment validation, or special-case A560 addresses.

**2026-07-24T06:48:34Z**

Commit `fc04bb77f` completes the imported-envelope ownership slice. The
semantic-fragment backend now dispatches a
`FragmentImportedConditionalSelectEnvelope` to the detached native-body
materializer and reserves live replacement normalization for
`FragmentConditionalSelectEnvelope`; an unknown envelope type rejects instead
of falling through. The pinned-Docker affected semantic-backend and detached
import gate is 133/133 green, Ruff passes, ast-grep passes, all 14
worktree-local import contracts pass, commit hooks pass, and
`graphify update .` completes.

The mandatory production A560 diagnostic canary completed in 132.41 seconds.
Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784875062_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-imported-envelope-owner-dispatch.txt`. The process did not
segfault. Hex-Rays completed the decompilation pipeline but returned no cfunc
with `hexrays_failure(code=-1, ea=0x40A560, description='INTERR: 51974')`.
This is not INTERR 52719.

The highest contiguous canary level is C5, not C6. The diagnostic DB records
two committed frontend-normalization transactions,
`73e6eb1c03be41bfba2acde8217f4a89` and
`fb151ae362474420bf1783872aa25e35`. Each transaction staged its fragment,
passed 3,357 prepublication and 6,263 postpublication outcomes, published its
root, and committed a receipt with 1,390 planned and 1,390 applied operations.
The second transaction follows the one controlled restart. Evidence generation
3 is discovered after the second normalization round.

SDK-first decoding of the exact runtime failure identifies `51974` as the
ctree-generation assertion that a surviving microinstruction must not carry
`minsn_t.iprops & IPROP_ASSERT`. The matching IDA 9.3 runtime binary contains
the unique `51974` call site immediately after testing bit 7 of the
microinstruction `iprops` field. This is a Hex-Rays internal consistency error,
not a host-process segfault and not a stale block-index assertion.

The first failed C6 obligation is therefore assertion-instruction lifecycle
hygiene before ctree generation. The diagnostic DB cannot yet identify the
responsible anchored instruction because its `instructions` table records the
opcode and operands but not `iprops` or an assertion marker. Continue by adding
first-class `iprops` and `is_assert` instruction snapshot fields, with no
backward-compatible schema path, then rerun the exact A560 canary and query the
DB for the first `blkN@EA` assertion owner. Do not clear assertion flags
generically, bypass ctree generation, infer ownership from text logs, or alter
semantic publication until the DB proves the instruction's origin.

**2026-07-24T07:03:03Z**

Commit `d1f9ee282` makes microinstruction assertion state first-class in
diagnostic schema v6. The live Hex-Rays adapter captures the raw `iprops`
bitmask and exact `IPROP_ASSERT` classification, the `instructions` table
persists indexed `iprops` and `is_assert` columns, and schema v5 is rejected
without migration. The pinned-Docker focused gate is 89/89 green, ast-grep
passes, all 14 worktree-local import contracts pass, the changed-file Ruff gate
passes with only the two pre-existing file-level findings excluded, commit
hooks pass, and `graphify update .` completes.

The mandatory production A560 diagnostic canary completed in 131.24 seconds.
Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784876298_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-assertion-state-diag.txt`. The process did not segfault and
reproduced `hexrays_failure(code=-1, ea=0x40A560,
description='INTERR: 51974')`.

The new DB evidence rejects the proposed generic assertion-hygiene fix.
Assertion moves are normal Hex-Rays constraints throughout the captured
maturities: the two GLBOPT2 pre-D810 snapshots each contain 49. At the failing
snapshot 15, the only assertion reachable from function entry is the original
native `mov #0, %arg_4` in `blk2@0x40A5AB`; it predates normalization and is not
owned by an imported body or semantic operation. Do not clear or omit
`IPROP_ASSERT` instructions.

The actual postpublication anomaly is global entry reachability. Snapshot 15
contains 381 blocks, but entry reaches only five:
`blk0@0x40A560`, `blk1@0x40A560`, `blk2@0x40A5AB`,
`blk3@0x40A5AE`, and the self-loop `blk4@0x40A5F0`. The imported body and
semantic routes are detached from entry.

Nevertheless, transactions `45f7a38c98d54511b0c28bfcd3e6edff` and
`b67d34f0e324489a8c702809643fa1dd` each report 1,390/1,390 applied operations,
3,357 passing prepublication outcomes, 6,263 passing postpublication outcomes,
root publication, and a committed receipt. Their single publication group
redirects predecessor identity anchored at `0x40A5AE` to a replacement
identity anchored at `0x40A5F0`. Postpublication `operation_reachability`
incorrectly accepts 478 operations as reachable from either a publication root
or an independent native-body root, so detached imported roots satisfy the
check after publication.

The pipeline therefore reached nominal C5 instrumentation, but the highest
trustworthy level is C4 because C5 postvalidation is unsound. The first failed
C5 obligation is that every required operation must be reachable from the
published function entry after root authority changes; detached
prepublication/native-body roots may not remain independent reachability
authorities. Treat INTERR 51974 as a downstream symptom of that disconnected
publication unless later DB evidence disproves the link.

Continue the v3.1 vertical loop with one focused postpublication validator
contract. Prepublication may validate a closed fragment from detached staging
roots. Postpublication must start at the actual projected/live function entry
and reject any required operation reachable only from an independent imported
root. The failed postcondition and anchored unreachable operations must be
persisted before the receipt aborts and rolls root authority back. Do not alter
the importer, assertion flags, or Rhad route semantics in this slice.

**2026-07-24T07:12:27Z**

Commit `20bd02a1f` phase-splits fragment reachability authority. Detached
publication and native-body roots remain valid while proving a closed staged
fragment, but postpublication validation now starts exclusively at the
projected function entry. The semantic backend applies that strict validator
before accepting a publication receipt. The focused portable-validator,
publication-gateway, and production-backend gate is 141/141 green both locally
and in the pinned Docker runtime; ast-grep passes, all 14 worktree-local import
contracts pass, the changed-file Ruff gate passes with only pre-existing
file-level findings excluded, commit hooks pass, and `graphify update .`
completes.

The mandatory production A560 diagnostic canary completed in 12.34 seconds.
Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784877078_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-published-entry-reachability.txt`. The process did not
segfault and Hex-Rays reported no INTERR. The semantic oracle remains red with
a short rollback body ending in `JUMPOUT(0x40B6C0)`.

Transaction `e487895abdb4457c84de4712b1ce6e57` stages all 1,390 planned
operations and passes 3,357 prepublication outcomes. It publishes the one root
group from predecessor identity anchored at `0x40A5AE` to the replacement
identity anchored at `0x40A5F0`. Strict postpublication validation then rejects
385 disconnected imported blocks and 385 unreachable operations, rolls the
root group and transaction back successfully, and records only an explicit
`aborted` receipt. No committed mutation receipt exists.

The highest trustworthy canary level remains C4. The first failed C5
obligation is entry-authoritative connectivity: imported block
`native[0x40A6B4-0x40A6C0;exact=0x40A6B4]:imported` is disconnected from the
projected function entry, making
`native-indirect-transfer@0x40A6BE` unreachable. The former INTERR 51974 is
therefore eliminated from this canary by rejecting the malformed publication
before ctree generation; it was a downstream symptom, not evidence that
`IPROP_ASSERT` should be stripped.

Continue from this explicit C5 failure by proving the published entry corridor
from the replacement identity anchored at `0x40A5F0` into one semantic imported
fragment. Reach one complete C5 vertical fragment before broad 91-route
publication. Do not weaken the postpublication gate, restore detached roots as
independent authority, clear assertion flags, or special-case A560 addresses.

**2026-07-24T07:26:23Z**

Commit `2d5c77947` re-establishes the required vertical-fragment milestone
under the strict entry-authoritative postpublication validator. Resolver proof
ownership and exact owned native ranges retain detached components as future
obligations, but no longer merge those components into the current live-root
publication. The complete portable inventory still validates and dispositions
them, so no proof is forgotten or reclassified as generic unreachable work.

The planner contract was red while proof-owned detached roots were selected and
green once they were deferred. The affected local and pinned-Docker planner,
manager, validator, gateway, and live semantic-backend gate is 185/185 green.
Ruff passes both changed files, ast-grep passes, all 14 worktree-local import
contracts pass, commit hooks pass, and `graphify update .` completes.

The mandatory production A560 diagnostic canary completed in 17.00 seconds
without a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784877620_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-deferred-detached-roots.txt`. The semantic oracle remains
red because the generated pseudocode contains one residual `while ( 1 )`.

Transaction `e7675afc0b1340369106cb352ac75415` is the first trustworthy C5
vertical publication after strict postpublication entry reachability became
mandatory. Its plan contains 102 blocks and 93 semantic operations, with one
93-block native body. It selects 40 portable transfer obligations, retains 188
as remaining work, and records zero unreachable obligations. All 639
prepublication and 1,180 postpublication outcomes pass. The one root group
publishes from predecessor identity anchored at `0x40A5AE` to the replacement
identity anchored at `0x40A5F0`; the 260/260 receipt commits without rollback.

The highest canary level is therefore C5, not C6. This satisfies v3.1's
real-fragment milestone and permits work on the broader route inventory, but it
does not make A560 semantically green. The DB identifies the first post-C5
obligation at MMAT_CALLS: `state_machine_cff_unflattener` declines
`resolver_session:indirect_dispatcher_materialized` with typed reason
`preopt_evidence_generation_unbound`. The payload records evidence generation
1, no postvalidated normalization generation, and no imported dispatcher
authority; the same decline repeats at MMAT_GLBOPT1. By GLBOPT1 post-D810, the
entry-reachable replacement has collapsed to the self-loop
`blk2@0x40A5F0`, which explains the residual infinite loop downstream.

Continue the v3.1 vertical loop from the 188 retained obligations and the
unbound-generation handoff. Broad publication must give each additional
component real entry-derived or canonical semantic publication authority; it
must not restore detached native-body roots as independent postpublication
reachability authorities. Preserve the committed strict C5 fragment as the
regression baseline while deciding how normalization hands the retained body
inventory to canonical state-route ownership.

**2026-07-24T07:37:06Z**

Correction to the preceding checkpoint: under v3.1's cumulative C0-C6
definitions, the latest production A560 canary reaches C2, not C5. Transaction
`e7675afc0b1340369106cb352ac75415` proves receipt-backed frontend
normalization for 40 selected obligations and independently proves that the
gateway can complete staging, publication, postvalidation, and receipt
mechanics for that normalization fragment. It does not reach C3 because the
canonical spine produces no semantic `FragmentPlan`. C4 and C5 therefore
cannot be claimed as the highest contiguous production-canary level. The
controlled terminal-fragment checkpoint at `385c3df3f` remains the separate
real-Rhad canonical C5 milestone; it does not substitute for production
pipeline integration.

Current authoritative source state is clean commit `0ca26ac1f9`. The primary
production evidence remains
`.tmp/logs/d810_logs/000000000040a560_1784877620_11.diag.sqlite3`. Its first
failed C3 obligation is the typed recovery-gate decision
`preopt_evidence_generation_unbound`: a partial, receipted normalization work
item deliberately leaves
`normalization_published_postvalidated_generation` unset while 188 obligations
remain, and both the early unflatten gate and
`canonical_semantic_evidence_for()` require whole-generation normalization
authority.

The DB also disproves a simple gate relaxation. At the MMAT_CALLS pre-D810
snapshot, none of the 91 state-route proofs has its source-write, delivery, and
target native anchors all represented directly in the portable `FlowGraph`.
The published imported blocks carry fictitious instruction addresses and
function-entry block starts; their native ownership survives in
`MbaBlockIdentityIndex` and the mutation receipt instead. The current canonical
binder consults only `FlowGraph` anchors, groups all 91 routes into one atomic
evidence object, and requires every route to bind. The canonical planner also
has no detached-native-body operand. Relaxing the lifecycle gate would
therefore run an all-or-nothing planner without the imported identity authority
it needs and would risk recreating stale physical-index failures. Any future
INTERR must first be decoded from the matching SDK source; `52719` is
`mba_t::get_mblock(n)` asserting `n < qty`, specifically an out-of-range
physical block index.

Falsifiable next hypothesis: the first production C3 fragment requires
canonical composition before publication, not another independent detached
PREOPT publication. A canonical pass must bind one route group against the
unpublished normalization plan plus current logical identity authority,
supersede the corresponding unresolved dispatcher operation, include the
required detached target body, and hand one closed atomic `FragmentPlan` to
the gateway. If this is correct, a focused portable contract will turn one
live delivery plus one detached target into one entry-reachable canonical plan
while ambiguous or incomplete identity remains a typed abstention. The next
A560 DB should then either record that one C3 plan or identify its first
missing stable-EA obligation; it must not advance whole-generation
normalization authority or publish a detached body on its own.

**2026-07-24T08:24:10Z**

The partial-canonical-composition checkpoint is committed through
`60f731a2c`, with one uncommitted two-file maturity-gate slice. Commit
`db172df44` implements the Phase 6 pure composition transform for one live
source and one detached target. Commits `e3f8afbed` and `a61497daf` implement
the Phase 4/6 candidate-evidence lifecycle and adapter capability without
relaxing whole-generation authority. Commit `60f731a2c` makes canonical
lowering consume that candidate plus the complete unpublished Phase 5
normalization inventory and select one deterministic route plan. The dirty
slice attempts to admit that continuation through the live unflattener.

The mandatory exact A560 canary completed in 34.63 seconds without a process
segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784881241_11.diag.sqlite3`; focused
pytest log: `.tmp/rhad-a560-v31-partial-canonical-exact.txt`. The semantic
oracle remains red with one residual `while ( 1 )`.

The highest contiguous production level remains C2. The DB preserves the
generation-1 frontend-normalization plan and its 260/260 committed receipt,
but contains no canonical mutation plan or canonical semantic-fragment
transaction. The first failed C3 obligation is now the CALLS maturity gate:
snapshot 3 records `state_machine_cff_unflattener` declining
`resolver_session:indirect_dispatcher_materialized` with typed reason
`maturity_not_registered`. Its payload records `evidence_generation=1`,
`indirect_dispatcher_materialized=false`, no whole-generation postvalidated
normalization authority, and no imported-identity readiness.

The secondary log confirms the contradictory other half of the gate. At
GLBOPT1 the same partial-composition evidence selects
`materialized_computed_goto_continuation`, but that family defers because it
declares CALLS only. This also causes repeated GLBOPT1 recovery-evidence work:
the DB records 7,952 identity decisions and the canary exceeds the preceding
17-second baseline by slightly more than 2x. Do not commit the dirty gate in
this form.

Next falsifiable hypothesis: receipted partial canonical composition is its
own CALLS admission authority. Admit that authority at the coarse maturity
gate without pretending `indirect_dispatcher_materialized` is true, and reject
it before expensive recovery work at non-CALLS maturities. The focused
contract must prove CALLS is granted, GLBOPT1 is declined before family
selection, and unrelated nonmaterialized and Tigress profiles are unchanged.
Only then rerun A560 and require either one C3 canonical plan or a new typed,
stable-EA composition obligation from the diagnostic DB.

**2026-07-24T08:29:10Z**

The CALLS-admission hypothesis is confirmed. The focused recovery-gate
contract proves that receipted partial canonical composition is admitted at
CALLS without reclassifying the function as an indirect/Tigress profile,
GLBOPT1 declines early with `canonical_composition_requires_calls`, ordinary
nonmaterialized CALLS remains unregistered, and Tigress keeps its existing
one-shot CALLS contract. The nearest lifecycle, capability, canonical-planning,
and maturity suite is 105/105 green, and Ruff passes.

The mandatory exact A560 canary completed in 12.69 seconds without a process
segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784881614_11.diag.sqlite3`; log:
`.tmp/rhad-a560-v31-canonical-calls-admission.txt`. The semantic oracle remains
red with one residual `while ( 1 )`.

The highest contiguous level remains C2. The DB preserves the generation-1
260/260 frontend-normalization receipt and records CALLS
`recovery_round_granted` with `indirect_dispatcher_materialized=false`.
GLBOPT1 records the new early typed decline. Identity decisions fall from
7,952 in the rejected gate attempt to 141, and runtime returns below the
preceding 17-second non-debug baseline. No canonical mutation plan or
transaction exists.

The first DB-visible CALLS decline after admission is materialized-handler
completeness: state `0x0872BFF1` has no live owner for target `0x40C62F`.
That is not the causal blocker for the candidate-composition lane, which
deliberately composes against the unpublished detached inventory instead of
requiring all live handlers. The actual scheduler blocker is visible only in
the secondary log: `lower_state_machine` is rejected because the pass spec
still requires `bound_canonical_semantic_evidence`. The candidate fallback
added at `60f731a2c` runs only when that analysis is absent, so the static pass
contract and implementation are contradictory.

This is also a Phase 8 visibility gap: the scheduler rejection is not persisted
as a lifecycle event or failed obligation. The next slice must make the
canonical lowerer accept either bound evidence or the candidate-plus-
normalization capabilities at its pass-contract boundary, while preserving the
existing typed rejection inside the pass when neither source is available.
The next A560 canary must either record one complete C3 plan or persist the
first stable-EA composition rejection in the diagnostic DB.

**2026-07-24T08:45:16Z**

The canonical pass-contract and failure-visibility slice is complete. The
semantic lowerer no longer statically requires
`bound_canonical_semantic_evidence`; it may enter through the existing
candidate-plus-normalization capability path. Partial canonical composition
has a one-shot CALLS budget per function, maturity, and evidence epoch, so a
failed candidate does not consume the ordinary 64-round non-indirect
convergence budget.

Canonical planning failures now cross the vendor callback boundary as typed
diagnostic obligations. Declared fragment rejections retain their native EA
and structured reason. The known frontend-normalization rejection is adapted
at the canonical pass boundary to retain the attempted route proof and source
EA. Unexpected exceptions still propagate rather than being swallowed after a
possibly partial backend publication.

The focused canonical transform, pipeline-driver, frontend-lifecycle,
capability, session-authority, and live recovery-gate suite is 259/259 green.
Ruff and ast-grep pass, all 14 worktree-local import contracts pass, and
`graphify update .` completes. The mandatory exact A560 canary completed in
15.41 seconds without a process segfault or INTERR.
Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784882874_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-canonical-corridor-final.txt`. The semantic oracle
remains red with one residual `while ( 1 )`.

The highest contiguous production level remains C2. The DB records the
generation-1 frontend-normalization transaction and committed receipt, 141
identity decisions, one accepted CALLS candidate attempt, and no canonical
plan. The first failed C3 obligation is now explicit:
`state_assignment@0x40A5C8:0xABB95547` at stable native EA `0x40A5C8` is
declined with typed reason `frontend_normalization_plan_rejected` because the
original route corridor is not closed. The next callback records
`canonical_composition_already_attempted`; GLBOPT1 still declines before
planning with `canonical_composition_requires_calls`.

Continue the v3.1 vertical loop at the corridor-closure obligation for
`0x40A5C8`. Do not broaden to the 91-route transaction. The next change must
explain which relevant live or detached edge leaves the projected
normalization corridor, make that edge identity visible to the diagnostic DB,
and either close one candidate fragment or decline with a narrower stable-EA
reason.

**2026-07-24T09:05:35Z**

The corridor-boundary observability slice is verified and ready for its own
commit. Frontend normalization still rejects open projected corridors, but the
rejection now records a deterministic reason, edge role, and both snapshot-local
block references paired with EA anchors. Canonical composition preserves that
structured failure in the diagnostic DB. The focused frontend and canonical
tests are 38/38 green; the broader canonical transform, pipeline, frontend
lifecycle, session-authority, and live capability suite is 163/163 green.
Ruff and diff checks pass.

The mandatory A560 diagnostic canary completed in 16.58 seconds without a
process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784883737_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-corridor-boundary-db.txt`. The semantic oracle remains red
with one residual `while ( 1 )`.

The highest contiguous production level remains C2. The generation-1
frontend-normalization transaction still commits 260/260 operations, the DB
still contains 141 identity decisions and no canonical plan, and no earlier
canary obligation regressed. The first failed C3 obligation remains
`state_assignment@0x40A5C8:0xABB95547`, but its exact closure boundary is now
queryable: external predecessor `blk7@0x40A560` enters corridor block
`blk4@0x40A5F0`.

That boundary is unrelated to the attempted route. In the same CALLS snapshot,
`blk6@0x40A560` compares `ebx` with terminal state `0x19A7218A`, its
fallthrough `blk7@0x40A560` jumps to `blk4@0x40A5F0`, and the candidate owns
state `0xABB95547`. The committed normalization plan identifies
`0x40A5F0` as the root replacement for
`native-indirect-transfer@0x40A605`; its imported
`native-indirect-transfer@0x40A5E3` independently routes terminal target
`0x40C898` or falls back to that root. The full-inventory planner is therefore
rejecting the candidate because a separately published terminal envelope enters
the common root, not because the `0x40A5C8` candidate corridor itself is open.

Next falsifiable hypothesis: canonical composition must consume a
candidate-scoped frontend-normalization projection, or the retained portable
component of the already validated normalization plan, rather than first
requiring closure of the complete transfer inventory against the later CALLS
graph. Strict corridor closure must remain unchanged inside the selected
component. Do not add `blk7@0x40A560` to the candidate by reachability, weaken
the external-predecessor veto, or broaden to the 91-route transaction.

**2026-07-24T09:42:23Z**

The retained-plan and omitted-delivery source-rebinding slice is verified and
ready for commit. PREOPT now retains the complete, serial-free normalization
plan only after a selected work-item receipt, under manager-owned
function/native-key/generation authority. CALLS consumes that exact plan through
a read-only lifecycle binding instead of replanning the complete inventory
against the mutated graph.

Canonical composition keeps the retained PREOPT source identity as proof of the
full state-write-to-delivery corridor, then binds a unique current block whose
identity is a contained subset and which owns the exact state write. A
materialized corridor EA in any other current block rejects the entire route as
`split_route_corridor_ownership`; generic stable-identity equality remains
strict. For the A560 candidate, this accounts for CALLS retaining the write at
`0x40A5B2` in `blk3@0x40A5AE` while omitting delivery EA `0x40A5C8`.

The affected architecture and manager set is 80/80 green. The broader unit-pass,
manager, authority, canonical-transform, computed-goto resolver, and adapter set
is 826/826 green. Changed-file Ruff and diff checks pass, ast-grep passes,
all 14 worktree-local import contracts pass, and `graphify update .` completes
with 44,724 nodes and 129,899 edges.

The mandatory exact A560 canary completed in 16.76 seconds without a process
segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784885824_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-live-source-subset.txt`. The semantic oracle remains red
with one residual `while ( 1 )`.

The previous `current_graph_owner_count_mismatch` at `0x40A5C8` is gone, and
CALLS proceeds into the canonical pipeline. The highest DB-proven contiguous
level nevertheless remains C2: the DB contains the generation-1
frontend-normalization plan and 260/260 committed receipt, but no canonical C3
plan, semantic-fragment transaction, or typed canonical rejection. The accepted
CALLS attempt then consumes its one-shot budget and the next callback records
`canonical_composition_already_attempted`.

The first failed obligation is therefore Phase 8/C3 diagnostic completeness.
The DB cannot yet identify the exception or scheduler boundary between canonical
pipeline entry and plan publication. The next slice must persist that exact
pipeline exception as a typed canonical diagnostic and then re-raise it; it must
not swallow an unexpected exception or claim a semantic failure. Only after the
DB exposes the underlying cause should the v3.1 vertical loop change planning or
publication behavior.

**2026-07-24T09:49:33Z**

The Phase 8/C3 diagnostic-completeness slice is verified and ready for its own
commit. The canonical pipeline boundary now records every unexpected exception
as a stable-EA fact-consumer decision and then re-raises the original exception
object. Existing typed `CanonicalSemanticFragmentRejected` declines retain their
previous behavior; a diagnostic-write failure cannot replace the underlying
pipeline exception.

The complete bounded-rerun runtime file is 62/62 green, and changed-file Ruff
checks pass. The mandatory exact A560 canary completed in 15.38 seconds without
a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784886519_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-canonical-exception.txt`. The semantic oracle remains red
with one residual `while ( 1 )`.

The highest contiguous production level remains C2. At MMAT_CALLS, the new DB
record identifies the first failed C3 obligation exactly:
`d810.transforms.fragment_plan.FragmentPlanRejected` with detail
`fragment plan contains duplicate block ids`, anchored at function EA
`0x40A560`. No canonical mutation plan or transaction is published before this
failure.

The next vertical-loop slice must identify the colliding portable block
identities in the candidate-scoped fragment plan, preserve both native EA
anchors in the rejection, and correct the composition at its identity source.
It must not deduplicate after construction, weaken `FragmentPlan` validation, or
attempt the broad 91-route publication.

**2026-07-24T09:58:14Z**

The duplicate plan-local block-id slice is verified and ready for its own
commit. The collision came from canonical composition naming every external
block from its current `start_ea`. In A560's CALLS graph, several imported
router blocks retain the placeholder start EA `0x40A560` while owning distinct
native instruction ranges, so distinct portable identities collapsed to one
`external:0x40A560` identifier.

Frontend normalization and canonical composition now share one portable
identity token and deterministic semantic-anchor implementation from
`d810.ir.block_identity`. The token contains the complete stable native ranges
and exact instruction EAs and never contains a block serial. Two current blocks
with genuinely identical stable identities reject as
`external_identity_ambiguous`, with both snapshot-local owners rendered as
`blkN@EA` and the complete stable identity included in the payload.

The identity, frontend-normalization, and canonical-composition suites are
56/56 green, and changed-file Ruff and diff checks pass. The mandatory exact
A560 canary completed in 16.39 seconds without a process segfault or INTERR.
Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784887027_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-identity-block-ids.txt`. The semantic oracle remains red
with one residual `while ( 1 )`.

The duplicate-block-id failure is gone, but the highest contiguous level
remains C2 because no canonical plan is yet published. The next C3 obligation
is a new `FragmentPlanRejected`: selected normalization replacement
`native[0x40A5F0-0x40A5F1,0x40A5F6-0x40A5F7,0x40A5F8-0x40A5F9,0x40A5FE-0x40A5FF;exact=0x40A5F0,0x40A5F6,0x40A5F8,0x40A5FE]:replacement`
does not include the original block it names. The next slice must close the
selected detached component over replacement-to-original ownership before
constructing the canonical plan; it must not weaken the plan invariant or
deduplicate blocks afterward.

**2026-07-24T10:03:41Z**

The detached-component boundary-ownership slice is verified and ready for its
own commit. The earlier checkpoint's wording was too loose: copying the
normalization replacement's original into the canonical plan would make the
canonical transaction re-own and republish an already published PREOPT block.
That would overlap authority rather than close the component.

The composer now projects every non-imported edge leaving the selected detached
native body into one stable-identity external block. A PREOPT replacement
therefore rebinds as current published authority at CALLS, with no
`replaces_block_id` and no extra owned original. The projection is performed
before plan construction; it does not deduplicate an invalid finished plan or
weaken replacement validation.

The canonical-transform, canonical-lowering, and frontend-normalization suites
are 51/51 green, and changed-file Ruff and diff checks pass. The mandatory exact
A560 canary completed in 16.39 seconds without a process segfault or INTERR.
Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784887378_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-detached-boundary.txt`. The semantic oracle remains red with
one residual `while ( 1 )`.

The missing-original failure is gone, but the highest contiguous level remains
C2 because no canonical plan is yet published. The next C3 obligation is a new
`FragmentPlanRejected`: imported operation
`native-indirect-transfer@0x40A5E3` retains computed-branch normalization while
the composed plan has canonical-semantic publication purpose. The next slice
must decide how the already-proven branch normalization becomes canonical
direct-route intent without granting the canonical plan generic frontend
normalization authority.

**2026-07-24T10:09:04Z**

The imported-branch construction-proof slice is verified and ready for its own
commit. Computed-branch normalization is not optional metadata: the detached
native-body materializer uses it before staging to cut the unresolved `m_ijmp`
suffix and synthesize the proven conditional branch. Removing it would expose
unresolved imported control flow to the canonical operation.

Canonical plans may now carry this proof only when the operation source is an
imported block, that block belongs to a native body in the same plan, and the
operation id is named by that body's proof set. A canonical operation on a live
replacement still rejects. This does not grant canonical plans generic
frontend-normalization authority or create a compatibility path.

The fragment-plan, canonical-transform, frontend-normalization, and
canonical-lowering suites are 79/79 green, and changed-file Ruff and diff checks
pass. The mandatory exact A560 canary completed without a process segfault or
INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784887699_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-canonical-imported-normalization.txt`. The semantic oracle
remains red with one residual `while ( 1 )`.

The phase-purpose rejection is gone, but the highest contiguous level remains
C2 because the canonical plan is stopped before publication recording. The next
C3 obligation is `RuntimeError: canonical semantic planning requires current
normalized authority`. The current lifecycle requires global
`normalization_published_postvalidated_generation == evidence_generation`,
although the candidate is backed by one committed normalization work item with
other obligations intentionally remaining. The next slice must model
receipt-scoped normalized authority for that selected obligation set; it must
not mark the entire generation normalized or bypass lifecycle authority.

**2026-07-24T10:30:48Z**

The receipt-scoped normalization-authority slice is verified and ready for its
own commit. One immutable portable token now binds the exact evidence
generation, publication revision, source plan lineage, receipted work-item id,
and selected, remaining, and unreachable obligation sets. The manager returns
the retained PREOPT plan only with that token; canonical composition copies the
token into its `FragmentPlan`; and lifecycle authority accepts it only when it
matches the session's current receipted scope. Repeated vertical work items must
advance by exactly one revision without changing source-plan lineage. Stale,
skipped, regressed, untyped, or scope-drifted authority rejects. This does not
mark the complete evidence generation normalized and adds no compatibility
path.

Focused local lifecycle, gateway, plan, lowering, and composition verification
is 145/145 green. The current pinned Docker resolver authority suite is 262/262
green. The earlier 303 count is not a current target: it included the
intentionally deleted 46-test legacy island lowerer, while five current tests
have since been added to the surviving resolver files. Changed-file Ruff and
diff checks pass.

The mandatory exact A560 canary completed in 15.27 seconds without a process
segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784888923_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-scoped-normalization-authority.txt`. The semantic oracle
remains red with one residual `while ( 1 )`.

A560 now reaches C3 for the selected vertical fragment. The DB records the
260-operation frontend-normalization transaction as committed, with all 639
prepublication and 1180 postpublication outcomes passing, and event 156 records
`canonical_semantic_plan_ready` through the scoped token. No canonical
transaction is staged, so C4 is not reached.

The first failed C4 obligation is
`SemanticFragmentBackendRejected: root inventory maps two plan blocks to one
physical version`. The final rebinding sequence includes the route source at
`blk4@0x40A5F0` and a separate exact identity at `0x40A5F6` that also resolves
to `blk4@0x40A5F0`; the current exception does not persist the two colliding
plan block ids or their complete portable identities. The next vertical slice
must first make that collision self-contained in the diagnostic DB, then prove
whether the two plan identities are legitimate roles on one logical published
version or an incorrect composition split. It must not silently deduplicate by
serial, weaken unique ownership, or broaden beyond this fragment.

**2026-07-24T10:38:56Z**

The root-inventory collision is now self-contained in the diagnostic DB without
changing its fail-closed behavior. `SemanticFragmentBackendRejected` may carry
a typed reason, native anchor, and portable payload. The root-inventory alias
rejection records both plan block ids, both complete stable identities, the
plan and atomic-group lineage, and one physical `blkN@EA` label. The canonical
exception boundary preserves that structure while still re-raising the same
exception; unstructured exceptions retain the existing generic diagnostic.

The two full affected pinned Docker runtime files are 144/144 green, and
changed-file Ruff and diff checks pass. The mandatory A560 canary completed in
15.46 seconds without a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784889382_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-root-inventory-collision-diag.txt`. The semantic oracle
remains red with one residual `while ( 1 )`, and the highest contiguous canary
level remains C3.

The DB proves the C4 failure is a composition-time owner alias. Projected
boundary block
`native[0x40A5F0-0x40A5F1,0x40A5F6-0x40A5F7,0x40A5F8-0x40A5F9,0x40A5FE-0x40A5FF;exact=0x40A5F0,0x40A5F6,0x40A5F8,0x40A5FE]`
and narrower current-graph block
`native[0x40A5F0-0x40A5F1,0x40A5F6-0x40A5F7;exact=0x40A5F6]`
both rebind uniquely to `blk4@0x40A5F0`. The next slice must canonicalize
these roles through the one proven current owner during plan composition, then
let fragment validation expose whether that shared block is also prohibited
dispatcher residue. The backend must continue rejecting arbitrary duplicate
physical bindings.

**2026-07-24T10:43:15Z**

The projected-boundary current-owner slice is verified and ready for its own
commit. During canonical composition, a projected PREOPT boundary now seeds a
current role only when its portable identity wholly contains exactly one
current block identity. Later predecessor or prohibited-dispatcher references
to that current block reuse the projected boundary id. Zero current owners
remain unresolved for the normal binding gate; multiple owners and two
projected boundaries sharing one current owner reject explicitly. The live
backend's arbitrary duplicate-physical-binding rejection remains unchanged.

The canonical transform, lowering, and plan suites are 48/48 green, and
changed-file Ruff and diff checks pass. The mandatory A560 canary completed in
14.64 seconds without a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784889758_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-projected-boundary-owner.txt`. The semantic oracle remains
red with one residual `while ( 1 )`, and the highest contiguous level remains
C3 because no canonical transaction is staged.

The proven `blk4@0x40A5F0` alias is gone. The first C4 obligation advances to
root-inventory block
`native[0x40A560-0x40A561,0xF1C00018-0xF1C00019;exact=0xF1C00018]`,
which does not rebind uniquely. Identity event 160 classifies it as ambiguous:
its range combines native `0x40A560` with fictitious PREOPT EA `0xF1C00018`,
and no current serial is selected. The next slice must trace that projected
boundary back to its normalization-plan owner and replace fictitious live
coordinates with the owner's portable native identity before composition. It
must not teach stable identity binding to accept fictitious EAs or select an
ambiguous candidate.

**2026-07-24T11:03:32Z**

The live/native EA provenance slice is verified and ready for its own commit.
`InsnSnapshot` and `BlockSnapshot` now retain the native origins returned by
the live adapter without replacing their callback-local live coordinates.
Stable block identity and `MbaBlockIdentityIndex.from_mba()` consume those
native origins, so Hex-Rays fictitious EAs cannot silently become portable
native identity. Receipt-published imported origins remain authoritative for
imported blocks.

The focused portable suite is 96/96 green. The pinned Docker adapter suite is
83/83 green across block identity, live-MBA indexing, the Hex-Rays translator,
and manager-owned frontend normalization. The mandatory exact A560 canary
completed in 12.45 seconds without a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784890738_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-native-ea-origin.txt`. The semantic oracle remains red with
one residual `while ( 1 )`, and the highest contiguous level remains C3
because no canonical transaction is staged.

The DB proves the intended ownership boundary advanced without losing the
committed PREOPT transaction. The prior mixed identity ending in fictitious
`0xF1C00018` is gone; `mba_t::map_fict_ea` resolves that live instruction to
native `0x40A5D0`. The first C4 obligation is now the genuinely native
root-inventory identity
`native[0x40A560-0x40A561,0x40A5D0-0x40A5D1;exact=0x40A5D0]`,
which still does not rebind uniquely. The next slice must make that ambiguity's
native owner set self-contained in the diagnostic DB, then repair ownership
provenance or plan composition from that evidence. It must not reintroduce
fictitious identity, select a candidate by block order, or weaken unique
rebinding.

**2026-07-24T11:08:40Z**

The identity-candidate observability slice is verified and ready for its own
commit. Every identity rebind decision now carries the deterministic set of
current `BoundBlock` candidates considered at the decisive exact, containment,
or maximum-overlap tier. The manager persists each candidate's anchored block
label, provenance, and complete portable stable identity in
`identity_decisions.candidates_json`; it never emits a bare snapshot-local
serial.

The focused local identity suite is 40/40 green, and the pinned Docker identity
plus manager runtime suite is 37/37 green. The mandatory exact A560 canary
completed in 11.59 seconds without a process segfault or INTERR. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784891162_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-identity-candidates.txt`. The PREOPT publication remains a
committed 260/260-operation transaction, the semantic oracle remains red with
one residual `while ( 1 )`, and the highest contiguous level remains C3.

Identity event 160 makes the first C4 failure self-contained. The requested
composite identity
`native[0x40A560-0x40A561,0x40A5D0-0x40A5D1;exact=0x40A5D0]`
has no single containing owner. Its equally scored overlap owners split between
the repeated entry-coordinate blocks such as `blk0@0x40A560` and the imported
native block `blk6@0x40A5CA`, whose identity contains `0x40A5D0`. The next
vertical slice must trace why root-inventory composition unions those two
owners into one required identity and preserve their lineage as separate
logical roles. It must not select one physical candidate, relax uniqueness, or
collapse the identity back to one EA.

**2026-07-24T11:29:28Z**

The canonical current-identity and dispatcher-SCC witness slice is verified and
ready for its own commit. Candidate composition now requires an explicit
current `serial -> StableBlockIdentity` authority exported by the live identity
index. Route sources, projected boundaries, predecessors, and prohibited
dispatcher roles consume that authority instead of re-deriving identity from
physical block starts. Equivalent prohibited roles in one unchanged dispatcher
SCC use one uniquely owned portable witness; if the SCC has no unique identity,
composition keeps every role so the backend still fails closed.

The focused canonical transform, lowering, and plan suite is 51/51 green both
locally and in the pinned Docker runtime. Changed-file Ruff and diff checks
pass. The first mandatory A560 canary after current-identity authority used DB
`.tmp/logs/d810_logs/000000000040a560_1784892046_11.diag.sqlite3`; event 160
then bound the `0x40A5D0` role to `blk6@0x40A5CA`, and the first failure moved
to synthetic dispatcher entry identity shared by 26 `blkN@0x40A560` blocks.

The final SCC-witness canary used DB
`.tmp/logs/d810_logs/000000000040a560_1784892735_11.diag.sqlite3` and pytest log
`.tmp/rhad-a560-v31-dispatcher-scc-witness-final.txt`. It completed in 13.03 seconds
without a process segfault. Event 164 records a 264-operation canonical plan;
all seven required current roles rebind uniquely, including
`blk4@0x40A5F0`, `blk6@0x40A5CA`, `blk35@0x40AE2E`, and
`blk41@0x40B334`. The gateway then aborts before fragment staging completes, so
the highest contiguous canary level remains C3.

The initiating staging failure is
`SemanticFragmentBackendRejected: fragment plan requires an imported
native-body materializer`. Rollback subsequently leaves
`blk66@0xF1C00880` with a block-type/successor-count mismatch. The matching IDA
SDK 9.3 verifier identifies `INTERR 50856` as “wrong size of a block successor
set”; it is a rollback-time IR invariant failure, not an OS segfault and not
the initiating staging error. The DB currently combines the secondary INTERR
and rollback failure in the aborted receipt while omitting the initiating
stage error from `fragment_staged` detail. The next slice must persist stage,
rollback, and verifier causes separately before wiring the materializer port,
then retry the same fragment. It must not treat rollback verification as the
primary semantic failure or claim C4.
