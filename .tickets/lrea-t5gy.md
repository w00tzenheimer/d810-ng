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

**2026-07-24T11:49:37Z**

Commit `0b2be5244` completes the fragment-failure observability slice. An
aborted fragment receipt now preserves an ordered, typed failure chain across
the gateway, manager observation bridge, SQLite transaction timeline, and
diagnostic renderer. `safe_verify` attaches the captured numeric INTERR and
verification context to the propagated exception. The publication orchestrator
records the initiating transaction phase separately from rollback and verifier
failures; it does not infer the primary cause from the final wrapper message.
The shared failure value type lives in its own mutation-domain module, so no
gateway/publication import cycle or compatibility re-export exists.

The focused local semantic-fragment and diagnostic suite is 137/137 green. The
same 137 tests pass in the pinned
`d810-idapro-9.3-test-runtime:py313-v1` Docker image; artifact:
`.tmp/fragment-failure-diagnostics-runtime.txt`. Ast-grep, all 14
worktree-local import contracts, changed-line Ruff, diff checks, commit hooks,
and `graphify update .` pass. A wider local probe found 13 pre-existing fake-MBA
failures whose test doubles lack the now-required `map_fict_ea` identity port;
production compatibility was not added to conceal those fixture deficiencies.

The mandatory exact A560 diagnostic canary completed in 11.94 seconds without
an OS segfault. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784893734_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-fragment-failure-chain.txt`. The semantic oracle remains
red with one residual `while ( 1 )`, so this is not A560 acceptance.

The highest contiguous canary level remains C3. The DB records the committed
frontend-normalization transaction, then the canonical 264-operation plan.
The canonical transaction timeline identifies the first C4 obligation as:

`stage_failure / stage / SemanticFragmentBackendRejected: fragment plan
requires an imported native-body materializer`.

It separately records `verifier_failure` with `INTERR 50856` and context
`staged semantic fragment rollback sweep`, followed by
`rollback_failure: staged semantic fragment discard cannot remove entry or
stop blocks`. The matching IDA SDK 9.3 `verify.cpp` meaning remains “wrong size
of a block successor set.” These are secondary recovery defects, not the
initiating semantic failure. The next vertical slice must inject the existing
manager/lifecycle-owned imported native-body materializer into canonical
publication without constructing an adapter locally, adding a fallback, or
publishing the broad 91-route transaction. It must rerun this exact canary and
reach C4 before any broader publication.

**2026-07-24T12:10:00Z**

Commits `39d5510f2` and `fc9789efc` complete the manager-owned native-body
materializer injection slice as two logical checkpoints. The lifecycle
coordinator owns construction for the active function and current MBA;
`FlowMaturityContext` retains a factory rather than a live SWIG wrapper so a
refreshed callback resolves against its current `mba_t`. PREOPT normalization
and canonical lowering now receive that capability explicitly. The frontend
adapter's duplicate `PreoptUnionSemanticNativeBodyMaterializer` constructor is
deleted, and neither consumer has a fallback or compatibility path.

Focused verification is 183/183 lifecycle, hook, and canonical tests plus
138/138 semantic-fragment and diagnostic tests locally. The pinned
`d810-idapro-9.3-test-runtime:py313-v1` Docker gate is 238/238; artifact:
`.tmp/canonical-materializer-injection-runtime.txt`. Ast-grep, all 14
worktree-local import contracts, changed-file Ruff, diff checks, commit hooks,
and `graphify update .` pass.

The mandatory exact A560 diagnostic canary completed without a process
segfault. The wrapper completed in 18.33 seconds and pytest in 16.02 seconds.
Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784894802_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-lifecycle-materializer.txt`. The semantic oracle remains
red with one residual `while ( 1 )`, so this is not A560 acceptance.

The highest contiguous canary level remains C3. The committed PREOPT
normalization transaction still applies all 260 operations, passes 639
prepublication and 1180 postpublication outcomes, publishes its root, and
commits its receipt. The canonical 264-item transaction now receives the
injected materializer, applies one item, and exposes the next first C4
obligation:

`stage_failure / stage / SemanticFragmentBackendRejected: PREOPT native body
requires the hxe_preoptimized destination MBA`.

The canonical publication runs at `MMAT_GLBOPT1`; the injected capability is
therefore present but its destination-maturity contract is wrong for this
consumer. The same aborted transaction separately records rollback-time
`INTERR 50856` in `staged semantic fragment rollback sweep`, followed by
`rollback_failure: staged semantic fragment discard cannot remove entry or
stop blocks`. Matching IDA SDK 9.3 `verify.cpp` defines 50856 as a block
successor-count/type mismatch. Those recovery defects remain secondary to the
stage rejection.

Continue the v3.1 vertical loop by deciding from the plan and receipt-backed
identity whether canonical lowering should reuse the native bodies already
published by PREOPT or needs a distinct current-maturity detached
materializer. Do not weaken the PREOPT-only invariant, clone through a
compatibility path, broaden publication, or treat the secondary rollback
failure as the initiating obligation.

**2026-07-24T12:24:03Z**

Commit `da823b267` completes the canonical published-import boundary slice.
Canonical component traversal now stops at a uniquely current native identity
that covers an imported successor and projects the complete current identity
as a `REUSE_PUBLISHED` boundary. Multiple covering current owners reject with
typed reason
`published_imported_boundary_current_owner_ambiguous`; the planner never
selects by serial order or treats an ambiguous binding as missing.

The focused portable canonical suite is 26/26 green. The nearby local
canonical and semantic-fragment runtime suites are 144/144 green, and the
pinned Docker transform, lowering, unflatten, and backend gate is 170/170;
artifact: `.tmp/canonical-current-boundary-runtime.txt`. Changed-file Ruff,
diff checks, ast-grep, all 14 worktree-local import contracts, commit hooks,
and `graphify update .` pass. The local and Docker SWIG deprecation warnings
are unchanged baseline noise.

The mandatory exact A560 diagnostic canary completed in 19.79 seconds without
a process segfault. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784895731_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-current-boundary.txt`. The semantic oracle remains red
with one residual `while ( 1 )`, so this is not A560 acceptance.

The DB proves the intended ownership move. The canonical plan shrank from 102
blocks, 94 operations, and a 94-block native body to 38 blocks, 24 operations,
and a 23-block native body. Fourteen uniquely surviving current identities are
now explicit published boundaries, including the normalized successor at
native `0x40A613`. The 23 remaining imported blocks are the actually missing
closed component rooted at native `0x40BECC`; no already-rebound suffix is
scheduled for rematerialization.

The highest contiguous canary level remains C3. The first C4 obligation is
unchanged and now narrowly scoped:

`stage_failure / stage / SemanticFragmentBackendRejected: PREOPT native body
requires the hxe_preoptimized destination MBA`.

Rollback still separately records `INTERR 50856` in
`staged semantic fragment rollback sweep`, followed by the failed entry/stop
discard. SDK 9.3 `verify.cpp` defines 50856 as a block
successor-count/type mismatch; it remains secondary. The next vertical slice
must give the 23-block missing component one explicit GLBOPT1-safe realization
contract or move its canonical publication to a maturity with matching
analyzed authority. It must not relax the PREOPT materializer invariant,
rematerialize the 71 blocks already cut away, or add a dual-authority fallback.

**2026-07-24T12:45:09Z**

Commit `02b727dce` completes the call-free CALLS native-body realization
slice. Canonical publication now receives a distinct
`CallsCallFreeSemanticNativeBodyMaterializer` when the destination is exactly
`MMAT_CALLS`. It reuses the existing detached-source capture, topology,
stack, and preparation preflights, rejects `m_call`, `m_icall`, and `m_ret`
anywhere in captured or prepared instruction trees, and populates only
unpublished blocks through the mutation gateway. PREOPT continues to use the
existing PREOPT-only materializer; unsupported maturities reject instead of
falling back.

The first implementation hypothesis incorrectly targeted GLBOPT1. The
uncommitted diagnostic canary at
`.tmp/logs/d810_logs/000000000040a560_1784896632_11.diag.sqlite3` disproved
that hypothesis: `fact_consumers` records that canonical route composition is
admitted at `MMAT_CALLS`, while later GLBOPT1 observes
`canonical_composition_requires_calls`. The policy was corrected before the
code commit rather than preserving a compatibility path.

Targeted TDD is 7/7 green, the broader local canonical, backend, import, and
manager suite is 280/280 green, and the pinned
`d810-idapro-9.3-test-runtime:py313-v1` Docker runtime gate is 177/177 green;
artifact: `.tmp/calls-call-free-native-body-runtime.txt`. Changed-file Ruff,
diff checks, ast-grep, all 14 worktree-local import contracts, commit hooks,
and `graphify update .` pass.

The mandatory corrected A560 canary completed in 20.37 seconds, with pytest
finishing in 17.65 seconds and the worker returning normally. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784896861_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-calls-call-free.txt`. The semantic oracle remains red with
one residual `while ( 1 )`, so this is not A560 acceptance.

The native-body materializer now succeeds. Canonical transaction
`ff9972bac8264b5c8d37c3c014528793` plans 73 operations and applies 70 before
the next prepublication rejection. The highest contiguous canary level
remains C3. The first failed C4 obligation is:

`stage_failure / stage / SemanticFragmentBackendRejected: fragment plan must
own exactly one projected function entry`.

The failed transaction then records two secondary rollback defects. SDK 9.3
`verify.cpp` defines `INTERR 50856` as a block successor-count/type mismatch.
SDK 9.3 `hexrays.hpp` defines `INTERR 52719` at
`mba_t::get_mblock(uint n)` as `n < qty`, so it is an out-of-range,
snapshot-local block lookup. These are decoded SDK assertions, not an OS
segfault, and neither supersedes the initiating projected-entry ownership
obligation.

There is also a diagnostic maturity-label discrepancy to resolve without
guessing: `fact_consumers` and materializer admission prove the canonical
consumer executes at CALLS, while the lifecycle plan and receipt rows label
the transaction `MMAT_GLBOPT1`. Treat the live evidence as contradictory
until callback/context timing is traced.

Continue the v3.1 vertical loop by identifying why the 23-block projected
component does not own exactly one function-entry projection, reproducing that
shape in a focused portable/backend test, and fixing ownership without
weakening validation or broadening to the 91-route publication. Preserve
fragment atomicity. Make rollback safe as a separately proven consequence if
the projection failure exercises it, but keep projected-entry ownership as
the primary C4 obligation.

**2026-07-24T12:55:07Z**

Commit `497fca4ce` completes the positional function-entry projection slice.
The live A560 shape has an empty one-way positional entry at
`blk0@0x40A560` whose sole successor is the identity-bearing semantic entry at
`blk1@0x40A560`. Canonical plans begin at that semantic entry, so the old
projection incorrectly required a plan block itself to occupy serial zero.

The backend now projects the positional entry through its existing published
logical proxy and version when no planned binding owns that physical block.
It does not invent a portable native plan identity or choose an entry by
address overlap. The projected entry remains a real, identity-index-owned
published boundary, and normal graph closure, identity ownership, root
reachability, original supersession, dispatcher exclusion, and topology
validation remain mandatory.

The focused red test reproduced the two-layer entry shape and failed with
`fragment plan must own exactly one projected function entry` before the
backend change. It is now green. The full semantic-fragment backend file is
82/82 green. The nearby backend, validation, publication-gateway, canonical,
manager, and detached-import suite is 343/343 green locally and 343/343 green
in pinned `d810-idapro-9.3-test-runtime:py313-v1` Docker; artifact:
`.tmp/positional-entry-projection-runtime.txt`. Changed-file Ruff, diff
checks, ast-grep, all 14 worktree-local import contracts, commit hooks, and
`graphify update .` pass.

The mandatory A560 canary completed with pytest in 17.57 seconds. The worker
returned normally and there was no OS segfault. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784897596_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-positional-entry.txt`. The semantic oracle remains red
with one residual `while ( 1 )`, so this is not A560 acceptance.

The intended boundary advanced: canonical fragment staging now completes and
prepublication validation runs. Transaction
`3ffc663054f04866aae2ae933067de46` plans 73 mutation items, applies the 70
prepublication items, stages the fragment, and records 198 prepublication
outcomes: 195 pass and three fail. The three root-publication items remain
unapplied. The highest contiguous canary level remains C3 because C4 requires
prepublication validation to pass.

The first failed C4 obligation is:

`fallthrough_topology /
native[0x40A607-0x40A615;exact=0x40A613]: two-way physical fallthrough is
missing, nonadjacent, or misordered`.

The same projection also reports reachable prohibited dispatcher residue at
`native[0x40A5F0-0x40A5F1,0x40A5F6-0x40A5F7,0x40A5F8-0x40A5F9,0x40A5FE-0x40A5FF;exact=0x40A5F0,0x40A5F6,0x40A5F8,0x40A5FE]`
and an identity/authority mismatch for that same dispatcher block. These may
share one ownership cause, but the DB does not yet prove that, so retain their
separate failed obligations.

Rollback again fails verification with SDK 9.3 `INTERR 50856`, the
block-type/tail versus successor-count invariant, in
`staged semantic fragment rollback sweep`. No `INTERR 52719` is present in
this canary. The rollback defect is secondary to the prepublication topology
failure and remains decoded from the matching SDK assertion.

Continue the v3.1 vertical loop from the `0x40A613` fallthrough obligation.
Reconstruct the projected physical neighbors, semantic successor order, and
binding states from the plan and DB, then write a focused red test for the
generic shape. Do not reorder or suppress validation, drop the dispatcher
failures, or broaden publication before this selected fragment reaches C4.

**2026-07-24T13:03:03Z**

Commit `46dee7e12` completes the serial-free opaque-fallthrough witness slice.
The preceding DB showed that published conditional `blk8@0x40A607`, anchored
by exact instruction `0x40A613`, had live successors `blk9@0x40A560` and
`blk14@0x40A560`; `blk9@0x40A560` was the actual adjacent first successor.
Validation failed only because the intentionally opaque neighbor was absent
from the serial-free projected block set.

`ProjectedFragmentBlock` now requires an
`adjacent_fallthrough_target_id`. The live backend derives that identifier
from `nextb` and maps it to either a projected block id or an EA-anchored
opaque endpoint. Validation requires the witness to equal the first semantic
successor and additionally requires either the corresponding projected block
at the next physical position or a published-boundary opaque endpoint. This
does not exempt published conditionals, parse serials in portable code, or
recursively import the remaining opaque corridor.

The focused test was red before the model change because no serial-free
adjacency witness existed. Positive portable and live-backend tests now prove
the opaque case, and a negative portable test proves that a reachable
published conditional without the witness still fails
`FALLTHROUGH_TOPOLOGY`.

The nearby backend, validation, publication-gateway, canonical, manager, and
detached-import suite is 346/346 green locally and 346/346 green in pinned
`d810-idapro-9.3-test-runtime:py313-v1` Docker; artifact:
`.tmp/opaque-fallthrough-witness-runtime.txt`. Changed-file Ruff, diff checks,
ast-grep, all 14 worktree-local import contracts, commit hooks, and
`graphify update .` pass.

The mandatory A560 canary completed with pytest in 17.37 seconds. The worker
returned normally and there was no OS segfault. Primary DB:
`.tmp/logs/d810_logs/000000000040a560_1784898095_11.diag.sqlite3`; pytest log:
`.tmp/rhad-a560-v31-opaque-fallthrough.txt`. The semantic oracle remains red
with one residual `while ( 1 )`, so this is not A560 acceptance.

The selected obligation advanced exactly as intended:
`FALLTHROUGH_TOPOLOGY` at `0x40A613` now passes. Canonical transaction
`982730eb6ffc4391b032d8bdd96dc290` still plans 73 items, applies the 70
prepublication items, stages the fragment, and runs 198 prepublication
outcomes; the pass count rises from 195 to 196 and the failure count falls
from three to two. The highest contiguous canary level remains C3 because
prepublication validation still aborts before C4.

The first remaining C4 obligation is:

`dispatcher_absence /
native[0x40A5F0-0x40A5F1,0x40A5F6-0x40A5F7,0x40A5F8-0x40A5F9,0x40A5FE-0x40A5FF;exact=0x40A5F0,0x40A5F6,0x40A5F8,0x40A5FE]:
reachable route enters a prohibited dispatcher router`.

The only sibling failure is `IDENTITY_OWNERSHIP` for that same block:
`projected identity or authority state differs from the plan`. This
co-location is evidence for one ownership-alias cause, but it is not yet
proof. Reconstruct the plan block, live binding, predecessor route, and stable
identity before choosing a fix.

Rollback still fails verification with SDK 9.3 `INTERR 50856`, the
block-type/tail versus successor-count invariant, in
`staged semantic fragment rollback sweep`. No `INTERR 52719` is present.
Continue from the `0x40A5F0` dispatcher-absence obligation, preserve the
identity mismatch as evidence, and do not suppress the prohibited-dispatcher
check or relabel the block merely to pass validation.

**2026-07-24T13:56:42Z**

Commits `401f8c69d` and `26523b70f` complete the next evidence-authority and
canonical-composition slices. Entry-consumer routes now live in
`ResolverPortableEvidence`, are merged through session-owned lifecycle
authority, and are projected without reading preparation-owned state. The
canonical planner groups a direct state assignment with its exact downstream
carried state choice, replaces the imported raw dispatcher operation inside
the detached plan, and carries predicate plus carrier use-def obligations in
the same atomic fragment. Portable and live-split identities match only when
they have the same native key, the same exact anchor, and nested native
ranges; overlap-only and anchor-only matches still reject.

The first mandatory canary after `401f8c69d` completed without a process
segfault. Primary DB:
`.tmp/rhad-a560-semantic-consumer-identity/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pytest log: `.tmp/rhad-a560-v31-semantic-consumer-identity.txt`. Event 6 proves
that `entry_consumer_routes` reached lifecycle authority. Canonical
composition then declined at exact anchor `0x40A5AB` with typed reason
`semantic_corridor_owner_count_mismatch`: the portable corridor owned a full
native interval while the current MBA exposed the exact split identity
`blk2@0x40A5AB`. The DB, not the text log, recorded that first incomplete
obligation in `fact_consumers`.

Commit `26523b70f` added the strict range-refinement relation and reran the
canary. Primary DB:
`.tmp/rhad-a560-corridor-refinement/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pytest log: `.tmp/rhad-a560-v31-corridor-refinement.txt`. The selected
fragment now reaches C3. Transaction
`fb25dde2de5546258def04f8f3033463` records a complete canonical plan
containing `state-choice@0x40BECC`. SQLite JSON-tree inspection proves
`native-indirect-transfer@0x40BEE5` is absent from live plan operations and
survives only in the preceding normalization receipt's historical
`remaining_obligation_ids`.

C4 is not reached. The first stage obligation is
`SemanticFragmentBackendRejected: CALLS native body must be call/return-free`
for the imported block anchored at `0x40B9A6`, whose captured instruction at
native `0x40BA56` has opcode 56. The transaction applies one operation before
this rejection, then its cleanup raises `INTERR 50856` and rollback fails to
discard entry/stop blocks. SDK 9.3 `verify.cpp` defines 50856 exactly as
`nsucc() != ns`, the wrong successor-set cardinality for the block type and
tail. No `INTERR 52719` and no OS segfault occur in this canary.

The highest current A560 level is therefore C3, not C4 or C6. Continue the
v3.1 vertical loop from the call-bearing native-body boundary and the
restart-safe staging defect it exposes. Determine whether the call block must
remain an owned published boundary or be preserved earlier by faithful
frontend normalization; do not weaken CALLS call/return ownership. Before any
new realization attempt, make transaction-wide preflight reject the fragment
before the first live mutation so an expected materializer abstention cannot
enter the failed rollback path. Do not broaden to 91 routes.

Focused verification for `26523b70f` is 328/328 local tests and 46/46 pinned
Docker tests at `.tmp/semantic-consumer-refinement-runtime.txt`. Changed-file
Ruff, diff checks, ast-grep, all 14 worktree-local import contracts, commit
hooks, and `graphify update .` pass. The semantic oracle remains red with one
residual `while ( 1 )`; this is a diagnostic canary, not A560 acceptance.

**2026-07-24T14:06:13Z**

Commit `2b619c18c` makes native-body admissibility a transaction-wide
preparation phase. Every materializer must now implement the explicit
two-phase contract: prepare a complete body from the immutable `FragmentPlan`
without changing the destination MBA, then stage only that exact preparation.
The gateway prepares all native bodies before it clones a replacement, changes
outline ranges, creates a logical version, or allocates a standalone block.
The old one-step materializer interface was deleted rather than retained as a
compatibility path.

The focused runtime test was red against the old ordering because the gateway
cloned the root replacement before invoking the rejecting materializer. It now
proves that a preparation rejection leaves `mba.qty`, outline ranges, identity
generation, staging state, and materializer stage-call count unchanged. The
complete local backend/importer suite is 250/250 green, and the pinned Docker
gate is also 250/250 green at
`.tmp/native-body-prepare-before-stage-runtime.txt`. Changed-file Ruff, diff
checks, ast-grep, all 14 worktree-local import contracts, commit hooks, and
`graphify update .` pass.

The mandatory A560 canary completed without a process segfault. Primary DB:
`.tmp/rhad-a560-native-body-preflight/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pytest log: `.tmp/rhad-a560-v31-native-body-preflight.txt`. Highest level
remains C3. The same first C4 obligation is preserved exactly:
`CALLS native body must be call/return-free` for the imported block anchored at
`0x40B9A6`, with forbidden opcode 56 at native `0x40BA56`.

The failure is now restart-safe. Transaction
`65e731204c06479aa63e763ee27fd584` records 123 planned operations, zero applied
operations, `fragment_staged=0`, no root-publication attempt, successful
rollback, and an aborted receipt containing only the initiating typed reason.
There is no verifier-failure event, no `INTERR 50856`, and no `INTERR 52719`.
Continue from ownership of the call-bearing `0x40B9A6` component: prove whether
it has a uniquely surviving published CALLS boundary or must be kept reachable
by faithful frontend normalization. Do not import calls through the call-free
materializer and do not broaden the selected fragment.

**2026-07-24T14:54:37Z**

Commit `3974e22be` completes the restart-safe analyzed-CALLS-companion slice.
The canonical CALLS materializer now rejects a call-bearing native body before
staging unless every raw PREOPT-union call EA has exactly one matching analyzed
CALLS owner. Missing authority queues only portable native ranges on the
session attachment, requests the existing controller-owned generated restart,
and records both the request and manager-preflight outcome in the diagnostic
database. Manager preflight generates each requested range at `MMAT_CALLS`,
matches it against the pristine PREOPT-union call inventory, caches the exact
analyzed owner, and acknowledges the range only after successful capture. The
old call-free materializer name was deleted rather than retained as an alias.

The first requested component `[0x40B9A6,0x40BB75)` now captures four analyzed
call owners at `0x40BA56`, `0x40BA72`, `0x40BA8C`, and `0x40BB35`. Import
preserves each complete analyzed owner, including `m_mov(m_call(...))` result
definitions, rebases its callinfo stack window, removes subsumed PREOPT
`m_push`/outgoing-stack setup, and clears `MBL_PUSH` only when setup was
removed. Preparation remains transaction-wide: neither a missing companion nor
a capture mismatch changes the destination MBA before the gateway receipt.

The focused suite is 443/443 green locally and 443/443 green in pinned
`d810-idapro-9.3-test-runtime:py313-v1` Docker; artifact:
`.tmp/calls-companion-runtime.txt`. Changed-file Ruff, diff checks, ast-grep,
all 14 worktree-local import contracts, the portable-core shape gate, commit
hooks, and `graphify update .` pass.

The mandatory A560 canary returned normally in 19.95 seconds with no OS
segfault, verifier event, or numeric `INTERR`. Primary DB:
`.tmp/rhad-a560-calls-companion/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pytest log: `.tmp/rhad-a560-v31-calls-companion.txt`. The semantic oracle
remains red and renders an eight-line stub with one `while ( 1 )`, so this is
not A560 acceptance.

The highest contiguous canary level remains C3. Transaction
`7d8bc544dc934027853b39ae1b5226aa` plans 123 operations, applies zero, stages
no fragment, attempts no root publication, and rolls back successfully after
requesting two portable companion ranges. Manager preflight then captures
`[0x40B9A6,0x40BB75)` but abstains for `[0x40C26D,0x40C2FB)` with
`call_ea_set_mismatch`; the pristine union owns calls `0x40C2A9` and
`0x40C2BE`. The follow-up transaction
`34f869bc75454aa681be73a76982411e` again applies zero operations and aborts
cleanly because the one controlled redo for evidence generation 1 has already
been consumed.

Continue the v3.1 vertical loop from that exact mismatch. The next diagnostic
slice must put the mismatching EA and both PREOPT/CALLS call inventories into
the manager-preflight DB event, because event 177 currently records only the
PREOPT inventory and generic reason. Then determine whether the isolated CALLS
range loses one real call or invents a resolver tail call, and correct range
construction or component ownership without weakening exact call parity,
granting another redo in the same evidence generation, or broadening the
91-route publication.

**2026-07-24T15:14:08Z**

Commit `453eb8910` made the preceding CALLS mismatch first-class diagnostic
evidence. The canary DB at
`.tmp/rhad-a560-companion-mismatch-diag/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`
records pristine PREOPT calls `0x40C2A9` and `0x40C2BE`, isolated CALLS calls
`0x40C2A9`, `0x40C2BE`, and `0x40C2F9`, and exact
`mismatch_ea=0x40C2F9`. Native decoding proves `0x40C2F9` is the component's
terminal `jmp eax`, not a native call, so exact call parity remained the
authority and no compatibility exception was added.

Commit `c1479d0ae` completes the resolver-tail analysis-boundary slice. The
portable native CFG now shortens isolated CALLS generation only when the
unique component-ending block has exclusively resolver-proven indirect edges
from one terminal instruction EA. The original native component remains the
PREOPT call-inventory boundary. CALLS generation and replacement capture use
the shortened range, and the diagnostic event records both boundaries.

The focused runtime suite is 450/450 green locally and 450/450 green in pinned
`d810-idapro-9.3-test-runtime:py313-v1` Docker. The Docker artifact produced by
the v3.1-required root invocation with
`-w lifecycle-resolver-evidence-authority` is
`.tmp/calls-companion-tail-trim-runtime-root.txt`. Changed-file Ruff, diff
checks, ast-grep, all 14 worktree-local import contracts, commit hooks, and
`graphify update .` pass.

The mandatory A560 diagnostic canary also used the root checkout plus
`-w lifecycle-resolver-evidence-authority` and returned normally in 17.48
seconds with no OS segfault, verifier event, or numeric `INTERR`. Primary DB:
`.tmp/rhad-a560-calls-tail-transfer-root/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pytest log: `.tmp/rhad-a560-v31-calls-tail-transfer-root.txt`. The semantic
oracle remains red with an eight-line stub and one `while ( 1 )`, so this is
not A560 acceptance.

The DB proves both requested companions now capture with exact parity. Event
176 preserves PREOPT range `[0x40B9A6,0x40BB75)` while generating CALLS over
`[0x40B9A6,0x40BB73)`, with matching calls `0x40BA56`, `0x40BA72`,
`0x40BA8C`, and `0x40BB35`. Event 177 preserves PREOPT range
`[0x40C26D,0x40C2FB)` while generating CALLS over
`[0x40C26D,0x40C2F9)`, with matching calls `0x40C2A9` and `0x40C2BE`.

The highest contiguous canary level remains C3. The follow-up canonical
transaction plans 123 operations but applies zero, stages no fragment,
attempts no root publication, and rolls back successfully. The first failed C4
obligation is now exact:
`CALLS companion stack window cannot be rebound; call=0x40C2A9 top=12 span=24`.

Continue the v3.1 vertical loop at that stable native call EA. Determine why
the captured CALLS callinfo's destination stack window cannot be represented
in the live MMAT_GLBOPT1 MBA, and make the diagnostic DB record the source
window, destination frame coordinates, and failed invariant before changing
the rebinding rule. Do not clamp offsets, discard arguments, bypass exact call
ownership, grant another redo, or broaden to the 91-route publication.

**2026-07-24T15:21:05Z**

Commit `9c840c360` completes the required stack-window observability slice.
Insufficient destination capacity and malformed source windows now raise typed
backend rejections with the native call EA, source call window, destination
frame coordinates, argument count, failed invariant, and required growth. The
existing canonical-pipeline fact-consumer path persists that payload; no
mutation-layer diagnostic import or compatibility event was added.

The focused local and pinned-Docker runtime suites are both 232/232 green;
Docker artifact: `.tmp/calls-stack-window-diagnostic-runtime.txt`.
Changed-file Ruff, diff checks, ast-grep, all 14 worktree-local import
contracts, commit hooks, and `graphify update .` pass.

The mandatory A560 canary returned normally in 16.76 seconds with no OS
segfault, verifier event, or numeric `INTERR`. Primary DB:
`.tmp/rhad-a560-calls-stack-window-diag/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pytest log: `.tmp/rhad-a560-v31-calls-stack-window-diag.txt`. The semantic
oracle remains red with one `while ( 1 )`, so this is not A560 acceptance.

The highest contiguous canary level remains C3. Canonical transaction
`c672f20a70f04273af6808da3b7c5a21` still plans 123 operations, applies zero,
stages no fragment, attempts no root publication, and rolls back successfully.
The first failed C4 obligation is now queryable as fact
`canonical_pipeline:0x40C2A9`, with reason
`calls_companion_destination_stack_window_insufficient`.

The exact DB payload proves six analyzed arguments and source call window
`[call_spd=16, stkargs_top=40)`, span 24. The destination MBA has
`tmpstk_size=12`, `stkoff_ida2vd(0)=12`, `frsize=1164`, `frregs=4`,
`stacksize=1180`, `minstkref=212`, and `fullsize=1440`; the failed invariant is
`destination_stack_zero_vd >= source_stack_span`, with required growth 12.

The next vertical step must determine whether the native function's actual
outgoing-call stack depth already proves a larger temporary-stack requirement
that Hex-Rays omitted because the detached path was unreachable. If so, the
solution must update the destination stack coordinate system atomically before
any body preparation and rebase every affected live/imported stack identity.
If not, preserve the rejection and revisit the publication boundary. Do not
emit negative decompiler stack coordinates merely because `verify.cpp` lacks a
direct `call_spd` inequality.

**2026-07-24T15:32:18Z**

Commit `063066cee` completes the native-frame stack-point slice. The
`hxe_stkpnts` provider now derives canonical stack depth from the authoritative
IDA `func_t` while the new MBA's frame fields are still zero. It does not add a
fallback or mutate live MBA frame coordinates after construction.

The focused local and pinned-Docker runtime suites are both 451/451 green.
Docker artifact:
`.tmp/calls-stack-native-frame-runtime-root.txt`. Changed-file Ruff, diff
checks, ast-grep, all 14 worktree-local import contracts, commit hooks, and
`graphify update .` pass.

The mandatory cache-disabled A560 canary returned normally in 17.86 seconds
and remains semantically red with one `while ( 1 )`. Pytest log:
`.tmp/rhad-a560-v31-native-frame.txt`; primary DB:
`.tmp/rhad-a560-native-frame/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-native-frame/test_real_loader_matches_reach0/sub_40A560.c`.

The DB proves the intended fact moved forward. Stack-point projection events 8
and 179 each apply all 28 resolver-owned call points at MMAT_ZERO with zero
abstentions and canonical SPD `-1168`. Native call `0x40C2A9` receives
`-1192`; the deepest native call `0x40B49E` receives `-1216`. The prior
`calls_companion_destination_stack_window_insufficient` rejection is absent.

The highest contiguous canary level remains C3 because the gateway does not
finish staging or pre-publication validation. After the controlled redo, the
canonical transaction plans 123 operations and applies 49 before the
state-choice operation anchored at native `0x40BECC` rejects predicate
realization. Plan item 49 is the fallthrough helper for the atomic conditional;
items 50 and 51 are its taken and fallthrough arms. The rejection reports
source `blk87@0x40A560` projected from native `0x40BECC`, expected predicate
EA `0xF1C00B1C`, and observed tail `0xF1C00B3C`.

Rollback then fails with `INTERR 52719`. The bundled SDK defines that number at
`.ida-sdk/src/include/hexrays.hpp` as the `mba_t::get_mblock(n)` assertion
`n < qty`, so the rollback path dereferenced a stale or out-of-range
maturity-local block index. This was visible in the diagnostic DB even though
the worker returned normally and the textual pytest failure showed only the
semantic oracle.

Continue the v3.1 vertical loop from the first C4 obligation: prove why the
portable predicate for native `0x40BECC` no longer matches the staged source
tail before its atomic two-arm realization. Preserve the native anchor in all
diagnostics and tests. Separately, enforce restart-safe failure semantics so a
failed staged operation cannot roll back through stale serials or continue on
an MBA whose restoration was not proved. Do not broaden the 123-operation
fragment, weaken predicate validation, or treat partial operation count as C4.

**2026-07-24T16:01:00Z — SDK assertion correction**

The preceding rollback summary compressed two distinct failures. Diagnostic
transaction `abb2bd5bcb724549a73bdbb005d2a304` first records a
`stage_failure` for the predicate mismatch at native `0x40BECC`. Its first
cleanup failure is then `INTERR 50856` during the
`staged semantic fragment rollback sweep`. The bundled SDK defines 50856 at
`.ida-sdk/src/verifier/verify.cpp:1155` as a block whose successor-set size
does not match its block type. Only after that malformed staged CFG reaches
cleanup does rollback encounter `INTERR 52719`; the SDK defines 52719 at
`.ida-sdk/src/include/hexrays.hpp:5570` as `mba_t::get_mblock(n)` asserting
`n < qty`, which is a stale or out-of-range maturity-local serial.

The first rollback-correctness obligation is therefore the malformed
successor cardinality, not the later stale lookup. The implementation must
either leave each partially staged block locally verifier-valid before an
operation can reject, or discard it through stable logical handles without
running a verifier over a half-realized conditional. It must not catch or
ignore either numeric error, scan for a replacement serial, or report a bare
block number without its native EA anchor.

**2026-07-24T16:14:26Z**

Commits `711f963c6`, `a9df2a272`, and `72f45e46c` complete the portable
storage-predicate slice. Canonical composition retains the stack identity,
predicate kind, width, constant, and proof-owned cut; detached preparation
materializes the predicate before staging; and transaction-local
operation-to-live-EA binding disambiguates a preserved consumer and synthesized
branch that intentionally share native EA `0x40BECC`. The focused pure,
backend, and detached-import suites used for those commits are green.

The first follow-up canary moved past predicate realization and exposed an
unidentified call-fallthrough shape at `blk81@0x40A560`. Commit `ac4163758`
makes that failure DB-first: every rejection now carries the portable
operation, stable native identity, live block with EA anchor, block type,
successors, tail opcode/destination, and owned-call details. Commit
`88fa93632` then fixes the generic representation mismatch: at MMAT_CALLS an
analyzed call may be the exactly-one nested `m_call` owned by a block-closing
`m_mov`, so call-fallthrough realization no longer requires the top-level
instruction itself to be `m_call` or `m_icall`. All 14 semantic-edge gateway
runtime tests pass, including top-level call, analyzed nested call, and
pre-helper rejection cases. Commit hooks preserve ast-grep, import-cycle,
all 14 import-linter contracts, and the portable shape gate.

The mandatory cache-disabled A560 canary at committed HEAD `88fa93632` returns
normally in 26.57 seconds and remains semantically red with one
`while ( 1 )`. Pytest log:
`.tmp/rhad-a560-v31-analyzed-call-owner.txt`; primary DB:
`.tmp/rhad-a560-analyzed-call-owner/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-analyzed-call-owner/test_real_loader_matches_reach0/sub_40A560.c`.

Diagnostic transaction `5b75485409f74c1085cc944bf013da3b` plans 123
operations, records 120 applied mutation operations, and completes detached
fragment staging. Root publication is not attempted. The highest contiguous
canary level remains C3 because C4 requires pre-publication validation to pass.
The first failed C4 obligation is outcome 107:
`dispatcher_absence` for
`native[0x40A5F0-0x40A5F1,0x40A5F6-0x40A5F7,0x40A5F8-0x40A5F9,0x40A5FE-0x40A5FF;exact=0x40A5F0,0x40A5F6,0x40A5F8,0x40A5FE]`,
because a reachable planned route still enters that prohibited dispatcher
router. Later failures are predicate and carrier use-def integrity at native
consumer `0x40BECC`, followed by identity ownership for the same prohibited
dispatcher identity.

Rollback then fails with `INTERR 50856`, the SDK-defined wrong-successor-
cardinality assertion in `.ida-sdk/src/verifier/verify.cpp:1155`. This canary
does not record a subsequent `52719`; that stale-block assertion remains a
known earlier double-cleanup symptom, not the first current failure.

Continue the v3.1 vertical loop from outcome 107. Determine which staged edge
keeps the prohibited dispatcher identity reachable and whether the plan omitted
its supersession or the projected reachability validator is observing a
staged-but-unpublished boundary. Do not weaken dispatcher absence, ignore the
later use-def failures, broaden the fragment, or claim C4 from completed staging
alone. In parallel with the semantic correction, rollback must restore
successor cardinality before verification or force a fresh-MBA restart; the
current MBA is not safe to reuse after restoration cannot be proved.

**2026-07-24T16:42:09Z**

Commit `68a455818` made the residual dispatcher route queryable and commit
`dd3a2eb27` then closed that specific composition gap without broadening the
selected publication. The diagnostic witness from
`.tmp/rhad-a560-dispatcher-witness/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`
proved that the route entering prohibited dispatcher identity `0x40A5F0` was
downstream of omitted, same-generation state-assignment routes inside the
selected imported component. Canonical composition now replaces those raw
dispatcher operations with their proof-owned direct semantic routes before
reprojecting the component.

The mandatory cache-disabled A560 canary at committed HEAD `dd3a2eb27`
returned normally in 32.34 seconds and remains semantically red with a
143-byte pseudocode body and one `while ( 1 )`. Pytest log:
`.tmp/rhad-a560-v31-nested-routes.txt`; primary DB:
`.tmp/rhad-a560-nested-routes/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-nested-routes/test_real_loader_matches_reach0/sub_40A560.c`.

The DB records two committed 260-operation frontend-normalization
transactions. The first canonical attempt requests ten proof-owned CALLS
companions and rolls back successfully with zero applied operations. The
follow-up canonical transaction `57acb31119504025a8fb9457124562db` plans 171
operations, applies zero, attempts no root publication, and rolls back
successfully. No segfault or INTERR occurs.

The highest contiguous canary level remains C3 because canonical planning
exists but C4 pre-publication validation does not start. The first failed C4
obligation is the imported native identity anchored at `0x40BB51`, whose
captured template has a conditional tail at native `0x40BB63`. Canonical
operation `route:state_assignment@0x40BB63:0xE9795EF` intentionally replaces
that dispatcher tail with one direct semantic edge to `0x40ACF3`, but the
portable operation does not yet carry the exact delivery instruction that must
be rewritten. Backend preflight therefore rejects the one-edge operation
against the two-successor captured template before staging.

Continue the v3.1 vertical loop by adding a typed, proof-owned direct-transfer
rewrite anchor to the portable operation and using it in both exact preflight
and live realization. Accept a conditional-template-to-direct-route collapse
only when that anchor equals the captured conditional tail and belongs to the
operation's native proof corridor. Do not merely relax successor-count
validation, infer the tail from block order, special-case A560 EAs, or broaden
the 171-operation fragment.

**2026-07-24T17:40:00Z**

Execution now follows
`/Users/mahmoud/src/idapro/d810/_gitless/RHAD_DEOBFU_STRAT_v3.3.md`. Commits
`1a766ae57`, `f1c4c2d44`, and `25e5595ed` establish the required two-lane
differential oracle before detached lowering: portable serial-free route
shapes and schema-v7 DB authority; canonical SDK microcode opcode capture;
and an isolated capture/compare tool that never starts D810. The reference
lane uses unchanged reference commit
`21b0d4783703bc4fb6910cfae51d92cd683d2c65`, patched disposable binary
SHA-256 `6358957fe74360725b125bdc41b16df9952d95b338792fd3521249e5030ddd8c`,
and the candidate lane uses fixture SHA-256
`2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`.
Both run under pinned image
`sha256:360f91d9d4ace70d89e03893f1d895d94383fa0fe426ddba9d3898a7922b650a`
with D810 disabled and `DECOMP_NO_CACHE`.

Independent DBs
`.tmp/rhad-oracle-v33.mcFPat/a560-c.diag.sqlite3` and
`.tmp/rhad-oracle-v33.mcFPat/a560-d.diag.sqlite3` produce identical stable
comparison rows, SHA-256
`3a00dcfd979044405b57c3c260db0d83e74a58b798a03f83c7aeb5e7eb4fc562`.
The first divergence is GENERATED at owner `0x40BB51` and rewrite anchor
`0x40BB63`: the reachable reference route is `m_goto -> 0x40ACF3`, while the
unpatched candidate is an unreachable `m_jcnd` with taken target `0x40C6F7`
and physical fallthrough `0x40BB69`; the candidate owner disappears by CALLS.
The normalizer accepts same-EA setup instructions only when the final
instruction owns the rewrite anchor and remains the unique terminator.

Verification is 129/129 local diagnostic/tool/serializer tests, 4/4 pinned
live-SDK serializer tests, clean Ruff and diff checks, ast-grep, all 14
worktree-local import contracts, commit hooks, and `graphify update .`.

The mandatory cache-disabled A560 canary at committed HEAD `25e5595ed`
returned normally in 18.46 seconds with no segfault or INTERR. Log:
`.tmp/rhad-a560-v33-oracle-canary.txt`; primary DB:
`.tmp/rhad-a560-v33-oracle-canary/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-oracle-canary/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`.

The highest contiguous main-A560 level remains C3. Canonical plan transaction
`ad4ee92c7235418bbc56dca5967a8812` plans 171 operations, applies zero, starts
no prepublication validation, and aborts cleanly without an SDK assertion.
The first C4 obligation is unchanged but now has differential proof:
`native[0x40BB51-0x40BB69;exact=0x40BB51]:imported` has a conditional tail at
`0x40BB63`, while proof-owned operation
`route:state_assignment@0x40BB63:0xE9795EF` requires one direct edge to
`0x40ACF3`. Continue v3.3 by carrying the exact direct-transfer rewrite anchor
in a portable detached rewrite plan, lowering and validating one closed C5
fragment off to the side, then publishing it once. Do not add a live-backend
exception or broaden to the 91-route publication.

**2026-07-24T21:43:58Z**

Commit `deddb3700` completes the portable direct-transfer rewrite contract
without changing the live Hex-Rays mutation backend. A canonical direct
operation now carries its semantic proof id, exact rewrite anchor, ordered
proof corridor, and an explicit ordered subset of instructions that the
rewrite supersedes. Imported rewrites require canonical native-body proof
ownership, and competing operations may not supersede the same native EA.
Frontend-normalization plans cannot carry this canonical rewrite intent.

The first draft incorrectly treated every proof-corridor instruction as
exclusive rewrite ownership. The first diagnostic canary exposed that error:
route `0x40BB63` has proof corridor `0x40BB44 -> 0x40BB4B -> 0x40BB63`, but
the reference ledger's only planned replacement is `0x40BB63`; the native
conditional at `0x40BB4B` is preserved. The final contract therefore records
the full proof corridor separately from the superseded set. Unit coverage
proves that preserved-corridor overlap is accepted while superseded-transfer
overlap is rejected.

Verification is 247/247 focused portable-plan, canonical-pass, validation,
pipeline, and gateway tests; changed-file Ruff and diff checks; ast-grep; all
14 worktree-local import contracts; commit hooks; and `graphify update .`.
Docker Desktop was found stopped between canaries, restarted, and verified
with matching client/server 29.6.2 before the authoritative rerun.

The mandatory cache-disabled A560 canary at commit `deddb3700` returned
normally in 25.23 seconds with no segfault or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-direct-contract-canary-v2.txt`; primary DB:
`.tmp/rhad-a560-v33-direct-contract-canary-v2/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-direct-contract-canary-v2/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`; this is not A560
acceptance.

The DB records two committed 260-operation frontend-normalization
transactions. The first canonical attempt requests the ten known CALLS
companions and aborts cleanly. Follow-up canonical transaction
`f535b3c9eacd4f3db34a4c34ea7c9cca` plans 171 operations, applies zero,
stages no fragment, attempts no root publication, and rolls back cleanly. Its
serialized plan proves operation
`route:state_assignment@0x40BB63:0xE9795EF` is owned by imported native
identity `0x40BB51`, carries rewrite anchor `0x40BB63`, proof corridor
`0x40BB44 -> 0x40BB4B -> 0x40BB63`, supersedes only `0x40BB63`, and targets
`0x40ACF3`.

The highest contiguous main-A560 level remains C3. The first failed C4
obligation is still detached PREOPT preflight for imported owner `0x40BB51`:
the captured template ends in a conditional transfer at `0x40BB63`, while
the proof-owned canonical operation requires one direct edge. Continue v3.3
by making the detached rewriter consume this portable envelope for one closed
route, validating that unpublished fragment through C5, and only then
publishing one root. Do not add a live-backend exception or broaden to the
91-route transaction.

**2026-07-24T22:15:41Z**

Commit `9385ceef9` completes detached realization of the portable direct-route
envelope before publication. The native-body preflight proves exact proof,
corridor, superseded-instruction, source-owner, and tail-anchor ownership;
detached preparation replaces only the superseded delivery instruction with
an unbound `m_goto`; and unpublished staging binds the target and consumes the
operation before generic semantic realization. No compatibility default or
live-EA special case was added.

Focused verification is 171/171 detached-import runtime tests, 86/86 semantic
backend runtime tests, 360/360 combined portable/canonical/validation/backend
tests, and 269/269 surviving resolver/session runtime tests. Ruff, diff check,
ast-grep, all 14 worktree-local import contracts, commit hooks, and
`graphify update .` are green.

The mandatory cache-disabled A560 canary at committed HEAD `9385ceef9`
returned normally in 18.66 seconds with no process crash. Log:
`.tmp/rhad-a560-v33-detached-direct-canary.txt`; primary DB:
`.tmp/rhad-a560-v33-detached-direct-canary/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-detached-direct-canary/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`; this is not A560
acceptance.

Canonical transaction `14d1b41ce74e4608bd1300d3cdb89c02` records
`fragment_staged=1`, no root-publication attempt, and 168 applied operations
out of 171 planned. The earlier owner `0x40BB51` / rewrite anchor `0x40BB63`
is no longer the first failure. The highest contiguous main-A560 level remains
C3 because the first failed C4 obligation is prepublication outcome 145:
`dispatcher_absence` for
`native[0x40A5F0-0x40A5F1,0x40A5F6-0x40A5F7,0x40A5F8-0x40A5F9,0x40A5FE-0x40A5FF;exact=0x40A5F0,0x40A5F6,0x40A5F8,0x40A5FE]`.
Its witness enters that prohibited identity from the imported native route at
`0x40C4B2`. Later predicate/carrier use-def and identity-ownership failures
are not treated as the first obligation.

Rollback then fails with `INTERR 50856`, which the bundled SDK defines at
`.ida-sdk/src/verifier/verify.cpp:1155` as successor cardinality disagreeing
with block type. That cleanup defect is separate from the semantic closure
failure. Numeric `INTERR` triage must continue to resolve the SDK assertion
first; `52719`, if observed again, is the out-of-range `mba_t::get_mblock(n)`
assertion at `.ida-sdk/src/include/hexrays.hpp:5570`, not an opaque Hex-Rays
crash.

Continue the v3.3 vertical loop from the `0x40C4B2 -> 0x40A5F0` witness. The
persisted canonical plan still represents `native-indirect-transfer@0x40C4B2`
as a raw edge to a reused published dispatcher, with no detached semantic
rewrite envelope. Determine whether the smallest closed fragment must retain
that imported normalization and its dispatcher dependency rather than cutting
at the uniquely published owner. Do not weaken dispatcher absence, add another
live-backend exception, or claim C4 from completed staging.

**2026-07-24T22:52:53Z**

Commits `abc4de99c` and `e0ec596c2` implement and correct the next vertical
composition slice; mechanical Ruff formatting is isolated in `d93e74bbb`.
When a selected detached route reaches a prohibited frontend replacement, the
composer now imports that replacement's pristine native identity, converts its
live conditional-select envelope to a portable imported envelope, and carries
the replacement operation and source/select/join ranges in the same unpublished
native body. The current-owner match requires complete identity containment and
the live block's native start EA; it does not fall back to EA-only matching.

Focused verification is 319/319 portable-plan, canonical composition,
detached-import, and semantic-backend tests. Ruff, ast-grep, all 14
worktree-local import contracts, commit hooks, and `graphify update .` are
green. Docker client/server 29.6.2 is live. The first Docker probe preserved
only its log because pytest used container-local `/tmp`; the authoritative
rerun uses a worktree-mounted `--basetemp` and preserves all artifacts.

The mandatory cache-disabled A560 diagnostic canary at committed HEAD
`e0ec596c2` returned normally in 17.42 seconds with no process crash. Log:
`.tmp/rhad-a560-v33-prohibited-reimport-canary-v2.txt`; primary DB:
`.tmp/rhad-a560-v33-prohibited-reimport-canary-v2/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-prohibited-reimport-canary-v2/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`; this is not A560
acceptance.

Canonical transaction `15669f01c6e347c1bdba171e20521c3b` proves the intended
composition change activated. Its plan grows from 55 to 56 native-body blocks
and from 56 to 57 proof ids. It contains imported owner
`0x40A5F0`/source-select anchor `0x40A5FE`, operation
`native-indirect-transfer@0x40A605`, and both incoming operations at
`0x40C4B2` and `0x40C663` target that imported owner. The broad reused
dispatcher boundary from the prior checkpoint is gone.

The highest contiguous main-A560 level remains C3. The first failed C4
obligation is prepublication outcome 148, `dispatcher_absence`, for current
owner `blk4@0x40A5F0` with exact native anchor `0x40A5F6`. Its witness now
enters through external transfer owner
`native[0x40C4AE-0x40C4B4;exact=0x40C4B2]`, not through the imported broad
`0x40A5F0` replacement. Later predicate/carrier use-def failures remain
secondary. Rollback still fails with SDK `INTERR 50856`, the successor-count
versus block-type invariant at `.ida-sdk/src/verifier/verify.cpp:1155`.

Continue the v3.3 loop at transfer owner `0x40C4B2`. The next obligation is to
give its complete reference conditional transaction detached ownership--the
conditional arm to `0x40C4B4` and direct arm to imported `0x40A5F0`--rather
than leaving the physical transfer block as a live external boundary. Do not
claim C4, weaken dispatcher absence, or broaden to the 91-route publication.

**2026-07-24T23:12:07Z**

Commits `b2e55d581`, `c89f0a42b`, and `09b65e60b` finish the direct-transfer
ownership slice. Ruff reflow is isolated in the first commit. Direct patch
evidence now uses the actual indirect-transfer EA as its source anchor, so a
patch corridor split across native blocks binds the physical transfer owner.
Canonical composition retains a proof-owned imported transfer when its edge
enters a selected prohibited replacement instead of cutting that transfer at
its uniquely published current owner. The final commit updates one stale test
assertion to the diagnostic wording introduced by `28ec10126`.

The expanded portable/frontend/canonical/runtime suite is 409/409 green.
Ruff, ast-grep, all 14 worktree-local import contracts, the portable-core
shape ratchet, commit hooks, and `graphify update .` are green. Docker
client/server 29.6.2 is live.

The mandatory cache-disabled A560 diagnostic canary at committed HEAD
`09b65e60b` returned normally in 17.32 seconds with no process crash. Log:
`.tmp/rhad-a560-v33-direct-owner-canary.txt`; primary DB:
`.tmp/rhad-a560-v33-direct-owner-canary/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-direct-owner-canary/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`; this is not A560
acceptance.

The committed frontend transaction `2305c8caee704a42a6e04a9facc60a12`
proves the ownership correction activated. Operation
`native-indirect-transfer@0x40C4B2` is now sourced by imported identity
`native[0x40C4AE-0x40C4B4;exact=0x40C4AE,0x40C4B2]` and directly targets the
imported/replacement `0x40A5F0` identity. The preceding imported topology is
preserved as `0x40C49A -> {0x40C4A8,0x40C4AE}` and
`0x40C4A8 -> 0x40C4AE`; it is no longer misbound to the prefix block.

Canonical transaction `03fcbee432154b64b7f1a5b4611ea8ae` contains 46 blocks
and 34 operations. It stages the fragment, does not attempt root publication,
and aborts during prepublication validation. The highest contiguous A560
level remains C3. The first failed C4 obligation is outcome 161,
`use_def_integrity`, for predicate
`state-choice@0x40BECC:0xEC71CA67:0xA0716E5B`, between native definition owner
`native[0x40A5AB-0x40A5AC;exact=0x40A5AB]` and imported consumer
`native[0x40BECC-0x40BEE7;exact=0x40BECC,0x40BED0,0x40BED6]`. Outcome 162 is
the paired def-use failure; outcomes 163-164 are the corresponding carrier
use-def/def-use failures from replacement route `0x40A5C8` to the same
consumer. The prior `0x40C4B2` dispatcher-absence failure is no longer the
first obligation.

Rollback then fails with SDK `INTERR 50856`; the defining assertion at
`.ida-sdk/src/verifier/verify.cpp:1155` is successor cardinality disagreeing
with block type. Continue the v3.3 vertical loop from the predicate/carrier
use-def break at imported consumer `0x40BECC`. Do not claim C4 or C5, weaken
the use-def gate, or broaden to the 91-route publication.

**2026-07-24T23:31:14Z**

Commits `4eebe4f6b` and `2541337a2` isolate Ruff formatting and make failed
data-flow validation rows persist missing site ids, observed definition/use
site ids, and relation counts. Commits `3281f9b57` and `363086f5c` similarly
isolate Ruff formatting and convert portable IDA stack offsets through
`mba.stkoff_ida2vd()` before live UD/DU queries. Focused verification is
52/52 validation/DB tests, 409/409 route tests, and 138/138 semantic-backend,
validation, and DB tests. Commit hooks and the architecture gates are green.

The mandatory cache-disabled A560 canary at `363086f5c` returned normally in
16.89 seconds with no process crash. Log:
`.tmp/rhad-a560-v33-stack-dataflow-canary.txt`; primary DB:
`.tmp/rhad-a560-v33-stack-dataflow-canary/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-stack-dataflow-canary/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`; this is not A560
acceptance.

The highest contiguous level remains C3. Canonical transaction
`6fe5fcabfbce497c8b40b40692cb7328` stages the fragment, does not attempt root
publication, and aborts at the same first C4 outcome 161. The enriched row
proves both planned native sites are present but the predicate use observes
zero reaching definitions. Stack-coordinate conversion is active: carrier
def-use outcome 164 now observes one actual use, but labels it
`unplanned-use:S64:...@0xF1C00CF4` because the staged imported instruction has
a transaction-local fictitious EA while the plan declares native consumer EA
`0x40BECC`. Predicate and carrier use-def queries still use native `0x40BECC`
against the staged instruction and therefore return no relation.

Rollback again fails with SDK `INTERR 50856`; the defining assertion at
`.ida-sdk/src/verifier/verify.cpp:1155` is successor cardinality disagreeing
with block type. Continue at the same C4 obligation by rebinding planned native
data-flow site EAs to transaction-local live EAs before querying, then map every
observed live EA back through instruction-origin authority before matching a
portable site. Do not accept raw fictitious EAs as portable evidence or weaken
the use-def gate.

**2026-07-24T23:37:25Z**

Commit `12ff2838f` maps planned native data-flow sites into staged instruction
origin authority before UD/DU queries and maps observed staged EAs back to
their native origins before portable-site matching. The focused
semantic-backend, validation, and diagnostic-DB suite is 139/139 green.

The mandatory cache-disabled A560 canary at `12ff2838f` returned normally in
18.66 seconds. Log:
`.tmp/rhad-a560-v33-instruction-origin-canary.txt`; primary DB:
`.tmp/rhad-a560-v33-instruction-origin-canary/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-instruction-origin-canary/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`; this is not A560
acceptance.

The highest contiguous canary level remains C3. Canonical transaction
`ec898969b7f448dab9db1dca2605f36c` now fails during staging, before C4
validation or root publication. Its first failed obligation is exact live-site
binding for imported native owner
`native[0x40BECC-0x40BEE7;exact=0x40BECC,0x40BED0,0x40BED6]`: several staged
microinstructions have native origin `0x40BECC`, so the generic origin lookup
rejects the ambiguous `imported@0x40BECC` instead of guessing. The next
vertical-loop slice must bind a data-flow site by portable storage identity,
width, and access role (definition or use), while preserving the generic
origin lookup's uniqueness requirement.

Stage cleanup first records SDK `INTERR 50856`, whose assertion at
`.ida-sdk/src/verifier/verify.cpp:1155` is successor cardinality disagreeing
with block type. Rollback then records SDK `INTERR 52719`; the defining
assertion at `.ida-sdk/src/include/hexrays.hpp:5570` is `n < qty` in
`mba_t::get_mblock(n)`, so rollback is attempting an out-of-range or stale
block index after the stage abort. Continue from the data-flow-specific live
site ambiguity; do not weaken origin authority, claim C4, or broaden to the
91-route publication.

**2026-07-24T23:48:14Z**

Commits `550c347e1` and `bbf164430` finish the one-to-many data-flow site
binding slice and isolate Ruff's whole-file reflow. When several staged
instructions share one native origin, the backend now selects by portable
storage identity, width, and access role (definition or use), and rejects zero
or multiple exact matches. Generic instruction-origin lookup remains strict.
The final exact-chain, semantic-backend, fragment-validation, and diagnostic
suite is 167/167 green; Ruff check/format, commit hooks, architecture gates,
and `graphify update .` are green. Docker client/server 29.6.2 is live.

The mandatory cache-disabled A560 diagnostic canary at committed HEAD
`bbf164430` returned normally in 18.69 seconds. Log:
`.tmp/rhad-a560-v33-dataflow-role-canary.txt`; primary DB:
`.tmp/rhad-a560-v33-dataflow-role-canary/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-dataflow-role-canary/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`; this is not A560
acceptance.

Canonical transaction `6600c389b01c433a8a3f6628ad6b7f82` now stages the
fragment and runs all 295 prepublication checks. It does not attempt root
publication. The prior carrier failures are repaired: outcomes 163-164 prove
both carrier use-def and def-use integrity. The only failures are outcomes 161
and 162 for predicate
`state-choice@0x40BECC:0xEC71CA67:0xA0716E5B`, between native definition owner
`native[0x40A5AB-0x40A5AC;exact=0x40A5AB]` and imported consumer owner
`native[0x40BECC-0x40BEE7;exact=0x40BECC,0x40BED0,0x40BED6]`. Both planned
sites exist, but the use observes no reaching definition and the definition
observes no declared use.

The highest contiguous level remains C3. The first C4 obligation is now the
predicate's live definition/use relation, not site identity. Rollback records
SDK `INTERR 50856`; `.ida-sdk/src/verifier/verify.cpp:1155` defines it as
successor cardinality disagreeing with block type after the validation abort.
Continue the v3.3 vertical loop by comparing the staged predicate producer and
consumer operands plus exact UD/DU chains. Do not weaken data-flow validation,
claim C4, or broaden to the 91-route publication.

**2026-07-25T00:04:39Z**

Commits `01531b5e7` and `d75385b06` finish the unpublished-root data-flow
projection slice and isolate Ruff's complete reflow as a separate style
commit. Exact register and stack queries now traverse the projected fragment
topology without physically exposing its root edge, while instruction and
storage matching still use live operands plus native instruction-origin
authority. The exact-chain, semantic-backend, fragment-validation, and
diagnostic-DB suite is 169/169 green; Ruff check/format, commit hooks,
architecture gates, and `graphify update .` are green.

The mandatory cache-disabled A560 diagnostic canary at committed HEAD
`d75385b06` failed in 36.29 seconds during the first decompile with
`INTERR 51974`; it did not segfault. Log:
`.tmp/rhad-a560-v33-projected-dataflow-canary.txt`; primary DB:
`.tmp/rhad-a560-v33-projected-dataflow-canary/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
No pseudocode artifact exists because Hex-Rays did not return a first cfunc.
This is not A560 acceptance.

The DB proves the selected narrow v3.3 fragment reached C5. Canonical
transaction `4919de50cdbd429e92e910c46c775c5f` contains 46 blocks, 34
operations, one native body, one owned original, one root, and two data-flow
obligations. It passes all 295 prepublication checks, publishes its root groups
and root exactly once, passes all 554 postpublication checks, and records a
committed semantic receipt. Predicate outcomes 161-162 and carrier outcomes
163-164 now pass across the unpublished root projection.

The highest contiguous canary level is therefore C5. The first failed
obligation is C6 semantic output: later Hex-Rays processing rejects the
postpublication MBA with `INTERR 51974`. Continue the v3.3 vertical loop by
identifying that verifier invariant and correlating it with an EA-anchored
published owner/target in the diagnostic DB. Do not broaden to the 91-route
publication or claim C6 until a fresh cache-disabled A560 cfunc satisfies the
established semantic oracle.

**2026-07-25T01:21:11Z**

Commit `60a57f4fa` corrects the false-closure condition behind the preceding
C5 receipt. A uniquely rebound published imported boundary may be reused only
when it is terminal in the selected normalization native body. If it still
owns a semantic operation, canonical composition now rejects the route with
the stable reason `published_imported_boundary_topology_unresolved` instead of
silently externalizing that operation and publishing an incomplete fragment.
The regression test was observed red before the guard and green afterward.

The focused portable/frontend/canonical/validation/runtime suite is 217/217
green. Changed-file Ruff check and format, ast-grep, all 14 worktree-local
import contracts, `graphify update .`, the portable-core shape ratchet, and
commit hooks are green. Docker client/server 29.6.2 is live. The pinned image
identity is
`sha256:360f91d9d4ace70d89e03893f1d895d94383fa0fe426ddba9d3898a7922b650a`;
the Rhad fixture SHA-256 is
`2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`.

The mandatory cache-disabled A560 diagnostic canary at committed HEAD
`60a57f4fa` returned normally in 20.06 seconds with no process crash, numeric
INTERR, canonical staging, root publication, or rollback. Log:
`.tmp/rhad-a560-v33-published-boundary-topology.txt`; primary DB:
`.tmp/rhad-a560-v33-published-boundary-topology/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-published-boundary-topology/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one `while ( 1 )`; this is not A560
acceptance.

The database records the first failure at snapshot 3 / MMAT_CALLS as fact
consumer `canonical_route:0x40B6C0`, declined for
`published_imported_boundary_topology_unresolved`. Its payload names imported
boundary `native[0x40B6C0-0x40B6CA;exact=0x40B6C0]`, live owner
`blk63@0x40A560`, and unresolved operation `native-body-edge@0x40B6C0`.
There are zero canonical semantic transactions; the only transaction is the
committed frontend-normalization publication. Thus the current highest
contiguous level is C2 and the first failed obligation is C3: construct a
complete detached semantic plan through the `0x40B6C0` frontier.

This deliberately withdraws the previous current-path C5 claim: the old
receipt proved operation execution and postpublication checks for a fragment
whose nonterminal published boundary had been incorrectly treated as closed.
Do not recover that C5 by recursively importing every nonterminal successor;
the exact probe of that coarse rule expanded to 133 imported blocks and
aborted on unrelated CALLS companion authority. Continue with the smallest
reference-equivalent conditional transaction at native `0x40B6C0`, whose
semantic arms are `0x40B6D6` and `0x40B790`, then re-run the v3.3 C0-C6 loop.

**2026-07-25T02:34:00Z**

Commits `b561f595e` and `3bf79ba7d` finish and separately format the
contextual-route generated-redo slice. The static resolver retains 117
contextual conditional plans without globalizing their targets. A typed C3
rejection at one stable native source promotes only its unique matching plan,
invalidates the generation-derived PREOPT source and preparation caches,
advances the evidence generation, and requests one provenance-bearing
controller restart. Repeated promotion of the same plan is idempotent and
does not discard the newly rebuilt caches. The focused resolver, lifecycle,
unflattener, and manager suite is 411/411 green; ast-grep is clean and all 14
worktree-local import contracts are kept. Ruff formatting is isolated in the
second commit.

The mandatory cache-disabled A560 canary at committed HEAD `3bf79ba7d`
returned normally in 31.11 seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-contextual-redo-v4.txt`; primary DB:
`.tmp/rhad-a560-v33-contextual-redo-v4/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-contextual-redo-v4/test_real_loader_matches_reach0/sub_40A560.c`.
The output remains semantically red as one `while ( 1 )`; this is not A560
acceptance.

The DB proves a generation-2 C5 publication. The original generation-1 C3
rejection promotes native source `0x40B6C0`, generation `1 -> 2`, and the
controller consumes that restart. Event 276 records a 316-item generation-2
plan. Items 117-119 are one fragment-atomic contextual conditional at native
`0x40B6C0`: helper plus taken target `0x40B6D6` plus fallthrough target
`0x40B790`; the old generic `0x40B6D4 -> 0x40B790` operation is absent. Batch
`09d127b199214db0817fdb1e549812a2` passes all 773 prepublication outcomes,
publishes its root once, passes all 1428 postpublication outcomes, and event
287 records a committed receipt. The partial work item selects 48 obligations
and leaves 180 explicit obligations, so this is not broad 91-route
publication.

Highest completed level is C5; C6 remains false-loop output. The next primary
visibility obligation is diagnostic: the generation-2 canonical rejection is
reported in memory but is not persisted because the latest-snapshot fact
consumer handler deduplicates the same consumer/fact tuple across the whole
function rather than within one snapshot. Event 406 therefore records only
the idempotent `contextual_patch_plan_promoted` decline, not the new rejection
payload. Fix snapshot-scoped fact-consumer deduplication, rerun the exact
canary, and continue from the first generation-2 native-EA-anchored rejection
stored in the DB. Do not infer it from the false-loop text, broaden the work
item, or claim C6.

**2026-07-25T02:40:23Z**

Commits `b40861d9f` and `149abd1f6` make late-bound fact-consumer deduplication
snapshot-scoped and isolate Ruff's reflow. Exact duplicate observations still
collapse within one snapshot, while the same fact tuple at a later maturity
snapshot retains its newer reason and payload. The focused diagnostic/runtime
suite is 106/106 green; pre-commit architecture and import gates pass.

The mandatory cache-disabled A560 canary returned normally in 31.39 seconds
with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-contextual-redo-v5.txt`; primary DB:
`.tmp/rhad-a560-v33-contextual-redo-v5/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-contextual-redo-v5/test_real_loader_matches_reach0/sub_40A560.c`.
It remains one false `while ( 1 )`; this is not A560 acceptance.

The highest completed level remains C5 through generation-2 receipt event
287. The first post-C5 obligation is now explicit at snapshot 11 /
`MMAT_CALLS`: `canonical_route:0x40B6C0` is declined for
`published_imported_boundary_topology_unresolved`. Its generation-2 payload
names imported boundary
`native[0x40B6C0-0x40B6CA;exact=0x40B6C0,0x40B6C2,0x40B6C8]`, unique live
owner `blk63@0x40A560`, and receipt-backed operation
`native-contextual-indirect-transfer@0x40B6C8:0x40B6D4`. This is distinct from
the generation-1 unresolved `native-body-edge@0x40B6C0` row at snapshot 3.

Continue with a narrow receipt-authority rule: a uniquely rebound published
boundary may close canonical target traversal only when its exact nonterminal
operation was selected by the current normalization work-item receipt and is
already a complete semantic direct or conditional rewrite. Keep rejecting an
unselected native-body edge, partial conditional, ambiguous owner, or stale
generation. Prove this red/green in the canonical transform before another
canary; do not reimport the whole successor closure or broaden toward 91
routes.

**2026-07-25T02:51:22Z**

Commit `fa0af30ab` implements the narrow receipt-authority rule. A published
nonterminal imported boundary closes canonical traversal only when the exact
operation belongs to both the current normalization work-item receipt and its
native-body proof set, and is either one semantic direct edge or a computed
two-arm conditional. The canonical transform suite is 28/28 green, including
a production-shaped receipted conditional and a negative unlowered native-body
conditional. Commit `0317cb93b` separately preserves the explicitly approved
repository-wide Ruff pass: 1,468 tracked Python files, with all 1,862 eligible
files now format-clean. The semantic commit's pre-commit architecture and all
14 import contracts passed before that style-only commit, and the style commit
passed them again.

The mandatory cache-disabled A560 diagnostic canary then returned normally in
38.10 seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-receipted-boundary-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-receipted-boundary-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-receipted-boundary-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The highest completed level remains C5 through generation-2 receipt event 287.
The receipt-backed contextual boundary at native source `0x40B6C0` now closes
successfully: there is no generation-2 rejection for that operation. The first
post-C5 obligation has advanced to snapshot 11 / `MMAT_CALLS` at native anchor
`0x40A607`. The DB records boundary
`native[0x40A607-0x40A615;exact=0x40A607]`, unique live owner
`blk8@0x40A560`, and unlowered operation `native-body-edge@0x40A607` under the
same bootstrap route proof `state_assignment@0x40A5C8:0xABB95547`. Event 406
declines contextual promotion because native source `0x40A607` has zero
contextual patch-plan candidates.

Continue the v3.3 vertical loop from `0x40A607`: determine why the bootstrap
fragment reaches this sibling boundary, establish its reference/native route
meaning at C1-C3, and either provide one complete semantic route proof or
correct an over-broad component traversal. Do not bless the raw native-body
edge, broaden publication, or reopen the now-proven `0x40B6C0` rule.

**2026-07-25T02:58:59Z**

Commit `4fcec4537` separates provisional component discovery from strict final
closure. The first pass may stop at one uniquely rebound published boundary
only long enough to discover nested state-route proof sources; after those
routes are projected, the second pass still rejects every unresolved raw
boundary. The upgraded nested-route regression reproduces a live imported
dispatcher boundary, while the existing strict rejection remains green. The
canonical transform suite is 28/28 green, Ruff has no delta, and pre-commit
architecture/import gates pass.

The mandatory cache-disabled A560 canary returned normally in 33.07 seconds
with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-projection-boundary-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-projection-boundary-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-projection-boundary-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains one false `while ( 1 )`; this is not A560 acceptance.

The production hypothesis is rejected: no available nested state-route proof
removed the edge to `0x40A607`, so strict post-projection validation records
the same snapshot 11 / `MMAT_CALLS` first obligation. Highest completed level
remains C5 at generation-2 receipt event 287; the failed boundary remains
`native[0x40A607-0x40A615;exact=0x40A607]`, uniquely rebound as
`blk8@0x40A560`, with `native-body-edge@0x40A607`. Event 406 still reports zero
contextual patch-plan candidates.

Continue at C1, not with another boundary exception. Identify the exact
reference routes for the semantic consumer's selected handler exits, compare
them with the available state-write inventory, and explain why the selected
component reaches the `0x40A607` dispatcher router after nested projection.
Add or repair one portable semantic proof only after that parity result is
explicit in the diagnostic DB.

**2026-07-25T03:04:21Z**

The v3.3 differential-oracle checkpoint was already present and has now been
audited rather than replayed. Commits `1a766ae57` and `25e5595ed` own the
portable comparison model, diagnostic tables, isolated capture adapter, and
tests. The reference ledger at `.tmp/rhad_reference_parity_ledger.json`
contains 756 committed transactions over the four protected Rhad functions
and is bound to fixture SHA-256
`2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`.
The unchanged reference repository is clean at
`21b0d4783703bc4fb6910cfae51d92cd683d2c65`, matching the manifest.

The reproducible isolated A560 artifact is
`.tmp/rhad-oracle-v33.mcFPat/a560-d.diag.sqlite3`, with manifest
`.tmp/rhad-oracle-v33.mcFPat/manifest-d.json`. It contains eight captures:
reference-patched and unpatched-baseline lanes at `MMAT_GENERATED`,
`MMAT_PREOPTIMIZED`, `MMAT_CALLS`, and `MMAT_GLBOPT1`, all cache-disabled and
with D810 disabled. Runs b, c, and d have identical serialized block dump
SHA-256 `bd8714769b9ac4e9d25c4eb264dc64d14b21ed9e26e29e328548392879027cf1`
and instruction dump SHA-256
`75ca09647cd4cf2aba15cee5b22530bddbed8a5dd4bc30f5832551a7e9838840`.

For the first selected route, the diagnostic DB now supplies the exact C1
parity result. Reference identity
`rhad:0x40A560:flow_route:0x40BB63` owns native `0x40BB51`, rewrites anchor
`0x40BB63`, and commits one direct target `0x40ACF3`. At
`MMAT_GENERATED`, the patched reference has a direct `m_goto` at `0x40BB63`
with sole successor `0x40ACF3`; the unpatched baseline still has `m_jcnd`
with taken successor `0x40C6F7` and physical fallthrough `0x40BB69`. The DB
marks this `transfer_kind` mismatch as the first divergence. Candidate owner
loss at `MMAT_CALLS` and `MMAT_GLBOPT1` is downstream and must not replace the
earlier generated-maturity obligation.

This recovered C1 oracle evidence does not reset or replay the completed
direct-route vertical. Commits `deddb3700` and `9385ceef9` already carry and
realize the complete `0x40BB51` / `0x40BB63` / `0x40ACF3` rewrite inside the
detached plan, and the current generation-2 path has a committed C5 receipt.
The first unmet obligation therefore remains post-C5 at native `0x40A607`:
explain which selected semantic exit still reaches that dispatcher router and
derive its exact reference-equivalent route proof. Use the audited oracle as
the C1 pattern for that exit; do not reimplement the direct rewrite, add a raw
boundary exception, or broaden publication.

**2026-07-25T03:28:50Z**

Commit `a4e2bd0c0` makes nested state-route projection decisions observable in
the canonical-composition fact-consumer payload. Every eligible proof now
records its native source anchor, projected or skipped disposition, reason,
source block identity, and corridor block identities when strict closure
later rejects the fragment. The canonical transform suite is 28/28 green,
Ruff is clean, and the pre-commit architecture/import gates pass.

The mandatory cache-disabled A560 diagnostic canary returned normally in
34.63 seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-nested-projection-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-nested-projection-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-nested-projection-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The highest completed level remains C5 through generation-2 receipt event
287. The first post-C5 obligation remains snapshot 11 / `MMAT_CALLS` at
`native[0x40A607-0x40A615;exact=0x40A607]`, uniquely rebound as
`blk8@0x40A560`, with unresolved `native-body-edge@0x40A607` under root proof
`state_assignment@0x40A5C8:0xABB95547`.

The new DB evidence corrects the preceding hypothesis. Of 89 eligible nested
state-route proofs, four were projected and 85 were outside this component.
The projected set is exactly native anchors `0x40BB63 -> 0x40ACF3`,
`0x40C2E9 -> 0x40C62F`, `0x40C6F1 -> 0x40AF00`, and
`0x40C7D1 -> 0x40B287`. Therefore the two reference-equivalent handler routes
were not missed; strict traversal reaches `0x40A607` through some other
selected incoming operation.

Continue the v3.3 loop by recording that incoming operation and native source
anchor on the unresolved-boundary rejection, then rerun the exact canary and
follow the resulting EA-keyed edge. Do not add another route proof, relax the
boundary, or broaden publication until that predecessor is identified in the
diagnostic DB.

**2026-07-25T03:33:45Z**

Commit `cbd209bc1` adds the unresolved boundary's incoming operation, source
block identity, native source anchor, and edge role to the same fact-consumer
payload. The canonical transform suite remains 28/28 green, Ruff is clean,
and the pre-commit architecture/import gates pass.

The mandatory cache-disabled A560 diagnostic canary returned normally in
33.20 seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-boundary-predecessor-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-boundary-predecessor-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-boundary-predecessor-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The highest completed level remains C5 through generation-2 receipt event
287. The snapshot 11 / `MMAT_CALLS` first post-C5 boundary is still
`0x40A607`, but its incoming edge is now exact:
`native-indirect-transfer@0x40C649` from imported source
`native[0x40C62F-0x40C64B;exact=0x40C62F,0x40C634,0x40C63A]`, with
`conditional_fallthrough` selecting `0x40A607`. Its sibling taken edge selects
the already-receipted `0x40B6C0` boundary.

The existing portable route `state_assignment@0x40C649:0xEC71CA67` was
skipped because `0x40C62F` becomes reachable only after projecting
`0x40C2E9 -> 0x40C62F`; this exposes a single-pass projection limitation.
However, a projection fixpoint alone would be semantically wrong. Reference
ledger transaction `rhad:0x40A560:flow_route:0x40C63A` owns state write
`0x40C62F`, flag writer `0x40C634`, and conditional branch `0x40C63A`, then
commits the direct target `0x40B9A6`. Our current proof instead anchors
`0x40C649` and records corridor `0x40C62F,0x40C634,0x40C649`, omitting the
decisive conditional.

Continue at C3 by correcting static state-route discovery to select the first
deterministic conditional after the proved state write as the delivery/rewrite
anchor and include it in the proof corridor. Prove the `0x40C62F` /
`0x40C634` / `0x40C63A` transaction in a narrow resolver test before adding
fixpoint projection. Do not rewrite `0x40C649`, add a boundary exception, or
iterate the current incorrect proof.

**2026-07-25T03:57:49Z**

The byte-level parity check corrected the prior capture-order hypothesis:
native `0x40C63A` is originally `mov eax, edx`, not a direct branch. The
reference indirect-jump phase first normalizes the `0x40C649` register jump
into a conditional rooted at `0x40C63A`; its later flow-route phase then
replaces that normalized root with the direct state target `0x40B9A6`.

Commit `12cfb2083` projects that already-proved intermediate normalization
shape without changing native bytes. It binds complete two-target patch plans
at their normalized predicate root and preserves the exact state corridor.
Commit `a3fb880f8` separately fixes the immediate native scanner so a
register-indirect jump with no `direct_target_ea` is a hard corridor boundary,
not a fabricated direct delivery that suppresses the plan-derived proof. The
focused resolver/canonical suite is 269/269 green; Ruff, ast-grep, graphify,
and all 14 import contracts pass.

The first mandatory canary after `12cfb2083` returned normally in 36.57
seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-normalized-state-root-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-normalized-state-root-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
It exposed the scanner shadowing bug: generation 1 still published
`0x40C62F -> 0x40C649 -> 0x40B9A6` as `direct_target`, and snapshot 11 still
failed at `0x40A607`.

The second mandatory canary after `a3fb880f8` returned normally in 33.77
seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-normalized-state-root-v2.txt`; primary DB:
`.tmp/rhad-a560-v33-normalized-state-root-v2/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-normalized-state-root-v2/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The C3 fact is now exact in the DB: `source_write=0x40C62F`,
`delivery=0x40C63A`, `target=0x40B9A6`, `delivery_kind=direct_target`, and
corridor `[0x40C62F,0x40C634,0x40C63A]`. The highest completed level remains
C5 through generation-2 receipt event 287. The first failed C6 obligation
remains snapshot 11 / `MMAT_CALLS` at `0x40A607`, but the per-proof payload
now makes the cause deterministic: projection entry 62 applies
`state_assignment@0x40C2E9:0x872BFF1` and makes `0x40C62F` reachable, while
entry 72 skips the corrected `state_assignment@0x40C63A:0xEC71CA67` as
`source_not_in_component` because projection runs only once over the original
component.

Continue with a bounded nested-route projection fixpoint. Recompute component
membership after each deterministic projection round, require monotonic
progress, reject conflicting or overlapping sibling proofs atomically, and
retain the existing strict final boundary validation. Prove the two-hop
`0x40C2E9 -> 0x40C62F -> 0x40C63A -> 0x40B9A6` vertical in the canonical
transform before another A560 diagnostic canary. Do not broaden to 91-route
publication, relax the `0x40A607` boundary, or add another semantic fact.

**2026-07-25T04:08:31Z**

Commit `5f5b34959` implements the requested monotonic nested-route projection
fixpoint and proves the two-hop canonical-transform case. The focused
resolver/canonical suite is 270/270 green; Ruff, ast-grep, graphify, and all 14
import contracts pass.

The mandatory cache-disabled A560 diagnostic canary returned normally in
17.58 seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-nested-fixpoint-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-nested-fixpoint-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The SQLite evidence proves the intended target chain: `0x40C2E9` projects in
round 1 and the corrected `0x40C63A -> 0x40B9A6` route projects in round 2.
It also rejects the current planner shape under v3.3. Starting from root proof
`state_assignment@0x40A5C8:0xABB95547`, the unrestricted connectivity
fixpoint projects 70 routes across 13 rounds before round 14 skips the 17
remaining proofs. The per-round projected counts are
`4,7,8,10,10,6,7,4,1,2,4,5,2`. This is effectively broad route expansion,
not the required smallest entry-connectable vertical fragment.

Strict C3 closure correctly declines the plan at native boundary `0x40AE3E`.
The exact incoming operation is
`route:state_assignment@0x40B52E:0x13B0D3B2`, sourced from
`native[0x40B51B-0x40B534;exact=0x40B51B]:imported`; the unresolved operation
is `native-body-edge@0x40AE3E`. No semantic fragment mutation was published.
The only committed receipt in this run is lifecycle event 28, the earlier
generation-1 frontend-normalization publication with 260/260 operations.

This corrects the prior C-level classification. That legacy frontend receipt
is not a v3.3 semantic C5 vertical. For the selected semantic route, C0-C2 are
complete and the first failed obligation is C3 closed-fragment planning at
`0x40AE3E`; C4 detached closure/oracle and C5 semantic publication remain
unreached. Do not add a route fact for `0x40AE3E`, relax strict closure, or
continue the global fixpoint. First redesign fragment selection so one
reference rewrite site and only its required dependencies form a bounded,
entry-connectable closed fragment, then drive that fragment through C3-C5.

**2026-07-25T04:20:22Z**

The bounded-fragment selection rule is now grounded in the reproducible
reference-patched CFG rather than inferred from the malformed candidate.
Capstone reachability over
`.tmp/rhad-oracle-v33.mcFPat/rhad_reference_patched.bin` (SHA-256
`6358957fe74360725b125bdc41b16df9952d95b338792fd3521249e5030ddd8c`),
using the manifest's exact `0x40A560-0x40C8A2` function range, shows that only
45 of the 93 committed reference flow-route transactions are reachable from
the function entry. The current canonical fixpoint projected 70 routes, so it
provably crossed into reference-unreachable topology; its expansion is not a
valid semantic closure.

The current `MMAT_CALLS` database also shows that only the bootstrap source
write at `0x40A5B2` is materialized as a route source. Therefore selecting a
different top-level live route cannot produce the required small vertical.
The correct seam is the first published boundary found by strict root
traversal. For `0x40AE3E`, the reference-patched suffix is entry-connectable,
reaches the real return at `0x40C89F`, and contains exactly three committed
flow-route rewrites:

- `0x40C341 -> 0x40AB31`;
- `0x40AB64 -> 0x40AA2C`;
- `0x40B52E -> 0x40AE3E`.

This makes `0x40AE3E` the first bounded v3.3 work item. Plan it as a published
root replacement with the call fallthrough and those three internal semantic
routes fragment-atomic, validate detached closure/oracle equivalence, and
publish one root transaction. Do not resume bootstrap-root composition until
that boundary has a semantic C5 receipt; the receipt can then close the
bootstrap fragment at the same stable native boundary.

**2026-07-25T04:33:11Z**

Commit `5b0e7754c` adds the first portable published-boundary planner without
wiring it into live publication. It resolves a uniquely EA-anchored imported
boundary, clones the current published owner as the replacement root, retains
the owned call fallthrough as the detached body entry, resolves nested semantic
routes under strict closure, and emits one canonical fragment plan. The pure
fixture proves one boundary-root replacement with one nested semantic route;
the focused canonical/resolver gate is 275/275 green. Ruff, ast-grep, all 14
import contracts, diff checks, and `graphify update .` pass. A requested full
`pyenv exec ruff format .` pass examined 1,862 files and changed none, so there
is no formatting-only diff or empty formatting commit.

The mandatory cache-disabled A560 diagnostic canary returned normally in
17.54 seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-boundary-planner-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-boundary-planner-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-boundary-planner-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The DB records only the legacy generation-1 frontend-normalization transaction:
260/260 operations committed at lifecycle event 28. It records no semantic
fragment transaction and no route-oracle comparison. The canonical fact
consumer again declines at snapshot 3 / `MMAT_CALLS`, native boundary
`0x40AE3E`, with incoming direct operation
`route:state_assignment@0x40B52E:0x13B0D3B2` from
`native[0x40B51B-0x40B534;exact=0x40B51B]:imported`. Therefore the selected
semantic vertical remains C2; its first failed obligation is C3 production
selection of the new bounded published-boundary plan. C4 detached oracle proof
and C5 semantic publication remain unreached. Continue by selecting this
portable boundary plan in the canonical pass and proving its exact three-route
reference equivalence before permitting live publication; do not resume the
70-route bootstrap expansion or treat the legacy receipt as semantic C5.

**2026-07-25T04:43:22Z**

Commit `d48b51b50` wires generic published-boundary selection into the
canonical pass but keeps it behind an explicit detached-oracle gate. A strict
root-composition rejection contributes its stable boundary anchor; when no
ordinary closed plan exists, the pass builds each unique boundary candidate,
selects deterministically, and rejects with the selected plan and route
inventory instead of returning it to the live publication backend. The
focused canonical/resolver gate is 276/276 green; Ruff, ast-grep, graphify,
and all 14 import contracts pass.

The mandatory cache-disabled A560 diagnostic canary returned normally in
17.92 seconds with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-boundary-selection-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-boundary-selection-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-boundary-selection-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The canary rejects before the new oracle gate. The canonical fact consumer at
snapshot 3 / `MMAT_CALLS` records
`published_boundary_predecessor_missing` for native boundary `0x40AE3E`.
The same SQLite snapshot binds
`native[0x40AE3E-0x40AE8B;exact=0x40AE3E]` to `blk48@0x40A560` and shows its
sole incoming block as `blk47@0x40A560`, whose tail is the synthetic
`m_jnz@0xF1C00480`; that predecessor is in the planner's prohibited dispatcher
set and is therefore excluded from boundary attachment. The owner itself
contains the imported call/state-write body and a synthetic
`m_goto@0x40A560`.

The highest completed semantic level remains C2. The first failed C3
obligation is no longer generic closure at `0x40AE3E`; it is proving a valid
entry attachment for that exact boundary without treating its prohibited
comparison predecessor as semantic authority. No semantic transaction,
route-oracle comparison, or semantic receipt exists. Before relaxing the
predecessor rule, make the rejection record the complete EA-anchored incoming
inventory and prove whether the bounded fragment can make the dispatcher
predecessor unreachable under detached root simulation. If it cannot, the
work item must include a proved semantic predecessor or move the publication
root; do not simply admit the dispatcher edge or claim C3.

**2026-07-25T04:50:38Z**

Commit `2dd6e5e39` makes the boundary-attachment failure self-contained in the
diagnostic DB without changing semantic acceptance. The rejection now records
the boundary block and identity, the current owner and identity, and every
incoming block as an EA-anchored label with portable stable identity and
prohibited classification. The focused canonical/resolver gate is 277/277
green; Ruff, ast-grep, graphify, and all 14 import contracts pass.

The mandatory cache-disabled A560 canary returned normally in 17.58 seconds
with no segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-boundary-predecessor-inventory-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-boundary-predecessor-inventory-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance. The highest completed semantic level remains C2, with no semantic
transaction, oracle comparison, or receipt.

The C3 rejection now proves the exact mismatch. Boundary
`native[0x40AE3E-0x40AE63;exact=0x40AE3E]` is bound to `blk48@0x40A560`, whose
sole incoming block is `blk47@0x40A560`, portable identity
`native[0x40AE26-0x40AE3E;exact=0x40AE2E]`, and is classified prohibited. The
isolated oracle DB `.tmp/rhad-oracle-v33.mcFPat/a560-d.diag.sqlite3` shows that
the reference-patched `MMAT_GENERATED` block starting at `0x40AE3E` instead
has one predecessor: the block starting at `0x40B51B`, whose terminator is the
reference direct rewrite `0x40B52E -> 0x40AE3E`. In the unpatched generated
lane, the native `0x40AE26-0x40AE3E` block ends in `m_ijmp` and `0x40AE3E` has
no predecessor.

Therefore admitting the current prohibited predecessor would preserve a
non-reference incoming edge and cannot satisfy C4 predecessor semantics. The
first C3 obligation is to select a reference-equivalent publication port:
either move the root upstream to a proved semantic predecessor or carry the
current incoming dispatcher edge as an explicit remaining work-item obligation
that cannot satisfy final C4/C5 acceptance. Do not remove the predecessor veto
without such authority, and do not classify `0x40AE3E` as an independently
publishable C5 root on the current evidence.

**2026-07-25T05:03:20Z**

Commit `befbe470f` tightens one-hop semantic-predecessor selection around an
exact state-write entry and its complete proof corridor. The focused
canonical/resolver gate is 278/278 green; Ruff, ast-grep, `graphify update .`,
and all 14 import contracts pass.

The mandatory cache-disabled A560 canary returned normally in 21.63 seconds
(19.62 seconds inside pytest) with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-state-write-reroot-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-state-write-reroot-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-state-write-reroot-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The highest completed semantic level remains C2. Snapshot 3 / `MMAT_CALLS`
still declines canonical composition with
`published_boundary_predecessor_missing` at native boundary `0x40AE3E`. The DB
contains no semantic-fragment transaction, validation outcome, route-oracle
comparison, or semantic receipt. Its only transaction is the legacy
generation-1 frontend-normalization publication, which committed 260/260
operations and is not semantic C5 evidence.

The failed re-root is now an exact C3 predicate mismatch, not missing native
evidence. The DB's state-write-route fact proves source write `0x40B51B`,
corridor `0x40B51B -> 0x40B526 -> 0x40B52E`, delivery `0x40B52E`, and target
`0x40AE3E`. Canonical projection deliberately gives the route its delivery
identity at `0x40B52E` and its state write a separate write identity at
`0x40B51B`; the current guard still nests the state-write-entry alternative
under a requirement that the delivery identity own `0x40B51B`. Continue by
proving the split-identity shape in the narrow test, then accept the source
block entry only through the exact write identity plus full corridor ending at
the exact delivery anchor. Do not broaden the delivery identity, admit the
dispatcher predecessor, or publish before C4.

**2026-07-25T05:07:46Z**

Commit `3c32206fe` corrects the split write/delivery identity predicate. A
semantic predecessor may now be the exact state-write block entry even when
the canonical route source identity begins at its later delivery instruction,
but only when the write identity owns the entry and the complete corridor ends
at an exact route delivery anchor. The focused canonical/resolver gate is
278/278 green; Ruff, ast-grep, `graphify update .`, and all 14 import contracts
pass.

The mandatory cache-disabled A560 canary returned normally in 22.23 seconds
(20.22 seconds inside pytest) with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-split-identity-reroot-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-split-identity-reroot-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-split-identity-reroot-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The split-identity proof advances the selected canonical route from native
boundary `0x40AE3E` to its reference-equivalent semantic predecessor
`0x40B51B`. Snapshot 3 / `MMAT_CALLS` now declines with
`published_boundary_current_owner_count_mismatch` at `0x40B51B`; its payload
reports zero current owners. This is a narrower C3 failure, but the highest
completed semantic level remains C2 because no bounded plan was produced. The
DB still contains no semantic-fragment transaction, validation outcome,
route-oracle comparison, or semantic receipt; only the legacy 260/260
frontend-normalization receipt exists.

Continue by making this zero-owner rejection self-contained: record the exact
normalization-plan boundary identity and every current EA-anchored identity
that overlaps or contains `0x40B51B`. Determine whether publication coalesced
the write and delivery into a larger live owner, omitted the write anchor from
current identity authority, or left the source block unpublished. Do not relax
identity containment, synthesize a live owner, or advance to C4 without that
evidence.

**2026-07-25T05:13:22Z**

Commit `df7e343ea` makes a published-boundary owner mismatch self-contained.
The rejection now records the normalization-plan block and stable identity plus
every EA-anchored current identity that contains the boundary anchor or
overlaps its native ranges. The focused canonical/resolver gate is 279/279
green; Ruff, ast-grep, `graphify update .`, and all 14 import contracts pass.

The mandatory cache-disabled A560 canary returned normally in 22.11 seconds
(20.22 seconds inside pytest) with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-boundary-owner-inventory-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-boundary-owner-inventory-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-boundary-owner-inventory-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The DB proves that normalization-plan block
`native[0x40B51B-0x40B534;exact=0x40B51B]:imported` has zero live owners and an
empty overlapping/current-anchor inventory at snapshot 3 / `MMAT_CALLS`.
Therefore the block is unpublished at this maturity; it is not hidden inside a
coalesced live identity and cannot itself serve as a replacement root. The
highest completed semantic level remains C2. No semantic transaction,
validation outcome, oracle comparison, or semantic receipt exists.

The portable state-route ledger contains no state assignment targeting
`0x40B51B`. The isolated reference oracle instead shows its unique predecessor
as the native conditional block starting at `0x40AB31`; its branch at
`0x40AB50` targets `0x40B51B` and its other arm remains the native
fallthrough. Continue by recording every normalization-plan operation entering
the unpublished boundary, including source block identity, source anchor,
operation id, edge role, and sibling arms. Then decide whether the bounded
publication root must move to the live `0x40AB31` owner. Do not treat
`0x40B51B` as a live root or fabricate a state-route predecessor.

**2026-07-25T05:17:16Z**

Commit `8e811e49c` adds complete normalization-plan incoming topology to an
unpublished-boundary rejection. Each entry records the operation id, portable
source block and identity, source anchor, incoming edge role, and every sibling
arm. The focused canonical/resolver gate is 279/279 green; Ruff, ast-grep,
`graphify update .`, and all 14 import contracts pass.

The mandatory cache-disabled A560 canary returned normally in 23.50 seconds
(21.37 seconds inside pytest) with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-boundary-incoming-topology-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-boundary-incoming-topology-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-boundary-incoming-topology-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The DB now proves one and only one normalization-plan operation enters the
unpublished `0x40B51B` block: `native-body-edge@0x40AB31`. Its portable source
is `native[0x40AB31-0x40AB56;exact=0x40AB31]:imported`; the complete native
conditional has taken target `0x40B51B` and fallthrough target `0x40AB56`.
This agrees with the isolated reference oracle and rejects the state-route
hypothesis. The highest completed semantic level remains C2 because no bounded
plan, C4 oracle, or semantic transaction exists.

Continue by adding the EA-anchored live-owner inventory for the incoming source
identity to the same DB payload. If `0x40AB31` has exactly one current owner,
move the bounded publication root there and retain the complete native
conditional plus the downstream `0x40B51B -> 0x40AE3E` semantic rewrite in one
detached fragment. If it has no owner, follow the unique incoming plan topology
again; do not guess or publish an unattached fragment.

**2026-07-25T05:21:11Z**

Commit `e208463b9` adds exact live-owner labels and overlap inventory for every
normalization-plan source entering an unpublished boundary. The focused
canonical/resolver gate is 279/279 green; Ruff, ast-grep, `graphify update .`,
and all 14 import contracts pass.

The mandatory cache-disabled A560 canary returned normally in 22.53 seconds
(20.50 seconds inside pytest) with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-boundary-source-owners-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-boundary-source-owners-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-boundary-source-owners-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The DB proves that incoming source
`native[0x40AB31-0x40AB56;exact=0x40AB31]:imported` also has zero current owners
and an empty current-overlap inventory. Receipt-backed event 30 records 93
current-MBA import bindings; querying that authority shows `0x40AE3E` is the
only live identity among `0x40AE3E`, `0x40B51B`, `0x40AB31`, and the upstream
`0x40C328` / `0x40C335` route block. Therefore recursively moving the live root
upstream is not viable. The highest completed semantic level remains C2.

The bounded vertical must return to the one live root at `0x40AE3E`. Its
prohibited dispatcher predecessor may be used only as an explicit temporary
publication port, not silently accepted as reference topology. Model that port
as a typed remaining work-item obligation that survives the C5 receipt and is
superseded when the upstream semantic fragment is later published. C4 should
compare the selected fragment's internal routes and normalize the temporary
external boundary port. This is the evidence-backed exception to the earlier
blanket predecessor veto; do not erase the obligation, call the port
reference-equivalent, or broaden to the 91-route publication.

**2026-07-25T05:30:37Z**

Commit `36480da21` introduces a serial-free `FragmentBoundaryPort` with typed
`temporary_dispatcher_entry` semantics and a stable retirement obligation.
Canonical plan validation requires the port predecessor to be an external
block, the target to be a plan root, and the predecessor not to be silently
classified as an already-eliminated prohibited dispatcher. The pass enables
the port only after the proved semantic predecessor and its incoming
normalization source both have zero live owners. The combined canonical,
resolver, fragment-plan, fragment-validation, and semantic-backend gate is
445/445 green; Ruff, ast-grep, `graphify update .`, and all 14 import contracts
pass.

The mandatory cache-disabled A560 canary returned normally in 20.86 seconds
(19.09 seconds inside pytest) with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-temporary-boundary-port-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-temporary-boundary-port-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-temporary-boundary-port-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red with one false `while ( 1 )`; this is not A560
acceptance.

The typed port advances the intended route-level fact: canonical composition
returns to native root `0x40AE3E` and passes the prior predecessor veto. It then
declines with `published_boundary_semantic_route_missing`, proving that forward
detached closure selected no semantic rewrite for the root. The highest
completed semantic level remains C2; there is still no semantic transaction,
oracle comparison, or semantic receipt.

Continue by recording the detached target block/operation inventory and every
nested state-route projection decision on this rejection. The next fix must
explain why proved route `0x40B51B -> 0x40AE3E` is not included in the forward
fragment; do not remove the requirement that a C3 fragment own at least one
real reference route, claim the temporary port itself as semantic work, or
publish before C4.

**2026-07-25T05:36:21Z**

Commit `c056aebbc` records the detached target inventory and the complete
nested state-route projection ledger when canonical composition rejects a
published boundary for owning no semantic route. The combined canonical,
resolver, fragment-plan, fragment-validation, and semantic-backend gate is
446/446 green; Ruff, ast-grep, `graphify update .`, and all 14 import contracts
pass.

The mandatory cache-disabled A560 canary completed normally in 19.03 seconds
inside pytest with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-missing-route-projection-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-missing-route-projection-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-missing-route-projection-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red as an eight-line stub with one false
`while ( 1 )`; this is not A560 acceptance.

The DB identifies the first failed obligation as
`published_boundary_semantic_route_missing@0x40AE3E`. The selected detached
component contains imported and live identities rooted at `0x40AE3E` and only
operation `native-body-edge@0x40AE3E`. Every one of the projected state routes
is skipped as `source_not_in_component`, including the required
`state_assignment@0x40B52E:0x13B0D3B2` delivery into `0x40AE3E`. The only
committed transaction/receipt remains the 260/260 frontend-normalization
publication; there are zero semantic-oracle runs or comparisons. Therefore the
highest completed semantic level remains C2, not C5.

Continue from this C3 composition obligation. Inspect and test the detached
component-selection contract so the bounded vertical can own the proved
incoming semantic route and its corridor without weakening the semantic-route
requirement, treating the temporary dispatcher port as semantic work, or
publishing before a C4 oracle comparison. Do not broaden to the 91-route
publication until one complete fragment reaches C5.

**2026-07-25T05:43:41Z**

Commit `fb03d3f61` makes normalization blocks reimportable when their sole live
owner is explicitly among the current originals being replaced by the bounded
transaction. Mixed replaced/retained ownership remains a hard rejection. This
models the real maturity split where `blk48@0x40AE3E` owns native range through
`0x40AE8B`, while frontend normalization retains separate `0x40AE3E` and
`0x40AE63` blocks. The combined vertical gate is 446/446 green; Ruff,
ast-grep, `graphify update .`, and all 14 import contracts pass.

The mandatory cache-disabled A560 canary completed normally in 19.01 seconds
inside pytest with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-replaced-owner-split-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-replaced-owner-split-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-replaced-owner-split-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red as the same eight-line infinite-loop stub; this is
not A560 acceptance.

The intended route fact advanced substantially. The DB now projects five real
state routes in four fixpoint rounds, including required
`state_assignment@0x40B52E:0x13B0D3B2`; the others are deliveries at
`0x40AE7A`, `0x40AA4F`, `0x40C341`, and `0x40AB64`. The first failed
obligation moved to
`published_imported_boundary_topology_unresolved@0x40A607`: imported operation
`native-body-edge@0x40A607` is owned live by `blk8@0x40A560` and is entered by
`native-indirect-transfer@0x40C802` from native source `0x40C7FC`. The only
committed transaction remains the 260/260 frontend-normalization publication,
and there are still zero semantic-oracle runs or comparisons. Therefore the
highest completed semantic level remains C2.

Continue from the `0x40A607` C3 boundary obligation. Determine whether the
`0x40C7FC -> 0x40A607` transfer has a reference-ledger semantic replacement or
is a valid closed external boundary before changing publication logic. Do not
classify `blk8@0x40A560` as replacement-owned, permit unresolved dispatcher
residue, or advance to C4 without a complete route-backed plan.

**2026-07-25T06:00:19Z**

Commit `b6e7a4d47` extends nested canonical projection to terminal-return
evidence instead of filtering it out as a non-state route. A projected
terminal is one atomic effect containing its direct route, return carrier,
terminal return, and terminal route; conflicting shared returns and unstaged
endpoints remain hard rejections. The combined canonical, resolver,
fragment-plan, fragment-validation, and semantic-backend gate is 447/447
green; Ruff, ast-grep, `graphify update .`, and all 14 import contracts pass.

The mandatory cache-disabled A560 canary completed normally in 21.26 seconds
inside pytest with no process crash or numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-nested-terminal-route-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-nested-terminal-route-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-nested-terminal-route-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red as the same eight-line infinite-loop stub; this is
not A560 acceptance.

The intended route fact advanced again. Canonical composition now selects
terminal proof `terminal_return@0x40C7F6:0x19A7218A` and reaches terminal
effect construction, then rejects it as
`nested_terminal_route_staged_owner_missing@0x40C7F6`. The current rejection
payload records only the proof identity and does not identify which
EA-anchored source or destination endpoint is unstaged. The only committed
transaction remains the 260/260 frontend-normalization publication; there are
zero semantic-oracle runs or comparisons. Therefore the highest completed
semantic level remains C2.

Continue by making this rejection inventory both terminal endpoints, their
roles and stable identities, plus the operation and target identities. Do not
change terminal ownership or staging acceptance until the DB identifies the
specific missing endpoint, and do not weaken the requirement that the route,
carrier, and return be wholly staged as one fragment-atomic operation.

**2026-07-25T06:07:34Z**

Commit `9133a59a4` makes the terminal staging rejection inventory the route
operation, both block IDs, both roles, both stable identities, and the direct
target ID while preserving the same hard rejection. A focused red test proved
the former proof-ID-only payload before the bounded implementation change. The
combined canonical, resolver, fragment-plan, fragment-validation, and
semantic-backend gate is 448/448 green; Ruff, ast-grep, `graphify update .`,
and all 14 import contracts pass.

The mandatory cache-disabled A560 canary completed normally in 19.37 seconds
wall time (17.62 seconds inside pytest) with no process crash or numeric
`INTERR`. It used image
`d810-idapro-9.3-test-runtime:py313-v1` and fixture SHA-256
`2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`.
Log: `.tmp/rhad-a560-v33-terminal-owner-inventory-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-terminal-owner-inventory-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-terminal-owner-inventory-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red as the same eight-line infinite-loop stub; this is
not A560 acceptance.

The DB now identifies the precise first failed C3 obligation. Terminal proof
`terminal_return@0x40C7F6:0x19A7218A` has an imported source identity spanning
`0x40C7E5-0x40C7FC`, but its destination identity spanning
`0x40C898-0x40C8A2` is classified `external`. Canonical composition therefore
rejects with `nested_terminal_route_staged_owner_missing@0x40C7F6`. The only
committed transaction remains the 260/260 frontend-normalization publication;
there are zero semantic-oracle runs or comparisons. The highest completed
semantic level remains C2.

Continue by tracing why the proved terminal-return destination becomes an
external boundary and add the smallest ownership/closure test for that exact
case. Do not merely permit an external terminal endpoint: the semantic route,
carrier, and terminal return must all be staged in the same detached fragment
before C3 can complete.

**2026-07-25T06:15:18Z**

Commit `d023352bd` keeps selected terminal-proof destinations inside the final
detached component even when their stable identity already has one live owner.
Ordinary published exits remain external; mixed, replaced, prohibited, and
ambiguous current-owner checks are unchanged. The strengthened atomic-terminal
test covers both detached-only and one-live-owner destinations. The combined
canonical, resolver, fragment-plan, fragment-validation, and semantic-backend
gate is 449/449 green; Ruff, ast-grep, `graphify update .`, and all 14 import
contracts pass.

The mandatory cache-disabled A560 canary completed normally in 20.64 seconds
wall time (18.84 seconds inside pytest) with no process crash or numeric
`INTERR`. Log: `.tmp/rhad-a560-v33-terminal-target-staged-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-terminal-target-staged-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-terminal-target-staged-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red as the same eight-line infinite-loop stub; this is
not A560 acceptance.

The intended route fact advanced: the prior
`nested_terminal_route_staged_owner_missing@0x40C7F6` rejection is gone, so the
terminal source, destination, carrier, and return now reach fragment
construction together. The first failed obligation moved to
`canonical_pipeline_exception@0x40A560` with
`FragmentPlanRejected: fragment block semantic anchor must belong to its
stable identity`. The DB does not identify the offending block, anchor, or
identity. The only committed transaction remains the 260/260 frontend
normalization publication; there are zero semantic-oracle runs or comparisons.
The highest completed semantic level remains C2 because no complete canonical
plan was produced.

Continue by enriching this invariant failure with the offending block ID,
role, semantic anchor, and stable identity so the DB exposes the exact native
coordinate mismatch. Do not guess that the terminal block is responsible or
change anchor/identity semantics until the diagnostic proves it.

**2026-07-25T06:21:12Z**

Commit `9e8e0a320` gives `FragmentPlanRejected` the same structured diagnostic
surface consumed by the canonical pipeline and populates it for fragment-block
anchor/identity mismatches. The focused test first disproved the suspected
terminal mismatch because `0x40C898` belongs to that terminal identity's native
range, then proved the real out-of-range invariant payload. The combined
canonical, resolver, fragment-plan, fragment-validation, and semantic-backend
gate is 450/450 green; Ruff, ast-grep, `graphify update .`, and all 14 import
contracts pass.

The mandatory cache-disabled A560 canary completed normally in 19.27 seconds
wall time (17.59 seconds inside pytest) with no process crash or numeric
`INTERR`. Log: `.tmp/rhad-a560-v33-fragment-anchor-inventory-v1.txt`; primary
DB:
`.tmp/rhad-a560-v33-fragment-anchor-inventory-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-fragment-anchor-inventory-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red as the same eight-line infinite-loop stub; this is
not A560 acceptance.

The DB identifies the actual offender as
`published-boundary@0x40AE3E:original`, not the terminal target. Its role is
`original`, materialization is `reuse_published`, and its stored stable
identity spans `0x40AE3E-0x40AE8B`, but composition assigns semantic anchor
`0x40A560` from the maturity-local live owner. The rejection is now
`fragment_block_semantic_anchor_identity_mismatch@0x40A560`. The only
committed transaction remains the 260/260 frontend-normalization publication;
there are zero semantic-oracle runs or comparisons. The highest completed
semantic level remains C2.

Continue with a focused boundary-composition test where the live owner's block
start differs from the portable boundary identity. Original and replacement
roots must use an anchor belonging to that portable identity; do not persist
the live block start as semantic identity or weaken the FragmentBlock
invariant.

**2026-07-25T06:25:50Z**

Commit `8955288bd` makes published-boundary original and replacement roots use
their portable `boundary_anchor_ea`, not the maturity-local live owner's block
start. The strengthened replacement-owned split test models a live owner at
`0x1005` with portable identity `0x1200-0x1211` and proves both roots remain
anchored at `0x1200`. The combined canonical, resolver, fragment-plan,
fragment-validation, and semantic-backend gate is 450/450 green; Ruff,
ast-grep, `graphify update .`, and all 14 import contracts pass.

The mandatory cache-disabled A560 canary completed normally in 23.44 seconds
wall time (20.94 seconds inside pytest) with no process crash or numeric
`INTERR`. Log: `.tmp/rhad-a560-v33-portable-boundary-anchor-v1.txt`; primary
DB:
`.tmp/rhad-a560-v33-portable-boundary-anchor-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-portable-boundary-anchor-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red as the same eight-line infinite-loop stub; this is
not A560 acceptance.

The boundary anchor mismatch is gone and canonical construction reaches the
terminal-carrier plan invariant. The first failed obligation is now
`fragment_plan_rejected@0x40A560`: return carrier
`return-carrier:terminal_return@0x40C7F6:0x19A7218A` requires every corridor EA
to be an exact instruction owned by its staged block identity. The DB does not
record the carrier's block, corridor EAs, exact-instruction inventory, or
missing subset. The only committed transaction and root-publication group
remain frontend-normalization evidence; there are zero semantic-oracle runs or
comparisons. The highest completed semantic level remains C2 because the
canonical plan still fails validation.

Continue by structuring this return-carrier rejection with the block ID, role,
stable identity, corridor anchors, exact-instruction inventory, and missing
anchors. Do not widen an identity or relax exact ownership until the DB
identifies the precise mismatch.

**2026-07-25T06:30:24Z**

Commit `f9cf7325b` structures the return-carrier exact-anchor invariant without
weakening it. The diagnostic now names the carrier block, role, semantic
anchor, stable identity, state-write and carrier EAs, complete corridor,
exact-instruction inventory, and missing subset. The existing terminal-plan
test proves the reason and payload. The combined canonical, resolver,
fragment-plan, fragment-validation, and semantic-backend gate is 450/450
green; Ruff, ast-grep, `graphify update .`, and all 14 import contracts pass.

The mandatory cache-disabled A560 canary completed normally in 19.90 seconds
wall time (18.20 seconds inside pytest) with no process crash or numeric
`INTERR`. Log:
`.tmp/rhad-a560-v33-terminal-carrier-anchor-inventory-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-terminal-carrier-anchor-inventory-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-terminal-carrier-anchor-inventory-v1/test_real_loader_matches_reach0/sub_40A560.c`.
It remains semantically red as the same eight-line infinite-loop stub; this is
not A560 acceptance.

The DB proves the exact first C3 mismatch. Imported block
`native[0x40C7E5-0x40C7FC;exact=0x40C7E5]:imported` owns the carrier's full
native range and exact state-write EA `0x40C7E5`, but its exact-instruction set
does not include carrier EA `0x40C7EA`. That is the sole missing anchor for
`return-carrier:terminal_return@0x40C7F6:0x19A7218A`, and the rejection is now
`fragment_return_carrier_exact_anchor_missing@0x40C7EA`. The only committed
transaction remains the 260/260 frontend-normalization publication; there are
zero semantic-oracle runs or comparisons. The highest completed semantic level
remains C2.

Continue by defining a coherent proof-owned identity refinement for terminal
carrier anchors: update the staged block identity, its token-derived block ID,
and every plan reference together, only after proving the carrier corridor is
inside the native range and owned by the selected terminal proof. Do not leave
a stale tokenized block ID or relax exact-anchor validation.

**2026-07-25T06:48:15Z**

Commit `18412e5fa` refines only proof-owned terminal anchors inside their staged
native ranges, retokenizes every changed imported block identity, and rewrites
all operation, native-body, carrier, and terminal-return references coherently.
The exact-anchor invariant remains strict. Commit `cd52a560c` is the separate
repository-wide Ruff formatting change requested by the user; Ruff reformatted
only the same two files and left the other 1,860 files unchanged.

The canonical-fragment unit file is 36/36 green. The established Docker
vertical gate is now 465/465 green across the semantic backend, manager native
preanalysis, resolver session/runtime, canonical lowering, canonical fragment,
and fragment-validation suites. Ruff is clean, ast-grep is clean, all 14 import
contracts pass, and `graphify update .` completed.

The mandatory cache-disabled A560 canary completed normally in 17.96 seconds
inside pytest with no process crash or reported numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-terminal-identity-refinement-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-terminal-identity-refinement-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-terminal-identity-refinement-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The pseudocode remains the same eight-line infinite-loop stub, so this is not
A560 acceptance.

The DB proves that the terminal exact-anchor rejection is gone and one complete
C3 canonical plan now exists at native boundary `0x40AE3E`. Plan
`canonical-boundary-composition:canonical-semantic:g1:0x40AE3E` contains 13
blocks, 10 operations, one native body, six semantic route proofs including
`terminal_return@0x40C7F6:0x19A7218A`, and the temporary dispatcher-entry port
whose retirement obligation is anchored at native predecessor `0x40B51B`.

The highest completed canary level is now C3. The first failed C4 obligation is
`canonical_boundary_detached_oracle_required@0x40AE3E`: the bounded plan must
receive detached reference-oracle proof before live publication. The DB still
contains only the 260/260 frontend-normalization receipt and reports zero
semantic-oracle runs or comparisons; therefore no semantic C5 publication is
claimed.

Continue with the v3.3 vertical loop at C4 for exactly this bounded
`0x40AE3E` plan. Capture and compare its detached reference route oracle before
publication; do not broaden to the 91-route batch or bypass the oracle gate.

**2026-07-25T07:39:16Z**

The C4 authority infrastructure is now split into three committed slices.
Commit `bfac0c596` adds the exact-input reference catalog, capability protocol,
and pure fragment-plan binder. Commit `64fec59a6` compares every proof-owned
direct rewrite against its staged unpublished projection and rejects a mismatch
before root preparation; the committed mutation receipt carries the passing
detached-oracle result. Commit `f36a17375` advances the disposable diagnostic
schema to version 8 and persists the run, ledger identity, oracle shape,
candidate shape, first divergence, and failed invariant in
`semantic_fragment_route_oracle_comparisons` through the normal gateway ->
manager -> core-observability -> SQLite boundary. There is no compatibility
schema or migration shim.

The portable catalog/binder suite is 114/114 green. The gateway and manager
gate is 43/43 green, including a malformed conditional staged terminator that
emits `transfer_kind`, discards staging, and never calls root preparation. The
diagnostic suite is 127/127 green. Ruff, ast-grep, the portable-shape gate, and
all 14 import-linter contracts are green after every slice.

The mandatory cache-disabled A560 diagnostic canary completed normally in
15.85 seconds inside pytest with no worker crash or reported numeric `INTERR`.
Log: `.tmp/rhad-a560-v33-c4-gateway-diag-v1.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-c4-gateway-diag-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-c4-gateway-diag-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The pseudocode remains the same eight-line false `while ( 1 )` stub, so this is
not A560 acceptance.

The DB remains authoritative. Its frontend-normalization transaction commits
260/260 operations and publishes its root with no rollback. At CALLS, fact
consumer row `snapshot=3, consumer_index=2` records the bounded plan
`canonical-boundary-composition:canonical-semantic:g1:0x40AE3E` with 13 blocks,
10 operations, one native body, six direct route proofs, and the temporary
dispatcher-entry port retired by semantic predecessor `0x40B51B`. It declines
with `canonical_boundary_detached_oracle_required` at native boundary
`0x40AE3E`. No semantic plan reaches the live gateway yet, so the new detached
comparison table has zero rows and no semantic C5 receipt exists.

The highest completed A560 level therefore remains C3. The first failed C4
obligation remains `canonical_boundary_detached_oracle_required@0x40AE3E`.
Next, prove one complete one-route C5 fragment using the exact audited reference
transaction and schema-8 comparison/receipt path; only then wire the bounded
six-route A560 selection. Do not broaden to the 91-route publication.

**2026-07-25T08:03:34Z**

The required one-route C5 vertical is complete and committed without broad
publication. Commit `3cb07358d` stamps a zero-way semantic replacement's new
`m_goto` with its exact rewrite anchor and makes staged rollback restore
temporary survivor protection through the sweep's proven compaction inventory,
rather than rebinding content identity after the normalizing sweep. This
eliminates the earlier projection mismatch and turns the missing-authority
rejection into a clean rollback with no `INTERR 52719`; the SDK mapping for
`52719` is the `mba_t::get_mblock` assertion `n < qty`. Commit `0b4bc7f1b` is
the requested separate Ruff-only formatting follow-up.

Commit `356bbb8f4` binds the exact cache-disabled reference transaction
`flow_route:0x40C7F6` to the real terminal fragment
`0x40C7F6 -> 0x40C898`. The pinned run uses fixture/candidate SHA-256
`2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c`,
reference binary SHA-256
`6358957fe74360725b125bdc41b16df9952d95b338792fd3521249e5030ddd8c`,
reference commit `21b0d4783703bc4fb6910cfae51d92cd683d2c65`, and runtime image ID
`sha256:360f91d9d4ace70d89e03893f1d895d94383fa0fe426ddba9d3898a7922b650a`.
The real Docker C5 canary is green. Log:
`.tmp/rhad-real-fragment-c5-reference-green-v2.txt`; authoritative schema-8
DB: `.tmp/rhad-real-fragment-c5-reference-green-v2.diag.sqlite3`.

The DB records exactly one matched `DETACHED_PREPUBLICATION` comparison for
owner `0x40C7E5`, rewrite anchor `0x40C7F6`, and ledger identity
`flow_route:0x40C7F6`. Transaction ordering is `plan_recorded`,
`detached_route_oracle:passed`, `fragment_staged`, prevalidation, root-group
publication, root publication, postvalidation, and finally
`receipt:committed`. The receipt is 7/7, both validation phases pass, root
publication succeeds, and rollback is not attempted. This satisfies one
complete C5 vertical fragment; it does not establish production A560 C5 or C6.

Verification is green for the 90-test semantic-fragment backend file, the
41-test portable fragment-validation file, the two focused anchor/rollback
regressions, the exact real C5 canary, and the 54-test catalog/oracle/diagnostic/
gateway/manager gate. Ruff is clean for the C5 test, `graphify update .`
completed, and every commit's ast-grep, portable-shape, import-cycle, and all
14 import-linter gates passed. The broader legacy `test_deferred_modifier.py`
file still has 79 unrelated fake-MBA failures because those doubles lack
`map_fict_ea`; its changed exact-anchor regression is green and this baseline
debt was not treated as evidence for or against C5.

The mandatory post-C5 cache-disabled A560 canary completed normally in 15.96
seconds inside pytest with no worker crash or reported numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-after-one-route-c5-diag-v1.txt`; primary DB:
`.tmp/rhad-a560-v33-after-one-route-c5-diag-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-after-one-route-c5-diag-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The pseudocode remains the same eight-line false `while ( 1 )` stub, so this is
not A560 acceptance.

The post-C5 DB remains authoritative: frontend normalization commits 260/260,
the production semantic comparison table has zero rows, and fact consumer
`snapshot=3, consumer_index=2` still declines the 13-block, 10-operation,
one-native-body, six-route boundary plan with
`canonical_boundary_detached_oracle_required@0x40AE3E`. Production A560
therefore remains at C3, with that C4 authority binding as the first failed
obligation. Continue by selecting and binding exactly the audited six ledger
routes to this bounded plan, then rerun the diagnostic canary. Do not broaden
to the 91-route publication.

**2026-07-25T08:39:19Z**

Commits `5eb033a0d`, `6b783462a`, and `adff26f68` bind the bounded canonical
plan to an exact configured six-route reference catalog through the routed
config-v2 runtime project. Commit `cfd2e09b9` is the separate Ruff-only
formatting change. The current resolver runtime suite is 278/278 green in
Docker; the inherited 303-test command is stale because its removed test file
collects no tests.

The first authority-enabled A560 canary selected the catalog but exposed an
opaque plan-construction failure at route anchor `0x40AB64`. Commit
`c36cbad58` adds a structured route-identity mismatch with the operation,
source and target block IDs, stable identities, reference owner and target
EAs, and independent containment booleans. Commit `2934925ec` is the separate
Ruff-only formatting follow-up. The focused fragment-plan, detached-oracle,
and canonical-lowering gate is 48/48 green; both commits pass ast-grep, the
portable-shape gate, import-cycle analysis, and all 14 import-linter contracts.

The mandatory exact cache-disabled A560 canary completed normally in 17.03
seconds inside pytest with no worker crash or reported numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-reference-identity-diag-v3.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-reference-identity-diag-v3/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-reference-identity-diag-v3/test_real_loader_matches_reach0/sub_40A560.c`.
The pseudocode remains the same eight-line false `while ( 1 )` stub, so this is
not A560 acceptance.

The DB identifies the first failed C4 obligation precisely. Route
`state_assignment@0x40AB64:0x23B8E806` targets
`native[0x40AA2C-0x40AA35;exact=0x40AA2C]:imported`, and target containment is
true for reference target `0x40AA2C`. Its delivery source is
`native[0x40AB56-0x40AB6A;exact=0x40AB56]:imported`, while the reference
operation owner is the earlier state write at `0x40AB4B`; owner containment is
therefore false. The canonical fact records the full proof corridor
`0x40AB4B, 0x40AB50, 0x40AB64`. No semantic oracle comparison or semantic
receipt exists; the only committed receipt remains the 260/260 frontend
normalization publication. Production A560 therefore remains at C3.

Continue by adding the stable operation owner explicitly to the portable
direct-rewrite contract and proving that its corridor is wholly owned by the
selected detached component. Do not change the authoritative reference owner,
merge it into the delivery block identity, or weaken containment. Validate one
route at `0x40AB64` before considering the remaining five routes.

**2026-07-25T08:49:13Z**

Commit `80a9dae02` adds a required stable operation-owner identity and exact
owner anchor to every portable direct rewrite. Canonical construction derives
that owner from the state write when one exists, while the delivery operation
continues to execute on the block containing the exact rewrite anchor. The
detached oracle now compares the explicit operation owner rather than assuming
that the owner and delivery tail occupy one native block. A pure split-owner
test proves owner `0x40B51B` can remain authoritative when the delivery block
contains only `0x40B52E`. Commit `943492485` is the separate Ruff-only
formatting follow-up.

The combined portable plan, canonical composition, detached oracle, gateway,
and semantic-backend gate is 200/200 green. The three focused detached PREOPT
direct-transfer runtime tests are 3/3 green. Ruff is clean for all eight
touched files, and both commits pass ast-grep, the portable-shape gate,
import-cycle analysis, and all 14 import-linter contracts.

The mandatory exact cache-disabled A560 canary completed normally in 18.43
seconds inside pytest with no worker crash or reported numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-direct-owner-contract-v1.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-direct-owner-contract-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-direct-owner-contract-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The pseudocode remains the same eight-line false `while ( 1 )` stub, so this is
not A560 acceptance.

The intended route fact advanced: the `0x40AB64` reference-owner mismatch is
gone, the six-route 31-operation semantic plan reaches the gateway, and its
first attempt aborts without mutation to request the required CALLS companion
for call `0x40AA30` over range `0x40AA2C-0x40AA60`. The controlled redo then
reaches detached direct-transfer preflight. Its first failed C4 obligation is
`detached_direct_transfer_tail_mismatch@0x40AA4F`: operation
`state_assignment@0x40AA4F:0xE41F690E` owns its corridor and superseded anchor,
but its imported delivery block continues to native tail `0x40AA57` with
opcode 42 rather than ending at the rewrite anchor `0x40AA4F`.

Both semantic receipts are aborted with zero applied operations, and there are
zero detached reference comparisons. Production A560 therefore remains at C3.
Continue by determining the proof-owned cut for the `0x40AA4F` delivery
envelope before changing backend lowering. Do not presume that the whole
`0x40AA35-0x40AA60` block is dispensable, and do not require the pre-rewrite
native tail to equal the semantic rewrite anchor when an explicit validated
cut can preserve required instructions through `0x40AA4F` and suppress only
the obsolete suffix.

**2026-07-25T09:10:00Z**

Commit `9805682cf` adds the typed direct-route delivery interval, carries it
from portable state-write evidence through canonical construction, validates
full interval ownership for imported detached sources, and lowers a direct
route by cutting the detached instruction suffix at one exact rewrite anchor
before appending `m_goto`. The backend rejects missing or ambiguous anchors,
suffix instructions outside the owned interval, and non-branch tails with
structured `detached_direct_transfer_cut_mismatch` payloads. Commit
`e84c37b42` is the separate Ruff-only formatting follow-up.

The focused semantic evidence, canonical composition, fragment-plan,
reference-oracle, gateway, backend, and Hex-Rays runtime gate is 396/396 green.
Both commits pass ast-grep, the portable-shape gate, import-cycle analysis, and
all 14 import-linter contracts. The interior-cut runtime proves that a source
containing preserved prefix instructions, an instruction at rewrite anchor
`0x3610`, and a conditional tail at `0x3614` stages only the prefix plus the
new direct transfer. No live MBA mutation occurs on a rejected cut.

The mandatory exact cache-disabled A560 canary completed normally in 11.71
seconds inside pytest with no worker crash or reported numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-delivery-cut-v1.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-delivery-cut-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-delivery-cut-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The pseudocode remains the same eight-line false `while ( 1 )` stub, so this is
not A560 acceptance.

The DB records only the 260/260 committed frontend-normalization transaction
and no canonical semantic transaction, comparison, or receipt. This canary's
highest completed level is therefore C2, a regression from the preceding C3
checkpoint. A separate focused worker trace at
`.tmp/rhad-a560-v33-delivery-cut-worker.txt` identifies the first failed C3
obligation as proof construction rejecting a direct route because its wider
physical delivery interval is outside its one-anchor `delivery_identity`.
That rejection is repeated from CALLS onward but is absent from the DB, which
is an observability defect: the DB correctly proves where progress stopped but
does not yet persist why.

The contract conflated two deliberately distinct authorities.
`PortableStateWriteRouteEvidence` uses `delivery_identity` to bind the exact
route anchor and `delivery_region_start_ea/end_ea` to own the physical suffix
that may be cut. Immediate routes explicitly construct the former as
`[delivery_ea, delivery_ea + 1)` while the latter extends through the native
transfer tail. Keep the proof-level anchor-in-region check, remove the invalid
requirement that the region fit inside the anchor identity, and retain the
full-region containment check when canonical planning binds an imported
physical source. Rerun the same A560 DB canary before interpreting the new
`0x40AA4F` cut result.

**2026-07-25T09:15:00Z**

Commit `c5fa61c90` corrects the proof contract with an explicit regression
test: a one-anchor stable `delivery_identity` may carry a wider exact physical
delivery interval. The anchor must still belong to both authorities, and the
later canonical imported-source plan still proves full interval containment.
Ruff produced no follow-up diff. The focused gate is now 397/397 green, and
the commit passes ast-grep, the portable-shape gate, import-cycle analysis, and
all 14 import-linter contracts.

The mandatory exact cache-disabled A560 rerun completed normally in 18.44
seconds inside pytest with no worker crash or reported numeric `INTERR`. Log:
`.tmp/rhad-a560-v33-delivery-cut-v2.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-delivery-cut-v2/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-delivery-cut-v2/test_real_loader_matches_reach0/sub_40A560.c`.
The pseudocode remains the same eight-line false `while ( 1 )` stub, so this is
not A560 acceptance.

The DB proves production C3 is restored. The six-route, 31-operation semantic
plan reaches the gateway; the first attempt aborts with zero applied operations
to request the exact CALLS companion for call `0x40AA30` over
`0x40AA2C-0x40AA60`, then controlled redo repeats the 260/260 committed
frontend transaction and retries the same semantic plan. The second semantic
receipt again aborts with zero applied operations and successful rollback.

The first failed C4 obligation is now the plan-owned terminal block
`native[0x40C898-0x40C8A2;exact=0x40C898,0x40C89F]:imported@0x40C89F`:
`CALLS native body cannot contain a return`. There are still zero detached
route comparisons and no semantic C5 receipt; the new `0x40AA4F` delivery cut
has not yet been reached on the redo path.

The next vertical slice must not merely allow an arbitrary CALLS `m_ret`.
CALLS preparation should identify exactly the `FragmentTerminalReturn` owned
by this native body's terminal block, remove only that exact terminal tail from
the detached prepared rows, reject every unplanned or ambiguous return, and
leave the terminal block unpublished. The semantic backend already materializes
return carriers and terminal returns before realizing route operations in the
same staged transaction, and validates their connected terminal route before
publication. Prove that deferral contract locally, then rerun the exact DB
canary.

**2026-07-25T09:30:00Z**

Commit `d8563f380` implements that exact deferral contract. CALLS preparation
removes only the unique final top-level `m_ret` named by a plan-owned
`FragmentTerminalReturn`; an unplanned return remains rejected, and the staged
terminal block stays empty so the semantic backend can synthesize the return
with its carrier and incoming route in one transaction. Commit `c7d3c22a5` is
the separate Ruff-only formatting follow-up. The focused semantic evidence,
plan, gateway, backend, and Hex-Rays runtime set is 370/370 green, with the
seven CALLS materializer cases and the existing atomic terminal-effects runtime
oracle also green. Both commits pass ast-grep, import-cycle analysis, the
portable-shape gate, and all 14 import-linter contracts.

The mandatory exact cache-disabled A560 canary completed normally inside
pytest in 20.70 seconds, but its semantic oracle still fails on the same false
`while ( 1 )`. Log: `.tmp/rhad-a560-v33-terminal-return-v1.txt`; primary
schema-8 DB:
`.tmp/rhad-a560-v33-terminal-return-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-terminal-return-v1/test_real_loader_matches_reach0/sub_40A560.c`.
A second capture-enabled reproduction completed in 26.58 seconds with log
`.tmp/rhad-a560-v33-terminal-return-v2.txt` and verifier artifact
`.tmp/rhad-a560-v33-terminal-return-v2-verify/verify_fail_20260725T092410.365384Z_000000000040A560_11.json`.

The DB proves that terminal-return deferral advances staging beyond the prior
barrier, but production remains at C3. The first semantic attempt requests the
exact `0x40AA30` CALLS companion and rolls back cleanly with zero applied
operations. After controlled redo, the 31-operation plan applies 24 gateway
operations before the first failed C4 obligation: call-fallthrough operation
`native-body-edge@0x40AE3E` binds its staged replacement as
`blk89@0x40A560`, but that block is `BLT_1WAY` with no successor and an
unmapped `m_goto` tail instead of the required zero-way block-closing analyzed
call. There are no detached reference comparisons and no C5 receipt.

This second rejection is not rollback-safe and is therefore a hard failure
under v3.3. The first cleanup verification raises numeric `INTERR 50856`, which
`verifier/verify.cpp` maps to `nsucc() != expected successor count`. The
capture identifies surviving `blk88@0x40A560` as `BLT_1WAY` with zero
successors after the staged sweep. The subsequent `INTERR 52719` maps in the
SDK to `mba_t::get_mblock(uint n)` asserting `n < qty`; it is a secondary
double-discard that tries to resolve transaction-local versions after the
first sweep already compacted the MBA.

Before changing `0x40AE3E` route semantics, reproduce and repair the rollback
contract: staged insertion and discard must preserve the published
fallthrough-to-stop edge, cleanup must be idempotent after a partially failed
stage, the semantic state must not retain compacted serial bindings, and the
fresh MBA must verify. Then rerun this exact diagnostic canary and continue
from the stable-EA `0x40AE3E` call-ownership mismatch only after rollback is
clean.

**2026-07-25T09:52:00Z**

The rollback contract is now repaired and committed in narrow slices.
Commits `6d9e66fba`, `0781eee02`, `5e74b0362`, and `3ec26b1b0` restore the
published tail fallthrough, invalidate failed staged state, recognize the
already-severed staged tail, rebind the shifted stop after sweep compaction,
and compare transient SWIG block wrappers by stable serial rather than Python
object identity. Commits `310c55aa8` and `c1d3ff41a` are the corresponding
separate Ruff-formatting changes. Commit `fe7e0299f` preserves the BLT_STOP
block's refined return-use lists while restoring only its predecessor metadata;
the SDK forbids dirty stop lists after CALLS information exists.

The successive canaries exposed three distinct verifier obligations rather
than a process segfault. `INTERR 50856` is `verify.cpp`'s wrong block-successor
cardinality check. Secondary `INTERR 52719` is `hexrays.hpp`'s out-of-range
`mba_t::get_mblock()` assertion after a repeated discard. V6 then reached
`INTERR 51328`, which is `verify.cpp`'s rejection of a BLT_STOP with dirty
use/def lists after callinfo was built. The focused regression makes an
attempt to dirty that stop fail exactly as 51328; the repaired cleanup never
makes that call. The complete semantic-fragment backend file is 94/94 green,
Ruff is clean, and the commit-time ast-grep, import-cycle, portable-shape, and
all 14 import-linter gates pass.

The mandatory exact cache-disabled A560 canary at `fe7e0299f` completed
normally in 21.01 seconds. Log: `.tmp/rhad-a560-v33-rollback-v7.txt`; primary
schema-8 DB:
`.tmp/rhad-a560-v33-rollback-v7/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-rollback-v7/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects the residual false `while ( 1 )`, so this is
not A560 acceptance.

The v7 DB proves rollback is now verifier-clean and honest. It contains no
`verifier_failure` event. The second 31-operation semantic attempt applies 24
operations, aborts before publication, and records `rollback_succeeded=1`.
There are zero detached route-oracle comparisons and no semantic C5 receipt.
Production therefore remains at C3.

The first failed C4 obligation is unchanged and native-EA anchored:
`native-body-edge@0x40AE3E` binds stable identity
`native[0x40AE3E-0x40AE8B;exact=0x40AE5D,0x40AE60,0x40AE69,0x40AE6F]`
to staged replacement `blk89@0x40A560`, which is `BLT_1WAY` with zero
successors and an unmapped `m_goto` tail. The operation requires the analyzed
zero-way block-closing call for the `0x40AE3E` call-fallthrough boundary. Do
not allow the goto as call fallthrough. Continue by reconciling canonical
source ownership and PREOPT/CALLS binding at stable native EA `0x40AE3E`, then
rerun the same diagnostic canary.

**2026-07-25T10:55:25Z**

Commits `d2b0ff7a8` and `2314a9596` preserve the exact operation inventory of
each committed frontend-normalization work item in
`NormalizationWorkItemAuthority`; the second commit is the separate Ruff-only
formatting change. The canonical composer may now reuse a currently published
direct or call-fallthrough boundary only when that exact supporting operation
belonged to the atomically committed and postvalidated work item. An
unreceipted boundary remains rejected, and a raw conditional still cannot be
declared semantic merely because its mutation calls completed. No compatibility
path or architecture ignore was added.

Focused verification is 157/157 local lifecycle, manager, plan, canonical
composition, and gateway tests plus 9/9 pinned Docker manager/runtime tests at
`.tmp/rhad-published-frontier-runtime.txt`. Both commits pass ast-grep,
import-cycle analysis, the portable-shape gate, and all 14 import-linter
contracts.

The mandatory exact cache-disabled A560 canary completed normally in 33.80
seconds with no process segfault, numeric `INTERR`, or verifier-failure event.
Log: `.tmp/rhad-a560-v33-published-frontier-v1.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-published-frontier-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
planner trace:
`.tmp/a560-published-frontier-trace-v1/composition-trace.json`. The semantic
oracle still rejects the false `while ( 1 )`, so this is not A560 acceptance.

The DB proves the new authority moves the canonical frontier past the prior
`0x40AE3E` CALLS boundary. Generation 1 commits its 260/260 normalization
transaction, then the first canonical attempt reaches the unresolved native
router path, promotes contextual source `0x40B790`, and requests one controlled
generated-MBA restart. Generation 2 commits a 288/288 normalization
transaction. No canonical semantic transaction, detached route comparison, or
semantic receipt follows.

The highest current v3.3 canary level is therefore C2. The first failed C3
obligation is recorded in `fact_consumers` at CALLS snapshot 11 as
`published_boundary_semantic_route_missing` for native router `0x40B6C0`.
Native bytes prove `0x40B6C0` is dispatcher selection topology: it compares the
state carrier, selects a table address, and flows through indirect transfer
`0x40B6D4`. Do not relabel that raw conditional as a closed published frontier.
Continue by recovering or composing its exact semantic route authority, keep
both arms atomic, and rerun the same diagnostic canary without broadening to
the 91-route publication.

**2026-07-25T11:10:55Z**

Commits `b8378a475` and `e0d66f4c7` add and separately format one exact
call-backed state-route proof. Frontend-normalized state-route discovery may
now cross a native call only when one unique `static_handler_exit_route`
matches the original indirect transfer, source block, state register, state
constant, semantic target, and complete dispatcher envelope. The portable
fact records the original transfer authority and every preserved call head;
ordinary routes cannot populate either field. No compatibility path or raw
router promotion was added.

Focused verification is 161/161 local portable-evidence, lifecycle, and
diagnostic-publication tests plus 11/11 pinned-Docker state-route resolver
tests. Changed production and unit files pass Ruff check, all seven changed
files pass Ruff format, and both commits pass ast-grep, import-cycle analysis,
the portable-shape gate, and all 14 import-linter contracts.

The mandatory exact cache-disabled A560 canary completed normally in 32.27
seconds with no process crash, numeric `INTERR`, or verifier event. Log:
`.tmp/rhad-a560-v33-call-backed-route-v1.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-call-backed-route-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-call-backed-route-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The eight-line pseudocode still contains the false `while ( 1 )`, so this is
not A560 acceptance.

The DB proves the intended route-level fact advanced even though the C level
did not. The state-write-route inventory increased from 89 to 90 and now
contains source write `0x40B469`, normalized delivery `0x40B4BA`, authority
transfer `0x40B4C3`, preserved call `0x40B49E`, state `0xBD9A2C2A`, and target
`0x40C592`. Generation 1 commits its 260/260 frontend transaction; generation
2 commits 288/288. There is still no canonical semantic transaction, detached
oracle comparison, or semantic publication receipt.

Production therefore remains at C2. The first failed C3 obligation remains
CALLS-native router `0x40B6C0`: nested projection sees the new
`state_assignment@0x40B4BA:0xBD9A2C2A` proof but records
`source_not_in_component`, then reports
`published_boundary_semantic_route_missing` at `0x40B6C0`. This rejects the
hypothesis that target recovery alone was the blocker. Continue by proving
the detached call corridor from state write `0x40B469` through call
`0x40B49E` to normalized delivery `0x40B4BA` belongs to the selected component
and carries exact call-fallthrough ownership. Do not relabel router
`0x40B6C0`, weaken component closure, or expand another route group until that
specific ownership obligation is resolved.

**2026-07-25T11:39:23Z**

Commits `d99f1e089`, `54dc4701d`, and `44b87212c` complete and separately
format the typed call-backed-corridor staging slice. Canonical state-write
proofs now preserve the exact authority transfer and ordered call corridor,
reject inconsistent ownership, and require the matching imported call and
delivery blocks plus their exact `CALL_FALLTHROUGH` edge whenever such a
proof is projected. The follow-up evidence fix keeps the authority transfer
inside the portable delivery region instead of incorrectly requiring it to
fit the deliberately one-EA delivery anchor identity. No compatibility path,
architecture ignore, or broad route publication was added.

Focused local verification is 232/232, the pinned Docker resolver suite is
279/279, and the existing real detached C5 oracle is 1/1. Repository-wide
Ruff formatting was retained in the separate `54dc4701d` commit as explicitly
authorized. All three commits pass ast-grep, import-cycle analysis, the
portable-shape gate, and all 14 import-linter contracts.

Two mandatory exact cache-disabled A560 canaries completed normally without a
process crash, numeric `INTERR`, or verifier event. The first, at
`.tmp/rhad-a560-v33-call-corridor-v1.txt`, exposed an evidence-construction
regression caused by the too-narrow identity invariant; `44b87212c` repairs
that contract. The current canary completed in 31.99 seconds. Log:
`.tmp/rhad-a560-v33-call-corridor-v2.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-call-corridor-v2/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-call-corridor-v2/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects the false `while ( 1 )`, so this is not
A560 acceptance.

The current DB records committed generation-1 and generation-2 frontend
transactions at 260/260 and 288/288 operations, respectively, but no canonical
semantic transaction, detached oracle comparison, or semantic C5 receipt.
Production therefore remains at C2. At CALLS snapshots 3 and 11, the exact
call-backed proof `state_assignment@0x40B4BA:0xBD9A2C2A` remains
`source_not_in_component`, with empty source and corridor block sets. The
first failed C3 obligation remains
`published_boundary_semantic_route_missing` at native router `0x40B6C0`.

The complete generation-2 frontend plan does contain call block
`native[0x40B3FF-0x40B4A4;exact=0x40B3FF]:imported`, delivery block
`native[0x40B4A4-0x40B4C5;exact=0x40B4A4,0x40B4B4,0x40B4BA]:imported`, their
`native-body-edge@0x40B3FF` call fallthrough, and normalized indirect transfer
`native-indirect-transfer@0x40B4C3`. The diagnostic transaction JSON is only
the selected publication work item, not that complete authority plan. The
actual connectivity defect is that `0x40B3FF` is one of 325 disconnected
native-body entry blocks and has no incoming operation edge. Forward component
traversal therefore cannot reach it merely because it is marked required.

This rejects the narrower required-staging hypothesis without invalidating the
typed proof or corridor validation. Continue at the bounded entry-connectivity
obligation: compose the smallest semantic-predecessor closure that connects a
selected root to handler entry `0x40B3FF`, then stage its call-backed route and
target as one closed detached fragment. Do not add all 325 entries, stage all
91 routes, or treat successful mutation calls as semantic publication. Before
changing closure behavior, make the diagnostic DB record each route-level
composition attempt and the exact entry-connectivity rejection so later
canaries do not collapse the evidence into one final rejection.

**2026-07-25T11:50:43Z**

Commits `18f57faf3` and `2625babb8` complete and separately format the
canonical-composition diagnostic ledger. Every route, boundary,
semantic-predecessor, and temporary-port composition attempt is now carried in
the typed final rejection and expanded by the runtime into one independently
queryable `fact_consumers` row. Each row records stable native route IDs and EA
anchors, outcome, reason, rejection payload, and accepted plan inventory. The
final composition summary remains compact. No semantic acceptance, fallback,
compatibility path, or schema-specific runtime dependency was added.

Focused verification is 47/47 portable canonical-composition tests and 65/65
pinned-Docker bounded-rerun runtime tests. The red runtime contract first
proved that only one summary row was persisted; the green contract proves two
attempt rows plus the compact summary. Repository-wide Ruff formatting is
clean, and both commits pass ast-grep, import-cycle analysis, the portable-shape
gate, and all 14 import-linter contracts.

The mandatory exact cache-disabled A560 canary completed normally in 32.51
seconds with no process crash, numeric `INTERR`, or verifier event. Log:
`.tmp/rhad-a560-v33-composition-ledger-v1.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-composition-ledger-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-composition-ledger-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects the same false `while ( 1 )`, so this is not
A560 acceptance.

The DB now contains 90 route-attempt rows plus one boundary-attempt row at each
of CALLS snapshots 3 and 11. Generation 1 and generation 2 frontend
transactions remain committed at 260/260 and 288/288 operations. There is no
canonical semantic transaction, detached oracle comparison, or semantic C5
receipt, so production remains at C2.

The ledger corrects the ordering of the next obligation. The exact call-backed
route `state_assignment@0x40B4BA:0xBD9A2C2A` is attempted as route index 31 at
both snapshots and first rejects with
`normalization_plan_owner_count_mismatch`: native delivery `0x40B4BA` has zero
eligible canonical route-source owners. The complete frontend plan does own
that EA, but in imported block
`native[0x40B4A4-0x40B4C5;exact=0x40B4A4,0x40B4B4,0x40B4BA]:imported`, while a
top-level canonical route source is intentionally required to be an external,
already-published owner. Relaxing that role check would expose a disconnected
imported root and is not the fix.

The disconnected handler-entry finding therefore remains valid but is now
properly downstream: handler entry `0x40B3FF` needs a bounded semantic
predecessor closure before `0x40B4BA` can be projected inside an
entry-connectable component. Continue by deriving the shortest proof chain
from an eligible published root through one route targeting `0x40B3FF`, then
include only that handler's call corridor and semantic target. The next red
contract must prove this closure remains bounded and fragment-atomic; do not
permit imported sources as independent publication roots or broaden to all 90
route attempts.

**2026-07-25T12:11:55Z**

Commits `1e7b9a473` and `8048d416c` recover and separately format the one
missing frontend-normalized state-write route. Route discovery now decodes
only the original prefix through the proven condition producer, requires its
end to equal the normalization start, and joins that prefix to the detached
plan's synthetic delivery. It never treats the original superseded select
tail as semantic instruction heads. The portable evidence is source write
`0x40ADF2`, condition producer `0x40ADF7`, synthetic delivery `0x40AE09`,
state `0xF6A636EF`, and target `0x40C4B4`. No A560 address is hard-coded in
production, no imported source is promoted to an independent publication
root, and no compatibility path was added.

This checkpoint corrects the final diagnosis recorded in `f22210f33`. The
diagnostic composition ledger proves the call-backed route
`state_assignment@0x40B4BA:0xBD9A2C2A` is already projected in the
entry-connected root component together with native call entry `0x40B3FF`.
Its rejection as an independent top-level root is expected ownership
enforcement, not a missing predecessor closure. The actual next missing
semantic fact was the frontend-normalized route at source write `0x40ADF2`.

The authoritative Docker resolver gate is 284/284 green: 247 resolver tests
plus 37 session-state tests. The increase from the prior 279 count is exactly
the five new corridor cases. Repository-wide Ruff formatting is clean and
was retained in the separate `8048d416c` commit. Both commits pass ast-grep,
import-cycle analysis, the portable-shape gate, and all 14 import-linter
contracts.

The mandatory cache-disabled A560 canary completed normally in 13.11 seconds
without a process crash, numeric `INTERR`, or verifier event. Log:
`.tmp/rhad-a560-v33-virtual-normalized-route-v1.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-virtual-normalized-route-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-virtual-normalized-route-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects the same false `while ( 1 )`, so this is not
A560 acceptance.

The DB confirms the route inventory advanced from 90 to 91. Snapshot 1 owns
`state_write_route:generation=1:revision=1:proof=424e1a1ff8c81f61b757`
with corridor `0x40ADF2, 0x40ADF7, 0x40AE09`, state `0xF6A636EF`, target
`0x40C4B4`, and direct-target delivery. Event 147 records
`canonical_semantic_plan_ready`; event 160 records a 396-item publication
plan; event 161 records its atomic abort. There are zero semantic route-oracle
comparisons and no semantic C5 receipt.

Production therefore advances from C2 to C3. The first failed C4 obligation
is exact detached-template ownership: the canonical native body requires
exactly one PREOPT union template but observes zero, raising
`SemanticFragmentBackendRejected` and recording
`canonical_pipeline_exception`. Continue at that one template-binding
failure. Do not weaken the exactly-one invariant, publish an unresolved union,
fall back to live copy-and-swap repair, or add backward compatibility.

**2026-07-25T12:54:52Z**

Commits `ebdb1eadc` and `d81439152` correct the C4 template diagnosis and keep
repository-wide Ruff formatting separate. The canonical direct route at
synthetic delivery `0x40AE09` now retains its superseded computed-branch
normalization plus the exact relocatable native tail at `0x40AE0C`,
`0x40AE0E`, `0x40AE12`, and `0x40AE16`. Detached preflight proves the original
split conditional, unique join ownership, complete contiguous relocation
inventory, exact byte-span equivalence, portable operands, and delivery
extent before staging the preserved prefix, relocated side effects, and one
semantic `goto`. Omitting one relocation head rejects before staging. This
supersedes the prior claim that the PREOPT template was absent: the template
existed, but canonical replacement had discarded the source normalization and
relocation envelope needed to bind it.

Verification is 584/584 affected unit/runtime tests plus 95/95 semantic
fragment backend tests. The authoritative Docker resolver gate is 285/285
green, increasing by exactly the native-tail inventory contract. Ruff format,
ast-grep, import-cycle analysis, the portable-shape gate, all 14 import
contracts, diff checks, and `graphify update .` pass.

The mandatory cache-disabled A560 canary completed normally in 18.37 seconds
without a process crash, numeric `INTERR`, or verifier event. Log:
`.tmp/rhad-a560-v33-split-normalized-tail-v1.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-split-normalized-tail-v1/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-split-normalized-tail-v1/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The DB records a committed 260-operation frontend-normalization transaction,
639/639 passing prepublication outcomes, 1180/1180 passing postpublication
outcomes, and receipt-backed binding of 93 imported blocks. Canonical
composition does not record a plan, detached oracle comparison, or semantic
receipt. Main-path A560 therefore reaches C2, not C3. The first failed
obligation is the CALLS fact-consumer rejection
`canonical_pipeline:0x40A560 / fragment_plan_rejected`: `fragment superseded
normalization requires its predicate anchor`. The transport added for
computed normalization copied a raw predicate anchor even when the replaced
operation used another predicate materialization and had no computed
normalization. Continue by pairing that temporary anchor only with an actual
computed normalization; do not weaken the pair invariant, discard relocation
evidence, broaden publication, or add compatibility behavior.

**2026-07-25T13:03:03Z**

Commit `314e7dddc` completes that narrow pair-invariant repair. A parameterized
runtime contract now proves a temporary superseded predicate anchor is copied
only when the replaced raw operation actually owns computed-branch
normalization; a plain conditional keeps neither field. The 80 affected
canonical/fragment-plan tests, Ruff checks, ast-grep, all 14 import contracts,
`graphify update .`, and pre-commit gates pass.

The mandatory cache-disabled A560 canary then completed normally in 23.47
seconds without a process crash, numeric `INTERR`, or verifier event. Log:
`.tmp/rhad-a560-v33-split-normalized-tail-v2.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-split-normalized-tail-v2/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-split-normalized-tail-v2/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The diagnostic DB proves the prior C2 failure is cleared. Both frontend passes
commit their 260-operation normalization transaction, all 1278 prepublication
and 2360 postpublication validations pass, and both canonical passes build the
same 396-operation plan. The first pass atomically aborts to request CALLS
companion evidence. Of 22 requested native components, 21 capture on the
controlled restart. The second canonical pass again aborts before staging
because native range `[0x40B3FF, 0x40B4E2)` still lacks analyzed companion
authority. There is no canonical staging, detached-oracle comparison, or C5
receipt. Main-path A560 therefore advances to C3; the first failed C4 obligation
is exact CALLS companion ownership for that one range.

Event 175 records the decisive mismatch: pristine PREOPT owns call
`0x40B49E`, while detached CALLS observes `0x40B49E` plus `0x40B4C3` and reports
`call_ea_set_mismatch` at `0x40B4C3`. Native disassembly proves `0x40B49E` is
`call dword ptr [0x42E224]`, whereas `0x40B4C3` is the component's terminal
`jmp eax`. CALLS has therefore classified a native indirect resolver exit as a
call-like microinstruction; it is not a second native call. Continue by proving
the portable resolver-cut ownership of exactly that extra CALLS instruction and
excluding only such proven maturity-derived exits from companion comparison.
Do not generally tolerate extra CALLS calls or weaken exact matching for the
genuine PREOPT call inventory.

**2026-07-25T13:12:45Z**

Commit `97c5a96d6` completes the interior resolver-cut CALLS slice. Detached
CALLS preparation now subtracts only a STOP block's proven terminal instruction
extent when every outgoing edge is an indirect `resolver_proven_native_cut`
with a target and the same source-instruction EA. This supports interior cuts
without tolerating extra CALLS calls or changing pristine PREOPT inventory
authority. The red interior-cut contract now passes, as do 286/286 focused
resolver/session tests, 9/9 companion and diagnostic-event contracts, the
authoritative 286/286 Docker resolver gate, Ruff, ast-grep, all 14 import
contracts, diff checks, `graphify update .`, and pre-commit gates.

The mandatory cache-disabled A560 canary completed normally in 19.97 seconds
without a process crash, numeric `INTERR`, or verifier event. Log:
`.tmp/rhad-a560-v33-interior-companion-cut-v3.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-interior-companion-cut-v3/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-interior-companion-cut-v3/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The DB proves the prior CALLS companion obligation is cleared. All 22 requested
components capture on the controlled restart. Event 175 records native range
`[0x40B3FF,0x40B4E2)`, exact PREOPT/CALLS call inventory `0x40B49E`, and the
two generated CALLS ranges `[0x40B3FF,0x40B4C3)` and
`[0x40B4C5,0x40B4E2)`, excluding only native resolver cut `0x40B4C3` through
its decoded end `0x40B4C5`.

Both frontend passes commit their 260-operation transaction, and both canonical
passes build the same 396-operation plan. The second canonical transaction now
advances past companion preparation and atomically aborts before staging at the
next detached proof. There is still no route-oracle comparison or semantic C5
receipt. Main-path A560 remains at C3; the first failed C4 obligation is
`detached_split_direct_corridor_mismatch` for
`route:state_assignment@0x40A72E:0x7C4FB03D`, specifically
`imported_envelope_owned`.

The canonical operation retains source write `0x40A723`, condition producer
`0x40A728`, rewrite/normalization start `0x40A72E`, unresolved transfer
`0x40A73D`, delivery region `[0x40A72E,0x40A73F)`, and proof corridor
`0x40A723,0x40A728,0x40A72E`, but its relocated-instruction inventory is empty.
Native disassembly shows the delivery sequence is `mov` at `0x40A72E`, `lea`
at `0x40A730`, `cmovl` at `0x40A736`, `mov` at `0x40A739`, `add` at
`0x40A73B`, and `jmp eax` at `0x40A73D`. Continue by proving why this
non-split normalization retained no relocation inventory and why the detached
template has zero unique join owners; do not synthesize an envelope, weaken
exact ownership, or broaden publication.

**2026-07-25T13:24:31Z**

Commit `9aa5158f3` clears the zero-length normalized-tail obligation without
weakening relocated-tail ownership. Detached preflight still proves the full
split conditional-select topology, exact zero source-to-predicate size, empty
relocation inventory, proof corridor, synthetic cut, and delivery extent; it
requires a portable imported join identity exactly when instructions will be
copied from that join. A paired contract proves the zero-length case succeeds
while a nonempty unowned relocation still rejects before staging. The complete
affected suite is 683/683 green, with Ruff format/check, ast-grep, all 14 import
contracts, diff checks, `graphify update .`, and pre-commit gates passing.

The mandatory cache-disabled A560 canary completed normally in 21.44 seconds
without a process crash, numeric `INTERR`, or verifier event. Log:
`.tmp/rhad-a560-v33-zero-length-normalized-tail-v4.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-zero-length-normalized-tail-v4/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-zero-length-normalized-tail-v4/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The DB proves `route:state_assignment@0x40A72E:0x7C4FB03D` now passes its
detached preflight and advances the first failure to the intentionally protected
relocated-tail route `route:state_assignment@0x40AE09:0xF6A636EF`. All 22 CALLS
companions still capture, both frontend 260-operation transactions commit, and
both 396-operation canonical plans are produced. The second canonical
transaction aborts before staging with no route-oracle comparison or semantic
C5 receipt. Main-path A560 remains at C3; the first failed C4 obligations are
`imported_envelope_owned` and `relocated_inventory_complete` at `0x40AE09`.

The canonical operation owns source write `0x40ADF2`, condition producer
`0x40ADF7`, normalization start `0x40ADFD`, predicate/rewrite `0x40AE09`,
relocations `0x40AE0C,0x40AE0E,0x40AE12,0x40AE16`, unresolved transfer
`0x40AE18`, and delivery region `[0x40ADFD,0x40AE1A)`. Crucially, its serialized
`source_computed_branch_normalization.conditional_select_envelope` is null.
The zero join matches are therefore caused by missing portable envelope
evidence, not permission to copy the four instructions without ownership.
Continue by finding why imported conditional-select discovery did not attach
the selected-value and join identities for this proof; do not relax the
nonempty-relocation gate or infer an envelope inside the mutation backend.

**2026-07-25T13:53:03Z**

Commits `cc2c9327d` and `43ff2cf34` complete the same-native-block
conditional-select ownership slice while keeping repository-wide Ruff
formatting separate. Resolver replay now retains original CMOV select and join
coordinates, portable frontend evidence validates the complete pair, and the
frontend planner constructs one explicit selected/join suffix partition only
when the native STOP block owns a complete two-target
`resolver_proven_native_cut`. The fragment contract admits that narrowly
specified nested suffix without weakening the existing wider-overlap
rejection. The affected portable-evidence, resolver, frontend, and fragment
suites are 373/373 green. Ruff format/check, ast-grep, all 14 worktree-local
import contracts, `graphify update .`, diff checks, and both pre-commit gates
pass.

The mandatory cache-disabled A560 Docker canary completed in 22.74 seconds.
Log: `.tmp/rhad-a560-v33-same-block-select-v5.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-same-block-select-v5/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-same-block-select-v5/test_real_loader_matches_reach0/sub_40A560.c`.
The worker completed without a process segfault, but the semantic oracle still
rejects one false `while ( 1 )`, so this is not A560 acceptance.

The diagnostic DB proves the prior `0x40AE09` envelope and relocation failures
are cleared. Its canonical operation now records selected range
`[0x40AE05,0x40AE08)`, join range `[0x40AE08,0x40AE1A)`, relocations
`0x40AE0C,0x40AE0E,0x40AE12,0x40AE16`, and unresolved transfer `0x40AE18`.
The canonical fragment stages, all 1009 prepublication outcomes pass, and the
receipt records 393/396 applied operations. Main-path A560 remains at C3
because C4 requires a passing detached reference-oracle comparison. The first
failed C4 obligation is now exactly `detached route oracle requires one pinned
reference run`; no route comparison is recorded and live root publication is
not attempted.

Cleanup after that intentional prepublication rejection exposes a separate
hard rollback defect. The transaction records `fragment_staged`, then rollback
verification raises numeric `INTERR 51328`, so rollback is reported failed.
The live IDA MCP confirms Hex-Rays `9.3.0.260213`, matching the diagnostic
native key. Hex-Rays SDK `verifier/verify.cpp` maps `51328` to a `BLT_STOP`
exit block with dirty use-def lists after `callinfo_built()`. The likely exact
path is `_detach_semantic_fragment_block`: removing a staged block's edge into
the published stop block unconditionally calls `stop.mark_lists_dirty()`.
Continue with a red runtime contract for a staged successor edge into a
calls-built STOP block and make rollback verifier-clean before establishing the
pinned reference run. Do not skip rollback verification, dirty the STOP block,
publish without the oracle, or classify this numeric INTERR as a segfault.

**2026-07-25T14:00:01Z**

Commit `f7b017bb2` makes staged-fragment rollback verifier-clean without
weakening use-def invalidation for ordinary successors. Detaching a staged
block now removes its predecessor metadata from a published `BLT_STOP` block
without calling `mark_lists_dirty()` on that stop; all non-stop successors keep
the prior invalidation behavior. The focused rollback contracts and the full
semantic-fragment backend suite are 95/95 green, with Ruff, ast-grep, all 14
import contracts, diff checks, `graphify update .`, and pre-commit gates
passing.

The mandatory cache-disabled A560 Docker canary completed normally in 28.66
seconds. Log: `.tmp/rhad-a560-v33-stop-use-def-v6.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-stop-use-def-v6/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-stop-use-def-v6/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The diagnostic DB records the latest canonical transaction as intentionally
aborted before root publication: the fragment staged, all 1009/1009
prepublication outcomes passed, 393/396 planned operations applied to the
detached graph, rollback succeeded, and no verifier failure was recorded. No
detached route-oracle comparison ran and no root publication was attempted.
Main-path A560 therefore remains at C3. The first failed C4 obligation remains
exactly `detached route oracle requires one pinned reference run`.

Continue with the v3.3 vertical loop by establishing one pinned reference run
for one complete route fragment, proving its detached equivalence, and
publishing only that fragment through C5 before attempting the broad 91-route
composition. Do not interpret the clean rollback as semantic acceptance or
bypass the pinned oracle gate.

**2026-07-25T14:29:23Z**

Commit `649358fdb` makes the publication root part of the exact-input reference
authority with schema 2 and no compatibility path. Canonical composition now
consults that complete configured scope before an otherwise successful generic
entry-root plan, and the binder requires the detached plan's sole root anchor
to equal the selected publication root. The affected local suite is 59/59
green; Ruff format/check, ast-grep, all 14 import contracts, diff checks, and
`graphify update .` pass.

The existing real one-route C5 vertical remains green after commit
`f381ad0f5` corrected its synthetic manifest to declare the plan's actual
delivery root `0x40C7F6`. Docker log:
`.tmp/rhad-a560-c5-pinned-root-v8.txt`; primary schema-8 DB:
`.tmp/rhad-a560-c5-pinned-root-v8/test_real_a560_terminal_fragme0/real-terminal-fragment.diag.sqlite3`.
The DB records one matched reference comparison for
`0x40C7F6 -> 0x40C898`, 32/32 prepublication checks, one successful root
publication, 59/59 postpublication checks, and a committed receipt with no
rollback. This preserves the required complete C5 vertical without broad
publication.

The mandatory full cache-disabled A560 canary then completed normally in
19.11 seconds without a process crash, numeric `INTERR`, or verifier failure.
Log: `.tmp/rhad-a560-v33-pinned-root-v7.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-pinned-root-v7/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-pinned-root-v7/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The DB proves configured authority is now selected, but the new fast path
stops at `published_boundary_predecessor_missing@0x40AE3E` before producing a
canonical plan. The sole incoming edge is the prohibited dispatcher-side
`blk47@0x40A560`, whose stable native identity is anchored at `0x40AE2E` over
range `[0x40AE26,0x40AE3E)`. Only the earlier 260/260 frontend-normalization
transaction commits; there is no semantic transaction, detached-oracle
comparison, or semantic receipt. Main-path A560 therefore reaches C2, and its
first failed obligation is C3 entry connection for the exact configured
boundary.

This is a control-flow regression in configured-scope selection, not new Rhad
semantics and not evidence that the pinned root is wrong. The ticket already
proves `0x40AE3E` is the only live root and must use the typed temporary
dispatcher-entry port whose stable retirement obligation is semantic
predecessor `0x40B51B`. Continue by routing the configured exact scope through
that existing evidence-backed port path, then bind all six selected routes and
rerun the mandatory A560 DB canary. Do not admit the prohibited edge as
reference topology, lose the retirement obligation, or fall back to the broad
396-operation entry-root plan.

**2026-07-25T14:44:03Z**

Commits `c59390351` and `a5afc0299` restore the previously proved typed
temporary-port path for an exact configured reference scope and keep the
requested Ruff formatting mechanical and separate. The configured root first
rejects its prohibited live predecessor, the sole selected reference route
entering that root identifies semantic predecessor `0x40B51B`, and the port is
admitted only after canonical composition proves that predecessor and its
incoming normalization source have no live owner. The stable retirement
obligation remains explicit. The affected portable, validation, gateway, and
runtime suite is 164/164 green; changed-file Ruff, ast-grep, all 14 import
contracts, diff checks, `graphify update .`, and pre-commit gates pass.

The mandatory full cache-disabled A560 canary completed normally in 18.48
seconds without a process crash, numeric `INTERR`, or verifier failure. Log:
`.tmp/rhad-a560-v33-pinned-port-v8.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-pinned-port-v8/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-pinned-port-v8/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The DB proves the intended bounded plan is restored and broad publication is
suppressed. Plan
`canonical-boundary-composition:canonical-semantic:g1:0x40AE3E` carries the
exact pinned run, six direct reference routes, ten canonical operations, and
one `temporary_dispatcher_entry` port from the external native identity
anchored at `0x40AE2E` to root `0x40AE3E`; its retirement obligation remains
`publish-semantic-predecessor@0x40B51B`. The gateway budgets 31 mutations, not
396. The first attempt aborts cleanly before staging to request CALLS companion
`0x40AA30`; after redo, the fragment stages with 29/31 applied mutations and
passes every recorded prepublication invariant except one. Rollback succeeds
in both attempts.

Main-path A560 is back at C3. The first failed C4 obligation is exactly
`root_reachability:published-boundary@0x40AE3E:replacement`: the projected root
is unreachable from ordinary function entry, so validation stops before the
detached reference comparison and live root publication. This is the missing
semantic integration of the already-serialized boundary port: plan validation
understands the typed port, but projected reachability does not yet use it as
temporary publication authority. Continue with the red validator contract that
requires predecessor-to-root reachability through that exact port, includes
the retirement obligation in the outcome, and leaves ordinary disconnected
roots rejected. Do not exempt arbitrary unreachable roots or erase the
obligation.

**2026-07-25T14:50:40Z**

Commits `70f4da05a` and `30ad111e7` make the typed temporary boundary port real
validation authority while keeping Ruff formatting separate. A port satisfies
root reachability only through its exact predecessor-to-root edge or one
registered physical root-fallthrough helper; arbitrary transitive paths remain
invalid. Published connectivity, original supersession, and dispatcher absence
are checked from function entry plus those exact temporary authorities, and the
positive diagnostic outcome retains the stable retirement obligation. The
affected validation, plan, oracle, gateway, canonical, resolver, and runtime
suite is 157/157 green; changed-file Ruff, repository-wide Ruff format,
ast-grep, all 14 import contracts, diff checks, `graphify update .`, and
pre-commit gates pass.

The mandatory full cache-disabled A560 canary completed normally in 23.02
seconds without a process crash, numeric `INTERR`, or verifier failure. Log:
`.tmp/rhad-a560-v33-port-reach-v9.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-port-reach-v9/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-port-reach-v9/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The DB proves the root-reachability failure is cleared. After the expected
CALLS companion request and redo, the bounded 31-mutation transaction stages
29 operations and passes all 84/84 prepublication validation outcomes. It then
records all six pinned route comparisons before rolling back cleanly. Every
comparison has the same and only divergence:
`reachable_from_entry oracle=True candidate=False`; transfer kind, rewrite
anchor, owner, target, and staged route shape otherwise match. The first
divergence is the route anchored at `0x40AA4F`; the other five anchors are
`0x40AE7A`, `0x40AB64`, `0x40B52E`, `0x40C341`, and `0x40C7F6`. No root
publication is attempted.

Main-path A560 therefore remains at C3, with a narrower first C4 obligation:
detached oracle reachability must use the same exact validated publication
authority as fragment validation. Normalize literal function entry plus only
validated typed-port predecessors when computing candidate route reachability,
and keep the port plus retirement obligation in the plan/DB as the explanation
for that normalization. Do not mark every disconnected staged block reachable,
weaken route-shape comparison, or skip the six-route oracle.

**2026-07-25T15:00:56Z**

Commit `cb5cb0f83` makes detached-oracle reachability consume the same pure
publication-authority normalization as fragment validation. The literal
function entry remains authority, and a temporary boundary predecessor is
added only when the projected predecessor-to-root edge or registered
fallthrough helper exactly witnesses the typed port. The negative contract
still rejects a disconnected route without that port. The affected portable
and runtime suite is 186/186 green; changed-file Ruff, repository-wide Ruff
format, ast-grep, all 14 import contracts, diff checks, `graphify update .`,
and pre-commit gates pass. Repository-wide Ruff formatting changed none of the
1,865 files, so no empty style commit was created.

The mandatory full cache-disabled A560 canary completed normally in 19.05
seconds without a process crash, numeric `INTERR`, verifier failure, or
diagnostic-write error. Log: `.tmp/rhad-a560-v33-oracle-port-v10.txt`; primary
schema-8 DB:
`.tmp/rhad-a560-v33-oracle-port-v10/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-oracle-port-v10/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle still rejects one false `while ( 1 )`, so this is not A560
acceptance.

The DB proves C4 is now complete for the bounded six-route fragment. After the
expected CALLS companion request and redo, all 84/84 prepublication validation
outcomes pass and all six detached route comparisons match at anchors
`0x40AA4F`, `0x40AE7A`, `0x40AB64`, `0x40B52E`, `0x40C341`, and `0x40C7F6`.
The 31-operation transaction stages 29 operations, then aborts during root
preparation before any publication write; rollback succeeds.

Main-path A560 has therefore reached C4. The first failed C5 obligation is
exact ownership of the typed publication predecessor anchored at `0x40AE2E`
for root `0x40AE3E`: the live backend reports that the predecessor is not owned
by exactly one fragment binding. Continue by making root preparation consume
the already-pinned inventory/port owner and prove that its live version is the
captured predecessor, while retaining rejection for physical-version aliases.
Do not weaken ownership to arbitrary serial matching, publish on ambiguity, or
skip the prepublication and route-oracle proofs that are now green.

**2026-07-25T15:13:52Z**

Commits `56c53862b` and `71709ec5f` make conditional publication ownership
fragment-atomic and keep the requested Ruff formatting separate. Canonical
boundary composition now owns the untouched sibling of each two-way incoming
root predecessor as a portable external block and rejects an incomplete
conditional envelope before live staging. The backend's exact-one-binding and
physical-version-alias guards remain unchanged. The full canonical composer
and semantic backend suite is 135/135 green; Ruff lint, repository-wide Ruff
format, architecture pre-commit gates, and `graphify update .` pass.

The mandatory cache-disabled A560 canary completed normally without a process
crash, numeric `INTERR`, verifier failure, or diagnostic-write error. Log:
`.tmp/rhad-a560-v33-owned-sibling-v11.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-owned-sibling-v11/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-owned-sibling-v11/test_real_loader_matches_reach0/sub_40A560.c`.
The output is still only the initial `memset` followed by one false
`while ( 1 )`, so A560 remains semantically red.

The DB records the first successful main-path C5 transaction mechanics for the
bounded six-route fragment: all six detached comparisons match, 85/85
prepublication checks pass, the conditional-fallthrough publication group
anchored at `0x40AE2E` publishes root `0x40AE3E`, 159/159 postpublication
checks pass, and the 31/31 receipt commits without rollback. This clears the
previous binding-ownership failure.

That committed receipt is not yet the strategy's complete entry-connectable
C5 gate. A recursive reachability query over postpublication snapshot 15 finds
only four blocks reachable from literal function entry:
`blk0@0x40A560 -> blk1@0x40A560 -> blk2@0x40A5F0 -> blk34@0x40A560`, with the
last block self-looping. The newly published semantic fragment is physically
present but unreachable from function entry. The validator treated the typed
temporary port as provisional publication authority, so its positive
postvalidation does not prove the v3.3 entry-connectability obligation.

Record the highest mechanical canary as C5, but keep the architecture gate
open at C5 entry reachability and C6 semantic output. The next vertical slice
must select or compose the smallest actual entry-connected reference-route
group, publish it through the same detached proof path, and make literal-entry
postpublication reachability queryable in the DB. Do not broaden to all 91
immediate routes merely because one provisional-port receipt committed.

**2026-07-25T15:31:11Z**

Commits `bacc80faf` and `f553a72f1` add the missing configured live-root
selection path and keep its repository-wide Ruff formatting separate. When a
configured reference scope contains exactly one route whose portable owner EA
is the configured publication root, the pass now requires one exact candidate
state route with the same state-write owner, rewrite anchor, and direct target;
it composes that connected route work item before considering detached-boundary
composition. Configured scopes with no route at the publication root retain the
existing boundary and temporary-port path. The lowering module is 10/10 green;
changed-file Ruff lint, repository-wide Ruff format, ast-grep, all 14 import
contracts, `graphify update .`, and both pre-commit runs pass.

The mandatory fresh cache-disabled A560 canary completed normally in 32.43
seconds without a process crash, numeric `INTERR`, verifier failure, or
diagnostic-write error. Log:
`.tmp/rhad-a560-v33-live-root-selector-v12.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-live-root-selector-v12/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-live-root-selector-v12/test_real_loader_matches_reach0/sub_40A560.c`.
The current manifest still selects the detached `0x40AE3E` group, so this run
is a regression guard for the new selector rather than an exercise of its live
route branch. The semantic oracle remains red on the same single false
`while ( 1 )`.

The diagnostic DB reproduces the prior bounded mechanics exactly. Transaction
`22ba9021abe842b49275e7561a3cc711` matches all six selected reference routes,
passes 85/85 prepublication and 159/159 postpublication checks, publishes the
conditional-fallthrough group anchored at `0x40AE2E`, and commits all 31/31
planned operations without rollback. At postpublication snapshot 15, however,
only four of 50 blocks are reachable from literal entry:
`blk0@0x40A560 -> blk1@0x40A560 -> blk2@0x40A5F0 -> blk34@0x40A560`, and
`blk34@0x40A560` self-loops at synthetic instruction EA `0xF1C006EC`. The
published cleanup/return component remains unreachable.

The highest mechanical canary therefore remains C5, while the first unmet
v3.3 obligation remains C5 literal-entry postpublication reachability; C6 is
still false. The next vertical slice is now pinned to the reference-proved
entry route owned at state write `0x40A5B2`, rewritten at `0x40A5C8`, and
targeting `0x40BECC`. Configure the smallest exact oracle scope for that live
root plus only the downstream direct rewrites required to close its detached
target component, then require C4 and literal-entry C5 before adding another
route group. Do not broaden to the 91 immediate routes or treat the provisional
`0x40AE3E` receipt as architecture acceptance.

**2026-07-25T15:52:30Z**

Commit `50969defa` replaces the six-route detached-boundary manifest with the
smallest reference-proved entry route: state-write owner `0x40A5B2`, rewrite
anchor `0x40A5C8`, state `0xABB95547`, and direct target `0x40BECC`. The
parser/manager suite is 25/25 green. The first exact canary with that manifest,
`.tmp/rhad-a560-v33-entry-root-v13.txt`, rejected while staging
`native-body-edge@0x40AE3E` because a CALLS-built imported block retained its
analyzed call, continuation, and stale synthetic `m_goto` in one
`BLT_1WAY`/zero-successor block. Its rollback then raised `INTERR 50856`, which
the matching SDK decodes at `verifier/verify.cpp:1082` as a block successor-set
size mismatch. The primary DB did not persist that semantic rejection or
verifier event, so the focused log and verifier artifact were required to
identify this observability defect.

Commit `d4c753e47` adds a focused imported-native CALLS regression and permits
the existing exact call/continuation splitter to accept transaction-local
`IMPORTED_NATIVE` provenance without a predecessor version. All call opcode,
analyzed-authority, native-EA ownership, continuation ownership, suffix, and
transaction checks remain unchanged. The new test first failed at the
lineage-only guard and then passed; the complete semantic-fragment backend is
96/96 green, changed-file Ruff lint passes, graphify is current, and all
pre-commit architecture gates pass. Repository-wide `pyenv exec ruff format
.` changed none of 1,865 files, so there is no style-only commit.

The mandatory fresh cache-disabled v14 A560 canary completed normally in
18.68 seconds. Output:
`.tmp/rhad-a560-v33-imported-call-split-v14.txt`; primary schema-8 DB:
`.tmp/rhad-a560-v33-imported-call-split-v14/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-imported-call-split-v14/test_real_loader_matches_reach0/sub_40A560.c`.
The worker returned normally, and the current DB contains no rollback,
verifier, or diagnostic-error event. The shared text log predates v14 by more
than six hours and its traceback line numbers match pre-`d4c753e47` source, so
it is explicitly not evidence for this canary.

The v14 DB proves that the imported-call slice advances staging: transaction
`7f68a211318d43bbb2f659161fdabdbc` stages and commits 260/260 mutations for a
102-block, 93-operation plan, with 639/639 prepublication and 1180/1180
postpublication outcomes passing and no rollback. However, that transaction
is still `frontend-normalization:0xA560:g1:root@0x40A5F0`, its publication
purpose is `frontend_normalization`, it names no prohibited dispatcher blocks,
and it contains no operation for the selected owner `0x40A5B2` or rewrite
anchor `0x40A5C8`. Both route-oracle tables contain zero comparisons. The
output remains only the initial `memset` followed by one false `while ( 1 )`.

Under v3.3 this is C2, not C5. The broad frontend-normalization receipt is
mechanically valid but does not satisfy canonical planning, detached proof, or
publication for the selected reference route. The first failed obligation is
C3: produce and persist the canonical one-route plan for owner `0x40A5B2`,
rewrite `0x40A5C8`, and target `0x40BECC`. Continue from the route selector or
its first rejection and make that decision visible in the diagnostic DB.
Require the detached route comparison before live publication; do not debug
the broad plan's downstream false loop, count its receipt as v3.3 C5, or add
another route group.

**2026-07-25T15:59:09Z — v14 correction and v3.3 pivot**

The unchanged v15 diagnostic rerun mounted fresh debug logs and confirms the
current `d4c753e47` source no longer reaches the imported-call rejection or
`INTERR 50856`. Output: `.tmp/rhad-a560-v33-entry-route-trace-v15.txt`;
primary DB:
`.tmp/rhad-a560-v33-entry-route-trace-v15/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The DB reproduces the same committed frontend-normalization receipt and red
`while ( 1 )` output as v14.

Correction: the DB does persist the later C3 decline, but in
`fact_consumers`, not the semantic-transaction tables queried for the v14
checkpoint. Its stable record is
`canonical_route:0x40A5B2` at `MMAT_CALLS`, reason
`canonical_configured_reference_scope_invalid`, with cause
`fragment and reference selection require exact rewrite anchors`. The accepted
composition-attempt record proves the one-route entry manifest is not one
small vertical fragment: selecting `state_assignment@0x40A5C8:0xABB95547`
also pulls downstream `state-choice@0x40BECC:0xEC71CA67:0xA0716E5B`, yielding
163 blocks and 150 operations before oracle binding rejects the incomplete
manifest.

Therefore the preceding instruction to continue expanding the `0x40A5B2`
entry plan is superseded. Adding all anchors required by that 150-operation
plan would repeat the broad-publication strategy that v3.3 forbids. Continue
with v3.3's prescribed first direct fixture instead: native owner `0x40BB51`,
delivery tail `0x40BB63`, and target `0x40ACF3`. Establish its exact isolated
reference shape and first candidate divergence, then build the smallest
detached rewrite and require its C4 oracle proof before any live publication.
The v14/v15 broad frontend receipt remains diagnostic evidence only and does
not raise the v3.3 canary above C2.

**2026-07-25T16:18:22Z — exact-corridor selector and first direct-fixture canary**

Commit `d3185d7ff` removes the obsolete assumption that a configured reference
owner EA must equal the candidate state-write EA. A direct candidate now
matches only when its complete write-to-delivery span equals the pinned
reference corridor and its rewrite anchor and direct target also agree
exactly. The focused positive fixture separates the owner, state write, and
rewrite coordinates; a companion test proves that matching rewrite and target
cannot conceal corridor drift. The canonical-lowering file is 12/12 green,
Ruff passes, Graphify is current, and both architecture gates pass.

Commit `4a56bc12d` replaces the superseded A560 entry-route manifest with the
single schema-2 v3.3 fixture proved by the reproducible differential-oracle
runs: native owner `0x40BB51`, state write `0x40BB44`, rewrite anchor
`0x40BB63`, corridor `[0x40BB44, 0x40BB69)`, and direct target `0x40ACF3`.
The manager, catalog, and canonical-lowering suites are 37/37 green. The old
manifest was removed rather than retained as compatibility. Repository-wide
`pyenv exec ruff format .` changed none of 1,865 files after either commit.

The mandatory fresh cache-disabled v16 A560 canary completed normally in
21.43 seconds without a crash, numeric INTERR, rollback, or diagnostic-write
failure. Output: `.tmp/rhad-a560-v33-direct-route-v16.txt`; primary schema-8
DB:
`.tmp/rhad-a560-v33-direct-route-v16/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode:
`.tmp/rhad-a560-v33-direct-route-v16/test_real_loader_matches_reach0/sub_40A560.c`.
The semantic oracle remains red on one false `while ( 1 )`.

The diagnostic DB proves the exact route is discovered and selected at
`MMAT_CALLS` as
`state_assignment@0x40BB63:0xE9795EF`. Canonical composition then rejects
before creating a route plan: `normalization_plan_owner_count_mismatch` at
stable route source `0x40BB63`, with zero normalization-plan owners. No
captured live snapshot contains `0x40BB44`, `0x40BB51`, `0x40BB63`, or target
`0x40ACF3`, so the configured fixture is disproved as a live-root route in the
current representation. The unrelated frontend-normalization transaction at
root `0x40A5F0` remains mechanically healthy: 260/260 operations commit, all
639 prepublication and 1,180 postpublication validations pass, and no rollback
occurs.

The v3.3 canary therefore remains C2. The first failed C3 obligation is to
give the selected detached fragment exactly one portable normalization-plan
owner for rewrite source `0x40BB63`, then apply the direct rewrite off-side and
persist its oracle comparison before any root publication. Do not weaken the
owner count, reinterpret `0x40BB51` as live, or extend the broad `0x40A5F0`
transaction. The next vertical slice must model the reference-owned
`0x40BB44`-`0x40BB69` corridor as detached normalization input and prove the
smallest closed component that contains it.

**2026-07-25T16:34:46Z — detached-intent retention and v17 checkpoint**

Commit `65a64679d` carries the exact configured reference route from session
authority through the live frontend adapter and manager into portable detached
normalization intent. The planner retains missing reference corridor starts,
the native owner and rewrite anchors, and direct or conditional targets as
required import roots. The selected live frontend work item remains unchanged;
these roots are complete-plan detached intent, not additional live publication
operations. Focused manager, pass, adapter, and planning tests are 92/92 green,
both architecture gates pass, and repository-wide formatting changed one test
assertion only, committed separately as `340e7aab5`.

The mandatory cache-disabled v17 A560 canary completed normally in 27.17
seconds without a crash, numeric INTERR, rollback, or diagnostic-write failure.
Output:
`.tmp/rhad-a560-v33-detached-intent-v17.txt`; primary diagnostic DB:
`.tmp/rhad-a560-v33-detached-intent-v17/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode is beside the DB. The semantic oracle remains red on one false
`while ( 1 )`.

The database still records the exact route selected at `MMAT_CALLS`, followed
by `normalization_plan_owner_count_mismatch` at stable rewrite source
`0x40BB63`, with zero owners. The unrelated live frontend transaction remains
exactly 260/260 committed operations rooted at `0x40A5F0`, with all 639
prepublication and 1,180 postpublication validations passing and no rollback.
This is expected because the live composer currently accepts only an
`EXTERNAL` source; it does not yet consume an `IMPORTED` source from complete
detached intent.

Do not claim that v17 proves the route owner was imported at runtime: schema-8
diagnostics persist the selected live work item but not the complete detached
normalization intent. The canary therefore remains C2 and the first failed
obligation remains C3. This is the first non-advancing runtime slice under the
v3.3 representation rule. The next slice must either make the complete intent
and imported route ownership queryable in the DB or produce the one-route
detached canonical plan from that imported source; another non-advancing slice
requires reconsidering the representation before further implementation.

**2026-07-25T16:55:29Z — portable owner split and authoritative v19 intent**

Commit `9cb375202` corrects the portable direct-rewrite contract derived from
the pinned fixture. It no longer conflates the evidence origin at `0x40BB44`
with the native operation owner at `0x40BB51`; the rewrite anchor remains
`0x40BB63`. The proof corridor must remain ordered and end at the rewrite, and
the operation owner must lie between the proof origin and rewrite anchor.
Forty-nine portable fragment and detached-oracle tests pass, with the
architecture gates green.

Commit `87335d2fc` records receipt-backed complete frontend-normalization
intent as a diagnostic lifecycle event, including the complete serial-free
plan. Commit `ddabb3ce8` contains only repository-wide Ruff formatting. The
first v18 canary exposed an invalid hook assumption: a partial work-item
receipt may have no fully published generation even though the current
evidence-generation plan authority is valid. That hook raised after the
successful PREOPT transaction, so v18 is not an accepted canary. Commit
`cf06358f4` keys the event from the active evidence generation and has 16/16
focused manager/adapter tests green.

The fresh cache-disabled v19 A560 canary completed normally in 26.04 seconds
without a crash, numeric INTERR, rollback, or diagnostic-write failure.
Output: `.tmp/rhad-a560-v33-plan-intent-v19.txt`; primary DB:
`.tmp/rhad-a560-v33-plan-intent-v19/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The semantic oracle remains red on one false `while ( 1 )`.

The new DB event is `frontend_normalization_plan_intent_recorded` at lifecycle
event 30. It records plan `frontend-normalization:0xA560:g1`: 487 blocks, 478
operations, 478 imported blocks, one native body, and a 792,096-byte complete
portable plan. The exact selected route topology is now authoritative:

- imported proof block `0x40BB3A` covers state write `0x40BB44`;
- imported source block `0x40BB51` covers rewrite `0x40BB63`;
- imported target block `0x40ACF3` covers target `0x40ACF3`;
- all three belong to `native-body:frontend-normalization:g1`;
- raw operation `native-body-edge@0x40BB51` owns predicate anchor `0x40BB63`
  and the unlowered successors `0x40C6F7` and `0x40BB69`;
- the body proof inventory includes
  `rhad:0x40A560:flow_route:0x40BB63`.

The canary remains C2, but the intended route-level fact advanced and this is
not a second non-advancing slice. The first failed C3 obligation is now
precise: canonical detached lowering must select the imported raw operation by
its operation-owned rewrite anchor `0x40BB63`, bind reference owner
`0x40BB51`, and replace both raw successors with direct target `0x40ACF3`
off-side. Do not weaken stable block identity globally or reinterpret the
imported source as live `EXTERNAL` authority; `0x40BB63` is an exact operation
anchor inside the source range, while `0x40BB51` is the block identity anchor.

**2026-07-25T17:23:49Z — one-route detached C3 plan and v21 checkpoint**

Commit `58b413504` adds a publication-ineligible `DetachedDirectRoutePlan` and
selects the configured imported source by the operation-owned predicate anchor
instead of requiring the rewrite EA to be an exact block-identity anchor. The
plan binds the reference owner independently from the state-write proof
origin, inventories every imported corridor owner, retains the superseded raw
operation, and produces one reference-owned direct semantic operation. The
configured pass records this complete plan and stops before live composition;
it does not reinterpret the imported source as live authority. Commit
`f1c43d6a6` contains only repository-wide Ruff formatting.

The first cache-disabled v20 canary rejected the plan with
`detached_direct_route_native_body_proof_missing`: the planner incorrectly
required raw operation `native-body-edge@0x40BB51` to appear in the native-body
proof inventory. The diagnostic DB showed that the pinned reference route ID,
not the raw topology operation ID, is the intended proof authority. Commit
`ceed28e9a` removes that false requirement while retaining the reference-route
ownership gate. The 105-test fragment, oracle, and pass suite is green; the
graph refresh and both architecture gates pass; repository-wide Ruff formatting
requires no further changes.

The mandatory fresh cache-disabled v21 A560 canary completed normally in
26.89 seconds with worker return code zero, no crash, numeric INTERR,
diagnostic-write failure, rollback, or aborted receipt. Output:
`.tmp/rhad-a560-v33-detached-c3-v21.txt`; primary DB:
`.tmp/rhad-a560-v33-detached-c3-v21/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode is beside the DB. The semantic oracle remains red on one false
`while ( 1 )`.

The v21 DB records one accepted
`configured_reference_detached_direct_route` attempt at `MMAT_CALLS` with:

- imported source `0x40BB51-0x40BB69`, exact owner `0x40BB51`;
- rewrite anchor `0x40BB63` selected from raw operation
  `native-body-edge@0x40BB51`;
- superseded conditional-taken and conditional-fallthrough arms;
- proof corridor `0x40BB44`, `0x40BB4B`, `0x40BB63`, owned by imported blocks
  anchored at `0x40BB3A` and `0x40BB51`;
- imported direct target `0x40ACF3-0x40AD06`, exact target `0x40ACF3`;
- pinned reference route `rhad:0x40A560:flow_route:0x40BB63`;
- evidence generation 1 and normalization plan
  `frontend-normalization:0xA560:g1`.

The existing frontend-normalization transaction remains mechanically healthy:
one receipt committed all 260 planned operations. The highest canary level is
now C3. The first failed obligation is C4:
`canonical_detached_direct_route_projection_missing` at stable rewrite anchor
`0x40BB63`. The next slice must realize this one operation in an unpublished
projected fragment or detached MBA, prove the resulting `m_goto` and target
against the pinned reference oracle, and only then select the smallest
entry-connectable closed fragment. Do not widen to the 91-route set or expose a
live root first.

**2026-07-25T17:49:31Z — portable-CFG integration baseline**

The amended execution plan continues this ticket from the committed C3
checkpoint in the isolated worktree
`/Users/mahmoud/src/idapro/d810/.worktrees/lrea-portable-cfg-integration` on
branch `diff/lrea-portable-cfg-integration`. The target is clean at
`d07b8dc9db20692f67464909c88beda6a03449be`; the read-only architectural donor
`/Users/mahmoud/src/idapro/d810/.worktrees/portable-cfg-transactions` is clean
at `ab769f182942f83191d883151d74b78fecac43cb`. Neither existing worktree was
modified, and the donor will be adapted component by component rather than
merged, rebased, or cherry-picked wholesale.

Docker 29.6.2 is responsive, and the pinned image
`d810-idapro-9.3-test-runtime:py313-v1` resolves to
`sha256:360f91d9d4ace70d89e03893f1d895d94383fa0fe426ddba9d3898a7922b650a`.
The required lifecycle baseline is 105/105 green across canonical fragment,
detached-route oracle, canonical-lowering, and frontend-normalization tests.

The latest authority DB remains the read-only v21 artifact at
`/Users/mahmoud/src/idapro/d810/.worktrees/lifecycle-resolver-evidence-authority/.tmp/rhad-a560-v33-detached-c3-v21/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
Highest accepted A560 level remains C3, and the first failed C4 obligation is
`canonical_detached_direct_route_projection_missing` at stable rewrite anchor
`0x40BB63`. The next implementation phase is the plan-neutral portable
transaction/projection foundation; C4 must remain mutation-free with respect
to the live MBA, and `DetachedDirectRoutePlan` remains publication-ineligible
C3 authority.

**2026-07-25T18:04:43Z — portable transaction/projection authority**

Commit `c6624c64f` ports and adapts the plan-neutral transaction foundation
without merging donor history. `PlanBlockRef` and `PlanInsnRef` are nominal,
plan-scoped identities; `TransactionAttemptId` binds plan, session, evidence
generation, and attempt; `CfgProjection` contains only a portable `FlowGraph`
whose integer node IDs are explicitly projection-local; and bound transactions
reject cross-plan, cross-session, cross-generation, and duplicate authority.
There is no `SnapshotBlockRef`, live SDK object, callback, or live block serial
authority in the portable contract. Typed projection failures record
`live_mutation_started=False`, while generation poison remains legal only after
a live write.

The same commit adds pure detached fragment projection from immutable snapshot
evidence. Clone and imported-block projection preserves explicit terminator EA
and terminator kind, derives root rewrites and fallthrough helpers off-side, and
normalizes the result into the portable transaction projection without reading
or mutating a live MBA. Commit `8be06aee4` is the separately requested
repository-wide Ruff formatting change; all 1,868 files then pass
`ruff format --check`.

Verification is 169/169 green across the new transaction/projection contracts
and the existing 105-test lifecycle baseline. `ruff check` passes, ast-grep is
clean, all 14 worktree-local import contracts are kept, commit-time cycle and
portable-shape gates pass, and `graphify update .` rebuilt the graph. This phase
does not change frontend normalization, resolver ownership, maturity behavior,
or a live MBA, so no new A560 canary was run and the highest accepted level
remains the v21 C3 checkpoint. The first failed obligation remains mutation-free
C4 projection of the direct route at stable rewrite anchor `0x40BB63`.

**2026-07-25T18:25:21Z — immutable native-body preparation boundary**

Commit `8dd0ab4d0` replaces the private SDK-bearing preparation record with two
explicitly separated values. `PreparedNativeBodyFact` is immutable authority
for plan and body scope, native ranges, stable block identities, instruction
native EAs, raw opcodes, primitive operand shapes, block flags, semantic edge
roles, predecessor topology, and portable terminator kinds. Block references
inside operand shapes deliberately omit their live coordinates. The separate
`PreparedNativeBodyPayload` retains the copied SDK instructions only for final
backend realization and cannot serve as semantic identity.

Construction recomputes and compares the payload's primitive signature against
the facts, and staging repeats that check while also rebinding the exact plan,
body, block identities, topology, and direct-transfer operation IDs. Mutable
payload drift therefore rejects before staging. The shared backend protocol now
requires `PreparedNativeBodyPreparation` and explicitly rejects the former
tuple-shaped result; no compatibility branch remains. Both PREOPT and CALLS
materializers use the existing detached template capture and importer, so this
is an output-boundary refactor rather than a second importer.

The focused runtime test prepares the same body twice and proves deterministic
facts and payload signatures, no live-serial fields, no SDK object in semantic
operand shapes, and no change to destination blocks, edges, fictitious-EA
allocation, dirty state, or identity generation. It also proves fact/payload
scope and opcode drift reject before mutation. Verification is 276/276 runtime
tests plus the 169/169 lifecycle gate; Ruff, ast-grep, all 14 import contracts,
cycle and portable-shape gates, diff checks, and `graphify update .` pass.
Commit `7c2997243` contains only the separately requested repository-wide Ruff
formatting, after which all 1,869 files pass `ruff format --check`.

This phase changes the native-body preparation boundary but does not publish a
root or alter frontend-normalization selection, resolver ownership, or maturity
restart behavior. No new A560 canary was run, so the accepted level remains C3
and the first failed obligation remains the mutation-free direct-route C4
projection at stable rewrite anchor `0x40BB63`.

**2026-07-25T19:17:25Z — scoped preparation authority and v23 reclassification**

Commits `b3c1e2ab5`, `064adc779`, and `e5d5fec28` made prepared native-body
facts portable, added a mutation-free direct-route projection, and connected
that projection to the configured A560 route. Commit `e4b1717db` contains only
the requested Ruff formatting. The first integration canary exposed a real
lineage defect after the PREOPT receipt committed: immutable facts belonged to
the selected publication plan
`frontend-normalization:0xA560:g1:root@0x40A5F0`, while the manager attempted to
authorize the different complete plan `frontend-normalization:0xA560:g1`.
The fail-open PREOPT dispatcher swallowed that post-receipt exception, so
CALLS reported `frontend_normalization_plan_intent_missing`.

Commit `a06e0b224` replaces that implicit plan-ID equivalence with typed
generation authority. It retains the complete plan, the exact committed
root-scoped work-item plan, its receipt, and only the immutable body facts that
the work item actually prepared. Lookup is by complete source lineage plus an
imported stable block ID and rejects absent or multiply owned blocks. The old
plan-only recording and prepared-body lookup APIs were removed rather than
kept as compatibility paths. Commit `fdfca0eb5` contains only Ruff formatting.
The focused manager, pass, transform, adapter, detached-import, and backend
gate is 351/351 green; Ruff lint and repository-wide formatting pass; both
commits passed ast-grep, cycle, portable-shape, and all 14 import contracts.

The mandatory fresh cache-disabled v23 A560 canary completed normally in
21.48 seconds with worker return code zero and no reported segfault or numeric
INTERR. Log:
`.tmp/rhad-a560-v33-scoped-authority-v23.txt`; primary DB:
`.tmp/rhad-a560-v33-scoped-authority-v23/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode is beside the DB. The semantic oracle remains red on one empty
`while ( 1 )`.

The prior authority regression is fixed. Transaction
`182b02907b85471d93111add9691b453` commits all 260 planned operations, passes
639 prepublication and 1180 postpublication validations, publishes its root,
and records the receipt. Lifecycle event 29 records complete plan intent
`frontend-normalization:0xA560:g1`, and event 30 binds current-MBA imported
identity. At CALLS the configured route plan is accepted for stable imported
source `0x40BB51`, rewrite anchor `0x40BB63`, proof corridor owners
`0x40BB3A` plus `0x40BB51`, and direct target `0x40ACF3`.

The next decline is typed `prepared_normalization_work_item_missing`. This is
correct abstention, not an authority regression: the committed work item's
native body contains 93 imported blocks and does not contain source block
`0x40BB51`, while the generation-wide complete body contains 478 blocks. The
code must not claim that an unselected complete body was prepared or weaken
lookup to body/range coincidence.

The v3.1 canary labels are corrected here. `DetachedDirectRoutePlan` is
portable per-site intent, not the complete canonical `FragmentPlan` required
by C3, and a pure `CfgProjection` is not gateway staging plus prepublication
validation required by C4. Therefore the highest strictly completed v3.1
A560 level is C2. The first failed obligation is
`C3_complete_vertical_fragment_plan` at rewrite anchor `0x40BB63`: promote the
single reference-owned route into one entry-connectable canonical
`FragmentPlan` whose detached native body owns the predicate/state-write
corridor, both superseded raw arms, the direct target, and dependencies. The
gateway must then prepare and stage that exact plan to establish C4, followed
by one atomic root publication and committed receipt for C5. Do not broaden to
the 91-route set, reuse the unrelated 93-block PREOPT work item as authority,
or call mutation-free projection C4.

**2026-07-25T19:27:08Z — v24 complete-plan composition boundary**

Commit `9b789df70` removes the false prepared-work-item prerequisite from the
configured direct-route critical path. The detached direct-route plan remains
the portable per-site preflight, but an accepted preflight now continues into
canonical `FragmentPlan` composition instead of stopping at a mutation-free
projection. Commit `02a7db410` contains only the separately requested Ruff
formatting for that logical slice. The relevant transform and pass gate is
159/159 green.

The mandatory fresh cache-disabled v24 A560 diagnostic canary completed
normally in 22.73 seconds with worker return code zero and no reported
segfault or numeric INTERR. Log:
`.tmp/rhad-a560-v33-vertical-fragment-v24.txt`; primary DB:
`.tmp/rhad-a560-v33-vertical-fragment-v24/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The semantic oracle remains red on one empty `while ( 1 )`.

The diagnostic DB records the detached direct-route attempt as accepted for
rewrite anchor `0x40BB63`, imported owner `0x40BB51`, corridor owners
`0x40BB3A` and `0x40BB51`, and target `0x40ACF3`. The subsequent canonical
composition reaches the composer and rejects with
`normalization_plan_owner_count_mismatch`: it searches block exact-instruction
anchors for `0x40BB63` and observes zero owners. The complete normalization
plan instead records one operation, `native-body-edge@0x40BB51`, whose
predicate anchor is exactly `0x40BB63`; its imported source block is stably
anchored at `0x40BB51` and spans `[0x40BB51,0x40BB69)`.

The highest strictly completed level remains C2. The first failed obligation
remains `C3_complete_vertical_fragment_plan`, but the false preparation
boundary is gone and the failure is now localized to operation-owned source
selection. The next falsifiable slice is to select exactly one normalization
operation by its predicate or superseded-predicate anchor, then separately
validate that operation's imported source block by stable native range and
identity before composing the canonical route. This must not add a block-EA
fallback, weaken stable identity matching, or broaden publication beyond the
single `0x40BB63` vertical fragment.

**2026-07-25T19:55:47Z — donor transaction-parity pause and executable ledger**

Rhad-specific vertical composition is paused. Commit `2e7b30aa0` is preserved
after the `403d798e6` canary checkpoint; no reset, revert, donor merge, or
cherry-pick was used. Its v25 canary completed normally without a segfault or
numeric INTERR, but the canonical boundary still rejected because imported
source `0x40BB51` and incoming corridor owner `0x40BB3A` had no current-MBA
owner at CALLS. The strict canary level remains C2 and the authorized Rhad
resume point remains `C3_complete_vertical_fragment_plan` at `0x40BB63`.

The portable representation foundation is accepted, but donor tip
`ab769f182942f83191d883151d74b78fecac43cb` is not transactionally integrated.
Commits `9b87d4bed` and `fd086d55b` add and separately format an executable
41-row parity ledger at
`tools/scripts/portable_cfg_transaction_parity_ledger.json`, enforced by
`tools/scripts/portable_cfg_transaction_parity_gate.py` and its unit test. The
ledger resolves every donor source/test anchor, names the current production
seam and status, and requires a concrete port, diagnostic proof, and acceptance
test for every guarantee. Normal audit passes; `--require-integrated` fails
with 38 pending guarantees. Three nominal representation/protocol guarantees
are accepted, four seams are partial, and all runtime creation, preflight,
poison/restart, diagnostic-authority, typed PatchPlan, coordinator, C5, and
protected-family obligations remain explicitly open.

The latest immutable v25 diagnostic database contains the existing semantic
fragment transaction and committed frontend-normalization receipt, but has no
`cfg_transaction_attempts`, `cfg_transaction_phase_events`, or
`cfg_creation_witnesses` tables. This is direct evidence that similarly named
portable types are not yet executable transaction authority. Before Rhad may
resume, port in order: typed pre-SDK PlanBlockRef reservation plus exact
post-SDK binding/creation receipts/witness persistence; immutable preflight and
a production five-phase participant; shared generation poisoning plus bounded
lifecycle restart and transaction diagnostics; then the sole shared
`FragmentPlan -> PatchPlan -> final binding -> DeferredGraphModifier`
coordinator with displaced runtime paths deleted and no compatibility layer.
The donor focused transaction gate and exact creation-witness C5 canary must
both pass at one clean integration SHA before returning to `0x40BB63`.

**2026-07-25T20:27:13Z — typed creation authority integrated and committed**

Rhad composition remains paused at the same C2/C3 boundary. Functional commit
`70660a65d` ports the first donor runtime slice, and formatting-only commit
`799b8dcde` contains the required repository-wide `pyenv exec ruff format .`
result. No donor commit was merged or cherry-picked.

The live identity index now reserves a `PlanBlockRef` under the exact
four-part `TransactionAttemptId` before SDK creation, binds the exact returned
coordinate afterward, and produces immutable `PlanBlockCreationReceipt`
authority. Anonymous SDK discoveries use `OBSERVED_EPHEMERAL`; the old
`SYNTHETIC` enum spelling, `MbaBlockHandle.synthetic()`, and
`create_synthetic_handle()` are removed with no compatibility alias. The
gateway records `planned -> bound -> observed -> committed`, and the manager
translates its typed authority into `cfg_transaction_attempts`,
`cfg_transaction_phase_events`, and `cfg_creation_witnesses`. A production
diagnostic-session test proves the reserved witness is queryable with no
returned coordinate before the simulated SDK creation, then proves the exact
creation receipt survives through committed diagnostic state. A separate
file-backed restart test proves the mapping remains queryable after SQLite is
closed and reopened. The diagnostic schema is now version 9.

Verification at `799b8dcde`:

- focused identity/gateway/diagnostic/ledger gate: 94 passed;
- affected manager, semantic-fragment, byte-emitter, and identity runtime gate:
  380 passed;
- executable parity ledger: PASS;
- strict parity gate: intentionally INCOMPLETE with 34 runtime guarantees
  pending;
- ast-grep: clean;
- import cycles: none across 945 modules;
- import-linter: all 14 contracts kept;
- portable shape-lint: no real-category regression.

The ledger now accepts pre-SDK synthetic reservation, exact returned-coordinate
binding, creation-receipt atomicity, and creation-witness persistence. Abort
diagnostics, anonymous-observation diagnostics, the complete transaction phase
timeline, and normalized attempt failure/poison authority remain partial. The
next authorized implementation slice is immutable transaction preflight plus
the production participant implementing project/preflight/bind/realize/observe.
No Rhad route may enter live gateway staging or root publication before that
participant is executable and proven.

**2026-07-25T21:24:30Z — immutable preflight and production participant checkpoint**

Rhad composition remains paused at the exact C2/C3 boundary and no donor
commit was merged or cherry-picked. Functional commit `d93a62752` ports the
immutable semantic-fragment transaction slice; formatting-only commit
`87d9a4fbc` contains the requested repository-wide Ruff formatting result.

The live production path now snapshots the full current CFG, identity lineage,
root inventory, native-body facts, return-carrier construction, flag evidence,
data flow, and value ranges while the gateway is idle. It validates both the
portable semantic projection and the full `CfgProjection` before opening a
batch. `PreparedSemanticFragmentAuthority` binds the exact plan object,
session, generation, snapshot token, root inventory, four-part attempt ID,
semantic projection, and CFG projection. Realization rejects foreign, stale,
same-ID-but-distinct, forged, malformed-payload, and reused authority before
the first SDK write.

`SemanticFragmentTransactionParticipant` is the production
`project -> preflight -> bind -> realize -> observe` implementation. Binding
preserves plan-local future identities and rebinds reused blocks through the
current `MbaBlockIdentityIndex`. Realization receives the exact immutable
authority object; staged observation independently re-reads live semantic
state, validates it, and compares it with immutable preflight. Preflight
failures leave MBA quantity, generation, roots, receipts, and gateway activity
unchanged. No direct-stage compatibility fallback was retained.

Verification at `87d9a4fbc`:

- exact authority and zero-write adversarial selection: 11 passed;
- full concrete semantic-fragment backend: 108 passed;
- portable transaction, validation, gateway, and policy selection: 133 passed;
- detached import plus manager native-preanalysis runtime selection: 196 passed;
- real Rhad fragment-publication E2E harness: 1 passed;
- post-format focused gateway/backend gate: 134 passed;
- executable parity ledger: PASS;
- Ruff check and repository-wide format check: clean;
- ast-grep: clean;
- import-linter: all 14 contracts kept;
- compileall and diff checks: clean;
- graphify refresh: complete with only the pre-existing skill-version warning.

The ledger deliberately keeps immutable snapshot, zero-write preflight,
single-use authority, payload-shape authority, and the production participant
at `partial`: their runtime guarantees are executable, but normalized
transaction-phase persistence and the shared typed PatchPlan coordinator are
not yet integrated. The next authorized slice is generation poisoning at the
first SDK write, the shared poison latch, lifecycle-controlled bounded restart,
and monotonic transaction-authority diagnostics. Rhad must remain paused until
that slice is green and committed.

**2026-07-25T15:06:49-0700 — divergent-generation poison and restart authority**

Rhad composition remains paused at the exact C2/C3 boundary, and no donor
commit was merged or cherry-picked. Functional commit `ab366f4da` ports the
post-write failure authority as one coupled runtime slice; formatting-only
commit `7eb3b6213` contains the separately requested repository-wide Ruff
formatting result.

The gateway now crosses an explicit irreversible boundary immediately before
the first SDK write. Any later failure poisons the shared live-MBA identity
generation, preserves the first typed failure and optional INTERR, emits the
monotonic `poisoned_restart_required` terminal phase, invalidates planned
creation witnesses, and performs only transaction-local logical abort. It does
not attempt physical graph rollback, cleanup, live lookup, or reuse after
divergence. Every sibling gateway over the same identity index rejects the
poisoned generation.

The session lifecycle now owns one bounded poisoned-generation recovery retry,
including the case where an ordinary evidence redo was already consumed. The
flowchart hook consumes that authority as exactly one `MERR_REDO`; a second
distinct same-epoch poison becomes terminal exhaustion and the decompile
controller refuses the poisoned output. Only genuinely changed portable facts
open a fresh evidence epoch. PREOPT dispatch and frontend normalization
propagate typed poison instead of swallowing it or claiming success.

Transaction diagnostics now persist the complete ordered
`planned -> projected -> preflighted -> bound -> realizing -> observed ->
committed` success timeline or one typed clean/poison terminal failure. The
first failure obligation, phase, reason, INTERR, mutation-start flag, and
invalidated creation refs survive SQLite close and reopen and cannot be
overwritten by later cleanup failures.

Verification at `7eb3b6213`:

- focused gateway, identity, lifecycle, diagnostic, semantic-backend, and
  ledger gate: 381 passed;
- semantic-fragment backend alone: 108 passed;
- executable parity ledger: PASS with zero errors;
- strict parity gate: intentionally INCOMPLETE with 26 guarantees pending;
- Ruff lint and repository-wide formatting: clean;
- ast-grep: clean;
- import-linter: all 14 contracts kept;
- compile and diff checks: clean;
- graphify refresh: complete with only the pre-existing skill-version warning.

The ledger now accepts partial-write poisoning, the shared generation latch,
lifecycle poison restart, retry exhaustion, changed-facts epoch reset, ordered
transaction phase events, file-backed attempt persistence, and monotonic first
failure. The next authorized slice is typed `FragmentPlan -> PatchPlan`
lowering, final boundary binding, planned helper identities with creation
witnesses, and one shared coordinator as the sole production mutation entrypoint.
Alternative and serial-shaped execution paths must be deleted with no
compatibility layer. Rhad remains paused until the remaining non-semantic donor
rows, the focused transaction gate, and one reconstructible creation-witness C5
transaction are accepted together at a clean SHA.

**2026-07-25T16:20:00-0700 — shared typed coordinator functional checkpoint**

Rhad composition remains paused at the exact C2/C3 boundary, and no donor
commit was merged or cherry-picked. Functional commit `e1c11ced2` routes both
ordinary `PatchPlan` and semantic `FragmentPlan` production work through the
shared typed coordinator; formatting-only commit `cdcb7a12e` contains the
separately requested Ruff pass over every tracked Python file. The unrelated
untracked Rhad microcode-capture test remains untouched.

`HexRaysMutationBackend.apply` is now the sole live mutation entry. A semantic
fragment is projected and preflighted while the gateway is idle, lowered into
one typed `PatchPlan`, bound to the exact four-part transaction attempt at the
final live boundary, realized through `DeferredGraphModifier`, observed from
the actual post-root graph, validated, and only then committed. The displaced
public fragment publisher, direct stage executor, untyped root executor,
serial-shaped plan operands, and parallel fragment backend protocol are
removed with no compatibility aliases.

Every replacement, imported block, empty block, conditional/call helper, and
root fallthrough helper now reserves its exact `PlanBlockRef` before the SDK
write and binds the block returned by that write afterward. Native and imported
replacement identities retain their semantic provenance; anonymous planned
creation is not used. Root helpers consume their predeclared creation authority
instead of falling back to generic insertion recording. The live diagnostic
canary remains reconstructible from transaction attempts, ordered phase rows,
mutation receipts, and creation witnesses.

Verification across the functional and post-format checkpoints:

- shared coordinator, gateway, identity, backend, pipeline, frontend, and live
  semantic-fragment gate: 356 passed;
- typed PatchPlan, final binding, prewrite cleanup, compatibility-absence, and
  coordinator architecture gate: 104 passed;
- post-format combined transaction gate: 418 passed;
- live semantic-fragment backend alone: 108 passed;
- executable parity ledger: PASS with zero schema or anchor errors;
- ast-grep, import cycles, all 14 import-linter contracts, portable shape-lint,
  compileall, Ruff format check, and diff checks: clean.

The 41-row ledger now has 22 accepted and 19 pending guarantees. This slice
accepts typed PatchPlan block references, final-boundary binding, prewrite
cleanup, removal of serial compatibility channels, FragmentPlan-to-PatchPlan
lowering, the shared coordinator, and the sole mutation entrypoint. The next
donor-first slice must close the executable full-graph projection contracts,
planned helper-witness architecture coverage, compiler snapshot/exact
transaction authority, post-root contract acceptance, and the focused
transaction gate before attempting the exact creation-witness C5 checksum.
Rhad must not resume from `0x40BB63` before those non-semantic rows are accepted
at one clean SHA.

**2026-07-25T16:43:27-0700 — reconstructible donor C5 checksum**

Rhad composition remained paused while the remaining donor transaction
guarantees were made executable. Commit `30da35989` made `CfgContract`
projection authority plan-neutral, functional commit `8f8f7a77e` closed the
focused transaction matrix, and their formatting-only companions are
`6c43fdf17` and `630cdddc8`. Commit `3597158f5` then strengthened the exact
real A560 terminal-fragment canary and connected its isolated emitter to the
same production transaction-authority adapter installed by `D810Manager`.

The preserved checksum database is
`.tmp/lrea-portable-cfg-c5-v3/real-terminal-fragment.diag.sqlite3`. Transaction
attempt `02d042ae0e964299b7cd04cb86d657c4` belongs to plan
`canonical-semantic-plan:rhad-terminal-route@0x40C7F6:g1`, session
`rhad-real-terminal-fragment-c5`, live-MBA generation 0, and evidence
generation 1. It records the exact ordered phases `planned -> projected ->
preflighted -> bound -> realizing -> observed -> committed`; mutation begins
only at `realizing`, and the final authority is committed and unpoisoned. The
same attempt is receipt authority for a 7/7 committed fragment publication.

The diagnostic DB records 32/32 passed prepublication obligations, 59/59
passed postpublication obligations, two committed clone-replacement creation
witnesses, and one committed planned root-fallthrough-helper witness. The
canary asserts all three requested and returned SDK creation coordinates, the
full phase order, exact session/generation authority, the detached reference
route comparison, the committed mutation receipt, root publication, block
version transitions, and semantic lifecycle operations. Focused diagnostic
persistence verification is 11/11 green, and the exact canary is 1/1 green.

The executable 41-row donor ledger is now 40 accepted and one pending. The
sole pending donor row is `protected_family_behavior_preserved`; the strict
gate must remain incomplete until Hodur, Sub7ffd, Tigress, and Approov are
proved at the final integration SHA. The pre-Rhad non-semantic transaction
gate and one reconstructible C5 checksum are complete, so the v3.1 vertical
loop may resume from its previously recorded first semantic obligation at
native rewrite anchor `0x40BB63`. Broad 91-route publication remains
prohibited until that one fragment is carried vertically through the live
path.

**2026-07-25T19:38:00-0700 — donor runtime parity and protected gate complete**

Rhad composition remained paused while the final donor integration checksum
was repaired and proved at clean production SHA `b52fe5b64`. Ordinary
`PatchPlan` conditional lowering had planned 35 operations for the Tigress
indirect oracle and applied 34 redirects, but adjacent fallthrough-helper
creation incorrectly demanded fragment-only authority and rejected the final
`LOWER_CONDITIONAL_STATE_TRANSITION`. Commit `b52fe5b64` changes that shared
SDK-write boundary to the plan-neutral transaction authority and adds a
focused regression proving a typed ordinary attempt may create the helper
without an active `FragmentPlan`. The focused coordinator, gateway, translator,
backend, and helper gate is 105/105 green. Ruff examined all 1,880 tracked
Python files and produced no formatting delta.

The exact Tigress Docker oracle is 1/1 green. Its primary diagnostic database
is `.tmp/logs/d810_logs/0000000180013e30_1785033168_9.diag.sqlite3`: the one
attempt records `planned -> projected -> preflighted -> bound -> realizing ->
observed -> committed`, is unpoisoned, and owns a 35/35 committed receipt. The
database again contains one `LOWER_CONDITIONAL_STATE_TRANSITION` at
`blk[22]@0x1800141B1`, so state `0x1C` is restored through production
provenance rather than inferred from pseudocode.

The explicit seven-node protected-family Docker matrix then passed 7/7 in
53.97 seconds. It covers both Hodur baselines, the Sub7ffd corridor regression,
the Tigress indirect semantic oracle, and all three Approov characterization
oracles. Log:
`.tmp/lrea-portable-cfg-protected-exact7-b52fe5b64.txt`.

The exact donor C5 checksum also passed at `b52fe5b64`; preserved log:
`.tmp/lrea-portable-cfg-c5-b52fe5b64-preserved.txt`; preserved database:
`.tmp/lrea-portable-cfg-c5-b52fe5b64/real-terminal-fragment.diag.sqlite3`.
The database records a 7/7 committed fragment receipt, 32/32 passed
prepublication outcomes, 59/59 passed postpublication outcomes, the complete
seven-phase transaction timeline, and three exact committed creation witnesses
for both replacements and the root fallthrough helper.

All 41 donor-ledger rows are now accepted, including
`protected_family_behavior_preserved`, and the strict executable parity gate
is expected to pass with no pending runtime guarantee. The donor-first pause is
therefore complete. Rhad may resume only through the v3.1 vertical loop from
the recorded first semantic obligation `C3_complete_vertical_fragment_plan`
at native rewrite anchor `0x40BB63`; broad 91-route publication remains
prohibited until that one fragment reaches live C5.

**2026-07-26T02:57:37Z — post-donor A560 projection parity and C3 boundary**

Commit `fb8de12a4` repairs the first fresh post-donor A560 transaction failure
without weakening immutable observation. Portable projection had recorded the
synthetic fallthrough helper as the `adjacent_fallthrough_target_id` of every
fallthrough source. The live projection correctly records that adjacency
witness only for a `BLT_2WAY` conditional source; one-way call sources prove
their helper through the separately validated physical source/helper topology.
The new regression first failed exactly as `block:imported-call` and then
proved immutable/live parity. The complete semantic-fragment backend is
109/109 green, the focused call/conditional/projection set is 47/47 green, and
all commit-time architecture gates pass. Ruff examined all 1,880 tracked
Python files and produced no formatting delta.

The mandatory fresh cache-disabled A560 diagnostic canary ran against
`fb8de12a4`. Log:
`.tmp/rhad-a560-call-projection-fb8de12a4.txt`; primary database:
`.tmp/rhad-a560-call-projection-fb8de12a4/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The worker returned normally in 16.95 seconds with no crash, numeric INTERR,
transaction failure, generation poison, rollback, or diagnostic-write failure.
Frontend transaction `ee07d1ea0621429fb9dc584874f5027c` records the complete
`planned -> projected -> preflighted -> bound -> realizing -> observed ->
committed` sequence, a 260/260 committed receipt, 639 passing prepublication
outcomes, and 1,180 passing postpublication outcomes. This broad
frontend-normalization receipt remains architecture evidence only; it is not
the selected route's C5 and does not authorize broad route publication.

The DB now exposes the next vertical obligation precisely. The configured
detached direct-route attempt is accepted for imported source `0x40BB51`,
rewrite anchor `0x40BB63`, corridor owners `0x40BB3A` plus `0x40BB51`, direct
target `0x40ACF3`, and reference route
`rhad:0x40A560:flow_route:0x40BB63`. Canonical fragment composition then
rejects with `published_boundary_current_owner_count_mismatch` at stable
boundary `0x40BB51`: its current-MBA identity inventory is empty, and the
incoming imported owner `0x40BB3A` also has no current owner. The output remains
the initial `memset` followed by one false empty loop.

The highest strictly completed v3.1 level therefore remains C2. The monotonic
first failed obligation is
`C3_complete_vertical_fragment_plan:published_boundary_current_owner_count_mismatch@0x40BB51`.
The next vertical slice must derive an entry-connectable detached publication
boundary from the receipt-backed current-MBA inventory while retaining
`0x40BB51` as the imported semantic source; it must not reinterpret the absent
imported source as live, weaken exact identity ownership, count the unrelated
broad receipt as route C5, or add another semantic route.

**2026-07-25T21:23:57-0700 — carrier ingress identity and closed-component boundary**

Functional commit `e1c87c228` wires the configured detached route through one
bounded carrier-ingress attempt when its imported source has no current owner.
Formatting-only commit `2b37f5ff2` is the separately requested Ruff pass. The
current graph identity inventory is now derived from each `FlowGraph` block's
native snapshot and confirmed through `MbaBlockIdentityIndex.rebind_identity()`;
it never indexes another maturity by the current graph's serial. The regression
uses deliberately shifted serial namespaces and makes `identity_for_serial()` a
hard failure.

The mandatory fresh cache-disabled A560 canary completed normally in 16.87
seconds with no crash, numeric INTERR, generation poison, rollback, or pending
restart. Log: `.tmp/rhad-a560-carrier-ingress-closed-gate.txt`; primary DB:
`.tmp/rhad-a560-carrier-ingress-closed-gate/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The DB records one committed generation-1 frontend-normalization transaction.
Identity decision event 172 confirms the graph-derived current owner as
`blk3@0x40A5AE`; the prior
`carrier_ingress_current_owner_count_mismatch@0x40A5AE` is gone.

The configured carrier attempt now gets far enough to project the selected
`0x40BB63 -> 0x40ACF3` route and its `0x40BB3A` plus `0x40BB51` corridor, but it
does not produce a complete publishable fragment. `fact_consumers` snapshot 3,
consumer 5 records the first failed obligation at stable boundary `0x40B6C0`:
operation `native-body-edge@0x40B6C0` is a published imported boundary with
unresolved semantic topology, entered from native source `0x40AD18` by
`native-indirect-transfer@0x40AD1C`. The production gate reports this as
`carrier_ingress_target_component_not_closed` and sets
`contextual_restart_permitted=false`; it therefore cannot broaden the fragment
one normalization generation at a time or exhaust the bounded restart budget.

The highest strictly completed v3.1 level remains C2. The new monotonic first
failed obligation is
`C3_complete_vertical_fragment_plan:carrier_ingress_target_component_not_closed@0x40B6C0`.
Focused carrier composition/lowering verification is 58/58 green, Ruff lint and
compile checks pass, and both commits passed ast-grep plus all 14 import
contracts. Continue from this exact closed-component obligation; do not raise
the restart budget, recursively import the path to `0x40BB63`, count the nested
route projection as a complete C3 plan, or broaden to the 91-route set.

**2026-07-25T21:46:29-0700 — typed published egress and rebound identity boundary**

Functional commit `1e86ee81b` retains each carrier-owned crossing into a
published block with unresolved semantic topology as one exact
`TEMPORARY_DISPATCHER_EGRESS` port. Every port names its staged source edge,
external target, and deterministic retirement obligation; ordinary canonical
composition remains fail-closed. Formatting-only commit `90eac1f6d` is the
separate repository-wide Ruff pass. Functional commit `95880cf6c` then removes
shared verifier-safe live start coordinates from portable current-graph
authority by publishing the exact stable identity of the uniquely rebound
handle while retaining graph serials only for callback-local topology. Ruff
examined all 1,880 tracked Python files after that fix and produced no delta.

The first mandatory A560 canary at `90eac1f6d` proved that the prior
`carrier_ingress_target_component_not_closed@0x40B6C0` rejection was gone, but
then exposed a false boundary alias at `0x40A68C`. The graph-derived probe for
`blk15@0x40A560` included the shared fake coordinate `0x40A560`, whereas the
identity index's uniquely rebound imported handle owned native `0x40A68C` and
`0x40A698`. Treating the probe as portable authority therefore also captured
`blk0@0x40A560` and produced
`projected_boundary_current_owner_ambiguous@0x40A68C`.

The fresh cache-disabled A560 canary at `95880cf6c` completed normally in 23.37
seconds with no crash, numeric INTERR, generation poison, rollback, or pending
restart. Log: `.tmp/rhad-a560-rebound-current-identity-95880cf6c.txt`; primary
DB:
`.tmp/rhad-a560-rebound-current-identity-95880cf6c/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The generation-1 frontend-normalization transaction again records the complete
seven-phase timeline, a 260/260 committed receipt, 639 passing prepublication
outcomes, and 1,180 passing postpublication outcomes. That broad receipt is C2
architecture evidence only.

Carrier composition now reaches reference-oracle binding, but the selected
route is not yet a valid C3 plan. `fact_consumers` snapshot 3 records
`fragment_reference_route_identity_mismatch` at rewrite anchor `0x40BB63`:
target `0x40ACF3` binds, while the nested operation claims owner identity
`0x40BB44` and fails to bind reference owner `0x40BB51`. No canonical semantic
transaction, validation outcome, root publication, or semantic receipt exists.
The highest strictly completed level therefore remains C2, and the monotonic
first failed obligation is
`C3_complete_vertical_fragment_plan:fragment_reference_route_identity_mismatch@0x40BB63`.
Continue by preserving the already verified detached-route owner authority
through nested carrier projection; do not relax reference binding, reinterpret
the state-write origin as the rewritten operation owner, or broaden beyond this
one vertical fragment.

**2026-07-25T22:24:27-0700 — refined plan identity authority and redo-scope boundary**

Commits `7dba0a827` and `b50670b3f` preserve the detached reference-route owner
through carrier projection and reuse the already projected dispatcher owner.
Commit `72bd62c87` makes clean preflight rejections retain their exact typed
validation reason in `cfg_transaction_attempts`. Commit `a0ad8b3f5` then
removes a shared synthetic live start from current-graph authority, but its
mandatory canary exposed a real post-write identity mismatch: immutable
preflight held the refined plan identity while staged observation substituted
the broader physical handle identity and poisoned the live generation.

Functional commit `1678adfe7` fixes that boundary directionally. A physical
current-MBA identity must cover every planned native range and exact
instruction anchor; preflight rejects non-covering authority before any SDK
write, while preflight and staged observation both expose the immutable plan
identity. The full block-identity plus semantic-fragment backend gate is
124/124 green. Formatting-only commit `282bec730` is the separately requested
Ruff pass.

The mandatory fresh cache-disabled A560 diagnostic canary at `282bec730`
completed normally in 15.91 seconds. Log:
`.tmp/rhad-a560-refined-plan-282bec730.txt`; primary DB:
`.tmp/rhad-a560-refined-plan-282bec730/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
There is no crash, numeric INTERR, poisoned generation, rollback, or partial
receipt. Both frontend-normalization attempts record the complete seven-phase
timeline and committed 260/260 receipts. The first carrier attempt rejects
cleanly to request analyzed CALLS companions, and the DB records the request,
capture, and generated-restart consumption. The second carrier attempt also
rejects before mutation. A560 still fails C6 only because the output contains
one false `while ( 1 )`.

The selected `0x40BB63` route now produces a complete canonical plan and enters
the transaction coordinator, so its highest strict level is C3. The broad
frontend-normalization path independently reaches C5 but is not the selected
route's vertical receipt. The first failed selected-route obligation is
`C4_staged_proof:runtime:preflight`, with exact reason
`canonical semantic normalization work-item scope drifted`.

The DB identifies why the authority is stale. Event 52 records normalization
plan intent at publication revision 1. After the companion-triggered generated
redo, events 271 through 312 commit the same 260-operation normalization plan
again and event 314 publishes the same work-item scope, but no revision-2 plan
intent event exists. The session lifecycle has advanced while
`SessionFrontendNormalizationPlanAuthority` still exposes revision 1. Continue
by retaining every immutable receipted work-item revision and selecting the
current exact authority after redo; do not bypass lifecycle comparison, reset
the session, reuse a stale receipt, or proceed to another semantic route.

**2026-07-25T22:32:01-0700 — redo receipt authority restored; C4 use-def boundary**

Functional commit `7293326ff` keys each immutable receipted normalization
work-item snapshot by publication revision and selects the latest revision for
the uniquely owning work item. It preserves earlier body-owner snapshots and
continues to reject multiple distinct owners. The focused normalization and
session-lifecycle gate is 64/64 green. Formatting-only commit `d74ecf6e0` is
the separate Ruff pass.

The mandatory fresh cache-disabled A560 diagnostic canary at `d74ecf6e0`
completed normally in 15.66 seconds. Log:
`.tmp/rhad-a560-receipt-revisions-d74ecf6e0.txt`; primary DB:
`.tmp/rhad-a560-receipt-revisions-d74ecf6e0/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
There is no crash, numeric INTERR, poisoned generation, rollback, or partial
write. A560 still fails C6 only because the pseudocode contains one false
`while ( 1 )`.

The DB proves the redo authority repair. Events 52 and 315 record the same
normalization work item at publication revisions 1 and 2, and event 521 marks
the canonical semantic plan ready against revision 2. The second selected
carrier attempt clears immutable lifecycle preflight, reaches projected C4
validation, and rejects cleanly with `mutation_started=0`.

The selected route therefore still has C3 strictly complete and now reaches
C4 prepublication proof. Its monotonic first failed obligation is
`C4_staged_proof:use_def_integrity:predicate:state-choice@0x40BECC:0xEC71CA67:0xA0716E5B:use-def`.
The staged projection reports no observed relation for either the planned
predicate materialized-use or carrier ingress-use. Continue from that exact
projection/observation mismatch; do not weaken use-def validation, synthesize
a passing diagnostic, publish the fragment, or broaden beyond this one route.

**2026-07-25T22:47:13-0700 — expected data-flow authority; typed predicate stage boundary**

Functional commit `45ffadc35` makes the pure fragment projector include every
plan-required UD and DU direction that realization must later observe, while
retaining snapshot-observed extra definitions and uses so preflight remains
fail-closed. A production participant test proves zero SDK writes through
preflight and proves the independently observed staged relation exactly equals
the immutable expected authority after realization. The complete portable
validation plus semantic-backend gate is 158/158 green. Formatting-only commit
`69995d139` is the repository-wide tracked-file Ruff pass.

The mandatory fresh cache-disabled A560 diagnostic canary at `69995d139`
finished in 17.77 seconds without a segfault or numeric INTERR. Log:
`.tmp/rhad-a560-projected-dataflow-69995d139.txt`; primary DB:
`.tmp/rhad-a560-projected-dataflow-69995d139/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
It did not return poisoned output: both permitted attempts poisoned during live
staging, and the lifecycle then exhausted the bounded distinct-incident
restart with an explicit runtime failure.

The selected carrier transaction now records `planned -> projected ->
preflighted -> bound -> realizing`, so the prior prewrite data-flow rejection
is gone. Each live attempt plans 49 items, applies 16, creates 15 witnessed
blocks, invalidates all 15 witnesses, aborts, and records
`poisoned_restart_required`. The first attempt requests and consumes the one
allowed poison restart; the second records exhaustion.

The selected route still has C3 strictly complete and now reaches C4 live
realization. Its monotonic first failed obligation is
`C4_staged_proof:runtime:stage`, with exact DB reason
`'route:state-choice@0x40BECC:0xEC71CA67:0xA0716E5B:carrier-ingress'`.
The failure occurs immediately after the planned fallthrough helper and before
the conditional-taken step, where realization requests the operation's typed
live predicate binding. Continue by proving and binding the clone-owned
storage-predicate materialization before semantic-edge realization; do not
catch the missing key, synthesize a binding, increase restart budget, or
broaden beyond this route.

**2026-07-25T23:21:00-0700 — clone-owned predicate staging; C4 suffix-proof boundary**

Functional commit `f03d196a1` lowers a clone-owned stack predicate as an
explicit typed PatchPlan normalization, snapshots immutable clone-source
instruction facts, validates the retained anchor and discardable suffix before
opening the gateway, rechecks the original and clone against that authority,
and binds the synthesized predicate EA before semantic-edge realization. It
also distinguishes the physical state-write definition from the synthesized
predicate use when both share one portable EA. The focused projection,
lowering, and production-backend gate is 167/167 green, including an unsafe
suffix rejection with zero writes. Formatting-only commit `204acc76f` is the
separate repository-wide tracked-file Ruff pass.

The mandatory fresh cache-disabled A560 diagnostic canary at `204acc76f`
finished in 15.46 seconds without a segfault, numeric INTERR, generation
poison, rollback, or partial receipt. Log:
`.tmp/rhad-a560-clone-predicate-204acc76f.txt`; primary DB:
`.tmp/rhad-a560-clone-predicate-204acc76f/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
A560 still fails C6 because the pseudocode contains one false `while ( 1 )`.

The DB records two independent 260/260 frontend-normalization receipts with
complete `planned -> projected -> preflighted -> bound -> realizing ->
observed -> committed` timelines. That path reaches C5 but is not the selected
semantic-route proof. The first carrier attempt rejects cleanly to request the
CALLS companion range. After redo, the selected carrier plan again reaches C3
and enters C4 projection, then rejects with `mutation_started=0` and
`poisoned=0`.

The selected route therefore has C3 strictly complete. Its first failed
obligation is
`C4_staged_proof:operation_topology:route:state-choice@0x40BECC:0xEC71CA67:0xA0716E5B:carrier-ingress`,
with DB reason `clone-owned storage predicate suffix is not atomically
discardable`. The current failure row does not identify the immutable suffix
instruction facts that violated the proof. Continue by making that portable
evidence reconstructible in the diagnostic failure, then repair only the
first unsafe or misclassified suffix instruction; do not weaken atomic suffix
validation, write live state, or broaden to another route.

**2026-07-25T23:35:00-0700 — first complete carrier-ingress C5 transaction**

Commit `d01e6397f` persists a canonical JSON rendering of immutable clone-source
suffix facts in the monotonic transaction failure reason. Its canary proved the
carrier root at `0x40A5AE` had two register-only dispatcher writes and an
implicit one-way edge, rather than an explicit transfer instruction. Commit
`8dc7f61e5` accepts that narrow shape only when the suffix contains `NOP` or
register-destination `MOV` instructions and the source's sole live successor
exactly equals the typed conditional-fallthrough target. Wrong successors and
side-effecting suffix writes reject before mutation. Commit `8bc922226` scopes
physical data-flow site matching to each typed obligation, allowing predicate
and carrier semantic aliases to share one proved physical access without
weakening duplicate-site rejection inside an obligation. The focused gate is
169/169 green. Repository-wide tracked-file Ruff format produced no delta for
these slices.

The mandatory cache-disabled A560 canary at `8bc922226` completed without a
segfault or numeric INTERR and produced the first reconstructible selected-route
C5 transaction. Log: `.tmp/rhad-a560-obligation-alias-8bc922226.txt`; primary
DB:
`.tmp/rhad-a560-obligation-alias-8bc922226/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
Attempt `8bcafee1067f4e34aef7cdd7626922b7` records the complete `planned ->
projected -> preflighted -> bound -> realizing -> observed -> committed`
timeline, the detached route oracle passes, and receipt event 556 commits all
49/49 operations. Its creation-witness checksum contains 11 committed synthetic
blocks, 14 committed imported-native blocks, one committed native block, six
non-creating planned references, and zero invalidations.

The required one-fragment C5 architecture milestone is therefore satisfied for
`route:state-choice@0x40BECC:0xEC71CA67:0xA0716E5B:carrier-ingress`. A560 is not
C6 accepted: its output still contains one false `while ( 1 )`. The first
post-C5 failure is `C6_semantic_acceptance:runtime:realization` at
`MMAT_GLBOPT2`. Subsequent prepared non-fragment PatchPlans reach `bound` and
then reject cleanly with `prepared patch binding quantity differs from live
batch`; no further mutation starts. Continue by tracing why those plans retain
the pre-publication MBA quantity after the committed 49-operation fragment.
Do not broaden to the 91-route batch or treat C5 as final A560 acceptance.

**2026-07-25T23:45:55-0700 — live identity refresh; C5 preserved**

Commits `a4b9ebcb0` and `476b6e99b` make the prepared/live PatchPlan
quantity mismatch reconstructible without weakening its zero-write rejection.
The first fresh canary records the exact split as `prepared=50, live=42` at
`MMAT_GLBOPT2`, proving that the flow-context identity snapshot survived
Hex-Rays compaction across optimizer callbacks. It was not a partial C5 write,
post-publication poison, or asynchronous resize inside the participant.

Commits `1696b6cf9` and `4ba0ec195` rebuild current-MBA identity authority
immediately before every flow-context transaction gateway is issued. The
context retains the lifecycle factory, not a stale binding; the plan compiler,
preflight, binder, and realization therefore share one freshly lifted live
authority. The quantity equality check remains mandatory. The affected
adapter, transaction, projection, and semantic-backend gate is 238/238 green,
and the second commit is the separately requested Ruff-only delta.

The mandatory cache-disabled A560 canary at `4ba0ec195` completed normally in
28.61 seconds. Log: `.tmp/rhad-a560-live-rebind-4ba0ec195.txt`; primary DB:
`.tmp/rhad-a560-live-rebind-4ba0ec195/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode is beside the DB. There is no segfault, numeric INTERR, poisoned
generation, rollback, post-C5 transaction rejection, or partial receipt. The
DB contains three committed seven-phase transactions and only the expected
pre-C5 CALLS-companion rejection. The selected carrier attempt retains its
complete matched detached oracle, committed creation witnesses, postvalidation,
and 49/49 receipt.

The strict highest level therefore remains C5. The output is 31 lines and
reaches the initial allocation before ending in one false empty `while ( 1 )`,
so A560 is not C6 accepted. The former
`C6_semantic_acceptance:runtime:realization` quantity failure is closed. The
first remaining obligation is now `C6_semantic_acceptance:false_infinite_loop`:
expand from the proven entry-connected carrier fragment using reference-ledger
routes and require the same detached proof, publication receipt, and liveness
budget. The diagnostic schema does not yet persist the C6 pseudocode-oracle
result itself; until that observability gap is closed, the exact E2E assertion
and copied pseudocode are the output authority. The v3.1 one-fragment gate now
permits a bounded broad-route attempt, but no C6 claim is allowed until the
full semantic oracle passes.

**2026-07-26T00:14:33-0700 — complete A560 reference scope; strict C3 anchor mismatch**

Commits `6205a2f02`, `349891c24`, and `e2007f524` make the Rhad oracle
generator compile ordered conditional transactions and select only
`flow_route` authority when another transaction shares the same native anchor.
Commits `2b0049e86` and `7218c162f` install the complete tracked A560 manifest
and select it in production. The manifest SHA-256 is
`9bc4682b608a49621588fb8f79af446fa7b98edcf55a5da755fecfe45c15c2e4`;
it contains 93 unique route IDs and owners, comprising 91 direct and two
conditional routes under publication root `0x40A5B2`. The focused route,
manager, lifecycle, validation, lowering, and backend gate is 272/272 green.

The mandatory cache-disabled A560 canary at `7218c162f` completed normally in
19.13 seconds without a segfault, numeric INTERR, generation poison, rollback,
or partial receipt. Log:
`.tmp/rhad-a560-full-flow-routes-7218c162f.txt`; primary DB:
`.tmp/rhad-a560-full-flow-routes-7218c162f/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode is beside the DB. The frontend-normalization transaction commits
through all seven phases with 639/639 prepublication and 1180/1180
postpublication checks, but no semantic PatchPlan transaction starts. The
output is a six-line false infinite loop, so A560 remains below C6.

The DB records the first broad-route C3 failure precisely. At `MMAT_CALLS`,
configured-root composition accepts a 150-operation plan containing two
reference rewrite anchors, then `bind_fragment_reference_oracle` rejects the
93-route selection with
`canonical_configured_reference_scope_invalid: fragment and reference
selection require exact rewrite anchors`. The highest proven architecture
level remains the earlier one-fragment C5 transaction. Continue by composing
the selected reference scope into one closed plan whose rewrite-anchor set is
exactly the selected 93-route set before binding or publication. Do not weaken
the exact-anchor oracle, bind a subset under full-scope authority, or publish
multiple independently live route fragments.

**2026-07-26T00:39:00-0700 — typed anchor inventory corrects broad C3 diagnosis**

Functional commit `31b076b11` makes detached-oracle authority failures carry
typed reason codes and exact planned, selected, missing, and unexpected stable
EA sets through the canonical rejection into the diagnostic DB. Ruff-only
commit `b6ba25da9` formats that slice. The focused canonical, oracle, manager,
and backend gate is 163/163 green with the unrelated random-identity
`PatchPlan()` assertion explicitly deselected.

The mandatory cache-disabled A560 canary at `b6ba25da9` completed normally in
19.39 seconds without a segfault, numeric INTERR, generation poison, rollback,
or partial receipt. Log:
`.tmp/rhad-a560-anchor-mismatch-b6ba25da9.txt`; primary DB:
`.tmp/rhad-a560-anchor-mismatch-b6ba25da9/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode is beside the DB. The C6 result remains the same six-line false
infinite loop.

This DB evidence corrects the preceding checkpoint's interpretation. The two
`route_proof_ids` on the accepted configured-root attempt describe its root
work-item evidence, not the complete staged plan's rewrite inventory. The
actual plan has 89 unique rewrite anchors against 93 selected anchors. It is
missing `0x40AE0B`, `0x40AE7A`, `0x40B36B`, `0x40BED0`, and `0x40C4D2`, and
has the unexpected anchor `0x40AE09`. The first three selected routes are
direct; the last two are the conditional routes. Continue from the earliest
stable-EA mismatch, selected `0x40AE0B` versus planned `0x40AE09`, and prove
whether that is a native-to-microcode coordinate error or an incorrectly
selected semantic envelope before addressing the two absent direct routes and
typed conditional authority. Do not weaken exact-anchor equality or describe
this as a two-route composition failure.

**2026-07-26T01:13:00-0700 — donor patch coordinate rebound to semantic authority**

Functional commit `8e017136c` removes reference authority from the direct-only
rewrite payload and binds it at the complete `FragmentOperation` instead. A
typed authority now preserves both the donor patch coordinate and the exact
candidate semantic coordinate. Non-equal coordinates bind only through one
unique owner, corridor, direct target, and operation match; exact-coordinate
routes still undergo the same owner and target identity validation. Detached
comparison normalizes the reference semantics to the bound candidate
coordinate while retaining the donor coordinate in the serialized authority.
Ruff-only commit `3ed2b8379` formats the slice. The focused route, fragment,
gateway, manager, lifecycle, and backend gate is 421/421 green with the known
random-identity `PatchPlan()` assertion deselected.

The mandatory cache-disabled A560 canary at `3ed2b8379` completed normally in
19.16 seconds without a segfault, numeric INTERR, generation poison, rollback,
or partial receipt. Log:
`.tmp/rhad-a560-semantic-anchor-3ed2b8379.txt`; primary DB:
`.tmp/rhad-a560-semantic-anchor-3ed2b8379/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode is beside the DB. A560 still emits the same six-line false infinite
loop and therefore remains below C6.

The DB proves one unique coordinate binding:
`rhad:0x40A560:flow_route:0x40AE0B` maps donor patch `0x40AE0B` to candidate
semantic rewrite `0x40AE09`. The planned inventory remains 89 operations, but
the unexpected set is now empty and the missing selection drops to
`0x40AE7A`, `0x40B36B`, `0x40BED0`, and `0x40C4D2`. The first failed C3
obligation is now the absent direct route at `0x40AE7A`; diagnose its evidence,
component ownership, and raw operation disposition before addressing
`0x40B36B` or either conditional route. Do not encode a function-specific
coordinate alias or treat donor byte placement as candidate IR identity.

**2026-07-26T01:00:24-07:00 — post-call state routes complete direct C3 inventory**

Functional commit `c8ac5bab1` fixes the two missing direct routes without
weakening publication boundaries. The diagnostic DB and receipt-backed
frontend plan prove that `0x40AE7A` and `0x40B36B` are normalized conditional
route sources immediately after `CALL_FALLTHROUGH` operations. Because those
raw normalization operations were already published, component selection
mistook them for closed semantic boundaries and stopped before their direct
state-assignment proofs could supersede them. The call-backed staging contract
now also accepts this exact post-call shape only when there is one imported
call predecessor, one normalized source operation at the proof anchor, an
unresolved transfer strictly inside the typed delivery region, and a wholly
owned state-write corridor. The call predecessor and route source then remain
staged as one closed corridor. The prior call-inside-corridor contract remains
unchanged. Ruff-only commit `78eb6ad55` formats the repository-wide tracked
Python set; two files changed and the unrelated untracked Rhad capture test was
not touched.

The affected canonical, oracle, gateway, manager, and runtime gate is 274/274
green with the known random-identity `PatchPlan()` assertion deselected.
Commit-time ast-grep, import-cycle analysis, portable-core shape lint, and all
14 import-linter contracts pass.

The mandatory cache-disabled A560 canary at clean code SHA `78eb6ad55`
completed normally in 17.46 seconds without a process crash, numeric INTERR,
generation poison, rollback, partial receipt, or semantic transaction attempt.
Log: `.tmp/rhad-a560-post-call-78eb6ad55.txt`; primary DB:
`.tmp/rhad-a560-post-call-78eb6ad55/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`;
pseudocode is beside the DB. A560 still emits the six-line false infinite loop,
so this is not C6 or semantic acceptance.

The DB now records 91 planned rewrite anchors against all 93 selected donor
routes, with no unexpected anchors. Both direct routes `0x40AE7A` and
`0x40B36B` are present. The only missing routes are conditional anchors
`0x40BED0` and `0x40C4D2`. Broad publication therefore remains at C3 and no
semantic PatchPlan may stage yet; the earlier one-fragment C5 remains the
highest architecture level proven on this branch. The first failed broad C3
obligation is the typed conditional route at `0x40BED0`. Continue by matching
its donor condition producer, predicate, both targets, complete operation
envelope, and fragment-level reference authority before addressing
`0x40C4D2`. Do not encode conditional authority in a direct-only payload,
publish the 91-route subset, or relax the exact 93-route oracle gate.

**2026-07-26T01:20:00-0700 — carried state choice projected off-side**

Functional commit `71b269d20` extends detached component composition to one
field-complete `STATE_CHOICE` proof. The immutable frontend plan atomically
replaces the imported raw conditional operation and both dispatcher arms with
the proof's semantic taken/fallthrough targets. SDK-facing storage-predicate
materialization remains deferred until the selected operation is under
canonical publication authority. The focused canonical-fragment suite is
48/48 green, including the new end-to-end nested-choice regression; commit-time
ast-grep, import-cycle, portable-core shape lint, and all 14 import-linter
contracts pass.

The mandatory cache-disabled A560 canary at clean code SHA `71b269d20`
completed normally in 16.74 seconds. Log:
`.tmp/rhad-a560-nested-choice-71b269d20.txt`; primary DB:
`.tmp/rhad-a560-nested-choice-71b269d20/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
There is no process crash, numeric INTERR, generation poison, rollback, or
partial transaction. The existing frontend-normalization transaction commits;
no canonical semantic transaction stages. A560 still emits the six-line false
infinite loop and remains below C6.

The DB still reports 91 planned direct rewrite anchors against 93 selected
routes, with no unexpected anchors and missing conditional donor anchors
`0x40BED0` and `0x40C4D2`. That is now the expected direct-only oracle-binding
blind spot, not evidence that the carried-choice proof is absent. The highest
architecture level remains the previously proven one-fragment C5; the broad
plan remains at C3. The first failed obligation is still conditional authority
binding for owner `0x40BECC` / donor patch `0x40BED0`: bind and compare the
typed conditional operation by owner, semantic predicate, both edge roles,
both targets, corridor, and reachability before any 93-route staging.

**2026-07-26T02:53:12-0700 — strict staged semantics expose helper parity**

Commits `71a1ff166` and `095f15da1` persist complete staged route coordinates
and distinguish a missing rewrite anchor from a wrong staged terminator. The
mandatory canary at `095f15da1` reached broad C4 with 1057/1057
prepublication checks and 93 oracle comparisons, then rejected three staged
divergences before publication. Its first comparison proved that the folded
delivery route `rhad:0x40A560:flow_route:0x40A5C8` had been realized as a
`GOTO` at the function entry `0x40A560`, not its proved rewrite anchor
`0x40A5C8`.

Commits `5b2bcbcd1` and `2b727a4f6` make immutable projection and staged
observation compare instruction order, terminator EA and kind, and flag-write
coordinates. Functional commit `c119a970b` then threads an explicit
instruction EA through zero-way `GOTO` creation and limits that authority to a
`FragmentDirectTransferRewrite`; generic direct edges do not inherit the
source block's semantic anchor. The focused proved-anchor gate is 3/3 green,
and the transaction/projection gate is 106/106 green. Repository formatting
already matched Ruff, so this slice produced no formatting-only commit. Four
Ruff lint findings in untouched portions of `cfg_mutations.py` remain baseline
debt outside this slice.

The mandatory cache-disabled A560 canary at clean code SHA `c119a970b` failed
safely in 19.29 seconds after the bounded poisoned-generation restart. Log:
`.tmp/rhad-a560-folded-direct-anchor-c119a970b.txt`; primary DB:
`.tmp/rhad-a560-folded-direct-anchor-c119a970b/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
There was no process segfault or numeric INTERR. The strict comparison now
rejects an earlier frontend-normalization divergence before the broad Rhad
composition is reached, so this run must not be described as broad C5 or C6.

The DB's chronological first failed transaction is attempt
`a553079b53d94276b0b6e53cfe5312bf`, plan
`frontend-normalization:0xA560:g1:root@0x40A5F0`. It completes immutable
preflight and live realization, then poisons at `runtime:stage` before root
publication because staged observation differs from preflight. The first
subjects are `fallthrough-helper:native-body-edge@0x40A607:instruction-eas`
and the same helper's terminator; the discrepancy repeats across generic
imported direct edges and their planned fallthrough helpers. The later
`runtime:post_observation_contract` failure
`CFG_50860_SUCC_MISMATCH@blk[1]` is downstream and is not the first obligation.

The highest level in this canary is C4 prepublication authority for the
frontend fragment; the previously committed one-fragment C5 milestone remains
the branch-wide high-water mark. Continue from helper creation parity: project
the helper's exact structural transfer semantics and realize the identical
immutable authority, using its planned `PlanBlockRef` and creation witness.
Do not suppress instruction/terminator comparison, assign a native rewrite EA
to a structural helper, or resume broad Rhad publication until this first
frontend obligation passes.

**2026-07-26T02:59:00-0700 — planned helper transfer parity complete**

Functional commit `5a61e42f4` gives every planned semantic fallthrough helper
one portable structural `GOTO` with no counterfeit native instruction
coordinate. Immutable projection records `terminator_kind=GOTO`,
`terminator_ea=None`, and an empty semantic instruction sequence. Live
observation verifies that the PlanBlockRef-owned SDK block is one-way, has one
successor, contains exactly one `m_goto`, and carries `MBL_GOTO` before
normalizing that synthetic instruction to the same portable representation.
Ruff-only commit `c6b15539a` formats the runtime proof. The focused helper gate
is 18/18 green and the transaction/projection gate remains 106/106 green.

The mandatory cache-disabled A560 canary at clean SHA `c6b15539a` again
failed safely in 19.13 seconds after the bounded poisoned-generation restart.
Log: `.tmp/rhad-a560-helper-transfer-c6b15539a.txt`; primary DB:
`.tmp/rhad-a560-helper-transfer-c6b15539a/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
There was no process segfault or numeric INTERR. All fallthrough-helper
instruction and terminator divergences from the preceding canary are gone.

The chronological first failed transaction is now attempt
`a85cc1d0076f4f9fab77f021b5d529bc`, plan
`frontend-normalization:0xA560:g1:root@0x40A5F0`, at `runtime:stage` after
immutable preflight and live realization but before publication. The first
subject is the clone-published root
`native[0x40A5F0-0x40A5F1,0x40A5F6-0x40A5F7,0x40A5F8-0x40A5F9,0x40A5FE-0x40A5FF;exact=0x40A5F0,0x40A5F6,0x40A5F8,0x40A5FE]:replacement`,
whose realized instruction sequence and terminator differ from immutable
projection. The same two fields diverge on 23 generic imported direct stubs;
there are zero remaining helper divergences.

This run again reaches C4 prepublication authority for the frontend fragment,
while the earlier one-fragment C5 milestone remains the branch-wide high-water
mark. Continue with the root replacement first: compare its immutable and
realized instruction coordinates and terminator kind/EA, then encode only the
typed direct-transfer behavior actually owned by its prepared block. Do not
restore broad semantic publication or treat the 23 later imported stubs as the
first obligation.

**2026-07-26T03:09:06-0700 — conditional-select projection parity complete**

Functional commit `9e4850244` makes immutable projection describe the same
typed contraction that the live backend performs for a clone-owned
`FragmentConditionalSelectEnvelope`: retain the instruction prefix through
the exact predicate anchor, make that anchor the portable conditional
terminator, and reject missing or ambiguous anchors before mutation. Imported
conditional-select envelopes remain untouched. Ruff-only commit `fc908996d`
formats all tracked Python sources; one production file changed. Both live
conditional-select runtime cases are green, strict immutable-versus-realized
comparison is exercised directly, and the transaction/projection gate remains
106/106 green. Commit-time ast-grep, import-cycle, portable-core shape, and all
14 import-linter contracts pass.

The mandatory cache-disabled A560 canary at clean code SHA `fc908996d` failed
safely in 20.03 seconds after the bounded poisoned-generation restart. Log:
`.tmp/rhad-a560-select-projection-fc908996d.txt`; primary DB:
`.tmp/rhad-a560-select-projection-fc908996d/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
There was no process segfault or numeric INTERR. The clone-published root and
all planned fallthrough-helper instruction/terminator divergences from the
preceding canaries are absent.

The DB's chronological first failed transaction is attempt
`9699a07508cf466e89ec3483d046207b`, plan
`frontend-normalization:0xA560:g1:root@0x40A5F0`. It records `planned`,
`projected`, `preflighted`, and `bound` with `mutation_started=0`, then
`realizing` and a poisoned `runtime:stage` failure before root publication.
The first subject is generic imported direct stub
`native[0x40A69A-0x40A6A0;exact=0x40A69A]:imported`, whose realized
instruction sequence and terminator differ from immutable projection. The
same two fields diverge on 23 imported stubs; there are zero former-root and
zero helper subjects. The attempt records 139 creation witnesses, with 131
invalidated by the poisoned generation, and the DB contains no numeric INTERR.

This canary reaches C4 prepublication authority for the frontend fragment; the
earlier one-fragment C5 milestone remains the branch-wide high-water mark. The
next vertical obligation is the first generic imported direct stub at stable
anchor `0x40A69A`: determine its immutable prepared transfer and exact live
contraction, then encode only that typed structural ownership. Do not assign a
proved rewrite coordinate that the operation does not own, suppress strict
instruction/terminator comparison, or widen to broad Rhad publication.

**2026-07-26T03:19:55-0700 — structural direct projection reaches live C5**

Functional commit `814a761fb` distinguishes plan-owned structural direct
transfers from native semantic rewrites. For an imported direct operation with
no `FragmentDirectTransferRewrite`, live observation now accepts a synthesized
`m_goto` only after proving its one-way topology, exact target operand,
`MBL_GOTO` shape, lack of native origin, payload-origin completeness, and
matching immutable structural terminator. The synthetic safe EA is then
removed from portable semantics; native payload coordinates and proved rewrite
anchors remain visible. Ruff-only commit `d23a15003` formats all tracked Python
sources; two files changed. The production participant, terminal publication,
prepared native direct-rewrite, and transaction/projection gates are green at
4/4 and 106/106. Commit-time architecture gates pass.

The mandatory cache-disabled A560 canary at clean code SHA `d23a15003` ran for
47.63 seconds and failed only after advancing into later decompilation and
GLBOPT. Log: `.tmp/rhad-a560-structural-direct-d23a15003.txt`; primary DB:
`.tmp/rhad-a560-structural-direct-d23a15003/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
There was no process segfault or numeric INTERR. All former frontend root,
helper, generic-direct instruction, and generic-direct terminator divergences
are absent.

The DB records frontend-normalization attempt
`800bacd95fa5464a89b5eccbb97019b3` as fully committed: staged fragment, root
publication, and post-observation receipt all succeed, with 139 creation
witnesses and no invalidations. Later frontend retries also commit. This is a
fresh exact A560 C5 transaction, though it is not final A560 acceptance or C6.

The first chronological canonical-composition rejection, attempt
`cc53c1662c6f4e38bc348c033fd8d84f`, is a clean, zero-write
`return_carrier_integrity` request for CALLS companion preparation. The
lifecycle satisfies that request and retries, so it is not the remaining
blocker. The first unresolved transaction is attempt
`296ecd12b3014bf380268145b9668779`: immutable projection, preflight, and final
binding pass with no writes; live realization starts and then poisons at
`runtime:stage` before root publication. Strict comparison reports 135
flag-write divergences and 18 terminator divergences, with no instruction-row
or block-set divergence. The first subject is imported block
`native[0x40A70E-0x40A73F;exact=0x40A70E,0x40A728,0x40A72E]:imported:flag-writes`.
The failed canonical attempt has 229 creation witnesses, 219 invalidated by
the poisoned generation.

The highest current level is therefore C5 for the exact frontend transaction;
canonical composition reaches C4 and fails its strict staged proof. Continue
from flag-write authority at imported block `0x40A70E`: compare immutable
prepared writes with SDK-observed writes and preserve only typed native-origin
semantics. Do not hide the 18 later terminator mismatches, weaken staged
comparison, or claim C6.

**2026-07-26T03:35:09-0700 — no-corridor flag authority aligned**

Functional commit `b93aa7bab` makes immutable imported-block projection obey
the same typed flag-write authority as live staged observation. A plan with no
`FragmentFlagCorridor` now carries no incidental condition-code-write
obligation; a plan that declares a corridor still preserves and strictly
compares the exact native write coordinates. The production participant
regression was red with immutable `{0x500000}` versus live `{}`, then the
participant plus selected-corridor safety gate passed 5/5. Ruff check and
format check pass for both touched files, and commit-time ast-grep, cycle,
portable-shape, and all 14 import-linter gates pass.

The mandatory cache-disabled A560 canary at clean code SHA `b93aa7bab`
completed without a process crash, numeric INTERR, or poisoned generation.
Log: `.tmp/rhad-a560-flag-write-b93aa7bab-db.txt`; primary DB:
`.tmp/rhad-a560-flag-write-b93aa7bab/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
Both frontend-normalization attempts commit through observation and receipt;
each records 139 creation witnesses with zero invalidations. This is exact C5
frontend proof, not C6. The emitted eight-line pseudocode still contains one
false `while ( 1 )`.

Canonical composition does not reach staged comparison in this canary, so the
absence of the previous 135 flag-write divergences is not itself a live C4
proof. The first canonical attempt requests CALLS companion preparation with
zero writes; the lifecycle captures the companions and consumes the bounded
restart. The retry then rejects cleanly in preflight, again with zero writes,
at
`return_carrier_integrity:return-carrier:terminal_return@0x40C7F6:0x19A7218A`:
`CALLS companion stack window cannot be rebound; call=0x40A91C top=12 span=16`.

The highest level in this canary is C5 for frontend normalization and C3 for
canonical composition; the branch-wide earlier one-fragment C5 remains valid.
Continue from the stable call anchor `0x40A91C` by comparing the captured CALLS
stack-window authority with the current canonical terminal-carrier binding.
Do not weaken return-carrier preflight, infer a block from a stale serial, or
resume broad route publication before this zero-write obligation is satisfied.

**2026-07-26T04:58:28-0700 — reachable stack-capacity corridor advances canonical staging**

Functional commit `d817135ec` replaces the detached-tail experiment with a
manager-owned native stack-capacity corridor over the already-reachable,
stack-neutral instruction at `0x40A574-0x40A57A`. The corridor installs and
releases both auto-SPD boundaries transactionally, records the portable call
inventory and original stack facts, and leaves no helper tail or compatibility
path. Ruff-only commit `c475422bf` formats that slice. The focused resolver and
manager-native-preanalysis gate is 276/276 green.

The first exact canary at `c475422bf` exposed a real SIGSEGV, not a verifier
INTERR: the hxe_stkpnts observer called `mba.stkoff_ida2vd(0)` before Hex-Rays
had initialized the coordinate machinery. Functional commit `1b3613898`
removes that unsafe phase crossing. The callback now observes only the raw
`tmpstk_size` scalar, and its regression test fails if coordinate conversion is
attempted during hxe_stkpnts. No compatibility diagnostic field remains.

The mandatory cache-disabled A560 canary at clean SHA `1b3613898` was
reproduced in pinned image `d810-idapro-9.3-test-runtime:py313-v1`. Log:
`.tmp/rhad-a560-stack-safe-pinned-1b3613898.txt`; primary DB:
`.tmp/rhad-a560-stack-safe-pinned-1b3613898/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
There is no process crash or numeric INTERR. The worker refuses poisoned output
after the bounded restart, so this is not C6 or final A560 acceptance.

The DB records raw `tmpstk_size=0` during all three hxe_stkpnts observations;
that phase-local scalar is diagnostic only. The operative proof is that the
old zero-write `call=0x40A91C top=12 span=16` rejection is gone. After one clean
CALLS-companion request, canonical attempts reach immutable projection,
preflight, final binding, and live realization. Frontend normalization remains
exact C5 with committed 260/260 receipts and 139 non-invalidated creation
witnesses per attempt.

Canonical attempt `2f8474b699414675b88cf60bf920cf03` then poisons at
`runtime:stage` after 403/406 operations, before root publication. Strict
comparison reports 18 imported-block terminator divergences and no former
flag-write blocker. The first stable subject is
`native[0x40A903-0x40A922;exact=0x40A903]:imported:terminator`; the same ordered
failure repeats after the lifecycle restart. Each failed attempt records 229
creation witnesses, 219 invalidated with the poisoned generation.

The highest current level is C5 for exact frontend normalization and C4 plus
partial live staging for canonical composition. Continue from terminator
authority at imported block `0x40A903`: compare the immutable prepared
terminator with the realized SDK terminator and encode the typed contraction
owned by that operation. Do not weaken strict comparison, reclassify partial
writes as C5, or resume broad 91-route publication.

**2026-07-26T05:18:23-0700 — analyzed CALL owners align immutable and live terminators**

Functional commit `729009178` makes one shared SDK call-owner recognizer the
authority for immutable native-body preparation, CALLS continuation splitting,
and live terminator observation. A CALL_FALLTHROUGH block now requires exactly
one top-level or nested analyzed call owner before any SDK write; its immutable
instruction inventory ends at that owner, and the realized `m_mov(m_call(...))`
tail projects as a typed CALL terminator. The duplicate deferred-modifier
recognizer is deleted. Ruff-only commit `95bdcddcd` formats the slice.

The strengthened CALLS-built imported-call regression is green. The full
semantic-fragment backend file improves from the clean `0a4e087f7` baseline of
113 passed / 5 failed to 114 passed / 4 failed; the four remaining failures are
the same pre-existing strict-authority failures. Eight focused detached-import
preparation and analyzed-call tests pass. Ruff check passes, and both commits'
ast-grep, cycle, import-linter, and portable-shape hooks pass.

The mandatory pinned, cache-disabled A560 canary at clean code SHA
`95bdcddcd` completes without a process crash or numeric INTERR. Log:
`.tmp/rhad-a560-call-owner-95bdcddcd.txt`; primary DB:
`.tmp/rhad-a560-call-owner-95bdcddcd/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The worker refuses poisoned output after the bounded restart, so this is not C6
or final A560 acceptance.

The DB proves the former 18 imported terminator divergences are gone. Frontend
normalization remains exact C5: each committed attempt applies 260/260
operations, passes 639 prepublication and 1180 postpublication outcomes, and
records 139 creation witnesses with zero invalidations. After one clean CALLS
companion request, canonical attempts apply 403/406 staged operations and pass
all 1057 prepublication validation outcomes before the detached route oracle
rejects publication.

The first unresolved attempt is `2af186abedba44e4846034008bf61fca`.
Its monotonic first failure is `runtime:detached_route_oracle` at route
`rhad:0x40A560:flow_route:0x40BED0` (`blk@0x40BECC`): candidate observation
finds the unowned staged successor
`fallthrough-helper:route:state-choice@0x40BECC:0xEC71CA67:0xA0716E5B`.
Route `rhad:0x40A560:flow_route:0x40C4D2` independently exposes the same defect
through `fallthrough-helper:native-state-choice@0x40C4C3`. The failed attempt's
229 creation witnesses are invalidated only after the poison latch fires.

The highest current level remains C5 for exact frontend normalization and C4
for canonical composition: the complete staged projection passes strict
prepublication validation but root publication is not attempted. Continue from
planned fallthrough-helper ownership at `0x40BECC`, making the helper an owned,
reconstructible route endpoint in detached oracle observation. Do not hide the
helper, relax the oracle, assign a raw serial, or resume broad publication
before both unowned-helper divergences are eliminated.

**2026-07-26T05:30:05-0700 — canonical A560 publication reaches exact C5**

Functional commit `debc6f198` teaches the detached oracle to retain and prove
planned fallthrough helpers as physical route witnesses. A helper is accepted
only when its deterministic ID and descriptor match the operation, it has a
same-generation staged identity binding with no native identity, it is the
adjacent one-way empty synthetic block, and its only edge reaches the declared
semantic target. Only after that proof is the physical helper hop normalized
to the donor route target. A negative test rejects a published or otherwise
unowned helper. Ruff-only commit `9f803be6a` formats the slice. The detached
oracle unit file is 13/13 green, the manager translation test and gateway
reference-route tests are green, and both commit-time architecture gates pass.

The mandatory pinned, cache-disabled A560 canary at clean code SHA
`9f803be6a` ran for 78.49 seconds without a process crash, numeric INTERR, or
poisoned generation. Log: `.tmp/rhad-a560-route-helper-9f803be6a.txt`; primary
DB: `.tmp/rhad-a560-route-helper-9f803be6a/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.

The DB records all 93 detached donor-route comparisons as matched. Canonical
attempt `2b6c9c5686284369ad9c92760a8944b1` commits 406/406 operations, passes
1057 prepublication and 1961 postpublication outcomes, publishes its root, and
records 229 creation witnesses with zero invalidations. Frontend normalization
also remains exact C5 at 260/260 operations with 139 non-invalidated witnesses.
This is the first complete broad canonical C5 publication on the integration
branch.

The E2E test still fails at C6. The first textual assertion is stale only in
its local name (`Param[1]` versus the equivalent `v50[1]`), but comparison with
`samples/oracle/sub_40A560_reference.c` proves the output is not semantically
complete: the command-line argument decoding loop and both `sub_40C8B0` calls
are absent, WNDCLASS initialization is incomplete, the keyed `sub_4069C0`
branch is absent, one cleanup slot and its callback are absent, and the terminal
return is absent. Do not relax the E2E oracle to accept the current output.

The highest current level is therefore C5 for both frontend normalization and
canonical composition, not C6 and not final A560 acceptance. The next vertical
obligation is reference-body effect coverage, beginning with the first omitted
command-line decoding subgraph after `CommandLineToArgvW`. Determine its exact
native anchors and why a 93/93 route-equivalent published fragment still loses
that reachable body before changing the oracle or adding more routes.

**2026-07-26T06:44:00-0700 — semantic ownership is enforced before displaced cleanup**

Commit `1a213ed9c` added the post-observation entry-reachability backstop. Its
83-second exact canary rejected the hypothesis that post-observation collapse
was the current C6 defect: canonical publication still reached C5, while the
remaining output defect was downstream. Functional commit `15cb59236` then
persisted receipt-backed, serial-free semantic operation ownership in the B1
session state; Ruff-only commit `0f2e40ded` formatted that slice. The ownership
is installed only after postvalidation and a committed receipt, is shared by
independent authority instances, and expires on evidence-generation advance.

The first exact canary at `0f2e40ded` hit the worker's 600-second timeout. A
bounded mounted-DB probe proved this was not Hex-Rays slowness, poison, or an
INTERR: canonical C5 committed, then ordinary cleanup opened 371 distinct
zero-write transactions that all rejected cleanly for overlap with committed
operation `route:state_assignment@0x40C685:0xAE5A330B` at native envelope
`0x40C665-0x40C696`. The caller classified the backend's `preflight` phase with
a vocabulary that accepts only `semantic_preflight`; the resulting `ValueError`
escaped before the cleanup pass counter advanced and recreated the plan on the
next block callback.

Functional commit `651d181f0` introduces one shared typed overlap proof, keeps
the participant's zero-write preflight backstop, and consumes that proof in the
executor before transaction construction. It also maps the latent backend
fallback to `semantic_preflight`. The focused architecture gate is 187/187
green; Ruff is clean apart from the pre-existing intentional E402 observability
import in `executor.py`, and all commit-time architecture gates pass.

The mandatory pinned A560 canary at `651d181f0` now terminates in 78.67 seconds.
Primary DB:
`.tmp/rhad-a560-owner-gate-651d181f0/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The DB contains only four CFG attempts: three committed attempts across two
plans and one clean zero-write CALLS-companion request. No displaced-cleanup
transaction is opened, no generation is poisoned, canonical publication
commits 406/406 operations, all 93 detached routes match, and the two fragment
plans retain 672 non-invalidated creation witnesses. Exact C5 therefore remains
proven.

C6 fails with `INTERR: 50409`. The SDK verifier documents 50409 as an `m_nop`
surviving to ctree because a microcode callback changed the MBA but returned
zero. The diagnostic snapshots themselves contain no `m_nop`; the contradiction
occurs after the committed C5 callback. Production code confirms the seam:
`StateMachineCffUnflattener.run_state_machine_unflatten()` unconditionally
returns zero under its legacy convergence contract even after the backend has
committed a receipt-backed FragmentPlan. The DB cannot currently record the
later verifier code, so its highest level is C5 and its last clean transient
failure is the resolved return-carrier companion request. The first current
failed obligation is
`hexrays_callback_change_accounting:committed_fragment_publication`: report one
logical callback change iff this invocation committed at least one fragment,
while preserving the legacy zero-return cadence when no fragment committed.
Record that decision in the diagnostic lifecycle and rerun the exact canary
before any further semantic-route work.

**2026-07-26T07:47:00-0700 — PREOPT publication has one accountable owner; 50409 remains**

Commit `1779545a5` made fragment callback accounting receipt-backed, and the
subsequent callback diagnostics at `8aa4cfee0`, `673d95a0c`, and `d314182ec`
proved that D810's block, instruction, and GLBOPT callbacks do not introduce an
unreported top-level or nested `m_nop`. Across those exact canaries, the only
observed NOP deltas were two EA-anchored JumpFixer writes at MMAT_CALLS; both
callbacks returned `1`, and both NOPs were absent from the later snapshots.

The attempted `hxe_preoptimized` repair at `2108d7e06` was falsified by the
exact canary: returning `MERR_LOOP` escaped immediately as `INTERR 50443`.
The SDK header makes the reason explicit: the requirement to return
`MERR_LOOP` after mutation belongs to `hxe_glbopt`; `MERR_LOOP` is an internal
code that must never be reported. It is not a valid successful-modification
signal for `hxe_preoptimized`.

Functional commit `3501ae4e2` therefore removes structural publication from
`hxe_preoptimized` and deletes its displaced callback-refresh channel. The
first PREOPT instruction-optimizer callback is now the sole production owner:
it publishes once, returns the optimizer's nonzero modified result, and
propagates generation poison. Ruff-only commit `89d6a291e` formats the slice.
The affected lifecycle and optimizer runtime gate is 58/58 green, the focused
ownership gate is 11/11 green, and all commit-time architecture gates pass.

The mandatory pinned, cache-disabled A560 canary at clean SHA `89d6a291e` ran
for 132.05 seconds. Log:
`.tmp/rhad-a560-optinsn-owner-89d6a291e.txt`; primary DB:
`.tmp/rhad-a560-optinsn-owner-89d6a291e/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
The immediate 50443 is gone, but ctree generation still fails with
`INTERR 50409`; this is not C6 or final A560 acceptance.

The DB proves exact C5 remains intact. Frontend normalization commits two
260/260 transactions across the generated restart, canonical composition
commits 406/406 operations, all 93 detached route comparisons pass, and no
generation is poisoned. The only callback NOP deltas are the same two
MMAT_CALLS JumpFixer sites, each reported with callback result `1`. Every
persisted snapshot through `MMAT_GLBOPT2 pre_d810` contains zero top-level or
nested NOPs. Hex-Rays reaches `hxe_glbopt`, structural analysis, and session
finish before the ctree verifier reports 50409.

The highest level remains C5. The first failed obligation is
`C5_postpublication_callback_integrity:ctree_nop_absence`. The next diagnostic
vertical step is an explicit live NOP inventory at `hxe_glbopt` entry and exit,
including an absence record, so the DB can distinguish a pre-existing NOP from
one created internally after the final callback. Do not resume Rhad semantic
composition or weaken the 50409 oracle until that boundary is proven.

**2026-07-26T08:13:12-0700 — JumpFixer folds enter the typed coordinator; 50409 persists**

Functional commit `db5772985` removes JumpFixer's direct
`DeferredGraphModifier.apply()` execution path. A proved constant fold now
emits one portable `ConvertToGoto`, compiles it with the exact current identity
mapping, and executes it through `HexRaysMutationBackend.apply` and the shared
project/preflight/bind/realize/observe coordinator. A rejected transaction
returns zero instead of claiming a callback mutation. Ruff-only commit
`c43b2e133` formats the tests. The focused runtime and architecture gate is
30/30 green; the strict 41-row donor parity gate, ast-grep scan, and all 14
import contracts remain green.

The mandatory pinned, cache-disabled A560 canary at clean code SHA
`c43b2e133` completed in 146.68 seconds and still failed at ctree generation
with `INTERR 50409`. Primary DB:
`.tmp/rhad-a560-typed-jump-fixer-c43b2e133/test_real_loader_matches_reach0/sub_40A560.diag.sqlite3`.
This is not C6 or final A560 acceptance.

The DB proves C5 remains intact. Frontend normalization commits 260/260 on
both generated attempts; canonical composition commits 406/406; all 93 donor
routes match; and no generation is poisoned. The former two direct JumpFixer
writes at `blk247@0x40C115` and `blk254@0x40C217` now appear as four ordinary
typed attempts across the generated restart. Every attempt reaches immutable
projection and rejects cleanly in preflight with `mutation_started=0` because
its source overlaps the committed canonical semantic operation. No JumpFixer
mutation receipt is emitted, so the previous 1-planned/0-applied committed
receipts are gone.

Both final `hxe_glbopt` boundaries remain explicit DB evidence rather than a
log inference: snapshots 7 and 16 record entry and exit
`hexrays_callback_nop_inventory` rows with `inventory_count=0`. Therefore no
literal `m_nop` is live when D810 enters or leaves the final GLBOPT2 callback,
even after the direct JumpFixer path is removed. The typed JumpFixer receipt
hypothesis is rejected.

The verifier boundary remains the first failed obligation:
`C5_postpublication_callback_integrity:ctree_nop_absence`. Continue with a
debugger breakpoint at the 50409 verifier arm to capture the exact live
`minsn_t`, owning block, and creation interval after the final callback. Do not
restore direct cleanup writes, weaken semantic ownership, or infer an
acceptable C6 result from the clean C5 receipts.

**2026-07-26T20:19:32Z**

2026-07-26 GENERATED reference-semantic publication pivot, amending this active ticket without restarting completed work.

Authoritative target state is HEAD b7d65b11ced6b815b21aa9897a0cb8eec9f669cb on diff/lrea-portable-cfg-integration. The worktree has one pre-existing untracked evidence test, tests/system/e2e/test_rhad_generated_microcode_capture.py; preserve it as user-owned work. The strict portable CFG transaction parity gate passes all 41 guarantees under pyenv Python 3.13.5.

Latest A560 DB inspected before implementation: .tmp/rhad-a560-gdb-late-attach-b7d65b11c/sub_40A560.diag.sqlite3. It records the existing broad PREOPT foundation: two committed 260/260 frontend-normalization receipts, one committed 406/406 canonical receipt, 93 matched detached route comparisons, and snapshots through MMAT_GLBOPT2. It does not contain a reference-compiler plan or a route-specific GENERATED publication receipt. The preceding exact cache-disabled canary at c43b2e133 remains C5 and fails at ctree with INTERR 50409; that is historical PREOPT evidence, not acceptance of the new checksum.

Reorient the immediate milestone from broad PREOPT publication to one bounded reference-semantic GENERATED checksum. Preserve the current FragmentPlan -> PatchPlan -> final binding -> shared coordinator authority, immutable preflight, creation witnesses, receipts, poisoning and restart, semantic ownership, and diagnostic events. Treat .worktrees/lrea-generated-publication-replay as behavior authority for reference-operation compilation and GENERATED lifecycle only, and .worktrees/rhad-generated-publication-experiment as historical evidence. Do not merge or cherry-pick either donor wholesale, add a compatibility layer, call DeferredGraphModifier directly, or create a second mutation gateway.

Compile the reference cmovl-selected operation over 0x40A5F0-0x40A605, preserving comparison 0x0BB2D365, true target 0x40B6C0, false target 0x40A607, exact imported closure, and exits 0x40A61B, 0x40A68C, and 0x40B790. Publish the predicate, both arms, terminal rewrite, closure, and boundary bindings as one transaction at GENERATED, then prove survival through PREOPT, the first authoritative CFG maturity, CALLS, and ctree without redo, poison, numeric INTERR, or mutation outside the shared coordinator.

The first unmet obligation is architectural mapping, not mutation: map the replay compiler, GENERATED producer, publication lifecycle, receipt, and maturity validation onto current production seams; enumerate and adapt or reject every replay dependency that bypasses current transaction authority. Then implement in separate compiler, GENERATED lifecycle, checksum semantics, diagnostic proof, and regression-repair commits. Do not resume broad 93-route PREOPT publication during this checksum and do not claim full A560 restoration from checksum success.

**2026-07-26T20:43:55Z**

Compiler slice committed as 2d370a58b. Added an IDA-free RhadConditionalRoute/RhadReferenceLedger compiler into the current FragmentPlan, exact A560 comparison 0x0BB2D365, producer 0x40A5F0, branch 0x40A5F6, terminal 0x40A605, targets 0x40B6C0/0x40A607, nine imported identities, and exits 0x40A61B/0x40A68C/0x40B790. Focused compiler plus FragmentPlan tests: 47 passed. sg scan clean; all 14 import contracts kept; strict 41-row parity gate PASS. Current first unmet obligation: actual-MMAT_GENERATED lifecycle seam, before transaction-profile work.

**2026-07-26T20:51:42Z**

Checkpoint 14917ad00: added manager-owned actual MMAT_GENERATED optinsn seam, once-per-MBA-generation lifecycle guard, graph-free identity indexing at GENERATED, complete injected live ports, recursion suppression, and modified-return propagation. Verification: 76 focused tests pass; sg clean; all 14 import contracts kept; strict 41-row parity gate PASS. Existing untracked capture test remains untouched.

**2026-07-26T23:00:17Z**



**2026-07-26T23:00:32Z**

2026-07-26 GENERATED checksum C6 checkpoint at commit c9cb1aab8.\n\nThe bounded A560 reference-semantic route now commits at actual MMAT_GENERATED through the existing FragmentPlan -> PatchPlan -> final binding -> shared coordinator -> HexRaysMutationBackend -> DeferredGraphModifier path. The graph-free publication profile performs no build_graph/use-def/dirty operations at GENERATED, imports the exact nine-block closure, rewrites 0x40A605 to the proven comparison 0x0BB2D365 with true 0x40B6C0 and false 0x40A607, and preserves exits 0x40A61B/0x40A68C/0x40B790.\n\nPrimary canary evidence: .tmp/generated-checksum-dev33.txt, 1/1 passed through ctree. The E2E copies and queries the diagnostic SQLite DB: one 13/13 committed receipt, pre/post validation and logical root publication confirmed, no poison or INTERR, route-specific passed observations at MMAT_GENERATED, MMAT_PREOPTIMIZED, MMAT_LOCOPT, and MMAT_CALLS, plus CMAT_FINAL. CALLS observes the expected optimized-away source, no surviving ijmp at 0x40A605, and retained reachability of 0x40B6C0. The binary SHA256 remains 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c.\n\nFailure policy is covered explicitly: generated preflight rejection is zero-write and non-poisoning; a generated post-write verifier failure poisons and does not roll back. Focused local gate is 157/157; actual-generated capture and final canary are green. Commit hooks pass sg, import-cycle detection, all 14 import contracts, and portable-core shape lint. The pre-existing user-owned untracked tests/system/e2e/test_rhad_generated_microcode_capture.py remains untouched. This proves only the requested checksum route, not full A560 restoration.

**2026-07-26T23:00:55Z**

Correction to the preceding escaped note: commit c9cb1aab8 is the bounded GENERATED checksum checkpoint. The authoritative evidence is .tmp/generated-checksum-dev33.txt plus its copied SQLite assertions: one 13/13 committed receipt; passed GENERATED, PREOPT, LOCOPT, CALLS, and CMAT_FINAL observations; no redo, poison, or INTERR. It proves this one route only, not full A560.

**2026-07-26T23:24:23Z**

C6 checksum accepted on 2026-07-26 at 25f74026b: exact A560 GENERATED canary 1 passed; diagnostic receipt 13/13 committed, attempt committed and unpoisoned, route passed GENERATED/PREOPT/LOCOPT/CALLS, CMAT_FINAL present, no rollback or INTERR; strict 41-row parity passed; focused unit 157 passed; runtime seam 210 passed; protected Hodur/Sub7FFD/Tigress/Approov 13 passed; input SHA-256 remains 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. This is the bounded checksum route only, not full A560 restoration.

**2026-07-26T23:39:04Z**

2026-07-26 second GENERATED shape selection: reference-order inventory has 228 A560 indirect-jump operations (39 cmov-selected, 64 simple, 117 existing-conditional-plus-indirect, 8 setcc-indexed). Earliest unproved simple_indirect_jump is reference _fixup_jmp_and_possible_jcc at source 0x40A607 / transfer 0x40A619, no predicate producer, semantic target 0x40A61B, owned corridor [0x40A607,0x40A615,0x40A617,0x40A619]. The accepted 0x40A605 body imports its source but deliberately preserves the 0x40A619 indirect tail, so it is not proved. Target-rooted closure is native roots [0x40A61B,0x40A62D,0x40A740] with boundary exits [0x40A633,0x40A74C] and expected Hex-Rays tail split witnesses at 0x40A631 and 0x40A74A. First unmet obligation: extend the typed Rhad compiler vocabulary/ledger beyond RhadConditionalRoute to a direct-route type that emits proof-owned FragmentDirectTransferRewrite; reject unsupported shapes before live mutation. Preserve the accepted 0x40A605 transaction and use the same producer/coordinator/backend.

**2026-07-26T23:45:11Z**

2026-07-26 full read-only inventory checkpoint: generated and validated 228 reference-order rows from pinned donor 21b0d4783703bc4fb6910cfae51d92cd683d2c65 plus unchanged fixture SHA-256 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Scratch artifact /tmp/rhad-a560-indirect-jump-reference-inventory.json has SHA-256 473c93f9ee089272c049259ba6a61901983fa23e685ab87cbcfb44f919b984bf. Counts are 39 cmov-selected, 64 simple, 117 existing-conditional-plus-indirect, 8 setcc-indexed. All 228 rows record symbol/variant, source+transfer EAs, predicate/flag producer, targets, owned corridor, target-rooted closure, exits, compiler support, and GENERATED proof. 177 operations have all target closures available in the current portable source-plan graph; 51 honestly retain at least one typed root_unavailable closure instead of guessed topology. Cross-checks reproduce the accepted 0x40A605 nine imported anchors and three exits exactly, and prove reference-order row 2 / 0x40A619 is the earliest unproved simple route with complete five-anchor target closure and exits 0x40A633/0x40A74C. This is evidence only; no production code changed while the single-batch design approval remains pending.

**2026-07-26T23:49:07Z**

2026-07-26 pre-implementation structural design correction: an in-memory two-operation FragmentPlan spike proved that changing the accepted batch to CANONICAL_SEMANTIC_LOWERING is invalid. Canonical purpose rejects the accepted 0x40A605 replacement-root computed normalization because it requires imported native-body proof, and it cannot retain the accepted frontend work-item scope. The correct typed missing contract is narrower: keep FRONTEND_NORMALIZATION and admit a direct transfer rewrite only when all existing proof conditions hold plus reference_route_authority is present, the source is an IMPORT_NATIVE block owned by a native body, the operation id is in that body proof_ids and the frontend selected_obligation_ids, and the RouteOracleRun binds the same input/function. Backend/coordinator code does not branch on publication_purpose, so this is a portable FragmentPlan admission contract, not another mutation path or gateway. Previous proposal to switch the batch purpose is withdrawn.

**2026-07-27T01:30:10Z**

2026-07-26 second distinct GENERATED operation shape proved at fc195e15b. Reference-order row 2 simple_indirect_jump now compiles and publishes through the same accepted transaction architecture: source native 0x40A607, source block anchor 0x40A615, transfer 0x40A619, semantic target 0x40A61B, owned corridor 0x40A607/0x40A615/0x40A617/0x40A619, imported closure 0x40A61B/0x40A62D/0x40A631/0x40A740/0x40A74A, exits 0x40A633/0x40A74C. Commits 214ddf741, 3e9395dfc, and fc195e15b add the typed direct source contract, shared GENERATED publication, diagnostic proof, and permanent regression coverage while preserving accepted 0x40A605 behavior. The exact canary reaches ctree and proves one 19/19 committed receipt for both complete operations, 14 reconstructible imported creation witnesses, typed plan and reference evidence persistence, actual MMAT_GENERATED publication, passed PREOPT/LOCOPT/CALLS lifecycle observations, removal of the 0x40A619 indirect transfer, survival of 0x40A61B while its source topology exists, legitimate later source retirement with no residual ijmp/icall and required reachable semantics, CMAT_FINAL, and no poison, rollback, redo, alternate mutation path, or numeric INTERR. Final gates: focused compiler/FragmentPlan/publication 166 passed; transaction/runtime seam 210 passed; exact A560 canary 1 passed; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13 passed across the 9-node core and recovered 4-node DSL complement; strict 41-row parity PASS; sg clean; 14/14 import contracts kept; input SHA-256 remains 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c; graphify updated with no tracked delta. The full semantic backend file retains its exact pre-existing four-failure baseline with one added passing regression; the two known broader dispatcher-pattern DSL failures were not chased. This proves two distinct reference operation shapes, not full A560 restoration. Ticket remains in progress. Next obligation is data-first application of the proved simple_indirect_jump shape to remaining same-shape A560 sites before existing_conditional_plus_indirect.

**2026-07-27T02:15:17Z**

2026-07-26 third GENERATED shape preimplementation selection at accepted SHA f50720273. Live 228-row coverage is grouped in docs/experiments/rhad-a560-indirect-jump-coverage-summary.json: cmov_selected_indirect 39 total / 39 vocabulary-supported / 1 compiled / 1 vertically proved / 1 in accepted receipt; simple_indirect_jump 64 / 64 / 1 / 1 / 1; existing_conditional_plus_indirect 117 / 0 / 0 / 0 / 0; setcc_indexed_table 8 / 0 / 0 / 0 / 0. Selection follows the inventory rather than expectation: reference-order 8 rhad:route@0x40A6A4, variant existing_conditional_plus_indirect, symbol JumpInliner._fixup_jmp_and_possible_jcc, source 0x40A68C, flag producer 0x40A692, predicate 0x40A698, selected value 0x40A69A, join/source block anchor 0x40A6A0, unresolved transfer 0x40A6A4, signed-less-than taken target 0x40A6A6 and signed-greater-or-equal fallthrough target 0x40A800, owned corridor 0x40A68C/0x40A698/0x40A69A/0x40A6A0/0x40A6A2/0x40A6A4, boundary exit 0x40A9A0. Dependency-closed publication must also include reference-order 7 route:rhad-direct@0x40A68A, which rewrites 0x40A68A to selected source 0x40A68C, plus both accepted operations. First unmet obligation is pre-live and typed: the inventory marks true-arm root 0x40A6A6 unavailable while only the 0x40A800 closure is complete; complete that closure and add a serial-free imported conditional-select compiler contract with native-body proof, selected scope, exact predicate orientation, matching RouteOracleRun, and reference authority. Current GENERATED realization then has one typed gap: it admits detached imported direct rewrites and replacement conditional-selects, but not an imported conditional-select normalized in detached preparation. Design: docs/superpowers/specs/2026-07-26-rhad-third-generated-operation-design.md. Ticket remains in progress and the user-owned untracked capture test remains untouched.

**2026-07-27T03:22:46Z**

2026-07-26 third distinct GENERATED operation shape accepted at 8183a6793. Reference-order row 8 rhad:route@0x40A6A4, variant existing_conditional_plus_indirect, now compiles from typed reference evidence and publishes at actual MMAT_GENERATED through the unchanged shared FragmentPlan -> PatchPlan -> immutable preflight -> final binding -> coordinator -> backend architecture. The complete dependency-closed batch includes route:rhad-direct@0x40A68A and preserves the permanently accepted 0x40A605 cmov-selected and 0x40A619 simple-indirect checksums. One 33/33 committed receipt covers the batch; 24 planned creation identities have reconstructible witnesses; four route-oracle comparisons pass; the 0x40A6A4 indirect transfer is removed; semantic targets 0x40A6A6 and 0x40A800 remain while source topology exists; CALLS legitimately retires the source with no residual ijmp/icall and preserves required reachable semantics; CMAT_FINAL is present; no poison, rollback, redo, alternate mutation path, build_graph at GENERATED, or numeric INTERR occurs. Logical commits: e3ba8783e reference design/inventory; 8560504ce compiler vocabulary; 9ff307f1b owned topology; cd419a778 third batch; af89e4c48 typed closure; b2a31b2a8 shared realization; 6b1ec6638 diagnostics; 37176e6fe regression checksum; 8183a6793 proof record. Final gates: focused compiler/FragmentPlan/GENERATED publication 126 passed; transaction/runtime 210 passed; exact A560 checksum 1 passed; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13 passed; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c; graphify update completed with no tracked delta. The user-owned untracked microcode-capture test remains untouched. This proves three distinct bounded reference operation shapes on the shared GENERATED architecture, not full A560 restoration. Ticket remains in progress. Next obligation is data-first application of the proved existing_conditional_plus_indirect shape to remaining same-shape A560 sites, followed by remaining indirect-jump variants including setcc-indexed tables.

**2026-07-27T05:47:19Z**

2026-07-26 fourth GENERATED shape selection at accepted checkpoint fd81625f8. The 228-row reference inventory selects earliest unproved setcc_indexed_table at reference order 16: rhad:route@0x40A77C, symbol JumpInliner._fixup_index_access, native source/block anchor 0x40A766, flag producer cmp@0x40A768, setcc predicate setl@0x40A76E, index shift 0x40A771, table lookup 0x40A774, additive decode 0x40A77A, unresolved transfer 0x40A77C. Typed table evidence is base 0x48B81C, 32-byte stride, 32-bit little-endian entries, full-EAX zeroing at 0x40A766 followed by 8-bit AL setcc (exact zero extension), admitted indices 0/1, additive key ESI=0xFDEE1C81, entry[0]=0x02528F45 -> false target 0x40ABC6 and entry[1]=0x02528AFD -> true target 0x40A77E. The flag corridor has no intervening flag writer. Owned corridor is 0x40A766/0x40A768/0x40A76E/0x40A771/0x40A774/0x40A77A/0x40A77C; imported closure is rooted at 0x40A77E and 0x40ABC6 with anchors 0x40A77E/0x40A792/0x40ABC6/0x40ABD4/0x40ABDA/0x40ABDE and exits 0x40A794/0x40AEE6/0x40B1D0. Dependency-closed publication must also include reference-order 14 route:rhad-direct@0x40A74A and row 15 rhad:route@0x40A764 before row 16, in addition to the accepted four-operation batch. First unmet obligation is typed and pre-live: the accepted compiler has no setcc_indexed_table operation vocabulary or exact table-derivation proof, and the shared GENERATED realizer does not yet admit a detached one-block computed normalization carrying this evidence. Implement through the existing FRONTEND_NORMALIZATION FragmentPlan -> PatchPlan -> immutable preflight -> final binding -> coordinator path; preserve all accepted 33/33 receipt and checksum regressions. Ticket remains in progress; do not close it.


**2026-07-27T07:21:47Z**

2026-07-27 fourth distinct GENERATED operation shape accepted at 65ef9b419 (code proof SHA 46d010c8ba96e72c241645ead3d911fff6ad0f14). Reference-order row 16 rhad:route@0x40A77C, variant setcc_indexed_table, now compiles from typed flag/index/table/decode evidence and publishes at actual MMAT_GENERATED through the unchanged FRONTEND_NORMALIZATION FragmentPlan -> PatchPlan -> immutable preflight -> final binding -> shared coordinator -> backend architecture. The dependency-closed seven-operation batch preserves the accepted 0x40A605 checksum and adds 0x40A74A, 0x40A764, and 0x40A77C without a second producer, gateway, transaction representation, direct DeferredGraphModifier path, sample-EA production guard, build_graph at GENERATED, or CALLS mutation.

The exact A560 canary reaches CMAT_FINAL with one 55/55 committed receipt and 40 reconstructible creation witnesses. Compiled plan/reference identity is persisted; 0x40A77C is absent after publication; targets 0x40A77E and 0x40ABC6 survive while source topology exists; CALLS legitimately retires the source topology with no residual ijmp/icall and preserved reachable semantics; no poison, rollback, redo, alternate mutation path, or numeric INTERR occurs. Input SHA-256 remains 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c.

Logical commits: 59ee90ec6 compiler vocabulary; ac052c033 seven-operation batch; cac5412ab operation semantics; 61757881d lifecycle diagnostics/exact checksum; 28902412a row15 boundary correction; 46d010c8b typed carrier-plan regression repair; 65ef9b419 proof record. Gates: focused compiler/GENERATED 226/226; transaction/architecture 330/330 with one explicitly deselected stale text-only parameter-name assertion; exact A560 checksum 1/1; pinned protected Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row parity PASS; sg clean; 14/14 import contracts kept; graphify updated with no tracked delta. The broader legacy semantic backend file retains its pre-existing four-failure baseline, and the known two broader dispatcher DSL failures were not chased. The user-owned untracked tests/system/e2e/test_rhad_generated_microcode_capture.py remains untouched.

This proves four distinct bounded reference operation shapes on the shared GENERATED architecture, not full A560 restoration. Ticket remains in progress. Next obligation is data-first instantiation of the proved setcc_indexed_table vocabulary for reference-order row 17 rhad:route@0x40A792, then the remaining same-shape A560 sites before constant-materialization work.

**2026-07-27T15:35:09Z**

2026-07-27 whole-function continuation audit at HEAD cd7b6eafd, preserving the accepted 0x40A605/0x40A619/0x40A6A4/0x40A77C GENERATED proofs and unchanged input SHA-256 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. The authoritative 228-row indirect-jump inventory selects reference row 17, rhad:route@0x40A792 (JumpInliner._fixup_index_access, setcc_indexed_table), as the first unproved operation. Native evidence is xor eax,eax @0x40A77E; cmp ebx,0x2100AFDD @0x40A780; setge al @0x40A786; mov eax,[eax*8+0x48B4F8] @0x40A789; add eax,esi @0x40A790; jmp eax @0x40A792. Table entries independently decoded from the unchanged binary with additive key 0xFDEE1C81: index 0 raw 0x02528B13 -> 0x40A794; index 1 raw 0x02529265 -> 0x40AEE6. Imported closure is 0x40A794/0x40A7A2/0x40A7A8/0x40A7AC and 0x40AEE6/0x40AEF4/0x40AEFA/0x40AEFE, with boundary exit 0x40A5F0. First unmet typed obligation: FragmentSetccIndexedTableEvidence and GENERATED preflight only represent explicit shift scaling; row 17 encodes stride 8 in the lookup address. Add a discriminated typed index-scaling contract (explicit shift versus scaled lookup), with strict rejection before live mutation, rather than optional fields or sample-EA dispatch. The newest persistent .tmp A560 SQLite database still contains the older 13/13 receipt, so durable current accepted proof must be persisted before expanding row 17. Ticket remains in_progress; do not close until exact whole-function A560 C6.

**2026-07-27T15:37:36Z**

2026-07-27 artifact-boundary amendment: preserve the stable 228-row indirect-jump inventory schema. Row 16 (rhad:route@0x40A77C, reference order 16) must reference one separate immutable typed table-proof artifact. The artifact is deterministic, serial-free, and bound to input SHA-256, function 0x40A560, pinned reference commit 21b0d4783703bc4fb6910cfae51d92cd683d2c65, operation ID, order index, exact native/table evidence, and semantic targets. Its content identity is mandatory input to the compiled operation, compiled-plan identity, and aggregate-program identity and must be persisted reconstructibly in diagnostics. Missing, mismatched, noncanonical, or wrong-binding evidence rejects before live mutation. This is not an optional sidecar, compatibility path, or reason to expand the stable ledger row schema; row 17 scaled-lookup work must build on this artifact authority.

**2026-07-27T15:54:16Z**

2026-07-27 row-16 artifact authority accepted. Commit 8af6bbbe3 replaces duplicated inline table facts with required typed artifact src/d810/conf/semantic_route_oracles/rhad_a560_row16_setcc_table_proof.json. Artifact identity sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 binds input 244907...35e4c, native function 0x40A560, reference commit 21b0d4783703bc4fb6910cfae51d92cd683d2c65, operation rhad:route@0x40A77C, order 16, exact table evidence, and targets. The stable inventory remains 228 operations with identical row key sets; row 16 references the content identity through its existing current_generated_proof field. Compilation rejects missing, noncanonical, hash-mismatched, wrong-input, wrong-function, wrong-reference, wrong-operation, or wrong-order artifacts before mutation. Aggregate program identity is sha256:cf2e243326aabb5e64d66ba30c65ae466c3f2366464a484412044c791d9c30a6 and is embedded in the compiled plan. Commit 438756fea persists the complete artifact in compiled diagnostics and repeats aggregate/artifact identities on publication. Fresh exact checksum is green at .tmp/logs/d810_logs/000000000040a560_accepted_55_row16_artifact_438756fea.diag.sqlite3 (DB SHA-256 7af62801e925a53c0d50817b07245c0fbdad84d496685b39269f583e8bd415de): one 55/55 committed receipt, 7 matched route comparisons, 40 committed non-invalidated witnesses, transaction committed/unpoisoned/no INTERR, and CMAT_FINAL. Focused portable tests 40/40 and exact Docker checksum 1/1 green; fixture hash unchanged. Next unmet obligation remains row 17 scaled-lookup index evidence; ticket stays in_progress.

**2026-07-27T16:35:36Z**

2026-07-27 row-17 scaled-lookup vertical accepted on the shared GENERATED architecture. Selected operation rhad:route@0x40A792, reference order 17, now owns required immutable artifact sha256:a67a3d2cc432df11ca627c90f06f3a854004a9463a529ee1d0cdf1f759406e67; the eight-operation aggregate identity is sha256:60ad0c4a0b7ac1e083dfaab96aae7c35908add96096417d402bd94cb777b76ef. The live shape required two typed obligations beyond the initial scaling discriminator: recursive exact ownership of the single nested m_mul under m_ldx, and pre-live proof that false target 0x40A794 is physically adjacent after superseding the 0x40A792 carrier. Unsupported setcc predicates now reject in the compiler and backend before mutation. Exact IDA 9.3 proof persists at .tmp/logs/d810_logs/000000000040a560_accepted_65_row17_scaled_lookup.diag.sqlite3, DB SHA-256 ceff5571b17e31a0ca864a885601fa3b1c438a3aec0107e26e51e1a314ff7a5f: one 65/65 committed receipt, 48 committed creation witnesses, eight matched routes, actual MMAT_GENERATED publication, passed PREOPT/LOCOPT/CALLS observations, CMAT_FINAL, no poison, rollback, redo, alternate path, or numeric INTERR. The accepted 0x40A605 checksum remains green and the row-17 indirect transfer is absent with required reachable semantics preserved. Logical commits: 15d420936, 57681cae9, 53eed0e43, 1224d11e1, 4c6b0d59d, a33311661. Gates: focused compiler/FragmentPlan/preflight 281 passed; transaction units 77 passed; strict 41-row parity gate passed; exact Docker checksum 1 passed; protected-family matrix 13/13 passed; sg clean; 14/14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. The broader semantic backend suite remains at its accepted pre-existing four-failure fixture baseline with 121 passing tests; those failures were not chased. The user-owned untracked microcode-capture test remains untouched. This proves a second setcc-indexed realization subshape and advances bounded A560 coverage, not whole-function restoration. Ticket remains in_progress. Next obligation: apply the proved setcc-indexed vocabulary data-first to the remaining same-shape A560 sites in reference order, stopping at the first new typed contract before constants.

**2026-07-27T16:44:30Z**

2026-07-27 post-row17 continuation selection at HEAD 12ea476c7. The checked-in coverage authority is now reconciled to the accepted eight-operation receipt: row 17 is typed_setcc_indexed_table with artifact sha256:a67a3d2cc432df11ca627c90f06f3a854004a9463a529ee1d0cdf1f759406e67, and the next unproved setcc row is 68. Reference-order continuation selects row 18 rhad:route@0x40A7AC, existing_conditional_plus_indirect. Pinned reference 21b0d4783703bc4fb6910cfae51d92cd683d2c65 and unchanged PE SHA-256 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c agree on source 0x40A794, cmp producer 0x40A79A against 0x1F0B7687, je predicate anchor 0x40A7A0, selected-value block 0x40A7A2, join 0x40A7A8, unresolved transfer 0x40A7AC, EQ semantic targets true 0x40A7AE and false 0x40A5F0. Owned corridor is 0x40A794/0x40A79A/0x40A7A0/0x40A7A2/0x40A7A8/0x40A7AA/0x40A7AC. Complete imported closure anchors are 0x40A7AE/0x40A7BA/0x40A7CD/0x40A7E5/0x40A7EF/0x40B4C5/0x40B4E2/0x40B4EE with boundary exits 0x40A607 and 0x40B6C0. First unmet typed obligation: one imported closure contains two preserved indirect transfers, 0x40A7EF and 0x40B4EE, with distinct boundary deliveries; RhadGeneratedTemplateFragment and generated-reference template capture currently carry an unpartitioned exit set and would assign both exits to both transfers. Replace the flat preserved-transfer evidence with deterministic per-transfer exit ownership and reject missing, duplicate, foreign, or aggregate-mismatched bindings before live mutation. Preserve the accepted producer, coordinator, gateway, and transaction representation. Ticket remains in_progress.

**2026-07-27T16:53:13Z**

User clarification (2026-07-27): row-16 table proof must remain a separate immutable typed artifact referenced by the stable 228-row inventory row and compiled plan. It is deterministic and serial-free, bound to input SHA-256, function, pinned reference commit, operation ID, and reference-order index. Its content identity participates in compiled-plan and aggregate-program identities, is persisted in diagnostics, and missing/mismatched evidence rejects before live mutation. It is mandatory evidence, not an optional sidecar or compatibility path.

**2026-07-27T17:33:34Z**

2026-07-27 row-18 existing_conditional_plus_indirect vertical accepted on the shared GENERATED architecture. Selected reference-order 18 rhad:route@0x40A7AC compiles from typed source/predicate/owned-corridor/closure evidence and publishes at actual MMAT_GENERATED through the existing FRONTEND_NORMALIZATION FragmentPlan -> PatchPlan -> immutable preflight -> final binding -> shared coordinator -> backend path. Row 16 remains bound to its separate mandatory immutable typed table-proof artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785; the stable inventory remains 228 rows; diagnostics reconstruct the artifact binding to input SHA-256 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c, function 0x40A560, reference commit 21b0d4783703bc4fb6910cfae51d92cd683d2c65, operation rhad:route@0x40A77C, and reference order 16. Its content identity remains a mandatory input to the compiled plan and aggregate program identity. Missing or mismatched evidence is covered by pre-live rejection tests; it is not an optional sidecar or compatibility path. Row-18 plan identity is rhad-reference-compiler:rhad-generated-reference@0x40A560:g1:sha256:29c818d5d6738be7759bf421aad6006d062aef15b1c95617b04baea14d0b2078 and aggregate identity is sha256:29c818d5d6738be7759bf421aad6006d062aef15b1c95617b04baea14d0b2078. Accepted diagnostic database .tmp/logs/d810_logs/000000000040a560_accepted_76_row18_existing_conditional.diag.sqlite3 has SHA-256 55c6a2e640a418be217d1b6e4ba83ab2b82feabb175479987b7d70d1712da4d1: one 76/76 committed receipt, 56 committed non-invalidated creation witnesses, nine matched route comparisons, committed unpoisoned attempt, successful root publication, no rollback, no numeric INTERR, passed GENERATED/PREOPTIMIZED/LOCOPT/CALLS observations, row-18 indirect transfer absent with both semantic deliveries preserved while source topology exists and no residual indirect transfer after legitimate CALLS retirement, and CMAT_FINAL present. Logical commits: a8ffe6790 per-transfer exit ownership; 53ea41b2b typed owned replacement arm admission; 6ccfba035 row-18 compilation; a296d95ba generic preserved live fallthrough carrier normalization; f8470ca3d nested typed delivery observation; 2f8fa1330 exact GENERATED proof; 6069538ee coverage authority. Gates: exact A560 checksum 1 passed and preserves 0x40A605; compiler/checksum 51 passed; transaction/FragmentPlan/backend 259 passed with the documented stale text-only parameter-name assertion deselected; runtime 207 passed and one platform skip; exact protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input binary SHA-256 unchanged. The expanded 65-case runtime matrix produced exactly the two known non-acceptance dispatcher-pattern failures and 63 passes; they were not chased. Ticket remains in_progress. Next data-first obligation is earliest unproved existing_conditional_plus_indirect reference-order row 9 rhad:route@0x40A6BE, stopping at its first typed contract before any constant-materialization work.

**2026-07-27T17:35:32Z**

2026-07-27 post-row18 data-first selection at HEAD f3695817d: earliest unproved existing_conditional_plus_indirect is reference-order row 9 rhad:route@0x40A6BE. Pinned reference and unchanged native bytes prove source 0x40A6A6, cmp producer 0x40A6AC against 0x4DFFC906, jl predicate 0x40A6B2, selected-value block 0x40A6B4, join 0x40A6BA, transfer 0x40A6BE, SLT true target 0x40A6C0 and SGE false target 0x40A960, owned corridor 0x40A6A6/0x40A6AC/0x40A6B2/0x40A6B4/0x40A6BA/0x40A6BC/0x40A6BE. False closure is complete at 0x40A960/0x40A96E/0x40A974/0x40A978 with exit 0x40AD1E. The first unmet typed obligation is the inventory-marked unavailable true-root closure: current native source-plan evidence stops at 0x40A6C0 and the accepted row-8 template hardwires 0x40A6BE to 0x40A960, so row 9 cannot compile both semantic arms. Add a typed exact imported native body for 0x40A6C0/0x40A6CE/0x40A6D4/0x40A6D8 and bind its preserved transfer 0x40A6D8 deterministically to typed boundary deliveries 0x40A6DA and 0x40AB76 before live mutation. Replace the row-8 direct boundary shortcut with the compiled row-9 conditional operation; reuse the existing producer, coordinator, gateway, transaction representation, and per-transfer exit contract. Preserve both mandatory setcc artifacts, the nine-operation row-18 receipt, and all green gates. Ticket remains in_progress.

**2026-07-27T17:50:16Z**

2026-07-27 row-9 data-first existing_conditional_plus_indirect vertical accepted on the shared GENERATED architecture. Reference-order 9 rhad:route@0x40A6BE now replaces the previous row-8 direct shortcut with typed source 0x40A6A6, cmp 0x40A6AC, jl 0x40A6B2, selected value 0x40A6B4, join 0x40A6BA, transfer 0x40A6BE, SLT target 0x40A6C0, and SGE target 0x40A960. Exact imported closures are 0x40A6C0/0x40A6CE/0x40A6D4/0x40A6D8 with preserved transfer 0x40A6D8 bound to exits 0x40A6DA and 0x40AB76, and 0x40A960/0x40A96E/0x40A974/0x40A978 with preserved transfer 0x40A978 bound to 0x40AD1E. Compilation uses the existing RhadExistingConditionalRoute vocabulary and unchanged producer/coordinator/gateway/transaction path. Plan identity is rhad-reference-compiler:rhad-generated-reference@0x40A560:g1:sha256:83a8921b4933be9be780024de86791fc1db9c764047f657bc588d16172bc87ba; aggregate identity is sha256:83a8921b4933be9be780024de86791fc1db9c764047f657bc588d16172bc87ba. Accepted SQLite .tmp/logs/d810_logs/000000000040a560_accepted_88_row9_existing_conditional.diag.sqlite3 has SHA-256 393dc2e4945e9b2f3db5712736a2d12419231df08869ae5dacb1bf952f1031e4: one 88/88 committed receipt, 65 committed non-invalidated creation witnesses, ten matched route comparisons, committed unpoisoned transaction, successful root publication, passed GENERATED/PREOPTIMIZED/LOCOPT/CALLS observations, CMAT_FINAL, and no rollback or numeric INTERR. Diagnostics still persist both mandatory immutable table artifacts; row 16 remains sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with exact input/function/reference/operation/order binding and identity participation. Logical commits: 4c5077ab9 operation evidence/compiler instantiation; bba603219 exact GENERATED regression; eeaa10ced inventory and coverage authority. Gates: exact A560 checksum 1/1; compiler/checksum 52/52; GENERATED runtime import 3/3; protected Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next same-shape obligation is reference-order row 10 rhad:route@0x40A6D8; its first unavailable true-root closure begins at 0x40A6DA and must be completed with exact typed evidence before live mutation.

**2026-07-27T17:51:25Z**

2026-07-27 post-row9 selection at HEAD 476826d2e: reference-order row 10 rhad:route@0x40A6D8 is the next unproved existing_conditional_plus_indirect. Exact native evidence is source 0x40A6C0, cmp 0x40A6C6 against 0x40D5B460, jl 0x40A6CC, selected value 0x40A6CE, join 0x40A6D4, transfer 0x40A6D8, SLT target 0x40A6DA, SGE target 0x40AB76. The source is already present in the accepted row-9 native body. False closure 0x40AB76/0x40AB84/0x40AB8A/0x40AB8E is complete with exit 0x40B17F. First unmet typed obligation is the unavailable true-root closure at 0x40A6DA: import exact body 0x40A6DA/0x40A6E8/0x40A6EE/0x40A6F2 and bind preserved transfer 0x40A6F2 to boundary deliveries 0x40A6F4 and 0x40AE8B before live mutation. Reuse the accepted conditional vocabulary and unchanged GENERATED architecture; preserve both mandatory table artifacts and the 88/88 receipt regressions. Ticket remains in_progress.

**2026-07-27T18:01:41Z**

2026-07-27 row-10 data-first existing_conditional_plus_indirect vertical accepted. Reference-order 10 rhad:route@0x40A6D8 compiles and publishes through the unchanged shared GENERATED transaction path with exact source 0x40A6C0, cmp 0x40A6C6, jl 0x40A6CC, selected block 0x40A6CE, join 0x40A6D4, transfer 0x40A6D8, targets 0x40A6DA and 0x40AB76. Imported closures are 0x40A6DA/0x40A6E8/0x40A6EE/0x40A6F2 with preserved transfer 0x40A6F2 -> exits 0x40A6F4/0x40AE8B, and 0x40AB76/0x40AB84/0x40AB8A/0x40AB8E with preserved transfer 0x40AB8E -> 0x40B17F. Plan and aggregate identity are sha256:4340fb158eae5e789e16daadb15d56036a55ce10298d82b0d718d1e694192aeb. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_99_row10_existing_conditional.diag.sqlite3 has SHA-256 12bd4cc7c914698005b692665c8ce56cfa0030482a42e4144a4ee85253955d0b: 99/99 committed receipt, 73 committed non-invalidated creation witnesses, eleven matched routes, committed unpoisoned transaction, all four maturity observations, CMAT_FINAL, no rollback or INTERR. Both mandatory table artifacts remain persisted and identity-bound; row 16 remains sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785. Logical commits: 0cd4191c9 operation evidence; 4f782cbe3 exact GENERATED proof; c12289afc inventory/coverage authority. Gates: checksum 1/1; compiler/checksum 53/53; runtime import 3/3; protected matrix 13/13; strict parity PASS; ast-grep clean; 14 import contracts kept; unchanged binary SHA-256 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c; graphify updated without tracked delta. Ticket remains in_progress. Next obligation is reference-order row 11 rhad:route@0x40A6F2; complete its unavailable 0x40A6F4 true-root closure with typed evidence before mutation.

**2026-07-27T18:03:12Z**

2026-07-27 row-11 selection at HEAD 048409b8e: rhad:route@0x40A6F2 uses source 0x40A6DA, cmp 0x40A6E0 against 0x40ABF871, jl 0x40A6E6, selected value 0x40A6E8, join 0x40A6EE, transfer 0x40A6F2, SLT target 0x40A6F4, SGE target 0x40AE8B. Source is owned by the accepted row-10 body. First unmet obligation: complete the unavailable 0x40A6F4 closure as exact blocks 0x40A6F4/0x40A702/0x40A708/0x40A70C with preserved transfer 0x40A70C bound to 0x40A70E and 0x40A5F0. The complete false closure is 0x40AE8B/0x40AE99/0x40AE9F/0x40AEA3 with preserved transfer 0x40AEA3 bound to 0x40A5F0. Preserve the current compiler vocabulary, shared transaction path, mandatory row-16/17 artifacts, and 99/99 regressions. Ticket remains in_progress.

**2026-07-27T18:17:23Z**

2026-07-27 row-11 data-first existing_conditional_plus_indirect vertical accepted. Reference-order 11 rhad:route@0x40A6F2 compiles and publishes through the unchanged shared GENERATED path from exact source 0x40A6DA, cmp producer 0x40A6E0 against 0x40ABF871, jl 0x40A6E6, selected block 0x40A6E8, join 0x40A6EE, transfer 0x40A6F2, SLT target 0x40A6F4, and SGE target 0x40AE8B. Exact imported closures are 0x40A6F4/0x40A702/0x40A708/0x40A70C with preserved transfer 0x40A70C bound to 0x40A5F0/0x40A70E, and 0x40AE8B/0x40AE99/0x40AE9F/0x40AEA3 with preserved transfer 0x40AEA3 bound to 0x40A5F0. Plan and aggregate identity are sha256:b5619021d12da0dd8370f4bc8706c71715cc5f46c6733445fb2b8a123deb5f0d. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_110_row11_existing_conditional.diag.sqlite3 has SHA-256 af35f466caafe040b162387313f97938f0faed1727a38fe822a542077bd695fb: one 110/110 committed receipt, 81 committed non-invalidated creation witnesses, twelve matched routes, committed unpoisoned transaction, successful root publication, passed GENERATED/PREOPTIMIZED/LOCOPT/CALLS observations, CMAT_FINAL, no rollback, redo, alternate path, or numeric INTERR. Both mandatory immutable setcc artifacts remain persisted and identity-bound; row 16 remains the separate required sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 artifact referenced by the stable 228-row inventory and compiled plan, participating in plan/aggregate identity and rejecting missing or mismatched evidence before mutation. Logical commits: 37f43bd32 operation evidence/compiler instantiation; d5fc37ba9 exact GENERATED proof; 5e683405e inventory/coverage authority. Gates: exact checksum 1/1; compiler/checksum 54/54; transaction core 21/21; GENERATED runtime import 3/3; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; input binary SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c; graphify updated without tracked delta. Ticket remains in_progress. Next obligation is reference-order 12 rhad:route@0x40A70C; both target closures are complete, so instantiate the proved RhadExistingConditionalRoute vocabulary with exact per-operation evidence and dependency closure before mutation.

**2026-07-27T18:41:05Z**

2026-07-27 row-12 data-first existing_conditional_plus_indirect vertical accepted on the shared GENERATED architecture. Reference-order 12 rhad:route@0x40A70C compiles and publishes through the unchanged shared GENERATED path from exact source 0x40A6F4, cmp producer 0x40A6FA against 0x357A351E, je predicate 0x40A700, selected block 0x40A702, join 0x40A708, transfer 0x40A70C, EQ target 0x40A70E, and NE target 0x40A5F0. The true imported closure is modeled from the live four-block split 0x40A70E/0x40A736/0x40A739/0x40A73D while retaining one physical template range 0x40A70E..0x40A73F; preserved transfer 0x40A73D is bound to 0x40A607/0x40B6C0. PREOPT delivers to semantic root 0x40A70E, first authoritative CFG canonically folds the entry plumbing to live anchor 0x40A71D, typed delivery ownership reconstructs semantic root 0x40A70E, and CALLS legitimately retires the source with no residual indirect transfer. Plan and aggregate identity are sha256:145a5fc8e1092ed4f100b10c565e0301128e41ebce9ad752455c070fba190be2. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_117_row12_existing_conditional.diag.sqlite3 has SHA-256 a53ebb0b957419172055b43c6fe06451be7d83dd1457df423caf6c3ebe505c7e: one 117/117 committed receipt, 85 committed non-invalidated creation witnesses, thirteen matched route comparisons, committed unpoisoned transaction, successful root publication, actual MMAT_GENERATED plus PREOPT/authoritative-CFG/CALLS observations, CMAT_FINAL, no poison, rollback, redo, alternate path, or numeric INTERR. Row 16 remains bound to its separate mandatory immutable typed artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785, referenced by the stable 228-row inventory and compiled plan, bound to input/function/reference/operation/order, included in plan and aggregate identities, persisted in diagnostics, and rejected before mutation when missing or mismatched. Logical commits: ab95c7829 compiler instantiation; 0089071a8 nested-cmov block-model regression repair; 4e9059237 exact GENERATED proof; bf07c1793 inventory/coverage authority. Gates: exact A560 checksum 1/1; compiler/checksum 55/55; transaction core 21/21; GENERATED runtime seam 7/7; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next unproved same-shape operation not already in the accepted batch is reference-order row 20 rhad:route@0x40A818: source 0x40A800, cmp 0x40A806 against 0x742F372A, jl 0x40A80C, selected block 0x40A80E, join 0x40A814, transfer 0x40A818, SLT target 0x40A81A, SGE target 0x40AA60. First unmet typed obligation: complete unavailable true-root closure 0x40A81A as exact body 0x40A81A/0x40A828/0x40A82E/0x40A832 and bind its preserved transfer 0x40A832 deterministically to boundary deliveries 0x40A834 and 0x40AC3D before live mutation; reuse the accepted producer, compiler vocabulary, coordinator, gateway, transaction representation, and row-16 artifact authority.

**2026-07-27T18:53:19Z**

2026-07-27 row-20 data-first existing_conditional_plus_indirect vertical accepted on the shared GENERATED architecture. Reference-order 20 rhad:route@0x40A818 compiles and publishes through the unchanged shared GENERATED path from exact source 0x40A800, cmp producer 0x40A806 against 0x742F372A, jl predicate 0x40A80C, selected block 0x40A80E, join 0x40A814, transfer 0x40A818, SLT target 0x40A81A, and SGE target 0x40AA60. Exact imported closures are 0x40A81A/0x40A828/0x40A82E/0x40A832 with preserved transfer 0x40A832 bound to 0x40A834/0x40AC3D, and 0x40AA60/0x40AA6E/0x40AA74/0x40AA78 with preserved transfer 0x40AA78 bound to 0x40ADBE. Plan and aggregate identity are sha256:d917a4d94f86e621dc284964ba6eb3c9a7668e30cf0f44d070f2a8b98902603d. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_128_row20_existing_conditional.diag.sqlite3 has SHA-256 e29c8db86bb27de1db490105e65d4639763e76472efc8a01030d34243ad13df1: one 128/128 committed receipt, 93 committed non-invalidated creation witnesses, fourteen matched route comparisons, committed unpoisoned transaction, successful root publication, actual MMAT_GENERATED plus PREOPT/authoritative-CFG/CALLS observations, CMAT_FINAL, no poison, rollback, redo, alternate path, or numeric INTERR. Row 16 remains bound to its separate mandatory immutable typed artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785, referenced by the stable 228-row inventory and compiled plan, included in plan and aggregate identities, persisted in diagnostics, and rejected before mutation when missing or mismatched. Logical commits: d03742e0a compiler instantiation; b6bad7b7a exact GENERATED proof; d3a47e15c inventory/coverage authority. Gates: exact A560 checksum 1/1; focused compiler/checksum plus transaction/runtime 84/84; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next unproved same-shape operation is reference-order row 21 rhad:route@0x40A832: source 0x40A81A, cmp 0x40A820 against 0x6D56E4D2, jl 0x40A826, selected block 0x40A828, join 0x40A82E, transfer 0x40A832, SLT target 0x40A834, SGE target 0x40AC3D. First unmet typed obligation: complete unavailable true-root closure 0x40A834 as exact body 0x40A834/0x40A842/0x40A848/0x40A84C and bind preserved transfer 0x40A84C deterministically to boundary deliveries 0x40A84E and 0x40AFDF before live mutation; reuse the accepted producer, compiler vocabulary, coordinator, gateway, transaction representation, and row-16 artifact authority.

**2026-07-27T19:03:17Z**

2026-07-27 row-21 data-first existing_conditional_plus_indirect vertical accepted on the shared GENERATED architecture. Reference-order 21 rhad:route@0x40A832 compiles and publishes through the unchanged shared GENERATED path from exact source 0x40A81A, cmp producer 0x40A820 against 0x6D56E4D2, jl predicate 0x40A826, selected block 0x40A828, join 0x40A82E, transfer 0x40A832, SLT target 0x40A834, and SGE target 0x40AC3D. Exact imported closures are 0x40A834/0x40A842/0x40A848/0x40A84C with preserved transfer 0x40A84C bound to 0x40A84E/0x40AFDF, and 0x40AC3D/0x40AC4A/0x40AC50/0x40AC54 with preserved transfer 0x40AC54 bound to 0x40B21C. Plan and aggregate identity are sha256:c109e28c341bdd89453932c7ff8cda5c478f5028ad434c8fe4c39956cf6eae1f. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_139_row21_existing_conditional.diag.sqlite3 has SHA-256 414ff2779d78a9c5fa4866cb5dfd2af1c733db9fb0474f21f9c06d1e0b722c30: one 139/139 committed receipt, 101 committed non-invalidated creation witnesses, fifteen matched route comparisons, committed unpoisoned transaction, successful root publication, actual MMAT_GENERATED plus PREOPT/authoritative-CFG/CALLS observations, CMAT_FINAL, no poison, rollback, redo, alternate path, or numeric INTERR. Row 16 remains bound to its separate mandatory immutable typed artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with stable inventory/compiled-plan reference, identity participation, diagnostic persistence, and pre-live rejection for missing or mismatched evidence. Logical commits: 8bc7424c9 compiler instantiation; 608b1de9d exact GENERATED proof; 9505a1517 inventory/coverage authority. Gates: exact A560 checksum 1/1; focused compiler/checksum plus transaction/runtime 85/85; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next unproved same-shape operation is reference-order row 22 rhad:route@0x40A84C: source 0x40A834, cmp 0x40A83A against 0x6859ABF3, jl 0x40A840, selected block 0x40A842, join 0x40A848, transfer 0x40A84C, SLT target 0x40A84E, SGE target 0x40AFDF. First unmet typed obligation: complete unavailable true-root closure 0x40A84E as exact body 0x40A84E/0x40A85C/0x40A862/0x40A866 and bind preserved transfer 0x40A866 deterministically to boundary deliveries 0x40A868 and 0x40A5F0 before live mutation; reuse the accepted producer, compiler vocabulary, coordinator, gateway, transaction representation, and row-16 artifact authority.

**2026-07-27T19:16:00Z**

2026-07-27 row-22 data-first existing_conditional_plus_indirect vertical accepted on the shared GENERATED architecture. Reference-order 22 rhad:route@0x40A84C compiles and publishes through the unchanged shared GENERATED path from exact source 0x40A834, cmp producer 0x40A83A against 0x6859ABF3, jl predicate 0x40A840, selected block 0x40A842, join 0x40A848, transfer 0x40A84C, SLT target 0x40A84E, and SGE target 0x40AFDF. Exact imported closures are 0x40A84E/0x40A85C/0x40A862/0x40A866 with preserved transfer 0x40A866 bound to 0x40A5F0/0x40A868, and 0x40AFDF/0x40AFED/0x40AFF3/0x40AFF7 with preserved transfer 0x40AFF7 bound to 0x40A5F0. Plan and aggregate identity are sha256:65e46df8e40d59e85a8dc082f4a02756d318e9022c41eeff4f1383dfa42dc825. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_150_row22_existing_conditional.diag.sqlite3 has SHA-256 627bd544303e3596760d31bd51d06d795368ae35fe310dadc0d8c2719ae7bb1e: one 150/150 committed receipt, 109 committed non-invalidated creation witnesses, sixteen matched route comparisons, committed unpoisoned transaction, successful root publication, actual MMAT_GENERATED plus PREOPT/authoritative-CFG/CALLS observations, CMAT_FINAL, no poison, rollback, redo, alternate path, or numeric INTERR. Row 16 remains bound to its separate mandatory immutable typed artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with stable 228-row inventory/compiled-plan reference, identity participation, diagnostic persistence, and pre-live rejection for missing or mismatched evidence. Logical commits: d2bd5469a compiler instantiation; 5a4ce7138 exact GENERATED proof; 9a0d12ef1 inventory/coverage authority. Gates: exact A560 checksum 1/1; focused compiler/checksum 58/58; transaction/runtime 28/28; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next unproved same-shape operation is reference-order row 23 rhad:route@0x40A866: source 0x40A84E, cmp 0x40A854 against 0x65203D55, je 0x40A85A, selected block 0x40A85C, join 0x40A862, transfer 0x40A866, EQ target 0x40A868, NE target 0x40A5F0. Its typed target closures are already complete at 0x40A868/0x40A8A7 and 0x40A5F0/0x40A605 with boundary exits 0x40A607/0x40B6C0. First unmet obligation: instantiate the proved RhadExistingConditionalRoute vocabulary with this exact evidence and dependency closure before live mutation; reuse the accepted producer, compiler, coordinator, gateway, transaction representation, and row-16 artifact authority.

**2026-07-27T19:31:18Z**

2026-07-27 row-23 data-first existing_conditional_plus_indirect vertical accepted on the shared GENERATED architecture. Reference-order 23 rhad:route@0x40A866 compiles and publishes through the unchanged shared GENERATED path from exact source 0x40A84E, cmp producer 0x40A854 against 0x65203D55, je predicate 0x40A85A, selected block 0x40A85C, join 0x40A862, transfer 0x40A866, EQ target 0x40A868, and NE target 0x40A5F0. The true closure is represented by exact PREOPT witnesses 0x40A868/0x40A8A0/0x40A8A3/0x40A8A7 with one physical owned range 0x40A868-0x40A8A9 and preserved transfer 0x40A8A7 bound to 0x40A607/0x40B6C0; the false closure reuses accepted 0x40A5F0/0x40A605. Preflight correctly rejected the initial two-witness closure before mutation, proving the typed first-failed-obligation path; exact PREOPT diagnostics then repaired the evidence without relaxing preflight or adding a path. Plan and aggregate identity are sha256:d3f6cc3c039ecddcc16291fcc0fcdc90ddf593848cdc54bed90052f3d520bce1. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_157_row23_existing_conditional.diag.sqlite3 has SHA-256 e021754222ce18862eb978539ab6ccc2bd92a5defd629d285d71005211c1a955: one 157/157 committed receipt, 113 committed non-invalidated creation witnesses, seventeen matched route comparisons, committed unpoisoned transaction, successful root publication, actual MMAT_GENERATED plus PREOPT/authoritative-CFG/CALLS observations, CMAT_FINAL, no poison, rollback, redo, alternate path, or numeric INTERR. Row 16 remains bound to its separate mandatory immutable typed artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with stable 228-row inventory/compiled-plan reference, identity participation, diagnostic persistence, and pre-live rejection for missing or mismatched evidence. Logical commits: 641658579 compiler instantiation; e075f8f21 exact nested PREOPT evidence repair; 08914197e exact GENERATED proof; 549b2ec5a inventory/coverage authority. Gates: exact A560 checksum 1/1; focused compiler/checksum 59/59; transaction/runtime 28/28; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next unproved same-shape operation is reference-order row 26 rhad:route@0x40A8CD: source 0x40A8B5, cmp 0x40A8BB against 0x0E9795EF, jl 0x40A8C1, selected block 0x40A8C3, join 0x40A8C9, transfer 0x40A8CD, SLT target 0x40A8CF, SGE target 0x40ACBF. First unmet typed obligation: complete unavailable true-root closure 0x40A8CF as exact carrier 0x40A8CF/0x40A8DD/0x40A8E3/0x40A8E7 and bind preserved transfer 0x40A8E7 to 0x40A8E9/0x40B024; the false closure 0x40ACBF/0x40ACCD/0x40ACD3/0x40ACD7 already exits at 0x40B26D. Reuse the accepted producer, compiler, coordinator, gateway, transaction representation, and row-16 artifact authority.

**2026-07-27T19:39:45Z**

2026-07-27 row-26 detached-prepublication dependency finding at HEAD b4cce169c. The typed compiler instance rhad:route@0x40A8CD compiled, but the exact Docker canary rejected it at DETACHED_PREPUBLICATION: reachable_from_entry oracle=True candidate=False. Diagnostic DB .tmp/logs/d810_logs/000000000040a560_1785180942_10.diag.sqlite3 records three aborted attempts, runtime:detached_route_oracle as first failure, mutation_started=1, poisoned=1, no numeric INTERR, and no committed receipt. Reference inventory proves 0x40A8B5 is delivered by unproved reference-order row 4 rhad:route@0x40A649, whose source is delivered by earliest-unproved simple_indirect_jump row 3 rhad:route@0x40A631. First unmet obligation is to instantiate rows 3 and 4 through typed RhadDirectRoute evidence and complete native-body/dependency closure, then bind row26 depends_on to row4 before rerunning publication. Do not weaken reachable_from_entry, add optional delivery metadata, or claim row26 C6 from this rejected run. Preserve mandatory row16 artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 and stable 228-row schema.

**2026-07-27T20:01:08Z**

2026-07-27 row-26 existing_conditional_plus_indirect vertical accepted after proving its reference-order delivery chain through simple_indirect_jump rows 3 and 4. Typed direct reference evidence is mandatory and exact: row 3 rhad:route@0x40A631 reference order 3 delivers 0x40A633; row 4 rhad:route@0x40A649 reference order 4 delivers row-26 source 0x40A8B5; row 26 rhad:route@0x40A8CD reference order 26 then selects SLT 0x40A8CF versus SGE 0x40ACBF. Production now compiles 20 operations and 130 imported blocks through the unchanged shared GENERATED producer/coordinator; plan and aggregate identity sha256:81e3b2acc8b61182240d33ab6b28eb92fb744bb2e4d4967344a9f41eaae5b98e. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_179_row26_delivery_chain.diag.sqlite3 has SHA-256 f0852d65140cd05bd93bfd098c52b8e74bccb324c3ea013366d225d8c98f3b12: one 179/179 committed receipt, 130 committed non-invalidated creation witnesses, twenty matched route comparisons, rows 3/4/26 matched at DETACHED_PREPUBLICATION and observed through GENERATED/PREOPT/LOCOPT before legitimate CALLS retirement, committed unpoisoned transaction, actual MMAT_GENERATED publication, CMAT_FINAL, zero diagnostic errors, no rollback, redo, alternate mutation path, poison, or numeric INTERR. Row 16 remains bound to separate mandatory immutable artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with stable 228-row inventory schema, exact input/function/reference commit/operation/order binding, plan and aggregate identity participation, diagnostic persistence, and pre-live rejection for missing or mismatched evidence. Logical commits: 6f7955e00 typed direct identities; 30b09eb5b row-26 delivery chain; 1e14763f1 exact publication proof; 98ee33211 inventory/coverage authority. Gates: exact A560 checksum 1/1; focused compiler/producer 63/63; transaction/runtime 28/28; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Per data-first ordering, next global operation is earliest unproved simple row 5 rhad:route@0x40A661, delivered from row-3 boundary 0x40A64B; first unmet obligation is to compile its exact typed reference identity and complete its target closure rooted at 0x40A663 with preserved boundary exits before mutation. The next existing_conditional chain site is row 27 rhad:route@0x40A8E7; its first unmet obligation is complete unavailable true-root closure 0x40A8E9 before mutation.

**2026-07-27T20:42:22Z**

2026-07-27 row-5 data-first simple_indirect_jump vertical accepted on the shared GENERATED architecture. Reference-order 5 rhad:route@0x40A661 compiles from exact source 0x40A64B, owner 0x40A65D, transfer 0x40A661, direct semantic target 0x40A663, owned corridor 0x40A64B/0x40A65D/0x40A65F/0x40A661, source alternate closure 0x40AAF1/0x40AAFB -> 0x40AAFD, target closure 0x40A663/0x40A675/0x40A679 plus 0x40AE1A/0x40AE24, and boundary exits 0x40A5CA/0x40AAFD/0x40AE26. Generic composition now stitches typed single exits to imported roots, keeps unresolved multi-exit carriers external, and derives superseded carrier exclusion from mandatory typed FragmentPlan evidence consistently across preflight, preparation, and staging. No sample-EA production guard, producer, coordinator, gateway, transaction form, or DeferredGraphModifier path was added. Plan and aggregate identity are sha256:17a74ebdd48270e1b87b974570ff7579f4bb0ffb87d7515cb507d70900c5d67f. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_190_row5_direct.diag.sqlite3 has SHA-256 3575ae82b9bc319eefbb14e7e8bd381591853b7b2cf00796ff4f8931e2d2ed36: one 190/190 committed receipt, 140 committed non-invalidated creation witnesses, 21 matched route comparisons, row5 matched at DETACHED_PREPUBLICATION, actual MMAT_GENERATED publication, 0x40A661 absent through GENERATED/PREOPT/LOCOPT/CALLS, target 0x40A663 retained in the maturity proof after legitimate source-topology retirement, committed unpoisoned transaction, successful root publication, CMAT_FINAL, zero diagnostic errors, no rollback, redo, alternate mutation path, poison, or numeric INTERR. The separate mandatory immutable row-16 artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785; it remains referenced by the stable 228-row inventory and compiled plan, bound to input SHA/function/pinned reference commit/operation/order, included in plan and aggregate identities, persisted in diagnostics, and rejected before live mutation when missing or mismatched. Logical commits: fa02b0aa0 compiler vocabulary and row5 instantiation; c9485af58 generic closure/staging regression repair; 0e0c9ab2a exact GENERATED proof; 7e0961082 inventory and coverage authority. Gates: exact combined 0x40A605 plus row5 checksum 1/1; focused compiler/publication/transaction/runtime 239/239; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next earliest unproved simple_indirect_jump is reference-order 6 rhad:route@0x40A679: source 0x40A663, owner 0x40A675, transfer 0x40A679, direct target 0x40AE26. Its target closure is already complete at 0x40AE26/0x40AE3C with boundary exits 0x40A5F0/0x40AE3E; first unmet obligation is to instantiate the proved RhadDirectRoute vocabulary with exact per-operation native-body proof and dependency closure before live mutation.

**2026-07-27T21:06:42Z**

2026-07-27 row-6 data-first simple_indirect_jump vertical accepted on the shared GENERATED architecture. Reference-order 6 rhad:route@0x40A679 compiles from exact source 0x40A663, owner 0x40A675, transfer 0x40A679, direct semantic target 0x40AE26, owned corridor 0x40A663/0x40A675/0x40A677/0x40A679, imported closure 0x40AE26/0x40AE3C with physical range 0x40AE26-0x40AE3E, preserved transfer 0x40AE3C -> 0x40A5F0/0x40AE3E, and dependency row 5. Exact preflight first rejected range_not_owned for 0x40AE26-0x40AE3E before live mutation; the typed missing contract was native-body entry authority for native@0x40AE26 and native@0x40AE3C, now carried by FragmentPlan evidence. The accepted producer, coordinator, gateway, transaction representation, and DeferredGraphModifier path remain unchanged; no sample-EA production guard or alternate mutation route was added. Plan and aggregate identity are sha256:2d2aaf24872ed49186c84fb144c119f7a3fa28b33dec9a36333b6112c8e964e5. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_193_row6_direct.diag.sqlite3 has SHA-256 d5de16ddf5cb605eaba80f385263a46d6fed46bb59e0ac281bc98d9a78fb2b04: one 193/193 committed receipt, 142 committed non-invalidated creation witnesses, 22 matched route comparisons, row6 matched at DETACHED_PREPUBLICATION, actual MMAT_GENERATED publication, PREOPT/authoritative-CFG/CALLS observation, legitimate later source retirement with no residual indirect transfer, preserved semantic exits 0x40A5F0/0x40AE3E, committed unpoisoned transaction, successful root publication, CMAT_FINAL, and no poison, rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. The separate mandatory immutable row-16 artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785; it remains referenced by the stable 228-row inventory and compiled plan, bound to input SHA/function/pinned reference commit/operation/order, included in plan and aggregate identities, persisted in diagnostics, and rejected before live mutation when missing or mismatched. Logical commits: 5b813d0d6 compiler instantiation; c93634ba6 typed target-entry authority repair; d0cc04417 exact GENERATED proof; e684a4391 inventory/coverage authority. Gates: exact combined 0x40A605 plus all-current-operation checksum 1/1; focused compiler/publication/transaction unit suite 184/184; pinned runtime suite 220/220; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next earliest unproved simple_indirect_jump is reference-order 19 rhad:route@0x40A7EF: source 0x40A7CD, owner 0x40A7E5, transfer 0x40A7EF, direct target 0x40B6C0, owned corridor 0x40A7CD/0x40A7E5/0x40A7E7/0x40A7E9/0x40A7EF, complete imported closure 0x40B6C0/0x40B6CA/0x40B6D0/0x40B6D4, and boundary exit 0x40B790. First unmet typed obligation: instantiate RhadDirectRoute with exact per-operation native-body proof and dependency closure before live mutation; reuse the accepted shared architecture and row-16 artifact authority.

**2026-07-27T21:20:04Z**

2026-07-27 row-19 data-first simple_indirect_jump vertical accepted on the shared GENERATED architecture. Reference-order 19 rhad:route@0x40A7EF compiles from exact source 0x40A7CD, owner 0x40A7E5, transfer 0x40A7EF, direct semantic target 0x40B6C0, owned corridor 0x40A7CD/0x40A7E5/0x40A7E7/0x40A7E9/0x40A7EF, complete imported closure 0x40B6C0/0x40B6CA/0x40B6D0/0x40B6D4, boundary exit 0x40B790, and dependency row 18 rhad:route@0x40A7AC. It uses the accepted RhadDirectRoute compiler, shared GENERATED producer/coordinator, FragmentPlan/PatchPlan/preflight/gateway transaction, and existing native-body witnesses unchanged; no new producer, coordinator, gateway, transaction form, direct DeferredGraphModifier path, compatibility metadata, or production sample-EA guard was added. Plan and aggregate identity are sha256:b52ed66646a2400dafa1fbb79b07f824a0308b07481e8ce5ae9a9040422c4870. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_194_row19_direct.diag.sqlite3 has SHA-256 95399d4e86e67fa4bc8357d8b5c01638aa3404c1c19afff0d48ed5e95817058c: one 194/194 committed receipt, 142 committed non-invalidated creation witnesses, 23 matched route comparisons, row19 matched at DETACHED_PREPUBLICATION, actual MMAT_GENERATED publication, PREOPT/authoritative-CFG/CALLS observation, 0x40A7EF absent after publication, exact 0x40B6C0 delivery while source topology exists, legitimate CALLS source retirement with 0x40B6C0 still reachable and no residual indirect transfer, committed unpoisoned transaction, successful root publication, CMAT_FINAL, and no poison, rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. The separate mandatory immutable row-16 artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785; it remains referenced by the stable 228-row inventory and compiled plan, bound to input SHA/function/pinned reference commit/operation/order, included in plan and aggregate identities, persisted in diagnostics, and rejected before live mutation when missing or mismatched. Logical commits: 0543fe2dd compiler instantiation; 1b3fadea3 exact GENERATED proof; 56959f1fe inventory/coverage authority. Gates: exact combined 0x40A605 plus all-current-operation checksum 1/1; focused compiler/publication/transaction unit suite 185/185; pinned runtime suite 220/220; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next earliest unproved simple_indirect_jump is reference-order 25 rhad:route@0x40A8B3: source 0x40A63F, owner 0x40A8A9, transfer 0x40A8B3, direct target 0x40A64B, owned corridor 0x40A63F/0x40A8A9/0x40A8AF/0x40A8B1/0x40A8B3, complete imported closure 0x40A64B/0x40A65D/0x40A661/0x40AAF1/0x40AAFB, and boundary exits 0x40A663/0x40AAFD. First unmet typed obligation: instantiate RhadDirectRoute with exact per-operation native-body proof and dependency closure before live mutation; reuse the accepted shared architecture and row-16 artifact authority.

**2026-07-27T21:33:01Z**

2026-07-27 row-25 data-first simple_indirect_jump vertical accepted on the shared GENERATED architecture. Reference-order 25 rhad:route@0x40A8B3 compiles from exact source 0x40A63F, owner 0x40A8A9, transfer 0x40A8B3, direct semantic target 0x40A64B, owned corridor 0x40A63F/0x40A8A9/0x40A8AF/0x40A8B1/0x40A8B3, complete imported closure 0x40A64B/0x40A65D/0x40A661/0x40AAF1/0x40AAFB, boundary exits 0x40A663/0x40AAFD, and dependency row 3 route:rhad-direct@0x40A631. It uses the accepted RhadDirectRoute compiler and unchanged shared GENERATED producer/coordinator/gateway transaction. Publication makes row-5 source topology genuinely reachable through LOCOPT; the exact canary records that new semantic delivery and its later legitimate CALLS retirement. No new producer, coordinator, gateway, transaction form, direct DeferredGraphModifier path, compatibility metadata, or production sample-EA guard was added. Plan and aggregate identity are sha256:bee0f50758d80d958024ad99d594e2544c54d7e02136cc2a28f058304dd64f8f. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_195_row25_direct.diag.sqlite3 has SHA-256 3ff8df51c5eb4ad9794b391f6d8ca77150bb3071dc41108c0bb672e68a52e98e: one 195/195 committed receipt, 142 committed non-invalidated creation witnesses, 24 matched route comparisons, row25 matched at DETACHED_PREPUBLICATION, actual MMAT_GENERATED publication, PREOPT/authoritative-CFG/CALLS observation, 0x40A8B3 absent after publication, exact 0x40A64B delivery while source topology exists, legitimate CALLS source retirement with no residual indirect transfer, committed unpoisoned transaction, successful root publication, CMAT_FINAL, and no poison, rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. The separate mandatory immutable row-16 artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with stable 228-row inventory/compiled-plan reference, exact binding, identity participation, diagnostic persistence, and pre-live rejection for missing or mismatched evidence. Logical commits: e29df2aec compiler instantiation; 52e5a1162 exact GENERATED proof and maturity regression repair; ba16d1a54 inventory/coverage authority. Gates: exact combined 0x40A605 plus all-current-operation checksum 1/1; focused compiler/publication/transaction unit suite 186/186; pinned runtime suite 220/220; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The next earliest unproved simple_indirect_jump is reference-order 29 rhad:route@0x40A95E: source 0x40A93C, owner 0x40A954, transfer 0x40A95E, direct target 0x40B6C0, corridor 0x40A93C/0x40A954/0x40A956/0x40A958/0x40A95E, closure 0x40B6C0/0x40B6CA/0x40B6D0/0x40B6D4, exit 0x40B790. Its first unmet typed obligation is the prerequisite delivery chain: prove row 27 rhad:route@0x40A8E7 including unavailable true-root 0x40A8E9 closure, then row 28 rhad:route@0x40A901 whose true closure owns row29 source, before instantiating row29 RhadDirectRoute. Do not weaken dependency or reachability evidence.

**2026-07-27T21:55:49Z**

2026-07-27 row-27 existing_conditional_plus_indirect vertical accepted on the unchanged shared GENERATED architecture. Reference-order 27 rhad:route@0x40A8E7 compiles from source 0x40A8CF, cmp producer 0x40A8D5 against 0x0CDF90C9, jl predicate 0x40A8DB, selected block 0x40A8DD, join 0x40A8E3, transfer 0x40A8E7, SLT target 0x40A8E9, and SGE target 0x40B024. Imported closure is exact at 0x40A8E9/0x40A8F7/0x40A8FD/0x40A901 and 0x40B024/0x40B032/0x40B038/0x40B03C, with boundary exits 0x40A5F0/0x40A903 and dependency row 26. Plan and aggregate identity sha256:d0c59a0f0ddbc8563265e792aed3944531e5307f20572528988014627d4f9087. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_196_row27_existing_conditional.diag.sqlite3 has SHA-256 a76972c4514b1476895c3d256a00f5258d86cc66072999e8c7ed30864fdab490: one 206/206 committed receipt, 150 committed creation witnesses, 25 matched comparisons, actual MMAT_GENERATED publication, PREOPT/LOCOPT exact target survival, legitimate CALLS source retirement with both semantic deliveries preserved, CMAT_FINAL, and no poison, rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. The mandatory immutable row-16 artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with stable 228-row inventory binding, identity participation, diagnostic persistence, and pre-live rejection. Logical commits: 8a1b3e8d9 compiler; 036514a62 publication proof; e1753dc91 inventory authority. Gates: exact checksum 1/1; focused compiler/FragmentPlan/PatchPlan 130/130; transaction/runtime 220/220; pinned protected-family matrix 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. The selected next operation is row 28 rhad:route@0x40A901; first unmet typed obligation is to complete the unavailable true-root closure at 0x40A903 before mutation. Row 28 then delivers row-29 source 0x40A93C.

**2026-07-27T22:14:05Z**

2026-07-27 rows 28 and 29 accepted as the prerequisite chain and selected simple_indirect_jump vertical. Row 28 rhad:route@0x40A901 uses exact source 0x40A8E9, cmp 0x40A8EF against 0x0BB2D365, je 0x40A8F5, selected 0x40A8F7, join 0x40A8FD, transfer 0x40A901, EQ target 0x40A903, NE target 0x40A5F0, closure 0x40A903/0x40A922/0x40A93C/0x40A954/0x40A95E plus 0x40B4F0/0x40B50D/0x40B519, and dependency row 27. Its plan identity is sha256:8b4908dc1265fe72499fbcff8bf8fa2c04c6deb51d1c07803a9605790fb8dbfa. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_197_row28_existing_conditional.diag.sqlite3 SHA-256 92b9c86c3372009763de767ef70f0bee1fed8b69ae070837ae53e60165fb1389 records one 217/217 receipt, 158 witnesses, 26 matched comparisons, exact maturity delivery, CALLS retirement, and CMAT_FINAL. Commits b20df21f7 compiler, 470e44403 publication, 693ce46c1 inventory. Row 29 route:rhad-direct@0x40A95E reuses the proved RhadDirectRoute vocabulary from source 0x40A93C, owner 0x40A954, transfer 0x40A95E to 0x40B6C0, boundary 0x40B790, and dependency row 28. Plan identity sha256:f57179b642b418a46ebc251ca34b65e2a0702b8249f687f7fe78c0131b174b2e. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_198_row29_direct.diag.sqlite3 SHA-256 5c79a4ad0e3064c9a00430463f4ebc60e4e67a81f2c29e7b45e0b448315c6713 records one 218/218 receipt, 158 witnesses, 27 matched comparisons, exact 0x40B6C0 delivery before legitimate retirement, and CMAT_FINAL. Commits 9961ec4b3 compiler, 54b49f87d publication, 4bb760717 inventory. Neither vertical changes the shared producer, coordinator, gateway, transaction representation, or row-16 artifact. Row-16 remains mandatory and unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with stable 228 rows. Final gates: exact checksum 1/1; focused compiler/FragmentPlan/PatchPlan 132/132; runtime 220/220; pinned protected-family 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA unchanged 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Next reference-order operation is row 30 rhad:route@0x40A978; first unmet typed obligation is complete unavailable true-root closure 0x40A97A before mutation. Next simple_indirect_jump is row 42 rhad:route@0x40AAFB.

**2026-07-27T22:35:34Z**

2026-07-27 row-30 existing_conditional_plus_indirect vertical accepted on the unchanged shared GENERATED architecture. Reference-order 30 rhad:route@0x40A978 compiles from source 0x40A960, cmp producer 0x40A966 against 0x636961E8, jl predicate 0x40A96C, selected block 0x40A96E, join 0x40A974, transfer 0x40A978, normalized SLT target 0x40A97A, and observed SGE target 0x40AD1E. The exact imported closure is 0x40A97A/0x40A988/0x40A98E/0x40A992 plus 0x40AD1E/0x40AD2C/0x40AD32/0x40AD36, with boundary exits 0x40A994/0x40B071/0x40B55B and semantic delivery dependency row 9 rhad:route@0x40A6BE. Plan and aggregate identity are sha256:119d154c5023023183694704004617f66512c297f5e1d6a9ff3d9559005e68d5. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_199_row30_existing_conditional.diag.sqlite3 has SHA-256 894986ecec8897564b611e4756b8bc3ee0e59e928d1dedb93540b4f172a2b5f9: one 229/229 committed receipt, 166 committed non-invalidated creation witnesses, 28 matched comparisons, actual MMAT_GENERATED publication, exact PREOPT/LOCOPT target survival, legitimate CALLS source retirement with both semantic deliveries preserved and no residual indirect transfer, CMAT_FINAL, committed unpoisoned transaction, successful root publication, and no rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. The mandatory separate immutable row-16 table-proof artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785; the inventory remains exactly 228 rows, and the artifact remains bound to input SHA/function/pinned reference commit/operation/order, included in compiled-plan and aggregate identities, persisted in diagnostics, and rejected before live mutation when missing or mismatched. Logical commits: 620eeb259 compiler; 294bdbb15 publication proof; b92684e30 inventory authority. Gates: exact combined checksum 1/1; focused compiler/FragmentPlan/PatchPlan 174/174; accepted transaction selection 105/105 with the known stale text-only assertion explicitly deselected; pinned runtime 220/220; pinned protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Next is row 31 rhad:route@0x40A992; first unmet typed obligation is to complete the unavailable true-root closure at 0x40A994 before mutation.

**2026-07-27T23:01:10Z**

2026-07-27 rows 31 and 32 existing_conditional_plus_indirect verticals accepted on the unchanged shared GENERATED architecture. Row 31 rhad:route@0x40A992 compiles source 0x40A97A, cmp 0x40A980 against 0x5E07BA29, jl 0x40A986, selected 0x40A988, join 0x40A98E, transfer 0x40A992, normalized SLT target 0x40A994, observed SGE target 0x40B071, complete eight-block closure, boundaries 0x40A5F0/0x40A9AE, and dependency row 30. Plan identity sha256:bb053b4c8cf7c517d9d7685aa69403b810fee461b8b52eb98a71fd511ddce554. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_200_row31_existing_conditional.diag.sqlite3 SHA-256 2d158e3f73ae6c5acb3343e4d4e2eba83edba2491c8612be8d07f0e894bd3c4b records 240/240 committed operations, 174 witnesses, 29 matched comparisons, actual MMAT_GENERATED publication, maturity proof through CALLS retirement, and CMAT_FINAL. Commits ff0941c18 compiler, 4afb20ad7 proof, 055f86926 inventory. Row 32 rhad:route@0x40A9AC compiles source 0x40A994, cmp 0x40A99A against 0x4DFFC906, je 0x40A9A0, selected 0x40A9A2, join 0x40A9A8, transfer 0x40A9AC, normalized EQ target 0x40A9AE, observed NE target 0x40A5F0, boundaries 0x40A607/0x40B6C0, and dependency row 31. Immutable preflight first rejected the guessed closure before mutation; PREOPT evidence proved the typed split 0x40A9AE/0x40A9D5/0x40A9D8/0x40A9DC, which is now encoded without a producer, coordinator, gateway, transaction, compatibility, or sample-EA exception. Plan identity sha256:718eac4cc38c38ca126da7b77a3a612b35cfd870c2ecf18b242599a82c4000d4. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_201_row32_existing_conditional.diag.sqlite3 SHA-256 f7e795aff49a344d7d6f4afcb4075d588a5eaaf821a1c0501d9cdf943d1f0739 records one 247/247 committed receipt, 178 witnesses, 30 matched comparisons, exact PREOPT/LOCOPT survival, legitimate CALLS source retirement with semantic delivery preserved, CMAT_FINAL, and no poison, rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. Commits 2fd07814a compiler, 5723247f9 typed topology repair, 89b6a47fa proof, 1a65821ba inventory. The separate mandatory immutable row-16 table-proof artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with exact input/function/reference commit/operation/order binding, plan and aggregate identity participation, diagnostic persistence, pre-live rejection, and a stable 228-row ledger. Final gates: exact checksum 1/1; compiler/FragmentPlan/PatchPlan/publication 176/176; transaction selection 154/154 with the known stale text-only assertion deselected; runtime 220/220; pinned protected Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Next in reference order is row 33 rhad:route@0x40A9DC, cmov_selected_indirect: source 0x40A9B3, flag producer 0x40A9C7, predicate 0x40A9D5, transfer 0x40A9DC, targets 0x40B6C0/0x40A607, complete imported closure through 0x40A619/0x40A68A and 0x40B6D4, boundaries 0x40A61B/0x40A68C/0x40B790, dependency row 32. First unmet typed obligation is to instantiate the accepted RhadConditionalRoute vocabulary with exact per-operation flag-safe cmov evidence, native-body closure, and dependency authority before live mutation.

**2026-07-27T23:22:52Z**

2026-07-27 row-33 cmov_selected_indirect vertical accepted through the unchanged shared GENERATED producer/coordinator and transaction architecture. Reference-order 33 rhad:route@0x40A9DC now carries required typed reference identity: JumpInliner._fixup_cmov, source 0x40A9B3 in imported root 0x40A9AE, cmp producer 0x40A9C7 against 0x0BB2D365, cmovl 0x40A9D5, selected block 0x40A9D5, join 0x40A9D8, transfer 0x40A9DC, normalized SLT target 0x40B6C0, observed SGE target 0x40A607, complete nine-block imported closure, boundaries 0x40A61B/0x40A68C/0x40B790, and dependency row 32. The shape exposed two typed compiler contracts rather than an architecture exception: RhadConditionalRoute previously lacked required reference order/symbol/variant/source/target identity and admitted only replacement-root ownership, and the FragmentPlan overlap guard modeled role-shared selects as one byte rather than one exact multi-byte instruction. Commits 99201719f and f0e2a8007 add exact-instruction overlap proof and generic imported cmov compilation; no optional fields, sample-EA dispatch guard, producer, coordinator, gateway, transaction representation, or direct DeferredGraphModifier path was added. Plan and aggregate identity sha256:b7879b85f4d3657987d23f2d727b70d951d9aeaccc6d6da735d08da6037a8226. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_202_row33_cmov.diag.sqlite3 SHA-256 d697c26e4161618ae5694a7ef8c15ef2f3cb1c24862f8d2a3545679aea46230d records one 250/250 committed receipt, 178 creation witnesses, 31 matched route comparisons, actual MMAT_GENERATED publication, both semantic arms through PREOPT, legitimate LOCOPT folding to reachable 0x40B6C0 with the conditional topology retired, CALLS source retirement, no residual indirect transfer, CMAT_FINAL, and no poison, rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. Commits 1b29d8a0b proof and 20c6f884e inventory complete the vertical. The separate mandatory immutable row-16 table-proof artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with exact input/function/reference commit/operation/order binding, compiled-plan and aggregate identity participation, diagnostic persistence, pre-live rejection, and the stable 228-row ledger. Gates: exact checksum 1/1; compiler/FragmentPlan/PatchPlan/publication 178/178; transaction selection 154/154 with the known stale text-only assertion deselected; runtime 220/220; pinned protected Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Next in reference order is row 34 rhad:route@0x40A9F6, existing_conditional_plus_indirect: source 0x40A9DE, cmp 0x40A9E4 against 0x2B8162DC, jl 0x40A9EA, selected 0x40A9EC, join 0x40A9F2, transfer 0x40A9F6, targets 0x40A9F8/0x40AD6E, complete 0x40AD6E closure to boundary 0x40B32C. First unmet typed obligation is to inventory and import the currently unavailable true-root 0x40A9F8 closure before compiling or mutating row 34.

**2026-07-27T23:39:52Z**

2026-07-27 row-34 existing_conditional_plus_indirect vertical accepted on the unchanged shared GENERATED architecture. Reference-order 34 rhad:route@0x40A9F6 compiles exact typed evidence for source 0x40A9DE, cmp producer 0x40A9E4 against 0x2B8162DC, jl predicate 0x40A9EA, selected block 0x40A9EC, join 0x40A9F2, transfer 0x40A9F6, normalized SLT target 0x40A9F8, observed SGE target 0x40AD6E, complete imported closure 0x40A9F8/0x40AA06/0x40AA0C/0x40AA10 and 0x40AD6E/0x40AD7C/0x40AD82/0x40AD86, boundary exits 0x40AA12/0x40B0BC/0x40B32C, and delivery dependency row 16 rhad:route@0x40A77C. It reuses the accepted RhadExistingConditionalRoute compiler, single GENERATED producer, FragmentPlan -> PatchPlan -> immutable preflight -> final binding -> shared coordinator transaction, and existing backend without another producer, gateway, transaction representation, direct DeferredGraphModifier path, compatibility metadata, or production sample-EA guard. Plan and aggregate identity sha256:418fda7e1490e750433255607ae544eb3b6eb29ae4cd3b1f97636f944a437a24. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_203_row34_existing_conditional.diag.sqlite3 has SHA-256 20e6d5640d9cc7b39aa4effe18884dcbc2a286c3968772ab596f6cf5888fe4ea: one 261/261 committed receipt, 186 committed non-invalidated imported-native creation witnesses, 32 matched route comparisons, actual MMAT_GENERATED publication, exact PREOPT/authoritative-CFG/LOCOPT survival of both targets while source topology exists, legitimate CALLS source retirement with both semantic deliveries preserved and no residual indirect transfer, CMAT_FINAL, committed unpoisoned state, successful root publication, and no rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. The mandatory separate immutable row-16 table-proof artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with exact input/function/reference commit/operation/order binding, compiled-plan and aggregate identity participation, diagnostic persistence, pre-live rejection, and the stable 228-row inventory. Logical commits: f75d38ce6 compiler and exact closure; 1eaedd01b exact GENERATED proof; 695f2e252 inventory/coverage authority. Fresh gates: exact combined checksum including permanent 0x40A605 regression 1/1; focused compiler/FragmentPlan/PatchPlan/publication 179/179; transaction core 77/77; runtime 220/220; pinned protected Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Next in reference order is row 35 rhad:route@0x40AA10, existing_conditional_plus_indirect: source 0x40A9F8, cmp producer 0x40A9FE, predicate 0x40AA04, selected 0x40AA06, join 0x40AA0C, transfer 0x40AA10, targets 0x40AA12/0x40B0BC, dependency row 34. First unmet typed obligation is to inventory and import the currently unavailable true-root 0x40AA12 closure before compilation or live mutation.

**2026-07-27T23:51:00Z**

2026-07-27 row-35 existing_conditional_plus_indirect vertical accepted on the unchanged shared GENERATED architecture. Reference-order 35 rhad:route@0x40AA10 compiles exact typed evidence for source 0x40A9F8, cmp producer 0x40A9FE against 0x29947C85, jl predicate 0x40AA04, selected block 0x40AA06, join 0x40AA0C, transfer 0x40AA10, normalized SLT target 0x40AA12, observed SGE target 0x40B0BC, complete imported closure 0x40AA12/0x40AA20/0x40AA26/0x40AA2A and 0x40B0BC/0x40B0CA/0x40B0D0/0x40B0D4, boundary exit 0x40A5F0, and dependency row 34. It reuses the accepted compiler, one GENERATED producer, FragmentPlan -> PatchPlan -> immutable preflight -> final binding -> shared coordinator transaction, and existing backend without another producer, gateway, transaction representation, direct DeferredGraphModifier path, compatibility metadata, or production sample-EA guard. Plan and aggregate identity sha256:1c5da12c9d0e4243c75b3ffbab3d99dd22f727743b16c25b7136a821cd1e1a21. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_204_row35_existing_conditional.diag.sqlite3 has SHA-256 45f5dff8c7ff01b7718253b98a9f44abcb9560cd3cde5b83c26bfb98a3298c2f: one 272/272 committed receipt, 194 committed non-invalidated imported-native witnesses, 33 matched route comparisons, actual MMAT_GENERATED publication, exact PREOPT/authoritative-CFG/LOCOPT survival of both targets while source topology exists, legitimate CALLS source retirement with both semantic deliveries preserved and no residual indirect transfer, CMAT_FINAL, committed unpoisoned state, successful root publication, and no rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. The mandatory separate immutable row-16 table-proof artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with exact binding, identity participation, diagnostic persistence, pre-live rejection, and the stable 228-row inventory. Logical commits: ef3c74eb7 compiler and exact closure; 67adb36f9 exact GENERATED proof; ae87bf97e inventory and coverage authority. Fresh gates: exact combined checksum including permanent 0x40A605 regression 1/1; focused compiler/FragmentPlan/PatchPlan/publication 180/180; transaction core 77/77; runtime 220/220; pinned protected Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row parity PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Next in reference order is row 36 rhad:route@0x40AA2A, existing_conditional_plus_indirect: source 0x40AA12, cmp producer 0x40AA18 against 0x23B8E806, predicate 0x40AA1E, selected 0x40AA20, join 0x40AA26, transfer 0x40AA2A, targets 0x40AA2C/0x40A5F0, dependency row 35. Its closure is already complete in the ledger. First unmet typed obligation is to instantiate the proved RhadExistingConditionalRoute vocabulary with exact per-operation evidence, native-body ownership, and dependency closure before live mutation.

**2026-07-28T00:11:23Z**

2026-07-27 row-36 existing_conditional_plus_indirect vertical accepted on the unchanged shared GENERATED architecture. Reference-order 36 rhad:route@0x40AA2A compiles exact typed evidence for source 0x40AA12, cmp producer 0x40AA18 against 0x23B8E806, jne predicate 0x40AA1E, selected block 0x40AA20, join 0x40AA26, transfer 0x40AA2A, normalized EQ target 0x40AA2C, observed NE target 0x40A5F0, complete imported closure 0x40AA2C/0x40AA35/0x40AA5A/0x40AA5E plus the existing 0x40A5F0/0x40A605 false closure, boundary exits 0x40A607/0x40B6C0, and dependency row 35. Immutable preflight first rejected the static three-block guess before mutation; live PREOPT evidence proved the typed AA5A split and omission of the absorbed AA41 stack adjustment. The repaired closure compiles and publishes without another producer, coordinator, gateway, transaction representation, direct DeferredGraphModifier path, compatibility metadata, or production sample-EA guard. Plan and aggregate identity sha256:97ab00935d1630a2b8f6062398ab98eee42a69730d6d3fee4a3f9d49a62057ab. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_205_row36_existing_conditional.diag.sqlite3 has SHA-256 ef841bc01f6f3798c4d719b2ef95671f4f20c647a0831cdf08e2662a1011b76b: one 279/279 committed receipt, 198 committed non-invalidated imported-native witnesses, 34 matched route comparisons, actual MMAT_GENERATED publication, exact GENERATED/PREOPT/authoritative-CFG/LOCOPT survival of both semantic targets while source topology exists, legitimate CALLS retirement with both deliveries preserved and no residual indirect transfer, CMAT_FINAL, committed unpoisoned state, successful root publication, and no rollback, redo, alternate path, lifecycle error, or numeric INTERR. The separate mandatory immutable row-16 table-proof artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with exact input/function/reference/operation/order binding, plan and aggregate identity participation, diagnostic persistence, pre-live rejection, and stable 228-row inventory. Logical commits: 0d862a2ff compiler, d7b921827 typed PREOPT topology repair, bb90e8626 exact proof, 575ea8c61 inventory authority. Fresh gates: exact A560 checksum 1/1; focused compiler/FragmentPlan/PatchPlan/publication 181/181; transaction/plan core 78/78; runtime 220/220; pinned protected Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row PASS via --require-integrated; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Next same-shape obligation is reference-order row 38 rhad:route@0x40AA78; first complete its unavailable 0x40AA7A target-rooted closure with exact typed native-body evidence before mutation. Reference-order row 37 rhad:route@0x40AA5E is the intervening cmov_selected_indirect operation with complete closure and existing conditional vocabulary, to be proved when continuing strict reference order.

**2026-07-28T00:12:54Z**

2026-07-28 strict reference-order continuation selects row 37 rhad:route@0x40AA5E, cmov_selected_indirect. Exact native evidence: imported source root 0x40AA35 with source operation start 0x40AA3B, cmp producer 0x40AA49 against 0x0BB2D365, selected cmovl at 0x40AA57, join at 0x40AA5A, unresolved transfer 0x40AA5E, normalized SLT target 0x40B6C0, observed SGE target 0x40A607, complete accepted nine-block target closure through 0x40A619/0x40A68A and 0x40B6D4, boundary exits 0x40A61B/0x40A68C/0x40B790, and dependency row 36. First unmet typed obligation: instantiate the accepted RhadConditionalRoute vocabulary with exact flag-safe imported cmov source/select/join identities and row-36 dependency authority. The live row-36 PREOPT capture proves the selected 0x40AA57 role is an exact instruction-backed overlap inside the substantive 0x40AA35 block, analogous to accepted row 33; model it through the existing exact-instruction overlap contract before mutation. Preserve the shared producer/coordinator/transaction path and mandatory row-16 artifact.

**2026-07-28T00:22:41Z**

2026-07-28 row-37 cmov_selected_indirect vertical accepted on the unchanged shared GENERATED architecture. Reference-order 37 rhad:route@0x40AA5E compiles typed evidence for imported source root 0x40AA35, source 0x40AA3B, cmp producer 0x40AA49 against 0x0BB2D365, cmovl/select 0x40AA57, join 0x40AA5A, transfer 0x40AA5E, normalized SLT target 0x40B6C0, observed SGE target 0x40A607, complete nine-block target closure, boundaries 0x40A61B/0x40A68C/0x40B790, and dependency row 36. It reuses the existing RhadConditionalRoute compiler, producer, FragmentPlan -> PatchPlan -> immutable preflight -> final binding -> shared coordinator, transaction representation, and backend with no alternate mutation path. Plan and aggregate identity sha256:f2a73f7bff74b1a5f015350c0f3e3656988dd2dfc09871fe832ada00ba2268b6. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_206_row37_cmov.diag.sqlite3 SHA-256 a2612f2f76e2881c54e9e11a115fc90c071e790ed4524019404a770485ac55b9 records one 283/283 committed receipt, 199 witnesses, 35 matched route comparisons, actual MMAT_GENERATED publication, exact maturity proof through CALLS retirement, CMAT_FINAL, no residual indirect transfer, and no poison, rollback, redo, alternate path, lifecycle error, or numeric INTERR. Logical commits: 65ffe2cee compiler, aff6b8a33 proof, 0d8328f97 inventory.

Clarification preserved as a mandatory contract, not a sidecar: the row-16 table proof remains a separate immutable typed deterministic serial-free artifact at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785, bound to input SHA-256 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c, function 0x40A560, pinned reference commit, row-16 operation ID and reference-order index. Its content identity remains required by both the inventory row and compiled plan, participates in compiled-plan and aggregate-program identities, is persisted in diagnostics, and missing or mismatched evidence rejects before live mutation. The inventory schema remains exactly 228 rows.

Ticket remains in_progress. Next strict reference-order operation is row 38 rhad:route@0x40AA78, existing_conditional_plus_indirect. First unmet typed obligation: complete the unavailable 0x40AA7A target-rooted closure with exact typed native-body evidence before compilation or live mutation.

**2026-07-28T00:29:48Z**

2026-07-28 row-37 final verification: exact combined A560 checksum 1/1; focused compiler/FragmentPlan/PatchPlan/publication 181/181; transaction/plan core 78/78; pinned runtime 220/220; protected Hodur/Sub7FFD/Tigress/Approov matrix 13/13; strict 41-row portable CFG transaction parity PASS with --require-integrated; ast-grep clean; all 14 import-linter contracts kept; graphify update completed with no tracked delta; fixture SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. The accepted compiled diagnostic event persists plan ID rhad-reference-compiler:rhad-generated-reference@0x40A560:g1:sha256:f2a73f7bff74b1a5f015350c0f3e3656988dd2dfc09871fe832ada00ba2268b6, aggregate identity sha256:f2a73f7bff74b1a5f015350c0f3e3656988dd2dfc09871fe832ada00ba2268b6, and required row-16 artifact identity sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 together. Ticket remains in_progress for row 38.

**2026-07-28T00:31:31Z**

2026-07-28 strict reference-order continuation selects row 38 rhad:route@0x40AA78, existing_conditional_plus_indirect, symbol JumpInliner._fixup_jmp_and_possible_jcc. Exact native evidence: source 0x40AA60, cmp producer 0x40AA66 against 0x7C4FB03D, jl predicate 0x40AA6C, selected block 0x40AA6E, join 0x40AA74, transfer 0x40AA78, normalized SLT target 0x40AA7A, observed SGE target 0x40ADBE, owned corridor 0x40AA60/0x40AA66/0x40AA6C/0x40AA6E/0x40AA74/0x40AA76/0x40AA78, and dependency row 20 rhad:route@0x40A818. First unmet obligation remains pre-live: complete the unavailable 0x40AA7A target-rooted closure. Native bytes prove 0x40AA7A starts the row-39 conditional corridor through transfer 0x40AA92; typed reference evidence binds its semantic exits to 0x40AA94 and 0x40B1F2. The other row-38 target 0x40ADBE has a complete four-anchor closure through 0x40ADD6 and boundary 0x40B21C. Model these as imported native-body evidence while preserving row 39 unresolved; reject any topology mismatch before live mutation.

**2026-07-28T00:57:06Z**

2026-07-28 row-38 existing_conditional_plus_indirect vertical accepted on the unchanged shared GENERATED architecture. Reference-order 38 rhad:route@0x40AA78 compiles typed evidence for source 0x40AA60, cmp producer 0x40AA66 against 0x7C4FB03D, jl predicate 0x40AA6C, selected block 0x40AA6E, join 0x40AA74, transfer 0x40AA78, semantic SLT target 0x40AA7A delivered through the surviving PREOPT root 0x40AA88, observed SGE target 0x40ADBE, complete imported closure 0x40AA88/0x40AA8E/0x40AA92 and 0x40ADBE/0x40ADCC/0x40ADD2/0x40ADD6, boundaries 0x40AA94/0x40B1F2/0x40B21C, and dependency row 20. Immutable preflight rejected both the initial unavailable 0x40AA7A block guess and the first incomplete component-root set before live mutation; captured PREOPT authority proved the typed semantic-target versus delivery-root distinction and required exact 0x40AA88 and 0x40ADBE component entries. No producer, coordinator, gateway, transaction representation, direct DeferredGraphModifier path, compatibility metadata, production sample-EA guard, or mba.build_graph call was added. Plan and aggregate identity sha256:2486f480addbbd3f098330761dcbb80325b566ada9ebfdc460a85facf9c113cc. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_207_row38_existing_conditional.diag.sqlite3 has SHA-256 da2ff2306c48c9b9ff5a3c579f64114de48c8d25c9685ff66151fbdfbed2fdc8: one 293/293 committed receipt, 206 committed non-invalidated imported-native witnesses, 36 matched route comparisons, actual MMAT_GENERATED publication, exact GENERATED/PREOPT/LOCOPT survival of semantic targets through delivery roots while source topology exists, legitimate CALLS retirement with no residual indirect transfer, CMAT_FINAL, committed unpoisoned state, successful root publication, and no rollback, redo, alternate mutation path, lifecycle error, or numeric INTERR. The mandatory separate immutable row-16 table-proof artifact remains unchanged at sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785, exactly bound to input SHA-256 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c, function 0x40A560, pinned reference commit, row-16 operation ID and reference order; its identity remains required by inventory and compiled plan, participates in plan and aggregate identity, persists in diagnostics, and rejects missing or mismatched evidence before live mutation. The inventory remains exactly 228 rows. Logical commits: 76232a390 compiler, 52c9e0f87 typed PREOPT topology repair, 6c2bff534 proof, 04657d713 inventory. Fresh gates: exact combined A560 checksum including permanent 0x40A605 regression 1/1; focused compiler/FragmentPlan/PatchPlan/publication 182/182; transaction core 78/78; runtime 220/220; protected Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged. Ticket remains in_progress. Next strict reference-order operation is row 39 rhad:route@0x40AA92; first unmet obligation is to complete the unavailable 0x40AA94 target-rooted closure with exact typed native-body evidence before compilation or live mutation.

**2026-07-28T01:00:04Z**

2026-07-28 strict reference-order continuation selects row 39 rhad:route@0x40AA92, existing_conditional_plus_indirect, symbol JumpInliner._fixup_jmp_and_possible_jcc. Pinned reference transaction authority at commit 21b0d4783703bc4fb6910cfae51d92cd683d2c65 proves source 0x40AA7A, cmp producer 0x40AA80 against 0x78BAC34B, jl predicate 0x40AA86, selected block 0x40AA88, join 0x40AA8E, transfer 0x40AA92, normalized SLT target 0x40AA94, observed SGE target 0x40B0F2, owned corridor 0x40AA7A/0x40AA80/0x40AA86/0x40AA88/0x40AA8E/0x40AA90/0x40AA92, and dependency row 38. First unmet obligation is pre-live: complete the unavailable 0x40AA94 target-rooted closure through the next unresolved transfer at 0x40AAAC, while preserving row 40 unresolved. The audit also found a directly blocking provisional row-38 boundary typo: production and its proof used 0x40B1F2, but both the stable inventory decimal target 4239602 and the pinned reference transaction at 0x40AA92 prove 0x40B0F2. Correct that typed boundary and rerun row-38 acceptance before compiling row 39; do not weaken preflight or carry the wrong exit forward.

**2026-07-28T01:18:21Z**

2026-07-27 row-38 boundary/identity re-acceptance before row 39: pinned reference authority proves row-39 false exit 0x40B0F2, correcting the provisional row-38 0x40B1F2 boundary. Audit found the accepted aggregate identity hashed only direct-route evidence, so the boundary change incorrectly retained sha256:2486f480.... Commit b6d0322d4 adds deterministic serial-free canonical identity payloads for every admitted typed reference-operation dataclass and binds all operation evidence into both portable-ledger and GENERATED-batch aggregate identities; missing or unsupported portable values reject typed. Commit 9312086c4 corrects row-38 production/template/E2E boundary evidence to 0x40B0F2. Commit 399fd968e re-accepts the stable 228-row inventory and coverage authority. Fresh accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_209_row38_typed_identity.diag.sqlite3, SHA-256 1acebb035b43b76aa100241d70bfd147f47fbec3161f8f61e6a004627c5f44f2, persists plan/aggregate identity sha256:f7889d6d0e8f2c52749dffd927849f71a605f17cc11dadf78bb6b4dd12f0e465 together with the mandatory row-16 artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785. Receipt is 293/293 committed, 206 committed non-invalidated imported-native witnesses, 36 matched comparisons, actual MMAT_GENERATED publication, MMAT_PREOPTIMIZED/LOCOPT/CALLS observations, CMAT_FINAL, root publication success, zero rollback and zero INTERR mentions. Historical accepted_207 and accepted_208 proofs are preserved. Input SHA remains 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Ticket remains in_progress. Selected next operation is row 39 rhad:route@0x40AA92; first unmet obligation remains completing the 0x40AA94 target-rooted closure through unresolved transfer 0x40AAAC while preserving row 40 unresolved.

**2026-07-28T02:04:25Z**

2026-07-27 row-39 existing_conditional_plus_indirect vertical accepted through the unchanged shared GENERATED architecture. Reference-order 39 rhad:route@0x40AA92 compiles typed evidence for source 0x40AA7A, cmp producer 0x40AA80 against 0x78BAC34B, jl predicate 0x40AA86, selected block 0x40AA88, join 0x40AA8E, transfer 0x40AA92, normalized SLT target 0x40AA94 delivered through imported root 0x40AAA2, observed SGE target 0x40B0F2, complete seven-block closure through 0x40AAAC and 0x40B10A, boundaries 0x40A5F0/0x40AAAE, and dependency row 38. The shape exposed required typed join_ea evidence and a generic captured-boundary preserved-transfer contract; no optional metadata, producer, coordinator, gateway, transaction representation, direct DeferredGraphModifier path, production sample-EA guard, or GENERATED build_graph call was added. Plan and aggregate identity sha256:d26de8c697ca3669d99c3bde9f70d64be87e245582dd1435ae6a6b085c0a831e. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_210_row39_existing_conditional.diag.sqlite3 SHA-256 57239fcb2e9d7c670d8bbb2b544771baa06b628381c93948386d401aac1ae325 records one 304/304 committed receipt, 214 committed non-invalidated imported-native witnesses, 37 matched comparisons, actual MMAT_GENERATED publication, GENERATED/PREOPT/LOCOPT/CALLS semantic proof, legitimate source retirement with no residual indirect transfer, CMAT_FINAL, root publication success, and no poison, rollback, redo, alternate path, or numeric INTERR. The mandatory separate immutable row-16 artifact remains sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785 with exact input/function/reference/operation/order binding, plan and aggregate identity participation, diagnostic persistence, pre-live rejection, and stable 228-row inventory. Logical commits: cffc7ba57 compiler vocabulary; 167bb503c row-39 semantics; 65c6bea52 publication diagnostics; eb9211610 inventory authority. Final gates: exact combined A560 checksum 146-test focused group including 1/1 live canary; transaction core 78/78; accepted runtime seam 221/221; pinned Docker Hodur/Sub7FFD/Tigress/Approov 13/13; strict 41-row parity PASS; ast-grep clean; all 14 import contracts kept; graphify updated with no tracked delta; input SHA-256 unchanged. Ticket remains in_progress. Next strict reference-order operation is row 40 rhad:route@0x40AAAC; first unmet obligation is to instantiate the proved RhadExistingConditionalRoute vocabulary with exact row-40 reference evidence, native-body proof, and dependency closure before live mutation.

**2026-07-28T02:34:44Z**

2026-07-27 row-40 existing_conditional_plus_indirect vertical accepted through the unchanged shared GENERATED architecture. Reference-order 40 rhad:route@0x40AAAC compiles pinned typed evidence for source 0x40AA94, cmp producer 0x40AA9A against 0x742F372A, jne predicate 0x40AAA0 normalized to EQ, selected block 0x40AAA2, join 0x40AAA8, transfer 0x40AAAC, targets 0x40AAAE/0x40A5F0, exact four-block true closure 0x40AAAE/0x40AAE8/0x40AAEB/0x40AAEF, boundaries 0x40A607/0x40B6C0, and dependency row 39. A typed missing contract was exposed by detached components reusing source stack VD 88 for distinct IDA slots: commit 6a083ec90 permits no template-wide alias and requires complete exact instruction-EA-scoped stack identities, otherwise rejecting before mutation. Logical commits: 6a083ec90 backend contract, bc6aa9a92 compiler/operation semantics, 7f7296027 exact publication diagnostics, 5ff614e98 inventory authority. Accepted DB .tmp/logs/d810_logs/000000000040a560_accepted_211_row40_existing_conditional.diag.sqlite3 SHA-256 aee4fb95b83da9d93f6184368ceefda165821990268c4506c9f81c659a645c2b persists aggregate identity sha256:d290b7a3da429f99a6a5c9c14680ffa8387e2269d718c551b7835065aaa3a9b5 and mandatory row-16 artifact sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785. It records one 312/312 committed receipt, 224 creation witnesses, 38/38 matched route comparisons, actual MMAT_GENERATED publication, semantic survival through authoritative CFG, legitimate CALLS retirement with no residual indirect, CMAT_FINAL, and no poison, rollback, redo, alternate path, or numeric INTERR. The inventory remains exactly 228 rows. Ticket remains in_progress and is not restarted or closed. Per the post-success data-first sequence, the selected next same-shape operation is reference-order 43 rhad:route@0x40AB15; first unmet obligation is exact row-43 reference evidence, native-body proof, and dependency closure before live mutation. Full protected/gate verification follows before that implementation.

**2026-07-28T02:42:13Z**

2026-07-27 row-40 final verification: exact combined A560 checksum including permanent 0x40A605 and new 0x40AAAC canaries 1/1; focused compiler/FragmentPlan/PatchPlan/transaction/runtime/live-publication group 425/425; pinned Docker Hodur/Sub7FFD/Tigress/Approov protected-family matrix 13/13; strict 41-row portable CFG transaction parity PASS with --require-integrated; ast-grep clean; all 14 import-linter contracts kept; graphify update completed with no tracked delta; fixture SHA-256 unchanged at 2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c. Accepted row-40 DB and identities remain as recorded in the preceding note. Ticket remains in_progress for row 43 rhad:route@0x40AB15.

**2026-07-28T02:44:22Z**

2026-07-27 row-43 preimplementation inventory, data-first same-shape continuation. Selected reference-order 43 rhad:route@0x40AB15, existing_conditional_plus_indirect, symbol JumpInliner._fixup_jmp_and_possible_jcc. Pinned donor commit 21b0d4783703bc4fb6910cfae51d92cd683d2c65 and unchanged binary prove source 0x40AAFD, cmp producer 0x40AB03 against 0x1EBFFA3C, jl predicate 0x40AB09, selected block 0x40AB0B, join 0x40AB11, transfer 0x40AB15, normalized SLT target 0x40AB17, observed SGE target 0x40B149, and owned corridor 0x40AAFD/0x40AB03/0x40AB09/0x40AB0B/0x40AB11/0x40AB13/0x40AB15. Publication dependency is unproved row 42 rhad:route@0x40AAFB, simple_indirect_jump, which delivers 0x40AAFD from the already imported 0x40AAF1 carrier and must be compiled in the same dependency-closed vertical through existing RhadDirectRoute vocabulary. The 0x40B149 closure is complete through 0x40B161 to 0x40A5F0. First unmet typed obligation is pre-live: complete the unavailable 0x40AB17 true-root closure as exact conditional source/select/join/tail identities through unresolved transfer 0x40AB2F, with typed exits 0x40AB31 and 0x40A5F0, while preserving row 44 unresolved. Reuse the existing producer, compiler, coordinator, gateway, transaction representation, and mandatory row-16 artifact; reject any topology mismatch before mutation.
