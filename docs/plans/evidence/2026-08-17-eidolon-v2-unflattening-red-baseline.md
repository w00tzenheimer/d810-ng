# Eidolon v2 unflattening completeness RED baseline

Date: 2026-08-17

Worktree: `eidolon-v2-unflattening-completeness`

Pre-task commit: `9aaf11e73`

Profile: `eidolon_v3_const_solve.json` (the config-v2 profile selected by all
three decompilation tests)

Task 1 status: `BLOCKED` for evidence completion. The preserved Docker
stdout runs predate the stricter applied-proof assertion and were not rerun
because the parent prohibited another long run. Their SQLite proof rows are
readable and show the assertion would fail, but that is derived evidence
rather than a fresh final-test transcript. The preserved A/B/C reasons also do
not exactly match all prose expectations in the brief; the discrepancies are
listed below.

## Scope and oracle

This baseline adds the third source-faithful MASM export and binds every
effect assertion to a CONST qword marker that resolves to one exact native
instruction. The existing session-scoped diagnostic receipt and post-D810
CFG BFS oracle remain the only reachability oracle. No production
unflattening source was changed.

The test now also rejects an applied dispatcher-removal batch whose own
`UnflattenDispatcherRemovalPreflightProof` is rejected. A clean mutation
receipt alone is insufficient when unrelated cleanup edits commit in the same
session. This stricter assertion was added after the first v2 runs showed
that A, B, and C could otherwise report `PASSED` while their applied
dispatcher-removal proofs were rejected.

## Fixture export and post-link identity

The C body was exported from the live IDA function at `0x7FF855576B50` by the
existing MASM exporter with materialized data and constant data enabled. The
body was not hand-reconstructed. Its generated function name was normalized
to the stable export `sub_7FF855576B50`; the three markers are in `CONST` and
point at private labels immediately before the native effects.

The standalone LLVM-linked image has image base `0x180000000`. The original
live source extents and measured post-link extents are:

| Fixture | Live source size | Linked start-end | Linked size |
| --- | ---: | --- | ---: |
| A `sub_7FF8569F0540` | `0x17E06` | `0x180014DE0-0x18002CC1C` | `0x17E3C` |
| B `sub_7FF8568132D0` | `0x1796C` | `0x18002CC20-0x1800445BB` | `0x1799B` |
| C `sub_7FF855576B50` | `0x54B` | `0x1800445C0-0x180044AFD` | `0x53D` |

The C extent was first intentionally set to `0x55B`; the canonical C run
reported `0x1800445C0-0x180044AFD`, so the table was corrected to `0x53D`
before the successful parity run. Adding C also caused IDA to absorb B's
five alignment bytes through the next export; `_resolve_fixture_ea` now
restores the measured B end with `ida_funcs.set_func_end` before the exact
extent assertion.

The linked marker storage and exact native effect addresses are:

| Marker | Storage EA | Native target EA | Instruction |
| --- | ---: | ---: | --- |
| `d810_callsite_sub_7FF8569F0540_memcpy` | `0x18004C5B7` | `0x180026779` | `call memcpy` |
| `d810_callsite_sub_7FF8568132D0_srw_lock` | `0x180050A70` | `0x180031247` | SRW-lock call |
| `d810_callsite_sub_7FF855576B50_message_box` | `0x180050AB2` | `0x180044A5A` | `call MessageBoxA` |
| `d810_callsite_sub_7FF855576B50_get_current_process` | `0x180050ABA` | `0x180044A60` | `call GetCurrentProcess` |
| `d810_callsite_sub_7FF855576B50_terminate_process` | `0x180050AC2` | `0x180044AF7` | tail `jmp TerminateProcess` |

The C terminal is a native tail jump, so the exact marker resolver accepts
`call` and a tail `jmp`; it still rejects every other mnemonic and keeps the
same exact-EA reachability requirement.

## Contract audit

- `TARGET_SIZES` records measured linked extents A=`0x17E3C`,
  B=`0x1799B`, C=`0x53D`; the loader restores an absorbed IDA function
  boundary before asserting the extent.
- Each explicit marker is a PUBLIC qword in `CONST` pointing through a
  relocation to one private `*_target` label in `_TEXT`, immediately before
  one native call or terminal tail jump. The local fixture parser checks that
  section metadata path; the build script verifies the linked PE export table.
- The transaction oracle selects the newest finished diagnostic session for
  the function after the test start, joins receipts and clean transaction
  attempts by that session ID, and requires planned-equals-applied commits.
- The exact-call oracle selects the newest `post_d810` snapshot inside that
  session window, requires entry serial 0 at the function EA, and delegates
  fail-closed successor traversal to the existing `reachable_call_eas`
  helper. Unknown successors and missing exact marker EAs fail.

## Hashes

Hashes were recorded before removing the generated DLL:

```text
d8b610654ad448184f871d892f3ada0a3920640e98a93a04801374c77e0df23a  samples/src/masm/sub_7FF855576B50.asm
49dc43ccaf6a92e4a21be2b79223e042d839e9e38455947f01dee57d07128e15  samples/src/masm/sub_7FF8569F0540.asm
30db1a3b74554c141407acb8cdaeab06b44cfe8b78cbe5dda6e77c49e803fa8f  samples/src/masm/sub_7FF8568132D0.asm
cf57a7b55d024fb28cb03f63c2afc0e8970febfbae480cb85385849898fa3f9d  samples/bins/unflattening_effect_safety.dll
```

The DLL is generated evidence only and is removed before commit.

## TDD evidence

The unit RED command was:

```bash
PYTHONPATH=src pytest -q tests/unit/test_unflattening_effect_safety_masm_fixtures.py -vv
```

Captured output: `8 collected; 6 passed; 2 failed`. The failures were the
raw exporter header (`Eidolon_ShowErrorAndTerminateProcess` instead of the
stable function export) and the absent three C marker exports. The output is
preserved at `.tmp/task1_fixture_red.txt`.

After source normalization, marker insertion, and build-script changes, the
focused unit GREEN command was the same command and produced:

```text
8 passed in 0.11s
```

## Build evidence

The required canonical build command was attempted from the main checkout:

```bash
./tools/scripts/run_system_tests_docker.sh exec \
  -w eidolon-v2-unflattening-completeness -- \
  bash -lc 'samples/scripts/build_masm.sh unflattening_effect_safety'
```

The first attempt exited `127` because the Docker image has no `brew`; the
script previously evaluated `brew --prefix llvm` under `set -e`. The script
now treats an absent Homebrew prefix as empty and resolves tools through
`PATH`. A post-fix canonical probe exited `1` because the image has no clang/
MASM toolchain. That is an environment limitation, not a source/export
failure.

The host LLVM build, used only to generate the evidence PE, was:

```bash
bash samples/scripts/build_masm.sh unflattening_effect_safety
```

It assembled A, B, and C, compiled 28 objects and skipped 2 existing objects,
linked `samples/bins/unflattening_effect_safety.dll`, and verified all three
functions plus all five marker exports. The resulting file was PE32+ x86-64.

## Docker system evidence

The runner was always invoked from `/Users/mahmoud/src/idapro/d810` with
`-w eidolon-v2-unflattening-completeness`, `-l`, and the exact bare output
filenames required by the brief. `D810_TEST_BINARY=unflattening_effect_safety.dll`
was supplied because the repository `.env` defaults to `libobfuscated.dll`.

The exact per-target commands and preserved artifacts were:

```bash
D810_TEST_BINARY=unflattening_effect_safety.dll \
  ./tools/scripts/run_system_tests_docker.sh test \
  -w eidolon-v2-unflattening-completeness -l \
  -o task1_target_a_red.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_a_after_preserves_memcpy_effect_and_commits \
  -vv -s

D810_TEST_BINARY=unflattening_effect_safety.dll \
  ./tools/scripts/run_system_tests_docker.sh test \
  -w eidolon-v2-unflattening-completeness -l \
  -o task1_target_b_red.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_b_after_preserves_srw_lock_effect_and_commits \
  -vv -s

D810_TEST_BINARY=unflattening_effect_safety.dll \
  ./tools/scripts/run_system_tests_docker.sh test \
  -w eidolon-v2-unflattening-completeness -l \
  -o task1_target_c_red.txt -- \
  tests/system/e2e/test_unflattening_effect_safety_fixtures.py::TestUnflatteningEffectSafetyDecompilation::test_target_c_after_preserves_termination_effects_and_commits \
  -vv -s
```

The first A run was stopped after an uninstrumented CPU-bound interval at
`MMAT_PREOPTIMIZED`; its partial log is `.tmp/task1_target_a_red.txt`.
A bounded Cython-enabled retry was preserved as
`.tmp/task1_target_a_red_cython.txt`; it completed in 188.19 seconds and the
old oracle printed:

```text
[EFFECT-SAFETY A] ea=0x180014de0 committed=[planned=142, applied=142, outcome=committed] pseudocode_bytes=43048
1 passed in 188.19s
```

Target B completed in 352.53 seconds using the old oracle:

```text
[EFFECT-SAFETY B] ea=0x18002cc20 committed=[planned=104, applied=104, outcome=committed; planned=1, applied=1, outcome=committed] pseudocode_bytes=57613
1 passed in 352.53s
```

Target C first exposed the provisional extent mismatch. After correcting the
measured extent to `0x53D`, the exact rerun completed in 11.19 seconds using
the old oracle:

```text
[EFFECT-SAFETY C] ea=0x1800445c0 committed_modifications=8 pseudocode_bytes=702
1 passed in 11.19s
```

The important RED evidence is in the transaction-owned proof rows, not those
old PASS summaries. The applied proof was rejected in every target:

| Target | Proof reason | Handlers | Post handlers | Lost blocks |
| --- | --- | ---: | ---: | ---: |
| A | `untyped_lost_block` | 134 | 134 | 152 |
| B | `untyped_lost_block` | 102 | 102 | 110 |
| C | `corridor_enumeration_incomplete` | 3 | 2 | 8 |

The stricter `_assert_dispatcher_removal_proof_accepted` oracle would fail on
these applied rejected proofs. It was added after the preserved Docker runs;
the stricter version was syntax-checked and covered by the focused unit gate,
but was not rerun in Docker after the parent requested no more long runs.

The preserved evidence does not exactly match every prose expectation in the
brief: A reports `untyped_lost_block` rather than
`authoritative_handler_lost`; B also reports `untyped_lost_block` rather
than a terminal-specific proof reason; and C reports
`corridor_enumeration_incomplete` without a literal `initial_state=None`
line. These are blockers for claiming exact live-failure parity, not reasons
to weaken the fixture oracle or production safety gates.

### Stable-EA lost-block inventory

The following are the complete stable-EA anchors from the applied proof rows.
Block serials are retained only alongside their EA anchors.

#### A: `untyped_lost_block`

```text
blk3@0x180014e99, blk4@0x180014ea0, blk5@0x180014eb1, blk6@0x180014ebc, blk7@0x180014ec7, blk8@0x180014ed2, blk9@0x180014edd, blk10@0x180014ee8, blk11@0x180014ef3, blk14@0x180014f38, blk15@0x180014f43, blk16@0x180014f4e, blk17@0x180014f59, blk18@0x180014f64, blk19@0x180014f6f, blk20@0x180014f7a, blk22@0x180015020, blk23@0x18001502b, blk24@0x180015036, blk25@0x180015041, blk26@0x18001504c, blk27@0x180015057, blk30@0x1800150ac, blk31@0x1800150b7, blk32@0x1800150c2, blk33@0x1800150cd, blk34@0x1800150d8, blk35@0x1800150e3, blk37@0x1800150f3, blk38@0x1800150fe, blk39@0x180015109, blk40@0x180015114, blk41@0x18001511f, blk43@0x180015143, blk44@0x18001514e, blk45@0x180015159, blk46@0x180015164, blk47@0x18001516f, blk50@0x1800151c2, blk51@0x1800151cd, blk52@0x1800151d8, blk53@0x1800151e3, blk54@0x1800151ee, blk59@0x18001603f, blk60@0x18001604a, blk61@0x180016055, blk62@0x180016060, blk63@0x18001606b, blk65@0x18001607b, blk66@0x180016086, blk67@0x180016091, blk68@0x18001609c, blk70@0x1800160c0, blk71@0x1800160cb, blk72@0x1800160d6, blk73@0x1800160e1, blk75@0x180016121, blk76@0x18001612c, blk77@0x180016137, blk79@0x18001614e, blk80@0x180016159, blk81@0x180016164, blk83@0x1800161dc, blk84@0x1800161e7, blk85@0x1800161f2, blk87@0x18001620c, blk88@0x180016217, blk89@0x180016222, blk91@0x180016246, blk92@0x180016251, blk93@0x18001625c, blk96@0x180016296, blk97@0x1800162a1, blk98@0x1800162ac, blk100@0x1800162ca, blk101@0x1800162d5, blk104@0x18001631a, blk105@0x180016325, blk107@0x18001633c, blk108@0x180016347, blk110@0x180016371, blk111@0x18001637c, blk114@0x1800163da, blk115@0x1800163e5, blk117@0x1800163f9, blk118@0x180016404, blk120@0x18001641b, blk121@0x180016426, blk123@0x18001645b, blk124@0x180016466, blk126@0x180016493, blk127@0x18001649e, blk129@0x1800164ae, blk130@0x1800164b9, blk135@0x180016be0, blk136@0x180016beb, blk139@0x180016e29, blk140@0x180016e34, blk142@0x180016e4b, blk143@0x180016e56, blk150@0x180017856, blk151@0x180017861, blk153@0x180017871, blk154@0x18001787c, blk156@0x180017922, blk157@0x18001792d, blk160@0x180017c9e, blk162@0x180017ce1, blk165@0x180017d41, blk171@0x180018f66, blk174@0x1800191f1, blk180@0x180019a0e, blk183@0x180019a9b, blk187@0x180019c0e, blk189@0x180019c3c, blk194@0x180019dd4, blk196@0x180019de4, blk201@0x18001a184, blk203@0x18001a1ae, blk205@0x18001a1ed, blk209@0x18001a56d, blk212@0x18001a62d, blk215@0x18001a684, blk217@0x18001ad55, blk220@0x18001ae48, blk222@0x18001ae5f, blk224@0x18001aea8, blk226@0x18001b025, blk229@0x18001b070, blk231@0x18001b08b, blk235@0x18001b289, blk237@0x18001b2cc, blk244@0x18001c70a, blk248@0x18001c907, blk251@0x18001ccbf, blk257@0x18001d27b, blk264@0x18001d8c8, blk269@0x18001da64, blk310@0x180020f63, blk386@0x1800263fa, blk423@0x180029ad4, blk428@0x180029b94, blk439@0x18002a64b, blk452@0x18002a9bf, blk455@0x18002aa11, blk473@0x18002b1a9, blk478@0x18002b92f, blk507@0x18002c6ee, blk513@0x18002c81c, blk516@0x18002c88e, blk519@0x18002c8fd, blk532@0x18002cb99
```

#### B: `untyped_lost_block`

```text
blk4@0x18002d1c3, blk5@0x18002d1ca, blk6@0x18002d1ce, blk7@0x18002d1d9, blk8@0x18002d1e4, blk9@0x18002d1ef, blk10@0x18002d1fa, blk11@0x18002d205, blk12@0x18002d210, blk14@0x18002d220, blk15@0x18002d22b, blk16@0x18002d236, blk17@0x18002d241, blk18@0x18002d24c, blk19@0x18002d257, blk22@0x18002d2ae, blk23@0x18002d2b9, blk24@0x18002d2c4, blk25@0x18002d2cf, blk26@0x18002d2da, blk29@0x18002d6fe, blk30@0x18002d709, blk31@0x18002d714, blk32@0x18002d71f, blk33@0x18002d72a, blk35@0x18002da1c, blk36@0x18002da27, blk37@0x18002da32, blk38@0x18002da3d, blk42@0x18002f1b0, blk43@0x18002f1bb, blk44@0x18002f1c6, blk45@0x18002f1d1, blk47@0x18002f213, blk48@0x18002f21e, blk49@0x18002f229, blk50@0x18002f234, blk52@0x18002f2a2, blk53@0x18002f2ad, blk54@0x18002f2b8, blk55@0x18002f2c3, blk61@0x18002f484, blk62@0x18002f48f, blk63@0x18002f49a, blk65@0x18002f54a, blk66@0x18002f555, blk67@0x18002f560, blk70@0x18002f7ae, blk71@0x18002f7b9, blk72@0x18002f7c4, blk79@0x1800307d6, blk80@0x1800307e1, blk81@0x1800307ec, blk83@0x180030803, blk84@0x18003080e, blk85@0x180030819, blk91@0x1800309f6, blk92@0x180030a01, blk93@0x180030a0c, blk96@0x180030b4f, blk97@0x180030b5a, blk98@0x180030b65, blk100@0x180030b9f, blk101@0x180030baa, blk102@0x180030bb5, blk104@0x180030d5b, blk105@0x180030d66, blk107@0x180030d82, blk108@0x180030d8d, blk111@0x180031224, blk112@0x18003122f, blk115@0x180031313, blk116@0x18003131e, blk118@0x1800313b6, blk119@0x1800313c1, blk128@0x1800326f3, blk129@0x1800326fe, blk132@0x1800328f9, blk133@0x180032904, blk136@0x180032d9e, blk137@0x180032da9, blk145@0x180033120, blk146@0x18003312b, blk148@0x18003313b, blk149@0x180033146, blk152@0x180033179, blk153@0x180033184, blk155@0x1800331f0, blk156@0x1800331fb, blk158@0x180033277, blk159@0x180033282, blk161@0x1800332db, blk162@0x1800332e6, blk167@0x180033f99, blk168@0x180033fa4, blk170@0x180034221, blk171@0x18003422c, blk175@0x1800342c1, blk177@0x180034342, blk180@0x180034852, blk185@0x180034a6a, blk187@0x180034ad8, blk189@0x180034af6, blk191@0x180034b06, blk254@0x180038494, blk276@0x18003b091, blk316@0x18003f575, blk325@0x18003f775, blk365@0x180042990, blk383@0x180043f19
```

#### C: `corridor_enumeration_incomplete`

```text
blk2@0x180044617, blk3@0x18004464b, blk4@0x18004464e, blk5@0x180044658, blk6@0x180044663, blk7@0x18004466a, blk12@0x1800447f5, blk17@0x1800448fc
```

## Concerns and handoff boundary

The fixture/export/profile work is packaged separately from production repair,
but the exact RED baseline remains blocked until the strict Docker cases are
rerun or an authorized equivalent transcript is supplied. The retained
effect-only assertions reported PASS while the applied proof rejected 152,
110, and 8 blocks. The C failure is
`corridor_enumeration_incomplete`, not the brief's more specific
`initial_state=None` wording; the preserved log does show interval-interior
handler recovery and only 2 of 3 handlers post-reachable. These discrepancies
are recorded rather than hidden or worked around in production.

Preserved Docker evidence:

```text
.tmp/task1_fixture_red.txt
.tmp/task1_target_a_red.txt
.tmp/task1_target_a_red_cython.txt
.tmp/task1_target_b_red.txt
.tmp/task1_target_c_red.txt
.tmp/logs/d810_logs/0000000180014de0_1786992548_119.diag.sqlite3
.tmp/logs/d810_logs/000000018002cc20_1786992948_11.diag.sqlite3
.tmp/logs/d810_logs/00000001800445c0_1786992841_11.diag.sqlite3
```
