# Task 5 report: bounded dispatcher self-reentry and effectful corridor safety

## Scope

- Worktree: `/Users/mahmoud/src/idapro/d810/.worktrees/eidolon-v2-unflattening-completeness`
- Branch: `diff/eidolon-v2-unflattening-completeness`
- Base SHA: `b0e1c0a34`
- Production scope: `dispatcher_corridor_coverage.py`; `minimal_unflatten_emit.py`
  was not needed because the focused RED isolated coverage enumeration.
- This patch covers Task 5-C's bounded dispatcher self-reentry case. Task 5-A's
  effectful corridor ownership remains deliberately unchanged and pending.

## Verified diagnosis

Target C has all six planned redirects. Its `corridor_enumeration_incomplete`
result is caused by `_upstream_corridor_paths` / `append_split_predecessor`
marking the expected dispatcher self-reentry merge as incomplete when an
already-seen feeder is a non-dispatcher merge input. The rejection is selected
by `build_dispatcher_removal_preflight_proof` before the untyped-loss
boundary. The exact lost anchors are recorded in `task-5-brief.md` and the
preserved `.tmp/task4_target_c_fix_round4.txt` artifact.

Task 1 A has complete corridor enumeration but fails the typed-retirement
subset check in `_retired_dispatcher_infrastructure` /
`_covered_control_only_comparison_corridor_region`. No production change is
authorized to broaden semantic/effectful retirement.

## RED

The exact portable C RED uses a branched, effect-free comparison suffix rather
than a target-specific graph:

```text
entry 0 -> 1, 8
1 -> dispatcher 3
8 -> merge 4
3 -> 4
4 -> 5, 10
5 -> 6
6 -> feeder 2
2 -> 3
```

The planned redirects are `1 -> 9` and `2 -> 9`. Before the production edit,
the baseline implementation reported `enumeration_complete=False` despite
zero residual corridors. The exact captured output is
`.tmp/task5_c_portable_red.txt`:

```text
1 failed, 4 passed, 51 deselected in 0.40s
```

The failure is solely the positive assertion that enumeration is complete;
the failure path contains `1 -> 3 -> 4 -> 5 -> 6 -> 2 -> 3`.
The entry-side `0 <-> 8` reverse-cycle negative and the merge/feeder reverse
cycle negative both remain incomplete. Two cap tests also remain incomplete
with zero residual corridors.

## GREEN

The production change accepts only a repeated feeder at `suffix[-2]` when all
of the following source-CFG facts hold:

- the repeated input is reached while expanding the dispatcher predecessor;
- the dispatcher has the suffix root as its sole successor;
- every ordered edge in the suffix exists;
- the feeder has the dispatcher as its sole successor; and
- the repeated feeder does not occur elsewhere in the suffix.

All other repeated non-dispatcher nodes still mark enumeration incomplete.
The focused corridor suite is green:

```text
PYTHONPATH=src pytest -q tests/unit/transforms/test_dispatcher_corridor_coverage.py -vv
56 passed in 0.20s
```

The branched self-reentry positive, entry-side reverse-cycle negative,
merge/feeder reverse-cycle negative, and `_MAX_CORRIDOR_DEPTH` /
`_MAX_CORRIDORS` cap tests are included. No residual-zero shortcut was added;
`enumeration_complete` remains an independent gate.

## Acceptance and gates

Changed-file Ruff and whitespace checks pass:

```text
ruff check src/d810/transforms/dispatcher_corridor_coverage.py \
  tests/unit/transforms/test_dispatcher_corridor_coverage.py
All checks passed!
git diff --check
```

Per the Task 5-C scope, Docker, merge, push, and Task 5-A acceptance were not
run. The pre-existing untracked fixture DLL remains untouched.

## Commit

Pending commit after the final worktree diff review.
