# L5: INTERR-code -> projected-invariant coverage

Status: planned (2026-06-06). Roadmap: `ROADMAP.md` (L5). Harness: Phases 1-3 +
L4 (projected gate).

## Goal
Every `native_verify` INTERR a lowering op can raise has a corresponding
**projected invariant** that rejects the bad plan pre-mutation -- so the reactive
rollback path becomes dead code for the projectable INTERR classes (AGENTS.md
"close a coverage gap" workflow).

## What d810 already has
`hexrays/contracts/invariants.py` (mblock checks, incl. `CFG_50860_SUCC_MISMATCH`),
`insn_invariants.py` (named MINSN_* codes), `native_oracle.py`,
`*parity_matrix.json` (python-check vs native-oracle parity).

## Gap
We reverse-engineered 50346 (graphcache-dirty) and 50860 (succ-mismatch)
**reactively**. 50346 has no projected invariant (it is a private-state assertion,
gated by stage -> handled by the maturity contract L10); 50860 IS structural and
should be a projected check on inserted-block successor consistency. The coverage
map is unpopulated.

## Approach
For each INTERR observed in the lab: classify projectable vs stage/runtime; for
projectable ones add a projected invariant + a `parity_matrix` entry; manufacture
a microcode-mutation fixture that deliberately triggers the code and assert the
projected gate (L4) rejects it pre-apply. Start with 50860 (leftover-goto ->
succ mismatch) and 50795/50804-class insn invariants for synthesized payloads.

## Fixture
Microcode-mutation cases (no C fixture): build a malformed insert (e.g. payload
retaining a goto -> 50860; bad opcode -> MINSN_50804) and assert projected
rejection; valid insert passes.

## Success criteria
Projected invariant rejects each covered INTERR class pre-mutation; parity matrix
green; the reactive INTERR no longer reaches `native_verify` for covered classes.

## Risks / IR-dump unknowns
The AGENTS.md projectability limit: some INTERRs only become true after IDA's
post-apply opt and cannot be projected (50346 is stage-class -> L10, not L5).

## Dependencies
L4 (projected gate wired first). Informed by L10 (stage-class codes).
