# Agent Instructions — Restructuring Lab

Status: 2026-06-06. Build mechanics live in `README.md` + `DESIGN.md`; this file
is the *why* and the operating rules. Read those first, this second.

## Mission

This micro-project is the **build/evidence half** of restructuring work (the
*observe half* is the registry harness in `tools/hexrays_structuring_lab/`). Its
reason to exist is one north-star goal:

> **Proven ways to lower the IR back to Hex-Rays microcode** — emit microcode
> the decompiler accepts *and* structures cleanly, with the unsafe paths gated
> out by construction rather than discovered at runtime.

That goal has two distinct obligations. Do not conflate them:

1. **Validity** — never emit microcode Hex-Rays rejects (`mba.verify()` throws an
   `INTERR`). This is the contract/oracle half.
2. **Structurability** — emit valid microcode Hex-Rays renders as readable
   pseudocode, not goto-soup (`bad_topology_collapse`). This is the observe
   half's cascade-vs-shared-convergence finding.

A fixture or finding belongs to **exactly one** of these. Tag it accordingly.

## The proven-lowering loop — where it lives, do not reinvent

The loop you are extending already exists in `src/d810`; this lab manufactures
evidence and regression fixtures for it. Authoritative sources:

- `src/d810/passes/transaction_policy.py` — the phase pipeline and the
  **transaction boundary**. Phase order:
  `semantic_preflight -> projected_contract -> live_pre_check -> lowering ->
  backend_apply -> post_apply_contract -> native_verify ->
  rollback_restore -> rollback_verification`.
- `src/d810/hexrays/mutation/` `DeferredGraphModifier` — the actor at
  `backend_apply` (live MBA mutation). "deferred modifier does applications."
- `src/d810/hexrays/contracts/` — the **ported verify contracts**:
  `invariants.py` (mblock-level, from the Hex-Rays verifier),
  `insn_invariants.py` (instruction-level named `INTERR` codes from
  `minsn_t::verify`/`mop_t::verify`, e.g. `MINSN_50804_INVALID_OPCODE`),
  `native_oracle.py` (Cython `_cblock_oracle`, returns
  `(interr_code, block_serial, message)`), and the `*parity_matrix.json` files.
- `src/d810/hexrays/mutation/cfg_verify.py` — `_InterrCatcher` grabs the numeric
  `INTERR` off `hxe_interr` before the exception throws. "see why interr codes
  happened."
- `src/d810/transforms/contract.py` — portable, backend-agnostic contract types
  (`CfgContract`, `BackendContractOracle`); the Hex-Rays oracle is injected.

## Core principle: gate proactively, not reactively

The transaction boundary is the whole point: phases before `lowering` see only
**projected/read-only** CFG views (reject cheaply, no rollback); `backend_apply`
onward mutate the live MBA (failure -> snapshot rollback).

- An `INTERR` caught at `native_verify` (post-mutation) is a **failure of the
  gate**, not a success of the safety net. The fix is to catch the same
  condition at `projected_contract` / `live_pre_check` (pre-mutation), so the
  plan is rejected before any mutation.
- Target: **drive rollback-firing to zero for the projectable `INTERR`
  classes.** When projected coverage is complete, the rollback path is dead code
  in practice.
- "Proven" = evidence the projected check subsumes the native one: keep the
  `*parity_matrix.json` entries green (python check vs native oracle), and use Z3
  (`src/d810/mba/verifier.py`, `@verifier`) where a hard proof is wanted instead
  of parity sampling.

## Projectability limit — honest scope

Some `INTERR`s only become true **after** Hex-Rays' own post-`backend_apply`
optimization mutates what you emitted; they are not visible on the pre-opt
projected CFG. For that class the rollback is an **irreducible safety net** — do
not claim it can be gated away. Eliminate the *projectable* classes; keep the
net for the rest.

## Workflow — closing one coverage gap (the unit of work here)

1. **Observe** which `INTERR` code reaches `native_verify`/`rollback` on a real
   run (e.g. `sub_7FFD3338C040`) or a fixture. Use the diag DB / `_InterrCatcher`
   output, not guesses.
2. **Classify**: is it projectable (decidable on the pre-opt projected
   `FlowGraph`)? If not, stop — it stays a rollback case; record why.
3. **Gate**: add or confirm a projected invariant in
   `src/d810/hexrays/contracts/` that rejects the plan at `projected_contract`.
4. **Manufacture** a fixture *here* (microcode-mutation tier — `DESIGN.md` §
   "Microcode Mutation Fixtures") that deliberately triggers that code, so the
   gate is regression-tested and cannot silently regress.
5. **Prove**: the relevant `*parity_matrix.json` entry is green; add a Z3 proof
   where the invariant warrants one.
6. **Record**: registry case + observation artifact, one hypothesis each.

## Evidence discipline (do not skip)

- No validity/structuring conclusion without the compiled-CFG validation gate
  passing first (`README.md` "Validated facts"; `DESIGN.md` status model).
  Source shape alone is not evidence.
- One CFG hypothesis per fixture. Keep fixtures tiny.
- A re-homed fixture carries a prior validation **only** if you prove the
  machine code byte-identical *or* re-run the `validate-cfg` gate against the new
  binary. State which, in the observation `note`.
- Never let this lab's build clobber `libobfuscated.dll` (isolated mounts; see
  `build_lab.sh`). Verify its hash is unchanged after every build.
