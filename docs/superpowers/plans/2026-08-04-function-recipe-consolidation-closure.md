# Function-recipe consolidation closure record

Status: completed, then tightened by the strict pass/execution-configuration
implementation on 2026-08-04.

The completed system has one public model:

1. Projects and function recipes contain ordered strict config-v2 pass entries.
2. Passes own typed options and stable transforms.
3. Passes expand to stable execution stages for scheduling and diagnostics.
4. `ExecutionScopeService` evaluates stage eligibility for both hooks and the
   Workbench.
5. Function recipes and tags are keyed by database identity, project, and EA.
6. Netnode is the default. SQLite is selected only by the typed
   `function_recipe_storage` application setting with an explicit safe path.
7. Saved recipes execute only through the atomic `Deobfuscate This` path.

The implementation deliberately removed the separate private-implementation
editor, persisted implementation overrides, compatibility aliases, inferred
storage locations, and public implementation-class diagnostics. Former data is
not migrated because its ownership and semantics cannot be established safely.

Verification is recorded by the strict plan in
`docs/superpowers/plans/2026-08-04-strict-pass-execution-configuration.md`.

## Native regression closure

The full native regression burn-down exposed one adjacent computed-transfer
case that the configuration refactor made reachable: a state write and its
terminal return-value carrier can live in different native blocks. The final
implementation makes four explicit decisions:

1. `FragmentReturnCarrier.block_id` owns the carrier instruction, while
   `state_write_block_id` owns the state assignment. Same-block corridors are
   still supported, but are no longer assumed.
2. Missing default-leaf state routes are promoted by the portable analysis
   layer, not the Hex-Rays resolver adapter. Conflicting proof producers cause
   abstention.
3. A proven scalar return carrier temporarily protects the active ABI return
   register from global DCE. The register is discovered through IDA's current
   calling convention and return-location calculation; no OS, section name,
   or architecture register name is hard-coded.
4. At `hxe_glbopt`, an imported explicit `m_ret` is converted to Hex-Rays'
   canonical `BLT_1WAY -> BLT_STOP` form. The hook returns `MERR_LOOP`, because
   a CFG mutation that is not acknowledged is itself an invalid decompiler
   state. ABI-register protection survives that loop and is released only at a
   stable global-optimization boundary.
5. Terminal-return evidence refines only the transient MBA prototype and clears
   `MBA_REFINE`, preventing Hex-Rays from replacing the proven scalar return
   with `noreturn`. `final_type` remains false: inferred evidence is not
   mislabeled as a user-specified prototype, and nothing is persisted to the
   IDB.
6. Direct semantic edges preserve the origin of a native `m_goto` that is
   retargeted in place. A genuinely synthesized structural goto has no native
   terminator EA, while any retained native prefix keeps its instruction
   origins. Preflight and live validation distinguish these cases explicitly.
7. Frontend source ownership and route-corridor closure use entry reachability.
   An entry-reachable conditional owner wins over same-EA stale trampolines;
   unreachable orphan predecessors do not veto an otherwise closed live route.
   A same-EA branch is classified as a CMOV/select split only when the complete
   selected-value and join envelope binds exactly.
8. Return-to-stop rewrites and prototype-driven use/def invalidation execute
   through the central mutation backend. The lifecycle layer owns evidence and
   timing, but does not write Hex-Rays CFG structures directly. Native MBA
   ownership is established by the caller and exact edge shape, not Python
   object identity: SWIG can expose distinct wrapper objects for the same
   native `mba_t` pointer.

Tradeoffs:

- The temporary no-delete marker is stronger than ordinary inferred liveness,
  but its lifetime is bounded to optimizer convergence and scoped by exact
  terminal-carrier evidence. If another cleanup requests a loop, protection is
  retained through that loop as well.
- Disabling return-type refinement is stronger than merely suggesting a type,
  but it is transient and justified by paired evidence for both the ABI carrier
  and the native return instruction. User-final types still take precedence.
- Canonicalizing all explicit returns in an evidence-owned fragment is broader
  than tracking one maturity-local block serial, but survives block merging and
  regeneration without leaking transient identities across maturities.
- Only single-register integer ABI returns are supported. Split-register,
  floating-point, vector, and aggregate returns fail closed until their carrier
  model is typed explicitly.
- Exact terminator semantics are now part of immutable preflight comparison.
  This caught stale test backends, but requires every backend fixture to model
  a direct edge as `GOTO` rather than `UNKNOWN`.
- Reachability filtering tolerates dead optimizer residue, but deliberately
  stops treating unreachable orphan edges as safety authority. Reachable
  competing owners and boundaries still cause abstention.
- The official Docker runner treats its baked-runtime label as a claim to
  verify, not an unconditional skip. It refreshes declared test dependencies
  and Git when stale, and mounts the repository object database read-only so a
  linked worktree can validate pinned donor commits inside the container. This
  adds setup time for stale images but removes false-green labels and
  host-path-dependent parity failures.
- Removing a Python-identity guard from the return-to-stop primitive gives up
  a superficially convenient ownership check. The alternative was invalid:
  real SWIG wrappers are not identity-stable. The backend instead accepts only
  an explicit return with either no edge or the exact canonical stop edge, and
  the lifecycle caller supplies both blocks from one live MBA.

## Final verification

- Official system suite: 3,538 passed, 59 skipped, 9 deselected, 1 expected
  xfail.
- Isolated unit suite with LLVM 19: 7,645 passed, 32 skipped.
- Semantic fragment backend: 133 passed.
- Required architecture gates: ast-grep clean; import-linter 14 contracts kept,
  0 broken.
