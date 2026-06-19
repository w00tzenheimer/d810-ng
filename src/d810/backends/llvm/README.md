# LLVM M1 Portable-IR Emitter

This package is the first `llr-k39s` front-lift scaffold. It emits textual LLVM
IR from portable `d810.ir.FlowGraph` snapshots after d810 structural recovery,
using canonical `Instruction` and `Varnode` records. It does not consume live
Hex-Rays objects, `InsnSnapshot` raw opcodes, or IDAvator APIs.

M1 deliberately follows IDAvator's supported-subset discipline: classify the
whole function first, record precise unsupported reasons, and emit no misleading
partial LLVM when any required instruction or terminator is unsupported.

Verification policy:

- `d810.backends.llvm.verification` provides the structured verification API for
  `opt -S -passes=verify`.
- The verifier looks for `LLVM_OPT`, Homebrew LLVM's `opt`, then `PATH`, and
  returns `passed`, `skipped`, or `failed` with the command, stdout/stderr, and
  reason.
- Live Docker evidence may report `skipped` only when no `opt` binary is
  available. If `opt` is available, verifier failure is a hard test failure.
- System Docker runs can make verifier execution mandatory with:
  `./tools/scripts/run_system_tests_docker.sh system -w llvm-lisa-restructure -l -o logs/llvm-m1o-opt-required-live-lift.log --enable-llvm-opt -- -k TestLLVMM1LiveLiftProbe -s`.
  The wrapper provisions LLVM `opt`, exports `LLVM_OPT`, and sets
  `D810_REQUIRE_LLVM_OPT=1`; with that environment, a skipped verifier result
  is a test failure.
- This is only the front-lift verification gate. It is not M3 Hex-Rays
  lower-back or optimized-LLVM parity over a dropped body.

Identity parity policy:

- Successful lifts carry a portable identity manifest emitted from the same
  accepted instruction map and varnode allocation list that produced the LLVM
  text.
- `d810.backends.llvm.identity_lowering` compares the source `FlowGraph`
  signature against that manifest and returns `passed`, `failed`, or
  `unsupported` with structured mismatch rows.
- This is an M1 identity-lower scaffold for the supported subset. It does not
  parse arbitrary LLVM IR, does not lower optimized LLVM back into Hex-Rays
  microcode, and is not the M3 body-emitter/drop interface.

M2a stock optimization policy:

- `d810.backends.llvm.optimization` provides an IDA-free stock `opt` pipeline
  runner with structured `passed`, `skipped`, and `failed` results.
- `LLVM_M2A_STOCK_PIPELINE` is the first measured-collapse pipeline:
  `instcombine,reassociate,sccp,simplifycfg,adce`. It is intentionally the
  small M0-proven subset, not `-O3` and not the final full M2 curated pipeline.
- The runner records coarse before/after IR metrics and keeps temporary
  filenames fixed inside the supplied temp directory.
- M2a proves that supported lifted IR can pass through the LLVM middle and
  remain verifier-clean. It does not prove decompiler/oracle equivalence of
  optimized LLVM; that remains the M3 lower-back/parity boundary.
- Future M2 work can expand toward the full curated list (`mem2reg`, `sroa`,
  `ipsccp`, `gvn`/`newgvn`, `cvp`, `early-cse`, `dse`,
  `aggressive-instcombine`, and constrained `simplifycfg`) and then add the
  d810 MBA/Z3 Souper-role passes.

M2b d810 MBA/Z3 custom pass socket:

- `d810.backends.llvm.custom_passes` is the first IDA-free socket for sequencing
  d810-verified MBA rewrites around the stock `opt` runner.
- The socket is intentionally Python-side textual/DTO infrastructure, not a
  compiled LLVM plugin and not a runtime project-config cutover.
- The first pass is `d810_mba_xor_or_sub_and`, backed by the existing
  `Xor_HackersDelightRule_1` identity from d810's MBA rule surface:
  `(x | y) - (x & y) => x ^ y`.
- Before rewriting, the pass proves the identity for the concrete scalar integer
  width through `d810.backends.mba.z3.prove_equivalence()` over the pure
  `d810.mba.dsl` expression tree. If the proof is unavailable or fails, the pass
  returns structured failure diagnostics and leaves the IR unchanged.
- The supported LLVM text shape is deliberately constrained to same-width scalar
  SSA instructions:
  `%or = or iN %x, %y`; `%and = and iN %x, %y`; `%out = sub iN %or, %and`.
  Constants, vector/pointer types, width mismatches, operand-order mismatches,
  missing producers, and unsupported custom pass IDs fail closed or produce
  explicit no-change results.
- This socket proves the d810 MBA/Z3 layer can be sequenced with M2a stock `opt`.
  Full M2 remains open for the broader curated pipeline, stronger MBA/Z3
  predicate folding, measured live collapse coverage, and oracle drift gates.

M2c opt-in custom+stock pipeline policy:

- `d810.backends.llvm.m2_pipeline` composes the M2b custom pre-pass, the M2a
  stock `opt` pipeline, and optimized-IR verification into one explicit
  opt-in runner.
- The runner records phase-by-phase DTOs for `custom_pre`, `stock_opt`, and
  `verify_optimized`, including before/after IR, coarse metrics, custom rewrite
  counts, stock `opt` results, and verifier results.
- Failure is structured and stops at the responsible phase: custom pass failure
  does not run stock `opt`; stock `opt` failure does not run verifier; missing
  `opt` remains a structured skip unless the caller or environment requires it.
- This does not change `run_llvm_opt_pipeline()` defaults and is not a runtime
  project-config cutover. It is also not a compiled LLVM plugin, M3 lower-back,
  or oracle parity proof.
- Full M2 remains open for a broader curated pipeline, additional d810 MBA/Z3
  predicate folding, larger live measured-collapse coverage, and native oracle
  drift gates.

M2d live coverage/collapse census:

- `d810.backends.llvm.m2_census` provides IDA-free row and summary DTOs for
  reporting live M2 pipeline coverage without importing Hex-Rays.
- The system census runs the opt-in M2c pipeline at the preferred
  `GLOBAL_ANALYZED` maturity over curated `restructuring_lab.dll` rows, with
  Docker-provisioned `opt` required.
- Rows distinguish missing functions, unsupported lifts, skipped/failed
  pipeline phases, verifier status, custom rewrite count, and before/after
  coarse LLVM metrics.
- The census is evidence for LLVM-level lift -> custom/stock opt -> verify
  coverage and measured collapse. It is not native decompile/oracle equivalence,
  does not consume M3 lower-back output, and does not close full M2.

M2e oracle/drift scaffold:

- `d810.backends.llvm.m2_oracle` adds IDA-free DTOs for M2 oracle/drift
  results with explicit `passed`, `failed`, `skipped`, `not_applicable`, and
  `unavailable` statuses.
- The first concrete oracle is fixture-level only: checked-in M0 optimized LLVM
  text can be compared against a normalized optimized-function signature for
  the corresponding expected fixture. This proves drift against that LLVM
  artifact, not native pseudocode parity.
- `d810.backends.llvm.m2_census` carries oracle status, oracle ID, oracle
  reason, and an oracle-status histogram alongside pipeline/collapse metrics.
  Live restructuring-lab census rows deliberately report `not_applicable` until
  a real row-level M2 oracle exists.
- This does not lower optimized LLVM into Hex-Rays microcode, mutate the
  decompiler graph, use IDAvator, start M4/config cutover, or satisfy the
  native decompile/oracle gate. Production native parity remains an M3/M4
  boundary.

M3a lower-back contract policy:

- `d810.backends.llvm.lower_back_contract` is an IDA-free risk-reduction
  prototype for the future LLVM->microcode drop boundary.
- It models the contract records a production dropper will need: functions,
  blocks, terminators, PHI nodes, edge moves, unsupported diagnostics, and a
  lower-back planning result.
- The first positive lowering is scalar PHI destructuring for tiny hand-authored
  CFGs. A PHI such as
  `%x = phi i32 [ %a, %then ], [ %b, %else ]` plans edge moves
  `then -> merge: x = a` and `else -> merge: x = b`, preserving predecessor
  labels and incoming order.
- M3b extends the contract with deterministic critical-edge bridge planning.
  When a PHI copy belongs to a critical predecessor->successor edge, the plan
  records an inserted bridge block and an edge rewrite, then places the
  parallel-copy group in that bridge. Bridge labels are stable
  `m3_split__<pred>__<succ>` strings when unique; existing-block collisions or
  sanitized generated-label collisions fail closed with `bridge_label_conflict`.
- Multiple PHIs targeting the same edge produce an ordered parallel-copy group.
  The planner preserves PHI order within each edge group and fails closed with
  `parallel_copy_conflict` if source/target overlap would require a temp or
  cycle-breaking plan that this DTO prototype does not yet model.
- The planner also fails closed for non-scalar PHIs, inconsistent predecessor
  edges, unknown block targets, unsupported call/memory instructions, and
  unsupported control such as `indirectbr`, `invoke`, or landingpad-style
  terminators.
- This is not the M3 production body emitter. It does not consume M1/M2
  optimized output, parse arbitrary LLVM modules, import IDAvator, mutate
  Hex-Rays microcode, or claim decompile/oracle parity. Production M3 remains
  responsible for the real lower-back interface, Hex-Rays CFG/body emission,
  and zero-INTERR oracle gate.

M3c optimized-LLVM readiness policy:

- `d810.backends.llvm.lower_back_readiness` is the first bridge from M2
  optimized LLVM text into the M3 lower-back contract model.
- It is still IDA-free and deliberately not a general LLVM parser. It accepts
  one constrained textual function, block labels, unconditional/conditional
  branches, scalar returns, scalar PHIs, and a small explicitly enumerated
  scalar body-instruction subset.
- The readiness API parses into `LlvmLowerBackFunction`, calls
  `plan_lower_back()`, and keeps parse diagnostics separate from lower-back plan
  diagnostics. Malformed or unsupported input never becomes a fake planned
  result.
- `plan_lower_back()` also rejects unknown body opcodes directly with
  `unsupported_instruction`, so future producers cannot bypass the readiness
  parser and overclaim lower-back support.
- M3c consumes M2 output for classification only. It does not mutate Hex-Rays
  microcode, does not use IDAvator, does not integrate a deferred graph
  modifier, and does not prove native oracle/decompile parity.

Current freeze-maturity policy:

- The target capture point is optimized/recovered microcode after d810 structural
  recovery, not raw `MMAT_ZERO`.
- The candidate range is defined by the IDA-free policy API in
  `d810.backends.llvm.maturity_policy`: `CALL_MODELED`, `GLOBAL_ANALYZED`, and
  `GLOBAL_OPTIMIZED`.
- The provisional preferred freeze point is `GLOBAL_ANALYZED` because it has
  global dataflow while preserving more predicate/value residue than later
  simplification. Hex-Rays maps this to `MMAT_GLBOPT1`, but the policy consumes
  only portable `FlowGraph.metadata["ir_maturity"]`.
- The decision criteria are to preserve enough predicate/value residue for LLVM
  while avoiding pre-recovery CFG noise.
- This package is the LLVM front-lift route only. M3 lower-back should expose a
  separate narrow drop interface with clear diagnostics and a decompile/oracle
  gate, borrowing IDAvator's `LLVMDropConverter.drop()` / `hxe_preoptimized`
  discipline where useful without adding an IDAvator dependency here.

Current supported subset:

- integer constants and register/stack/global/lvar/temp varnodes with 1/2/4/8
  byte scalar widths,
- one `alloca` per distinct non-const varnode,
- `MOVE`, `ADD`, `SUB`, `MUL`, `OR`, `AND`, `XOR`, `NEG`,
  width-increasing `ZEXT`, `SIGN_BIT`, `OVERFLOW_ADD`, and `OVERFLOW_FLAG`,
- materialized canonical `PredicateKind` comparisons as `icmp` plus zero-extend
  into the result varnode,
- one-way block edges as `br label`,
- conditional branches from `Instruction.control.transfer` plus `PredicateKind`,
  using `succs[0]` as true and `succs[1]` as false for the current M1 policy,
- table branches from `Instruction.control.switch_cases` as LLVM `switch` when
  the portable selector, case rows, default row, and successor targets are
  complete and case constants are unique after selector-width canonicalization,
- direct/indirect/intrinsic `CallKind` operations as opaque external calls when
  the canonical call effect and portable call target are present; no purity or
  memory attributes are attached, so LLVM must treat them as side-effecting,
- direct-cell `LOAD` / `STORE` operations only when
  `Instruction.memory.kind == DIRECT_CELL`; each concrete storage cell maps to
  its own distinct alloca, and target/value/access widths must match,
- `RETURN` with an `i32` return varnode, or fixed `ret i32 0` when no return
  value is available.

Unsupported in the current M1 subset: segmented/pointer/unknown memory accesses,
volatile/atomic/precise alias semantics, incomplete call payloads, incomplete
table/switch payloads, indirect branches, carry/borrow and flags beyond the
explicit sign/overflow ops above, truthy predicate materialization, non-scalar
widths, casts other than width-increasing `ZEXT`, and any operation that would
require raw opcode provenance to infer behavior.
