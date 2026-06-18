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

M3a lower-back contract policy:

- `d810.backends.llvm.lower_back_contract` is an IDA-free risk-reduction
  prototype for the future LLVM->microcode drop boundary.
- It models the contract records a production dropper will need: functions,
  blocks, terminators, PHI nodes, edge moves, unsupported diagnostics, and a
  lower-back planning result.
- The only positive lowering in M3a is scalar PHI destructuring for a tiny
  hand-authored diamond CFG. A PHI such as
  `%x = phi i32 [ %a, %then ], [ %b, %else ]` plans edge moves
  `then -> merge: x = a` and `else -> merge: x = b`, preserving predecessor
  labels and incoming order.
- The planner fails closed for critical-edge splits, non-scalar PHIs, unknown
  block targets, unsupported call/memory instructions, and unsupported control
  such as `indirectbr`, `invoke`, or landingpad-style terminators.
- This is not the M3 production body emitter. It does not consume M1/M2
  optimized output, parse arbitrary LLVM modules, import IDAvator, mutate
  Hex-Rays microcode, or claim decompile/oracle parity. Production M3 remains
  responsible for the real lower-back interface, Hex-Rays CFG/body emission,
  and zero-INTERR oracle gate.

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
