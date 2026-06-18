# LLVM M1 Portable-IR Emitter

This package is the first `llr-k39s` front-lift scaffold. It emits textual LLVM
IR from portable `d810.ir.FlowGraph` snapshots after d810 structural recovery,
using canonical `Instruction` and `Varnode` records. It does not consume live
Hex-Rays objects, `InsnSnapshot` raw opcodes, or IDAvator APIs.

M1 deliberately follows IDAvator's supported-subset discipline: classify the
whole function first, record precise unsupported reasons, and emit no misleading
partial LLVM when any required instruction or terminator is unsupported.

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
- `MOVE`, `ADD`, `SUB`, and `AND`,
- materialized canonical `PredicateKind` comparisons as `icmp` plus zero-extend
  into the result varnode,
- one-way block edges as `br label`,
- conditional branches from `Instruction.control.transfer` plus `PredicateKind`,
  using `succs[0]` as true and `succs[1]` as false for the current M1 policy,
- `RETURN` with an `i32` return varnode, or fixed `ret i32 0` when no return
  value is available.

Unsupported in the current M1 subset: calls, store/memory effects beyond scalar
varnode allocas, tables/switches, indirect branches, flags/overflow-specific
predicates, truthy predicate materialization, non-scalar widths, and any
operation that would require raw opcode provenance to infer behavior.
