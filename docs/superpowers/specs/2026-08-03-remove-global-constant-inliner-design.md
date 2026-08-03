# Remove GlobalConstantInliner Design

## Goal

Delete `GlobalConstantInliner` and its legacy pass identity without losing the
useful behavior that was unique to the flow rule. `constant-simplification`
remains the sole public constant operation, and `FoldReadonlyDataRule` remains
the sole live memory-read materializer.

## Decision Authority

Pointer-like value rejection belongs in the shared global-constness decision,
not in a particular optimizer. The portable evidence model gains a
`value_is_pointer_like` fact and the stable rejection reason
`pointer_like_value`. The Hex-Rays evidence adapter computes the fact using
IDA address-space evidence:

- values narrower than four bytes are never treated as pointers;
- zero remains an ordinary constant;
- an all-ones `BADADDR` sentinel is pointer-like;
- a value that lands in a mapped segment is pointer-like;
- a small value whose image-base rebasing lands in a mapped segment is
  pointer-like; and
- the existing common 64-bit ASLR-range checks remain conservative fallbacks.

This keeps platform and file-format knowledge out of the portable oracle. The
backend reports one boolean fact; the oracle applies it uniformly to every
otherwise-inlineable read. Pointer rejection never converts an unsafe memory
source into a safe one and never authorizes persistent `const`.

## Shape and Maturity Coverage

`FoldReadonlyDataRule` already runs at the old rule's PREOPTIMIZED and LOCOPT
maturities, plus later safe maturities. It already handles direct `mov`
globals, table-displacement loads, and nested source expressions.

The missing direct flow shape is an `m_ldx` whose address operand `ins.r` is a
`mop_v`. The peephole resolver will recognize that shape as a memory read and
replace the whole load with an immediate move after the shared decision
accepts it. It must not replace the address operand in place and leave the
`ldx` intact.

The old flow rule recursively visited destinations. That behavior is not
ported: destinations are writes, not r-value reads, and treating them as
constant sources is unsound. Source operands retain bounded recursive folding,
and call targets retain their existing protection.

## Removal Boundary

Delete the implementation module, flow registration/import, legacy pass ID,
pipeline conflict branch, shipped legacy rule entries, and class-specific
tests. Convert useful pointer/RVA and decompilation coverage to the shared
adapter or `FoldReadonlyDataRule`. Generic sample fixtures and function names
may remain, but comments must describe **Simplify constants**, not the deleted
class.

No compatibility alias or deserialization path remains for
`global-constant-inliner`; the user explicitly chose removal over legacy
support.

## Verification

Verification covers portable decision tests, real-IDA evidence and folding
tests, pass/config/catalog tests, the broader unit suite, real-IDA runtime
selectors, ast-grep, import-linter, and a graphify refresh. A repository search
must find no active `GlobalConstantInliner`, `global-constant-inliner`, or
`global_const_inline` implementation references.
