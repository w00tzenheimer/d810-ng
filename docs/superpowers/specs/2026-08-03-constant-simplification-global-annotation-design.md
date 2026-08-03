# Constant Simplification Global Annotation Design

## Goal

Make `constant-simplification` handle dynamic indexed global tables as well as
concrete global reads. A read such as `LOOKUP_TABLE[runtime_index]` cannot be
replaced with one immediate while the index is unknown, but the complete table
can still receive a persistent `const` qualifier when the IDB proves the item
is non-writable data with no write evidence.

This is an internal stage of the existing public operation. It does not add a
new rule, pass, or user-facing choice.

## Architecture

The portable constness layer answers two independent questions:

1. whether a concrete read can become an immediate; and
2. whether a complete canonical data item can receive persistent `const`.

The second question uses item-level evidence and therefore does not require a
concrete element address, a 1/2/4/8-byte read width, a decoded value, or the
pointer-value filter used by immediate materialization. It accepts only a
readable, non-writable IDA data item with no direct write xref anywhere in its
half-open item range. Writable items, code, tails, unresolved bytes, missing
segments, and contradictory write evidence abstain.

The Hex-Rays backend uses two complementary evidence sources. Defined data
items come from function data xrefs and are canonicalized to their existing IDA
item heads. Undefined dynamic tables come from an architecture-neutral
microcode footprint such as `base + 4 * (index & 7)`: the offset interval and
load width prove a 32-byte range and an eight-element unsigned array even when
IDA currently models only one unknown byte at `base`.

The private `FoldReadonlyDataRule` invokes this backend only when config-v2's
public `constant-simplification` bundle supplies its internal persistence flag.
It scans defined references once at `MMAT_CALLS` and inspects each `ldx` for a
bounded dynamic footprint. Type changes are immediately visible in the IDB;
the current runtime-indexed expression remains dynamic, and later
decompilations consume the persisted annotation. No Hex-Rays redo or new
public pass is required.

## Platform Independence

Policy must not inspect operating systems, binary formats, processor families,
or conventional segment names. It consumes only IDA item kind, canonical item
bounds, segment permissions, and xrefs. A data item in readable, non-writable
executable memory is eligible because it is a data item, on macOS, Linux,
Windows, or any other supported target.

`allow_executable_readonly` remains the explicitly dangerous escape hatch for
ephemeral read inlining only. It never authorizes persistent typing of code or
unresolved executable bytes.

## Persistent Mutation Safety

D810 stores an IDB-local, versioned ownership receipt for every `const`
qualifier it applies. The receipt records the canonical item head and the
original and applied type renderings.

- An already-const item without a receipt is user-owned and is left alone.
- If a D810-owned item later acquires write evidence and its current type still
  matches the applied receipt, D810 removes only the top-level `const` and
  deletes the receipt.
- If the current type differs from the receipt, D810 treats it as a later user
  edit and neither rewrites nor removes it.
- A written const item without a D810 receipt is reported but never modified.
- Failed type reads, failed applications, and receipt errors abstain and never
  gate decompilation.

This is deliberately safer than `const_globals.py`, whose `fix_written=True`
mode can remove any const qualifier regardless of ownership.

## Runtime Activation

The public pass expansion supplies the internal
`persist_global_const_annotations=true` setting to its memory rule. The same
private rule defaults the setting to false, so legacy/direct configurations do
not activate global annotation.

The annotation stage ignores `memory_policy=aggressive_no_direct_writes`
because writable-memory heuristics never prove whole-item immutability. It also
ignores `allow_executable_readonly` for persistent typing. Those options retain
their existing meanings for per-read materialization.

## Diagnostics

Each annotation run returns a typed report with one outcome per canonical item
and aggregate changed/applied/removed counts. Logging records exact half-open
item ranges, element counts, and stable reasons. Failures are diagnostic only
and never gate the existing peephole rewrite.

## Verification

Verification must prove:

- item-level policy is independent of read width and pointer-like values;
- R+X data is eligible while R+X code remains ineligible;
- writable and directly-written items are ineligible in every memory policy;
- dynamic indexed table references prove the complete bounded table range;
- applying `const` changes the IDB exactly once and a second run is idempotent;
- D810-owned stale const is removed while user-owned or user-edited const is
  preserved;
- the dangerous executable override never persists const;
- existing concrete-read simplification still passes; and
- the supported Docker system-test runner shows the lookup table type before
  and after activation.
