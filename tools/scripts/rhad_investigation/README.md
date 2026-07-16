# Rhadamanthys loader investigations

These scripts preserve focused, sample-specific Hex-Rays experiments used while
generalizing d810's computed-goto and detached-handler support. They are not
production recognizers. Hard-coded EAs belong only to this investigation
fixture; production code must remain address- and sample-agnostic.

The scripts expect a disposable copy of the loader under `.tmp/`. Never point
an idalib experiment at the canonical fixture when testing byte materialization.
Always close idalib databases with `close_database(False)`.

## Maturity visibility

`probe_maturity_allblks.py` materializes the computed-goto dispatcher, then
compares normal, `DECOMP_ALL_BLKS`, and explicit-range generation at
`MMAT_GENERATED`, `MMAT_PREOPTIMIZED`, `MMAT_LOCOPT`, and `MMAT_CALLS`.

```bash
cp samples/bins/rhad_loader_unpacked.bin .tmp/rhad_maturity_probe.bin
tools/scripts/run_system_tests_docker.sh exec -- \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_maturity_allblks.py
```

## Flowchart range injection

`probe_flowchart_append.py` inspects whether the proven native handler range is
already present in the `hxe_flowchart` graph. Set `RHAD_FLOWCHART_MODE=append`
to reproduce the experimental `qflow_chart_t.append_to_flowchart()` injection.

```bash
cp samples/bins/rhad_loader_unpacked.bin .tmp/rhad_flowchart_append_probe.bin
tools/scripts/run_system_tests_docker.sh exec -- \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_flowchart_append.py

RHAD_FLOWCHART_MODE=append \
tools/scripts/run_system_tests_docker.sh exec -- \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_flowchart_append.py
```

The `.tmp/probe_*.py` entries may be symlinks for command-history convenience;
the tracked copies in this directory are authoritative.

## PREOPT detached-range import

`probe_preopt_snippet_import.py` tests whether explicit detached ranges can be
generated at `MMAT_PREOPTIMIZED`, imported into the live top-level MBA from
`hxe_preoptimized`, connected only through resolver-proven routes, and then
left to Hex-Rays for LOCOPT and CALLS analysis.

```bash
cp samples/bins/rhad_loader_unpacked.bin .tmp/rhad_preopt_probe.bin
tools/scripts/run_system_tests_docker.sh exec -- \
  env RHAD_PREOPT_BIN=/work/.tmp/rhad_preopt_probe.bin \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_preopt_snippet_import.py
```

Set `RHAD_PREOPT_IMPORT_ALL=1` to import every prepared PREOPT primary template
instead of only the route-planned frontier. Set `D810_DIAG_SNAPSHOT=1` and
`RHAD_PREOPT_DIAG_OUTPUT=/work/.tmp/rhad_preopt.diag.sqlite3` to copy the
closed diagnostic database out of the ephemeral Docker container.

The first July 2026 result established a useful negative boundary. Explicit
MBA outline ranges plus native call EAs allow destination-side CALLS analysis
to succeed; fictitious call EAs fail with `call analysis failed`. A later
experiment replaced per-target fragments with one conservative native-CFG
closure:
38 native blocks, 16 merged ranges, 40 internal edges, one 63-block PREOPT
template, and one import. It preserves shared blocks and the previously
missing native edge `0x40BB3D -> 0x40C6DA`.

The fair control-manifest replay is still worse than the current path. Replay
waits for the same local CALLS-capture timing token in both runs: callback 1
replays zero rows, callback 2 imports the union and replays zero rows, and
callback 3 offers the same 81-row control manifest. The connected union accepts
38 direct and 3 conditional boundaries and abstains on 44 planned candidates:
4 conditional siblings, 2 conflicting direct blocks, 20 direct-shape
mismatches, 17 via-target mismatches, and 1 synthetic conditional-shape
mismatch. Final pseudocode is 566 lines / 89 rough calls / 4 `while (1)` loops,
versus 555 / 84 / 2 for the current control and 201 lines for the regenerated
reference.

That result falsified maturity-local control-manifest replay, not PREOPT union
import. The follow-up modeled resolver-transfer cut points as explicit boundary
ports owned by the closure. It captures direct and conditional ports before
the live graph changes, binds them to imported blocks through native-EA
provenance, and applies each port only when its imported topology still matches
the proof. Terminal-return ports additionally require a unique captured ABI
return carrier; the port and carrier are preflighted as one transaction and
both abstain when the carrier cannot be proved.

With native closure, all source blocks, source-built graph topology, and
boundary ports enabled, the resulting PREOPT import applies 75 ports with no
port abstentions. It restores the captured carrier from native `0x40C7EA` in
the imported terminal block anchored at `0x40C898`, then lets Hex-Rays perform
LOCOPT and CALLS analysis. After stack-point and call-result provenance repair,
the final `sub_40A560` pseudocode has 211 lines / 5,671 bytes, zero dispatcher
`while (1)` loops, no residual `HIBYTE` operators, six cleanup `free` calls,
the direct `sub_40F830() && MessageBoxW(...) == 7` guard, and the same terminal
`return &off_48B8A4` as the freshly regenerated neighboring-tool oracle. The
bad-SP warning is gone. The remaining raw-text differences are local naming,
calling-convention presentation, and equivalent cleanup expressions. The
known-good LOCOPT/CALLS importer remains the production path while this PREOPT
closure stays an investigation profile.

The successful profile is:

```bash
tools/scripts/run_system_tests_docker.sh exec -- \
  env RHAD_PREOPT_BIN=/work/.tmp/rhad_preopt_probe.bin \
      RHAD_PREOPT_UNION_CLOSURE=1 \
      RHAD_PREOPT_NATIVE_CLOSURE=1 \
      RHAD_PREOPT_BOUNDARY_PORTS=1 \
      RHAD_PREOPT_ALL_BLOCKS=1 \
      RHAD_PREOPT_SOURCE_BUILD_GRAPH=1 \
      RHAD_PREOPT_UNION_GENERATION_MODE=snippet \
      RHAD_PREOPT_MAX_ATTEMPTS=3 \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_preopt_snippet_import.py
```

## Imported-frontier provenance

`probe_imported_frontier.py` explains a lost transition by projecting every
live microcode instruction back to its native EA and, for imported code, to the
detached template that owns it. Register the probe after headless startup so a
d810 module reload cannot discard its hook. Its output always labels a
maturity-local block together with its stable anchor, for example
`blk411@0x40C659`.

```bash
cp samples/bins/rhad_loader_unpacked.bin .tmp/rhad_frontier_probe.bin
rm -f .tmp/rhad_frontier_probe.{id0,id1,id2,nam,til,i64}
tools/scripts/run_system_tests_docker.sh exec -l --enable-diag-snapshot -- \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_imported_frontier.py \
  /work/.tmp/rhad_frontier_probe.bin \
  --trace-ea 0x40C659 --depth 4 --rounds 2
```

This probe isolated a legacy LOCOPT ownership bug. Early-maturity boundary
capture correctly retains every exact native source for a state/target pair.
The later residual-route bridge must not activate every one of those sources,
because doing so can replace a still-live dispatcher frontier with an imported
clone. The portable producer therefore remains multi-source, while the legacy
bridge deterministically activates only the lowest-EA source for each
`(state, target)` pair. Unselected sources stay on the dispatcher and ordinary
state-machine lowering handles them. This distinction preserves both the
75-port PREOPT result and the ordinary LOCOPT/CALLS semantic parity test.

## Cross-function transferability

`probe_transfer_function.py` applies the ordinary public two-round workflow to
another protected function without manually marking it as an indirect
dispatcher, setting callee types, or calling resolver internals. It can also
decompile a binary patched by the neighboring static rewriter as a comparison
oracle.

```bash
tools/scripts/run_system_tests_docker.sh exec -- \
  env RHAD_TRANSFER_BIN=/work/.tmp/rhad_transferability/rhad_d810.bin \
      RHAD_TRANSFER_FUNC=0x40D200 \
      RHAD_TRANSFER_END=0x40F82F \
      RHAD_TRANSFER_OUTPUT=/work/.tmp/rhad_transferability/sub_40D200_d810.c \
      RHAD_TRANSFER_RESOLUTION_OUTPUT=/work/.tmp/rhad_transferability/sub_40D200.resolution.json \
      RHAD_TRANSFER_TRANSFERS_OUTPUT=/work/.tmp/rhad_transferability/sub_40D200.transfers.json \
      RHAD_TRANSFER_ORIGINS_OUTPUT=/work/.tmp/rhad_transferability/sub_40D200.origins.json \
      D810_DIAG_SNAPSHOT=1 \
      RHAD_TRANSFER_DIAG_OUTPUT=/work/.tmp/rhad_transferability/sub_40D200.diag.sqlite3 \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_transfer_function.py
```

Set `RHAD_TRANSFER_MODE=native` and point `RHAD_TRANSFER_BIN` at a disposable
copy produced by the reference rewriter to capture its Hex-Rays pseudocode.
Set `RHAD_TRANSFER_END` when fresh IDA analysis cannot infer the obfuscated
function boundary; the neighboring rewriter discovers the same boundary by
scanning through the function's terminal `ret`. When an existing IDA function
ends early, the probe extends it to this explicit exclusive end before the
first decompilation.

Set `RHAD_TRANSFER_RESOLUTION_OUTPUT` to persist the resolver's site-to-target
map, patch-plan anchors, and invariant native-register context for comparison
with the neighboring tool's linear scan.

Set `RHAD_TRANSFER_TRANSFERS_OUTPUT` to persist the live microcode transfer
evidence. For the second protected function, detached static replay proves the
two-arm terminal transfer at native `0x40DACE` to native targets `0x40D381`
and `0x40E5C0`. The production lowering consumes this as authorization for the
existing stack-carried selector; it still resolves both final handler blocks
from the state map and never installs the replay targets as guessed edges.

`probe_static_detached_replay.py` isolates that first-frontier native fixpoint.
It seeds a detached target with the resolver's exact target-entry register
context, records the first computed-jump frontier, and deliberately does not
follow the resolved targets into another handler.

```bash
cp samples/bins/rhad_loader_unpacked.bin .tmp/rhad_static_replay.bin
rm -f .tmp/rhad_static_replay.{id0,id1,id2,nam,til,i64}
tools/scripts/run_system_tests_docker.sh exec -- \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_static_detached_replay.py \
  /work/.tmp/rhad_static_replay.bin 0x40DABB \
  ecx=0x48BD94 edx=0x48BF50 ebx=0xD1978CAF \
  esi=0x48BDE4 edi=0x48BB98
```

These EAs are investigation-fixture anchors only. The production recognizer is
profile-scoped and address-agnostic: it requires an exact two-arm replay, one
unique live microcode block owning the replayed indirect-jump EA, and strict
pure paths from the folded stack selector to that endpoint. Imported clones,
incomplete polarity, ambiguous owners, calls, stores, and unknown effects all
cause abstention.

The current `sub_40D200` result is a semantic-coverage improvement, not a full
parity claim. It removes the false dispatcher loop and exposes substantially
more body code than the neighboring rewriter's function-range decompile, but
two frontiers still render as `JUMPOUT`:

- native `0x40F821` is the function's real return epilogue (`mov eax`, stack
  restore, pops, `ret 0x10`), which Hex-Rays has not reattached as a return;
- synthetic `0xF1C00088` maps through the import-origin registry to native
  `0x40DDC3`, a computed jump which is not yet lowered. The neighboring
  rewriter reconstructs that site as a native comparison with direct arms to
  `0x40F1C1` and `0x40ED9E`.

Accordingly, use this probe and its E2E as a transferability/coverage gate. A
future full-unflattening gate must eliminate or structurally justify both
frontiers instead of treating a lower `JUMPOUT` count as semantic equivalence.

Set `RHAD_TRANSFER_ORIGINS_OUTPUT` to persist the current imported-instruction
registry as `(synthetic EA, native EA)` pairs. This is the authoritative way to
interpret a ctree statement whose EA is in d810's fictitious `0xF1C...` range;
microcode block serials and synthetic EAs are not native ownership anchors.

## First-decompile INTERR 50735

`probe_interr_50735.py` audits every analyzed `m_call`/`m_icall` argument and
prints the native call EA, current block EA, argument index, operand size, and
formal type size when Hex-Rays' 50735 invariant would fail. `--bare` isolates
the static byte materializer from the d810 manager. The provider switches
separately disable transient stack-point and callinfo restoration.

```bash
cp samples/bins/rhad_loader_unpacked.bin .tmp/rhad_interr_50735.bin
rm -f .tmp/rhad_interr_50735.{id0,id1,id2,nam,til,i64}
tools/scripts/run_system_tests_docker.sh exec -- \
  /app/ida/.venv/bin/python \
  tools/scripts/rhad_investigation/probe_interr_50735.py \
  /work/.tmp/rhad_interr_50735.bin --bare --attempts 2
```

The historical failure was first-decompile-only: immediately after resolver
materialization, `decompile(0x40A560)` returned `None`, code `-1`, error EA
`0x40A560`, and `INTERR: 50735`; a later d810 decompile succeeded. SDK
`verify.cpp` defines 50735 precisely as an `mcallarg_t` operand size that does
not match `argument.type.get_size()`. Fresh disposable runs under the available
Hex-Rays 9.2 and 9.3 images now succeed on the first bare attempt with failure
code zero, including the original resolver commit under 9.3. Do not add a blind
retry: use this audit and d810's `MINSN_50735_CALL_ARGUMENT_SIZE_MISMATCH`
contract to identify the malformed call if it returns.
