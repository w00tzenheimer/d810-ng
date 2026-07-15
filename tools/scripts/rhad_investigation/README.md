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
LOCOPT and CALLS analysis. The final `sub_40A560` pseudocode has 213 lines,
zero dispatcher `while (1)` loops, the same ordered named-call inventory as a
freshly regenerated neighboring-tool oracle (apart from two `HIBYTE` ctree
operators), six cleanup `free` calls, and the same terminal
`return &off_48B8A4`. Both outputs pass the repository's semantic parity
predicate. The remaining raw-text differences are Hex-Rays stack/type
presentation artifacts (`__cdecl` and the bad-SP warning), not missing
control-flow behavior. The known-good LOCOPT/CALLS importer remains the
production path while this PREOPT closure stays an investigation profile.

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
