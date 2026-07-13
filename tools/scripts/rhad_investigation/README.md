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

The July 2026 result is a useful negative boundary. Explicit MBA outline
ranges plus native call EAs allow destination-side CALLS analysis to succeed;
fictitious call EAs fail with `call analysis failed`. However, importing the
route frontier (9 templates) or all prepared primary templates (64 templates)
still leaves 54 unresolved transitions and one infinite dispatcher loop. The
known-good LOCOPT/CALLS importer remains the production path.
