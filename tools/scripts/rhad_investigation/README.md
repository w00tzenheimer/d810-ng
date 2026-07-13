# Rhadamanthys loader investigations

These scripts preserve focused, sample-specific Hex-Rays experiments used while
generalizing d810's computed-goto and detached-handler support. They are not
production recognizers. Hard-coded EAs belong only to this investigation
fixture; production code must remain address- and sample-agnostic.

Both scripts expect a disposable copy of the loader under `.tmp/`. Never point
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
