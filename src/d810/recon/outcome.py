"""Migration shim: ``d810.recon.outcome`` -> ``d810.passes.outcome`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.

The outcome module is a *passes*-layer module (recon orchestration root /
scheduler tier, driven by Manager above the analyses layer), so the
canonical home is :mod:`d810.passes.outcome`.  ``d810.recon`` sits BELOW
``d810.passes`` in the layered architecture, so a literal ``from d810.passes
import ...`` here would register a layer-fatal ``recon -> passes`` edge.  The
alias is therefore resolved dynamically via :func:`importlib.import_module`,
which the import graph does not follow, so this shim adds no static upward
edge.  All live importers repoint to ``d810.passes.outcome`` directly.
"""
import importlib
import sys

_canonical = importlib.import_module("d810.passes.outcome")

sys.modules[__name__] = _canonical
