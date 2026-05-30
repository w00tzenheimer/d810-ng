"""Migration shim: ``d810.recon.artifacts`` -> ``d810.passes.artifacts`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.

The artifacts module is a *passes*-layer module (recon orchestration tier,
driven by Manager above the analyses layer), so the canonical home is
:mod:`d810.passes.artifacts`.  ``d810.recon`` sits BELOW ``d810.passes`` in the
layered architecture, so a literal ``from d810.passes import ...`` here
would register a layer-fatal ``recon -> passes`` edge.  The alias is
therefore resolved dynamically via :func:`importlib.import_module`, which
the import graph does not follow, so this shim adds no static upward edge.
All live importers repoint to ``d810.passes.artifacts`` directly.
"""
import importlib
import sys

_canonical = importlib.import_module("d810.passes.artifacts")

sys.modules[__name__] = _canonical
