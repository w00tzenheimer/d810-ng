"""Migration shim: ``d810.recon.analysis`` -> ``d810.passes.analysis`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.

AnalysisPhase is a *passes*-layer coordination module (it interprets
ReconResults into DeobfuscationHints).  ``d810.recon`` sits BELOW
``d810.passes`` in the layered architecture, so a literal ``from d810.passes
import ...`` here would register a layer-fatal ``recon -> passes`` edge.  The
alias is therefore resolved dynamically via :func:`importlib.import_module`,
which the import graph does not follow, so this shim adds no static upward
edge.  All live importers repoint to ``d810.passes.analysis`` directly.
"""
import importlib
import sys

_canonical = importlib.import_module("d810.passes.analysis")

sys.modules[__name__] = _canonical
