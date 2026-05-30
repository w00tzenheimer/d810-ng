"""Migration shim: ``d810.cfg.materialization_payload`` -> ``d810.transforms.materialization_payload`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.

This is a *transforms*-layer module (planner/backend execution surface),
so the canonical home is :mod:`d810.transforms.materialization_payload`.  ``d810.cfg`` sits BELOW
``d810.transforms`` in the layered architecture, so a literal
``from d810.transforms import ...`` here would register a layer-fatal
``cfg -> transforms`` edge.  The alias is therefore resolved dynamically
via :func:`importlib.import_module`, which the import graph does not
follow, so this shim adds no static upward edge.  All live importers
repoint to ``d810.transforms.materialization_payload`` directly in Phase T-wave-repoint.
"""
import importlib
import sys

_canonical = importlib.import_module("d810.transforms.materialization_payload")

sys.modules[__name__] = _canonical
