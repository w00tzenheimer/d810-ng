"""Migration shim: ``d810.cfg.materialization_backend`` -> ``d810.transforms.materialization_backend`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("d810.transforms.materialization_backend")
