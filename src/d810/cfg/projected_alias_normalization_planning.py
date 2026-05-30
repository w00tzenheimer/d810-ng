"""Migration shim: ``d810.cfg.projected_alias_normalization_planning`` -> ``d810.transforms.projected_alias_normalization_planning`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("d810.transforms.projected_alias_normalization_planning")
