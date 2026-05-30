"""Migration shim: ``d810.cfg.transform.simplify_identical_branch`` -> ``d810.transforms.simplify_identical_branch`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("d810.transforms.simplify_identical_branch")
