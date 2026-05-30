"""Migration shim: ``d810.cfg.contracts.transaction_policy`` -> ``d810.passes.transaction_policy`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("d810.passes.transaction_policy")
