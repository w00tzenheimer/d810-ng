"""Migration shim: ``d810.cfg.terminal_tail_dce_diagnosis`` -> ``d810.transforms.terminal_tail_dce_diagnosis`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("d810.transforms.terminal_tail_dce_diagnosis")
