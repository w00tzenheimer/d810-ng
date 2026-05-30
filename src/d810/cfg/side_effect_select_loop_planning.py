"""Migration shim: ``d810.cfg.side_effect_select_loop_planning`` -> ``d810.transforms.side_effect_select_loop_planning`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("d810.transforms.side_effect_select_loop_planning")
