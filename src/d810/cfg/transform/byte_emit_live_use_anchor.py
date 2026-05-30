"""Migration shim: ``d810.cfg.transform.byte_emit_live_use_anchor`` -> ``d810.transforms.byte_emit_live_use_anchor`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import importlib
import sys

sys.modules[__name__] = importlib.import_module("d810.transforms.byte_emit_live_use_anchor")
