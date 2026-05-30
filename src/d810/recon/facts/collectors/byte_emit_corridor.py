"""Migration shim: ``d810.recon.facts.collectors.byte_emit_corridor`` -> ``d810.analyses.value_flow.byte_emit_corridor`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import byte_emit_corridor as _canonical

sys.modules[__name__] = _canonical
