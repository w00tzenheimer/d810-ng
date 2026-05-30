"""Migration shim: ``d810.recon.facts.collectors.loop_carrier`` -> ``d810.analyses.value_flow.loop_carrier`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import loop_carrier as _canonical

sys.modules[__name__] = _canonical
