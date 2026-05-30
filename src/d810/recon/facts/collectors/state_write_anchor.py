"""Migration shim: ``d810.recon.facts.collectors.state_write_anchor`` -> ``d810.analyses.value_flow.state_write_anchor`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import state_write_anchor as _canonical

sys.modules[__name__] = _canonical
