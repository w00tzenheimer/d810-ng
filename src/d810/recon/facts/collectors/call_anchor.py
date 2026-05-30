"""Migration shim: ``d810.recon.facts.collectors.call_anchor`` -> ``d810.analyses.value_flow.call_anchor`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.value_flow import call_anchor as _canonical

sys.modules[__name__] = _canonical
