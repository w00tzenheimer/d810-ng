"""Migration shim: ``d810.recon.flow.analysis_stats`` -> ``d810.analyses.control_flow.analysis_stats`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import analysis_stats as _canonical

sys.modules[__name__] = _canonical
