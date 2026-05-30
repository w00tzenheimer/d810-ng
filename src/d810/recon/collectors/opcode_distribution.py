"""Migration shim: ``d810.recon.collectors.opcode_distribution`` -> ``d810.analyses.control_flow.opcode_distribution`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import opcode_distribution as _canonical

sys.modules[__name__] = _canonical
