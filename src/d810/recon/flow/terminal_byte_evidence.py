"""Migration shim: ``d810.recon.flow.terminal_byte_evidence`` -> ``d810.analyses.control_flow.terminal_byte_evidence`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import terminal_byte_evidence as _canonical

sys.modules[__name__] = _canonical
