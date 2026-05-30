"""Migration shim: ``d810.recon.flow.switch_table_analysis`` -> ``d810.analyses.control_flow.switch_table_analysis`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.analyses.control_flow import switch_table_analysis as _canonical

sys.modules[__name__] = _canonical
