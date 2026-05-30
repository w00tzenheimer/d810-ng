"""Migration shim: ``d810.recon.flow.reconstruction_diagnostics`` -> ``d810.transforms.reconstruction_diagnostics`` (dissolution, llr-lyly).

sys.modules alias preserving the old import path; re-exports public AND
private symbols.  Deleted in Phase Z once consumers repoint.
"""
import sys

from d810.transforms import reconstruction_diagnostics as _canonical

sys.modules[__name__] = _canonical
