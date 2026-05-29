"""Back-compat shim. Canonical home: ``d810.analyses.control_flow.interval_map``.

Relocated in the LS6 bst-cluster split (Landing Sequence step 6 / ticket
d81-1w16).  This shim re-exports the public surface so existing
``d810.recon.flow.interval_map`` importers keep working until they are
repointed to the canonical path (LS6 S8/S9).  Do not add new code here.
"""
from __future__ import annotations

from d810.analyses.control_flow.interval_map import *  # noqa: F401,F403
from d810.analyses.control_flow.interval_map import __all__  # noqa: F401
