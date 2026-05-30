"""Migration shim: ``d810.cfg.observability`` -> ``d810.core.observability_cfg`` (dissolution, llr-lyly).

sys.modules alias for the CFG observability / event API: the event
dataclasses, ``observe_cfg_provenance`` / ``observe_cfg_provenance_latest``,
``observe_watch_block_transition`` and ``diagnostics_enabled``.  Deleted in
Phase Z once consumers repoint to :mod:`d810.core.observability_cfg`.

Surface note: the producer-side provenance buffer helpers
(``drain_pending_provenance`` / ``reset_pending_provenance``) are
intentionally NOT carried by this shim.  They are producer state, not an
observability concern; their canonical home is :mod:`d810.ir.provenance`
-- import them directly from there.
"""
import sys

from d810.core import observability_cfg as _canonical

sys.modules[__name__] = _canonical
