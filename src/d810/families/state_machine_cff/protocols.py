"""Back-compat re-export of state-machine CFF runtime Protocols.

The canonical home for these pure INTERFACE Protocols is now
``d810.capabilities.unflattening_strategy`` -- the lowest legal layer for
interfaces, so both this ``d810.families`` mid-layer and the
``d810.optimizers...engine`` high layer can import them DOWNWARD.  This
module keeps the symbols importable from the old path for back-compat.
New code should import from ``d810.capabilities.unflattening_strategy``.
"""
from __future__ import annotations

from d810.capabilities.unflattening_strategy import (
    StateMachineFamilyRuntimeServices,
    UnflatteningStrategy,
)

__all__ = ["StateMachineFamilyRuntimeServices", "UnflatteningStrategy"]
