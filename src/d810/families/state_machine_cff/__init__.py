"""State-machine CFF family contracts + §1a profile discovery.

Importing this package eagerly imports every §1a profile module (``hodur``, ``approov``,
``tigress``) so each :class:`StateMachineCffFamily` subclass auto-registers via
``Registrant`` — this is the "scanner loads the project" auto-config.
``families.registry.select_family`` then enumerates them in REGISTRATION order
(``hodur``, ``approov``, ``tigress``) and returns the first match; ``ApproovFamily`` is
polled before ``TigressFamily`` so it keeps the switch-table claim by default.
"""
from __future__ import annotations

from .lowering_plan import FlowAutomaton, LoweringGraph
from .protocols import StateMachineFamilyRuntimeServices, UnflatteningStrategy

# §1a family base + profiles. The profile imports are eager (registration side effect);
# re-exporting the submodules also suppresses the implicit submodule->parent cycle edge.
from .base import StateMachineCffFamily
from .hodur import HodurFamily
from .approov import ApproovFamily
from .tigress import TigressFamily

__all__ = [
    "FlowAutomaton",
    "LoweringGraph",
    "StateMachineFamilyRuntimeServices",
    "UnflatteningStrategy",
    "StateMachineCffFamily",
    "HodurFamily",
    "ApproovFamily",
    "TigressFamily",
]
