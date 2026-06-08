"""State-machine CFF family contracts + §1a profile discovery.

Importing this package eagerly imports every §1a profile module (``hodur``, ``approov``)
so each :class:`StateMachineCffFamily` subclass auto-registers via ``Registrant`` — this
is the "scanner loads the project" auto-config. ``families.registry.select_family`` then
enumerates them (disjoint kind claims -> order-independent) with no hand-maintained list.
"""
from __future__ import annotations

from .lowering_plan import FlowAutomaton, LoweringGraph
from .protocols import StateMachineFamilyRuntimeServices, UnflatteningStrategy

# §1a family base + profiles. The profile imports are eager (registration side effect);
# re-exporting the submodules also suppresses the implicit submodule->parent cycle edge.
from .base import StateMachineCffFamily
from .hodur import HodurFamily
from .approov import ApproovFamily

__all__ = [
    "FlowAutomaton",
    "LoweringGraph",
    "StateMachineFamilyRuntimeServices",
    "UnflatteningStrategy",
    "StateMachineCffFamily",
    "HodurFamily",
    "ApproovFamily",
]
