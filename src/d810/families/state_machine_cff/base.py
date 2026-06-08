"""StateMachineCffFamily — self-registering base for §1a state-machine-CFF profiles.

A *profile* (``HodurFamily``, ``ApproovFamily``, ...) is a concrete subclass that
auto-registers via :class:`d810.core.registry.Registrant` — the same discovery
mechanism the rule subsystems use, so a profile becomes available simply by being
imported when the scanner loads the project (no hand-maintained list).

The live selector (:func:`d810.families.registry.select_family`) polls registered
profiles and returns the first match. Profiles own DISJOINT dispatcher-kind sets
(``DispatcherType``): ``HodurFamily`` owns ``CONDITIONAL_CHAIN``, ``ApproovFamily`` owns
switch/indirect — so at most one claims any graph and selection is order-independent (no
priority/tiebreak). The live entry still hardcodes ``HodurFamily()`` and never calls
``select_family``, so the registry is inert in production until the cutover wires it in.
Each profile implements the §1a Family Protocol — ``detect`` + ``pipeline_for`` — and runs
on the ONE shared spine (``passes.driver.run_pipeline`` over the five passes). The base
adds discovery only; it never patches microcode.
"""
from __future__ import annotations

import abc

from d810.core.registry import Registrant


class StateMachineCffFamily(Registrant):
    """Self-registering base for state-machine-CFF unflattening profiles.

    Concrete subclasses register into ``StateMachineCffFamily.registry`` and are
    enumerated via :meth:`all`. Structurally satisfies the §1a ``Family`` Protocol
    (``detect`` + ``pipeline_for``) — NOT a nominal Protocol base: ``Family`` is
    ``@runtime_checkable``, so ``isinstance(profile, Family)`` is True structurally, and
    nominal inheritance would clash (``Registry`` vs ``_ProtocolMeta`` metaclasses +
    Protocol's no-instantiate guard).
    """

    #: Display / selection name (the §1a Family Protocol attribute).
    name: str = "state_machine_cff"

    @abc.abstractmethod
    def detect(self, graph, capabilities, context=None):
        """Return the dispatcher match this profile claims (truthy), else ``None``."""

    @abc.abstractmethod
    def pipeline_for(self, match, context):
        """Return the ordered ``PassSpec`` tuple this profile runs on the shared spine."""