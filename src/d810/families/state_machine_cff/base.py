"""StateMachineCffFamily — self-registering base for unflatten state-machine-CFF profiles.

A *profile* (``HodurFamily``, ``ApproovFamily``, ...) is a concrete subclass that
auto-registers via :class:`d810.core.registry.Registrant` — the same discovery
mechanism the rule subsystems use, so a profile becomes available simply by being
imported when the scanner loads the project (no hand-maintained list).

The live selector (:func:`d810.families.registry.select_family`) polls registered
profiles and returns the first match. Profiles own DISJOINT dispatcher-kind sets
(``RouterKind``): ``HodurFamily`` owns ``CONDITION_CHAIN``, ``ApproovFamily`` owns
switch/indirect — so at most one claims any graph and selection is order-independent (no
priority/tiebreak). The live entry still hardcodes ``HodurFamily()`` and never calls
``select_family``, so the registry is inert in production until the cutover wires it in.
Each profile implements the unflatten Family Protocol — ``detect`` + ``pipeline_for`` — and runs
on the ONE shared spine (``passes.driver.run_pipeline`` over the five passes). The base
adds discovery only; it never patches microcode.
"""
from __future__ import annotations

import abc

from d810.core.registry import Registrant
from d810.ir.maturity import IRMaturity


class StateMachineCffFamily(Registrant):
    """Self-registering base for state-machine-CFF unflattening profiles.

    Concrete subclasses register into ``StateMachineCffFamily.registry`` and are
    enumerated via :meth:`all`. Structurally satisfies the unflatten ``Family`` Protocol
    (``detect`` + ``pipeline_for``) — NOT a nominal Protocol base: ``Family`` is
    ``@runtime_checkable``, so ``isinstance(profile, Family)`` is True structurally, and
    nominal inheritance would clash (``Registry`` vs ``_ProtocolMeta`` metaclasses +
    Protocol's no-instantiate guard).
    """

    #: Display / selection name (the unflatten Family Protocol attribute).
    name: str = "state_machine_cff"

    #: The backend-agnostic IR maturities (:class:`d810.ir.maturity.IRMaturity` — NO IDA
    #: import here; the IDA-bound unflatten rule resolves them to ``ida_hexrays.MMAT_*`` via
    #: :mod:`d810.hexrays.ir_maturity`) at which THIS profile's dispatcher shape is
    #: recoverable. The rule is registered at the UNION of every profile's maturities and,
    #: once ``select_family`` picks a profile, only recovers at one of ITS declared
    #: maturities — so each family "registers to run at its desired maturity level" (ticket
    #: llr-a93i) instead of a single global stage, and the declaration is portable across IR
    #: backends (Hex-Rays / Ghidra / Binary Ninja). Default is ``GLOBAL_ANALYZED`` (Hex-Rays
    #: ``MMAT_GLBOPT1`` — the historical non-indirect recovery stage where global dataflow
    #: facts are available). A profile whose shape the backend folds earlier MAY also list
    #: ``CALL_MODELED`` (``MMAT_CALLS``) to recover pre-fold; ``LOCAL_OPTIMIZED``
    #: (``MMAT_LOCOPT``) is avoided because pre-call-modeling the multi-back-edge machines
    #: collapse (36→3 back-edges) and mis-recover.
    recovery_maturities: "tuple[IRMaturity, ...]" = (IRMaturity.GLOBAL_ANALYZED,)

    @abc.abstractmethod
    def detect(self, graph, capabilities, context=None):
        """Return the dispatcher match this profile claims (truthy), else ``None``."""

    @abc.abstractmethod
    def pipeline_for(self, match, context):
        """Return the ordered ``PassSpec`` tuple this profile runs on the shared spine."""