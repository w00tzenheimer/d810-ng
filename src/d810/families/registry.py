"""Family selection — the §1a ``select_family`` entry point.

Profiles are discovered via :class:`d810.core.registry.Registrant`: every
:class:`StateMachineCffFamily` subclass auto-registers when its module is imported
(the ``d810.families.state_machine_cff`` package eagerly imports them on load — the
"scanner loads the project" auto-config), so there is no hand-maintained family list.
``select_family`` polls the registered profiles and returns the first match. Profiles own
DISJOINT dispatcher-kind sets (``HodurFamily`` = ``CONDITIONAL_CHAIN``, ``ApproovFamily`` =
switch/indirect), so at most one claims any graph and the result is order-independent — no
priority/tiebreak.

Inert in production: the live maturity hook hardcodes ``HodurFamily()`` and never calls
``select_family`` (only the §1a driver / unit tests do).
"""
from __future__ import annotations

# Importing the package runs its __init__, which eagerly imports every profile module so
# each StateMachineCffFamily subclass auto-registers (registration side effect).
from d810.families.state_machine_cff import StateMachineCffFamily


def registered_families() -> tuple:
    """Return one instance of every registered profile."""
    return tuple(family() for family in StateMachineCffFamily.all())


def select_family(graph, project_config, *, capabilities=frozenset()):
    """Return the registered profile that recognizes ``graph``, or ``None``.

    Mirrors §1a ``select_family``. Profiles own disjoint dispatcher-kind sets, so the
    first ``detect`` that returns non-None is the unique match (order-independent).
    """
    for family in registered_families():
        if family.detect(graph, capabilities, context=project_config) is not None:
            return family
    return None
