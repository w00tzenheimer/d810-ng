"""Family selection — the §1a ``select_family`` entry point.

Skeleton registry: returns the first registered family whose ``detect`` matches the portable
``FlowGraph``. Behavior-neutral until families carry real ``detect`` bodies (seam-pending); the
default registry is empty so ``select_family`` returns ``None`` (nothing runs) and the live
``HodurUnflattener`` path is unaffected.
"""
from __future__ import annotations

from d810.families.state_machine_cff.hodur_pipeline import HodurFamily

# Registered families, highest-priority first. HodurFamily.detect is still inert (returns None),
# so this list participates structurally without changing behavior.
_FAMILIES: tuple = (HodurFamily(),)


def registered_families() -> tuple:
    return _FAMILIES


def select_family(graph, project_config, *, capabilities=frozenset()):
    """Return the family that recognizes ``graph``, or ``None``.

    Mirrors §1a ``select_family``. Inert until a family's ``detect`` returns non-None.
    """
    for family in _FAMILIES:
        if family.detect(graph, capabilities, context=project_config) is not None:
            return family
    return None
