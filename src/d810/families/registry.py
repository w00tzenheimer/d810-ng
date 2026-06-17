"""Family selection — the unflatten ``select_family`` entry point.

Profiles are discovered via :class:`d810.core.registry.Registrant`: every
:class:`StateMachineCffFamily` subclass auto-registers when its module is imported
(the ``d810.families.state_machine_cff`` package eagerly imports them on load — the
"scanner loads the project" auto-config), so there is no hand-maintained family list.
``select_family`` polls the registered profiles in REGISTRATION order (``hodur``,
``approov``, ``tigress``) and returns the first match. ``HodurFamily`` owns the disjoint
``CONDITION_CHAIN`` shape; ``ApproovFamily`` and ``TigressFamily`` both own switch /
indirect, so registration order disambiguates them (Approov keeps switch by default).

Hybrid config override (``router_resolution`` policy): a project may bias / restrict the
selection without a code change. ``project_config["router_resolution"]`` accepts ``deny``
(exclude these family names), ``require`` (restrict to exactly this name), and ``prefer``
(a ``name -> bias`` map that stable-sorts candidates by descending bias). The DEFAULT
(absent / empty policy) preserves registration-order first-match exactly.

Inert in production: the live maturity hook hardcodes ``HodurFamily()`` and never calls
``select_family`` (only the unflatten driver / unit tests do); no golden config sets
``router_resolution``.
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

    Mirrors unflatten ``select_family``: polls the candidate profiles and returns the first
    whose ``detect`` claims ``graph``. With the default (absent / empty)
    ``router_resolution`` policy this is registration-order first-match, unchanged. The
    optional ``project_config["router_resolution"]`` policy filters (``deny`` / ``require``)
    and biases (``prefer``) the candidate order before polling.
    """
    policy = {}
    if isinstance(project_config, dict):
        policy = project_config.get("router_resolution", {}) or {}

    deny = set(policy.get("deny", ()))
    require = policy.get("require")
    prefer = policy.get("prefer", {}) or {}

    candidates = [f for f in registered_families() if f.name not in deny]
    if require:
        candidates = [f for f in candidates if f.name == require]
    if prefer:
        # Stable sort by descending bias preserves registration order among ties.
        candidates.sort(key=lambda f: -float(prefer.get(f.name, 0.0)))

    for family in candidates:
        if family.detect(graph, capabilities, context=project_config) is not None:
            return family
    return None
