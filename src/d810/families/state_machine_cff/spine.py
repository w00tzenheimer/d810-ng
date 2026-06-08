"""Chain-based §1a spine: ONE detect point, passes selected by resolved kind.

``StateMachineCffSpine`` replaces the per-family ``detect`` gate at the live §1a
entry (llr-g3l8 slice 2). Detection runs the ranked :func:`resolve_dispatcher`
chain over :func:`default_dispatcher_resolvers` (equality-chain outranks switch),
collapsing ``HodurFamily``/``ApproovFamily`` shape-specific gating into one
resolution; the resolved ``router_kind`` then selects the pass shape via
:func:`pipeline_for_kind`. This un-regresses abc-on-§1a (the chain gates SWITCH ->
the standard seeded-fold passes, no emulation).

It structurally satisfies the §1a ``Family`` Protocol (``detect`` + ``pipeline_for``)
WITHOUT being a ``Registrant`` — it is the hardcoded live entry, not a discovered
profile. The five passes re-derive everything from ``ctx.graph``, so the resolution
returned by ``detect`` is purely the run_pipeline gate (never consumed by a pass).
"""
from __future__ import annotations

from d810.analyses.control_flow.dispatcher_recovery import (
    default_dispatcher_resolvers,
)
from d810.analyses.control_flow.dispatcher_resolver import resolve_dispatcher
from d810.families.state_machine_cff.pipeline import pipeline_for_kind

__all__ = ["StateMachineCffSpine"]


class StateMachineCffSpine:
    """Live §1a entry: chain-resolved detection + kind-selected pass shape."""

    #: Display / selection name (the §1a Family Protocol attribute).
    name = "state_machine_cff"

    def detect(self, graph, capabilities, context=None):
        """Resolve the dispatcher via the ranked chain (the single detect point)."""
        if graph is None or not hasattr(graph, "blocks"):
            return None
        return resolve_dispatcher(graph, default_dispatcher_resolvers())

    def pipeline_for(self, match, context):
        """Return the §1a pass shape for the resolved ``match.router_kind``."""
        return pipeline_for_kind(match.router_kind)
