"""Portable values that identify one top-level decompilation session.

The lifecycle coordinator owns creation and release of a session.  This module
contains only immutable identity passed to observers, so it stays usable from
unit tests and layers that must not import the live Hex-Rays adapter.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from d810.core.execution_journal import DecompilationSessionId


class DecompilationEvent(enum.Enum):
    """Portable event keys for one manager-owned decompilation lifecycle."""

    SESSION_STARTED = "decompilation.session.started"
    SESSION_FINISHED = "decompilation.session.finished"
    MATURITY_CHANGED = "decompilation.maturity.changed"
    POST_D810_CAPTURE = "decompilation.post_d810.capture"
    HEXRAYS_FLOWCHART_READY = "decompilation.hexrays.flowchart.ready"
    HEXRAYS_GENERATED_READY = "decompilation.hexrays.generated.ready"
    HEXRAYS_PREOPT_READY = "decompilation.hexrays.preopt.ready"
    HEXRAYS_LOCOPT_READY = "decompilation.hexrays.locopt.ready"
    HEXRAYS_STKPNTS = "decompilation.hexrays.stkpnts"
    HEXRAYS_BUILD_CALLINFO = "decompilation.hexrays.callinfo.build"
    HEXRAYS_CALLS_DONE = "decompilation.hexrays.calls_done"
    HEXRAYS_CALLS_POST_D810 = "decompilation.hexrays.calls_post_d810"
    FLOWGRAPH_READY = "decompilation.flowgraph.ready"


@dataclass(frozen=True, slots=True)
class DecompilationSessionEvent:
    """Identity of a manager-owned top-level decompilation session."""

    function_ea: int
    database_identity: str
    top_level_epoch: int
    #: Correlation identity for the execution journal (see
    #: ``d810.core.execution_journal``). Defaulted via a factory rather than
    #: a fixed value so every event still mints its own fresh, globally-unique
    #: session id, and so existing keyword-argument publishers (e.g.
    #: ``DecompilationSessionContext.event`` in ``manager/decompilation_lifecycle.py``)
    #: stay source-compatible without passing this field explicitly.
    session_id: DecompilationSessionId = field(
        default_factory=DecompilationSessionId.new
    )
