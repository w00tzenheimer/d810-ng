"""Portable values that identify one top-level decompilation session.

The lifecycle coordinator owns creation and release of a session.  This module
contains only immutable identity passed to observers, so it stays usable from
unit tests and layers that must not import the live Hex-Rays adapter.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class DecompilationEvent(enum.Enum):
    """Portable event keys for one manager-owned decompilation lifecycle."""

    SESSION_STARTED = "decompilation.session.started"
    SESSION_FINISHED = "decompilation.session.finished"
    MATURITY_CHANGED = "decompilation.maturity.changed"
    POST_D810_CAPTURE = "decompilation.post_d810.capture"
    HEXRAYS_FLOWCHART_READY = "decompilation.hexrays.flowchart.ready"
    HEXRAYS_PREOPT_READY = "decompilation.hexrays.preopt.ready"
    HEXRAYS_LOCOPT_READY = "decompilation.hexrays.locopt.ready"
    HEXRAYS_STKPNTS = "decompilation.hexrays.stkpnts"
    HEXRAYS_BUILD_CALLINFO = "decompilation.hexrays.callinfo.build"
    HEXRAYS_CALLS_DONE = "decompilation.hexrays.calls_done"
    FLOWGRAPH_READY = "decompilation.flowgraph.ready"


@dataclass(frozen=True, slots=True)
class DecompilationSessionEvent:
    """Identity of a manager-owned top-level decompilation session."""

    function_ea: int
    database_identity: str
    top_level_epoch: int
