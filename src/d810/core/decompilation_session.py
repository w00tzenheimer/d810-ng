"""Portable values that identify one top-level decompilation session.

The lifecycle coordinator owns creation and release of a session.  This module
contains only immutable identity passed to observers, so it stays usable from
unit tests and layers that must not import the live Hex-Rays adapter.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DecompilationSessionEvent:
    """Identity of a manager-owned top-level decompilation session."""

    function_ea: int
    database_identity: str
    top_level_epoch: int
