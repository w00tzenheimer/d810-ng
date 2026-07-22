"""Portable semantic roles for control-flow edge publication."""

from __future__ import annotations

from enum import Enum


class SemanticEdgeRole(str, Enum):
    """The semantic position occupied by one published CFG edge.

    These roles describe meaning, not the current Hex-Rays block shape.  The
    mutation backend decides whether the role requires zero-way
    materialization, an in-place one-way redirect, an explicit conditional
    target rewrite, or a physically adjacent fallthrough helper.
    """

    DIRECT = "direct"
    CONDITIONAL_TAKEN = "conditional_taken"
    CONDITIONAL_FALLTHROUGH = "conditional_fallthrough"


__all__ = ["SemanticEdgeRole"]
