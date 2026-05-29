"""Backward-compatibility shim: value-flow facts moved to ``d810.analyses.value_flow``.

The canonical home is now :mod:`d810.analyses.value_flow` (Landing
Sequence LS7, Commit 1).  This star re-export keeps
``d810.recon.facts.value_flow`` importers working until the consumer
cutover (Commit 2) and shim retirement (Commit 3).
"""
from __future__ import annotations

from d810.analyses.value_flow import *  # noqa: F401,F403
