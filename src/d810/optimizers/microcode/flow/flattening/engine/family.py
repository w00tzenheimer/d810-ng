"""Migration shim: ``CFFStrategyFamily`` relocated to
``d810.families.state_machine_cff.family`` (LS13 C2, ticket d81-eo03).

Plain re-import preserving object identity for the dozen existing
``engine.family`` / ``hodur`` consumers. New code imports from the canonical
``d810.families.state_machine_cff`` location.
"""
from __future__ import annotations

from d810.families.state_machine_cff.family import CFFStrategyFamily, DetectionResult

__all__ = ["CFFStrategyFamily", "DetectionResult"]
