"""Compatibility shim for the renamed emulated-dispatcher family."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.emulated_dispatcher_family import (
    EmulatedDispatcherDetection,
    EmulatedDispatcherStrategyFamily,
)

OllvmDetection = EmulatedDispatcherDetection
OllvmStrategyFamily = EmulatedDispatcherStrategyFamily

__all__ = ["OllvmDetection", "OllvmStrategyFamily"]
