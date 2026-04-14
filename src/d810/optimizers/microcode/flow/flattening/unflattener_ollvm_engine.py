"""Compatibility shim for the renamed emulated-dispatcher engine rule."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.unflattener_emulated_dispatcher_engine import (
    EmulatedDispatcherUnflattener,
)

OllvmEngineUnflattener = EmulatedDispatcherUnflattener

__all__ = ["OllvmEngineUnflattener"]
