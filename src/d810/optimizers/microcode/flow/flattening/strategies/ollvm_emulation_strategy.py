"""Compatibility shim for the renamed emulated-dispatcher strategy."""
from __future__ import annotations

from d810.optimizers.microcode.flow.flattening.strategies.emulated_dispatcher_strategy import (
    EMULATED_DISPATCHER_METADATA_KEY,
    EMULATED_DISPATCHER_MODIFICATIONS_KEY,
    EmulatedDispatcherMetadata,
    EmulatedDispatcherStrategy,
    extract_emulated_dispatcher_metadata,
    extract_emulated_dispatcher_modifications,
)

OLLVM_EMULATION_METADATA_KEY = EMULATED_DISPATCHER_METADATA_KEY
OLLVM_EMULATION_MODIFICATIONS_KEY = EMULATED_DISPATCHER_MODIFICATIONS_KEY
OllvmEmulationMetadata = EmulatedDispatcherMetadata
OllvmEmulationStrategy = EmulatedDispatcherStrategy
extract_ollvm_emulation_metadata = extract_emulated_dispatcher_metadata
extract_ollvm_emulation_modifications = extract_emulated_dispatcher_modifications

__all__ = [
    "OLLVM_EMULATION_METADATA_KEY",
    "OLLVM_EMULATION_MODIFICATIONS_KEY",
    "OllvmEmulationMetadata",
    "OllvmEmulationStrategy",
    "extract_ollvm_emulation_metadata",
    "extract_ollvm_emulation_modifications",
]
