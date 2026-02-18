"""Abstract-interpreter type notes.

ConstMap: dict mapping variable identifiers to (value, size) tuples.
Will be populated when d810.analysis.dataflow is implemented.

This module intentionally contains only type aliases and documentation.
The concrete GEN/KILL dataflow logic remains in
:class:`d810.optimizers.microcode.flow.constant_prop.stackvars_constprop.StackVariableConstantPropagationRule`
and is excluded from the evaluator refactor (see plan section 2.3).
"""

from __future__ import annotations

from typing import TypeAlias

#: Maps a variable identifier (e.g. stack-variable offset as ``int``) to a
#: ``(value, byte_size)`` pair representing a proven-constant binding.
#: Used as the abstract state in the GEN/KILL fixed-point dataflow analysis.
ConstMap: TypeAlias = dict[str, tuple[int, int]]

__all__ = ["ConstMap"]
