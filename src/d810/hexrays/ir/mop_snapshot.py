"""Mop snapshot dispatcher with a portable implementation for scalar doubles."""

from d810.core.cymode import CythonMode
from d810.hexrays.ir.p_mop_snapshot import (
    MopSnapshot as PythonMopSnapshot,
    raw_instruction_identity,
    raw_mop_identity,
)

MopSnapshot = PythonMopSnapshot
if CythonMode().is_enabled():
    try:
        from d810.speedups.cythxr.mop_snapshot import MopSnapshot
    except ImportError:
        pass
