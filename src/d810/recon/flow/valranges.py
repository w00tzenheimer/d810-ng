"""Compatibility wrappers for Hex-Rays value-range collection.

The live IDA-native implementation lives in
``d810.evaluator.hexrays_microcode.valranges``. This wrapper keeps the
historical recon import path stable for dump/collector code without importing
``ida_hexrays`` in ``recon.flow`` itself.
"""
from __future__ import annotations

from d810.core.typing import Dict, List


def collect_block_valranges(blk) -> List[str]:
    """Delegate block-level collection to the evaluator implementation."""
    from d810.evaluator.hexrays_microcode.valranges import collect_block_valranges

    return collect_block_valranges(blk)


def collect_instruction_valranges(blk, ins) -> List[str]:
    """Delegate instruction-level collection to the evaluator implementation."""
    from d810.evaluator.hexrays_microcode.valranges import (
        collect_instruction_valranges,
    )

    return collect_instruction_valranges(blk, ins)


def collect_mba_valranges(mba) -> Dict[int, List[str]]:
    """Delegate MBA-level collection to the evaluator implementation."""
    from d810.evaluator.hexrays_microcode.valranges import collect_mba_valranges

    return collect_mba_valranges(mba)


__all__ = [
    "collect_block_valranges",
    "collect_instruction_valranges",
    "collect_mba_valranges",
]
