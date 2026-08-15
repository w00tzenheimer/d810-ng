"""Capture IDA's complete live function flowchart for Stage C validation."""

from __future__ import annotations

import ida_funcs
import ida_gdl

from d810.transforms.native_cfg_normalization import NativeFlowchartBlock

__all__ = ["capture_live_native_flowchart"]


def capture_live_native_flowchart(function_ea: int) -> tuple[NativeFlowchartBlock, ...]:
    function = ida_funcs.get_func(int(function_ea))
    if function is None or int(function.start_ea) != int(function_ea):
        raise RuntimeError(f"no exact function at 0x{int(function_ea):X}")
    flowchart = ida_gdl.FlowChart(function)
    rows = []
    for block in flowchart:
        start_ea = int(block.start_ea)
        end_ea = int(block.end_ea)
        if end_ea <= start_ea:
            raise RuntimeError(f"empty live flowchart block at 0x{start_ea:X}")
        rows.append(
            NativeFlowchartBlock(
                start_ea=start_ea,
                end_ea=end_ea,
                successor_eas=tuple(
                    int(successor.start_ea) for successor in block.succs()
                ),
            )
        )
    if not rows:
        raise RuntimeError(f"empty live flowchart for 0x{int(function_ea):X}")
    return tuple(sorted(rows, key=lambda item: item.start_ea))
