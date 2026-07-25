"""Print IDA stack-frame evidence for selected native instruction EAs.

Run against a disposable binary copy.  The probe may create or extend the
requested function, but always closes the database without saving an IDB.
"""

from __future__ import annotations

import os
from pathlib import Path

import idapro


BIN = Path(os.environ["RHAD_STACK_PROBE_BIN"]).resolve()
FUNCTION_EA = int(os.environ["RHAD_STACK_PROBE_FUNC"], 0)
FUNCTION_END = int(os.environ["RHAD_STACK_PROBE_END"], 0)
INSTRUCTION_EAS = tuple(
    int(item.strip(), 0)
    for item in os.environ["RHAD_STACK_PROBE_EAS"].split(",")
    if item.strip()
)


assert idapro.open_database(str(BIN), True) == 0
try:
    import ida_auto
    import ida_bytes
    import ida_frame
    import ida_funcs
    import ida_ua
    import idaapi

    idaapi.auto_wait()
    function = ida_funcs.get_func(FUNCTION_EA)
    if function is None:
        ida_auto.plan_and_wait(FUNCTION_EA, FUNCTION_END)
        ida_ua.create_insn(FUNCTION_EA)
        ida_funcs.add_func(FUNCTION_EA, FUNCTION_END)
        idaapi.auto_wait()
        function = ida_funcs.get_func(FUNCTION_EA)
    if function is None:
        raise RuntimeError(f"could not create function 0x{FUNCTION_EA:X}")
    if int(function.end_ea) != FUNCTION_END:
        ida_auto.plan_and_wait(FUNCTION_EA, FUNCTION_END)
        ida_funcs.set_func_end(FUNCTION_EA, FUNCTION_END)
        idaapi.auto_wait()
        function = ida_funcs.get_func(FUNCTION_EA)
    if function is None or int(function.end_ea) != FUNCTION_END:
        raise RuntimeError(f"could not extend function 0x{FUNCTION_EA:X}")

    print(
        "STACK_FUNCTION",
        f"start=0x{int(function.start_ea):X}",
        f"end=0x{int(function.end_ea):X}",
        f"frsize={int(function.frsize)}",
        f"frregs={int(function.frregs)}",
        f"argsize={int(function.argsize)}",
        flush=True,
    )
    for instruction_ea in INSTRUCTION_EAS:
        instruction = ida_ua.insn_t()
        if ida_ua.decode_insn(instruction, instruction_ea) <= 0:
            print(f"STACK_INSN ea=0x{instruction_ea:X} decode=failed", flush=True)
            continue
        owner = ida_funcs.get_func(instruction_ea)
        print(
            "STACK_INSN",
            f"ea=0x{instruction_ea:X}",
            f"contains={ida_funcs.func_contains(function, instruction_ea)}",
            f"owner={None if owner is None else f'0x{int(owner.start_ea):X}'}",
            f"spd={int(ida_frame.get_spd(function, instruction_ea))}",
            f"delta={int(ida_frame.get_sp_delta(function, instruction_ea))}",
            flush=True,
        )
        flags = ida_bytes.get_flags(instruction_ea)
        for operand_index, operand in enumerate(instruction.ops):
            if int(operand.type) == int(ida_ua.o_void):
                break
            annotated = bool(ida_bytes.is_stkvar(flags, operand_index))
            frame_offset = (
                int(
                    ida_frame.calc_stkvar_struc_offset(
                        function,
                        instruction,
                        operand_index,
                    )
                )
                if annotated
                else None
            )
            print(
                "STACK_OPERAND",
                f"ea=0x{instruction_ea:X}",
                f"index={operand_index}",
                f"type={int(operand.type)}",
                f"reg={int(operand.reg)}",
                f"addr=0x{int(operand.addr):X}",
                f"annotated={annotated}",
                f"frame_offset={frame_offset}",
                flush=True,
            )
finally:
    idapro.close_database(False)
