"""Normalize the first conditional edge in the selected dispatch function."""

import ida_bytes
import idautils
import idc

from d810.backends.ida.idb_preparation.script_runner import PreparationScriptContext
from d810.core.typing import cast


function_ea = int(globals()["function_ea"])
preparation = cast(PreparationScriptContext, globals()["preparation"])


conditional_ea = next(
    (
        int(ea)
        for ea in idautils.FuncItems(function_ea)
        if idc.print_insn_mnem(int(ea)).lower() in {"jz", "je"}
    ),
    None,
)
if conditional_ea is None:
    raise RuntimeError("selected function has no conditional dispatcher edge")
if int(ida_bytes.get_byte(conditional_ea)) != 0x74:
    raise RuntimeError(
        f"dispatcher edge at {conditional_ea:#x} is not a short JE instruction"
    )

preparation.note_function(function_ea)
preparation.patch_bytes(conditional_ea, b"\xeb")
