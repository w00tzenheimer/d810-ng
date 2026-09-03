"""Runtime coverage for the aliased-stack reaching-definitions fallback."""

from __future__ import annotations

import idautils
import ida_hexrays
import os
import platform

from d810.evaluator.hexrays_microcode.chains import find_reaching_defs_for_stkvar
from tests.system.runtime.conftest import gen_microcode_at_maturity


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    if platform.system() == "Windows":
        return "libobfuscated.dll"
    if platform.system() == "Darwin":
        return "libobfuscated.dylib"
    return "libobfuscated.so"


def _first_live_aliased_stack_def():
    """Find a real direct aliased-stack write and a successor it reaches."""
    for function_ea in idautils.Functions():
        mba = gen_microcode_at_maturity(function_ea, ida_hexrays.MMAT_GLBOPT1)
        if mba is None:
            continue
        minstkref = int(getattr(mba, "minstkref", 0) or 0)
        if minstkref <= 0 or minstkref >= 0x10000000:
            continue
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            instruction = block.head
            while instruction is not None:
                destination = instruction.d
                if (
                    destination is not None
                    and destination.t == ida_hexrays.mop_S
                    and destination.s is not None
                    and int(destination.s.off) >= minstkref
                    and int(destination.size) > 0
                    and int(block.nsucc()) > 0
                ):
                    return (
                        mba,
                        int(block.succ(0)),
                        int(destination.s.off),
                        int(destination.size),
                        int(block.serial),
                        int(instruction.ea),
                    )
                instruction = instruction.next
    return None


class TestAliasedStackReachingDefs:
    binary_name = _get_default_binary()

    def test_live_aliased_stack_slot_yields_its_direct_definition(
        self, libobfuscated_setup
    ) -> None:
        found = _first_live_aliased_stack_def()
        assert found is not None, "sample binary has no direct aliased stack write"
        mba, reader_serial, offset, size, writer_serial, writer_ea = found

        definitions = find_reaching_defs_for_stkvar(mba, reader_serial, offset, size)

        assert (writer_serial, writer_ea) in {
            (definition.block_serial, definition.ins_ea) for definition in definitions
        }
