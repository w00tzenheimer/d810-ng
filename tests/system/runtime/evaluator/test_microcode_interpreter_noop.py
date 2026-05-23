from __future__ import annotations

import os
import platform


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


class TestMicroCodeInterpreterNoop:
    binary_name = _get_default_binary()

    def test_treats_nop_as_noop(self, real_asts):
        import ida_hexrays

        from d810.evaluator.hexrays_microcode.emulator import (
            MicroCodeEnvironment,
            MicroCodeInterpreter,
        )

        _, source_ins = real_asts[0]
        ins = ida_hexrays.minsn_t(source_ins)
        ins.opcode = ida_hexrays.m_nop
        ins.l.erase()
        ins.r.erase()
        ins.d.erase()

        interpreter = MicroCodeInterpreter()
        env = MicroCodeEnvironment()

        assert interpreter._eval_instruction(ins, env) is None
