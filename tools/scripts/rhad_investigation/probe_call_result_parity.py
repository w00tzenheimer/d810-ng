"""Trace one detached call result across the Rhad CALLS replay rounds."""

from __future__ import annotations

import argparse
from pathlib import Path

import idapro


FUNCTION_EA = 0x40A560
CALLEE_EA = 0x40F830
CALL_EA = 0x40ABFA
PREDICATE_EA = 0x40AC11
ZERO_ARG_TYPE = "int __cdecl sub_40F830(void)"


def _instructions(block: object) -> tuple[object, ...]:
    result: list[object] = []
    instruction = block.head
    while instruction is not None:
        result.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(result)


def _instruction_tree(instruction: object) -> tuple[object, ...]:
    import ida_hexrays

    pending = [instruction]
    result: list[object] = []
    while pending:
        current = pending.pop()
        result.append(current)
        for operand in (current.l, current.r, current.d):
            if int(operand.t) == int(ida_hexrays.mop_d):
                pending.append(operand.d)
    return tuple(result)


def _contains_callee(instruction: object) -> bool:
    import ida_hexrays

    return any(
        int(nested.opcode) == int(ida_hexrays.m_call)
        and int(nested.l.t) == int(ida_hexrays.mop_v)
        and int(nested.l.g) == CALLEE_EA
        for nested in _instruction_tree(instruction)
    )


def _callinfo_rows(instruction: object) -> tuple[tuple[object, ...], ...]:
    import ida_hexrays

    rows: list[tuple[object, ...]] = []
    for nested in _instruction_tree(instruction):
        if (
            int(nested.opcode) != int(ida_hexrays.m_call)
            or int(nested.l.t) != int(ida_hexrays.mop_v)
            or int(nested.l.g) != CALLEE_EA
            or int(nested.d.t) != int(ida_hexrays.mop_f)
        ):
            continue
        callinfo = nested.d.f
        rows.append(
            (
                hex(int(nested.ea)),
                len(callinfo.args),
                str(callinfo.return_type),
                tuple(str(register) for register in callinfo.retregs),
                str(callinfo.return_regs),
                int(callinfo.call_spd),
                int(callinfo.stkargs_top),
                int(callinfo.flags),
            )
        )
    return tuple(rows)


def _dump_relevant_mba(label: str, mba: object) -> None:
    from d810.hexrays.mutation.detached_handler_island import (
        imported_detached_snippet_instruction_origins,
    )

    origins = dict(imported_detached_snippet_instruction_origins(mba))
    rows: list[tuple[object, ...]] = []
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        instructions = _instructions(block)
        relevant = []
        for instruction in instructions:
            native_ea = int(origins.get(int(instruction.ea), int(instruction.ea)))
            if native_ea in (CALL_EA, PREDICATE_EA) or _contains_callee(instruction):
                relevant.append(
                    (
                        hex(int(instruction.ea)),
                        hex(native_ea),
                        int(instruction.opcode),
                        str(instruction),
                        _callinfo_rows(instruction),
                    )
                )
        if relevant:
            rows.append(
                (
                    f"blk{int(block.serial)}@0x{int(block.start):X}",
                    tuple(int(predecessor) for predecessor in block.predset),
                    tuple(int(successor) for successor in block.succset),
                    tuple(relevant),
                )
            )
    print("CALL_RESULT_MBA", label, int(mba.maturity), tuple(rows), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    assert idapro.open_database(str(args.binary), True) == 0
    recovered = "None"
    try:
        import ida_hexrays
        import idaapi
        import idc

        idaapi.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()
        assert idc.SetType(CALLEE_EA, ZERO_ARG_TYPE)

        import d810.headless as headless

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        try:
            import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg
            from d810.hexrays.preanalysis.calls_done_preanalysis import (
                register_calls_done_preanalysis_handler,
                unregister_calls_done_preanalysis_handler,
            )
            from d810.hexrays.preanalysis.indirect_jump_labels import (
                mark_indirect_dispatcher,
            )

            callback_count = 0

            def trace_calls_done(
                *, function_ea: int, mba: object, decision: dict
            ) -> None:
                nonlocal callback_count
                if int(function_ea) != FUNCTION_EA:
                    return
                callback_count += 1
                _dump_relevant_mba(
                    f"calls-{callback_count}-redo-{bool(decision.get('request_redo'))}",
                    mba,
                )

            cg.install()
            register_calls_done_preanalysis_handler(
                "rhad.call_result_probe",
                trace_calls_done,
            )
            try:
                mark_indirect_dispatcher(FUNCTION_EA)
                ida_hexrays.clear_cached_cfuncs()
                first = ida_hexrays.decompile(FUNCTION_EA)
                assert first is not None
                assert (
                    cg.prepare_detached_handler_snippets(
                        FUNCTION_EA,
                        live_mba=first.mba,
                    )
                    > 0
                )
                ida_hexrays.clear_cached_cfuncs()
                cfunc = ida_hexrays.decompile(FUNCTION_EA)
                assert cfunc is not None
                _dump_relevant_mba("final", cfunc.mba)
                recovered = str(cfunc)
            finally:
                unregister_calls_done_preanalysis_handler("rhad.call_result_probe")
                cg.uninstall()
        finally:
            headless.stop()
    finally:
        idapro.close_database(False)

    args.output.write_text(recovered, encoding="utf-8")


if __name__ == "__main__":
    main()
