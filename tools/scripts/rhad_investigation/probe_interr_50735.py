"""Isolate the provider that prevents first-decompile INTERR 50735.

Run this only against a disposable copy of the Rhadamanthys loader.  The
computed-goto resolver patches native bytes in the opened database.

The IDA 9.1 verifier assigns 50735 to an ``mcallarg_t`` whose operand size does
not match its formal ``tinfo_t`` size.  This probe observes every analyzed call
at ``hxe_callinfo_built`` and prints mismatches with stable native EA anchors.
It can independently disable d810's transient stack-point and callinfo
providers to distinguish the two inputs to Hex-Rays call analysis.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from types import SimpleNamespace

import idapro


FUNCTION_EA = 0x40A560
ZERO_ARG_CALLEE_EA = 0x40F830
ZERO_ARG_TYPE = "int __cdecl sub_40F830(void)"


def _argument_rows(block: object) -> tuple[tuple[object, ...], ...]:
    import ida_hexrays

    call = block.tail
    if call is None or int(call.d.t) != int(ida_hexrays.mop_f):
        return ()
    rows: list[tuple[object, ...]] = []
    for index, argument in enumerate(call.d.f.args):
        argument_size = int(argument.size)
        type_size = int(argument.type.get_size())
        rows.append(
            (
                index,
                argument_size,
                type_size,
                argument_size == type_size,
                hex(int(argument.ea)),
                str(argument.type),
                str(argument),
            )
        )
    return tuple(rows)


def _call_identity(block: object) -> tuple[str, str, int]:
    call = block.tail
    if call is None:
        return ("none", "none", 0)
    return (
        f"0x{int(call.ea):X}",
        f"0x{int(block.start):X}",
        int(call.opcode),
    )


class _CallArgumentAudit:
    """Observe call arguments immediately after Hex-Rays analyzes each call."""

    def __init__(self) -> None:
        import ida_hexrays

        class Hooks(ida_hexrays.Hexrays_Hooks):
            def callinfo_built(inner_self, block: object) -> int:
                del inner_self
                rows = _argument_rows(block)
                call_ea, block_ea, opcode = _call_identity(block)
                mismatches = tuple(row for row in rows if not bool(row[3]))
                if mismatches:
                    print(
                        "CALLARG_MISMATCH",
                        f"call={call_ea}",
                        f"block={block_ea}",
                        f"opcode={opcode}",
                        f"args={rows}",
                        flush=True,
                    )
                return 0

        self.hooks = Hooks()

    def hook(self) -> None:
        self.hooks.hook()

    def unhook(self) -> None:
        self.hooks.unhook()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--disable-stkpnts", action="store_true")
    parser.add_argument("--disable-callinfo", action="store_true")
    parser.add_argument("--set-zero-arg-type", action="store_true")
    parser.add_argument("--bare", action="store_true")
    parser.add_argument("--attempts", type=int, default=2)
    args = parser.parse_args()

    assert idapro.open_database(str(args.binary), True) == 0
    try:
        import ida_hexrays
        import idaapi
        import idc

        idaapi.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()
        if args.set_zero_arg_type:
            assert idc.SetType(ZERO_ARG_CALLEE_EA, ZERO_ARG_TYPE)

        if args.bare:
            import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg
            from d810.analyses.control_flow.native_preanalysis_session import (
                NativePreanalysisSessionState,
            )
            from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
                resolver_session_state,
            )

            resolution = cg.resolve_computed_gotos_static(FUNCTION_EA)
            assert resolution is not None
            resolver_state = resolver_session_state(
                SimpleNamespace(
                    native_preanalysis=NativePreanalysisSessionState(),
                    extensions={},
                )
            )
            materialized = cg.materialize_computed_gotos(
                resolution,
                state=resolver_state,
            )
            print(
                "BARE_MATERIALIZATION",
                f"sites={resolution.site_count}",
                f"targets={resolution.target_count}",
                f"materialized={materialized}",
                flush=True,
            )
            audit = _CallArgumentAudit()
            audit.hook()
            try:
                for attempt in range(1, max(1, int(args.attempts)) + 1):
                    ida_hexrays.clear_cached_cfuncs()
                    failure = ida_hexrays.hexrays_failure_t()
                    cfunc = ida_hexrays.decompile(FUNCTION_EA, failure)
                    print(
                        "DECOMPILE_RESULT",
                        f"attempt={attempt}",
                        f"success={cfunc is not None}",
                        f"code={int(failure.code)}",
                        f"errea=0x{int(failure.errea):X}",
                        f"description={failure.desc()!r}",
                        "bare=True",
                        flush=True,
                    )
            finally:
                audit.unhook()
            return

        import d810.headless as headless

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        logging.disable(logging.CRITICAL)
        try:
            import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg
            from d810.hexrays.preanalysis.callinfo_preanalysis import (
                unregister_callinfo_preanalysis_handler,
            )
            from d810.hexrays.preanalysis.stkpnts_preanalysis import (
                unregister_stkpnts_preanalysis_handler,
            )

            cg.install()
            print(
                "PROVIDER_CAPABILITIES",
                f"stkpnts={cg._upsert_stkpnt is not None}",
                f"callinfo_copy={cg._copy_mcallinfo is not None}",
                flush=True,
            )
            if args.disable_stkpnts:
                unregister_stkpnts_preanalysis_handler("computed_goto_resolver.stkpnts")
            if args.disable_callinfo:
                unregister_callinfo_preanalysis_handler(
                    "computed_goto_resolver.callinfo"
                )

            audit = _CallArgumentAudit()
            audit.hook()
            try:
                headless.prepare_native_preanalysis(FUNCTION_EA)
                for attempt in range(1, max(1, int(args.attempts)) + 1):
                    ida_hexrays.clear_cached_cfuncs()
                    failure = ida_hexrays.hexrays_failure_t()
                    cfunc = ida_hexrays.decompile(FUNCTION_EA, failure)
                    print(
                        "DECOMPILE_RESULT",
                        f"attempt={attempt}",
                        f"success={cfunc is not None}",
                        f"code={int(failure.code)}",
                        f"errea=0x{int(failure.errea):X}",
                        f"description={failure.desc()!r}",
                        f"disable_stkpnts={args.disable_stkpnts}",
                        f"disable_callinfo={args.disable_callinfo}",
                        f"set_zero_arg_type={args.set_zero_arg_type}",
                        flush=True,
                    )
            finally:
                audit.unhook()
                cg.uninstall()
        finally:
            headless.stop()
    finally:
        idapro.close_database(False)


if __name__ == "__main__":
    main()
