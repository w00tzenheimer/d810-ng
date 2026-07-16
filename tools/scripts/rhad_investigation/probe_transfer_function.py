"""Measure d810 transferability on another protected Rhadamanthys function.

The probe deliberately follows the public two-round UI workflow: decompile once,
prepare detached handler snippets through the registered capability, then
decompile again if snippets were captured.  It does not mark the function as an
indirect dispatcher, set callee types, or invoke resolver internals directly.

Run only against a disposable binary copy.  The computed-goto resolver may
materialize native byte patches in the opened database.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

import idapro


BIN = Path(os.environ["RHAD_TRANSFER_BIN"]).resolve()
FUNCTION_EA = int(os.environ.get("RHAD_TRANSFER_FUNC", "0x40D200"), 0)
FUNCTION_END = (
    int(os.environ["RHAD_TRANSFER_END"], 0)
    if "RHAD_TRANSFER_END" in os.environ
    else None
)
MODE = os.environ.get("RHAD_TRANSFER_MODE", "d810").strip().lower()
OUTPUT = Path(
    os.environ.get(
        "RHAD_TRANSFER_OUTPUT",
        f".tmp/rhad_transferability/sub_{FUNCTION_EA:X}_{MODE}.c",
    )
).resolve()
DIAG_OUTPUT = os.environ.get("RHAD_TRANSFER_DIAG_OUTPUT")
RESOLUTION_OUTPUT = os.environ.get("RHAD_TRANSFER_RESOLUTION_OUTPUT")
TRANSFER_OUTPUT = os.environ.get("RHAD_TRANSFER_TRANSFERS_OUTPUT") or os.environ.get(
    "RHAD_TRANSFER_TRANSFER_OUTPUT"
)
ORIGIN_OUTPUT = os.environ.get("RHAD_TRANSFER_ORIGINS_OUTPUT")
TRACE_HANDLER_ROUTES = os.environ.get("RHAD_TRANSFER_TRACE_HANDLER_ROUTES") == "1"
TRACE_HANDLER_EAS = frozenset(
    int(item.strip(), 0)
    for item in os.environ.get("RHAD_TRANSFER_TRACE_HANDLER_EAS", "").split(",")
    if item.strip()
)
CTREE_OUTPUT = os.environ.get("RHAD_TRANSFER_CTREE_OUTPUT")
SIDECAR_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")


def _clear_sidecars(binary: Path) -> None:
    for suffix in SIDECAR_SUFFIXES:
        for stale in (
            binary.with_suffix(suffix),
            Path(str(binary) + suffix),
        ):
            stale.unlink(missing_ok=True)


def _pseudocode(cfunc: object | None) -> str:
    if cfunc is None:
        return "None"
    import idaapi

    return "\n".join(
        idaapi.tag_remove(str(line.line)) for line in cfunc.get_pseudocode()
    )


def _print_summary(
    *,
    first: object | None,
    final: object | None,
    prepared: int,
    materialized: bool,
    resolution: object | None,
) -> None:
    text = _pseudocode(final)
    print(
        "TRANSFER_RESULT",
        f"mode={MODE}",
        f"function=0x{FUNCTION_EA:X}",
        f"first={first is not None}",
        f"final={final is not None}",
        f"prepared={prepared}",
        f"materialized={materialized}",
        f"sites={0 if resolution is None else int(resolution.site_count)}",
        f"targets={0 if resolution is None else int(resolution.target_count)}",
        f"lines={len(text.splitlines())}",
        f"while1={text.count('while ( 1 )') + text.count('while (1)')}",
        f"jumpout={text.count('JUMPOUT(')}",
        f"inline_asm={text.count('__asm')}",
        flush=True,
    )


def _write_ctree_statement_anchors(cfunc: object, destination: Path) -> None:
    """Persist statement order with native EA anchors for parity triage."""
    import ida_hexrays

    rows: list[dict[str, object]] = []

    class _StatementVisitor(ida_hexrays.ctree_visitor_t):
        def __init__(self) -> None:
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)

        def visit_insn(self, insn: object) -> int:  # type: ignore[override]
            rows.append(
                {
                    "index": len(rows),
                    "op": int(insn.op),
                    "opname": str(insn.opname),
                    "ea": f"0x{int(insn.ea):X}",
                }
            )
            return 0

    _StatementVisitor().apply_to(cfunc.body, None)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(rows, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if MODE not in {"d810", "native"}:
    raise SystemExit(f"unsupported RHAD_TRANSFER_MODE={MODE!r}")

_clear_sidecars(BIN)
assert idapro.open_database(str(BIN), True) == 0
try:
    import ida_hexrays
    import ida_auto
    import ida_funcs
    import ida_ua
    import idaapi

    idaapi.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    function_created = False
    function_extended = False
    if ida_funcs.get_func(FUNCTION_EA) is None:
        if FUNCTION_END is not None:
            ida_auto.plan_and_wait(FUNCTION_EA, FUNCTION_END)
        ida_ua.create_insn(FUNCTION_EA)
        function_created = bool(
            ida_funcs.add_func(
                FUNCTION_EA,
                idaapi.BADADDR if FUNCTION_END is None else FUNCTION_END,
            )
        )
    if ida_funcs.get_func(FUNCTION_EA) is None:
        raise RuntimeError(f"IDA could not define function 0x{FUNCTION_EA:X}")
    if function_created:
        idaapi.auto_wait()
    function = ida_funcs.get_func(FUNCTION_EA)
    if FUNCTION_END is not None and int(function.end_ea) != FUNCTION_END:
        ida_auto.plan_and_wait(FUNCTION_EA, FUNCTION_END)
        function_extended = bool(
            ida_funcs.set_func_end(FUNCTION_EA, FUNCTION_END)
        )
        idaapi.auto_wait()
        function = ida_funcs.get_func(FUNCTION_EA)
        if int(function.end_ea) != FUNCTION_END:
            raise RuntimeError(
                "IDA could not extend function "
                f"0x{FUNCTION_EA:X} from 0x{int(function.end_ea):X} "
                f"to 0x{FUNCTION_END:X}"
            )
    print(
        "FUNCTION_READY",
        f"function=0x{FUNCTION_EA:X}",
        f"end={None if FUNCTION_END is None else hex(FUNCTION_END)}",
        f"actual_end=0x{int(function.end_ea):X}",
        f"created={function_created}",
        f"extended={function_extended}",
        flush=True,
    )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    first = None
    final = None
    prepared = 0
    materialized = False
    resolution = None

    if MODE == "native":
        ida_hexrays.clear_cached_cfuncs()
        first = ida_hexrays.decompile(FUNCTION_EA)
        final = first
    else:
        import d810.headless as headless
        from d810.capabilities.detached_handler_snippets import (
            prepare_detached_handler_snippets,
        )
        import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        if TRACE_HANDLER_ROUTES:
            import d810.transforms.minimal_unflatten_emit as emit_module

            trace_context = {}
            original_recover_handler_transitions = (
                emit_module.recover_handler_transitions
            )
            original_resolve_exit_states = (
                emit_module.resolve_materialized_handler_exit_states
            )

            def trace_recover_handler_transitions(flow_graph, *args, **kwargs):
                trace_context["flow_graph"] = flow_graph
                return original_recover_handler_transitions(
                    flow_graph,
                    *args,
                    **kwargs,
                )

            def trace_resolve_exit_states(transitions, routes, handler_serials):
                resolved = original_resolve_exit_states(
                    transitions,
                    routes,
                    handler_serials,
                )
                graph = trace_context["flow_graph"]
                for transition in resolved:
                    handler_block = graph.get_block(int(transition.handler))
                    if (
                        TRACE_HANDLER_EAS
                        and (
                            handler_block is None
                            or int(handler_block.start_ea) not in TRACE_HANDLER_EAS
                        )
                    ):
                        continue
                    for arm in transition.arms:
                        path_labels = []
                        for serial in arm.ordered_path:
                            block = graph.get_block(int(serial))
                            path_labels.append(
                                f"blk{int(serial)}@0x{int(block.start_ea):X}"
                                if block is not None
                                else f"blk{int(serial)}@?"
                            )
                        matching_routes = [
                            route
                            for route in routes
                            if int(route.source_block_serial) in arm.ordered_path
                            or (
                                route.source_handler_serial is not None
                                and int(route.source_handler_serial)
                                == int(transition.handler)
                            )
                        ]
                        print(
                            "HANDLER_ROUTE",
                            (
                                f"handler=blk{int(transition.handler)}@"
                                f"0x{int(handler_block.start_ea):X}"
                                if handler_block is not None
                                else f"handler=blk{int(transition.handler)}@?"
                            ),
                            f"states={[hex(int(state)) for state in transition.states]}",
                            f"next={None if arm.next_state is None else hex(int(arm.next_state))}",
                            f"branch={arm.branch_block}",
                            f"source_keyed={arm.source_keyed_block}",
                            f"path={path_labels}",
                            "routes="
                            + repr(
                                [
                                    (
                                        int(route.source_block_serial),
                                        hex(int(route.state_constant)),
                                        int(route.target_handler_serial),
                                        route.proof_kind,
                                        route.source_handler_serial,
                                        route.handler_exit_proven,
                                    )
                                    for route in matching_routes
                                ]
                            ),
                            flush=True,
                        )
                return resolved

            emit_module.recover_handler_transitions = (
                trace_recover_handler_transitions
            )
            emit_module.resolve_materialized_handler_exit_states = (
                trace_resolve_exit_states
            )
        cg.install()
        try:
            ida_hexrays.clear_cached_cfuncs()
            first = ida_hexrays.decompile(FUNCTION_EA)
            prepared = int(
                prepare_detached_handler_snippets(
                    FUNCTION_EA,
                    live_mba=None if first is None else first.mba,
                )
            )
            if prepared:
                ida_hexrays.clear_cached_cfuncs()
                final = ida_hexrays.decompile(FUNCTION_EA)
            else:
                final = first
            materialized = cg.is_computed_goto_materialized(FUNCTION_EA)
            resolution = cg._RESOLUTIONS_BY_EA.get(FUNCTION_EA)
            if ORIGIN_OUTPUT and final is not None:
                from d810.hexrays.mutation.detached_handler_island import (
                    imported_detached_snippet_instruction_origins,
                )

                destination = Path(ORIGIN_OUTPUT).resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    json.dumps(
                        [
                            {
                                "imported_ea": f"0x{int(imported_ea):X}",
                                "native_ea": f"0x{int(native_ea):X}",
                            }
                            for imported_ea, native_ea in (
                                imported_detached_snippet_instruction_origins(
                                    final.mba
                                )
                            )
                        ],
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                print("ORIGIN_JSON", destination, flush=True)
            if TRANSFER_OUTPUT:
                from d810.hexrays.preanalysis.indirect_jump_labels import (
                    get_materialized_indirect_transfers,
                )

                destination = Path(TRANSFER_OUTPUT).resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    json.dumps(
                        [
                            {
                                "source_jmp_ea": f"0x{int(transfer.source_jmp_ea):X}",
                                "source_block_ea": f"0x{int(transfer.source_block_ea):X}",
                                "target_eas": [
                                    f"0x{int(target_ea):X}"
                                    for target_ea in transfer.target_eas
                                ],
                                "resolver_kind": transfer.resolver_kind,
                                "source_register_values": [
                                    [int(register), f"0x{int(value):X}"]
                                    for register, value in transfer.source_register_values
                                ],
                                "target_register_values": [
                                    [int(register), f"0x{int(value):X}"]
                                    for register, value in transfer.target_register_values
                                ],
                            }
                            for transfer in get_materialized_indirect_transfers(
                                FUNCTION_EA
                            )
                        ],
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                print("TRANSFER_JSON", destination, flush=True)
            if RESOLUTION_OUTPUT and resolution is not None:
                destination = Path(RESOLUTION_OUTPUT).resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(
                    json.dumps(
                        {
                            "function_ea": int(resolution.function_ea),
                            "jmp_targets": {
                                f"0x{int(jmp_ea):X}": [
                                    f"0x{int(target_ea):X}"
                                    for target_ea in target_eas
                                ]
                                for jmp_ea, target_eas in sorted(
                                    resolution.jmp_targets.items()
                                )
                            },
                            "patch_plans": [
                                {
                                    "jmp_ea": f"0x{int(plan.jmp_ea):X}",
                                    "block_entry": (
                                        f"0x{int(plan.block_entry):X}"
                                    ),
                                    "patch_start": (
                                        f"0x{int(plan.patch_start):X}"
                                    ),
                                    "target_eas": [
                                        f"0x{int(target_ea):X}"
                                        for target_ea in plan.target_eas
                                    ],
                                }
                                for plan in resolution.patch_plans
                            ],
                            "function_context_register_values": [
                                [str(register), f"0x{int(value):X}"]
                                for register, value in (
                                    resolution.function_context_register_values
                                )
                            ],
                        },
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                print("RESOLUTION_JSON", destination, flush=True)
        finally:
            cg.uninstall()
            headless.stop()

    OUTPUT.write_text(_pseudocode(final), encoding="utf-8")
    if CTREE_OUTPUT and final is not None:
        ctree_destination = Path(CTREE_OUTPUT).resolve()
        _write_ctree_statement_anchors(final, ctree_destination)
        print("CTREE_JSON", ctree_destination, flush=True)
    _print_summary(
        first=first,
        final=final,
        prepared=prepared,
        materialized=materialized,
        resolution=resolution,
    )

    if DIAG_OUTPUT:
        from d810.core.diag import find_latest_diag_db_path

        diag_path = find_latest_diag_db_path(FUNCTION_EA)
        if diag_path is not None:
            destination = Path(DIAG_OUTPUT).resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(diag_path, destination)
            print("DIAG_DB", destination, flush=True)
finally:
    idapro.close_database(False)
