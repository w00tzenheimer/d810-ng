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
from collections import Counter
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
PREPARE_ONLY = os.environ.get("RHAD_TRANSFER_PREPARE_ONLY") == "1"
TRACE_BOOTSTRAP_SOURCE = os.environ.get("RHAD_TRANSFER_TRACE_BOOTSTRAP_SOURCE")
TRACE_BOOTSTRAP_STATE = os.environ.get("RHAD_TRANSFER_TRACE_BOOTSTRAP_STATE")
TRACE_BOOTSTRAP_STATE_MREG = os.environ.get("RHAD_TRANSFER_TRACE_BOOTSTRAP_MREG")
TRACE_BOOTSTRAP_HANDLER_EAS = frozenset(
    int(item.strip(), 0)
    for item in os.environ.get("RHAD_TRANSFER_TRACE_BOOTSTRAP_HANDLER_EAS", "").split(
        ","
    )
    if item.strip()
)
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
TRACE_ROUTE_BUILD = os.environ.get("RHAD_TRANSFER_TRACE_ROUTE_BUILD") == "1"
TRACE_SESSION_STATE = os.environ.get("RHAD_TRANSFER_TRACE_SESSION_STATE") == "1"
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


def _write_transfer_inventory(state: object | None, destination: Path) -> None:
    """Write only portable resolver evidence, without retaining live MBA state."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(
            [
                {
                    "source_jmp_ea": f"0x{int(transfer.source_jmp_ea):X}",
                    "source_block_ea": f"0x{int(transfer.source_block_ea):X}",
                    "target_eas": [
                        f"0x{int(target_ea):X}" for target_ea in transfer.target_eas
                    ],
                    "resolver_kind": transfer.resolver_kind,
                    "selector_state_var_reg": transfer.selector_state_var_reg,
                    "selector_state_constant": (
                        None
                        if transfer.selector_state_constant is None
                        else f"0x{int(transfer.selector_state_constant):X}"
                    ),
                    "selector_compare_constant": (
                        None
                        if transfer.selector_compare_constant is None
                        else f"0x{int(transfer.selector_compare_constant):X}"
                    ),
                    "condition_code": transfer.condition_code,
                    "true_target_ea": (
                        None
                        if transfer.true_target_ea is None
                        else f"0x{int(transfer.true_target_ea):X}"
                    ),
                    "false_target_ea": (
                        None
                        if transfer.false_target_ea is None
                        else f"0x{int(transfer.false_target_ea):X}"
                    ),
                    "source_register_values": [
                        [int(register), f"0x{int(value):X}"]
                        for register, value in transfer.source_register_values
                    ],
                    "target_register_values": [
                        [int(register), f"0x{int(value):X}"]
                        for register, value in transfer.target_register_values
                    ],
                }
                for transfer in (() if state is None else state.materialized_transfers)
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _trace_static_bootstrap_route(state: object | None) -> None:
    """Print the native dispatcher answer used by bootstrap discovery, if asked."""
    if (
        state is None
        or TRACE_BOOTSTRAP_SOURCE is None
        or TRACE_BOOTSTRAP_STATE is None
        or TRACE_BOOTSTRAP_STATE_MREG is None
    ):
        return
    from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
        _bootstrap_native_replay_inputs,
        _resolve_concrete_dispatch_corridor,
    )

    source_ea = int(TRACE_BOOTSTRAP_SOURCE, 0)
    state_value = int(TRACE_BOOTSTRAP_STATE, 0)
    state_mreg = int(TRACE_BOOTSTRAP_STATE_MREG, 0)
    transfers = tuple(state.materialized_transfers)
    context_mregs, register_snapshots_by_ea, dispatch_anchor_eas = (
        _bootstrap_native_replay_inputs(transfers)
    )
    initial_mregs = dict(context_mregs)
    initial_mregs[state_mreg] = state_value
    target = _resolve_concrete_dispatch_corridor(
        source_ea,
        initial_mregs=initial_mregs,
        handler_eas=TRACE_BOOTSTRAP_HANDLER_EAS,
        register_snapshots_by_ea=register_snapshots_by_ea,
        dispatch_anchor_eas=dispatch_anchor_eas,
        return_first_indirect_target=not TRACE_BOOTSTRAP_HANDLER_EAS,
    )
    print(
        "BOOTSTRAP_NATIVE_ROUTE",
        f"source=0x{source_ea:X}",
        f"state_mreg={state_mreg}",
        f"state=0x{state_value:X}",
        f"handler_eas={[hex(ea) for ea in sorted(TRACE_BOOTSTRAP_HANDLER_EAS)]}",
        f"target={None if target is None else hex(int(target))}",
        flush=True,
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
        function_extended = bool(ida_funcs.set_func_end(FUNCTION_EA, FUNCTION_END))
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
        from d810.hexrays.preanalysis.flowchart_preanalysis import (
            register_flowchart_preanalysis_handler,
            unregister_flowchart_preanalysis_handler,
        )
        import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg
        from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
            resolver_session_state,
        )
        from session_probe_evidence import (
            capture_preopt_union_preparation,
            latest_preopt_union_preparation,
            native_preanalysis_boundary_port_count,
        )

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        if TRACE_ROUTE_BUILD:
            import d810.optimizers.microcode.flow.flattening.state_machine_cff_unflattener as unflat_module

            original_build_materialized_state_routes = (
                unflat_module._build_materialized_state_routes
            )
            original_project_materialized_state_routes = (
                unflat_module._portable_materialized_state_route_evidence
            )
            original_rebind_materialized_state_routes = (
                unflat_module._rebind_portable_materialized_state_routes
            )

            def identity_label(identity):
                if identity is None:
                    return None
                intervals = identity.native_eas.intervals
                return "+".join(
                    f"0x{int(interval.start_ea):X}-0x{int(interval.end_ea):X}"
                    for interval in intervals
                )

            def live_route_label(route, flow_graph):
                def block_label(serial):
                    block = flow_graph.get_block(int(serial))
                    return (
                        f"blk{int(serial)}@0x{int(block.start_ea):X}"
                        if block is not None
                        else f"terminal@0x{int(route.target_native_ea or 0):X}"
                    )

                return {
                    "source": block_label(route.source_block_serial),
                    "state": f"0x{int(route.state_constant):08X}",
                    "target": block_label(route.target_handler_serial),
                    "source_handler": (
                        None
                        if route.source_handler_serial is None
                        else block_label(route.source_handler_serial)
                    ),
                    "source_native_ea": (
                        None
                        if route.source_native_ea is None
                        else f"0x{int(route.source_native_ea):X}"
                    ),
                    "target_native_ea": (
                        None
                        if route.target_native_ea is None
                        else f"0x{int(route.target_native_ea):X}"
                    ),
                    "proof_kind": route.proof_kind,
                }

            def portable_route_label(route):
                return {
                    "source": identity_label(route.source_identity),
                    "state": f"0x{int(route.state_constant):08X}",
                    "target": identity_label(route.target_identity),
                    "source_handler": identity_label(route.source_handler_identity),
                    "source_handler_region": identity_label(
                        route.source_handler_region_identity
                    ),
                    "source_native_ea": (
                        None
                        if route.source_native_ea is None
                        else f"0x{int(route.source_native_ea):X}"
                    ),
                    "target_native_ea": (
                        None
                        if route.target_native_ea is None
                        else f"0x{int(route.target_native_ea):X}"
                    ),
                    "proof_kind": route.proof_kind,
                }

            def trace_build_materialized_state_routes(flow_graph, *args, **kwargs):
                handler_states = kwargs.get("handler_states") or {}
                transfers = tuple(kwargs.get("transfers") or ())

                def block_label(serial):
                    block = flow_graph.get_block(int(serial))
                    return (
                        f"blk{int(serial)}@0x{int(block.start_ea):X}"
                        if block is not None
                        else f"blk{int(serial)}@?"
                    )

                print(
                    "ROUTE_BUILD_INPUT",
                    f"handler_state_sources={len(handler_states)}",
                    f"handler_state_pairs={sum(len(states) for states in handler_states.values())}",
                    "handler_state_fanout="
                    + repr(
                        [
                            (block_label(serial), len(states))
                            for serial, states in sorted(handler_states.items())
                            if len(states) > 1
                        ]
                    ),
                    "transfer_kinds="
                    + repr(sorted(Counter(t.resolver_kind for t in transfers).items())),
                    flush=True,
                )
                routes = original_build_materialized_state_routes(
                    flow_graph,
                    *args,
                    **kwargs,
                )
                source_handler_counts = Counter(
                    route.source_handler_serial
                    for route in routes
                    if route.source_handler_serial is not None
                )
                print(
                    "ROUTE_BUILD_OUTPUT",
                    f"routes={len(routes)}",
                    "proof_kinds="
                    + repr(
                        sorted(Counter(route.proof_kind for route in routes).items())
                    ),
                    "source_handler_routes="
                    + repr(
                        [
                            (block_label(serial), count)
                            for serial, count in sorted(source_handler_counts.items())
                        ]
                    ),
                    flush=True,
                )
                return routes

            unflat_module._build_materialized_state_routes = (
                trace_build_materialized_state_routes
            )

            def trace_project_materialized_state_routes(
                routes, identity_index, *args, **kwargs
            ):
                projected = original_project_materialized_state_routes(
                    routes, identity_index, *args, **kwargs
                )
                terminal_routes = tuple(
                    route
                    for route in routes
                    if route.proof_kind == "terminal_state_route"
                )
                if terminal_routes:
                    print(
                        "PORTABLE_TERMINAL_PROJECT",
                        "live="
                        + repr(
                            [
                                (
                                    live_route_label(route, kwargs.get("flow_graph"))
                                    if kwargs.get("flow_graph") is not None
                                    else {
                                        "source_identity": identity_label(
                                            identity_index.identity_for_serial(
                                                route.source_block_serial
                                            )
                                        ),
                                        "state": f"0x{int(route.state_constant):08X}",
                                        "source_native_ea": route.source_native_ea,
                                        "target_native_ea": route.target_native_ea,
                                    }
                                )
                                for route in terminal_routes
                            ]
                        ),
                        "portable="
                        + repr(
                            [
                                portable_route_label(route)
                                for route in projected
                                if route.proof_kind == "terminal_state_route"
                            ]
                        ),
                        flush=True,
                    )
                return projected

            def trace_rebind_materialized_state_routes(
                evidence, identity_index, *args, **kwargs
            ):
                rebound = original_rebind_materialized_state_routes(
                    evidence, identity_index, *args, **kwargs
                )
                terminal_evidence = tuple(
                    route
                    for route in evidence
                    if route.proof_kind == "terminal_state_route"
                )
                if terminal_evidence:
                    print(
                        "PORTABLE_TERMINAL_REBIND",
                        "portable="
                        + repr(
                            [portable_route_label(route) for route in terminal_evidence]
                        ),
                        "rebound="
                        + repr(
                            [
                                live_route_label(route, kwargs["flow_graph"])
                                for route in rebound
                                if route.proof_kind == "terminal_state_route"
                            ]
                        ),
                        flush=True,
                    )
                return rebound

            unflat_module._portable_materialized_state_route_evidence = (
                trace_project_materialized_state_routes
            )
            unflat_module._rebind_portable_materialized_state_routes = (
                trace_rebind_materialized_state_routes
            )
        if TRACE_SESSION_STATE:
            manager_lifecycle = headless._state.manager.decompilation_lifecycle
            hook_lifecycle = (
                headless._state.manager.hx_decompiler_hook._decompilation_lifecycle
            )
            print(
                "RESOLVER_LIFECYCLE_PORTS",
                f"manager_id={id(manager_lifecycle)}",
                f"hook_id={id(hook_lifecycle)}",
                f"same={manager_lifecycle is hook_lifecycle}",
                flush=True,
            )
            coordinator_type = type(manager_lifecycle)
            original_ensure_hexrays_session = coordinator_type.ensure_hexrays_session

            def trace_ensure_hexrays_session(self, **kwargs):
                session, created = original_ensure_hexrays_session(self, **kwargs)
                print(
                    "RESOLVER_SESSION_ENSURE",
                    f"kwargs={kwargs}",
                    f"session_id={id(session)}",
                    f"created={created}",
                    "active="
                    + repr(
                        [
                            (
                                f"0x{int(activation.session.function_ea):X}",
                                id(activation.session),
                                bool(activation.owns_session),
                            )
                            for activation in self._active_sessions
                        ]
                    ),
                    flush=True,
                )
                return session, created

            coordinator_type.ensure_hexrays_session = trace_ensure_hexrays_session
            from d810.manager.decompilation_lifecycle import (
                DecompilationLifecycleCoordinator,
            )

            original_finish_hexrays_session = (
                DecompilationLifecycleCoordinator.finish_hexrays_session
            )

            def trace_finish_hexrays_session(self):
                active = [
                    (
                        f"0x{int(activation.session.function_ea):X}",
                        bool(activation.owns_session),
                        int(activation.session.native_preanalysis_depth),
                    )
                    for activation in self._active_sessions
                ]
                print("RESOLVER_SESSION_FINISH_BEFORE", active, flush=True)
                result = original_finish_hexrays_session(self)
                print(
                    "RESOLVER_SESSION_FINISH_AFTER",
                    [
                        (
                            f"0x{int(activation.session.function_ea):X}",
                            bool(activation.owns_session),
                            int(activation.session.native_preanalysis_depth),
                        )
                        for activation in self._active_sessions
                    ],
                    flush=True,
                )
                return result

            DecompilationLifecycleCoordinator.finish_hexrays_session = (
                trace_finish_hexrays_session
            )
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
                    if TRACE_HANDLER_EAS and (
                        handler_block is None
                        or int(handler_block.start_ea) not in TRACE_HANDLER_EAS
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

            emit_module.recover_handler_transitions = trace_recover_handler_transitions
            emit_module.resolve_materialized_handler_exit_states = (
                trace_resolve_exit_states
            )
        observed_resolver_state: list[object] = []
        observed_preopt_union_preparation: list[object] = []
        observed_session_states: set[int] = set()

        if TRACE_SESSION_STATE:
            original_prepare_detached_handler_snippets = (
                cg.prepare_detached_handler_snippets
            )
            original_discover_static_native_bootstrap_routes = (
                cg._discover_static_native_bootstrap_routes
            )
            original_static_native_bootstrap_route_candidates = (
                cg._static_native_bootstrap_route_candidates
            )
            original_static_native_handler_entry_eas = (
                cg._static_native_handler_entry_eas
            )

            def trace_prepare_detached_handler_snippets(state):
                print(
                    "RESOLVER_PREPARE_INPUT",
                    f"state_id={id(state)}",
                    f"materialization={state.materialization is not None}",
                    f"materialized={bool(state.materialized)}",
                    f"transfers={len(state.materialized_transfers)}",
                    flush=True,
                )
                return original_prepare_detached_handler_snippets(state)

            cg.prepare_detached_handler_snippets = (
                trace_prepare_detached_handler_snippets
            )

            def trace_static_native_handler_entry_eas(graph, dispatcher_blocks):
                handler_eas = original_static_native_handler_entry_eas(
                    graph,
                    dispatcher_blocks,
                )
                print(
                    "BOOTSTRAP_DISCOVERY_HANDLERS",
                    f"dispatcher_blocks={len(dispatcher_blocks)}",
                    f"handlers={[hex(int(ea)) for ea in sorted(handler_eas)]}",
                    flush=True,
                )
                return handler_eas

            def trace_static_native_bootstrap_route_candidates(
                graph,
                transfers,
                *,
                native_route_resolver=None,
            ):
                corridor = [
                    (
                        int(serial),
                        int(graph.get_block(int(serial)).start_ea),
                        (
                            None
                            if graph.get_block(int(serial)).tail is None
                            else int(graph.get_block(int(serial)).tail.ea)
                        ),
                        len(graph.get_block(int(serial)).succs),
                    )
                    for serial in cg._native_entry_corridor_serials(graph)
                ]
                print(
                    "BOOTSTRAP_DISCOVERY_CORRIDOR",
                    "blocks="
                    + repr(
                        [
                            (
                                serial,
                                hex(start_ea),
                                None if tail_ea is None else hex(tail_ea),
                                successor_count,
                            )
                            for serial, start_ea, tail_ea, successor_count in corridor
                        ]
                    ),
                    flush=True,
                )
                candidates = original_static_native_bootstrap_route_candidates(
                    graph,
                    transfers,
                    native_route_resolver=native_route_resolver,
                )
                print(
                    "BOOTSTRAP_DISCOVERY_CANDIDATES",
                    f"entry_serial={int(graph.entry_serial)}",
                    "candidates="
                    + repr(
                        [
                            tuple(hex(int(item)) for item in candidate)
                            for candidate in candidates
                        ]
                    ),
                    flush=True,
                )
                return candidates

            def trace_discover_static_native_bootstrap_routes(*, mba, decision, state):
                print(
                    "BOOTSTRAP_DISCOVERY_INPUT",
                    f"entry=0x{int(getattr(mba, 'entry_ea', 0)):X}",
                    f"transfers={len(state.materialized_transfers)}",
                    f"generation={int(state.evidence_generation)}",
                    flush=True,
                )
                cg._static_native_handler_entry_eas = (
                    trace_static_native_handler_entry_eas
                )
                cg._static_native_bootstrap_route_candidates = (
                    trace_static_native_bootstrap_route_candidates
                )
                try:
                    discovered = original_discover_static_native_bootstrap_routes(
                        mba=mba,
                        decision=decision,
                        state=state,
                    )
                finally:
                    cg._static_native_handler_entry_eas = (
                        original_static_native_handler_entry_eas
                    )
                    cg._static_native_bootstrap_route_candidates = (
                        original_static_native_bootstrap_route_candidates
                    )
                print(
                    "BOOTSTRAP_DISCOVERY_RESULT",
                    f"discovered={bool(discovered)}",
                    f"routes={len(state.native_preanalysis.bootstrap_routes)}",
                    flush=True,
                )
                return discovered

            cg._discover_static_native_bootstrap_routes = (
                trace_discover_static_native_bootstrap_routes
            )

        def observe_resolver_state(
            *, function_ea: int, mba: object, decision: dict
        ) -> None:
            if int(function_ea) != FUNCTION_EA:
                return
            session = decision.get("session")
            if session is not None:
                state = resolver_session_state(session)
                observed_resolver_state[:] = [state]
                capture_preopt_union_preparation(
                    state,
                    observed_preopt_union_preparation,
                )
                if TRACE_SESSION_STATE and id(state) not in observed_session_states:
                    observed_session_states.add(id(state))
                    print(
                        "RESOLVER_SESSION_FLOWCHART",
                        f"entry=0x{int(getattr(mba, 'entry_ea', 0)):X}",
                        f"session_id={id(session)}",
                        f"state_id={id(state)}",
                        f"session={session.identity_key}",
                        "resolver_attachment="
                        f"{type(session.resolver_attachment).__name__}",
                        f"materialization={state.materialization is not None}",
                        f"materialized={bool(state.materialized)}",
                        f"transfers={len(state.materialized_transfers)}",
                        f"evidence_generation={int(state.evidence_generation)}",
                        flush=True,
                    )

        cg.install()
        register_flowchart_preanalysis_handler(
            "rhad.transfer_function.capture_session",
            observe_resolver_state,
        )
        try:
            prepared = headless.prepare_native_preanalysis(FUNCTION_EA)
            if TRACE_SESSION_STATE:
                lifecycle = headless._state.manager.decompilation_lifecycle
                active_session = lifecycle.current_session(FUNCTION_EA)
                prepared_state = (
                    None
                    if active_session is None
                    else resolver_session_state(active_session)
                )
                print(
                    "RESOLVER_SESSION_PREPARED",
                    f"prepared={prepared}",
                    f"session_id={None if active_session is None else id(active_session)}",
                    f"state_id={None if prepared_state is None else id(prepared_state)}",
                    f"session={None if active_session is None else active_session.identity_key}",
                    "resolver_attachment="
                    f"{None if active_session is None else type(active_session.resolver_attachment).__name__}",
                    f"materialization={prepared_state is not None and prepared_state.materialization is not None}",
                    f"materialized={False if prepared_state is None else bool(prepared_state.materialized)}",
                    f"transfers={0 if prepared_state is None else len(prepared_state.materialized_transfers)}",
                    flush=True,
                )
            if PREPARE_ONLY:
                lifecycle = headless._state.manager.decompilation_lifecycle
                session = lifecycle.current_session(FUNCTION_EA)
                state = None if session is None else resolver_session_state(session)
            else:
                ida_hexrays.clear_cached_cfuncs()
                first = headless.decompile(FUNCTION_EA)
                final = first
                state = observed_resolver_state[0] if observed_resolver_state else None
                if TRACE_SESSION_STATE and state is not None:
                    native_state = state.native_preanalysis
                    lifecycle = headless._state.manager.decompilation_lifecycle
                    active_session = lifecycle.current_session(FUNCTION_EA)
                    print(
                        "RESOLVER_SESSION_AFTER_DECOMPILE",
                        f"session_active={active_session is not None}",
                        f"evidence_generation={int(native_state.evidence_generation)}",
                        "normalization_published_postvalidated_generation="
                        f"{native_state.normalization_published_postvalidated_generation}",
                        f"redo_generation={native_state.redo_generation}",
                        "pending_generated_restart_generation="
                        f"{native_state.pending_generated_restart_generation}",
                        flush=True,
                    )
            union_preparation = latest_preopt_union_preparation(
                state,
                observed_preopt_union_preparation,
            )
            print(
                "PREOPT_UNION_RESULT",
                "prepared="
                f"{union_preparation is not None and union_preparation.prepared}",
                (
                    "primary=None"
                    if union_preparation is None
                    or union_preparation.primary_seed_ea is None
                    else f"primary=0x{union_preparation.primary_seed_ea:X}"
                ),
                (
                    "ports=0"
                    if union_preparation is None
                    else f"ports={native_preanalysis_boundary_port_count(state)}"
                ),
                flush=True,
            )
            materialized = False if state is None else state.is_materialized
            resolution = (
                None
                if state is None
                else state.portable_evidence.computed_goto_resolution
            )
            _trace_static_bootstrap_route(state)
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
                                imported_detached_snippet_instruction_origins(final.mba)
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
                destination = Path(TRANSFER_OUTPUT).resolve()
                _write_transfer_inventory(state, destination)
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
                                    f"0x{int(target_ea):X}" for target_ea in target_eas
                                ]
                                for jmp_ea, target_eas in sorted(
                                    resolution.jmp_targets.items()
                                )
                            },
                            "patch_plans": [
                                {
                                    "jmp_ea": f"0x{int(plan.jmp_ea):X}",
                                    "block_entry": (f"0x{int(plan.block_entry):X}"),
                                    "patch_start": (f"0x{int(plan.patch_start):X}"),
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
                            "conditional_state_choices": [
                                {
                                    "source_jmp_ea": (
                                        f"0x{int(choice.source_jmp_ea):X}"
                                    ),
                                    "source_block_ea": (
                                        f"0x{int(choice.source_block_ea):X}"
                                    ),
                                    "condition_code": choice.condition_code,
                                    "selector_state_var_reg": (
                                        choice.selector_state_var_reg
                                    ),
                                    "predicate_true_state": (
                                        None
                                        if choice.predicate_true_state is None
                                        else f"0x{int(choice.predicate_true_state):X}"
                                    ),
                                    "predicate_false_state": (
                                        None
                                        if choice.predicate_false_state is None
                                        else f"0x{int(choice.predicate_false_state):X}"
                                    ),
                                    "resolver_kind": choice.resolver_kind,
                                }
                                for choice in resolution.conditional_state_choices
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
            unregister_flowchart_preanalysis_handler(
                "rhad.transfer_function.capture_session"
            )
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
