"""Probe PREOPT detached-range import into a live top-level Rhad MBA.

This is an investigation harness, not production profile logic.  Run it only
against a disposable copy because the computed-goto resolver patches the input
database's native bytes.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil

import idapro


BIN = Path(
    os.environ.get("RHAD_PREOPT_BIN", ".tmp/rhad_preopt_probe.bin")
).resolve()
FUNC_EA = 0x40A560
TAIL_START = 0x40B9A6
TAIL_END = 0x40BB75
DIAG_OUTPUT = os.environ.get("RHAD_PREOPT_DIAG_OUTPUT")
IMPORT_ALL_PREPARED = os.environ.get("RHAD_PREOPT_IMPORT_ALL") == "1"


assert idapro.open_database(str(BIN), True) == 0
try:
    import ida_hexrays
    import idaapi

    import d810.headless as headless
    import d810.hexrays.mutation.detached_handler_island as detached_island
    from d810.hexrays.mutation.detached_handler_island import (
        clear_detached_handler_call_templates,
        find_unique_live_block_by_ea,
        imported_detached_snippet_instruction_origins,
        imported_detached_snippet_target_eas,
        materialize_detached_snippet_templates,
        safe_verify,
    )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
    from d810.hexrays.preanalysis.indirect_jump_labels import (
        get_materialized_indirect_transfers,
    )
    from d810.optimizers.microcode.flow.jumps import computed_goto_resolver as cg
    from d810.optimizers.microcode.flow.jumps import (
        materialized_computed_goto_island as island,
    )

    idaapi.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    headless.configure(project="default_unflattening_ollvm.json")
    headless.start()
    cg.install()
    try:
        resolution = cg.resolve_and_materialize(FUNC_EA)
        assert resolution is not None
        # Direct invocation bypasses the flowchart hook that normally creates
        # the staged CALLS session.  Recreate only that bookkeeping so this
        # harness exercises the real multi-pass preanalysis callbacks.
        cg._RESOLUTIONS_BY_EA[FUNC_EA] = resolution
        cg._MATERIALIZATION_SESSIONS[FUNC_EA] = cg._MaterializationSession(
            resolution
        )
        transfers = get_materialized_indirect_transfers(FUNC_EA)
        print(
            "RESOLVER",
            f"sites={resolution.site_count}",
            f"targets={resolution.target_count}",
            f"transfers={len(transfers)}",
            flush=True,
        )

        clear_detached_handler_call_templates()

        def plan_entry_bridge(mba, current_transfers):
            from d810.analyses.control_flow.dispatcher_recovery import (
                recover_dispatcher,
            )
            from d810.analyses.control_flow.residual_entry_bridge import (
                plan_residual_entry_bridge,
            )
            from d810.backends.hexrays.evidence.residual_entry_bridge import (
                recognize_residual_entry_bridge,
                recover_initial_state_write,
                recover_state_routing_nodes,
            )
            from d810.hexrays.mutation.ir_translator import lift

            evidence = recognize_residual_entry_bridge(mba)
            if evidence is None:
                return None
            graph = lift(mba)
            recovery = recover_dispatcher(
                graph,
                None,
                materialized_indirect_transfers=current_transfers,
            )
            if recovery.dispatch_map is None or recovery.state_var_reg is None:
                return None
            routing_nodes = recover_state_routing_nodes(
                mba,
                state_register=int(recovery.state_var_reg),
                after_ea=int(evidence.source_store_ea),
                before_ea=int(evidence.source_store_ea) + 0x100,
                transfers=current_transfers,
            )
            if not routing_nodes:
                return None
            initial_state = recover_initial_state_write(
                mba,
                state_register=int(recovery.state_var_reg),
                after_ea=int(evidence.source_store_ea),
                before_ea=min(node.source_block_ea for node in routing_nodes),
            )
            if initial_state is None:
                return None
            handler_serial = recovery.dispatch_map.resolve_target(
                int(evidence.taken_state_constant)
            )
            handler = (
                graph.get_block(handler_serial)
                if handler_serial is not None
                else None
            )
            if handler is None:
                return None
            residual_target = cg._exact_equality_native_target(
                current_transfers,
                int(evidence.fallthrough_state_constant),
            )
            if residual_target is None:
                return None
            plan = plan_residual_entry_bridge(
                evidence=evidence,
                initial_state=int(initial_state),
                routing_nodes=routing_nodes,
                live_state_targets={
                    int(evidence.taken_state_constant): int(handler.start_ea)
                },
                residual_state_targets={
                    int(evidence.fallthrough_state_constant): int(residual_target)
                },
                required_patch_size=11,
            )
            return None if plan is None else (evidence, plan)

        captured_entry_result: list[tuple[object, object, int]] = []
        original_native_entry_bridge = cg._materialize_residual_entry_bridge

        def capture_entry_bridge_without_native_patch(
            _resolution,
            current_transfers,
            mba,
        ):
            result = plan_entry_bridge(mba, current_transfers)
            print(
                "CALLS_ENTRY_PLAN",
                f"captured={result is not None}",
                f"result={result}",
                flush=True,
            )
            if result is None:
                return (0, ())
            evidence, plan = result
            predicate_ida_stkoff = int(
                mba.stkoff_vd2ida(int(evidence.predicate_stack_identity[0]))
            )
            captured_entry_result[:] = [
                (evidence, plan, predicate_ida_stkoff)
            ]
            # Report one staged change to exercise the ordinary MERR_LOOP redo,
            # but publish no native-patch transfer.  The next PREOPT callback
            # consumes the portable plan and performs the logical-CFG rewrite.
            return (1, ())

        cg._materialize_residual_entry_bridge = (
            capture_entry_bridge_without_native_patch
        )

        class PreoptImportProbe(ida_hexrays.Hexrays_Hooks):
            def __init__(self) -> None:
                super().__init__()
                self.preopt_callbacks = 0
                self.calls_callbacks = 0
                self.entry_bridges = 0

            def preoptimized(self, mba):
                if int(mba.entry_ea) != FUNC_EA:
                    return 0
                self.preopt_callbacks += 1
                entry_result = (
                    captured_entry_result[0]
                    if captured_entry_result
                    else None
                )
                entry_evidence = (
                    None if entry_result is None else entry_result[0]
                )
                entry_plan = None if entry_result is None else entry_result[1]
                predicate_ida_stkoff = (
                    None if entry_result is None else int(entry_result[2])
                )
                current_transfers = get_materialized_indirect_transfers(
                    FUNC_EA
                )
                imported_count = 0
                if entry_result is not None:
                    if IMPORT_ALL_PREPARED:
                        prepared_targets = tuple(
                            sorted(
                                target_ea
                                for function_ea, target_ea in detached_island._DETACHED_SNIPPET_TEMPLATES
                                if int(function_ea) == FUNC_EA
                            )
                        )
                        imported_count = len(
                            materialize_detached_snippet_templates(
                                mba,
                                FUNC_EA,
                                prepared_targets,
                                expected_template_maturity=(
                                    ida_hexrays.MMAT_PREOPTIMIZED
                                ),
                                allow_raw_preopt_calls=True,
                                import_native_preopt_ranges=True,
                            )
                        )
                    else:
                        imported_count = island._materialize_missing_detached_snippets(
                            mba,
                            current_transfers,
                            require_live_residual_source=False,
                            expected_template_maturity=(
                                ida_hexrays.MMAT_PREOPTIMIZED
                            ),
                            allow_raw_preopt_calls=True,
                            import_native_preopt_ranges=True,
                        )
                imported_targets = imported_detached_snippet_target_eas(mba)
                entry_bridge = 0
                seeded_anchor = 0
                bridge_diagnostic: tuple[object, ...] = ()
                if (
                    entry_evidence is not None
                    and entry_plan is not None
                    and predicate_ida_stkoff is not None
                ):
                    source = find_unique_live_block_by_ea(
                        mba,
                        int(entry_plan.anchor_ea),
                    )
                    true_target = find_unique_live_block_by_ea(
                        mba,
                        int(entry_plan.true_target_ea),
                    )
                    false_target = find_unique_live_block_by_ea(
                        mba,
                        int(entry_plan.false_target_ea),
                    )
                    if (
                        source is not None
                        and int(source.nsucc()) == 0
                        and true_target is not None
                        and false_target is not None
                    ):
                        seed_modifier = DeferredGraphModifier(mba)
                        seed_modifier.queue_terminal_goto_change(
                            block_serial=int(source.serial),
                            goto_target=int(true_target.serial),
                            description=(
                                f"PREOPT proven entry anchor 0x{int(entry_plan.anchor_ea):X} "
                                f"-> 0x{int(entry_plan.true_target_ea):X}"
                            ),
                            priority=5,
                        )
                        seeded_anchor = int(
                            seed_modifier.apply(
                                defer_post_apply_maintenance=True
                            )
                        )
                        source = find_unique_live_block_by_ea(
                            mba,
                            int(entry_plan.anchor_ea),
                        )
                        true_target = find_unique_live_block_by_ea(
                            mba,
                            int(entry_plan.true_target_ea),
                        )
                        false_target = find_unique_live_block_by_ea(
                            mba,
                            int(entry_plan.false_target_ea),
                        )
                    bridge_diagnostic = (
                        (
                            None
                            if source is None
                            else f"blk{int(source.serial)}@0x{int(entry_plan.anchor_ea):X}"
                        ),
                        None if source is None else int(source.nsucc()),
                        (
                            None
                            if source is None or source.tail is None
                            else hex(int(source.tail.ea))
                        ),
                        (
                            None
                            if true_target is None
                            else f"blk{int(true_target.serial)}@0x{int(entry_plan.true_target_ea):X}"
                        ),
                        (
                            None
                            if false_target is None
                            else f"blk{int(false_target.serial)}@0x{int(entry_plan.false_target_ea):X}"
                        ),
                    )
                    if (
                        source is not None
                        and source.tail is not None
                        and true_target is not None
                        and false_target is not None
                        and int(source.nsucc()) in (1, 2)
                    ):
                        predicate_vd_stkoff = int(
                            mba.stkoff_ida2vd(predicate_ida_stkoff)
                        )
                        condition = ida_hexrays.mop_t()
                        condition.make_stkvar(mba, predicate_vd_stkoff)
                        condition.size = int(
                            entry_evidence.predicate_stack_identity[1]
                        )
                        rewrite_ea = int(source.head.ea)
                        nonzero_true_target = (
                            true_target
                            if int(entry_evidence.condition_code) == 5
                            else false_target
                        )
                        nonzero_false_target = (
                            false_target
                            if int(entry_evidence.condition_code) == 5
                            else true_target
                        )
                        modifier = DeferredGraphModifier(mba)
                        modifier.queue_lower_conditional_state_transition(
                            source_serial=int(source.serial),
                            old_dispatcher_serial=int(source.succset[0]),
                            rewrite_from_ea=rewrite_ea,
                            condition_operand=condition,
                            false_target_serial=int(
                                nonzero_false_target.serial
                            ),
                            true_target_serial=int(
                                nonzero_true_target.serial
                            ),
                            proof_id=(
                                f"preopt_entry_bridge:0x{int(entry_evidence.predicate_ea):X}"
                            ),
                            description=(
                                f"PREOPT entry bridge 0x{int(entry_evidence.predicate_ea):X} "
                                f"at 0x{int(entry_plan.anchor_ea):X} -> "
                                f"0x{int(entry_plan.false_target_ea):X}/"
                                f"0x{int(entry_plan.true_target_ea):X}"
                            ),
                            rule_priority=1000,
                        )
                        entry_bridge = int(
                            modifier.apply(defer_post_apply_maintenance=True)
                        )
                        self.entry_bridges += int(entry_bridge)
                residual_routes = island._apply_residual_state_route_bridges(
                    mba,
                    current_transfers,
                )
                terminal_routes = island._apply_detached_snippet_terminal_routes(
                    mba,
                    current_transfers,
                )
                verified = safe_verify(
                    mba,
                    "PREOPT detached snippet probe",
                    logger_func=print,
                )
                print(
                    "PREOPT_IMPORT",
                    f"callback={self.preopt_callbacks}",
                    f"qty={int(mba.qty)}",
                    f"imported_count={imported_count}",
                    f"imported_targets={[hex(ea) for ea in imported_targets]}",
                    f"entry_plan={entry_plan}",
                    f"bridge_diagnostic={bridge_diagnostic}",
                    f"seeded_anchor={seeded_anchor}",
                    f"entry_bridge={entry_bridge}",
                    f"residual_routes={residual_routes}",
                    f"terminal_routes={terminal_routes}",
                    f"verified={verified}",
                    flush=True,
                )
                return 0

            def calls_done(self, mba):
                if int(mba.entry_ea) != FUNC_EA:
                    return 0
                self.calls_callbacks += 1
                origins = dict(
                    imported_detached_snippet_instruction_origins(mba)
                )
                rows: list[tuple[object, ...]] = []
                for serial in range(int(mba.qty)):
                    block = mba.get_mblock(serial)
                    instruction = block.head
                    while instruction is not None:
                        native_ea = origins.get(int(instruction.ea))
                        if (
                            native_ea is not None
                            and TAIL_START <= native_ea < TAIL_END
                            and int(instruction.opcode)
                            in (
                                int(ida_hexrays.m_call),
                                int(ida_hexrays.m_icall),
                            )
                        ):
                            rows.append(
                                (
                                    f"blk{int(block.serial)}@0x{native_ea:X}",
                                    f"call@0x{native_ea:X}",
                                    f"flags=0x{int(block.flags):X}",
                                    f"d={int(instruction.d.t)}",
                                    f"arglist={bool(instruction.d.is_arglist())}",
                                )
                            )
                        if instruction is block.tail:
                            break
                        instruction = instruction.next
                verified = safe_verify(
                    mba,
                    "CALLS detached snippet probe",
                    logger_func=print,
                )
                print(
                    "CALLS_IMPORT",
                    f"callback={self.calls_callbacks}",
                    f"qty={int(mba.qty)}",
                    f"calls={rows}",
                    f"verified={verified}",
                    flush=True,
                )
                return 0

        hook = PreoptImportProbe()
        hook.hook()
        try:
            ida_hexrays.clear_cached_cfuncs()
            cfunc = None
            last_failure = ""
            for attempt in range(1, 7):
                if attempt > 1:
                    ida_hexrays.clear_cached_cfuncs()
                decompile_failure = ida_hexrays.hexrays_failure_t()
                cfunc = ida_hexrays.decompile_func(
                    idaapi.get_func(FUNC_EA),
                    decompile_failure,
                    ida_hexrays.DECOMP_NO_CACHE,
                )
                last_failure = decompile_failure.desc()
                fixed_point = FUNC_EA in cg._MATERIALIZED_EAS
                prepared = (
                    cg.prepare_detached_handler_snippets(
                        FUNC_EA,
                        live_mba=cfunc.mba,
                        template_maturity=ida_hexrays.MMAT_PREOPTIMIZED,
                    )
                    if cfunc is not None and not fixed_point
                    else 0
                )
                print(
                    "DECOMPILE",
                    f"attempt={attempt}",
                    f"ok={cfunc is not None}",
                    f"failure={last_failure!r}",
                    f"entry_bridges={hook.entry_bridges}",
                    f"fixed_point={fixed_point}",
                    f"prepared={prepared}",
                    flush=True,
                )
                if (
                    cfunc is not None
                    and hook.entry_bridges > 0
                    and fixed_point
                ):
                    break
            if cfunc is not None:
                pseudocode = "\n".join(
                    idaapi.tag_remove(str(line.line))
                    for line in cfunc.get_pseudocode()
                )
                print(
                    "PSEUDOCODE",
                    f"lines={len(pseudocode.splitlines())}",
                    f"while1={pseudocode.count('while ( 1 )') + pseudocode.count('while (1)')}",
                    f"calls={pseudocode.count('(') - pseudocode.count('if (')}",
                    flush=True,
                )
                print(pseudocode, flush=True)
        finally:
            hook.unhook()
            cg._materialize_residual_entry_bridge = original_native_entry_bridge
    finally:
        cg.uninstall()
        headless.stop()
        if DIAG_OUTPUT:
            from d810.core.diag import find_latest_diag_db_path

            diag_path = find_latest_diag_db_path(FUNC_EA)
            if diag_path is not None:
                destination = Path(DIAG_OUTPUT).resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(diag_path, destination)
                print("DIAG_DB", destination, flush=True)
finally:
    idapro.close_database(False)
