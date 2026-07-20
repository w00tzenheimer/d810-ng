"""Probe PREOPT detached-range import into a live top-level Rhad MBA.

This is an investigation harness, not production profile logic.  Run it only
against a disposable copy because the computed-goto resolver patches the input
database's native bytes.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import shutil

import idapro


BIN = Path(os.environ.get("RHAD_PREOPT_BIN", ".tmp/rhad_preopt_probe.bin")).resolve()
FUNC_EA = 0x40A560
TAIL_START = 0x40B9A6
TAIL_END = 0x40BB75
DIAG_OUTPUT = os.environ.get("RHAD_PREOPT_DIAG_OUTPUT")
QUIET_LOGS = os.environ.get("RHAD_PREOPT_QUIET_LOGS") == "1"
IMPORT_ALL_PREPARED = os.environ.get("RHAD_PREOPT_IMPORT_ALL") == "1"
CAPTURE_TRANSITION_MANIFEST = os.environ.get("RHAD_PREOPT_TRANSITION_MANIFEST") == "1"
REPLAY_TRANSITION_MANIFEST = os.environ.get("RHAD_PREOPT_TRANSITION_REPLAY") == "1"
REPLAY_TRANSITION_MANIFEST_DATABASE = os.environ.get("RHAD_PREOPT_REPLAY_MANIFEST_DB")
ENTRY_DUMP = os.environ.get("RHAD_PREOPT_ENTRY_DUMP") == "1"
APPLY_INCOMING_BOUNDARIES = os.environ.get("RHAD_PREOPT_INCOMING_BOUNDARIES") == "1"
APPLY_INTERIOR_ENTRY_BRIDGES = os.environ.get("RHAD_PREOPT_INTERIOR_ENTRIES") == "1"
USE_UNION_CLOSURE = os.environ.get("RHAD_PREOPT_UNION_CLOSURE") == "1"
USE_NATIVE_SEMANTIC_CLOSURE = os.environ.get("RHAD_PREOPT_NATIVE_CLOSURE") == "1"
BOUNDARY_PORT_MODE = os.environ.get("RHAD_PREOPT_BOUNDARY_PORTS") == "1"
TRACE_REDIRECT_CATEGORIES = os.environ.get("RHAD_TRACE_REDIRECT_CATEGORIES") == "1"
STACK_CALLINFO_DIAG = os.environ.get("RHAD_PREOPT_STACK_CALLINFO_DIAG") == "1"
STKPNTS_INJECT = os.environ.get("RHAD_PREOPT_STKPNTS_INJECT") == "1"
STKPNTS_DUMP = os.environ.get("RHAD_PREOPT_STKPNTS_DUMP") == "1"
UNIQUE_IMPORTED_BLOCK_STARTS = os.environ.get("RHAD_PREOPT_UNIQUE_BLOCK_STARTS") == "1"
RAW_UNION_CALLS = os.environ.get("RHAD_PREOPT_RAW_UNION_CALLS") == "1" or STKPNTS_INJECT
CALL_COMPANION_SWEEP = os.environ.get("RHAD_PREOPT_CALL_COMPANION_SWEEP") == "1"
PRODUCTION_CALLINFO = os.environ.get("RHAD_PREOPT_PRODUCTION_CALLINFO") == "1"
FULL_HANDLER_CLOSURE = os.environ.get("RHAD_PREOPT_FULL_HANDLER_CLOSURE") == "1"
UNION_GENERATE_ONLY = os.environ.get("RHAD_PREOPT_UNION_GENERATE_ONLY") == "1"
MAX_DECOMPILE_ATTEMPTS = int(os.environ.get("RHAD_PREOPT_MAX_ATTEMPTS", "6"))
PREOPT_ALL_BLOCKS = os.environ.get("RHAD_PREOPT_ALL_BLOCKS") == "1"
SOURCE_BUILD_GRAPH = os.environ.get("RHAD_PREOPT_SOURCE_BUILD_GRAPH") == "1"
TOPLEVEL_ALL_BLOCKS = os.environ.get("RHAD_TOPLEVEL_ALL_BLOCKS") == "1"
SKIP_PREPARE = os.environ.get("RHAD_PREOPT_SKIP_PREPARE") == "1"
UNION_GENERATION_MODE = os.environ.get(
    "RHAD_PREOPT_UNION_GENERATION_MODE",
    "snippet",
)
if UNION_GENERATION_MODE not in {
    "snippet",
    "function",
    "function_outlined",
}:
    raise ValueError(
        "RHAD_PREOPT_UNION_GENERATION_MODE must be snippet, function, "
        "or function_outlined"
    )
if BOUNDARY_PORT_MODE and (
    REPLAY_TRANSITION_MANIFEST or REPLAY_TRANSITION_MANIFEST_DATABASE is not None
):
    raise ValueError("boundary-port mode refuses CALLS transition-manifest replay")


assert idapro.open_database(str(BIN), True) == 0
try:
    import ida_hexrays
    import ida_bytes
    import ida_funcs
    import ida_frame
    import ida_gdl
    import ida_idp
    import ida_ua
    import idaapi

    import d810.headless as headless
    import d810.hexrays.mutation.detached_handler_island as detached_island
    from d810.hexrays.mutation.detached_handler_island import (
        clear_detached_handler_call_templates,
        capture_detached_snippet_companion_templates,
        capture_detached_snippet_template,
        DetachedSnippetBoundaryPortOwner,
        DetachedSnippetConditionalBoundaryPort,
        DetachedSnippetDirectBoundaryPort,
        detached_snippet_template_block_eas,
        find_unique_live_block_by_ea,
        imported_detached_snippet_instruction_origins,
        imported_detached_snippet_direct_boundary_evidence,
        imported_detached_snippet_conditional_boundary_evidence,
        imported_detached_snippet_terminal_origins,
        imported_detached_snippet_target_eas,
        materialize_detached_snippet_templates,
        normalize_detached_snippet_boundary_ports,
        safe_verify,
    )

    if STKPNTS_INJECT or STKPNTS_DUMP:
        from d810.speedups.cythxr._chexrays_api import (
            copy_mcallinfo,
            snapshot_stkpnts,
            upsert_stkpnt,
        )
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
    from d810.hexrays.mutation.cfg_mutations import (
        change_1way_block_successor,
        insert_goto_instruction,
        insert_nop_blk,
    )
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        materialized_terminal_target_eas_by_source,
        unique_materialized_equality_target_eas,
    )
    from d810.analyses.control_flow.detached_handler_island import (
        make_resolver_cut_boundary_port,
        merge_detached_snippet_ranges,
    )
    from d810.ir.block_identity import block_label
    from d810.hexrays.utils.hexrays_formatters import format_minsn_t
    from d810.optimizers.microcode.flow.jumps import computed_goto_resolver as cg
    from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
        resolver_session_state,
    )
    from d810.optimizers.microcode.flow.jumps import (
        materialized_computed_goto_island as island,
    )

    idaapi.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    headless.configure(project="default_unflattening_ollvm.json")
    headless.start()
    from d810.hexrays.preanalysis import preopt_preanalysis

    print(
        "D810_PREOPT_DISPATCH",
        "hook_method="
        f"{type(headless._state.manager.hx_decompiler_hook).preoptimized.__module__}."
        f"{type(headless._state.manager.hx_decompiler_hook).preoptimized.__qualname__}",
        f"handlers={tuple(sorted(preopt_preanalysis._PREOPT_PREANALYSIS_HANDLERS))}",
        flush=True,
    )
    original_restore_terminal_return_carriers = island.restore_terminal_return_carriers

    def trace_restore_terminal_return_carriers(mba, function_ea):
        if int(function_ea) == FUNC_EA and int(mba.maturity) == int(
            ida_hexrays.MMAT_GENERATED
        ):
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                instructions = _block_instructions(block)
                if int(block.start) != 0x40A5D0 and not any(
                    int(instruction.ea) == 0x40A5D0 for instruction in instructions
                ):
                    continue
                print(
                    "D810_PREOPT_TERMINAL_WRITER",
                    f"blk{int(block.serial)}@0x{int(block.start):X}",
                    f"type={int(block.type)}",
                    f"succ={tuple(int(row) for row in block.succset)}",
                    "instructions="
                    f"{tuple((hex(int(instruction.ea)), format_minsn_t(instruction)) for instruction in instructions)}",
                    flush=True,
                )
        print(
            "D810_TERMINAL_RESTORE_ATTEMPT",
            f"func=0x{int(function_ea):X}",
            f"maturity={int(mba.maturity)}",
            flush=True,
        )
        restored = original_restore_terminal_return_carriers(mba, function_ea)
        print(
            "D810_TERMINAL_RESTORE_RESULT",
            f"func=0x{int(function_ea):X}",
            f"maturity={int(mba.maturity)}",
            f"restored={int(restored)}",
            flush=True,
        )
        return restored

    island.restore_terminal_return_carriers = trace_restore_terminal_return_carriers
    if QUIET_LOGS:
        logging.disable(logging.CRITICAL)
    cg.install()
    try:
        import d810.transforms.minimal_unflatten_emit as minimal_emit
        from d810.analyses.control_flow.detached_handler_island import (
            block_intersects_owned_ranges,
        )
        from preopt_transition_manifest import (
            plan_preopt_manifest_boundaries,
            build_transition_manifest,
            load_transition_manifest,
            persist_transition_manifest,
            select_replay_transition_manifest,
            select_timed_replay_transition_manifest,
        )
        from preopt_incoming_boundary import (
            PreoptDirectReplayMode,
            PreoptDirectIncomingBoundary,
            PreoptIncomingBoundaryPlan,
            classify_preopt_direct_replay_shape,
            exclude_conflicting_direct_boundaries_by_source,
            exclude_direct_boundaries_with_conditional_source,
            expand_preopt_boundary_target_closure,
            orient_preopt_conditional_boundary,
            plan_preopt_incoming_boundaries,
        )
        from preopt_interior_entry import (
            PreoptImportedEntryOwner,
            PreoptInteriorEntryCandidate,
            index_preopt_imported_entry_owners,
            plan_preopt_interior_entry_bridges,
        )
        from native_cfg_adapter import (
            NativeFlowBlockFact,
            build_native_cfg_from_flow_facts,
            can_decode_proven_native_successor,
            has_native_semantic_boundary,
            is_native_direct_control_operand,
            needs_native_flow_decode,
            select_visited_native_flow_facts,
        )
        from native_semantic_closure import (
            ClosureAbstentionReason,
            NativeEdge,
            NativeEdgeKind,
            ResolverProvenHandlerEntry,
            plan_native_semantic_closure,
        )
        from preopt_union_region import (
            plan_preopt_union_region,
            select_missing_preopt_union_region,
        )
        from preopt_boundary_port import (
            PreoptBoundaryEndpointOwner,
            PreoptBoundaryPortPlan,
            coalesce_preopt_conditional_boundary_ports,
            derive_preopt_fixed_source_arm_routes,
            exclude_preopt_conditional_topology_with_planned_predicates,
            merge_preopt_exact_route_targets,
            plan_preopt_conditional_routing_boundary_ports,
            plan_preopt_resolver_boundary_ports,
            plan_preopt_terminal_return_boundary_ports,
        )
        from preopt_boundary_port_capture import (
            CapturedPreoptClosureCrossings,
            PreoptPortBlockFact,
            PreoptPortTailKind,
            canonical_snippet_stack_offset,
            captured_port_instruction_eas,
            capture_preopt_boundary_ports,
            capture_preopt_live_to_imported_crossings,
            classify_captured_endpoint_owner,
            direct_endpoint_delivery_mode,
            exclude_closure_conditionals_superseded_by_captured,
            exclude_direct_endpoints_superseded_by_conditionals,
            exclude_ports_satisfied_by_internal_edges,
            reaching_register_definitions,
            select_captured_direct_owner_bindings,
            semantic_delta_block_entry_eas,
            state_transition_owned_endpoint_eas,
        )
        from preopt_state_transition_boundary import (
            PreoptConditionalTopologyFact,
            PreoptUnresolvedStateCut,
            extend_semantic_seed_eas_with_terminal_targets,
            merge_exact_state_payload_handler_eas,
            plan_preopt_conditional_state_choice_boundary_ports,
            plan_preopt_owned_literal_state_write_boundary_ports,
            plan_preopt_state_transition_boundary_ports,
            preopt_entry_bridge_source_fact,
            prove_preopt_pruned_conditional_fixed_state_sources,
            recognize_preopt_conditional_state_choices,
            recognize_preopt_pruned_conditional_state_choices,
            recognize_preopt_stack_carried_state_choices,
        )

        def nested_instructions(instruction):
            """Yield one microinstruction and every nested ``mop_d`` child."""
            yield instruction
            for operand in (instruction.l, instruction.r, instruction.d):
                if int(operand.t) == int(ida_hexrays.mop_d):
                    yield from nested_instructions(operand.d)

        def block_instructions(block):
            instruction = block.head
            while instruction is not None:
                yield instruction
                if instruction is block.tail:
                    break
                instruction = instruction.next

        def native_instruction_ea(instruction, origins):
            live_ea = int(instruction.ea)
            imported_origin = origins.get(live_ea)
            if imported_origin is not None:
                return int(imported_origin)
            if ida_bytes.is_loaded(live_ea):
                return live_ea
            return None

        def block_native_eas(block, origins):
            return frozenset(
                native_ea
                for instruction in block_instructions(block)
                for native_ea in (native_instruction_ea(instruction, origins),)
                if native_ea is not None
            )

        def stack_operand_rows(operand, mba):
            rows = []
            if int(operand.t) == int(ida_hexrays.mop_S):
                vd_offset = int(operand.s.off)
                rows.append(
                    (
                        vd_offset,
                        int(mba.stkoff_vd2ida(vd_offset)),
                        int(operand.size),
                    )
                )
            elif int(operand.t) == int(ida_hexrays.mop_d):
                nested = operand.d
                rows.extend(stack_operand_rows(nested.l, mba))
                rows.extend(stack_operand_rows(nested.r, mba))
                rows.extend(stack_operand_rows(nested.d, mba))
            elif int(operand.t) == int(ida_hexrays.mop_f):
                for argument in operand.f.args:
                    rows.extend(stack_operand_rows(argument, mba))
            return tuple(rows)

        def dump_call_argument_regions(label, mba):
            if not STACK_CALLINFO_DIAG:
                return
            origins = dict(imported_detached_snippet_instruction_origins(mba))
            rows = []
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                instructions = tuple(block_instructions(block))
                calls = tuple(
                    nested
                    for instruction in instructions
                    for nested in nested_instructions(instruction)
                    if int(nested.opcode)
                    in (int(ida_hexrays.m_call), int(ida_hexrays.m_icall))
                )
                if not calls:
                    continue
                native_eas = block_native_eas(block, origins)
                anchor_ea = min(native_eas, default=None)
                predecessors = tuple(
                    (
                        int(predecessor),
                        min(
                            block_native_eas(
                                mba.get_mblock(int(predecessor)),
                                origins,
                            ),
                            default=None,
                        ),
                    )
                    for predecessor in block.predset
                )
                instruction_rows = tuple(
                    (
                        hex(int(instruction.ea)),
                        (
                            None
                            if native_instruction_ea(instruction, origins) is None
                            else hex(
                                int(
                                    native_instruction_ea(
                                        instruction,
                                        origins,
                                    )
                                )
                            )
                        ),
                        int(instruction.opcode),
                        stack_operand_rows(instruction.l, mba),
                        stack_operand_rows(instruction.r, mba),
                        stack_operand_rows(instruction.d, mba),
                        format_minsn_t(instruction),
                    )
                    for instruction in instructions
                )
                for call in calls:
                    call_native_ea = native_instruction_ea(call, origins)
                    rows.append(
                        (
                            (
                                f"blk{serial}@0x{anchor_ea:X}"
                                if anchor_ea is not None
                                else f"block@fict:0x{int(block.start):X}"
                            ),
                            hex(int(call.ea)),
                            (
                                None
                                if call_native_ea is None
                                else hex(int(call_native_ea))
                            ),
                            tuple(
                                (
                                    f"blk{pred_serial}@0x{pred_anchor:X}"
                                    if pred_anchor is not None
                                    else f"blk{pred_serial}@fict"
                                )
                                for pred_serial, pred_anchor in predecessors
                            ),
                            tuple(int(successor) for successor in block.succset),
                            instruction_rows,
                        )
                    )
            print("CALL_ARGUMENT_REGIONS", f"label={label}", tuple(rows), flush=True)

        def dump_stack_basis_probe(label, mba, native_ea, vd_offset):
            if not STACK_CALLINFO_DIAG:
                return
            point = mba.locate_stkpnt(int(native_ea))
            location = ida_hexrays.vdloc_t()
            location.set_stkoff(int(vd_offset))
            native_spd = int(
                ida_frame.get_spd(ida_funcs.get_func(FUNC_EA), int(native_ea))
            )
            transient_spd = native_spd if point is None else int(point.spd)
            default_idaloc = mba.vd2idaloc(location, 4)
            explicit_idaloc = ida_hexrays.mba_t.vd2idaloc(
                location,
                4,
                transient_spd,
            )
            native_insn = ida_ua.insn_t()
            native_frame_offsets = []
            if ida_ua.decode_insn(native_insn, int(native_ea)) > 0:
                function = ida_funcs.get_func(FUNC_EA)
                for operand_index, operand in enumerate(native_insn.ops):
                    if int(operand.type) == int(ida_ua.o_void):
                        break
                    frame_offset = int(
                        ida_frame.calc_stkvar_struc_offset(
                            function,
                            native_insn,
                            operand_index,
                        )
                    )
                    if frame_offset != int(idaapi.BADADDR):
                        native_frame_offsets.append(frame_offset)
            print(
                "STACK_BASIS_PROBE",
                f"label={label}",
                f"native_ea=0x{int(native_ea):X}",
                f"vd={int(vd_offset)}",
                f"vd2ida={int(mba.stkoff_vd2ida(int(vd_offset)))}",
                f"ida_zero_vd={int(mba.stkoff_ida2vd(0))}",
                f"tmpstk_size={int(mba.tmpstk_size)}",
                f"frsize={int(mba.frsize)}",
                f"frregs={int(mba.frregs)}",
                f"stacksize={int(mba.stacksize)}",
                f"fullsize={int(mba.fullsize)}",
                f"native_spd={native_spd}",
                f"transient_spd={transient_spd}",
                "located_point="
                f"{None if point is None else (hex(int(point.ea)), int(point.spd))}",
                f"native_frame_offsets={tuple(native_frame_offsets)}",
                f"default_idaloc={default_idaloc}",
                f"explicit_idaloc={explicit_idaloc}",
                "default_stkoff="
                f"{int(default_idaloc.stkoff()) if default_idaloc.is_stkoff() else None}",
                "explicit_stkoff="
                f"{int(explicit_idaloc.stkoff()) if explicit_idaloc.is_stkoff() else None}",
                flush=True,
            )

        def dump_native_stack_identity_diff(label, mba):
            if not STACK_CALLINFO_DIAG:
                return
            function = ida_funcs.get_func(FUNC_EA)
            exact = 0
            corrected = []
            missing = []
            ambiguous = []
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                for instruction in block_instructions(block):
                    vd_offsets = tuple(
                        dict.fromkeys(
                            int(operand.s.off)
                            for operand in detached_island._instruction_operands(
                                instruction
                            )
                            if int(operand.t) == int(ida_hexrays.mop_S)
                        )
                    )
                    if not vd_offsets:
                        continue
                    native_ea = int(instruction.ea)
                    native_insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(native_insn, native_ea) <= 0:
                        missing.append((hex(native_ea), vd_offsets, "decode"))
                        continue
                    native_offsets = []
                    for operand_index, operand in enumerate(native_insn.ops):
                        if int(operand.type) == int(ida_ua.o_void):
                            break
                        frame_offset = int(
                            ida_frame.calc_stkvar_struc_offset(
                                function,
                                native_insn,
                                operand_index,
                            )
                        )
                        if frame_offset != int(idaapi.BADADDR):
                            native_offsets.append(frame_offset)
                    native_offsets = tuple(dict.fromkeys(native_offsets))
                    if len(vd_offsets) != 1 or len(native_offsets) != 1:
                        ambiguous.append((hex(native_ea), vd_offsets, native_offsets))
                        continue
                    vd_offset = int(vd_offsets[0])
                    fragment_ida = int(mba.stkoff_vd2ida(vd_offset))
                    heuristic = int(
                        detached_island._normalize_template_ida_stkoff(
                            FUNC_EA,
                            mba,
                            fragment_ida,
                        )
                    )
                    native_offset = int(native_offsets[0])
                    if heuristic == native_offset:
                        exact += 1
                    else:
                        corrected.append(
                            (
                                hex(native_ea),
                                vd_offset,
                                fragment_ida,
                                heuristic,
                                native_offset,
                            )
                        )
            print(
                "NATIVE_STACK_IDENTITY_DIFF",
                f"label={label}",
                f"exact={exact}",
                f"corrected={tuple(corrected)}",
                f"missing={tuple(missing)}",
                f"ambiguous={tuple(ambiguous)}",
                flush=True,
            )

        def reachable_block_serials(mba, root_serial):
            pending = [int(root_serial)]
            reachable = set()
            while pending:
                serial = pending.pop()
                if serial in reachable or not 0 <= serial < int(mba.qty):
                    continue
                reachable.add(serial)
                pending.extend(
                    int(successor) for successor in mba.get_mblock(serial).succset
                )
            return frozenset(reachable)

        def dump_final_native_inventory(mba):
            origins = dict(imported_detached_snippet_instruction_origins(mba))
            native_eas_by_serial = {
                serial: block_native_eas(mba.get_mblock(serial), origins)
                for serial in range(int(mba.qty))
            }
            entry_serial = 0 if int(mba.qty) > 0 else None
            entry_candidates = () if entry_serial is None else (entry_serial,)
            reachable = (
                frozenset()
                if entry_serial is None
                else reachable_block_serials(mba, entry_serial)
            )

            call_rows = []
            synthetic_call_rows = []
            stack_callinfo_rows = []
            function = ida_funcs.get_func(FUNC_EA)
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                block_eas = native_eas_by_serial[serial]
                for instruction in block_instructions(block):
                    for nested in nested_instructions(instruction):
                        if int(nested.opcode) not in (
                            int(ida_hexrays.m_call),
                            int(ida_hexrays.m_icall),
                        ):
                            continue
                        live_ea = int(nested.ea)
                        native_ea = native_instruction_ea(nested, origins)
                        callinfo = (
                            nested.d.f
                            if int(nested.d.t) == int(ida_hexrays.mop_f)
                            else None
                        )
                        anchor_ea = (
                            native_ea
                            if native_ea is not None
                            else min(block_eas, default=None)
                        )
                        row = (
                            (
                                f"blk{serial}@0x{anchor_ea:X}"
                                if anchor_ea is not None
                                else f"block@fict:0x{int(block.start):X}"
                            ),
                            hex(live_ea),
                            None if native_ea is None else hex(native_ea),
                            bool(serial in reachable),
                            int(nested.opcode),
                            None if callinfo is None else len(callinfo.args),
                            str(nested),
                        )
                        if native_ea is None:
                            synthetic_call_rows.append(row)
                        else:
                            call_rows.append(row)
                        if STACK_CALLINFO_DIAG:
                            mba_stkpnt = (
                                None
                                if native_ea is None
                                else mba.locate_stkpnt(native_ea)
                            )
                            native_spd = None
                            if function is not None and native_ea is not None:
                                native_spd = int(ida_frame.get_spd(function, native_ea))
                            stack_callinfo_rows.append(
                                (
                                    row[0],
                                    row[1],
                                    row[2],
                                    native_spd,
                                    (
                                        None
                                        if mba_stkpnt is None
                                        else (
                                            hex(int(mba_stkpnt.ea)),
                                            int(mba_stkpnt.spd),
                                        )
                                    ),
                                    None
                                    if callinfo is None
                                    else int(callinfo.call_spd),
                                    None
                                    if callinfo is None
                                    else int(callinfo.stkargs_top),
                                    None if callinfo is None else int(callinfo.cc),
                                    ()
                                    if callinfo is None
                                    else tuple(
                                        (
                                            int(argument.t),
                                            int(argument.ea),
                                            str(argument.argloc),
                                            str(argument),
                                        )
                                        for argument in callinfo.args
                                    ),
                                )
                            )

            captured_block_eas = ()
            if union_import_primary_seed_eas:
                captured_block_eas = detached_snippet_template_block_eas(
                    FUNC_EA,
                    union_import_primary_seed_eas[0],
                )
            bindings_by_native_ea = {
                native_ea: tuple(
                    serial
                    for serial, serial_native_eas in (native_eas_by_serial.items())
                    if int(native_ea) in serial_native_eas
                )
                for native_ea in captured_block_eas
            }
            missing_captured = tuple(
                hex(native_ea)
                for native_ea, serials in bindings_by_native_ea.items()
                if not serials
            )
            unreachable_captured = tuple(
                (
                    hex(native_ea),
                    tuple(f"blk{serial}@0x{native_ea:X}" for serial in serials),
                )
                for native_ea, serials in bindings_by_native_ea.items()
                if serials and not any(serial in reachable for serial in serials)
            )
            reachable_captured = tuple(
                hex(native_ea)
                for native_ea, serials in bindings_by_native_ea.items()
                if any(serial in reachable for serial in serials)
            )

            print(
                "FINAL_MICROCODE_CALLS",
                tuple(
                    sorted(
                        call_rows,
                        key=lambda row: (int(row[2], 16), row[0], row[1]),
                    )
                ),
                flush=True,
            )
            print(
                "FINAL_SYNTHETIC_MICROCODE_CALLS",
                tuple(synthetic_call_rows),
                flush=True,
            )
            if STACK_CALLINFO_DIAG:
                print(
                    "FINAL_STACK_MODEL",
                    {
                        "tmpstk_size": int(mba.tmpstk_size),
                        "frsize": int(mba.frsize),
                        "frregs": int(mba.frregs),
                        "stacksize": int(mba.stacksize),
                        "fullsize": int(mba.fullsize),
                        "spd_adjust": int(mba.spd_adjust),
                    },
                    flush=True,
                )
                print(
                    "FINAL_STACK_CALLINFO",
                    tuple(stack_callinfo_rows),
                    flush=True,
                )
            print(
                "FINAL_CAPTURED_BLOCK_REACHABILITY",
                f"entry_candidates={tuple(f'blk{serial}@0x{FUNC_EA:X}' for serial in entry_candidates)}",
                f"reachable_blocks={len(reachable)}",
                f"captured_blocks={len(captured_block_eas)}",
                f"reachable_captured={len(reachable_captured)}",
                f"missing_captured={missing_captured}",
                f"unreachable_captured={unreachable_captured}",
                flush=True,
            )

        instruction_origins: dict[int, int] = {}
        transition_manifest_captures: list[tuple[object, ...]] = []
        external_replay_manifest = (
            ()
            if REPLAY_TRANSITION_MANIFEST_DATABASE is None
            else load_transition_manifest(
                Path(REPLAY_TRANSITION_MANIFEST_DATABASE).resolve()
            )
        )
        if external_replay_manifest:
            print(
                "EXTERNAL_TRANSITION_MANIFEST",
                f"database={Path(REPLAY_TRANSITION_MANIFEST_DATABASE).resolve()}",
                f"rows={len(external_replay_manifest)}",
                flush=True,
            )
        union_source_generation_active = [False]
        union_import_seed_eas: list[tuple[int, ...]] = []
        union_import_primary_seed_eas: list[int] = []
        union_stack_point_ranges: list[tuple[tuple[int, int], ...]] = []
        transient_imported_stack_points: dict[int, int] = {}
        route_callinfo_templates: dict[int, object] = {}
        boundary_port_plans: list[object] = []
        boundary_port_captures: list[object] = []
        latest_template_boundary_port_count = [0]
        original_transition_recovery = (
            minimal_emit.recover_state_write_transitions_via_partitioned_fixpoint
        )
        traced_redirect_functions = {
            "base": minimal_emit.build_state_write_redirects,
            "source_keyed": minimal_emit.build_source_keyed_handler_redirects,
            "terminal_state_route": minimal_emit.build_exact_terminal_state_route_redirects,
            "conditional_bridge": minimal_emit.build_materialized_conditional_handler_bridges,
            "conditional_arm": minimal_emit.build_conditional_arm_redirects,
        }
        original_direct_edge_keys = minimal_emit._applied_direct_boundary_edge_keys
        original_conditional_edge_keys = (
            minimal_emit._applied_conditional_boundary_edge_keys
        )

        def redirect_category_row(flow_graph, modification):
            modification_type = type(modification).__name__
            if modification_type in {"RedirectGoto", "RedirectBranch"}:
                return (
                    modification_type,
                    block_label(flow_graph, modification.from_serial),
                    block_label(flow_graph, modification.old_target),
                    block_label(flow_graph, modification.new_target),
                )
            if modification_type == "ConvertToGoto":
                return (
                    modification_type,
                    block_label(flow_graph, modification.block_serial),
                    None,
                    block_label(flow_graph, modification.goto_target),
                )
            if modification_type == "LowerConditionalStateTransition":
                return (
                    modification_type,
                    block_label(flow_graph, modification.source_serial),
                    block_label(flow_graph, modification.old_dispatcher_serial),
                    (
                        block_label(flow_graph, modification.false_target_serial),
                        block_label(flow_graph, modification.true_target_serial),
                    ),
                )
            return (modification_type, repr(modification))

        def traced_redirect_builder(category, original):
            def traced(flow_graph, *args, **kwargs):
                modifications = original(flow_graph, *args, **kwargs)
                print(
                    "REDIRECT_CATEGORY",
                    f"category={category}",
                    f"func=0x{int(flow_graph.func_ea):X}",
                    f"rows={tuple(redirect_category_row(flow_graph, modification) for modification in modifications)}",
                    flush=True,
                )
                return modifications

            return traced

        if TRACE_REDIRECT_CATEGORIES:
            for category, original in traced_redirect_functions.items():
                setattr(
                    minimal_emit,
                    original.__name__,
                    traced_redirect_builder(category, original),
                )

            def traced_boundary_edge_keys(category, original):
                def traced(flow_graph, *args, **kwargs):
                    edges = original(flow_graph, *args, **kwargs)
                    print(
                        "BOUNDARY_EDGE_KEYS",
                        f"category={category}",
                        f"func=0x{int(flow_graph.func_ea):X}",
                        "rows="
                        f"{tuple((block_label(flow_graph, source), block_label(flow_graph, target)) for source, target in sorted(edges))}",
                        flush=True,
                    )
                    if category == "direct" and args:
                        for evidence in args[0]:
                            if original(flow_graph, (evidence,)):
                                continue
                            port = evidence.port
                            target_blocks = [
                                block
                                for block in flow_graph.blocks.values()
                                if int(block.start_ea) == int(port.target_ea)
                            ]
                            print(
                                "BOUNDARY_EDGE_MISS",
                                f"endpoint=0x{int(port.endpoint_block_ea):X}",
                                f"target=0x{int(port.target_ea):X}",
                                f"mode={port.delivery_mode}",
                                f"owner={port.endpoint_owner.value}",
                                "owner_live_identity="
                                f"{port.endpoint_owner is minimal_emit.DetachedSnippetBoundaryPortOwner.LIVE}",
                                "endpoint_anchors="
                                f"{tuple(hex(int(ea)) for ea in evidence.endpoint_anchor_eas)}",
                                "target_anchors="
                                f"{tuple(hex(int(ea)) for ea in evidence.target_anchor_eas)}",
                                "target_preds="
                                f"{tuple((block_label(flow_graph, block.serial), tuple(block_label(flow_graph, pred) for pred in block.preds)) for block in target_blocks)}",
                                "pred_max_eas="
                                f"{tuple((block_label(flow_graph, pred), hex(max({int(flow_graph.get_block(pred).start_ea), *(int(insn.ea) for insn in flow_graph.get_block(pred).insn_snapshots if int(insn.ea) > 0)}))) for block in target_blocks for pred in block.preds if flow_graph.get_block(pred) is not None)}",
                                flush=True,
                            )
                    return edges

                return traced

            minimal_emit._applied_direct_boundary_edge_keys = traced_boundary_edge_keys(
                "direct", original_direct_edge_keys
            )
            minimal_emit._applied_conditional_boundary_edge_keys = (
                traced_boundary_edge_keys(
                    "conditional",
                    original_conditional_edge_keys,
                )
            )

        def production_boundary_ports(
            capture,
            closure_crossings,
            imported_block_eas,
            closure_boundary_edges,
            live_native_eas,
            captured_instruction_eas,
        ):
            imported_entries = {int(ea) for ea in imported_block_eas}
            live_entries = {int(ea) for ea in live_native_eas}
            captured_instructions = {int(ea) for ea in captured_instruction_eas}
            closure_crossings = exclude_closure_conditionals_superseded_by_captured(
                closure_crossings,
                capture,
            )
            direct_owner_binding_rows = []

            def production_owner_for_ea(ea, preferred_owner=None):
                owner = classify_captured_endpoint_owner(
                    int(ea),
                    imported_block_eas=imported_entries,
                    live_native_eas=live_entries,
                    preferred_owner=preferred_owner,
                )
                if owner is None:
                    raise ValueError(
                        f"captured boundary endpoint has no import owner: 0x{int(ea):X}"
                    )
                return DetachedSnippetBoundaryPortOwner(owner.value)

            direct = list(closure_crossings.direct)
            suppressed_closure_edges = []
            state_owned_endpoints = state_transition_owned_endpoint_eas(capture)
            for edge in closure_boundary_edges:
                if (
                    edge.kind is not NativeEdgeKind.INDIRECT
                    or edge.source_instruction_ea is None
                ):
                    raise ValueError(
                        "closure transfer ports require an exact indirect "
                        "source instruction"
                    )
                if int(edge.source_ea) in state_owned_endpoints:
                    continue
                if int(edge.source_instruction_ea) not in captured_instructions:
                    suppressed_closure_edges.append(
                        (
                            int(edge.source_ea),
                            int(edge.source_instruction_ea),
                            int(edge.target_ea),
                        )
                    )
                    continue
                target_ea = int(edge.target_ea)
                if target_ea in imported_entries:
                    target_owner = DetachedSnippetBoundaryPortOwner.IMPORTED
                elif target_ea in live_entries:
                    target_owner = DetachedSnippetBoundaryPortOwner.LIVE
                else:
                    raise ValueError(
                        f"closure boundary target has no import owner: 0x{target_ea:X}"
                    )
                direct.append(
                    make_resolver_cut_boundary_port(
                        source_block_ea=int(edge.source_ea),
                        source_instruction_ea=int(edge.source_instruction_ea),
                        target_ea=target_ea,
                        source_owner=(DetachedSnippetBoundaryPortOwner.IMPORTED),
                        target_owner=target_owner,
                        provenance=(
                            edge.provenance
                            if edge.provenance is not None
                            else edge.kind.value
                        ),
                    )
                )
            print(
                "PREOPT_BOUNDARY_PORT_SUPPRESSED_FOLDED_SOURCES",
                [
                    (
                        hex(source_ea),
                        hex(instruction_ea),
                        hex(target_ea),
                    )
                    for source_ea, instruction_ea, target_ea in suppressed_closure_edges
                ],
                flush=True,
            )
            for row in capture.direct:
                frontier_by_endpoint: dict[int, set[int]] = {}
                for edge in row.frontier_edges:
                    frontier_by_endpoint.setdefault(
                        int(edge.source_block_ea), set()
                    ).add(int(edge.dispatcher_target_ea))
                for endpoint_ea in row.terminal_endpoint_block_eas:
                    frontier_by_endpoint.setdefault(int(endpoint_ea), set())
                for endpoint_ea, old_successor_eas in sorted(
                    frontier_by_endpoint.items()
                ):
                    owner_bindings = select_captured_direct_owner_bindings(
                        row.request,
                        endpoint_ea=int(endpoint_ea),
                        old_successor_eas=old_successor_eas,
                        imported_block_eas=imported_entries,
                        live_native_eas=live_entries,
                    )
                    if not owner_bindings:
                        raise ValueError(
                            "captured direct boundary endpoint has no coherent "
                            f"owner binding: source=0x{int(row.request.source_block_ea):X} "
                            f"endpoint=0x{int(endpoint_ea):X}"
                        )
                    direct_owner_binding_rows.append(
                        (
                            hex(int(row.request.source_block_ea)),
                            hex(int(endpoint_ea)),
                            int(row.request.source_block_ea) in imported_entries,
                            int(row.request.source_block_ea) in live_entries,
                            int(endpoint_ea) in imported_entries,
                            int(endpoint_ea) in live_entries,
                            tuple(
                                (
                                    binding.source_owner.value,
                                    binding.endpoint_owner.value,
                                )
                                for binding in owner_bindings
                            ),
                        )
                    )
                    target_owner = production_owner_for_ea(
                        row.request.target_ea,
                        row.request.target_owner,
                    )
                    for owner_binding in owner_bindings:
                        direct.append(
                            DetachedSnippetDirectBoundaryPort(
                                source_block_ea=int(row.request.source_block_ea),
                                source_instruction_ea=int(
                                    row.request.source_instruction_ea
                                ),
                                endpoint_block_ea=int(endpoint_ea),
                                old_successor_eas=tuple(sorted(old_successor_eas)),
                                target_ea=int(row.request.target_ea),
                                state_register=int(row.request.state_register),
                                state_constant=int(row.request.state_constant),
                                source_owner=DetachedSnippetBoundaryPortOwner(
                                    owner_binding.source_owner.value
                                ),
                                endpoint_owner=DetachedSnippetBoundaryPortOwner(
                                    owner_binding.endpoint_owner.value
                                ),
                                target_owner=target_owner,
                                old_successor_owners=tuple(
                                    DetachedSnippetBoundaryPortOwner(owner.value)
                                    for owner in owner_binding.old_successor_owners
                                ),
                                delivery_mode=direct_endpoint_delivery_mode(
                                    row,
                                    old_successor_eas=old_successor_eas,
                                ).value,
                                resolver_kind=str(row.request.resolver_kind),
                            )
                        )

            conditional = list(
                DetachedSnippetConditionalBoundaryPort(
                    source_block_ea=int(row.source_block_ea),
                    predicate_ea=int(row.predicate_ea),
                    old_taken_target_ea=(
                        None
                        if row.old_taken_target_ea is None
                        else int(row.old_taken_target_ea)
                    ),
                    old_fallthrough_target_ea=(
                        None
                        if row.old_fallthrough_target_ea is None
                        else int(row.old_fallthrough_target_ea)
                    ),
                    taken_target_ea=int(row.taken_target_ea),
                    fallthrough_target_ea=int(row.fallthrough_target_ea),
                    state_register=(
                        None
                        if row.request.state_register is None
                        else int(row.request.state_register)
                    ),
                    taken_state=(
                        None
                        if row.request.taken_state is None
                        else int(row.request.taken_state)
                    ),
                    fallthrough_state=(
                        None
                        if row.request.fallthrough_state is None
                        else int(row.request.fallthrough_state)
                    ),
                    source_owner=production_owner_for_ea(
                        row.source_block_ea,
                        row.request.source_owner,
                    ),
                    taken_target_owner=production_owner_for_ea(
                        row.taken_target_ea,
                        row.request.taken_target_owner,
                    ),
                    fallthrough_target_owner=production_owner_for_ea(
                        row.fallthrough_target_ea,
                        row.request.fallthrough_target_owner,
                    ),
                    resolver_kind=str(row.request.resolver_kind),
                    logical_source_anchor_ea=(
                        None
                        if row.request.logical_source_anchor_ea is None
                        else int(row.request.logical_source_anchor_ea)
                    ),
                    predicate_ida_stkoff=(
                        None
                        if row.request.predicate_ida_stkoff is None
                        else int(row.request.predicate_ida_stkoff)
                    ),
                    predicate_size=(
                        None
                        if row.request.predicate_size is None
                        else int(row.request.predicate_size)
                    ),
                    condition_code=(
                        None
                        if row.request.condition_code is None
                        else int(row.request.condition_code)
                    ),
                )
                for row in capture.conditional
            )
            conditional.extend(closure_crossings.conditional)
            print(
                "PREOPT_DIRECT_OWNER_BINDINGS",
                direct_owner_binding_rows,
                flush=True,
            )
            return normalize_detached_snippet_boundary_ports(
                tuple(direct),
                tuple(conditional),
            )

        def capture_transition_recovery(flow_graph, *args, **kwargs):
            transitions = original_transition_recovery(
                flow_graph,
                *args,
                **kwargs,
            )
            if (
                CAPTURE_TRANSITION_MANIFEST
                and int(flow_graph.func_ea) == FUNC_EA
                and instruction_origins
            ):
                transition_manifest_captures.append(
                    build_transition_manifest(
                        flow_graph,
                        transitions,
                        instruction_origins=instruction_origins,
                        state_var_reg=(
                            kwargs["state_var_reg"]
                            if "state_var_reg" in kwargs
                            else None
                        ),
                        capture_index=len(transition_manifest_captures) + 1,
                    )
                )
            return transitions

        if CAPTURE_TRANSITION_MANIFEST:
            minimal_emit.recover_state_write_transitions_via_partitioned_fixpoint = (
                capture_transition_recovery
            )

        def preopt_port_tail_kind(block) -> PreoptPortTailKind:
            if block.tail is None:
                return PreoptPortTailKind.NONE
            opcode = int(block.tail.opcode)
            if ida_hexrays.is_mcode_jcond(opcode):
                return PreoptPortTailKind.CONDITIONAL
            if opcode == int(ida_hexrays.m_goto):
                return PreoptPortTailKind.GOTO
            if opcode in {
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
            }:
                return PreoptPortTailKind.CALL
            if opcode in {
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_jtbl),
            }:
                return PreoptPortTailKind.INDIRECT
            if opcode == int(ida_hexrays.m_ret):
                return PreoptPortTailKind.RETURN
            return PreoptPortTailKind.OTHER

        def build_preopt_port_block_facts(
            mba,
            *,
            snippet_return_address_size: int | None = None,
        ):
            def canonical_stack_offset(vd_offset: int) -> int:
                if mba.mbr.is_snippet():
                    if snippet_return_address_size is None:
                        raise ValueError(
                            "snippet stack normalization requires the live "
                            "return-address size"
                        )
                    return canonical_snippet_stack_offset(
                        int(vd_offset),
                        int(snippet_return_address_size),
                    )
                return int(mba.stkoff_vd2ida(int(vd_offset)))

            native_entry_by_serial: dict[int, int] = {}
            serials_by_native_entry: dict[int, list[int]] = {}
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                native_entry_ea = detached_island._unique_block_native_ea(block)
                if native_entry_ea is None:
                    continue
                native_entry_by_serial[int(serial)] = int(native_entry_ea)
                serials_by_native_entry.setdefault(int(native_entry_ea), []).append(
                    int(serial)
                )
            ambiguous_entry_eas = frozenset(
                entry_ea
                for entry_ea, serials in serials_by_native_entry.items()
                if len(serials) != 1
            )
            facts: dict[int, PreoptPortBlockFact] = {}
            for serial, native_entry_ea in sorted(native_entry_by_serial.items()):
                if native_entry_ea in ambiguous_entry_eas:
                    continue
                block = mba.get_mblock(serial)
                instruction_eas = tuple(
                    int(instruction.ea)
                    for instruction in detached_island._instructions(block)
                    if int(instruction.ea) > 0
                )
                register_constant_writes = tuple(
                    (
                        int(instruction.d.r),
                        int(instruction.l.nnn.value),
                        int(instruction.ea),
                    )
                    for instruction in detached_island._instructions(block)
                    if int(instruction.opcode) == int(ida_hexrays.m_mov)
                    and int(instruction.l.t) == int(ida_hexrays.mop_n)
                    and int(instruction.d.t) == int(ida_hexrays.mop_r)
                    and int(instruction.ea) > 0
                )
                register_write_eas = tuple(
                    (int(instruction.d.r), int(instruction.ea))
                    for instruction in detached_island._instructions(block)
                    if int(instruction.d.t) == int(ida_hexrays.mop_r)
                    and bool(instruction.modifies_d())
                    and int(instruction.ea) > 0
                )
                register_copy_writes = tuple(
                    (
                        int(instruction.d.r),
                        int(instruction.l.r),
                        int(instruction.ea),
                    )
                    for instruction in detached_island._instructions(block)
                    if int(instruction.opcode) == int(ida_hexrays.m_mov)
                    and int(instruction.l.t) == int(ida_hexrays.mop_r)
                    and int(instruction.d.t) == int(ida_hexrays.mop_r)
                    and bool(instruction.modifies_d())
                    and int(instruction.ea) > 0
                )
                register_stack_loads = tuple(
                    (
                        int(instruction.d.r),
                        canonical_stack_offset(int(instruction.l.s.off)),
                        int(instruction.l.size),
                        int(instruction.ea),
                    )
                    for instruction in detached_island._instructions(block)
                    if int(instruction.opcode) == int(ida_hexrays.m_mov)
                    and int(instruction.l.t) == int(ida_hexrays.mop_S)
                    and int(instruction.d.t) == int(ida_hexrays.mop_r)
                    and bool(instruction.modifies_d())
                    and int(instruction.ea) > 0
                )
                stack_register_stores = tuple(
                    (
                        canonical_stack_offset(int(instruction.d.s.off)),
                        int(instruction.d.size),
                        int(instruction.l.r),
                        int(instruction.ea),
                    )
                    for instruction in detached_island._instructions(block)
                    if int(instruction.opcode) == int(ida_hexrays.m_mov)
                    and int(instruction.l.t) == int(ida_hexrays.mop_r)
                    and int(instruction.d.t) == int(ida_hexrays.mop_S)
                    and int(instruction.ea) > 0
                )
                has_side_effects = any(
                    bool(instruction.has_side_effects())
                    for instruction in detached_island._instructions(block)
                )
                successor_eas: list[int] = []
                successors_complete = True
                has_synthetic_function_exit_successor = False
                for successor_serial in block.succset:
                    successor_ea = native_entry_by_serial.get(int(successor_serial))
                    if successor_ea is None or successor_ea in ambiguous_entry_eas:
                        successor_block = mba.get_mblock(int(successor_serial))
                        successor_is_synthetic_function_exit = (
                            successor_block is not None
                            and int(successor_block.nsucc()) == 0
                            and not tuple(
                                instruction
                                for instruction in detached_island._instructions(
                                    successor_block
                                )
                                if int(instruction.ea) > 0
                            )
                        )
                        if successor_is_synthetic_function_exit:
                            has_synthetic_function_exit_successor = True
                        else:
                            successors_complete = False
                        continue
                    successor_eas.append(int(successor_ea))
                end_ea = int(block.end)
                if end_ea <= native_entry_ea:
                    end_ea = max(instruction_eas, default=native_entry_ea) + 1
                tail_kind = preopt_port_tail_kind(block)
                taken_successor_ea = None
                fallthrough_successor_ea = None
                if (
                    tail_kind is PreoptPortTailKind.CONDITIONAL
                    and block.tail is not None
                    and int(block.tail.d.t) == int(ida_hexrays.mop_b)
                ):
                    taken_successor_ea = native_entry_by_serial.get(int(block.tail.d.b))
                    if taken_successor_ea is not None:
                        fallthrough_candidates = tuple(
                            successor_ea
                            for successor_ea in successor_eas
                            if int(successor_ea) != int(taken_successor_ea)
                        )
                        if len(fallthrough_candidates) == 1:
                            fallthrough_successor_ea = int(fallthrough_candidates[0])
                facts[native_entry_ea] = PreoptPortBlockFact(
                    start_ea=native_entry_ea,
                    end_ea=end_ea,
                    instruction_eas=instruction_eas,
                    successor_eas=tuple(successor_eas),
                    successors_complete=successors_complete,
                    register_constant_writes=register_constant_writes,
                    register_write_eas=register_write_eas,
                    register_copy_writes=register_copy_writes,
                    register_stack_loads=register_stack_loads,
                    stack_register_stores=stack_register_stores,
                    has_synthetic_function_exit_successor=(
                        has_synthetic_function_exit_successor
                    ),
                    has_side_effects=has_side_effects,
                    tail_ea=(
                        None
                        if block.tail is None or int(block.tail.ea) <= 0
                        else int(block.tail.ea)
                    ),
                    taken_successor_ea=taken_successor_ea,
                    fallthrough_successor_ea=fallthrough_successor_ea,
                    tail_kind=tail_kind,
                )
            return facts, ambiguous_entry_eas

        lifecycle = headless._state.manager.decompilation_lifecycle
        session, _created = lifecycle.ensure_hexrays_session(
            function_ea=FUNC_EA,
            database_identity=headless._state.manager._database_identity,
        )
        resolver_state = resolver_session_state(session)
        resolution = cg.resolve_and_materialize(FUNC_EA, state=resolver_state)
        assert resolution is not None
        resolver_state.begin_materialization(resolution)
        transfers = resolver_state.materialized_transfers
        print(
            "RESOLVER",
            f"sites={resolution.site_count}",
            f"targets={resolution.target_count}",
            f"patch_plans={len(resolution.patch_plans)}",
            f"transfers={len(transfers)}",
            flush=True,
        )
        patch_plan_sources = {int(plan.jmp_ea) for plan in resolution.patch_plans}
        resolver_materialized_bridge_targets_by_source_ea: dict[int, set[int]] = {}
        for plan in resolution.patch_plans:
            if (
                plan.condition_code is None
                or plan.false_target_ea is None
                or len(plan.new_block_eas) < 2
            ):
                continue
            false_bridge_ea = int(plan.new_block_eas[-1])
            resolver_materialized_bridge_targets_by_source_ea.setdefault(
                false_bridge_ea,
                set(),
            ).add(int(plan.false_target_ea))
        print(
            "RESOLVER_UNMATERIALIZED_SITES",
            [
                (hex(int(source_ea)), tuple(hex(int(ea)) for ea in targets))
                for source_ea, targets in sorted(resolution.jmp_targets.items())
                if int(source_ea) not in patch_plan_sources
            ],
            flush=True,
        )

        clear_detached_handler_call_templates()

        def build_native_semantic_cfg(
            function,
            *,
            live_native_eas,
            seed_eas,
            resolver_cut_eas,
            resolver_target_eas_by_source,
        ):
            def cut_edges_for_range(start_ea, end_ea):
                edges = []
                for source_ea in sorted(
                    cut_ea
                    for cut_ea in resolver_cut_eas
                    if int(start_ea) <= int(cut_ea) < int(end_ea)
                ):
                    targets = tuple(
                        dict.fromkeys(
                            int(target_ea)
                            for target_ea in resolver_target_eas_by_source.get(
                                int(source_ea), ()
                            )
                        )
                    )
                    if len(targets) == 1:
                        edges.append(
                            NativeEdge(
                                NativeEdgeKind.INDIRECT,
                                targets[0],
                                resolver_proven=True,
                                provenance="materialized_terminal_target",
                                source_instruction_ea=int(source_ea),
                            )
                        )
                    else:
                        edges.append(
                            NativeEdge(
                                NativeEdgeKind.INDIRECT,
                                provenance="ambiguous_materialized_terminal_target",
                                source_instruction_ea=int(source_ea),
                            )
                        )
                return tuple(edges)

            def decode_missing_flow_block(start_ea):
                start_ea = int(start_ea)
                requested_func_ea = int(function.start_ea)
                owner = ida_funcs.get_func(start_ea)
                owner_func_ea = None if owner is None else int(owner.start_ea)
                is_code = bool(ida_bytes.is_code(ida_bytes.get_full_flags(start_ea)))
                if not can_decode_proven_native_successor(
                    is_code=is_code,
                    owner_func_ea=owner_func_ea,
                    requested_func_ea=requested_func_ea,
                ):
                    print(
                        "NATIVE_CFG_DECODE_ABSTAIN",
                        f"entry_ea=0x{start_ea:X}",
                        "reason=non_code_or_foreign_function",
                        f"requested_func=0x{requested_func_ea:X}",
                        f"owner_func={None if owner_func_ea is None else hex(owner_func_ea)}",
                        f"chunknum={ida_funcs.get_func_chunknum(function, start_ea)}",
                        f"is_code={is_code}",
                        flush=True,
                    )
                    return None
                current_ea = start_ea
                for _instruction_count in range(10000):
                    instruction = ida_ua.insn_t()
                    size = int(ida_ua.decode_insn(instruction, current_ea))
                    if size <= 0:
                        print(
                            "NATIVE_CFG_DECODE_ABSTAIN",
                            f"entry_ea=0x{start_ea:X}",
                            f"cursor_ea=0x{current_ea:X}",
                            "reason=decode_failed",
                            f"is_code={ida_bytes.is_code(ida_bytes.get_full_flags(current_ea))}",
                            flush=True,
                        )
                        return None
                    next_ea = current_ea + size
                    instruction_features = int(instruction.get_canon_feature())
                    is_call = bool(ida_idp.is_call_insn(instruction))
                    is_basic_block_end = bool(
                        ida_idp.is_basic_block_end(instruction, False)
                    )
                    has_stop_feature = bool(instruction_features & int(ida_idp.CF_STOP))
                    direct_target_ea = None
                    if is_native_direct_control_operand(
                        operand_is_near=(
                            int(instruction.ops[0].type)
                            in {int(idaapi.o_near), int(idaapi.o_far)}
                        ),
                        is_call=is_call,
                        is_basic_block_end=is_basic_block_end,
                        has_stop_feature=has_stop_feature,
                    ):
                        direct_target_ea = int(instruction.ops[0].addr)
                    force_stop = current_ea in resolver_cut_eas
                    is_return = bool(ida_idp.is_ret_insn(instruction, 0))
                    is_indirect = bool(ida_idp.is_indirect_jump_insn(instruction))
                    if force_stop or is_return or is_indirect:
                        return NativeFlowBlockFact(
                            start_ea=start_ea,
                            end_ea=next_ea,
                            is_return_tail=is_return,
                            is_indirect_jump_tail=is_indirect,
                            terminal_instruction_ea=int(current_ea),
                            force_stop=force_stop,
                            cut_edges=cut_edges_for_range(start_ea, next_ea),
                        )
                    if has_native_semantic_boundary(
                        resolver_cut=force_stop,
                        is_return=is_return,
                        is_indirect_jump=is_indirect,
                        is_call=is_call,
                        direct_branch_target_ea=direct_target_ea,
                        has_stop_feature=has_stop_feature,
                    ):
                        if direct_target_ea is None:
                            print(
                                "NATIVE_CFG_DECODE_CUT",
                                f"entry_ea=0x{start_ea:X}",
                                f"tail_ea=0x{current_ea:X}",
                                "reason=processor_stop_without_target",
                                flush=True,
                            )
                            return NativeFlowBlockFact(
                                start_ea=start_ea,
                                end_ea=next_ea,
                                terminal_instruction_ea=int(current_ea),
                                force_stop=True,
                            )
                        successors = ()
                        if direct_target_ea is not None:
                            successors = (direct_target_ea,)
                            if ida_funcs.func_contains(
                                function, next_ea
                            ) and ida_bytes.is_flow(ida_bytes.get_full_flags(next_ea)):
                                successors += (next_ea,)
                        return NativeFlowBlockFact(
                            start_ea=start_ea,
                            end_ea=next_ea,
                            successor_eas=successors,
                            direct_branch_target_ea=direct_target_ea,
                        )
                    next_owner = ida_funcs.get_func(next_ea)
                    next_owner_func_ea = (
                        None if next_owner is None else int(next_owner.start_ea)
                    )
                    next_is_code = bool(
                        ida_bytes.is_code(ida_bytes.get_full_flags(next_ea))
                    )
                    if not can_decode_proven_native_successor(
                        is_code=next_is_code,
                        owner_func_ea=next_owner_func_ea,
                        requested_func_ea=requested_func_ea,
                    ):
                        print(
                            "NATIVE_CFG_DECODE_CUT",
                            f"entry_ea=0x{start_ea:X}",
                            f"tail_ea=0x{current_ea:X}",
                            f"next_ea=0x{next_ea:X}",
                            "reason=non_code_or_foreign_function",
                            f"owner_func={None if next_owner_func_ea is None else hex(next_owner_func_ea)}",
                            f"is_code={next_is_code}",
                            flush=True,
                        )
                        return NativeFlowBlockFact(
                            start_ea=start_ea,
                            end_ea=next_ea,
                            force_stop=True,
                        )
                    current_ea = next_ea
                return None

            facts_by_start_ea = {}
            for flow_block in ida_gdl.FlowChart(function):
                start_ea = int(flow_block.start_ea)
                end_ea = int(flow_block.end_ea)
                tail_ea = int(ida_bytes.prev_head(end_ea, start_ea))
                instruction = ida_ua.insn_t()
                decoded = (
                    tail_ea != int(idaapi.BADADDR)
                    and int(ida_ua.decode_insn(instruction, tail_ea)) > 0
                )
                instruction_features = (
                    int(instruction.get_canon_feature()) if decoded else 0
                )
                is_call_tail = bool(decoded and ida_idp.is_call_insn(instruction))
                is_basic_block_end = bool(
                    decoded and ida_idp.is_basic_block_end(instruction, False)
                )
                has_stop_feature = bool(instruction_features & int(ida_idp.CF_STOP))
                direct_target_ea = None
                if decoded and is_native_direct_control_operand(
                    operand_is_near=(
                        int(instruction.ops[0].type)
                        in {int(idaapi.o_near), int(idaapi.o_far)}
                    ),
                    is_call=is_call_tail,
                    is_basic_block_end=is_basic_block_end,
                    has_stop_feature=has_stop_feature,
                ):
                    direct_target_ea = int(instruction.ops[0].addr)
                facts_by_start_ea[start_ea] = NativeFlowBlockFact(
                    start_ea=start_ea,
                    end_ea=end_ea,
                    successor_eas=tuple(
                        int(successor.start_ea) for successor in flow_block.succs()
                    ),
                    direct_branch_target_ea=direct_target_ea,
                    is_call_tail=is_call_tail,
                    is_return_tail=bool(
                        decoded and ida_idp.is_ret_insn(instruction, 0)
                    ),
                    is_indirect_jump_tail=bool(
                        decoded and ida_idp.is_indirect_jump_insn(instruction)
                    ),
                    terminal_instruction_ea=(int(tail_ea) if decoded else None),
                    force_stop=(
                        not decoded
                        or any(
                            start_ea <= int(cut_ea) < end_ea
                            for cut_ea in resolver_cut_eas
                        )
                    ),
                    cut_edges=cut_edges_for_range(start_ea, end_ea),
                )
            pending = list(int(seed_ea) for seed_ea in seed_eas)
            visited = set()
            while pending:
                entry_ea = int(pending.pop())
                if entry_ea in visited:
                    continue
                visited.add(entry_ea)
                if entry_ea in live_native_eas and entry_ea not in seed_eas:
                    continue
                fact = facts_by_start_ea.get(entry_ea)
                if fact is not None and int(fact.end_ea) <= int(fact.start_ea):
                    print(
                        "NATIVE_CFG_PLACEHOLDER_FACT",
                        f"entry_ea=0x{entry_ea:X}",
                        f"end_ea=0x{int(fact.end_ea):X}",
                        f"successors={[hex(int(ea)) for ea in fact.successor_eas]}",
                        f"live={entry_ea in live_native_eas}",
                        flush=True,
                    )
                if needs_native_flow_decode(fact):
                    prior_fact = fact
                    fact = decode_missing_flow_block(entry_ea)
                    if fact is None:
                        continue
                    print(
                        "NATIVE_CFG_REDECODE",
                        f"entry_ea=0x{entry_ea:X}",
                        f"prior_end={None if prior_fact is None else hex(int(prior_fact.end_ea))}",
                        f"end=0x{int(fact.end_ea):X}",
                        f"successors={[hex(int(ea)) for ea in fact.successor_eas]}",
                        f"direct_target={None if fact.direct_branch_target_ea is None else hex(int(fact.direct_branch_target_ea))}",
                        f"force_stop={fact.force_stop}",
                        f"indirect={fact.is_indirect_jump_tail}",
                        f"terminal={None if fact.terminal_instruction_ea is None else hex(int(fact.terminal_instruction_ea))}",
                        flush=True,
                    )
                    facts_by_start_ea[entry_ea] = fact
                if fact.force_stop or fact.is_return_tail or fact.is_indirect_jump_tail:
                    continue
                pending.extend(int(ea) for ea in fact.successor_eas)
            return build_native_cfg_from_flow_facts(
                select_visited_native_flow_facts(
                    facts_by_start_ea,
                    visited_entry_eas=visited,
                ),
                excluded_entry_eas=live_native_eas,
                retained_entry_eas=seed_eas,
            )

        def prepare_union_semantic_closure(
            surviving_native_eas: frozenset[int],
            preopt_live_native_eas: frozenset[int],
        ) -> int:
            current_transfers = resolver_state.materialized_transfers
            plan = plan_preopt_union_region(current_transfers)
            import_plan = select_missing_preopt_union_region(
                plan,
                surviving_native_eas,
            )
            union_import_seed_eas[:] = [import_plan.seed_eas]
            union_import_primary_seed_eas[:] = (
                []
                if import_plan.primary_seed_ea is None
                else [int(import_plan.primary_seed_ea)]
            )
            print(
                "UNION_PLAN",
                f"seeds={len(plan.seed_eas)}",
                f"ranges={len(plan.native_ranges)}",
                f"missing_seeds={[hex(ea) for ea in import_plan.seed_eas]}",
                f"missing_ranges={len(import_plan.native_ranges)}",
                f"abstentions={[(hex(row.target_ea), row.reason.value) for row in plan.abstentions]}",
                flush=True,
            )
            if (
                import_plan.primary_seed_ea is None
                or not import_plan.native_ranges
                or import_plan.abstentions
            ):
                return 0
            function = idaapi.get_func(FUNC_EA)
            semantic_ranges = import_plan.native_ranges
            capture_ranges = semantic_ranges
            capture_block_entry_eas = frozenset()
            closure_crossings = CapturedPreoptClosureCrossings((), (), ())
            semantic_closure = None
            semantic_unproven_abstentions = ()
            if USE_NATIVE_SEMANTIC_CLOSURE:
                assert function is not None
                semantic_live_boundary_eas = (
                    frozenset() if FULL_HANDLER_CLOSURE else preopt_live_native_eas
                )
                resolver_cut_eas = frozenset(
                    int(source_ea) for source_ea in resolution.jmp_targets
                )
                state_registers = {
                    int(transfer.selector_state_var_reg)
                    for transfer in current_transfers
                    if transfer.resolver_kind
                    in {
                        "condition_chain_handler_evidence",
                        "static_equality_fixpoint",
                    }
                    and transfer.selector_state_var_reg is not None
                }
                terminal_requests = ()
                base_semantic_seed_eas = (
                    plan.seed_eas if FULL_HANDLER_CLOSURE else import_plan.seed_eas
                )
                semantic_seed_eas = tuple(base_semantic_seed_eas)
                if len(state_registers) == 1:
                    terminal_requests = resolver_state.terminal_return_carrier_requests
                    semantic_seed_eas = extend_semantic_seed_eas_with_terminal_targets(
                        base_semantic_seed_eas,
                        terminal_requests,
                        state_register=next(iter(state_registers)),
                    )
                target_sets: dict[int, set[int]] = {
                    int(source_ea): {int(target_ea) for target_ea in target_eas}
                    for source_ea, target_eas in resolution.jmp_targets.items()
                }
                if len(state_registers) == 1:
                    for (
                        source_ea,
                        target_eas,
                    ) in materialized_terminal_target_eas_by_source(
                        current_transfers,
                        next(iter(state_registers)),
                    ).items():
                        target_sets.setdefault(int(source_ea), set()).update(
                            int(target_ea) for target_ea in target_eas
                        )
                else:
                    for transfer in current_transfers:
                        if transfer.resolver_kind not in {
                            "static_fixpoint",
                            "detached_static_fixpoint",
                        }:
                            continue
                        target_sets.setdefault(
                            int(transfer.source_jmp_ea), set()
                        ).update(int(ea) for ea in transfer.target_eas)
                resolver_target_eas_by_source = {
                    source_ea: tuple(sorted(target_eas))
                    for source_ea, target_eas in target_sets.items()
                }
                native_cfg = build_native_semantic_cfg(
                    function,
                    live_native_eas=semantic_live_boundary_eas,
                    seed_eas=semantic_seed_eas,
                    resolver_cut_eas=resolver_cut_eas,
                    resolver_target_eas_by_source=(resolver_target_eas_by_source),
                )
                semantic_closure = plan_native_semantic_closure(
                    native_cfg,
                    tuple(
                        ResolverProvenHandlerEntry(
                            entry_ea=int(seed_ea),
                            provenance="static_handler_entry_route",
                        )
                        for seed_ea in semantic_seed_eas
                    ),
                    import_boundary_target_eas=semantic_live_boundary_eas,
                )
                unproven_abstentions = tuple(
                    row
                    for row in semantic_closure.abstentions
                    if not (
                        row.reason is ClosureAbstentionReason.MISSING_CFG_BLOCK
                        and row.target_ea is not None
                        and int(row.target_ea) in preopt_live_native_eas
                    )
                )
                semantic_unproven_abstentions = unproven_abstentions
                print(
                    "NATIVE_SEMANTIC_CLOSURE",
                    f"full_handlers={FULL_HANDLER_CLOSURE}",
                    f"seeds={len(semantic_seed_eas)}",
                    f"blocks={len(semantic_closure.included_block_eas)}",
                    f"ranges={len(semantic_closure.native_ranges)}",
                    f"internal_edges={len(semantic_closure.proven_internal_edges)}",
                    f"boundary_edges={len(semantic_closure.proven_import_boundary_edges)}",
                    f"abstentions={[(row.reason.value, None if row.source_block_ea is None else hex(row.source_block_ea), None if row.target_ea is None else hex(row.target_ea)) for row in semantic_closure.abstentions]}",
                    f"unproven={len(unproven_abstentions)}",
                    flush=True,
                )
                print(
                    "NATIVE_SEMANTIC_BOUNDARY_EDGES",
                    [
                        (
                            hex(int(row.source_ea)),
                            None
                            if row.source_instruction_ea is None
                            else hex(int(row.source_instruction_ea)),
                            row.kind.value,
                            hex(int(row.target_ea)),
                            row.provenance,
                        )
                        for row in semantic_closure.proven_import_boundary_edges
                    ],
                    flush=True,
                )
                print(
                    "NATIVE_SEMANTIC_BLOCKS",
                    [
                        (
                            hex(int(entry_ea)),
                            hex(int(native_cfg.blocks_by_ea[entry_ea].end_ea)),
                            [
                                (
                                    edge.kind.value,
                                    None
                                    if edge.target_ea is None
                                    else hex(int(edge.target_ea)),
                                )
                                for edge in native_cfg.blocks_by_ea[
                                    entry_ea
                                ].outgoing_edges
                            ],
                        )
                        for entry_ea in semantic_closure.included_block_eas
                    ],
                    flush=True,
                )
                print(
                    "NATIVE_SEMANTIC_RANGES",
                    [
                        (hex(int(row.start_ea)), hex(int(row.end_ea)))
                        for row in semantic_closure.native_ranges
                    ],
                    flush=True,
                )
                if unproven_abstentions:
                    unresolved_resolver_rows = []
                    for row in unproven_abstentions:
                        if row.source_block_ea is None:
                            continue
                        native_block = native_cfg.blocks_by_ea[int(row.source_block_ea)]
                        tail_ea = int(
                            ida_bytes.prev_head(
                                int(native_block.end_ea),
                                int(native_block.start_ea),
                            )
                        )
                        transfer_rows = tuple(
                            (
                                transfer.resolver_kind,
                                tuple(
                                    hex(int(target_ea))
                                    for target_ea in transfer.target_eas
                                ),
                                tuple(
                                    (int(register), hex(int(value)))
                                    for register, value in transfer.source_register_values
                                ),
                            )
                            for transfer in current_transfers
                            if int(transfer.source_jmp_ea) == tail_ea
                        )
                        unresolved_resolver_rows.append(
                            (
                                hex(int(row.source_block_ea)),
                                hex(tail_ea),
                                tuple(
                                    hex(int(target_ea))
                                    for target_ea in resolver_target_eas_by_source.get(
                                        tail_ea, ()
                                    )
                                ),
                                tuple(
                                    hex(int(target_ea))
                                    for target_ea in resolution.jmp_targets.get(
                                        tail_ea, ()
                                    )
                                ),
                                transfer_rows,
                            )
                        )
                    print(
                        "PREOPT_UNPROVEN_CUT_RESOLVER_EVIDENCE",
                        unresolved_resolver_rows,
                        flush=True,
                    )
                state_transition_cut_candidates = bool(
                    BOUNDARY_PORT_MODE
                    and unproven_abstentions
                    and all(
                        row.reason is ClosureAbstentionReason.UNPROVEN_INDIRECT_TARGET
                        and row.source_block_ea is not None
                        for row in unproven_abstentions
                    )
                )
                if (
                    unproven_abstentions
                    and not UNION_GENERATE_ONLY
                    and not state_transition_cut_candidates
                ):
                    return 0
                semantic_ranges = tuple(
                    (int(row.start_ea), int(row.end_ea))
                    for row in semantic_closure.native_ranges
                )
                state_payload_handler_eas: dict[int, set[int]] = {}
                if len(state_registers) == 1:
                    state_register = next(iter(state_registers))
                    state_payload_handler_eas = {
                        int(state): {int(target_ea)}
                        for state, target_ea in (
                            unique_materialized_equality_target_eas(
                                current_transfers,
                                int(state_register),
                            ).items()
                        )
                    }
                    state_payload_handler_eas = merge_exact_state_payload_handler_eas(
                        state_payload_handler_eas,
                        state_register=int(state_register),
                        exact_routes=tuple(
                            (
                                int(request.state_var_reg),
                                int(request.state_constant),
                                int(request.terminal_target_ea),
                            )
                            for request in terminal_requests
                        ),
                    )
                    print(
                        "PREOPT_EXACT_TERMINAL_STATE_TARGETS",
                        [
                            (
                                hex(int(request.source_handler_ea)),
                                hex(int(request.state_constant)),
                                hex(int(request.terminal_target_ea)),
                            )
                            for request in terminal_requests
                            if int(request.state_var_reg) == int(state_register)
                        ],
                        flush=True,
                    )
                if BOUNDARY_PORT_MODE:
                    boundary_port_plan = plan_preopt_resolver_boundary_ports(
                        current_transfers,
                        imported_block_ranges={
                            int(entry_ea): (
                                int(native_cfg.blocks_by_ea[entry_ea].start_ea),
                                int(native_cfg.blocks_by_ea[entry_ea].end_ea),
                            )
                            for entry_ea in semantic_closure.included_block_eas
                        },
                        live_native_eas=preopt_live_native_eas,
                        state_payload_handler_eas=state_payload_handler_eas,
                    )
                    boundary_port_plans[:] = [boundary_port_plan]
                    print(
                        "PREOPT_BOUNDARY_PORT_PLAN",
                        f"transfers={len(current_transfers)}",
                        f"kinds={sorted((kind, sum(row.resolver_kind == kind for row in current_transfers)) for kind in {row.resolver_kind for row in current_transfers})}",
                        f"direct={len(boundary_port_plan.direct)}",
                        f"conditional={len(boundary_port_plan.conditional)}",
                        f"abstentions={len(boundary_port_plan.abstentions)}",
                        flush=True,
                    )
                    print(
                        "PREOPT_BOUNDARY_PORT_DIRECT",
                        [
                            (
                                hex(int(row.source_block_ea)),
                                hex(int(row.source_instruction_ea)),
                                row.source_owner.value,
                                hex(int(row.target_ea)),
                                row.target_owner.value,
                                hex(int(row.state_constant)),
                            )
                            for row in boundary_port_plan.direct
                        ],
                        flush=True,
                    )
                    print(
                        "PREOPT_BOUNDARY_PORT_CONDITIONAL",
                        [
                            (
                                hex(int(row.source_block_ea)),
                                hex(int(row.predicate_ea)),
                                row.source_owner.value,
                                hex(int(row.fallthrough_target_ea)),
                                row.fallthrough_target_owner.value,
                                hex(int(row.taken_target_ea)),
                                row.taken_target_owner.value,
                            )
                            for row in boundary_port_plan.conditional
                        ],
                        flush=True,
                    )
                    print(
                        "PREOPT_BOUNDARY_PORT_ABSTENTIONS",
                        [
                            (
                                hex(int(row.source_ea)),
                                row.reason.value,
                                None
                                if row.target_ea is None
                                else hex(int(row.target_ea)),
                            )
                            for row in boundary_port_plan.abstentions
                        ],
                        flush=True,
                    )
            if UNION_GENERATION_MODE == "snippet":
                ranges = ida_hexrays.mba_ranges_t()
            else:
                assert function is not None
                ranges = ida_hexrays.mba_ranges_t(function)
            if UNION_GENERATION_MODE != "function":
                for start_ea, end_ea in semantic_ranges:
                    ranges.ranges.push_back(idaapi.range_t(int(start_ea), int(end_ea)))
            failure = ida_hexrays.hexrays_failure_t()
            generation_flags = int(ida_hexrays.DECOMP_NO_WAIT)
            if PREOPT_ALL_BLOCKS:
                generation_flags |= int(ida_hexrays.DECOMP_ALL_BLKS)
            union_source_generation_active[0] = True
            try:
                snippet = cg._generate_microcode_without_d810(
                    ida_hexrays.gen_microcode,
                    ranges,
                    failure,
                    None,
                    generation_flags,
                    ida_hexrays.MMAT_PREOPTIMIZED,
                )
            finally:
                union_source_generation_active[0] = False
            if snippet is None:
                print(
                    "UNION_CAPTURE",
                    "captured=False",
                    f"failure={failure.desc()!r}",
                    flush=True,
                )
                return 0
            source_edges_before = sum(
                int(snippet.get_mblock(serial).nsucc())
                for serial in range(int(snippet.qty))
            )
            if SOURCE_BUILD_GRAPH:
                snippet.build_graph()
            source_edges_after = sum(
                int(snippet.get_mblock(serial).nsucc())
                for serial in range(int(snippet.qty))
            )
            print(
                "UNION_SOURCE_GRAPH",
                f"build_requested={SOURCE_BUILD_GRAPH}",
                f"edges_before={source_edges_before}",
                f"edges_after={source_edges_after}",
                flush=True,
            )
            empty_in_range_blocks = []
            for serial in range(int(snippet.qty)):
                source_block = snippet.get_mblock(serial)
                instruction_eas = []
                instruction = source_block.head
                while instruction is not None:
                    if int(instruction.ea) > 0:
                        instruction_eas.append(int(instruction.ea))
                    if instruction is source_block.tail:
                        break
                    instruction = instruction.next
                if instruction_eas or not any(
                    int(start_ea) <= int(source_block.start) < int(end_ea)
                    for start_ea, end_ea in semantic_ranges
                ):
                    continue
                empty_in_range_blocks.append(
                    (
                        int(source_block.serial),
                        hex(int(source_block.start)),
                        int(source_block.type),
                        [int(successor) for successor in source_block.succset],
                    )
                )
            print(
                "UNION_SOURCE_EMPTY_IN_RANGE",
                empty_in_range_blocks,
                flush=True,
            )
            print(
                "UNION_SOURCE_PRIMARY_IDENTITY",
                [
                    (
                        int(source_block.serial),
                        hex(int(source_block.start)),
                        None
                        if detached_island._unique_block_native_ea(source_block) is None
                        else hex(
                            int(detached_island._unique_block_native_ea(source_block))
                        ),
                        [
                            hex(int(ea))
                            for ea in detached_island._block_native_eas(source_block)
                        ],
                        [int(successor) for successor in source_block.succset],
                    )
                    for source_block in (
                        snippet.get_mblock(serial) for serial in range(int(snippet.qty))
                    )
                    if int(source_block.start) == int(import_plan.primary_seed_ea)
                    or int(import_plan.primary_seed_ea)
                    in detached_island._block_native_eas(source_block)
                ],
                flush=True,
            )
            if semantic_unproven_abstentions:
                unresolved_source_eas = {
                    int(row.source_block_ea)
                    for row in semantic_unproven_abstentions
                    if row.source_block_ea is not None
                }
                unresolved_rows = []
                for serial in range(int(snippet.qty)):
                    source_block = snippet.get_mblock(serial)
                    instruction_rows = []
                    instruction = source_block.head
                    while instruction is not None:
                        instruction_rows.append(
                            (
                                hex(int(instruction.ea)),
                                int(instruction.opcode),
                                instruction.dstr(),
                            )
                        )
                        if instruction is source_block.tail:
                            break
                        instruction = instruction.next
                    native_eas = {
                        int(instruction_ea, 16)
                        for instruction_ea, _opcode, _text in instruction_rows
                        if int(instruction_ea, 16) > 0
                    }
                    matching_sources = sorted(unresolved_source_eas & native_eas)
                    if not matching_sources:
                        continue
                    unresolved_rows.append(
                        (
                            [hex(ea) for ea in matching_sources],
                            f"blk{int(source_block.serial)}@0x{min(native_eas):X}",
                            int(source_block.type),
                            [int(successor) for successor in source_block.succset],
                            instruction_rows,
                        )
                    )
                print(
                    "PREOPT_UNPROVEN_CUT_SHAPES",
                    unresolved_rows,
                    flush=True,
                )
            if BOUNDARY_PORT_MODE and boundary_port_plans:
                port_facts, ambiguous_port_entry_eas = build_preopt_port_block_facts(
                    snippet,
                    snippet_return_address_size=(
                        first_preopt_return_address_sizes[0]
                        if first_preopt_return_address_sizes
                        else None
                    ),
                )
                if captured_preopt_entry_seed:
                    entry_evidence = captured_preopt_entry_seed[0][0]
                    print(
                        "PREOPT_STACK_CELL_REBASE",
                        f"live_vd={hex(int(entry_evidence.stack_cell_identity[0]))}",
                        "snippet_loads="
                        f"{[(hex(int(block_ea)), int(register), hex(int(stack_off)), int(size), hex(int(load_ea))) for block_ea, fact in sorted(port_facts.items()) for register, stack_off, size, load_ea in fact.register_stack_loads]}",
                        flush=True,
                    )
                closure_port_facts = {
                    int(block_ea): fact
                    for block_ea, fact in port_facts.items()
                    if block_intersects_owned_ranges(
                        int(fact.start_ea),
                        fact.instruction_eas,
                        semantic_ranges,
                    )
                }
                capture_block_entry_eas = semantic_delta_block_entry_eas(
                    closure_port_facts,
                    live_native_eas=surviving_native_eas,
                    requested_root_eas=(int(import_plan.primary_seed_ea),),
                )
                if any(
                    detached_island._unique_block_native_ea(snippet.get_mblock(serial))
                    == int(import_plan.primary_seed_ea)
                    for serial in range(int(snippet.qty))
                ):
                    capture_block_entry_eas = frozenset(
                        (*capture_block_entry_eas, int(import_plan.primary_seed_ea))
                    )
                capture_range_rows = [
                    (
                        int(port_facts[entry_ea].start_ea),
                        int(port_facts[entry_ea].end_ea),
                    )
                    for entry_ea in sorted(capture_block_entry_eas)
                    if entry_ea in port_facts
                ]
                missing_capture_entries = {
                    int(entry_ea)
                    for entry_ea in capture_block_entry_eas
                    if int(entry_ea) not in port_facts
                }
                fallback_capture_ranges = {
                    (int(start_ea), int(end_ea))
                    for entry_ea in missing_capture_entries
                    for start_ea, end_ea in semantic_ranges
                    if int(start_ea) <= int(entry_ea) < int(end_ea)
                }
                if any(
                    not any(
                        int(start_ea) <= int(entry_ea) < int(end_ea)
                        for start_ea, end_ea in fallback_capture_ranges
                    )
                    for entry_ea in missing_capture_entries
                ):
                    print(
                        "PREOPT_CAPTURE_RANGE_ABSTAIN",
                        [hex(ea) for ea in sorted(missing_capture_entries)],
                        flush=True,
                    )
                    return 0
                capture_ranges = merge_detached_snippet_ranges(
                    (*capture_range_rows, *sorted(fallback_capture_ranges))
                )
                print(
                    "PREOPT_SEMANTIC_DELTA_BLOCKS",
                    f"closure_blocks={len(closure_port_facts)}",
                    f"owned={len(capture_block_entry_eas)}",
                    [hex(ea) for ea in sorted(capture_block_entry_eas)],
                    flush=True,
                )
                print(
                    "PREOPT_STATE_WRITE_FACTS",
                    [
                        (
                            hex(int(block_ea)),
                            tuple(
                                (
                                    int(register),
                                    hex(int(constant)),
                                    hex(int(write_ea)),
                                )
                                for register, constant, write_ea in fact.register_constant_writes
                                if int(register) in state_registers
                            ),
                            tuple(hex(int(ea)) for ea in fact.successor_eas),
                            fact.tail_kind.value,
                            None if fact.tail_ea is None else hex(int(fact.tail_ea)),
                        )
                        for block_ea, fact in sorted(port_facts.items())
                        if any(
                            int(register) in state_registers
                            for register, _constant, _write_ea in fact.register_constant_writes
                        )
                    ],
                    flush=True,
                )
                state_transition_cuts: list[PreoptUnresolvedStateCut] = []
                if len(state_registers) == 1:
                    state_register = next(iter(state_registers))
                    for abstention in semantic_unproven_abstentions:
                        if (
                            abstention.reason
                            is not ClosureAbstentionReason.UNPROVEN_INDIRECT_TARGET
                            or abstention.source_block_ea is None
                        ):
                            continue
                        native_block = native_cfg.blocks_by_ea.get(
                            int(abstention.source_block_ea)
                        )
                        if native_block is None:
                            continue
                        tail_eas = {
                            int(edge.source_instruction_ea)
                            for edge in native_block.outgoing_edges
                            if edge.kind is NativeEdgeKind.INDIRECT
                            and not edge.resolver_proven
                            and edge.source_instruction_ea is not None
                        }
                        if len(tail_eas) != 1:
                            continue
                        state_transition_cuts.append(
                            PreoptUnresolvedStateCut(
                                source_block_ea=int(native_block.start_ea),
                                tail_ea=next(iter(tail_eas)),
                                state_register=int(state_register),
                            )
                        )
                state_handler_eas = state_payload_handler_eas
                imported_block_ranges = {
                    int(entry_ea): (
                        int(native_cfg.blocks_by_ea[entry_ea].start_ea),
                        int(native_cfg.blocks_by_ea[entry_ea].end_ea),
                    )
                    for entry_ea in semantic_closure.included_block_eas
                }
                live_capture_port_facts = (
                    {}
                    if not latest_preopt_live_port_facts
                    else dict(latest_preopt_live_port_facts[0])
                )
                for (
                    evidence,
                    _initial_state,
                    _state_register,
                ) in captured_preopt_entry_seed:
                    source_fact = preopt_entry_bridge_source_fact(evidence)
                    if source_fact is not None:
                        live_capture_port_facts[int(source_fact.start_ea)] = source_fact
                pruned_live_conditional_source_eas = tuple(
                    sorted(
                        int(source_ea)
                        for source_ea, fact in live_capture_port_facts.items()
                        if fact.tail_kind is PreoptPortTailKind.CONDITIONAL
                        and fact.tail_ea is not None
                        and fact.successors_complete
                        and not fact.successor_eas
                    )
                )
                pruned_live_conditional_topology = {}
                conditional_routing_targets_by_source_ea: dict[int, set[int]] = {}
                live_conditional_native_cfg = None
                if pruned_live_conditional_source_eas:
                    live_conditional_native_cfg = build_native_semantic_cfg(
                        function,
                        live_native_eas=preopt_live_native_eas,
                        seed_eas=pruned_live_conditional_source_eas,
                        resolver_cut_eas=resolver_cut_eas,
                        resolver_target_eas_by_source=(resolver_target_eas_by_source),
                    )
                    for (
                        native_block
                    ) in live_conditional_native_cfg.blocks_by_ea.values():
                        exact_targets = {
                            int(edge.target_ea)
                            for edge in native_block.outgoing_edges
                            if edge.target_ea is not None
                            and (
                                edge.kind is not NativeEdgeKind.INDIRECT
                                or edge.resolver_proven
                            )
                        }
                        if exact_targets:
                            conditional_routing_targets_by_source_ea.setdefault(
                                int(native_block.start_ea), set()
                            ).update(exact_targets)
                    for (
                        source_ea,
                        target_eas,
                    ) in resolver_materialized_bridge_targets_by_source_ea.items():
                        conditional_routing_targets_by_source_ea.setdefault(
                            int(source_ea), set()
                        ).update(int(target_ea) for target_ea in target_eas)
                    for source_ea in pruned_live_conditional_source_eas:
                        source_fact = live_capture_port_facts[source_ea]
                        native_block = live_conditional_native_cfg.blocks_by_ea.get(
                            source_ea
                        )
                        if native_block is None or source_fact.tail_ea is None:
                            continue
                        predicate_ea = int(source_fact.tail_ea)
                        if not (
                            int(native_block.start_ea)
                            <= predicate_ea
                            < int(native_block.end_ea)
                        ):
                            continue
                        taken_targets = {
                            int(edge.target_ea)
                            for edge in native_block.outgoing_edges
                            if edge.kind is NativeEdgeKind.CONDITIONAL_TRUE
                            and edge.target_ea is not None
                        }
                        fallthrough_targets = {
                            int(edge.target_ea)
                            for edge in native_block.outgoing_edges
                            if edge.kind is NativeEdgeKind.CONDITIONAL_FALSE
                            and edge.target_ea is not None
                        }
                        if len(taken_targets) != 1 or len(fallthrough_targets) != 1:
                            continue
                        taken_ea = next(iter(taken_targets))
                        fallthrough_ea = next(iter(fallthrough_targets))
                        if taken_ea == fallthrough_ea:
                            continue
                        pruned_live_conditional_topology[source_ea] = (
                            PreoptConditionalTopologyFact(
                                source_block_ea=source_ea,
                                predicate_ea=predicate_ea,
                                taken_successor_ea=taken_ea,
                                fallthrough_successor_ea=fallthrough_ea,
                            )
                        )
                    conditional_arm_seed_eas = {
                        int(arm_ea)
                        for fact in pruned_live_conditional_topology.values()
                        for arm_ea in (
                            fact.taken_successor_ea,
                            fact.fallthrough_successor_ea,
                        )
                    }
                    if conditional_arm_seed_eas:
                        conditional_arm_native_cfg = build_native_semantic_cfg(
                            function,
                            live_native_eas=preopt_live_native_eas,
                            seed_eas=conditional_arm_seed_eas,
                            resolver_cut_eas=resolver_cut_eas,
                            resolver_target_eas_by_source=(
                                resolver_target_eas_by_source
                            ),
                        )
                        for (
                            native_block
                        ) in conditional_arm_native_cfg.blocks_by_ea.values():
                            exact_targets = {
                                int(edge.target_ea)
                                for edge in native_block.outgoing_edges
                                if edge.target_ea is not None
                                and (
                                    edge.kind is not NativeEdgeKind.INDIRECT
                                    or edge.resolver_proven
                                )
                            }
                            if exact_targets:
                                conditional_routing_targets_by_source_ea.setdefault(
                                    int(native_block.start_ea), set()
                                ).update(exact_targets)
                pruned_live_conditional_choices = (
                    recognize_preopt_pruned_conditional_state_choices(
                        blocks_by_ea=live_capture_port_facts,
                        native_topology_by_ea=(pruned_live_conditional_topology),
                        state_register=next(iter(state_registers)),
                        source_owner=PreoptBoundaryEndpointOwner.LIVE,
                    )
                    if len(state_registers) == 1
                    else ()
                )
                conditional_state_choices = ()
                if state_transition_cuts:
                    conditional_state_choices = tuple(
                        sorted(
                            set(
                                recognize_preopt_conditional_state_choices(
                                    tuple(state_transition_cuts),
                                    blocks_by_ea=port_facts,
                                )
                            )
                            | set(
                                recognize_preopt_stack_carried_state_choices(
                                    tuple(state_transition_cuts),
                                    blocks_by_ea=port_facts,
                                    entry_bridge_evidence=(
                                        ()
                                        if not captured_preopt_entry_seed
                                        else (captured_preopt_entry_seed[0][0],)
                                    ),
                                )
                            ),
                            key=lambda row: (
                                int(row.consumer_tail_ea),
                                int(row.predicate_block_ea),
                                int(row.predicate_ea),
                                int(row.state_register),
                            ),
                        )
                    )
                state_transition_plan = (
                    plan_preopt_state_transition_boundary_ports(
                        tuple(state_transition_cuts),
                        blocks_by_ea=port_facts,
                        state_handler_eas=state_handler_eas,
                        state_payload_handler_eas=state_payload_handler_eas,
                        conditional_choices=conditional_state_choices,
                        imported_block_ranges=imported_block_ranges,
                        live_native_eas=preopt_live_native_eas,
                    )
                    if state_transition_cuts
                    else PreoptBoundaryPortPlan((), (), ())
                )
                pruned_live_conditional_plan = (
                    plan_preopt_conditional_state_choice_boundary_ports(
                        pruned_live_conditional_choices,
                        state_handler_eas=state_handler_eas,
                        state_payload_handler_eas=state_payload_handler_eas,
                        imported_block_ranges=imported_block_ranges,
                        live_native_eas=preopt_live_native_eas,
                    )
                    if pruned_live_conditional_choices
                    else PreoptBoundaryPortPlan((), (), ())
                )
                literal_state_plan = (
                    plan_preopt_owned_literal_state_write_boundary_ports(
                        imported_blocks_by_ea=port_facts,
                        live_blocks_by_ea=live_capture_port_facts,
                        state_register=next(iter(state_registers)),
                        state_handler_eas=state_handler_eas,
                        state_payload_handler_eas=state_payload_handler_eas,
                        imported_block_ranges=imported_block_ranges,
                        live_native_eas=preopt_live_native_eas,
                    )
                    if len(state_registers) == 1
                    else PreoptBoundaryPortPlan((), (), ())
                )
                terminal_return_plan = (
                    plan_preopt_terminal_return_boundary_ports(
                        tuple(pruned_live_conditional_topology.values()),
                        terminal_requests,
                        imported_block_ranges=imported_block_ranges,
                        live_native_eas=preopt_live_native_eas,
                    )
                    if pruned_live_conditional_topology and terminal_requests
                    else PreoptBoundaryPortPlan((), (), ())
                )
                already_planned_conditionals = (
                    boundary_port_plans[0].conditional
                    + state_transition_plan.conditional
                    + pruned_live_conditional_plan.conditional
                    + terminal_return_plan.conditional
                )
                stable_routing_endpoint_eas = {
                    int(target_ea)
                    for target_eas in state_handler_eas.values()
                    for target_ea in target_eas
                } | {int(request.source_handler_ea) for request in terminal_requests}
                exact_direct_rows = tuple(
                    (int(row.source_block_ea), int(row.target_ea))
                    for row in (
                        boundary_port_plans[0].direct
                        + state_transition_plan.direct
                        + literal_state_plan.direct
                    )
                )
                source_sensitive_targets_by_source_ea: dict[int, set[int]] = {}
                for source_ea, target_ea in exact_direct_rows:
                    source_sensitive_targets_by_source_ea.setdefault(
                        source_ea, set()
                    ).add(target_ea)
                fixed_source_arm_routes = derive_preopt_fixed_source_arm_routes(
                    tuple(pruned_live_conditional_topology.values()),
                    source_sensitive_targets_by_source_ea=(
                        source_sensitive_targets_by_source_ea
                    ),
                )
                conditional_choice_arm_routes: list[tuple[int, int]] = []
                for choice in pruned_live_conditional_choices:
                    topology = pruned_live_conditional_topology.get(
                        int(choice.predicate_block_ea)
                    )
                    if topology is None:
                        continue
                    for arm_ea, state in (
                        (topology.taken_successor_ea, choice.taken_state),
                        (
                            topology.fallthrough_successor_ea,
                            choice.fallthrough_state,
                        ),
                    ):
                        targets = {
                            int(target_ea)
                            for target_ea in state_handler_eas.get(
                                int(state) & 0xFFFFFFFF, ()
                            )
                        }
                        if len(targets) == 1:
                            conditional_choice_arm_routes.append(
                                (int(arm_ea), next(iter(targets)))
                            )
                conditional_routing_targets_by_source_ea = (
                    merge_preopt_exact_route_targets(
                        conditional_routing_targets_by_source_ea,
                        exact_routes=(
                            exact_direct_rows
                            + fixed_source_arm_routes
                            + tuple(conditional_choice_arm_routes)
                        ),
                    )
                )
                conditional_routing_plan = (
                    plan_preopt_conditional_routing_boundary_ports(
                        exclude_preopt_conditional_topology_with_planned_predicates(
                            tuple(pruned_live_conditional_topology.values()),
                            already_planned_conditionals,
                        ),
                        exact_targets_by_source_ea=(
                            conditional_routing_targets_by_source_ea
                        ),
                        stable_endpoint_eas=stable_routing_endpoint_eas,
                        imported_block_ranges=imported_block_ranges,
                        live_native_eas=preopt_live_native_eas,
                    )
                    if pruned_live_conditional_topology
                    else PreoptBoundaryPortPlan((), (), ())
                )
                print(
                    "PREOPT_STATE_TRANSITION_BOUNDARY_PLAN",
                    f"cuts={len(state_transition_cuts)}",
                    f"handlers={len(state_handler_eas)}",
                    f"direct={len(state_transition_plan.direct)}",
                    f"conditional={len(state_transition_plan.conditional)}",
                    f"abstentions={len(state_transition_plan.abstentions)}",
                    [
                        (
                            hex(int(row.consumer_tail_ea)),
                            hex(int(row.predicate_block_ea)),
                            hex(int(row.predicate_ea)),
                            hex(int(row.taken_state)),
                            hex(int(row.fallthrough_state)),
                        )
                        for row in conditional_state_choices
                    ],
                    [
                        (
                            hex(int(row.source_ea)),
                            row.reason.value,
                            None if row.target_ea is None else hex(int(row.target_ea)),
                        )
                        for row in state_transition_plan.abstentions
                    ],
                    flush=True,
                )
                print(
                    "PREOPT_PRUNED_LIVE_CONDITIONAL_PLAN",
                    f"topology={len(pruned_live_conditional_topology)}",
                    f"choices={len(pruned_live_conditional_choices)}",
                    f"conditional={len(pruned_live_conditional_plan.conditional)}",
                    f"abstentions={len(pruned_live_conditional_plan.abstentions)}",
                    [
                        (
                            hex(int(row.predicate_block_ea)),
                            hex(int(row.predicate_ea)),
                            hex(int(row.taken_state)),
                            hex(int(row.fallthrough_state)),
                        )
                        for row in pruned_live_conditional_choices
                    ],
                    flush=True,
                )
                print(
                    "PREOPT_LITERAL_STATE_WRITE_BOUNDARY_PLAN",
                    f"direct={len(literal_state_plan.direct)}",
                    f"abstentions={len(literal_state_plan.abstentions)}",
                    [
                        (
                            hex(int(row.source_ea)),
                            row.reason.value,
                            None if row.target_ea is None else hex(int(row.target_ea)),
                        )
                        for row in literal_state_plan.abstentions
                    ],
                    flush=True,
                )
                print(
                    "PREOPT_TERMINAL_RETURN_BOUNDARY_PLAN",
                    f"conditional={len(terminal_return_plan.conditional)}",
                    f"abstentions={len(terminal_return_plan.abstentions)}",
                    [
                        (
                            hex(int(row.source_block_ea)),
                            hex(int(row.predicate_ea)),
                            hex(int(row.taken_target_ea)),
                            hex(int(row.fallthrough_target_ea)),
                            row.taken_state,
                            row.fallthrough_state,
                        )
                        for row in terminal_return_plan.conditional
                    ],
                    [
                        (
                            hex(int(row.source_ea)),
                            row.reason.value,
                            None if row.target_ea is None else hex(int(row.target_ea)),
                        )
                        for row in terminal_return_plan.abstentions
                    ],
                    flush=True,
                )
                print(
                    "PREOPT_CONDITIONAL_ROUTING_BOUNDARY_PLAN",
                    f"conditional={len(conditional_routing_plan.conditional)}",
                    f"abstentions={len(conditional_routing_plan.abstentions)}",
                    [
                        (
                            hex(int(row.source_block_ea)),
                            hex(int(row.predicate_ea)),
                            hex(int(row.taken_target_ea)),
                            hex(int(row.fallthrough_target_ea)),
                        )
                        for row in conditional_routing_plan.conditional
                    ],
                    [
                        (
                            hex(int(row.source_ea)),
                            row.reason.value,
                            None if row.target_ea is None else hex(int(row.target_ea)),
                        )
                        for row in conditional_routing_plan.abstentions
                    ],
                    flush=True,
                )
                if state_transition_plan.abstentions and not UNION_GENERATE_ONLY:
                    return 0
                base_boundary_port_plan = boundary_port_plans[0]
                conditional_candidates = (
                    base_boundary_port_plan.conditional
                    + state_transition_plan.conditional
                    + pruned_live_conditional_plan.conditional
                    + terminal_return_plan.conditional
                    + conditional_routing_plan.conditional
                )
                (
                    merged_conditional,
                    conditional_merge_abstentions,
                ) = coalesce_preopt_conditional_boundary_ports(conditional_candidates)
                conditional_source_blocks = {
                    int(row.source_block_ea) for row in conditional_candidates
                } | {
                    int(row.predicate_block_ea)
                    for row in pruned_live_conditional_choices
                }
                merged_direct_by_key = {}
                for row in (
                    base_boundary_port_plan.direct
                    + state_transition_plan.direct
                    + literal_state_plan.direct
                ):
                    if int(row.source_block_ea) in conditional_source_blocks:
                        continue
                    key = (
                        int(row.source_block_ea),
                        int(row.source_instruction_ea),
                        int(row.target_ea),
                        int(row.state_register),
                        int(row.state_constant),
                        row.source_owner,
                        row.target_owner,
                    )
                    merged_direct_by_key.setdefault(key, row)
                boundary_port_plans[:] = [
                    PreoptBoundaryPortPlan(
                        direct=tuple(
                            sorted(
                                merged_direct_by_key.values(),
                                key=lambda row: (
                                    int(row.source_block_ea),
                                    int(row.source_instruction_ea),
                                    int(row.target_ea),
                                ),
                            )
                        ),
                        conditional=merged_conditional,
                        abstentions=tuple(
                            sorted(
                                set(base_boundary_port_plan.abstentions)
                                | set(state_transition_plan.abstentions)
                                | set(pruned_live_conditional_plan.abstentions)
                                | set(terminal_return_plan.abstentions)
                                | set(conditional_merge_abstentions)
                                | set(literal_state_plan.abstentions),
                                key=lambda row: (
                                    int(row.source_ea),
                                    row.reason.value,
                                    row.target_ea is None,
                                    row.target_ea or 0,
                                ),
                            )
                        ),
                    )
                ]
                from d810.analyses.control_flow.dispatcher_recovery import (
                    recover_dispatcher,
                )
                from d810.hexrays.mutation.ir_translator import lift

                source_flow_graph = lift(snippet)
                source_dispatcher_recovery = recover_dispatcher(
                    source_flow_graph,
                    None,
                    materialized_indirect_transfers=resolver_state.materialized_transfers,
                )
                source_dispatcher_map = source_dispatcher_recovery.dispatch_map
                source_dispatcher_router_eas = frozenset(
                    int(block.start_ea)
                    for serial in (
                        ()
                        if source_dispatcher_map is None
                        else source_dispatcher_map.dispatcher_blocks
                    )
                    if (block := source_flow_graph.get_block(int(serial))) is not None
                    and int(block.start_ea) > 0
                )
                dispatcher_entry_eas = (
                    frozenset(
                        int(dispatcher_ea)
                        for transfer in resolver_state.materialized_transfers
                        for dispatcher_ea in transfer.dispatcher_router_eas
                    )
                    | source_dispatcher_router_eas
                )
                fixed_state_expected_targets_by_source_ea: dict[int, set[int]] = {}
                fixed_state_expected_write_eas_by_source_ea: dict[int, set[int]] = {}
                exact_state_transition_source_eas = frozenset(
                    int(row.source_block_ea)
                    for row in (
                        state_transition_plan.direct + literal_state_plan.direct
                    )
                    if row.source_owner is PreoptBoundaryEndpointOwner.LIVE
                )
                proven_indirect_source_block_eas = frozenset(
                    int(source_ea)
                    for source_ea in exact_state_transition_source_eas
                    if live_conditional_native_cfg is not None
                    and (
                        native_source := (
                            live_conditional_native_cfg.blocks_by_ea.get(int(source_ea))
                        )
                    )
                    is not None
                    and any(
                        edge.kind is NativeEdgeKind.INDIRECT
                        for edge in native_source.outgoing_edges
                    )
                )
                for row in (
                    base_boundary_port_plan.direct
                    + state_transition_plan.direct
                    + literal_state_plan.direct
                ):
                    if row.source_owner is not PreoptBoundaryEndpointOwner.LIVE:
                        continue
                    fixed_state_expected_targets_by_source_ea.setdefault(
                        int(row.source_block_ea),
                        set(),
                    ).add(int(row.target_ea))
                    fixed_state_expected_write_eas_by_source_ea.setdefault(
                        int(row.source_block_ea),
                        set(),
                    ).add(int(row.source_instruction_ea))
                print(
                    "PREOPT_PROVEN_INDIRECT_SOURCE_BLOCKS",
                    [hex(int(ea)) for ea in sorted(proven_indirect_source_block_eas)],
                    flush=True,
                )
                print(
                    "PREOPT_INDIRECT_FIXED_STATE_PROOF_INPUTS",
                    [
                        (
                            hex(int(source_ea)),
                            (
                                None
                                if live_conditional_native_cfg is None
                                or (
                                    native_source := (
                                        live_conditional_native_cfg.blocks_by_ea.get(
                                            int(source_ea)
                                        )
                                    )
                                )
                                is None
                                else (
                                    hex(int(native_source.start_ea)),
                                    hex(int(native_source.end_ea)),
                                    tuple(
                                        (
                                            edge.kind.value,
                                            (
                                                None
                                                if edge.target_ea is None
                                                else hex(int(edge.target_ea))
                                            ),
                                            bool(edge.resolver_proven),
                                        )
                                        for edge in native_source.outgoing_edges
                                    ),
                                )
                            ),
                            tuple(
                                hex(int(ea))
                                for ea in sorted(
                                    fixed_state_expected_targets_by_source_ea.get(
                                        int(source_ea), ()
                                    )
                                )
                            ),
                            tuple(
                                hex(int(ea))
                                for ea in sorted(
                                    fixed_state_expected_write_eas_by_source_ea.get(
                                        int(source_ea), ()
                                    )
                                )
                            ),
                            tuple(
                                hex(int(ea))
                                for ea in live_capture_port_facts[
                                    int(source_ea)
                                ].instruction_eas
                            ),
                            (int(source_ea) in pruned_live_conditional_topology),
                            live_capture_port_facts[
                                int(source_ea)
                            ].has_synthetic_function_exit_successor,
                            (
                                int(source_ea)
                                in {
                                    int(choice.predicate_block_ea)
                                    for choice in (pruned_live_conditional_choices)
                                }
                            ),
                            int(source_ea) in proven_indirect_source_block_eas,
                        )
                        for source_ea in sorted(
                            fixed_state_expected_targets_by_source_ea
                        )
                        if int(source_ea) in live_capture_port_facts
                        and int(source_ea) not in pruned_live_conditional_topology
                    ],
                    flush=True,
                )
                proven_pruned_conditional_direct_source_eas = (
                    prove_preopt_pruned_conditional_fixed_state_sources(
                        blocks_by_ea=live_capture_port_facts,
                        native_topology_by_ea=(pruned_live_conditional_topology),
                        state_register=next(iter(state_registers)),
                        dispatcher_router_eas=dispatcher_entry_eas,
                        resolver_bridge_targets_by_source_ea=(
                            resolver_materialized_bridge_targets_by_source_ea
                        ),
                        expected_target_eas_by_source_ea=(
                            fixed_state_expected_targets_by_source_ea
                        ),
                        expected_state_write_eas_by_source_ea=(
                            fixed_state_expected_write_eas_by_source_ea
                        ),
                        proven_indirect_source_block_eas=(
                            proven_indirect_source_block_eas
                        ),
                        excluded_source_eas=frozenset(
                            int(choice.predicate_block_ea)
                            for choice in pruned_live_conditional_choices
                        ),
                    )
                    if len(state_registers) == 1
                    else frozenset()
                )
                print(
                    "PREOPT_PRUNED_ROUTER_CONDITIONAL_DIRECT_PROOFS",
                    f"count={len(proven_pruned_conditional_direct_source_eas)}",
                    [
                        hex(int(ea))
                        for ea in sorted(proven_pruned_conditional_direct_source_eas)
                    ],
                    f"resolver_bridges={len(resolver_materialized_bridge_targets_by_source_ea)}",
                    flush=True,
                )
                resolver_targets_by_source_block_ea: dict[int, set[int]] = {}
                for transfer in resolver_state.materialized_transfers:
                    if transfer.resolver_kind not in {
                        "static_fixpoint",
                        "detached_static_fixpoint",
                    }:
                        continue
                    resolver_targets_by_source_block_ea.setdefault(
                        int(transfer.source_block_ea), set()
                    ).update(int(ea) for ea in transfer.target_eas)
                print(
                    "PREOPT_BOUNDARY_PORT_SOURCE_DISPATCHER",
                    f"recovered={source_dispatcher_map is not None}",
                    f"router_eas={len(source_dispatcher_router_eas)}",
                    f"entry_ea={None if source_dispatcher_map is None else hex(int(source_flow_graph.get_block(int(source_dispatcher_map.dispatcher_entry_block)).start_ea))}",
                    flush=True,
                )
                capture_port_facts = dict(port_facts)
                live_source_shapes = []
                for request in boundary_port_plans[0].direct:
                    if request.source_owner is not PreoptBoundaryEndpointOwner.LIVE:
                        continue
                    candidates = tuple(
                        fact
                        for fact in live_capture_port_facts.values()
                        if int(fact.start_ea) == int(request.source_block_ea)
                        or int(request.source_instruction_ea)
                        in map(int, fact.instruction_eas)
                    )
                    live_source_shapes.append(
                        (
                            "direct",
                            hex(int(request.source_block_ea)),
                            hex(int(request.source_instruction_ea)),
                            tuple(
                                (
                                    hex(int(fact.start_ea)),
                                    None
                                    if fact.tail_ea is None
                                    else hex(int(fact.tail_ea)),
                                    fact.tail_kind.value,
                                    tuple(hex(int(ea)) for ea in fact.successor_eas),
                                    fact.successors_complete,
                                )
                                for fact in candidates
                            ),
                        )
                    )
                for request in boundary_port_plans[0].conditional:
                    if request.source_owner is not PreoptBoundaryEndpointOwner.LIVE:
                        continue
                    candidates = tuple(
                        fact
                        for fact in live_capture_port_facts.values()
                        if int(fact.start_ea) == int(request.source_block_ea)
                        or int(request.predicate_ea) in map(int, fact.instruction_eas)
                    )
                    live_source_shapes.append(
                        (
                            "conditional",
                            hex(int(request.source_block_ea)),
                            hex(int(request.predicate_ea)),
                            tuple(
                                (
                                    hex(int(fact.start_ea)),
                                    None
                                    if fact.tail_ea is None
                                    else hex(int(fact.tail_ea)),
                                    fact.tail_kind.value,
                                    tuple(hex(int(ea)) for ea in fact.successor_eas),
                                    None
                                    if fact.taken_successor_ea is None
                                    else hex(int(fact.taken_successor_ea)),
                                    None
                                    if fact.fallthrough_successor_ea is None
                                    else hex(int(fact.fallthrough_successor_ea)),
                                )
                                for fact in candidates
                            ),
                        )
                    )
                print(
                    "PREOPT_LIVE_BOUNDARY_SOURCE_SHAPES",
                    live_source_shapes,
                    flush=True,
                )
                boundary_port_capture = capture_preopt_boundary_ports(
                    boundary_port_plans[0],
                    blocks_by_ea=capture_port_facts,
                    live_blocks_by_ea=live_capture_port_facts,
                    dispatcher_entry_eas=dispatcher_entry_eas,
                    resolver_cut_instruction_eas=frozenset(
                        int(transfer.source_jmp_ea)
                        for transfer in resolver_state.materialized_transfers
                        if transfer.resolver_kind
                        in {
                            "static_fixpoint",
                            "detached_static_fixpoint",
                        }
                    )
                    | frozenset(int(cut.tail_ea) for cut in state_transition_cuts),
                    resolver_targets_by_source_block_ea=(
                        resolver_targets_by_source_block_ea
                    ),
                    proven_pruned_conditional_direct_source_eas=(
                        proven_pruned_conditional_direct_source_eas
                    ),
                )
                boundary_port_capture = exclude_ports_satisfied_by_internal_edges(
                    boundary_port_capture,
                    proven_internal_edges=frozenset(
                        (
                            int(edge.source_ea),
                            int(edge.target_ea),
                        )
                        for edge in semantic_closure.proven_internal_edges
                    ),
                )
                boundary_port_capture = (
                    exclude_direct_endpoints_superseded_by_conditionals(
                        boundary_port_capture
                    )
                )
                closure_crossings = capture_preopt_live_to_imported_crossings(
                    blocks_by_ea=closure_port_facts,
                    proven_internal_edges=tuple(
                        (int(edge.source_ea), int(edge.target_ea))
                        for edge in semantic_closure.proven_internal_edges
                    ),
                    imported_block_eas=capture_block_entry_eas,
                    live_native_eas=preopt_live_native_eas,
                    excluded_source_eas=state_transition_owned_endpoint_eas(
                        boundary_port_capture
                    ),
                )
                boundary_port_captures[:] = [boundary_port_capture]
                print(
                    "PREOPT_BOUNDARY_PORT_CAPTURE",
                    f"facts={len(port_facts)}",
                    f"ambiguous_entries={[hex(ea) for ea in sorted(ambiguous_port_entry_eas)]}",
                    f"dispatcher_entries={[hex(ea) for ea in sorted(dispatcher_entry_eas)]}",
                    f"direct={len(boundary_port_capture.direct)}",
                    f"conditional={len(boundary_port_capture.conditional)}",
                    f"abstentions={len(boundary_port_capture.abstentions)}",
                    flush=True,
                )
                print(
                    "PREOPT_LIVE_TO_IMPORTED_CROSSINGS",
                    f"direct={len(closure_crossings.direct)}",
                    f"conditional={len(closure_crossings.conditional)}",
                    "direct_rows="
                    f"{[(hex(int(row.source_block_ea)), hex(int(row.source_instruction_ea)), hex(int(row.target_ea)), row.delivery_mode) for row in closure_crossings.direct]}",
                    "conditional_rows="
                    f"{[(hex(int(row.source_block_ea)), hex(int(row.predicate_ea)), hex(int(row.taken_target_ea)), hex(int(row.fallthrough_target_ea))) for row in closure_crossings.conditional]}",
                    "abstentions="
                    f"{[(hex(int(row.source_ea)), row.reason.value, [hex(int(ea)) for ea in row.target_eas]) for row in closure_crossings.abstentions]}",
                    flush=True,
                )
                print(
                    "PREOPT_BOUNDARY_PORT_CAPTURE_DIRECT",
                    [
                        (
                            hex(int(row.request.source_block_ea)),
                            hex(int(row.request.source_instruction_ea)),
                            [hex(ea) for ea in row.corridor_block_eas],
                            [
                                (
                                    hex(int(edge.source_block_ea)),
                                    hex(int(edge.dispatcher_target_ea)),
                                )
                                for edge in row.frontier_edges
                            ],
                            [hex(int(ea)) for ea in row.terminal_endpoint_block_eas],
                            row.delivery_mode.value,
                            hex(int(row.request.target_ea)),
                        )
                        for row in boundary_port_capture.direct
                    ],
                    flush=True,
                )
                print(
                    "PREOPT_BOUNDARY_PORT_CAPTURE_CONDITIONAL",
                    [
                        (
                            hex(int(row.source_block_ea)),
                            hex(int(row.predicate_ea)),
                            None
                            if row.old_fallthrough_target_ea is None
                            else hex(int(row.old_fallthrough_target_ea)),
                            None
                            if row.old_taken_target_ea is None
                            else hex(int(row.old_taken_target_ea)),
                            hex(int(row.fallthrough_target_ea)),
                            hex(int(row.taken_target_ea)),
                        )
                        for row in boundary_port_capture.conditional
                    ],
                    flush=True,
                )
                print(
                    "PREOPT_BOUNDARY_PORT_CAPTURE_ABSTENTIONS",
                    [
                        (
                            hex(int(row.source_ea)),
                            row.reason.value,
                            None if row.block_ea is None else hex(int(row.block_ea)),
                        )
                        for row in boundary_port_capture.abstentions
                    ],
                    flush=True,
                )
                direct_request_by_instruction_ea = {
                    int(row.source_instruction_ea): row
                    for row in boundary_port_plans[0].direct
                }

                def boundary_port_abstention_shape(row):
                    request = direct_request_by_instruction_ea.get(int(row.source_ea))
                    fact = (
                        None
                        if row.block_ea is None
                        else port_facts.get(int(row.block_ea))
                    )
                    return (
                        hex(int(row.source_ea)),
                        (
                            None
                            if request is None
                            else hex(int(request.source_block_ea))
                        ),
                        (None if request is None else hex(int(request.target_ea))),
                        row.reason.value,
                        (
                            None
                            if row.block_ea is None
                            else (
                                hex(int(row.block_ea)),
                                (None if fact is None else hex(int(fact.tail_ea or 0))),
                                (None if fact is None else fact.tail_kind.value),
                                (
                                    []
                                    if fact is None
                                    else [hex(ea) for ea in fact.successor_eas]
                                ),
                            )
                        ),
                    )

                print(
                    "PREOPT_BOUNDARY_PORT_CAPTURE_ABSTENTION_SHAPES",
                    [
                        boundary_port_abstention_shape(row)
                        for row in boundary_port_capture.abstentions
                    ],
                    flush=True,
                )
                reaching_definitions_by_register = {
                    int(register): reaching_register_definitions(
                        port_facts,
                        int(register),
                    )
                    for register in {
                        int(request.state_register)
                        for request in boundary_port_plans[0].direct
                    }
                }
                print(
                    "PREOPT_BOUNDARY_PORT_UNOWNED_FRONTIERS",
                    [
                        (
                            hex(int(request.source_instruction_ea)),
                            hex(int(request.target_ea)),
                            [
                                (
                                    hex(int(block_ea)),
                                    fact.tail_kind.value,
                                    (
                                        None
                                        if fact.tail_ea is None
                                        else hex(int(fact.tail_ea))
                                    ),
                                    [hex(ea) for ea in fact.successor_eas],
                                    [
                                        hex(ea)
                                        for ea in fact.successor_eas
                                        if int(ea) in dispatcher_entry_eas
                                    ],
                                    [
                                        (
                                            hex(ea),
                                            [
                                                hex(target_ea)
                                                for target_ea in sorted(
                                                    resolver_targets_by_source_block_ea.get(
                                                        int(ea), set()
                                                    )
                                                )
                                            ],
                                        )
                                        for ea in fact.successor_eas
                                        if int(ea) in proven_indirect_source_block_eas
                                    ],
                                )
                                for block_ea, fact in sorted(port_facts.items())
                                if reaching_definitions_by_register[
                                    int(request.state_register)
                                ][1][int(block_ea)]
                                == frozenset({int(request.source_instruction_ea)})
                            ],
                        )
                        for request in boundary_port_plans[0].direct
                        if any(
                            int(row.source_ea) == int(request.source_instruction_ea)
                            for row in boundary_port_capture.abstentions
                        )
                    ],
                    flush=True,
                )
            snippet_native_eas = cg._live_mba_native_eas(snippet)
            visible_seed_eas = tuple(
                seed_ea for seed_ea in plan.seed_eas if seed_ea in snippet_native_eas
            )
            missing_seed_eas = tuple(
                seed_ea
                for seed_ea in plan.seed_eas
                if seed_ea not in snippet_native_eas
            )
            outside_function_seed_eas = tuple(
                seed_ea
                for seed_ea in plan.seed_eas
                if function is not None
                and not ida_funcs.func_contains(function, int(seed_ea))
            )
            print(
                "UNION_GENERATION",
                f"mode={UNION_GENERATION_MODE}",
                f"flags=0x{generation_flags:X}",
                f"blocks={int(snippet.qty)}",
                f"native_eas={len(snippet_native_eas)}",
                f"visible_seeds={len(visible_seed_eas)}/{len(plan.seed_eas)}",
                f"missing_seeds={[hex(ea) for ea in missing_seed_eas]}",
                f"outside_function_seeds={[hex(ea) for ea in outside_function_seed_eas]}",
                flush=True,
            )
            if UNION_GENERATE_ONLY:
                return 0
            template_boundary_ports = ()
            if BOUNDARY_PORT_MODE and boundary_port_captures:
                imported_port_block_eas = capture_block_entry_eas
                template_boundary_ports = production_boundary_ports(
                    boundary_port_captures[0],
                    closure_crossings,
                    imported_port_block_eas,
                    semantic_closure.proven_import_boundary_edges,
                    preopt_live_native_eas,
                    captured_port_instruction_eas(port_facts),
                )
                print(
                    "PREOPT_BOUNDARY_PORT_TEMPLATE",
                    "records="
                    f"{len(template_boundary_ports.direct) + len(template_boundary_ports.conditional)}",
                    f"imported_blocks={len(imported_port_block_eas)}",
                    flush=True,
                )
                direct_rows_by_endpoint_target = {}
                for direct_port in template_boundary_ports.direct:
                    direct_rows_by_endpoint_target.setdefault(
                        (
                            int(direct_port.endpoint_block_ea),
                            int(direct_port.target_ea),
                        ),
                        [],
                    ).append(
                        (
                            hex(int(direct_port.source_block_ea)),
                            hex(int(direct_port.source_instruction_ea)),
                            direct_port.source_owner.value,
                            direct_port.endpoint_owner.value,
                            direct_port.target_owner.value,
                            direct_port.resolver_kind,
                        )
                    )
                print(
                    "PREOPT_BOUNDARY_PORT_DUPLICATE_BINDINGS",
                    [
                        (
                            hex(endpoint_ea),
                            hex(target_ea),
                            tuple(rows),
                        )
                        for (endpoint_ea, target_ea), rows in sorted(
                            direct_rows_by_endpoint_target.items()
                        )
                        if len(rows) > 1
                    ],
                    flush=True,
                )
                latest_template_boundary_port_count[0] = len(
                    template_boundary_ports.direct
                ) + len(template_boundary_ports.conditional)
                imported_port_eas = {
                    int(ea)
                    for port in template_boundary_ports.direct
                    for ea, owner in (
                        (port.source_block_ea, port.source_owner),
                        (port.endpoint_block_ea, port.endpoint_owner),
                        (port.target_ea, port.target_owner),
                    )
                    if owner == DetachedSnippetBoundaryPortOwner.IMPORTED
                } | {
                    int(ea)
                    for port in template_boundary_ports.conditional
                    for ea, owner in (
                        (port.source_block_ea, port.source_owner),
                        (port.taken_target_ea, port.taken_target_owner),
                        (
                            port.fallthrough_target_ea,
                            port.fallthrough_target_owner,
                        ),
                    )
                    if owner == DetachedSnippetBoundaryPortOwner.IMPORTED
                }
                print(
                    "PREOPT_BOUNDARY_PORT_IMPORTED_BINDINGS",
                    [
                        (
                            hex(ea),
                            [
                                (
                                    hex(int(block_ea)),
                                    [
                                        hex(int(instruction_ea))
                                        for instruction_ea in fact.instruction_eas
                                        if int(instruction_ea) == ea
                                    ],
                                )
                                for block_ea, fact in port_facts.items()
                                if int(block_ea) == ea
                                or ea
                                in {
                                    int(instruction_ea)
                                    for instruction_ea in fact.instruction_eas
                                }
                            ],
                        )
                        for ea in sorted(imported_port_eas)
                    ],
                    flush=True,
                )
            calls_failure = ida_hexrays.hexrays_failure_t()
            union_stack_point_ranges[:] = [tuple(capture_ranges)]
            union_source_generation_active[0] = True
            try:
                calls_snippet = cg._generate_microcode_without_d810(
                    ida_hexrays.gen_microcode,
                    ranges,
                    calls_failure,
                    None,
                    generation_flags,
                    ida_hexrays.MMAT_CALLS,
                )
            finally:
                union_source_generation_active[0] = False
            capture_result = capture_detached_snippet_companion_templates(
                FUNC_EA,
                int(import_plan.primary_seed_ea),
                snippet,
                calls_snippet,
                capture_ranges,
                boundary_ports=template_boundary_ports,
                owned_block_entry_eas=capture_block_entry_eas,
            )
            if PRODUCTION_CALLINFO:
                cg.capture_detached_route_callinfo_templates(
                    FUNC_EA,
                    semantic_ranges,
                )
            if not capture_result.captured and CALL_COMPANION_SWEEP:
                sweep_rows = []
                sweep_call_eas: set[int] = set()
                for entry_range in semantic_ranges:
                    sweep_ranges = ida_hexrays.mba_ranges_t()
                    for start_ea, end_ea in (
                        entry_range,
                        *(row for row in semantic_ranges if row != entry_range),
                    ):
                        sweep_ranges.ranges.push_back(
                            idaapi.range_t(int(start_ea), int(end_ea))
                        )
                    sweep_failure = ida_hexrays.hexrays_failure_t()
                    union_source_generation_active[0] = True
                    try:
                        sweep_mba = cg._generate_microcode_without_d810(
                            ida_hexrays.gen_microcode,
                            sweep_ranges,
                            sweep_failure,
                            None,
                            generation_flags,
                            ida_hexrays.MMAT_CALLS,
                        )
                    finally:
                        union_source_generation_active[0] = False
                    analyzed_call_eas = ()
                    analyzed_call_rows = ()
                    duplicate_call_ea = None
                    if sweep_mba is not None:
                        signatures, duplicate_call_ea = (
                            detached_island._detached_call_signatures(sweep_mba)
                        )
                        analyzed_call_eas = tuple(
                            sorted(
                                call_ea
                                for call_ea, signature in signatures.items()
                                if signature.has_arglist
                            )
                        )
                        analyzed_call_rows = tuple(
                            (
                                hex(int(nested.ea)),
                                tuple(
                                    (
                                        int(argument.t),
                                        int(argument.ea),
                                        str(argument),
                                    )
                                    for argument in nested.d.f.args
                                ),
                                format_minsn_t(nested),
                            )
                            for serial in range(int(sweep_mba.qty))
                            for instruction in block_instructions(
                                sweep_mba.get_mblock(serial)
                            )
                            for nested in nested_instructions(instruction)
                            if int(nested.opcode)
                            in (
                                int(ida_hexrays.m_call),
                                int(ida_hexrays.m_icall),
                            )
                            and int(nested.d.t) == int(ida_hexrays.mop_f)
                        )
                        for serial in range(int(sweep_mba.qty)):
                            for instruction in block_instructions(
                                sweep_mba.get_mblock(serial)
                            ):
                                for nested in nested_instructions(instruction):
                                    mba_independent_operand_types = {
                                        int(ida_hexrays.mop_z),
                                        int(ida_hexrays.mop_n),
                                        int(ida_hexrays.mop_v),
                                        int(ida_hexrays.mop_d),
                                    }
                                    if (
                                        int(nested.opcode)
                                        not in (
                                            int(ida_hexrays.m_call),
                                            int(ida_hexrays.m_icall),
                                        )
                                        or int(nested.d.t) != int(ida_hexrays.mop_f)
                                        or any(
                                            int(current.t)
                                            not in mba_independent_operand_types
                                            for argument in nested.d.f.args
                                            for current in (
                                                detached_island._walk_operand_tree(
                                                    argument
                                                )
                                            )
                                        )
                                    ):
                                        continue
                                    route_callinfo_templates.setdefault(
                                        int(nested.ea),
                                        ida_hexrays.minsn_t(nested),
                                    )
                        sweep_call_eas.update(analyzed_call_eas)
                    sweep_rows.append(
                        (
                            f"[0x{int(entry_range[0]):X},0x{int(entry_range[1]):X})",
                            0 if sweep_mba is None else int(sweep_mba.qty),
                            tuple(hex(ea) for ea in analyzed_call_eas),
                            (
                                None
                                if duplicate_call_ea is None
                                else hex(int(duplicate_call_ea))
                            ),
                            analyzed_call_rows,
                            sweep_failure.desc(),
                        )
                    )
                print(
                    "UNION_CALL_COMPANION_SWEEP",
                    f"covered={[hex(ea) for ea in sorted(sweep_call_eas)]}",
                    "missing="
                    f"{[hex(ea) for ea in sorted(set(capture_result.call_eas) - sweep_call_eas)]}",
                    f"rows={sweep_rows}",
                    flush=True,
                )
            captured = capture_result.captured
            if RAW_UNION_CALLS and not captured:
                dump_call_argument_regions("source-preopt-union", snippet)
                dump_stack_basis_probe(
                    "source-preopt-union",
                    snippet,
                    0x40AF23,
                    216,
                )
                dump_native_stack_identity_diff("source-preopt-union", snippet)
                captured = capture_detached_snippet_template(
                    FUNC_EA,
                    int(import_plan.primary_seed_ea),
                    snippet,
                    capture_ranges,
                    boundary_ports=template_boundary_ports,
                    owned_block_entry_eas=capture_block_entry_eas,
                )
                print(
                    "UNION_STKPNTS_PRIMARY_CAPTURE",
                    f"captured={captured}",
                    f"primary=0x{int(import_plan.primary_seed_ea):X}",
                    flush=True,
                )
            print(
                "UNION_CALL_COMPANION",
                f"captured={capture_result.captured}",
                f"replacement_required={capture_result.replacement_required}",
                f"calls={[hex(ea) for ea in capture_result.call_eas]}",
                f"reason={capture_result.reason!r}",
                "mismatch="
                f"{None if capture_result.mismatch_ea is None else hex(int(capture_result.mismatch_ea))}",
                f"calls_blocks={0 if calls_snippet is None else int(calls_snippet.qty)}",
                f"failure={calls_failure.desc()!r}",
                flush=True,
            )
            captured_block_eas = detached_snippet_template_block_eas(
                FUNC_EA,
                int(import_plan.primary_seed_ea),
            )
            duplicate_live_block_eas = tuple(
                sorted(set(captured_block_eas).intersection(preopt_live_native_eas))
            )
            unexpected_duplicate_live_block_eas = tuple(
                ea
                for ea in duplicate_live_block_eas
                if ea not in capture_block_entry_eas
            )
            if unexpected_duplicate_live_block_eas:
                clear_detached_handler_call_templates()
                captured = False
            if captured:
                terminal_transfers = cg._detached_static_terminal_transfers(
                    resolution,
                    import_plan.seed_eas,
                )
                if terminal_transfers:
                    resolver_state.merge_materialized_transfers(terminal_transfers)
            print(
                "UNION_CAPTURE",
                f"captured={captured}",
                f"mode={UNION_GENERATION_MODE}",
                f"primary=0x{int(import_plan.primary_seed_ea):X}",
                f"blocks={int(snippet.qty)}",
                f"native_eas={len(snippet_native_eas)}",
                f"visible_seeds={len(visible_seed_eas)}/{len(plan.seed_eas)}",
                f"capture_blocks={len(captured_block_eas)}",
                f"semantic_closure={semantic_closure is not None}",
                f"semantic_ranges={len(semantic_ranges)}",
                f"capture_ranges={len(capture_ranges)}",
                f"duplicate_live_blocks={[hex(ea) for ea in duplicate_live_block_eas]}",
                "unexpected_duplicate_live_blocks="
                f"{[hex(ea) for ea in unexpected_duplicate_live_block_eas]}",
                flush=True,
            )
            return int(captured)

        def register_union_seed_aliases(mba) -> int:
            if not union_import_seed_eas:
                return 0
            origins = dict(imported_detached_snippet_instruction_origins(mba))
            identity = detached_island.stable_mba_identity(mba)
            registered = 0
            for target_ea in union_import_seed_eas[0]:
                key = (identity, int(target_ea))
                if key in detached_island._IMPORTED_SNIPPET_ROOTS:
                    continue
                imported_eas = {
                    int(imported_ea)
                    for imported_ea, native_ea in origins.items()
                    if int(native_ea) == int(target_ea)
                }
                matches = []
                for serial in range(int(mba.qty)):
                    block = mba.get_mblock(serial)
                    instruction = block.head
                    while instruction is not None:
                        if int(instruction.ea) in imported_eas:
                            matches.append(block)
                            break
                        if instruction is block.tail:
                            break
                        instruction = instruction.next
                unique_matches = {int(block.serial): block for block in matches}
                if len(unique_matches) != 1:
                    continue
                root = next(iter(unique_matches.values()))
                anchor_eas: list[int] = []
                owned_instruction_eas: list[int] = []
                instruction = root.head
                while instruction is not None:
                    instruction_ea = int(instruction.ea)
                    anchor_eas.append(instruction_ea)
                    if instruction_ea in origins:
                        owned_instruction_eas.append(instruction_ea)
                    if instruction is root.tail:
                        break
                    instruction = instruction.next
                detached_island._IMPORTED_SNIPPET_ROOTS[key] = (
                    detached_island._ImportedSnippetRoot(
                        serial_hint=int(root.serial),
                        anchor_eas=tuple(anchor_eas),
                        owned_instruction_eas=tuple(owned_instruction_eas),
                    )
                )
                registered += 1
            return registered

        def dump_imported_seed_connectivity(label, mba) -> None:
            if not union_import_seed_eas:
                return
            origins = dict(imported_detached_snippet_instruction_origins(mba))

            def block_label(block) -> str:
                anchor_eas = []
                instruction = block.head
                while instruction is not None:
                    instruction_ea = int(instruction.ea)
                    anchor_eas.append(origins.get(instruction_ea, instruction_ea))
                    if instruction is block.tail:
                        break
                    instruction = instruction.next
                anchor_ea = min(
                    (ea for ea in anchor_eas if int(ea) > 0),
                    default=int(block.start),
                )
                return f"blk{int(block.serial)}@0x{int(anchor_ea):X}"

            reachable = {0}
            pending = [0]
            while pending:
                serial = pending.pop()
                block = mba.get_mblock(serial)
                for index in range(int(block.nsucc())):
                    successor = int(block.succ(index))
                    if successor not in reachable:
                        reachable.add(successor)
                        pending.append(successor)

            current_transfers = resolver_state.materialized_transfers
            for seed_ea in union_import_seed_eas[0]:
                root = find_unique_live_block_by_ea(mba, int(seed_ea))
                route_sources = []
                for transfer in current_transfers:
                    if int(seed_ea) not in {
                        int(target_ea) for target_ea in transfer.target_eas
                    }:
                        continue
                    source = find_unique_live_block_by_ea(
                        mba,
                        int(transfer.source_block_ea),
                    )
                    route_sources.append(
                        (
                            f"0x{int(transfer.source_block_ea):X}",
                            transfer.resolver_kind,
                            None if source is None else block_label(source),
                            (
                                None
                                if source is None
                                else [
                                    block_label(mba.get_mblock(int(source.succ(index))))
                                    for index in range(int(source.nsucc()))
                                ]
                            ),
                        )
                    )
                print(
                    "IMPORTED_SEED_CONNECTIVITY",
                    f"stage={label}",
                    f"seed_ea=0x{int(seed_ea):X}",
                    f"root={None if root is None else block_label(root)}",
                    f"reachable={root is not None and int(root.serial) in reachable}",
                    f"preds={None if root is None else [block_label(mba.get_mblock(int(root.pred(index)))) for index in range(int(root.npred()))]}",
                    f"succs={None if root is None else [block_label(mba.get_mblock(int(root.succ(index)))) for index in range(int(root.nsucc()))]}",
                    f"route_sources={route_sources}",
                    flush=True,
                )

        def dump_imported_terminal_routes(label, mba) -> None:
            """Print imported terminal transfers with stable native anchors."""
            origins = dict(imported_detached_snippet_instruction_origins(mba))

            def block_label(block) -> str:
                native_eas = tuple(
                    int(origins[int(instruction.ea)])
                    for instruction in detached_island._instructions(block)
                    if int(instruction.ea) in origins
                )
                anchor_ea = min(
                    native_eas,
                    default=(
                        int(block.head.ea)
                        if block.head is not None
                        else int(block.start)
                    ),
                )
                return f"blk{int(block.serial)}@0x{anchor_ea:X}"

            rows = []
            terminal_opcodes = {
                int(ida_hexrays.m_goto),
                int(ida_hexrays.m_ijmp),
            }
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                tail = block.tail
                if (
                    tail is None
                    or int(tail.opcode) not in terminal_opcodes
                    or int(tail.ea) not in origins
                ):
                    continue
                successor_labels = tuple(
                    block_label(mba.get_mblock(int(block.succ(index))))
                    for index in range(int(block.nsucc()))
                )
                rows.append(
                    (
                        block_label(block),
                        f"tail_native=0x{int(origins[int(tail.ea)]):X}",
                        f"tail_imported=0x{int(tail.ea):X}",
                        f"opcode={int(tail.opcode)}",
                        f"nsucc={int(block.nsucc())}",
                        f"succs={successor_labels}",
                        tail.dstr(),
                    )
                )
            print(
                "IMPORTED_TERMINAL_ROUTES",
                f"stage={label}",
                f"rows={rows}",
                flush=True,
            )

        def dump_boundary_owned_terminal_sources(label, mba) -> None:
            terminal_origins = imported_detached_snippet_terminal_origins(mba)
            selected = island._boundary_owned_terminal_source_blocks(
                mba,
                terminal_origins,
            )
            native_exit_by_source = {}
            for imported_exit_ea, native_exit_ea in terminal_origins:
                source = find_unique_live_block_by_ea(mba, imported_exit_ea)
                if source is not None:
                    native_exit_by_source[int(source.serial)] = int(native_exit_ea)
            print(
                "BOUNDARY_OWNED_TERMINAL_SOURCES",
                f"stage={label}",
                "selected="
                f"{[f'blk{serial}@0x{native_exit_by_source[serial]:X}' for serial in sorted(selected) if serial in native_exit_by_source]}",
                "terminal_origins="
                f"{[(hex(imported), hex(native)) for imported, native in terminal_origins]}",
                "applied_direct="
                f"{len(imported_detached_snippet_direct_boundary_evidence(mba))}",
                flush=True,
            )

        def dump_preopt_incoming_boundary_shapes(
            label,
            mba,
            current_transfers,
            imported_targets,
        ):
            if not APPLY_INCOMING_BOUNDARIES:
                return None
            target_closure = expand_preopt_boundary_target_closure(
                current_transfers,
                imported_target_eas=imported_targets,
            )
            plan = plan_preopt_incoming_boundaries(
                current_transfers,
                imported_target_eas=target_closure.target_eas,
            )
            replay_capture = ()
            replay_plan = None
            if REPLAY_TRANSITION_MANIFEST:
                replay_capture = select_timed_replay_transition_manifest(
                    transition_manifest_captures,
                    external_replay_manifest,
                )
            if replay_capture:
                replay_plan = plan_preopt_manifest_boundaries(
                    replay_capture,
                    state_register=20,
                )
                replay_direct = tuple(
                    PreoptDirectIncomingBoundary(
                        source_ea=int(row.source_ea),
                        target_ea=int(row.target_ea),
                        state_constant=int(row.state_constant),
                        state_register=int(row.state_register),
                        via_ea=(None if row.via_ea is None else int(row.via_ea)),
                        requires_literal_state_write=(
                            bool(row.requires_literal_state_write)
                        ),
                    )
                    for row in replay_plan.direct
                )
                plan = PreoptIncomingBoundaryPlan(
                    direct=tuple(
                        sorted(
                            set(plan.direct) | set(replay_direct),
                            key=lambda row: (
                                row.source_ea,
                                row.target_ea,
                                row.state_constant,
                            ),
                        )
                    ),
                    conditional=plan.conditional,
                    abstentions=plan.abstentions,
                )
            for kind, rows in (
                ("direct", plan.direct),
                ("conditional", plan.conditional),
            ):
                for row in rows:
                    source_ea = (
                        int(row.source_ea)
                        if kind == "direct"
                        else int(row.predicate_ea)
                    )
                    source = find_unique_preopt_block_by_native_ea(
                        mba,
                        source_ea,
                    )
                    instructions = []
                    target_blocks = []
                    if kind == "conditional":
                        target_blocks = [
                            (
                                f"0x{int(target_ea):X}",
                                (
                                    None
                                    if (
                                        target_block
                                        := find_unique_preopt_block_by_native_ea(
                                            mba,
                                            int(target_ea),
                                        )
                                    )
                                    is None
                                    else int(target_block.serial)
                                ),
                            )
                            for target_ea in (
                                row.false_target_ea,
                                row.true_target_ea,
                            )
                        ]
                    if source is not None:
                        instruction = source.head
                        while instruction is not None:
                            instructions.append(
                                (
                                    hex(int(instruction.ea)),
                                    int(instruction.opcode),
                                    int(instruction.l.t),
                                    int(instruction.r.t),
                                    int(instruction.d.t),
                                )
                            )
                            if instruction is source.tail:
                                break
                            instruction = instruction.next
                    print(
                        "PREOPT_INCOMING_SHAPE",
                        f"stage={label}",
                        f"kind={kind}",
                        f"source_ea=0x{source_ea:X}",
                        f"source={None if source is None else f'blk{int(source.serial)}@0x{source_ea:X}'}",
                        f"nsucc={None if source is None else int(source.nsucc())}",
                        f"type={None if source is None else int(source.type)}",
                        f"tail_ea={None if source is None or source.tail is None else hex(int(source.tail.ea))}",
                        f"tail_op={None if source is None or source.tail is None else int(source.tail.opcode)}",
                        f"insns={instructions}",
                        f"target_blocks={target_blocks}",
                        f"row={row}",
                        flush=True,
                    )
            print(
                "PREOPT_INCOMING_PLAN",
                f"stage={label}",
                f"direct={len(plan.direct)}",
                f"conditional={len(plan.conditional)}",
                f"target_closure={len(target_closure.target_eas)}",
                f"target_eas={[hex(ea) for ea in target_closure.target_eas]}",
                f"ambiguous_sources={[hex(ea) for ea in target_closure.ambiguous_source_eas]}",
                f"abstentions={[(hex(row.source_ea), row.reason.value) for row in plan.abstentions]}",
                f"replay_capture={None if not replay_capture else replay_capture[0].capture_index}",
                f"replay_rows={len(replay_capture)}",
                f"replay_direct={0 if replay_plan is None else len(replay_plan.direct)}",
                f"replay_abstentions={[] if replay_plan is None else [(hex(row.source_ea), row.reason.value) for row in replay_plan.abstentions]}",
                flush=True,
            )
            return plan

        def find_unique_preopt_block_by_native_ea(mba, native_ea):
            """Bind one stable native EA across live and imported PREOPT IR."""
            native_ea = int(native_ea)
            origins = dict(imported_detached_snippet_instruction_origins(mba))
            direct = find_unique_live_block_by_ea(mba, native_ea)
            if direct is not None:
                return direct
            matches = {}
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                instruction = block.head
                while instruction is not None:
                    instruction_ea = int(instruction.ea)
                    if int(origins.get(instruction_ea, instruction_ea)) == native_ea:
                        matches[int(block.serial)] = block
                        break
                    if instruction is block.tail:
                        break
                    instruction = instruction.next
            return next(iter(matches.values())) if len(matches) == 1 else None

        def _block_instructions(block):
            instructions = []
            instruction = block.head
            while instruction is not None:
                instructions.append(instruction)
                if instruction is block.tail:
                    break
                instruction = instruction.next
            return tuple(instructions)

        def plan_preopt_interior_entries(mba):
            if not APPLY_INTERIOR_ENTRY_BRIDGES or not union_import_primary_seed_eas:
                return None
            template = detached_island._DETACHED_SNIPPET_TEMPLATES.get(
                (FUNC_EA, int(union_import_primary_seed_eas[0]))
            )
            if template is None:
                print(
                    "PREOPT_INTERIOR_ENTRY_PLAN",
                    "reason=template_missing",
                    flush=True,
                )
                return None

            entry_candidates_by_instruction_ea = {}
            for template_block in template.blocks:
                for instruction in template_block.instructions:
                    entry_candidates_by_instruction_ea.setdefault(
                        int(instruction.ea),
                        set(),
                    ).add(int(template_block.native_entry_ea))
            ambiguous_template_instruction_eas = tuple(
                sorted(
                    instruction_ea
                    for instruction_ea, native_entry_eas in entry_candidates_by_instruction_ea.items()
                    if len(native_entry_eas) != 1
                )
            )
            native_entry_by_instruction_ea = {
                instruction_ea: next(iter(native_entry_eas))
                for instruction_ea, native_entry_eas in entry_candidates_by_instruction_ea.items()
                if len(native_entry_eas) == 1
            }
            template_predecessor_entries = {
                int(template_block.native_entry_ea): tuple(
                    sorted(
                        int(predecessor.native_entry_ea)
                        for predecessor in template.blocks
                        if int(template_block.source_serial)
                        in {
                            int(successor_serial)
                            for successor_serial in predecessor.successor_serials
                        }
                    )
                )
                for template_block in template.blocks
            }

            imported_origins = dict(imported_detached_snippet_instruction_origins(mba))
            native_origins_by_imported_serial = {}
            predecessor_count_by_imported_serial = {}
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                native_origins = tuple(
                    int(imported_origins[int(instruction.ea)])
                    for instruction in _block_instructions(block)
                    if int(instruction.ea) in imported_origins
                )
                if not native_origins:
                    continue
                native_origins_by_imported_serial[int(serial)] = native_origins
                predecessor_count_by_imported_serial[int(serial)] = int(block.npred())

            owner_index = index_preopt_imported_entry_owners(
                native_entry_by_instruction_ea=(native_entry_by_instruction_ea),
                native_origins_by_imported_serial=(native_origins_by_imported_serial),
                predecessor_count_by_imported_serial=(
                    predecessor_count_by_imported_serial
                ),
            )
            connected_owner_topology = tuple(
                (
                    int(native_entry_ea),
                    tuple(
                        (
                            int(owner.serial),
                            int(owner.predecessor_count),
                        )
                        for owner in imported_owners
                    ),
                    template_predecessor_entries.get(
                        int(native_entry_ea),
                        (),
                    ),
                )
                for native_entry_ea, imported_owners in (
                    owner_index.owners_by_native_entry
                )
                if any(int(owner.predecessor_count) > 0 for owner in imported_owners)
            )
            candidates = []
            placeholder_ambiguities = []
            orphaned_without_placeholders = []
            for native_entry_ea, imported_owners in owner_index.owners_by_native_entry:
                placeholders = []
                for serial in range(int(mba.qty)):
                    block = mba.get_mblock(serial)
                    instructions = _block_instructions(block)
                    if any(
                        int(instruction.ea) in imported_origins
                        for instruction in instructions
                    ):
                        continue
                    if int(block.start) == int(native_entry_ea) or any(
                        int(instruction.ea) == int(native_entry_ea)
                        for instruction in instructions
                    ):
                        placeholders.append(block)
                if len(placeholders) != 1:
                    placeholder_ambiguities.append(
                        (int(native_entry_ea), len(placeholders))
                    )
                    if (
                        not placeholders
                        and imported_owners
                        and all(
                            int(owner.predecessor_count) == 0
                            for owner in imported_owners
                        )
                    ):
                        orphaned_without_placeholders.append(
                            (
                                int(native_entry_ea),
                                tuple(int(owner.serial) for owner in imported_owners),
                                template_predecessor_entries.get(
                                    int(native_entry_ea),
                                    (),
                                ),
                            )
                        )
                    continue
                placeholder = placeholders[0]
                candidates.append(
                    PreoptInteriorEntryCandidate(
                        native_entry_ea=int(native_entry_ea),
                        placeholder_serial=int(placeholder.serial),
                        placeholder_instruction_count=len(
                            _block_instructions(placeholder)
                        ),
                        placeholder_successor_count=int(placeholder.nsucc()),
                        imported_owners=tuple(
                            PreoptImportedEntryOwner(
                                serial=int(owner.serial),
                                predecessor_count=int(owner.predecessor_count),
                            )
                            for owner in imported_owners
                        ),
                    )
                )

            plan = plan_preopt_interior_entry_bridges(tuple(candidates))
            print(
                "PREOPT_INTERIOR_ENTRY_PLAN",
                f"bridges={[(hex(row.native_entry_ea), f'blk{row.placeholder_serial}@0x{row.native_entry_ea:X}', f'blk{row.imported_serial}@0x{row.native_entry_ea:X}') for row in plan.bridges]}",
                f"abstentions={[(hex(row.native_entry_ea), row.reason.value) for row in plan.abstentions]}",
                f"placeholder_ambiguities={[(hex(ea), count) for ea, count in placeholder_ambiguities]}",
                f"ambiguous_template_instruction_eas={[hex(ea) for ea in ambiguous_template_instruction_eas]}",
                f"ambiguous_imported_serials={[f'blk{serial}@imported-origin' for serial in owner_index.ambiguous_serials]}",
                f"connected_owner_topology={[(hex(ea), [(f'blk{serial}@0x{ea:X}', npred) for serial, npred in owners], [hex(pred_ea) for pred_ea in predecessor_eas]) for ea, owners, predecessor_eas in connected_owner_topology]}",
                f"orphaned_without_placeholders={[(hex(ea), [f'blk{serial}@0x{ea:X}' for serial in serials], [hex(pred_ea) for pred_ea in predecessor_eas]) for ea, serials, predecessor_eas in orphaned_without_placeholders]}",
                flush=True,
            )
            return plan

        def apply_preopt_interior_entries(mba, plan):
            if plan is None or not plan.bridges:
                return 0
            modifier = DeferredGraphModifier(mba)
            queued = 0
            for row in plan.bridges:
                placeholder = mba.get_mblock(int(row.placeholder_serial))
                imported = mba.get_mblock(int(row.imported_serial))
                if (
                    placeholder is None
                    or imported is None
                    or len(_block_instructions(placeholder)) != 0
                    or int(placeholder.nsucc()) != 0
                    or int(imported.npred()) != 0
                    or int(placeholder.serial) == int(imported.serial)
                ):
                    print(
                        "PREOPT_INTERIOR_ENTRY_SKIP",
                        f"entry_ea=0x{int(row.native_entry_ea):X}",
                        "reason=rebind_shape_mismatch",
                        flush=True,
                    )
                    continue
                modifier.queue_terminal_goto_change(
                    block_serial=int(placeholder.serial),
                    goto_target=int(imported.serial),
                    description=(
                        f"PREOPT interior entry bridge 0x{int(row.native_entry_ea):X}"
                    ),
                    priority=5,
                )
                queued += 1
            applied = int(modifier.apply(defer_post_apply_maintenance=True))
            print(
                "PREOPT_INTERIOR_ENTRY_APPLY",
                f"queued={queued}",
                f"applied={applied}",
                flush=True,
            )
            return applied

        def dump_preopt_closing_opcode_violations(label, mba):
            closing_opcodes = {
                int(ida_hexrays.m_goto),
                int(ida_hexrays.m_jcnd),
                int(ida_hexrays.m_jtbl),
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_ret),
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
            }
            origins = dict(imported_detached_snippet_instruction_origins(mba))
            violations = []
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                instructions = []
                instruction = block.head
                while instruction is not None:
                    instructions.append(instruction)
                    instruction = instruction.next
                for instruction in instructions[:-1]:
                    if int(instruction.opcode) in closing_opcodes:
                        instruction_ea = int(instruction.ea)
                        violations.append(
                            (
                                int(block.serial),
                                int(origins.get(instruction_ea, instruction_ea)),
                                int(instruction.opcode),
                            )
                        )
            print(
                "PREOPT_CLOSING_VIOLATIONS",
                f"label={label}",
                f"rows={[(f'blk{serial}@0x{ea:X}', opcode) for serial, ea, opcode in violations]}",
                flush=True,
            )
            return tuple(violations)

        def print_verify_log(message, *args, **_kwargs):
            print(message % args if args else message, flush=True)

        def _preopt_state_write_matches(block, row):
            if not row.requires_literal_state_write:
                return True
            origins = dict(imported_detached_snippet_instruction_origins(block.mba))
            matches = []
            instruction = block.head
            while instruction is not None:
                if (
                    int(origins.get(int(instruction.ea), int(instruction.ea)))
                    == int(row.source_ea)
                    and int(instruction.opcode) == int(ida_hexrays.m_mov)
                    and int(instruction.l.t) == int(ida_hexrays.mop_n)
                    and int(instruction.l.size) == 4
                    and (int(instruction.l.nnn.value) & 0xFFFFFFFF)
                    == int(row.state_constant)
                    and int(instruction.d.t) == int(ida_hexrays.mop_r)
                    and int(instruction.d.r) == int(row.state_register)
                    and int(instruction.d.size) == 4
                ):
                    matches.append(instruction)
                if instruction is block.tail:
                    break
                instruction = instruction.next
            return matches[0] if len(matches) == 1 else None

        def apply_preopt_incoming_boundaries(mba, plan):
            if not APPLY_INCOMING_BOUNDARIES or plan is None:
                return 0, 0, ()

            source_identity_by_ea = {}
            for row in plan.direct:
                source = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(row.source_ea),
                )
                if source is not None:
                    source_identity_by_ea[int(row.source_ea)] = int(source.serial)
            for row in plan.conditional:
                source = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(row.predicate_ea),
                )
                if source is not None:
                    source_identity_by_ea[int(row.predicate_ea)] = int(source.serial)
            direct_rows = exclude_direct_boundaries_with_conditional_source(
                plan.direct,
                plan.conditional,
                source_identity_by_ea=source_identity_by_ea,
            )
            skipped = [
                (int(row.source_ea), "conditional_sibling")
                for row in plan.direct
                if row not in direct_rows
            ]
            direct_rows, conflicting_source_eas = (
                exclude_conflicting_direct_boundaries_by_source(
                    direct_rows,
                    source_identity_by_ea=source_identity_by_ea,
                )
            )
            skipped.extend(
                (int(source_ea), "conflicting_direct_block")
                for source_ea in conflicting_source_eas
            )

            direct_modifier = DeferredGraphModifier(mba)
            queued_direct = 0
            edge_rows = []
            for row in direct_rows:
                source = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(row.source_ea),
                )
                target = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(row.target_ea),
                )
                via = (
                    None
                    if row.via_ea is None
                    else find_unique_preopt_block_by_native_ea(
                        mba,
                        int(row.via_ea),
                    )
                )
                closing_tail = bool(
                    source is not None
                    and source.tail is not None
                    and (
                        int(source.tail.opcode)
                        in {
                            int(ida_hexrays.m_goto),
                            int(ida_hexrays.m_ijmp),
                            int(ida_hexrays.m_jcnd),
                            int(ida_hexrays.m_jtbl),
                        }
                        or ida_hexrays.is_mcode_jcond(int(source.tail.opcode))
                    )
                )
                tail_is_call = bool(
                    source is not None
                    and source.tail is not None
                    and int(source.tail.opcode)
                    in {
                        int(ida_hexrays.m_call),
                        int(ida_hexrays.m_icall),
                    }
                )
                tail_is_goto = bool(
                    source is not None
                    and source.tail is not None
                    and int(source.tail.opcode) == int(ida_hexrays.m_goto)
                )
                tail_is_indirect_jump = bool(
                    source is not None
                    and source.tail is not None
                    and int(source.tail.opcode) == int(ida_hexrays.m_ijmp)
                )
                mode = (
                    PreoptDirectReplayMode.ABSTAIN
                    if source is None
                    else classify_preopt_direct_replay_shape(
                        has_via=row.via_ea is not None,
                        source_nsucc=int(source.nsucc()),
                        tail_is_call=tail_is_call,
                        tail_is_goto=tail_is_goto,
                        tail_is_indirect_jump=tail_is_indirect_jump,
                        tail_is_closing=closing_tail,
                        via_is_adjacent=bool(
                            via is not None
                            and source.nextb is not None
                            and int(source.nextb.serial) == int(via.serial)
                        ),
                        successor_is_via=bool(
                            via is not None
                            and int(source.nsucc()) == 1
                            and int(source.succ(0)) == int(via.serial)
                        ),
                    )
                )
                if (
                    source is None
                    or target is None
                    or int(source.serial) == int(target.serial)
                    or source.tail is None
                    or mode is PreoptDirectReplayMode.ABSTAIN
                    or not _preopt_state_write_matches(source, row)
                ):
                    skipped.append((int(row.source_ea), "direct_shape_mismatch"))
                    continue
                if mode in {
                    PreoptDirectReplayMode.REDIRECT_EDGE,
                    PreoptDirectReplayMode.PRESERVE_CALL,
                }:
                    edge_rows.append(row)
                    continue
                if closing_tail and not tail_is_indirect_jump:
                    source.make_nop(source.tail)
                    source.mark_lists_dirty()
                direct_modifier.queue_terminal_goto_change(
                    block_serial=int(source.serial),
                    goto_target=int(target.serial),
                    description=(
                        f"PREOPT resolver boundary 0x{int(row.source_ea):X} "
                        f"state=0x{int(row.state_constant):X} -> "
                        f"0x{int(row.target_ea):X}"
                    ),
                    priority=5,
                )
                queued_direct += 1
            direct_applied = int(
                direct_modifier.apply(defer_post_apply_maintenance=True)
            )
            if direct_applied != queued_direct:
                skipped.append(
                    (
                        0,
                        f"direct_apply_partial:{direct_applied}/{queued_direct}",
                    )
                )

            for row in edge_rows:
                source = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(row.source_ea),
                )
                target = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(row.target_ea),
                )
                via = (
                    None
                    if row.via_ea is None
                    else find_unique_preopt_block_by_native_ea(
                        mba,
                        int(row.via_ea),
                    )
                )
                if (
                    source is None
                    or target is None
                    or via is None
                    or source.tail is None
                ):
                    skipped.append((int(row.source_ea), "edge_rebind_failed"))
                    continue
                tail_is_call = int(source.tail.opcode) in {
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                }
                tail_is_goto = int(source.tail.opcode) == int(ida_hexrays.m_goto)
                if int(source.nsucc()) == 0:
                    if tail_is_call:
                        if source.nextb is None or int(source.nextb.serial) != int(
                            via.serial
                        ):
                            skipped.append(
                                (int(row.source_ea), "call_via_not_adjacent")
                            )
                            continue
                    elif not (
                        tail_is_goto
                        and int(source.tail.l.t) == int(ida_hexrays.mop_b)
                        and int(source.tail.l.b) == int(via.serial)
                    ):
                        skipped.append((int(row.source_ea), "goto_via_target_mismatch"))
                        continue
                    source.type = ida_hexrays.BLT_1WAY
                    source.succset.push_back(int(via.serial))
                    via.predset.push_back(int(source.serial))
                    source.mark_lists_dirty()
                    via.mark_lists_dirty()
                    mba.mark_chains_dirty()
                elif not (
                    int(source.nsucc()) == 1 and int(source.succ(0)) == int(via.serial)
                ):
                    skipped.append((int(row.source_ea), "via_edge_mismatch"))
                    continue

                if tail_is_call:
                    helper = insert_nop_blk(source, force_adjacent=True)
                    insert_goto_instruction(
                        helper,
                        int(target.serial),
                        nop_previous_instruction=True,
                    )
                    applied = change_1way_block_successor(
                        helper,
                        int(target.serial),
                        verify=False,
                    )
                else:
                    applied = change_1way_block_successor(
                        source,
                        int(target.serial),
                        verify=False,
                    )
                if applied:
                    direct_applied += 1
                    print(
                        "PREOPT_DIRECT_EDGE_APPLIED",
                        f"source_ea=0x{int(row.source_ea):X}",
                        f"via_ea=0x{int(row.via_ea):X}",
                        f"target_ea=0x{int(row.target_ea):X}",
                        f"preserved_call={tail_is_call}",
                        flush=True,
                    )
                else:
                    skipped.append((int(row.source_ea), "edge_redirect_failed"))

            conditional_applied = 0
            for row in plan.conditional:
                source = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(row.predicate_ea),
                )
                oriented = orient_preopt_conditional_boundary(row)
                false_target = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(oriented.false_target_ea),
                )
                true_target = find_unique_preopt_block_by_native_ea(
                    mba,
                    int(oriented.true_target_ea),
                )
                if (
                    source is None
                    or false_target is None
                    or true_target is None
                    or int(source.serial)
                    in {
                        int(false_target.serial),
                        int(true_target.serial),
                    }
                    or int(false_target.serial) == int(true_target.serial)
                    or int(source.nsucc()) != 0
                    or source.tail is None
                    or int(source.tail.ea) != int(row.predicate_ea)
                    or int(source.tail.opcode) != int(ida_hexrays.m_jcnd)
                    or int(source.tail.l.t) == int(ida_hexrays.mop_z)
                ):
                    skipped.append(
                        (int(row.predicate_ea), "conditional_shape_mismatch")
                    )
                    continue
                condition = ida_hexrays.mop_t()
                condition.assign(source.tail.l)
                seed_target = true_target
                modifier = DeferredGraphModifier(mba)
                modifier.queue_terminal_goto_change(
                    block_serial=int(source.serial),
                    goto_target=int(seed_target.serial),
                    description=(
                        f"PREOPT conditional seed 0x{int(row.predicate_ea):X} "
                        f"-> 0x{int(oriented.true_target_ea):X}"
                    ),
                    priority=5,
                )
                modifier.queue_lower_conditional_state_transition(
                    source_serial=int(source.serial),
                    old_dispatcher_serial=int(seed_target.serial),
                    rewrite_from_ea=int(row.predicate_ea),
                    condition_operand=condition,
                    false_target_serial=int(false_target.serial),
                    true_target_serial=int(true_target.serial),
                    state_register=int(row.state_register),
                    state_size=4,
                    false_state=int(oriented.false_state),
                    true_state=int(oriented.true_state),
                    proof_id=(
                        f"preopt_incoming_conditional:0x{int(row.predicate_ea):X}"
                    ),
                    description=(
                        f"PREOPT conditional boundary 0x{int(row.predicate_ea):X} "
                        f"-> 0x{int(oriented.false_target_ea):X}/"
                        f"0x{int(oriented.true_target_ea):X}"
                    ),
                    rule_priority=1000,
                )
                applied = int(modifier.apply(defer_post_apply_maintenance=True))
                if applied == 2:
                    conditional_applied += 1
                else:
                    skipped.append(
                        (
                            int(row.predicate_ea),
                            f"conditional_apply_partial:{applied}/2",
                        )
                    )
            return direct_applied, conditional_applied, tuple(skipped)

        def plan_entry_bridge(mba, current_transfers, *, preopt_seed=None):
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

            evidence = (
                recognize_residual_entry_bridge(mba)
                if preopt_seed is None
                else preopt_seed[0]
            )
            if evidence is None:
                print(
                    "ENTRY_PLAN_STAGE",
                    "reason=residual_entry_evidence_missing",
                    flush=True,
                )
                return None
            graph = lift(mba)
            recovery = recover_dispatcher(
                graph,
                None,
                materialized_indirect_transfers=current_transfers,
            )
            if recovery.dispatch_map is None or recovery.state_var_reg is None:
                print(
                    "ENTRY_PLAN_STAGE",
                    "reason=dispatcher_recovery_missing",
                    f"source_store_ea=0x{int(evidence.source_store_ea):X}",
                    flush=True,
                )
                return None
            if preopt_seed is not None and int(preopt_seed[2]) != int(
                recovery.state_var_reg
            ):
                print(
                    "ENTRY_PLAN_STAGE",
                    "reason=state_register_mismatch",
                    f"preopt_reg={int(preopt_seed[2])}",
                    f"calls_reg={int(recovery.state_var_reg)}",
                    flush=True,
                )
                return None
            routing_nodes = recover_state_routing_nodes(
                mba,
                state_register=int(recovery.state_var_reg),
                after_ea=int(evidence.source_store_ea),
                before_ea=int(evidence.source_store_ea) + 0x100,
                transfers=current_transfers,
            )
            if not routing_nodes:
                print(
                    "ENTRY_PLAN_STAGE",
                    "reason=routing_nodes_missing",
                    f"source_store_ea=0x{int(evidence.source_store_ea):X}",
                    flush=True,
                )
                return None
            initial_state = (
                recover_initial_state_write(
                    mba,
                    state_register=int(recovery.state_var_reg),
                    after_ea=int(evidence.source_store_ea),
                    before_ea=min(node.source_block_ea for node in routing_nodes),
                )
                if preopt_seed is None
                else int(preopt_seed[1])
            )
            if initial_state is None:
                print(
                    "ENTRY_PLAN_STAGE",
                    "reason=initial_state_missing",
                    f"source_store_ea=0x{int(evidence.source_store_ea):X}",
                    f"routing_start_ea=0x{min(node.source_block_ea for node in routing_nodes):X}",
                    flush=True,
                )
                return None
            handler_serial = recovery.dispatch_map.resolve_target(
                int(evidence.taken_state_constant)
            )
            handler = (
                graph.get_block(handler_serial) if handler_serial is not None else None
            )
            if handler is None:
                print(
                    "ENTRY_PLAN_STAGE",
                    "reason=taken_state_handler_missing",
                    f"taken_state=0x{int(evidence.taken_state_constant):X}",
                    flush=True,
                )
                return None
            residual_target = cg._exact_equality_native_target(
                current_transfers,
                int(evidence.fallthrough_state_constant),
            )
            if residual_target is None:
                print(
                    "ENTRY_PLAN_STAGE",
                    "reason=residual_target_missing",
                    f"fallthrough_state=0x{int(evidence.fallthrough_state_constant):X}",
                    flush=True,
                )
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
            if plan is None:
                print(
                    "ENTRY_PLAN_STAGE",
                    "reason=portable_plan_abstained",
                    f"source_store_ea=0x{int(evidence.source_store_ea):X}",
                    f"taken_target_ea=0x{int(handler.start_ea):X}",
                    f"fallthrough_target_ea=0x{int(residual_target):X}",
                    flush=True,
                )
                return None
            return (evidence, plan)

        def dump_entry_window(label, mba):
            if not ENTRY_DUMP:
                return
            for serial in range(int(mba.qty)):
                block = mba.get_mblock(serial)
                instructions = []
                instruction = block.head
                while instruction is not None:
                    instruction_ea = int(instruction.ea)
                    if 0x40A590 <= instruction_ea <= 0x40A5E0:
                        instructions.append(
                            f"0x{instruction_ea:X}:{instruction.dstr()}"
                        )
                    if instruction is block.tail:
                        break
                    instruction = instruction.next
                if not instructions:
                    continue
                successor_anchors = []
                for index in range(int(block.nsucc())):
                    successor = mba.get_mblock(int(block.succ(index)))
                    successor_ea = int(successor.start)
                    if successor_ea <= 0 and successor.head is not None:
                        successor_ea = int(successor.head.ea)
                    successor_anchors.append(
                        f"blk{int(successor.serial)}@0x{successor_ea:X}"
                    )
                block_ea = int(block.start)
                if block_ea <= 0 and block.head is not None:
                    block_ea = int(block.head.ea)
                print(
                    "ENTRY_WINDOW",
                    f"stage={label}",
                    f"block=blk{int(block.serial)}@0x{block_ea:X}",
                    f"succ={successor_anchors}",
                    f"insns={instructions}",
                    flush=True,
                )

        captured_entry_result: list[tuple[object, object, int]] = []
        captured_preopt_entry_seed: list[tuple[object, int, int]] = []
        latest_preopt_live_native_eas: list[frozenset[int]] = []
        first_preopt_return_address_sizes: list[int] = []
        latest_preopt_live_port_facts: list[dict[int, PreoptPortBlockFact]] = []
        original_native_entry_bridge = cg._materialize_residual_entry_bridge

        def capture_entry_bridge_without_native_patch(
            _resolution,
            current_transfers,
            mba,
        ):
            if BOUNDARY_PORT_MODE:
                return (0, ())
            dump_entry_window("calls", mba)
            result = plan_entry_bridge(
                mba,
                current_transfers,
                preopt_seed=(
                    captured_preopt_entry_seed[0]
                    if captured_preopt_entry_seed
                    else None
                ),
            )
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
            captured_entry_result[:] = [(evidence, plan, predicate_ida_stkoff)]
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
                self.build_callinfo_callbacks = 0
                self.callinfo_callbacks = 0
                self.bad_call_sp_seen = False
                self.entry_bridges = 0
                self.boundary_ports_applied = 0
                self.latest_boundary_ports_applied = 0
                self.latest_boundary_ports_abstained = 0

            def stkpnts(self, mba, stack_points):
                is_profile = int(mba.entry_ea) == FUNC_EA
                is_source = bool(union_source_generation_active[0])
                if STKPNTS_DUMP and (is_profile or is_source):
                    rows = tuple(
                        (int(ea), int(spd))
                        for ea, spd in snapshot_stkpnts(stack_points)
                    )
                    print(
                        "TRANSIENT_STKPNTS_SNAPSHOT",
                        f"entry={hex(int(mba.entry_ea))}",
                        f"source_generation={is_source}",
                        f"qty={len(rows)}",
                        tuple(
                            (hex(ea), spd)
                            for ea, spd in rows
                            if is_source or 0x40AEF0 <= ea < 0x40AFA0
                        ),
                        flush=True,
                    )
                if not is_profile or is_source:
                    return 0
                if not STKPNTS_INJECT:
                    return 0
                if not union_import_primary_seed_eas:
                    return 0
                template = detached_island._DETACHED_SNIPPET_TEMPLATES.get(
                    (FUNC_EA, int(union_import_primary_seed_eas[0]))
                )
                if template is None:
                    return 0
                function = ida_funcs.get_func(FUNC_EA)
                if function is None:
                    return 0
                call_eas = tuple(
                    sorted(
                        {
                            int(nested.ea)
                            for block in template.blocks
                            for instruction in block.instructions
                            for nested in nested_instructions(instruction)
                            if int(nested.opcode)
                            in (
                                int(ida_hexrays.m_call),
                                int(ida_hexrays.m_icall),
                            )
                        }
                    )
                )
                imported_points = dict(transient_imported_stack_points)
                before = dict(snapshot_stkpnts(stack_points))
                inserted = []
                updated = []
                for live_ea, spd in sorted(imported_points.items()):
                    if upsert_stkpnt(stack_points, live_ea, spd):
                        inserted.append((live_ea, spd))
                    else:
                        updated.append((live_ea, spd))
                for call_ea in call_eas:
                    spd = int(ida_frame.get_spd(function, int(call_ea)))
                    if upsert_stkpnt(stack_points, int(call_ea), spd):
                        inserted.append((int(call_ea), spd))
                    else:
                        updated.append((int(call_ea), spd))
                after = dict(snapshot_stkpnts(stack_points))
                print(
                    "TRANSIENT_STKPNTS_INJECT",
                    f"ranges={tuple((hex(start), hex(end)) for start, end in union_stack_point_ranges[0]) if union_stack_point_ranges else ()}",
                    f"imported_points={len(imported_points)}",
                    f"inserted={len(inserted)}",
                    f"updated={len(updated)}",
                    f"before={tuple((hex(ea), before.get(ea)) for ea in call_eas)}",
                    f"after={tuple((hex(ea), after.get(ea)) for ea in call_eas)}",
                    flush=True,
                )
                self.bad_call_sp_seen = bool(mba.bad_call_sp_detected())
                return 0

            def build_callinfo(self, block, _call_type):
                import ida_nalt
                import ida_typeinf

                mba = block.mba
                if int(mba.entry_ea) != FUNC_EA:
                    return None
                if union_source_generation_active[0]:
                    return None
                self.build_callinfo_callbacks += 1
                instruction = block.tail
                origins = dict(imported_detached_snippet_instruction_origins(mba))
                native_ea = (
                    None
                    if instruction is None
                    else native_instruction_ea(instruction, origins)
                )
                block_eas = block_native_eas(block, origins)
                anchor_ea = (
                    native_ea if native_ea is not None else min(block_eas, default=None)
                )
                call = instruction
                callinfo_evidence = None
                route_template = (
                    None
                    if native_ea is None
                    else route_callinfo_templates.get(int(native_ea))
                )
                if route_template is not None and not PRODUCTION_CALLINFO:
                    function = ida_funcs.get_func(FUNC_EA)
                    if function is not None:
                        prepared = ida_hexrays.mcallinfo_t()
                        if not copy_mcallinfo(prepared, route_template.d.f):
                            return None
                        source_span = int(
                            int(route_template.d.f.stkargs_top)
                            - int(route_template.d.f.call_spd)
                        )
                        destination_top = int(mba.stkoff_ida2vd(0))
                        prepared.stkargs_top = destination_top
                        prepared.call_spd = destination_top - source_span
                        print(
                            "ROUTE_CALLINFO_TEMPLATE",
                            f"block=blk{int(block.serial)}@0x{int(native_ea):X}",
                            f"call_spd={int(prepared.call_spd)}",
                            f"stkargs_top={int(prepared.stkargs_top)}",
                            f"args={tuple(str(argument) for argument in prepared.args)}",
                            flush=True,
                        )
                        return prepared
                if call is not None and int(call.opcode) == int(ida_hexrays.m_icall):
                    call_ea = int(call.ea)
                    operand_type = ida_typeinf.tinfo_t()
                    has_operand_type = bool(
                        ida_nalt.get_op_tinfo(operand_type, call_ea, 0)
                    )
                    profile_ea, resolution = cg._callinfo_profile_resolution(
                        resolver_state,
                        int(mba.entry_ea),
                        call_ea,
                    )
                    transfers = (
                        resolver_state.materialized_transfers
                        if int(profile_ea) == FUNC_EA
                        else ()
                    )
                    reentry_eas = (
                        frozenset()
                        if resolution is None
                        else cg._proven_callinfo_reentry_eas(
                            resolution,
                            transfers,
                        )
                    )
                    no_stack_adjustment = (
                        None
                        if not reentry_eas
                        else cg.native_corridor_has_no_stack_adjustment(
                            call_ea,
                            reentry_eas,
                        )
                    )
                    evidence = (
                        None
                        if resolution is None
                        else cg.collect_three_argument_callee_purged_evidence(
                            block,
                            proven_reentry_eas=reentry_eas,
                            has_authoritative_type=has_operand_type,
                            call_stack_deficit=cg.native_call_stack_deficit(
                                block,
                                call_ea,
                            ),
                            caller_stack_adjustment=(
                                0 if no_stack_adjustment is True else None
                            ),
                            word_size=4,
                        )
                    )
                    callinfo_evidence = (
                        f"profile=0x{profile_ea:X}",
                        f"resolution={resolution is not None}",
                        f"has_operand_type={has_operand_type}",
                        f"reentries={tuple(hex(ea) for ea in sorted(reentry_eas))}",
                        f"no_stack_adjustment={no_stack_adjustment}",
                        f"evidence={evidence}",
                        "proof="
                        f"{None if evidence is None else cg.prove_three_argument_callee_purged_call(evidence)}",
                    )
                print(
                    "BUILD_CALLINFO_ABSTAINED",
                    f"callback={self.build_callinfo_callbacks}",
                    "block="
                    f"{f'blk{int(block.serial)}@0x{anchor_ea:X}' if anchor_ea is not None else f'block@fict:0x{int(block.start):X}'}",
                    "operand_types="
                    f"{None if instruction is None else (int(instruction.l.t), int(instruction.r.t), int(instruction.d.t))}",
                    "insn="
                    f"{None if instruction is None else format_minsn_t(instruction)}",
                    "block_insns="
                    f"{tuple(format_minsn_t(candidate) for candidate in block_instructions(block))}",
                    f"evidence={callinfo_evidence}",
                    flush=True,
                )
                return None

            def callinfo_built(self, block):
                mba = block.mba
                if int(mba.entry_ea) != FUNC_EA:
                    return 0
                if union_source_generation_active[0]:
                    return 0
                self.callinfo_callbacks += 1
                instruction = block.tail
                origins = dict(imported_detached_snippet_instruction_origins(mba))
                native_ea = (
                    None
                    if instruction is None
                    else native_instruction_ea(instruction, origins)
                )
                block_eas = block_native_eas(block, origins)
                anchor_ea = (
                    native_ea if native_ea is not None else min(block_eas, default=None)
                )
                anchor = (
                    f"blk{int(block.serial)}@0x{anchor_ea:X}"
                    if anchor_ea is not None
                    else f"block@fict:0x{int(block.start):X}"
                )
                callinfo = (
                    instruction.d.f
                    if instruction is not None
                    and int(instruction.opcode)
                    in (int(ida_hexrays.m_call), int(ida_hexrays.m_icall))
                    and int(instruction.d.t) == int(ida_hexrays.mop_f)
                    else None
                )
                point = None if native_ea is None else mba.locate_stkpnt(int(native_ea))
                bad_call_sp = bool(mba.bad_call_sp_detected())
                first_bad_call = bad_call_sp and not self.bad_call_sp_seen
                instruction_text = (
                    None if instruction is None else format_minsn_t(instruction)
                )
                block_text = (
                    ()
                    if instruction is None
                    or int(instruction.opcode) != int(ida_hexrays.m_icall)
                    else tuple(
                        format_minsn_t(candidate)
                        for candidate in block_instructions(block)
                    )
                )
                print(
                    "CALLINFO_BUILT",
                    f"callback={self.callinfo_callbacks}",
                    f"block={anchor}",
                    f"call_ea={None if native_ea is None else hex(int(native_ea))}",
                    f"bad_call_sp={bad_call_sp}",
                    f"first_bad_call={first_bad_call}",
                    "point="
                    f"{None if point is None else (hex(int(point.ea)), int(point.spd))}",
                    f"call_spd={None if callinfo is None else int(callinfo.call_spd)}",
                    "stkargs_top="
                    f"{None if callinfo is None else int(callinfo.stkargs_top)}",
                    f"cc={None if callinfo is None else int(callinfo.cc)}",
                    "args="
                    f"{() if callinfo is None else tuple((int(argument.t), int(argument.ea), str(argument.argloc), str(argument)) for argument in callinfo.args)}",
                    "operand_types="
                    f"{None if instruction is None else (int(instruction.l.t), int(instruction.r.t), int(instruction.d.t))}",
                    f"insn={instruction_text}",
                    f"block_insns={block_text}",
                    flush=True,
                )
                self.bad_call_sp_seen = bad_call_sp
                return 0

            def preoptimized(self, mba):
                if int(mba.entry_ea) != FUNC_EA:
                    return 0
                if union_source_generation_active[0]:
                    return 0
                self.preopt_callbacks += 1
                dump_entry_window(f"preopt-before-import-{self.preopt_callbacks}", mba)
                live_port_facts, live_ambiguous_entry_eas = (
                    build_preopt_port_block_facts(
                        mba,
                        snippet_return_address_size=None,
                    )
                )
                latest_preopt_live_port_facts[:] = [live_port_facts]
                print(
                    "PREOPT_LIVE_PORT_FACTS",
                    f"callback={self.preopt_callbacks}",
                    f"facts={len(live_port_facts)}",
                    "ambiguous_entries="
                    f"{[hex(ea) for ea in sorted(live_ambiguous_entry_eas)]}",
                    flush=True,
                )
                latest_preopt_live_native_eas[:] = [cg._live_mba_native_eas(mba)]
                if not first_preopt_return_address_sizes:
                    first_preopt_return_address_sizes.append(int(mba.retsize))
                current_transfers = resolver_state.materialized_transfers
                if not captured_preopt_entry_seed:
                    from d810.backends.hexrays.evidence.residual_entry_bridge import (
                        recognize_preoptimized_residual_entry_bridge,
                        recover_initial_state_write,
                        recover_state_routing_nodes,
                    )

                    evidence = recognize_preoptimized_residual_entry_bridge(mba)
                    state_registers = {
                        int(transfer.selector_state_var_reg)
                        for transfer in current_transfers
                        if transfer.selector_state_var_reg is not None
                    }
                    routing_nodes = ()
                    routing_start_candidates = ()
                    initial_state = None
                    state_register = (
                        next(iter(state_registers))
                        if len(state_registers) == 1
                        else None
                    )
                    if evidence is not None and state_register is not None:
                        routing_nodes = recover_state_routing_nodes(
                            mba,
                            state_register=state_register,
                            after_ea=int(evidence.source_store_ea),
                            before_ea=int(evidence.source_store_ea) + 0x100,
                            transfers=current_transfers,
                        )
                        routing_start_candidates = tuple(
                            sorted(
                                {
                                    int(transfer.source_block_ea)
                                    for transfer in current_transfers
                                    if transfer.resolver_kind == "static_fixpoint"
                                    and int(evidence.source_store_ea)
                                    < int(transfer.source_block_ea)
                                    < int(evidence.source_store_ea) + 0x100
                                }
                            )
                        )
                    routing_start_ea = (
                        min(node.source_block_ea for node in routing_nodes)
                        if routing_nodes
                        else (
                            routing_start_candidates[0]
                            if routing_start_candidates
                            else None
                        )
                    )
                    if routing_start_ea is not None and state_register is not None:
                        initial_state = recover_initial_state_write(
                            mba,
                            state_register=state_register,
                            after_ea=int(evidence.source_store_ea),
                            before_ea=int(routing_start_ea),
                        )
                    if (
                        evidence is not None
                        and state_register is not None
                        and initial_state is not None
                        and routing_start_ea is not None
                    ):
                        captured_preopt_entry_seed.append(
                            (evidence, int(initial_state), state_register)
                        )
                    print(
                        "PREOPT_ENTRY_SEED",
                        f"captured={bool(captured_preopt_entry_seed)}",
                        f"evidence={evidence}",
                        "stack_cell_ida="
                        f"{None if evidence is None else hex(int(mba.stkoff_vd2ida(int(evidence.stack_cell_identity[0]))))}",
                        f"state_register={state_register}",
                        f"initial_state={None if initial_state is None else hex(int(initial_state))}",
                        f"routing_nodes={len(routing_nodes)}",
                        f"routing_start_candidates={[hex(ea) for ea in routing_start_candidates]}",
                        flush=True,
                    )
                entry_result = (
                    captured_entry_result[0] if captured_entry_result else None
                )
                entry_evidence = None if entry_result is None else entry_result[0]
                entry_plan = None if entry_result is None else entry_result[1]
                predicate_ida_stkoff = (
                    None if entry_result is None else int(entry_result[2])
                )
                imported_count = 0
                applied_boundary_ports = 0
                abstained_boundary_ports = 0
                if IMPORT_ALL_PREPARED or USE_UNION_CLOSURE:
                    prepared_targets = tuple(
                        sorted(
                            target_ea
                            for function_ea, target_ea in detached_island._DETACHED_SNIPPET_TEMPLATES
                            if int(function_ea) == FUNC_EA
                        )
                    )
                    materialize_result = materialize_detached_snippet_templates(
                        mba,
                        FUNC_EA,
                        prepared_targets,
                        expected_template_maturity=(ida_hexrays.MMAT_PREOPTIMIZED),
                        allow_raw_preopt_calls=(
                            not USE_UNION_CLOSURE or RAW_UNION_CALLS
                        ),
                        import_native_preopt_ranges=(
                            not USE_UNION_CLOSURE or RAW_UNION_CALLS
                        ),
                    )
                    imported_count = len(materialize_result)
                    if imported_count:
                        function = ida_funcs.get_func(FUNC_EA)
                        if function is not None:
                            imported_origins = dict(
                                imported_detached_snippet_instruction_origins(mba)
                            )
                            unique_start_rows = []
                            if UNIQUE_IMPORTED_BLOCK_STARTS:
                                for serial in range(int(mba.qty)):
                                    block = mba.get_mblock(serial)
                                    if block.head is None or not any(
                                        int(instruction.ea) in imported_origins
                                        for instruction in block_instructions(block)
                                    ):
                                        continue
                                    block.start = int(block.head.ea)
                                    block.end = int(block.head.ea) + 1
                                    native_eas = block_native_eas(
                                        block,
                                        imported_origins,
                                    )
                                    unique_start_rows.append(
                                        (
                                            f"blk{serial}@0x{min(native_eas):X}",
                                            hex(int(block.start)),
                                        )
                                    )
                                print(
                                    "UNIQUE_IMPORTED_BLOCK_STARTS",
                                    tuple(unique_start_rows),
                                    flush=True,
                                )
                            transient_imported_stack_points.clear()
                            transient_imported_stack_points.update(
                                {
                                    int(live_ea): int(
                                        ida_frame.get_spd(
                                            function,
                                            int(native_ea),
                                        )
                                    )
                                    for live_ea, native_ea in imported_detached_snippet_instruction_origins(
                                        mba
                                    )
                                    if int(native_ea) > 0
                                }
                            )
                    dump_call_argument_regions(
                        f"live-preopt-after-import-{self.preopt_callbacks}",
                        mba,
                    )
                    if BOUNDARY_PORT_MODE and imported_count:
                        applied_boundary_ports = len(
                            materialize_result.applied_boundary_ports
                        )
                        abstained_boundary_ports = len(
                            materialize_result.abstained_boundary_ports
                        )
                        self.boundary_ports_applied += applied_boundary_ports
                        self.latest_boundary_ports_applied = applied_boundary_ports
                        self.latest_boundary_ports_abstained = abstained_boundary_ports
                        applied_conditionals = (
                            imported_detached_snippet_conditional_boundary_evidence(mba)
                        )
                        applied_direct = (
                            imported_detached_snippet_direct_boundary_evidence(mba)
                        )
                        print(
                            "PREOPT_APPLIED_DIRECT_PORTS",
                            f"count={len(applied_direct)}",
                            "rows="
                            f"{[(hex(int(row.port.source_block_ea)), row.port.source_owner.value, hex(int(row.port.endpoint_block_ea)), row.port.endpoint_owner.value, tuple(hex(int(ea)) for ea in row.port.old_successor_eas), tuple(owner.value for owner in row.port.old_successor_owners), row.port.delivery_mode, hex(int(row.port.target_ea)), row.port.target_owner.value) for row in applied_direct]}",
                            flush=True,
                        )
                        print(
                            "PREOPT_APPLIED_CONDITIONAL_PORTS",
                            f"count={len(applied_conditionals)}",
                            "rows="
                            f"{[(hex(int(row.port.source_block_ea)), hex(int(row.port.predicate_ea)), hex(int(row.port.taken_target_ea)), hex(int(row.port.fallthrough_target_ea))) for row in applied_conditionals]}",
                            flush=True,
                        )
                        dump_imported_terminal_routes(
                            f"preopt-{self.preopt_callbacks}-post-ports",
                            mba,
                        )
                        dump_boundary_owned_terminal_sources(
                            f"preopt-{self.preopt_callbacks}-post-ports",
                            mba,
                        )
                elif entry_result is not None:
                    imported_count = island._materialize_missing_detached_snippets(
                        mba,
                        current_transfers,
                        require_live_residual_source=False,
                        expected_template_maturity=(ida_hexrays.MMAT_PREOPTIMIZED),
                        allow_raw_preopt_calls=True,
                        import_native_preopt_ranges=True,
                    )
                alias_count = register_union_seed_aliases(mba)
                interior_entry_plan = (
                    None if BOUNDARY_PORT_MODE else plan_preopt_interior_entries(mba)
                )
                interior_entry_bridges = (
                    0
                    if interior_entry_plan is None
                    else apply_preopt_interior_entries(
                        mba,
                        interior_entry_plan,
                    )
                )
                dump_entry_window(f"preopt-after-import-{self.preopt_callbacks}", mba)
                imported_targets = imported_detached_snippet_target_eas(mba)
                incoming_boundary_plan = dump_preopt_incoming_boundary_shapes(
                    f"preopt-{self.preopt_callbacks}",
                    mba,
                    current_transfers,
                    imported_targets,
                )
                if not BOUNDARY_PORT_MODE and entry_result is None and imported_count:
                    direct_entry_plan = plan_entry_bridge(
                        mba,
                        current_transfers,
                        preopt_seed=(
                            captured_preopt_entry_seed[0]
                            if captured_preopt_entry_seed
                            else None
                        ),
                    )
                    print(
                        "PREOPT_ENTRY_PLAN",
                        f"direct={direct_entry_plan is not None}",
                        f"result={direct_entry_plan}",
                        flush=True,
                    )
                    if direct_entry_plan is not None:
                        direct_evidence, direct_plan = direct_entry_plan
                        direct_predicate_ida_stkoff = int(
                            mba.stkoff_vd2ida(
                                int(direct_evidence.predicate_stack_identity[0])
                            )
                        )
                        entry_result = (
                            direct_evidence,
                            direct_plan,
                            direct_predicate_ida_stkoff,
                        )
                        captured_entry_result[:] = [entry_result]
                        entry_evidence = direct_evidence
                        entry_plan = direct_plan
                        predicate_ida_stkoff = direct_predicate_ida_stkoff
                if CAPTURE_TRANSITION_MANIFEST:
                    instruction_origins.clear()
                    instruction_origins.update(
                        dict(imported_detached_snippet_instruction_origins(mba))
                    )
                entry_bridge = 0
                seeded_anchor = 0
                bridge_diagnostic: tuple[object, ...] = ()
                if (
                    not BOUNDARY_PORT_MODE
                    and entry_evidence is not None
                    and entry_plan is not None
                    and predicate_ida_stkoff is not None
                ):
                    bridge_anchor_ea = int(entry_evidence.source_store_ea)
                    source = find_unique_preopt_block_by_native_ea(
                        mba,
                        bridge_anchor_ea,
                    )
                    true_target = find_unique_preopt_block_by_native_ea(
                        mba,
                        int(entry_plan.true_target_ea),
                    )
                    false_target = find_unique_preopt_block_by_native_ea(
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
                                f"PREOPT proven entry state store 0x{bridge_anchor_ea:X} "
                                f"-> 0x{int(entry_plan.true_target_ea):X}"
                            ),
                            priority=5,
                        )
                        seeded_anchor = int(
                            seed_modifier.apply(defer_post_apply_maintenance=True)
                        )
                        source = find_unique_preopt_block_by_native_ea(
                            mba,
                            bridge_anchor_ea,
                        )
                        true_target = find_unique_preopt_block_by_native_ea(
                            mba,
                            int(entry_plan.true_target_ea),
                        )
                        false_target = find_unique_preopt_block_by_native_ea(
                            mba,
                            int(entry_plan.false_target_ea),
                        )
                    bridge_diagnostic = (
                        (
                            None
                            if source is None
                            else f"blk{int(source.serial)}@0x{bridge_anchor_ea:X}"
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
                        condition.size = int(entry_evidence.predicate_stack_identity[1])
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
                            false_target_serial=int(nonzero_false_target.serial),
                            true_target_serial=int(nonzero_true_target.serial),
                            proof_id=(
                                f"preopt_entry_bridge:0x{int(entry_evidence.predicate_ea):X}"
                            ),
                            description=(
                                f"PREOPT entry bridge 0x{int(entry_evidence.predicate_ea):X} "
                                f"at state store 0x{bridge_anchor_ea:X} -> "
                                f"0x{int(entry_plan.false_target_ea):X}/"
                                f"0x{int(entry_plan.true_target_ea):X}"
                            ),
                            rule_priority=1000,
                        )
                        entry_bridge = int(
                            modifier.apply(defer_post_apply_maintenance=True)
                        )
                        self.entry_bridges += int(entry_bridge)
                if BOUNDARY_PORT_MODE:
                    residual_routes = 0
                    terminal_routes = 0
                    incoming_direct = 0
                    incoming_conditional = 0
                    incoming_skipped = ()
                else:
                    residual_routes = island._apply_residual_state_route_bridges(
                        mba,
                        current_transfers,
                    )
                    terminal_routes = island._apply_detached_snippet_terminal_routes(
                        mba,
                        current_transfers,
                    )
                    (
                        incoming_direct,
                        incoming_conditional,
                        incoming_skipped,
                    ) = apply_preopt_incoming_boundaries(
                        mba,
                        incoming_boundary_plan,
                    )
                dump_preopt_closing_opcode_violations(
                    f"preopt-{self.preopt_callbacks}-after-boundaries",
                    mba,
                )
                verified = safe_verify(
                    mba,
                    "PREOPT detached snippet probe",
                    logger_func=print_verify_log,
                )
                print(
                    "PREOPT_IMPORT",
                    f"callback={self.preopt_callbacks}",
                    f"qty={int(mba.qty)}",
                    f"imported_count={imported_count}",
                    f"applied_boundary_ports={applied_boundary_ports}",
                    f"abstained_boundary_ports={abstained_boundary_ports}",
                    f"alias_count={alias_count}",
                    f"interior_entry_bridges={interior_entry_bridges}",
                    f"imported_targets={[hex(ea) for ea in imported_targets]}",
                    f"entry_plan={entry_plan}",
                    f"bridge_diagnostic={bridge_diagnostic}",
                    f"seeded_anchor={seeded_anchor}",
                    f"entry_bridge={entry_bridge}",
                    f"residual_routes={residual_routes}",
                    f"terminal_routes={terminal_routes}",
                    f"incoming_boundary_plan={incoming_boundary_plan}",
                    f"incoming_direct={incoming_direct}",
                    f"incoming_conditional={incoming_conditional}",
                    f"incoming_skipped={incoming_skipped}",
                    f"verified={verified}",
                    flush=True,
                )
                return 0

            def calls_done(self, mba):
                if int(mba.entry_ea) != FUNC_EA:
                    return 0
                self.calls_callbacks += 1
                origins = dict(imported_detached_snippet_instruction_origins(mba))
                dump_imported_seed_connectivity(f"calls-{self.calls_callbacks}", mba)
                dump_imported_terminal_routes(f"calls-{self.calls_callbacks}", mba)
                dump_boundary_owned_terminal_sources(
                    f"calls-{self.calls_callbacks}", mba
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
            for attempt in range(1, MAX_DECOMPILE_ATTEMPTS + 1):
                if attempt > 1:
                    ida_hexrays.clear_cached_cfuncs()
                decompile_failure = ida_hexrays.hexrays_failure_t()
                decompile_flags = int(ida_hexrays.DECOMP_NO_CACHE)
                if TOPLEVEL_ALL_BLOCKS:
                    decompile_flags |= int(ida_hexrays.DECOMP_ALL_BLKS)
                cfunc = ida_hexrays.decompile_func(
                    idaapi.get_func(FUNC_EA),
                    decompile_failure,
                    decompile_flags,
                )
                last_failure = decompile_failure.desc()
                fixed_point = resolver_state.materialized
                prepared = 0
                # Preparation is independently idempotent from native byte
                # materialization.  A completed decompile can publish new
                # CALLS evidence (for example, a terminal return-carrier
                # request) even after the computed-goto byte patch has reached
                # its fixed point.  Match the production UI lifecycle: always
                # give the between-decompile preparer a chance to consume that
                # evidence, then redo only when it captured something new.
                if cfunc is not None and not SKIP_PREPARE:
                    if USE_UNION_CLOSURE:
                        prepared = prepare_union_semantic_closure(
                            latest_preopt_live_native_eas[0]
                            if latest_preopt_live_native_eas
                            else cg._live_mba_native_eas(cfunc.mba),
                            latest_preopt_live_native_eas[0]
                            if latest_preopt_live_native_eas
                            else cg._live_mba_native_eas(cfunc.mba),
                        )
                        prepared += cg.prepare_terminal_return_carrier_templates(
                            resolver_state
                        )
                    else:
                        prepared = cg.prepare_detached_handler_snippets(
                            resolver_state,
                            live_mba=cfunc.mba,
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
                if cfunc is not None and (
                    (
                        BOUNDARY_PORT_MODE
                        and latest_template_boundary_port_count[0] > 0
                        and hook.latest_boundary_ports_applied
                        == latest_template_boundary_port_count[0]
                        and hook.latest_boundary_ports_abstained == 0
                    )
                    or (
                        not BOUNDARY_PORT_MODE
                        and hook.entry_bridges > 0
                        and fixed_point
                    )
                ):
                    break
            if cfunc is not None:
                dump_final_native_inventory(cfunc.mba)
                if STACK_CALLINFO_DIAG:
                    call_rows: list[tuple[object, ...]] = []

                    class CtreeCallVisitor(ida_hexrays.ctree_visitor_t):
                        def __init__(self) -> None:
                            ida_hexrays.ctree_visitor_t.__init__(
                                self,
                                ida_hexrays.CV_FAST,
                            )

                        def visit_expr(self, expression):
                            if int(expression.op) != int(ida_hexrays.cot_call):
                                return 0
                            callee = expression.x
                            callee_ea = (
                                int(callee.obj_ea)
                                if int(callee.op) == int(ida_hexrays.cot_obj)
                                else None
                            )
                            rendered = expression.print1(cfunc)
                            call_rows.append(
                                (
                                    hex(int(expression.ea)),
                                    (None if callee_ea is None else hex(callee_ea)),
                                    len(expression.a),
                                    idaapi.tag_remove(str(rendered)),
                                )
                            )
                            return 0

                    CtreeCallVisitor().apply_to(cfunc.body, None)
                    print("FINAL_CTREE_CALLS", tuple(call_rows), flush=True)
                pseudocode = "\n".join(
                    idaapi.tag_remove(str(line.line)) for line in cfunc.get_pseudocode()
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
            minimal_emit.recover_state_write_transitions_via_partitioned_fixpoint = (
                original_transition_recovery
            )
            if TRACE_REDIRECT_CATEGORIES:
                for original in traced_redirect_functions.values():
                    setattr(minimal_emit, original.__name__, original)
                minimal_emit._applied_direct_boundary_edge_keys = (
                    original_direct_edge_keys
                )
                minimal_emit._applied_conditional_boundary_edge_keys = (
                    original_conditional_edge_keys
                )
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
                if CAPTURE_TRANSITION_MANIFEST and transition_manifest_captures:
                    selected_manifest = select_replay_transition_manifest(
                        transition_manifest_captures
                    )
                    persist_transition_manifest(destination, selected_manifest)
                    print(
                        "TRANSITION_MANIFEST",
                        f"capture={selected_manifest[0].capture_index}",
                        f"rows={len(selected_manifest)}",
                        "unresolved="
                        f"{sum(row.status == 'unresolved' for row in selected_manifest)}",
                        flush=True,
                    )
                print("DIAG_DB", destination, flush=True)
finally:
    idapro.close_database(False)
