"""Runtime-layer regression tests for the computed-goto resolver."""
from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

from d810.optimizers.microcode.flow.jumps.computed_goto_resolver import (
    ComputedGotoResolution,
    _ConcreteHandlerStateWrite,
    _build_conditional_handler_state_routes,
    _build_materialized_state_routes,
    _apply_concrete_equality_setcc,
    _canonical_low_byte_parent,
    _native_equality_selector_is_materializable,
    _native_final_state_write_before_live_tail,
    _NativeEqualityRow,
    _PatchPlan,
    _static_equality_route_candidate,
    _static_absorb_eas,
    _static_equality_candidate_target,
    _states_with_validated_exact_equality_routes,
    _setcc_equality_delivery_targets,
    _encode_two_way_branch,
    _encode_direct_jump,
    _encode_x86_register_immediate32,
    _equality_setcc_condition_code,
    _equality_fragment_owned_ranges,
    _exact_equality_fragment_transfers,
    _equality_transfers_activated_by_targets,
    _exact_equality_native_target,
    _function_context_register_values,
    _is_concrete_handler_entry,
    _is_ignorable_corridor_store,
    _is_materialized_dispatch_instruction,
    _state_write_values_match,
    _insn_writes_first_operand,
    _sv_process_writer,
    _corridor_memory_spaces_may_alias,
    _plan_residual_state_route_patches,
    _plan_misrouted_exact_state_route_patches,
    _plan_exact_state_write_route_patches,
    _plan_all_residual_state_route_patches,
    _build_residual_state_route_evidence,
    _residual_predicate_inherited_states,
    _partition_residual_route_branches,
    recover_conditional_handler_bridge_transfers_from_mba,
    _recover_condition_chain_handler_transfers_from_mba,
    _recover_static_handler_entry_route_transfers,
    _select_register_indirect_patch_region,
    _choose_dispatch_patch_region,
    _claim_exact_function_tail_range,
    _plan_unseen_residual_state_route_patches,
    _resolve_concrete_handler_state_write,
    _unique_equality_state_targets,
    _unique_static_equality_handler_targets,
    is_computed_goto_materialized,
    _on_build_callinfo,
    _callinfo_profile_resolution,
    _proven_callinfo_reentry_eas,
    _zero_arg_call_type_is_proven,
)
from d810.optimizers.microcode.flow.jumps import computed_goto_resolver
from d810.hexrays.hooks.optimization_suppression import (
    d810_optimization_is_suppressed,
)
from d810.analyses.control_flow.minimal_state_recovery import StateWriteTransition
from d810.analyses.control_flow.call_abi import (
    StackCallAbiEvidence,
    StackCallAbiProof,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
    MaterializedStateRoute,
)
from d810.analyses.control_flow.semantic_transition import StateWriteAnchor
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot


def test_native_tail_state_scan_does_not_cross_block_start(monkeypatch):
    import idautils

    scanned_ranges: list[tuple[int, int]] = []

    def record_heads(start_ea: int, end_ea: int):
        scanned_ranges.append((int(start_ea), int(end_ea)))
        return ()

    monkeypatch.setattr(idautils, "Heads", record_heads)
    block = BlockSnapshot(
        serial=100,
        block_type=1,
        succs=(316,),
        preds=(99,),
        flags=0,
        start_ea=0x40B157,
        insn_snapshots=(
            InsnSnapshot(opcode=0, ea=0x40B157, operands=()),
            InsnSnapshot(opcode=0, ea=0xF1C0072C, operands=()),
        ),
    )

    assert _native_final_state_write_before_live_tail(
        block,
        state_var_reg=20,
        incoming_state=0xCCEC5DE0,
    ) is None
    assert (0x40B157, 0x40B158) in scanned_ranges


def test_function_context_register_values_require_one_non_top_singleton():
    states = {
        0x1000: {},
        0x1010: {"esi": frozenset({0xFDEE1C81}), "edx": frozenset({0x48B744})},
        0x1020: {"esi": frozenset({0xFDEE1C81}), "edx": None},
        0x1030: {"esi": frozenset({0xFDEE1C81}), "eax": frozenset({1, 2})},
    }

    assert _function_context_register_values(states) == (("esi", 0xFDEE1C81),)


def test_zero_arg_call_type_requires_profile_and_first_access_clobbers() -> None:
    assert _zero_arg_call_type_is_proven(
        profile_owned=True,
        direct_call=True,
        has_operand_type=False,
        has_callee_type=False,
        guessed_arg_count=0,
        callee_argsize=0,
        first_fastcall_register_accesses=("write", "write"),
    )


def test_zero_arg_call_type_abstains_on_register_read_or_existing_type() -> None:
    common = {
        "profile_owned": True,
        "direct_call": True,
        "has_operand_type": False,
        "has_callee_type": False,
        "guessed_arg_count": 0,
        "callee_argsize": 0,
    }

    assert not _zero_arg_call_type_is_proven(
        **common,
        first_fastcall_register_accesses=("write", "read"),
    )
    assert not _zero_arg_call_type_is_proven(
        **{**common, "has_callee_type": True},
        first_fastcall_register_accesses=("write", "write"),
    )


def test_build_callinfo_applies_proven_three_argument_stdcall(monkeypatch) -> None:
    import ida_hexrays
    import ida_nalt

    function_ea = 0x1000
    call_ea = 0x1030
    reentry_ea = 0x2020
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={reentry_ea: (0x3000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_RESOLUTIONS_BY_EA",
        {function_ea: resolution},
    )
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: False)
    monkeypatch.setattr(
        computed_goto_resolver,
        "native_call_stack_deficit",
        lambda _block, _call_ea: 12,
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "native_corridor_has_no_stack_adjustment",
        lambda _call_ea, _reentry_eas: True,
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "collect_three_argument_callee_purged_evidence",
        lambda *_args, **_kwargs: StackCallAbiEvidence(
            word_size=4,
            outgoing_stack_offsets=(-12, -8, -4),
            call_stack_deficit=12,
            argument_values_proven=True,
            continuation_is_linear=True,
            continuation_reaches_proven_reentry=True,
            caller_stack_adjustment=0,
            has_authoritative_type=False,
        ),
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "prove_three_argument_callee_purged_call",
        lambda _evidence: StackCallAbiProof(3, 12),
        raising=False,
    )
    applied: list[StackCallAbiProof] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "apply_three_argument_stdcall_type",
        lambda _call_type, proof: not applied.append(proof),
        raising=False,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "build_three_argument_stdcall_callinfo",
        lambda _block, _call_type, _proof: "prepared-callinfo",
        raising=False,
    )
    block = SimpleNamespace(
        tail=SimpleNamespace(
            opcode=ida_hexrays.m_icall,
            ea=call_ea,
        )
    )

    decision: dict[str, object] = {"callinfo": None}
    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision=decision,
    )

    assert applied == [StackCallAbiProof(3, 12)]
    assert decision["callinfo"] == "prepared-callinfo"


def test_callinfo_reentry_accepts_only_exact_native_resolver_evidence() -> None:
    resolution = ComputedGotoResolution(
        function_ea=0x1000,
        jmp_targets={},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x2020,
        source_block_ea=0x2000,
        materialized_anchor_eas=(),
        target_eas=(0x3000,),
        resolver_kind="detached_static_fixpoint",
    )
    inferred = MaterializedIndirectTransfer(
        source_jmp_ea=0x4040,
        source_block_ea=0x4000,
        materialized_anchor_eas=(),
        target_eas=(0x5000,),
        resolver_kind="condition_chain_handler_evidence",
    )

    assert _proven_callinfo_reentry_eas(resolution, (exact, inferred)) == frozenset(
        {0x2020}
    )


def test_build_callinfo_derives_exact_detached_reentry_before_calls(
    monkeypatch,
) -> None:
    import ida_hexrays
    import ida_nalt

    function_ea = 0x1000
    call_ea = 0x1030
    reentry_ea = 0x2020
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={0x4040: (0x5000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=reentry_ea,
        source_block_ea=0x2000,
        materialized_anchor_eas=(),
        target_eas=(0x3000,),
        resolver_kind="detached_static_fixpoint",
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_RESOLUTIONS_BY_EA",
        {function_ea: resolution},
    )
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: False)
    monkeypatch.setattr(
        computed_goto_resolver,
        "get_materialized_indirect_transfers",
        lambda _function_ea: (),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "record_materialized_indirect_transfers",
        lambda _function_ea, _transfers: None,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_detached_static_terminal_transfers",
        lambda _resolution, entry_eas: (exact,) if entry_eas == (0x1010,) else (),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "native_call_stack_deficit",
        lambda _block, _call_ea: 12,
    )
    observed_reentries: list[frozenset[int]] = []

    def no_adjustment(_call_ea, reentry_eas):
        observed_reentries.append(reentry_eas)
        return True if reentry_ea in reentry_eas else None

    monkeypatch.setattr(
        computed_goto_resolver,
        "native_corridor_has_no_stack_adjustment",
        no_adjustment,
    )

    def evidence(_block, **kwargs):
        return StackCallAbiEvidence(
            word_size=4,
            outgoing_stack_offsets=(-12, -8, -4),
            call_stack_deficit=kwargs["call_stack_deficit"],
            argument_values_proven=True,
            continuation_is_linear=True,
            continuation_reaches_proven_reentry=True,
            caller_stack_adjustment=kwargs["caller_stack_adjustment"],
            has_authoritative_type=False,
        )

    monkeypatch.setattr(
        computed_goto_resolver,
        "collect_three_argument_callee_purged_evidence",
        evidence,
    )
    applied: list[StackCallAbiProof] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "apply_three_argument_stdcall_type",
        lambda _call_type, proof: not applied.append(proof),
    )
    prepared_callinfo = object()
    monkeypatch.setattr(
        computed_goto_resolver,
        "build_three_argument_stdcall_callinfo",
        lambda _block, _call_type, _proof: prepared_callinfo,
    )
    block = SimpleNamespace(
        start=0x1010,
        tail=SimpleNamespace(opcode=ida_hexrays.m_icall, ea=call_ea),
    )
    decision: dict[str, object] = {}

    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision=decision,
    )

    assert observed_reentries == [
        frozenset({0x4040}),
        frozenset({0x2020, 0x4040}),
    ]
    assert applied == [StackCallAbiProof(3, 12)]
    assert decision["callinfo"] is prepared_callinfo


def test_callinfo_profile_rebinds_isolated_snippet_to_native_owner(
    monkeypatch,
) -> None:
    import ida_funcs

    resolution = ComputedGotoResolution(
        function_ea=0x1000,
        jmp_targets={0x2020: (0x3000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_RESOLUTIONS_BY_EA",
        {0x1000: resolution},
    )
    monkeypatch.setattr(
        ida_funcs,
        "get_func",
        lambda call_ea: (
            SimpleNamespace(start_ea=0x1000) if call_ea == 0x1030 else None
        ),
    )

    assert _callinfo_profile_resolution(0x1010, 0x1030) == (
        0x1000,
        resolution,
    )


def test_callinfo_profile_uses_active_detached_capture_owner(monkeypatch) -> None:
    import ida_funcs

    resolution = ComputedGotoResolution(
        function_ea=0x1000,
        jmp_targets={0x2020: (0x3000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_RESOLUTIONS_BY_EA",
        {0x1000: resolution},
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_SNIPPET_CAPTURE_ACTIVE",
        True,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_SNIPPET_CAPTURE_PROFILE_EA",
        0x1000,
        raising=False,
    )
    monkeypatch.setattr(ida_funcs, "get_func", lambda _ea: None)

    assert _callinfo_profile_resolution(0x1010, 0x1030) == (
        0x1000,
        resolution,
    )


def test_build_callinfo_preserves_authoritative_indirect_type(monkeypatch) -> None:
    import ida_hexrays
    import ida_nalt

    function_ea = 0x1000
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={0x2020: (0x3000,)},
        reachable_eas=(),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_RESOLUTIONS_BY_EA",
        {function_ea: resolution},
    )
    monkeypatch.setattr(ida_nalt, "get_op_tinfo", lambda *_args: True)
    called: list[bool] = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "collect_three_argument_callee_purged_evidence",
        lambda *_args, **_kwargs: called.append(True),
        raising=False,
    )
    block = SimpleNamespace(
        tail=SimpleNamespace(
            opcode=ida_hexrays.m_icall,
            ea=0x1030,
        )
    )

    _on_build_callinfo(
        function_ea=function_ea,
        block=block,
        call_type=object(),
        decision={},
    )

    assert called == []


def test_nested_snippet_generation_suppresses_d810() -> None:
    observed = []

    def generate(*args):
        observed.append((args, d810_optimization_is_suppressed()))
        return "snippet"

    assert computed_goto_resolver._generate_microcode_without_d810(
        generate,
        "ranges",
        "failure",
        None,
        0x10,
        3,
    ) == "snippet"
    assert observed == [
        (("ranges", "failure", None, 0x10, 3), True),
    ]


def test_live_mba_native_eas_rebind_imported_instruction_origins() -> None:
    class Instruction:
        def __init__(self, ea: int, next_instruction=None) -> None:
            self.ea = ea
            self.next = next_instruction

    tail = Instruction(0xF1C00008)
    head = Instruction(0xF1C00004, tail)

    block = SimpleNamespace(
        start=0x40B157,
        head=head,
        tail=tail,
    )

    class Mba:
        qty = 1

        @staticmethod
        def get_mblock(serial: int):
            assert serial == 0
            return block

    assert computed_goto_resolver._live_mba_native_eas(
        Mba(),
        imported_instruction_origins=(
            (0xF1C00004, 0x40B163),
            (0xF1C00008, 0x40B168),
        ),
    ) == frozenset({0x40B157, 0x40B163, 0x40B168})


def test_static_transfer_preserves_register_across_nonwriting_cmp(
    monkeypatch,
) -> None:
    idaapi = ModuleType("idaapi")
    idaapi.o_reg = 1
    idaapi.CF_CHG1 = 0x2
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)

    class Operand:
        type = idaapi.o_reg
        reg = 3

    class Instruction:
        ops = (Operand(), Operand())

        @staticmethod
        def get_canon_feature() -> int:
            return 0

    state = {"ebx": frozenset({0x7F9D6412})}

    _sv_process_writer("cmp", Instruction(), state)

    assert state["ebx"] == frozenset({0x7F9D6412})


def test_handler_state_replay_crosses_call_for_callee_saved_state_register(
    monkeypatch,
) -> None:
    idaapi = ModuleType("idaapi")
    idaapi.o_void = 0
    idaapi.o_reg = 1
    idaapi.o_imm = 2
    idaapi.o_mem = 3
    idaapi.o_displ = 4
    idaapi.o_phrase = 5
    idaapi.CF_CHG1 = 0x2
    mnemonics = {
        0x40C1BB: "call",
        0x40C1D6: "mov",
        0x40C1F0: "jmp",
    }
    idaapi.print_insn_mnem = lambda ea: mnemonics.get(int(ea), "")
    monkeypatch.setitem(sys.modules, "idaapi", idaapi)
    monkeypatch.setitem(sys.modules, "ida_bytes", ModuleType("ida_bytes"))

    class Operand:
        def __init__(self, kind=0, *, reg=0, value=0):
            self.type = kind
            self.reg = reg
            self.value = value

    class Instruction:
        def __init__(self):
            self.ops = [Operand(), Operand()]
            self._feature = 0

        def get_canon_feature(self) -> int:
            return self._feature

    ida_ua = ModuleType("ida_ua")
    ida_ua.insn_t = Instruction

    def decode_insn(insn, ea):
        if int(ea) == 0x40C1BB:
            insn.ops = [Operand(), Operand()]
            insn._feature = 0
            return 0x1B
        if int(ea) == 0x40C1D6:
            insn.ops = [
                Operand(idaapi.o_reg, reg=3),
                Operand(idaapi.o_imm, value=0x7F9D6412),
            ]
            insn._feature = idaapi.CF_CHG1
            return 0x1A
        if int(ea) == 0x40C1F0:
            insn.ops = [Operand(), Operand()]
            insn._feature = 0
            return 2
        return 0

    ida_ua.decode_insn = decode_insn
    monkeypatch.setitem(sys.modules, "ida_ua", ida_ua)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_state",
        lambda _mregs: {"ebx": frozenset({0xA7933EA0})},
    )

    assert _resolve_concrete_handler_state_write(
        0x40C1BB,
        initial_mregs={20: 0xA7933EA0},
        state_register_name="ebx",
    ) == _ConcreteHandlerStateWrite(0x7F9D6412, 0x40C1F0)


def test_static_handler_entry_route_replays_condition_chain_leaf() -> None:
    state = 0x1EBFFA3C
    context = 0xFDEE1C81
    leaf = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B157,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )
    context_evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5CA,),
        target_eas=(0x40A5F0,),
        context_register_values=((36, context),),
        resolver_kind="static_fixpoint",
    )
    calls = []

    def resolve(start_ea: int, **kwargs):
        calls.append((start_ea, kwargs))
        return 0x40B163

    assert _recover_static_handler_entry_route_transfers(
        (leaf, context_evidence),
        route_resolver=resolve,
    ) == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B149,
            source_block_ea=0x40B149,
            materialized_anchor_eas=(),
            target_eas=(0x40B163,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            context_register_values=((36, context),),
            resolver_kind="static_handler_entry_route",
        ),
    )
    assert calls == [
        (
            0x40B149,
            {
                "initial_mregs": {20: state, 36: context},
                "handler_eas": frozenset(),
                "dispatch_anchor_eas": frozenset({0x40A5CA}),
                "return_first_indirect_target": True,
            },
        )
    ]


def test_prepatch_handler_entry_route_replays_native_equality_leaf(
    monkeypatch,
) -> None:
    state = 0x1EBFFA3C
    context = 0xFDEE1C81
    row = _NativeEqualityRow(
        register_name="ebx",
        state_constant=state,
        direct_target_ea=0x40B157,
        block_entry_ea=0x40B149,
        branch_ea=0x40B155,
        branch_size=2,
        condition_code=4,
        terminal_jmp_ea=0x40B161,
        terminal_end_ea=0x40B163,
        selector_kind="jcc",
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={},
        reachable_eas=(0x40A560,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
        function_context_register_values=(("esi", context),),
    )
    calls = []
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_register_mreg",
        lambda name: {"ebx": 20, "esi": 36}.get(name),
    )

    def resolve(start_ea: int, **kwargs):
        calls.append((start_ea, kwargs))
        return 0x40B163

    assert computed_goto_resolver._recover_prepatch_handler_entry_routes(
        resolution,
        (row,),
        route_resolver=resolve,
        range_resolver=lambda target_ea: (
            (target_ea, 0x40B17F),
        ),
    ) == (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B149,
            source_block_ea=0x40B149,
            materialized_anchor_eas=(),
            target_eas=(0x40B163,),
            selector_state_var_reg=20,
            selector_state_constant=state,
            context_register_values=((36, context),),
            resolver_kind="static_handler_entry_route",
            owned_native_ranges=((0x40B163, 0x40B17F),),
        ),
    )
    assert calls == [
        (
            0x40B149,
            {
                "initial_mregs": {20: state, 36: context},
                "handler_eas": frozenset(),
                "return_first_indirect_target": True,
            },
        )
    ]


def test_static_handler_entry_route_abstains_on_conflicting_context() -> None:
    leaf = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B157,),
        selector_state_var_reg=20,
        selector_state_constant=0x1EBFFA3C,
        resolver_kind="condition_chain_handler_evidence",
    )
    conflicting_context = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A5E3 + index,
            source_block_ea=0x40A5CA,
            materialized_anchor_eas=(0x40A5CA,),
            target_eas=(0x40A5F0,),
            context_register_values=((36, value),),
            resolver_kind="static_fixpoint",
        )
        for index, value in enumerate((0xFDEE1C81, 0xA0716E5B))
    )

    assert _recover_static_handler_entry_route_transfers(
        (leaf, *conflicting_context),
        route_resolver=lambda *_args, **_kwargs: 0x40B163,
    ) == ()


def test_static_handler_entry_route_abstains_on_conflicting_leaf_proofs() -> None:
    leaves = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B149,
            source_block_ea=0x40B149,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=20,
            selector_state_constant=0x1EBFFA3C,
            resolver_kind="condition_chain_handler_evidence",
        )
        for target_ea in (0x40B157, 0x40B15E)
    )
    context = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5CA,),
        target_eas=(0x40A5F0,),
        context_register_values=((36, 0xFDEE1C81),),
        resolver_kind="static_fixpoint",
    )

    assert _recover_static_handler_entry_route_transfers(
        (*leaves, context),
        route_resolver=lambda *_args, **_kwargs: 0x40B163,
    ) == ()


def test_prepare_detached_snippets_publishes_static_handler_entry_routes(
    monkeypatch,
) -> None:
    function_ea = 0x40A560
    leaf = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B157,),
        selector_state_var_reg=20,
        selector_state_constant=0x1EBFFA3C,
        resolver_kind="condition_chain_handler_evidence",
    )
    route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B149,
        source_block_ea=0x40B149,
        materialized_anchor_eas=(),
        target_eas=(0x40B163,),
        selector_state_var_reg=20,
        selector_state_constant=0x1EBFFA3C,
        context_register_values=((36, 0xFDEE1C81),),
        resolver_kind="static_handler_entry_route",
    )
    resolution = ComputedGotoResolution(
        function_ea=function_ea,
        jmp_targets={},
        reachable_eas=(function_ea,),
        arch="x86",
        executed_insns=0,
        seeds_run=0,
    )
    recorded = []
    planned = []

    monkeypatch.setitem(
        computed_goto_resolver._RESOLUTIONS_BY_EA,
        function_ea,
        resolution,
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "get_materialized_indirect_transfers",
        lambda _function_ea: (leaf,),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_recover_static_handler_entry_route_transfers",
        lambda _transfers: (route,),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "record_materialized_indirect_transfers",
        lambda key, transfers: recorded.append((key, transfers)),
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "get_terminal_return_carrier_requests",
        lambda _function_ea: (),
    )
    monkeypatch.setitem(sys.modules, "ida_hexrays", ModuleType("ida_hexrays"))
    monkeypatch.setitem(sys.modules, "idaapi", ModuleType("idaapi"))
    mutation_module = ModuleType(
        "d810.hexrays.mutation.detached_handler_island"
    )
    for name in (
        "capture_detached_replacement_snippet_template",
        "capture_detached_snippet_template",
        "capture_terminal_return_carrier_template",
        "detached_snippet_requires_analyzed_calls",
        "has_detached_replacement_snippet_template",
        "has_detached_snippet_template",
        "has_terminal_return_carrier_template",
        "imported_detached_snippet_instruction_origins",
    ):
        setattr(mutation_module, name, lambda *_args, **_kwargs: False)
    monkeypatch.setitem(
        sys.modules,
        "d810.hexrays.mutation.detached_handler_island",
        mutation_module,
    )

    from d810.analyses.control_flow import detached_handler_island

    monkeypatch.setattr(
        detached_handler_island,
        "plan_detached_snippet_routes",
        lambda transfers, **_kwargs: planned.append(transfers) or (),
    )

    assert computed_goto_resolver.prepare_detached_handler_snippets(function_ea) == 0
    assert recorded == [(function_ea, (leaf, route))]
    assert planned == [(leaf, route)]


def test_detached_static_terminal_transfers_seed_each_island_from_function_context(
    monkeypatch,
) -> None:
    source_state = 0x7F9D6412
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={},
        reachable_eas=(0x40A560,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        function_context_register_values=(("esi", 0xFDEE1C81),),
    )
    calls: list[tuple[int, tuple[tuple[str, int], ...]]] = []

    def fixpoint(
        entry_ea: int,
        *,
        initial_register_values: tuple[tuple[str, int], ...] = (),
    ) -> tuple[dict, dict, dict, dict, int]:
        calls.append((entry_ea, initial_register_values))
        return (
            {0x40C703: {"ebx": frozenset({source_state})}},
            {0x40C703: [0x40AF00]},
            {},
            {0x40C703: 0x40C6DA},
            17,
        )

    monkeypatch.setattr(computed_goto_resolver, "_static_resolver_fixpoint", fixpoint)
    monkeypatch.setattr(
        computed_goto_resolver,
        "_static_register_state_before_jmp",
        lambda _block_entry, _entry_state, _jmp_ea: {
            "ebx": frozenset({source_state})
        },
    )
    monkeypatch.setattr(
        computed_goto_resolver,
        "_residual_context_mregs",
        lambda values: {
            20: int(dict(values)["ebx"])
        }
        if "ebx" in dict(values)
        else {},
    )

    (transfer,) = computed_goto_resolver._detached_static_terminal_transfers(
        resolution,
        (0x40B9A6,),
    )

    assert calls == [(0x40B9A6, (("esi", 0xFDEE1C81),))]
    assert transfer.source_jmp_ea == 0x40C703
    assert transfer.source_block_ea == 0x40C6DA
    assert transfer.target_eas == (0x40AF00,)
    assert transfer.source_register_values == ((20, source_state),)
    assert transfer.resolver_kind == "detached_static_fixpoint"


def test_static_absorb_set_includes_resolver_proven_terminal_targets() -> None:
    epilogue_ea = 0x40C898
    plan = _PatchPlan(
        jmp_ea=0x40A5E3,
        block_entry=0x40A5CA,
        patch_start=0x40A5D0,
        patch_bytes=b"\x90",
        region_end=0x40A5E5,
        insn_heads=(0x40A5D0,),
        new_block_eas=(0x40A5D6,),
        target_eas=(epilogue_ea, 0x40A5F0),
    )
    resolution = ComputedGotoResolution(
        function_ea=0x40A560,
        jmp_targets={0x40A5E3: (epilogue_ea, 0x40A5F0)},
        reachable_eas=(0x40A560,),
        arch="x86",
        executed_insns=1,
        seeds_run=0,
        patch_plans=(plan,),
        block_entries=(0x40A5CA,),
    )

    assert epilogue_ea in _static_absorb_eas(
        resolution,
        new_block_eas=(0x40A5D6,),
    )


def test_residual_route_partition_preserves_live_conditional_predicate() -> None:
    desktop_predicate = 0x40C404
    message_predicate = 0x40C5D1
    ordinary_route = 0x40C640
    facts = {
        desktop_predicate: {(6, 0xA5A94B86, 0x40B8E6)},
        message_predicate: {(6, 0x1F0B7687, 0x40A7AE)},
        ordinary_route: {(6, 0xEC71CA67, 0x40B9A6)},
    }

    protected, patchable = _partition_residual_route_branches(
        facts,
        frozenset({desktop_predicate, message_predicate}),
    )

    assert set(protected) == {desktop_predicate, message_predicate}
    assert set(patchable) == {ordinary_route}


def test_residual_predicate_inherits_exact_preceding_state_write() -> None:
    state = 0x1F0B7687
    write_ea = 0x40C5CA
    predicate_ea = 0x40C5D1
    block = BlockSnapshot(
        serial=260,
        block_type=0,
        succs=(261, 262),
        preds=(259,),
        flags=0,
        start_ea=0x40C5BD,
        insn_snapshots=(
            InsnSnapshot(opcode=0, ea=write_ea, operands=(), kind=InsnKind.MOV),
            InsnSnapshot(
                opcode=0,
                ea=predicate_ea,
                operands=(),
                kind=InsnKind.COND_JUMP,
            ),
        ),
    )
    graph = FlowGraph(
        blocks={260: block},
        entry_serial=260,
        func_ea=0x40A560,
    )

    assert _residual_predicate_inherited_states(
        graph,
        ((260, state, 0x40A7AE),),
        state_write_sites={(260, state): write_ea},
    ) == {predicate_ea: state}
    assert _residual_predicate_inherited_states(
        graph,
        ((260, state, 0x40A7AE),),
        state_write_sites={(260, state): predicate_ea + 1},
    ) == {}


def test_conditional_handler_bridge_requires_residual_route_not_predicate_patch(
    monkeypatch,
) -> None:
    state_register = 20
    false_state = 0xA5A94B86
    true_state = 0x304E8694
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A607,
            source_block_ea=0x40A607,
            materialized_anchor_eas=(),
            target_eas=(0x40B8E6,),
            selector_state_var_reg=state_register,
            selector_state_constant=false_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40A620,
            source_block_ea=0x40A620,
            materialized_anchor_eas=(),
            target_eas=(0x40A7AE,),
            selector_state_var_reg=state_register,
            selector_state_constant=true_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
    )
    bridge_module = ModuleType(
        "d810.backends.hexrays.evidence.residual_entry_bridge"
    )
    bridge_module.recognize_conditional_handler_bridges = (
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                predicate_ea=0x40C404,
                source_block_ea=0x40C3F0,
                predicate_register=44,
                    predicate_size=4,
                    predicate_compare_register=None,
                    predicate_compare_constant=None,
                    predicate_predecessor_ea=0x40C3FC,
                true_state=true_state,
                false_state=false_state,
                true_target_ea=0x40A7AE,
                false_target_ea=0x40B8E6,
                true_is_taken=True,
            ),
        )
    )
    bridge_module.predicate_arm_reaches_ea = (
        lambda _mba, *, predicate_ea, route_ea: (predicate_ea, route_ea)
        == (0x40C404, 0x40C422)
    )
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )
    assert recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
    ) == ()

    residual_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C422,
        source_block_ea=0x40C422,
        materialized_anchor_eas=(),
        target_eas=(0x40A7AE,),
        selector_state_var_reg=state_register,
        selector_state_constant=true_state,
        resolver_kind="residual_state_route",
    )
    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers + (residual_route,),
        object(),
    )

    assert bridge.resolver_kind == "conditional_handler_bridge"
    assert bridge.source_jmp_ea == 0x40C404
    assert bridge.target_eas == (0x40A7AE, 0x40B8E6)


def test_conditional_handler_bridge_accepts_imported_predicate_with_exact_arms(
    monkeypatch,
) -> None:
    state_register = 20
    true_state = 0x2100AFDD
    false_state = 0x0E9795EF
    predicate_ea = 0xF1C00248
    true_target = 0x40AF00
    false_target = 0x40ACE7
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40ACD3,
            source_block_ea=0x40ACD3,
            materialized_anchor_eas=(),
            target_eas=(false_target,),
            selector_state_var_reg=state_register,
            selector_state_constant=false_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40AEFE,
            source_block_ea=0x40AEEC,
            materialized_anchor_eas=(0x40AEF2,),
            target_eas=(true_target, 0x40A5F0),
            condition_code=4,
            true_target_ea=true_target,
            false_target_ea=0x40A5F0,
            selector_state_var_reg=state_register,
            selector_compare_constant=true_state,
            resolver_kind="static_equality_fixpoint",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40ACFB,
            source_block_ea=0x40ACE7,
            materialized_anchor_eas=(),
            target_eas=(false_target,),
            selector_state_var_reg=state_register,
            selector_state_constant=false_state,
            resolver_kind="residual_state_route",
        ),
    )
    bridge_module = ModuleType(
        "d810.backends.hexrays.evidence.residual_entry_bridge"
    )
    bridge_module.recognize_conditional_handler_bridges = (
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                predicate_ea=predicate_ea,
                source_block_ea=predicate_ea,
                predicate_register=8,
                predicate_size=4,
                predicate_compare_register=None,
                predicate_compare_constant=None,
                predicate_predecessor_ea=predicate_ea,
                true_state=true_state,
                false_state=false_state,
                true_target_ea=true_target,
                false_target_ea=false_target,
                true_is_taken=True,
            ),
        )
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: True
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        imported_predicate_eas=frozenset({predicate_ea}),
    )

    assert bridge.source_jmp_ea == predicate_ea
    assert bridge.target_eas == (true_target, false_target)
    assert bridge.predicate_true_state == true_state
    assert bridge.predicate_false_state == false_state
    assert bridge.predicate_preserve_live is True


def test_imported_predicate_accepts_static_equality_state_register_proof(
    monkeypatch,
) -> None:
    state_register = 20
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    predicate_ea = 0xF1C00410
    true_target = 0x40B3F3
    false_target = 0x40A560
    dispatcher_target = 0x40A607

    def static_route(
        source_ea: int,
        state: int,
        target_ea: int,
    ) -> MaterializedIndirectTransfer:
        return MaterializedIndirectTransfer(
            source_jmp_ea=source_ea,
            source_block_ea=source_ea,
            materialized_anchor_eas=(source_ea,),
            target_eas=(target_ea, dispatcher_target),
            condition_code=4,
            true_target_ea=target_ea,
            false_target_ea=dispatcher_target,
            selector_state_var_reg=state_register,
            selector_compare_constant=state,
            resolver_kind="static_equality_fixpoint",
        )

    transfers = (
        static_route(0x40B3E5, true_state, true_target),
        static_route(0x40B6C8, false_state, false_target),
    )
    bridge_module = ModuleType(
        "d810.backends.hexrays.evidence.residual_entry_bridge"
    )
    bridge_module.recognize_conditional_handler_bridges = (
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                predicate_ea=predicate_ea,
                source_block_ea=predicate_ea,
                predicate_register=8,
                predicate_size=4,
                predicate_compare_register=None,
                predicate_compare_constant=None,
                predicate_predecessor_ea=predicate_ea,
                true_state=true_state,
                false_state=false_state,
                true_target_ea=true_target,
                false_target_ea=false_target,
                true_is_taken=True,
            ),
        )
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        imported_predicate_eas=frozenset({predicate_ea}),
    )

    assert bridge.selector_state_var_reg == state_register
    assert bridge.predicate_true_state == true_state
    assert bridge.predicate_false_state == false_state
    assert bridge.predicate_preserve_live is True


def test_live_opaque_bridge_accepts_exact_inherited_handler_route(
    monkeypatch,
) -> None:
    state_register = 20
    inherited_state = 0x742F372A
    taken_state = 0xCCEC5DE0
    predicate_ea = 0x40C22F
    transfers = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=source_ea,
            source_block_ea=source_ea,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=state_register,
            selector_state_constant=state,
            resolver_kind="condition_chain_handler_evidence",
        )
        for source_ea, state, target_ea in (
            (0x40AA8E, inherited_state, 0x40AAA2),
            (0x40C168, taken_state, 0x40C16A),
        )
    )
    bridge_module = ModuleType(
        "d810.backends.hexrays.evidence.residual_entry_bridge"
    )
    bridge_module.recognize_conditional_handler_bridges = (
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                predicate_ea=predicate_ea,
                source_block_ea=0x40C20C,
                predicate_register=None,
                predicate_size=4,
                predicate_compare_register=None,
                predicate_compare_constant=0x62,
                predicate_predecessor_ea=0x40C217,
                true_state=taken_state,
                false_state=inherited_state,
                true_target_ea=0x40C16A,
                false_target_ea=0x40AAA2,
                true_is_taken=True,
            ),
        )
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        inherited_states_by_predicate_ea={predicate_ea: inherited_state},
    )

    assert bridge.source_jmp_ea == predicate_ea
    assert bridge.predicate_register is None
    assert bridge.predicate_false_state == inherited_state
    assert bridge.false_target_ea == 0x40AAA2
    assert bridge.predicate_preserve_live is True


def test_live_register_predicate_accepts_exact_inherited_handler_route(
    monkeypatch,
) -> None:
    state_register = 20
    inherited_state = 0x1F0B7687
    taken_state = 0x78BAC34B
    predicate_ea = 0x40C5D1
    inherited_target = 0x40A7AE
    taken_target = 0x40B100
    transfers = tuple(
        MaterializedIndirectTransfer(
            source_jmp_ea=source_ea,
            source_block_ea=source_ea,
            materialized_anchor_eas=(),
            target_eas=(target_ea,),
            selector_state_var_reg=state_register,
            selector_state_constant=state,
            resolver_kind="condition_chain_handler_evidence",
        )
        for source_ea, state, target_ea in (
            (0x40C5EF, inherited_state, inherited_target),
            (0x40C85F, taken_state, taken_target),
        )
    )
    bridge_module = ModuleType(
        "d810.backends.hexrays.evidence.residual_entry_bridge"
    )
    bridge_module.recognize_conditional_handler_bridges = (
        lambda *_args, **_kwargs: (
            SimpleNamespace(
                predicate_ea=predicate_ea,
                source_block_ea=0x40C5BD,
                predicate_register=44,
                predicate_size=4,
                predicate_compare_register=None,
                predicate_compare_constant=0,
                predicate_predecessor_ea=0x40C5CA,
                true_state=taken_state,
                false_state=inherited_state,
                true_target_ea=taken_target,
                false_target_ea=inherited_target,
                true_is_taken=True,
            ),
        )
    )
    bridge_module.predicate_arm_reaches_ea = lambda *_args, **_kwargs: False
    monkeypatch.setitem(
        sys.modules,
        "d810.backends.hexrays.evidence.residual_entry_bridge",
        bridge_module,
    )

    (bridge,) = recover_conditional_handler_bridge_transfers_from_mba(
        transfers,
        object(),
        inherited_states_by_predicate_ea={predicate_ea: inherited_state},
    )

    assert bridge.source_jmp_ea == predicate_ea
    assert bridge.predicate_register == 44
    assert bridge.true_target_ea == taken_target
    assert bridge.false_target_ea == inherited_target
    assert bridge.predicate_preserve_live is True


def test_state_write_values_require_exact_native_mov_identity() -> None:
    assert _state_write_values_match(
        mnemonic="mov",
        destination_mreg=20,
        immediate=0x304E8694,
        state_var_reg=20,
        state_constant=0x304E8694,
    )
    assert not _state_write_values_match(
        mnemonic="jmp",
        destination_mreg=None,
        immediate=None,
        state_var_reg=20,
        state_constant=0x304E8694,
    )
    assert not _state_write_values_match(
        mnemonic="mov",
        destination_mreg=20,
        immediate=0xA5A94B86,
        state_var_reg=20,
        state_constant=0x304E8694,
    )


def test_materialized_profile_is_published_after_preanalysis_fixed_point():
    function_ea = 0x40A560
    computed_goto_resolver._MATERIALIZED_EAS.add(function_ea)
    try:
        assert is_computed_goto_materialized(function_ea)
        assert not is_computed_goto_materialized(function_ea + 1)
    finally:
        computed_goto_resolver._MATERIALIZED_EAS.discard(function_ea)


def test_materialized_profile_is_published_during_staged_preanalysis():
    function_ea = 0x40A560
    computed_goto_resolver._MATERIALIZATION_SESSIONS[function_ea] = object()
    try:
        assert is_computed_goto_materialized(function_ea)
    finally:
        computed_goto_resolver._MATERIALIZATION_SESSIONS.pop(function_ea, None)


def test_function_context_register_values_abstain_on_conflicting_or_unknown_values():
    states = {
        0x1000: {"esi": frozenset({1})},
        0x1010: {"esi": frozenset({2}), "edi": None},
    }

    assert _function_context_register_values(states) == ()


def test_encode_two_way_branch_preserves_conditional_arm_polarity():
    body = _encode_two_way_branch(
        branch_ea=0x1000,
        condition_code=4,
        true_target_ea=0x2000,
        false_target_ea=0x3000,
    )

    assert body == b"\x0f\x84\xfa\x0f\x00\x00\xe9\xf5\x1f\x00\x00"


def test_equality_setcc_condition_code_normalizes_x86_aliases():
    assert _equality_setcc_condition_code("sete") == 4
    assert _equality_setcc_condition_code("setz") == 4
    assert _equality_setcc_condition_code("setne") == 5
    assert _equality_setcc_condition_code("setnz") == 5
    assert _equality_setcc_condition_code("setl") is None


def test_apply_concrete_equality_setcc_updates_only_low_byte():
    assert _apply_concrete_equality_setcc("setne", (7, 7), 0x123456FF) == 0x12345600
    assert _apply_concrete_equality_setcc("setne", (7, 8), 0x12345600) == 0x12345601
    assert _apply_concrete_equality_setcc("setz", (7, 7), 0) == 1
    assert _apply_concrete_equality_setcc("setl", (7, 8), 0) is None


def test_canonical_low_byte_parent_handles_separate_ida_subregister_ids():
    assert _canonical_low_byte_parent("al") == "eax"
    assert _canonical_low_byte_parent("cl") == "ecx"
    assert _canonical_low_byte_parent("dl") == "edx"
    assert _canonical_low_byte_parent("bl") == "ebx"
    assert _canonical_low_byte_parent("ah") is None


def test_setcc_equality_rows_are_route_evidence_not_byte_delivery():
    assert _native_equality_selector_is_materializable("jcc")
    assert not _native_equality_selector_is_materializable("setcc")


def test_setcc_equality_candidate_preserves_native_target_until_live_validation():
    row = _NativeEqualityRow(
        "ebx",
        0x304E8694,
        0x40B334,
        0x40B32C,
        0x40B334,
        3,
        5,
        0x40B340,
        0x40B342,
        "setcc",
    )

    candidate = _static_equality_route_candidate(
        row,
        _PatchPlan(
            0x40B340,
            0x40B32C,
            0x40B334,
            b"\xe9\x09\x00\x00\x00",
            0x40B342,
            (0x40B334,),
            (0x40B334,),
            target_eas=(0x40B342,),
        ),
        state_var_reg=20,
        context_mregs={36: 0xFDEE1C81},
    )

    assert candidate is not None
    assert candidate.resolver_kind == "static_equality_candidate"
    assert candidate.selector_state_constant == 0x304E8694
    assert candidate.selector_state_var_reg == 20
    assert candidate.source_jmp_ea == 0x40B340
    assert candidate.source_block_ea == 0x40B32C
    assert candidate.target_eas == (0x40B342,)
    assert candidate.materialized_region_end_ea == 0x40B342
    assert _static_equality_candidate_target(
        candidate,
        20,
        live_target_block=203,
        dispatcher_blocks=frozenset({124, 129}),
        dispatch_anchor_eas=frozenset({0x40A5F0}),
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) == (
        0x304E8694,
        0x40B342,
    )
    assert _static_equality_candidate_target(
        candidate,
        21,
        live_target_block=203,
        dispatcher_blocks=frozenset({124, 129}),
        dispatch_anchor_eas=frozenset({0x40A5F0}),
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) is None
    assert _static_equality_candidate_target(
        candidate,
        20,
        live_target_block=124,
        dispatcher_blocks=frozenset({124, 129}),
        dispatch_anchor_eas=frozenset({0x40A5F0}),
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) is None
    dispatcher_candidate = candidate.__class__(
        source_jmp_ea=candidate.source_jmp_ea,
        source_block_ea=candidate.source_block_ea,
        materialized_anchor_eas=(),
        target_eas=(0x40A5F0,),
        selector_state_constant=0x13B0D3B2,
        selector_state_var_reg=20,
        resolver_kind="static_equality_candidate",
    )
    assert _static_equality_candidate_target(
        dispatcher_candidate,
        20,
        live_target_block=203,
        dispatcher_blocks=frozenset({124, 129}),
        dispatch_anchor_eas=frozenset(),
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) is None
    # Candidate evidence owns the native blocks but is not a logical route
    # until CALLS maps the target EA to exactly one live microcode handler.
    assert _exact_equality_native_target((candidate,), 0x304E8694) is None


def test_setcc_equality_candidate_abstains_without_discriminating_targets():
    row = _NativeEqualityRow(
        "ebx",
        0x304E8694,
        0x40B334,
        0x40B32C,
        0x40B334,
        3,
        5,
        0x40B340,
        0x40B342,
        "setcc",
    )

    assert _static_equality_route_candidate(
        row,
        _PatchPlan(
            0x40B340,
            0x40B32C,
            0x40B334,
            b"",
            0x40B342,
            (),
            (),
            target_eas=(0x40B342, 0x40A5F0),
        ),
        state_var_reg=20,
        context_mregs={},
    ) is None


def test_setcc_equality_candidate_uses_replay_proven_post_terminal_match():
    row = _NativeEqualityRow(
        "ebx",
        0x13B0D3B2,
        0x40AE28,
        0x40AE26,
        0x40AE2E,
        3,
        4,
        0x40AE3C,
        0x40AE3E,
        "setcc",
    )
    plan = _PatchPlan(
        0x40AE3C,
        0x40AE26,
        0x40AE28,
        b"\xe9\xc3\xf7\xff\xff",
        0x40AE3E,
        (0x40AE28,),
        (0x40AE28,),
        target_eas=(0x40A5F0,),
    )

    candidate = _static_equality_route_candidate(
        row,
        plan,
        state_var_reg=20,
        context_mregs={36: 0xFDEE1C81},
        replay_match_target_ea=0x40AE3E,
        replay_nonmatch_target_ea=0x40A5F0,
    )

    assert candidate is not None
    assert candidate.selector_state_constant == 0x13B0D3B2
    assert candidate.target_eas == (0x40AE3E,)
    assert candidate.materialized_region_end_ea == 0x40AE3E


def test_setcc_equality_candidate_rejects_unproven_post_terminal_match():
    row = _NativeEqualityRow(
        "ebx",
        0x13B0D3B2,
        0x40AE28,
        0x40AE26,
        0x40AE2E,
        3,
        4,
        0x40AE3C,
        0x40AE3E,
        "setcc",
    )
    plan = _PatchPlan(
        0x40AE3C,
        0x40AE26,
        0x40AE28,
        b"",
        0x40AE3E,
        (),
        (),
        target_eas=(0x40A5F0,),
    )

    assert (
        _static_equality_route_candidate(
            row,
            plan,
            state_var_reg=20,
            context_mregs={},
            replay_match_target_ea=0x40AE40,
            replay_nonmatch_target_ea=0x40A5F0,
        )
        is None
    )
    assert (
        _static_equality_route_candidate(
            row,
            plan,
            state_var_reg=20,
            context_mregs={},
            replay_match_target_ea=0x40AE3E,
            replay_nonmatch_target_ea=0x40A600,
        )
        is None
    )


def test_setcc_equality_delivery_requires_match_handler_and_nonmatch_fallback():
    row = _NativeEqualityRow(
        "ebx",
        0x304E8694,
        0x40B334,
        0x40B32C,
        0x40B334,
        3,
        5,
        0x40B340,
        0x40B342,
        "setcc",
    )

    assert _setcc_equality_delivery_targets(
        row,
        match_target_ea=0x40B342,
        nonmatch_target_ea=0x40A5F0,
        proven_match_target_ea=0x40B342,
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) == (0x40A5F0, 0x40B342)
    assert _setcc_equality_delivery_targets(
        row,
        match_target_ea=0x40A5F0,
        nonmatch_target_ea=0x40B342,
        proven_match_target_ea=0x40A5F0,
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) is None
    assert _setcc_equality_delivery_targets(
        row,
        match_target_ea=0x40B342,
        nonmatch_target_ea=0x40B344,
        proven_match_target_ea=0x40B342,
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) is None
    assert _setcc_equality_delivery_targets(
        row,
        match_target_ea=0x40B342,
        nonmatch_target_ea=0x40A5F0,
        proven_match_target_ea=0x40B344,
        dispatcher_fallback_eas=frozenset({0x40A5F0}),
    ) is None


def test_encode_direct_jump_preserves_short_site_or_abstains():
    assert _encode_direct_jump(0x1000, 2, 0x1070) == b"\xEB\x6E"
    assert _encode_direct_jump(0x1000, 2, 0x2000) is None
    assert _encode_direct_jump(0x1000, 5, 0x2000) == b"\xE9\xFB\x0F\x00\x00"


def test_encode_x86_register_immediate32_is_register_generic_and_bounded():
    assert _encode_x86_register_immediate32(3, 0xA0716E5B) == b"\xBB\x5B\x6E\x71\xA0"
    assert _encode_x86_register_immediate32(0, 0x12345678) == b"\xB8\x78\x56\x34\x12"
    assert _encode_x86_register_immediate32(8, 1) is None


def test_entry_bridge_selects_only_jump_before_first_routing_node() -> None:
    assert computed_goto_resolver._select_prologue_entry_jump(
        ((0x40A5C8, 2), (0x40A5D6, 5)),
        routing_start_ea=0x40A5CA,
    ) == (0x40A5C8, 2)
    assert computed_goto_resolver._select_prologue_entry_jump(
        ((0x40A5C8, 2), (0x40A5C9, 2)),
        routing_start_ea=0x40A5CA,
    ) is None


def test_entry_bridge_waits_for_one_residual_route_round() -> None:
    assert not computed_goto_resolver._entry_bridge_ready(
        entry_bridge_materialized=False,
        state_route_rounds=0,
    )
    assert computed_goto_resolver._entry_bridge_ready(
        entry_bridge_materialized=False,
        state_route_rounds=1,
    )
    assert not computed_goto_resolver._entry_bridge_ready(
        entry_bridge_materialized=True,
        state_route_rounds=1,
    )


def test_exact_equality_native_target_selects_matching_arm_and_abstains_on_conflict():
    state = 0xEC71CA67
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B9A4,
        source_block_ea=0x40B98C,
        materialized_anchor_eas=(0x40B998, 0x40B99E),
        target_eas=(0x40B9A6, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40B9A6,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        selector_state_on_left=True,
        resolver_kind="static_equality_fixpoint",
    )

    residual_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C6F7,
        source_block_ea=0x40C6F7,
        materialized_anchor_eas=(0x40C6F7,),
        target_eas=(0x40AEE6,),
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )
    assert _exact_equality_native_target((transfer, residual_route), state) == 0x40B9A6
    conflicting = MaterializedIndirectTransfer(
        source_jmp_ea=0x5000,
        source_block_ea=0x4FF0,
        materialized_anchor_eas=(),
        target_eas=(0x6000,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )
    assert _exact_equality_native_target((transfer, conflicting), state) is None

    route_evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C629,
        source_block_ea=0x40C623,
        materialized_anchor_eas=(),
        target_eas=(0x40B9A6,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )
    assert _exact_equality_native_target((route_evidence,), state) == 0x40B9A6


def test_exact_equality_native_target_prefers_static_fixpoint_over_condition_chain_continuation():
    state = 0x19A7218A
    static_fixpoint = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5DF, 0x40A5E5),
        target_eas=(0x40A5F0, 0x40C898),
        condition_code=4,
        true_target_ea=0x40C898,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        selector_state_on_left=True,
        resolver_kind="static_fixpoint",
    )
    condition_chain_continuation = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5CA,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(),
        target_eas=(0x40A5D0,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )

    assert _exact_equality_native_target(
        (static_fixpoint, condition_chain_continuation),
        state,
    ) == 0x40C898


def test_validated_exact_route_suppresses_duplicate_condition_chain_glue_evidence():
    state = 0x304E8694
    validated = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B340,
        source_block_ea=0x40B32C,
        materialized_anchor_eas=(),
        target_eas=(0x40B342,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )
    candidate = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B340,
        source_block_ea=0x40B32C,
        materialized_anchor_eas=(),
        target_eas=(0x40B342,),
        selector_state_constant=state,
        resolver_kind="static_equality_candidate",
    )

    assert _states_with_validated_exact_equality_routes(
        (candidate, validated),
    ) == frozenset({state})


def test_materialized_state_replay_prefers_exact_equality_handler_over_coarse_range():
    incoming_state = 0xEC71CA67
    next_state = 0xA5A94B86
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            111: _block(111, 0x40B36B),
            163: _block(163, 0x40BCA3),
            216: _block(216, 0x40C4F6),
        },
        entry_serial=111,
        func_ea=0x40A560,
    )
    transfers = (
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40B36B,
            source_block_ea=0x40B36B,
            materialized_anchor_eas=(),
            target_eas=(0x40B36B,),
            selector_state_constant=incoming_state,
            resolver_kind="condition_chain_handler_evidence",
        ),
        MaterializedIndirectTransfer(
            source_jmp_ea=0x40C4F4,
            source_block_ea=0x40C4DC,
            materialized_anchor_eas=(0x40C4E8, 0x40C4EE),
            target_eas=(0x40C4F6, 0x40A5F0),
            condition_code=4,
            true_target_ea=0x40C4F6,
            false_target_ea=0x40A5F0,
            selector_state_var_reg=20,
            selector_compare_constant=next_state,
            resolver_kind="static_equality_fixpoint",
        ),
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({111, 163, 216}),
        transfers=transfers,
        handler_states={111: (incoming_state,)},
        handler_targets={incoming_state: 111},
        handler_target_resolver=lambda _state: 163,
        handler_state_resolver=lambda *_args, **_kwargs: _ConcreteHandlerStateWrite(
            next_state, 0x40B36B
        ),
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            111,
            next_state,
            216,
            source_handler_serial=111,
            handler_exit_proven=True,
        ),
    )


def test_validated_exact_equality_handler_seeds_outgoing_state_replay():
    incoming_state = 0xA5540595
    next_state = 0xBCDE2EFB
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            186: _block(186, 0x40C069),
            216: _block(216, 0x40C4F6),
        },
        entry_serial=216,
        func_ea=0x40A560,
    )
    incoming_route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C4F4,
        source_block_ea=0x40C4DC,
        materialized_anchor_eas=(),
        target_eas=(0x40C4F6,),
        selector_state_constant=incoming_state,
        resolver_kind="static_equality_route",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({186}),
        transfers=(incoming_route,),
        handler_targets={next_state: 186},
        handler_state_resolver=lambda *_args, **_kwargs: _ConcreteHandlerStateWrite(
            next_state, 0x40C525
        ),
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            216,
            next_state,
            186,
            source_handler_serial=216,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_anchor_canonicalizes_coarse_route_to_live_exact_handler():
    state = 0x2100AFDD
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            82: _block(82, 0x40C6DA),
            59: _block(59, 0x40ABEE),
            226: _block(226, 0x40AF00),
        },
        entry_serial=82,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AEFE,
        source_block_ea=0x40AEE6,
        materialized_anchor_eas=(0x40AEF2, 0x40AEF8),
        target_eas=(0x40AF00, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40AF00,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_equality_fixpoint",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(82, state, state_var_reg=20),),
        out_reg_maps={82: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({59, 226}),
        transfers=(transfer,),
        route_resolver=lambda *_args, **_kwargs: 0x40ABEE,
    )

    assert routes == (MaterializedStateRoute(82, state, 226),)


def test_materialized_state_anchor_prefers_imported_replacement_over_native_handler():
    state = 0x2100AFDD
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            82: _block(82, 0x40C6DA),
            226: _block(226, 0x40AF00),
            281: _block(281, 0x40A560),
        },
        entry_serial=82,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AEFE,
        source_block_ea=0x40AEE6,
        materialized_anchor_eas=(0x40AEF2, 0x40AEF8),
        target_eas=(0x40AF00, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40AF00,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_equality_fixpoint",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(82, state, state_var_reg=20),),
        out_reg_maps={82: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({226, 281}),
        transfers=(transfer,),
        handler_targets={state: 281},
        replacement_handler_serials=frozenset({281}),
    )

    assert routes == (MaterializedStateRoute(82, state, 281),)


def test_materialized_state_anchor_prefers_exact_live_handler_over_bst_router():
    state = 0xA5540595
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            146: _block(146, 0x40B668),
            175: _block(175, 0x40BC50),
            204: _block(204, 0x40C4F6),
        },
        entry_serial=146,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B668,
        source_block_ea=0x40B668,
        materialized_anchor_eas=(0x40B668,),
        target_eas=(0x40C4F6,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(146, state, state_var_reg=20),),
        out_reg_maps={146: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({175, 204}),
        dispatcher_block_serials=frozenset({8, 175}),
        transfers=(transfer,),
        handler_targets={state: 204},
        exact_handler_override_serials=frozenset({204}),
    )

    assert routes == (MaterializedStateRoute(146, state, 204),)


def test_live_residual_state_edge_survives_when_state_write_was_folded_away():
    state = 0xA5540595
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            146: _block(146, 0x40B668, succs=(243,)),
            147: _block(147, 0x40B685, (0x40B668,), succs=(243,)),
            175: _block(175, 0x40BC21),
            243: _block(243, 0x40C4F6, preds=(146,)),
        },
        entry_serial=146,
        func_ea=0x40A560,
    )
    evidence = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B668,
        source_block_ea=0x40B668,
        materialized_anchor_eas=(),
        target_eas=(0x40C4F6,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route_evidence",
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B685,
        source_block_ea=0x40B685,
        materialized_anchor_eas=(0x40B685,),
        target_eas=(0x40C4F6,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({175, 243}),
        dispatcher_block_serials=frozenset({8, 175}),
        transfers=(evidence, transfer),
        handler_targets={state: 243},
        exact_handler_override_serials=frozenset({243}),
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            146,
            state,
            243,
            proof_kind="exact_live_state_edge",
        ),
    )


def test_materialized_state_anchor_uses_validated_exact_route_when_corridor_abstains():
    state = 0x304E8694
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            203: _block(203, 0x40B342),
            234: _block(234, 0x40C842),
        },
        entry_serial=234,
        func_ea=0x40A560,
    )
    validated = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B340,
        source_block_ea=0x40B32C,
        materialized_anchor_eas=(),
        target_eas=(0x40B342,),
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(234, state, state_var_reg=20, instruction_ea=0x40C842),
        ),
        out_reg_maps={234: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({203}),
        transfers=(validated,),
        route_resolver=lambda *_args, **_kwargs: None,
    )

    assert routes == (MaterializedStateRoute(234, state, 203),)


def test_materialized_state_anchor_keeps_exact_terminal_endpoint():
    state = 0x19A7218A
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            198: _block(198, 0x40C309),
            239: _block(239, 0x40A5D0),
            300: BlockSnapshot(
                serial=300,
                block_type=6,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x40C898,
                insn_snapshots=(),
                kind=BlockKind.EXTERNAL,
            ),
        },
        entry_serial=198,
        func_ea=0x40A560,
    )
    static_fixpoint = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5E3,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(0x40A5DF, 0x40A5E5),
        target_eas=(0x40A5F0, 0x40C898),
        condition_code=4,
        true_target_ea=0x40C898,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        selector_state_on_left=True,
        resolver_kind="static_fixpoint",
    )
    condition_chain_continuation = MaterializedIndirectTransfer(
        source_jmp_ea=0x40A5CA,
        source_block_ea=0x40A5CA,
        materialized_anchor_eas=(),
        target_eas=(0x40A5D0,),
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(198, state, state_var_reg=20, instruction_ea=0x40C328),
        ),
        out_reg_maps={198: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({239}),
        transfers=(static_fixpoint, condition_chain_continuation),
        handler_targets={state: 239},
        route_resolver=lambda *_args, **_kwargs: 0x40A5D0,
        handler_state_resolver=lambda *_args, **_kwargs: None,
        terminal_target_resolver=lambda _target_ea: True,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            198,
            state,
            300,
            proof_kind="terminal_state_route",
        ),
    )


def test_equality_fragment_claims_detached_source_and_handler_before_analysis():
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AEFE,
        source_block_ea=0x40AEE6,
        materialized_anchor_eas=(0x40AEF2, 0x40AEF8),
        target_eas=(0x40AF00, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40AF00,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=0x2100AFDD,
        selector_state_on_left=True,
        resolver_kind="static_equality_fixpoint",
        materialized_region_end_ea=0x40AF00,
    )

    unrelated = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C4F4,
        source_block_ea=0x40C4DC,
        materialized_anchor_eas=(),
        target_eas=(0x40C4F6, 0x40A5F0),
        resolver_kind="static_equality_fixpoint",
    )
    assert _equality_transfers_activated_by_targets(
        (transfer, unrelated),
        (0x40AEE6,),
    ) == (transfer,)

    assert _equality_fragment_owned_ranges(
        (transfer,),
        block_end=lambda ea: ea + 0x20,
    ) == (
        (0x40A5F0, 0x40A610),
        (0x40AEE6, 0x40AF00),
        (0x40AF00, 0x40AF20),
    )


def _block(
    serial: int,
    start_ea: int,
    insn_eas: tuple[int, ...] = (),
    *,
    preds: tuple[int, ...] = (),
    succs: tuple[int, ...] = (),
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=start_ea,
        insn_snapshots=tuple(
            InsnSnapshot(opcode=0, ea=ea, operands=()) for ea in insn_eas
        ),
    )


def test_conditional_handler_routes_bind_imported_target_serial() -> None:
    predicate_ea = 0xF1C00400
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    graph = FlowGraph(
        blocks={
            124: _block(124, 0x40B3F3),
            300: _block(300, 0x40A560),
            304: _block(304, 0x40A560, (predicate_ea,)),
        },
        entry_serial=304,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40A560,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40B3F3, 0x40C1A0),
        condition_code=5,
        true_target_ea=0x40B3F3,
        false_target_ea=0x40C1A0,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert _build_conditional_handler_state_routes(
        graph,
        (transfer,),
        target_serial_resolver=lambda ea: 300 if ea == 0x40C1A0 else None,
    ) == (
        MaterializedStateRoute(304, true_state, 124, proof_kind="conditional_arm"),
        MaterializedStateRoute(304, false_state, 300, proof_kind="conditional_arm"),
    )


def test_conditional_handler_routes_bind_both_arms_from_exact_state_map() -> None:
    predicate_ea = 0xF1C01534
    true_state = 0x7F9D6412
    false_state = 0xA7933EA0
    graph = FlowGraph(
        blocks={
            124: _block(124, 0x40A560),
            300: _block(300, 0x40A560),
            304: _block(304, 0x40A560, (predicate_ea,)),
        },
        entry_serial=304,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40A560,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40B3F3, 0x40C1A0),
        condition_code=5,
        true_target_ea=0x40B3F3,
        false_target_ea=0x40C1A0,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert _build_conditional_handler_state_routes(
        graph,
        (transfer,),
        exact_handler_by_state={true_state: 124, false_state: 300},
    ) == (
        MaterializedStateRoute(304, true_state, 124, proof_kind="conditional_arm"),
        MaterializedStateRoute(304, false_state, 300, proof_kind="conditional_arm"),
    )


def test_conditional_handler_routes_prefer_imported_target_over_native_copy() -> None:
    predicate_ea = 0x40C5D1
    true_state = 0x78BAC34B
    false_state = 0x1F0B7687
    graph = FlowGraph(
        blocks={
            21: _block(21, 0x40A7AE),
            98: _block(98, 0x40B100),
            247: BlockSnapshot(
                serial=247,
                block_type=0,
                succs=(248, 415),
                preds=(246,),
                flags=0,
                start_ea=0x40C586,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0,
                        ea=predicate_ea,
                        operands=(),
                        kind=InsnKind.EQUALITY_JUMP,
                        is_conditional_jump=True,
                    ),
                ),
            ),
            307: _block(307, 0x40A560),
            308: _block(308, 0x40A560, (predicate_ea,)),
        },
        entry_serial=247,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40C5BD,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40B100, 0x40A7AE),
        condition_code=5,
        true_target_ea=0x40B100,
        false_target_ea=0x40A7AE,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert _build_conditional_handler_state_routes(
        graph,
        (transfer,),
        target_serial_resolver=lambda ea: 307 if ea == 0x40A7AE else None,
    ) == (
        MaterializedStateRoute(247, false_state, 307, proof_kind="conditional_arm"),
        MaterializedStateRoute(247, true_state, 98, proof_kind="conditional_arm"),
    )


def test_conditional_handler_routes_bind_imported_arm_successors() -> None:
    predicate_ea = 0xF1C00400
    true_state = 0xB34CE2DF
    false_state = 0x82F1899D
    graph = FlowGraph(
        blocks={
            156: _block(156, 0x40BC50),
            179: _block(179, 0x40BCBA),
            305: _block(305, 0x40A560, succs=(306, 308)),
            306: _block(306, 0x40A560, preds=(305,), succs=(307,)),
            307: _block(307, 0x40A560, preds=(306, 308)),
            308: _block(308, 0x40A560, preds=(305,), succs=(307,)),
        },
        entry_serial=305,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=predicate_ea,
        source_block_ea=0x40A560,
        materialized_anchor_eas=(predicate_ea,),
        target_eas=(0x40BCBA, 0x40BC50),
        condition_code=5,
        true_target_ea=0x40BCBA,
        false_target_ea=0x40BC50,
        resolver_kind="conditional_handler_bridge",
        predicate_true_state=true_state,
        predicate_false_state=false_state,
        predicate_true_is_taken=True,
        predicate_preserve_live=True,
    )

    assert _build_conditional_handler_state_routes(
        graph,
        (transfer,),
        arm_source_serial_resolver=lambda _transfer: (306, 308),
    ) == (
        MaterializedStateRoute(306, true_state, 179, proof_kind="conditional_arm"),
        MaterializedStateRoute(308, false_state, 156, proof_kind="conditional_arm"),
    )


def test_validated_setcc_target_survives_live_condition_chain_snapshot_and_lowering(
    monkeypatch,
):
    state = 0x304E8694
    unrelated_state = 0xA7933EA0
    graph = FlowGraph(
        blocks={
            124: _block(124, 0x40A5F0),
            129: _block(129, 0x40B32C),
            130: _block(130, 0x40C180),
            203: _block(203, 0x40B33A, (0x40B34E,)),
            204: _block(204, 0x40C1A0),
            234: _block(234, 0x40C842),
        },
        entry_serial=234,
        func_ea=0x40A560,
    )
    validated = MaterializedIndirectTransfer(
        source_jmp_ea=0x40B340,
        source_block_ea=0x40B32C,
        materialized_anchor_eas=(),
        target_eas=(0x40B342,),
        next_target_ea=0x40B354,
        selector_state_var_reg=20,
        selector_state_constant=state,
        resolver_kind="static_equality_route",
    )

    class _Row:
        def __init__(self, state_const: int, target_block: int, compare_block: int):
            self.state_const = state_const
            self.target_block = target_block
            self.compare_block = compare_block

    class _DispatchMap:
        router_kind = RouterKind.CONDITION_CHAIN
        dispatcher_entry_block = 124
        rows = (
            _Row(state, 203, 129),
            _Row(unrelated_state, 204, 130),
        )

    class _Recovery:
        dispatch_map = _DispatchMap()
        state_var_reg = 20

    from d810.analyses.control_flow import dispatcher_recovery
    translator_module = ModuleType("d810.hexrays.mutation.ir_translator")
    translator_module.lift = lambda _mba: graph
    monkeypatch.setitem(
        sys.modules,
        "d810.hexrays.mutation.ir_translator",
        translator_module,
    )
    monkeypatch.setattr(
        dispatcher_recovery,
        "recover_dispatcher",
        lambda _graph, _hints, *, materialized_indirect_transfers: _Recovery(),
    )

    snapshot_evidence = _recover_condition_chain_handler_transfers_from_mba(
        (validated,),
        object(),
    )

    # The live router reports a glue block for the same state, but the already
    # validated native body is authoritative.  The unrelated row proves the
    # collector ran instead of merely returning no evidence.
    live_rows = tuple(
        transfer
        for transfer in snapshot_evidence
        if transfer.resolver_kind == "live_state_dispatcher_row_evidence"
    )
    assert tuple(
        transfer.selector_state_constant for transfer in live_rows
    ) == (state, unrelated_state)
    condition_rows = tuple(
        transfer
        for transfer in snapshot_evidence
        if transfer.resolver_kind == "condition_chain_handler_evidence"
    )
    assert tuple(
        transfer.selector_state_constant for transfer in condition_rows
    ) == (unrelated_state,)
    assert condition_rows[0].target_eas == (0x40C1A0,)

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(234, state, state_var_reg=20, instruction_ea=0x40C842),
        ),
        out_reg_maps={234: {20: state}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({204}),
        dispatcher_block_serials=frozenset({124, 129}),
        handler_targets={state: 129},
        state_register_name="ebx",
        handler_state_resolver=lambda *_args, **_kwargs: None,
        transfers=(validated, *snapshot_evidence),
        route_resolver=lambda *_args, **_kwargs: None,
    )

    assert routes == (MaterializedStateRoute(234, state, 203),)


def test_materialized_state_routes_use_latest_matching_transfer_and_full_reg_snapshot():
    state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            71: _block(71, 0x7100, (0x7110,)),
            124: _block(124, 0x4000),
            203: _block(203, 0x9000, (0x9004,)),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )
    transfers = (
        MaterializedIndirectTransfer(
            0x7105,
            0x4100,
            (0x7100,),
            (0x9000,),
            context_register_values=((28, 0xFDEE1C81),),
            source_register_values=((12, 0x48B7FC),),
            corridor_register_snapshots=((0x4200, ((16, 0x48B7FC),)),),
        ),
        MaterializedIndirectTransfer(
            0x7110,
            0x5000,
            (0x7110,),
            (0x9000,),
            context_register_values=((28, 0xFDEE1C81),),
            source_register_values=((12, 0x48B7FC),),
        ),
    )
    calls = []

    def route(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        calls.append(
            (
                start_ea,
                dict(initial_mregs),
                handler_eas,
                register_snapshots_by_ea,
                dispatch_anchor_eas,
            )
        )
        return 0x9000

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {4: 0x1234, 20: 0}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({203}),
        transfers=transfers,
        route_resolver=route,
    )

    assert routes == (MaterializedStateRoute(71, state, 203),)
    assert calls == [
        (
            0x5000,
            {4: 0x1234, 20: state, 28: 0xFDEE1C81},
            frozenset({0x9000, 0x9004}),
            {
                0x4100: {12: 0x48B7FC},
                0x4200: {16: 0x48B7FC},
                0x5000: {12: 0x48B7FC},
            },
            frozenset({0x7100, 0x7110}),
        )
    ]


def test_materialized_state_routes_replay_handler_when_microcode_lost_state_write():
    incoming_state = 0xA5540595
    next_state = 0xBCDE2EFB
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            183: _block(183, 0x3000),
            213: _block(213, 0x40C4F6),
        },
        entry_serial=213,
        func_ea=0x40A560,
    )
    calls = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        calls.append((start_ea, dict(initial_mregs), state_register_name))
        return _ConcreteHandlerStateWrite(next_state, 0x4000)

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({183}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40A5F0,
                source_block_ea=0x40A5F0,
                materialized_anchor_eas=(0x40A5F0,),
                target_eas=(0x40C4F6,),
                selector_state_constant=incoming_state,
                resolver_kind="condition_chain_handler_evidence",
            ),
        ),
        handler_targets={next_state: 183},
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            213,
            next_state,
            183,
            source_handler_serial=213,
            handler_exit_proven=True,
        ),
    )
    assert calls == [
        (
            0x40C4F6,
            {20: incoming_state},
            "ebx",
        )
    ]


def test_materialized_state_routes_replay_imported_handler_at_native_entry_alias():
    incoming_state = 0x1F0B7687
    next_state = 0xB34CE2DF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            179: _block(179, 0x40BCBA),
            304: _block(304, 0x40A560),
        },
        entry_serial=304,
        func_ea=0x40A560,
    )
    replay_starts = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        replay_starts.append(start_ea)
        return _ConcreteHandlerStateWrite(next_state, 0x40A7EF)

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({179, 304}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(),
        handler_states={304: (incoming_state,)},
        handler_targets={next_state: 179},
        handler_entry_eas_by_serial={304: 0x40A7AE},
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            304,
            next_state,
            179,
            source_handler_serial=304,
            handler_exit_proven=True,
        ),
    )
    assert replay_starts == [0x40A7AE]


def test_materialized_state_routes_recover_final_state_near_live_handler_tail():
    incoming_state = 0x96B0D1E5
    final_state = 0x7F9D6412
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            116: _block(116, 0x40B3F3),
            207: _block(207, 0x40C3E7),
        },
        entry_serial=207,
        func_ea=0x40A560,
    )
    tail_calls = []

    def replay_unchanged_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        assert start_ea == 0x40C3E7
        return _ConcreteHandlerStateWrite(incoming_state, start_ea)

    def recover_tail_state(block, *, state_var_reg, incoming_state):
        tail_calls.append((block.serial, state_var_reg, incoming_state))
        return final_state

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({116, 207}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(),
        handler_states={207: (incoming_state,)},
        handler_targets={final_state: 116},
        handler_state_resolver=replay_unchanged_state,
        handler_exit_state_resolver=recover_tail_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            207,
            final_state,
            116,
            source_handler_serial=207,
            handler_exit_proven=True,
        ),
    )
    assert tail_calls == [(207, 20, incoming_state)]


def test_materialized_state_routes_prefer_live_tail_over_intermediate_replay():
    incoming_state = 0x96B0D1E5
    intermediate_state = 0xA5A94B86
    final_state = 0x7F9D6412
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            116: _block(116, 0x40B3F3),
            162: _block(162, 0x40BCA3),
            207: _block(207, 0x40C3E7),
        },
        entry_serial=207,
        func_ea=0x40A560,
    )

    def replay_intermediate_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        return _ConcreteHandlerStateWrite(intermediate_state, start_ea)

    def recover_tail_state(block, *, state_var_reg, incoming_state):
        assert block.serial == 207
        return final_state

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({116, 162, 207}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(),
        handler_states={207: (incoming_state,)},
        handler_targets={intermediate_state: 162, final_state: 116},
        handler_state_resolver=replay_intermediate_state,
        handler_exit_state_resolver=recover_tail_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            207,
            final_state,
            116,
            source_handler_serial=207,
            handler_exit_proven=True,
        ),
    )


def test_live_tail_state_preserves_precise_replayed_exit_owner():
    incoming_state = 0x1F0B7687
    final_state = 0xB34CE2DF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A607),
            21: _block(21, 0x40A7AE),
            23: _block(23, 0x40A7E5, (0x40A7EF,)),
            179: _block(179, 0x40BCA3),
        },
        entry_serial=21,
        func_ea=0x40A560,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({21, 179}),
        transfers=(),
        handler_states={21: (incoming_state,)},
        handler_targets={final_state: 179},
        handler_state_resolver=lambda *_args, **_kwargs: (
            _ConcreteHandlerStateWrite(final_state, 0x40A7EF)
        ),
        handler_exit_state_resolver=lambda *_args, **_kwargs: final_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            23,
            final_state,
            179,
            source_handler_serial=21,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_routes_use_live_tail_when_native_replay_raises():
    incoming_state = 0x96B0D1E5
    final_state = 0x7F9D6412
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            116: _block(116, 0x40B3F3),
            207: _block(207, 0x40C3E7),
        },
        entry_serial=207,
        func_ea=0x40A560,
    )

    def replay_detached_native_tail(*_args, **_kwargs):
        raise RuntimeError("native replay cannot enter the detached tail")

    def recover_tail_state(block, *, state_var_reg, incoming_state):
        assert block.serial == 207
        assert state_var_reg == 20
        return final_state

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({116, 207}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40C3D9,
                source_block_ea=0x40C3D9,
                materialized_anchor_eas=(0x40C3D9,),
                target_eas=(0x40C3E7,),
                selector_state_constant=incoming_state,
                resolver_kind="condition_chain_handler_evidence",
            ),
        ),
        handler_targets={final_state: 116},
        handler_state_resolver=replay_detached_native_tail,
        handler_exit_state_resolver=recover_tail_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            207,
            final_state,
            116,
            source_handler_serial=207,
            handler_exit_proven=True,
        ),
    )


def test_unique_handler_evidence_exonerates_dispatcher_labeled_replay_source():
    incoming_state = 0x96B0D1E5
    final_state = 0x7F9D6412
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            116: _block(116, 0x40B3F3),
            207: _block(207, 0x40C3E7),
        },
        entry_serial=207,
        func_ea=0x40A560,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({116}),
        dispatcher_block_serials=frozenset({8, 207}),
        transfers=(
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40C3D9,
                source_block_ea=0x40C3D9,
                materialized_anchor_eas=(0x40C3D9,),
                target_eas=(0x40C3E7,),
                selector_state_constant=incoming_state,
                resolver_kind="condition_chain_handler_evidence",
            ),
        ),
        handler_targets={final_state: 116},
        handler_state_resolver=lambda *_args, **_kwargs: None,
        handler_exit_state_resolver=lambda *_args, **_kwargs: final_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            207,
            final_state,
            116,
            source_handler_serial=207,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_routes_route_replayed_range_state_through_dispatcher():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )
    dispatch_calls = []
    interval_calls = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        assert start_ea == 0x40AD96
        assert initial_mregs[20] == incoming_state
        return _ConcreteHandlerStateWrite(next_state, 0x40A5F0)

    def route_dispatcher(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        dispatch_calls.append((start_ea, dict(initial_mregs), handler_eas))
        return 0x40BCF9

    def route_interval(state):
        interval_calls.append(state)
        return 154

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154}),
        dispatcher_block_serials=frozenset({8}),
        transfers=(),
        route_resolver=route_dispatcher,
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=route_interval,
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )
    assert interval_calls == [next_state]
    assert dispatch_calls == []


def test_materialized_state_routes_continue_from_internal_router_block():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            9: _block(9, 0x40B6C0),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        return _ConcreteHandlerStateWrite(next_state, 0x40A5F0)

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154}),
        dispatcher_block_serials=frozenset({8, 9}),
        transfers=(
            MaterializedIndirectTransfer(
                source_jmp_ea=0x40B6C5,
                source_block_ea=0x40B6C0,
                materialized_anchor_eas=(0x40B6C0,),
                target_eas=(0x40BCF9,),
                selector_state_constant=next_state,
                resolver_kind="static_equality_route",
            ),
        ),
        route_resolver=lambda *_args, **_kwargs: None,
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=lambda _state: 9,
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )


def test_materialized_state_routes_replay_from_microcode_selected_router_anchor():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            145: _block(145, 0x40B940),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )
    dispatch_starts = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        return _ConcreteHandlerStateWrite(next_state, 0x40A5F0)

    def route_dispatcher(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        dispatch_starts.append(start_ea)
        return 0x40BCF9 if start_ea == 0x40B940 else None

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154}),
        dispatcher_block_serials=frozenset({8, 145}),
        transfers=(),
        route_resolver=route_dispatcher,
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=lambda _state: 145,
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )
    assert dispatch_starts == [0x40B940]


def test_materialized_state_routes_try_dispatch_entry_router_successors():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0, succs=(9, 131)),
            9: _block(9, 0x40A607),
            131: _block(131, 0x40B6C0),
            145: _block(145, 0x40B940),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )
    dispatch_starts = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        return _ConcreteHandlerStateWrite(next_state, 0x40A5F0)

    def route_dispatcher(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        dispatch_starts.append(start_ea)
        return 0x40BCF9 if start_ea == 0x40B6C0 else None

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154}),
        dispatcher_block_serials=frozenset({8, 9, 131, 145}),
        transfers=(),
        route_resolver=route_dispatcher,
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=lambda _state: 145,
        handler_state_resolver=replay_handler_state,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            77,
            next_state,
            154,
            source_handler_serial=77,
            handler_exit_proven=True,
        ),
    )
    assert dispatch_starts == [0x40B940, 0x40A607, 0x40B6C0]


def test_materialized_state_routes_abstain_when_router_successors_disagree():
    incoming_state = 0x7C4FB03D
    next_state = 0xF6A636EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0, succs=(9, 131)),
            9: _block(9, 0x40A607),
            131: _block(131, 0x40B6C0),
            145: _block(145, 0x40B940),
            77: _block(77, 0x40AD96),
            154: _block(154, 0x40BCF9),
            155: _block(155, 0x40BD10),
        },
        entry_serial=77,
        func_ea=0x40A560,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 154, 155}),
        dispatcher_block_serials=frozenset({8, 9, 131, 145}),
        transfers=(),
        route_resolver=lambda start_ea, **_kwargs: {
            0x40A607: 0x40BCF9,
            0x40B6C0: 0x40BD10,
        }.get(start_ea),
        handler_states={77: (incoming_state,)},
        handler_targets={incoming_state: 77},
        handler_target_resolver=lambda _state: 145,
        handler_state_resolver=lambda *_args, **_kwargs: (
            _ConcreteHandlerStateWrite(next_state, 0x40A5F0)
        ),
        state_register_name="ebx",
    )

    assert routes == ()


def test_materialized_state_routes_reject_dispatcher_node_as_handler_target():
    state = 0xE9795EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            67: _block(67, 0x40ACE7),
            71: _block(71, 0x7100),
            187: _block(187, 0x40C0C8),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )

    def route_to_dispatcher_node(*_args, **_kwargs):
        return 0x40C0C8

    assert _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({67, 187}),
        dispatcher_block_serials=frozenset({8, 187}),
        transfers=(),
        route_resolver=route_to_dispatcher_node,
    ) == ()


def test_materialized_state_routes_keep_exact_handler_over_router_overlap():
    state = 0xF7088159
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            71: _block(71, 0x7100),
            164: _block(164, 0x40BD0D),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )

    assert _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({164}),
        authoritative_handler_serials=frozenset({164}),
        dispatcher_block_serials=frozenset({8, 164}),
        transfers=(),
        route_resolver=lambda *_args, **_kwargs: 0x40BD0D,
    ) == (MaterializedStateRoute(71, state, 164),)


def test_materialized_state_routes_keep_resolver_proven_handler_over_router_overlap():
    state = 0xF7088159
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x40A5F0),
            71: _block(71, 0x7100),
            164: _block(164, 0x40BD0D),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )
    transfer = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BCF4,
        source_block_ea=0x40BCF9,
        materialized_anchor_eas=(0x40BCF9,),
        target_eas=(0x40BD0D,),
        selector_state_constant=state,
        resolver_kind="condition_chain_handler_evidence",
    )

    assert _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset(),
        dispatcher_block_serials=frozenset({8, 164}),
        transfers=(transfer,),
        route_resolver=lambda *_args, **_kwargs: 0x40BD0D,
    ) == (MaterializedStateRoute(71, state, 164),)


def test_materialized_state_routes_limit_corridor_to_state_expected_handler():
    state = 0xE9795EF
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            67: _block(67, 0x40ACE7),
            71: _block(71, 0x7100),
            187: _block(187, 0x40C0C8),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )
    accepted_handler_sets = []

    def route_to_expected_handler(
        _start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        accepted_handler_sets.append(handler_eas)
        return 0x40ACE7

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(StateWriteAnchor(71, state, state_var_reg=20),),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({67, 187}),
        handler_targets={state: 67},
        transfers=(),
        route_resolver=route_to_expected_handler,
    )

    assert routes == (MaterializedStateRoute(71, state, 67),)
    assert accepted_handler_sets == [frozenset({0x40ACE7})]


def test_handler_replay_follows_entry_dispatch_and_keys_exact_exit_block():
    incoming_state = 0xCB1F8618
    next_state = 0x7C4FB03D
    graph = FlowGraph(
        blocks={
            8: _block(8, 0x4000),
            26: _block(26, 0x40B810, (0x40B879,)),
            77: _block(77, 0x40ADE6),
            143: _block(143, 0x40B804, (0x40B810,)),
        },
        entry_serial=143,
        func_ea=0x40A560,
    )
    replay_calls = []

    def replay_handler_state(
        start_ea,
        *,
        initial_mregs,
        state_register_name,
        dispatch_anchor_eas,
    ):
        replay_calls.append(start_ea)
        if start_ea == 0x40B804:
            return _ConcreteHandlerStateWrite(incoming_state, 0x40B80E)
        return _ConcreteHandlerStateWrite(next_state, 0x40B879)

    def resolve_handler_body(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
        return_first_indirect_target,
    ):
        assert start_ea == 0x40B804
        assert handler_eas == frozenset({0x40B804, 0x40B810})
        assert not return_first_indirect_target
        return 0x40B810

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(),
        out_reg_maps={},
        dispatcher_entry_serial=8,
        state_var_reg=20,
        handler_serials=frozenset({77, 143}),
        transfers=(),
        handler_states={143: (incoming_state,)},
        handler_targets={next_state: 77},
        handler_state_resolver=replay_handler_state,
        handler_entry_resolver=resolve_handler_body,
        state_register_name="ebx",
    )

    assert routes == (
        MaterializedStateRoute(
            26,
            next_state,
            77,
            source_handler_serial=143,
            handler_exit_proven=True,
        ),
    )
    assert replay_calls == [0x40B804, 0x40B810]


def test_concrete_handler_entry_requires_completed_indirect_dispatch():
    handler_eas = frozenset({0x9000, 0x9004})

    assert not _is_concrete_handler_entry(0x9004, handler_eas, 0)
    assert _is_concrete_handler_entry(0x9004, handler_eas, 1)
    assert not _is_concrete_handler_entry(0x9010, handler_eas, 3)


def test_native_writer_detection_uses_canonical_change_bit():
    class FakeInsn:
        def __init__(self, features):
            self.features = features

        def get_canon_feature(self):
            return self.features

    change_first = 0x2

    assert _insn_writes_first_operand(FakeInsn(0x2), change_first)
    assert _insn_writes_first_operand(FakeInsn(0xA), change_first)
    assert not _insn_writes_first_operand(FakeInsn(0x1), change_first)


def test_concrete_corridor_skips_only_flag_neutral_mov_store():
    assert _is_ignorable_corridor_store("mov")
    assert not _is_ignorable_corridor_store("add")
    assert not _is_ignorable_corridor_store("call")


def test_materialized_dispatch_instruction_accepts_both_branch_arms():
    assert _is_materialized_dispatch_instruction("jge")
    assert _is_materialized_dispatch_instruction("jmp")
    assert not _is_materialized_dispatch_instruction("mov")


def test_corridor_memory_alias_guard_distinguishes_stack_from_nonstack():
    assert _corridor_memory_spaces_may_alias("stack", "stack")
    assert _corridor_memory_spaces_may_alias("unknown", "nonstack")
    assert not _corridor_memory_spaces_may_alias("stack", "nonstack")


def test_materialized_state_routes_fall_back_to_dispatcher_and_abstain_off_handler():
    state = 0xA5A94B86
    graph = FlowGraph(
        blocks={
            71: _block(71, 0x7100),
            124: _block(124, 0x4000),
            203: _block(203, 0x9000),
        },
        entry_serial=71,
        func_ea=0x40A560,
    )
    starts: list[int] = []

    def route(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        starts.append(start_ea)
        return 0xDEAD

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(71, state, state_var_reg=20),
            StateWriteAnchor(71, state, state_var_stkoff=0x44C),
        ),
        out_reg_maps={71: {20: state}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({203}),
        transfers=(),
        route_resolver=route,
    )

    assert routes == ()
    assert starts == [0x4000]


def test_materialized_state_routes_partition_register_snapshot_at_anchor_ea():
    state = 0xAE5A330B
    graph = FlowGraph(
        blocks={
            70: _block(70, 0x7000),
            71: _block(71, 0x7100, preds=(70,)),
            124: _block(124, 0x4000),
            203: _block(203, 0x9000),
        },
        entry_serial=70,
        func_ea=0x40A560,
    )
    calls: list[tuple[int, dict[int, int]]] = []

    def route(
        start_ea,
        *,
        initial_mregs,
        handler_eas,
        register_snapshots_by_ea,
        dispatch_anchor_eas,
    ):
        calls.append((start_ea, dict(initial_mregs)))
        return (
            0x9000
            if start_ea == 0x4000 and initial_mregs.get(4) == 0x1234
            else None
        )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(71, state, state_var_reg=20, instruction_ea=0x7110),
        ),
        in_stk_maps={71: {}},
        in_reg_maps={71: {}},
        out_stk_maps={70: {}},
        out_reg_maps={70: {4: 0x1234}, 71: {20: state}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({203}),
        transfers=(),
        route_resolver=route,
    )

    assert routes == (MaterializedStateRoute(71, state, 203),)
    assert calls == [
        (0x7110, {20: state}),
        (0x7110, {4: 0x1234, 20: state}),
        (0x4000, {20: state}),
        (0x4000, {4: 0x1234, 20: state}),
    ]


def test_materialized_state_route_aliases_proven_dispatch_predecessor() -> None:
    state = 0xF32B2D3A
    graph = FlowGraph(
        blocks={
            80: _block(80, 0x8000, preds=(79,), succs=(81, 119)),
            81: _block(81, 0x8100, preds=(80,), succs=(124,)),
            119: _block(119, 0x8900, preds=(80,), succs=(6,)),
            124: _block(124, 0x4000, preds=(81,)),
            154: _block(154, 0x9000),
        },
        entry_serial=80,
        func_ea=0x40A560,
    )

    routes = _build_materialized_state_routes(
        graph,
        state_write_anchors=(
            StateWriteAnchor(80, state, state_var_reg=20, instruction_ea=0x8010),
        ),
        in_stk_maps={80: {}},
        in_reg_maps={80: {}},
        out_stk_maps={79: {}},
        out_reg_maps={79: {}, 80: {20: state}, 81: {20: state}},
        dispatcher_entry_serial=124,
        state_var_reg=20,
        handler_serials=frozenset({154}),
        transfers=(),
        route_resolver=lambda *_args, **_kwargs: 0x9000,
    )

    assert routes == (
        MaterializedStateRoute(80, state, 154),
        MaterializedStateRoute(81, state, 154),
    )


def test_unique_equality_state_targets_reject_conflicting_rows() -> None:
    assert _unique_equality_state_targets(
        (
            ("ebx", 0xA5A94B86, 0x40B8E6),
            ("ebx", 0xAE5A330B, 0x40C47E),
            ("ebx", 0xAE5A330B, 0x40C47E),
            ("ebx", 0xDEADBEEF, 0x401000),
            ("ebx", 0xDEADBEEF, 0x402000),
            ("eax", 0xA5A94B86, 0x499999),
        ),
        "ebx",
    ) == {
        0xA5A94B86: 0x40B8E6,
        0xAE5A330B: 0x40C47E,
    }


def test_unique_static_equality_handler_targets_select_matching_arm() -> None:
    state = 0x2100AFDD
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x40AEFE,
        source_block_ea=0x40AEE6,
        materialized_anchor_eas=(0x40AEF2, 0x40AEF8),
        target_eas=(0x40AF00, 0x40A5F0),
        condition_code=4,
        true_target_ea=0x40AF00,
        false_target_ea=0x40A5F0,
        selector_state_var_reg=20,
        selector_compare_constant=state,
        resolver_kind="static_equality_fixpoint",
    )
    residual = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C6F7,
        source_block_ea=0x40C6F7,
        materialized_anchor_eas=(0x40C6F7,),
        target_eas=(0x40AEE6,),
        selector_state_constant=state,
        resolver_kind="residual_state_route",
    )
    assert _unique_static_equality_handler_targets(
        (exact, residual), 20
    ) == {
        state: 0x40AF00,
    }


def test_claim_exact_function_tail_reparents_standalone_handler() -> None:
    parent = SimpleNamespace(start_ea=0x40A560, end_ea=0x40C700)
    detached = SimpleNamespace(start_ea=0x40B8E6, end_ea=0x40B940)
    owners = {0x40B8E6: detached}
    calls: list[tuple[object, ...]] = []

    def append_tail(function: object, start_ea: int, end_ea: int) -> bool:
        calls.append(("append", function, start_ea, end_ea))
        if owners.get(start_ea) is detached:
            return False
        owners[start_ea] = parent
        return True

    def delete_function(start_ea: int) -> bool:
        calls.append(("delete", start_ea))
        owners.pop(start_ea, None)
        return True

    assert _claim_exact_function_tail_range(
        parent,
        0x40B8E6,
        0x40B940,
        get_function=lambda ea: owners.get(ea),
        append_function_tail=append_tail,
        delete_function=delete_function,
    )
    assert calls == [
        ("append", parent, 0x40B8E6, 0x40B940),
        ("delete", 0x40B8E6),
        ("append", parent, 0x40B8E6, 0x40B940),
    ]


def test_claim_exact_function_tail_abstains_from_deleting_broader_owner() -> None:
    parent = SimpleNamespace(start_ea=0x40A560, end_ea=0x40C700)
    broader = SimpleNamespace(start_ea=0x40B800, end_ea=0x40BA00)
    deleted: list[int] = []

    assert not _claim_exact_function_tail_range(
        parent,
        0x40B8E6,
        0x40B940,
        get_function=lambda _ea: broader,
        append_function_tail=lambda *_args: False,
        delete_function=lambda ea: deleted.append(ea) or True,
    )
    assert deleted == []


def test_exact_equality_fragment_ownership_excludes_unvalidated_candidates() -> None:
    exact = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BECA,
        source_block_ea=0x40BEB2,
        materialized_anchor_eas=(0x40BEBE, 0x40BEC4),
        target_eas=(0x40BECC, 0x40A5F0),
        resolver_kind="static_equality_fixpoint",
    )
    candidate = MaterializedIndirectTransfer(
        source_jmp_ea=0x40BECA,
        source_block_ea=0x40BEB2,
        materialized_anchor_eas=(0x40BEBE,),
        target_eas=(0x40BECC,),
        resolver_kind="static_equality_candidate",
    )
    route = MaterializedIndirectTransfer(
        source_jmp_ea=0x40C422,
        source_block_ea=0x40C422,
        materialized_anchor_eas=(0x40C422,),
        target_eas=(0x40B8E6,),
        resolver_kind="residual_state_route",
    )

    assert _exact_equality_fragment_transfers((exact, candidate, route)) == (
        exact,
    )


def test_plan_residual_state_routes_requires_one_way_dispatch_back_edge() -> None:
    state = 0xA5A94B86
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x1000, succs=(124,)),
            11: _block(11, 0x1100, succs=(124, 20)),
            12: _block(12, 0x1200, succs=(20,)),
            124: _block(124, 0x4000, preds=(10, 11)),
            20: _block(20, 0x2000),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transitions = (
        StateWriteTransition(10, state, 99, True, None),
        StateWriteTransition(11, state, 99, True, None),
        StateWriteTransition(12, state, 99, True, None),
        StateWriteTransition(10, 0x1234, 99, True, None),
    )

    assert _plan_residual_state_route_patches(
        graph,
        transitions,
        dispatcher_entry_serial=124,
        state_targets={state: 0x40B8E6},
    ) == ((10, state, 0x40B8E6),)


def test_residual_patch_site_abstains_at_shared_state_join() -> None:
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x40B51B, succs=(30,)),
            20: _block(20, 0x40AB56, succs=(30,)),
            30: _block(
                30,
                0x40B534,
                (0x40B534, 0x40B540),
                preds=(10, 20),
            ),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )

    assert computed_goto_resolver._residual_patch_site_is_path_local(
        graph,
        source_serial=10,
        patch_ea=0x40B534,
    ) is False


def test_residual_patch_site_accepts_single_predecessor_corridor() -> None:
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x40B51B, succs=(20,)),
            20: _block(20, 0x40B526, preds=(10,), succs=(30,)),
            30: _block(
                30,
                0x40B534,
                (0x40B534, 0x40B540),
                preds=(20,),
            ),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )

    assert computed_goto_resolver._residual_patch_site_is_path_local(
        graph,
        source_serial=10,
        patch_ea=0x40B534,
    ) is True


def test_residual_state_route_evidence_keeps_unpatchable_target_ea() -> None:
    state = 0xF6A636EF
    target_ea = 0x40C4B4
    graph = FlowGraph(
        blocks={10: _block(10, 0x40ADE6, (0x40ADEC,))},
        entry_serial=10,
        func_ea=0x40A560,
    )

    (evidence,) = _build_residual_state_route_evidence(
        graph,
        ((10, state, target_ea),),
        state_write_sites={(10, state): 0x40ADEC},
        state_var_reg=20,
        existing_transfers=(),
    )

    assert evidence.resolver_kind == "residual_state_route_evidence"
    assert evidence.source_jmp_ea == 0x40ADEC
    assert evidence.source_block_ea == 0x40ADE6
    assert evidence.target_eas == (target_ea,)
    assert evidence.selector_state_constant == state
    assert evidence.selector_state_var_reg == 20

    assert _build_residual_state_route_evidence(
        graph,
        ((10, state, target_ea),),
        state_write_sites={(10, state): 0x40ADEC},
        state_var_reg=20,
        existing_transfers=(evidence,),
    ) == ()


def test_plan_misrouted_exact_state_route_outranks_coarse_bst_interval() -> None:
    state = 0xA5A94B86
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x40B354, succs=(124,)),
            20: _block(20, 0x40B8E0, (0x40B8E6,)),
            99: _block(99, 0x40B880),
            124: _block(124, 0x40A607),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )

    assert _plan_misrouted_exact_state_route_patches(
        graph,
        (StateWriteTransition(10, state, 99, False, None),),
        state_routes={state: (0x40B8E6, 0x40B940)},
        state_write_sites={(10, state): 0x40B354},
    ) == ((10, state, 0x40B8E6),)
    assert _plan_misrouted_exact_state_route_patches(
        graph,
        (StateWriteTransition(10, state, 20, False, None),),
        state_routes={state: (0x40B8E6, 0x40B940)},
        state_write_sites={(10, state): 0x40B354},
    ) == ()


def test_plan_exact_state_write_route_without_coarse_transition() -> None:
    state = 0xA7933EA0
    graph = FlowGraph(
        blocks={10: _block(10, 0x40B8E6)},
        entry_serial=10,
        func_ea=0x40A560,
    )

    assert _plan_exact_state_write_route_patches(
        graph,
        state_routes={state: (0x40C1A0, 0x40C20C)},
        state_write_sites={(10, state): 0x40B908},
    ) == ((10, state, 0x40C1A0),)
    assert _plan_misrouted_exact_state_route_patches(
        graph,
        (StateWriteTransition(10, state, 99, False, None),),
        state_routes={state: (0x40B8E6, 0x40B940)},
        state_write_sites={},
    ) == ()


def test_plan_unseen_residual_state_routes_uses_microcode_absence_not_root_shape() -> None:
    missing_state = 0xA5A94B86
    live_state = 0xEC71CA67
    graph = FlowGraph(
        blocks={
            201: _block(201, 0x40B354, (0x40B36B,), succs=(236,)),
            236: _block(236, 0x40B6C0, succs=(7,)),
            237: _block(237, 0x40B9A0, (0x40B9A6,)),
            7: _block(7, 0x40A607),
        },
        entry_serial=7,
        func_ea=0x40A560,
    )
    transitions = (
        StateWriteTransition(201, missing_state, 237, False, None, via_block=236),
        StateWriteTransition(201, live_state, 237, False, None, via_block=236),
    )

    assert _plan_unseen_residual_state_route_patches(
        graph,
        transitions,
        state_targets={
            missing_state: 0x40B8E0,
            live_state: 0x40B9A0,
        },
    ) == ((201, missing_state, 0x40B8E0),)


def test_plan_all_residual_routes_keeps_primary_and_unseen_work_in_same_round() -> None:
    terminal_state = 0xA5A94B86
    routed_but_detached_state = 0x2100AFDD
    graph = FlowGraph(
        blocks={
            10: _block(10, 0x40C400, succs=(124,)),
            11: _block(11, 0x40C6DA, succs=(124,)),
            124: _block(124, 0x40A607, preds=(10, 11)),
        },
        entry_serial=10,
        func_ea=0x40A560,
    )
    transitions = (
        StateWriteTransition(10, terminal_state, None, True, None),
        StateWriteTransition(11, routed_but_detached_state, 59, False, None),
    )

    assert _plan_all_residual_state_route_patches(
        graph,
        transitions,
        dispatcher_entry_serial=124,
        state_targets={
            terminal_state: 0x40C47E,
            routed_but_detached_state: 0x40AEE6,
        },
    ) == (
        (10, terminal_state, 0x40C47E),
        (11, routed_but_detached_state, 0x40AEE6),
    )

    assert _plan_all_residual_state_route_patches(
        graph,
        transitions,
        dispatcher_entry_serial=124,
        state_targets={
            terminal_state: 0x40C47E,
            routed_but_detached_state: 0x40AEE6,
        },
        state_write_sites={(11, routed_but_detached_state): 0x40C6DA},
    ) == ((11, routed_but_detached_state, 0x40AEE6),)


def test_select_register_indirect_patch_region_uses_only_register_target_chain() -> None:
    assert _select_register_indirect_patch_region(
        (
            (0x40C6F7, 0x40C6F9, "mov", True, False),
            (0x40C6F9, 0x40C6FB, "mov", True, False),
            (0x40C6FB, 0x40C6FD, "add", True, False),
            (0x40C6FD, 0x40C6FF, "jmp", False, True),
        )
    ) == (0x40C6F7, 8)

    assert _select_register_indirect_patch_region(
        (
            (0x1000, 0x1005, "mov", False, False),
            (0x1005, 0x1007, "jmp", False, True),
        )
    ) is None


def test_dispatch_patch_region_prefers_terminal_indirect_over_earlier_jcc() -> None:
    decoded = (
        (0x40B90F, 0x40B915, "jnz", False, False),
        (0x40B921, 0x40B927, "jge", False, False),
        (0x40B927, 0x40B929, "mov", True, False),
        (0x40B929, 0x40B92B, "add", True, False),
        (0x40B92B, 0x40B931, "lea", True, False),
        (0x40B931, 0x40B933, "jmp", False, True),
    )

    assert _choose_dispatch_patch_region(
        ((0x40B90F, 6), (0x40B921, 6)),
        decoded,
    ) == (0x40B927, 12)


def test_residual_route_patch_site_never_falls_back_to_payload_jcc(monkeypatch) -> None:
    calls: list[int] = []

    def _scan(
        write_ea: int,
        *,
        materialized_anchor_eas: frozenset[int],
    ) -> tuple[int, int] | None:
        calls.append(int(write_ea))
        assert materialized_anchor_eas == frozenset({0x40B06B})
        return (0x40B06B, 6)

    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_post_state_write_indirect_site",
        _scan,
    )

    assert computed_goto_resolver._native_residual_route_patch_site(
        0x40B04A,
        materialized_anchor_eas=frozenset({0x40B06B}),
    ) == (0x40B06B, 6)
    assert calls == [0x40B04A]


def test_residual_route_patch_site_abstains_without_terminal_indirect(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        computed_goto_resolver,
        "_native_post_state_write_indirect_site",
        lambda _write_ea, *, materialized_anchor_eas: None,
    )

    assert computed_goto_resolver._native_residual_route_patch_site(
        0x40B04A,
        materialized_anchor_eas=frozenset({0x40B06B}),
    ) is None
