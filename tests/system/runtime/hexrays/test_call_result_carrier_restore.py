"""Runtime contract for cross-maturity call-result carrier restoration."""

from __future__ import annotations

import copy
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    CallResultCarrier,
    NativePreanalysisSessionState,
)
from d810.analyses.control_flow.terminal_return_carrier_evidence import (
    TerminalReturnCarrierSourceKind,
)
from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.expressions import ValueOpKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from tests.native_preanalysis import make_native_key
from tests.system.runtime.mutation_gateway import make_mutation_gateway


NATIVE_KEY = make_native_key()


def _portable_transfer(
    source_ea: int,
    *,
    target_ea: int | None = None,
    resolver_kind: str = "static_fixpoint",
    selector_state_var_reg: int | None = None,
) -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=int(source_ea),
        source_block_ea=int(source_ea),
        materialized_anchor_eas=(int(source_ea),),
        target_eas=(() if target_ea is None else (int(target_ea),)),
        resolver_kind=resolver_kind,
        selector_state_var_reg=selector_state_var_reg,
    )


def test_calls_done_defers_generated_restart_to_the_flowchart_owner() -> None:
    """CALLS cannot return a documented full-decompilation restart code."""

    def callback(_event, **kwargs) -> None:
        decision = kwargs["decision"]
        decision["request_redo"] = True
        decision["defer_generated_restart"] = True
        decision["reason"] = "preopt_template_refreshed"

    hook = SimpleNamespace(callback=callback)
    mba = SimpleNamespace(entry_ea=0x40D200)

    assert HexraysDecompilationHook.calls_done(hook, mba) == 0


def test_calls_done_retains_calls_loop_for_ordinary_redo_requests() -> None:
    """Existing CALLS-local evidence rounds must retain their old contract."""

    def callback(_event, **kwargs) -> None:
        decision = kwargs["decision"]
        decision["request_redo"] = True
        decision["reason"] = "calls_local_change"

    hook = SimpleNamespace(callback=callback)
    mba = SimpleNamespace(entry_ea=0x40D200)

    assert HexraysDecompilationHook.calls_done(hook, mba) == ida_hexrays.MERR_LOOP


def _session_resolver_state(
    *,
    transfers: tuple[object, ...] = (),
    materialized: bool = True,
):
    """Build the final session-owned resolver attachment used by flow rules."""
    from d810.analyses.control_flow.native_preanalysis_session import (
        NativePreanalysisFacts,
        NativePreanalysisSessionState,
    )
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedSnippetBoundaryPorts,
    )
    from d810.analyses.control_flow.native_semantic_closure import NativeCfg
    from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
        ResolverSessionState,
    )

    native_preanalysis = NativePreanalysisSessionState(
        facts=NativePreanalysisFacts(
            key=NATIVE_KEY,
            native_cfg=NativeCfg({}),
            semantic_closure=None,
            transfers=transfers,
            boundary_ports=DetachedSnippetBoundaryPorts((), ()),
        )
    )
    state = ResolverSessionState(
        native_preanalysis=native_preanalysis,
        native_key=NATIVE_KEY,
        materialized=materialized,
    )
    return state


def _bind_rule_resolver_state(
    monkeypatch,
    rule: object,
    *,
    transfers: tuple[object, ...] = (),
    materialized: bool = True,
):
    state = _session_resolver_state(
        transfers=transfers,
        materialized=materialized,
    )
    monkeypatch.setattr(
        rule,
        "current_resolver_session_state",
        lambda: state,
    )
    mutation_gateway = make_mutation_gateway()
    rule.set_flow_context(
        SimpleNamespace(
            new_mba_mutation_gateway=mutation_gateway.new_transaction,
        )
    )
    return state


class _Operand:
    def __init__(
        self,
        operand_type: int = ida_hexrays.mop_z,
        *,
        register: int = -1,
        size: int = 4,
        stack_offset: int | None = None,
        value: int | None = None,
        nested: "_Instruction | None" = None,
        target_ea: int = 0,
    ) -> None:
        self.t = int(operand_type)
        self.r = int(register)
        self.size = int(size)
        self.s = (
            SimpleNamespace(off=int(stack_offset)) if stack_offset is not None else None
        )
        self.nnn = SimpleNamespace(value=int(value)) if value is not None else None
        self.d = nested
        self.g = int(target_ea)
        self.a = None
        self.f = None

    def erase(self) -> None:
        self.t = int(ida_hexrays.mop_z)
        self.r = -1
        self.s = None
        self.nnn = None
        self.d = None

    def make_stkvar(self, _mba: object, stack_offset: int) -> None:
        self.t = int(ida_hexrays.mop_S)
        self.s = SimpleNamespace(off=int(stack_offset))

    def make_reg(self, register: int, size: int) -> None:
        self.t = int(ida_hexrays.mop_r)
        self.r = int(register)
        self.size = int(size)

    def make_number(self, value: int, size: int, _ea: int) -> None:
        self.t = int(ida_hexrays.mop_n)
        self.nnn = SimpleNamespace(value=int(value))
        self.size = int(size)

    def make_insn(self, instruction: "_Instruction") -> None:
        self.t = int(ida_hexrays.mop_d)
        self.d = instruction

    def make_blkref(self, serial: int) -> None:
        self.t = int(ida_hexrays.mop_b)
        self.b = int(serial)


class _Instruction:
    def __init__(
        self,
        opcode: int,
        ea: int,
        *,
        left: _Operand | None = None,
        right: _Operand | None = None,
        dest: _Operand | None = None,
    ) -> None:
        self.opcode = int(opcode)
        self.ea = int(ea)
        self.l = left or _Operand()
        self.r = right or _Operand()
        self.d = dest or _Operand()
        self.next: _Instruction | None = None

    def setaddr(self, ea: int) -> None:
        self.ea = int(ea)


class _SerialList(list[int]):
    def push_back(self, serial: int) -> None:
        self.append(int(serial))


class _Block:
    def __init__(
        self,
        serial: int,
        start_ea: int,
        instructions: tuple[_Instruction, ...],
        successors: tuple[int, ...],
        predecessors: tuple[int, ...] = (),
    ) -> None:
        self.serial = int(serial)
        self.start = int(start_ea)
        self.succset = _SerialList(successors)
        self.predset = _SerialList(predecessors)
        self.type = ida_hexrays.BLT_1WAY
        self.flags = 0
        self.dirty = 0
        self._set_instructions(instructions)

    def _set_instructions(self, instructions: tuple[_Instruction, ...]) -> None:
        self.head = instructions[0]
        self.tail = instructions[-1]
        for current, following in zip(instructions, instructions[1:]):
            current.next = following
        self.tail.next = None

    def instructions(self) -> tuple[_Instruction, ...]:
        result = []
        instruction = self.head
        while instruction is not None:
            result.append(instruction)
            instruction = instruction.next
        return tuple(result)

    def insert_into_block(
        self,
        instruction: _Instruction,
        previous: _Instruction | None,
    ) -> None:
        current = list(self.instructions())
        index = 0 if previous is None else current.index(previous) + 1
        current.insert(index, instruction)
        self._set_instructions(tuple(current))

    def nsucc(self) -> int:
        return len(self.succset)

    def mark_lists_dirty(self) -> None:
        self.dirty += 1


class _MBA:
    def __init__(self, blocks: tuple[_Block, ...], entry_ea: int = 0x40A560) -> None:
        self.blocks = blocks
        self.qty = len(blocks)
        self.entry_ea = int(entry_ea)
        self.chains_dirty = 0

    def get_mblock(self, serial: int) -> _Block:
        return self.blocks[int(serial)]

    def stkoff_vd2ida(self, stack_offset: int) -> int:
        return int(stack_offset) + 0x1000

    def stkoff_ida2vd(self, stack_offset: int) -> int:
        return int(stack_offset) - 0x1000

    def mark_chains_dirty(self) -> None:
        self.chains_dirty += 1

    def verify(self, _always: bool) -> None:
        return None


def _raw_mba() -> _MBA:
    return_mreg = int(ida_hexrays.reg2mreg(0))
    call = _Instruction(
        ida_hexrays.m_call,
        0x40B2A0,
        left=_Operand(ida_hexrays.mop_v, target_ea=0x471234),
    )
    carrier_write = _Instruction(
        ida_hexrays.m_mov,
        0x40B2AB,
        left=_Operand(ida_hexrays.mop_r, register=return_mreg),
        dest=_Operand(ida_hexrays.mop_S, stack_offset=0x40),
    )
    branch = _Instruction(
        ida_hexrays.m_jnz,
        0x40B2B1,
        left=_Operand(ida_hexrays.mop_r, register=return_mreg),
        right=_Operand(ida_hexrays.mop_n, value=0),
        dest=_Operand(ida_hexrays.mop_b),
    )
    return _MBA(
        (
            _Block(0, 0x40B281, (call,), (1,)),
            _Block(1, 0x40B2A6, (carrier_write, branch), (2, 3)),
            _Block(2, 0x40B2B7, (_Instruction(ida_hexrays.m_nop, 0x40B2B7),), ()),
            _Block(3, 0x40B668, (_Instruction(ida_hexrays.m_nop, 0x40B668),), ()),
        )
    )


def _lowered_mba(*, with_consumer: bool) -> tuple[_MBA, _Block, _Instruction]:
    call_expression = _Instruction(
        ida_hexrays.m_call,
        0x40B2A0,
        left=_Operand(ida_hexrays.mop_v, target_ea=0x471234),
    )
    branch = _Instruction(
        ida_hexrays.m_jnz,
        0x40B2B1,
        left=_Operand(ida_hexrays.mop_d, nested=call_expression),
        right=_Operand(ida_hexrays.mop_n, value=0),
        dest=_Operand(ida_hexrays.mop_b),
    )
    branch_block = _Block(0, 0x40B27B, (branch,), (1, 2))
    consumer_source = (
        _Operand(ida_hexrays.mop_S, stack_offset=0x40)
        if with_consumer
        else _Operand(ida_hexrays.mop_n, value=7)
    )
    consumer = _Instruction(
        ida_hexrays.m_mov,
        0x40AC74,
        left=consumer_source,
        dest=_Operand(ida_hexrays.mop_r, register=9),
    )
    return (
        _MBA(
            (
                branch_block,
                _Block(1, 0x40AC6A, (consumer,), ()),
                _Block(2, 0x40B668, (_Instruction(ida_hexrays.m_nop, 0x40B668),), ()),
            )
        ),
        branch_block,
        branch,
    )


def _fake_minsn(value: int | _Instruction) -> _Instruction:
    if isinstance(value, _Instruction):
        return copy.deepcopy(value)
    return _Instruction(ida_hexrays.m_nop, int(value))


def _analyzed_call_result_mba(
    *,
    call_ea: int = 0x40ABFA,
    callee_ea: int = 0x40F830,
    result_mreg: int | None = None,
) -> _MBA:
    result_register = (
        int(ida_hexrays.reg2mreg(0)) if result_mreg is None else int(result_mreg)
    )
    call = _Instruction(
        ida_hexrays.m_call,
        call_ea,
        left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
        dest=_Operand(ida_hexrays.mop_f),
    )
    call.d.f = SimpleNamespace(args=())
    owner = _Instruction(
        ida_hexrays.m_mov,
        call_ea,
        left=_Operand(ida_hexrays.mop_d, nested=call, size=4),
        dest=_Operand(
            ida_hexrays.mop_r,
            register=result_register,
            size=4,
        ),
    )
    return _MBA((_Block(0, call_ea - 6, (owner,), ()),))


def _bare_call_result_mba(
    *,
    call_ea: int = 0x40ABFA,
    callee_ea: int = 0x40F830,
    duplicate: bool = False,
) -> _MBA:
    def raw_call() -> _Instruction:
        call = _Instruction(
            ida_hexrays.m_call,
            call_ea,
            left=_Operand(ida_hexrays.mop_v, target_ea=callee_ea),
            dest=_Operand(ida_hexrays.mop_f, size=0),
        )
        call.d.f = SimpleNamespace(args=())
        return call

    blocks = [_Block(0, call_ea - 6, (raw_call(),), ())]
    if duplicate:
        blocks.append(_Block(1, call_ea - 2, (raw_call(),), ()))
    blocks.append(
        _Block(
            len(blocks),
            call_ea + 5,
            (_Instruction(ida_hexrays.m_nop, call_ea + 5),),
            (),
        )
    )
    return _MBA(tuple(blocks))


def test_restores_analyzed_call_result_definition_by_native_ea(monkeypatch) -> None:
    from d810.hexrays.mutation import detached_handler_island

    function_ea = 0x40A560
    detached_handler_island.clear_detached_handler_call_templates()
    try:
        detached_handler_island.capture_detached_handler_call_templates(
            function_ea,
            _analyzed_call_result_mba(),
        )
        replayed = _bare_call_result_mba()
        raw_call = replayed.get_mblock(0).head
        original_callinfo = raw_call.d.f
        monkeypatch.setattr(
            detached_handler_island.ida_hexrays,
            "minsn_t",
            _fake_minsn,
        )

        changed = detached_handler_island.restore_detached_call_result_definitions(
            replayed,
            function_ea,
        )

        assert changed == 1
        owner = replayed.get_mblock(0).head
        assert int(owner.opcode) == int(ida_hexrays.m_mov)
        assert int(owner.l.t) == int(ida_hexrays.mop_d)
        assert int(owner.l.d.opcode) == int(ida_hexrays.m_call)
        assert int(owner.l.d.ea) == 0x40ABFA
        assert int(owner.l.d.d.t) == int(ida_hexrays.mop_f)
        assert int(owner.l.size) == int(owner.l.d.d.size) == 4
        assert owner.l.d.d.f is not original_callinfo
        assert int(owner.d.t) == int(ida_hexrays.mop_r)
        assert int(owner.d.r) == int(ida_hexrays.reg2mreg(0))
        assert int(owner.d.size) == 4
        assert replayed.get_mblock(0).dirty == 1
        assert replayed.chains_dirty == 1
    finally:
        detached_handler_island.clear_detached_handler_call_templates()


def test_call_result_definition_restore_abstains_on_duplicate_native_owner(
    monkeypatch,
) -> None:
    from d810.hexrays.mutation import detached_handler_island

    function_ea = 0x40A560
    detached_handler_island.clear_detached_handler_call_templates()
    try:
        detached_handler_island.capture_detached_handler_call_templates(
            function_ea,
            _analyzed_call_result_mba(),
        )
        replayed = _bare_call_result_mba(duplicate=True)
        monkeypatch.setattr(
            detached_handler_island.ida_hexrays,
            "minsn_t",
            _fake_minsn,
        )

        assert (
            detached_handler_island.restore_detached_call_result_definitions(
                replayed,
                function_ea,
            )
            == 0
        )
        assert all(
            int(block.head.opcode) == int(ida_hexrays.m_call)
            for block in replayed.blocks[:-1]
        )
    finally:
        detached_handler_island.clear_detached_handler_call_templates()


def test_call_result_definition_restore_abstains_on_conflicting_result_register(
    monkeypatch,
) -> None:
    from d810.hexrays.mutation import detached_handler_island

    function_ea = 0x40A560
    detached_handler_island.clear_detached_handler_call_templates()
    try:
        detached_handler_island.capture_detached_handler_call_templates(
            function_ea,
            _analyzed_call_result_mba(result_mreg=7),
        )
        detached_handler_island.capture_detached_handler_call_templates(
            function_ea,
            _analyzed_call_result_mba(result_mreg=9),
        )
        replayed = _bare_call_result_mba()
        monkeypatch.setattr(
            detached_handler_island.ida_hexrays,
            "minsn_t",
            _fake_minsn,
        )

        assert (
            detached_handler_island.restore_detached_call_result_definitions(
                replayed,
                function_ea,
            )
            == 0
        )
        assert int(replayed.get_mblock(0).head.opcode) == int(ida_hexrays.m_call)
    finally:
        detached_handler_island.clear_detached_handler_call_templates()


def test_restores_cached_call_result_after_consumers_are_reconnected(
    monkeypatch,
) -> None:
    from d810.hexrays.mutation import detached_handler_island

    raw = _raw_mba()
    facts = detached_handler_island.capture_call_result_carriers(raw)
    assert len(facts) == 1

    lowered, branch_block, branch = _lowered_mba(with_consumer=True)
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)

    changed = detached_handler_island.restore_call_result_carriers(lowered, facts)

    assert changed == 1
    assignment, preserved_branch = branch_block.instructions()
    assert preserved_branch is branch
    assert int(assignment.opcode) == int(ida_hexrays.m_mov)
    assert int(assignment.l.t) == int(ida_hexrays.mop_d)
    assert int(assignment.l.d.opcode) == int(ida_hexrays.m_call)
    assert int(assignment.d.t) == int(ida_hexrays.mop_S)
    assert int(assignment.d.s.off) == 0x40
    assert int(branch.l.t) == int(ida_hexrays.mop_S)
    assert int(branch.l.s.off) == 0x40
    assert branch_block.dirty == 1
    assert lowered.chains_dirty == 1


def test_abstains_until_a_nonpredicate_carrier_consumer_is_live(monkeypatch) -> None:
    from d810.hexrays.mutation import detached_handler_island

    facts = detached_handler_island.capture_call_result_carriers(_raw_mba())
    assert len(facts) == 1
    lowered, branch_block, branch = _lowered_mba(with_consumer=False)
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)

    assert detached_handler_island.restore_call_result_carriers(lowered, facts) == 0
    assert branch_block.instructions() == (branch,)
    assert int(branch.l.t) == int(ida_hexrays.mop_d)


def _terminal_return_carrier_snippet(
    *,
    source_ea: int = 0x40C7E5,
    carrier_ea: int = 0x40C7EA,
    carrier_source_size: int = 4,
) -> _MBA:
    return_mreg = int(ida_hexrays.reg2mreg(0))
    state_write = _Instruction(
        ida_hexrays.m_mov,
        source_ea,
        left=_Operand(ida_hexrays.mop_n, value=0x19A7218A),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    carrier = _Instruction(
        ida_hexrays.m_mov,
        carrier_ea,
        left=_Operand(
            ida_hexrays.mop_v,
            target_ea=0x48B8A4,
            size=carrier_source_size,
        ),
        dest=_Operand(ida_hexrays.mop_r, register=return_mreg),
    )
    branch = _Instruction(ida_hexrays.m_jnz, 0x40C7F0)
    return _MBA(
        (
            _Block(
                0,
                source_ea,
                (_Instruction(ida_hexrays.m_nop, 0x40C7E4),),
                (1,),
            ),
            _Block(1, source_ea, (state_write, carrier, branch), (2,)),
        )
    )


def _terminal_return_live_mba(*, state: int = 0x19A7218A) -> tuple[_MBA, _Block]:
    state_write = _Instruction(
        ida_hexrays.m_mov,
        0x40C7E5,
        left=_Operand(ida_hexrays.mop_n, value=state),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    block = _Block(0, 0x40C7E5, (state_write,), (1,))
    return _MBA((block,)), block


def test_captures_terminal_return_carrier_as_portable_evidence() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    capture_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C7E5, 0x40C7F4),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C7E5, 0x40C7EA),
    )
    terminal_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40C898, 0x40C8A0),),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(0x40C898,),
    )

    evidence = detached_handler_island.capture_terminal_return_carrier_evidence(
        0x40A560,
        request,
        _terminal_return_carrier_snippet(),
        capture_identity=capture_identity,
        terminal_identity=terminal_identity,
        terminal_return_ea=0x40C898,
    )

    assert evidence is not None
    assert evidence.operation is ValueOpKind.MOVE
    assert evidence.source.kind is TerminalReturnCarrierSourceKind.STORAGE_VALUE
    assert evidence.source.storage_identity == StorageIdentity(
        StorageIdentityKind.GLOBAL,
        0x48B8A4,
    )
    assert evidence.state_write_ea == 0x40C7E5
    assert evidence.carrier_ea == 0x40C7EA
    assert evidence.corridor_instruction_eas == (0x40C7E5, 0x40C7EA)


def test_terminal_carrier_capture_owns_exact_corridor_missing_from_route() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    source_ea = 0x40C7E5
    carrier_ea = 0x40C7EA
    delivery_ea = 0x40C7F0
    terminal_ea = 0x40C898
    request = TerminalReturnCarrierRequest(
        source_handler_ea=source_ea,
        terminal_target_ea=terminal_ea,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    route_identity = StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(source_ea, source_ea + 1),
            NativeEaInterval(delivery_ea, delivery_ea + 1),
        ),
        native_key=NATIVE_KEY,
        exact_instruction_eas=(source_ea, delivery_ea),
    )

    evidence = detached_handler_island.capture_terminal_return_carrier_evidence(
        0x40A560,
        request,
        _terminal_return_carrier_snippet(),
        capture_identity=route_identity,
        terminal_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(terminal_ea, terminal_ea + 8),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(terminal_ea,),
        ),
        terminal_return_ea=terminal_ea,
    )

    assert evidence is not None
    assert evidence.corridor_instruction_eas == (source_ea, carrier_ea)
    assert evidence.capture_identity.exact_instruction_eas == frozenset(
        {source_ea, carrier_ea, delivery_ea}
    )
    assert evidence.capture_identity.native_ranges.contains(carrier_ea)
    assert carrier_ea not in route_identity.exact_instruction_eas


def test_portable_terminal_carrier_capture_abstains_on_invalid_source() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )

    assert (
        detached_handler_island.capture_terminal_return_carrier_evidence(
            0x40A560,
            request,
            _terminal_return_carrier_snippet(carrier_source_size=0),
            capture_identity=StableBlockIdentity.from_intervals(
                (NativeEaInterval(0x40C7E5, 0x40C7F4),),
                native_key=NATIVE_KEY,
                exact_instruction_eas=(0x40C7E5, 0x40C7EA),
            ),
            terminal_identity=StableBlockIdentity.from_intervals(
                (NativeEaInterval(0x40C898, 0x40C8A0),),
                native_key=NATIVE_KEY,
                exact_instruction_eas=(0x40C898,),
            ),
            terminal_return_ea=0x40C898,
        )
        is None
    )


def test_captures_stack_terminal_carrier_through_stable_frame_identity(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    source_ea = 0x40CC1C
    carrier_ea = 0x40CC30
    terminal_ea = 0x40CD8C
    state = 0x69225E4
    stable_ida_stkoff = 0x1010
    state_write = _Instruction(
        ida_hexrays.m_mov,
        source_ea,
        left=_Operand(ida_hexrays.mop_n, value=state),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    carrier = _Instruction(
        ida_hexrays.m_xdu,
        carrier_ea,
        left=_Operand(ida_hexrays.mop_S, stack_offset=0x44, size=1),
        dest=_Operand(
            ida_hexrays.mop_r,
            register=int(ida_hexrays.reg2mreg(0)),
            size=4,
        ),
    )
    snippet = _MBA(
        (
            _Block(
                0,
                source_ea,
                (state_write, carrier, _Instruction(ida_hexrays.m_jnz, 0x40CC34)),
                (1,),
            ),
        ),
        entry_ea=0x40C8B0,
    )
    request = TerminalReturnCarrierRequest(
        source_handler_ea=source_ea,
        terminal_target_ea=terminal_ea,
        state_var_reg=20,
        state_constant=state,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_native_instruction_stack_frame_offsets",
        lambda _function_ea, instruction_ea: (
            (stable_ida_stkoff,) if int(instruction_ea) == carrier_ea else ()
        ),
    )

    evidence = detached_handler_island.capture_terminal_return_carrier_evidence(
        0x40C8B0,
        request,
        snippet,
        capture_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(source_ea, 0x40CC38),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(source_ea, carrier_ea),
        ),
        terminal_identity=StableBlockIdentity.from_intervals(
            (NativeEaInterval(terminal_ea, terminal_ea + 8),),
            native_key=NATIVE_KEY,
            exact_instruction_eas=(terminal_ea,),
        ),
        terminal_return_ea=terminal_ea,
    )

    assert evidence is not None
    assert evidence.operation is ValueOpKind.ZEXT
    assert evidence.source.storage_identity == StorageIdentity(
        StorageIdentityKind.STACK,
        stable_ida_stkoff,
    )
    assert evidence.source.width == 1
    assert evidence.return_width == 4


def test_replays_exact_early_maturity_return_carrier_into_terminal_state_handler(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    detached_handler_island.clear_terminal_return_carrier_templates()
    try:
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            request,
            _terminal_return_carrier_snippet(),
        )
        lowered, block = _terminal_return_live_mba()

        assert (
            detached_handler_island.restore_terminal_return_carriers(
                lowered,
                0x40A560,
            )
            == 1
        )

        state_write, carrier = block.instructions()
        assert int(state_write.ea) == 0x40C7E5
        assert int(carrier.ea) == 0x40C7EA
        assert int(carrier.opcode) == int(ida_hexrays.m_mov)
        assert int(carrier.l.t) == int(ida_hexrays.mop_v)
        assert int(carrier.l.g) == 0x48B8A4
        assert int(carrier.d.t) == int(ida_hexrays.mop_r)
        assert int(carrier.d.r) == int(ida_hexrays.reg2mreg(0))
        assert lowered.chains_dirty == 1
    finally:
        detached_handler_island.clear_terminal_return_carrier_templates()


@pytest.mark.parametrize(
    "carrier_opcode",
    (ida_hexrays.m_mov, ida_hexrays.m_xdu, ida_hexrays.m_xds),
)
def test_replays_stack_terminal_carrier_through_stable_frame_identity(
    monkeypatch,
    carrier_opcode: int,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    source_ea = 0x40CC1C
    carrier_ea = 0x40CC30
    state = 0x69225E4
    source_vd_stkoff = 0x44
    stable_ida_stkoff = 0x1010
    return_mreg = int(ida_hexrays.reg2mreg(0))
    request = TerminalReturnCarrierRequest(
        source_handler_ea=source_ea,
        terminal_target_ea=0x40CD8C,
        state_var_reg=20,
        state_constant=state,
    )
    state_write = _Instruction(
        ida_hexrays.m_mov,
        source_ea,
        left=_Operand(ida_hexrays.mop_n, value=state),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    carrier = _Instruction(
        carrier_opcode,
        carrier_ea,
        left=_Operand(ida_hexrays.mop_S, stack_offset=source_vd_stkoff),
        dest=_Operand(ida_hexrays.mop_r, register=return_mreg),
    )
    snippet = _MBA(
        (
            _Block(
                0,
                source_ea,
                (state_write, carrier, _Instruction(ida_hexrays.m_jnz, 0x40CC34)),
                (1,),
            ),
        )
    )
    lowered_write = _Instruction(
        ida_hexrays.m_mov,
        0xF1C0008C,
        left=_Operand(ida_hexrays.mop_n, value=state),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    lowered_block = _Block(0, 0x40C8B0, (lowered_write,), (1,))
    lowered = _MBA((lowered_block,), entry_ea=0x40C8B0)
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    monkeypatch.setattr(
        detached_handler_island,
        "_native_instruction_stack_frame_offsets",
        lambda _function_ea, instruction_ea: (
            (stable_ida_stkoff,) if int(instruction_ea) == carrier_ea else ()
        ),
    )
    detached_handler_island.clear_terminal_return_carrier_templates()
    try:
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40C8B0,
            request,
            snippet,
        )
        assert (
            detached_handler_island.restore_terminal_return_carriers(
                lowered,
                0x40C8B0,
            )
            == 1
        )

        _state_write, restored = lowered_block.instructions()
        assert int(restored.ea) == carrier_ea
        assert int(restored.l.t) == int(ida_hexrays.mop_S)
        assert int(restored.l.s.off) == int(lowered.stkoff_ida2vd(stable_ida_stkoff))
        assert int(restored.d.r) == return_mreg
    finally:
        detached_handler_island.clear_terminal_return_carrier_templates()


def test_replays_unique_terminal_carrier_into_equivalent_one_way_state_writer(
    monkeypatch,
) -> None:
    """An imported arm writing the same terminal state keeps the ABI result."""
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    native_write = _Instruction(
        ida_hexrays.m_mov,
        0x40C7E5,
        left=_Operand(ida_hexrays.mop_n, value=0x19A7218A),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    imported_write = _Instruction(
        ida_hexrays.m_mov,
        0xF10000,
        left=_Operand(ida_hexrays.mop_n, value=0x19A7218A),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    native = _Block(0, 0x40C7E5, (native_write,), (2,))
    imported = _Block(1, 0x40A560, (imported_write,), (2,))
    lowered = _MBA((native, imported))
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    detached_handler_island.clear_terminal_return_carrier_templates()
    try:
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            request,
            _terminal_return_carrier_snippet(),
        )

        assert (
            detached_handler_island.restore_terminal_return_carriers(
                lowered,
                0x40A560,
            )
            == 2
        )

        _state_write, carrier = imported.instructions()
        assert int(carrier.ea) == 0x40C7EA
        assert int(carrier.l.t) == int(ida_hexrays.mop_v)
        assert int(carrier.l.g) == 0x48B8A4
        assert int(carrier.d.r) == int(ida_hexrays.reg2mreg(0))
    finally:
        detached_handler_island.clear_terminal_return_carrier_templates()


def test_terminal_return_carrier_replay_abstains_when_state_proof_drifted(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    detached_handler_island.clear_terminal_return_carrier_templates()
    try:
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            request,
            _terminal_return_carrier_snippet(),
        )
        lowered, block = _terminal_return_live_mba(state=0xDEADBEEF)

        assert (
            detached_handler_island.restore_terminal_return_carriers(
                lowered,
                0x40A560,
            )
            == 0
        )
        assert len(block.instructions()) == 1
    finally:
        detached_handler_island.clear_terminal_return_carrier_templates()


def test_terminal_return_carrier_replay_abstains_on_multiple_state_writes(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    first_write = _Instruction(
        ida_hexrays.m_mov,
        0xF10000,
        left=_Operand(ida_hexrays.mop_n, value=0x19A7218A),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    second_write = _Instruction(
        ida_hexrays.m_mov,
        0xF10004,
        left=_Operand(ida_hexrays.mop_n, value=0x19A7218A),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    block = _Block(0, 0x40A560, (first_write, second_write), (1,))
    lowered = _MBA((block,))
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    detached_handler_island.clear_terminal_return_carrier_templates()
    try:
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            request,
            _terminal_return_carrier_snippet(),
        )

        assert (
            detached_handler_island.restore_terminal_return_carriers(
                lowered,
                0x40A560,
            )
            == 0
        )
        assert block.instructions() == (first_write, second_write)
    finally:
        detached_handler_island.clear_terminal_return_carrier_templates()


def test_terminal_return_carrier_replay_abstains_on_ambiguous_terminal_identity(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    first_request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    second_request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40D120,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    imported_write = _Instruction(
        ida_hexrays.m_mov,
        0xF10000,
        left=_Operand(ida_hexrays.mop_n, value=0x19A7218A),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    block = _Block(0, 0x40A560, (imported_write,), (1,))
    lowered = _MBA((block,))
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    detached_handler_island.clear_terminal_return_carrier_templates()
    try:
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            first_request,
            _terminal_return_carrier_snippet(),
        )
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            second_request,
            _terminal_return_carrier_snippet(
                source_ea=0x40D120,
                carrier_ea=0x40D125,
            ),
        )

        assert (
            detached_handler_island.restore_terminal_return_carriers(
                lowered,
                0x40A560,
            )
            == 0
        )
        assert block.instructions() == (imported_write,)
    finally:
        detached_handler_island.clear_terminal_return_carrier_templates()


def test_terminal_return_carrier_replay_uses_imported_native_origin(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    terminal_target_ea = 0x40C898
    terminal_state = 0x19A7218A
    first_request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=terminal_target_ea,
        state_var_reg=20,
        state_constant=terminal_state,
    )
    second_request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40D120,
        terminal_target_ea=terminal_target_ea,
        state_var_reg=20,
        state_constant=terminal_state,
    )
    imported_write_ea = 0xF10000
    imported_write = _Instruction(
        ida_hexrays.m_mov,
        imported_write_ea,
        left=_Operand(ida_hexrays.mop_n, value=terminal_state),
        dest=_Operand(ida_hexrays.mop_r, register=20),
    )
    block = _Block(0, 0x40A560, (imported_write,), (1,))
    lowered = _MBA((block,))
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    detached_handler_island.clear_terminal_return_carrier_templates()
    detached_handler_island.clear_imported_detached_snippet_roots()
    try:
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            first_request,
            _terminal_return_carrier_snippet(),
        )
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            second_request,
            _terminal_return_carrier_snippet(
                source_ea=second_request.source_handler_ea,
                carrier_ea=0x40D125,
            ),
        )
        detached_handler_island._IMPORTED_INSTRUCTION_ORIGINS[
            (detached_handler_island.stable_mba_identity(lowered), imported_write_ea)
        ] = first_request.source_handler_ea

        assert (
            detached_handler_island.restore_terminal_return_carriers(
                lowered,
                0x40A560,
            )
            == 1
        )
        _state_write, carrier = block.instructions()
        assert int(carrier.ea) == 0x40C7EA
    finally:
        detached_handler_island.clear_terminal_return_carrier_templates()
        detached_handler_island.clear_imported_detached_snippet_roots()


def test_refines_guessed_void_return_type_from_proven_carrier_width(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        TerminalReturnCarrierRequest,
    )
    from d810.hexrays.mutation import detached_handler_island

    class _ReturnType:
        def __init__(self, declaration: int) -> None:
            self.declaration = int(declaration)

        def get_size(self) -> int:
            return 4

    class _VoidType:
        def is_void(self) -> bool:
            return True

    class _FunctionType:
        def __init__(self) -> None:
            self.return_type: _ReturnType | None = None

        def is_func(self) -> bool:
            return True

        def get_rettype(self) -> _VoidType:
            return _VoidType()

        def set_func_rettype(self, return_type: _ReturnType) -> int:
            self.return_type = return_type
            return int(detached_handler_island.ida_typeinf.TERR_OK)

    request = TerminalReturnCarrierRequest(
        source_handler_ea=0x40C7E5,
        terminal_target_ea=0x40C898,
        state_var_reg=20,
        state_constant=0x19A7218A,
    )
    function_type = _FunctionType()
    mba = SimpleNamespace(final_type=False, idb_type=function_type)
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    monkeypatch.setattr(
        detached_handler_island.ida_typeinf,
        "tinfo_t",
        _ReturnType,
    )
    detached_handler_island.clear_terminal_return_carrier_templates()
    try:
        assert detached_handler_island.capture_terminal_return_carrier_template(
            0x40A560,
            request,
            _terminal_return_carrier_snippet(),
        )

        assert detached_handler_island.refine_transient_terminal_return_type(
            mba,
            0x40A560,
        )
        assert function_type.return_type is not None
        assert function_type.return_type.declaration == (
            int(detached_handler_island.ida_typeinf.BT_INT32)
            | int(detached_handler_island.ida_typeinf.BTMT_UNKSIGN)
        )
        assert mba.final_type is True
    finally:
        detached_handler_island.clear_terminal_return_carrier_templates()


def test_does_not_refine_user_final_return_type(monkeypatch) -> None:
    from d810.hexrays.mutation import detached_handler_island

    mba = SimpleNamespace(final_type=True, idb_type=object())
    monkeypatch.setattr(
        detached_handler_island.ida_typeinf,
        "tinfo_t",
        lambda _declaration: pytest.fail("final type must not be replaced"),
    )

    assert not detached_handler_island.refine_transient_terminal_return_type(
        mba,
        0x40A560,
    )


def test_detached_target_lookup_accepts_live_block_start_anchor() -> None:
    from d810.hexrays.mutation import detached_handler_island

    block = _Block(
        0,
        0x40B8E6,
        (_Instruction(ida_hexrays.m_mov, 0x40B8ED),),
        (),
    )

    assert detached_handler_island._blocks_containing_ea(
        _MBA((block,)),
        0x40B8E6,
    ) == (block,)


def test_materializes_arm_state_register_write(monkeypatch) -> None:
    from d810.hexrays.mutation import deferred_modifier

    monkeypatch.setattr(deferred_modifier.ida_hexrays, "minsn_t", _fake_minsn)
    modifier = deferred_modifier.DeferredGraphModifier(
        SimpleNamespace(entry_ea=0x40A560)
    )

    assignment = modifier._materialize_register_state_write(
        ea=0x40B2B1,
        state_register=20,
        state_size=4,
        state_value=0xA5540595,
    )

    assert int(assignment.opcode) == int(ida_hexrays.m_mov)
    assert int(assignment.l.t) == int(ida_hexrays.mop_n)
    assert int(assignment.l.nnn.value) == 0xA5540595
    assert int(assignment.l.size) == 4
    assert int(assignment.d.t) == int(ida_hexrays.mop_r)
    assert int(assignment.d.r) == 20
    assert int(assignment.d.size) == 4


def test_locopt_hook_continues_after_preanalysis_modifies_microcode() -> None:
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
    from d810.core.decompilation_session import DecompilationEvent

    mba = SimpleNamespace(entry_ea=0x40A560)
    events: list[object] = []

    def callback(event: object, **kwargs: object) -> None:
        assert event is DecompilationEvent.HEXRAYS_LOCOPT_READY
        assert kwargs["function_ea"] == 0x40A560
        assert kwargs["mba"] is mba
        decision = kwargs["decision"]
        assert decision == {"request_redo": False}
        decision["microcode_modified"] = True
        decision["details"] = {"imported_snippets": 1}
        events.append(event)

    hook = SimpleNamespace(callback=callback)

    assert HexraysDecompilationHook.locopt(hook, mba) == 0
    assert events == [DecompilationEvent.HEXRAYS_LOCOPT_READY]


def test_preoptimized_hook_dispatches_live_mba_before_locopt() -> None:
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
    from d810.core.decompilation_session import DecompilationEvent

    mba = SimpleNamespace(entry_ea=0x40A560)
    events: list[object] = []

    def callback(event: object, **kwargs: object) -> None:
        assert event is DecompilationEvent.HEXRAYS_PREOPT_READY
        assert kwargs["function_ea"] == 0x40A560
        assert kwargs["mba"] is mba
        decision = kwargs["decision"]
        assert decision == {"request_redo": False}
        decision["microcode_modified"] = True
        decision["details"] = {"terminal_return_carriers": 1}
        events.append(event)

    hook = SimpleNamespace(callback=callback)

    assert HexraysDecompilationHook.preoptimized(hook, mba) == 0
    assert events == [DecompilationEvent.HEXRAYS_PREOPT_READY]


def test_preoptimized_hook_owns_top_level_structural_mutation() -> None:
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
    from d810.core.decompilation_session import DecompilationEvent

    mba = SimpleNamespace(entry_ea=0x40A560, maturity=1)
    session = SimpleNamespace(native_preanalysis_depth=0)
    identity_index = object()
    mutation_gateway = object()
    materializer = object()
    lifecycle_calls: list[tuple[object, ...]] = []
    events: list[object] = []
    lifecycle = SimpleNamespace(
        ensure_hexrays_session=lambda **kwargs: (session, False),
        current_session=lambda function_ea: session,
        build_current_mba_identity_index=lambda **kwargs: identity_index,
        new_current_mba_mutation_gateway=lambda **kwargs: mutation_gateway,
        new_semantic_native_body_materializer=lambda **kwargs: materializer,
        preopt_ready_was_emitted=lambda **kwargs: False,
        mark_preopt_ready_emitted=lambda **kwargs: lifecycle_calls.append(
            (
                "mark",
                int(kwargs["function_ea"]),
                bool(kwargs["microcode_modified"]),
                bool(kwargs["callback_pointer_refresh_required"]),
            )
        ),
    )

    def callback(event: object, **kwargs: object) -> None:
        events.append((event, kwargs))
        kwargs["decision"]["microcode_modified"] = True

    hook = SimpleNamespace(
        callback=callback,
        _decompilation_lifecycle=lifecycle,
        _database_identity="sample.i64",
    )

    assert HexraysDecompilationHook.preoptimized(hook, mba) == 0
    assert events == [
        (
            DecompilationEvent.HEXRAYS_PREOPT_READY,
            {
                "function_ea": 0x40A560,
                "mba": mba,
                "decision": {
                    "request_redo": False,
                    "session": session,
                    "identity_index": identity_index,
                    "mutation_gateway": mutation_gateway,
                    "semantic_native_body_materializer": materializer,
                    "microcode_modified": True,
                },
            },
        )
    ]
    assert lifecycle_calls == [("mark", 0x40A560, True, False)]


def test_preoptimized_hook_suppresses_manager_native_preanalysis_snippet() -> None:
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook

    mba = SimpleNamespace(entry_ea=0x40D48E, maturity=1)
    session = SimpleNamespace(
        native_preanalysis_depth=1,
        native_preanalysis=NativePreanalysisSessionState(),
        native_key=NATIVE_KEY,
        resolver_attachment=None,
        identity_key="sample.i64:0x40D48E:1",
    )
    events: list[object] = []
    lifecycle = SimpleNamespace(
        ensure_hexrays_session=lambda **kwargs: (session, False),
        current_session=lambda function_ea: session,
        build_current_mba_identity_index=lambda **kwargs: object(),
        new_current_mba_mutation_gateway=lambda **kwargs: object(),
        preopt_ready_was_emitted=lambda **kwargs: False,
        mark_preopt_ready_emitted=lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("internal snippet marked the public PREOPT generation")
        ),
    )
    hook = SimpleNamespace(
        callback=lambda *args, **kwargs: events.append((args, kwargs)),
        _decompilation_lifecycle=lifecycle,
        _database_identity="sample.i64",
    )

    assert HexraysDecompilationHook.preoptimized(hook, mba) == 0
    assert events == []


def test_preoptimized_hook_returns_success_when_microcode_is_unchanged() -> None:
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook

    mba = SimpleNamespace(entry_ea=0x40A560)
    hook = SimpleNamespace(callback=lambda event, **kwargs: None)

    assert HexraysDecompilationHook.preoptimized(hook, mba) == 0


def test_hexrays_hooks_own_the_preopt_generation_guard() -> None:
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
    from d810.core.decompilation_session import DecompilationEvent

    mba = SimpleNamespace(entry_ea=0x40A560)
    lifecycle_calls: list[tuple[str, int]] = []
    lifecycle = SimpleNamespace(
        begin_current_mba_generation=lambda *, function_ea: lifecycle_calls.append(
            ("begin", function_ea)
        ),
        mark_preopt_ready_emitted=(
            lambda *, function_ea, microcode_modified, callback_pointer_refresh_required: lifecycle_calls.append(
                (
                    "preopt",
                    function_ea,
                    microcode_modified,
                    callback_pointer_refresh_required,
                )
            )
        ),
    )

    def callback(event: object, **kwargs: object) -> None:
        assert event in {
            DecompilationEvent.HEXRAYS_FLOWCHART_READY,
            DecompilationEvent.HEXRAYS_PREOPT_READY,
        }

    hook = SimpleNamespace(
        callback=callback,
        _decompilation_lifecycle=lifecycle,
    )

    assert HexraysDecompilationHook.flowchart(hook, object(), mba, object(), 0) == 0
    assert HexraysDecompilationHook.preoptimized(hook, mba) == 0
    assert lifecycle_calls == [
        ("begin", 0x40A560),
        ("preopt", 0x40A560, False, False),
    ]


def test_flowchart_hook_scopes_active_lifecycle_session_into_decision() -> None:
    """Flowchart lazily creates and scopes one coordinator-owned session."""
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
    from d810.core.decompilation_session import DecompilationEvent

    mba = SimpleNamespace(entry_ea=0x40D200)
    session = SimpleNamespace(event=object())
    identity_index = object()
    ensured: list[tuple[int, str, int | None]] = []
    queried_function_eas: list[int] = []

    def current_session(function_ea: int) -> object:
        queried_function_eas.append(function_ea)
        return session

    def ensure_hexrays_session(
        *,
        function_ea: int,
        database_identity: str,
        callback_entry_ea: int | None,
    ) -> tuple[object, bool]:
        ensured.append((function_ea, database_identity, callback_entry_ea))
        return session, len(ensured) == 1

    events: list[object] = []

    def callback(event: object, *args: object, **kwargs: object) -> None:
        events.append(event)
        assert args == ()
        assert event is DecompilationEvent.HEXRAYS_FLOWCHART_READY
        assert kwargs["function_ea"] == 0x40D200
        assert kwargs["mba"] is mba
        assert kwargs["decision"] == {
            "request_redo": False,
            "session": session,
        }

    hook = SimpleNamespace(
        callback=callback,
        _decompilation_lifecycle=SimpleNamespace(
            ensure_hexrays_session=ensure_hexrays_session,
            current_session=current_session,
            build_current_mba_identity_index=lambda **kwargs: (
                identity_index
                if kwargs == {"function_ea": 0x40D200, "mba": mba}
                else None
            ),
        ),
    )

    assert HexraysDecompilationHook.flowchart(hook, object(), mba, object(), 0) == 0
    assert HexraysDecompilationHook.flowchart(hook, object(), mba, object(), 0) == 0
    assert ensured == [
        (0x40D200, "", None),
        (0x40D200, "", None),
    ]
    assert queried_function_eas == [0x40D200, 0x40D200]
    assert events == [
        DecompilationEvent.HEXRAYS_FLOWCHART_READY,
        DecompilationEvent.HEXRAYS_FLOWCHART_READY,
    ]


def test_flowchart_hook_uses_containing_function_as_lifecycle_owner(
    monkeypatch,
) -> None:
    """An internal MBA entry must not create a second function session."""
    import d810.hexrays.hooks.hexrays_hooks as hook_module
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
    from d810.core.decompilation_session import DecompilationEvent

    mba = SimpleNamespace(entry_ea=0x40D348)
    session = SimpleNamespace(event=object())
    ensured: list[int] = []
    emitted_function_eas: list[int] = []
    monkeypatch.setattr(
        hook_module.idaapi,
        "get_func",
        lambda ea: SimpleNamespace(start_ea=0x40D200) if ea == 0x40D348 else None,
    )

    def callback(event: object, *args: object, **kwargs: object) -> None:
        if event is DecompilationEvent.SESSION_STARTED:
            return
        emitted_function_eas.append(int(kwargs["function_ea"]))

    hook = SimpleNamespace(
        callback=callback,
        _decompilation_lifecycle=SimpleNamespace(
            ensure_hexrays_session=lambda *, function_ea, database_identity, callback_entry_ea: (
                ensured.append(function_ea) or session,
                False,
            ),
            current_session=lambda function_ea: (
                session if function_ea == 0x40D200 else None
            ),
        ),
    )

    assert HexraysDecompilationHook.flowchart(hook, object(), mba, object(), 0) == 0
    assert ensured == [0x40D200]
    assert emitted_function_eas == [0x40D200]


def test_stkpnts_hook_dispatches_transient_stack_points() -> None:
    from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
    from d810.core.decompilation_session import DecompilationEvent

    mba = SimpleNamespace(entry_ea=0x40A560)
    stack_points = object()
    events: list[object] = []

    def callback(event: object, **kwargs: object) -> None:
        assert event is DecompilationEvent.HEXRAYS_STKPNTS
        assert kwargs == {
            "function_ea": 0x40A560,
            "mba": mba,
            "stack_points": stack_points,
            "decision": {"request_redo": False},
        }
        events.append(event)

    hook = SimpleNamespace(callback=callback)

    assert HexraysDecompilationHook.stkpnts(hook, mba, stack_points) == 0
    assert events == [DecompilationEvent.HEXRAYS_STKPNTS]


def test_detached_island_uses_standalone_predicate_fork_topology(
    monkeypatch,
) -> None:
    from d810.analyses.control_flow.detached_handler_island import (
        DetachedHandlerIslandPlan,
    )
    from d810.hexrays.mutation import detached_handler_island
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier

    source = _Block(
        0,
        0x40C586,
        (_Instruction(ida_hexrays.m_jnz, 0x40C5D1),),
        (1, 2),
    )
    false_handler = _Block(
        1,
        0x40BCA3,
        (_Instruction(ida_hexrays.m_goto, 0x40BCBA),),
        (),
    )
    true_handler = _Block(
        2,
        0x40B74C,
        (_Instruction(ida_hexrays.m_jnz, 0x40B765),),
        (),
    )
    mba = _MBA((source, false_handler, true_handler))
    argument = _Operand(ida_hexrays.mop_S, stack_offset=0xD0)
    call = _Instruction(
        ida_hexrays.m_call,
        0x40A7B5,
        left=_Operand(ida_hexrays.mop_v, target_ea=0x41E4AB),
        dest=_Operand(ida_hexrays.mop_f),
    )
    call.d.f = SimpleNamespace(args=[argument])
    plan = DetachedHandlerIslandPlan(
        source_predicate_ea=0x40C5D1,
        detached_entry_ea=0x40A7AE,
        detached_end_ea=0x40A7CD,
        call_target_ea=0x41E4AB,
        call_argument_ida_stkoff=0xCC,
        predicate_ida_stkoff=0x1C,
        state_register=20,
        false_state=0xB34CE2DF,
        true_state=0x82F1899D,
        false_target_ea=0x40BCA3,
        true_target_ea=0x40B74C,
    )
    inserted: list[int] = []
    standalone: list[tuple[int, bool, tuple[int, ...]]] = []
    next_serial = 3

    def find(_mba: object, ea: int) -> _Block | None:
        return {
            0x40C5D1: source,
            0x40BCA3: false_handler,
            0x40B74C: true_handler,
        }.get(int(ea))

    def append_block(block: _Block) -> None:
        mba.blocks += (block,)
        mba.qty += 1

    def insert(
        _modifier: DeferredGraphModifier,
        source_serial: int,
    ) -> int:
        nonlocal next_serial
        inserted.append(int(source_serial))
        block = _Block(
            next_serial,
            0x40C5D1,
            (_Instruction(ida_hexrays.m_nop, 0x40C5D1),),
            (),
        )
        append_block(block)
        next_serial += 1
        return int(block.serial)

    def create(
        _modifier: DeferredGraphModifier,
        *,
        ref_serial: int,
        blk_ins: list[_Instruction] | tuple[_Instruction, ...] | None = None,
        target_serial: int | None = None,
        is_0_way: bool = False,
        verify: bool = True,
    ) -> int:
        del target_serial
        assert verify is False
        nonlocal next_serial
        instructions = tuple(blk_ins or ())
        standalone.append(
            (
                int(ref_serial),
                bool(is_0_way),
                tuple(int(instruction.opcode) for instruction in instructions),
            )
        )
        body = tuple(instructions) or (_Instruction(ida_hexrays.m_nop, 0x40C5D1),)
        block = _Block(next_serial, 0x40C5D1, body, ())
        append_block(block)
        next_serial += 1
        return int(block.serial)

    monkeypatch.setattr(detached_handler_island, "find_unique_live_block_by_ea", find)
    monkeypatch.setattr(
        detached_handler_island,
        "_unique_call_template",
        lambda _mba, _function_ea, _callee_ea: SimpleNamespace(
            instruction=call,
            argument_size=4,
        ),
    )
    monkeypatch.setattr(detached_handler_island.ida_hexrays, "minsn_t", _fake_minsn)
    monkeypatch.setattr(
        DeferredGraphModifier,
        "insert_nop_block_now",
        insert,
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "create_standalone_block",
        create,
    )
    monkeypatch.setattr(
        DeferredGraphModifier,
        "redirect_one_way_now",
        lambda _modifier, _source, _target, verify=False: True,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_remove_all_instructions",
        lambda _modifier, _block: None,
    )
    monkeypatch.setattr(
        detached_handler_island,
        "_remove_nops",
        lambda _modifier, _block: None,
    )

    assert detached_handler_island.materialize_detached_handler_island(
        mba,
        plan,
        mutation_gateway=make_mutation_gateway(mba),
    )
    assert inserted == [source.serial]
    assert standalone == [
        (source.serial, False, (ida_hexrays.m_mov,)),
        (source.serial, True, (ida_hexrays.m_mov,)),
        (source.serial, False, ()),
    ]
