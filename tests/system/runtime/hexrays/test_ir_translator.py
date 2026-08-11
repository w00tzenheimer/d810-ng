"""Tests for IDAIRTranslator.

System-level integration tests that verify IDAIRTranslator remains the private
final-boundary lowering adapter behind the public PatchPlan runtime port.

Runs in IDA environment (system/runtime); skips gracefully without IDA.
"""

from __future__ import annotations

import importlib
import platform
from dataclasses import dataclass, fields, is_dataclass, replace
from types import SimpleNamespace

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.core.events import EventEmitter
from d810.hexrays.mutation.mba_mutation_events import (
    MbaCfgTransactionAuthorityObserved,
    MbaMutationCommitted,
)
from d810.ir.flowgraph import (
    PredicateKind,
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    OperandKind,
)
from d810.ir.expressions import ValueOpKind
from d810.ir.maturity import MaturityEnvelope
from d810.transforms.graph_modification import (
    CloneConditionalAsGoto,
    CreateConditionalRedirect,
    DuplicateReplayAndRedirect,
    DuplicateReplayEntry,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    RedirectBranch,
    RedirectGoto,
    RemoveEdge,
)
from d810.transforms.plan import (
    ExecutionPolicy,
    PatchDuplicateBlock,
    PatchDuplicateReplayAndRedirect,
    PatchInsertBlock,
    PatchBlockSpec,
    PatchNopInstructions,
    PatchPlan,
    PatchRedirectBranch,
    PatchRedirectGoto,
    compile_patch_plan,
)
from d810.transforms.cfg_transaction import (
    CfgProjection,
    CfgTransactionPhase,
    LogicalBlockRef,
    PlanBlockRef,
    PreparedCfgTransaction,
    TransactionAttemptId,
)
from d810.transforms.materialization_payload import (
    CapturedBlockBody,
    CapturedBlockBodySummary,
)
from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.hexrays.ir.mba_identity_index import BlockHandleProvenance
from d810.hexrays.mutation.patch_binding import (
    PatchBindingRejected,
    bind_patch_plan,
)
from d810.hexrays.mutation.patch_transaction import BoundPatchCfgTransaction
from d810.hexrays.mutation.ir_translator import (
    _build_lvar_stkoff_map,
    _branch_predicate_only_from_hexrays,
    _block_kind_from_hexrays,
    _insn_kind_from_hexrays,
    _operand_kind_from_hexrays,
    capture_mop_snapshot,
)
from tests.system.runtime.mutation_gateway import make_mutation_gateway


_DEFAULT_TEST_BINARY = (
    "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
)
_TEST_MATURITY = MaturityEnvelope(ir=None, provider="hexrays", provider_id=4)
_MANUAL_PLAN_ID = "system-ir-translator"
_MANUAL_SNAPSHOT_ID = "system-ir-translator:m4:g0"
_MANUAL_SESSION_ID = "system-ir-translator-session"
_MANUAL_COORDINATES: dict[LogicalBlockRef, int] = {}


def _manual_ref(serial: int) -> LogicalBlockRef:
    ref = LogicalBlockRef(_MANUAL_SESSION_ID, f"logical:{serial}", 0)
    _MANUAL_COORDINATES[ref] = serial
    return ref


def _manual_plan(*steps, execution_policy=ExecutionPolicy.STRICT) -> PatchPlan:
    refs: list[LogicalBlockRef] = []

    def collect(value: object) -> None:
        if isinstance(value, LogicalBlockRef):
            if value not in refs:
                refs.append(value)
            return
        if is_dataclass(value):
            for field in fields(value):
                collect(getattr(value, field.name))
            return
        if isinstance(value, (tuple, list, set, frozenset)):
            for item in value:
                collect(item)
            return
        if isinstance(value, dict):
            for key, item in value.items():
                collect(key)
                collect(item)

    collect(steps)
    return PatchPlan(
        plan_id=_MANUAL_PLAN_ID,
        snapshot_id=_MANUAL_SNAPSHOT_ID,
        source_maturity=_TEST_MATURITY,
        source_generation=0,
        steps=tuple(steps),
        execution_policy=execution_policy,
        source_coordinates=tuple((ref, _MANUAL_COORDINATES[ref]) for ref in refs),
    )


class _FakeLocation:
    def __init__(self, *, stack_offset: int | None) -> None:
        self.stack_offset = stack_offset
        self.stkoff_called = False

    def is_stkoff(self) -> bool:
        return self.stack_offset is not None

    def stkoff(self) -> int:
        self.stkoff_called = True
        if self.stack_offset is None:
            raise AssertionError("stkoff() must not be called for non-stack locations")
        return int(self.stack_offset)


class _FakeVars:
    def __init__(self, locations: tuple[_FakeLocation, ...]) -> None:
        self.size_called = False
        self.values = tuple(
            SimpleNamespace(location=location) for location in locations
        )

    def size(self) -> int:
        self.size_called = True
        return len(self.values)

    def __getitem__(self, index: int) -> object:
        return self.values[index]


def test_lvar_stkoff_map_checks_location_kind_before_reading_offset() -> None:
    non_stack = _FakeLocation(stack_offset=None)
    stack = _FakeLocation(stack_offset=0x38)
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_LVARS,
        vars=_FakeVars((non_stack, stack)),
    )

    assert _build_lvar_stkoff_map(mba) == {1: 0x38}
    assert not non_stack.stkoff_called
    assert stack.stkoff_called


def test_lvar_stkoff_map_does_not_touch_lvars_before_lvar_maturity() -> None:
    variables = _FakeVars((_FakeLocation(stack_offset=0x38),))
    mba = SimpleNamespace(
        maturity=ida_hexrays.MMAT_CALLS,
        vars=variables,
    )

    assert _build_lvar_stkoff_map(mba) == {}
    assert not variables.size_called


@dataclass(frozen=True)
class _BlockRef:
    block_num: int


def _block(
    serial: int, succs: tuple[int, ...], preds: tuple[int, ...]
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0,
        insn_snapshots=(),
    )


def _cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            2: _block(2, (), (45,)),
            44: _block(44, (45,), ()),
            122: _block(122, (45,), ()),
            45: _block(45, (2,), (44, 122)),
            199: _block(199, (), ()),
        },
        entry_serial=44,
        func_ea=0,
    )


def _corridor_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            44: _block(44, (45,), ()),
            45: _block(45, (46,), (44,)),
            46: _block(46, (2,), (45,)),
            2: _block(2, (), (46,)),
        },
        entry_serial=44,
        func_ea=0,
    )


def test_hexrays_enum_values_map_to_cfg_semantic_kinds():
    assert _block_kind_from_hexrays(ida_hexrays.BLT_2WAY) == BlockKind.TWO_WAY
    assert _block_kind_from_hexrays(ida_hexrays.BLT_1WAY) == BlockKind.ONE_WAY
    assert _insn_kind_from_hexrays(ida_hexrays.m_goto) == InsnKind.GOTO
    assert _insn_kind_from_hexrays(ida_hexrays.m_sub) == InsnKind.SUB
    assert _insn_kind_from_hexrays(ida_hexrays.m_stx) == InsnKind.STORE
    assert _insn_kind_from_hexrays(ida_hexrays.m_xds) == InsnKind.XDS
    assert _insn_kind_from_hexrays(ida_hexrays.m_ret) == InsnKind.RET
    assert _insn_kind_from_hexrays(ida_hexrays.m_jnz) == InsnKind.EQUALITY_JUMP
    assert _insn_kind_from_hexrays(ida_hexrays.m_jcnd) == InsnKind.COND_JUMP
    # E3-prep: ``m_jtbl`` lands in portable ``TABLE_JUMP`` so
    # dispatcher analyses can detect switch-table-style tails
    # without reaching for vendor opcode constants.
    assert _insn_kind_from_hexrays(ida_hexrays.m_jtbl) == InsnKind.TABLE_JUMP
    assert _operand_kind_from_hexrays(ida_hexrays.mop_b) == OperandKind.BLOCK
    assert _operand_kind_from_hexrays(ida_hexrays.mop_n) == OperandKind.NUMBER
    assert _operand_kind_from_hexrays(ida_hexrays.mop_S) == OperandKind.STACK


def test_table_jump_kind_distinct_from_other_jump_kinds():
    """E3-prep regression cover: ``m_jtbl`` MUST NOT collapse into
    ``GOTO`` / ``COND_JUMP`` / ``EQUALITY_JUMP``.  If a future edit
    to ``_insn_kind_from_hexrays`` accidentally sweeps ``m_jtbl``
    into one of those branches (e.g. by expanding the predicate
    helper), this test catches it."""
    table_jump = _insn_kind_from_hexrays(ida_hexrays.m_jtbl)
    assert table_jump is InsnKind.TABLE_JUMP
    assert table_jump is not InsnKind.GOTO
    assert table_jump is not InsnKind.COND_JUMP
    assert table_jump is not InsnKind.EQUALITY_JUMP
    assert table_jump is not InsnKind.UNKNOWN


def test_capture_mop_snapshot_preserves_switch_case_rows():
    """Switch-table prep: carry mcases values/targets into portable cfg."""
    mop = SimpleNamespace(
        t=ida_hexrays.mop_c,
        size=0,
        c=SimpleNamespace(
            values=((0, 1), (), (0xFFFFFFFFFFFFFFFF,)),
            targets=(10, 99, 12),
        ),
    )

    snapshot = capture_mop_snapshot(mop)

    assert snapshot is not None
    assert snapshot.kind is OperandKind.CASE_LIST
    assert snapshot.switch_cases == (
        ((0, 1), 10),
        ((), 99),
        ((0xFFFFFFFFFFFFFFFF,), 12),
    )


def test_capture_mop_snapshot_preserves_nested_stack_refs():
    """Switch-table prep: nested dispatch expressions expose state refs."""
    stack_mop = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=0x38),
    )
    const_mop = SimpleNamespace(
        t=ida_hexrays.mop_n,
        size=4,
        nnn=SimpleNamespace(value=0xF),
    )
    nested_expr = SimpleNamespace(
        t=ida_hexrays.mop_d,
        size=4,
        d=SimpleNamespace(l=stack_mop, r=const_mop, d=stack_mop),
    )

    direct_snapshot = capture_mop_snapshot(stack_mop)
    nested_snapshot = capture_mop_snapshot(nested_expr)

    assert direct_snapshot is not None
    assert direct_snapshot.stack_refs == (0x38,)
    assert nested_snapshot is not None
    assert nested_snapshot.kind is OperandKind.SUBINSN
    assert nested_snapshot.stack_refs == (0x38,)


def test_capture_mop_snapshot_preserves_nested_value_op_kind():
    left_mop = SimpleNamespace(
        t=ida_hexrays.mop_S,
        size=4,
        s=SimpleNamespace(off=0x38),
    )
    right_mop = SimpleNamespace(
        t=ida_hexrays.mop_n,
        size=4,
        nnn=SimpleNamespace(value=0xF),
    )
    nested_expr = SimpleNamespace(
        t=ida_hexrays.mop_d,
        size=4,
        d=SimpleNamespace(opcode=ida_hexrays.m_xor, l=left_mop, r=right_mop),
    )

    nested_snapshot = capture_mop_snapshot(nested_expr)

    assert nested_snapshot is not None
    assert nested_snapshot.kind is OperandKind.SUBINSN
    assert nested_snapshot.sub_value_op_kind is ValueOpKind.XOR
    assert nested_snapshot.sub_l is not None
    assert nested_snapshot.sub_l.stack_refs == (0x38,)


def test_hexrays_branch_opcodes_map_to_backend_neutral_predicates():
    assert _branch_predicate_only_from_hexrays(ida_hexrays.m_jnz) is (PredicateKind.NE)
    assert _branch_predicate_only_from_hexrays(ida_hexrays.m_jz) is PredicateKind.EQ
    assert _branch_predicate_only_from_hexrays(ida_hexrays.m_jae) is (PredicateKind.UGE)
    assert _branch_predicate_only_from_hexrays(ida_hexrays.m_jb) is (PredicateKind.ULT)
    assert _branch_predicate_only_from_hexrays(ida_hexrays.m_jg) is (PredicateKind.SGT)
    assert _branch_predicate_only_from_hexrays(ida_hexrays.m_jle) is (PredicateKind.SLE)


def _conditional_duplicate_cfg() -> FlowGraph:
    return FlowGraph(
        blocks={
            2: _block(2, (), (45,)),
            3: _block(3, (), (45,)),
            44: _block(44, (45,), ()),
            122: _block(122, (45,), ()),
            45: BlockSnapshot(
                serial=45,
                block_type=2,
                succs=(2, 3),
                preds=(44, 122),
                flags=0,
                start_ea=0,
                insn_snapshots=(
                    InsnSnapshot(
                        opcode=0x70,
                        ea=0x1010,
                        operands=(_BlockRef(2),),
                        operand_slots=(("d", _BlockRef(2)),),
                    ),
                ),
            ),
            199: _block(199, (), ()),
        },
        entry_serial=44,
        func_ea=0,
    )


def _captured_body(
    source_serial: int = 45,
    *,
    contains_call: bool = False,
) -> CapturedBlockBody:
    instructions = (InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0, operands=()),)
    return CapturedBlockBody(
        backend_id="hexrays.insn_snapshot",
        capture_id=f"translator-test:{source_serial}",
        summary=CapturedBlockBodySummary(
            source_blocks=(source_serial,),
            instruction_count=len(instructions),
            source_eas=frozenset(),
            contains_call=contains_call,
        ),
        payload=instructions,
    )


def _get_real_mba():
    import idaapi
    import idc

    test_functions = (
        "abc_xor_dispatch",
        "abc_or_dispatch",
        "nested_simple",
        "test_cst_simplification",
        "test_xor",
        "test_mba_guessing",
        "test_chained_add",
    )

    for func_name in test_functions:
        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea == idaapi.BADADDR:
            func_ea = idc.get_name_ea_simple("_" + func_name)
        if func_ea == idaapi.BADADDR:
            continue

        func = idaapi.get_func(func_ea)
        if func is None:
            continue

        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            mbr,
            hf,
            None,
            ida_hexrays.DECOMP_NO_WAIT,
            ida_hexrays.MMAT_CALLS,
        )
        if mba is not None:
            return mba

    pytest.skip("No runtime mba_t available for InsertBlock lowering test")


def _find_insertable_edge(mba) -> tuple[int, int] | None:
    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        if blk.serial == 0:
            continue
        if blk.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            continue
        if blk.nsucc() != 1:
            continue
        return blk.serial, blk.succ(0)
    return None


def _find_duplicate_candidate(mba) -> tuple[int, int] | None:
    for i in range(mba.qty):
        source_blk = mba.get_mblock(i)
        if source_blk is None:
            continue
        if source_blk.serial == 0:
            continue
        if source_blk.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            continue
        if source_blk.nsucc() != 1:
            continue

        for pred_idx in range(source_blk.npred()):
            pred_serial = source_blk.pred(pred_idx)
            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None:
                continue
            if pred_blk.serial == 0:
                continue
            if (
                pred_blk.nsucc() == 1
                and pred_blk.succ(0) == source_blk.serial
                and source_blk.succ(0) != pred_blk.serial
            ):
                return pred_blk.serial, source_blk.serial
    return None


def _find_conditional_duplicate_candidate(mba) -> tuple[int, int] | None:
    for i in range(mba.qty):
        source_blk = mba.get_mblock(i)
        if source_blk is None:
            continue
        if source_blk.serial == 0:
            continue
        if source_blk.type in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP):
            continue
        if source_blk.nsucc() != 2:
            continue
        if source_blk.tail is None or not ida_hexrays.is_mcode_jcond(
            source_blk.tail.opcode
        ):
            continue

        for pred_idx in range(source_blk.npred()):
            pred_serial = source_blk.pred(pred_idx)
            pred_blk = mba.get_mblock(pred_serial)
            if pred_blk is None or pred_blk.serial == 0:
                continue
            if pred_blk.nsucc() == 1 and pred_blk.succ(0) == source_blk.serial:
                return pred_blk.serial, source_blk.serial
            if (
                pred_blk.nsucc() == 2
                and pred_blk.tail is not None
                and ida_hexrays.is_mcode_jcond(pred_blk.tail.opcode)
                and pred_blk.tail.d.t == ida_hexrays.mop_b
                and pred_blk.tail.d.b == source_blk.serial
            ):
                return pred_blk.serial, source_blk.serial
    return None


def _find_fallthrough_redirect_candidate(
    mba,
) -> tuple[int, int, int] | None:
    for i in range(mba.qty):
        block = mba.get_mblock(i)
        if (
            block is None
            or block.serial == 0
            or block.nsucc() != 2
            or block.tail is None
            or not ida_hexrays.is_mcode_jcond(block.tail.opcode)
            or block.tail.d.t != ida_hexrays.mop_b
        ):
            continue
        branch_target = int(block.tail.d.b)
        fallthrough = next(
            (
                int(block.succ(index))
                for index in range(2)
                if int(block.succ(index)) != branch_target
            ),
            None,
        )
        if fallthrough is None:
            continue
        for target in range(mba.qty - 1):
            target_block = mba.get_mblock(target)
            if (
                target not in {block.serial, branch_target, fallthrough}
                and target_block is not None
                and target_block.type
                not in (ida_hexrays.BLT_XTRN, ida_hexrays.BLT_STOP)
            ):
                return int(block.serial), fallthrough, target
    return None


def _created_serial(gateway: object, ref: PlanBlockRef) -> int:
    assert ref.plan_id
    matches = tuple(
        receipt
        for receipt in gateway.identity_index.plan_creation_receipts
        if receipt.plan_ref == ref
    )
    assert len(matches) == 1
    receipt = matches[0]
    assert receipt.attempt_id.plan_id == ref.plan_id
    return receipt.returned_serial


def _gateway_for_plan(plan: PatchPlan, mba: object | None = None):
    """Build a test gateway representing the plan's exact source snapshot."""
    assert plan.source_generation is not None
    assert plan.source_maturity is not None
    if mba is None or not hasattr(mba, "qty"):
        mba = SimpleNamespace(
            qty=512,
            maturity=plan.source_maturity.provider_id,
            entry_ea=0,
        )
    return make_mutation_gateway(
        mba,
        generation=plan.source_generation,
        snapshot_id=plan.snapshot_id,
        maturity=plan.source_maturity.provider_id,
        session_id=_MANUAL_SESSION_ID,
    )


def _lower(backend: IDAIRTranslator, plan: PatchPlan, mba: object) -> int:
    if not hasattr(mba, "qty"):
        snapshot_serials = {serial for _ref, serial in plan.source_coordinates}

        def collect(value: object) -> None:
            if is_dataclass(value):
                for field in fields(value):
                    collect(getattr(value, field.name))
            elif isinstance(value, (tuple, list, set, frozenset)):
                for item in value:
                    collect(item)
            elif isinstance(value, dict):
                for key, item in value.items():
                    collect(key)
                    collect(item)

        collect(plan)
        mba = SimpleNamespace(
            qty=max(snapshot_serials, default=-1) + 1,
            maturity=plan.source_maturity.provider_id,
            entry_ea=int(getattr(mba, "entry_ea", 0) or 0),
        )
    gateway = _gateway_for_plan(plan, mba)
    source_refs = {
        ref: gateway.identity_index.plan_ref_for_serial(serial)
        for ref, serial in plan.source_coordinates
    }

    def bind_source_refs(value: object) -> object:
        if isinstance(value, (LogicalBlockRef,)):
            return source_refs.get(value, value)
        if isinstance(value, tuple):
            return tuple(bind_source_refs(item) for item in value)
        if isinstance(value, list):
            return [bind_source_refs(item) for item in value]
        if isinstance(value, dict):
            return {
                bind_source_refs(key): bind_source_refs(item)
                for key, item in value.items()
            }
        if is_dataclass(value):
            return replace(
                value,
                **{
                    field.name: bind_source_refs(getattr(value, field.name))
                    for field in fields(value)
                },
            )
        return value

    bound_plan = replace(
        plan,
        steps=bind_source_refs(plan.steps),
        new_blocks=bind_source_refs(plan.new_blocks),
        relocation_map=bind_source_refs(plan.relocation_map),
        source_coordinates=tuple(
            (source_refs.get(ref, ref), serial)
            for ref, serial in plan.source_coordinates
        ),
    )
    return _lower_bound(backend, bound_plan, mba, gateway)


def _lower_bound(
    backend: IDAIRTranslator,
    plan: PatchPlan,
    mba: object,
    gateway: object,
) -> int:
    """Exercise translator lowering beneath the production participant seam."""
    child = gateway.new_transaction()
    attempt = TransactionAttemptId.new(
        plan.plan_id,
        child.session_id,
        child.generation,
    )
    quantity = max(int(getattr(mba, "qty", 0) or 0), 1)
    authority_graph = FlowGraph(
        blocks={serial: _block(serial, (), ()) for serial in range(quantity)},
        entry_serial=0,
        func_ea=int(getattr(mba, "entry_ea", 0) or 0),
    )
    projection = CfgProjection(
        plan_id=plan.plan_id,
        snapshot_id=plan.snapshot_id,
        graph=authority_graph,
    )
    prepared = PreparedCfgTransaction(
        attempt_id=attempt,
        projection=projection,
        obligation_ids=("translator_test_boundary",),
    )
    child._record_cfg_attempt_planned(
        plan_id=plan.plan_id,
        plan_refs=tuple(spec.block_id for spec in plan.new_blocks),
        attempt=attempt,
    )
    child._record_cfg_projected()
    child._record_cfg_preflighted()
    try:
        child._prepare_patch_binding(attempt, serial_quantity=int(mba.qty))
        binding = bind_patch_plan(plan, child.identity_index, attempt)
        child.register_patch_plan_reservations(binding.reservations)
        child._record_cfg_bound()
        bound = BoundPatchCfgTransaction(
            prepared=prepared,
            session_id=attempt.session_id,
            generation=attempt.generation,
            bindings=binding.bindings,
            plan=plan,
            patch_binding=binding,
        )
        result = backend.lower(
            plan,
            mba,
            mutation_gateway=child,
            bound_transaction=bound,
        )
    except Exception:
        if (
            child.current_transaction_attempt is not None
            and not child.generation_poisoned
        ):
            child.abort(reason="translator test boundary rejected")
        raise
    if result <= 0:
        if (
            child.current_transaction_attempt is not None
            and not child.generation_poisoned
        ):
            if child.transaction_failure is None:
                child._record_clean_cfg_failure(
                    reason="translator returned no applied operations",
                    failure_phase="lowering",
                    first_failed_obligation="runtime:lowering",
                )
            child.abort(reason="translator returned no applied operations")
        return result
    observed = (
        backend.lift(mba)
        if callable(getattr(mba, "get_mblock", None))
        else _FakeDeferredGraphModifier(mba).observe_live_graph()
    )
    child.observe_patch_realization(
        observed,
        applied_operation_count=len(plan.steps),
    )
    child.commit()
    return result


def test_queue_bound_patch_plan_resolves_current_transaction_authority_after_reload(
    monkeypatch,
) -> None:
    """A translator kept live across a module reload must not reject authority.

    The normal D810 reload lifecycle may refresh ``patch_transaction`` while a
    live translator still holds its former module-global import.  The current
    transaction type remains authoritative; the stale imported class does not.
    """
    import d810.hexrays.mutation.ir_translator as ir_translator_module
    from d810.hexrays.mutation import patch_transaction as patch_transaction_module

    class _StaleBoundPatchCfgTransaction:
        pass

    class _CurrentBoundPatchCfgTransaction:
        def __init__(self, plan: object, attempt: object) -> None:
            self.plan = plan
            self.prepared = SimpleNamespace(attempt_id=attempt)
            # Deliberately fail the next exact-authority check.  Reaching this
            # ValueError proves the class-authority check accepted the current
            # transaction type rather than the translator's stale import.
            self.patch_binding = SimpleNamespace(plan=object())

    plan = object()
    attempt = object()
    bound = _CurrentBoundPatchCfgTransaction(plan, attempt)
    monkeypatch.setattr(
        patch_transaction_module,
        "BoundPatchCfgTransaction",
        _CurrentBoundPatchCfgTransaction,
    )
    monkeypatch.setattr(
        ir_translator_module,
        "BoundPatchCfgTransaction",
        _StaleBoundPatchCfgTransaction,
        raising=False,
    )

    translator = IDAIRTranslator.__new__(IDAIRTranslator)
    with pytest.raises(ValueError, match="authority differs from binding"):
        translator._queue_bound_patch_plan(
            plan,
            object(),
            mutation_gateway=SimpleNamespace(current_transaction_attempt=attempt),
            bound_transaction=bound,
            deferred_modifier_module=object(),
        )


def test_queue_bound_patch_plan_rejects_stale_transaction_authority_after_reload(
    monkeypatch,
) -> None:
    """Reload safety must retain the exact current class-authority boundary."""
    import d810.hexrays.mutation.ir_translator as ir_translator_module
    from d810.hexrays.mutation import patch_transaction as patch_transaction_module

    class _StaleBoundPatchCfgTransaction:
        def __init__(self, plan: object, attempt: object) -> None:
            self.plan = plan
            self.prepared = SimpleNamespace(attempt_id=attempt)
            self.patch_binding = SimpleNamespace(plan=object())

    class _CurrentBoundPatchCfgTransaction:
        pass

    plan = object()
    attempt = object()
    stale_bound = _StaleBoundPatchCfgTransaction(plan, attempt)
    monkeypatch.setattr(
        patch_transaction_module,
        "BoundPatchCfgTransaction",
        _CurrentBoundPatchCfgTransaction,
    )
    monkeypatch.setattr(
        ir_translator_module,
        "BoundPatchCfgTransaction",
        _StaleBoundPatchCfgTransaction,
        raising=False,
    )

    translator = IDAIRTranslator.__new__(IDAIRTranslator)
    with pytest.raises(TypeError, match="requires bound transaction authority"):
        translator._queue_bound_patch_plan(
            plan,
            object(),
            mutation_gateway=SimpleNamespace(current_transaction_attempt=attempt),
            bound_transaction=stale_bound,
            deferred_modifier_module=object(),
        )


def _compile_for_gateway(
    backend: IDAIRTranslator,
    mba: object,
    gateway: object,
    modifications: list[object],
) -> PatchPlan:
    index = gateway.identity_index
    return compile_patch_plan(
        modifications,
        backend.lift(mba),
        snapshot_id=index.snapshot_id,
        source_maturity=MaturityEnvelope(
            ir=None,
            provider="hexrays",
            provider_id=index.maturity,
        ),
        source_generation=index.generation,
        block_refs_by_serial=index.plan_refs_by_serial(),
    )


def _compile_test_patch_plan(
    modifications: list[object],
    cfg: FlowGraph | None = None,
) -> PatchPlan:
    return compile_patch_plan(
        modifications,
        cfg,
        source_maturity=_TEST_MATURITY,
        source_generation=0,
        block_refs_by_serial={
            serial: LogicalBlockRef(
                _MANUAL_SESSION_ID,
                f"compiler-source:{serial}",
                0,
            )
            for serial in range(1024)
        },
    )


class TestIDAIRTranslatorBasics:
    """Test basic IDAIRTranslator properties and interface."""

    def test_backend_name(self):
        """Test that IDAIRTranslator.name returns 'ida'."""
        backend = IDAIRTranslator()
        assert backend.name == "ida"

    def test_translator_is_not_a_public_patch_runtime(self):
        """Final-boundary lowering must remain behind the runtime port."""
        from d810.transforms.protocol import PatchPlanRuntime

        backend = IDAIRTranslator()
        assert not isinstance(backend, PatchPlanRuntime)

    def test_lower_requires_patch_plan(self):
        backend = IDAIRTranslator()
        with pytest.raises(TypeError, match="requires PatchPlan"):
            backend.lower(  # type: ignore[arg-type]
                [RedirectGoto(from_serial=1, old_target=2, new_target=3)],
                object(),
                mutation_gateway=make_mutation_gateway(),
                bound_transaction=object(),  # type: ignore[arg-type]
            )


class _FakeDeferredGraphModifier:
    def __init__(self, mba: object):
        self.mba = mba
        self.calls: list[tuple] = []
        self.verify_failed = False
        self.transaction_complete = False
        self.bound_plan = None
        self.mutation_gateway = None
        self.superseded_count = 0

    def take_superseded_count(self) -> int:
        """Mirror the real modifier: one-shot read of the coalescing tally.

        ``lower`` reports this to the gateway so the realization inventory can
        reconcile ``applied + superseded == planned``. The double consumes it
        the same way, so a test that sets a tally sees it read exactly once.
        """
        count = int(self.superseded_count)
        self.superseded_count = 0
        return count

    def configure_patch_bindings(
        self,
        bound_plan: object,
        *,
        mutation_gateway: object,
    ) -> None:
        self.bound_plan = bound_plan
        self.mutation_gateway = mutation_gateway

    def observe_live_graph(self) -> FlowGraph:
        quantity = max(int(getattr(self.mba, "qty", 0) or 0), 1)
        return FlowGraph(
            blocks={serial: _block(serial, (), ()) for serial in range(quantity)},
            entry_serial=0,
            func_ea=int(getattr(self.mba, "entry_ea", 0) or 0),
        )

    def queue_goto_change(self, src: int, new: int, description: str = "") -> None:
        self.calls.append(("goto", src, new, description))

    def queue_conditional_target_change(
        self,
        src: int,
        new: int,
        old_target: int | None = None,
        expected_helper_serial: int | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            ("branch", src, new, old_target, description, expected_helper_serial)
        )

    def queue_convert_to_goto(
        self, serial: int, target: int, description: str = ""
    ) -> None:
        self.calls.append(("convert", serial, target, description))

    def queue_edge_redirect(
        self,
        *,
        src_block: int,
        old_target: int,
        new_target: int,
        via_pred: int,
        clone_until: int | None = None,
        source_new_target: int | None = None,
        rule_priority: int,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "edge_redirect",
                src_block,
                old_target,
                new_target,
                via_pred,
                clone_until,
                source_new_target,
                rule_priority,
                description,
            )
        )

    def queue_edge_split_trampoline(
        self,
        *,
        source_block: int,
        via_pred: int,
        old_target: int,
        new_target: int,
        expected_serial: int,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "edge_split_trampoline",
                source_block,
                via_pred,
                old_target,
                new_target,
                expected_serial,
                description,
            )
        )

    def queue_create_conditional_redirect(
        self,
        *,
        source_blk_serial: int,
        ref_blk_serial: int,
        conditional_target_serial: int,
        fallthrough_target_serial: int,
        old_target_serial: int | None = None,
        instructions_to_copy: tuple[object, ...] | list[object] | None = None,
        expected_conditional_serial: int | None = None,
        expected_fallthrough_serial: int | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "create_conditional",
                source_blk_serial,
                ref_blk_serial,
                conditional_target_serial,
                fallthrough_target_serial,
                old_target_serial,
                tuple(instructions_to_copy or ()),
                expected_conditional_serial,
                expected_fallthrough_serial,
                description,
            )
        )

    def queue_create_and_redirect(
        self,
        *,
        source_block_serial: int,
        final_target_serial: int,
        instructions_to_copy: list[object],
        is_0_way: bool = False,
        expected_serial: int | None = None,
        description: str = "",
        old_target_serial: int | None = None,
    ) -> None:
        self.calls.append(
            (
                "create_and_redirect",
                source_block_serial,
                final_target_serial,
                len(instructions_to_copy),
                is_0_way,
                expected_serial,
                description,
                old_target_serial,
            )
        )

    def queue_duplicate_block(
        self,
        *,
        source_block_serial: int,
        pred_serial: int | None,
        target_serial: int | None = None,
        conditional_target: int | None = None,
        fallthrough_target: int | None = None,
        expected_serial: int | None = None,
        expected_secondary_serial: int | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "duplicate_block",
                source_block_serial,
                pred_serial,
                target_serial,
                conditional_target,
                fallthrough_target,
                expected_serial,
                expected_secondary_serial,
                description,
            )
        )

    def queue_duplicate_replay_and_redirect(
        self,
        *,
        source_block_serial: int,
        dispatcher_entry_serial: int,
        per_pred_replays: tuple,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "duplicate_replay",
                source_block_serial,
                dispatcher_entry_serial,
                tuple(
                    (
                        pred,
                        target,
                        replay_serial,
                        clone_serial,
                        len(instructions),
                    )
                    for pred, target, replay_serial, clone_serial, instructions in per_pred_replays
                ),
                description,
            )
        )

    def queue_clone_conditional_as_goto(
        self,
        *,
        source_block_serial: int,
        pred_serial: int,
        goto_target_serial: int,
        expected_serial: int | None = None,
        description: str = "",
    ) -> None:
        self.calls.append(
            (
                "clone_conditional_as_goto",
                source_block_serial,
                pred_serial,
                goto_target_serial,
                expected_serial,
                description,
            )
        )

    def queue_insn_nop(self, serial: int, ea: int, description: str = "") -> None:
        self.calls.append(("nop", serial, ea, description))

    def queue_remove_edge(
        self, from_serial: int, to_serial: int, description: str = ""
    ) -> None:
        self.calls.append(("remove_edge", from_serial, to_serial, description))

    def _check_edge_split_trampoline_preconditions(
        self,
        *,
        source_block_serial: int | None,
        via_pred: int | None,
        old_target: int | None,
        new_target: int | None,
    ) -> bool:
        return all(
            value is not None
            for value in (source_block_serial, via_pred, old_target, new_target)
        )

    def apply(self, **kwargs) -> int:  # noqa: ANN003
        self.calls.append(("apply", kwargs))
        assert self.bound_plan is not None
        assert self.mutation_gateway is not None
        self.mutation_gateway.begin_patch_realization(
            self.bound_plan.attempt_id,
            plan_refs=tuple(
                reservation.plan_ref for reservation in self.bound_plan.reservations
            ),
        )
        for reservation in self.bound_plan.reservations:
            returned_serial = int(self.bound_plan.serial_for(reservation.plan_ref))
            self.mutation_gateway.bind_reserved_plan_block(
                self.bound_plan.attempt_id,
                reservation.plan_ref,
                insertion_serial=returned_serial,
                returned_serial=returned_serial,
            )
        if self.bound_plan.reservations:
            try:
                self.mba.qty = int(self.mba.qty) + len(self.bound_plan.reservations)
            except Exception:
                pass
        self.transaction_complete = True
        return sum(1 for call in self.calls if call[0] != "apply")


class TestTypedPatchBinding:
    def test_lower_closes_typed_attempt_with_truthful_runtime_receipt(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mba = SimpleNamespace(qty=1, maturity=4)
        gateway = make_mutation_gateway(mba, generation=7)
        block_ref = gateway.identity_index.plan_ref_for_serial(0)
        plan = PatchPlan(
            plan_id="typed-runtime-receipt",
            snapshot_id=gateway.identity_index.snapshot_id,
            source_maturity=_TEST_MATURITY,
            source_generation=7,
            steps=(PatchNopInstructions(block_ref, (0x401000,)),),
            source_coordinates=((block_ref, 0),),
        )
        child_gateways: list[object] = []
        emitter = EventEmitter()
        phases: list[MbaCfgTransactionAuthorityObserved] = []
        committed: list[MbaMutationCommitted] = []
        emitter.on(MbaCfgTransactionAuthorityObserved, phases.append)
        emitter.on(MbaMutationCommitted, committed.append)
        gateway.event_emitter = emitter

        def _factory(mba: object, **kwargs) -> _FakeDeferredGraphModifier:
            child = kwargs["mutation_gateway"]
            child_gateways.append(child)
            modifier = _FakeDeferredGraphModifier(mba)
            apply = modifier.apply

            def _apply(**apply_kwargs) -> int:
                child.begin_patch_realization(
                    child.current_transaction_attempt,
                    plan_refs=(),
                )
                return apply(**apply_kwargs)

            modifier.apply = _apply  # type: ignore[method-assign]
            return modifier

        graph = FlowGraph(
            blocks={0: _block(0, (), ())},
            entry_serial=0,
            func_ea=0x401000,
        )
        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        translator_module = importlib.import_module(
            "d810.hexrays.mutation.ir_translator"
        )
        monkeypatch.setattr(deferred_modifier, "DeferredGraphModifier", _factory)
        monkeypatch.setattr(translator_module, "lift", lambda _mba: graph)

        assert _lower_bound(IDAIRTranslator(), plan, mba, gateway) == 1

        child = child_gateways[0]
        assert child.active is False
        assert [event.phase for event in phases] == [
            CfgTransactionPhase.PLANNED,
            CfgTransactionPhase.PROJECTED,
            CfgTransactionPhase.PREFLIGHTED,
            CfgTransactionPhase.BOUND,
            CfgTransactionPhase.REALIZING,
            CfgTransactionPhase.OBSERVED,
            CfgTransactionPhase.COMMITTED,
        ]
        assert child.receipts[-1].planned_operation_count == 1
        assert child.receipts[-1].operation_count == 1
        assert committed[-1].receipt is child.receipts[-1]

    def test_lower_binds_snapshot_ref_only_at_modifier_queue_boundary(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mba = SimpleNamespace(qty=1, maturity=4)
        gateway = make_mutation_gateway(mba, generation=7)
        block_ref = gateway.identity_index.plan_ref_for_serial(0)
        plan = PatchPlan(
            plan_id="typed-lowering",
            snapshot_id=gateway.identity_index.snapshot_id,
            source_maturity=_TEST_MATURITY,
            source_generation=7,
            steps=(PatchNopInstructions(block_ref, (0x401000,)),),
            source_coordinates=((block_ref, 0),),
        )
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(deferred_modifier, "DeferredGraphModifier", _factory)

        assert _lower_bound(IDAIRTranslator(), plan, mba, gateway) == 1
        assert created[0].bound_plan is not None
        assert created[0].calls[0][:3] == ("nop", 0, 0x401000)

    def test_lower_rejects_wrong_snapshot_before_modifier_creation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mba = SimpleNamespace(qty=1, maturity=4)
        gateway = make_mutation_gateway(mba, generation=7)
        stale_ref = LogicalBlockRef("stale-session", "logical:0", 0)
        plan = PatchPlan(
            plan_id="typed-lowering",
            snapshot_id="stale-snapshot",
            source_maturity=_TEST_MATURITY,
            source_generation=7,
            steps=(PatchNopInstructions(stale_ref, (0x401000,)),),
        )
        created: list[object] = []
        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            lambda *_args, **_kwargs: created.append(object()),
        )

        with pytest.raises(PatchBindingRejected, match="snapshot authority"):
            _lower_bound(IDAIRTranslator(), plan, mba, gateway)

        assert created == []

    def test_queue_exception_aborts_all_prewrite_identity_residue_and_retry_works(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mba = SimpleNamespace(qty=1, maturity=4)
        gateway = make_mutation_gateway(mba, generation=7)
        source = gateway.identity_index.plan_ref_for_serial(0)
        created_ref = PlanBlockRef("typed-retry", "insert:0")
        plan = PatchPlan(
            plan_id="typed-retry",
            snapshot_id=gateway.identity_index.snapshot_id,
            source_maturity=_TEST_MATURITY,
            source_generation=7,
            steps=(
                PatchInsertBlock(
                    block_id=created_ref,
                    pred_serial=source,
                    succ_serial=source,
                    instructions=(),
                ),
            ),
            new_blocks=(PatchBlockSpec(created_ref, "insert", template_block=source),),
            source_coordinates=((source, 0),),
        )
        child_gateways: list[object] = []
        call_count = 0

        def _factory(mba: object, **kwargs) -> _FakeDeferredGraphModifier:
            nonlocal call_count
            call_count += 1
            child_gateways.append(kwargs["mutation_gateway"])
            modifier = _FakeDeferredGraphModifier(mba)
            if call_count == 1:

                def _explode(**_kwargs) -> None:
                    raise RuntimeError("queue exploded before SDK write")

                modifier.queue_create_and_redirect = _explode  # type: ignore[method-assign]
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(deferred_modifier, "DeferredGraphModifier", _factory)
        baseline_proxy_count = gateway.identity_index.logical_proxy_count

        with pytest.raises(RuntimeError, match="queue exploded"):
            _lower_bound(IDAIRTranslator(), plan, mba, gateway)

        assert not child_gateways[0].active
        assert gateway.identity_index.logical_proxy_count == baseline_proxy_count
        assert gateway.identity_index.plan_creation_receipts == ()

        assert _lower_bound(IDAIRTranslator(), plan, mba, gateway) == 1

    def test_partial_reservation_failure_aborts_prewrite_identity_residue(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mba = SimpleNamespace(qty=1, maturity=4)
        gateway = make_mutation_gateway(mba, generation=7)
        refs = (
            PlanBlockRef("reservation-retry", "insert:0"),
            PlanBlockRef("reservation-retry", "insert:1"),
        )
        plan = PatchPlan(
            plan_id="reservation-retry",
            snapshot_id=gateway.identity_index.snapshot_id,
            source_maturity=_TEST_MATURITY,
            source_generation=7,
            new_blocks=tuple(PatchBlockSpec(ref, "insert") for ref in refs),
        )
        child_gateways: list[object] = []
        gateway_type = type(gateway)
        index_type = type(gateway.identity_index)
        original_new_transaction = gateway_type.new_transaction
        original_reserve = index_type.reserve_plan_block
        reservation_calls = 0

        def _new_transaction(self):
            child = original_new_transaction(self)
            child_gateways.append(child)
            return child

        def _reserve(self, attempt, ref, **kwargs):
            nonlocal reservation_calls
            reservation_calls += 1
            if reservation_calls == 2:
                raise RuntimeError("second reservation failed")
            return original_reserve(self, attempt, ref, **kwargs)

        monkeypatch.setattr(gateway_type, "new_transaction", _new_transaction)
        monkeypatch.setattr(index_type, "reserve_plan_block", _reserve)
        baseline_proxy_count = gateway.identity_index.logical_proxy_count

        with pytest.raises(RuntimeError, match="second reservation failed"):
            _lower_bound(IDAIRTranslator(), plan, mba, gateway)

        assert not child_gateways[0].active
        assert gateway.identity_index.logical_proxy_count == baseline_proxy_count
        assert gateway.identity_index.plan_creation_receipts == ()

        monkeypatch.setattr(
            index_type,
            "reserve_plan_block",
            original_reserve,
        )
        assert _lower_bound(IDAIRTranslator(), plan, mba, gateway) == 0


class TestIDAIntegration:
    """Integration tests requiring IDA runtime.

    These tests verify that the backend can interact with real IDA types.
    """

    binary_name = _DEFAULT_TEST_BINARY

    def test_lift_returns_flowgraph(self):
        """Test lift() returns a FlowGraph flowgraph for a real mba_t."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "lift")
        assert callable(backend.lift)

    def test_lower_accepts_real_mba(self):
        """Test lower() accepts a real mba_t instance."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "lower")
        assert callable(backend.lower)

    def test_verify_accepts_real_mba(self):
        """Test verify() accepts a real mba_t instance."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "verify")
        assert callable(backend.verify)

    def test_lower_applies_insert_block_patch_plan_to_real_mba(
        self, libobfuscated_setup
    ):
        mba = _get_real_mba()
        edge = _find_insertable_edge(mba)
        if edge is None:
            pytest.skip("No 1-way edge available for InsertBlock runtime test")

        pred_serial, succ_serial = edge
        backend = IDAIRTranslator()
        gateway = make_mutation_gateway(mba)
        patch_plan = _compile_for_gateway(
            backend,
            mba,
            gateway,
            [
                InsertBlock(
                    pred_serial=pred_serial,
                    succ_serial=succ_serial,
                    instructions=(
                        InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0, operands=()),
                    ),
                )
            ],
        )
        insert_step = next(
            step for step in patch_plan.steps if isinstance(step, PatchInsertBlock)
        )

        count = _lower_bound(backend, patch_plan, mba, gateway)

        assert count == 1
        mba.verify(True)

        pred_blk = mba.get_mblock(pred_serial)
        assert pred_blk is not None
        assert pred_blk.nsucc() == 1
        inserted_serial = _created_serial(gateway, insert_step.block_id)
        assert pred_blk.succ(0) == inserted_serial

        inserted_blk = mba.get_mblock(inserted_serial)
        assert inserted_blk is not None
        assert inserted_blk.nsucc() == 1
        assert inserted_blk.succ(0) == succ_serial

    def test_fallthrough_redirect_publishes_typed_helper_receipt(
        self,
        libobfuscated_setup,
    ):
        mba = _get_real_mba()
        candidate = _find_fallthrough_redirect_candidate(mba)
        if candidate is None:
            pytest.skip("No conditional fallthrough redirect candidate available")
        source, old_fallthrough, new_target = candidate
        backend = IDAIRTranslator()
        gateway = make_mutation_gateway(mba)
        patch_plan = _compile_for_gateway(
            backend,
            mba,
            gateway,
            [RedirectBranch(source, old_fallthrough, new_target)],
        )
        step = patch_plan.steps[0]
        assert isinstance(step, PatchRedirectBranch)
        assert step.fallthrough_helper_block_id is not None

        assert _lower_bound(backend, patch_plan, mba, gateway) == 1
        mba.verify(True)

        receipts = tuple(
            receipt
            for receipt in gateway.identity_index.plan_creation_receipts
            if receipt.plan_ref == step.fallthrough_helper_block_id
        )
        assert len(receipts) == 1
        receipt = receipts[0]
        assert (
            receipt.logical_version.handle.provenance
            is BlockHandleProvenance.CREATED_SYNTHETIC
        )
        helper = mba.get_mblock(receipt.returned_serial)
        assert helper is not None
        assert helper.nsucc() == 1
        assert helper.succ(0) == new_target

    def test_lower_applies_duplicate_block_patch_plan_to_real_mba(
        self, libobfuscated_setup
    ):
        mba = _get_real_mba()
        candidate = _find_duplicate_candidate(mba)
        if candidate is None:
            pytest.skip(
                "No supported predecessor/source pair available for DuplicateBlock runtime test"
            )

        pred_serial, source_serial = candidate
        backend = IDAIRTranslator()
        gateway = make_mutation_gateway(mba)
        patch_plan = _compile_for_gateway(
            backend,
            mba,
            gateway,
            [
                DuplicateBlock(
                    source_block=source_serial,
                    target_block=None,
                    pred_serial=pred_serial,
                )
            ],
        )
        duplicate_step = next(
            step for step in patch_plan.steps if isinstance(step, PatchDuplicateBlock)
        )
        assert (
            gateway.identity_index.plan_ref_for_serial(pred_serial)
            == duplicate_step.pred_serial
        )

        count = _lower_bound(backend, patch_plan, mba, gateway)

        assert count == 1
        mba.verify(True)

        pred_blk = mba.get_mblock(pred_serial)
        assert pred_blk is not None
        duplicated_serial = _created_serial(gateway, duplicate_step.block_id)
        assert duplicated_serial in {pred_blk.succ(i) for i in range(pred_blk.nsucc())}

        duplicated_blk = mba.get_mblock(duplicated_serial)
        assert duplicated_blk is not None
        assert duplicated_blk.nsucc() == len(duplicate_step.source_successors)

    def test_lower_applies_conditional_duplicate_block_patch_plan_to_real_mba(
        self, libobfuscated_setup
    ):
        mba = _get_real_mba()
        candidate = _find_conditional_duplicate_candidate(mba)
        if candidate is None:
            pytest.skip(
                "No supported predecessor/source pair available for conditional DuplicateBlock runtime test"
            )

        pred_serial, source_serial = candidate
        backend = IDAIRTranslator()
        gateway = make_mutation_gateway(mba)
        patch_plan = _compile_for_gateway(
            backend,
            mba,
            gateway,
            [
                DuplicateBlock(
                    source_block=source_serial,
                    target_block=None,
                    pred_serial=pred_serial,
                )
            ],
        )
        duplicate_step = next(
            step for step in patch_plan.steps if isinstance(step, PatchDuplicateBlock)
        )

        assert duplicate_step.fallthrough_block_id is not None

        count = _lower_bound(backend, patch_plan, mba, gateway)

        assert count == 1
        mba.verify(True)

        pred_blk = mba.get_mblock(pred_serial)
        assert pred_blk is not None
        duplicated_serial = _created_serial(gateway, duplicate_step.block_id)
        assert duplicated_serial in {pred_blk.succ(i) for i in range(pred_blk.nsucc())}

        duplicated_blk = mba.get_mblock(duplicated_serial)
        assert duplicated_blk is not None
        assert duplicated_blk.nsucc() == 2

        fallthrough_serial = _created_serial(
            gateway, duplicate_step.fallthrough_block_id
        )
        duplicated_default = mba.get_mblock(fallthrough_serial)
        assert duplicated_default is not None
        assert duplicated_default.nsucc() == 1

    def test_lower_applies_concrete_patch_plan(self, monkeypatch: pytest.MonkeyPatch):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _manual_plan(
            PatchRedirectGoto(
                from_serial=_manual_ref(7),
                old_target=_manual_ref(8),
                new_target=_manual_ref(9),
            )
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "goto"
        assert created[0].calls[0][1:3] == (7, 9)

    def test_lower_applies_redirect_branch_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _manual_plan(
            PatchRedirectBranch(
                from_serial=_manual_ref(15),
                old_target=_manual_ref(16),
                new_target=_manual_ref(66),
            )
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][:4] == ("branch", 15, 66, 16)
        assert created[0].calls[0][4].startswith("redirect branch ")

    def test_lower_applies_edge_split_trampoline_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                EdgeRedirectViaPredSplit(
                    src_block=45,
                    old_target=2,
                    new_target=2,
                    via_pred=122,
                    rule_priority=550,
                )
            ],
            _cfg(),
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "edge_split_trampoline"
        step = patch_plan.steps[0]
        expected = created[0].bound_plan.serial_for(step.block_id)
        assert created[0].calls[0][1:6] == (45, 122, 2, 2, expected)

    def test_lower_applies_edge_split_corridor_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                EdgeRedirectViaPredSplit(
                    src_block=45,
                    old_target=46,
                    new_target=2,
                    via_pred=44,
                    clone_until=46,
                    rule_priority=550,
                )
            ],
            _corridor_cfg(),
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "edge_redirect"
        assert created[0].calls[0][1:8] == (45, 46, 2, 44, 46, None, 550)

    def test_compile_insert_requires_exact_source_graph(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        with pytest.raises(ValueError, match="requires FlowGraph context"):
            compile_patch_plan(
                [
                    InsertBlock(
                        pred_serial=45,
                        succ_serial=2,
                        instructions=(
                            InsnSnapshot(opcode=0x77, ea=0x1000, operands=()),
                        ),
                    )
                ]
            )
        assert created == []

    def test_lower_applies_conditional_redirect_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        instructions = (InsnSnapshot(opcode=ida_hexrays.m_nop, ea=0, operands=()),)
        patch_plan = _compile_test_patch_plan(
            [
                CreateConditionalRedirect(
                    source_block=44,
                    ref_block=45,
                    conditional_target=199,
                    fallthrough_target=2,
                    old_target_serial=45,
                    instructions=instructions,
                )
            ],
            _cfg(),
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "create_conditional"
        step = patch_plan.steps[0]
        expected_conditional = created[0].bound_plan.serial_for(step.block_id)
        expected_fallthrough = created[0].bound_plan.serial_for(
            step.fallthrough_block_id
        )
        assert created[0].calls[0][1:9] == (
            44,
            45,
            199,
            2,
            45,
            instructions,
            expected_conditional,
            expected_fallthrough,
        )

    def test_lower_applies_insert_block_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                InsertBlock(
                    pred_serial=45,
                    succ_serial=199,
                    instructions=(InsnSnapshot(opcode=0x77, ea=0x1000, operands=()),),
                )
            ],
            _cfg(),
        )

        count = _lower(backend, patch_plan, SimpleNamespace(entry_ea=0x180000000))

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "create_and_redirect"
        step = patch_plan.steps[0]
        expected = created[0].bound_plan.serial_for(step.block_id)
        assert created[0].calls[0][1:6] == (45, 199, 1, False, expected)

    def test_lower_applies_duplicate_block_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                DuplicateBlock(
                    source_block=45,
                    target_block=199,
                    pred_serial=44,
                )
            ],
            _cfg(),
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "duplicate_block"
        step = patch_plan.steps[0]
        expected = created[0].bound_plan.serial_for(step.block_id)
        assert created[0].calls[0][1:8] == (45, 44, 199, None, None, expected, None)

    def test_lower_applies_duplicate_replay_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                DuplicateReplayAndRedirect(
                    source_serial=45,
                    dispatcher_entry=2,
                    per_pred_replays=(
                        DuplicateReplayEntry(
                            pred_serial=44,
                            target_serial=199,
                            captured_body=_captured_body(45),
                        ),
                        DuplicateReplayEntry(
                            pred_serial=122,
                            target_serial=199,
                            captured_body=_captured_body(45),
                        ),
                    ),
                )
            ],
            _cfg(),
        )

        assert isinstance(patch_plan.steps[0], PatchDuplicateReplayAndRedirect)
        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "duplicate_replay"
        assert created[0].calls[0][1:3] == (45, 2)
        step = patch_plan.steps[0]
        first, second = step.per_pred_replays
        bound = created[0].bound_plan
        assert created[0].calls[0][3] == (
            (44, 199, bound.serial_for(first.replay_block_id), None, 1),
            (
                122,
                199,
                bound.serial_for(second.replay_block_id),
                bound.serial_for(second.clone_block_id),
                1,
            ),
        )

    def test_lower_rejects_call_captured_duplicate_replay_before_modifier_creation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                DuplicateReplayAndRedirect(
                    source_serial=45,
                    dispatcher_entry=2,
                    per_pred_replays=(
                        DuplicateReplayEntry(
                            pred_serial=44,
                            target_serial=199,
                            captured_body=_captured_body(45),
                        ),
                        DuplicateReplayEntry(
                            pred_serial=122,
                            target_serial=199,
                            captured_body=_captured_body(45),
                        ),
                    ),
                )
            ],
            _cfg(),
        )
        replay_step = patch_plan.steps[0]
        assert isinstance(replay_step, PatchDuplicateReplayAndRedirect)
        first, second = replay_step.per_pred_replays
        patch_plan = replace(
            patch_plan,
            steps=(
                replace(
                    replay_step,
                    per_pred_replays=(
                        replace(
                            first,
                            captured_body=_captured_body(45, contains_call=True),
                        ),
                        second,
                    ),
                ),
            ),
        )

        count = _lower(backend, patch_plan, object())

        assert count == 0
        assert created == []

    def test_lower_applies_conditional_duplicate_block_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                DuplicateBlock(
                    source_block=45,
                    target_block=None,
                    pred_serial=44,
                )
            ],
            _conditional_duplicate_cfg(),
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "duplicate_block"
        step = patch_plan.steps[0]
        bound = created[0].bound_plan
        assert created[0].calls[0][1:8] == (
            45,
            44,
            None,
            2,
            3,
            bound.serial_for(step.block_id),
            bound.serial_for(step.fallthrough_block_id),
        )

    def test_lower_applies_conditional_duplicate_block_patch_plan_with_explicit_targets(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                DuplicateBlock(
                    source_block=45,
                    target_block=None,
                    pred_serial=44,
                    conditional_target=199,
                    fallthrough_target=3,
                )
            ],
            _conditional_duplicate_cfg(),
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "duplicate_block"
        step = patch_plan.steps[0]
        bound = created[0].bound_plan
        assert created[0].calls[0][1:8] == (
            45,
            44,
            None,
            199,
            3,
            bound.serial_for(step.block_id),
            bound.serial_for(step.fallthrough_block_id),
        )

    def test_lower_applies_clone_conditional_as_goto_patch_plan(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                CloneConditionalAsGoto(
                    source_block=45,
                    pred_serial=44,
                    goto_target=2,
                    reason="fix predecessor simple case",
                )
            ],
            _conditional_duplicate_cfg(),
        )

        count = _lower(backend, patch_plan, object())

        assert count == 1
        assert len(created) == 1
        assert created[0].calls[0][0] == "clone_conditional_as_goto"
        step = patch_plan.steps[0]
        expected = created[0].bound_plan.serial_for(step.block_id)
        assert created[0].calls[0][1:5] == (45, 44, 2, expected)
        assert "fix predecessor simple case" in created[0].calls[0][5]

    def test_compile_insert_never_falls_back_to_backend_local_lowering(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        with pytest.raises(ValueError, match="requires FlowGraph context"):
            compile_patch_plan(
                [
                    InsertBlock(
                        pred_serial=45,
                        succ_serial=2,
                        instructions=(
                            InsnSnapshot(opcode=0x77, ea=0x1000, operands=()),
                        ),
                    )
                ]
            )
        assert created == []

    def test_lower_rejects_unreconstructable_patch_insert_block_before_modifier_creation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                InsertBlock(
                    pred_serial=45,
                    succ_serial=199,
                    instructions=(
                        InsnSnapshot(opcode=0x77, ea=0x1000, operands=(object(),)),
                    ),
                )
            ],
            _cfg(),
        )

        count = _lower(backend, patch_plan, SimpleNamespace(entry_ea=0x180000000))

        assert count == 0
        assert created == []

    def test_lower_rejects_call_captured_patch_insert_block_before_modifier_creation(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan(
            [
                InsertBlock(
                    pred_serial=45,
                    succ_serial=199,
                    captured_body=_captured_body(45, contains_call=True),
                )
            ],
            _cfg(),
        )

        assert isinstance(patch_plan.steps[0], PatchInsertBlock)

        count = _lower(backend, patch_plan, SimpleNamespace(entry_ea=0x180000000))

        assert count == 0
        assert created == []

    def test_lower_queues_remove_edge(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(
            deferred_modifier,
            "DeferredGraphModifier",
            _factory,
        )

        backend = IDAIRTranslator()
        patch_plan = _compile_test_patch_plan([RemoveEdge(from_serial=45, to_serial=2)])

        count = _lower(backend, patch_plan, object())

        assert len(created) == 1
        modifier = created[0]
        # Should have queued remove_edge + apply
        remove_calls = [c for c in modifier.calls if c[0] == "remove_edge"]
        assert len(remove_calls) == 1
        assert remove_calls[0][:3] == ("remove_edge", 45, 2)
        assert remove_calls[0][3].startswith("remove edge ")
        assert count > 0


class TestExecutionPolicyGuard:
    """Safety regressions for the ExecutionPolicy NOP-only gate.

    When execution_policy is one of the relaxed NOP cleanup policies:
    - Plans containing only PatchNopInstructions must pass the step-type guard and
      reach the modifier (the guard must NOT reject them).
    - Plans containing any structural step (redirect, duplicate, insert, etc.) must
      be rejected immediately by lower() — the guard must return 0 before the modifier
      is even created.

    These tests verify the guard stays active regardless of other refactoring.
    Ticket: d81-3hdl (ExecutionPolicy redesign)
    """

    def test_cfg_edit_rejected_when_relaxed(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """lower() must return 0 for any non-NOP step when policy is NOP_CLEANUP_RELAXED.

        This ensures the relaxed policy cannot be accidentally reused for structural
        mutations (goto redirects, block creation, edge rewrites).
        """
        created: list = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(deferred_modifier, "DeferredGraphModifier", _factory)

        backend = IDAIRTranslator()

        # PatchRedirectGoto is a structural CFG edit — must be rejected under relaxed policy.
        plan = _compile_test_patch_plan(
            [RedirectGoto(from_serial=10, old_target=20, new_target=30)],
        )
        plan = replace(
            plan,
            execution_policy=ExecutionPolicy.NOP_CLEANUP_RELAXED,
        )
        count = _lower(backend, plan, object())

        assert count == 0, (
            "CFG-edit plan must be rejected when policy is NOP_CLEANUP_RELAXED"
        )
        assert created == [], "Modifier must not be created when guard rejects the plan"

    def test_nop_only_plan_passes_guard(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """lower() must not reject a NOP-only plan when policy is NOP_CLEANUP_RELAXED.

        The step-type guard must pass and reach the modifier, confirming the guard
        does not over-reject legitimate cleanup plans.
        """
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(deferred_modifier, "DeferredGraphModifier", _factory)

        backend = IDAIRTranslator()

        # PatchNopInstructions is the only allowed step type — must pass the guard.
        nop_plan = _manual_plan(
            PatchNopInstructions(block_serial=_manual_ref(7), insn_eas=(0xDEAD,)),
            execution_policy=ExecutionPolicy.NOP_CLEANUP_RELAXED,
        )
        _lower(backend, nop_plan, object())

        assert len(created) == 1, (
            "NOP-only plan must not be rejected by the step-type guard; "
            "modifier should have been created"
        )

    def test_nop_relaxed_skips_pre_cleanup_post_contract(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """NOP cleanup must reach optimize_local before live post-contract checks."""
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        class _ExplodingContract:
            def verify(self, *_args, **_kwargs):
                raise AssertionError("post contract must not run before cleanup")

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(deferred_modifier, "DeferredGraphModifier", _factory)

        backend = IDAIRTranslator(contract=_ExplodingContract())
        nop_plan = _manual_plan(
            PatchNopInstructions(block_serial=_manual_ref(7), insn_eas=(0xDEAD,)),
            execution_policy=ExecutionPolicy.NOP_CLEANUP_RELAXED,
        )

        assert _lower(backend, nop_plan, object()) == 1
        assert len(created) == 1
        apply_calls = [call for call in created[0].calls if call[0] == "apply"]
        assert len(apply_calls) == 1
        assert apply_calls[0][1]["post_apply_hook"] is None
        assert apply_calls[0][1]["run_optimize_local"] is True

    def test_nop_merge_blocks_relaxed_uses_deep_cleanup(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ):
        created: list[_FakeDeferredGraphModifier] = []

        def _factory(mba: object, **_kwargs) -> _FakeDeferredGraphModifier:
            modifier = _FakeDeferredGraphModifier(mba)
            created.append(modifier)
            return modifier

        deferred_modifier = importlib.import_module(
            "d810.hexrays.mutation.deferred_modifier"
        )
        monkeypatch.setattr(deferred_modifier, "DeferredGraphModifier", _factory)

        backend = IDAIRTranslator()
        nop_plan = _manual_plan(
            PatchNopInstructions(block_serial=_manual_ref(7), insn_eas=(0xDEAD,)),
            execution_policy=ExecutionPolicy.NOP_MERGE_BLOCKS_RELAXED,
        )

        assert _lower(backend, nop_plan, object()) == 1
        apply_calls = [call for call in created[0].calls if call[0] == "apply"]
        assert len(apply_calls) == 1
        assert apply_calls[0][1]["run_deep_cleaning"] is True
        assert apply_calls[0][1]["run_optimize_local"] is False
