from __future__ import annotations

from pathlib import Path
from types import MethodType, SimpleNamespace

import ida_hexrays
import pytest

from d810.core.stats import OptimizationStatistics
from d810.hexrays.hooks import optblock_adapter
from d810.hexrays.hooks.callback_mutation_diagnostics import (
    build_callback_nop_delta_records,
    build_callback_nop_inventory_records,
    capture_live_nop_sites,
)
from d810.hexrays.hooks.hexrays_hooks import HexraysDecompilationHook
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.optimizers.microcode.flow.context import FlowMaturityContext


class _Instruction:
    def __init__(self, opcode: int, ea: int, next_instruction=None) -> None:
        self.opcode = int(opcode)
        self.ea = int(ea)
        self.next = next_instruction

    def for_all_insns(self, _visitor) -> bool:
        return False


class _Block:
    def __init__(
        self,
        *,
        serial: int,
        start: int,
        end: int,
        head: _Instruction | None,
    ) -> None:
        self.serial = int(serial)
        self.start = int(start)
        self.end = int(end)
        self.head = head


class _Mba:
    def __init__(
        self,
        blocks: tuple[_Block, ...],
        *,
        entry_ea: int = 0x401000,
        maturity: int = ida_hexrays.MMAT_GLBOPT2,
    ) -> None:
        self._blocks = blocks
        self.qty = len(blocks)
        self.entry_ea = int(entry_ea)
        self.maturity = int(maturity)
        for block in blocks:
            block.mba = self

    def get_mblock(self, serial: int) -> _Block:
        return self._blocks[serial]


class _RejectUnrelatedBlockMba(_Mba):
    """Prove callback-local diagnostics do not walk sibling blocks."""

    def get_mblock(self, serial: int) -> _Block:
        if int(serial) != 0:
            raise AssertionError("callback diagnostics scanned an unrelated block")
        return super().get_mblock(serial)


class _NopWritingRule:
    name = "unreported_nop_writer"
    priority = 100

    def __init__(self, instruction: _Instruction) -> None:
        self._instruction = instruction
        self.current_maturity = None
        self.current_generation = 0

    def set_flow_context(self, _flow_context) -> None:
        return None

    def optimize(self, _block) -> int:
        self._instruction.opcode = ida_hexrays.m_nop
        return 0


class _ExecutionScope:
    def __init__(self, rule: _NopWritingRule) -> None:
        self._rule = rule

    def active_stages(self, **_kwargs):
        return (SimpleNamespace(implementation=self._rule),)


class _GlboptNopProbe:
    def __init__(self) -> None:
        self.reports = []
        self.inventories = []

    def prefold_return_reg_consumer_def_eas_for(self, _function_ea: int):
        return frozenset()

    def _capture_callback_nop_sites(self, mba):
        return capture_live_nop_sites(mba)

    def _report_callback_nop_delta(self, mba, **kwargs) -> None:
        self.reports.append((mba, kwargs))

    def _report_callback_nop_inventory(self, mba, **kwargs) -> None:
        self.inventories.append((mba, kwargs))


def test_callback_nop_delta_records_unreported_live_write_with_ea_anchor() -> None:
    instruction = _Instruction(ida_hexrays.m_mov, 0x40C115)
    mba = _Mba(
        (
            _Block(
                serial=77,
                start=0x40C100,
                end=0x40C120,
                head=instruction,
            ),
        )
    )
    before = capture_live_nop_sites(mba)

    instruction.opcode = ida_hexrays.m_nop
    after = capture_live_nop_sites(mba)

    records = build_callback_nop_delta_records(
        before=before,
        after=after,
        callback_kind="optblock_rule",
        callback_name="JumpFixer",
        callback_result=0,
        maturity="MMAT_GLBOPT2",
    )

    assert len(records) == 1
    record = records[0]
    assert record.strategy == "hexrays_callback_nop_delta"
    assert record.decision == "mutation_unreported"
    assert record.payload == {
        "block_anchor": "blk77@0x40c100",
        "block_end_ea": "0x40c120",
        "callback_kind": "optblock_rule",
        "callback_name": "JumpFixer",
        "callback_result": 0,
        "instruction_ea": "0x40c115",
        "instruction_ordinal": 0,
        "instruction_path": "top[0]",
    }


def test_callback_nop_delta_distinguishes_nonzero_report_and_exception() -> None:
    instruction = _Instruction(ida_hexrays.m_nop, 0x401010)
    site = capture_live_nop_sites(
        _Mba(
            (
                _Block(
                    serial=2,
                    start=0x401000,
                    end=0x401020,
                    head=instruction,
                ),
            )
        )
    )

    reported = build_callback_nop_delta_records(
        before=(),
        after=site,
        callback_kind="glbopt_hook",
        callback_name="return_const_corruption_cleanup",
        callback_result=ida_hexrays.MERR_LOOP,
        maturity="MMAT_GLBOPT2",
    )
    raised = build_callback_nop_delta_records(
        before=(),
        after=site,
        callback_kind="optblock_rule",
        callback_name="broken_rule",
        callback_result=None,
        maturity="MMAT_GLBOPT2",
        exception_name="RuntimeError",
    )

    assert reported[0].decision == "mutation_reported"
    assert reported[0].reason == "callback returned a nonzero mutation result"
    assert raised[0].decision == "mutation_result_missing"
    assert raised[0].reason == "callback raised after creating an m_nop"
    assert raised[0].payload["exception_name"] == "RuntimeError"


def test_callback_nop_delta_ignores_preexisting_nop() -> None:
    instruction = _Instruction(ida_hexrays.m_nop, 0x401010)
    mba = _Mba(
        (
            _Block(
                serial=2,
                start=0x401000,
                end=0x401020,
                head=instruction,
            ),
        )
    )
    snapshot = capture_live_nop_sites(mba)

    assert (
        build_callback_nop_delta_records(
            before=snapshot,
            after=snapshot,
            callback_kind="optblock_rule",
            callback_name="no_change",
            callback_result=0,
            maturity="MMAT_GLBOPT2",
        )
        == ()
    )


def test_callback_nop_inventory_records_explicit_absence() -> None:
    records = build_callback_nop_inventory_records(
        sites=(),
        callback_kind="glbopt_hook",
        callback_name="hxe_glbopt_boundary",
        stage="entry",
        maturity="MMAT_GLBOPT2",
    )

    assert len(records) == 1
    assert records[0].strategy == "hexrays_callback_nop_inventory"
    assert records[0].decision == "absent"
    assert records[0].payload == {
        "callback_kind": "glbopt_hook",
        "callback_name": "hxe_glbopt_boundary",
        "inventory_count": 0,
        "stage": "entry",
    }


def test_callback_nop_inventory_records_ea_anchored_presence() -> None:
    sites = capture_live_nop_sites(
        _Mba(
            (
                _Block(
                    serial=77,
                    start=0x40C100,
                    end=0x40C120,
                    head=_Instruction(ida_hexrays.m_nop, 0x40C115),
                ),
            )
        )
    )

    records = build_callback_nop_inventory_records(
        sites=sites,
        callback_kind="glbopt_hook",
        callback_name="hxe_glbopt_boundary",
        stage="exit",
        maturity="MMAT_GLBOPT2",
    )

    assert len(records) == 1
    assert records[0].decision == "present"
    assert records[0].payload["block_anchor"] == "blk77@0x40c100"
    assert records[0].payload["instruction_ea"] == "0x40c115"
    assert records[0].payload["instruction_path"] == "top[0]"
    assert records[0].payload["inventory_count"] == 1
    assert records[0].payload["stage"] == "exit"


def test_callback_nop_delta_captures_nested_mop_d_instruction() -> None:
    nested = _Instruction(ida_hexrays.m_mov, 0x401014)
    outer = _Instruction(ida_hexrays.m_add, 0x401010)
    outer.l = SimpleNamespace(t=ida_hexrays.mop_d, d=nested)
    outer.r = SimpleNamespace(t=ida_hexrays.mop_z)
    outer.d = SimpleNamespace(t=ida_hexrays.mop_z)
    mba = _Mba(
        (
            _Block(
                serial=3,
                start=0x401000,
                end=0x401020,
                head=outer,
            ),
        )
    )
    before = capture_live_nop_sites(mba)

    nested.opcode = ida_hexrays.m_nop
    after = capture_live_nop_sites(mba)
    records = build_callback_nop_delta_records(
        before=before,
        after=after,
        callback_kind="optinsn_callback",
        callback_name="PeepholeOptimizer",
        callback_result=0,
        maturity="MMAT_GLBOPT2",
    )

    assert len(records) == 1
    assert records[0].payload["instruction_path"] == "top[0].l.d"
    assert records[0].payload["instruction_ea"] == "0x401014"


def test_optblock_callback_exception_logs_typed_context_before_rethrow(
    monkeypatch,
) -> None:
    """The SWIG boundary must not hide the callback traceback or its anchor."""
    block = _Block(
        serial=45,
        start=0x7FF859C07656,
        end=0x7FF859C07670,
        head=None,
    )
    _Mba(
        (block,),
        entry_ea=0x7FF859C06F60,
        maturity=ida_hexrays.MMAT_GLBOPT1,
    )
    observed = []
    logged = []

    monkeypatch.setattr(
        optblock_adapter,
        "observe_optblock_callback_exception",
        lambda **kwargs: observed.append(kwargs),
        raising=False,
    )
    monkeypatch.setattr(
        optblock_adapter,
        "optimizer_logger",
        SimpleNamespace(exception=lambda *args, **kwargs: logged.append((args, kwargs))),
    )
    monkeypatch.setattr(
        optblock_adapter,
        "maturity_to_string",
        lambda _maturity: "MMAT_GLBOPT1",
    )

    class _FailingManager:
        _pipeline_just_fired = False

        @staticmethod
        def _func(_blk):
            raise TypeError("deliberate callback failure")

    with pytest.raises(TypeError, match="deliberate callback failure"):
        BlockOptimizerManager.func(_FailingManager(), block)

    assert len(logged) == 1
    message, *args = logged[0][0]
    rendered = message % tuple(args)
    assert "func=0x7ff859c06f60" in rendered
    assert "maturity=MMAT_GLBOPT1" in rendered
    assert "blk45@0x7ff859c07656" in rendered
    assert "TypeError: deliberate callback failure" in rendered
    assert len(observed) == 1
    assert observed[0].items() >= {
        "func_ea": 0x7FF859C06F60,
        "maturity": "MMAT_GLBOPT1",
        "block_serial": 45,
        "block_ea": 0x7FF859C07656,
        "error_type": "TypeError",
        "error_message": "deliberate callback failure",
    }.items()
    assert "TypeError: deliberate callback failure" in observed[0]["traceback_text"]


def test_optblock_callback_damaged_start_clears_unpaired_block_serial(
    monkeypatch,
) -> None:
    """A damaged SWIG start accessor must not emit a serial without an EA."""

    class _DamagedStartBlock:
        serial = 45
        end = 0x7FF859C07670
        head = None

        @property
        def start(self) -> int:
            raise RuntimeError("damaged SWIG block start")

    block = _DamagedStartBlock()
    _Mba(
        (block,),
        entry_ea=0x7FF859C06F60,
        maturity=ida_hexrays.MMAT_GLBOPT1,
    )
    observed = []
    monkeypatch.setattr(
        optblock_adapter,
        "observe_optblock_callback_exception",
        lambda **kwargs: observed.append(kwargs),
        raising=False,
    )
    monkeypatch.setattr(
        optblock_adapter,
        "optimizer_logger",
        SimpleNamespace(exception=lambda *_args, **_kwargs: None),
    )
    monkeypatch.setattr(
        optblock_adapter,
        "maturity_to_string",
        lambda _maturity: "MMAT_GLBOPT1",
    )
    original = TypeError("original callback error")

    class _FailingManager:
        _pipeline_just_fired = False

        @staticmethod
        def _func(_blk):
            raise original

    with pytest.raises(TypeError) as raised:
        BlockOptimizerManager.func(_FailingManager(), block)

    assert raised.value is original
    assert len(observed) == 1
    assert observed[0]["block_serial"] is None
    assert observed[0]["block_ea"] is None


@pytest.mark.parametrize("failure_site", ("traceback", "logger", "publisher"))
def test_optblock_callback_diagnostic_failure_never_masks_original_error(
    monkeypatch,
    failure_site: str,
) -> None:
    """The SWIG boundary must preserve the original exception object exactly."""
    block = _Block(serial=45, start=0x401000, end=0x401020, head=None)
    _Mba((block,))
    original = TypeError("original optimizer callback failure")

    def _fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"diagnostic {failure_site} failure")

    if failure_site == "traceback":
        monkeypatch.setattr(optblock_adapter.traceback, "format_exc", _fail)
    elif failure_site == "logger":
        monkeypatch.setattr(
            optblock_adapter,
            "optimizer_logger",
            SimpleNamespace(exception=_fail),
        )
    else:
        monkeypatch.setattr(
            optblock_adapter,
            "observe_optblock_callback_exception",
            _fail,
            raising=False,
        )

    class _FailingManager:
        _pipeline_just_fired = False

        @staticmethod
        def _func(_blk):
            raise original

    with pytest.raises(TypeError) as raised:
        BlockOptimizerManager.func(_FailingManager(), block)

    assert raised.value is original


def test_block_optimizer_reports_a_rule_nop_write_that_returns_zero() -> None:
    instruction = _Instruction(ida_hexrays.m_mov, 0x401010)
    block = _Block(
        serial=4,
        start=0x401000,
        end=0x401020,
        head=instruction,
    )
    _Mba((block,))
    rule = _NopWritingRule(instruction)
    persisted = []
    manager = BlockOptimizerManager(
        OptimizationStatistics(),
        Path("."),
        ctx_cls=FlowMaturityContext,
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT2
    manager.configure(
        execution_scope_service=_ExecutionScope(rule),
        execution_scope_project_name="test",
        execution_scope_idb_key="test-idb",
        fact_consumer_callback=lambda _func_ea, records: persisted.extend(records),
    )

    assert manager.optimize(block) == 0

    assert len(persisted) == 1
    assert persisted[0].decision == "mutation_unreported"
    assert persisted[0].payload["callback_name"] == "unreported_nop_writer"


def test_block_optimizer_nop_diagnostics_are_callback_block_local() -> None:
    instruction = _Instruction(ida_hexrays.m_mov, 0x401010)
    block = _Block(
        serial=0,
        start=0x401000,
        end=0x401020,
        head=instruction,
    )
    _RejectUnrelatedBlockMba(
        (
            block,
            _Block(
                serial=1,
                start=0x402000,
                end=0x402020,
                head=_Instruction(ida_hexrays.m_mov, 0x402010),
            ),
        )
    )
    rule = _NopWritingRule(instruction)
    persisted = []
    manager = BlockOptimizerManager(
        OptimizationStatistics(),
        Path("."),
        ctx_cls=FlowMaturityContext,
    )
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT2
    manager.configure(
        execution_scope_service=_ExecutionScope(rule),
        execution_scope_project_name="test",
        execution_scope_idb_key="test-idb",
        fact_consumer_callback=lambda _func_ea, records: persisted.extend(records),
    )

    assert manager.optimize(block) == 0

    assert len(persisted) == 1
    assert persisted[0].decision == "mutation_unreported"
    assert persisted[0].payload["block_anchor"] == "blk0@0x401000"


def test_glbopt_reports_its_nop_write_with_merr_loop(
    monkeypatch,
) -> None:
    instruction = _Instruction(ida_hexrays.m_mov, 0x401010)
    mba = _Mba(
        (
            _Block(
                serial=0,
                start=0x401000,
                end=0x401020,
                head=instruction,
            ),
        )
    )
    probe = _GlboptNopProbe()
    hook = HexraysDecompilationHook(lambda *_args, **_kwargs: None)
    hook._block_optimizer = probe
    monkeypatch.setattr(
        HexraysDecompilationHook,
        "_decision_for_mba",
        lambda _self, _mba, **_kwargs: {},
    )
    monkeypatch.setattr(
        "d810.hexrays.hooks.hexrays_hooks.prune_unreachable_condition_chain",
        lambda *_args, **_kwargs: 0,
    )

    def create_nop(_mba, **_kwargs) -> int:
        instruction.opcode = ida_hexrays.m_nop
        return 1

    monkeypatch.setattr(
        "d810.hexrays.hooks.hexrays_hooks.apply_return_const_corruption_cleanup",
        create_nop,
    )

    assert hook.glbopt(mba) == ida_hexrays.MERR_LOOP

    assert len(probe.reports) == 1
    _, report = probe.reports[0]
    assert report["callback_kind"] == "glbopt_hook"
    assert report["callback_name"] == "return_const_corruption_cleanup"
    assert report["callback_result"] == ida_hexrays.MERR_LOOP
    assert [
        (inventory["stage"], len(inventory["sites"]))
        for _mba, inventory in probe.inventories
    ] == [("entry", 0), ("exit", 1)]


def test_instruction_optimizer_reports_a_nop_write_that_returns_false() -> None:
    instruction = _Instruction(ida_hexrays.m_mov, 0x401010)
    block = _Block(
        serial=9,
        start=0x401000,
        end=0x401020,
        head=instruction,
    )
    _Mba((block,))
    persisted = []
    manager = SimpleNamespace(
        _fact_consumer_callback=(lambda _func_ea, records: persisted.extend(records)),
        current_maturity=ida_hexrays.MMAT_GLBOPT2,
        instruction_visitor=SimpleNamespace(blk=None),
        _last_optimizer_tried="synthetic_nop_writer",
    )
    manager._capture_callback_nop_sites = MethodType(
        InstructionOptimizerManager._capture_callback_nop_sites,
        manager,
    )
    manager._report_callback_nop_delta = MethodType(
        InstructionOptimizerManager._report_callback_nop_delta,
        manager,
    )
    manager.log_info_on_input = lambda _blk, _ins: False

    def create_unreported_nop(_blk, _ins) -> bool:
        instruction.opcode = ida_hexrays.m_nop
        return False

    manager.optimize = create_unreported_nop

    assert InstructionOptimizerManager.func(manager, block, instruction) is False

    assert len(persisted) == 1
    assert persisted[0].decision == "mutation_unreported"
    assert persisted[0].payload["callback_kind"] == "optinsn_callback"


def test_instruction_optimizer_nop_diagnostics_are_callback_block_local() -> None:
    instruction = _Instruction(ida_hexrays.m_mov, 0x401010)
    block = _Block(
        serial=0,
        start=0x401000,
        end=0x401020,
        head=instruction,
    )
    _RejectUnrelatedBlockMba(
        (
            block,
            _Block(
                serial=1,
                start=0x402000,
                end=0x402020,
                head=_Instruction(ida_hexrays.m_mov, 0x402010),
            ),
        )
    )
    persisted = []
    manager = SimpleNamespace(
        _fact_consumer_callback=(lambda _func_ea, records: persisted.extend(records)),
        current_maturity=ida_hexrays.MMAT_GLBOPT2,
        instruction_visitor=SimpleNamespace(blk=None),
        _last_optimizer_tried="synthetic_nop_writer",
    )
    manager._capture_callback_nop_sites = MethodType(
        InstructionOptimizerManager._capture_callback_nop_sites,
        manager,
    )
    manager._report_callback_nop_delta = MethodType(
        InstructionOptimizerManager._report_callback_nop_delta,
        manager,
    )
    manager.log_info_on_input = lambda _blk, _ins: False

    def create_unreported_nop(_blk, _ins) -> bool:
        instruction.opcode = ida_hexrays.m_nop
        return False

    manager.optimize = create_unreported_nop

    assert InstructionOptimizerManager.func(manager, block, instruction) is False

    assert len(persisted) == 1
    assert persisted[0].decision == "mutation_unreported"
    assert persisted[0].payload["block_anchor"] == "blk0@0x401000"
