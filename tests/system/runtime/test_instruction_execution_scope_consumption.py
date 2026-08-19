"""Runtime tests for instruction-pipeline execution-scope consumption."""

from __future__ import annotations

import os
import platform
from pathlib import Path
from types import SimpleNamespace

import ida_hexrays
import pytest

from d810.core.stats import OptimizationStatistics
from d810.core.execution_scope import ExecutionStageIdentity
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.ir.maturity import IRMaturity
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer
from d810.optimizers.microcode.instructions.pattern_matching import (
    handler as _pattern_handler,
)
from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternOptimizer,
)
from d810.passes.scheduler import PassScheduler, RunLater


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )


class _NamedImplementation:
    def __init__(self, name: str):
        self.name = name


class _FakeExecutionScopeService:
    def __init__(
        self,
        active_by_key: dict[tuple[int, int], tuple[_NamedImplementation, ...]],
    ):
        self.active_by_key = active_by_key
        self.calls: list[tuple[int, int, str, str, str]] = []
        self.scheduled_calls: list[tuple[ExecutionStageIdentity, ...]] = []

    def active_stages(
        self,
        *,
        project_name: str,
        idb_key: str,
        func_ea: int,
        pipeline: str,
        maturity: int,
        function_tags=None,
    ) -> tuple[SimpleNamespace, ...]:
        self.calls.append((func_ea, maturity, pipeline, project_name, idb_key))
        return tuple(
            SimpleNamespace(implementation=implementation)
            for implementation in self.active_by_key.get((func_ea, maturity), tuple())
        )

    def identity_for_implementation(self, implementation, *, pipeline):
        del pipeline
        if implementation.name != "Rule.RequestLater":
            return None
        return ExecutionStageIdentity(
            pass_id="request-later",
            stage_id="request-later",
        )

    def scheduled_stages(self, *, identities, func_ea, pipeline):
        del func_ea, pipeline
        resolved = tuple(identities)
        self.scheduled_calls.append(resolved)
        if resolved == (ExecutionStageIdentity("request-later", "request-later"),):
            return (
                SimpleNamespace(
                    implementation=_NamedImplementation("Rule.RequestLater")
                ),
            )
        return ()


class _CaptureOptimizer:
    name = "CaptureOptimizer"

    def __init__(self):
        self.allowed: list[frozenset[str] | None] = []
        self.scheduled: list[frozenset[str] | None] = []
        self.rules = ()

    def get_optimized_instruction(
        self,
        blk,
        ins,
        *,
        contextual_anchor_ins=None,
        allowed_rule_names: frozenset[str] | None = None,
        scheduled_rule_names: frozenset[str] | None = None,
    ):
        del contextual_anchor_ins
        self.allowed.append(allowed_rule_names)
        self.scheduled.append(scheduled_rule_names)
        return None


class _FastPortfolioRule:
    name = "Rule.Fast"
    PORTFOLIO_TIER = "fast"
    maturities = (1,)

    def __init__(self):
        self.admission_decisions: list[bool] = []

    def set_residual_admission(self, admitted: bool) -> None:
        self.admission_decisions.append(admitted)


class _PatternRule:
    def __init__(self, name: str, replacement):
        self.name = name
        self._replacement = replacement
        self.calls = 0
        self.maturities = [2, 3, 4, 5]

    def check_pattern_and_replace(self, pattern, candidate):
        self.calls += 1
        return self._replacement


class _ScheduledInstructionRule:
    name = "Rule.Scheduled"

    def __init__(self):
        self.maturities = [ida_hexrays.MMAT_GLBOPT1]
        self.calls = 0

    def check_and_replace(self, blk, ins):
        self.calls += 1
        return None


class _RunLaterRequestingRule:
    name = "Rule.RequestLater"

    def __init__(self):
        self._requests = (
            RunLater(
                IRMaturity.GLOBAL_OPTIMIZED,
                reason="needs GLBOPT2",
            ),
        )

    def drain_run_later_requests(self):
        requests = self._requests
        self._requests = ()
        return requests


class _CallbackInstruction:
    def __init__(self, fingerprint: int, *, ea: int = 0x401010) -> None:
        self.fingerprint = int(fingerprint)
        self.ea = int(ea)
        self.opcode = ida_hexrays.m_add
        self.swap_count = 0

    def _print(self) -> str:
        return f"callback:{self.fingerprint}"

    def swap(self, replacement) -> None:
        self.swap_count += 1
        self.fingerprint, replacement.fingerprint = (
            replacement.fingerprint,
            self.fingerprint,
        )

    def optimize_solo(self) -> None:
        return None

    def for_all_insns(self, _visitor) -> bool:
        return False


class _CallbackOptimizer:
    name = "CallbackOptimizer"
    rules = ()

    def __init__(self, replacements) -> None:
        self.replacements = tuple(replacements)
        self.last_matched_rule_name = "Rule.Callback"
        self._pending_replacement_rule = SimpleNamespace(name="Rule.Callback")
        self.accepted = 0
        self.rejected = []
        self.calls = 0

    def get_optimized_instruction(
        self,
        _blk,
        _ins,
        *,
        allowed_rule_names=None,
        scheduled_rule_names=None,
    ):
        del allowed_rule_names, scheduled_rule_names
        self.calls += 1
        return self.replacements[0] if self.replacements else None

    def record_mutation_accepted(self) -> None:
        self.accepted += 1

    def record_mutation_rejected(self, reason: str) -> None:
        self.rejected.append(reason)


def _make_block(func_ea: int) -> SimpleNamespace:
    block = SimpleNamespace(mba=SimpleNamespace(entry_ea=func_ea), serial=0)
    block.mark_lists_dirty = lambda: None
    return block


def _make_callback_manager(*optimizers) -> InstructionOptimizerManager:
    manager = object.__new__(InstructionOptimizerManager)
    manager._decompilation_lifecycle = None
    manager._fact_consumer_callback = None
    manager._execution_scope_service = None
    manager._execution_scope_project_name = ""
    manager._execution_scope_idb_key = ""
    manager._execution_scope_func_ea = -1
    manager._active_instruction_rule_names_by_maturity = {}
    manager._residual_admission_cache_key = None
    manager._residual_admission_cache_value = False
    manager.current_maturity = ida_hexrays.MMAT_GLBOPT2
    manager.instruction_visitor = SimpleNamespace(blk=None)
    manager._active_optimizers = list(optimizers)
    manager.instruction_optimizers = list(optimizers)
    manager._scheduled_implementation_names = frozenset()
    manager._last_optimizer_tried = None
    manager._rewrite_seen = {}
    manager._cycle_quarantined_rule_names = {}
    manager.log_info_on_input = lambda _blk, _ins: False
    manager.analyzer = SimpleNamespace(analyze=lambda *_args, **_kwargs: None)
    manager._capture_callback_nop_sites = lambda _block: None
    manager._report_callback_nop_delta = lambda _block, **_kwargs: None
    return manager


class TestInstructionScopeCaching:
    """Tests for InstructionOptimizerManager rule-scope caching behavior.

    Requires a real IDB so that minsn_visitor_t.__init__() (called inside
    InstructionOptimizerManager.__init__) has valid IDA state.
    """

    binary_name = _get_default_binary()

    def test_instruction_scope_cache_is_used_per_function_and_maturity(
        self, libobfuscated_setup
    ):
        manager = InstructionOptimizerManager(
            OptimizationStatistics(), Path("."), optimizer_cls=InstructionOptimizer
        )
        manager.analyzer = SimpleNamespace(analyze=lambda *_args, **_kwargs: None)
        capture = _CaptureOptimizer()
        manager.instruction_optimizers = [capture]
        manager._active_optimizers = list(manager.instruction_optimizers)

        scope_service = _FakeExecutionScopeService(
            {
                (0x401000, 1): (
                    _NamedImplementation("Rule.A"),
                    _NamedImplementation("Rule.B"),
                ),
                (0x401000, 2): (_NamedImplementation("Rule.C"),),
                (0x402000, 2): (_NamedImplementation("Rule.D"),),
            }
        )
        manager.configure(
            execution_scope_service=scope_service,
            execution_scope_project_name="proj",
            execution_scope_idb_key="idb",
        )

        ins = SimpleNamespace(opcode=ida_hexrays.m_add)
        blk_401000 = _make_block(0x401000)

        manager.current_maturity = 1
        assert manager.optimize(blk_401000, ins) is False
        assert capture.allowed[-1] == frozenset({"Rule.A", "Rule.B"})
        assert capture.scheduled[-1] == frozenset()
        assert len(scope_service.calls) == 1

        # Second call with same (func_ea, maturity) must NOT re-query the service.
        assert manager.optimize(blk_401000, ins) is False
        assert len(scope_service.calls) == 1

        # New maturity → new query.
        manager.current_maturity = 2
        assert manager.optimize(blk_401000, ins) is False
        assert capture.allowed[-1] == frozenset({"Rule.C"})
        assert capture.scheduled[-1] == frozenset()
        assert len(scope_service.calls) == 2

        # New func_ea → new query.
        blk_402000 = _make_block(0x402000)
        assert manager.optimize(blk_402000, ins) is False
        assert capture.allowed[-1] == frozenset({"Rule.D"})
        assert capture.scheduled[-1] == frozenset()
        assert len(scope_service.calls) == 3

    def test_residual_admission_scans_fast_rules_once_per_scope(
        self, libobfuscated_setup
    ):
        manager = InstructionOptimizerManager(
            OptimizationStatistics(), Path("."), optimizer_cls=InstructionOptimizer
        )
        manager.analyzer = SimpleNamespace(analyze=lambda *_args, **_kwargs: None)
        capture = _CaptureOptimizer()
        fast_rule = _FastPortfolioRule()
        capture.rules = (fast_rule,)
        manager.instruction_optimizers = [capture]
        manager._active_optimizers = [capture]
        manager.current_maturity = 1
        manager.configure(
            execution_scope_service=_FakeExecutionScopeService(
                {(0x401000, 1): (_NamedImplementation("Rule.Fast"),)}
            ),
            execution_scope_project_name="proj",
            execution_scope_idb_key="idb",
        )

        rule_name = manager._rule_name
        fast_rule_name_lookups = 0

        def count_fast_rule_name(candidate):
            nonlocal fast_rule_name_lookups
            if candidate is fast_rule:
                fast_rule_name_lookups += 1
            return rule_name(candidate)

        manager._rule_name = count_fast_rule_name
        block = _make_block(0x401000)
        instruction = SimpleNamespace(opcode=ida_hexrays.m_add)

        assert manager.optimize(block, instruction) is False
        assert manager.optimize(block, instruction) is False

        assert fast_rule_name_lookups == 1
        assert fast_rule.admission_decisions == [True, True]

        assert manager.optimize(_make_block(0x402000), instruction) is False

        assert fast_rule_name_lookups == 2
        assert fast_rule.admission_decisions == [True, True, False]

    def test_instruction_run_later_request_joins_execution_scope_names(
        self, libobfuscated_setup
    ):
        manager = InstructionOptimizerManager(
            OptimizationStatistics(), Path("."), optimizer_cls=InstructionOptimizer
        )
        manager.analyzer = SimpleNamespace(analyze=lambda *_args, **_kwargs: None)
        capture = _CaptureOptimizer()
        manager.instruction_optimizers = [capture]
        manager._active_optimizers = list(manager.instruction_optimizers)
        manager.current_maturity = ida_hexrays.MMAT_GLBOPT1
        scope_service = _FakeExecutionScopeService({})
        manager.configure(
            execution_scope_service=scope_service,
            execution_scope_project_name="proj",
            execution_scope_idb_key="idb",
            pass_scheduler=PassScheduler(),
        )
        manager._execution_scope_func_ea = 0x401000

        manager._record_run_later_requests(
            _RunLaterRequestingRule(),
            ida_hexrays.MMAT_GLBOPT1,
        )
        manager.current_maturity = ida_hexrays.MMAT_GLBOPT2
        manager._drain_run_later_for_maturity(
            SimpleNamespace(entry_ea=0x401000),
        )

        assert manager.optimize(_make_block(0x401000), SimpleNamespace()) is False
        assert capture.allowed[-1] == frozenset({"Rule.RequestLater"})
        assert capture.scheduled[-1] == frozenset({"Rule.RequestLater"})
        assert scope_service.scheduled_calls == [
            (ExecutionStageIdentity("request-later", "request-later"),)
        ]


def test_instruction_optimizer_scheduled_rule_bypasses_static_maturity():
    optimizer = InstructionOptimizer(
        [ida_hexrays.MMAT_GLBOPT1],
        OptimizationStatistics(),
        log_dir=Path("."),
    )
    rule = _ScheduledInstructionRule()
    optimizer.rules = {rule}
    blk = SimpleNamespace(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_GLBOPT2),
    )

    optimizer.get_optimized_instruction(
        blk,
        SimpleNamespace(opcode=ida_hexrays.m_add),
        allowed_rule_names=frozenset({"Rule.Scheduled"}),
    )
    assert rule.calls == 0

    optimizer.get_optimized_instruction(
        blk,
        SimpleNamespace(opcode=ida_hexrays.m_add),
        allowed_rule_names=frozenset({"Rule.Scheduled"}),
        scheduled_rule_names=frozenset({"Rule.Scheduled"}),
    )
    assert rule.calls == 1


def test_pattern_optimizer_filters_matches_by_allowed_rule_names(monkeypatch):
    optimizer = PatternOptimizer(
        [ida_hexrays.MMAT_PREOPTIMIZED], OptimizationStatistics(), log_dir=Path(".")
    )
    optimizer._use_legacy_storage = True
    optimizer.rules = {object()}
    optimizer._allowed_root_opcodes = {ida_hexrays.m_add}

    rule_disabled = _PatternRule(
        "Rule.Disabled",
        SimpleNamespace(tag="disabled", _print=lambda: "disabled", ea=0x401000),
    )
    rule_enabled = _PatternRule(
        "Rule.Enabled",
        SimpleNamespace(tag="enabled", _print=lambda: "enabled", ea=0x401000),
    )
    optimizer.pattern_storage = SimpleNamespace(
        get_matching_rule_pattern_info=lambda _ast: [
            SimpleNamespace(rule=rule_disabled, pattern=object()),
            SimpleNamespace(rule=rule_enabled, pattern=object()),
        ]
    )

    monkeypatch.setattr(_pattern_handler, "minsn_to_ast", lambda _ins: object())

    blk = SimpleNamespace(mba=SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED))
    ins = SimpleNamespace(opcode=ida_hexrays.m_add, _print=lambda: "orig", ea=0x401000)

    new_ins = optimizer.get_optimized_instruction(
        blk,
        ins,
        allowed_rule_names=frozenset({"Rule.Enabled"}),
    )

    assert new_ins is not None
    assert getattr(new_ins, "tag", "") == "enabled"
    assert rule_disabled.calls == 0
    assert rule_enabled.calls == 1


def test_instruction_callback_normalizes_legacy_and_sdk_signatures_and_preserves_optflags():
    """Both callback ABI shapes must reach one context/committer path."""
    manager = _make_callback_manager()

    block = _make_block(0x401000)
    instruction = _CallbackInstruction(1)
    observed = []
    contexts = []

    real_context_factory = InstructionOptimizerManager._build_instruction_commit_context

    def capture_context(block, instruction_value, optflags):
        context = real_context_factory(manager, block, instruction_value, optflags)
        observed.append(optflags)
        contexts.append(context)
        return context

    manager._build_instruction_commit_context = capture_context
    manager.optimize = lambda _blk, _ins: False

    assert InstructionOptimizerManager.func(manager, block, instruction) == 0
    no_neighbor_flag = int(getattr(ida_hexrays, "OPTI_NO_LDXOPT", 0x8))
    assert InstructionOptimizerManager.func(manager, block, instruction, no_neighbor_flag) == 0
    assert observed == [0, no_neighbor_flag]
    assert contexts[0].capabilities.may_touch_neighboring_instructions is True
    assert contexts[1].capabilities.may_touch_neighboring_instructions is False


def test_instruction_callback_rejects_unknown_sdk_argument_count():
    manager = object.__new__(InstructionOptimizerManager)
    with pytest.raises(TypeError, match="two or three"):
        InstructionOptimizerManager.func(manager, None, _CallbackInstruction(1), 0, 1)


def test_instruction_context_builder_uses_mba_maturity_without_manager_state():
    """Quarantine callbacks may use object.__new__ manager test doubles."""
    manager = object.__new__(InstructionOptimizerManager)
    mba = SimpleNamespace(entry_ea=0x401000, maturity=ida_hexrays.MMAT_LOCOPT)
    block = SimpleNamespace(mba=mba)

    context = InstructionOptimizerManager._build_instruction_commit_context(
        manager,
        block,
        _CallbackInstruction(1),
        0,
    )

    assert context.epoch.function_ea == 0x401000
    assert context.epoch.maturity == ida_hexrays.MMAT_LOCOPT


def test_instruction_callback_null_block_skips_block_required_rule_before_mba_access(
    monkeypatch,
):
    monkeypatch.setattr(
        "d810.hexrays.hooks.optinsn_adapter.check_ins_mop_size_are_ok",
        lambda _instruction: True,
    )

    class _BlockRequiredRule:
        name = "Rule.BlockRequired"
        requires_block_context = True

        def __init__(self):
            self.calls = 0

        def check_and_replace(self, block, _ins):
            self.calls += 1
            raise AssertionError(f"unexpected block access: {block.mba}")

    class _ContextFreeRule:
        name = "Rule.ContextFree"
        requires_block_context = False

        def check_and_replace(self, _block, _ins):
            return _CallbackInstruction(2)

    class _Optimizer:
        name = "ContextOptimizer"

        def __init__(self):
            self.block_required = _BlockRequiredRule()
            self.context_free = _ContextFreeRule()
            self.rules = (self.block_required, self.context_free)
            self.last_matched_rule_name = None
            self._pending_replacement_rule = None
            self.calls = []
            self.accepted = 0

        def get_optimized_instruction(self, block, ins, *, allowed_rule_names, **_kwargs):
            self.calls.append((block, ins))
            for rule in self.rules:
                if allowed_rule_names is not None and rule.name not in allowed_rule_names:
                    continue
                replacement = rule.check_and_replace(block, ins)
                if replacement is not None:
                    self.last_matched_rule_name = rule.name
                    self._pending_replacement_rule = rule
                    return replacement
            return None

        def record_mutation_accepted(self):
            self.accepted += 1

        def record_mutation_rejected(self, _reason):
            raise AssertionError("context-free candidate should commit")

    optimizer = _Optimizer()
    manager = _make_callback_manager(optimizer)
    manager._resolve_active_instruction_rule_names = lambda _block: frozenset(
        {"Rule.BlockRequired", "Rule.ContextFree"}
    )

    result = InstructionOptimizerManager.func(manager, None, _CallbackInstruction(1))

    assert result == 1
    assert len(optimizer.calls) == 1
    assert optimizer.calls[0][0] is None
    assert optimizer.block_required.calls == 0
    assert optimizer.accepted == 1


def test_instruction_callback_commits_first_matching_rule_once(monkeypatch):
    monkeypatch.setattr(
        "d810.hexrays.hooks.optinsn_adapter.check_ins_mop_size_are_ok",
        lambda _instruction: True,
    )
    monkeypatch.setattr(
        "d810.hexrays.hooks.optinsn_adapter._safe_verify",
        lambda *_args, **_kwargs: None,
    )
    first = _CallbackInstruction(2)
    second = _CallbackInstruction(3)
    winner = _CallbackOptimizer((first,))
    loser = _CallbackOptimizer((second,))
    manager = _make_callback_manager(winner, loser)

    result = InstructionOptimizerManager.func(
        manager,
        _make_block(0x401000),
        _CallbackInstruction(1),
    )

    assert result == 1
    assert winner.calls == 1
    assert winner.accepted == 1
    assert loser.calls == 0


def test_instruction_callback_does_not_visit_nested_rules_after_rejection(monkeypatch):
    monkeypatch.setattr(
        "d810.hexrays.hooks.optinsn_adapter.check_ins_mop_size_are_ok",
        lambda _instruction: True,
    )
    monkeypatch.setattr(
        "d810.hexrays.hooks.optinsn_adapter._safe_verify",
        lambda *_args, **_kwargs: None,
    )
    optimizer = _CallbackOptimizer((_CallbackInstruction(1),))
    manager = _make_callback_manager(optimizer)
    nested_calls = []
    instruction = _CallbackInstruction(1)
    instruction.for_all_insns = lambda visitor: nested_calls.append(visitor) or True

    result = InstructionOptimizerManager.func(
        manager,
        _make_block(0x401000),
        instruction,
    )

    assert result == 0
    assert optimizer.rejected == ["rewrite-noop"]
    assert nested_calls == []
