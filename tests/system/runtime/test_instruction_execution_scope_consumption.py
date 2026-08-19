"""Runtime tests for instruction-pipeline execution-scope consumption."""

from __future__ import annotations

import os
import platform
from pathlib import Path
from types import SimpleNamespace

import ida_hexrays

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


def _make_block(func_ea: int) -> SimpleNamespace:
    return SimpleNamespace(mba=SimpleNamespace(entry_ea=func_ea), serial=0)


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
