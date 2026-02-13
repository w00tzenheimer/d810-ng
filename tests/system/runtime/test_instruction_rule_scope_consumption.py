"""Runtime tests for instruction-pipeline rule-scope consumption."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import ida_hexrays

from d810.core.stats import OptimizationStatistics
from d810.hexrays.hexrays_hooks import InstructionOptimizerManager
from d810.optimizers.microcode.instructions.pattern_matching.handler import PatternOptimizer


class _NamedRule:
    def __init__(self, name: str):
        self.name = name


class _FakeRuleScopeService:
    def __init__(self, active_by_key: dict[tuple[int, int], tuple[_NamedRule, ...]]):
        self.active_by_key = active_by_key
        self.calls: list[tuple[int, int, str, str, str]] = []

    def get_active_rules(
        self,
        *,
        project_name: str,
        idb_key: str,
        func_ea: int,
        pipeline: str,
        maturity: int,
        function_tags=None,
    ) -> tuple[_NamedRule, ...]:
        self.calls.append((func_ea, maturity, pipeline, project_name, idb_key))
        return self.active_by_key.get((func_ea, maturity), tuple())


class _CaptureOptimizer:
    name = "CaptureOptimizer"

    def __init__(self):
        self.allowed: list[frozenset[str] | None] = []

    def get_optimized_instruction(
        self,
        blk,
        ins,
        *,
        allowed_rule_names: frozenset[str] | None = None,
    ):
        self.allowed.append(allowed_rule_names)
        return None


class _LegacyOptimizer:
    name = "LegacyOptimizer"

    def __init__(self):
        self.calls = 0

    def get_optimized_instruction(self, blk, ins):
        self.calls += 1
        return None


class _PatternRule:
    def __init__(self, name: str, replacement):
        self.name = name
        self._replacement = replacement
        self.calls = 0

    def check_pattern_and_replace(self, pattern, candidate):
        self.calls += 1
        return self._replacement


def _make_block(func_ea: int) -> SimpleNamespace:
    return SimpleNamespace(mba=SimpleNamespace(entry_ea=func_ea), serial=0)


def test_instruction_scope_cache_is_used_per_function_and_maturity(monkeypatch):
    monkeypatch.setattr(
        "d810.hexrays.hexrays_hooks.InstructionVisitorManager",
        lambda _optimizer: SimpleNamespace(),
    )
    manager = InstructionOptimizerManager(OptimizationStatistics(), Path("."))
    manager.analyzer = SimpleNamespace(analyze=lambda *_args, **_kwargs: None)
    capture = _CaptureOptimizer()
    manager.instruction_optimizers = [capture]

    scope_service = _FakeRuleScopeService(
        {
            (0x401000, 1): (_NamedRule("Rule.A"), _NamedRule("Rule.B")),
            (0x401000, 2): (_NamedRule("Rule.C"),),
            (0x402000, 2): (_NamedRule("Rule.D"),),
        }
    )
    manager.configure(
        rule_scope_service=scope_service,
        rule_scope_project_name="proj",
        rule_scope_idb_key="idb",
    )

    ins = SimpleNamespace(opcode=ida_hexrays.m_add)
    blk_401000 = _make_block(0x401000)

    manager.current_maturity = 1
    assert manager.optimize(blk_401000, ins) is False
    assert capture.allowed[-1] == frozenset({"Rule.A", "Rule.B"})
    assert len(scope_service.calls) == 1

    assert manager.optimize(blk_401000, ins) is False
    assert len(scope_service.calls) == 1

    manager.current_maturity = 2
    assert manager.optimize(blk_401000, ins) is False
    assert capture.allowed[-1] == frozenset({"Rule.C"})
    assert len(scope_service.calls) == 2

    blk_402000 = _make_block(0x402000)
    assert manager.optimize(blk_402000, ins) is False
    assert capture.allowed[-1] == frozenset({"Rule.D"})
    assert len(scope_service.calls) == 3


def test_instruction_optimizer_accepts_legacy_signature_without_filter_kwarg(monkeypatch):
    monkeypatch.setattr(
        "d810.hexrays.hexrays_hooks.InstructionVisitorManager",
        lambda _optimizer: SimpleNamespace(),
    )
    manager = InstructionOptimizerManager(OptimizationStatistics(), Path("."))
    manager.analyzer = SimpleNamespace(analyze=lambda *_args, **_kwargs: None)
    legacy = _LegacyOptimizer()
    manager.instruction_optimizers = [legacy]
    manager.current_maturity = 1

    assert manager.optimize(_make_block(0x401000), SimpleNamespace(opcode=ida_hexrays.m_add)) is False
    assert legacy.calls == 1


def test_pattern_optimizer_filters_matches_by_allowed_rule_names(monkeypatch):
    optimizer = PatternOptimizer([ida_hexrays.MMAT_PREOPTIMIZED], OptimizationStatistics(), log_dir=Path("."))
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

    monkeypatch.setattr(
        "d810.optimizers.microcode.instructions.pattern_matching.handler.minsn_to_ast",
        lambda _ins: object(),
    )

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
