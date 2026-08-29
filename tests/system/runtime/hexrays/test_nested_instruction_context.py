"""Runtime contracts for nested instruction ownership context."""

from __future__ import annotations

from collections import defaultdict
import platform
from types import SimpleNamespace

import pytest


def _block(*, maturity: int, entry_ea: int = 0x401000) -> SimpleNamespace:
    return SimpleNamespace(
        mba=SimpleNamespace(entry_ea=entry_ea, maturity=maturity),
        serial=0,
    )


class _CaptureOptimizer:
    name = "CaptureOptimizer"
    rules = ()

    def __init__(self) -> None:
        self.calls: list[tuple[object, object, object]] = []

    def get_optimized_instruction(
        self,
        blk,
        ins,
        *,
        contextual_anchor_ins=None,
        allowed_rule_names=None,
        scheduled_rule_names=None,
    ):
        del allowed_rule_names, scheduled_rule_names
        self.calls.append((blk, ins, contextual_anchor_ins))
        return None


def _manager(capture: _CaptureOptimizer):
    from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager

    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager._active_optimizers = [capture]
    manager._last_optimizer_tried = None
    manager._cycle_quarantined_rule_names = defaultdict(set)
    manager._scheduled_implementation_names = frozenset()
    manager._residual_admission_cache_key = None
    manager._residual_admission_cache_value = False
    manager.current_maturity = 2
    manager.stats = None
    manager.generate_z3_code = False
    manager.analyzer = SimpleNamespace(analyze=lambda *_args, **_kwargs: None)
    manager._resolve_active_instruction_rule_names = lambda _blk: frozenset()
    manager._has_active_fast_mba_provider = lambda **_kwargs: False
    return manager


@pytest.mark.runtime
def test_direct_instruction_optimization_defaults_anchor_to_candidate() -> None:
    import ida_hexrays

    capture = _CaptureOptimizer()
    manager = _manager(capture)
    block = _block(maturity=ida_hexrays.MMAT_LOCOPT)
    candidate = SimpleNamespace(opcode=ida_hexrays.m_mov, ea=0x401010)

    assert manager.optimize(block, candidate) is False
    assert capture.calls == [(block, candidate, candidate)]


@pytest.mark.runtime
def test_nested_instruction_visitor_uses_top_level_owner_as_anchor() -> None:
    from d810.hexrays.hooks.optinsn_adapter import InstructionVisitorManager

    calls: list[tuple[object, object, object]] = []

    class _Manager:
        def optimize(
            self,
            block,
            candidate,
            *,
            contextual_anchor_ins=None,
            **_kwargs,
        ):
            calls.append((block, candidate, contextual_anchor_ins))
            return False

    block = object()
    candidate = object()
    owner = object()
    visitor = SimpleNamespace(
        instruction_optimizer=_Manager(),
        blk=block,
        curins=candidate,
        topins=owner,
    )

    assert InstructionVisitorManager.visit_minsn(visitor) is False
    assert calls == [(block, candidate, owner)]


@pytest.mark.runtime
def test_nested_instruction_visitor_falls_back_to_candidate_without_topins() -> None:
    from d810.hexrays.hooks.optinsn_adapter import InstructionVisitorManager

    calls: list[object] = []

    class _Manager:
        def optimize(
            self,
            _block,
            _candidate,
            *,
            contextual_anchor_ins=None,
            **_kwargs,
        ):
            calls.append(contextual_anchor_ins)
            return False

    candidate = object()
    visitor = SimpleNamespace(
        instruction_optimizer=_Manager(),
        blk=object(),
        curins=candidate,
    )

    assert InstructionVisitorManager.visit_minsn(visitor) is False
    assert calls == [candidate]


@pytest.mark.runtime
def test_lnot_contextual_prover_uses_definition_anchor(monkeypatch) -> None:
    import ida_hexrays

    from d810.backends.ast.z3_proof_policy import Z3ProofResult, Z3ProofStatus
    import d810.optimizers.microcode.instructions.z3.predicates as predicates

    class _Prover:
        instances: list["_Prover"] = []

        def __init__(self, *, blk=None, ins=None, policy=None):
            self.blk = blk
            self.ins = ins
            self.policy = policy
            type(self).instances.append(self)

        def prove_always_zero(self, _mop):
            return Z3ProofResult(
                status=Z3ProofStatus.PROVED,
                reason=None,
                observed_expression_nodes=1,
                elapsed_ms=0.1,
            )

    monkeypatch.setattr(predicates, "Z3MopProver", _Prover)
    rule = predicates.Z3lnotRuleGeneric()
    rule.configure({})
    rule._current_blk = object()
    rule._current_ins = object()
    definition_anchor = object()
    rule._definition_search_ins = definition_anchor

    x0 = SimpleNamespace(t=ida_hexrays.mop_r, size=4)

    class _Candidate:
        dst_mop = SimpleNamespace(size=1)

        def __getitem__(self, name: str):
            if name == "x_0":
                return SimpleNamespace(mop=x0)
            raise KeyError(name)

    candidate = _Candidate()
    additions: list[tuple[str, int, int]] = []
    candidate.add_constant_leaf = lambda name, value, size: additions.append(
        (name, value, size)
    )

    assert rule.check_candidate(candidate) is True
    assert additions == [("val_res", 1, 1)]
    assert _Prover.instances[0].ins is definition_anchor


@pytest.mark.runtime
def test_z3_context_is_cleared_when_rule_check_raises(monkeypatch) -> None:
    from d810.optimizers.microcode.instructions.handler import GenericPatternRule
    from d810.optimizers.microcode.instructions.z3.predicates import (
        Z3lnotRuleGeneric,
    )

    def _raise(_self, _blk, _instruction):
        raise RuntimeError("sentinel")

    monkeypatch.setattr(GenericPatternRule, "check_and_replace", _raise)
    rule = Z3lnotRuleGeneric()
    block = object()
    candidate = object()
    owner = object()

    with pytest.raises(RuntimeError, match="sentinel"):
        rule.check_and_replace(
            block,
            candidate,
            contextual_anchor_ins=owner,
        )

    assert rule._current_blk is None
    assert rule._current_ins is None
    assert rule._definition_search_ins is None


@pytest.mark.runtime
def test_z3_constant_override_accepts_nested_owner_context(monkeypatch) -> None:
    """Pattern-less Z3 rules must preserve the contextual-call contract."""

    import d810.optimizers.microcode.instructions.z3.cst as cst

    monkeypatch.setattr(cst, "minsn_to_ast", lambda _instruction: None)
    rule = cst.Z3ConstantOptimization()
    block = object()
    candidate = object()
    owner = object()

    assert (
        rule.check_and_replace_with_context(
            block,
            candidate,
            contextual_anchor_ins=owner,
        )
        is None
    )
    assert rule._current_blk is None
    assert rule._current_ins is None
    assert rule._definition_search_ins is None


class TestNativeNestedInstructionTraversal:
    """Exercise the owner seam through Hex-Rays' real nested-instruction walk."""

    binary_name = (
        "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"
    )

    def test_for_all_insns_binds_and_restores_owner_anchor(self, libobfuscated_setup):
        import ida_hexrays
        import idc

        from tests.system.runtime.conftest import gen_microcode_at_maturity

        from d810.hexrays.hooks.optinsn_adapter import (
            InstructionOptimizerManager,
            InstructionVisitorManager,
        )

        class _NativeCaptureManager:
            def __init__(self) -> None:
                self.calls: list[tuple[object, object, object]] = []

            def optimize(
                self,
                block,
                candidate,
                *,
                contextual_anchor_ins=None,
                **_kwargs,
            ):
                self.calls.append((block, candidate, contextual_anchor_ins))
                return False

        def _empty_mop():
            mop = ida_hexrays.mop_t()
            mop.erase()
            return mop

        def _number(value: int, size: int):
            mop = ida_hexrays.mop_t()
            mop.make_number(value, size)
            return mop

        nested = ida_hexrays.minsn_t(0x401014)
        nested.opcode = ida_hexrays.m_add
        nested.l = _number(1, 4)
        nested.r = _number(2, 4)
        nested.d = _empty_mop()

        nested_mop = ida_hexrays.mop_t()
        nested_mop.create_from_insn(nested)
        nested_mop.size = 4

        owner = ida_hexrays.minsn_t(0x401000)
        owner.opcode = ida_hexrays.m_mov
        owner.l = nested_mop
        owner.r = _empty_mop()
        owner.d = _empty_mop()

        capture = _NativeCaptureManager()
        visitor = InstructionVisitorManager(capture)
        source_ea = idc.get_name_ea_simple("test_cst_simplification")
        mba = gen_microcode_at_maturity(source_ea, ida_hexrays.MMAT_LOCOPT)
        assert mba is not None
        block = mba.get_mblock(0)
        manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
        manager.__dict__.update(
            dict(
                _decompilation_lifecycle=None,
                _last_optimizer_tried=None,
                instruction_visitor=visitor,
                log_info_on_input=lambda *_args: False,
                optimize=lambda *_args: False,
                _capture_callback_nop_sites=lambda *_args: None,
                _report_callback_nop_delta=lambda *_args, **_kwargs: None,
            )
        )

        assert manager.func(block, owner) is False

        nested_calls = [call for call in capture.calls if call[1] is not owner]
        assert nested_calls, capture.calls
        assert all(call[2] is owner for call in nested_calls), capture.calls
        assert not hasattr(visitor, "_contextual_anchor_ins")
