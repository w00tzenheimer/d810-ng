"""Tests for optimizer pre-filtering layers (maturity gate, active list, operand check)."""

from __future__ import annotations

from collections import defaultdict
from types import SimpleNamespace

import ida_hexrays

from d810.core.decompilation_session import DecompilationEvent
from d810.core.stats import OptimizationStatistics
from d810.hexrays.hooks import optinsn_adapter
from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer
from d810.optimizers.microcode.instructions.peephole.fold_readonlydata import (
    _has_potential_readonly_operand,
)


class _StubRule:
    """Minimal rule stub that records check_and_replace calls."""

    def __init__(self, name: str, maturities: list[int] | None = None):
        self.name = name
        self.maturities = maturities or [
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
        ]
        self.calls = 0

    def check_and_replace(self, blk, ins):
        self.calls += 1
        return None

    def record_mutation_accepted(self):
        pass

    def record_mutation_rejected(self, _reason: str):
        pass


class _ConcreteOptimizer(InstructionOptimizer):
    """Concrete subclass for testing (InstructionOptimizer is generic)."""

    RULE_CLASSES = [object]  # Accept any rule via isinstance

    def add_rule(self, rule):
        self.rules.add(rule)
        return True


def _make_blk(maturity: int) -> SimpleNamespace:
    return SimpleNamespace(mba=SimpleNamespace(maturity=maturity), serial=0)


def _make_ins(opcode: int = ida_hexrays.m_mov) -> SimpleNamespace:
    return SimpleNamespace(opcode=opcode, ea=0x1000)


class _MutationRule:
    """Rule stub whose metadata changes only at the mutation boundary."""

    name = "MutationRule"
    maturities = [ida_hexrays.MMAT_LOCOPT]

    def __init__(self, replacement):
        self.replacement = replacement
        self.accepted = False
        self.rejected_reason = None

    def check_and_replace(self, _blk, _ins):
        return self.replacement

    def record_mutation_accepted(self):
        self.accepted = True

    def record_mutation_rejected(self, reason: str):
        self.rejected_reason = reason

    def execution_metadata(self):
        return {
            "mba_provider_outcome": {
                "provider": "catalogue",
                "status": "applied" if self.accepted else "improved",
            }
        }


class _SwappableInstruction:
    def __init__(self, label: str, *, valid: bool):
        self.label = label
        self.valid = valid
        self.opcode = ida_hexrays.m_mov
        self.ea = 0x401000

    def swap(self, other):
        self.label, other.label = other.label, self.label
        self.valid, other.valid = other.valid, self.valid

    def _print(self):
        return self.label


def _mutation_manager(optimizer, stats):
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager.current_maturity = ida_hexrays.MMAT_LOCOPT
    manager._active_optimizers = [optimizer]
    manager._last_optimizer_tried = None
    manager._rewrite_seen = defaultdict(set)
    manager._scheduled_implementation_names = frozenset()
    manager._resolve_active_instruction_rule_names = lambda _blk: None
    manager.analyzer = SimpleNamespace(analyze=lambda _blk, _ins: None)
    manager.stats = stats
    manager.generate_z3_code = False
    return manager


def test_maturity_gate_blocks_optimizer_at_wrong_maturity():
    """Layer 1: optimizer-level maturity gate skips entire optimizer."""
    stats = OptimizationStatistics()
    opt = _ConcreteOptimizer(
        maturities=[ida_hexrays.MMAT_GENERATED, ida_hexrays.MMAT_PREOPTIMIZED],
        stats=stats,
    )
    rule = _StubRule(
        "EarlyRule",
        maturities=[ida_hexrays.MMAT_GENERATED, ida_hexrays.MMAT_PREOPTIMIZED],
    )
    opt.add_rule(rule)

    blk = _make_blk(ida_hexrays.MMAT_LOCOPT)
    ins = _make_ins()

    result = opt.get_optimized_instruction(blk, ins)

    assert result is None
    assert rule.calls == 0, f"Rule was called {rule.calls} times at wrong maturity"


def test_maturity_gate_allows_optimizer_at_correct_maturity():
    """Layer 1: optimizer passes through at correct maturity."""
    stats = OptimizationStatistics()
    opt = _ConcreteOptimizer(
        maturities=[
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
        ],
        stats=stats,
    )
    rule = _StubRule("LocoptRule")
    opt.add_rule(rule)

    blk = _make_blk(ida_hexrays.MMAT_LOCOPT)
    ins = _make_ins()

    result = opt.get_optimized_instruction(blk, ins)

    assert result is None  # Rule returns None
    assert rule.calls == 1, "Rule was not called at correct maturity"


def test_optimizer_quarantines_only_the_rule_that_closed_a_rewrite_cycle():
    """A cycle must stop its producer, not every rule at the instruction."""
    stats = OptimizationStatistics()
    opt = _ConcreteOptimizer(
        maturities=[ida_hexrays.MMAT_LOCOPT],
        stats=stats,
    )
    cobra = _StubRule("CobraSolveRule", maturities=[ida_hexrays.MMAT_LOCOPT])
    independent = _StubRule("IndependentRule", maturities=[ida_hexrays.MMAT_LOCOPT])
    opt.add_rule(cobra)
    opt.add_rule(independent)

    opt.set_cycle_quarantined_rule_names(frozenset({"CobraSolveRule"}))
    result = opt.get_optimized_instruction(
        _make_blk(ida_hexrays.MMAT_LOCOPT),
        _make_ins(),
    )

    assert result is None
    assert cobra.calls == 0
    assert independent.calls == 1


def test_cycle_detection_allows_represented_pre_state_but_quarantines_a_revisit(
    monkeypatch,
):
    """Only a return to X after X -> Y is a rewrite cycle at one site."""
    from d810.hexrays.hooks import optinsn_adapter
    from d810.optimizers.microcode.instructions import handler as handler_module

    class _SwappableInstruction:
        def __init__(self, form: str):
            self.form = form
            self.ea = 0x7FF856F84A8E

        def swap(self, other):
            self.form, other.form = other.form, self.form

    class _TransitionRule(_StubRule):
        def check_and_replace(self, _blk, ins):
            self.calls += 1
            return _SwappableInstruction({"X": "Y", "Y": "X"}[ins.form])

    monkeypatch.setattr(optinsn_adapter, "check_ins_mop_size_are_ok", lambda _ins: True)
    monkeypatch.setattr(optinsn_adapter, "count_minsn_nodes", lambda _ins: 1)
    monkeypatch.setattr(
        optinsn_adapter,
        "hash_minsn",
        lambda ins, _func_ea=0: hash(ins.form),
    )
    monkeypatch.setattr(handler_module, "format_minsn_t", lambda ins: ins.form)

    rule = _TransitionRule("CobraSolveRule", [ida_hexrays.MMAT_LOCOPT])
    optimizer = _ConcreteOptimizer([ida_hexrays.MMAT_LOCOPT], stats=None)
    optimizer.add_rule(rule)
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager._active_optimizers = [optimizer]
    manager._rewrite_seen = defaultdict(set)
    manager._cycle_quarantined_rule_names = defaultdict(set)
    manager.current_maturity = ida_hexrays.MMAT_LOCOPT
    manager.stats = None
    manager.generate_z3_code = False
    manager.analyzer = SimpleNamespace(analyze=lambda _blk, _ins: None)
    manager._resolve_active_instruction_rule_names = lambda _blk: None
    manager._scheduled_implementation_names = frozenset()
    blk = SimpleNamespace(
        mba=SimpleNamespace(
            entry_ea=0x7FF856F83C70,
            maturity=ida_hexrays.MMAT_LOCOPT,
        )
    )

    first_x = _SwappableInstruction("X")
    assert manager.optimize(blk, first_x)
    assert first_x.form == "Y"

    represented_x = _SwappableInstruction("X")
    assert manager.optimize(blk, represented_x)
    assert represented_x.form == "Y"

    assert manager.optimize(blk, first_x)
    assert first_x.form == "X"
    assert not manager.optimize(blk, first_x)
    assert manager._cycle_quarantined_rule_names[
        (0x7FF856F83C70, ida_hexrays.MMAT_LOCOPT, 0x7FF856F84A8E)
    ] == {"CobraSolveRule"}


def test_cycle_detection_rejects_a_noop_without_quarantining_its_producer(
    monkeypatch,
):
    """A rule returning the current form cannot keep the callback alive."""
    from d810.hexrays.hooks import optinsn_adapter
    from d810.optimizers.microcode.instructions import handler as handler_module

    class _SwappableInstruction:
        def __init__(self, form: str):
            self.form = form
            self.ea = 0x7FF856F84A8E

        def swap(self, other):
            self.form, other.form = other.form, self.form

    class _IdempotentRule(_StubRule):
        def check_and_replace(self, _blk, ins):
            self.calls += 1
            return _SwappableInstruction(ins.form)

    monkeypatch.setattr(optinsn_adapter, "check_ins_mop_size_are_ok", lambda _ins: True)
    monkeypatch.setattr(optinsn_adapter, "count_minsn_nodes", lambda _ins: 1)
    monkeypatch.setattr(
        optinsn_adapter,
        "hash_minsn",
        lambda ins, _func_ea=0: hash(ins.form),
    )
    monkeypatch.setattr(handler_module, "format_minsn_t", lambda ins: ins.form)

    rule = _IdempotentRule("CobraSolveRule", [ida_hexrays.MMAT_LOCOPT])
    optimizer = _ConcreteOptimizer([ida_hexrays.MMAT_LOCOPT], stats=None)
    optimizer.add_rule(rule)
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager._active_optimizers = [optimizer]
    manager._rewrite_seen = defaultdict(set)
    manager._cycle_quarantined_rule_names = defaultdict(set)
    manager.current_maturity = ida_hexrays.MMAT_LOCOPT
    manager.stats = None
    manager.generate_z3_code = False
    manager.analyzer = SimpleNamespace(analyze=lambda _blk, _ins: None)
    manager._resolve_active_instruction_rule_names = lambda _blk: None
    manager._scheduled_implementation_names = frozenset()
    blk = SimpleNamespace(
        mba=SimpleNamespace(
            entry_ea=0x7FF856F83C70,
            maturity=ida_hexrays.MMAT_LOCOPT,
        )
    )
    ins = _SwappableInstruction("already-folded")

    assert not manager.optimize(blk, ins)
    assert not manager._cycle_quarantined_rule_names


def test_outer_mutation_owner_emits_final_rule_telemetry_only_after_acceptance(
    monkeypatch,
):
    """A replacement is not a rule firing until the swap survives all guards."""

    stats = OptimizationStatistics()
    optimizer = _ConcreteOptimizer(
        maturities=[ida_hexrays.MMAT_LOCOPT],
        stats=stats,
    )
    rule = _MutationRule(_SwappableInstruction("replacement", valid=True))
    optimizer.add_rule(rule)
    manager = _mutation_manager(optimizer, stats)
    original = _SwappableInstruction("original", valid=True)
    blk = SimpleNamespace(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_LOCOPT, entry_ea=0x401000)
    )

    monkeypatch.setattr(
        optinsn_adapter, "check_ins_mop_size_are_ok", lambda ins: ins.valid
    )
    monkeypatch.setattr(optinsn_adapter, "count_minsn_nodes", lambda _ins: 1)
    monkeypatch.setattr(optinsn_adapter, "hash_minsn", lambda ins, _ea: hash(ins.label))

    assert manager.optimize(blk, original)
    execution = stats.get_rule_execution("MutationRule")
    assert execution is not None
    assert execution.metadata["mba_provider_outcome"]["status"] == "applied"
    assert rule.accepted


def test_outer_mutation_rejection_emits_no_applied_rule_telemetry(monkeypatch):
    """An invalid replacement retains its provider outcome but never fires a rule."""

    stats = OptimizationStatistics()
    optimizer = _ConcreteOptimizer(
        maturities=[ida_hexrays.MMAT_LOCOPT],
        stats=stats,
    )
    rule = _MutationRule(_SwappableInstruction("invalid", valid=False))
    optimizer.add_rule(rule)
    manager = _mutation_manager(optimizer, stats)
    original = _SwappableInstruction("original", valid=True)
    blk = SimpleNamespace(
        mba=SimpleNamespace(maturity=ida_hexrays.MMAT_LOCOPT, entry_ea=0x401000)
    )

    monkeypatch.setattr(
        optinsn_adapter, "check_ins_mop_size_are_ok", lambda ins: ins.valid
    )
    monkeypatch.setattr(optinsn_adapter, "format_minsn_t", lambda _ins: "unit-ins")

    assert not manager.optimize(blk, original)
    assert stats.get_rule_execution("MutationRule") is None
    assert not rule.accepted
    assert rule.rejected_reason == "invalid_operand_size"


def test_instruction_adapter_emits_top_level_preopt_with_live_ports() -> None:
    session = SimpleNamespace(native_preanalysis_depth=0)
    identity_index = object()
    mutation_gateway = object()
    materializer = object()
    calls: list[object] = []

    class _Lifecycle:
        preopt_emitted = False

        def current_session(self, function_ea: int):
            calls.append(("session", function_ea))
            return session

        def preopt_ready_was_emitted(self, *, function_ea: int) -> bool:
            calls.append(("already-emitted", function_ea))
            return self.preopt_emitted

        def mark_preopt_ready_emitted(
            self,
            *,
            function_ea: int,
            microcode_modified: bool,
        ) -> None:
            calls.append(
                (
                    "mark-emitted",
                    function_ea,
                    microcode_modified,
                )
            )
            self.preopt_emitted = True

        def build_current_mba_identity_index(self, *, function_ea: int, mba: object):
            calls.append(("index", function_ea, mba))
            return identity_index

        def new_current_mba_mutation_gateway(self, *, function_ea: int, maturity: int):
            calls.append(("gateway", function_ea, maturity))
            return mutation_gateway

        def new_semantic_native_body_materializer(
            self,
            *,
            function_ea: int,
            mba: object,
        ):
            calls.append(("materializer", function_ea, mba))
            return materializer

    class _Emitter:
        def emit(self, event, **kwargs):
            calls.append(("emit", event, kwargs))
            kwargs["decision"]["microcode_modified"] = True

    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager._decompilation_lifecycle = _Lifecycle()
    manager.event_emitter = _Emitter()
    mba = SimpleNamespace(
        entry_ea=0x40D200,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert manager._emit_top_level_preopt_ready(mba)
    assert calls == [
        ("session", 0x40D200),
        ("already-emitted", 0x40D200),
        ("index", 0x40D200, mba),
        ("gateway", 0x40D200, ida_hexrays.MMAT_PREOPTIMIZED),
        ("materializer", 0x40D200, mba),
        (
            "emit",
            DecompilationEvent.HEXRAYS_PREOPT_READY,
            {
                "function_ea": 0x40D200,
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
        ),
        ("mark-emitted", 0x40D200, True),
    ]
    assert not manager._emit_top_level_preopt_ready(mba)
    assert calls[-2:] == [
        ("session", 0x40D200),
        ("already-emitted", 0x40D200),
    ]
    assert len(calls) == 9


def test_instruction_adapter_emits_preopt_for_new_mba_at_same_maturity() -> None:
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager.current_maturity = ida_hexrays.MMAT_PREOPTIMIZED
    manager.current_blk_serial = None
    emitted: list[object] = []
    manager._emit_top_level_preopt_ready = lambda mba: emitted.append(mba) or False

    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED)
    manager.log_info_on_input(SimpleNamespace(mba=mba, serial=0), _make_ins())

    assert emitted == [mba]


def test_instruction_adapter_skips_duplicate_preopt_publication() -> None:
    calls: list[object] = []
    session = SimpleNamespace(native_preanalysis_depth=0)

    class _Lifecycle:
        def current_session(self, function_ea: int):
            calls.append(("session", function_ea))
            return session

        def preopt_ready_was_emitted(self, *, function_ea: int) -> bool:
            calls.append(("already-emitted", function_ea))
            return True

        def build_current_mba_identity_index(self, **kwargs):
            raise AssertionError("duplicate PREOPT fallback rebuilt the live index")

    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager._decompilation_lifecycle = _Lifecycle()
    manager.event_emitter = object()
    mba = SimpleNamespace(
        entry_ea=0x40D200,
        maturity=ida_hexrays.MMAT_PREOPTIMIZED,
    )

    assert not manager._emit_top_level_preopt_ready(mba)
    assert calls == [
        ("session", 0x40D200),
        ("already-emitted", 0x40D200),
    ]


def test_block_adapter_rebuilds_flow_context_for_new_evidence_generation() -> None:
    class _Context:
        def __init__(self, **kwargs):
            self.created_with = kwargs
            self.refreshed = []

        def refresh_mba(self, mba):
            self.refreshed.append(mba)

        def set_function_priors_provider(self, _provider):
            pass

        def set_phase(self, **_kwargs):
            pass

        def prime_for_rules(self, _rules):
            pass

    generation = [1]
    evidence_generation = [7]
    manager = BlockOptimizerManager.__new__(BlockOptimizerManager)
    manager.current_maturity = ida_hexrays.MMAT_CALLS
    manager._flow_context = None
    manager._flow_context_key = None
    manager._flow_context_type = _Context
    manager._decompilation_lifecycle = SimpleNamespace(
        current_mba_generation=lambda *, function_ea: generation[0],
        current_evidence_generation=lambda *, function_ea: evidence_generation[0],
    )
    manager._validated_fact_view_provider = None
    manager._fact_consumer_callback = None
    manager._flow_context_summary_provider = None
    manager._planner_outcome_callback = None
    manager._flow_gate_outcome_callback = None
    manager._function_priors_provider = None
    manager._attach_hint_summary = lambda _context: None
    bindings = []
    manager._bind_resolver_session_state = lambda context, mba: bindings.append(
        ("state", context, mba)
    )
    manager._bind_mutation_gateway_port = lambda context, mba: bindings.append(
        ("gateway", context, mba)
    )
    mba = SimpleNamespace(
        entry_ea=0x40D200,
        maturity=ida_hexrays.MMAT_CALLS,
        this=0x1111,
    )
    blk = SimpleNamespace(mba=mba)

    first = manager._get_or_create_flow_context(
        blk,
        phase_priority=100,
        phase_index=0,
        phase_rules=(),
    )
    same = manager._get_or_create_flow_context(
        blk,
        phase_priority=100,
        phase_index=0,
        phase_rules=(),
    )
    evidence_generation[0] = 8
    regenerated = manager._get_or_create_flow_context(
        blk,
        phase_priority=100,
        phase_index=0,
        phase_rules=(),
    )

    assert same is first
    assert first.refreshed == [mba]
    assert regenerated is not first
    assert [kind for kind, _context, _mba in bindings] == [
        "state",
        "gateway",
        "state",
        "gateway",
    ]


def test_block_adapter_rebuilds_flow_context_for_new_mba_address() -> None:
    class _Context:
        def __init__(self, **_kwargs):
            pass

        def refresh_mba(self, _mba):
            raise AssertionError("a different mba_t reused the prior flow context")

        def set_function_priors_provider(self, _provider):
            pass

        def set_phase(self, **_kwargs):
            pass

        def prime_for_rules(self, _rules):
            pass

    manager = BlockOptimizerManager.__new__(BlockOptimizerManager)
    manager.current_maturity = ida_hexrays.MMAT_CALLS
    manager._flow_context = None
    manager._flow_context_key = None
    manager._flow_context_type = _Context
    manager._decompilation_lifecycle = SimpleNamespace(
        current_mba_generation=lambda *, function_ea: 1
    )
    manager._validated_fact_view_provider = None
    manager._fact_consumer_callback = None
    manager._flow_context_summary_provider = None
    manager._planner_outcome_callback = None
    manager._flow_gate_outcome_callback = None
    manager._function_priors_provider = None
    manager._attach_hint_summary = lambda _context: None
    bindings = []
    manager._bind_resolver_session_state = lambda context, mba: bindings.append(
        ("state", context, mba)
    )
    manager._bind_mutation_gateway_port = lambda context, mba: bindings.append(
        ("gateway", context, mba)
    )
    first_mba = SimpleNamespace(
        entry_ea=0x40D200,
        maturity=ida_hexrays.MMAT_CALLS,
        this=0x1111,
    )
    regenerated_mba = SimpleNamespace(
        entry_ea=0x40D200,
        maturity=ida_hexrays.MMAT_CALLS,
        this=0x2222,
    )

    first = manager._get_or_create_flow_context(
        SimpleNamespace(mba=first_mba),
        phase_priority=100,
        phase_index=0,
        phase_rules=(),
    )
    regenerated = manager._get_or_create_flow_context(
        SimpleNamespace(mba=regenerated_mba),
        phase_priority=100,
        phase_index=0,
        phase_rules=(),
    )

    assert regenerated is not first
    assert [kind for kind, _context, _mba in bindings] == [
        "state",
        "gateway",
        "state",
        "gateway",
    ]


class _MockOptimizer:
    """Mock optimizer with maturities and a call counter."""

    def __init__(self, name: str, maturities: list[int]):
        self.name = name
        self.maturities = maturities
        self.calls = 0
        self.cur_maturity = ida_hexrays.MMAT_PREOPTIMIZED

    def get_optimized_instruction(
        self,
        blk,
        ins,
        *,
        allowed_rule_names=None,
        scheduled_rule_names=None,
    ):
        self.calls += 1
        return None


def test_active_optimizer_list_filters_by_maturity():
    """Layer 2: only maturity-relevant optimizers are iterated in optimize()."""
    early_opt = _MockOptimizer(
        "EarlyOpt",
        [ida_hexrays.MMAT_GENERATED, ida_hexrays.MMAT_PREOPTIMIZED],
    )
    locopt_opt = _MockOptimizer(
        "LocoptOpt",
        [ida_hexrays.MMAT_LOCOPT, ida_hexrays.MMAT_CALLS, ida_hexrays.MMAT_GLBOPT1],
    )

    mgr = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    # Minimal initialization for the test
    mgr.instruction_optimizers = [early_opt, locopt_opt]
    mgr.current_maturity = None
    mgr.current_blk_serial = None
    mgr._rewrite_seen = {}
    mgr._execution_scope_service = None
    mgr._execution_scope_project_name = ""
    mgr._execution_scope_idb_key = ""
    mgr.analyzer = SimpleNamespace(
        set_maturity=lambda m: None, analyze=lambda blk, ins: None
    )
    mgr.event_emitter = None
    mgr.dump_intermediate_microcode = False
    mgr.stats = None
    mgr._active_instruction_rule_names_by_maturity = {}
    mgr.instruction_visitor = None
    mgr._last_optimizer_tried = None
    mgr.log_dir = None
    mgr._preanalysis_phase = None
    mgr._analysis_runtime = None
    mgr._run_later_scheduler = None
    mgr._scheduled_stage_identities = frozenset()
    mgr._scheduled_implementation_names = frozenset()

    # Simulate maturity change to MMAT_LOCOPT
    blk = _make_blk(ida_hexrays.MMAT_LOCOPT)
    ins = _make_ins()
    mgr.log_info_on_input(blk, ins)

    # Now call optimize - only locopt_opt should be called
    mgr.optimize(blk, ins)

    assert early_opt.calls == 0, (
        f"EarlyOpt was called {early_opt.calls} times at LOCOPT"
    )
    assert locopt_opt.calls == 1, "LocoptOpt was not called at LOCOPT"


def test_instruction_optimizer_abstains_during_scoped_suppression():
    from d810.hexrays.hooks.optimization_suppression import (
        suppress_d810_optimization,
    )

    optimizer = _MockOptimizer("LocoptOpt", [ida_hexrays.MMAT_LOCOPT])
    mgr = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    mgr.instruction_optimizers = [optimizer]
    mgr.current_maturity = ida_hexrays.MMAT_LOCOPT
    mgr.current_blk_serial = None
    mgr._rewrite_seen = {}
    mgr._execution_scope_service = None
    mgr._execution_scope_project_name = ""
    mgr._execution_scope_idb_key = ""
    mgr.analyzer = SimpleNamespace(
        set_maturity=lambda m: None, analyze=lambda blk, ins: None
    )
    mgr.event_emitter = None
    mgr.dump_intermediate_microcode = False
    mgr.stats = None
    mgr._active_instruction_rule_names_by_maturity = {}
    mgr.instruction_visitor = None
    mgr._last_optimizer_tried = None
    mgr.log_dir = None
    mgr._preanalysis_phase = None
    mgr._analysis_runtime = None
    mgr._run_later_scheduler = None
    mgr._scheduled_stage_identities = frozenset()
    mgr._scheduled_implementation_names = frozenset()
    mgr._active_optimizers = [optimizer]

    with suppress_d810_optimization():
        assert mgr.optimize(_make_blk(ida_hexrays.MMAT_LOCOPT), _make_ins()) is False
    assert optimizer.calls == 0


def test_instruction_optimizer_accepts_destination_owned_imported_mba():
    optimizer = _MockOptimizer(
        "EarlyOpt",
        [ida_hexrays.MMAT_PREOPTIMIZED, ida_hexrays.MMAT_LOCOPT],
    )
    mgr = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    mgr.current_maturity = ida_hexrays.MMAT_PREOPTIMIZED
    mgr._execution_scope_service = None
    mgr._scheduled_stage_identities = frozenset()
    mgr._scheduled_implementation_names = frozenset()
    mgr._active_optimizers = [optimizer]
    mgr._last_optimizer_tried = None
    mgr.analyzer = SimpleNamespace(analyze=lambda _blk, _ins: None)
    mgr._resolve_active_instruction_rule_names = lambda _blk: frozenset()

    shared_ea = 0x40EAA7
    mba = SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED)
    native = SimpleNamespace(
        mba=mba,
        serial=10,
        head=SimpleNamespace(ea=shared_ea),
    )
    imported = SimpleNamespace(
        mba=mba,
        serial=110,
        head=SimpleNamespace(ea=shared_ea),
    )
    assert mgr.optimize(imported, _make_ins()) is False
    assert optimizer.calls == 1

    assert mgr.optimize(native, _make_ins()) is False
    assert optimizer.calls == 2

    mgr.current_maturity = ida_hexrays.MMAT_LOCOPT
    assert mgr.optimize(imported, _make_ins()) is False
    assert optimizer.calls == 3


def test_owned_fake_block_registry_distinguishes_native_clone_with_same_ea():
    from d810.hexrays.mutation.cfg_verify import (
        clear_owned_fake_block_registrations,
        is_owned_fake_block,
        register_owned_fake_block,
    )

    clear_owned_fake_block_registrations()
    try:
        mba = SimpleNamespace(this=0xA000, map_fict_ea=lambda ea: ea)
        instruction = SimpleNamespace(ea=0x40EAA7, next=None)
        imported = SimpleNamespace(
            this=0xB000,
            serial=110,
            head=instruction,
            tail=instruction,
        )
        imported_wrapper = SimpleNamespace(this=0xB000)
        native_clone = SimpleNamespace(this=0xC000)

        register_owned_fake_block(mba, imported)

        assert is_owned_fake_block(mba, imported_wrapper)
        assert not is_owned_fake_block(mba, native_clone)
    finally:
        clear_owned_fake_block_registrations()


class _FakeMop:
    """Minimal mop stub with type field."""

    def __init__(self, t: int, size: int = 4):
        self.t = t
        self.size = size

    def __bool__(self):
        return self.t != ida_hexrays.mop_z


class _FakeInsForFold:
    """Minimal instruction stub for FoldReadonlyDataRule pre-check tests."""

    def __init__(
        self, opcode: int, l_type: int, r_type: int, d_type: int = ida_hexrays.mop_r
    ):
        self.opcode = opcode
        self.ea = 0x1000
        self.l = _FakeMop(l_type)
        self.r = _FakeMop(r_type)
        self.d = _FakeMop(d_type)


def test_has_potential_readonly_operand_rejects_pure_register():
    """Layer 3: pure register instructions have no readonly operand potential."""
    ins = _FakeInsForFold(
        opcode=ida_hexrays.m_xor,
        l_type=ida_hexrays.mop_r,
        r_type=ida_hexrays.mop_r,
    )
    assert _has_potential_readonly_operand(ins) is False


def test_has_potential_readonly_operand_rejects_constant():
    """Layer 3: constant-only instructions have no readonly operand potential."""
    ins = _FakeInsForFold(
        opcode=ida_hexrays.m_mov,
        l_type=ida_hexrays.mop_n,
        r_type=ida_hexrays.mop_z,
    )
    assert _has_potential_readonly_operand(ins) is False


def test_has_potential_readonly_operand_accepts_mop_v():
    """Layer 3: mop_v (global variable) is a readonly candidate."""
    ins = _FakeInsForFold(
        opcode=ida_hexrays.m_xor,
        l_type=ida_hexrays.mop_v,
        r_type=ida_hexrays.mop_r,
    )
    assert _has_potential_readonly_operand(ins) is True


def test_has_potential_readonly_operand_accepts_mop_d():
    """Layer 3: mop_d (nested sub-instruction) may contain readonly refs."""
    ins = _FakeInsForFold(
        opcode=ida_hexrays.m_add,
        l_type=ida_hexrays.mop_d,
        r_type=ida_hexrays.mop_r,
    )
    assert _has_potential_readonly_operand(ins) is True


def test_has_potential_readonly_operand_accepts_mop_S():
    """Layer 3: mop_S (stack/segment) may reference readonly segment."""
    ins = _FakeInsForFold(
        opcode=ida_hexrays.m_mov,
        l_type=ida_hexrays.mop_S,
        r_type=ida_hexrays.mop_z,
    )
    assert _has_potential_readonly_operand(ins) is True
