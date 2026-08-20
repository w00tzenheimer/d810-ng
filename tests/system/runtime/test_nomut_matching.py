"""Unit tests for non-mutating pattern matching hot-path integration.

These tests verify that the PatternOptimizer correctly switches between
mutating and non-mutating pattern matching based on environment variables.

NOTE: These tests require IDA Pro SDK and are skipped in pure unit test mode.
They verify feature flags and initialization, which requires IDA imports.
"""

import pytest
from types import SimpleNamespace

# Skip all tests in this module if IDA is not available
pytest.importorskip("ida_hexrays", reason="IDA Pro SDK not available")

from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternOptimizer,
    RulePatternInfo,
)
from d810.optimizers.microcode.instructions.pattern_matching import (
    handler as pattern_handler,
)
from d810.hexrays.expr.ast import AstLeaf, AstNode
from d810.hexrays.ir.mop_snapshot import MopSnapshot
from d810.core.stats import OptimizationStatistics
from d810.core.settings import reset_settings
from d810.backends.mba.ida import IDAPatternAdapter
from d810.mba.provider_outcome import ProviderOutcomeStatus

import ida_hexrays


def _register_mop(reg: int, valnum: int = 0, size: int = 4):
    """Build the small native-mop-shaped object used by provenance tests."""

    return SimpleNamespace(
        t=ida_hexrays.mop_r,
        size=size,
        r=reg,
        reg=reg,
        valnum=valnum,
    )


def _register_snapshot(reg: int, valnum: int, size: int = 4):
    """Build the snapshot representation emitted by the recursive resolver."""

    return MopSnapshot(t=ida_hexrays.mop_r, size=size, reg=reg, valnum=valnum)


def _resolved_register_ast(*mops):
    """Build an AST whose leaves retain the supplied native operand snapshots."""

    leaves = []
    for index, mop in enumerate(mops):
        leaf = AstLeaf(f"x{index}")
        leaf.mop = mop
        leaves.append(leaf)
    if len(leaves) == 1:
        return leaves[0]
    tree = leaves[0]
    for leaf in leaves[1:]:
        tree = AstNode(ida_hexrays.m_add, tree, leaf)
    return tree


def test_tracker_fallback_is_disabled_before_locopt(monkeypatch):
    """Tracker reconstruction waits for the native provenance lifecycle boundary."""

    optimizer = object.__new__(PatternOptimizer)
    optimizer._use_tracker_resolution_fallback = True
    optimizer._tracker_resolution_opcodes = {ida_hexrays.m_sub}
    optimizer._trace_tracker_resolution = False
    optimizer.cur_maturity = ida_hexrays.MMAT_PREOPTIMIZED
    blk = SimpleNamespace(mba=SimpleNamespace(maturity=ida_hexrays.MMAT_PREOPTIMIZED))
    ins = SimpleNamespace(opcode=ida_hexrays.m_sub)
    raw_ast = object()

    def unexpected_resolution(*_args, **_kwargs):
        raise AssertionError("tracker resolution must not run before LOCOPT")

    from d810.evaluator.hexrays_microcode import def_search

    monkeypatch.setattr(
        def_search, "recursively_resolve_ast", unexpected_resolution, raising=False
    )

    assert optimizer._resolve_ast_with_tracker(blk, ins, raw_ast) is None


def test_tracker_fallback_rejects_unversioned_borrowed_register_at_locopt(monkeypatch):
    """A clobbered raw register cannot safely carry a tracker replacement."""

    optimizer = object.__new__(PatternOptimizer)
    optimizer._use_tracker_resolution_fallback = True
    optimizer._tracker_resolution_opcodes = {ida_hexrays.m_sub}
    optimizer._trace_tracker_resolution = False
    optimizer.cur_maturity = ida_hexrays.MMAT_LOCOPT
    blk = SimpleNamespace(mba=SimpleNamespace(maturity=ida_hexrays.MMAT_LOCOPT))
    destination = _register_mop(1, valnum=0)
    ins = SimpleNamespace(opcode=ida_hexrays.m_sub, d=destination)
    raw_ast = object()
    resolved_ast = _resolved_register_ast(
        _register_snapshot(1, valnum=0),
        _register_snapshot(2, valnum=0),
    )

    from d810.evaluator.hexrays_microcode import def_search

    monkeypatch.setattr(
        def_search,
        "recursively_resolve_ast",
        lambda *_args, **_kwargs: resolved_ast,
        raising=False,
    )

    assert optimizer._resolve_ast_with_tracker(blk, ins, raw_ast) is None


def test_tracker_fallback_accepts_native_versioned_locopt_provenance(monkeypatch):
    """LOCOPT tracker matching remains available when native versions prove it."""

    optimizer = object.__new__(PatternOptimizer)
    optimizer._use_tracker_resolution_fallback = True
    optimizer._tracker_resolution_opcodes = {ida_hexrays.m_sub}
    optimizer._trace_tracker_resolution = False
    optimizer.cur_maturity = ida_hexrays.MMAT_LOCOPT
    blk = SimpleNamespace(mba=SimpleNamespace(maturity=ida_hexrays.MMAT_LOCOPT))
    destination = _register_snapshot(1, valnum=2)
    ins = SimpleNamespace(opcode=ida_hexrays.m_sub, d=destination)
    raw_ast = object()
    resolved_ast = _resolved_register_ast(
        _register_snapshot(1, valnum=1),
        _register_snapshot(2, valnum=3),
    )

    from d810.evaluator.hexrays_microcode import def_search

    monkeypatch.setattr(
        def_search,
        "recursively_resolve_ast",
        lambda *_args, **_kwargs: resolved_ast,
        raising=False,
    )

    assert optimizer._resolve_ast_with_tracker(blk, ins, raw_ast) is resolved_ast


def test_direct_locopt_match_preempts_tracker_provenance_gate(monkeypatch):
    """The safety gate applies only to tracker fallback, never direct matches."""

    optimizer = object.__new__(PatternOptimizer)
    optimizer.rules = [object()]
    optimizer._allowed_root_opcodes = {ida_hexrays.m_sub}
    optimizer._use_tracker_resolution_fallback = True
    optimizer._pending_replacement_rule = None
    labels = []
    sentinel = object()
    raw_ast = object()
    blk = SimpleNamespace(mba=SimpleNamespace(maturity=ida_hexrays.MMAT_LOCOPT))
    ins = SimpleNamespace(opcode=ida_hexrays.m_sub)

    monkeypatch.setattr(pattern_handler, "minsn_to_ast", lambda _ins: raw_ast)

    def direct_match(*_args, **kwargs):
        labels.append(kwargs["source_label"])
        return sentinel if kwargs["source_label"] == "direct" else None

    optimizer._try_matches = direct_match

    def unexpected_tracker(*_args, **_kwargs):
        raise AssertionError("tracker fallback must not run after a direct match")

    optimizer._resolve_ast_with_tracker = unexpected_tracker

    assert optimizer.get_optimized_instruction(blk, ins) is sentinel
    assert labels == ["direct"]


@pytest.fixture(autouse=True)
def _reset_runtime_settings_after_test(monkeypatch):
    """Undo env overrides before rebuilding the settings singleton.

    ``monkeypatch`` normally tears down after this fixture.  Undoing it here
    first ensures ``reset_settings()`` observes the restored environment and
    no opt-in setting leaks into the next IDA test.
    """

    yield
    monkeypatch.undo()
    reset_settings()


class TestNomutMatchingHotPath:
    """Test suite for nomut matching hot-path switching."""

    def test_nomut_matching_default_disabled(self, monkeypatch):
        """Verify _use_nomut_matching defaults to False (opt-in)."""
        # Clear any existing env var
        monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert optimizer._use_nomut_matching is False

    def test_nomut_matching_disabled_via_env(self, monkeypatch):
        """Verify D810_NOMUT_MATCHING=0 disables nomut matching."""
        monkeypatch.setenv("D810_NOMUT_MATCHING", "0")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert optimizer._use_nomut_matching is False

    def test_nomut_matching_enabled_via_env(self, monkeypatch):
        """Verify D810_NOMUT_MATCHING=1 enables nomut matching."""
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert optimizer._use_nomut_matching is True

    def test_nomut_matching_enabled_from_runtime_setting(self, monkeypatch):
        """A configured runtime setting selects non-mutating matching."""
        from d810.core.settings import configure_settings, reset_settings

        monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()
        configure_settings(nomut_matching=True)

        try:
            optimizer = PatternOptimizer(
                maturities=[],
                stats=None,
                log_dir=None,
            )
            assert optimizer._use_nomut_matching is True
        finally:
            reset_settings()

    def test_nomut_matching_requires_indexed_storage(self, monkeypatch):
        """Verify nomut only activates when not using legacy storage."""
        # Enable nomut but force legacy storage
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")
        reset_settings()

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        # Nomut flag is set, but won't be used because legacy storage is active
        assert optimizer._use_nomut_matching is True
        assert optimizer._use_legacy_storage is True
        # In get_optimized_instruction, the condition is:
        # if self._use_nomut_matching and not self._use_legacy_storage:
        # So with legacy storage, the nomut path won't execute

    def test_match_bindings_initialized(self, monkeypatch):
        """Verify _match_bindings is created at init."""
        monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert hasattr(optimizer, "_match_bindings")
        assert optimizer._match_bindings is not None
        # Should be reusable (reset between attempts)
        # Use to_dict() to verify it's empty (count is private in Cython)
        assert len(optimizer._match_bindings.to_dict()) == 0

    def test_legacy_path_active_when_nomut_disabled(self, monkeypatch):
        """Verify legacy path is active when nomut is disabled."""
        monkeypatch.setenv("D810_NOMUT_MATCHING", "0")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        # Legacy path should be active
        assert optimizer._use_nomut_matching is False
        assert optimizer._use_legacy_storage is False
        # The hot loop will use check_pattern_and_replace instead of nomut

    def test_nomut_path_active_with_indexed_storage(self, monkeypatch):
        """Verify nomut path is active when explicitly enabled with indexed storage."""
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        # Nomut path should be active
        assert optimizer._use_nomut_matching is True
        assert optimizer._use_legacy_storage is False
        # The hot loop will use _match_nomut + BindingsProxy

    def test_pattern_optimizer_route_uses_indexed_candidates_and_selected_matcher(
        self, monkeypatch
    ):
        """Default lookup is indexed; final matching follows the NOMUT flag."""

        class Rule:
            name = "RouteRule"
            maturities = [7]

            def __init__(self):
                self.legacy_calls = 0

            def check_pattern_and_replace(self, _pattern, _candidate):
                self.legacy_calls += 1
                return None

        class IndexedStorage:
            def __init__(self, info):
                self.info = info
                self.calls = 0

            def get_candidates(self, _candidate):
                self.calls += 1
                return [self.info]

        class LegacyStorage:
            def __init__(self):
                self.calls = 0

            def get_matching_rule_pattern_info(self, _candidate):
                self.calls += 1
                return []

        def build_optimizer(*, use_nomut, indexed, legacy):
            optimizer = object.__new__(PatternOptimizer)
            optimizer.cur_maturity = 7
            optimizer.stats = None
            optimizer._use_nomut_matching = use_nomut
            optimizer._use_legacy_storage = False
            optimizer._use_indexed_legacy_fallback = False
            optimizer._indexed_storage = indexed
            optimizer.pattern_storage = legacy
            optimizer._structural_rules_by_root_opcode = {}
            optimizer._match_bindings = pattern_handler.MatchBindings()
            optimizer._run_later_callback = None
            optimizer._pending_replacement_rule = None
            optimizer._get_candidates = PatternOptimizer._get_candidates.__get__(
                optimizer
            )
            return optimizer

        legacy_rule = Rule()
        legacy_info = RulePatternInfo(legacy_rule, object())
        indexed = IndexedStorage(legacy_info)
        legacy = LegacyStorage()
        default_optimizer = build_optimizer(
            use_nomut=False,
            indexed=indexed,
            legacy=legacy,
        )
        default_optimizer._try_matches(
            None,
            object(),
            object(),
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label="route-default",
        )
        assert indexed.calls == 1
        assert legacy.calls == 0
        assert legacy_rule.legacy_calls == 1

        nomut_rule = Rule()
        nomut_info = RulePatternInfo(nomut_rule, object())
        nomut_indexed = IndexedStorage(nomut_info)
        nomut_legacy = LegacyStorage()
        nomut_optimizer = build_optimizer(
            use_nomut=True,
            indexed=nomut_indexed,
            legacy=nomut_legacy,
        )
        nomut_calls = []
        monkeypatch.setattr(
            pattern_handler,
            "_match_nomut",
            lambda *_args: nomut_calls.append(True) or False,
        )
        nomut_optimizer._try_matches(
            None,
            object(),
            object(),
            allowed_rule_names=None,
            scheduled_rule_names=None,
            source_label="route-nomut",
        )
        assert nomut_indexed.calls == 1
        assert nomut_legacy.calls == 0
        assert nomut_calls == [True]
        assert nomut_rule.legacy_calls == 0


def test_pattern_optimizer_forwards_catalogue_outcome_to_central_statistics():
    """A direct-provider adapter's outcome survives the PatternOptimizer path."""

    class Rule:
        name = "DirectCatalogue"
        maturities = [7]
        accepted = 0

        @staticmethod
        def check_pattern_and_replace(pattern, test_ast):
            del pattern, test_ast
            return Instruction()

        @staticmethod
        def execution_metadata():
            return {
                "mba_provider_outcome": {
                    "provider": "catalogue",
                    "status": "applied" if Rule.accepted else "improved",
                    "fingerprint": "native-island",
                }
            }

        @staticmethod
        def record_mutation_accepted():
            Rule.accepted += 1

    class Instruction:
        ea = 0

        @staticmethod
        def _print():
            return "unit-ins"

    stats = OptimizationStatistics()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = stats
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._pending_replacement_rule = None
    optimizer._get_candidates = lambda _ast: [RulePatternInfo(Rule(), object())]

    result = optimizer._try_matches(
        None,
        Instruction(),
        object(),
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="unit",
    )

    assert result is not None
    assert stats.get_rule_execution("DirectCatalogue") is None

    optimizer.record_mutation_accepted()
    execution = stats.get_rule_execution("DirectCatalogue")
    assert execution is not None
    assert execution.metadata["mba_provider_outcome"]["provider"] == "catalogue"
    assert execution.metadata["mba_provider_outcome"]["status"] == "applied"


def test_nomut_success_records_the_bound_catalogue_replacement_outcome(monkeypatch):
    """The supported nomut ``get_replacement`` path emits direct telemetry."""

    class Instruction:
        ea = 0

        @staticmethod
        def _print():
            return "unit-ins"

    class Adapter:
        name = "DirectCatalogue"
        maturities = [7]
        REPLACEMENT_PATTERN = "replacement-pattern"

        def __init__(self):
            self.bound_replacements: list[object] = []
            self.legacy_bindings: list[object] = []

        @staticmethod
        def check_candidate(_proxy):
            return True

        @staticmethod
        def get_replacement(_proxy):
            return Instruction()

        def record_bound_replacement_outcome(self, replacement):
            self.bound_replacements.append(replacement)

        def record_legacy_match_bindings(self, pattern, source_ast):
            self.legacy_bindings.append((pattern, source_ast))

        @staticmethod
        def execution_metadata():
            return {}

    adapter = Adapter()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = True
    optimizer._use_legacy_storage = False
    optimizer._match_bindings = pattern_handler.MatchBindings()
    optimizer._run_later_callback = None
    pattern = object()
    test_ast = object()
    optimizer._get_candidates = lambda _ast: [RulePatternInfo(adapter, pattern)]
    monkeypatch.setattr(pattern_handler, "_match_nomut", lambda *_args: True)

    result = optimizer._try_matches(
        None,
        Instruction(),
        test_ast,
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="unit",
    )

    assert result is not None
    assert adapter.bound_replacements == ["replacement-pattern"]
    assert adapter.legacy_bindings == [(pattern, test_ast)]


def test_pattern_runtime_error_notifies_attempt_context_before_clear(monkeypatch):
    """The existing optimizer catch finalizes an error row, not a no-match."""

    class Instruction:
        ea = 0

        @staticmethod
        def _print():
            return "unit-ins"

    class Adapter:
        name = "DirectCatalogue"
        maturities = [7]

        def __init__(self):
            self.errors: list[RuntimeError] = []
            self.cleared = 0

        @staticmethod
        def bind_match_context(_blk, _ins):
            return None

        @staticmethod
        def check_pattern_and_replace(_pattern, _candidate):
            raise RuntimeError("matcher failure")

        def record_attempt_error(self, exc):
            self.errors.append(exc)

        def clear_match_context(self):
            self.cleared += 1

    adapter = Adapter()
    optimizer = object.__new__(PatternOptimizer)
    optimizer.stats = None
    optimizer.cur_maturity = 7
    optimizer._use_nomut_matching = False
    optimizer._use_legacy_storage = False
    optimizer._run_later_callback = None
    optimizer._get_candidates = lambda _ast: [RulePatternInfo(adapter, object())]

    result = optimizer._try_matches(
        None,
        Instruction(),
        object(),
        allowed_rule_names=None,
        scheduled_rule_names=None,
        source_label="unit",
    )

    assert result is None
    assert [str(error) for error in adapter.errors] == ["matcher failure"]
    assert adapter.cleared == 1


def test_direct_catalogue_refuses_success_telemetry_without_exact_island_profile():
    """A native adapter never replaces required profile identity with a guess."""

    class Leaf:
        def is_node(self) -> bool:
            return False

    class Rule:
        name = "direct"
        CANONICAL_NAME = "direct"
        ALIASES = ()

    adapter = object.__new__(IDAPatternAdapter)
    adapter.rule = Rule()
    adapter._attempt_started = None
    adapter._attempt_destination_size = 4
    adapter._last_provider_outcome = None
    adapter._profile_fingerprint = lambda _ast: None

    adapter._record_catalogue_success(Leaf(), Leaf())

    outcome = adapter._last_provider_outcome
    assert outcome is not None
    assert outcome.status is ProviderOutcomeStatus.RECONSTRUCTION_FAILED
    assert outcome.refusal_reason == "profile_unavailable"


def test_direct_catalogue_context_error_is_not_downgraded_to_unchanged():
    class Leaf:
        def is_node(self) -> bool:
            return False

    class Rule:
        name = "direct"
        CANONICAL_NAME = "direct"
        ALIASES = ()

    adapter = object.__new__(IDAPatternAdapter)
    adapter.rule = Rule()
    adapter._attempt_started = None
    adapter._attempt_destination_size = 4
    adapter._attempt_input_ast = Leaf()
    adapter._last_provider_outcome = None
    adapter.provider_outcome_history = []
    adapter._attempt_outcome_index = None
    adapter._profile_fingerprint = lambda _ast: "exact-native-island"
    adapter.begin_provider_outcome_capture()

    adapter.record_attempt_error(RuntimeError("matcher failure"))
    adapter.clear_match_context()

    assert len(adapter.provider_outcomes()) == 1
    outcome = adapter.provider_outcomes()[0]
    assert outcome.status is ProviderOutcomeStatus.ERROR
    assert outcome.fingerprint == "exact-native-island"
    assert outcome.refusal_reason == "RuntimeError"


def test_direct_catalogue_bound_nomut_success_uses_the_same_profiled_outcome():
    class Leaf:
        def is_node(self) -> bool:
            return False

    class Rule:
        name = "direct"
        CANONICAL_NAME = "direct"
        ALIASES = ()

    adapter = object.__new__(IDAPatternAdapter)
    adapter.rule = Rule()
    adapter._attempt_started = None
    adapter._attempt_destination_size = 4
    adapter._attempt_input_ast = Leaf()
    adapter._last_provider_outcome = None
    adapter.provider_outcome_history = []
    adapter._attempt_outcome_index = None
    adapter._profile_fingerprint = lambda _ast: "exact-native-island"
    adapter.begin_provider_outcome_capture()

    adapter.record_bound_replacement_outcome(Leaf())

    outcome = adapter.provider_outcomes()[0]
    assert outcome.status is ProviderOutcomeStatus.IMPROVED
    assert outcome.fingerprint == "exact-native-island"

    adapter.record_mutation_accepted()
    assert adapter.provider_outcomes()[0].status is ProviderOutcomeStatus.APPLIED


def test_direct_catalogue_outer_rejection_keeps_candidate_non_applied():
    class Leaf:
        def is_node(self) -> bool:
            return False

    class Rule:
        name = "direct"
        CANONICAL_NAME = "direct"
        ALIASES = ()

    adapter = object.__new__(IDAPatternAdapter)
    adapter.rule = Rule()
    adapter._attempt_started = None
    adapter._attempt_destination_size = 4
    adapter._attempt_input_ast = Leaf()
    adapter._last_provider_outcome = None
    adapter.provider_outcome_history = []
    adapter._attempt_outcome_index = None
    adapter._profile_fingerprint = lambda _ast: "exact-native-island"
    adapter.begin_provider_outcome_capture()

    adapter.record_bound_replacement_outcome(Leaf())
    adapter.record_mutation_rejected("rewrite_cycle")

    outcome = adapter.provider_outcomes()[0]
    assert outcome.status is ProviderOutcomeStatus.IMPROVED
    assert outcome.refusal_reason == "rewrite_cycle"
    assert outcome.metadata["mutation_outcome"] == "rejected"

    def test_feature_flags_are_independent(self, monkeypatch):
        """D810_NOMUT_MATCHING and D810_LEGACY_STORAGE control different aspects.

        PR4 invariant: The two flags are orthogonal.
        - D810_NOMUT_MATCHING controls whether to use non-mutating match
        - D810_LEGACY_STORAGE controls whether to use legacy pattern storage

        All four combinations are valid, but only some are useful:
        1. nomut=0, legacy=0 (default) -> Indexed storage with clone+match
        2. nomut=1, legacy=0 -> Fast path: nomut + indexed storage (opt-in)
        3. nomut=1, legacy=1 -> Legacy storage ignores nomut (nomut flag set but not used)
        4. nomut=0, legacy=1 -> Legacy path (both optimizations disabled)
        """
        # Test case 1: Default (nomut OFF, indexed storage)
        monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()
        opt1 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt1._use_nomut_matching is False
        assert opt1._use_legacy_storage is False

        # Test case 2: Nomut ON, indexed storage (opt-in fast path)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        reset_settings()
        opt2 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt2._use_nomut_matching is True
        assert opt2._use_legacy_storage is False

        # Test case 3: Nomut ON, legacy storage (nomut disabled by legacy check)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")
        reset_settings()
        opt3 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt3._use_nomut_matching is True  # Flag set
        assert opt3._use_legacy_storage is True  # But legacy storage takes precedence
        # In get_optimized_instruction: if _use_nomut_matching and not _use_legacy_storage
        # So nomut path won't execute with legacy storage

        # Test case 4: Both disabled (full legacy path)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "0")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")
        reset_settings()
        opt4 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt4._use_nomut_matching is False
        assert opt4._use_legacy_storage is True
