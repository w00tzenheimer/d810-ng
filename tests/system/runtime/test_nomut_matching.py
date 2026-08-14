"""Unit tests for non-mutating pattern matching hot-path integration.

These tests verify that the PatternOptimizer correctly switches between
mutating and non-mutating pattern matching based on environment variables.

NOTE: These tests require IDA Pro SDK and are skipped in pure unit test mode.
They verify feature flags and initialization, which requires IDA imports.
"""

import pytest

# Skip all tests in this module if IDA is not available
pytest.importorskip("ida_hexrays", reason="IDA Pro SDK not available")

from d810.optimizers.microcode.instructions.pattern_matching.handler import (
    PatternOptimizer,
    RulePatternInfo,
)
from d810.optimizers.microcode.instructions.pattern_matching import (
    handler as pattern_handler,
)
from d810.core.stats import OptimizationStatistics
from d810.backends.mba.ida import IDAPatternAdapter
from d810.mba.provider_outcome import ProviderOutcomeStatus


class TestNomutMatchingHotPath:
    """Test suite for nomut matching hot-path switching."""

    def test_nomut_matching_default_disabled(self, monkeypatch):
        """Verify _use_nomut_matching defaults to False (opt-in)."""
        # Clear any existing env var
        monkeypatch.delenv("D810_NOMUT_MATCHING", raising=False)
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)

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

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        assert optimizer._use_nomut_matching is True

    def test_nomut_matching_requires_indexed_storage(self, monkeypatch):
        """Verify nomut only activates when not using legacy storage."""
        # Enable nomut but force legacy storage
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")

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

        optimizer = PatternOptimizer(
            maturities=[],
            stats=None,
            log_dir=None,
        )

        # Nomut path should be active
        assert optimizer._use_nomut_matching is True
        assert optimizer._use_legacy_storage is False
        # The hot loop will use _match_nomut + BindingsProxy


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
        opt1 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt1._use_nomut_matching is False
        assert opt1._use_legacy_storage is False

        # Test case 2: Nomut ON, indexed storage (opt-in fast path)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        opt2 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt2._use_nomut_matching is True
        assert opt2._use_legacy_storage is False

        # Test case 3: Nomut ON, legacy storage (nomut disabled by legacy check)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")
        opt3 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt3._use_nomut_matching is True  # Flag set
        assert opt3._use_legacy_storage is True  # But legacy storage takes precedence
        # In get_optimized_instruction: if _use_nomut_matching and not _use_legacy_storage
        # So nomut path won't execute with legacy storage

        # Test case 4: Both disabled (full legacy path)
        monkeypatch.setenv("D810_NOMUT_MATCHING", "0")
        monkeypatch.setenv("D810_LEGACY_STORAGE", "1")
        opt4 = PatternOptimizer(maturities=[], stats=None, log_dir=None)
        assert opt4._use_nomut_matching is False
        assert opt4._use_legacy_storage is True
