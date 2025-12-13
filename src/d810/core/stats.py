from __future__ import annotations

import dataclasses
from collections import defaultdict
from enum import Enum, auto
from typing import Any, Dict, List, Optional

from .logging import getLogger
from .registry import EventEmitter

logger = getLogger("D810")


class OptimizationEvent(Enum):
    """Events emitted during optimization for instrumentation/testing."""

    # Optimizer-level events
    OPTIMIZER_MATCH = auto()  # An optimizer matched and transformed an instruction
    OPTIMIZER_START = auto()  # Optimizer starting to process
    OPTIMIZER_END = auto()  # Optimizer finished processing

    # Rule-level events
    RULE_MATCH = auto()  # A rule matched a pattern
    RULE_APPLIED = auto()  # A rule was successfully applied

    # CFG-level events
    CFG_RULE_PATCHES = auto()  # A CFG rule produced patches

    # Session events
    SESSION_START = auto()  # Optimization session started
    SESSION_END = auto()  # Optimization session ended


@dataclasses.dataclass
class RuleExecution:
    """Record of a single rule execution for detailed analysis."""

    rule: type | object  # The actual rule class or instance
    rule_name: str  # Cached name for quick access
    match_count: int = 1  # Number of times this rule matched
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    @classmethod
    def from_rule(cls, rule: type | object, **metadata) -> "RuleExecution":
        """Create a RuleExecution from a rule object."""
        if isinstance(rule, type):
            name = getattr(rule, "registrant_name", None) or rule.__name__
        else:
            name = getattr(rule, "name", None) or rule.__class__.__name__
        return cls(rule=rule, rule_name=name, metadata=metadata)


@dataclasses.dataclass
class OptimizationStatistics:
    """Centralized statistics for optimizers & rules.

    Tracks usage across instruction optimizers, individual instruction rules,
    and block (CFG) rules. Provides reset/report and query helpers.

    Now enhanced with:
    - EventEmitter for decoupled instrumentation
    - Tracking of actual rule objects (not just names)
    - Registry-based rule lookup
    - Rich query APIs for test assertions
    """

    # instruction optimizer usage (e.g., PatternOptimizer, ChainOptimizer...)
    instruction_optimizer_usage: Dict[str, int] = dataclasses.field(
        default_factory=lambda: defaultdict(int)
    )

    # instruction rule usage by name (legacy, kept for backward compatibility)
    instruction_rule_usage: Dict[str, int] = dataclasses.field(
        default_factory=lambda: defaultdict(int)
    )

    # block/CFG rule usage; we store list of patch counts per use
    cfg_rule_usages: Dict[str, List[int]] = dataclasses.field(
        default_factory=lambda: defaultdict(list)
    )

    # NEW: Track actual rule objects (keyed by normalized name)
    rule_executions: Dict[str, RuleExecution] = dataclasses.field(default_factory=dict)

    # NEW: Ordered list of rule firings for sequence analysis
    rule_execution_log: List[RuleExecution] = dataclasses.field(default_factory=list)

    # NEW: EventEmitter for pub/sub instrumentation
    events: EventEmitter[OptimizationEvent] = dataclasses.field(
        default_factory=lambda: EventEmitter[OptimizationEvent]()
    )

    def reset(self) -> None:
        self.instruction_optimizer_usage.clear()
        self.instruction_rule_usage.clear()
        self.cfg_rule_usages.clear()
        self.rule_executions.clear()
        self.rule_execution_log.clear()
        # Don't clear event handlers - they persist across sessions

    # -------------------------------------------------------------------------
    # Recording APIs (enhanced to track rule objects)
    # -------------------------------------------------------------------------

    def record_optimizer_match(self, optimizer_name: str) -> None:
        self.instruction_optimizer_usage[optimizer_name] += 1
        self.events.emit(OptimizationEvent.OPTIMIZER_MATCH, optimizer_name)

    def record_instruction_rule_match(self, rule_name: str) -> None:
        """Record a rule match by name (legacy API)."""
        self.instruction_rule_usage[rule_name] += 1
        self.events.emit(OptimizationEvent.RULE_MATCH, rule_name)

    def record_rule_fired(
        self,
        rule: type | object,
        registry_class: Optional[type] = None,
        **metadata,
    ) -> None:
        """Record that a rule fired, tracking the actual rule object.

        Args:
            rule: The rule class or instance that fired
            registry_class: Optional Registrant subclass to look up rule by name
            **metadata: Additional context (e.g., instruction address, block)
        """
        # Create execution record
        execution = RuleExecution.from_rule(rule, **metadata)
        normalized_name = execution.rule_name.lower()

        # Update aggregated stats
        if normalized_name in self.rule_executions:
            self.rule_executions[normalized_name].match_count += 1
        else:
            self.rule_executions[normalized_name] = execution

        # Add to execution log for sequence analysis
        self.rule_execution_log.append(execution)

        # Also update legacy counters for backward compatibility
        self.instruction_rule_usage[execution.rule_name] += 1

        # Emit event with the actual rule object
        self.events.emit(OptimizationEvent.RULE_APPLIED, rule, metadata)

    def record_cfg_rule_patches(self, rule_name: str, nb_patches: int) -> None:
        self.cfg_rule_usages[rule_name].append(nb_patches)
        self.events.emit(OptimizationEvent.CFG_RULE_PATCHES, rule_name, nb_patches)

    # -------------------------------------------------------------------------
    # Query APIs (enhanced for test assertions)
    # -------------------------------------------------------------------------

    def get_optimizer_match_count(self, optimizer_name: str) -> int:
        return int(self.instruction_optimizer_usage.get(optimizer_name, 0))

    def get_instruction_rule_match_count(self, rule_name: str) -> int:
        return int(self.instruction_rule_usage.get(rule_name, 0))

    def get_cfg_rule_patch_counts(self, rule_name: str) -> List[int]:
        return list(self.cfg_rule_usages.get(rule_name, []))

    # NEW: Query methods for rule objects
    def get_rule_execution(self, rule_name: str) -> Optional[RuleExecution]:
        """Get execution stats for a rule by name."""
        return self.rule_executions.get(rule_name.lower())

    def get_fired_rules(self) -> List[type | object]:
        """Get list of all rules that fired (as actual objects)."""
        return [ex.rule for ex in self.rule_executions.values()]

    def get_fired_rule_names(self) -> List[str]:
        """Get list of all rule names that fired."""
        return [ex.rule_name for ex in self.rule_executions.values()]

    def did_rule_fire(self, rule: type | str) -> bool:
        """Check if a specific rule fired.

        Args:
            rule: Either a rule class/instance or a rule name string
        """
        if isinstance(rule, str):
            return rule.lower() in self.rule_executions
        elif isinstance(rule, type):
            name = getattr(rule, "registrant_name", None) or rule.__name__
            return name.lower() in self.rule_executions
        else:
            name = getattr(rule, "name", None) or rule.__class__.__name__
            return name.lower() in self.rule_executions

    def get_rule_match_count(self, rule: type | str) -> int:
        """Get match count for a rule by class or name."""
        if isinstance(rule, str):
            name = rule.lower()
        elif isinstance(rule, type):
            name = (getattr(rule, "registrant_name", None) or rule.__name__).lower()
        else:
            name = (getattr(rule, "name", None) or rule.__class__.__name__).lower()

        execution = self.rule_executions.get(name)
        return execution.match_count if execution else 0

    def get_execution_log(self) -> List[RuleExecution]:
        """Get the ordered list of rule executions for sequence analysis."""
        return list(self.rule_execution_log)

    def assert_rule_fired(
        self,
        rule: type | str,
        min_count: int = 1,
        max_count: Optional[int] = None,
    ) -> None:
        """Assert that a rule fired within expected bounds.

        For use in tests to verify deobfuscation behavior.

        Args:
            rule: Rule class or name to check
            min_count: Minimum expected firings (default 1)
            max_count: Maximum expected firings (None = no upper bound)

        Raises:
            AssertionError: If rule didn't fire or fired outside bounds
        """
        count = self.get_rule_match_count(rule)
        rule_name = (
            rule
            if isinstance(rule, str)
            else (
                getattr(rule, "registrant_name", None)
                or getattr(rule, "name", None)
                or (
                    rule.__name__ if isinstance(rule, type) else rule.__class__.__name__
                )
            )
        )

        if count < min_count:
            fired = self.get_fired_rule_names()
            raise AssertionError(
                f"Expected rule '{rule_name}' to fire at least {min_count} time(s), "
                f"but it fired {count} time(s). "
                f"Rules that fired: {fired}"
            )

        if max_count is not None and count > max_count:
            raise AssertionError(
                f"Expected rule '{rule_name}' to fire at most {max_count} time(s), "
                f"but it fired {count} time(s)."
            )

    def assert_no_rule_fired(self) -> None:
        """Assert that no rules fired (useful for negative tests)."""
        if self.rule_executions:
            fired = self.get_fired_rule_names()
            raise AssertionError(f"Expected no rules to fire, but these fired: {fired}")

    # -------------------------------------------------------------------------
    # Reporting APIs
    # -------------------------------------------------------------------------

    def report(self) -> None:
        # Optimizers
        for optimizer_name, nb_match in self.instruction_optimizer_usage.items():
            if nb_match > 0:
                logger.info(
                    "Instruction optimizer '%s' has been used %d times",
                    optimizer_name,
                    nb_match,
                )

        # Instruction rules (use new execution data if available)
        if self.rule_executions:
            for name, execution in self.rule_executions.items():
                if execution.match_count > 0:
                    logger.info(
                        "Instruction Rule '%s' has been used %d times",
                        execution.rule_name,
                        execution.match_count,
                    )
        else:
            # Fallback to legacy counters
            for rule_name, nb_match in self.instruction_rule_usage.items():
                if nb_match > 0:
                    logger.info(
                        "Instruction Rule '%s' has been used %d times",
                        rule_name,
                        nb_match,
                    )

        # CFG rules
        for rule_name, patch_list in self.cfg_rule_usages.items():
            nb_use = len(patch_list)
            if nb_use > 0:
                logger.info(
                    "BlkRule '%s' has been used %d times for a total of %d patches",
                    rule_name,
                    nb_use,
                    sum(patch_list),
                )

    def summary(self) -> Dict[str, Any]:
        """Get a summary dict for programmatic access."""
        return {
            "optimizer_matches": dict(self.instruction_optimizer_usage),
            "rule_matches": {
                ex.rule_name: ex.match_count for ex in self.rule_executions.values()
            },
            "cfg_patches": {
                name: {"uses": len(patches), "total_patches": sum(patches)}
                for name, patches in self.cfg_rule_usages.items()
            },
            "total_rule_firings": len(self.rule_execution_log),
        }

    # -------------------------------------------------------------------------
    # JSON Serialization APIs
    # -------------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Serialize statistics to a dictionary for JSON export.

        Returns a structure suitable for saving as test expectations.
        """
        return {
            "optimizer_matches": dict(self.instruction_optimizer_usage),
            "instruction_rule_matches": dict(self.instruction_rule_usage),
            "rule_executions": {
                name: {
                    "rule_name": ex.rule_name,
                    "match_count": ex.match_count,
                }
                for name, ex in self.rule_executions.items()
            },
            "cfg_rule_usages": {
                name: list(patches) for name, patches in self.cfg_rule_usages.items()
            },
            "total_rule_firings": len(self.rule_execution_log),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize statistics to JSON string."""
        import json

        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OptimizationStatistics":
        """Create statistics from a dictionary (e.g., loaded from JSON)."""
        stats = cls()
        stats.instruction_optimizer_usage.update(data.get("optimizer_matches", {}))
        stats.instruction_rule_usage.update(data.get("instruction_rule_matches", {}))
        for name, ex_data in data.get("rule_executions", {}).items():
            stats.rule_executions[name] = RuleExecution(
                rule=None,  # Can't reconstruct rule object from JSON
                rule_name=ex_data["rule_name"],
                match_count=ex_data["match_count"],
            )
        for name, patches in data.get("cfg_rule_usages", {}).items():
            stats.cfg_rule_usages[name] = list(patches)
        return stats

    @classmethod
    def from_json(cls, json_str: str) -> "OptimizationStatistics":
        """Create statistics from a JSON string."""
        import json

        return cls.from_dict(json.loads(json_str))

    def assert_matches(
        self,
        expected: "OptimizationStatistics | Dict[str, Any]",
        *,
        check_counts: bool = True,
        allow_extra_rules: bool = True,
    ) -> None:
        """Assert that this statistics object matches expected values.

        Args:
            expected: Expected statistics (OptimizationStatistics or dict)
            check_counts: If True, verify exact match counts. If False,
                         only verify that rules fired (count >= 1).
            allow_extra_rules: If True, allow rules to fire that aren't
                              in expected. If False, fail on extra rules.

        Raises:
            AssertionError: If statistics don't match expected values.
        """
        if isinstance(expected, dict):
            expected = self.from_dict(expected)

        # Check optimizer matches
        for name, expected_count in expected.instruction_optimizer_usage.items():
            actual_count = self.instruction_optimizer_usage.get(name, 0)
            if check_counts:
                if actual_count != expected_count:
                    raise AssertionError(
                        f"Optimizer '{name}' expected {expected_count} matches, "
                        f"got {actual_count}"
                    )
            else:
                if expected_count > 0 and actual_count == 0:
                    raise AssertionError(
                        f"Optimizer '{name}' expected to fire but didn't"
                    )

        # Check rule executions
        for name, expected_ex in expected.rule_executions.items():
            actual_ex = self.rule_executions.get(name)
            if actual_ex is None:
                raise AssertionError(
                    f"Rule '{expected_ex.rule_name}' expected to fire but didn't. "
                    f"Rules that fired: {self.get_fired_rule_names()}"
                )
            if check_counts and actual_ex.match_count != expected_ex.match_count:
                raise AssertionError(
                    f"Rule '{expected_ex.rule_name}' expected {expected_ex.match_count} "
                    f"matches, got {actual_ex.match_count}"
                )

        # Check CFG rule usages
        for name, expected_patches in expected.cfg_rule_usages.items():
            actual_patches = self.cfg_rule_usages.get(name, [])
            if check_counts:
                if actual_patches != expected_patches:
                    raise AssertionError(
                        f"CFG rule '{name}' expected patches {expected_patches}, "
                        f"got {actual_patches}"
                    )
            else:
                if expected_patches and not actual_patches:
                    raise AssertionError(
                        f"CFG rule '{name}' expected to fire but didn't"
                    )

        # Check for extra rules if not allowed
        if not allow_extra_rules:
            extra_optimizers = set(self.instruction_optimizer_usage) - set(
                expected.instruction_optimizer_usage
            )
            extra_rules = set(self.rule_executions) - set(expected.rule_executions)
            extra_cfg = set(self.cfg_rule_usages) - set(expected.cfg_rule_usages)

            if extra_optimizers or extra_rules or extra_cfg:
                raise AssertionError(
                    f"Unexpected rules fired:\n"
                    f"  Optimizers: {extra_optimizers or 'none'}\n"
                    f"  Rules: {extra_rules or 'none'}\n"
                    f"  CFG rules: {extra_cfg or 'none'}"
                )
