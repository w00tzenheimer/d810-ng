"""Deobfuscation test case dataclass definitions.

This module defines the data structures used to specify deobfuscation test cases
in a declarative, data-driven manner.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from d810.core.typing import Optional


@dataclass
class BinaryOverride:
    """Override configuration for a specific binary format.

    Use this to specify different expectations for .dll vs .dylib binaries
    when the obfuscation patterns or deobfuscation results differ.

    Example::

        DeobfuscationCase(
            function="ollvm_func",
            required_rules=["BnotOr_FactorRule_1"],
            dll_override=BinaryOverride(
                required_rules=["Z3ConstantOptimization"],
            ),
        )
    """

    # Override before assertions
    obfuscated_contains: Optional[list[str]] = None
    obfuscated_regexes: Optional[list[str]] = None
    obfuscated_not_contains: Optional[list[str]] = None

    # Override after assertions
    expected_code: Optional[str] = None
    acceptable_patterns: Optional[list[str]] = None
    deobfuscated_contains: Optional[list[str]] = None
    deobfuscated_regexes: Optional[list[str]] = None
    deobfuscated_not_contains: Optional[list[str]] = None

    # Override rule assertions
    required_rules: Optional[list[str]] = None
    expected_rules: Optional[list[str]] = None
    forbidden_rules: Optional[list[str]] = None

    # Override behavior
    must_change: Optional[bool] = None
    allow_unchanged_pseudocode_if_rules_fired: Optional[bool] = None
    skip: Optional[str] = None  # Skip reason for this binary
    operator_complexity_mode: Optional[str] = None
    operator_complexity_ops: Optional[list[str]] = None


@dataclass
class DeobfuscationCase:
    """Specification for a deobfuscation test case.

    Each instance describes a single test: the function to deobfuscate,
    what patterns indicate obfuscation, what the expected output looks like,
    and which rules should fire.

    Example::

        DeobfuscationCase(
            function="test_chained_add",
            project="default_instruction_only.json",
            obfuscated_contains=["0xFFFFFFEF"],
            expected_code='''
                __int64 __fastcall test_chained_add(__int64 a1) {
                    return 2 * a1[1] + 0x33;
                }
            ''',
            acceptable_patterns=["2 * a1[1]", "a1[1] + a1[1]"],
            required_rules=["ArithmeticChain"],
        )

    Attributes:
        function: Name of the function to test (without leading underscore).
        project: D810 project configuration file to use.
        description: Optional description of what this test verifies.

        obfuscated_contains: Patterns that MUST be present in obfuscated code.
        obfuscated_regexes: Regex patterns that MUST match obfuscated code.
        obfuscated_not_contains: Patterns that MUST NOT be present in obfuscated code.

        expected_code: The exact expected deobfuscated code (normalized).
        acceptable_patterns: Alternative patterns that indicate successful deobfuscation.
        deobfuscated_contains: Patterns that MUST be present after deobfuscation.
        deobfuscated_regexes: Regex patterns that MUST match after deobfuscation.
        deobfuscated_not_contains: Patterns that MUST NOT be present after deobfuscation.

        required_rules: Rules that MUST fire during deobfuscation (test fails if not).
        expected_rules: Rules that SHOULD fire (warning if missing, not failure).
        forbidden_rules: Rules that MUST NOT fire (test fails if they do).

        semantic_reference: Repo-relative C source path whose ``int
            <function>(int input)`` is compiled and diffed against the AFTER
            pseudocode (behavioral equivalence; single-int-arg only).
        must_change: Whether deobfuscation must change the code (default: True).
        allow_unchanged_pseudocode_if_rules_fired: Permit an unchanged rendered
            pseudocode string only when the explicitly required CFG rule(s)
            recorded a native mutation. This is for SDK renderer no-ops, not a
            general relaxation of ``must_change``.
        check_stats: Whether to verify rule firing statistics (default: True).
        skip: If set, skip this test with this reason.
        operator_complexity_mode: Optional complexity trend assertion mode:
            "decrease" or "non_increase".
        operator_complexity_ops: Optional operator tokens to count for complexity.

        dll_override: Override config for .dll binaries.
        dylib_override: Override config for .dylib binaries.
    """

    # Required: Function to test
    function: str

    # Project configuration
    project: str = "default_instruction_only.json"

    # Optional per-function typed state-CFF threshold override. The runner
    # applies this through an in-memory function recipe and preserves the
    # active recipe's family and recovery strategy.
    state_cff_min_state_constant: Optional[int] = None

    # Optional description
    description: str = ""

    # Before assertions (obfuscated code)
    obfuscated_contains: list[str] = field(default_factory=list)
    obfuscated_regexes: list[str] = field(default_factory=list)
    obfuscated_not_contains: list[str] = field(default_factory=list)

    # After assertions (deobfuscated code)
    expected_code: Optional[str] = None
    acceptable_patterns: list[str] = field(default_factory=list)
    deobfuscated_contains: list[str] = field(default_factory=list)
    deobfuscated_regexes: list[str] = field(default_factory=list)
    deobfuscated_not_contains: list[str] = field(default_factory=list)

    # Rule assertions
    required_rules: list[str] = field(default_factory=list)
    expected_rules: list[str] = field(default_factory=list)
    forbidden_rules: list[str] = field(default_factory=list)

    # AST metrics baseline (from CodeComparator.count_ast_statements)
    expected_ast_stats: Optional[dict[str, int]] = None
    # Hex-Rays rendering and ctree simplification can legitimately change
    # statement shape across SDK releases without changing semantics.  Keep
    # those baselines exact and explicit instead of weakening them to ranges.
    expected_ast_stats_by_sdk: dict[int, dict[str, int]] = field(
        default_factory=dict
    )

    # Behavioral semantic-equivalence oracle: repo-root-relative path to a C
    # source file containing ``int <function>(int input){...}``.  When set, the
    # deobfuscated AFTER pseudocode is compiled next to that reference and their
    # outputs are diffed over an input range -- a behavioral check strictly
    # stronger than ``must_change`` (single ``int``-arg references only).
    semantic_reference: Optional[str] = None

    # Behavior flags
    must_change: bool = True
    allow_unchanged_pseudocode_if_rules_fired: bool = False
    check_stats: bool = True
    skip: Optional[str] = None
    # When True, a function absent from the current binary is a SKIP, not a
    # failure.  Used by Windows-only fixtures (e.g. MASM-linked ``src/masm/*.asm``
    # functions that exist only in the PE ``.dll``, not the ``.dylib``/``.so``).
    skip_if_function_absent: bool = False
    operator_complexity_mode: Optional[str] = None
    operator_complexity_ops: list[str] = field(default_factory=list)

    # Binary-specific overrides
    dll_override: Optional[BinaryOverride] = None
    dylib_override: Optional[BinaryOverride] = None

    def __post_init__(self):
        """Normalize expected_code by dedenting."""
        if self.expected_code is not None:
            self.expected_code = textwrap.dedent(self.expected_code).strip()

    def expected_ast_stats_for_sdk(self, sdk_version: int) -> Optional[dict[str, int]]:
        """Return the exact AST baseline declared for one IDA SDK."""
        return self.expected_ast_stats_by_sdk.get(
            int(sdk_version), self.expected_ast_stats
        )

    def get_effective_config(self, binary_suffix: str) -> DeobfuscationCase:
        """Get effective configuration with binary-specific overrides applied.

        Args:
            binary_suffix: The binary file suffix (e.g., ".dll", ".dylib")

        Returns:
            A new DeobfuscationCase with overrides merged in.
        """
        # Select the appropriate override
        override: Optional[BinaryOverride] = None
        if binary_suffix == ".dll" and self.dll_override:
            override = self.dll_override
        elif binary_suffix == ".dylib" and self.dylib_override:
            override = self.dylib_override

        if override is None:
            return self

        # Create a copy with overrides applied
        return DeobfuscationCase(
            function=self.function,
            project=self.project,
            state_cff_min_state_constant=self.state_cff_min_state_constant,
            description=self.description,
            # Apply overrides (use override value if not None, else original)
            obfuscated_contains=(
                override.obfuscated_contains
                if override.obfuscated_contains is not None
                else self.obfuscated_contains
            ),
            obfuscated_regexes=(
                override.obfuscated_regexes
                if override.obfuscated_regexes is not None
                else self.obfuscated_regexes
            ),
            obfuscated_not_contains=(
                override.obfuscated_not_contains
                if override.obfuscated_not_contains is not None
                else self.obfuscated_not_contains
            ),
            expected_code=(
                override.expected_code
                if override.expected_code is not None
                else self.expected_code
            ),
            acceptable_patterns=(
                override.acceptable_patterns
                if override.acceptable_patterns is not None
                else self.acceptable_patterns
            ),
            deobfuscated_contains=(
                override.deobfuscated_contains
                if override.deobfuscated_contains is not None
                else self.deobfuscated_contains
            ),
            deobfuscated_regexes=(
                override.deobfuscated_regexes
                if override.deobfuscated_regexes is not None
                else self.deobfuscated_regexes
            ),
            deobfuscated_not_contains=(
                override.deobfuscated_not_contains
                if override.deobfuscated_not_contains is not None
                else self.deobfuscated_not_contains
            ),
            required_rules=(
                override.required_rules
                if override.required_rules is not None
                else self.required_rules
            ),
            expected_rules=(
                override.expected_rules
                if override.expected_rules is not None
                else self.expected_rules
            ),
            forbidden_rules=(
                override.forbidden_rules
                if override.forbidden_rules is not None
                else self.forbidden_rules
            ),
            expected_ast_stats=self.expected_ast_stats,
            expected_ast_stats_by_sdk=self.expected_ast_stats_by_sdk,
            semantic_reference=self.semantic_reference,
            must_change=(
                override.must_change
                if override.must_change is not None
                else self.must_change
            ),
            allow_unchanged_pseudocode_if_rules_fired=(
                override.allow_unchanged_pseudocode_if_rules_fired
                if override.allow_unchanged_pseudocode_if_rules_fired is not None
                else self.allow_unchanged_pseudocode_if_rules_fired
            ),
            check_stats=self.check_stats,
            skip=override.skip if override.skip is not None else self.skip,
            skip_if_function_absent=self.skip_if_function_absent,
            operator_complexity_mode=(
                override.operator_complexity_mode
                if override.operator_complexity_mode is not None
                else self.operator_complexity_mode
            ),
            operator_complexity_ops=(
                override.operator_complexity_ops
                if override.operator_complexity_ops is not None
                else self.operator_complexity_ops
            ),
            # Don't copy overrides to the effective config
            dll_override=None,
            dylib_override=None,
        )

    @property
    def test_id(self) -> str:
        """Generate a test ID for pytest parametrization."""
        return self.function
