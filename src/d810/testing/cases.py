"""Deobfuscation test case dataclass definitions.

This module defines the data structures used to specify deobfuscation test cases
in a declarative, data-driven manner.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass, field
from typing import Optional


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
    obfuscated_not_contains: Optional[list[str]] = None

    # Override after assertions
    expected_code: Optional[str] = None
    acceptable_patterns: Optional[list[str]] = None
    deobfuscated_contains: Optional[list[str]] = None
    deobfuscated_not_contains: Optional[list[str]] = None

    # Override rule assertions
    required_rules: Optional[list[str]] = None
    expected_rules: Optional[list[str]] = None
    forbidden_rules: Optional[list[str]] = None

    # Override behavior
    must_change: Optional[bool] = None
    skip: Optional[str] = None  # Skip reason for this binary


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
        obfuscated_not_contains: Patterns that MUST NOT be present in obfuscated code.

        expected_code: The exact expected deobfuscated code (normalized).
        acceptable_patterns: Alternative patterns that indicate successful deobfuscation.
        deobfuscated_contains: Patterns that MUST be present after deobfuscation.
        deobfuscated_not_contains: Patterns that MUST NOT be present after deobfuscation.

        required_rules: Rules that MUST fire during deobfuscation (test fails if not).
        expected_rules: Rules that SHOULD fire (warning if missing, not failure).
        forbidden_rules: Rules that MUST NOT fire (test fails if they do).

        must_change: Whether deobfuscation must change the code (default: True).
        check_stats: Whether to verify rule firing statistics (default: True).
        skip: If set, skip this test with this reason.

        dll_override: Override config for .dll binaries.
        dylib_override: Override config for .dylib binaries.
    """

    # Required: Function to test
    function: str

    # Project configuration
    project: str = "default_instruction_only.json"

    # Optional description
    description: str = ""

    # Before assertions (obfuscated code)
    obfuscated_contains: list[str] = field(default_factory=list)
    obfuscated_not_contains: list[str] = field(default_factory=list)

    # After assertions (deobfuscated code)
    expected_code: Optional[str] = None
    acceptable_patterns: list[str] = field(default_factory=list)
    deobfuscated_contains: list[str] = field(default_factory=list)
    deobfuscated_not_contains: list[str] = field(default_factory=list)

    # Rule assertions
    required_rules: list[str] = field(default_factory=list)
    expected_rules: list[str] = field(default_factory=list)
    forbidden_rules: list[str] = field(default_factory=list)

    # Behavior flags
    must_change: bool = True
    check_stats: bool = True
    skip: Optional[str] = None

    # Binary-specific overrides
    dll_override: Optional[BinaryOverride] = None
    dylib_override: Optional[BinaryOverride] = None

    def __post_init__(self):
        """Normalize expected_code by dedenting."""
        if self.expected_code is not None:
            self.expected_code = textwrap.dedent(self.expected_code).strip()

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
            description=self.description,
            # Apply overrides (use override value if not None, else original)
            obfuscated_contains=(
                override.obfuscated_contains
                if override.obfuscated_contains is not None
                else self.obfuscated_contains
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
            must_change=(
                override.must_change
                if override.must_change is not None
                else self.must_change
            ),
            check_stats=self.check_stats,
            skip=override.skip if override.skip is not None else self.skip,
            # Don't copy overrides to the effective config
            dll_override=None,
            dylib_override=None,
        )

    @property
    def test_id(self) -> str:
        """Generate a test ID for pytest parametrization."""
        return self.function
