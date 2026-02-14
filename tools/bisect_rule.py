#!/usr/bin/env python3
"""Bisect which block-level rule causes CFG corruption in predecessor_uniformity_pattern."""

import json
import subprocess
import sys
from pathlib import Path

# 8 block rules to bisect
RULES = [
    "BlockLevelEgglogOptimizer",
    "StackVariableConstantPropagationRule",
    "FixPredecessorOfConditionalJumpBlock",
    "Unflattener",
    "UnflattenerSwitchCase",
    "BadWhileLoop",
    "UnflattenerTigressIndirect",
    "JumpFixer",
]

ORIGINAL_CONFIG = "example_libobfuscated.json"
TEST_CASE_FILE = "tests/system/cases/libobfuscated_comprehensive.py"


def backup_test_case():
    """Backup the original test case file."""
    src = Path(TEST_CASE_FILE)
    dst = Path(TEST_CASE_FILE + ".backup")
    dst.write_text(src.read_text())
    print(f"Backed up {TEST_CASE_FILE} to {dst}")


def restore_test_case():
    """Restore the original test case file."""
    src = Path(TEST_CASE_FILE + ".backup")
    dst = Path(TEST_CASE_FILE)
    if src.exists():
        dst.write_text(src.read_text())
        src.unlink()
        print(f"Restored {TEST_CASE_FILE}")


def modify_test_case_config(config_name):
    """Temporarily modify the test case to use the specified config."""
    test_case_path = Path(TEST_CASE_FILE)
    content = test_case_path.read_text()

    # Find and replace the project config for predecessor_uniformity_pattern
    # Looking for: project="example_libobfuscated.json"
    original_line = f'project="{ORIGINAL_CONFIG}"'
    new_line = f'project="{config_name}"'

    # Find the predecessor_uniformity_pattern case and replace its project line
    lines = content.split('\n')
    in_predecessor_case = False
    modified = False

    for i, line in enumerate(lines):
        if 'function="predecessor_uniformity_pattern"' in line:
            in_predecessor_case = True
        elif in_predecessor_case and 'project=' in line:
            lines[i] = line.replace(original_line, new_line)
            modified = True
            break

    if not modified:
        print(f"WARNING: Could not find project line for predecessor_uniformity_pattern")
        return False

    test_case_path.write_text('\n'.join(lines))
    print(f"Modified test case to use {config_name}")
    return True


def run_test(config_name):
    """Run the test with the specified config and return True if it passes."""
    print(f"\n{'='*80}")
    print(f"Testing with config: {config_name}")
    print(f"{'='*80}\n")

    # Modify the test case to use this config
    if not modify_test_case_config(config_name):
        return None

    # Run the test
    cmd = [
        "pytest",
        "tests/system/e2e/test_libdeobfuscated_dsl.py::TestDispatcherPatterns::test_dispatcher_patterns[predecessor_uniformity_pattern]",
        "-v",
        "--tb=short",
        "-s",  # Capture stdout to see decompilation output
    ]

    env = {"D810_TEST_BINARY": "libobfuscated.dll", "PYTHONPATH": "src"}

    result = subprocess.run(
        cmd,
        env={**subprocess.os.environ, **env},
        capture_output=True,
        text=True,
    )

    # Check if test passed
    passed = result.returncode == 0 and "PASSED" in result.stdout

    # Print last 20 lines of output for context
    print("\nLast 20 lines of output:")
    print("-" * 80)
    output_lines = (result.stdout + result.stderr).split('\n')
    print('\n'.join(output_lines[-20:]))
    print("-" * 80)

    return passed


def main():
    """Run bisection to find the culprit rule."""
    print("D810 Block Rule Bisection")
    print("=" * 80)
    print(f"Testing {len(RULES)} block-level rules")
    print(f"Test case: predecessor_uniformity_pattern")
    print(f"Binary: libobfuscated.dll")
    print("=" * 80)

    # Backup test case
    backup_test_case()

    try:
        results = {}

        # Test baseline (all rules enabled)
        print("\n\nBASELINE TEST (all rules enabled):")
        baseline_passed = run_test(ORIGINAL_CONFIG)
        results["ALL_ENABLED"] = baseline_passed

        # Test each rule disabled
        for rule_name in RULES:
            config_name = f"example_libobfuscated_no_{rule_name}.json"
            passed = run_test(config_name)
            results[rule_name] = passed

        # Print summary
        print("\n\n" + "=" * 80)
        print("BISECTION RESULTS")
        print("=" * 80)
        print(f"{'Rule':<50} {'Result':<10}")
        print("-" * 80)
        print(f"{'ALL_ENABLED (baseline)':<50} {'PASS' if results['ALL_ENABLED'] else 'FAIL':<10}")

        for rule_name in RULES:
            result = results[rule_name]
            result_str = "PASS" if result else "FAIL" if result is not None else "ERROR"
            print(f"{rule_name:<50} {result_str:<10}")

        print("-" * 80)

        # Identify culprits
        culprits = [
            rule for rule in RULES
            if results[rule] and not results["ALL_ENABLED"]
        ]

        if culprits:
            print("\nCULPRIT RULES (test PASSES when disabled):")
            for culprit in culprits:
                print(f"  - {culprit}")
        else:
            print("\nNo single culprit found. The issue may be caused by:")
            print("  - Multiple rules interacting")
            print("  - A rule not in the bisection set")
            print("  - Environmental factors")

    finally:
        # Restore test case
        restore_test_case()

        # Clean up config files
        print("\nCleaning up temporary config files...")
        for rule_name in RULES:
            config_path = Path(f"src/d810/conf/example_libobfuscated_no_{rule_name}.json")
            if config_path.exists():
                config_path.unlink()
                print(f"  Deleted {config_path.name}")


if __name__ == "__main__":
    main()
