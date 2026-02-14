#!/usr/bin/env python3
"""Bisect which block-level rule causes CFG corruption in predecessor_uniformity_pattern.

This version runs a minimal test per config to check if decompilation succeeds.
"""

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


def create_config_variant(rule_to_disable):
    """Create a config variant with one rule disabled."""
    with open("src/d810/conf/example_libobfuscated.json", "r") as f:
        base_config = json.load(f)

    # Disable the specified rule
    for rule in base_config["blk_rules"]:
        if rule["name"] == rule_to_disable:
            rule["is_activated"] = False
            break

    config_name = f"example_libobfuscated_no_{rule_to_disable}.json"
    config_path = Path(f"src/d810/conf/{config_name}")

    with open(config_path, "w") as f:
        json.dump(base_config, f, indent=2)

    return config_path, config_name


def cleanup_config(config_path):
    """Delete a temporary config file."""
    if config_path.exists():
        config_path.unlink()


def run_test_inline(config_name):
    """Run inline test script that checks if decompilation succeeds."""
    test_script = f'''
import idaapi
import ida_funcs
import ida_name

# Find function
func_ea = ida_name.get_name_ea(idaapi.BADADDR, "predecessor_uniformity_pattern")
if func_ea == idaapi.BADADDR:
    print("RESULT: ERROR - Function not found")
    idaapi.qexit(1)

# Get function object
func = ida_funcs.get_func(func_ea)
if not func:
    print("RESULT: ERROR - No func_t")
    idaapi.qexit(1)

# Decompile BEFORE d810
before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
if before is None:
    print("RESULT: ERROR - Decompilation failed BEFORE d810")
    idaapi.qexit(1)

before_code = "\\n".join([str(before.get_pseudocode()[i]) for i in range(before.get_pseudocode().size())])
print("=" * 80)
print("BEFORE D810:")
print("=" * 80)
print(before_code)
print("=" * 80)

# Load d810 with specified config
import sys
sys.path.insert(0, "/Users/mahmoud/src/idapro/d810/src")

from d810.core.config import D810ConfigManager
config_mgr = D810ConfigManager()
config_mgr.load_configuration("{config_name}")

from d810.core.emulator import D810Optimizer
optimizer = D810Optimizer(config_mgr)

# Run d810
optimizer.optimize_function(func_ea)

# Decompile AFTER d810
after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
if after is None:
    print("RESULT: FAIL - Decompilation returned None after d810 (CFG corruption)")
    idaapi.qexit(1)

after_code = "\\n".join([str(after.get_pseudocode()[i]) for i in range(after.get_pseudocode().size())])
print("=" * 80)
print("AFTER D810:")
print("=" * 80)
print(after_code)
print("=" * 80)

print("RESULT: PASS - Decompilation succeeded after d810")
idaapi.qexit(0)
'''

    # Write test script to temp file
    script_path = Path("/tmp/d810_bisect_test.py")
    script_path.write_text(test_script)

    # Run IDA in batch mode with the test script
    cmd = [
        "/Applications/IDA Professional 9.2.app/Contents/MacOS/ida64",
        "-A",
        "-S" + str(script_path),
        "/Users/mahmoud/src/idapro/d810/samples/bins/libobfuscated.dll",
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
    )

    # Parse result
    output = result.stdout + result.stderr

    if "RESULT: PASS" in output:
        # Extract BEFORE and AFTER code
        before_code = ""
        after_code = ""

        lines = output.split("\n")
        in_before = False
        in_after = False

        for line in lines:
            if line.startswith("=" * 80):
                continue
            if "BEFORE D810:" in line:
                in_before = True
                in_after = False
                continue
            if "AFTER D810:" in line:
                in_after = True
                in_before = False
                continue
            if "RESULT:" in line:
                in_before = False
                in_after = False
                continue

            if in_before:
                before_code += line + "\n"
            elif in_after:
                after_code += line + "\n"

        return True, before_code.strip(), after_code.strip()
    elif "RESULT: FAIL" in output:
        return False, None, None
    else:
        print(f"ERROR: Could not parse result from output")
        print("Output:", output[-500:])  # Last 500 chars
        return None, None, None


def main():
    """Run bisection to find the culprit rule."""
    print("D810 Block Rule Bisection v2")
    print("=" * 80)
    print(f"Testing {len(RULES)} block-level rules")
    print(f"Test case: predecessor_uniformity_pattern")
    print(f"Binary: libobfuscated.dll")
    print("=" * 80)

    results = {}
    before_code_sample = None
    after_code_sample = None

    # Test baseline (all rules enabled)
    print("\n\nBASELINE TEST (all rules enabled):")
    print("=" * 80)
    passed, before, after = run_test_inline(ORIGINAL_CONFIG)
    results["ALL_ENABLED"] = passed

    if passed and before:
        before_code_sample = before
        after_code_sample = after

    # Test each rule disabled
    for rule_name in RULES:
        print(f"\n\nTesting with {rule_name} DISABLED:")
        print("=" * 80)

        config_path, config_name = create_config_variant(rule_name)

        try:
            passed, before, after = run_test_inline(config_name)
            results[rule_name] = passed

            # Save first passing config's output
            if passed and not before_code_sample and before:
                before_code_sample = before
                after_code_sample = after

        finally:
            cleanup_config(config_path)

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
        rule
        for rule in RULES
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

    # Print pseudocode samples
    if before_code_sample:
        print("\n\n" + "=" * 80)
        print("PSEUDOCODE BEFORE DEOBFUSCATION (obfuscated)")
        print("=" * 80)
        print(before_code_sample)

    if after_code_sample:
        print("\n\n" + "=" * 80)
        print("PSEUDOCODE AFTER DEOBFUSCATION (for passing config)")
        print("=" * 80)
        print(after_code_sample)


if __name__ == "__main__":
    main()
