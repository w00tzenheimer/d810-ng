#!/usr/bin/env python3
"""Bisect which block-level rule causes CFG corruption in predecessor_uniformity_pattern.

This version runs a minimal test per config to check if decompilation succeeds.
Uses ``import idapro`` (idalib) instead of spawning ida64 as a subprocess.
"""

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

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
    with open(_REPO_ROOT / "src" / "d810" / "conf" / "example_libobfuscated.json") as f:
        base_config = json.load(f)

    # Disable the specified rule
    for rule in base_config["blk_rules"]:
        if rule["name"] == rule_to_disable:
            rule["is_activated"] = False
            break

    config_name = f"example_libobfuscated_no_{rule_to_disable}.json"
    config_path = _REPO_ROOT / "src" / "d810" / "conf" / config_name

    with open(config_path, "w") as f:
        json.dump(base_config, f, indent=2)

    return config_path, config_name


def cleanup_config(config_path):
    """Delete a temporary config file."""
    if config_path.exists():
        config_path.unlink()


def run_test_inline(config_name: str) -> tuple[bool | None, str, str]:
    """Run decompilation inline using idalib. Returns (passed, before_code, after_code)."""
    import idaapi
    import ida_name

    func_ea = ida_name.get_name_ea(idaapi.BADADDR, "predecessor_uniformity_pattern")
    if func_ea == idaapi.BADADDR:
        print("ERROR: Function not found")
        return None, "", ""

    before = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    if before is None:
        print("ERROR: Decompilation failed BEFORE d810")
        return None, "", ""

    before_code = "\n".join(
        str(before.get_pseudocode()[i])
        for i in range(before.get_pseudocode().size())
    )

    print("=" * 80)
    print("BEFORE D810:")
    print("=" * 80)
    print(before_code)
    print("=" * 80)

    from d810.core.config import D810ConfigManager
    from d810.core.emulator import D810Optimizer

    config_mgr = D810ConfigManager()
    config_mgr.load_configuration(config_name)
    optimizer = D810Optimizer(config_mgr)
    optimizer.optimize_function(func_ea)

    after = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    if after is None:
        print("RESULT: FAIL - Decompilation returned None after d810 (CFG corruption)")
        return False, before_code, ""

    after_code = "\n".join(
        str(after.get_pseudocode()[i])
        for i in range(after.get_pseudocode().size())
    )

    print("=" * 80)
    print("AFTER D810:")
    print("=" * 80)
    print(after_code)
    print("=" * 80)

    print("RESULT: PASS - Decompilation succeeded after d810")
    return True, before_code, after_code


def main():
    """Run bisection to find the culprit rule."""
    import idapro

    binary_path = _REPO_ROOT / "samples" / "bins" / "libobfuscated.dll"
    idapro.open_database(str(binary_path), run_auto_analysis=True)

    import idaapi  # noqa: F401
    import ida_funcs  # noqa: F401
    import ida_name  # noqa: F401

    print("D810 Block Rule Bisection v2")
    print("=" * 80)
    print(f"Testing {len(RULES)} block-level rules")
    print("Test case: predecessor_uniformity_pattern")
    print("Binary: libobfuscated.dll")
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
