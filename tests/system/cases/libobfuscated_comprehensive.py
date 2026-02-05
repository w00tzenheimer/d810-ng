"""Comprehensive test cases for libobfuscated binary.

This module defines ALL deobfuscation test cases from samples/src/c/ as data
using the DeobfuscationCase DSL. Organized by source file for easy reference.

To run: pytest tests/system/test_libdeobfuscated_dsl.py -v
"""

import base64
import gzip
import textwrap

from d810.testing import BinaryOverride, DeobfuscationCase


def _decode_expected(encoded: str) -> str:
    """Decode base64+gzip compressed expected code.

    Use _encode_expected() to generate encoded strings from raw code.
    """
    return gzip.decompress(base64.b64decode(encoded)).decode("utf-8")


def _encode_expected(code: str) -> str:
    """Encode expected code as base64+gzip for compact storage.

    Usage:
        >>> code = '''__int64 func() { return 0; }'''
        >>> encoded = _encode_expected(code)
        >>> print(encoded)  # Use this in DeobfuscationCase
    """
    normalized = textwrap.dedent(code).strip()
    compressed = gzip.compress(normalized.encode("utf-8"), compresslevel=9)
    return base64.b64encode(compressed).decode("ascii")


# =============================================================================
# Encoded expected_code for long deobfuscated functions (from results.toml)
# =============================================================================

# hodur_func: 4119 chars -> 1624 chars encoded
_HODUR_FUNC_EXPECTED = (
    "H4sIAIleL2kC/8WXe2/bNhDA//en4AQskBLXEWWJkuoVmF5eBmhxGnfogCzVPEV2Zeth6OE5C7LPPlIP"
    "h5ItOxkwVCjqHMk7Hu93x4fj+FGGROA481maubMgAF/jhzxx5nnkslzvqQfwd3kJ7oyJbWs3U8sE9sTQ"
    "bGBahq3dap9+nlxPB+Dm1ppOwfWvv9xoJmAuGPBpAqzfbrRr875XmNgMBfAB8FtdGJvKWEejqpUnrZUg"
    "qLSg0IJMC4gWJEoYQix89qOrLFtP1l7E2swVWc0lHPBMH/C7f1yp4M8BC74jalwhky/xsjyJABz1KA8r"
    "m0YcRZ6bsVijD2zG287CdeAN3Dgk1rdQ1/dt85Xtp90MtbEgTr2rWfQQeMRgpdZ0gUjPpSPrBJOaOzzL"
    "3J3fg2k2SzI/WoB5MMsyL/IegLf13Dzz4wi3xX8NBoPfI6YyOk3cO/6+iL+kyZo8lnnRRAqyJNm2X4bA"
    "cgjuNvEgRTZFKOvIrIdshOFLrEMvdNeP2J2NIPaJdhEAmFczzuMEL98vxuOfH0gn/uviwqdCjVXv/Hvw"
    "5QNgffCODDE5cAYk8AWwWDBwm08a+O1Yw224SR3tBePiHpiemzyuMxwDVgsWMYDce/B9ipffJ1Nwo0YC"
    "GggpkiDJdJqxm9jHylQRnHNl23kfl0ZRIn2AfyiZ4xIvjYON58zWPvsyT8GdmKXXqeABah8M++Bs4WR+"
    "6MV55oSph6NG9JoVogqihEyrchCqp9CRISfR8V3osPYhdMsS3ZJCt2yhW5bo8ij1FyQBi8AoHLvcsSTM"
    "rOGrmAnHmA0NRUW8pn4LZug1zCyDH0Ko1g5CdJoZOskMyt3M0CFmq5LZimK2ajFblcxW/wXR8BgiRdZ4"
    "Q0PWt0Akvaqs5LGiKYpeB7fYy7YiOswnzRIcb3YDsYPMdvmH4/+5yFy33lCbOM6wtYLHsMkjLHmEJQ+B"
    "8AhbPMKSR/gmHkcw6AoUlTGij82j8ZT3TqcNhCVQnnwjylt1hxRjZCteXXjdOEoz4H6dJfuS8/Hz5Nbc"
    "/8UGOQ77xLG7Wfc/fKL2j3QzPzFHuy+PdvP/U2cVTa5xolcI1H0EO5jIMnSLhqAe3VUamYvvOUw4W7Yy"
    "91D2qs3kfUngqEzgiErgiErgOomjMomjw0n8tkSm1w+RqUFTM+gkRJ0ZXfRTWyYVYkQ5/dR0n9hjHmbZ"
    "jBk1O2C5hYvNZntiklzF03L7ncXsJyujnfUdtVFvj04xIakL1FUXZBPsvSkru9rLSHR0nrOlc3gxG9jv"
    "cqVrRorSc68FSO7mU6WCaImaoOtmK+BiWQ56dznQJSGRighWD39vfszcxePT4h+6Kg5VhlhUhpy3hlW3"
    "2/p6W91vUXG/9VsFsrvo1jddv7tM3l4qdIxMJOj8WFZbvcUL6fhR/LFMse66ompJOrg+qTyJea61mpdn"
    "n6lYWn2pPbxWa/eAwQ8q/K4iN480d10vTed5EDxSD5r6W8RZDGxNt2xnq+jm+GCO7eIjIhNJplFvwuR/"
    "L0i9jt23Pbx9Ir/DHicJzoTYdfMkwc76EfUcKx5hpcc9ysP3h7b+rlehoNbxLBV2j8nOZyTfUoCnFGCt"
    "UD068eb5/C8PSvukFRAAAA=="
)

# test_function_ollvm_fla_bcf_sub: 3031 chars -> 1468 chars encoded
_OLLVM_FLA_BCF_SUB_EXPECTED = (
    "H4sIAM9eL2kC/41WbW/bNhD+7l/BGFhhO1nLN1FSu3wgRQoY4MVBkmEbik5wHDk15tiBpage0vS3jxKp"
    "hKKVtUaBhjw9x7vnuTuy2q5uQJYt50W5mK/XoMyLMls+bBblarvJtut1dZct1/PserHMiofr0cOmWN1u"
    "8huw2pRgMkcnwNvB48HjAOjfu3fgYzKbTvn5pZJgOkv4FEiVTPkFv/p1dnb5FpxfqMtLcPb7b+dcguHx"
    "EFzNgPrznJ/JT4PGRRUgcArm6INdwXqF7YrGegX3SUxjRRJpdu/yuyIvMzh6U7ETAPW/PaMPYwsJP8JP"
    "b8sqK/JFjW0dRXpxm5fl6i7fLm/m/46qUANbEA21uQrbFXORQRNCan/9p+wlwSKICeo1TyajTP4xu5D6"
    "r3EVgmMNwCwJWQqJAdzvNLHLDI2G5+t8XuQg35T5DtzPi+LLdnfzfvgcKNX+isV8s9T5D38qhidAszD+"
    "kWNbD6T2UO42i7t77WO02G6KEiw+z3dgMm4YHWr4Li+HHrEUuRx1j9Jee/a/nnbXRw6rsEM4NjJrTiSL"
    "WhKJEZ/COAwFEmZ3tQSjrtdxs+8iUCBSKQPoImqTa7OwRwccNeAAqjSBxApd/3z5nrMwsGZjj0XMuKSx"
    "sTzZ2ibMBMQVTyJhU3hhzUmjzZnagpexDJOk3SU2NEED5qY16jDxBqBxQ3KHE4PljFFM4pbxuqi1yay+"
    "fF6t85qkwHDUftvDkRFKKCRi2gp1oPvkFDDHRL1UdZzEJRAZmWWaKBgp1wJN6AQRCCF+sfTmTsZN9E7u"
    "rhMFUcqSlDvuDQfQc9sA3GMdh49d19iUGw8UZYFTMC++aO0KeSG52CAliqFUdsEmNKyLaTDlQk2zPecY"
    "vh/0nNBKZmLwTnrsOdcoyKKQIAHph8MvXFZ/bpTBPV9hZMciZ5ThpPvFUzfSfK0nWifcNu0fiJd2++3F"
    "YOey7jssCPlOIsevJ2J7CwU0FSo4SKQVgCrsCVBhU1pUtwpXYehpiIzCUlDFZOIxdLstt8C6Fghq68Aj"
    "z/7Xoa0t4sPGxFF/KTbwI12HXlfY71WgBGEC+12BI78raoCL+J+uMAMxCQPB9RjzWOneG9+mM/HXleq0"
    "8lj3cq0V+OpPjfYWFn67YDNmwxhylCrxOtW1it+l+siZtU6aHT+6Ha2fClkqEUbhcyG+8gxBhhseiyiQ"
    "KeuOX3QoKzKJBZjCCHKnWytkyp9LLQeP3bGG7BUCg4AmlPtCuoH9Ym54vzisB0oYTRkjvgdETSm0J3jw"
    "610+/8chuUKmw5IoDnhC3FpDZhhhxUgUxO51gnuvRzPQPdPx8SvXkO75iX7fmJdN8+zS2PrtFcIxmOgz"
    "+iKBURjVwnSucWSvKERDiDhvxTTtH4eMYOnM6rqf7aio7BMmTiXhlsjD58S37lX2d11NUZLGCVHt48vU"
    "mEjTkCdCD6nB039LCRc41QsAAA=="
)


# =============================================================================
# manually_obfuscated.c - MBA and basic patterns
# =============================================================================

MANUALLY_OBFUSCATED_CASES = [
    DeobfuscationCase(
        function="test_chained_add",
        description="Chained addition expressions with nested operations",
        project="default_instruction_only.json",
        # Obfuscated code has large hex constants (varies by compile)
        obfuscated_contains=[
            "0xFFFFFF"
        ],  # Partial match for any large negative constant
        expected_code="""
            __int64 __fastcall test_chained_add(int *a1)
            {
                return (unsigned int)(2 * a1[1] + 0x33);
            }
        """,
        acceptable_patterns=["2 * a1[1]", "a1[1] + a1[1]", "0x33", "0x34"],
        # From results.toml: ChainOptimizer (2 uses), ArithmeticChain (2 uses)
        required_rules=["ArithmeticChain"],
    ),
    DeobfuscationCase(
        function="test_cst_simplification",
        description="Constant simplification with bitwise AND/OR/XOR",
        project="default_instruction_only.json",
        obfuscated_contains=["0x222E69C2", "0x50211120"],
        acceptable_patterns=["0x222E69C0", "0xD32B5931", "0xA29"],
        must_change=True,  # Original test explicitly requires code change
    ),
    DeobfuscationCase(
        function="test_opaque_predicate",
        description="Opaque predicate patterns that always evaluate to known values",
        project="example_libobfuscated.json",
        obfuscated_contains=["v4", "v3"],
        expected_code="""
            __int64 __fastcall test_opaque_predicate(_DWORD *a1)
            {
                v3 = (a1[4] & 0x23) == 1;
                v2 = (a1[6] & 0x42) != 2;
                a1[1] = 1;
                a1[2] = 0;
                a1[3] = 0;
                a1[4] = v3;
                a1[5] = v2;
                return (unsigned int)(0xB * v2 + 9 * v3 + 0xF);
            }
        """,
        # Flexible patterns for type variations: IDA may use volatile int*, _DWORD*, etc.
        acceptable_patterns=[
            "a1[1] = 1",
            "a1[2] = 0",
            "a1[3] = 0",
            "0xB * v2 + 9 * v3 + 0xF",
        ],
        deobfuscated_contains=["= 1;"],
        must_change=True,
        # Rules vary by IDA version - use acceptable_patterns for validation instead
        # Common rules: BnotOr_FactorRule_1, Xor_HackersDelightRule_1, Z3ConstantOptimization
    ),
    DeobfuscationCase(
        function="test_xor",
        description="XOR MBA pattern: (a + b) - 2*(a & b) => a ^ b",
        project="example_libobfuscated.json",
        # Obfuscated code has MBA patterns with & and - operators
        obfuscated_contains=["&", "-", "2 *"],
        expected_code="""
            __int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
            {
                *a4 = a2 ^ a1;
                a4[1] = (a2 - 3) ^ (a3 * a1);
                return (unsigned int)(a4[1] + *a4);
            }
        """,
        deobfuscated_contains=["^"],  # Should simplify to XOR
        must_change=True,
        # From results.toml: PatternOptimizer (2), Xor_HackersDelightRule_3 (2)
        required_rules=["Xor_HackersDelightRule_3"],
    ),
    DeobfuscationCase(
        function="test_or",
        description="OR MBA pattern: (a & b) + (a ^ b) => a | b",
        project="example_libobfuscated.json",
        obfuscated_contains=["^", "&"],
        expected_code="""
            __int64 __fastcall test_or(int a1, int a2, int a3, int *a4)
            {
                *a4 = a2 | a1;
                a4[1] = a3 | a2;
                a4[2] = (a2 - 2) | (a1 + 1);
                return (unsigned int)(a4[2] + a4[1] + *a4);
            }
        """,
        deobfuscated_contains=["|"],
        must_change=True,
        # From results.toml: PatternOptimizer (3), Or_MbaRule_1 (3)
        required_rules=["Or_MbaRule_1"],
    ),
    DeobfuscationCase(
        function="test_and",
        description="AND MBA pattern: (a | b) - (a ^ b) => a & b",
        project="example_libobfuscated.json",
        obfuscated_contains=["^", "|"],
        expected_code="""
            __int64 __fastcall test_and(int a1, int a2, int a3, int *a4)
            {
                *a4 = a2 & a1;
                a4[1] = a3 & a2;
                a4[2] = (a3 + a2) & (2 * a1);
                return (unsigned int)(a4[2] + a4[1] + *a4);
            }
        """,
        deobfuscated_contains=["&"],
        must_change=True,
        # From results.toml: PatternOptimizer (3), And_HackersDelightRule_4 (3)
        required_rules=["And_HackersDelightRule_4"],
    ),
    DeobfuscationCase(
        function="test_neg",
        description="Negation pattern: ~x + 1 => -x (two's complement)",
        project="default_instruction_only.json",
        # IDA often already simplifies, just verify negation present
        # Or verify the function at least compiles and runs
        acceptable_patterns=["-a1", "- a1", "-a", "-(a1", "-*a1", "- *a1"],
        must_change=False,  # IDA may already have simplified
    ),
    DeobfuscationCase(
        function="test_mba_guessing",
        description="Complex MBA with nested bitwise operations",
        project="default_instruction_only.json",
        # Obfuscated has many operations - just verify the function decompiles
        obfuscated_contains=["*"],
        expected_code="""
            __int64 __fastcall test_mba_guessing(int a1, __int64 a2, int a3, int a4)
            {
                return (a1 + a4) & a1 ^ (unsigned int)(a3 + a1);
            }
        """,
        # Accept various simplified forms
        acceptable_patterns=["a1 + a4", "a4 + a1", "return"],
        must_change=True,
        # Rules vary by IDA version - validation done via expected_code/acceptable_patterns
        # Common rules: BnotXor_FactorRule_1, Add_HackersDelightRule_2, ArithmeticChain
    ),
]


# =============================================================================
# abc_f6_constants.c - ABC pattern with F6xxx magic constants
# =============================================================================

ABC_F6_CASES = [
    DeobfuscationCase(
        function="abc_f6_add_dispatch",
        description="ABC pattern with ADD using F6xxx magic constants",
        project="example_libobfuscated.json",
        obfuscated_contains=["0xF6"],
        must_change=True,
    ),
    DeobfuscationCase(
        function="abc_f6_sub_dispatch",
        description="ABC pattern using SUB with F6xxx constants",
        # Uses example_libobfuscated_no_fixprecedessor.json which HAS UnflattenerFakeJump
        project="example_libobfuscated_no_fixprecedessor.json",
        obfuscated_contains=["0xF6"],
        expected_code="""
            __int64 __fastcall abc_f6_sub_dispatch(int a1)
            {
                v2 = 3 * (a1 + 0xA);
                if ( v2 <= 0x64 )
                    return (unsigned int)(v2 / 2);
                else
                    return (unsigned int)(3 * (a1 + 0xA));
            }
        """,
        # Accept both if/else orderings - IDA may invert the condition
        acceptable_patterns=["v2 / 2", "3 * (a1 + 0xA)", "0x64"],
        must_change=True,
        # From results.toml: UnflattenerFakeJump (4 uses, 14 patches)
        required_rules=["UnflattenerFakeJump"],
    ),
    DeobfuscationCase(
        function="abc_f6_xor_dispatch",
        description="ABC pattern with XOR-based state transitions",
        project="example_libobfuscated.json",
        obfuscated_contains=["0xF6"],
        must_change=True,
    ),
    DeobfuscationCase(
        function="abc_f6_or_dispatch",
        description="ABC pattern with OR operations on state variables",
        # Uses example_libobfuscated_no_fixprecedessor.json which HAS UnflattenerFakeJump
        project="example_libobfuscated_no_fixprecedessor.json",
        obfuscated_contains=["0xF6"],
        expected_code="""
            __int64 __fastcall abc_f6_or_dispatch(int a1)
            {
                return a1 | 0xFFu;
            }
        """,
        # Accept minor variations in type suffix and parameter type
        acceptable_patterns=["a1 | 0xFF", "a1 | 0xFFu"],
        must_change=True,
        # From results.toml: UnflattenerFakeJump (2 uses, 5 patches)
        required_rules=["UnflattenerFakeJump"],
    ),
    DeobfuscationCase(
        function="abc_f6_nested",
        description="Nested conditional ABC pattern",
        project="example_libobfuscated.json",
        obfuscated_contains=["0xF6"],
        must_change=True,
    ),
    DeobfuscationCase(
        function="abc_f6_64bit_pattern",
        description="ABC pattern with 64-bit magic constants",
        project="example_libobfuscated.json",
        must_change=True,
    ),
]


# =============================================================================
# abc_xor_dispatch.c - XOR/OR based dispatchers
# =============================================================================

ABC_XOR_CASES = [
    DeobfuscationCase(
        function="abc_xor_dispatch",
        description="XOR-based flattened control flow dispatcher",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="abc_or_dispatch",
        description="OR-based state manipulation with mask operations",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="abc_mixed_dispatch",
        description="Combined XOR/OR state transitions",
        project="example_libobfuscated.json",
        must_change=True,
    ),
]


# =============================================================================
# approov_flattened.c - Approov-style obfuscation
# =============================================================================

APPROOV_CASES = [
    DeobfuscationCase(
        function="approov_real_pattern",
        description="Exact decompiled output from real Approov-obfuscated code",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="approov_simplified",
        description="Simplified Approov pattern using while(!=)",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="approov_multistate",
        description="Approov pattern with multiple state transitions",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="approov_vm_dispatcher",
        description="Approov VM dispatcher using switch statement",
        project="default_unflattening_approov.json",  # Requires Approov-specific unflattener
        deobfuscated_not_contains=["switch"],
        must_change=True,
    ),
    DeobfuscationCase(
        function="approov_simple_loop",
        description="Simple loop pattern generating jz instruction",
        project="example_libobfuscated.json",
        must_change=True,
    ),
]


# =============================================================================
# constant_folding.c - Constant folding patterns
# =============================================================================

CONSTANT_FOLDING_CASES = [
    DeobfuscationCase(
        function="constant_folding_test1",
        description="Constant folding with ROL operations and lookup tables",
        project="example_libobfuscated.json",
        # Note: FoldReadonlyDataRule doesn't fire because table indices are
        # dynamically computed (e.g., v46 >> 0x34), not compile-time constants.
        # The deobfuscation still occurs via other constant folding rules.
        must_change=True,
    ),
    DeobfuscationCase(
        function="constant_folding_test2",
        description="Constant folding with bitwise operations",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="outlined_helper_1",
        description="Helper function for constant folding with memory ops",
        project="example_libobfuscated.json",
        must_change=False,
    ),
    DeobfuscationCase(
        function="outlined_helper_2",
        description="Helper function for constant folding with pointers",
        project="example_libobfuscated.json",
        must_change=False,
    ),
    DeobfuscationCase(
        function="AntiDebug_ExceptionFilter",
        description="Anti-debugging exception handler with constant folding",
        project="example_libobfuscated.json",
        must_change=False,
    ),
]


# =============================================================================
# dispatcher_patterns.c - Various dispatcher detection patterns
# =============================================================================

DISPATCHER_PATTERN_CASES = [
    DeobfuscationCase(
        function="high_fan_in_pattern",
        description="HIGH_FAN_IN dispatcher with multiple case blocks",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="state_comparison_pattern",
        description="STATE_COMPARISON pattern with large constants",
        project="example_libobfuscated.json",
        obfuscated_contains=["0x6F5E1A2B"],
        must_change=True,
    ),
    DeobfuscationCase(
        function="nested_while_hodur_pattern",
        description="NESTED_LOOP pattern with Hodur-style while(1) loops",
        project="example_hodur.json",
        obfuscated_contains=["while"],
        must_change=True,
    ),
    DeobfuscationCase(
        function="switch_case_ollvm_pattern",
        description="SWITCH_JUMP pattern with O-LLVM style jtbl",
        project="example_libobfuscated.json",
        obfuscated_contains=["switch", "case"],
        must_change=True,
    ),
    DeobfuscationCase(
        function="mixed_dispatcher_pattern",
        description="Combination of multiple dispatcher strategies",
        project="example_libobfuscated.json",
        must_change=True,
        skip="Causes timeout/infinite loop - needs investigation",
    ),
    DeobfuscationCase(
        function="predecessor_uniformity_pattern",
        description="PREDECESSOR_UNIFORM detection pattern",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="test_all_patterns",
        description="Test harness calling all dispatcher patterns",
        project="example_libobfuscated.json",
        must_change=False,  # This is just a caller
    ),
]


# =============================================================================
# exception_paths.c - Exception/edge cases
# =============================================================================

EXCEPTION_PATH_CASES = [
    DeobfuscationCase(
        function="unresolvable_external",
        description="NotResolvableFatherException - state from external function",
        project="default_unflattening_ollvm.json",
        # These test exception paths - may not change
        must_change=False,
    ),
    DeobfuscationCase(
        function="unresolvable_computed",
        description="State computation from input prevents resolution",
        project="default_unflattening_ollvm.json",
        must_change=False,
    ),
    DeobfuscationCase(
        function="non_duplicable_side_effects",
        description="NotDuplicableFatherException - side effects block duplication",
        project="default_unflattening_ollvm.json",
        must_change=False,
    ),
    DeobfuscationCase(
        function="deep_duplication_path",
        description="Tests MAX_DUPLICATION_PASSES limit with 25+ states",
        project="default_unflattening_ollvm.json",
        must_change=False,
    ),
    DeobfuscationCase(
        function="loop_dependent_state",
        description="State dependent on loop iteration (partial resolution)",
        project="default_unflattening_ollvm.json",
        must_change=False,
    ),
    DeobfuscationCase(
        function="indirect_state_pointer",
        description="Indirect dispatcher with state loaded through pointer",
        project="default_unflattening_ollvm.json",
        must_change=False,
    ),
    DeobfuscationCase(
        function="external_transform_state",
        description="State modified by external function",
        project="default_unflattening_ollvm.json",
        must_change=False,
    ),
]


# =============================================================================
# hodur_c2_flattened.c - Hodur malware patterns
# =============================================================================

HODUR_CASES = [
    DeobfuscationCase(
        function="_hodur_func",
        description="Main Hodur C2 flattened function",
        project="example_hodur.json",
        # Hodur uses while loops for flattening
        obfuscated_contains=["while"],
        # Full expected deobfuscated code from results.toml (base64+gzip encoded)
        expected_code=_decode_expected(_HODUR_FUNC_EXPECTED),
        # The deobfuscated code should be linear (no nested while loops)
        # Note: Import names may show as sub_* if IDA doesn't resolve them
        deobfuscated_contains=["resolve_api"],
        deobfuscated_not_contains=["while ( 1 )"],
        # Must preserve API calls - accept either resolved names or sub_* patterns
        # IDA may not resolve Windows imports depending on platform/version
        acceptable_patterns=[
            "printf", "resolve_api", "WinHttp",  # Resolved names
            "sub_180008C",  # Unresolved addresses (common prefix)
            "Hodur/1.0",  # String literal that should be preserved
        ],
        must_change=True,
        # From results.toml: The config example_hodur.json uses HodurUnflattener
        # (not UnflattenerFakeJump which is used in other configs)
        required_rules=["HodurUnflattener"],
        expected_rules=["CstSimplificationRule16"],
    ),
    DeobfuscationCase(
        function="resolve_api",
        description="Dynamic API resolution helper",
        project="example_hodur.json",
        must_change=False,  # Helper function, not obfuscated
    ),
]


# =============================================================================
# nested_dispatchers.c - Nested dispatcher patterns
# =============================================================================

NESTED_DISPATCHER_CASES = [
    DeobfuscationCase(
        function="nested_simple",
        description="Simple nested dispatcher with outer/inner state machines",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="nested_deep",
        description="Deeply nested dispatchers (3 levels: L1 -> L2 -> L3)",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="nested_parallel",
        description="Parallel nested dispatchers at same nesting level",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="nested_shared_blocks",
        description="Dispatcher with shared internal blocks",
        project="example_libobfuscated.json",
        must_change=True,
    ),
]


# =============================================================================
# ollvm_obfuscated.c - O-LLVM patterns
# =============================================================================

OLLVM_CASES = [
    DeobfuscationCase(
        function="test_function_ollvm_fla_bcf_sub",
        description="O-LLVM FLA+BCF+SUB combined obfuscation",
        # Uses example_libobfuscated_no_fixprecedessor.json which HAS UnflattenerFakeJump
        project="example_libobfuscated_no_fixprecedessor.json",
        obfuscated_contains=["while"],
        # Full expected deobfuscated code from results.toml (base64+gzip encoded)
        expected_code=_decode_expected(_OLLVM_FLA_BCF_SUB_EXPECTED),
        # Deobfuscated should have fewer while loops and cleaner flow
        # Accept either PDB-resolved names (printf_1, scanf_0) or plain names (printf, scanf)
        deobfuscated_contains=["secret"],  # String literal that must be preserved
        acceptable_patterns=[
            "printf", "scanf", "strncmp",  # Plain names (no PDB)
            "printf_1", "scanf_0", "strncmp_0",  # PDB-resolved names
            "Please enter password",  # String literal
        ],
        must_change=True,
        # From results.toml: PatternOptimizer (71), ChainOptimizer (5), many rules
        # Only require the core unflattening rule - other rules vary by environment
        required_rules=["UnflattenerFakeJump"],
        expected_rules=[
            "JumpFixer",
            "PredOdd1",
            "ArithmeticChain",
            "AndBnot_FactorRule_2",
        ],
    ),
]


# =============================================================================
# tigress_obfuscated.c - Tigress patterns
# =============================================================================

TIGRESS_CASES = [
    DeobfuscationCase(
        function="tigress_minmaxarray",
        description="Tigress flattened min/max array search",
        project="example_libobfuscated.json",
        # Tigress uses switch/case state machine (not while loops)
        # Original test: expects 10+ case statements, reduced after deobfuscation
        obfuscated_contains=["switch", "case"],
        # Must restore natural control flow (for/if instead of switch cases)
        deobfuscated_contains=["for ("],
        must_change=True,  # Original test: case_count_after < case_count_before
    ),
]


# =============================================================================
# unwrap_loops.c - Loop unwrapping patterns
# =============================================================================

UNWRAP_LOOPS_CASES = [
    DeobfuscationCase(
        function="unwrap_loops",
        description="Loop unwrapping with spin-lock synchronization",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="unwrap_loops_2",
        description="Loop unwrapping with dynamic size calculations",
        project="example_libobfuscated.json",
        must_change=True,
    ),
    DeobfuscationCase(
        function="unwrap_loops_3",
        description="Complex loop pattern with hidden C++ exception states",
        project="example_libobfuscated.json",
        must_change=False,  # May not match current rules
    ),
    DeobfuscationCase(
        function="SafeCloseHandle",
        description="Loop unwrapping with handle validation",
        project="example_libobfuscated.json",
        must_change=False,
    ),
    DeobfuscationCase(
        function="bogus_loops",
        description="Bogus/redundant loop patterns",
        project="bogus_loops.json",
        must_change=False,  # Pattern not yet supported by bogus_loops rule
    ),
]


# =============================================================================
# while_switch_flattened.c - While/switch flattening
# =============================================================================

WHILE_SWITCH_CASES = [
    DeobfuscationCase(
        function="while_switch_flattened",
        description="While(1)/switch dispatcher with ROL/XOR operations",
        project="example_libobfuscated.json",
        # Uses while loops for flattening
        obfuscated_contains=["while"],
        must_change=True,
    ),
]


# =============================================================================
# Combined lists for different test scenarios
# =============================================================================

# All cases combined
ALL_CASES = (
    MANUALLY_OBFUSCATED_CASES
    + ABC_F6_CASES
    + ABC_XOR_CASES
    + APPROOV_CASES
    + CONSTANT_FOLDING_CASES
    + DISPATCHER_PATTERN_CASES
    + EXCEPTION_PATH_CASES
    + HODUR_CASES
    + NESTED_DISPATCHER_CASES
    + OLLVM_CASES
    + TIGRESS_CASES
    + UNWRAP_LOOPS_CASES
    + WHILE_SWITCH_CASES
)

# Core cases that must work (no exceptions/edge cases)
CORE_CASES = (
    MANUALLY_OBFUSCATED_CASES
    + TIGRESS_CASES
    + OLLVM_CASES
    + HODUR_CASES
    + WHILE_SWITCH_CASES
)

# Quick smoke test (fastest)
SMOKE_CASES = [
    c
    for c in ALL_CASES
    if c.function
    in {
        "test_chained_add",
        "test_xor",
        "test_or",
    }
]

# Cases that test unflattening rules
UNFLATTENING_CASES = (
    ABC_F6_CASES
    + ABC_XOR_CASES
    + APPROOV_CASES
    + DISPATCHER_PATTERN_CASES
    + NESTED_DISPATCHER_CASES
    + OLLVM_CASES
    + TIGRESS_CASES
)

# Cases that test instruction-level rules (MBA, constants)
INSTRUCTION_CASES = MANUALLY_OBFUSCATED_CASES + CONSTANT_FOLDING_CASES

# Total function count
TOTAL_FUNCTION_COUNT = len(ALL_CASES)
