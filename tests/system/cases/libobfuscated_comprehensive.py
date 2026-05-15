"""Comprehensive test cases for libobfuscated binary.

This module defines ALL deobfuscation test cases from samples/src/c/ as data
using the DeobfuscationCase DSL. Organized by source file for easy reference.

To run: pytest tests/system/e2e/test_libdeobfuscated_dsl.py -v
"""

import base64
import gzip
import textwrap

from d810.testing import DeobfuscationCase


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

# hodur_func (example_libobfuscated.json): 4876 chars -> 1508 chars encoded
_HODUR_FUNC_EXPECTED = (
    "H4sIADl+1GkC/81XW2+jRhh996+YWmoEjpPMYG7eNFJ9S/tgabXbh6pKvdTB2MHGYAFmnUbpb99vADPD"
    "xSR219KiKOZyON/lnBlmDMN2Q1VGT95s6xvzrWsKYuOlgeAw0kcRuUU3N+jBDzaXEn6awNnj5op09adJ"
    "HidxOJ3hcIoDFLJthpHlDKPJHCaSGUZhGJXHuByEhVL5UGsGUVnWis5BVhyEBVL4QEsOwgIpuZo4yCCD"
    "yIMUEnn2DAmGMZ8GoTl1HNSKCBaFtGttZHz68+PnochINJatXOxxgYeUeNiv6blBiMynqY9abcRg2cmw"
    "GJfVJ+P6uBIXNx+nELWQ0/4XXuUC66zgjl7TtQ5E3RPto8c4Vh/Pysrp4BpW+Sysyv9mZcNPZcAua5VU"
    "Gn9E44CMUSoz6gzYY4ykPKIxAxLmS2pL1P/r8+g+hsdqRxJ5UNQJj89SoHZK8UnDiIruEL5NL3S4CLaP"
    "BtExxv2eigVh6wb2wrVmsVPGzd/p7HRDrnGzjXD2JyYE9hwJMYsYXyaTV8Ks5Zm7WABcG42b1m663jjW"
    "temtKeWO9PuMkCPVUtI8MT02PqQ2F5oPrQn6I5z6oe0u0NyZhqFF87Z2lrkNbc+Fe97X6+vrv90mRx+n"
    "J2HahZ3S03ravYbloaqrI0Ubj/O4Vuok1BKhyfErAB/CS7o2lInWV4fFV6gY+oT1eH/MPR/KsuMH8PML"
    "rRzOLi9trk6exEZXCIi+3CGBngJ8KKILpKAvSICLAdyz6Q28u+/BPbjVvW1U9+lygoaW6T9vQmiP0HMW"
    "HiLiB/RzAJ1pI4GfOMQL6E2xW6QDaQvlsfaOgSb6VuA5kWVMN7ZQwZ2K3alqAukI4LVOG11s3VVsJDLA"
    "93ALxm/jx9Bzmei55PRcHtBzyfTMhljcJV0UlpnAVMhR5wghpaOElM8tpFwppEyFVH9kIVeJkCtOyNUB"
    "IVc1Qq5OF7JzlJDKuYVUKoVUqJDKEULKar2QQeibm2cB+tpGzd3yH8N+XISmWZywE5HWiUjrRCSJirQ+"
    "INK6RqT1CSIdo41Etalcvn2Htds75ZMq5aPffngGn2IN2v0blNO8yX3Xd/RrjXFRzZj0J/p+mXXhhR4a"
    "9/qjsbHrd7uDE0d0zgjr6bLWCG5iBJczgnvACG6NEdwzG4G8xwgnbh7e8kEkl6e61Buk0KqXUuPGH+Mg"
    "4BMRWOTbwwDpACAOD6GAQt27qzmbhlPoXAQSR1J+0UeP1wrTRfKbyWYO69c7rOwyZzX7N/o1NBfPL4v/"
    "ik7jFm37VVu6bFPjZVvVui1bu9k1rrPtett9B+sl9sMHvxGFDfBbXuK8gw9VTXAqtfhGOaNseQ47ANgI"
    "0C9gsDVNKwjmW8d5rliux8qxvUQ/DlUyD39lOYFVsA03RX04nOAVJOj7ILtnmlvfj7dB3N4i3lGUEyw4"
    "t5irVoAXn+uF574Vbn2XH72sulxlL6fQkiJt8j8jZqT5F14br427Mx3fAHq1Cv8MEwAA"
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
        operator_complexity_mode="non_increase",
        operator_complexity_ops=["+", "-", "*", "^", "&", "|"],
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
            __int64 __fastcall test_xor(__int64 a1, __int64 a2, __int64 a3, __int64 *a4)
            {
                *a4 = a2 ^ a1;
                a4[1] = (a2 - 3) ^ (a3 * a1);
                return a4[1] + *a4;
            }
        """,
        acceptable_patterns=[],
        deobfuscated_contains=["^"],  # Should simplify to XOR
        must_change=True,
        operator_complexity_mode="decrease",
        operator_complexity_ops=["+", "-", "*", "&", "|", "^"],
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
        acceptable_patterns=[],
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
        acceptable_patterns=[],
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
        # Run with FixPredecessor + generic/switch-case unflatteners (no Hodur)
        project="example_libobfuscated.json",
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
        deobfuscated_contains=[
            "return (unsigned int)(2 * (a1 + 0x2A));",
            "return 0xFFFFFFFE * (a1 + 0x2A);",
        ],
        deobfuscated_not_contains=[
            "while ( 1 )",
            "return result;",
            "0xFFFFFFAC",
        ],
    ),
    DeobfuscationCase(
        function="abc_or_dispatch",
        description="OR-based state manipulation with mask operations",
        project="example_libobfuscated_abc.json",
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
        # Until dynamic-index folding is implemented, this case is a stability
        # check rather than a "must simplify" assertion.
        must_change=False,
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
        description="Mixed CFF pattern: while(1) dispatcher with large state constants, "
                    "conditional branch, and loop-back. Deobfuscates to do-while loop "
                    "with if/else and arithmetic chain.",
        # Use flatfold profile so Unflattener is not constrained by the
        # example profile's narrow whitelist.
        project="flatfold.json",
        obfuscated_contains=["0xABCD1234", "while"],
        deobfuscated_not_contains=["0xABCD1234", "0x12345678", "0x9ABCDEF0"],
        deobfuscated_contains=["0xDEAD"],
        must_change=True,
    ),
    DeobfuscationCase(
        function="predecessor_uniformity_pattern",
        description="PREDECESSOR_UNIFORM detection pattern",
        project="default_instruction_only.json",
        # This pattern intentionally compiles to a structured switch/while form;
        # deobfuscation should stay safe and not force a rewrite.
        must_change=False,
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
        project="example_libobfuscated.json",
        # Hodur uses while loops for flattening
        obfuscated_contains=["while"],
        expected_code=_decode_expected(_HODUR_FUNC_EXPECTED),
        expected_ast_stats={"statements": 38, "returns": 3, "whiles": 0, "gotos": 1, "ifs": 7},
        # The deobfuscated code should be linear (no nested while loops)
        # Note: Import names may show as sub_* if IDA doesn't resolve them
        # (resolve_api checked via acceptable_patterns instead)
        deobfuscated_not_contains=["while ( 1 )"],
        # Must preserve API calls - accept either resolved names or sub_* patterns
        # IDA may not resolve Windows imports depending on platform/version
        acceptable_patterns=[
            "printf", "resolve_api", "WinHttp",  # Resolved names
            "sub_180008C",  # Unresolved addresses (common prefix)
            "Hodur/1.0",  # String literal that should be preserved
        ],
        must_change=True,
        required_rules=["UnflattenerFakeJump"],
        expected_rules=["CstSimplificationRule16"],
    ),
    DeobfuscationCase(
        function="resolve_api",
        description="Dynamic API resolution helper",
        project="example_libobfuscated.json",
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
# hardened_ollvm_cond_chain.c - Hardened OLLVM conditional chain patterns
# =============================================================================

HARDENED_OLLVM_COND_CHAIN_CASES = [
    DeobfuscationCase(
        function="hardened_cond_chain_simple",
        description="Hardened OLLVM conditional chain (6 states, binary search dispatch)",
        project="example_libobfuscated.json",
        # Use state-machine constants instead of symbol names to remain backend-stable
        # across PE/Mach-O naming differences.
        obfuscated_contains=["0x1000", "0x6000"],
        # After deobfuscation, table references should be resolved away and the
        # output should match IDA's collapsed equivalent of the manual
        # unflattening.  Depending on the decompile path, IDA may print the
        # return with or without an explicit unsigned cast; both forms are
        # equivalent for the recovered unsigned-int expression.
        deobfuscated_contains=[
            "dword_18001D440 = 3 * a1 + 7;",
        ],
        deobfuscated_not_contains=["g_opaque_table"],
        acceptable_patterns=[
            "return 3 * a1 + 7;",
            "return (unsigned int)(3 * a1 + 7);",
        ],
        must_change=True,
        # FixPredecessor intentionally stays disabled for this terminal
        # conditional-chain shape: predecessor-local rewrites can erase the
        # final return.  The active owner is the whole-chain emulated
        # dispatcher lowerer, which folds the table-driven state constants and
        # materializes the payload corridor as one unit.  Keep this outcome
        # based because current block-rule stats do not reliably report the
        # emulated-dispatcher owner even when the lowerer applies.
        required_rules=[],
        expected_rules=[],
    ),
    DeobfuscationCase(
        function="sub_7FFC1EB47830",
        description="Real hardened OLLVM conditional chain from malware sample (14 states, nested dispatch, opaque table)",
        project="example_libobfuscated.json",
        # Avoid address-dependent symbol assertions (varies by backend/build base).
        obfuscated_contains=["0x623FEB6A"],
        must_change=True,
        # Keep this outcome-focused: rule composition may vary (FixPred vs Unflattener).
        required_rules=[],
    ),
]


# =============================================================================
# sub_7FFC1E9D3BB0.c - Buffer resize with OLLVM CFF and opaque constants
# =============================================================================

RESIZE_BUFFER_CFF_CASES = [
    DeobfuscationCase(
        function="sub_7FFC1E9D3BB0_resize",
        description=(
            "Buffer resize function with OLLVM CFF. Uses opaque constant table "
            "with complex MBA expressions for state transitions. Tests "
            "FoldReadonlyDataRule with fold_writable_constants, "
            "FixPredecessorOfConditionalJumpBlock, and Unflattener."
        ),
        project="flatfold.json",
        # PE/Mach-O symbol recovery can name the opaque table differently.
        # Assert stable state constants instead of the source symbol spelling.
        obfuscated_contains=["0x41698846", "0x7BE4032F"],
        deobfuscated_not_contains=[
            "g_resize_opaque_table",
            "n0x3C837EFA",
            "n0x7BE4032F",
            "0x41698846",
            "0x3E118C46",
        ],
        acceptable_patterns=[
            "a2 + 16",
            "a2 + 0x10",
            "a2 + 8",
            "= 0",
        ],
        must_change=True,
        check_stats=True,
        required_rules=["FixPredecessorOfConditionalJumpBlock"],
        expected_rules=["FixPredecessorOfConditionalJumpBlock", "FoldReadonlyDataRule"],
        skip="Semantically wrong: incomplete handler resolution (0 transitions) causes variable loss via IDA DCE",
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
    + HARDENED_OLLVM_COND_CHAIN_CASES
    + RESIZE_BUFFER_CFF_CASES
)

# Core cases that must work (no exceptions/edge cases)
CORE_CASES = (
    MANUALLY_OBFUSCATED_CASES
    + TIGRESS_CASES
    + OLLVM_CASES
    + HODUR_CASES
    + WHILE_SWITCH_CASES
    + HARDENED_OLLVM_COND_CHAIN_CASES
    + RESIZE_BUFFER_CFF_CASES
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
    + HARDENED_OLLVM_COND_CHAIN_CASES
)

# Cases that test instruction-level rules (MBA, constants)
INSTRUCTION_CASES = MANUALLY_OBFUSCATED_CASES + CONSTANT_FOLDING_CASES

# Total function count
TOTAL_FUNCTION_COUNT = len(ALL_CASES)
