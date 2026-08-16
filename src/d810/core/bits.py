"""Bitwise operation constants and utilities.

This module contains pure Python constants and utility functions for
bitwise operations, MBA (Mixed Boolean-Arithmetic) simplification,
and pattern matching. No IDA dependencies.
"""

import ctypes

# =============================================================================
# Bitwise Operation Constants
# =============================================================================

# Subtraction modulo lookup table for different bit widths
# Used in rules that need to know the modulus for a given bit width
# Example: For 8-bit (1 byte), modulus is 0x100 (256)
SUB_TABLE: dict[int, int] = {
    1: 0x100,  # 8-bit:  2^8  = 256
    2: 0x10000,  # 16-bit: 2^16 = 65536
    4: 0x100000000,  # 32-bit: 2^32
    8: 0x10000000000000000,  # 64-bit: 2^64
    16: 0x100000000000000000000000000000000,  # 128-bit: 2^128
}

# All-ones mask (bitwise NOT mask) for different bit widths
# XORing with an all-ones mask is equivalent to bitwise NOT (~)
# Example: For 8-bit, mask is 0xFF (all bits set)
AND_TABLE: dict[int, int] = {
    1: 0xFF,  # 8-bit:  all ones
    2: 0xFFFF,  # 16-bit: all ones
    4: 0xFFFFFFFF,  # 32-bit: all ones
    8: 0xFFFFFFFFFFFFFFFF,  # 64-bit: all ones
    16: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,  # 128-bit: all ones
}

# Most Significant Bit mask for different bit widths
# Used to check/extract the sign bit
# Example: For 8-bit, MSB mask is 0x80 (bit 7)
MSB_TABLE: dict[int, int] = {
    1: 0x80,  # 8-bit:  bit 7
    2: 0x8000,  # 16-bit: bit 15
    4: 0x80000000,  # 32-bit: bit 31
    8: 0x8000000000000000,  # 64-bit: bit 63
    16: 0x80000000000000000000000000000000,  # 128-bit: bit 127
}

# ctypes lookup tables for signed/unsigned integer conversions
# Maps byte size to the corresponding ctypes type
CTYPE_SIGNED_TABLE: dict[int, type] = {
    1: ctypes.c_int8,
    2: ctypes.c_int16,
    4: ctypes.c_int32,
    8: ctypes.c_int64,
    16: ctypes.c_ubyte * 16,  # 128-bit: array of bytes
}

CTYPE_UNSIGNED_TABLE: dict[int, type] = {
    1: ctypes.c_uint8,
    2: ctypes.c_uint16,
    4: ctypes.c_uint32,
    8: ctypes.c_uint64,
    16: ctypes.c_ubyte * 16,  # 128-bit: array of bytes
}


# Canonical names of binary mcode operations whose concrete result is pure and
# therefore safe to calculate without an IDA runtime.  Callers map their
# vendor opcode representation to these names at the boundary.
BINARY_FOLD_OPCODES: frozenset[str] = frozenset(
    {
        "add",
        "sub",
        "mul",
        "udiv",
        "sdiv",
        "umod",
        "smod",
        "and",
        "or",
        "xor",
        "shl",
        "shr",
        "sar",
        "cfadd",
        "ofadd",
        "seto",
        "setp",
        "setz",
        "setnz",
        "setae",
        "setb",
        "seta",
        "setbe",
        "setg",
        "setge",
        "setl",
        "setle",
    }
)

UNARY_FOLD_OPCODES: frozenset[str] = frozenset(
    {"mov", "neg", "lnot", "bnot", "xds", "xdu", "low", "high", "sets"}
)


# =============================================================================
# Conversion Functions
# =============================================================================


def unsigned_to_signed(unsigned_value: int, nb_bytes: int) -> int:
    """Convert an unsigned integer to its signed representation.

    Args:
        unsigned_value: The unsigned integer value
        nb_bytes: The number of bytes (1, 2, 4, 8, or 16)

    Returns:
        The signed integer representation
    """
    ctype_class = CTYPE_SIGNED_TABLE[nb_bytes]
    if nb_bytes == 16:
        # For 128-bit values, convert to bytes and back as signed
        byte_array = ctype_class()
        for i in range(16):
            byte_array[i] = (unsigned_value >> (i * 8)) & 0xFF
        # Convert back to int, treating as signed
        result = 0
        for i in range(16):
            result |= byte_array[i] << (i * 8)
        # Apply sign extension if MSB is set
        if result & (1 << 127):
            result |= ~((1 << 128) - 1)
        return result
    else:
        return ctype_class(unsigned_value).value


def signed_to_unsigned(signed_value: int, nb_bytes: int) -> int:
    """Convert a signed integer to its unsigned representation.

    Args:
        signed_value: The signed integer value
        nb_bytes: The number of bytes (1, 2, 4, 8, or 16)

    Returns:
        The unsigned integer representation
    """
    ctype_class = CTYPE_UNSIGNED_TABLE[nb_bytes]
    if nb_bytes == 16:
        # For 128-bit values, convert to bytes and back as unsigned
        byte_array = ctype_class()
        for i in range(16):
            byte_array[i] = (signed_value >> (i * 8)) & 0xFF
        # Convert back to int as unsigned
        result = 0
        for i in range(16):
            result |= byte_array[i] << (i * 8)
        return result & ((1 << 128) - 1)
    else:
        return ctype_class(signed_value).value


# =============================================================================
# Bit Manipulation Functions
# =============================================================================


def get_msb(value: int, nb_bytes: int) -> int:
    """Get the most significant bit of a value.

    Args:
        value: The integer value
        nb_bytes: The number of bytes (determines bit width)

    Returns:
        0 or 1 depending on the MSB
    """
    return (value & MSB_TABLE[nb_bytes]) >> (nb_bytes * 8 - 1)


def get_add_cf(op1: int, op2: int, nb_bytes: int) -> int:
    """Calculate the carry flag for addition."""
    res = op1 + op2
    return get_msb((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))), nb_bytes)


def get_add_of(op1: int, op2: int, nb_bytes: int) -> int:
    """Calculate the overflow flag for addition."""
    res = op1 + op2
    return get_msb(((op1 ^ res) & (~(op1 ^ op2))), nb_bytes)


def get_sub_cf(op1: int, op2: int, nb_bytes: int) -> int:
    """Calculate the carry flag for subtraction."""
    res = op1 - op2
    return get_msb((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))), nb_bytes)


def get_sub_of(op1: int, op2: int, nb_bytes: int) -> int:
    """Calculate the overflow flag for subtraction."""
    res = op1 - op2
    return get_msb(((op1 ^ res) & (op1 ^ op2)), nb_bytes)


def get_parity_flag(op1: int, op2: int, nb_bytes: int) -> int:
    """Calculate the parity flag for a subtraction result.

    Returns 1 if the number of set bits is even, 0 if odd.
    """
    if nb_bytes == 16:
        tmp = signed_to_unsigned(op1 - op2, nb_bytes)
    else:
        tmp = CTYPE_UNSIGNED_TABLE[nb_bytes](op1 - op2).value
    return (bin(tmp).count("1") + 1) % 2


def fold_binary_opcode(
    opcode: str,
    left: int,
    right: int,
    *,
    left_bytes: int,
    right_bytes: int,
    result_bytes: int,
) -> int | None:
    """Evaluate a pure binary microcode operation with explicit widths.

    ``opcode`` is the canonical Hex-Rays opcode name without its ``m_``
    prefix (for example ``"setb"`` or ``"ofadd"``).  The explicit source and
    result widths are essential for flag operations: their result is a byte,
    while their arithmetic and comparison semantics are defined at the source
    operand width.

    Return ``None`` when the operation is unsupported, structurally invalid,
    or cannot be evaluated safely (such as division by zero).
    """

    if (
        left_bytes not in AND_TABLE
        or right_bytes not in AND_TABLE
        or result_bytes not in AND_TABLE
    ):
        return None

    # Hex-Rays' binary arithmetic, flag, and comparison opcodes require
    # identically sized value operands.  Shifts are the exception: their
    # count may be a narrower byte operand.
    if opcode not in {"shl", "shr", "sar"} and left_bytes != right_bytes:
        return None

    left &= AND_TABLE[left_bytes]
    right &= AND_TABLE[right_bytes]
    result_mask = AND_TABLE[result_bytes]

    if opcode == "add":
        return (left + right) & result_mask
    if opcode == "sub":
        return (left - right) & result_mask
    if opcode == "mul":
        return (left * right) & result_mask
    if opcode == "udiv":
        return None if right == 0 else (left // right) & result_mask
    if opcode == "sdiv":
        signed_left = unsigned_to_signed(left, left_bytes)
        signed_right = unsigned_to_signed(right, right_bytes)
        if signed_right == 0:
            return None
        quotient = (abs(signed_left) // abs(signed_right)) * (
            -1 if (signed_left < 0) ^ (signed_right < 0) else 1
        )
        return signed_to_unsigned(quotient, result_bytes) & result_mask
    if opcode == "umod":
        return None if right == 0 else (left % right) & result_mask
    if opcode == "smod":
        signed_left = unsigned_to_signed(left, left_bytes)
        signed_right = unsigned_to_signed(right, right_bytes)
        if signed_right == 0:
            return None
        quotient = (abs(signed_left) // abs(signed_right)) * (
            -1 if (signed_left < 0) ^ (signed_right < 0) else 1
        )
        remainder = signed_left - (quotient * signed_right)
        return signed_to_unsigned(remainder, result_bytes) & result_mask
    if opcode == "and":
        return (left & right) & result_mask
    if opcode == "or":
        return (left | right) & result_mask
    if opcode == "xor":
        return (left ^ right) & result_mask
    if opcode == "shl":
        return (left << right) & result_mask
    if opcode == "shr":
        return (left >> right) & result_mask
    if opcode == "sar":
        return (unsigned_to_signed(left, left_bytes) >> right) & result_mask
    if opcode == "cfadd":
        return get_add_cf(left, right, left_bytes)
    if opcode == "ofadd":
        return get_add_of(left, right, left_bytes)
    if opcode == "seto":
        return get_sub_of(left, right, left_bytes)
    if opcode == "setp":
        return get_parity_flag(left, right, left_bytes)
    if opcode == "setz":
        return int(left == right)
    if opcode == "setnz":
        return int(left != right)
    if opcode == "setae":
        return int(left >= right)
    if opcode == "setb":
        return int(left < right)
    if opcode == "seta":
        return int(left > right)
    if opcode == "setbe":
        return int(left <= right)

    signed_left = unsigned_to_signed(left, left_bytes)
    signed_right = unsigned_to_signed(right, right_bytes)
    if opcode == "setg":
        return int(signed_left > signed_right)
    if opcode == "setge":
        return int(signed_left >= signed_right)
    if opcode == "setl":
        return int(signed_left < signed_right)
    if opcode == "setle":
        return int(signed_left <= signed_right)
    return None


def fold_unary_opcode(
    opcode: str,
    value: int,
    *,
    input_bytes: int,
    result_bytes: int,
) -> int | None:
    """Evaluate a pure unary microcode operation with explicit widths."""

    if input_bytes not in AND_TABLE or result_bytes not in AND_TABLE:
        return None

    value &= AND_TABLE[input_bytes]
    result_mask = AND_TABLE[result_bytes]
    if opcode in {"mov", "xdu", "low"}:
        return value & result_mask
    if opcode == "neg":
        return (-value) & result_mask
    if opcode == "lnot":
        return int(value == 0) & result_mask
    if opcode == "bnot":
        return (~value) & result_mask
    if opcode == "xds":
        return signed_to_unsigned(unsigned_to_signed(value, input_bytes), result_bytes)
    if opcode == "high":
        return (value >> (result_bytes * 8)) & result_mask
    if opcode == "sets":
        return int(unsigned_to_signed(value, input_bytes) < 0)
    return None


# =============================================================================
# Rotation Functions
# =============================================================================


def ror(x: int, n: int, nb_bits: int = 32) -> int:
    """Rotate right.

    Masks the input to *nb_bits* before rotating and masks the result,
    so callers need not pre-sanitize the value.
    """
    full_mask = (1 << nb_bits) - 1
    x &= full_mask
    n %= nb_bits
    return ((x >> n) | (x << (nb_bits - n))) & full_mask


def rol(x: int, n: int, nb_bits: int = 32) -> int:
    """Rotate left.

    Masks the input to *nb_bits* before rotating and masks the result,
    so callers need not pre-sanitize the value.
    """
    return ror(x, nb_bits - n, nb_bits)


def __rol__(value: int, count: int, bits: int) -> int:
    """Rotate left on an unsigned integer of given bit width."""
    mask = (1 << bits) - 1
    count %= bits
    value &= mask
    return ((value << count) & mask) | (value >> (bits - count))


def __ror__(value: int, count: int, bits: int) -> int:
    """Rotate right on an unsigned integer of given bit width."""
    return __rol__(value, -count, bits)


def __ROL1__(value: int, count: int) -> int:
    """Rotate left 8-bit."""
    return __rol__(value, count, 8)


def __ROL2__(value: int, count: int) -> int:
    """Rotate left 16-bit."""
    return __rol__(value, count, 16)


def __ROL4__(value: int, count: int) -> int:
    """Rotate left 32-bit."""
    return __rol__(value, count, 32)


def __ROL8__(value: int, count: int) -> int:
    """Rotate left 64-bit."""
    return __rol__(value, count, 64)


def __ROR1__(value: int, count: int) -> int:
    """Rotate right 8-bit."""
    return __ror__(value, count, 8)


def __ROR2__(value: int, count: int) -> int:
    """Rotate right 16-bit."""
    return __ror__(value, count, 16)


def __ROR4__(value: int, count: int) -> int:
    """Rotate right 32-bit."""
    return __ror__(value, count, 32)


def __ROR8__(value: int, count: int) -> int:
    """Rotate right 64-bit."""
    return __ror__(value, count, 64)


def popcount(value: int, width: int = 32) -> int:
    """Count the number of set bits (population count).

    Args:
        value: The integer value.
        width: Bit width to mask to (default 32).

    Returns:
        Number of 1-bits in the value.
    """
    mask = (1 << width) - 1
    return bin(value & mask).count("1")


def is_state_constant(
    value: int,
    *,
    min_popcount: int = 6,
    max_popcount: int = 26,
) -> bool:
    """Check if a value looks like a control-flow flattening state constant.

    State constants used by obfuscators are typically pseudo-random 32-bit
    values with moderate bit density. This heuristic detects them via:
    1. Range check: value must be in [0x10000000, 0xFFFFFFFF]
    2. Half-entropy: both high and low 16-bit halves must be non-zero
    3. Popcount: set bits must be in [min_popcount, max_popcount]

    Args:
        value: The integer constant to check.
        min_popcount: Minimum number of set bits (default 6).
        max_popcount: Maximum number of set bits (default 26).

    Returns:
        True if the value has characteristics of a state constant.
    """
    if value < 0x10000000 or value > 0xFFFFFFFF:
        return False
    high = (value >> 16) & 0xFFFF
    low = value & 0xFFFF
    if high == 0 or low == 0:
        return False
    bit_count = bin(value & 0xFFFFFFFF).count("1")
    return min_popcount <= bit_count <= max_popcount


__all__ = [
    # Constants
    "SUB_TABLE",
    "AND_TABLE",
    "MSB_TABLE",
    "CTYPE_SIGNED_TABLE",
    "CTYPE_UNSIGNED_TABLE",
    # Conversion functions
    "unsigned_to_signed",
    "signed_to_unsigned",
    # Bit manipulation
    "get_msb",
    "get_add_cf",
    "get_add_of",
    "get_sub_cf",
    "get_sub_of",
    "get_parity_flag",
    # Rotation functions
    "ror",
    "rol",
    "__rol__",
    "__ror__",
    "__ROL1__",
    "__ROL2__",
    "__ROL4__",
    "__ROL8__",
    "__ROR1__",
    "__ROR2__",
    "__ROR4__",
    "__ROR8__",
    # State constant detection
    "popcount",
    "is_state_constant",
]
