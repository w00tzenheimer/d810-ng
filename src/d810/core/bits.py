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
    1: 0x100,                                    # 8-bit:  2^8  = 256
    2: 0x10000,                                  # 16-bit: 2^16 = 65536
    4: 0x100000000,                              # 32-bit: 2^32
    8: 0x10000000000000000,                      # 64-bit: 2^64
    16: 0x100000000000000000000000000000000,     # 128-bit: 2^128
}

# All-ones mask (bitwise NOT mask) for different bit widths
# XORing with an all-ones mask is equivalent to bitwise NOT (~)
# Example: For 8-bit, mask is 0xFF (all bits set)
AND_TABLE: dict[int, int] = {
    1: 0xFF,                                     # 8-bit:  all ones
    2: 0xFFFF,                                   # 16-bit: all ones
    4: 0xFFFFFFFF,                               # 32-bit: all ones
    8: 0xFFFFFFFFFFFFFFFF,                       # 64-bit: all ones
    16: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,      # 128-bit: all ones
}

# Most Significant Bit mask for different bit widths
# Used to check/extract the sign bit
# Example: For 8-bit, MSB mask is 0x80 (bit 7)
MSB_TABLE: dict[int, int] = {
    1: 0x80,                                     # 8-bit:  bit 7
    2: 0x8000,                                   # 16-bit: bit 15
    4: 0x80000000,                               # 32-bit: bit 31
    8: 0x8000000000000000,                       # 64-bit: bit 63
    16: 0x80000000000000000000000000000000,      # 128-bit: bit 127
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


# =============================================================================
# Rotation Functions
# =============================================================================

def ror(x: int, n: int, nb_bits: int = 32) -> int:
    """Rotate right."""
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (nb_bits - n))


def rol(x: int, n: int, nb_bits: int = 32) -> int:
    """Rotate left."""
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
]
