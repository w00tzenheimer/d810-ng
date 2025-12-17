import pytest

# Import from d810.core.bits (IDA-independent bitwise utilities)
from d810.core.bits import signed_to_unsigned, unsigned_to_signed, get_parity_flag

def test_signed_to_unsigned_small_sizes():
    # Test positive values
    assert signed_to_unsigned(42, 1) == 42
    assert signed_to_unsigned(1000, 2) == 1000
    assert signed_to_unsigned(123456, 4) == 123456
    assert signed_to_unsigned(9876543210, 8) == 9876543210

    # Test negative values (should wrap around)
    assert signed_to_unsigned(-1, 1) == 255
    assert signed_to_unsigned(-1, 2) == 65535
    assert signed_to_unsigned(-1, 4) == 4294967295
    assert signed_to_unsigned(-1, 8) == 18446744073709551615

    # Test edge cases
    assert signed_to_unsigned(0, 1) == 0
    assert signed_to_unsigned(127, 1) == 127
    assert signed_to_unsigned(-128, 1) == 128

def test_unsigned_to_signed_small_sizes():
    # Test positive values
    assert unsigned_to_signed(42, 1) == 42
    assert unsigned_to_signed(1000, 2) == 1000
    assert unsigned_to_signed(123456, 4) == 123456
    assert unsigned_to_signed(9876543210, 8) == 9876543210

    # Test values that should be interpreted as negative
    assert unsigned_to_signed(255, 1) == -1
    assert unsigned_to_signed(65535, 2) == -1
    assert unsigned_to_signed(4294967295, 4) == -1
    assert unsigned_to_signed(18446744073709551615, 8) == -1

    # Test edge cases
    assert unsigned_to_signed(0, 1) == 0
    assert unsigned_to_signed(127, 1) == 127
    assert unsigned_to_signed(128, 1) == -128

def test_signed_to_unsigned_16_bytes():
    # Test positive values
    test_val = 123456789012345678901234567890123456789
    assert signed_to_unsigned(test_val, 16) == test_val

    # Test negative values (should be treated as unsigned 128-bit)
    negative_val = -1
    expected = (1 << 128) - 1
    assert signed_to_unsigned(negative_val, 16) == expected

    # Test zero
    assert signed_to_unsigned(0, 16) == 0

    # Test large positive value
    large_val = (1 << 127) - 1
    assert signed_to_unsigned(large_val, 16) == large_val

def test_unsigned_to_signed_16_bytes():
    # Test positive values
    test_val = 123456789012345678901234567890123456789
    assert unsigned_to_signed(test_val, 16) == test_val

    # Test values that should be interpreted as negative (MSB set)
    msb_set = 1 << 127
    expected = msb_set - (1 << 128)
    assert unsigned_to_signed(msb_set, 16) == expected

    # Test all bits set (should be -1)
    all_bits_set = (1 << 128) - 1
    assert unsigned_to_signed(all_bits_set, 16) == -1

    # Test zero
    assert unsigned_to_signed(0, 16) == 0

def test_roundtrip_conversion():
    # Signed -> unsigned -> signed
    signed_test_values = [0, 1, -1, 42, -42, 127, -128, -1, 42, -100]
    for val in signed_test_values:
        for size in [1, 2, 4, 8]:
            unsigned = signed_to_unsigned(val, size)
            back_to_signed = unsigned_to_signed(unsigned, size)
            assert back_to_signed == val, f"Signed roundtrip failed for {val} at size {size}: {val} -> {unsigned} -> {back_to_signed}"

    # Unsigned -> signed -> unsigned
    unsigned_test_cases = [
        (0, [1, 2, 4, 8]),
        (1, [1, 2, 4, 8]),
        (42, [1, 2, 4, 8]),
        (127, [1, 2, 4, 8]),
        (255, [1, 2, 4, 8]),
        (65535, [2, 4, 8]),
        (4294967295, [4, 8]),
    ]
    for val, sizes in unsigned_test_cases:
        for size in sizes:
            signed = unsigned_to_signed(val, size)
            back_to_unsigned = signed_to_unsigned(signed, size)
            assert back_to_unsigned == val, f"Unsigned roundtrip failed for {val} at size {size}: {val} -> {signed} -> {back_to_unsigned}"

def test_get_parity_flag():
    # Even number of 1s (should return 1)
    assert get_parity_flag(1, 2, 4) == 1
    assert get_parity_flag(4, 4, 4) == 1
    assert get_parity_flag(3, 0, 1) == 1

    # Odd number of 1s (should return 0)
    assert get_parity_flag(1, 0, 4) == 0
    assert get_parity_flag(7, 2, 4) == 1
    assert get_parity_flag(1, 0, 1) == 0

    # 16-byte cases
    assert get_parity_flag(1, 0, 16) == 0
    assert get_parity_flag(3, 0, 16) == 1

def test_large_values_16_bytes():
    # Test maximum 128-bit unsigned value
    max_u128 = (1 << 128) - 1
    assert signed_to_unsigned(max_u128, 16) == max_u128
    assert unsigned_to_signed(max_u128, 16) == -1

    # Test maximum 128-bit signed value
    max_s128 = (1 << 127) - 1
    assert unsigned_to_signed(max_s128, 16) == max_s128

    # Test minimum 128-bit signed value
    min_s128 = -(1 << 127)
    assert signed_to_unsigned(min_s128, 16) == 1 << 127

def test_invalid_sizes():
    with pytest.raises(KeyError):
        signed_to_unsigned(42, 3)
    with pytest.raises(KeyError):
        unsigned_to_signed(42, 32)
    with pytest.raises(KeyError):
        get_parity_flag(1, 2, 64)

