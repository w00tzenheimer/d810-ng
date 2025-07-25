import ctypes
import sys

from d810.hexrays.hexrays_helpers import MSB_TABLE, CacheImpl

CTYPE_SIGNED_TABLE = {
    1: ctypes.c_int8,
    2: ctypes.c_int16,
    4: ctypes.c_int32,
    8: ctypes.c_int64,
}
CTYPE_UNSIGNED_TABLE = {
    1: ctypes.c_uint8,
    2: ctypes.c_uint16,
    4: ctypes.c_uint32,
    8: ctypes.c_uint64,
}


def get_all_subclasses(python_class):
    python_class.__subclasses__()

    subclasses = set()
    check_these = [python_class]

    while check_these:
        parent = check_these.pop()
        for child in parent.__subclasses__():
            if child not in subclasses:
                subclasses.add(child)
                check_these.append(child)

    return sorted(subclasses, key=lambda x: x.__name__)


def unsigned_to_signed(unsigned_value, nb_bytes):
    return CTYPE_SIGNED_TABLE[nb_bytes](unsigned_value).value


def signed_to_unsigned(signed_value, nb_bytes):
    return CTYPE_UNSIGNED_TABLE[nb_bytes](signed_value).value


def get_msb(value, nb_bytes):
    return (value & MSB_TABLE[nb_bytes]) >> (nb_bytes * 8 - 1)


def get_add_cf(op1, op2, nb_bytes):
    res = op1 + op2
    return get_msb((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (~(op1 ^ op2)))), nb_bytes)


def get_add_of(op1, op2, nb_bytes):
    res = op1 + op2
    return get_msb(((op1 ^ res) & (~(op1 ^ op2))), nb_bytes)


def get_sub_cf(op1, op2, nb_bytes):
    res = op1 - op2
    return get_msb((((op1 ^ op2) ^ res) ^ ((op1 ^ res) & (op1 ^ op2))), nb_bytes)


def get_sub_of(op1, op2, nb_bytes):
    res = op1 - op2
    return get_msb(((op1 ^ res) & (op1 ^ op2)), nb_bytes)


def get_parity_flag(op1, op2, nb_bytes):
    tmp = CTYPE_UNSIGNED_TABLE[nb_bytes](op1 - op2).value
    return (bin(tmp).count("1") + 1) % 2


def ror(x, n, nb_bits=32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (nb_bits - n))


def rol(x, n, nb_bits=32):
    return ror(x, nb_bits - n, nb_bits)


def __rol__(value: int, count: int, bits: int) -> int:
    """
    Rotate left on an unsigned integer of given bit width.
    """
    mask = (1 << bits) - 1
    count %= bits
    value &= mask
    return ((value << count) & mask) | (value >> (bits - count))


def __ror__(value: int, count: int, bits: int) -> int:
    """
    Rotate right on an unsigned integer of given bit width.
    """
    return __rol__(value, -count, bits)


def rol1(value: int, count: int) -> int:
    return __rol__(value, count, 8)


def rol2(value: int, count: int) -> int:
    return __rol__(value, count, 16)


def rol4(value: int, count: int) -> int:
    return __rol__(value, count, 32)


def rol8(value: int, count: int) -> int:
    return __rol__(value, count, 64)


def ror1(value: int, count: int) -> int:
    return __ror__(value, count, 8)


def ror2(value: int, count: int) -> int:
    return __ror__(value, count, 16)


def ror4(value: int, count: int) -> int:
    return __ror__(value, count, 32)


def ror8(value: int, count: int) -> int:
    return __ror__(value, count, 64)


# ------------------------------------------------------------------
# Singleton caches that survive importlib.reload()
# ------------------------------------------------------------------
_module = sys.modules[__name__]

if not hasattr(_module, "_SHARED_MOP_CONSTANT_CACHE"):
    setattr(_module, "_SHARED_MOP_CONSTANT_CACHE", CacheImpl(max_size=20480))
if not hasattr(_module, "_SHARED_MOP_TO_AST_CACHE"):
    setattr(_module, "_SHARED_MOP_TO_AST_CACHE", CacheImpl(max_size=20480))

# A global cache for constant mop_t objects
MOP_CONSTANT_CACHE: CacheImpl = _module._SHARED_MOP_CONSTANT_CACHE

# The cache should be managed in a scope that persists across calls.
# A global variable is a common way to do this in IDA scripts.
MOP_TO_AST_CACHE: CacheImpl = _module._SHARED_MOP_TO_AST_CACHE
