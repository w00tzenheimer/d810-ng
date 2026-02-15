"""Unit tests for EA validation helpers without IDA."""
from d810.hexrays.table_utils import (
    BADADDR, is_valid_database_ea, is_code_ea, get_func_safe, get_flags_safe,
    validate_code_target,
)


def test_is_valid_database_ea_without_ida():
    assert is_valid_database_ea(0x401000) is False


def test_is_code_ea_without_ida():
    assert is_code_ea(0x401000) is False


def test_get_func_safe_without_ida():
    assert get_func_safe(0x401000) is None


def test_get_flags_safe_without_ida():
    assert get_flags_safe(0x401000) == 0


def test_validate_code_target_without_ida():
    assert validate_code_target(0x401000) is False


def test_badaddr_constant():
    assert BADADDR == 0xFFFFFFFFFFFFFFFF
