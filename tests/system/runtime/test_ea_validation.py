"""System tests for EA validation guards (IDA required)."""
import os

import pytest


@pytest.mark.usefixtures("ida_database")
class TestEaValidationHelpers:
    # Any real sample binary is fine for EA guard tests.
    binary_name = os.getenv("D810_TEST_BINARY", "libobfuscated.dll")

    @pytest.mark.ida_required
    def test_valid_ea_accepted(self):
        import idaapi
        from d810.hexrays.table_utils import is_valid_database_ea
        min_ea = idaapi.inf_get_min_ea()
        assert is_valid_database_ea(min_ea) is True

    @pytest.mark.ida_required
    def test_badaddr_rejected(self):
        from d810.hexrays.table_utils import is_valid_database_ea
        assert is_valid_database_ea(0xFFFFFFFFFFFFFFFF) is False

    @pytest.mark.ida_required
    def test_above_max_ea_rejected(self):
        import idaapi
        from d810.hexrays.table_utils import is_valid_database_ea
        max_ea = idaapi.inf_get_max_ea()
        assert is_valid_database_ea(max_ea + 0x100000) is False

    @pytest.mark.ida_required
    def test_is_code_ea_on_invalid_returns_false(self):
        from d810.hexrays.table_utils import is_code_ea
        assert is_code_ea(0xDEADBEEFDEADBEEF) is False

    @pytest.mark.ida_required
    def test_get_func_safe_on_invalid_returns_none(self):
        from d810.hexrays.table_utils import get_func_safe
        assert get_func_safe(0xDEADBEEFDEADBEEF) is None

    @pytest.mark.ida_required
    def test_get_flags_safe_on_invalid_returns_zero(self):
        from d810.hexrays.table_utils import get_flags_safe
        assert get_flags_safe(0xDEADBEEFDEADBEEF) == 0
