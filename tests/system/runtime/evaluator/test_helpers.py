"""Unit tests for d810.evaluator.helpers — _RotateHelper Registrant registry.

Covers the class-based registry provided by :class:`_RotateHelper` (a
:class:`~d810.core.registry.Registrant` subclass).  All 8 ROL/ROR helpers
auto-register via ``__init_subclass__`` when the module is imported.

No IDA dependencies; pure-Python only.
"""

from __future__ import annotations

import pytest

from d810.evaluator.helpers.rotate import (
    _RotateHelper,
    ROL1, ROL2, ROL4, ROL8,
    ROR1, ROR2, ROR4, ROR8,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALL_ROTATE_NAMES = (
    "__ROL1__",
    "__ROL2__",
    "__ROL4__",
    "__ROL8__",
    "__ROR1__",
    "__ROR2__",
    "__ROR4__",
    "__ROR8__",
)


# ---------------------------------------------------------------------------
# TestRotateHelperRegistry — count, names, callables, bit_widths
# ---------------------------------------------------------------------------


class TestRotateHelperRegistry:
    """Tests for _RotateHelper Registrant-based registry."""

    def test_registry_has_exactly_eight_entries(self):
        """Exactly 8 helpers are registered via __init_subclass__."""
        assert len(_RotateHelper.registry) == 8

    @pytest.mark.parametrize("name", _ALL_ROTATE_NAMES)
    def test_all_names_present(self, name: str):
        """Each of the 8 rotate names is findable via lookup."""
        fn = _RotateHelper.lookup(name)
        assert fn is not None, f"_RotateHelper registry missing {name}"

    @pytest.mark.parametrize("name", _ALL_ROTATE_NAMES)
    def test_each_lookup_is_callable(self, name: str):
        """Every registered helper returns a callable."""
        fn = _RotateHelper.lookup(name)
        assert callable(fn), f"{name} lookup result is not callable"

    @pytest.mark.parametrize("name,expected_width", [
        ("__ROL1__", 8),
        ("__ROL2__", 16),
        ("__ROL4__", 32),
        ("__ROL8__", 64),
        ("__ROR1__", 8),
        ("__ROR2__", 16),
        ("__ROR4__", 32),
        ("__ROR8__", 64),
    ])
    def test_bit_width_classvar(self, name: str, expected_width: int):
        """Each helper class has the correct bit_width ClassVar."""
        klass = _RotateHelper.find(name)
        assert klass is not None, f"_RotateHelper.find({name!r}) returned None"
        assert klass.bit_width == expected_width, (
            f"{name}.bit_width == {klass.bit_width}, expected {expected_width}"
        )

    def test_lookup_unknown_returns_none(self):
        """lookup() returns None for an unregistered name."""
        assert _RotateHelper.lookup("__NONEXISTENT__") is None

    def test_find_unknown_returns_none(self):
        """find() returns None for an unregistered name."""
        assert _RotateHelper.find("__NONEXISTENT__") is None

    def test_lookup_case_insensitive(self):
        """normalize_key lowercases so lookup is case-insensitive."""
        fn_upper = _RotateHelper.lookup("__ROL4__")
        fn_lower = _RotateHelper.lookup("__rol4__")
        assert fn_upper is not None
        assert fn_lower is not None
        # Both resolve to the same evaluate classmethod
        assert fn_upper(0x12345678, 8) == fn_lower(0x12345678, 8)


# ---------------------------------------------------------------------------
# TestRotateHelperCorrectness — math correctness
# ---------------------------------------------------------------------------


class TestRotateHelperCorrectness:
    """Tests that the rotate helpers produce mathematically correct results."""

    def test_rol4_by_8(self):
        """__ROL4__(0x12345678, 8) == 0x34567812."""
        fn = _RotateHelper.lookup("__ROL4__")
        assert fn is not None
        assert fn(0x12345678, 8) == 0x34567812

    def test_ror4_by_8(self):
        """__ROR4__(0x12345678, 8) == 0x78123456."""
        fn = _RotateHelper.lookup("__ROR4__")
        assert fn is not None
        assert fn(0x12345678, 8) == 0x78123456

    def test_rol1_by_1(self):
        """__ROL1__(0x80, 1) == 0x01 (MSB wraps to LSB in 8-bit)."""
        fn = _RotateHelper.lookup("__ROL1__")
        assert fn is not None
        assert fn(0x80, 1) == 0x01

    def test_ror1_by_1(self):
        """__ROR1__(0x01, 1) == 0x80 (LSB wraps to MSB in 8-bit)."""
        fn = _RotateHelper.lookup("__ROR1__")
        assert fn is not None
        assert fn(0x01, 1) == 0x80

    def test_rol8_by_32(self):
        """__ROL8__(0x0000000100000000, 32) == 0x0000000000000001."""
        fn = _RotateHelper.lookup("__ROL8__")
        assert fn is not None
        assert fn(0x0000000100000000, 32) == 0x0000000000000001

    def test_rol_ror_inverse(self):
        """ROL then ROR by the same amount returns the original value."""
        rol4 = _RotateHelper.lookup("__ROL4__")
        ror4 = _RotateHelper.lookup("__ROR4__")
        assert rol4 is not None and ror4 is not None
        for value in (0x00000001, 0xDEADBEEF, 0x12345678, 0xFFFFFFFF):
            for count in (1, 4, 8, 16, 31):
                assert ror4(rol4(value, count), count) == value, (
                    f"ROL then ROR mismatch for value=0x{value:08X} count={count}"
                )
