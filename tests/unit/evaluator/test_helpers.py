"""Unit tests for d810.evaluator.helpers.

Covers :class:`HelperRegistry` registration, lookup, and the
:meth:`HelperRegistry.auto_register_rotate_helpers` bulk-registration path.
No IDA dependencies; pure-Python only.
"""

from __future__ import annotations

import pytest

from d810.evaluator.helpers import HelperRegistry, get_registry


# ---------------------------------------------------------------------------
# Helpers
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
# HelperRegistry — basic registration and lookup
# ---------------------------------------------------------------------------


class TestHelperRegistryBasic:
    """Tests for manual register / lookup."""

    def test_register_and_lookup_returns_callable(self):
        """A registered function is returned by lookup."""
        reg = HelperRegistry()
        fn = lambda v, c: v + c  # noqa: E731
        reg.register("__TEST__", fn)
        result = reg.lookup("__TEST__")
        assert result is fn

    def test_lookup_unknown_returns_none(self):
        """Lookup of an unregistered name returns None."""
        reg = HelperRegistry()
        assert reg.lookup("__nonexistent__") is None

    def test_lookup_empty_registry_returns_none(self):
        """Lookup on a fresh empty registry always returns None."""
        reg = HelperRegistry()
        assert reg.lookup("__ROL4__") is None

    def test_register_overwrites_existing_entry(self):
        """Re-registering a name replaces the previous callable."""
        reg = HelperRegistry()
        fn_a = lambda v, c: v  # noqa: E731
        fn_b = lambda v, c: c  # noqa: E731
        reg.register("__FOO__", fn_a)
        reg.register("__FOO__", fn_b)
        assert reg.lookup("__FOO__") is fn_b

    def test_len_tracks_entries(self):
        """__len__ returns the number of registered helpers."""
        reg = HelperRegistry()
        assert len(reg) == 0
        reg.register("__A__", lambda v, c: v)
        assert len(reg) == 1
        reg.register("__B__", lambda v, c: c)
        assert len(reg) == 2

    def test_contains_operator(self):
        """``in`` operator works for registered and unregistered names."""
        reg = HelperRegistry()
        reg.register("__ROL4__", lambda v, c: v)
        assert "__ROL4__" in reg
        assert "__ROR4__" not in reg

    def test_register_with_mismatched_name_raises(self):
        """register() raises ValueError when fn.name disagrees with the key."""
        from d810.evaluator.helpers.rotate import ROL4

        reg = HelperRegistry()
        with pytest.raises(ValueError, match="registered under"):
            reg.register("__WRONG_NAME__", ROL4)

    def test_register_callable_is_callable_after_lookup(self):
        """Looked-up helpers can be called and produce a result."""
        reg = HelperRegistry()
        reg.register("__DOUBLE__", lambda v, c: v * 2)
        fn = reg.lookup("__DOUBLE__")
        assert fn is not None
        assert fn(5, 0) == 10


# ---------------------------------------------------------------------------
# HelperRegistry — auto_register_rotate_helpers
# ---------------------------------------------------------------------------


class TestAutoRegisterRotateHelpers:
    """Tests for the bulk rotate-helper registration path."""

    def test_auto_register_populates_all_eight(self):
        """auto_register_rotate_helpers() registers all 8 ROL/ROR helpers."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        for name in _ALL_ROTATE_NAMES:
            assert reg.lookup(name) is not None, f"{name} was not registered"

    def test_auto_register_produces_callables(self):
        """Each auto-registered entry is callable."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        for name in _ALL_ROTATE_NAMES:
            fn = reg.lookup(name)
            assert callable(fn), f"{name} is not callable"

    def test_auto_register_is_idempotent(self):
        """Calling auto_register_rotate_helpers() twice does not raise."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        reg.auto_register_rotate_helpers()  # should not raise
        assert len(reg) == len(_ALL_ROTATE_NAMES)

    def test_auto_register_count(self):
        """Exactly 8 helpers are registered."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        assert len(reg) == 8


# ---------------------------------------------------------------------------
# HelperRegistry — correctness of rotate results
# ---------------------------------------------------------------------------


class TestRotateHelperCorrectness:
    """Tests that the rotate helpers produce mathematically correct results."""

    def test_rol4_by_8(self):
        """__ROL4__(0x12345678, 8) == 0x34567812."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        fn = reg.lookup("__ROL4__")
        assert fn is not None
        assert fn(0x12345678, 8) == 0x34567812

    def test_ror4_by_8(self):
        """__ROR4__(0x12345678, 8) == 0x78123456."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        fn = reg.lookup("__ROR4__")
        assert fn is not None
        assert fn(0x12345678, 8) == 0x78123456

    def test_rol1_by_1(self):
        """__ROL1__(0x80, 1) == 0x01 (MSB wraps to LSB in 8-bit)."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        fn = reg.lookup("__ROL1__")
        assert fn is not None
        assert fn(0x80, 1) == 0x01

    def test_ror1_by_1(self):
        """__ROR1__(0x01, 1) == 0x80 (LSB wraps to MSB in 8-bit)."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        fn = reg.lookup("__ROR1__")
        assert fn is not None
        assert fn(0x01, 1) == 0x80

    def test_rol8_by_32(self):
        """__ROL8__(0x0000000100000000, 32) == 0x0000000000000001.

        Rotating ``1 << 32`` left by 32 positions in a 64-bit word moves the
        set bit from position 32 to position 0 (wrap-around).
        """
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        fn = reg.lookup("__ROL8__")
        assert fn is not None
        # bit 32 rotated left 32 positions wraps to bit 0
        assert fn(0x0000000100000000, 32) == 0x0000000000000001

    def test_rol_ror_inverse(self):
        """ROL then ROR by the same amount returns the original value."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        rol4 = reg.lookup("__ROL4__")
        ror4 = reg.lookup("__ROR4__")
        assert rol4 is not None and ror4 is not None
        for value in (0x00000001, 0xDEADBEEF, 0x12345678, 0xFFFFFFFF):
            for count in (1, 4, 8, 16, 31):
                assert ror4(rol4(value, count), count) == value, (
                    f"ROL then ROR mismatch for value=0x{value:08X} count={count}"
                )

    @pytest.mark.parametrize("name,bit_width", [
        ("__ROL1__", 8),
        ("__ROL2__", 16),
        ("__ROL4__", 32),
        ("__ROL8__", 64),
        ("__ROR1__", 8),
        ("__ROR2__", 16),
        ("__ROR4__", 32),
        ("__ROR8__", 64),
    ])
    def test_helper_has_bit_width_attribute(self, name: str, bit_width: int):
        """Each auto-registered helper has a bit_width attribute."""
        reg = HelperRegistry()
        reg.auto_register_rotate_helpers()
        fn = reg.lookup(name)
        assert fn is not None
        assert hasattr(fn, "bit_width"), f"{name} has no bit_width attribute"
        assert fn.bit_width == bit_width, (
            f"{name}.bit_width == {fn.bit_width}, expected {bit_width}"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


class TestGetRegistry:
    """Tests for the get_registry() singleton accessor."""

    def test_get_registry_returns_helper_registry(self):
        """get_registry() returns a HelperRegistry instance."""
        reg = get_registry()
        assert isinstance(reg, HelperRegistry)

    def test_get_registry_is_singleton(self):
        """Multiple calls return the same object."""
        reg1 = get_registry()
        reg2 = get_registry()
        assert reg1 is reg2

    def test_get_registry_has_rotate_helpers(self):
        """The singleton is pre-populated with all rotate helpers."""
        reg = get_registry()
        for name in _ALL_ROTATE_NAMES:
            assert reg.lookup(name) is not None, (
                f"Singleton registry missing {name}"
            )

    def test_get_registry_rol4_callable(self):
        """__ROL4__ from the singleton registry produces a correct result."""
        fn = get_registry().lookup("__ROL4__")
        assert fn is not None
        assert fn(0x12345678, 8) == 0x34567812
