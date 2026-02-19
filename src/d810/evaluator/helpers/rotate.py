"""Thin wrappers around the rotate helpers in :mod:`d810.core.bits`.

Each wrapper satisfies :class:`~d810.evaluator.protocol.HelperProtocol`
by attaching ``name`` and ``bit_width`` metadata to the underlying
pure-Python function.  The actual arithmetic stays in ``d810.core.bits``
so that module remains free of any evaluator framework dependency.
"""

from __future__ import annotations

from d810.core.typing import Callable

from d810.core.bits import (
    __ROL1__,
    __ROL2__,
    __ROL4__,
    __ROL8__,
    __ROR1__,
    __ROR2__,
    __ROR4__,
    __ROR8__,
)


class _RotateHelper:
    """Wraps a rotate function with :class:`HelperProtocol`-compatible metadata.

    Args:
        fn: The underlying rotate callable from :mod:`d810.core.bits`.
        name: The canonical helper name (e.g. ``"__ROL4__"``).
        bit_width: The integer bit width this helper operates on.
    """

    def __init__(self, fn: Callable[[int, int], int], name: str, bit_width: int) -> None:
        self._fn = fn
        self.name = name
        self.bit_width = bit_width
        # Preserve introspection attributes for debugging
        self.__name__ = name
        self.__doc__ = fn.__doc__

    def __call__(self, value: int, count: int) -> int:
        """Delegate to the wrapped rotate function.

        Args:
            value: Integer operand to rotate.
            count: Rotation amount in bits.

        Returns:
            Rotated value masked to :attr:`bit_width` bits.
        """
        return self._fn(value, count)

    def __repr__(self) -> str:
        return f"_RotateHelper(name={self.name!r}, bit_width={self.bit_width})"


# ---------------------------------------------------------------------------
# Pre-built instances for each rotate variant
# ---------------------------------------------------------------------------

ROL1: _RotateHelper = _RotateHelper(__ROL1__, "__ROL1__", 8)
ROL2: _RotateHelper = _RotateHelper(__ROL2__, "__ROL2__", 16)
ROL4: _RotateHelper = _RotateHelper(__ROL4__, "__ROL4__", 32)
ROL8: _RotateHelper = _RotateHelper(__ROL8__, "__ROL8__", 64)

ROR1: _RotateHelper = _RotateHelper(__ROR1__, "__ROR1__", 8)
ROR2: _RotateHelper = _RotateHelper(__ROR2__, "__ROR2__", 16)
ROR4: _RotateHelper = _RotateHelper(__ROR4__, "__ROR4__", 32)
ROR8: _RotateHelper = _RotateHelper(__ROR8__, "__ROR8__", 64)

#: All eight standard rotate helpers in registration order.
ALL_ROTATE_HELPERS: tuple[_RotateHelper, ...] = (
    ROL1,
    ROL2,
    ROL4,
    ROL8,
    ROR1,
    ROR2,
    ROR4,
    ROR8,
)

__all__ = [
    "ROL1",
    "ROL2",
    "ROL4",
    "ROL8",
    "ROR1",
    "ROR2",
    "ROR4",
    "ROR8",
    "ALL_ROTATE_HELPERS",
]
