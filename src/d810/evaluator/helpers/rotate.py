"""Thin wrappers around the rotate helpers in :mod:`d810.core.bits`.

Each concrete subclass satisfies the rotate helper interface by
registering itself via :class:`~d810.core.registry.Registrant`.
The actual arithmetic stays in ``d810.core.bits`` so that module
remains free of any evaluator framework dependency.
"""

from __future__ import annotations

from d810.core.typing import ClassVar

from d810.core.registry import Registrant
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


class _RotateHelper(Registrant):
    """Base class for rotate helper functions.

    Subclasses register themselves automatically via :class:`Registrant`.
    Each subclass must set :attr:`registrant_name` (the canonical helper
    name, e.g. ``"__ROL4__"``) and :attr:`bit_width`.
    """

    registrant_name: ClassVar[str]
    bit_width: ClassVar[int]

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        """Perform the rotation.

        Args:
            value: Integer operand to rotate.
            count: Rotation amount in bits.

        Returns:
            Rotated value masked to :attr:`bit_width` bits.
        """
        raise NotImplementedError

    @classmethod
    def lookup(cls, name: str) -> Callable[[int, int], int] | None:
        """Return the ``evaluate`` classmethod for *name*, or ``None``.

        Drop-in replacement for the old singleton registry lookup pattern.

        Args:
            name: Canonical helper name (e.g. ``"__ROL4__"``).

        Returns:
            Bound classmethod callable, or ``None`` if not registered.
        """
        klass = cls.find(name)
        return klass.evaluate if klass is not None else None


# ---------------------------------------------------------------------------
# Concrete rotate helpers — 8 variants
# ---------------------------------------------------------------------------


class ROL1(_RotateHelper):
    registrant_name = "__ROL1__"
    bit_width = 8

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        return __ROL1__(value, count)


class ROL2(_RotateHelper):
    registrant_name = "__ROL2__"
    bit_width = 16

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        return __ROL2__(value, count)


class ROL4(_RotateHelper):
    registrant_name = "__ROL4__"
    bit_width = 32

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        return __ROL4__(value, count)


class ROL8(_RotateHelper):
    registrant_name = "__ROL8__"
    bit_width = 64

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        return __ROL8__(value, count)


class ROR1(_RotateHelper):
    registrant_name = "__ROR1__"
    bit_width = 8

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        return __ROR1__(value, count)


class ROR2(_RotateHelper):
    registrant_name = "__ROR2__"
    bit_width = 16

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        return __ROR2__(value, count)


class ROR4(_RotateHelper):
    registrant_name = "__ROR4__"
    bit_width = 32

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        return __ROR4__(value, count)


class ROR8(_RotateHelper):
    registrant_name = "__ROR8__"
    bit_width = 64

    @classmethod
    def evaluate(cls, value: int, count: int) -> int:
        return __ROR8__(value, count)


__all__ = [
    "_RotateHelper",
    "ROL1",
    "ROL2",
    "ROL4",
    "ROL8",
    "ROR1",
    "ROR2",
    "ROR4",
    "ROR8",
]
