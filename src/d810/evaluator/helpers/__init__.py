"""Helper registry for microcode evaluation helpers.

:class:`HelperRegistry` is a lightweight name-to-callable map used by the
evaluator to look up functions such as ``__ROL4__`` or ``__ROR8__`` without
scattering ``getattr(d810.core.bits, ...)`` calls throughout the codebase.

Usage::

    from d810.evaluator.helpers import get_registry

    registry = get_registry()
    fn = registry.lookup("__ROL4__")
    if fn is not None:
        result = fn(0x12345678, 8)

The module-level singleton is populated with all eight ROL/ROR helpers at
import time via :meth:`HelperRegistry.auto_register_rotate_helpers`.
"""

from __future__ import annotations

import threading
from typing import Callable


class HelperRegistry:
    """Registry mapping helper names to their callable implementations.

    Each entry stores a callable that satisfies
    :class:`~d810.evaluator.protocol.HelperProtocol`.  The registry is the
    single authoritative source for helper lookup; it replaces the
    ``getattr(d810.core.bits, helper_name, None)`` idiom used across
    multiple files.

    Examples:
        >>> reg = HelperRegistry()
        >>> reg.register("__ROL4__", lambda v, c: v, bit_width=32)
        >>> reg.lookup("__ROL4__") is not None
        True
        >>> reg.lookup("__nonexistent__") is None
        True
    """

    def __init__(self) -> None:
        self._registry: dict[str, Callable[[int, int], int]] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        fn: Callable[[int, int], int],
        *,
        bit_width: int = 0,
    ) -> None:
        """Register a helper function under *name*.

        If the callable already exposes a ``name`` attribute, *name* must
        match it (this guards against accidental mismatches).  Passing
        *bit_width* is optional metadata; it is stored on the callable via
        a ``bit_width`` attribute when not already present.

        Args:
            name: The canonical lookup key (e.g. ``"__ROL4__"``).
            fn: Callable taking ``(value: int, count: int) -> int``.
            bit_width: Bit width this helper operates on.  Used for
                documentation and protocol compliance only.

        Raises:
            ValueError: If *name* conflicts with an existing
                ``fn.name`` attribute.
        """
        existing_name = getattr(fn, "name", None)
        if existing_name is not None and existing_name != name:
            raise ValueError(
                f"Helper callable has name={existing_name!r} but was "
                f"registered under {name!r}."
            )
        # Attach metadata if the callable doesn't already carry it
        if not hasattr(fn, "bit_width") and bit_width:
            try:
                fn.bit_width = bit_width  # type: ignore[attr-defined]
            except AttributeError:
                pass  # built-in or C function — skip
        self._registry[name] = fn

    def auto_register_rotate_helpers(self) -> None:
        """Register all eight ROL/ROR helpers from :mod:`d810.core.bits`.

        Imports the pre-wrapped :class:`~d810.evaluator.helpers.rotate._RotateHelper`
        instances from :mod:`d810.evaluator.helpers.rotate` and adds each one
        under its canonical name.  This is idempotent; calling it multiple
        times has no effect because the same objects are re-registered under
        the same keys.
        """
        from d810.evaluator.helpers.rotate import ALL_ROTATE_HELPERS

        for helper in ALL_ROTATE_HELPERS:
            self.register(helper.name, helper, bit_width=helper.bit_width)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def lookup(self, name: str) -> Callable[[int, int], int] | None:
        """Find a helper by name.

        Args:
            name: The canonical helper name (e.g. ``"__ROL4__"``).

        Returns:
            The registered callable, or ``None`` if not found.
        """
        return self._registry.get(name)

    def __len__(self) -> int:
        return len(self._registry)

    def __contains__(self, name: object) -> bool:
        return name in self._registry

    def __repr__(self) -> str:
        keys = list(self._registry)
        return f"HelperRegistry({keys!r})"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_singleton: HelperRegistry | None = None
_lock: threading.Lock = threading.Lock()


def get_registry() -> HelperRegistry:
    """Return the module-level :class:`HelperRegistry` singleton.

    The registry is lazily created and pre-populated with all eight
    standard rotate helpers on first access.  Thread-safe via
    double-checked locking so concurrent callers never race to
    initialise the singleton.

    Returns:
        The shared :class:`HelperRegistry` instance.
    """
    global _singleton
    if _singleton is None:
        with _lock:
            if _singleton is None:
                _singleton = HelperRegistry()
                _singleton.auto_register_rotate_helpers()
    return _singleton


__all__ = [
    "HelperRegistry",
    "get_registry",
]
