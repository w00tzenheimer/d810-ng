"""Event emitter for d810 core.

Extracted from registry.py so that event subscription/emission can be
imported without pulling in the full Registry/Registrant machinery.
"""
from __future__ import annotations

import collections
import dataclasses
import functools

from d810.core.typing import Callable, Generic, Hashable, TypeVar

E = TypeVar("E", bound=Hashable)


@dataclasses.dataclass
class EventEmitter(Generic[E]):
    _listeners: collections.defaultdict[E, set[Callable]] = dataclasses.field(
        default_factory=lambda: collections.defaultdict(set), init=False
    )

    def on(self, event: E, handler: Callable | None = None):
        """Register an event handler for the given event."""
        if handler:
            self._listeners[event].add(handler)
            return handler

        @functools.wraps(self.on)
        def decorator(func):
            self.on(event, func)
            return func

        return decorator

    def once(self, event: E, handler: Callable):
        @functools.wraps(handler)
        def once_handler(*args, **kwargs):
            self.remove(event, once_handler)
            return handler(*args, **kwargs)

        self.on(event, once_handler)

    def remove(self, event: E, handler: Callable):
        self._listeners[event].discard(handler)

    def clear(self):
        self._listeners.clear()

    def emit(self, event: E, *args, **kwargs):
        for handler in self._listeners[event]:
            handler(*args, **kwargs)
