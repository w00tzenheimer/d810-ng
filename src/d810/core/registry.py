"""Registry metaclass, Registrant base, and supporting utilities.

This module provides:
    Registry      - ABCMeta subclass for auto-registering subclasses
    Registrant    - Base class using Registry metaclass
    FilterableGenerator - Lazy filterable view over registered classes
    get_all_subclasses  - Recursive subclass enumeration
    EventEmitter  - Re-exported from core.events for backward compat
    SingletonMeta / singleton - Thread-safe singleton, merged from singleton.py

All utility descriptors (NotGiven, survives_reload, reify, deferred_property,
typename, typecheck, resolve_forward_ref, lazy_type, CombineMeta, async_await,
coroutine, type aliases) live in core.descriptors and are re-exported here for
backward compatibility.
"""
import collections
import dataclasses
import functools
import threading
from abc import ABCMeta

from d810.core.typing import (
    Any,
    Callable,
    ClassVar,
    Generic,
    Hashable,
    Iterable,
    Optional,
    TypeAlias,
    TypeVar,
    cast,
)

T = TypeVar("T")
_R = TypeVar("_R", bound="Registrant")

# ---------------------------------------------------------------------------
# Re-exports from descriptors (backward compat: importers of registry get these)
# ---------------------------------------------------------------------------
from d810.core.descriptors import (  # noqa: E402
    NOT_GIVEN,
    NotGiven,
    Thunk,
    Defer,
    TypeRef,
    DeferTypeRef,
    survives_reload,
    CombineMeta,
    combine_meta,
    async_await,
    coroutine,
    typename,
    typecheck,
    resolve_forward_ref,
    deferred_property,
    lazy_type,
    reify,
)

# Re-export EventEmitter from core.events for backward compat
from d810.core.events import EventEmitter  # noqa: E402


# ---------------------------------------------------------------------------
# FilterableGenerator
# ---------------------------------------------------------------------------


class FilterableGenerator(Generic[T]):
    """
    Wraps an Iterable of classes and a list of predicates.
    You can .filter(...) repeatedly to build up predicates,
    and only when you iterate do we apply them.
    """

    def __init__(
        self,
        source: Iterable[T],
        predicates: list[Callable[[T], bool]] | None = None,
    ):
        self._source = source
        self._preds = list(predicates or [])

    def filter(self, predicate: Callable[[T], bool]) -> "FilterableGenerator[T]":
        return FilterableGenerator(self._source, self._preds + [predicate])

    def __iter__(self):
        for cls in self._source:
            if all(pred(cls) for pred in self._preds):
                yield cls

    def __repr__(self):
        # avoid consuming the generator!
        return f"<FilterableGenerator preds={len(self._preds)} source={self._source!r}>"


# ---------------------------------------------------------------------------
# Registry metaclass & Registrant base
# ---------------------------------------------------------------------------


class Registry(ABCMeta):
    """Metaclass for registering subclasses."""

    def __init__(
        self,
        name: str,
        bases: tuple[type, ...],
        attrs: dict[str, Any],
    ):
        """Metaclass constructor that wires up class registries.

        Every concrete subclass receives its *own* ``registry`` and
        ``lazy_registry`` dictionaries so that sibling hierarchies do *not*
        accidentally share the same registry from a common ancestor.
        """

        super().__init__(name, bases, attrs)

        # Skip wiring for the Registrant sentinel itself.
        if name == "Registrant":
            return

        # If this is a direct subclass of Registrant, give it its own registries
        if Registrant in bases:
            self.registry: dict[str, type[Any]] = {}
            self.lazy_registry: dict[str, Thunk[type[Any]]] = {}


class Registrant(metaclass=Registry):
    """Self-registering resource."""

    registrant_name: ClassVar[str]
    """Name to register the resource under."""

    registry: ClassVar[dict[str, type[Any]]] = {}
    """Registry of registered resources."""

    lazy_registry: ClassVar[dict[str, Thunk[type[Any]]]] = {}
    """Registry of lazy registrations."""

    def __init_subclass__(cls):
        # Register *cls* into every immediate parent that is itself a
        # Registrant (except for the root Registrant, which we leave empty to
        # avoid an unwieldy global registry).
        visited = set()
        to_visit = list(cls.__bases__)
        while to_visit:
            base = to_visit.pop()
            if base in visited:
                continue
            visited.add(base)
            if Registrant in base.__bases__:
                base.register(cls)
            else:
                to_visit.extend(base.__bases__)

    @staticmethod
    def keyof(kls: type) -> str:
        """Return the key of the resource."""
        key_attr = getattr(kls, "registrant_name", kls.__name__)
        return key_attr

    @classmethod
    def normalize_key(cls, key: str) -> str:
        """Normalize a key."""
        return key.lower()

    @classmethod
    def register(cls, alt: type[Any]):
        """Directly register a subclass (unless it tries to register itself)."""
        # a class should not add itself to _its own_ registry
        if alt is cls and "registry" in cls.__dict__:
            return
        name = cls.normalize_key(cls.keyof(alt))
        # Pop any lazy registration
        cls.lazy_registry.pop(name, None)
        cls.registry[name] = alt

    @classmethod
    def lazy_register(cls, load: Thunk[type[Any]]):
        """Register a thunk (hook) under its function name for lazy initialization."""
        if load.__name__ not in cls.registry:
            cls.lazy_registry[load.__name__] = load

    @classmethod
    def get(cls, name: str) -> _R:  # type: ignore
        """Look up a registered subclass by name, loading lazily if needed."""
        key = cls.normalize_key(name)
        if factory := cls.lazy_registry.get(key):
            sub = factory()
            # move from lazy to real registry
            del cls.lazy_registry[key]
            cls.registry[key] = sub
            return cast(_R, sub)

        return cast(_R, cls.registry[key])

    @classmethod
    def find(cls, name: str) -> _R | None:  # type: ignore
        """Find a registered subclass by name (case-insensitive).

        Unlike get(), returns None if not found instead of raising KeyError.
        Useful for checking if a rule exists before removing it.
        """
        try:
            return cls.get(name)
        except KeyError:
            return None

    @classmethod
    def all(cls) -> list[type[Any]]:
        """Return every concrete subclass currently registered for *cls*."""
        return list(cls.registry.values())

    @classmethod
    def get_subclasses(cls, base: type | None = None) -> list[type]:
        """Return every concrete subclass of *base* that has been registered.

        Parameters
        ----------
        base: type
            The root class you are interested in (e.g. ``InstructionOptimizationRule``).

        Notes
        -----
        * ``base`` itself must ultimately inherit from :class:`Registrant`.
        * Works even when ``cls`` is the *Registrant* class itself.
        """

        if base is None:
            base = cls

        if not issubclass(base, Registrant):
            raise TypeError(
                f"get_subclasses() expects a Registrant-derived base class, received: {base} for class: {cls.__name__}"
            )

        # Every Registrant-derived class owns its *own* registry dict.  Simply
        # walk the MRO below *base* and aggregate them.
        collected: list[type] = []

        def _collect(sub):
            # Append concrete subclasses first
            if sub is not base and not getattr(sub, "__abstractmethods__", False):
                collected.extend(sub.registry.values())  # type: ignore[attr-defined]
            # Recurse into further subclasses
            for child in sub.__subclasses__():
                _collect(child)

        _collect(base)
        # Remove duplicates while preserving order
        unique: list[type] = []
        seen = set()
        for subcls in collected:
            if subcls not in seen:
                unique.append(subcls)
                seen.add(subcls)
        return unique

    @classmethod
    def filter(cls, predicate: Callable[[type], bool]) -> FilterableGenerator[type]:
        """
        Start a chain of filters over a generator of cls.registry.values().
        You can then .filter(...) again and again, and finally iterate it:
            for C in Registry.filter(p1).filter(p2): ...
        """
        return FilterableGenerator(cls.registry.values(), [predicate])


def get_all_subclasses(python_class: type) -> list[type]:
    """Return all subclasses of a class, recursively.

    Traverses the entire class hierarchy to find all concrete subclasses,
    returning them sorted by class name.
    """
    subclasses = set()
    check_these = [python_class]

    while check_these:
        parent = check_these.pop()
        for child in parent.__subclasses__():
            if child not in subclasses:
                subclasses.add(child)
                check_these.append(child)

    return sorted(subclasses, key=lambda x: x.__name__)


# ---------------------------------------------------------------------------
# Singleton pattern (merged from singleton.py)
# ---------------------------------------------------------------------------


class SingletonMeta(type):
    """
    Thread-safe implementation of Singleton metaclass.
    Can also be used as a decorator.
    """

    _instances: dict[type, object] = {}
    _locks: dict[type, threading.Lock] = {}

    def __call__(cls: type[T], *args: Any, **kwargs: Any) -> T:
        if cls not in SingletonMeta._instances:
            # use class-level _lock if defined, else fallback to internal lock
            lock: threading.Lock = getattr(
                cls, "_lock", SingletonMeta._locks.setdefault(cls, threading.Lock())
            )
            with lock:
                if cls not in SingletonMeta._instances:
                    instance = type.__call__(cls, *args, **kwargs)
                    SingletonMeta._instances[cls] = instance
        return cast(T, SingletonMeta._instances[cls])


    @classmethod
    def _reset_for_test(cls, target_cls: type) -> None:
        """Remove singleton instance for a specific class. For use in tests only."""
        cls._instances.pop(target_cls, None)


def singleton(cls: type[T]) -> type[T]:
    """
    Decorator to apply SingletonMeta behavior to a class.
    """

    class SingletonWrapper(cls, metaclass=SingletonMeta):
        pass

    SingletonWrapper.__name__ = cls.__name__
    SingletonWrapper.__doc__ = cls.__doc__
    SingletonWrapper.__module__ = cls.__module__
    return cast(type[T], SingletonWrapper)
