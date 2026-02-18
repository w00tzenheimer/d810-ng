"""Utility descriptors and decorators for d810 core.

Extracted from registry.py to allow lightweight import of common utilities
without pulling in the full Registry/Registrant metaclass machinery.

Contents:
    NotGiven / NOT_GIVEN  - sentinel for unset values
    Thunk / Defer / TypeRef / DeferTypeRef - type aliases
    survives_reload       - class decorator for reload-safe singletons
    CombineMeta / combine_meta - metaclass combiner
    async_await / coroutine    - async helpers
    typename / typecheck / resolve_forward_ref - type utilities
    deferred_property / lazy_type - lazy initialisation helpers
    reify                 - cached-property descriptor
"""
from __future__ import annotations

import functools
import importlib
import sys
from collections.abc import MutableMapping
from functools import cache, wraps
from types import GenericAlias, MappingProxyType
from weakref import WeakKeyDictionary

from d810.core.typing import (
    Annotated,
    Any,
    AnyStr,
    AsyncGenerator,
    Callable,
    Coroutine,
    ForwardRef,
    Generator,
    Generic,
    Literal,
    LiteralString,
    Optional,
    Self,
    Sequence,
    TypeAlias,
    TypeAliasType,
    TypeVar,
    cast,
    get_args,
    get_origin,
    get_type_hints,
    overload,
)

T = TypeVar("T")

# ---------------------------------------------------------------------------
# Sentinels & type aliases
# ---------------------------------------------------------------------------

AnnotatedAny: TypeAlias = Annotated[Any, ...]  # safely parameterized

timestamp: TypeAlias = int
Thunk: TypeAlias = Callable[[], T]
OnePlus: TypeAlias = T | Sequence[T]
Defer: TypeAlias = T | Thunk[T]
TypeRef: TypeAlias = str | ForwardRef | GenericAlias | TypeAliasType | AnnotatedAny
DeferTypeRef: TypeAlias = Defer[type] | TypeRef
"""A typelike reference which can be wrapped to be resolved later."""


class NotGiven:
    """Placeholder for value which isn't given."""

    def __init__(self):
        raise NotImplementedError()

    def __bool__(self):
        return False

    def __repr__(self):
        return "NOT_GIVEN"

    @staticmethod
    def params(**kwargs):
        """Return a dict of the given parameters which are not NOT_GIVEN."""
        return {k: v for k, v in kwargs.items() if not isinstance(v, NotGiven)}


# Using __new__ to implement singleton pattern
NOT_GIVEN = object.__new__(NotGiven)
"""Placeholder for value which isn't given."""

# ---------------------------------------------------------------------------
# survives_reload
# ---------------------------------------------------------------------------


def survives_reload(cls=None, *, reload_key: str = ""):
    """
    Class decorator (optionally parameterized) that enables a class to survive
    reloads by storing a shared instance on the module object, keyed by
    `reload_key` (or `_SHARED_<ClassName>`).

    Usage:
        @survives_reload
        class MyClass: ...

        @survives_reload()
        class MyClass: ...

        BLAH = survives_reload(MyClass, reload_key="FOO")
    """
    def decorator(inner_cls):
        _reload_key = reload_key or f"_SHARED_{inner_cls.__name__}"
        _module = sys.modules[inner_cls.__module__]

        @functools.wraps(inner_cls)
        def get_shared_instance(*args, **kwargs):
            existing = getattr(_module, _reload_key, None)
            if existing is not None:
                return existing
            inst = inner_cls.__new__(inner_cls, *args, **kwargs)
            inner_cls.__init__(inst, *args, **kwargs)
            setattr(_module, _reload_key, inst)
            return inst

        return get_shared_instance

    # Handle all three cases:
    # 1. @survives_reload
    # 2. @survives_reload()
    # 3. survives_reload(SomeClass, reload_key=...)
    if cls is not None and callable(cls):
        return decorator(cls)
    return decorator


# ---------------------------------------------------------------------------
# CombineMeta
# ---------------------------------------------------------------------------


class CombineMeta:
    def __prepare__(
        self,
        name: str,
        bases: tuple[type, ...],
        **kwargs: Any
    ) -> MutableMapping[str, Any]:
        namespace: MutableMapping[str, Any] = {}
        for metaclass in self._get_most_derived_metaclasses(bases):
            ns = metaclass.__prepare__(name, bases, **kwargs)
            if type(ns) in (dict, type(namespace)):
                namespace.update(ns)
            else:
                if type(namespace) is not dict:
                    raise TypeError(
                        "metaclass conflict: " "multiple custom namespaces defined."
                    )
                ns.update(namespace)
                namespace = ns
        return namespace

    def __call__(
        self,
        name: str,
        bases: tuple[type, ...],
        namespace: MutableMapping[str, Any],
        **kwargs: Any
    ) -> type:
        metaclasses = self._get_most_derived_metaclasses(bases)
        if len(metaclasses) > 1:
            merged_name = "__".join(meta.__name__ for meta in metaclasses)
            ns = self.__prepare__(merged_name, tuple(metaclasses))
            metaclass = self(merged_name, tuple(metaclasses), ns, **kwargs)
        else:
            (metaclass,) = metaclasses or (type,)
        return metaclass(name, bases, dict(namespace), **kwargs)

    @staticmethod
    def _get_most_derived_metaclasses(
        bases: tuple[type, ...]
    ) -> list[type]:
        metaclasses: list[type] = []
        for metaclass in map(type, bases):
            if metaclass is not type:
                metaclasses = [
                    other for other in metaclasses if not issubclass(metaclass, other)
                ]
                if not any(issubclass(other, metaclass) for other in metaclasses):
                    metaclasses.append(metaclass)
        return metaclasses


combine_meta = CombineMeta()

# ---------------------------------------------------------------------------
# Async helpers
# ---------------------------------------------------------------------------


def async_await(
    fn: Callable[..., Coroutine[Any, Any, T]],
) -> Callable[..., Generator[Any, None, T]]:
    """
    Decorator to convert an async function to a generator for use with a
    more intuitive async __await__.
    """

    @wraps(fn)
    def wrapper(*args, **kwargs):
        async_gen = fn(*args, **kwargs)
        return async_gen.__await__()

    return wrapper


def coroutine(
    fn: Callable[..., AsyncGenerator[None, T]],
) -> Callable[..., Coroutine[Any, Any, AsyncGenerator[None, T]]]:
    """Auto-starting coroutine decorator."""

    @wraps(fn)
    async def calls_asend(*args, **kwargs):
        gen = fn(*args, **kwargs)
        try:
            await gen.asend(None)  # type: ignore
        except StopAsyncIteration:
            print("StopAsyncIteration")  # Doesn't print
        return gen

    return calls_asend


# ---------------------------------------------------------------------------
# Type utilities
# ---------------------------------------------------------------------------


def typename(t: TypeRef) -> str:
    """Return the name of a type, or the name of a value's type."""

    if get_origin(t) is None:
        if not isinstance(t, type):
            t = type(t)
        return t.__name__  # type: ignore
    return str(t)


def typecheck(value: Any, t: TypeRef) -> bool:
    """
    More featureful type checking. Supports isinstance, but also the zoo of
    `typing` types which are not supported by isinstance.
    """

    try:
        # type, Optional, Union, @runtime_checkable
        return isinstance(value, t)  # type: ignore
    except TypeError:
        pass

    if t is Any:
        return True
    if t in {None, type(None)}:
        return value is None
    if t in {AnyStr, LiteralString}:
        return isinstance(value, (str, bytes))

    # Generic types

    origin, args = get_origin(t), get_args(t)

    if origin is Literal:
        return value in args

    if origin is Annotated:
        return typecheck(value, args[0])

    if isinstance(t, TypeAliasType):
        return typecheck(value, t.__value__)  # type: ignore [attr-defined]

    return False


def resolve_forward_ref(
    obj: TypeRef,
    globalns: dict[str, Any] | None = None,
    localns: dict[str, Any] | MappingProxyType[str, Any] | None = None,
):
    """Resolve a singular forward reference."""

    def dummy(x: TypeRef):
        pass

    _localns: dict[str, Any] = (
        cast(dict[str, Any], localns) if localns is not None else {}
    )
    return get_type_hints(dummy, globalns, _localns)["x"]


# ---------------------------------------------------------------------------
# Lazy / deferred initialisation
# ---------------------------------------------------------------------------


class deferred_property(Generic[T]):
    """A property which can be resolved later with minimal friction."""

    deferral: WeakKeyDictionary[type, Thunk[T]]

    def __init__(self):
        self.deferral = WeakKeyDictionary()

    def __set_name__(self, owner, name: str):
        self.__name__ = name

    @overload
    def __get__(self, instance: None, owner) -> Self: ...
    @overload
    def __get__(self, instance, owner) -> T: ...

    def __get__(self, instance, owner) -> Self | T:
        if instance is None:
            return self

        value = instance.__dict__.get(self.__name__, NOT_GIVEN)
        if value is not NOT_GIVEN:
            return value

        try:
            value = self.deferral.pop(instance)()
            setattr(instance, self.__name__, value)
            return value
        except KeyError:
            raise AttributeError(
                f"{typename(owner)}.{self.__name__} has no deferral"
            ) from None

    def __set__(self, instance, value: T):
        instance.__dict__[self.__name__] = value
        return value

    def defer(self, instance, deferral: Defer[T]):
        """Explicitly defer a value."""
        if callable(deferral):
            self.deferral[instance] = deferral
        else:
            setattr(instance, self.__name__, deferral)
        return self


def lazy_type(t: DeferTypeRef, cls: Optional[type] = None) -> Defer[type]:
    """Return a lazy type which can be resolved later."""

    if isinstance(t, (type, Callable)):
        return cast(type | Callable, t)
    if cls is None:
        raise ValueError("cls must be given if t is unbound")

    @cache
    def factory():
        global_ns = importlib.import_module(cls.__module__).__dict__
        return resolve_forward_ref(t, global_ns, cls.__dict__)

    return factory


# ---------------------------------------------------------------------------
# reify descriptor
# ---------------------------------------------------------------------------


class reify(Generic[T]):
    """
    Acts similar to a property, except the result will be
    set as an attribute on the instance instead of recomputed
    each access.
    """

    def __init__(self, fn: Callable[..., T]) -> None:
        self.fn = fn
        # Copy function attributes to preserve metadata
        self.__name__ = getattr(fn, "__name__", "<unknown>")
        self.__doc__ = getattr(fn, "__doc__", None)
        self.__module__ = getattr(fn, "__module__", "") or ""
        self.__qualname__ = getattr(fn, "__qualname__", "") or ""
        self.__annotations__ = getattr(fn, "__annotations__", {})

    @overload
    def __get__(self, instance: None, owner: type) -> "reify[T]": ...

    @overload
    def __get__(self, instance: Any, owner: type) -> T: ...

    def __get__(self, instance: Any, owner: type) -> "T | reify[T]":
        if instance is None:
            return self

        fn = self.fn
        val = fn(instance)
        setattr(instance, fn.__name__, val)
        return val
