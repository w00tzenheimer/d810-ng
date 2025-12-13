import collections
import dataclasses
import functools
import importlib
import sys
from abc import ABCMeta
from functools import cache, wraps
from types import GenericAlias, MappingProxyType
from collections.abc import MutableMapping
from typing import (
    Annotated,
    Any,
    AnyStr,
    AsyncGenerator,
    Callable,
    ClassVar,
    Coroutine,
    ForwardRef,
    Generator,
    Generic,
    Hashable,
    Iterable,
    Literal,
    Optional,
    Sequence,
    TypeAlias,
    TypeVar,
    cast,
    get_args,
    get_origin,
    get_type_hints,
    overload,
)
from weakref import WeakKeyDictionary

from .typing import LiteralString, Self, TypeAliasType

T = TypeVar("T")
_R = TypeVar("_R", bound="Registrant")
AnnotatedAny: TypeAlias = Annotated[Any, ...]  # safely parameterized


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

# Pyright does not follow TypeVarType when passing type[T] to a function...
timestamp: TypeAlias = int
Thunk: TypeAlias = Callable[[], T]
OnePlus: TypeAlias = T | Sequence[T]
Defer: TypeAlias = T | Thunk[T]
TypeRef: TypeAlias = str | ForwardRef | GenericAlias | TypeAliasType | AnnotatedAny
DeferTypeRef: TypeAlias = Defer[type] | TypeRef
"""A typelike reference which can be wrapped to be resolved later."""


def survives_reload(cls=None, *, reload_key: str = ""):
    """
    Class decorator (optionally parameterized) that enables a class to survive reloads by storing a shared instance
    on the module object, keyed by `reload_key` (or `_SHARED_<ClassName>`).

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


# Alternatively, could use ForwardRef._evaluate but that's private. This is at least public and legal.
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
        # # If someone defined `name` as a @property on the class we end up with a
        # # `property` object - not the actual value.  Fallback to class-name in
        # # that case.
        # if isinstance(key_attr, property):
        #     return cls.__name__
        return key_attr  # or cls.__name__

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
        # Exclude any classes earmarked for lazy loading so we don't trigger them
        # exclude: set[type] = set()
        # for load in cls.lazy_registry.values():
        #     try:
        #         exclude.add(load())
        #     except Exception:
        #         pass
        # gen = (c for c in cls.registry.values() if c not in exclude)
        return FilterableGenerator(cls.registry.values(), [predicate])


def get_all_subclasses(python_class: type) -> list[type]:
    """Return all subclasses of a class, recursively.

    Traverses the entire class hierarchy to find all concrete subclasses,
    returning them sorted by class name.
    """
    python_class.__subclasses__()

    subclasses = set()
    check_these = [python_class]

    while check_these:
        parent = check_these.pop()
        for child in parent.__subclasses__():
            if child not in subclasses:
                subclasses.add(child)
                check_these.append(child)

    return sorted(subclasses, key=lambda x: x.__name__)


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
