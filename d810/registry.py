from abc import ABCMeta
from functools import cache, wraps
from types import GenericAlias, MappingProxyType
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
    Literal,
    LiteralString,
    Optional,
    Self,
    Sequence,
    TypeAliasType,
    cast,
    get_args,
    get_origin,
    get_type_hints,
    overload,
)
from weakref import WeakKeyDictionary


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
# Pyright is too stupid to follow TypeVarType when passing type[T] to a function,
#  so this probably won't work.
type timestamp = int

type Thunk[T] = Callable[[], T]
type OnePlus[T] = T | Sequence[T]
type Defer[T] = T | Thunk[T]
type TypeRef = str | ForwardRef | GenericAlias | TypeAliasType | Annotated
type DeferTypeRef = Defer[type] | TypeRef
"""A typelike reference which can be wrapped to be resolved later."""


def async_await[T](
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


def coroutine[T](
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


# Alternatively, could use ForwardRef._evaluate but that's private. This is at least public and legal.3
def resolve_forward_ref(
    obj: TypeRef,
    globalns: dict[str, Any] | None = None,
    localns: dict[str, Any] | MappingProxyType[str, Any] | None = None,
):
    """Resolve a singular forward reference."""

    def dummy(x: TypeRef):
        pass

    localns_cast = cast(localns, MappingProxyType[str, Any])
    return get_type_hints(dummy, globalns, localns_cast)["x"]


class deferred_property[T]:
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
        global_ns = load_module(cls.__module__).__dict__
        return resolve_forward_ref(t, global_ns, cls.__dict__)

    return factory


class Registry(ABCMeta):
    """Metaclass for registering subclasses."""

    def __init__(cls, name: str, bases: tuple[type, ...], attrs: dict[str, Any]):
        super().__init__(name, bases, attrs)
        # Don't register resource base classes
        # print(f"Registry.__init__ {name}")
        if name != "Registrant":
            # Register only Registrant subclass subclasses
            if Registrant in cls.__bases__:
                cls.registry = {}
                cls.lazy_registry = {}
            else:
                cls.register(cls)  # type: ignore


class Registrant(metaclass=Registry):
    """Self-registering resource."""

    registrant_name: ClassVar[str]
    """Name to register the resource under."""

    registry: ClassVar[dict[str, type[Self]]] = {}
    """Registry of registered resources."""

    lazy_registry: ClassVar[dict[str, Thunk[type[Self]]]] = {}
    """Registry of lazy registrations."""

    def __init_subclass__(cls):
        # Only register subclasses of Resource subclasses
        # print(f"Registrant.__init_subclass__ {cls.__name__}")
        if Registrant not in cls.__bases__:
            cls.register(cls)

    @classmethod
    def keyof(cls) -> str:
        """Return the key of the resource."""
        key_attr = getattr(cls, "registrant_name", cls.__name__)
        # # If someone defined `name` as a @property on the class we end up with a
        # # `property` object – not the actual value.  Fallback to class-name in
        # # that case.
        # if isinstance(key_attr, property):
        #     return cls.__name__
        return key_attr  # or cls.__name__

    @classmethod
    def normalize_key(cls, key: str) -> str:
        """Normalize a key."""
        return key.lower()

    @classmethod
    def register(cls, alt: type[Self]):
        """Directly register a subclass."""

        name = cls.normalize_key(cls.keyof())
        # Pop any lazy registration
        cls.lazy_registry.pop(name, None)
        cls.registry[name] = alt

    @classmethod
    def lazy_register(cls, load: Thunk[type[Self]]):
        """Register a hook for lazy initialization."""
        if load.__name__ not in cls.registry:
            cls.lazy_registry[load.__name__] = load

    @classmethod
    def get(cls, name: str) -> type[Self]:
        """Retrieve a registered subclass."""

        name = cls.normalize_key(name)
        if factory := cls.lazy_registry.get(name):
            type = factory()
            del cls.lazy_registry[name]
            cls.registry[name] = type
            return type

        return cls.registry[name]

    @classmethod
    def all(cls) -> list[type[Self]]:  # type: ignore[type-var]
        """Return every concrete subclass currently registered for *cls*.

        Example ::

            from d810.optimizers.instructions.handler import InstructionOptimizationRule
            all_instruction_rules = InstructionOptimizationRule.all()
        """
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
