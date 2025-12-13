"""
d810.typing: Compatibility typing imports for d810 plugins and integration.

This module provides imports and unified access to typing symbols
used throughout the d810 project. It wraps Python's built-in typing module
and selected backports (e.g., typing_extensions) to ensure consistent
availability of type hints and protocols across different Python versions
used in IDA Pro environments.

Use d810.typing instead of directly importing from typing or typing_extensions in plugin code.
All exported names are explicitly added to __all__.
"""

# isort: skip_file
from __future__ import annotations
import sys

# taken from: https://github.com/python/cpython/blob/3.10/Lib/typing.py
from typing import (
    # Super-special typing primitives.
    Annotated,
    Any,
    Callable,
    ClassVar,
    Concatenate,
    Final,
    ForwardRef,
    Generic,
    Literal,
    Optional,
    ParamSpec,
    Protocol,
    Tuple,
    Type,
    TypeVar,
    Union,
    # ABCs (from collections.abc).
    AbstractSet,  # collections.abc.Set.
    ByteString,
    Container,
    ContextManager,
    Hashable,
    ItemsView,
    Iterable,
    Iterator,
    KeysView,
    Mapping,
    MappingView,
    MutableMapping,
    MutableSequence,
    MutableSet,
    Sequence,
    Sized,
    ValuesView,
    Awaitable,
    AsyncIterator,
    AsyncIterable,
    Coroutine,
    Collection,
    AsyncGenerator,
    AsyncContextManager,
    # Structural checks, a.k.a. protocols.
    Reversible,
    SupportsAbs,
    SupportsBytes,
    SupportsComplex,
    SupportsFloat,
    SupportsIndex,
    SupportsInt,
    SupportsRound,
    # Concrete collection types.
    ChainMap,
    Counter,
    Deque,
    Dict,
    DefaultDict,
    List,
    OrderedDict,
    Set,
    FrozenSet,
    NamedTuple,  # Not really a type.
    TypedDict,  # Not really a type.
    Generator,
    # Other concrete types.
    BinaryIO,
    IO,
    Match,
    Pattern,
    TextIO,
    # One-off things.
    AnyStr,
    cast,
    final,
    get_args,
    get_origin,
    get_type_hints,
    is_typeddict,
    NewType,
    no_type_check,
    no_type_check_decorator,
    NoReturn,
    overload,
    ParamSpecArgs,
    ParamSpecKwargs,
    runtime_checkable,
    Text,
    TYPE_CHECKING,
    TypeAlias,
    TypeGuard,
)


# Multiple python version compatible import for typing.override
if sys.version_info >= (3, 11):
    from typing import Self  # noqa: F401
    from typing import NotRequired  # noqa: F401
    from typing import LiteralString  # noqa: F401

if sys.version_info >= (3, 12):
    from typing import override  # noqa: F401
    from typing import TypeAliasType  # noqa: F401


if sys.version_info.major == 3 and sys.version_info.minor in (10, 11):
    # Multiple python version compatible import for override, TypeAliasType, Self, NotRequired, LiteralString
    if sys.version_info.minor <= 11:
        from d810._vendor.typing_extensions import override  # noqa: F401
        from d810._vendor.typing_extensions import TypeAliasType  # noqa: F401
    if sys.version_info.minor == 10:
        from d810._vendor.typing_extensions import Self  # noqa: F401
        from d810._vendor.typing_extensions import NotRequired  # noqa: F401
        from d810._vendor.typing_extensions import LiteralString  # noqa: F401


# Please keep __all__ alphabetized within each category.
__all__ = [
    # Super-special typing primitives.
    "Annotated",
    "Any",
    "Callable",
    "ClassVar",
    "Concatenate",
    "Final",
    "ForwardRef",
    "Generic",
    "Literal",
    "Optional",
    "ParamSpec",
    "Protocol",
    "Tuple",
    "Type",
    "TypeVar",
    "Union",
    # ABCs (from collections.abc).
    "AbstractSet",  # collections.abc.Set.
    "ByteString",
    "Container",
    "ContextManager",
    "Hashable",
    "ItemsView",
    "Iterable",
    "Iterator",
    "KeysView",
    "Mapping",
    "MappingView",
    "MutableMapping",
    "MutableSequence",
    "MutableSet",
    "Sequence",
    "Sized",
    "ValuesView",
    "Awaitable",
    "AsyncIterator",
    "AsyncIterable",
    "Coroutine",
    "Collection",
    "AsyncGenerator",
    "AsyncContextManager",
    # Structural checks, a.k.a. protocols.
    "Reversible",
    "SupportsAbs",
    "SupportsBytes",
    "SupportsComplex",
    "SupportsFloat",
    "SupportsIndex",
    "SupportsInt",
    "SupportsRound",
    # Concrete collection types.
    "ChainMap",
    "Counter",
    "Deque",
    "Dict",
    "DefaultDict",
    "List",
    "OrderedDict",
    "Set",
    "FrozenSet",
    "NamedTuple",  # Not really a type.
    "TypedDict",  # Not really a type.
    "Generator",
    # Other concrete types.
    "BinaryIO",
    "IO",
    "Match",
    "Pattern",
    "TextIO",
    # One-off things.
    "AnyStr",
    "cast",
    "final",
    "get_args",
    "get_origin",
    "get_type_hints",
    "is_typeddict",
    "NewType",
    "no_type_check",
    "no_type_check_decorator",
    "NoReturn",
    "overload",
    "ParamSpecArgs",
    "ParamSpecKwargs",
    "runtime_checkable",
    "Text",
    "TYPE_CHECKING",
    "TypeAlias",
    "TypeGuard",
] + [
    "override",
    "TypeAliasType",
    "Self",
    "NotRequired",
    "LiteralString",
]
