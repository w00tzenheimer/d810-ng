"""Stable, IDA-free contracts for native MBA extensions.

The extension package must be able to depend on this module without loading
Hex-Rays, an optimizer manager, or a provider implementation.  Native objects
therefore cross this boundary only through the deliberately opaque
``native_context`` field.  The IDA-bound host owns that context and keeps it
immutable for the lifetime of one callback candidate.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from d810.core.typing import Protocol
from d810.mba.island_profile import (
    IslandBlocker,
    MbaIslandClass,
    MbaIslandProfile,
)
from d810.mba.typed_term import TypedBvTerm


_VALID_DESTINATION_SIZES = frozenset({1, 2, 4, 8})


def _copy_json_value(
    value: object, *, _active_containers: set[int] | None = None
) -> object:
    """Copy one JSON value into a plain, validated storage structure.

    This helper is intentionally private: the extension contract exposes the
    persistence protocol, not a second JSON implementation.  Keeping the
    value boundary here makes the host's storage implementation independent of
    caller-owned containers while remaining IDA-free.
    """

    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise TypeError("persistence values must contain finite JSON numbers")
        return value
    if isinstance(value, (Mapping, list)):
        active_containers = set() if _active_containers is None else _active_containers
        identity = id(value)
        if identity in active_containers:
            raise TypeError("persistence values must not contain cycles")
        active_containers.add(identity)
        try:
            if isinstance(value, Mapping):
                copied: dict[str, object] = {}
                for key, item in value.items():
                    if type(key) is not str:
                        raise TypeError("persistence mapping keys must be strings")
                    copied[key] = _copy_json_value(
                        item, _active_containers=active_containers
                    )
                return copied
            return [
                _copy_json_value(item, _active_containers=active_containers)
                for item in value
            ]
        finally:
            active_containers.remove(identity)
    raise TypeError("persistence value must be JSON-safe")


def _freeze_json_value(value: object) -> object:
    """Return a recursively immutable snapshot of a copied JSON value."""

    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_json_value(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json_value(item) for item in value)
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise TypeError("persistence value must be JSON-safe")


@dataclass(frozen=True, slots=True)
class NativeMbaCandidate:
    """An immutable native candidate with canonical and source terms.

    ``term`` is the canonical term used by extension algorithms.  ``raw_term``
    retains source order and is optional only for callers that intentionally
    do not expose a source representation.  ``native_context`` is opaque by
    design: portable extensions can carry it through callbacks but cannot
    inspect or construct IDA values.
    """

    destination_size: int
    term: TypedBvTerm
    raw_term: TypedBvTerm | None
    profile: MbaIslandProfile
    native_context: object

    def __post_init__(self) -> None:
        if (
            type(self.destination_size) is not int
            or self.destination_size not in _VALID_DESTINATION_SIZES
        ):
            raise ValueError("destination_size must be one of 1, 2, 4, or 8 bytes")
        if not isinstance(self.term, TypedBvTerm):
            raise TypeError("term must be a TypedBvTerm")
        expected_width = self.destination_size * 8
        if self.term.width != expected_width:
            raise ValueError("term width must match destination_size")
        if self.raw_term is not None:
            if not isinstance(self.raw_term, TypedBvTerm):
                raise TypeError("raw_term must be a TypedBvTerm or None")
            if self.raw_term.width != expected_width:
                raise ValueError("raw_term width must match destination_size")
        if not isinstance(self.profile, MbaIslandProfile):
            raise TypeError("profile must be an MbaIslandProfile")
        if self.profile.width_bits != expected_width:
            raise ValueError("profile width must match destination_size")
        if self.native_context is None:
            raise TypeError("native_context must be a non-null opaque context")


@dataclass(frozen=True, slots=True)
class NativeMbaReconstruction:
    """Native replacement AST and instruction produced by the host facade."""

    replacement_ast: object
    replacement_instruction: object

    def __post_init__(self) -> None:
        if self.replacement_ast is None:
            raise TypeError("replacement_ast must be a native object")
        if self.replacement_instruction is None:
            raise TypeError("replacement_instruction must be a native object")


class EgraphPersistenceService(Protocol):
    """Namespace-scoped JSON persistence supplied by the native host."""

    def get_json(self, key: str) -> Mapping[str, object] | None: ...

    def put_json(self, key: str, value: Mapping[str, object]) -> None: ...

    def delete(self, key: str) -> None: ...

    def keys(self, *, prefix: str = "") -> tuple[str, ...]: ...


class NativeMbaHostServices(Protocol):
    """The sole extension-facing native MBA composition facade."""

    def capture_instruction(self, instruction: object) -> NativeMbaCandidate | None: ...

    def capture_ast(
        self, ast: object, *, destination_size: int
    ) -> NativeMbaCandidate: ...

    def prepare_cross_block(
        self,
        candidate: NativeMbaCandidate,
        *,
        block: object,
        instruction: object,
        use_constants: bool,
        use_def_use: bool,
    ) -> NativeMbaCandidate: ...

    def rebuild(
        self,
        candidate: NativeMbaCandidate,
        replacement: TypedBvTerm,
    ) -> NativeMbaReconstruction | None: ...

    def prove(
        self,
        candidate: NativeMbaCandidate,
        reconstruction: NativeMbaReconstruction,
        *,
        certificate: str | None,
        known_constants: object | None,
    ) -> bool: ...

    def profile_metadata(
        self, candidate: NativeMbaCandidate
    ) -> Mapping[str, object]: ...

    def persistence(self, namespace: str) -> EgraphPersistenceService: ...


__all__ = [
    "EgraphPersistenceService",
    "IslandBlocker",
    "MbaIslandClass",
    "MbaIslandProfile",
    "NativeMbaCandidate",
    "NativeMbaHostServices",
    "NativeMbaReconstruction",
    "TypedBvTerm",
]
