"""Query-friendly metadata for unflattening and reconstruction algorithms.

The goal is to make algorithm families searchable without forcing callers to
reverse-engineer strategy names or grep for implementation details.  Metadata
is attached directly to the primary class/function implementing a technique and
registered in a lightweight in-memory index.
"""
from __future__ import annotations

from dataclasses import dataclass
from d810.core.typing import Any, Callable, Iterable, TypeVar

__all__ = [
    "AlgorithmMetadata",
    "algorithm_metadata",
    "find_algorithm_metadata",
    "get_algorithm_metadata",
    "get_algorithm_metadata_for_object",
    "iter_algorithm_metadata",
]

_DecoratedT = TypeVar("_DecoratedT")


@dataclass(frozen=True, slots=True)
class AlgorithmMetadata:
    """Describes one queryable algorithm entry point."""

    algorithm_id: str
    family: str
    summary: str
    use_cases: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    related_paths: tuple[str, ...] = ()
    module: str | None = None
    object_qualname: str | None = None


_REGISTRY: dict[str, AlgorithmMetadata] = {}
_OBJECT_INDEX: dict[str, str] = {}


def _qualname_for_object(obj: object) -> str:
    module = getattr(obj, "__module__", "")
    qualname = getattr(obj, "__qualname__", getattr(obj, "__name__", type(obj).__name__))
    if module:
        return f"{module}.{qualname}"
    return str(qualname)


def algorithm_metadata(
    *,
    algorithm_id: str,
    family: str,
    summary: str,
    use_cases: Iterable[str] = (),
    examples: Iterable[str] = (),
    tags: Iterable[str] = (),
    related_paths: Iterable[str] = (),
) -> Callable[[_DecoratedT], _DecoratedT]:
    """Decorate a class/function with searchable algorithm metadata."""

    def decorator(obj: _DecoratedT) -> _DecoratedT:
        metadata = AlgorithmMetadata(
            algorithm_id=str(algorithm_id),
            family=str(family),
            summary=str(summary),
            use_cases=tuple(str(item) for item in use_cases),
            examples=tuple(str(item) for item in examples),
            tags=tuple(str(item) for item in tags),
            related_paths=tuple(str(item) for item in related_paths),
            module=getattr(obj, "__module__", None),
            object_qualname=_qualname_for_object(obj),
        )
        _REGISTRY[metadata.algorithm_id] = metadata
        _OBJECT_INDEX[metadata.object_qualname or metadata.algorithm_id] = metadata.algorithm_id
        setattr(obj, "__algorithm_metadata__", metadata)
        return obj

    return decorator


def iter_algorithm_metadata() -> tuple[AlgorithmMetadata, ...]:
    """Return all known metadata entries in a stable order."""
    return tuple(
        sorted(
            _REGISTRY.values(),
            key=lambda meta: (meta.family, meta.algorithm_id),
        )
    )


def get_algorithm_metadata(algorithm_id: str) -> AlgorithmMetadata | None:
    """Return metadata by stable algorithm identifier."""
    return _REGISTRY.get(str(algorithm_id))


def get_algorithm_metadata_for_object(obj: object) -> AlgorithmMetadata | None:
    """Return metadata attached to *obj*, if any."""
    metadata = getattr(obj, "__algorithm_metadata__", None)
    if isinstance(metadata, AlgorithmMetadata):
        return metadata
    algorithm_id = _OBJECT_INDEX.get(_qualname_for_object(obj))
    if algorithm_id is None:
        return None
    return _REGISTRY.get(algorithm_id)


def find_algorithm_metadata(
    *,
    family: str | None = None,
    tag: str | None = None,
    search: str | None = None,
) -> tuple[AlgorithmMetadata, ...]:
    """Search metadata entries by family, tag, or free-text substring."""
    family_filter = family.casefold() if family else None
    tag_filter = tag.casefold() if tag else None
    search_filter = search.casefold() if search else None

    matches: list[AlgorithmMetadata] = []
    for metadata in iter_algorithm_metadata():
        if family_filter is not None and metadata.family.casefold() != family_filter:
            continue
        if tag_filter is not None and tag_filter not in {
            item.casefold() for item in metadata.tags
        }:
            continue
        if search_filter is not None:
            haystack = "\n".join(
                (
                    metadata.algorithm_id,
                    metadata.family,
                    metadata.summary,
                    *metadata.use_cases,
                    *metadata.examples,
                    *metadata.tags,
                    *metadata.related_paths,
                    metadata.object_qualname or "",
                )
            ).casefold()
            if search_filter not in haystack:
                continue
        matches.append(metadata)
    return tuple(matches)
