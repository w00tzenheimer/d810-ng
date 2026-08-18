"""Portable runtime-identity and package-resource digest helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.machinery
from importlib import resources
import json
from pathlib import Path, PurePosixPath
from types import ModuleType


class RuntimeSemanticsUnavailable(OSError):
    """The active runtime cannot provide a verifiable implementation identity."""


@dataclass(frozen=True, slots=True)
class NativeMatcherRuntimeIdentity:
    """Identity of the POD matcher implementation actually selected at import."""

    pod_backend: str
    implementation: str
    artifact_identity: str

    def __post_init__(self) -> None:
        if self.pod_backend not in {"python", "cython"}:
            raise ValueError("pod_backend must be python or cython")
        if type(self.implementation) is not str or not self.implementation:
            raise ValueError("implementation must be a non-empty string")
        if type(self.artifact_identity) is not str:
            raise ValueError("artifact_identity must be a string")

    def payload(self) -> dict[str, str]:
        """Return the stable identity fields included in the digest."""

        return {
            "pod_backend": self.pod_backend,
            "implementation": self.implementation,
            "artifact_identity": self.artifact_identity,
        }


def loaded_extension_artifact_identity(module: ModuleType) -> str:
    """Hash the loaded extension file, failing closed for opaque modules."""

    origin = getattr(module, "__file__", None)
    if not isinstance(origin, str) or not origin:
        spec = getattr(module, "__spec__", None)
        origin = getattr(spec, "origin", None)
    suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    if (
        not isinstance(origin, str)
        or not origin
        or origin in {"built-in", "frozen"}
        or not origin.endswith(suffixes)
    ):
        raise RuntimeSemanticsUnavailable(
            "active Cython POD matcher has no opaque extension artifact"
        )
    path = Path(origin)
    try:
        artifact_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise RuntimeSemanticsUnavailable(
            f"active Cython POD matcher artifact is unreadable: {path}"
        ) from exc
    module_name = getattr(module, "__name__", None)
    if type(module_name) is not str or not module_name:
        raise RuntimeSemanticsUnavailable(
            "active Cython POD matcher artifact has no module identity"
        )
    return f"{module_name}:{path.name}:{artifact_digest}"


def _manifest(package_name: str) -> tuple[str, ...]:
    try:
        payload = json.loads(
            resources.files(package_name)
            .joinpath("runtime_semantics_manifest.json")
            .read_text(encoding="utf-8")
        )
    except (ModuleNotFoundError, OSError, TypeError, ValueError) as exc:
        raise RuntimeSemanticsUnavailable(
            f"runtime semantics manifest unavailable for {package_name}"
        ) from exc
    if type(payload) is not dict or payload.get("schema_version") != 1:
        raise RuntimeSemanticsUnavailable("runtime semantics manifest has invalid schema")
    source_names = payload.get("runtime_sources")
    if type(source_names) is not list or not source_names:
        raise RuntimeSemanticsUnavailable(
            "runtime semantics manifest has no source resources"
        )
    validated: list[str] = []
    for source_name in source_names:
        if type(source_name) is not str or not source_name:
            raise RuntimeSemanticsUnavailable(
                "runtime semantics manifest has an invalid source resource"
            )
        path = PurePosixPath(source_name)
        if path.is_absolute() or ".." in path.parts:
            raise RuntimeSemanticsUnavailable(
                "runtime semantics manifest contains an unsafe resource path"
            )
        validated.append(source_name)
    return tuple(validated)


def runtime_semantics_digest(
    identity: NativeMatcherRuntimeIdentity,
    *,
    package_name: str = "d810",
) -> str:
    """Digest packaged runtime sources plus the active POD artifact identity."""

    if not isinstance(identity, NativeMatcherRuntimeIdentity):
        raise TypeError("identity must be a NativeMatcherRuntimeIdentity")
    if not identity.artifact_identity:
        raise RuntimeSemanticsUnavailable(
            "active POD matcher has no artifact identity"
        )
    try:
        package_root = resources.files(package_name)
    except (ModuleNotFoundError, OSError, TypeError) as exc:
        raise RuntimeSemanticsUnavailable(
            f"runtime semantics package unavailable for {package_name}"
        ) from exc
    digest = hashlib.sha256()
    digest.update(b"d810-runtime-semantics-v2\0")
    digest.update(
        json.dumps(
            identity.payload(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
    )
    digest.update(b"\0")
    for source_name in _manifest(package_name):
        source_path = package_root.joinpath(*PurePosixPath(source_name).parts)
        try:
            source_bytes = source_path.read_bytes()
        except OSError as exc:
            raise RuntimeSemanticsUnavailable(
                f"runtime semantics source resource unavailable: {source_name}"
            ) from exc
        digest.update(source_name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source_bytes)
        digest.update(b"\0")
    return digest.hexdigest()


__all__ = [
    "NativeMatcherRuntimeIdentity",
    "RuntimeSemanticsUnavailable",
    "loaded_extension_artifact_identity",
    "runtime_semantics_digest",
]
