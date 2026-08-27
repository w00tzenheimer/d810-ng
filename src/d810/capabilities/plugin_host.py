"""Host-owned capability registry for activated plugins."""

from __future__ import annotations

from dataclasses import dataclass
from d810.core.plugins import BackendUnavailable, PluginHostCapabilities
from d810.core.typing import Any, Sequence, TypeVar

__all__ = [
    "PluginCapabilityAccessError",
    "PluginHostCapabilityRegistry",
]


C = TypeVar("C")


class PluginCapabilityAccessError(BackendUnavailable):
    """A plugin requested an unavailable or undeclared host capability."""


def _required_callable_members(protocol: type[Any]) -> tuple[str, ...]:
    """Return callable members a non-runtime-checkable protocol requires."""
    members: set[str] = set()
    for base in reversed(getattr(protocol, "__mro__", (protocol,))):
        for name, member in vars(base).items():
            if not name.startswith("_") and callable(member):
                members.add(name)
    return tuple(sorted(members))


def _service_matches_protocol(protocol: type[Any], service: object) -> bool:
    """Check a service without invoking ``isinstance`` on non-runtime Protocols."""
    if getattr(protocol, "_is_protocol", False) and getattr(
        protocol, "_is_runtime_protocol", False
    ):
        return isinstance(service, protocol)
    return all(
        callable(getattr(service, member, None))
        for member in _required_callable_members(protocol)
    )


def _validate_capability_id(capability_id: str) -> str:
    if not isinstance(capability_id, str):
        raise TypeError("capability ID must be a string")
    if (
        not capability_id
        or "." not in capability_id
        or any(not part for part in capability_id.split("."))
        or any(char.isspace() for char in capability_id)
    ):
        raise ValueError(f"invalid capability ID: {capability_id!r}")
    return capability_id


class PluginHostCapabilityRegistry(PluginHostCapabilities):
    """Authoritative stable-ID to typed-service mapping owned by D810."""

    __slots__ = ("_by_id", "_id_by_protocol")

    def __init__(self) -> None:
        self._by_id: dict[str, tuple[type[Any], object]] = {}
        self._id_by_protocol: dict[type[Any], str] = {}

    def register(self, capability_id: str, protocol: type[C], service: C) -> None:
        """Register one stable capability ID and its typed service instance."""
        capability_id = _validate_capability_id(capability_id)
        if capability_id in self._by_id:
            raise ValueError(f"capability ID {capability_id!r} is already registered")
        if protocol in self._id_by_protocol:
            raise ValueError(f"capability protocol {protocol!r} is already registered")
        if not _service_matches_protocol(protocol, service):
            name = getattr(protocol, "__name__", repr(protocol))
            raise TypeError(
                f"service for capability {capability_id!r} does not implement {name}"
            )
        self._by_id[capability_id] = (protocol, service)
        self._id_by_protocol[protocol] = capability_id

    def validate(self, requirements: Sequence[str]) -> None:
        """Validate manifest requirement IDs before a provider is resolved."""
        for requirement in requirements:
            capability_id = _validate_capability_id(requirement)
            if capability_id not in self._by_id:
                raise PluginCapabilityAccessError(
                    f"missing host capability: {capability_id}"
                )

    def require(self, capability: type[C]) -> C:
        """Resolve a registered service from the unrestricted host view."""
        try:
            _protocol, service = self._by_id[self._id_by_protocol[capability]]
        except KeyError as exc:
            name = getattr(capability, "__name__", repr(capability))
            raise PluginCapabilityAccessError(
                f"host capability {name!r} is not registered"
            ) from exc
        return service  # type: ignore[return-value]

    def optional(self, capability: type[C]) -> C | None:
        """Resolve a registered service, returning ``None`` when absent."""
        capability_id = self._id_by_protocol.get(capability)
        if capability_id is None:
            return None
        return self._by_id[capability_id][1]  # type: ignore[return-value]

    def view_for(self, requirements: Sequence[str]) -> PluginHostCapabilities:
        """Return an immutable host view limited to declared requirement IDs."""
        declared = tuple(requirements)
        self.validate(declared)
        return _PluginHostCapabilityView(self, declared)

    def _require_declared(self, capability: type[C], declared: tuple[str, ...]) -> C:
        capability_id = self._id_by_protocol.get(capability)
        if capability_id is None:
            name = getattr(capability, "__name__", repr(capability))
            raise PluginCapabilityAccessError(
                f"host capability {name!r} is not registered"
            )
        if capability_id not in declared:
            raise PluginCapabilityAccessError(
                f"host capability {capability_id!r} is not declared"
            )
        return self.require(capability)


@dataclass(frozen=True, slots=True)
class _PluginHostCapabilityView(PluginHostCapabilities):
    _registry: PluginHostCapabilityRegistry
    requirements: tuple[str, ...]

    def require(self, capability: type[C]) -> C:
        return self._registry._require_declared(capability, self.requirements)

    def optional(self, capability: type[C]) -> C | None:
        capability_id = self._registry._id_by_protocol.get(capability)
        if capability_id is None or capability_id not in self.requirements:
            return None
        return self._registry.optional(capability)
