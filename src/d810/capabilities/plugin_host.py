"""Host-owned capability registry for activated plugins."""

from __future__ import annotations

from dataclasses import dataclass
import threading
from types import MappingProxyType
from d810.core.plugins import (
    BackendUnavailable,
    PluginHostCapabilities,
    PluginIdentity,
)
from d810.core.typing import Any, Callable, Mapping, Sequence, TypeVar

__all__ = [
    "CapabilityRegistrationLease",
    "PluginCapabilityAccessError",
    "PluginHostCapabilityRegistry",
]


C = TypeVar("C")


class PluginCapabilityAccessError(BackendUnavailable):
    """A plugin requested an unavailable or undeclared host capability."""


class CapabilityRegistrationLease:
    """Identity-bound, idempotent ownership of one registry registration."""

    __slots__ = (
        "_registry",
        "_capability_id",
        "_protocol",
        "_token",
        "_lock",
        "_released",
    )

    def __init__(self, registry, capability_id, protocol, token) -> None:
        self._registry = registry
        self._capability_id = capability_id
        self._protocol = protocol
        self._token = token
        self._lock = threading.Lock()
        self._released = False

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._registry._release(self._capability_id, self._protocol, self._token)

    close = release


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

    __slots__ = ("_by_id", "_id_by_protocol", "_lock")

    def __init__(self) -> None:
        self._by_id: dict[
            str,
            tuple[
                type[Any],
                object,
                object,
                Callable[[PluginIdentity], object] | None,
            ],
        ] = {}
        self._id_by_protocol: dict[type[Any], str] = {}
        self._lock = threading.RLock()

    def register(
        self,
        capability_id: str,
        protocol: type[C],
        service: C,
        *,
        activation_binder: Callable[[PluginIdentity], C] | None = None,
    ) -> CapabilityRegistrationLease:
        """Register one stable capability ID and its typed service instance."""
        capability_id = _validate_capability_id(capability_id)
        if activation_binder is not None and not callable(activation_binder):
            raise TypeError("activation_binder must be callable")
        with self._lock:
            if capability_id in self._by_id:
                raise ValueError(
                    f"capability ID {capability_id!r} is already registered"
                )
            if protocol in self._id_by_protocol:
                raise ValueError(
                    f"capability protocol {protocol!r} is already registered"
                )
        if not _service_matches_protocol(protocol, service):
            name = getattr(protocol, "__name__", repr(protocol))
            raise TypeError(
                f"service for capability {capability_id!r} does not implement {name}"
            )
        with self._lock:
            if capability_id in self._by_id:
                raise ValueError(
                    f"capability ID {capability_id!r} is already registered"
                )
            if protocol in self._id_by_protocol:
                raise ValueError(
                    f"capability protocol {protocol!r} is already registered"
                )
            token = object()
            self._by_id[capability_id] = (
                protocol,
                service,
                token,
                activation_binder,
            )
            self._id_by_protocol[protocol] = capability_id
        return CapabilityRegistrationLease(self, capability_id, protocol, token)

    def _release(self, capability_id: str, protocol: type[Any], token: object) -> None:
        with self._lock:
            current = self._by_id.get(capability_id)
            if current is None or current[0] is not protocol or current[2] is not token:
                return
            del self._by_id[capability_id]
            if self._id_by_protocol.get(protocol) == capability_id:
                del self._id_by_protocol[protocol]

    def validate(self, requirements: Sequence[str]) -> None:
        """Validate manifest requirement IDs before a provider is resolved."""
        with self._lock:
            for requirement in requirements:
                capability_id = _validate_capability_id(requirement)
                if capability_id not in self._by_id:
                    raise PluginCapabilityAccessError(
                        f"missing host capability: {capability_id}"
                    )

    def require(self, capability: type[C]) -> C:
        """Resolve a registered service from the unrestricted host view."""
        with self._lock:
            try:
                _protocol, service, _token, binder = self._by_id[
                    self._id_by_protocol[capability]
                ]
            except KeyError as exc:
                name = getattr(capability, "__name__", repr(capability))
                raise PluginCapabilityAccessError(
                    f"host capability {name!r} is not registered"
                ) from exc
            if binder is not None:
                raise PluginCapabilityAccessError(
                    "activation-bound host capability requires an activation view"
                )
            return service  # type: ignore[return-value]

    def optional(self, capability: type[C]) -> C | None:
        """Resolve a registered service, returning ``None`` when absent."""
        with self._lock:
            capability_id = self._id_by_protocol.get(capability)
            if capability_id is None:
                return None
            if self._by_id[capability_id][3] is not None:
                raise PluginCapabilityAccessError(
                    "activation-bound host capability requires an activation view"
                )
            return self._by_id[capability_id][1]  # type: ignore[return-value]

    def view_for(
        self, requirements: Sequence[str], identity: PluginIdentity
    ) -> PluginHostCapabilities:
        """Return an activation-scoped view limited to declared requirements."""
        if not isinstance(identity, PluginIdentity):
            raise TypeError("host capability views require a PluginIdentity")
        declared = tuple(requirements)
        self.validate(declared)
        with self._lock:
            snapshots = []
            seen_ids: set[str] = set()
            for capability_id in declared:
                if capability_id in seen_ids:
                    continue
                seen_ids.add(capability_id)
                protocol, service, token, binder = self._by_id[capability_id]
                snapshots.append((capability_id, protocol, service, token, binder))
        bound: dict[type[Any], object] = {}
        for capability_id, protocol, service, token, binder in snapshots:
            value = binder(identity) if binder is not None else service
            if not _service_matches_protocol(protocol, value):
                name = getattr(protocol, "__name__", repr(protocol))
                raise TypeError(
                    f"bound service for capability {capability_id!r} does not implement {name}"
                )
            bound[protocol] = value
        with self._lock:
            for capability_id, protocol, service, token, binder in snapshots:
                current = self._by_id.get(capability_id)
                if (
                    current is None
                    or current[0] is not protocol
                    or current[1] is not service
                    or current[2] is not token
                    or current[3] is not binder
                ):
                    raise PluginCapabilityAccessError(
                        "host capability registration changed during activation view construction"
                    )
        return _PluginHostCapabilityView(
            self,
            declared,
            identity,
            MappingProxyType(bound),
        )


@dataclass(frozen=True, slots=True)
class _PluginHostCapabilityView(PluginHostCapabilities):
    _registry: PluginHostCapabilityRegistry
    requirements: tuple[str, ...]
    _identity: PluginIdentity
    _bound: Mapping[type[Any], object]

    def require(self, capability: type[C]) -> C:
        if capability not in self._bound:
            raise PluginCapabilityAccessError(
                "host capability is not declared in this activation view"
            )
        return self._bound[capability]  # type: ignore[return-value]

    def optional(self, capability: type[C]) -> C | None:
        return self._bound.get(capability)  # type: ignore[return-value]
