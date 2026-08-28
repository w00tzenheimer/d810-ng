from __future__ import annotations

import threading

import pytest

from d810.capabilities.plugin_host import (
    PluginCapabilityAccessError,
    PluginHostCapabilityRegistry,
)
from d810.core.plugins import PluginIdentity
from d810.core.typing import Protocol, runtime_checkable


@runtime_checkable
class ExampleService(Protocol):
    def execute(self, value: int) -> str: ...


class ExampleServiceImpl:
    def execute(self, value: int) -> str:
        return str(value)


class OtherService(Protocol):
    def inspect(self) -> str: ...


class IncompleteService:
    pass


def test_registry_rejects_duplicate_capability_id() -> None:
    registry = PluginHostCapabilityRegistry()
    registry.register("example.service.v1", ExampleService, ExampleServiceImpl())

    with pytest.raises(ValueError, match="already registered"):
        registry.register("example.service.v1", OtherService, object())


def test_registry_rejects_duplicate_protocol() -> None:
    registry = PluginHostCapabilityRegistry()
    registry.register("example.service.v1", ExampleService, ExampleServiceImpl())

    with pytest.raises(ValueError, match="already registered"):
        registry.register("other.service.v1", ExampleService, ExampleServiceImpl())


def test_registry_rejects_protocol_service_mismatch() -> None:
    registry = PluginHostCapabilityRegistry()

    with pytest.raises(TypeError, match="does not implement"):
        registry.register("example.service.v1", ExampleService, IncompleteService())


def test_plugin_view_resolves_required_and_optional_service() -> None:
    service = ExampleServiceImpl()
    registry = PluginHostCapabilityRegistry()
    registry.register("example.service.v1", ExampleService, service)
    view = registry.view_for(
        ("example.service.v1",), PluginIdentity("example", None, None, "test")
    )

    assert view.require(ExampleService) is service
    assert view.optional(ExampleService) is service


def test_activation_view_binds_services_to_host_identity() -> None:
    class BoundService:
        def __init__(self):
            self.identities = []

        def execute(self, value: int) -> str:
            return str(value)

        def bind_activation(self, identity):
            self.identities.append(identity)
            return (identity, self)

    service = BoundService()
    registry = PluginHostCapabilityRegistry()
    registry.register("example.service.v1", ExampleService, service)
    identity = PluginIdentity("example", "example", "1", "origin")
    view = registry.view_for(("example.service.v1",), identity)

    assert view.require(ExampleService) == (identity, service)
    assert service.identities == [identity]


def test_plugin_view_returns_none_for_optional_missing_service() -> None:
    registry = PluginHostCapabilityRegistry()
    view = registry.view_for((), PluginIdentity("example", None, None, "test"))

    assert view.optional(ExampleService) is None


def test_plugin_view_rejects_access_to_undeclared_host_service() -> None:
    registry = PluginHostCapabilityRegistry()
    registry.register("example.service.v1", ExampleService, ExampleServiceImpl())
    view = registry.view_for((), PluginIdentity("example", None, None, "test"))

    with pytest.raises(PluginCapabilityAccessError, match="not declared"):
        view.require(ExampleService)


def test_registration_lease_is_idempotent_and_cannot_release_new_owner() -> None:
    registry = PluginHostCapabilityRegistry()
    first = registry.register(
        "example.service.v1", ExampleService, ExampleServiceImpl()
    )
    first.release()
    first.close()
    second = registry.register(
        "example.service.v1", ExampleService, ExampleServiceImpl()
    )
    first.release()
    assert registry.require(ExampleService) is not None
    second.release()
    with pytest.raises(PluginCapabilityAccessError, match="not registered"):
        registry.require(ExampleService)


def test_duplicate_live_owner_is_rejected_until_lease_release() -> None:
    registry = PluginHostCapabilityRegistry()
    lease = registry.register(
        "example.service.v1", ExampleService, ExampleServiceImpl()
    )
    with pytest.raises(ValueError, match="already registered"):
        registry.register("example.service.v1", ExampleService, ExampleServiceImpl())
    lease.release()


def test_concurrent_view_reads_and_release_are_safe() -> None:
    registry = PluginHostCapabilityRegistry()
    lease = registry.register(
        "example.service.v1", ExampleService, ExampleServiceImpl()
    )
    view = registry.view_for(
        ("example.service.v1",), PluginIdentity("example", None, None, "test")
    )
    failures = []

    def read_view() -> None:
        try:
            for _ in range(100):
                service = view.optional(ExampleService)
                if service is not None:
                    service.execute(1)
        except BaseException as exc:  # pragma: no cover - assertion below
            failures.append(exc)

    reader = threading.Thread(target=read_view)
    reader.start()
    lease.release()
    reader.join(timeout=1)
    assert not reader.is_alive()
    assert failures == []


def test_plugin_view_is_immutable_and_copies_requirements() -> None:
    registry = PluginHostCapabilityRegistry()
    registry.register("example.service.v1", ExampleService, ExampleServiceImpl())
    requirements = ["example.service.v1"]
    view = registry.view_for(
        requirements, PluginIdentity("example", None, None, "test")
    )
    requirements.clear()

    assert view.require(ExampleService).execute(7) == "7"
    with pytest.raises(AttributeError):
        view.requirements = ()  # type: ignore[attr-defined]


def test_registry_validator_reports_missing_capability_id() -> None:
    registry = PluginHostCapabilityRegistry()

    with pytest.raises(
        PluginCapabilityAccessError, match="missing host capability: missing.service.v1"
    ):
        registry.validate(("missing.service.v1",))
