from __future__ import annotations

from d810.capabilities.plugin_host import PluginHostCapabilityRegistry
from d810.core.plugins import (
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    PassImplementationRequirement,
)
from d810.core.typing import Protocol
from d810.manager.pass_implementation_availability import (
    project_pass_implementation_availability,
)
from d810.manager.workbench_recipe_models import PassImplementationStatus


class ExampleService(Protocol):
    def execute(self, value: int) -> str: ...


class ExampleServiceImpl:
    def execute(self, value: int) -> str:
        return str(value)


def test_missing_host_requirement_is_reported_without_loading_plugin_runtime() -> None:
    loaded = False

    def provides():
        nonlocal loaded
        loaded = True
        return object()

    host = PluginHostCapabilityRegistry()
    manifest = BackendManifest(
        name="example",
        api_version=1,
        provides=provides,
        requires=("example.missing.v1",),
        implements={"example-pass": "example-implementation"},
    )
    backends = BackendRegistry(
        source=lambda: (
            BackendSpec(
                name="example",
                load_manifest=lambda: manifest,
                origin="example-wheel",
            ),
        ),
        host=host,
        requirement_validator=host.validate,
    )

    availability = project_pass_implementation_availability(
        "example-pass",
        PassImplementationRequirement(
            distribution="example-package",
            backend_name="example",
        ),
        backends,
    )

    assert availability is not None
    assert availability.status is PassImplementationStatus.UNAVAILABLE
    assert "missing host capability: example.missing.v1" in availability.detail
    assert loaded is False


def test_ambiguous_declarations_validate_every_exact_manifest() -> None:
    validated: list[tuple[str, ...]] = []
    host = PluginHostCapabilityRegistry()

    def validate(requirements):
        validated.append(tuple(requirements))
        host.validate(requirements)

    manifests = tuple(
        BackendManifest(
            name=name,
            api_version=1,
            provides=lambda: object(),
            requires=(f"example.{name}.v1",),
            implements={"example-pass": f"{name}-implementation"},
        )
        for name in ("first", "second")
    )
    backends = BackendRegistry(
        source=lambda: tuple(
            BackendSpec(
                name=manifest.name,
                load_manifest=lambda manifest=manifest: manifest,
                origin=f"{manifest.name}-wheel",
            )
            for manifest in manifests
        ),
        host=host,
        requirement_validator=validate,
    )

    availability = project_pass_implementation_availability(
        "example-pass",
        PassImplementationRequirement("example-package", "first"),
        backends,
    )

    assert availability is not None
    assert availability.status is PassImplementationStatus.AMBIGUOUS
    assert availability.backend_names == ("first", "second")
    assert validated == [("example.first.v1",), ("example.second.v1",)]


def test_same_name_candidates_preserve_origin_and_validate_each_manifest() -> None:
    validated: list[tuple[str, ...]] = []
    host = PluginHostCapabilityRegistry()
    host.register("example.available.v1", ExampleService, ExampleServiceImpl())

    def validate(requirements):
        validated.append(tuple(requirements))
        host.validate(requirements)

    preferred = BackendManifest(
        name="example",
        api_version=1,
        provides=lambda: object(),
        requires=("example.missing.v1",),
        implements={"example-pass": "preferred-implementation"},
    )
    fallback = BackendManifest(
        name="example",
        api_version=1,
        provides=lambda: object(),
        requires=("example.available.v1",),
        implements={"example-pass": "fallback-implementation"},
    )
    backends = BackendRegistry(
        source=lambda: (
            BackendSpec(
                name="example",
                load_manifest=lambda: preferred,
                origin="preferred-wheel",
            ),
        ),
        builtins=(
            BackendSpec(
                name="example",
                load_manifest=lambda: fallback,
                origin="builtin",
            ),
        ),
        host=host,
        requirement_validator=validate,
    )

    declarations = backends.implementation_declarations_for("example-pass")
    availability = project_pass_implementation_availability(
        "example-pass",
        PassImplementationRequirement("example-package", "example"),
        backends,
    )

    assert tuple(declaration[0].backend_origin for declaration in declarations) == (
        "builtin",
        "preferred-wheel",
    )
    assert availability is not None
    assert availability.status is PassImplementationStatus.AMBIGUOUS
    assert availability.backend_names == ("example", "example")
    assert validated == [
        ("example.available.v1",),
        ("example.missing.v1",),
    ]
