from __future__ import annotations

from d810.capabilities.plugin_host import PluginHostCapabilityRegistry
from d810.core.plugins import (
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    PassImplementationRequirement,
)
from d810.manager.pass_implementation_availability import (
    project_pass_implementation_availability,
)
from d810.manager.workbench_recipe_models import PassImplementationStatus


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
