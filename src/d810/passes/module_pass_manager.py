"""Module-level owner for pass registries and per-function pass managers."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from d810.capabilities.resolver import CapabilitySet
from d810.ir.maturity import IRMaturity
from d810.passes.function_pass_manager import FunctionPassManager
from d810.passes.pipeline_config_parser import require_config_v2_project
from d810.passes.operational_config_v2 import (
    CONFIG_V2_OPERATIONAL_REGISTRY_NAME,
    default_pass_registries,
)
from d810.passes.registry import PassRegistry, PassRegistryError
from d810.passes.pass_pipeline import require_pipeline_v2_specs


class ModulePassManager:
    """Own project-scope pass-manager state without importing backend adapters."""

    def __init__(
        self,
        *,
        pass_registries: Mapping[str, PassRegistry] | None = None,
        analysis_providers: Mapping[str, Callable[[object], object]] | None = None,
    ) -> None:
        self._pass_registries: dict[str, PassRegistry] = default_pass_registries()
        self._pass_registries.update(pass_registries or {})
        self._analysis_providers: dict[str, Callable[[object], object]] = dict(
            analysis_providers or {}
        )
        self._function_managers: dict[int, FunctionPassManager] = {}

    def register_pass_registry(self, name: str, registry: PassRegistry) -> None:
        """Register a pass-id registry under a project/family-local name."""
        if not name:
            raise PassRegistryError("registry name must be non-empty")
        self._pass_registries[str(name)] = registry

    def pass_registry_for(self, name: str) -> PassRegistry:
        """Return a registered pass-id registry."""
        try:
            return self._pass_registries[str(name)]
        except KeyError as exc:
            raise PassRegistryError(f"unknown pass registry: {name!r}") from exc

    def function_manager_for(self, func_ea: int) -> FunctionPassManager:
        """Return the isolated FunctionPassManager for ``func_ea``."""
        key = int(func_ea)
        manager = self._function_managers.get(key)
        if manager is None:
            manager = FunctionPassManager(
                analysis_providers=self._analysis_providers,
            )
            self._function_managers[key] = manager
        return manager

    def reset_function(self, func_ea: int) -> None:
        """Clear pass-manager state for one function only."""
        key = int(func_ea)
        manager = self._function_managers.pop(key, None)
        if manager is not None:
            manager.reset_func(key)

    def reset_project(self) -> None:
        """Clear all per-function pass-manager state."""
        for manager in self._function_managers.values():
            manager.reset_all()
        self._function_managers.clear()

    def run_function(
        self,
        *,
        source,
        family,
        backend,
        project_config,
        maturity: IRMaturity,
        capabilities: CapabilitySet | None = None,
        input_facts: object | None = None,
        analysis_seeds: Mapping[str, object] | None = None,
        pipeline_registry_name: str | None = None,
        pipeline_v2_specs=None,
    ):
        """Run one function through its isolated FunctionPassManager."""
        configs = require_config_v2_project(project_config)
        if pipeline_v2_specs is None:
            effective_registry_name = (
                pipeline_registry_name or CONFIG_V2_OPERATIONAL_REGISTRY_NAME
            )
            pipeline_registry = self.pass_registry_for(effective_registry_name)
            pipeline_v2_specs = tuple(
                pipeline_registry.build_spec(config) for config in configs
            )
        compiled_specs = require_pipeline_v2_specs(pipeline_v2_specs)
        return self.function_manager_for(source.func_ea).run(
            source=source,
            family=family,
            backend=backend,
            project_config=project_config,
            maturity=maturity,
            capabilities=capabilities,
            input_facts=input_facts,
            analysis_seeds=analysis_seeds,
            pipeline_v2_specs=compiled_specs,
        )
