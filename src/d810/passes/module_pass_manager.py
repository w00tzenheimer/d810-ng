"""Module-level owner for pass registries and per-function pass managers."""
from __future__ import annotations

from collections.abc import Callable, Mapping

from d810.capabilities.resolver import CapabilitySet
from d810.ir.maturity import IRMaturity
from d810.passes.function_pass_manager import FunctionPassManager
from d810.passes.pipeline_config_parser import (
    pipeline_configs_from_project_config,
    pass_specs_from_project_config,
)
from d810.passes.pipeline_shadow import (
    compare_pipeline_v2_shadow,
    require_pipeline_v2_shadow_match,
)
from d810.passes.registry import PassRegistry, PassRegistryError


class ModulePassManager:
    """Own project-scope pass-manager state without importing backend adapters."""

    def __init__(
        self,
        *,
        pass_registries: Mapping[str, PassRegistry] | None = None,
        analysis_providers: Mapping[str, Callable[[object], object]] | None = None,
    ) -> None:
        self._pass_registries: dict[str, PassRegistry] = dict(pass_registries or {})
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

    def pipeline_configs_for(self, project_config):
        """Parse optional project ``pipeline_v2`` config payloads."""
        return pipeline_configs_from_project_config(project_config)

    def pass_specs_from_project_config(self, project_config, registry_name: str):
        """Build PassSpecs from project ``pipeline_v2`` using a named registry."""
        return pass_specs_from_project_config(
            project_config,
            self.pass_registry_for(registry_name),
        )

    def compare_pipeline_v2_shadow(
        self,
        project_config,
        registry_name: str,
        live_specs,
    ):
        """Compare explicit ``pipeline_v2`` config against live family specs."""
        return compare_pipeline_v2_shadow(
            project_config=project_config,
            registry=self.pass_registry_for(registry_name),
            live_specs=tuple(live_specs),
        )

    def require_pipeline_v2_shadow_match(
        self,
        project_config,
        registry_name: str,
        live_specs,
    ):
        """Fail loud when explicit ``pipeline_v2`` config drifts from live specs."""
        return require_pipeline_v2_shadow_match(
            project_config=project_config,
            registry=self.pass_registry_for(registry_name),
            live_specs=tuple(live_specs),
        )

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
        require_pipeline_v2_shadow_match: bool = False,
    ):
        """Run one function through its isolated FunctionPassManager."""
        pipeline_registry = None
        if require_pipeline_v2_shadow_match:
            if pipeline_registry_name is None:
                raise PassRegistryError(
                    "pipeline_v2 shadow enforcement requires a registry name"
                )
            pipeline_registry = self.pass_registry_for(pipeline_registry_name)
        return self.function_manager_for(source.func_ea).run(
            source=source,
            family=family,
            backend=backend,
            project_config=project_config,
            maturity=maturity,
            capabilities=capabilities,
            input_facts=input_facts,
            analysis_seeds=analysis_seeds,
            pipeline_v2_shadow_registry=pipeline_registry,
            require_pipeline_v2_shadow_match=require_pipeline_v2_shadow_match,
        )
