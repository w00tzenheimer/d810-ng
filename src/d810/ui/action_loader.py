"""Dynamic action discovery/instantiation for d810-ng UI actions.

This loader discovers action modules from ``d810.ui.actions`` and instantiates
``D810ActionHandler`` implementations with dependency injection.
"""
from __future__ import annotations

import importlib.util
import inspect
import pkgutil
import sys
from types import ModuleType
from d810.core.typing import Any

from d810.core.logging import getLogger
from d810.ui import actions
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")

_SKIP_MODULES = frozenset(
    {
        "base",
        "ida_handler",
        "predicates",
    }
)


class ActionLoader:
    """Discovers and instantiates context-menu action handlers."""

    def __init__(self) -> None:
        self._loaded_modules: list[str] = []
        self._action_instances: list[D810ActionHandler] = []

    def load_actions(
        self,
        state: Any,
        ida_modules: dict[str, Any] | None = None,
    ) -> list[D810ActionHandler]:
        """Load action modules and instantiate action handlers."""
        self._loaded_modules.clear()
        self._action_instances.clear()

        seen_action_ids: set[str] = set()
        for mod_info in pkgutil.walk_packages(
            actions.__path__, prefix=f"{actions.__name__}."
        ):
            if mod_info.ispkg:
                continue

            module_basename = mod_info.name.rsplit(".", 1)[-1]
            if module_basename in _SKIP_MODULES or module_basename.endswith("_logic"):
                continue

            module = self._safe_import_module(mod_info)
            if module is None:
                continue

            for action in self._build_actions_from_module(
                module, state=state, ida_modules=ida_modules
            ):
                action_id = getattr(action, "ACTION_ID", "")
                if not action_id:
                    logger.warning("Skipping action with empty ACTION_ID in %s", module.__name__)
                    continue
                if action_id in seen_action_ids:
                    logger.warning("Duplicate action id %s from %s", action_id, module.__name__)
                    continue
                seen_action_ids.add(action_id)
                self._action_instances.append(action)

        return list(self._action_instances)

    def unload_actions(self) -> int:
        """Unload instantiated actions by calling ``term`` when available."""
        action_count = 0
        for action in reversed(self._action_instances):
            term = getattr(action, "term", None)
            if callable(term):
                try:
                    term()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Action teardown failed for %r: %s", action, exc)
            action_count += 1

        self._action_instances.clear()
        self._loaded_modules.clear()
        return action_count

    @property
    def action_instances(self) -> list[D810ActionHandler]:
        return list(self._action_instances)

    def _safe_import_module(self, mod_info: pkgutil.ModuleInfo) -> ModuleType | None:
        """Import action module with extension-style fault tolerance."""
        spec = mod_info.module_finder.find_spec(mod_info.name)
        if spec is None or spec.loader is None:
            logger.warning("Skipping %s: no import spec/loader", mod_info.name)
            return None

        if mod_info.name in sys.modules:
            module = sys.modules[mod_info.name]
            self._loaded_modules.append(module.__name__)
            return module

        module = importlib.util.module_from_spec(spec)
        sys.modules[module.__name__] = module
        try:
            spec.loader.exec_module(module)
        except BaseException as exc:  # noqa: BLE001
            sys.modules.pop(module.__name__, None)
            logger.warning("Error while loading extension %s: %s", mod_info.name, exc)
            return None

        self._loaded_modules.append(module.__name__)
        return module

    def _build_actions_from_module(
        self,
        module: ModuleType,
        state: Any,
        ida_modules: dict[str, Any] | None,
    ) -> list[D810ActionHandler]:
        """Build action instances from module using factory or class discovery."""
        actions_from_module: list[D810ActionHandler] = []

        if hasattr(module, "get_action"):
            try:
                action_or_cls = module.get_action()
                action = self._instantiate_action(
                    action_or_cls, state=state, ida_modules=ida_modules
                )
                if action is not None:
                    actions_from_module.append(action)
            except Exception as exc:  # noqa: BLE001
                logger.warning("get_action() failed in %s: %s", module.__name__, exc)
            return actions_from_module

        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module.__name__:
                continue
            if not issubclass(obj, D810ActionHandler) or obj is D810ActionHandler:
                continue
            action = self._instantiate_action(obj, state=state, ida_modules=ida_modules)
            if action is not None:
                actions_from_module.append(action)

        return actions_from_module

    @staticmethod
    def _instantiate_action(
        action_or_cls: Any,
        state: Any,
        ida_modules: dict[str, Any] | None,
    ) -> D810ActionHandler | None:
        if isinstance(action_or_cls, D810ActionHandler):
            return action_or_cls

        if inspect.isclass(action_or_cls) and issubclass(action_or_cls, D810ActionHandler):
            return action_or_cls(state, ida_modules=ida_modules)

        if callable(action_or_cls):
            candidate = action_or_cls()
            if isinstance(candidate, D810ActionHandler):
                return candidate

        return None
