"""Dynamic action discovery/instantiation for d810-ng UI actions.

This loader discovers action modules from ``d810.ui.actions`` via
:class:`~d810._vendor.ida_reloader.ida_reloader.Scanner` and instantiates
``D810ActionHandler`` implementations using the
:class:`~d810.core.registry.Registrant` registry populated at import time.
"""
from __future__ import annotations

from d810.core.typing import Any

from d810.core.logging import getLogger
from d810.ui import actions
from d810.ui.actions.base import D810ActionHandler
from d810._vendor.ida_reloader.ida_reloader import Scanner

logger = getLogger("D810.ui")


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

        Scanner.scan(actions.__path__, prefix=f"{actions.__name__}.", skip_packages=True)

        seen_action_ids: set[str] = set()
        for cls in D810ActionHandler.all():
            if not getattr(cls, "ACTION_ID", ""):
                continue
            if cls.ACTION_ID in seen_action_ids:
                logger.warning("Duplicate action id %s from %s", cls.ACTION_ID, cls)
                continue
            seen_action_ids.add(cls.ACTION_ID)
            try:
                action = cls(state, ida_modules=ida_modules)
                self._action_instances.append(action)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to instantiate %s: %s", cls, exc)

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
