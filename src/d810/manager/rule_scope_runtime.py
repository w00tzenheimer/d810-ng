"""Runtime service for database-scoped function tags and invalidation."""

from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.persistence import FunctionStorageLocator
from d810.core.rule_scope import (
    FunctionRuleOverlay,
    RuleScopeEvent,
    RuleScopeInvalidation,
)
from d810.core.typing import Any, Callable, Optional, Set


logger = getLogger("D810")


class RuleScopeRuntime:
    """Own storage-backed rule-scope state for the manager facade."""

    def __init__(
        self,
        *,
        storage_factory: Callable[..., Any],
        event_emitter: Any,
        project_name_provider: Callable[[], str],
        database_identity_provider: Callable[[], str],
        config_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self._storage_factory = storage_factory
        self._event_emitter = event_emitter
        self._project_name_provider = project_name_provider
        self._database_identity_provider = database_identity_provider
        self._config_provider = config_provider
        self._config: dict[str, Any] = {}
        self.storage: Any = None

    def configure(self, config: dict[str, Any]) -> None:
        self._config = dict(config)

    def emit_invalidation(
        self,
        reason: RuleScopeEvent,
        *,
        project_name: str | None = None,
        func_eas: frozenset[int] | None = None,
        changed_rules: frozenset[str] | None = None,
    ) -> None:
        self._event_emitter.emit(
            reason,
            RuleScopeInvalidation(
                reason=reason,
                project_name=project_name,
                func_eas=func_eas,
                changed_rules=changed_rules,
            ),
        )

    def initialize_storage(self) -> None:
        old_storage = self.storage
        if self._config_provider is not None:
            self._config = dict(self._config_provider())
        target = self._config.get("function_recipe_storage")
        configured_backend = self._config.get("function_recipe_backend")
        if configured_backend is None:
            # A configured filesystem target is the historical explicit SQLite
            # form. With no storage setting at all, keep function recipes inside
            # the IDB so log cleanup cannot erase them and separate IDBs cannot
            # collide by function address.
            backend = "sqlite" if target is not None else "netnode"
        else:
            backend = str(configured_backend).strip().lower()
        if target is None:
            if backend == "sqlite":
                if old_storage is not None:
                    try:
                        old_storage.close()
                    except Exception:
                        pass
                self.storage = None
                logger.warning(
                    "function_recipe_backend=sqlite requires an explicit "
                    "function_recipe_storage path outside the erasable log directory"
                )
                self.emit_invalidation(
                    RuleScopeEvent.IDB_OVERLAY_RELOADED,
                    project_name=self._project_name(),
                )
                return
            else:
                target = "$ d810.optimization_storage"
        try:
            if old_storage is not None:
                try:
                    old_storage.close()
                except Exception:
                    pass
            self.storage = self._storage_factory(target, backend=backend)
            logger.info(
                "Function recipe storage configured: backend=%s target=%s",
                backend,
                target,
            )
            self.emit_invalidation(
                RuleScopeEvent.IDB_OVERLAY_RELOADED,
                project_name=self._project_name(),
            )
        except Exception as exc:
            self.storage = None
            logger.warning("Failed to initialize function recipe storage: %s", exc)
            self.emit_invalidation(
                RuleScopeEvent.IDB_OVERLAY_RELOADED,
                project_name=self._project_name(),
            )

    def _locator(self, function_ea: int) -> FunctionStorageLocator:
        return FunctionStorageLocator(
            database_identity=str(self._database_identity_provider()),
            project_name=self._project_name(),
            function_addr=int(function_ea),
        )

    def get_rule_overlay(self, function_ea: int) -> FunctionRuleOverlay | None:
        storage = self.storage
        if storage is None:
            return None
        tags = storage.get_function_tags(self._locator(function_ea))
        if not tags:
            return None
        return FunctionRuleOverlay(
            function_tags=frozenset(tags),
        )

    def get_function_tags(self, function_addr: int) -> set[str]:
        self._ensure_storage()
        if self.storage is None:
            return set()
        if not hasattr(self.storage, "get_function_tags"):
            return set()
        return set(self.storage.get_function_tags(self._locator(function_addr)))

    def set_function_tags(
        self,
        *,
        function_addr: int,
        tags: Optional[Set[str]] = None,
    ) -> None:
        self._ensure_storage()
        if self.storage is None:
            logger.warning("Function recipe storage unavailable; tags not persisted")
            return
        if not hasattr(self.storage, "set_function_tags"):
            logger.warning("Function recipe storage does not support function tags")
            return
        normalized_tags = {
            str(tag).strip() for tag in (tags or set()) if str(tag).strip()
        }
        self.storage.set_function_tags(self._locator(function_addr), normalized_tags)
        self.emit_invalidation(
            RuleScopeEvent.FUNCTION_TAGS_UPDATED,
            project_name=self._project_name(),
            func_eas=frozenset({int(function_addr)}),
        )

    def close(self) -> None:
        if self.storage is not None:
            try:
                self.storage.close()
            except Exception:
                pass
            self.storage = None

    def _ensure_storage(self) -> None:
        if self.storage is None:
            self.initialize_storage()

    def _project_name(self) -> str:
        return str(self._project_name_provider() or "")


__all__ = ["RuleScopeRuntime"]
