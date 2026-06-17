"""Runtime service for function-rule scope persistence and invalidation."""

from __future__ import annotations

import pathlib

from d810.core.logging import getLogger
from d810.core.persistence import ActiveRuleInferenceConfig
from d810.core.rule_scope import (
    FunctionRuleOverlay,
    RuleInferenceOverlay,
    RuleScopeEvent,
    RuleScopeInvalidation,
    RuleScopeService,
)
from d810.core.typing import Any, Callable, Optional, Set


logger = getLogger("D810")


class RuleScopeRuntime:
    """Own storage-backed rule-scope state for the manager facade."""

    def __init__(
        self,
        *,
        storage_factory: Callable[..., Any],
        rule_scope_service: RuleScopeService,
        event_emitter: Any,
        log_dir: pathlib.Path,
        project_name_provider: Callable[[], str],
        config_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        self._storage_factory = storage_factory
        self._rule_scope_service = rule_scope_service
        self._event_emitter = event_emitter
        self._log_dir = pathlib.Path(log_dir)
        self._project_name_provider = project_name_provider
        self._config_provider = config_provider
        self._config: dict[str, Any] = {}
        self.storage: Any = None
        self._active_rule_inference: RuleInferenceOverlay | None = None

    @property
    def active_rule_inference(self) -> RuleInferenceOverlay | None:
        return self._active_rule_inference

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
        backend = (
            str(self._config.get("function_rules_backend", "sqlite")).strip().lower()
        )
        target = self._config.get("function_rules_storage")
        if target is None:
            if backend == "sqlite":
                target = self._log_dir / "d810_function_rules.db"
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
                "Function-rules storage configured: backend=%s target=%s",
                backend,
                target,
            )
            self.load_active_inference_from_storage()
            self.emit_invalidation(
                RuleScopeEvent.IDB_OVERLAY_RELOADED,
                project_name=self._project_name(),
            )
        except Exception as exc:
            self.storage = None
            logger.warning("Failed to initialize function-rules storage: %s", exc)
            self.emit_invalidation(
                RuleScopeEvent.IDB_OVERLAY_RELOADED,
                project_name=self._project_name(),
            )

    def load_active_inference_from_storage(self) -> None:
        storage = self.storage
        if storage is None or not hasattr(storage, "get_active_rule_inference"):
            self._active_rule_inference = None
            self._rule_scope_service.set_active_inference(None)
            return
        persisted = storage.get_active_rule_inference()
        if persisted is None:
            self._active_rule_inference = None
            self._rule_scope_service.set_active_inference(None)
            return
        inference = RuleInferenceOverlay(
            name=str(persisted.name).strip() or "unnamed_inference",
            enabled_rules=frozenset(str(rule) for rule in persisted.enabled_rules),
            disabled_rules=frozenset(str(rule) for rule in persisted.disabled_rules),
            target_func_eas=frozenset(int(ea) for ea in persisted.target_func_eas),
            target_tags_any=frozenset(
                str(tag).strip()
                for tag in persisted.target_tags_any
                if str(tag).strip()
            ),
            target_tags_all=frozenset(
                str(tag).strip()
                for tag in persisted.target_tags_all
                if str(tag).strip()
            ),
            notes=str(persisted.notes),
        )
        self._active_rule_inference = inference
        self._rule_scope_service.set_active_inference(inference)
        self.emit_invalidation(
            RuleScopeEvent.INFERENCE_APPLIED,
            project_name=self._project_name(),
            changed_rules=frozenset(inference.enabled_rules | inference.disabled_rules),
        )

    def get_rule_overlay(self, function_ea: int) -> FunctionRuleOverlay | None:
        storage = self.storage
        if storage is None:
            return None
        config = storage.get_function_rules(function_ea)
        if config is None:
            return None
        return FunctionRuleOverlay(
            enabled_rules=frozenset(config.enabled_rules),
            disabled_rules=frozenset(config.disabled_rules),
            function_tags=frozenset(config.tags),
        )

    def get_function_rule_override(self, function_addr: int) -> Any | None:
        self._ensure_storage()
        if self.storage is None:
            return None
        return self.storage.get_function_rules(function_addr)

    def set_function_rule_override(
        self,
        *,
        function_addr: int,
        enabled_rules: Optional[Set[str]] = None,
        disabled_rules: Optional[Set[str]] = None,
        notes: str = "",
    ) -> None:
        self._ensure_storage()
        if self.storage is None:
            logger.warning("Function-rules storage unavailable; override not persisted")
            return
        self.storage.set_function_rules(
            function_addr=function_addr,
            enabled_rules=enabled_rules,
            disabled_rules=disabled_rules,
            notes=notes,
        )
        self.emit_invalidation(
            RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            project_name=self._project_name(),
            func_eas=frozenset({int(function_addr)}),
            changed_rules=frozenset(
                (enabled_rules or set()) | (disabled_rules or set())
            ),
        )

    def clear_function_rule_override(self, function_addr: int) -> None:
        self._ensure_storage()
        if self.storage is None:
            logger.warning("Function-rules storage unavailable; override not cleared")
            return

        existing = self.storage.get_function_rules(function_addr)
        if existing is None:
            return

        if existing.tags:
            self.storage.set_function_rules(
                function_addr=function_addr,
                enabled_rules=set(),
                disabled_rules=set(),
                notes="",
            )
        else:
            self.storage.clear_function_rules(function_addr)

        self.emit_invalidation(
            RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            project_name=self._project_name(),
            func_eas=frozenset({int(function_addr)}),
            changed_rules=frozenset(
                set(existing.enabled_rules) | set(existing.disabled_rules)
            ),
        )

    def get_function_tags(self, function_addr: int) -> set[str]:
        self._ensure_storage()
        if self.storage is None:
            return set()
        if not hasattr(self.storage, "get_function_tags"):
            return set()
        return set(self.storage.get_function_tags(function_addr))

    def set_function_tags(
        self,
        *,
        function_addr: int,
        tags: Optional[Set[str]] = None,
    ) -> None:
        self._ensure_storage()
        if self.storage is None:
            logger.warning("Function-rules storage unavailable; tags not persisted")
            return
        if not hasattr(self.storage, "set_function_tags"):
            logger.warning("Function-rules storage does not support function tags")
            return
        normalized_tags = {
            str(tag).strip() for tag in (tags or set()) if str(tag).strip()
        }
        self.storage.set_function_tags(function_addr, normalized_tags)
        self.emit_invalidation(
            RuleScopeEvent.FUNCTION_TAGS_UPDATED,
            project_name=self._project_name(),
            func_eas=frozenset({int(function_addr)}),
        )

    def set_active_rule_inference(
        self,
        *,
        inference_name: str,
        enabled_rules: Optional[Set[str]] = None,
        disabled_rules: Optional[Set[str]] = None,
        target_func_eas: Optional[Set[int]] = None,
        target_tags_any: Optional[Set[str]] = None,
        target_tags_all: Optional[Set[str]] = None,
        notes: str = "",
    ) -> None:
        self._ensure_storage()
        inference = RuleInferenceOverlay(
            name=str(inference_name).strip() or "unnamed_inference",
            enabled_rules=frozenset(enabled_rules or set()),
            disabled_rules=frozenset(disabled_rules or set()),
            target_func_eas=frozenset(int(ea) for ea in (target_func_eas or set())),
            target_tags_any=frozenset(
                str(tag).strip()
                for tag in (target_tags_any or set())
                if str(tag).strip()
            ),
            target_tags_all=frozenset(
                str(tag).strip()
                for tag in (target_tags_all or set())
                if str(tag).strip()
            ),
            notes=notes,
        )
        self._active_rule_inference = inference
        self._rule_scope_service.set_active_inference(inference)
        if self.storage is not None and hasattr(self.storage, "set_active_rule_inference"):
            self.storage.set_active_rule_inference(
                ActiveRuleInferenceConfig(
                    name=inference.name,
                    enabled_rules=set(inference.enabled_rules),
                    disabled_rules=set(inference.disabled_rules),
                    target_func_eas=set(inference.target_func_eas),
                    target_tags_any=set(inference.target_tags_any),
                    target_tags_all=set(inference.target_tags_all),
                    notes=inference.notes,
                )
            )
        self.emit_invalidation(
            RuleScopeEvent.INFERENCE_APPLIED,
            project_name=self._project_name(),
            changed_rules=frozenset(
                (enabled_rules or set()) | (disabled_rules or set())
            ),
        )

    def clear_active_rule_inference(self) -> None:
        self._ensure_storage()
        self._active_rule_inference = None
        self._rule_scope_service.set_active_inference(None)
        if self.storage is not None and hasattr(
            self.storage, "clear_active_rule_inference"
        ):
            self.storage.clear_active_rule_inference()
        self.emit_invalidation(
            RuleScopeEvent.INFERENCE_CLEARED,
            project_name=self._project_name(),
        )

    def get_active_rule_inference(self) -> RuleInferenceOverlay | None:
        return self._active_rule_inference

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
