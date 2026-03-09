from __future__ import annotations

import enum
from dataclasses import dataclass, field

from d810.core.typing import Any, Callable, Iterable, Protocol
from d810.core.logging import getLogger
from d810.core.registry import EventEmitter

logger = getLogger("D810.rule_scope")

PIPELINE_INSTRUCTION = "instruction"
PIPELINE_FLOW = "flow"
PIPELINE_CTREE = "ctree"


class RuleScopeEvent(enum.Enum):
    PROJECT_RULES_RELOADED = "project_rules_reloaded"
    IDB_OVERLAY_RELOADED = "idb_overlay_reloaded"
    FUNCTION_OVERRIDE_UPDATED = "function_override_updated"
    FUNCTION_TAGS_UPDATED = "function_tags_updated"
    INFERENCE_APPLIED = "inference_applied"
    INFERENCE_CLEARED = "inference_cleared"
    HINTS_APPLIED = "hints_applied"


@dataclass(frozen=True, slots=True)
class RuleScopeInvalidation:
    reason: RuleScopeEvent
    project_name: str | None = None
    func_eas: frozenset[int] | None = None
    changed_rules: frozenset[str] | None = None


@dataclass(frozen=True, slots=True)
class ScopeKey:
    project_name: str
    idb_key: str
    func_ea: int
    pipeline: str


@dataclass(frozen=True, slots=True)
class RuleSelectorCompiled:
    rule_name: str
    maturities: frozenset[int]
    allow_eas: frozenset[int] | None = None
    deny_eas: frozenset[int] | None = None
    tags_any: frozenset[str] = frozenset()
    tags_all: frozenset[str] = frozenset()
    enabled: bool = True


@dataclass(slots=True)
class CompiledRuleTable:
    generation: int
    by_pipeline: dict[str, tuple[Any, ...]]
    by_pipeline_rule_name: dict[str, dict[str, Any]]
    selectors: dict[str, RuleSelectorCompiled]
    by_pipeline_maturity: dict[str, dict[int, tuple[str, ...]]]
    by_pipeline_any_maturity: dict[str, tuple[str, ...]]


@dataclass(slots=True)
class ActiveRuleBundle:
    generation: int
    pipeline: str
    func_ea: int
    by_maturity: dict[int, tuple[Any, ...]]


@dataclass(slots=True)
class RuleScopeCaches:
    compiled: CompiledRuleTable | None = None
    active_by_scope: dict[ScopeKey, ActiveRuleBundle] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleDelta:
    """A single rule adjustment inferred from recon analysis.

    Represents a diff from baseline rule behavior for a specific function.
    Deltas are ephemeral by default (applied per-decompilation via
    ``apply_hints``) and can be persisted to project config via the
    ``persist_inference`` action.

    Precedence (highest to lowest):
        1. User ``per_function_overrides`` in project JSON
        2. User ``whitelisted_functions`` / ``blacklisted_functions``
        3. Inference ``override`` deltas (this type, runtime)
        4. Inference ``suppress``/``activate`` deltas (this type, runtime)
        5. Global rule config defaults

    Actions:
        - ``"suppress"``: Disable the rule for this function.
        - ``"activate"``: Force-enable the rule for this function.
        - ``"override"``: Apply parameter overrides from ``overrides`` dict.

    The naming choice of "inference" reflects that these adjustments are
    *derived from automated recon analysis*, not hand-authored presets.
    "Delta" conveys a diff from baseline behavior.
    """
    rule_name: str
    action: str                 # "suppress" | "activate" | "override"
    overrides: dict[str, Any]   # {} for suppress/activate; key:value for override


@dataclass(frozen=True, slots=True)
class FunctionRuleOverlay:
    enabled_rules: frozenset[str] = frozenset()
    disabled_rules: frozenset[str] = frozenset()
    function_tags: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class RuleInferenceOverlay:
    name: str
    enabled_rules: frozenset[str] = frozenset()
    disabled_rules: frozenset[str] = frozenset()
    target_func_eas: frozenset[int] = frozenset()
    target_tags_any: frozenset[str] = frozenset()
    target_tags_all: frozenset[str] = frozenset()
    notes: str = ""


InferenceFactory = Callable[[Any], list[RuleDelta]]
"""Callable that, given analysis context, produces a list of RuleDelta adjustments."""


class FunctionRuleOverlayProvider(Protocol):
    def __call__(self, function_ea: int) -> FunctionRuleOverlay | None: ...


@dataclass(frozen=True, slots=True)
class ApplyHintsResult:
    """Records what changed when ``RuleScopeService.apply_hints()`` ran.

    Attributes:
        func_ea: Function address the hints targeted.
        inferences_applied: Names of inferences that were activated.
        inferences_not_found: Names requested but not in the inference registry.
        rules_suppressed: Rule names that were added to the overlay's
            disabled set for this function.
        cache_invalidated: Whether the scope cache was invalidated.
        generation_before: Service generation before the hints were applied.
        generation_after: Service generation after the hints were applied.
    """
    func_ea: int
    inferences_applied: tuple[str, ...]
    inferences_not_found: tuple[str, ...]
    rules_suppressed: tuple[str, ...]
    cache_invalidated: bool
    generation_before: int
    generation_after: int


class HintOverlayProvider:
    """Overlay provider that merges hint-driven suppressions with a delegate.

    Implements the ``FunctionRuleOverlayProvider`` protocol. For each
    function EA, it returns the union of:

    - Any overlay from the *delegate* provider (if set), and
    - Hint-driven rule suppressions registered via ``suppress_rules()``.

    This provider composes with (not replaces) any pre-existing overlay
    provider on the ``RuleScopeService``.
    """

    def __init__(
        self,
        delegate: FunctionRuleOverlayProvider | None = None,
    ) -> None:
        self._delegate = delegate
        self._suppressions: dict[int, frozenset[str]] = {}
        self._hint_inferences: dict[int, list[RuleInferenceOverlay]] = {}

    @property
    def delegate(self) -> FunctionRuleOverlayProvider | None:
        return self._delegate

    def suppress_rules(
        self,
        func_ea: int,
        rule_names: frozenset[str],
    ) -> None:
        """Register rule suppressions for a function.

        Args:
            func_ea: Target function address.
            rule_names: Rule names to disable for this function.
        """
        existing = self._suppressions.get(func_ea, frozenset())
        self._suppressions[func_ea] = existing | rule_names

    def has_suppressions(self, func_ea: int) -> bool:
        """Check whether any hint-driven suppressions exist for *func_ea*."""
        return bool(self._suppressions.get(func_ea))

    def get_suppressions(self, func_ea: int) -> frozenset[str]:
        """Return hint-owned suppressions for *func_ea* (excludes delegate)."""
        return self._suppressions.get(func_ea, frozenset())

    def clear_func(self, func_ea: int) -> None:
        """Remove all hint-driven inferences and suppressions for a function."""
        self._hint_inferences.pop(func_ea, None)
        self._suppressions.pop(func_ea, None)

    def clear_suppressions(self, func_ea: int | None = None) -> None:
        """Remove suppressions for *func_ea*, or all if ``None``."""
        if func_ea is None:
            self._suppressions.clear()
        else:
            self._suppressions.pop(func_ea, None)

    def add_inference(self, func_ea: int, inference: RuleInferenceOverlay) -> None:
        """Register a hint-driven inference activation for a function.

        Multiple inferences for the same function accumulate; their
        ``enabled_rules`` and ``disabled_rules`` are merged at query time.

        Args:
            func_ea: Target function address.
            inference: Inference overlay to activate for this function.
        """
        self._hint_inferences.setdefault(func_ea, []).append(inference)

    def get_hint_inferences(self, func_ea: int) -> list[RuleInferenceOverlay]:
        """Return all hint-driven inferences registered for *func_ea*."""
        return self._hint_inferences.get(func_ea, [])

    def merged_hint_inference(self, func_ea: int) -> RuleInferenceOverlay | None:
        """Return a single merged inference for *func_ea*, or ``None``.

        Merges all per-function hint inferences into one overlay whose
        ``enabled_rules`` and ``disabled_rules`` are the union of all
        registered inferences.
        """
        inferences = self._hint_inferences.get(func_ea)
        if not inferences:
            return None
        if len(inferences) == 1:
            return inferences[0]
        merged_enabled: set[str] = set()
        merged_disabled: set[str] = set()
        names: list[str] = []
        for r in inferences:
            merged_enabled.update(r.enabled_rules)
            merged_disabled.update(r.disabled_rules)
            names.append(r.name)
        return RuleInferenceOverlay(
            name="+".join(names),
            enabled_rules=frozenset(merged_enabled),
            disabled_rules=frozenset(merged_disabled),
            target_func_eas=frozenset({func_ea}),
        )

    def __call__(self, function_ea: int) -> FunctionRuleOverlay | None:
        delegate_overlay = (
            self._delegate(function_ea) if self._delegate is not None else None
        )
        hint_disabled = self._suppressions.get(function_ea, frozenset())

        if delegate_overlay is None and not hint_disabled:
            return None

        base_enabled = (
            delegate_overlay.enabled_rules if delegate_overlay else frozenset()
        )
        base_disabled = (
            delegate_overlay.disabled_rules if delegate_overlay else frozenset()
        )
        base_tags = (
            delegate_overlay.function_tags if delegate_overlay else frozenset()
        )

        return FunctionRuleOverlay(
            enabled_rules=base_enabled,
            disabled_rules=base_disabled | hint_disabled,
            function_tags=base_tags,
        )


class RuleScopeService:
    """Compiles rule selectors and serves active rules per function quickly.

    Phase 1 scope:
    - cache structs + invalidation events
    - compile selectors from existing rule config objects
    - no optimizer-path behavioral changes yet
    """

    def __init__(self) -> None:
        self._generation = 0
        self._caches = RuleScopeCaches()
        self._attached = False
        self._overlay_provider: FunctionRuleOverlayProvider | None = None
        self._overlay_cache: dict[int, FunctionRuleOverlay | None] = {}
        self._active_inference: RuleInferenceOverlay | None = None
        self._inference_registry: dict[str, InferenceFactory] = {}
        self._hint_overlay: HintOverlayProvider | None = None

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def active_cache_size(self) -> int:
        return len(self._caches.active_by_scope)

    def attach(self, emitter: EventEmitter) -> None:
        if self._attached:
            return
        for event in RuleScopeEvent:
            emitter.on(event, self._on_event)
        self._attached = True

    def _on_event(self, payload: RuleScopeInvalidation | None = None) -> None:
        if payload is None:
            return
        self.invalidate(payload)

    def invalidate(self, payload: RuleScopeInvalidation) -> None:
        partial_reasons = {
            RuleScopeEvent.FUNCTION_OVERRIDE_UPDATED,
            RuleScopeEvent.FUNCTION_TAGS_UPDATED,
            RuleScopeEvent.HINTS_APPLIED,
        }
        if payload.reason in partial_reasons and payload.func_eas:
            self._invalidate_functions(payload.func_eas)
            return
        self._invalidate_all()

    def _invalidate_all(self) -> None:
        self._generation += 1
        self._caches.compiled = None
        self._caches.active_by_scope.clear()
        self._overlay_cache.clear()
        if logger.debug_on:
            logger.debug("rule-scope full invalidation -> generation=%d", self._generation)

    def _invalidate_functions(self, func_eas: frozenset[int]) -> None:
        self._generation += 1
        to_delete = [
            key
            for key in self._caches.active_by_scope.keys()
            if key.func_ea in func_eas
        ]
        for key in to_delete:
            self._caches.active_by_scope.pop(key, None)
        for func_ea in func_eas:
            self._overlay_cache.pop(func_ea, None)
        if logger.debug_on:
            logger.debug(
                "rule-scope partial invalidation (%d funcs) -> removed %d bundles, generation=%d",
                len(func_eas),
                len(to_delete),
                self._generation,
            )

    def set_overlay_provider(
        self,
        provider: FunctionRuleOverlayProvider | None,
    ) -> None:
        self._overlay_provider = provider
        self._overlay_cache.clear()

    def set_active_inference(self, inference: RuleInferenceOverlay | None) -> None:
        self._active_inference = inference

    def register_inference(self, name: str, factory: InferenceFactory) -> None:
        """Register a named inference factory for later invocation by ``apply_hints()``.

        Args:
            name: Inference name used as registry key.
            factory: Callable that accepts analysis context and returns
                a list of :class:`RuleDelta` adjustments.
        """
        self._inference_registry[name] = factory

    def get_registered_inference(self, name: str) -> InferenceFactory | None:
        """Look up an inference factory by name from the registry.

        Args:
            name: Inference name to look up.

        Returns:
            The registered factory, or ``None`` if not found.
        """
        return self._inference_registry.get(name)

    def get_hint_state_summary(self, func_ea: int) -> dict:
        """Return a summary of hint-driven state for a function.

        Provides activation observability without a full reporting surface.

        Args:
            func_ea: Function address to query.

        Returns:
            Dictionary with keys ``func_ea``, ``has_hint_inferences``,
            ``inference_names``, ``suppressed_rules``, ``generation``.
        """
        has_inferences = False
        inference_names: list[str] = []
        suppressed: list[str] = []

        if self._hint_overlay is not None:
            hint_inferences = self._hint_overlay.get_hint_inferences(func_ea)
            has_inferences = bool(hint_inferences)
            inference_names = [r.name for r in hint_inferences]

            # Read only hint-owned suppressions (not delegate overlay)
            hint_suppressed = self._hint_overlay.get_suppressions(func_ea)
            if hint_suppressed:
                suppressed = sorted(hint_suppressed)

        return {
            "func_ea": func_ea,
            "has_hint_inferences": has_inferences,
            "inference_names": inference_names,
            "suppressed_rules": suppressed,
            "generation": self._generation,
        }

    def clear_hint_state(self, func_ea: int) -> None:
        """Clear all hint-driven inferences and suppressions for *func_ea*.

        Delegates to ``HintOverlayProvider.clear_func()`` and invalidates
        caches so subsequent ``get_active_rules()`` calls see the removal.
        """
        if self._hint_overlay is not None:
            self._hint_overlay.clear_func(func_ea)
            self.invalidate(
                RuleScopeInvalidation(
                    reason=RuleScopeEvent.HINTS_APPLIED,
                    func_eas=frozenset({func_ea}),
                )
            )

    def apply_hints(self, hints: Any) -> ApplyHintsResult:
        """Apply analysed deobfuscation hints to rule scope configuration.

        Bridges ``DeobfuscationHints`` -> overlay/inference activation.
        Accepts any object with ``func_ea``, ``recommended_inferences``,
        and ``suppress_rules`` attributes (duck-typed to avoid a hard
        import of ``d810.recon.models``).

        Args:
            hints: Analysed hints from AnalysisPhase.

        Returns:
            ``ApplyHintsResult`` recording what changed.
        """
        func_ea: int = hints.func_ea
        recommended_inferences: tuple[str, ...] = hints.recommended_inferences
        suppress_rules: tuple[str, ...] = hints.suppress_rules

        generation_before = self._generation
        inferences_applied: list[str] = []
        inferences_not_found: list[str] = []

        # --- 0. Clear previous hint state for this function ------------------
        # Each call is a full replace, not an append: a later call with
        # empty/different hints for the same func_ea retracts earlier decisions.
        had_previous_state = False
        if self._hint_overlay is not None:
            had_previous_state = (
                bool(self._hint_overlay.get_hint_inferences(func_ea))
                or self._hint_overlay.has_suppressions(func_ea)
            )
            self._hint_overlay.clear_func(func_ea)

        # --- 1. Apply recommended inferences ---------------------------------
        for inference_name in recommended_inferences:
            factory = self._inference_registry.get(inference_name)
            if factory is None:
                inferences_not_found.append(inference_name)
                continue
            # Invoke factory to get deltas, then convert to overlay
            deltas = factory(hints)
            logger.info(
                "rule_inference: func=0x%x inference=%r produced %d delta(s)",
                func_ea, inference_name, len(deltas),
            )
            enabled: set[str] = set()
            disabled: set[str] = set()
            for delta in deltas:
                if delta.action == "activate":
                    if self._user_config_overrides_delta(delta, func_ea):
                        logger.warning(
                            "rule_inference: func=0x%x delta activate(%s) -> "
                            "overridden by user config (rule is blacklisted)",
                            func_ea, delta.rule_name,
                        )
                    else:
                        enabled.add(delta.rule_name)
                        logger.info(
                            "rule_inference: func=0x%x delta activate(%s) -> applied",
                            func_ea, delta.rule_name,
                        )
                elif delta.action == "suppress":
                    if self._user_config_overrides_delta(delta, func_ea):
                        logger.warning(
                            "rule_inference: func=0x%x delta suppress(%s) -> "
                            "overridden by user config (rule is whitelisted)",
                            func_ea, delta.rule_name,
                        )
                    else:
                        disabled.add(delta.rule_name)
                        logger.info(
                            "rule_inference: func=0x%x delta suppress(%s) -> applied",
                            func_ea, delta.rule_name,
                        )
            scoped = RuleInferenceOverlay(
                name=inference_name,
                enabled_rules=frozenset(enabled),
                disabled_rules=frozenset(disabled),
                target_func_eas=frozenset({func_ea}),
            )
            # Store per-function via HintOverlayProvider (not global _active_inference)
            if self._hint_overlay is None:
                self._hint_overlay = HintOverlayProvider(
                    delegate=self._overlay_provider,
                )
                self._overlay_provider = self._hint_overlay
                self._overlay_cache.clear()
            self._hint_overlay.add_inference(func_ea, scoped)
            inferences_applied.append(inference_name)

        # --- 2. Apply suppress_rules via HintOverlayProvider -----------------
        rules_suppressed: list[str] = []
        if suppress_rules:
            suppression_set = frozenset(suppress_rules)
            # Lazily create the HintOverlayProvider, wrapping any existing
            # provider as delegate.
            if self._hint_overlay is None:
                self._hint_overlay = HintOverlayProvider(
                    delegate=self._overlay_provider,
                )
                self._overlay_provider = self._hint_overlay
                self._overlay_cache.clear()
            self._hint_overlay.suppress_rules(func_ea, suppression_set)
            rules_suppressed = list(suppress_rules)

        # --- 3. Invalidate caches for this function --------------------------
        any_change = bool(inferences_applied) or bool(rules_suppressed) or had_previous_state
        if any_change:
            self.invalidate(
                RuleScopeInvalidation(
                    reason=RuleScopeEvent.HINTS_APPLIED,
                    func_eas=frozenset({func_ea}),
                    changed_rules=frozenset(rules_suppressed) or None,
                )
            )

        generation_after = self._generation
        result = ApplyHintsResult(
            func_ea=func_ea,
            inferences_applied=tuple(inferences_applied),
            inferences_not_found=tuple(inferences_not_found),
            rules_suppressed=tuple(rules_suppressed),
            cache_invalidated=any_change,
            generation_before=generation_before,
            generation_after=generation_after,
        )
        if logger.debug_on:
            logger.debug(
                "apply_hints func_ea=0x%x: inferences=%s suppressed=%s gen=%d->%d",
                func_ea,
                result.inferences_applied,
                result.rules_suppressed,
                generation_before,
                generation_after,
            )
        return result

    def compile_base_rules(
        self,
        *,
        project_name: str,
        instruction_rules: Iterable[Any],
        flow_rules: Iterable[Any],
        ctree_rules: Iterable[Any],
    ) -> None:
        by_pipeline = {
            PIPELINE_INSTRUCTION: tuple(instruction_rules),
            PIPELINE_FLOW: tuple(flow_rules),
            PIPELINE_CTREE: tuple(ctree_rules),
        }
        by_pipeline_rule_name: dict[str, dict[str, Any]] = {}
        selectors: dict[str, RuleSelectorCompiled] = {}
        by_pipeline_maturity: dict[str, dict[int, list[str]]] = {}
        by_pipeline_any_maturity: dict[str, list[str]] = {}

        for pipeline, rules in by_pipeline.items():
            rule_map: dict[str, Any] = {}
            maturity_map: dict[int, list[str]] = {}
            any_maturity: list[str] = []

            for rule in rules:
                rule_name = self._rule_name(rule)
                selector_key = f"{pipeline}:{rule_name}"
                selector = self._selector_from_rule(rule_name, rule)
                selectors[selector_key] = selector
                rule_map[rule_name] = rule

                if selector.maturities:
                    for m in selector.maturities:
                        maturity_map.setdefault(int(m), []).append(rule_name)
                else:
                    any_maturity.append(rule_name)

            by_pipeline_rule_name[pipeline] = rule_map
            by_pipeline_maturity[pipeline] = {
                m: tuple(dict.fromkeys(names)) for m, names in maturity_map.items()
            }
            by_pipeline_any_maturity[pipeline] = list(dict.fromkeys(any_maturity))

        self._caches.compiled = CompiledRuleTable(
            generation=self._generation,
            by_pipeline=by_pipeline,
            by_pipeline_rule_name=by_pipeline_rule_name,
            selectors=selectors,
            by_pipeline_maturity=by_pipeline_maturity,
            by_pipeline_any_maturity={
                p: tuple(names) for p, names in by_pipeline_any_maturity.items()
            },
        )
        self._caches.active_by_scope.clear()
        if logger.debug_on:
            logger.debug(
                "compiled rule table for project=%s generation=%d",
                project_name,
                self._generation,
            )

    def get_active_rules(
        self,
        *,
        project_name: str,
        idb_key: str,
        func_ea: int,
        pipeline: str,
        maturity: int,
        function_tags: frozenset[str] | None = None,
    ) -> tuple[Any, ...]:
        compiled = self._caches.compiled
        if compiled is None:
            return tuple()

        scope = ScopeKey(
            project_name=project_name,
            idb_key=idb_key,
            func_ea=func_ea,
            pipeline=pipeline,
        )
        bundle = self._caches.active_by_scope.get(scope)
        if bundle is not None and bundle.generation == self._generation:
            cached = bundle.by_maturity.get(maturity)
            if cached is not None:
                return cached

        tags = set(function_tags or frozenset())
        overlay = self._get_overlay(func_ea)
        if overlay is not None:
            tags.update(overlay.function_tags)
        effective_tags = frozenset(tags)
        rules_by_name = compiled.by_pipeline_rule_name.get(pipeline, {})
        names = list(compiled.by_pipeline_maturity.get(pipeline, {}).get(maturity, tuple()))
        names.extend(compiled.by_pipeline_any_maturity.get(pipeline, tuple()))
        if not names:
            return tuple()

        # Determine the effective inference: per-function hint inference takes
        # precedence over the global _active_inference for this function.
        effective_inference = self._active_inference
        if self._hint_overlay is not None:
            hint_inference = self._hint_overlay.merged_hint_inference(func_ea)
            if hint_inference is not None:
                effective_inference = hint_inference

        active_for_maturity: list[Any] = []
        for rule_name in names:
            selector = compiled.selectors.get(f"{pipeline}:{rule_name}")
            if selector is None:
                continue
            if not self._overlay_allows(overlay, rule_name):
                continue
            if not self._inference_allows(
                inference=effective_inference,
                rule_name=rule_name,
                func_ea=func_ea,
                tags=effective_tags,
            ):
                continue
            if not self._selector_allows(selector, func_ea=func_ea, tags=effective_tags):
                continue
            rule = rules_by_name.get(rule_name)
            if rule is not None:
                active_for_maturity.append(rule)

        active_tuple = tuple(active_for_maturity)
        if bundle is not None and bundle.generation == self._generation:
            bundle.by_maturity[maturity] = active_tuple
            return active_tuple

        new_bundle = ActiveRuleBundle(
            generation=self._generation,
            pipeline=pipeline,
            func_ea=func_ea,
            by_maturity={maturity: active_tuple},
        )
        self._caches.active_by_scope[scope] = new_bundle
        return active_tuple

    @staticmethod
    def _rule_name(rule: Any) -> str:
        return str(getattr(rule, "name", rule.__class__.__name__))

    @staticmethod
    def _normalize_ea_list(values: Iterable[Any]) -> frozenset[int]:
        normalized: set[int] = set()
        for value in values:
            if isinstance(value, str):
                normalized.add(int(value, 16) if value.startswith("0x") else int(value))
            else:
                normalized.add(int(value))
        return frozenset(normalized)

    @staticmethod
    def _selector_from_rule(rule_name: str, rule: Any) -> RuleSelectorCompiled:
        maturities = frozenset(int(m) for m in getattr(rule, "maturities", []) if m is not None)

        allow_eas: frozenset[int] | None = None
        if bool(getattr(rule, "use_whitelist", False)):
            allow_eas = RuleScopeService._normalize_ea_list(
                getattr(rule, "whitelisted_function_ea_list", [])
            )

        deny_eas: frozenset[int] | None = None
        if bool(getattr(rule, "use_blacklist", False)):
            deny_eas = RuleScopeService._normalize_ea_list(
                getattr(rule, "blacklisted_function_ea_list", [])
            )

        tags_any = RuleScopeService._normalize_tag_list(getattr(rule, "tags_any", []))
        tags_all = RuleScopeService._normalize_tag_list(getattr(rule, "tags_all", []))

        return RuleSelectorCompiled(
            rule_name=rule_name,
            maturities=maturities,
            allow_eas=allow_eas,
            deny_eas=deny_eas,
            tags_any=tags_any,
            tags_all=tags_all,
            enabled=True,
        )

    @staticmethod
    def _selector_allows(
        selector: RuleSelectorCompiled,
        *,
        func_ea: int,
        tags: frozenset[str],
    ) -> bool:
        if not selector.enabled:
            return False
        if selector.allow_eas is not None and func_ea not in selector.allow_eas:
            return False
        if selector.deny_eas is not None and func_ea in selector.deny_eas:
            return False
        if selector.tags_any and selector.tags_any.isdisjoint(tags):
            return False
        if selector.tags_all and not selector.tags_all.issubset(tags):
            return False
        return True

    def _get_overlay(self, func_ea: int) -> FunctionRuleOverlay | None:
        if self._overlay_provider is None:
            return None
        if func_ea in self._overlay_cache:
            return self._overlay_cache[func_ea]
        overlay = self._overlay_provider(func_ea)
        self._overlay_cache[func_ea] = overlay
        return overlay

    @staticmethod
    def _overlay_allows(
        overlay: FunctionRuleOverlay | None,
        rule_name: str,
    ) -> bool:
        if overlay is None:
            return True
        if overlay.enabled_rules and rule_name not in overlay.enabled_rules:
            return False
        if rule_name in overlay.disabled_rules:
            return False
        return True

    @staticmethod
    def _normalize_tag_list(values: Iterable[Any]) -> frozenset[str]:
        normalized: set[str] = set()
        for value in values:
            tag = str(value).strip()
            if tag:
                normalized.add(tag)
        return frozenset(normalized)

    @staticmethod
    def _inference_targets_function(
        inference: RuleInferenceOverlay,
        *,
        func_ea: int,
        tags: frozenset[str],
    ) -> bool:
        if inference.target_func_eas and func_ea not in inference.target_func_eas:
            return False
        if inference.target_tags_any and inference.target_tags_any.isdisjoint(tags):
            return False
        if inference.target_tags_all and not inference.target_tags_all.issubset(tags):
            return False
        return True

    @staticmethod
    def _inference_allows(
        *,
        inference: RuleInferenceOverlay | None,
        rule_name: str,
        func_ea: int,
        tags: frozenset[str],
    ) -> bool:
        if inference is None:
            return True
        if not RuleScopeService._inference_targets_function(
            inference,
            func_ea=func_ea,
            tags=tags,
        ):
            return True
        if inference.enabled_rules and rule_name not in inference.enabled_rules:
            return False
        if rule_name in inference.disabled_rules:
            return False
        return True

    def _user_config_overrides_delta(
        self,
        delta: RuleDelta,
        func_ea: int,
    ) -> bool:
        """Check whether user config (whitelist/blacklist) would override a delta.

        For ``suppress`` deltas: returns ``True`` if the rule has an
        ``allow_eas`` whitelist containing *func_ea* (user explicitly
        whitelisted this function for the rule).

        For ``activate`` deltas: returns ``True`` if the rule has a
        ``deny_eas`` blacklist containing *func_ea* (user explicitly
        blacklisted this function from the rule).

        Returns ``False`` if no compiled selectors exist or the rule is
        not found in any pipeline.
        """
        compiled = self._caches.compiled
        if compiled is None:
            return False

        # Selectors are keyed as "{pipeline}:{rule_name}"; check all pipelines.
        for key, selector in compiled.selectors.items():
            if selector.rule_name != delta.rule_name:
                continue
            if delta.action == "suppress":
                if selector.allow_eas is not None and func_ea in selector.allow_eas:
                    return True
            elif delta.action == "activate":
                if selector.deny_eas is not None and func_ea in selector.deny_eas:
                    return True
        return False
