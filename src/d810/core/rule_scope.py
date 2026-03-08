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
    RECIPE_APPLIED = "recipe_applied"
    RECIPE_CLEARED = "recipe_cleared"
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


@dataclass(frozen=True, slots=True)
class FunctionRuleOverlay:
    enabled_rules: frozenset[str] = frozenset()
    disabled_rules: frozenset[str] = frozenset()
    function_tags: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class RuleRecipeOverlay:
    name: str
    enabled_rules: frozenset[str] = frozenset()
    disabled_rules: frozenset[str] = frozenset()
    target_func_eas: frozenset[int] = frozenset()
    target_tags_any: frozenset[str] = frozenset()
    target_tags_all: frozenset[str] = frozenset()
    notes: str = ""


class FunctionRuleOverlayProvider(Protocol):
    def __call__(self, function_ea: int) -> FunctionRuleOverlay | None: ...


@dataclass(frozen=True, slots=True)
class ApplyHintsResult:
    """Records what changed when ``RuleScopeService.apply_hints()`` ran.

    Attributes:
        func_ea: Function address the hints targeted.
        recipes_applied: Names of recipes that were activated.
        recipes_not_found: Names requested but not in the recipe registry.
        rules_suppressed: Rule names that were added to the overlay's
            disabled set for this function.
        cache_invalidated: Whether the scope cache was invalidated.
        generation_before: Service generation before the hints were applied.
        generation_after: Service generation after the hints were applied.
    """
    func_ea: int
    recipes_applied: tuple[str, ...]
    recipes_not_found: tuple[str, ...]
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
        self._hint_recipes: dict[int, list[RuleRecipeOverlay]] = {}

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
        """Remove all hint-driven recipes and suppressions for a function."""
        self._hint_recipes.pop(func_ea, None)
        self._suppressions.pop(func_ea, None)

    def clear_suppressions(self, func_ea: int | None = None) -> None:
        """Remove suppressions for *func_ea*, or all if ``None``."""
        if func_ea is None:
            self._suppressions.clear()
        else:
            self._suppressions.pop(func_ea, None)

    def add_recipe(self, func_ea: int, recipe: RuleRecipeOverlay) -> None:
        """Register a hint-driven recipe activation for a function.

        Multiple recipes for the same function accumulate; their
        ``enabled_rules`` and ``disabled_rules`` are merged at query time.

        Args:
            func_ea: Target function address.
            recipe: Recipe overlay to activate for this function.
        """
        self._hint_recipes.setdefault(func_ea, []).append(recipe)

    def get_hint_recipes(self, func_ea: int) -> list[RuleRecipeOverlay]:
        """Return all hint-driven recipes registered for *func_ea*."""
        return self._hint_recipes.get(func_ea, [])

    def merged_hint_recipe(self, func_ea: int) -> RuleRecipeOverlay | None:
        """Return a single merged recipe for *func_ea*, or ``None``.

        Merges all per-function hint recipes into one overlay whose
        ``enabled_rules`` and ``disabled_rules`` are the union of all
        registered recipes.
        """
        recipes = self._hint_recipes.get(func_ea)
        if not recipes:
            return None
        if len(recipes) == 1:
            return recipes[0]
        merged_enabled: set[str] = set()
        merged_disabled: set[str] = set()
        names: list[str] = []
        for r in recipes:
            merged_enabled.update(r.enabled_rules)
            merged_disabled.update(r.disabled_rules)
            names.append(r.name)
        return RuleRecipeOverlay(
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
        self._active_recipe: RuleRecipeOverlay | None = None
        self._recipe_registry: dict[str, RuleRecipeOverlay] = {}
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

    def set_active_recipe(self, recipe: RuleRecipeOverlay | None) -> None:
        self._active_recipe = recipe

    def register_recipe(self, recipe: RuleRecipeOverlay) -> None:
        """Register a named recipe for later lookup by ``apply_hints()``.

        Args:
            recipe: Recipe overlay to register. Its ``name`` is used as key.
        """
        self._recipe_registry[recipe.name] = recipe

    def get_registered_recipe(self, name: str) -> RuleRecipeOverlay | None:
        """Look up a recipe by name from the registry.

        Args:
            name: Recipe name to look up.

        Returns:
            The registered recipe, or ``None`` if not found.
        """
        return self._recipe_registry.get(name)

    def get_hint_state_summary(self, func_ea: int) -> dict:
        """Return a summary of hint-driven state for a function.

        Provides activation observability without a full reporting surface.

        Args:
            func_ea: Function address to query.

        Returns:
            Dictionary with keys ``func_ea``, ``has_hint_recipes``,
            ``recipe_names``, ``suppressed_rules``, ``generation``.
        """
        has_recipes = False
        recipe_names: list[str] = []
        suppressed: list[str] = []

        if self._hint_overlay is not None:
            hint_recipes = self._hint_overlay.get_hint_recipes(func_ea)
            has_recipes = bool(hint_recipes)
            recipe_names = [r.name for r in hint_recipes]

            # Read only hint-owned suppressions (not delegate overlay)
            hint_suppressed = self._hint_overlay.get_suppressions(func_ea)
            if hint_suppressed:
                suppressed = sorted(hint_suppressed)

        return {
            "func_ea": func_ea,
            "has_hint_recipes": has_recipes,
            "recipe_names": recipe_names,
            "suppressed_rules": suppressed,
            "generation": self._generation,
        }

    def clear_hint_state(self, func_ea: int) -> None:
        """Clear all hint-driven recipes and suppressions for *func_ea*.

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

        Bridges ``DeobfuscationHints`` -> overlay/recipe activation.
        Accepts any object with ``func_ea``, ``recommended_recipes``,
        and ``suppress_rules`` attributes (duck-typed to avoid a hard
        import of ``d810.recon.models``).

        Args:
            hints: Analysed hints from AnalysisPhase.

        Returns:
            ``ApplyHintsResult`` recording what changed.
        """
        func_ea: int = hints.func_ea
        recommended_recipes: tuple[str, ...] = hints.recommended_recipes
        suppress_rules: tuple[str, ...] = hints.suppress_rules

        generation_before = self._generation
        recipes_applied: list[str] = []
        recipes_not_found: list[str] = []

        # --- 0. Clear previous hint state for this function ------------------
        # Each call is a full replace, not an append: a later call with
        # empty/different hints for the same func_ea retracts earlier decisions.
        had_previous_state = False
        if self._hint_overlay is not None:
            had_previous_state = (
                bool(self._hint_overlay.get_hint_recipes(func_ea))
                or self._hint_overlay.has_suppressions(func_ea)
            )
            self._hint_overlay.clear_func(func_ea)

        # --- 1. Apply recommended recipes -----------------------------------
        for recipe_name in recommended_recipes:
            recipe = self._recipe_registry.get(recipe_name)
            if recipe is None:
                recipes_not_found.append(recipe_name)
                continue
            # Narrow the recipe to this function by adding func_ea to targets
            scoped = RuleRecipeOverlay(
                name=recipe.name,
                enabled_rules=recipe.enabled_rules,
                disabled_rules=recipe.disabled_rules,
                target_func_eas=recipe.target_func_eas | frozenset({func_ea}),
                target_tags_any=recipe.target_tags_any,
                target_tags_all=recipe.target_tags_all,
                notes=recipe.notes,
            )
            # Store per-function via HintOverlayProvider (not global _active_recipe)
            if self._hint_overlay is None:
                self._hint_overlay = HintOverlayProvider(
                    delegate=self._overlay_provider,
                )
                self._overlay_provider = self._hint_overlay
                self._overlay_cache.clear()
            self._hint_overlay.add_recipe(func_ea, scoped)
            recipes_applied.append(recipe_name)

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
        any_change = bool(recipes_applied) or bool(rules_suppressed) or had_previous_state
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
            recipes_applied=tuple(recipes_applied),
            recipes_not_found=tuple(recipes_not_found),
            rules_suppressed=tuple(rules_suppressed),
            cache_invalidated=any_change,
            generation_before=generation_before,
            generation_after=generation_after,
        )
        if logger.debug_on:
            logger.debug(
                "apply_hints func_ea=0x%x: recipes=%s suppressed=%s gen=%d->%d",
                func_ea,
                result.recipes_applied,
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

        # Determine the effective recipe: per-function hint recipe takes
        # precedence over the global _active_recipe for this function.
        effective_recipe = self._active_recipe
        if self._hint_overlay is not None:
            hint_recipe = self._hint_overlay.merged_hint_recipe(func_ea)
            if hint_recipe is not None:
                effective_recipe = hint_recipe

        active_for_maturity: list[Any] = []
        for rule_name in names:
            selector = compiled.selectors.get(f"{pipeline}:{rule_name}")
            if selector is None:
                continue
            if not self._overlay_allows(overlay, rule_name):
                continue
            if not self._recipe_allows(
                recipe=effective_recipe,
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
    def _recipe_targets_function(
        recipe: RuleRecipeOverlay,
        *,
        func_ea: int,
        tags: frozenset[str],
    ) -> bool:
        if recipe.target_func_eas and func_ea not in recipe.target_func_eas:
            return False
        if recipe.target_tags_any and recipe.target_tags_any.isdisjoint(tags):
            return False
        if recipe.target_tags_all and not recipe.target_tags_all.issubset(tags):
            return False
        return True

    @staticmethod
    def _recipe_allows(
        *,
        recipe: RuleRecipeOverlay | None,
        rule_name: str,
        func_ea: int,
        tags: frozenset[str],
    ) -> bool:
        if recipe is None:
            return True
        if not RuleScopeService._recipe_targets_function(
            recipe,
            func_ea=func_ea,
            tags=tags,
        ):
            return True
        if recipe.enabled_rules and rule_name not in recipe.enabled_rules:
            return False
        if rule_name in recipe.disabled_rules:
            return False
        return True
