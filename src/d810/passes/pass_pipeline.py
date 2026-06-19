"""Pipeline vocabulary — the LLVM new-PassManager shape adapted for a vendor backend.

This is the target call-graph vocabulary the optimizers-thinning end-state is built around
(see docs/plans/2026-05-31-optimizers-thinning-execution-workflow-spec.md unflatten). Families return
``PassSpec``s; passes schedule analyses (facts) + transforms (a ``PatchPlan``); a ``MutationBackend``
applies the plan and returns a fresh ``FlowGraph`` snapshot (the sound invalidation epoch).

Additive + behavior-neutral: nothing here is wired into the runtime yet. Net-new types only;
every concept that already exists is *bound to*, never duplicated.
"""
from __future__ import annotations

from collections.abc import Mapping as ABCMapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from d810.core.typing import Any, Callable, Mapping, Protocol, TypeVar, runtime_checkable
from d810.core.config import ProjectConfiguration
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity
from d810.analyses.value_flow.model import ValidatedFactView
from d810.capabilities.resolver import CapabilitySet
from d810.passes.scheduler import RunLater
from d810.transforms.plan import PatchPlan

# Rewrite-plan vocabulary alias (canonical home already exists).
RewritePlan = PatchPlan

_EnumT = TypeVar("_EnumT", bound=Enum)


class PipelineConfigError(ValueError):
    """Invalid PipelineConfig v2 serialization payload."""


def _require_mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, ABCMapping):
        raise PipelineConfigError(f"{field_name} must be a mapping")
    return value


def _optional_mapping(value: object, field_name: str) -> Mapping[str, object]:
    if value is None:
        return {}
    return _require_mapping(value, field_name)


def _parse_enum(enum_type: type[_EnumT], value: object, field_name: str) -> _EnumT:
    if isinstance(value, enum_type):
        return value
    if isinstance(value, str):
        try:
            return enum_type[value]
        except KeyError:
            pass
        try:
            return enum_type(value)
        except ValueError:
            pass
    raise PipelineConfigError(f"invalid {field_name}: {value!r}")


def _parse_string_set(value: object, field_name: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
        raise PipelineConfigError(f"{field_name} must be a sequence of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise PipelineConfigError(f"{field_name} must contain only strings")
        result.append(item)
    return frozenset(result)


def _parse_maturity_set(value: object, field_name: str) -> frozenset[IRMaturity]:
    if value is None:
        return frozenset()
    if isinstance(value, str) or not isinstance(value, (list, tuple, set, frozenset)):
        raise PipelineConfigError(f"{field_name} must be a sequence of maturities")
    return frozenset(_parse_enum(IRMaturity, item, field_name) for item in value)


def _parse_optional_maturity(value: object, field_name: str) -> IRMaturity | None:
    if value is None:
        return None
    return _parse_enum(IRMaturity, value, field_name)


def _parse_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise PipelineConfigError(f"{field_name} must be a boolean")
    return value


def _parse_nonempty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PipelineConfigError(f"{field_name} must be a non-empty string")
    return value


@runtime_checkable
class FunctionSource(Protocol):
    """Portable handle to the function under analysis plus its live backend source.

    ``live_source`` is the opaque backend object (e.g. a live ``mba_t``) that a
    ``MutationBackend`` consumes when applying a rewrite plan. Portable passes read
    ``flow_graph`` and never touch ``live_source``.
    """

    @property
    def flow_graph(self) -> FlowGraph: ...
    @property
    def func_ea(self) -> int: ...
    @property
    def live_source(self) -> object: ...


@dataclass(frozen=True)
class FunctionPipelineContext:
    """Everything a pipeline pass needs for one function at one maturity."""

    source: FunctionSource
    graph: FlowGraph
    maturity: IRMaturity
    project_config: ProjectConfiguration
    facts: ValidatedFactView
    # Backend-provided capability instances keyed by Protocol type (the north-star
    # ``capabilities`` object). Empty by default — passes query via ``optional`` so a
    # run with no capabilities is a no-op for them.
    capabilities: CapabilitySet = field(default_factory=CapabilitySet)


@dataclass(frozen=True)
class CapabilityPolicy:
    """Capabilities a pass requires from the backend (keys like ``"live_mba"``,
    ``"valranges"``, ``"condition_chain_walkers"``). Empty == no special requirements."""

    required: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SafetyPolicy:
    """Guard-rails the backend honours when applying a pass's rewrite plan."""

    name: str = "default"
    golden_required: bool = False


class PassGranularity(str, Enum):
    """IR unit a pass operates on."""

    FUNCTION = "function"
    CFG = "cfg"


class PassScope(str, Enum):
    """Decompiler-native pass scope for D810 contract metadata."""

    PROGRAM = "program"
    IMAGE = "image"
    SEGMENT = "segment"
    FUNCTION = "function"
    REGION = "region"
    SCC = "scc"
    BLOCK = "block"
    INSTRUCTION = "instruction"
    EXPRESSION = "expression"
    FACT = "fact"


class BackendRoute(str, Enum):
    """Backend apply route for a pass result."""

    MUTATION_BACKEND = "mutation_backend"
    ANALYSIS_ONLY = "analysis_only"


class SchedulerPolicy(str, Enum):
    """How eligible scheduled work enters a pass-manager run."""

    WORKLIST = "worklist"
    REPLAY_AFTER_PIPELINE = "replay_after_pipeline"


@dataclass(frozen=True)
class PreservedAnalyses:
    """LLVM ``PreservedAnalyses`` analog -- an OPTIMISTIC carry-forward HINT, not the
    invalidation mechanism. The sound base is ``FlowGraph`` snapshot identity (a cached fact
    is valid iff computed against the current snapshot); ``MutationBackend.apply`` returns a
    fresh snapshot whose new identity drives invalidation, because apply triggers the vendor
    backend's own re-optimisation. ``preserved`` is layered on top purely as an intra-maturity
    optimisation and must use ``none()`` across maturities.
    """

    all_preserved: bool = True
    kept: frozenset[str] = frozenset()

    @classmethod
    def all(cls) -> "PreservedAnalyses":
        return cls(all_preserved=True)

    @classmethod
    def none(cls) -> "PreservedAnalyses":
        return cls(all_preserved=False, kept=frozenset())

    @classmethod
    def preserving(cls, keys: "frozenset[str] | set[str]") -> "PreservedAnalyses":
        return cls(all_preserved=False, kept=frozenset(keys))

    def preserves(self, key: str) -> bool:
        return self.all_preserved or key in self.kept


@dataclass(frozen=True)
class AnalysisContract:
    """Declared analysis dependencies and products for a pass."""

    required: frozenset[str] = frozenset()
    provided: frozenset[str] = frozenset()


_MATURITY_ORDER: Mapping[IRMaturity, int] = {
    maturity: index for index, maturity in enumerate(IRMaturity)
}


@dataclass(frozen=True)
class MaturityRange:
    """Range/preference metadata for native D810 pass contracts."""

    min: IRMaturity | None = None
    max: IRMaturity | None = None
    preferred: IRMaturity | None = None

    def __post_init__(self) -> None:
        if self.min is not None and self.max is not None:
            if _MATURITY_ORDER[self.min] > _MATURITY_ORDER[self.max]:
                raise PipelineConfigError("maturity.min must not be after maturity.max")
        if self.preferred is not None and not self.contains(self.preferred):
            raise PipelineConfigError("maturity.preferred must be inside maturity range")

    def contains(self, maturity: IRMaturity) -> bool:
        if self.min is not None and _MATURITY_ORDER[maturity] < _MATURITY_ORDER[self.min]:
            return False
        if self.max is not None and _MATURITY_ORDER[maturity] > _MATURITY_ORDER[self.max]:
            return False
        return True

    def to_dict(self) -> dict[str, object]:
        return {
            "min": None if self.min is None else self.min.value,
            "max": None if self.max is None else self.max.value,
            "preferred": None if self.preferred is None else self.preferred.value,
        }

    @classmethod
    def from_dict(cls, payload: object) -> "MaturityRange":
        data = _optional_mapping(payload, "contract.maturity")
        return cls(
            min=_parse_optional_maturity(data.get("min"), "maturity.min"),
            max=_parse_optional_maturity(data.get("max"), "maturity.max"),
            preferred=_parse_optional_maturity(
                data.get("preferred"), "maturity.preferred"
            ),
        )


@dataclass(frozen=True)
class FactRequirement:
    """Required and optional fact inputs declared by a native pass contract."""

    required: frozenset[str] = frozenset()
    optional: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, object]:
        return {
            "required": sorted(self.required),
            "optional": sorted(self.optional),
        }

    @classmethod
    def from_dict(cls, payload: object) -> "FactRequirement":
        data = _optional_mapping(payload, "requires.facts")
        return cls(
            required=_parse_string_set(
                data.get("required", ()), "requires.facts.required"
            ),
            optional=_parse_string_set(
                data.get("optional", ()), "requires.facts.optional"
            ),
        )


@dataclass(frozen=True)
class PassRequires:
    """Analysis/evidence/fact inputs for a native D810 pass contract."""

    analyses: frozenset[str] = frozenset()
    evidence: frozenset[str] = frozenset()
    facts: FactRequirement = field(default_factory=FactRequirement)

    def to_dict(self) -> dict[str, object]:
        return {
            "analyses": sorted(self.analyses),
            "evidence": sorted(self.evidence),
            "facts": self.facts.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: object) -> "PassRequires":
        data = _optional_mapping(payload, "requires")
        return cls(
            analyses=_parse_string_set(data.get("analyses", ()), "requires.analyses"),
            evidence=_parse_string_set(data.get("evidence", ()), "requires.evidence"),
            facts=FactRequirement.from_dict(data.get("facts", {})),
        )


@dataclass(frozen=True)
class PassOutputs:
    """Fact outputs produced by a native D810 pass contract."""

    facts: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, object]:
        return {"facts": sorted(self.facts)}

    @classmethod
    def from_dict(cls, payload: object) -> "PassOutputs":
        data = _optional_mapping(payload, "outputs")
        return cls(facts=_parse_string_set(data.get("facts", ()), "outputs.facts"))


@dataclass(frozen=True)
class PassPreserves:
    """Analysis and fact namespaces preserved by a native D810 pass contract."""

    analyses: frozenset[str] = frozenset()
    facts: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, object]:
        return {
            "analyses": sorted(self.analyses),
            "facts": sorted(self.facts),
        }

    @classmethod
    def from_dict(cls, payload: object, field_name: str) -> "PassPreserves":
        data = _optional_mapping(payload, field_name)
        return cls(
            analyses=_parse_string_set(
                data.get("analyses", ()), f"{field_name}.analyses"
            ),
            facts=_parse_string_set(data.get("facts", ()), f"{field_name}.facts"),
        )


@dataclass(frozen=True)
class PassInvalidates:
    """Analysis and fact namespaces invalidated by a native D810 pass contract."""

    analyses: frozenset[str] = frozenset()
    facts: frozenset[str] = frozenset()

    def to_dict(self) -> dict[str, object]:
        return {
            "analyses": sorted(self.analyses),
            "facts": sorted(self.facts),
        }

    @classmethod
    def from_dict(cls, payload: object, field_name: str) -> "PassInvalidates":
        data = _optional_mapping(payload, field_name)
        return cls(
            analyses=_parse_string_set(
                data.get("analyses", ()), f"{field_name}.analyses"
            ),
            facts=_parse_string_set(data.get("facts", ()), f"{field_name}.facts"),
        )


@dataclass(frozen=True)
class PassSafety:
    """Safety policy metadata for native D810 pass contracts."""

    policy: str = "default"
    requires_oracle: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "policy": self.policy,
            "requires_oracle": self.requires_oracle,
        }

    @classmethod
    def from_dict(cls, payload: object) -> "PassSafety":
        data = _optional_mapping(payload, "safety")
        return cls(
            policy=_parse_nonempty_string(data.get("policy", "default"), "safety.policy"),
            requires_oracle=_parse_bool(
                data.get("requires_oracle", False), "safety.requires_oracle"
            ),
        )


@dataclass(frozen=True)
class PassContract:
    """D810-native deobfuscation pass contract metadata.

    Analysis validity is intentionally separate from evidence and fact validity.
    For example, a pass may preserve ``dominators`` while invalidating raw
    dispatcher evidence or stale CFG-shape facts.
    """

    scope: PassScope = PassScope.FUNCTION
    maturity: MaturityRange = field(default_factory=MaturityRange)
    requires: PassRequires = field(default_factory=PassRequires)
    outputs: PassOutputs = field(default_factory=PassOutputs)
    preserves: PassPreserves = field(default_factory=PassPreserves)
    invalidates: PassInvalidates = field(default_factory=PassInvalidates)
    safety: PassSafety = field(default_factory=PassSafety)

    def to_dict(self) -> dict[str, object]:
        return {
            "scope": self.scope.value,
            "maturity": self.maturity.to_dict(),
            "requires": self.requires.to_dict(),
            "outputs": self.outputs.to_dict(),
            "preserves": self.preserves.to_dict(),
            "invalidates": self.invalidates.to_dict(),
            "safety": self.safety.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: object) -> "PassContract":
        data = _optional_mapping(payload, "contract")
        return cls(
            scope=_parse_enum(
                PassScope,
                data.get("scope", PassScope.FUNCTION.value),
                "scope",
            ),
            maturity=MaturityRange.from_dict(data.get("maturity", {})),
            requires=PassRequires.from_dict(data.get("requires", {})),
            outputs=PassOutputs.from_dict(data.get("outputs", {})),
            preserves=PassPreserves.from_dict(data.get("preserves", {}), "preserves"),
            invalidates=PassInvalidates.from_dict(
                data.get("invalidates", {}), "invalidates"
            ),
            safety=PassSafety.from_dict(data.get("safety", {})),
        )


@dataclass(frozen=True)
class PipelineConfig:
    """PipelineConfig v2: declarative pass-manager contract."""

    pass_id: str
    maturity_gates: frozenset[IRMaturity] = frozenset()
    granularity: PassGranularity = PassGranularity.FUNCTION
    requirements: CapabilityPolicy = field(default_factory=CapabilityPolicy)
    analyses: AnalysisContract = field(default_factory=AnalysisContract)
    preservation: PreservedAnalyses = field(default_factory=PreservedAnalyses.all)
    scheduler_policy: SchedulerPolicy = SchedulerPolicy.WORKLIST
    backend_route: BackendRoute = BackendRoute.MUTATION_BACKEND
    safety_policy: SafetyPolicy = field(default_factory=SafetyPolicy)
    contract: PassContract = field(default_factory=PassContract)

    def enabled_at(self, maturity: IRMaturity | None) -> bool:
        if self.maturity_gates:
            return maturity in self.maturity_gates
        if self.contract.maturity != MaturityRange():
            return maturity is not None and self.contract.maturity.contains(maturity)
        return True

    def to_dict(self) -> dict[str, object]:
        """Serialize this config using stable string values."""
        return {
            "pass_id": self.pass_id,
            "maturity_gates": sorted(stage.value for stage in self.maturity_gates),
            "granularity": self.granularity.value,
            "requirements": {
                "required": sorted(self.requirements.required),
            },
            "analyses": {
                "required": sorted(self.analyses.required),
                "provided": sorted(self.analyses.provided),
            },
            "preservation": {
                "all_preserved": self.preservation.all_preserved,
                "kept": sorted(self.preservation.kept),
            },
            "scheduler_policy": self.scheduler_policy.value,
            "backend_route": self.backend_route.value,
            "safety_policy": {
                "name": self.safety_policy.name,
                "golden_required": self.safety_policy.golden_required,
            },
            "contract": self.contract.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "PipelineConfig":
        """Deserialize a PipelineConfig v2 payload.

        Enum fields accept either enum names (``WORKLIST``) or stable values
        (``worklist``). ``IRMaturity`` gates accept enum names or values too.
        """
        data = _require_mapping(payload, "pipeline config")
        pass_id = data.get("pass_id", data.get("pass"))
        if not isinstance(pass_id, str) or not pass_id:
            raise PipelineConfigError("pass_id must be a non-empty string")

        requirements_data = _require_mapping(
            data.get("requirements", {}), "requirements"
        )
        analyses_data = _require_mapping(data.get("analyses", {}), "analyses")
        preservation_data = _require_mapping(
            data.get("preservation", {}), "preservation"
        )
        safety_policy_data = _require_mapping(
            data.get("safety_policy", {}), "safety_policy"
        )
        contract_payload = data.get("contract")
        if contract_payload is None:
            contract_payload = {
                key: data[key]
                for key in (
                    "scope",
                    "maturity",
                    "requires",
                    "outputs",
                    "preserves",
                    "invalidates",
                    "safety",
                )
                if key in data
            }

        maturity_gates = _parse_maturity_set(
            data.get("maturity_gates", ()), "maturity_gates"
        )
        preservation = PreservedAnalyses(
            all_preserved=_parse_bool(
                preservation_data.get("all_preserved", True),
                "preservation.all_preserved",
            ),
            kept=_parse_string_set(
                preservation_data.get("kept", ()), "preservation.kept"
            ),
        )
        return cls(
            pass_id=pass_id,
            maturity_gates=maturity_gates,
            granularity=_parse_enum(
                PassGranularity,
                data.get("granularity", PassGranularity.FUNCTION.value),
                "granularity",
            ),
            requirements=CapabilityPolicy(
                required=_parse_string_set(
                    requirements_data.get("required", ()),
                    "requirements.required",
                )
            ),
            analyses=AnalysisContract(
                required=_parse_string_set(
                    analyses_data.get("required", ()), "analyses.required"
                ),
                provided=_parse_string_set(
                    analyses_data.get("provided", ()), "analyses.provided"
                ),
            ),
            preservation=preservation,
            scheduler_policy=_parse_enum(
                SchedulerPolicy,
                data.get("scheduler_policy", SchedulerPolicy.WORKLIST.value),
                "scheduler_policy",
            ),
            backend_route=_parse_enum(
                BackendRoute,
                data.get("backend_route", BackendRoute.MUTATION_BACKEND.value),
                "backend_route",
            ),
            safety_policy=SafetyPolicy(
                name=_parse_nonempty_string(
                    safety_policy_data.get("name", "default"),
                    "safety_policy.name",
                ),
                golden_required=_parse_bool(
                    safety_policy_data.get("golden_required", False),
                    "safety_policy.golden_required",
                ),
            ),
            contract=PassContract.from_dict(contract_payload),
        )


_PRESERVED_UNSET = object()


@dataclass(frozen=True, init=False)
class PassResult:
    """What a pass produces: derived facts, a (possibly empty) rewrite plan, and an
    OPTIMISTIC same-maturity invalidation hint (the sound base is snapshot identity).

    ``preserved`` remains default-all for legacy callers. The custom initializer also
    records whether the caller supplied it explicitly, so the driver can use the
    owning ``PassSpec``'s preservation default when a result truly omits a policy.
    """

    facts: tuple[object, ...]
    rewrite_plan: PatchPlan
    preserved: PreservedAnalyses
    run_later: tuple[RunLater, ...]
    analysis_outputs: Mapping[str, object]
    _preserved_explicit: bool = field(default=False, repr=False, compare=False)

    def __init__(
        self,
        *,
        facts: tuple[object, ...] = (),
        rewrite_plan: PatchPlan | None = None,
        preserved: PreservedAnalyses | object = _PRESERVED_UNSET,
        run_later: tuple[RunLater, ...] = (),
        analysis_outputs: Mapping[str, object] | None = None,
    ) -> None:
        preserved_explicit = preserved is not _PRESERVED_UNSET
        preserved_value = (
            preserved if preserved_explicit else PreservedAnalyses.all()
        )
        object.__setattr__(self, "facts", facts)
        object.__setattr__(
            self,
            "rewrite_plan",
            rewrite_plan if rewrite_plan is not None else PatchPlan(),
        )
        object.__setattr__(self, "preserved", preserved_value)
        object.__setattr__(self, "run_later", run_later)
        object.__setattr__(
            self,
            "analysis_outputs",
            MappingProxyType({} if analysis_outputs is None else dict(analysis_outputs)),
        )
        object.__setattr__(self, "_preserved_explicit", preserved_explicit)

    @property
    def preserved_explicit(self) -> bool:
        """Whether this result supplied a result-level preservation policy."""
        return self._preserved_explicit


@runtime_checkable
class PipelinePass(Protocol):
    name: str

    def run(self, context: FunctionPipelineContext) -> PassResult: ...


@dataclass(frozen=True)
class PassSpec:
    """Declarative registration of a pass: how to build it + its policies."""

    name: str
    pass_factory: Callable[..., PipelinePass]
    requirements: CapabilityPolicy
    safety_policy: SafetyPolicy
    maturity_gates: frozenset[IRMaturity] = frozenset()
    granularity: PassGranularity = PassGranularity.FUNCTION
    analyses: AnalysisContract = field(default_factory=AnalysisContract)
    preservation: PreservedAnalyses = field(default_factory=PreservedAnalyses.all)
    scheduler_policy: SchedulerPolicy = SchedulerPolicy.WORKLIST
    backend_route: BackendRoute = BackendRoute.MUTATION_BACKEND
    contract: PassContract = field(default_factory=PassContract)

    @property
    def pass_id(self) -> str:
        return self.name

    @property
    def config(self) -> PipelineConfig:
        return PipelineConfig(
            pass_id=self.pass_id,
            maturity_gates=self.maturity_gates,
            granularity=self.granularity,
            requirements=self.requirements,
            analyses=self.analyses,
            preservation=self.preservation,
            scheduler_policy=self.scheduler_policy,
            backend_route=self.backend_route,
            safety_policy=self.safety_policy,
            contract=self.contract,
        )

    def enabled_at(self, maturity: IRMaturity | None) -> bool:
        return self.config.enabled_at(maturity)


@runtime_checkable
class MutationBackend(Protocol):
    """Backend apply boundary. The Hex-Rays implementation lives in ``backends/hexrays``
    and satisfies this structurally. ``apply`` returns a FRESH ``FlowGraph`` snapshot of the
    post-apply state -- the new snapshot identity (not ``preserved``) is the source of truth
    for what is now stale.
    """

    def apply(
        self,
        rewrite_plan: PatchPlan,
        live_source: object,
        safety_policy: SafetyPolicy,
    ) -> FlowGraph: ...


# Convenience singletons for PassSpec authoring (families read like the unflatten pseudocode).
no_caps = CapabilityPolicy()
live_mba = CapabilityPolicy(required=frozenset({"live_mba"}))
default = SafetyPolicy(name="default")
golden = SafetyPolicy(name="golden", golden_required=True)
