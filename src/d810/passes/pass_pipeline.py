"""Pipeline vocabulary — the LLVM new-PassManager shape adapted for a vendor backend.

This is the target call-graph vocabulary the optimizers-thinning end-state is built around
(see docs/plans/2026-05-31-optimizers-thinning-execution-workflow-spec.md unflatten). Families return
``PassSpec``s; passes schedule analyses (facts) + transforms (a ``PatchPlan``); a ``MutationBackend``
applies the plan and returns a fresh ``FlowGraph`` snapshot (the sound invalidation epoch).

Additive + behavior-neutral: nothing here is wired into the runtime yet. Net-new types only;
every concept that already exists is *bound to*, never duplicated.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from d810.core.typing import Any, Callable, Protocol, runtime_checkable
from d810.core.config import ProjectConfiguration
from d810.ir.flowgraph import FlowGraph
from d810.ir.maturity import IRMaturity
from d810.analyses.value_flow.model import ValidatedFactView
from d810.capabilities.resolver import CapabilitySet
from d810.passes.scheduler import RunLater
from d810.transforms.plan import PatchPlan

# Rewrite-plan vocabulary alias (canonical home already exists).
RewritePlan = PatchPlan


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

    def enabled_at(self, maturity: IRMaturity | None) -> bool:
        return not self.maturity_gates or maturity in self.maturity_gates


@dataclass(frozen=True)
class PassResult:
    """What a pass produces: derived facts, a (possibly empty) rewrite plan, and an
    OPTIMISTIC same-maturity invalidation hint (the sound base is snapshot identity)."""

    facts: tuple[object, ...] = ()
    rewrite_plan: PatchPlan = field(default_factory=PatchPlan)
    preserved: PreservedAnalyses = field(default_factory=PreservedAnalyses.all)
    run_later: tuple[RunLater, ...] = ()


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
