"""Pipeline vocabulary — the LLVM new-PassManager shape adapted for a vendor backend.

This is the target call-graph vocabulary the optimizers-thinning end-state is built around
(see docs/plans/2026-05-31-optimizers-thinning-execution-workflow-spec.md §1a). Families return
``PassSpec``s; passes schedule analyses (facts) + transforms (a ``PatchPlan``); a ``MutationBackend``
applies the plan and returns a fresh ``FlowGraph`` snapshot (the sound invalidation epoch).

Additive + behavior-neutral: nothing here is wired into the runtime yet. Net-new types only;
every concept that already exists is *bound to*, never duplicated.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Any, Callable, Protocol, runtime_checkable
from d810.core.config import ProjectConfiguration
from d810.ir.flowgraph import FlowGraph, SnapshotStage
from d810.analyses.value_flow.model import ValidatedFactView
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
    maturity: SnapshotStage
    project_config: ProjectConfiguration
    facts: ValidatedFactView


@dataclass(frozen=True)
class CapabilityPolicy:
    """Capabilities a pass requires from the backend (keys like ``"live_mba"``,
    ``"valranges"``, ``"bst_walkers"``). Empty == no special requirements."""

    required: frozenset[str] = frozenset()


@dataclass(frozen=True)
class SafetyPolicy:
    """Guard-rails the backend honours when applying a pass's rewrite plan."""

    name: str = "default"
    golden_required: bool = False


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
class PassResult:
    """What a pass produces: derived facts, a (possibly empty) rewrite plan, and an
    OPTIMISTIC same-maturity invalidation hint (the sound base is snapshot identity)."""

    facts: tuple[object, ...] = ()
    rewrite_plan: PatchPlan = field(default_factory=PatchPlan)
    preserved: PreservedAnalyses = field(default_factory=PreservedAnalyses.all)


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


# Convenience singletons for PassSpec authoring (families read like the §1a pseudocode).
no_caps = CapabilityPolicy()
live_mba = CapabilityPolicy(required=frozenset({"live_mba"}))
default = SafetyPolicy(name="default")
golden = SafetyPolicy(name="golden", golden_required=True)
