"""unflatten driver acceptance (structural): run_pipeline IS the north-star loop.

Exercises the portable driver with injected null deps + the real HodurFamily passes:
detect -> pipeline_for -> validate_capabilities -> pass.run -> (apply on non-empty plan).
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from d810.passes.analysis_manager import AnalysisManager
from d810.analyses.value_flow.contract_evidence import contract_evidence_payload
from d810.passes.pass_pipeline import (
    AnalysisContract,
    BackendRoute,
    FactRequirement,
    FunctionPipelineContext,
    PassContract,
    PassInvalidates,
    PassOutputs,
    PassResult,
    PassRequires,
    PassSpec,
    PassPreserves,
    PassSafety,
    PipelineConfig,
    PreservedAnalyses,
    SafetyPolicy,
    SchedulerPolicy,
    default,
    live_mba,
    no_caps,
)
from d810.passes.scheduler import PassScheduler, RunLater, RunLaterDomain
from d810.passes.registry import PassRegistry
from d810.transforms.plan import PatchPlan
from d810.passes.driver import (
    AnalysisContractError,
    BackendRouteError,
    CapabilityError,
    PassContractError,
    effective_safety_policy,
    run_pipeline,
    validate_capabilities,
)
from d810.families.state_machine_cff import HodurFamily
from d810.families.state_machine_cff.pipeline import standard_state_machine_passes
from d810.families.state_machine_cff import approov as approov_pipeline
from d810.families.state_machine_cff import tigress as tigress_pipeline
from d810.families.state_machine_cff import ApproovFamily
from d810.families.state_machine_cff import TigressFamily
from d810.families.registry import select_family, registered_families
from d810.capabilities.dispatcher import RouterKind, TableProvenance
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity

# A real 1-block FlowGraph so the (now real) recover_dispatcher pass can run over it.
_GRAPH = FlowGraph(
    blocks={
        0: BlockSnapshot(
            serial=0, block_type=1, succs=(), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=(),
        )
    },
    entry_serial=0,
    func_ea=0x1000,
)


# --- minimal injected test doubles -------------------------------------------------
@dataclass
class _Src:
    flow_graph: object = _GRAPH
    func_ea: int = 0x1000
    live_source: object = "LIVE"


class _Facts:
    def __init__(self):
        self.invalidations = 0
        self.last_graph = None
        self.last_preserved = None

    def view(self):
        return self

    def invalidate_to(self, graph, preserved):
        self.invalidations += 1
        self.last_graph = graph
        self.last_preserved = preserved


class _Backend:
    def __init__(self, caps=("live_mba",)):
        self._caps = frozenset(caps)
        self.applied = 0
        self.safety_policies = []

    def capabilities(self):
        return self._caps

    def apply(self, plan, live_source, safety_policy):
        self.applied += 1
        self.safety_policies.append(safety_policy)
        return "G1"  # fresh snapshot identity


class _RecordingScheduler:
    def __init__(self):
        self.requests = []

    def request(self, **kwargs):
        self.requests.append(kwargs)
        return True

    def drain(self, **kwargs):
        return ()


class _MatchingHodur:
    """A Family-Protocol double (NOT a registered profile — does not subclass the
    Registrant family, else it would auto-register and pollute select_family) whose
    detect() returns a match; pipeline_for delegates to the real HodurFamily."""

    name = "matching_hodur"

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return HodurFamily().pipeline_for(match, context)


def _run_specs(
    specs: tuple[PassSpec, ...],
    *,
    facts=None,
    backend=None,
    maturity=IRMaturity.CANONICAL,
):
    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return specs

    return run_pipeline(
        source=_Src(),
        family=_OneShot(),
        backend=backend if backend is not None else _Backend(),
        facts=facts if facts is not None else AnalysisManager(_GRAPH),
        project_config=None,
        maturity=maturity,
    )


class _MutatingPass:
    name = "mutating"

    def run(self, ctx) -> PassResult:
        return PassResult(
            rewrite_plan=PatchPlan(planner_modifications=(object(),))
        )


def test_run_pipeline_runs_all_five_passes_no_apply_on_empty_plans():
    backend = _Backend()
    facts = AnalysisManager(_GRAPH)
    out = run_pipeline(
        source=_Src(), family=_MatchingHodur(), backend=backend,
        facts=facts, project_config=None, maturity=None,
    )
    # skeleton transforms emit empty plans -> backend.apply never called, graph unchanged.
    assert backend.applied == 0
    assert out is _GRAPH


def test_run_pipeline_does_not_record_empty_run_later_requests():
    backend = _Backend()
    facts = AnalysisManager(_GRAPH)
    scheduler = _RecordingScheduler()
    run_pipeline(
        source=_Src(), family=_MatchingHodur(), backend=backend,
        facts=facts, project_config=None, maturity=IRMaturity.CANONICAL,
        scheduler=scheduler,
    )
    assert scheduler.requests == []


def test_default_safety_policy_still_reaches_backend_for_specs_without_native_safety():
    backend = _Backend()

    _run_specs((PassSpec("mutating", _MutatingPass, no_caps, default),), backend=backend)

    assert backend.safety_policies == [SafetyPolicy()]


def test_native_contract_safety_policy_reaches_backend_when_legacy_default():
    backend = _Backend()
    spec = PassSpec(
        "mutating",
        _MutatingPass,
        no_caps,
        default,
        contract=PassContract(
            safety=PassSafety(policy="guarded-rewrite", requires_oracle=False)
        ),
    )

    assert effective_safety_policy(spec) == SafetyPolicy(
        name="guarded-rewrite",
        golden_required=False,
    )

    _run_specs((spec,), backend=backend)

    assert backend.safety_policies == [
        SafetyPolicy(name="guarded-rewrite", golden_required=False)
    ]


def test_native_contract_safety_requires_oracle_maps_to_golden_required():
    backend = _Backend()
    spec = PassSpec(
        "mutating",
        _MutatingPass,
        no_caps,
        default,
        contract=PassContract(
            safety=PassSafety(policy="guarded-rewrite", requires_oracle=True)
        ),
    )

    _run_specs((spec,), backend=backend)

    assert backend.safety_policies == [
        SafetyPolicy(name="guarded-rewrite", golden_required=True)
    ]


def test_legacy_safety_policy_takes_precedence_over_native_contract_safety():
    backend = _Backend()
    legacy = SafetyPolicy(name="legacy-golden", golden_required=True)
    spec = PassSpec(
        "mutating",
        _MutatingPass,
        no_caps,
        legacy,
        contract=PassContract(
            safety=PassSafety(policy="guarded-rewrite", requires_oracle=False)
        ),
    )

    assert effective_safety_policy(spec) == legacy

    _run_specs((spec,), backend=backend)

    assert backend.safety_policies == [legacy]


def test_registry_config_contract_safety_is_used_by_runtime_bridge():
    registry = PassRegistry()
    registry.register("mutating", _MutatingPass)
    config = PipelineConfig(
        pass_id="mutating",
        contract=PassContract(
            safety=PassSafety(policy="guarded-rewrite", requires_oracle=True)
        ),
    )
    spec = registry.build_spec(config)
    backend = _Backend()

    _run_specs((spec,), backend=backend)

    assert spec.contract.safety == PassSafety(
        policy="guarded-rewrite",
        requires_oracle=True,
    )
    assert backend.safety_policies == [
        SafetyPolicy(name="guarded-rewrite", golden_required=True)
    ]


def test_run_pipeline_no_match_is_a_noop():
    backend = _Backend()
    out = run_pipeline(
        source=_Src(), family=HodurFamily(), backend=backend,  # detect() -> None
        facts=_Facts(), project_config=None, maturity=None,
    )
    assert backend.applied == 0 and out is _GRAPH


def test_run_pipeline_applies_nonempty_plan_and_invalidates():
    """A pass that emits a real plan drives backend.apply + facts.invalidate + re-context."""
    class _Mutator:
        name = "mutate"

        def run(self, ctx) -> PassResult:
            # Non-empty plan via the planner_modifications channel the driver checks.
            plan = PatchPlan(planner_modifications=(object(),))
            return PassResult(rewrite_plan=plan)

    class _OneShot:
        # Standalone Family-Protocol double (not a Registrant subclass -> no registration).
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (PassSpec("mutate", _Mutator, no_caps, default),)

    backend, facts = _Backend(), _Facts()
    out = run_pipeline(
        source=_Src(), family=_OneShot(), backend=backend,
        facts=facts, project_config=None, maturity=None,
    )
    assert backend.applied == 1
    assert facts.invalidations == 1
    assert out == "G1"


def test_missing_required_analysis_raises_contract_error():
    class _NeedsDomtree:
        name = "needs_domtree"

        def run(self, ctx) -> PassResult:
            return PassResult()

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "needs_domtree",
                    _NeedsDomtree,
                    no_caps,
                    default,
                    analyses=AnalysisContract(
                        required=frozenset({"domtree"}),
                    ),
                ),
            )

    with pytest.raises(AnalysisContractError, match="missing required analyses"):
        run_pipeline(
            source=_Src(), family=_OneShot(), backend=_Backend(),
            facts=AnalysisManager(_GRAPH), project_config=None,
            maturity=IRMaturity.CANONICAL,
        )


def test_required_analysis_present_runs():
    class _NeedsDomtree:
        name = "needs_domtree"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.get_analysis("domtree") == "D"
            return PassResult()

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "needs_domtree",
                    _NeedsDomtree,
                    no_caps,
                    default,
                    analyses=AnalysisContract(
                        required=frozenset({"domtree"}),
                    ),
                ),
            )

    facts = AnalysisManager(_GRAPH)
    facts.put_analysis("domtree", "D")

    out = run_pipeline(
        source=_Src(), family=_OneShot(), backend=_Backend(),
        facts=facts, project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert out is _GRAPH


def test_required_analysis_provider_runs():
    calls: list[object] = []

    class _NeedsDomtree:
        name = "needs_domtree"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.get_analysis("domtree") == "D"
            return PassResult()

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "needs_domtree",
                    _NeedsDomtree,
                    no_caps,
                    default,
                    analyses=AnalysisContract(
                        required=frozenset({"domtree"}),
                    ),
                ),
            )

    facts = AnalysisManager(
        _GRAPH,
        providers={"domtree": lambda graph: calls.append(graph) or "D"},
    )

    out = run_pipeline(
        source=_Src(), family=_OneShot(), backend=_Backend(),
        facts=facts, project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert out is _GRAPH
    assert calls == [_GRAPH]


def test_native_contract_required_analysis_missing_raises_contract_error():
    class _NeedsDomtree:
        name = "needs_domtree"

        def run(self, ctx) -> PassResult:
            return PassResult()

    spec = PassSpec(
        "needs_domtree",
        _NeedsDomtree,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(analyses=frozenset({"domtree"}))
        ),
    )

    with pytest.raises(PassContractError, match="analyses"):
        _run_specs((spec,))


def test_native_contract_required_analysis_provider_runs():
    calls: list[object] = []

    class _NeedsDomtree:
        name = "needs_domtree"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.get_analysis("domtree") == "D"
            return PassResult()

    spec = PassSpec(
        "needs_domtree",
        _NeedsDomtree,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(analyses=frozenset({"domtree"}))
        ),
    )
    facts = AnalysisManager(
        _GRAPH,
        providers={"domtree": lambda graph: calls.append(graph) or "D"},
    )

    _run_specs((spec,), facts=facts)

    assert calls == [_GRAPH]


def test_native_contract_required_fact_missing_raises_contract_error():
    class _NeedsFact:
        name = "needs_fact"

        def run(self, ctx) -> PassResult:
            return PassResult()

    spec = PassSpec(
        "needs_fact",
        _NeedsFact,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(
                facts=FactRequirement(required=frozenset({"state_transition"}))
            )
        ),
    )

    with pytest.raises(PassContractError, match="facts"):
        _run_specs((spec,))


def test_native_contract_required_fact_accepts_live_observation_kind():
    observation = type("_Obs", (), {"kind": "state_transition"})()

    class _NeedsFact:
        name = "needs_fact"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_fact("state_transition")
            return PassResult()

    spec = PassSpec(
        "needs_fact",
        _NeedsFact,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(
                facts=FactRequirement(required=frozenset({"state_transition"}))
            )
        ),
    )
    facts = AnalysisManager(
        _GRAPH,
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    _run_specs((spec,), facts=facts)


def test_native_contract_optional_fact_missing_still_runs():
    ran = False

    class _OptionalFact:
        name = "optional_fact"

        def run(self, ctx) -> PassResult:
            nonlocal ran
            ran = True
            return PassResult()

    spec = PassSpec(
        "optional_fact",
        _OptionalFact,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(
                facts=FactRequirement(optional=frozenset({"carrier_store_candidates"}))
            )
        ),
    )

    _run_specs((spec,))

    assert ran is True


def test_native_contract_required_evidence_missing_raises_contract_error():
    class _NeedsEvidence:
        name = "needs_evidence"

        def run(self, ctx) -> PassResult:
            return PassResult()

    spec = PassSpec(
        "needs_evidence",
        _NeedsEvidence,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(evidence=frozenset({"dispatcher_predicates"}))
        ),
    )

    with pytest.raises(PassContractError, match="evidence"):
        _run_specs((spec,))


def test_native_contract_required_evidence_accepts_live_canonical_observation_token():
    observation = type(
        "_Obs",
        (),
        {
            "payload": contract_evidence_payload("dispatcher_predicates"),
            "evidence": ("cmp %state, #1",),
        },
    )()

    class _NeedsEvidence:
        name = "needs_evidence"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_evidence("dispatcher_predicates")
            return PassResult()

    spec = PassSpec(
        "needs_evidence",
        _NeedsEvidence,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(evidence=frozenset({"dispatcher_predicates"}))
        ),
    )
    facts = AnalysisManager(
        _GRAPH,
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    _run_specs((spec,), facts=facts)


def test_native_contract_required_evidence_rejects_raw_diagnostic_observation_text():
    observation = type(
        "_Obs",
        (),
        {"evidence": ("dispatcher_predicates", "cmp %state, #1")},
    )()

    class _NeedsEvidence:
        name = "needs_evidence"

        def run(self, ctx) -> PassResult:
            return PassResult()

    spec = PassSpec(
        "needs_evidence",
        _NeedsEvidence,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(evidence=frozenset({"dispatcher_predicates"}))
        ),
    )
    facts = AnalysisManager(
        _GRAPH,
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    with pytest.raises(PassContractError, match="evidence"):
        _run_specs((spec,), facts=facts)


def test_native_contract_state_write_evidence_accepts_canonical_state_write_fact():
    observation = type(
        "_Obs",
        (),
        {
            "kind": "StateWriteAnchorFact",
            "payload": {
                "state_var_stkoff": 0x10,
                **contract_evidence_payload("state_variable_writes"),
            },
            "evidence": ("mov #1, %var_10.4",),
        },
    )()

    class _NeedsStateWriteEvidence:
        name = "needs_state_write_evidence"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_evidence("state_variable_writes")
            return PassResult()

    spec = PassSpec(
        "needs_state_write_evidence",
        _NeedsStateWriteEvidence,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(evidence=frozenset({"state_variable_writes"}))
        ),
    )
    facts = AnalysisManager(
        _GRAPH,
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    _run_specs((spec,), facts=facts)


def test_native_contract_state_write_evidence_rejects_raw_matching_text():
    observation = type(
        "_Obs",
        (),
        {"evidence": ("state_variable_writes", "mov #1, %var_10.4")},
    )()

    class _NeedsStateWriteEvidence:
        name = "needs_state_write_evidence"

        def run(self, ctx) -> PassResult:
            return PassResult()

    spec = PassSpec(
        "needs_state_write_evidence",
        _NeedsStateWriteEvidence,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(evidence=frozenset({"state_variable_writes"}))
        ),
    )
    facts = AnalysisManager(
        _GRAPH,
        input_facts=type("_Facts", (), {"active_observations": (observation,)})(),
    )

    with pytest.raises(PassContractError, match="evidence"):
        _run_specs((spec,), facts=facts)


def test_native_contract_required_evidence_accepts_explicit_published_token():
    class _NeedsEvidence:
        name = "needs_evidence"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_evidence("dispatcher_predicates")
            return PassResult()

    spec = PassSpec(
        "needs_evidence",
        _NeedsEvidence,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(evidence=frozenset({"dispatcher_predicates"}))
        ),
    )
    facts = AnalysisManager(_GRAPH)
    facts.put_evidence("dispatcher_predicates", object())

    _run_specs((spec,), facts=facts)


def test_graph_changing_mutation_clears_evidence_before_later_requirement():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_evidence("branch_targets")
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _NeedsEvidence:
        name = "needs_evidence"

        def run(self, ctx) -> PassResult:
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_evidence("branch_targets", object())
    specs = (
        PassSpec("mutator", _Mutator, no_caps, default),
        PassSpec(
            "needs_evidence",
            _NeedsEvidence,
            no_caps,
            default,
            contract=PassContract(
                requires=PassRequires(evidence=frozenset({"branch_targets"}))
            ),
        ),
    )

    with pytest.raises(PassContractError, match="branch_targets"):
        _run_specs(specs, facts=facts)


def test_native_contract_output_fact_publishes_for_later_required_fact():
    fact = type("_Fact", (), {"kind": "state_transition"})()

    class _PublishFact:
        name = "publish_fact"

        def run(self, ctx) -> PassResult:
            return PassResult(facts=(fact,))

    class _NeedsFact:
        name = "needs_fact"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.get_fact("state_transition") == (fact,)
            return PassResult()

    specs = (
        PassSpec(
            "publish_fact",
            _PublishFact,
            no_caps,
            default,
            contract=PassContract(
                outputs=PassOutputs(facts=frozenset({"state_transition"}))
            ),
        ),
        PassSpec(
            "needs_fact",
            _NeedsFact,
            no_caps,
            default,
            contract=PassContract(
                requires=PassRequires(
                    facts=FactRequirement(required=frozenset({"state_transition"}))
                )
            ),
        ),
    )

    _run_specs(specs)


def test_native_contract_output_fact_rejects_unexpected_kind():
    class _PublishFact:
        name = "publish_fact"

        def run(self, ctx) -> PassResult:
            return PassResult(facts=(type("_Fact", (), {"kind": "unexpected"})(),))

    spec = PassSpec(
        "publish_fact",
        _PublishFact,
        no_caps,
        default,
        contract=PassContract(
            outputs=PassOutputs(facts=frozenset({"state_transition"}))
        ),
    )

    with pytest.raises(PassContractError, match="undeclared contract facts"):
        _run_specs((spec,))


def test_native_contract_output_fact_rejects_missing_kind():
    class _PublishFact:
        name = "publish_fact"

        def run(self, ctx) -> PassResult:
            return PassResult(facts=(object(),))

    spec = PassSpec(
        "publish_fact",
        _PublishFact,
        no_caps,
        default,
        contract=PassContract(
            outputs=PassOutputs(facts=frozenset({"state_transition"}))
        ),
    )

    with pytest.raises(PassContractError, match="without a kind"):
        _run_specs((spec,))


def test_native_contract_invalidation_drops_fact_while_preserving_analysis():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_analysis("dominators")
            assert not ctx.facts.has_fact("state_transition")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_analysis("dominators", "D")
    facts.put_fact("state_transition", type("_Fact", (), {"kind": "state_transition"})())
    specs = (
        PassSpec(
            "mutator",
            _Mutator,
            no_caps,
            default,
            preservation=PreservedAnalyses.preserving({"dominators"}),
            contract=PassContract(
                preserves=PassPreserves(analyses=frozenset({"dominators"})),
                invalidates=PassInvalidates(facts=frozenset({"state_transition"})),
            ),
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts)


def test_native_contract_preserves_analyses_when_result_omits_policy():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_analysis("dominators")
            assert not ctx.facts.has_analysis("value_ranges")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_analysis("dominators", "D")
    facts.put_analysis("value_ranges", "V")
    specs = (
        PassSpec(
            "mutator",
            _Mutator,
            no_caps,
            default,
            contract=PassContract(
                preserves=PassPreserves(analyses=frozenset({"dominators"}))
            ),
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts)


def test_result_level_preservation_overrides_native_contract_preserves():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(
                rewrite_plan=PatchPlan(planner_modifications=(object(),)),
                preserved=PreservedAnalyses.preserving({"value_ranges"}),
            )

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert not ctx.facts.has_analysis("dominators")
            assert ctx.facts.has_analysis("value_ranges")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_analysis("dominators", "D")
    facts.put_analysis("value_ranges", "V")
    specs = (
        PassSpec(
            "mutator",
            _Mutator,
            no_caps,
            default,
            contract=PassContract(
                preserves=PassPreserves(analyses=frozenset({"dominators"}))
            ),
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts)


def test_native_contract_preserves_facts_after_graph_changing_mutation():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_fact("raw_instruction_addresses")
            assert not ctx.facts.has_fact("stale_cfg_shape")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_fact(
        "raw_instruction_addresses",
        type("_Fact", (), {"kind": "raw_instruction_addresses"})(),
    )
    facts.put_fact("stale_cfg_shape", type("_Fact", (), {"kind": "stale_cfg_shape"})())
    specs = (
        PassSpec(
            "mutator",
            _Mutator,
            no_caps,
            default,
            contract=PassContract(
                preserves=PassPreserves(facts=frozenset({"raw_instruction_addresses"}))
            ),
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts)


def test_native_contract_invalidates_facts_override_preserves_facts():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_fact("raw_instruction_addresses")
            assert not ctx.facts.has_fact("stale_cfg_shape")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_fact(
        "raw_instruction_addresses",
        type("_Fact", (), {"kind": "raw_instruction_addresses"})(),
    )
    facts.put_fact("stale_cfg_shape", type("_Fact", (), {"kind": "stale_cfg_shape"})())
    specs = (
        PassSpec(
            "mutator",
            _Mutator,
            no_caps,
            default,
            contract=PassContract(
                preserves=PassPreserves(
                    facts=frozenset({"raw_instruction_addresses", "stale_cfg_shape"})
                ),
                invalidates=PassInvalidates(facts=frozenset({"stale_cfg_shape"})),
            ),
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts)


def test_empty_native_fact_preservation_keeps_legacy_fact_behavior_on_mutation():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_fact("raw_instruction_addresses")
            assert ctx.facts.has_fact("stale_cfg_shape")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_fact(
        "raw_instruction_addresses",
        type("_Fact", (), {"kind": "raw_instruction_addresses"})(),
    )
    facts.put_fact("stale_cfg_shape", type("_Fact", (), {"kind": "stale_cfg_shape"})())
    specs = (
        PassSpec(
            "mutator",
            _Mutator,
            no_caps,
            default,
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts)


def test_native_fact_preservation_does_not_preserve_analyses():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_fact("raw_instruction_addresses")
            assert not ctx.facts.has_analysis("dominators")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_analysis("dominators", "D")
    facts.put_fact(
        "raw_instruction_addresses",
        type("_Fact", (), {"kind": "raw_instruction_addresses"})(),
    )
    specs = (
        PassSpec(
            "mutator",
            _Mutator,
            no_caps,
            default,
            preservation=PreservedAnalyses.none(),
            contract=PassContract(
                preserves=PassPreserves(facts=frozenset({"raw_instruction_addresses"}))
            ),
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts)


def test_preserved_fact_and_analysis_do_not_preserve_evidence_after_mutation():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_analysis("dominators")
            assert ctx.facts.has_fact("raw_instruction_addresses")
            assert not ctx.facts.has_evidence("branch_targets")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    facts.put_analysis("dominators", "D")
    facts.put_fact(
        "raw_instruction_addresses",
        type("_Fact", (), {"kind": "raw_instruction_addresses"})(),
    )
    facts.put_evidence("branch_targets", object())
    specs = (
        PassSpec(
            "mutator",
            _Mutator,
            no_caps,
            default,
            contract=PassContract(
                preserves=PassPreserves(
                    analyses=frozenset({"dominators"}),
                    facts=frozenset({"raw_instruction_addresses"}),
                )
            ),
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts)


def test_real_lower_contract_preserves_only_declared_mutation_state():
    recovered_edge = type("_Fact", (), {"kind": "recovered_cfg_edge"})()

    class _LowerLikeMutator:
        name = "lower_like_mutator"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_analysis("plan_semantic_regions")
            assert ctx.facts.has_analysis("recover_dispatcher")
            assert ctx.facts.has_analysis("transition_result")
            assert ctx.facts.has_fact("dispatcher_family")
            assert ctx.facts.has_fact("semantic_region")
            assert ctx.facts.has_fact("state_transition")
            return PassResult(
                facts=(recovered_edge,),
                rewrite_plan=PatchPlan(planner_modifications=(object(),)),
            )

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.has_analysis("function_boundaries")
            assert not ctx.facts.has_analysis("dominators")
            assert ctx.facts.has_fact("raw_instruction_addresses")
            assert ctx.facts.get_fact("recovered_cfg_edge") == (recovered_edge,)
            assert not ctx.facts.has_fact("dispatcher_family")
            assert not ctx.facts.has_fact("semantic_region")
            assert not ctx.facts.has_fact("stale_cfg_shape")
            assert not ctx.facts.has_fact("state_transition")
            assert not ctx.facts.has_evidence("branch_targets")
            return PassResult()

    facts = AnalysisManager(_GRAPH)
    for name in (
        "dominators",
        "function_boundaries",
        "plan_semantic_regions",
        "recover_dispatcher",
        "transition_result",
    ):
        facts.put_analysis(name, object())
    for name in (
        "dispatcher_family",
        "raw_instruction_addresses",
        "semantic_region",
        "stale_cfg_shape",
        "state_transition",
    ):
        facts.put_fact(name, type("_Fact", (), {"kind": name})())
    facts.put_evidence("branch_targets", object())
    specs = (
        PassSpec(
            "lower_like_mutator",
            _LowerLikeMutator,
            no_caps,
            default,
            contract=standard_state_machine_passes()[3].contract,
        ),
        PassSpec("reader", _Reader, no_caps, default),
    )

    _run_specs(specs, facts=facts, maturity=IRMaturity.GLOBAL_ANALYZED)


def test_legacy_pass_result_facts_without_native_contract_remain_allowed():
    class _LegacyFactPass:
        name = "legacy_fact_pass"

        def run(self, ctx) -> PassResult:
            return PassResult(facts=(object(),))

    _run_specs((PassSpec("legacy_fact_pass", _LegacyFactPass, no_caps, default),))


def test_declared_analysis_output_is_visible_to_later_pass():
    class _PublishDomtree:
        name = "publish_domtree"

        def run(self, ctx) -> PassResult:
            return PassResult(analysis_outputs={"domtree": "D"})

    class _NeedsDomtree:
        name = "needs_domtree"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.get_analysis("domtree") == "D"
            return PassResult()

    class _TwoPasses:
        name = "two_passes"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "publish_domtree",
                    _PublishDomtree,
                    no_caps,
                    default,
                    analyses=AnalysisContract(
                        provided=frozenset({"domtree"}),
                    ),
                ),
                PassSpec(
                    "needs_domtree",
                    _NeedsDomtree,
                    no_caps,
                    default,
                    analyses=AnalysisContract(
                        required=frozenset({"domtree"}),
                    ),
                ),
            )

    run_pipeline(
        source=_Src(), family=_TwoPasses(), backend=_Backend(),
        facts=AnalysisManager(_GRAPH), project_config=None,
        maturity=IRMaturity.CANONICAL,
    )


def test_undeclared_analysis_output_is_rejected():
    class _PublishDomtree:
        name = "publish_domtree"

        def run(self, ctx) -> PassResult:
            return PassResult(analysis_outputs={"domtree": "D"})

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec("publish_domtree", _PublishDomtree, no_caps, default),
            )

    with pytest.raises(AnalysisContractError, match="undeclared analyses"):
        run_pipeline(
            source=_Src(), family=_OneShot(), backend=_Backend(),
            facts=AnalysisManager(_GRAPH), project_config=None,
            maturity=IRMaturity.CANONICAL,
        )


def test_analysis_only_pass_with_empty_plan_succeeds():
    class _Analyzer:
        name = "analyzer"

        def run(self, ctx) -> PassResult:
            return PassResult(analysis_outputs={"domtree": "D"})

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "analyzer",
                    _Analyzer,
                    no_caps,
                    default,
                    analyses=AnalysisContract(
                        provided=frozenset({"domtree"}),
                    ),
                    backend_route=BackendRoute.ANALYSIS_ONLY,
                ),
            )

    facts = AnalysisManager(_GRAPH)

    out = run_pipeline(
        source=_Src(), family=_OneShot(), backend=_Backend(),
        facts=facts, project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert out is _GRAPH
    assert facts.get_analysis("domtree") == "D"


def test_analysis_only_pass_with_rewrite_plan_fails_before_apply():
    class _Analyzer:
        name = "analyzer"

        def run(self, ctx) -> PassResult:
            return PassResult(
                analysis_outputs={"domtree": "D"},
                rewrite_plan=PatchPlan(planner_modifications=(object(),)),
            )

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "analyzer",
                    _Analyzer,
                    no_caps,
                    default,
                    analyses=AnalysisContract(
                        provided=frozenset({"domtree"}),
                    ),
                    backend_route=BackendRoute.ANALYSIS_ONLY,
                ),
            )

    backend = _Backend()
    facts = AnalysisManager(_GRAPH)

    with pytest.raises(BackendRouteError, match="analysis-only pass"):
        run_pipeline(
            source=_Src(), family=_OneShot(), backend=backend,
            facts=facts, project_config=None,
            maturity=IRMaturity.CANONICAL,
        )

    assert backend.applied == 0
    assert facts.get_analysis("domtree") is None


def test_mutation_backend_pass_with_rewrite_plan_still_applies():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (PassSpec("mutator", _Mutator, no_caps, default),)

    backend, facts = _Backend(), _Facts()

    out = run_pipeline(
        source=_Src(), family=_OneShot(), backend=backend,
        facts=facts, project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert backend.applied == 1
    assert facts.invalidations == 1
    assert out == "G1"


def test_noop_backend_apply_preserves_analysis_epoch():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _Reader:
        name = "reader"

        def run(self, ctx) -> PassResult:
            assert ctx.facts.get_analysis("recover_dispatcher") == "R"
            return PassResult()

    class _TwoPasses:
        name = "two_passes"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec("mutator", _Mutator, no_caps, default),
                PassSpec("reader", _Reader, no_caps, default),
            )

    class _NoopBackend(_Backend):
        def apply(self, plan, live_source, safety_policy):
            self.applied += 1
            return _GRAPH

    facts = AnalysisManager(_GRAPH)
    facts.put_analysis("recover_dispatcher", "R")
    out = run_pipeline(
        source=_Src(), family=_TwoPasses(), backend=_NoopBackend(),
        facts=facts, project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert out is _GRAPH
    assert facts.get_analysis("recover_dispatcher") == "R"


def test_spec_preservation_applies_when_result_omits_preservation():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(rewrite_plan=PatchPlan(planner_modifications=(object(),)))

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "mutator",
                    _Mutator,
                    no_caps,
                    default,
                    preservation=PreservedAnalyses.preserving({"domtree"}),
                ),
            )

    facts = _Facts()

    run_pipeline(
        source=_Src(), family=_OneShot(), backend=_Backend(),
        facts=facts, project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert facts.last_preserved == PreservedAnalyses.preserving({"domtree"})


def test_result_preservation_overrides_spec_default():
    class _Mutator:
        name = "mutator"

        def run(self, ctx) -> PassResult:
            return PassResult(
                rewrite_plan=PatchPlan(planner_modifications=(object(),)),
                preserved=PreservedAnalyses.none(),
            )

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "mutator",
                    _Mutator,
                    no_caps,
                    default,
                    preservation=PreservedAnalyses.all(),
                ),
            )

    facts = _Facts()

    run_pipeline(
        source=_Src(), family=_OneShot(), backend=_Backend(),
        facts=facts, project_config=None,
        maturity=IRMaturity.CANONICAL,
    )

    assert facts.last_preserved == PreservedAnalyses.none()


def test_run_pipeline_records_pass_result_run_later_requests():
    """A pass result can ask the injected scheduler for later-maturity work."""
    request = RunLater(
        IRMaturity.GLOBAL_ANALYZED,
        reason="needs optimized graph",
    )

    class _AskLater:
        name = "ask_later"

        def run(self, ctx) -> PassResult:
            return PassResult(run_later=(request,))

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (PassSpec("ask_later", _AskLater, no_caps, default),)

    scheduler = _RecordingScheduler()
    out = run_pipeline(
        source=_Src(), family=_OneShot(), backend=_Backend(),
        facts=_Facts(), project_config=None,
        maturity=IRMaturity.CANONICAL,
        scheduler=scheduler,
    )

    assert out is _GRAPH
    assert scheduler.requests == [{
        "func_ea": 0x1000,
        "pass_id": "ask_later",
        "current_maturity": IRMaturity.CANONICAL,
        "run_later": request,
        "domain": RunLaterDomain.PIPELINE_PASS,
    }]


def test_run_pipeline_drains_pipeline_domain_into_worklist_without_duplicate():
    """Pipeline run_later work is consumed by the pipeline, not cfg rule lookup."""
    calls: list[IRMaturity] = []
    request = RunLater(
        IRMaturity.GLOBAL_ANALYZED,
        reason="needs optimized graph",
    )

    class _AskLater:
        name = "same_name_as_possible_cfg_rule"

        def run(self, ctx) -> PassResult:
            calls.append(ctx.maturity)
            if ctx.maturity is IRMaturity.CANONICAL:
                return PassResult(run_later=(request,))
            return PassResult()

    class _OneShot:
        name = "one_shot"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec(
                    "same_name_as_possible_cfg_rule",
                    _AskLater,
                    no_caps,
                    default,
                ),
            )

    scheduler = PassScheduler()
    run_pipeline(
        source=_Src(), family=_OneShot(), backend=_Backend(),
        facts=_Facts(), project_config=None,
        maturity=IRMaturity.CANONICAL,
        scheduler=scheduler,
    )

    assert calls == [IRMaturity.CANONICAL]
    assert scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
    ) == ()

    run_pipeline(
        source=_Src(), family=_OneShot(), backend=_Backend(),
        facts=_Facts(), project_config=None,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        scheduler=scheduler,
    )

    assert calls == [
        IRMaturity.CANONICAL,
        IRMaturity.GLOBAL_ANALYZED,
    ]
    assert scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        domain=RunLaterDomain.PIPELINE_PASS,
    ) == ()


def test_run_pipeline_scheduled_worklist_pass_dedupes_at_normal_position():
    calls: list[str] = []

    class _First:
        name = "first"

        def run(self, ctx) -> PassResult:
            calls.append("first")
            return PassResult()

    class _Second:
        name = "second"

        def run(self, ctx) -> PassResult:
            calls.append("second")
            return PassResult()

    class _TwoPasses:
        name = "two_passes"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec("first", _First, no_caps, default),
                PassSpec("second", _Second, no_caps, default),
            )

    scheduler = PassScheduler()
    scheduler.request(
        func_ea=0x1000,
        pass_id="second",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
        domain=RunLaterDomain.PIPELINE_PASS,
    )

    run_pipeline(
        source=_Src(), family=_TwoPasses(), backend=_Backend(),
        facts=_Facts(), project_config=None,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        scheduler=scheduler,
    )

    assert calls == ["first", "second"]
    assert scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        domain=RunLaterDomain.PIPELINE_PASS,
    ) == ()


def test_run_pipeline_replay_after_pipeline_policy_is_explicit_opt_in():
    calls: list[str] = []

    class _First:
        name = "first"

        def run(self, ctx) -> PassResult:
            calls.append("first")
            return PassResult()

    class _Second:
        name = "second"

        def run(self, ctx) -> PassResult:
            calls.append("second")
            return PassResult()

    class _TwoPasses:
        name = "two_passes"

        def detect(self, graph, capabilities, context=None):
            return object()

        def pipeline_for(self, match, context):
            return (
                PassSpec("first", _First, no_caps, default),
                PassSpec(
                    "second",
                    _Second,
                    no_caps,
                    default,
                    scheduler_policy=SchedulerPolicy.REPLAY_AFTER_PIPELINE,
                ),
            )

    scheduler = PassScheduler()
    scheduler.request(
        func_ea=0x1000,
        pass_id="second",
        current_maturity=IRMaturity.CANONICAL,
        run_later=RunLater(IRMaturity.GLOBAL_ANALYZED),
        domain=RunLaterDomain.PIPELINE_PASS,
    )

    run_pipeline(
        source=_Src(), family=_TwoPasses(), backend=_Backend(),
        facts=_Facts(), project_config=None,
        maturity=IRMaturity.GLOBAL_ANALYZED,
        scheduler=scheduler,
    )

    assert calls == ["first", "second", "second"]
    assert scheduler.drain(
        func_ea=0x1000,
        current_maturity=IRMaturity.GLOBAL_ANALYZED,
        domain=RunLaterDomain.PIPELINE_PASS,
    ) == ()


def test_validate_capabilities_fails_loud_on_missing():
    backend = _Backend(caps=())  # no live_mba
    try:
        validate_capabilities(backend, live_mba)
    except CapabilityError:
        pass
    else:
        raise AssertionError("expected CapabilityError for missing live_mba")
    # no_caps always passes
    validate_capabilities(backend, no_caps)


def test_select_family_registers_hodur_but_is_inert():
    assert any(isinstance(f, HodurFamily) for f in registered_families())
    assert select_family(graph="G0", project_config=None) is None  # detect inert


# --- ApproovFamily: the second unflatten profile on the shared spine (scaffold) ----------
class _FakeMap:
    """Stand-in StateDispatcherMap carrying table route/provenance discriminators."""

    def __init__(self, router_kind, table_provenance=None):
        self.router_kind = router_kind
        self.table_provenance = table_provenance


def test_approov_detect_is_kind_scoped_to_switch_and_indirect(monkeypatch):
    """detect claims switch/indirect kinds, rejects equality-chain and non-graphs."""
    fam = ApproovFamily()
    # Non-graph / missing graph -> inert, before the front-end is consulted.
    assert fam.detect(None, frozenset()) is None
    assert fam.detect("G0", frozenset()) is None  # no .blocks

    def _stub(source, table_provenance=None):
        return lambda graph: _FakeMap(source, table_provenance)

    # Switch-table and indirect-jump are CLAIMED (truthy map returned).
    monkeypatch.setattr(approov_pipeline, "build_dispatch_map_any_kind",
                        _stub(RouterKind.TABLE, TableProvenance.SWITCH))
    assert fam.detect(_GRAPH, frozenset()) is not None
    monkeypatch.setattr(approov_pipeline, "build_dispatch_map_any_kind",
                        _stub(
                            RouterKind.TABLE,
                            TableProvenance.INDIRECT_JUMP_TABLE,
                        ))
    assert fam.detect(_GRAPH, frozenset()) is not None

    # Equality-chain belongs to HodurFamily -> ApproovFamily must NOT claim it.
    monkeypatch.setattr(approov_pipeline, "build_dispatch_map_any_kind",
                        _stub(RouterKind.CONDITION_CHAIN))
    assert fam.detect(_GRAPH, frozenset()) is None
    # Front-end found nothing -> None.
    monkeypatch.setattr(approov_pipeline, "build_dispatch_map_any_kind", lambda graph: None)
    assert fam.detect(_GRAPH, frozenset()) is None


def test_approov_pipeline_for_switch_is_standard_no_emulation():
    """TABLE/switch runs the standard seeded-fold spine — NO emulation
    (abc_or_dispatch folds masked-OR writes via the partitioned fixpoint)."""
    specs = ApproovFamily().pipeline_for(
        _FakeMap(RouterKind.TABLE, TableProvenance.SWITCH), None
    )
    assert [s.name for s in specs] == [
        "recover_dispatcher",
        "recover_state_transitions",
        "plan_semantic_regions",
        "lower_state_machine",
        "cleanup_residual_dispatcher",
    ]
    by_name = {s.name: s for s in specs}
    assert "emulation" not in by_name["recover_state_transitions"].requirements.required
    assert "emulation" not in by_name["lower_state_machine"].requirements.required


def test_approov_pipeline_for_indirect_is_emulation_gated():
    """TABLE/indirect_jump_table needs the emulator + pins RouterKind.TABLE (M3+, structural)."""
    specs = ApproovFamily().pipeline_for(
        _FakeMap(RouterKind.TABLE, TableProvenance.INDIRECT_JUMP_TABLE),
        None,
    )
    by_name = {s.name: s for s in specs}
    assert "emulation" in by_name["recover_state_transitions"].requirements.required
    assert "emulation" in by_name["lower_state_machine"].requirements.required
    assert by_name["lower_state_machine"].pass_factory().configured_kind == RouterKind.TABLE
    assert (
        by_name["lower_state_machine"]
        .pass_factory()
        .configured_table_provenance
        is TableProvenance.INDIRECT_JUMP_TABLE
    )


def test_registry_registers_both_profiles():
    fams = registered_families()
    assert any(isinstance(f, ApproovFamily) for f in fams)
    assert any(isinstance(f, HodurFamily) for f in fams)
    # Selection is order-independent: profiles own disjoint dispatcher kinds, so there is
    # no priority/tiebreak — registration order does not matter.


# --- TigressFamily: the third unflatten profile on the shared spine (M3 slice 1) ---------
def test_tigress_detect_is_kind_scoped_to_switch_and_indirect(monkeypatch):
    """detect claims switch/indirect kinds, rejects equality-chain and non-graphs."""
    fam = TigressFamily()
    # Non-graph / missing graph -> inert, before the front-end is consulted.
    assert fam.detect(None, frozenset()) is None
    assert fam.detect("G0", frozenset()) is None  # no .blocks

    def _stub(source, table_provenance=None):
        return lambda graph: _FakeMap(source, table_provenance)

    # Switch-table and indirect-jump are CLAIMED (truthy map returned).
    monkeypatch.setattr(tigress_pipeline, "build_dispatch_map_any_kind",
                        _stub(RouterKind.TABLE, TableProvenance.SWITCH))
    assert fam.detect(_GRAPH, frozenset()) is not None
    monkeypatch.setattr(tigress_pipeline, "build_dispatch_map_any_kind",
                        _stub(
                            RouterKind.TABLE,
                            TableProvenance.INDIRECT_JUMP_TABLE,
                        ))
    assert fam.detect(_GRAPH, frozenset()) is not None

    # Equality-chain belongs to HodurFamily -> TigressFamily must NOT claim it.
    monkeypatch.setattr(tigress_pipeline, "build_dispatch_map_any_kind",
                        _stub(RouterKind.CONDITION_CHAIN))
    assert fam.detect(_GRAPH, frozenset()) is None
    # Front-end found nothing -> None.
    monkeypatch.setattr(tigress_pipeline, "build_dispatch_map_any_kind", lambda graph: None)
    assert fam.detect(_GRAPH, frozenset()) is None


def test_tigress_pipeline_for_switch_is_standard_no_emulation():
    """TABLE/switch runs the standard seeded-fold spine — NO emulation."""
    specs = TigressFamily().pipeline_for(
        _FakeMap(RouterKind.TABLE, TableProvenance.SWITCH), None
    )
    assert [s.name for s in specs] == [
        "recover_dispatcher",
        "recover_state_transitions",
        "plan_semantic_regions",
        "lower_state_machine",
        "cleanup_residual_dispatcher",
    ]
    by_name = {s.name: s for s in specs}
    assert "emulation" not in by_name["recover_state_transitions"].requirements.required
    assert "emulation" not in by_name["lower_state_machine"].requirements.required


def test_tigress_pipeline_for_indirect_is_emulation_gated():
    """TABLE/indirect_jump_table needs the emulator + pins RouterKind.TABLE (slice 2)."""
    specs = TigressFamily().pipeline_for(
        _FakeMap(RouterKind.TABLE, TableProvenance.INDIRECT_JUMP_TABLE),
        None,
    )
    by_name = {s.name: s for s in specs}
    assert "emulation" in by_name["recover_state_transitions"].requirements.required
    assert "emulation" in by_name["lower_state_machine"].requirements.required
    assert by_name["lower_state_machine"].pass_factory().configured_kind == RouterKind.TABLE
    assert (
        by_name["lower_state_machine"]
        .pass_factory()
        .configured_table_provenance
        is TableProvenance.INDIRECT_JUMP_TABLE
    )


def test_registry_registers_tigress_profile():
    assert any(isinstance(f, TigressFamily) for f in registered_families())


# --- select_family router_resolution policy (hybrid config override, M3 slice 1) ----
class _ClaimAny:
    """A Family-Protocol double (NOT a Registrant subclass -> no auto-registration)
    that always claims; named so the policy can target it by name."""

    def __init__(self, name):
        self.name = name

    def detect(self, graph, capabilities, context=None):
        return object()

    def pipeline_for(self, match, context):
        return ()


def test_select_family_default_empty_policy_is_registration_order(monkeypatch):
    """No router_resolution -> first registered claimant wins (order preserved)."""
    a, b = _ClaimAny("alpha"), _ClaimAny("beta")
    monkeypatch.setattr("d810.families.registry.registered_families", lambda: (a, b))
    assert select_family("G", project_config=None) is a
    assert select_family("G", project_config={}) is a


def test_select_family_require_restricts_to_named_family(monkeypatch):
    """require=<name> restricts candidates to exactly that family."""
    a, b = _ClaimAny("alpha"), _ClaimAny("beta")
    monkeypatch.setattr("d810.families.registry.registered_families", lambda: (a, b))
    cfg = {"router_resolution": {"require": "beta"}}
    assert select_family("G", project_config=cfg) is b


def test_select_family_deny_excludes_named_family(monkeypatch):
    """deny=[<name>] excludes that family from the candidate set."""
    a, b = _ClaimAny("alpha"), _ClaimAny("beta")
    monkeypatch.setattr("d810.families.registry.registered_families", lambda: (a, b))
    cfg = {"router_resolution": {"deny": ["alpha"]}}
    assert select_family("G", project_config=cfg) is b


def test_select_family_prefer_biases_candidate_order(monkeypatch):
    """prefer={<name>: bias} stable-sorts candidates by descending bias."""
    a, b = _ClaimAny("alpha"), _ClaimAny("beta")
    monkeypatch.setattr("d810.families.registry.registered_families", lambda: (a, b))
    cfg = {"router_resolution": {"prefer": {"beta": 10.0}}}
    assert select_family("G", project_config=cfg) is b


def test_select_family_require_no_match_returns_none(monkeypatch):
    """require=<name> for an absent / non-claiming family -> None."""
    a = _ClaimAny("alpha")
    monkeypatch.setattr("d810.families.registry.registered_families", lambda: (a,))
    cfg = {"router_resolution": {"require": "tigress"}}
    assert select_family("G", project_config=cfg) is None
