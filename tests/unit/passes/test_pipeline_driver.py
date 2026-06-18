"""unflatten driver acceptance (structural): run_pipeline IS the north-star loop.

Exercises the portable driver with injected null deps + the real HodurFamily passes:
detect -> pipeline_for -> validate_capabilities -> pass.run -> (apply on non-empty plan).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.passes.pass_pipeline import (
    FunctionPipelineContext,
    PassResult,
    PassSpec,
    SafetyPolicy,
    default,
    live_mba,
    no_caps,
)
from d810.passes.scheduler import PassScheduler, RunLater, RunLaterDomain
from d810.transforms.plan import PatchPlan
from d810.passes.driver import CapabilityError, run_pipeline, validate_capabilities
from d810.families.state_machine_cff import HodurFamily
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

    def view(self):
        return self

    def invalidate_to(self, graph, preserved):
        self.invalidations += 1


class _Backend:
    def __init__(self, caps=("live_mba",)):
        self._caps = frozenset(caps)
        self.applied = 0

    def capabilities(self):
        return self._caps

    def apply(self, plan, live_source, safety_policy):
        self.applied += 1
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


def test_run_pipeline_runs_all_five_passes_no_apply_on_empty_plans():
    backend = _Backend()
    facts = _Facts()
    out = run_pipeline(
        source=_Src(), family=_MatchingHodur(), backend=backend,
        facts=facts, project_config=None, maturity=None,
    )
    # skeleton transforms emit empty plans -> backend.apply never called, graph unchanged.
    assert backend.applied == 0
    assert facts.invalidations == 0
    assert out is _GRAPH


def test_run_pipeline_does_not_record_empty_run_later_requests():
    backend = _Backend()
    facts = _Facts()
    scheduler = _RecordingScheduler()
    run_pipeline(
        source=_Src(), family=_MatchingHodur(), backend=backend,
        facts=facts, project_config=None, maturity=IRMaturity.CANONICAL,
        scheduler=scheduler,
    )
    assert scheduler.requests == []


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


def test_run_pipeline_drains_pipeline_domain_and_replays_named_pass():
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
        IRMaturity.GLOBAL_ANALYZED,
    ]
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
