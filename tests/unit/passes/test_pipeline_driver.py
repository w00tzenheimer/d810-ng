"""§1a driver acceptance (structural): run_pipeline IS the north-star loop.

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
from d810.transforms.plan import PatchPlan
from d810.passes.driver import CapabilityError, run_pipeline, validate_capabilities
from d810.families.state_machine_cff import HodurFamily
from d810.families.state_machine_cff import approov as approov_pipeline
from d810.families.state_machine_cff import ApproovFamily
from d810.families.registry import select_family, registered_families
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.capabilities.dispatcher import RouterKind
from d810.ir.flowgraph import BlockSnapshot, FlowGraph

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


# --- ApproovFamily: the second §1a profile on the shared spine (scaffold) ----------
class _FakeMap:
    """Stand-in StateDispatcherMap carrying only the kind discriminator detect reads."""

    def __init__(self, source):
        self.source = source


def test_approov_detect_is_kind_scoped_to_switch_and_indirect(monkeypatch):
    """detect claims switch/indirect kinds, rejects equality-chain and non-graphs."""
    fam = ApproovFamily()
    # Non-graph / missing graph -> inert, before the front-end is consulted.
    assert fam.detect(None, frozenset()) is None
    assert fam.detect("G0", frozenset()) is None  # no .blocks

    def _stub(source):
        return lambda graph: _FakeMap(source)

    # Switch-table and indirect-jump are CLAIMED (truthy map returned).
    monkeypatch.setattr(approov_pipeline, "build_dispatch_map_any_kind",
                        _stub(DispatcherType.SWITCH_TABLE))
    assert fam.detect(_GRAPH, frozenset()) is not None
    monkeypatch.setattr(approov_pipeline, "build_dispatch_map_any_kind",
                        _stub(DispatcherType.INDIRECT_JUMP))
    assert fam.detect(_GRAPH, frozenset()) is not None

    # Equality-chain belongs to HodurFamily -> ApproovFamily must NOT claim it.
    monkeypatch.setattr(approov_pipeline, "build_dispatch_map_any_kind",
                        _stub(DispatcherType.CONDITIONAL_CHAIN))
    assert fam.detect(_GRAPH, frozenset()) is None
    # Front-end found nothing -> None.
    monkeypatch.setattr(approov_pipeline, "build_dispatch_map_any_kind", lambda graph: None)
    assert fam.detect(_GRAPH, frozenset()) is None


def test_approov_pipeline_for_emulation_gated_and_switch_pinned():
    """Same five passes as Hodur, but emulation-required + router pinned to SWITCH."""
    specs = ApproovFamily().pipeline_for(match=object(), context=None)
    assert [s.name for s in specs] == [
        "recover_dispatcher",
        "recover_state_transitions",
        "plan_semantic_regions",
        "lower_state_machine",
        "cleanup_residual_dispatcher",
    ]
    by_name = {s.name: s for s in specs}
    # Indirect-target folding needs the emulator capability on the two passes that resolve
    # and lower transitions.
    assert "emulation" in by_name["recover_state_transitions"].requirements.required
    assert "emulation" in by_name["lower_state_machine"].requirements.required
    # The lowering factory pins the SWITCH router shape (injectable LowerStateMachine).
    lowered = by_name["lower_state_machine"].pass_factory()
    assert lowered.configured_kind == RouterKind.SWITCH


def test_registry_registers_both_profiles():
    fams = registered_families()
    assert any(isinstance(f, ApproovFamily) for f in fams)
    assert any(isinstance(f, HodurFamily) for f in fams)
    # Selection is order-independent: profiles own disjoint dispatcher kinds, so there is
    # no priority/tiebreak — registration order does not matter.
