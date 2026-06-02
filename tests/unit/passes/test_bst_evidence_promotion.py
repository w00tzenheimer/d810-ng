"""§1a gap3/gap4: the entry's BST/interval evidence promotes into the production DAG.

When the entry threads ``bst_evidence`` (the pristine-mba ``analyze_bst_dispatcher`` result) through
the AnalysisManager, ``LowerStateMachine`` must build the BST-enriched DAG and pass ``dag`` +
``dispatcher`` (+ the snapshot ``constant_result`` feeder) into ``lower_to_direct_graph`` — the
signal that flips edge classification from the shallow exact-chain to the interval-map lookup that
yields CONDITIONAL_RETURN edges (the §1a returns=0 -> returns=N fix). Absent the evidence, the call
stays on the committed shallow path (``dispatcher=None``, ``dag=None``), byte-identical.

These are wiring tests: the heavy DAG build + lower are monkeypatched so the test stays portable
(no live mba) and asserts only the promotion decision + argument threading.
"""
from __future__ import annotations

from types import SimpleNamespace

import d810.passes.unflatten.state_machine as sm
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.pass_pipeline import FunctionPipelineContext
from d810.transforms.plan import PatchPlan


def _recovery():
    return SimpleNamespace(
        dispatch_map=SimpleNamespace(rows=()),
        dispatcher_block_serial=2,
        state_var_stkoff=0x3C,
        bst_block_serials=(2, 3),
    )


def _bst_evidence():
    return SimpleNamespace(
        dispatcher=SimpleNamespace(lookup=lambda c: None),
        handler_range_map={4: (0, 5)},
        bst_node_blocks=(2, 3),
        pre_header_serial=1,
        initial_state=0,
    )


def _ctx(am):
    return FunctionPipelineContext(
        source=SimpleNamespace(live_source=object()),
        graph=am.graph, maturity=None, project_config=None, facts=am.view(),
    )


def _patch_heavy(monkeypatch):
    """Stub the heavy analyses so the wiring test holds no live-mba coupling. Returns the
    captured-kwargs dicts for the DAG build and the lower call."""
    lower_kw: dict = {}
    dag_kw: dict = {}
    sentinel_dag = object()

    def fake_lower(graph, facts, **kw):
        lower_kw.update(kw)
        return PatchPlan()

    def fake_build(**kw):
        dag_kw.update(kw)
        return sentinel_dag

    monkeypatch.setattr(sm, "lower_to_direct_graph", fake_lower)
    monkeypatch.setattr(sm, "build_live_linearized_state_dag_from_graph", fake_build)
    monkeypatch.setattr(sm, "_convert_bst_to_result",
                        lambda bst: SimpleNamespace(transitions=({"x": 1},)))
    monkeypatch.setattr(sm, "run_snapshot_constant_fixpoint", lambda g, off: "CONST")
    return lower_kw, dag_kw, sentinel_dag


def test_bst_evidence_present_threads_enriched_dag_and_dispatcher(monkeypatch):
    am = AnalysisManager(object())
    am.put_analysis("recover_dispatcher", _recovery())
    am.put_analysis("transition_result", SimpleNamespace(transitions=({"x": 1},)))
    am.put_analysis("bst_evidence", _bst_evidence())
    lower_kw, dag_kw, sentinel_dag = _patch_heavy(monkeypatch)

    sm.LowerStateMachine().run(_ctx(am))

    # The enriched DAG (built with the interval map) is threaded into the lowering, and the
    # IntervalDispatcher arms the full-reconstruction gate (lower_to_direct_graph line 439).
    assert lower_kw.get("dag") is sentinel_dag
    assert lower_kw.get("dispatcher") is not None
    assert lower_kw.get("constant_result") == "CONST"
    # The DAG build received the BST interval map + the opaque live mba (not the shallow inputs).
    assert dag_kw.get("dispatcher") is not None
    assert dag_kw.get("handler_range_map") == {4: (0, 5)}
    assert dag_kw.get("mba") is not None


def test_bst_evidence_absent_stays_on_shallow_path(monkeypatch):
    am = AnalysisManager(object())
    am.put_analysis("recover_dispatcher", _recovery())
    am.put_analysis("transition_result", SimpleNamespace(transitions=({"x": 1},)))
    # deliberately no "bst_evidence" published
    lower_kw, dag_kw, _ = _patch_heavy(monkeypatch)

    sm.LowerStateMachine().run(_ctx(am))

    # No enriched DAG built here; dispatcher absent -> gate 439 off -> committed byte-identical path.
    assert lower_kw.get("dag") is None
    assert lower_kw.get("dispatcher") is None
    assert dag_kw == {}  # build_live_linearized_state_dag_from_graph not called by the pass
