"""Task 0.1: every pre-lift seam registry must consult the policy gate.

These registries are pure Python, but they live under ``d810.hexrays``, and the
``unit-tests-no-hexrays`` import contract bars ``tests.unit`` from importing that
package -- hence a system test for logic that needs no IDA.

Suppression is asserted by **handler call count**, not by output. A handler that
ran and then decided to do nothing is not suppressed; only a handler that was
never invoked is.
"""

from __future__ import annotations

import pytest

from d810.core.normalization_policy import (
    NormalizationDecision,
    PolicyVerdict,
    Seam,
    set_normalization_policy,
)
from d810.hexrays.preanalysis.calls_done_preanalysis import (
    register_calls_done_preanalysis_handler,
    run_calls_done_preanalysis_handlers,
    unregister_calls_done_preanalysis_handler,
)
from d810.hexrays.preanalysis.flowchart_preanalysis import (
    register_flowchart_preanalysis_handler,
    run_flowchart_preanalysis_handlers,
    unregister_flowchart_preanalysis_handler,
)
from d810.hexrays.preanalysis.preopt_preanalysis import (
    register_preopt_preanalysis_handler,
    run_preopt_preanalysis_handlers,
    unregister_preopt_preanalysis_handler,
)

pytestmark = pytest.mark.pure_python

FUNCTION_EA = 0x401000


class _Policy:
    def __init__(self, decision):
        self.decision = decision

    def decide(self, function_ea, seam):
        return PolicyVerdict(self.decision, "test")


class _Counter:
    def __init__(self):
        self.calls = 0

    def __call__(self, **kwargs):
        self.calls += 1


@pytest.fixture(autouse=True)
def _isolate():
    set_normalization_policy(None)
    yield
    set_normalization_policy(None)
    for unregister in (
        unregister_flowchart_preanalysis_handler,
        unregister_preopt_preanalysis_handler,
        unregister_calls_done_preanalysis_handler,
    ):
        for name in ("gate-test-mutator", "gate-test-readonly"):
            unregister(name)


def _run_flowchart():
    run_flowchart_preanalysis_handlers(
        function_ea=FUNCTION_EA, mba=object(), decision={}
    )


class TestFlowchartSeamGate:
    def test_default_policy_runs_every_handler(self):
        mutator, readonly = _Counter(), _Counter()
        register_flowchart_preanalysis_handler("gate-test-mutator", mutator)
        register_flowchart_preanalysis_handler(
            "gate-test-readonly", readonly, read_only=True
        )

        _run_flowchart()

        assert mutator.calls == 1
        assert readonly.calls == 1

    def test_suppress_all_invokes_nothing(self):
        mutator, readonly = _Counter(), _Counter()
        register_flowchart_preanalysis_handler("gate-test-mutator", mutator)
        register_flowchart_preanalysis_handler(
            "gate-test-readonly", readonly, read_only=True
        )
        set_normalization_policy(_Policy(NormalizationDecision.SUPPRESS_ALL))

        _run_flowchart()

        assert mutator.calls == 0
        assert readonly.calls == 0

    def test_suppress_mutators_keeps_read_only_handlers(self):
        mutator, readonly = _Counter(), _Counter()
        register_flowchart_preanalysis_handler("gate-test-mutator", mutator)
        register_flowchart_preanalysis_handler(
            "gate-test-readonly", readonly, read_only=True
        )
        set_normalization_policy(_Policy(NormalizationDecision.SUPPRESS_MUTATORS))

        _run_flowchart()

        assert mutator.calls == 0
        assert readonly.calls == 1

    def test_unmarked_handler_is_treated_as_a_mutator(self):
        unmarked = _Counter()
        register_flowchart_preanalysis_handler("gate-test-mutator", unmarked)
        set_normalization_policy(_Policy(NormalizationDecision.SUPPRESS_MUTATORS))

        _run_flowchart()

        assert unmarked.calls == 0

    def test_failing_policy_suppresses_rather_than_permits(self):
        class _Exploding:
            def decide(self, function_ea, seam):
                raise RuntimeError("boom")

        mutator = _Counter()
        register_flowchart_preanalysis_handler("gate-test-mutator", mutator)
        set_normalization_policy(_Exploding())

        _run_flowchart()

        assert mutator.calls == 0


class TestOtherSeamsAreGatedToo:
    """The PREOPT seam is the one a hook-class-level gate would have missed."""

    def test_preopt_seam_is_gated(self):
        mutator = _Counter()
        register_preopt_preanalysis_handler("gate-test-mutator", mutator)
        set_normalization_policy(_Policy(NormalizationDecision.SUPPRESS_ALL))

        run_preopt_preanalysis_handlers(
            function_ea=FUNCTION_EA, mba=object(), decision={}
        )

        assert mutator.calls == 0

    def test_calls_done_seam_is_gated(self):
        mutator = _Counter()
        register_calls_done_preanalysis_handler("gate-test-mutator", mutator)
        set_normalization_policy(_Policy(NormalizationDecision.SUPPRESS_ALL))

        run_calls_done_preanalysis_handlers(
            function_ea=FUNCTION_EA, mba=object(), decision={}
        )

        assert mutator.calls == 0


class TestSeamIdentityIsReported:
    def test_each_registry_reports_its_own_seam(self):
        seen = []

        class _Recorder:
            def decide(self, function_ea, seam):
                seen.append(seam)
                return PolicyVerdict(NormalizationDecision.RUN, "")

        set_normalization_policy(_Recorder())
        register_flowchart_preanalysis_handler("gate-test-mutator", _Counter())
        register_preopt_preanalysis_handler("gate-test-mutator", _Counter())

        _run_flowchart()
        run_preopt_preanalysis_handlers(
            function_ea=FUNCTION_EA, mba=object(), decision={}
        )

        assert Seam.FLOWCHART in seen
        assert Seam.PREOPT in seen
