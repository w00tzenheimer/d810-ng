"""Runtime integration proof for generic per-attempt execution provenance.

One ordinary config-v2 ``run_pipeline`` execution must persist an
:class:`~d810.core.execution_journal.ExecutionAttempt` for every pass in the
configured pipeline: one that runs to completion, one that safely abstains
(a declared prerequisite -- here, a required backend capability -- is not
satisfiable), and one that is not scheduled at the current maturity at all.
See the plan's Task 3, Step 5.

"One ordinary config-v2 run" here means one config-v2-enabled session's
journal, not one single non-raising ``run_pipeline()`` call: a pass that
"safely abstains" is one whose own declared prerequisites (a required
backend capability, analysis, fact, or evidence -- see ``driver.
_ABSTAIN_EXCEPTION_TYPES``) are not satisfiable, which the driver still
propagates as a real exception rather than swallowing it (see the
"CAUTION" against changing pass error propagation). A raised exception
necessarily stops the ``run_pipeline`` call it occurred in, so this test
drives three separate config-v2 calls -- one that completes, one that
raises on an unmet capability, one whose only configured pass is not
eligible at the current maturity -- all sharing one session and one
journal, and asserts every one of the three attempts landed durably in
that one session's history.

This test avoids importing IDA-dependent modules (``ida_hexrays``,
``d810.manager``, ``d810.hexrays.hooks.*``), matching
``test_pass_pipeline_integration.py`` in this directory: the portable driver
(``d810.passes.driver.run_pipeline``) is exercised directly with injected
fakes, the same pattern ``tests/unit/passes/test_pipeline_driver.py`` uses
for the rest of the driver's behavior.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

import pytest

from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptStatus,
)
from d810.core.execution_journal_store import ExecutionJournalStore
from d810.ir.flowgraph import BlockSnapshot, FlowGraph
from d810.ir.maturity import IRMaturity
from d810.passes.analysis_manager import AnalysisManager
from d810.passes.driver import (
    NOT_SCHEDULED_AT_MATURITY_REASON,
    CapabilityError,
    run_pipeline,
)
from d810.passes.pass_pipeline import (
    PassContract,
    PassRequires,
    PassResult,
    PassSpec,
    default,
    no_caps,
)
from d810.transforms.plan import PatchPlan

_GRAPH = FlowGraph(
    blocks={
        0: BlockSnapshot(
            serial=0,
            block_type=1,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0x2000,
            insn_snapshots=(),
        )
    },
    entry_serial=0,
    func_ea=0x2000,
)


@dataclass
class _Source:
    flow_graph: object = _GRAPH
    func_ea: int = 0x2000
    live_source: object = "LIVE"


class _Backend:
    """A backend advertising no optional capabilities -- enough to run
    ``eligible`` and to make ``needs_capability`` abstain."""

    def capabilities(self):
        return frozenset()

    def apply(self, plan, live_source, safety_policy):
        return "UNUSED"


class _NeverDetectedFamily:
    """A Family double config-v2 execution must never consult."""

    name = "never_detected"

    def detect(self, graph, capabilities, context=None):
        raise AssertionError("config-v2 execution must not detect a live family")

    def pipeline_for(self, match, context):
        raise AssertionError("config-v2 execution must not use live family specs")


class _RanPass:
    """Completes with no mutation work -- the "runs" case."""

    name = "eligible_pass"

    def run(self, ctx) -> PassResult:
        return PassResult(rewrite_plan=PatchPlan())


class _AbstainedPass:
    """Declares a backend capability the fake backend never advertises,
    so the driver's prerequisite validation gate raises before ``run()``
    is ever called -- the "safely abstains" case."""

    name = "needs_capability_pass"

    def run(self, ctx) -> PassResult:
        raise AssertionError("abstaining pass must never reach run()")


class _NotScheduledPass:
    """Gated to a later maturity than this run uses -- the "not scheduled"
    case; it must never be constructed or run."""

    name = "later_maturity_pass"

    def run(self, ctx) -> PassResult:
        raise AssertionError("a maturity-ineligible pass must never run")


def _journal_store() -> ExecutionJournalStore:
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return ExecutionJournalStore(Path(tmp.name))


def _run_config_v2(specs, *, journal, session_id) -> object:
    return run_pipeline(
        source=_Source(),
        family=_NeverDetectedFamily(),
        backend=_Backend(),
        facts=AnalysisManager(_GRAPH),
        project_config={},
        maturity=IRMaturity.CANONICAL,
        pipeline_v2_specs=specs,
        journal=journal,
        session_id=session_id,
    )


def test_one_config_v2_session_persists_run_abstain_and_not_scheduled_attempts() -> (
    None
):
    ran_spec = PassSpec("eligible_pass", _RanPass, no_caps, default)
    abstained_spec = PassSpec(
        "needs_capability_pass",
        _AbstainedPass,
        no_caps,
        default,
        contract=PassContract(
            requires=PassRequires(capabilities=frozenset({"live_mba"}))
        ),
    )
    not_scheduled_spec = PassSpec(
        "later_maturity_pass",
        _NotScheduledPass,
        no_caps,
        default,
        maturity_gates=frozenset({IRMaturity.GLOBAL_ANALYZED}),
    )
    session = DecompilationSessionId.new()
    journal = _journal_store()

    try:
        # A pass that runs to completion.
        final_graph = _run_config_v2((ran_spec,), journal=journal, session_id=session)
        assert final_graph is _GRAPH

        # A pass that safely abstains: its declared capability requirement
        # is not satisfiable, so the driver's prerequisite gate raises --
        # and, per the CAUTION against changing pass error propagation,
        # that exception is not swallowed here either.
        with pytest.raises(
            CapabilityError, match=r"missing backend capabilities \['live_mba'\]"
        ):
            _run_config_v2((abstained_spec,), journal=journal, session_id=session)

        # A pass that is not scheduled at the current maturity: filtered out
        # before validation or ``run()``, so this call completes normally
        # with no eligible work.
        final_graph = _run_config_v2(
            (not_scheduled_spec,), journal=journal, session_id=session
        )
        assert final_graph is _GRAPH

        attempts = {
            attempt.stage_id: attempt
            for attempt in journal.attempts_for_session(session)
        }
        assert set(attempts) == {
            "eligible_pass",
            "needs_capability_pass",
            "later_maturity_pass",
        }

        ran = attempts["eligible_pass"]
        assert ran.status is ExecutionAttemptStatus.COMPLETED
        assert ran.reason_code is None

        abstained = attempts["needs_capability_pass"]
        assert abstained.status is ExecutionAttemptStatus.ABSTAINED
        assert abstained.reason_code is not None
        assert "CapabilityError" in abstained.reason_code

        not_scheduled = attempts["later_maturity_pass"]
        assert not_scheduled.status is ExecutionAttemptStatus.ABSTAINED
        assert not_scheduled.reason_code == NOT_SCHEDULED_AT_MATURITY_REASON

        # Every attempt in this session's history is correlated under the
        # one session, in the order the three calls happened.
        assert {a.attempt_id.session for a in attempts.values()} == {session}
        ordered = journal.attempts_for_session(session)
        assert [a.stage_id for a in ordered] == [
            "eligible_pass",
            "needs_capability_pass",
            "later_maturity_pass",
        ]
    finally:
        journal.close()
