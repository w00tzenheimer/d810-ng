"""Unit tests for the earliest per-function normalization policy gate.

Task 0.1 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md``. This is review finding
P1 #4's "one earliest gate", landed before there is anything to suppress, so that
every later mutator is born behind it instead of retrofitted.

The gate lives in ``d810.core`` rather than ``d810.manager`` as the plan first
proposed. The seam registries it must gate are ``d810.hexrays.preanalysis.*``,
and ``d810.manager`` sits *above* ``d810.hexrays`` in the layered-architecture
contract, so a manager-owned policy imported by a registry would be an upward
import. ``d810.core`` is the bottom layer, so the protocol and the installed-
policy slot live there and the manager installs a concrete policy at runtime.
"""

from __future__ import annotations

import pytest

from d810.core.normalization_policy import (
    NormalizationDecision,
    PolicyVerdict,
    Seam,
    decide,
    handler_is_permitted,
    installed_policy,
    set_normalization_policy,
)

pytestmark = pytest.mark.pure_python


@pytest.fixture(autouse=True)
def _clear_policy():
    """Never leak an installed policy between tests."""
    set_normalization_policy(None)
    yield
    set_normalization_policy(None)


class _StubPolicy:
    def __init__(self, decision, reason="stub"):
        self.decision = decision
        self.reason = reason
        self.calls = []

    def decide(self, function_ea: int, seam: Seam) -> PolicyVerdict:
        self.calls.append((function_ea, seam))
        return PolicyVerdict(self.decision, self.reason)


class _ExplodingPolicy:
    def decide(self, function_ea: int, seam: Seam) -> PolicyVerdict:
        raise RuntimeError("policy backend unavailable")


class TestDefaultIsBehaviourPreserving:
    """With no policy installed the gate must change nothing."""

    def test_no_policy_installed_yields_run(self):
        verdict = decide(0x401000, Seam.FLOWCHART)

        assert verdict.decision is NormalizationDecision.RUN

    def test_no_policy_installed_permits_mutators(self):
        verdict = decide(0x401000, Seam.FLOWCHART)

        assert handler_is_permitted(verdict, read_only=False)
        assert handler_is_permitted(verdict, read_only=True)

    def test_installed_policy_is_reported(self):
        assert installed_policy() is None
        policy = _StubPolicy(NormalizationDecision.RUN)
        set_normalization_policy(policy)

        assert installed_policy() is policy


class TestSuppressAll:
    def test_suppresses_mutating_handlers(self):
        set_normalization_policy(_StubPolicy(NormalizationDecision.SUPPRESS_ALL))

        verdict = decide(0x401000, Seam.FLOWCHART)

        assert not handler_is_permitted(verdict, read_only=False)

    def test_suppresses_read_only_handlers_too(self):
        set_normalization_policy(_StubPolicy(NormalizationDecision.SUPPRESS_ALL))

        verdict = decide(0x401000, Seam.FLOWCHART)

        assert not handler_is_permitted(verdict, read_only=True)


class TestSuppressMutators:
    """Read-only observation must survive; anything that writes must not."""

    def test_read_only_handlers_still_run(self):
        set_normalization_policy(_StubPolicy(NormalizationDecision.SUPPRESS_MUTATORS))

        verdict = decide(0x401000, Seam.FLOWCHART)

        assert handler_is_permitted(verdict, read_only=True)

    def test_mutating_handlers_are_suppressed(self):
        set_normalization_policy(_StubPolicy(NormalizationDecision.SUPPRESS_MUTATORS))

        verdict = decide(0x401000, Seam.FLOWCHART)

        assert not handler_is_permitted(verdict, read_only=False)


class TestPolicyFailsClosed:
    """Seam handlers are fail-open; the gate is the opposite on purpose.

    A handler that raises must never break a decompile, so the registries
    swallow handler exceptions. The gate cannot inherit that: an unavailable
    policy must not silently license mutation on a function that may hold a
    certificate.
    """

    def test_raising_policy_suppresses_everything(self):
        set_normalization_policy(_ExplodingPolicy())

        verdict = decide(0x401000, Seam.FLOWCHART)

        assert verdict.decision is NormalizationDecision.SUPPRESS_ALL
        assert not handler_is_permitted(verdict, read_only=False)
        assert not handler_is_permitted(verdict, read_only=True)

    def test_raising_policy_records_a_reason(self):
        set_normalization_policy(_ExplodingPolicy())

        verdict = decide(0x401000, Seam.FLOWCHART)

        assert verdict.reason

    def test_policy_returning_garbage_suppresses_everything(self):
        class _Garbage:
            def decide(self, function_ea, seam):
                return "yes please"

        set_normalization_policy(_Garbage())

        verdict = decide(0x401000, Seam.FLOWCHART)

        assert verdict.decision is NormalizationDecision.SUPPRESS_ALL


class TestSeamIsPassedThrough:
    def test_policy_receives_function_and_seam(self):
        policy = _StubPolicy(NormalizationDecision.RUN)
        set_normalization_policy(policy)

        decide(0x401000, Seam.PREOPT)
        decide(0x402000, Seam.CALLS_DONE)

        assert policy.calls == [
            (0x401000, Seam.PREOPT),
            (0x402000, Seam.CALLS_DONE),
        ]

    def test_every_seam_has_a_distinct_value(self):
        values = [seam.value for seam in Seam]

        assert len(values) == len(set(values))
        assert set(values) >= {
            "flowchart",
            "preopt",
            "locopt",
            "calls_done",
            "callinfo",
            "stkpnts",
        }
