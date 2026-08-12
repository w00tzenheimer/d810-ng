"""Earliest per-function gate for pre-lift seam handlers.

Review finding P1 #4 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md`` asks for one
gate consulted by every preanalysis dispatcher, resolver writer, and native
gateway, so that a function carrying a normalization certificate cannot be
mutated underneath it. This is that gate, landed before there is anything to
suppress: the default verdict is ``RUN``, so installing it changes no behaviour.

**Why it lives in ``d810.core``.** The plan first proposed
``d810.manager.normalization_policy``. The registries that must consult it are
``d810.hexrays.preanalysis.*``, and the layered-architecture contract places
``d810.manager`` above ``d810.hexrays`` -- a registry importing the manager is an
upward import and breaks the contract. So the protocol and the installed-policy
slot live in the bottom layer, and the manager installs a concrete
certificate-aware policy at runtime. Dependency inversion, not an ignore.

**Two suppression levels, because the seam has two kinds of mutation.** Both
flowchart-seam consumers at the pinned baseline write, but they write different
things: the computed-goto resolver patches bytes, while indirect-label
materialization only touches items, crefs, switch metadata and function
boundaries. A gate that stopped byte writes alone would let a "frozen" function
have its item map rewritten anyway, so ``SUPPRESS_MUTATORS`` covers any handler
not explicitly declared read-only.

**The gate fails closed; handlers fail open.** Seam registries deliberately
swallow handler exceptions -- preanalysis must never break a decompile. The gate
must not inherit that. An unavailable or malfunctioning policy has to deny, or a
transient failure silently licenses mutation on a certified function.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.typing import Protocol, runtime_checkable

logger = getLogger("d810.core.normalization_policy")

__all__ = [
    "FunctionNormalizationPolicy",
    "NormalizationDecision",
    "PolicyVerdict",
    "Seam",
    "decide",
    "handler_is_permitted",
    "installed_policy",
    "set_normalization_policy",
]


class Seam(str, enum.Enum):
    """Pre-lift seams that dispatch registered handlers."""

    FLOWCHART = "flowchart"
    PREOPT = "preopt"
    LOCOPT = "locopt"
    CALLS_DONE = "calls_done"
    CALLINFO = "callinfo"
    STKPNTS = "stkpnts"


class NormalizationDecision(str, enum.Enum):
    RUN = "RUN"
    """Run every handler. The default, and behaviour-preserving."""

    SUPPRESS_MUTATORS = "SUPPRESS_MUTATORS"
    """Run only handlers explicitly declared read-only."""

    SUPPRESS_ALL = "SUPPRESS_ALL"
    """Run nothing at this seam, including read-only observation."""


@dataclass(frozen=True, slots=True)
class PolicyVerdict:
    decision: NormalizationDecision
    reason: str = ""


@runtime_checkable
class FunctionNormalizationPolicy(Protocol):
    def decide(self, function_ea: int, seam: Seam) -> PolicyVerdict: ...


_policy: FunctionNormalizationPolicy | None = None

_DEFAULT = PolicyVerdict(NormalizationDecision.RUN, "no policy installed")


def set_normalization_policy(policy: FunctionNormalizationPolicy | None) -> None:
    """Install (or clear, with ``None``) the process-wide policy."""
    global _policy
    _policy = policy


def installed_policy() -> FunctionNormalizationPolicy | None:
    return _policy


def decide(function_ea: int, seam: Seam) -> PolicyVerdict:
    """Ask the installed policy what may run for ``function_ea`` at ``seam``.

    Returns ``RUN`` when no policy is installed. Any failure -- an exception, or
    a return value that is not a ``PolicyVerdict`` -- denies everything rather
    than falling through to ``RUN``.
    """
    policy = _policy
    if policy is None:
        return _DEFAULT
    try:
        verdict = policy.decide(int(function_ea), seam)
    except Exception:
        logger.debug(
            "normalization policy raised for 0x%X at %s; failing closed",
            int(function_ea),
            seam.value,
            exc_info=True,
        )
        return PolicyVerdict(
            NormalizationDecision.SUPPRESS_ALL, "policy raised; failed closed"
        )
    if not isinstance(verdict, PolicyVerdict):
        logger.debug(
            "normalization policy returned %r for 0x%X at %s; failing closed",
            type(verdict).__name__,
            int(function_ea),
            seam.value,
        )
        return PolicyVerdict(
            NormalizationDecision.SUPPRESS_ALL,
            f"policy returned {type(verdict).__name__}; failed closed",
        )
    return verdict


def handler_is_permitted(verdict: PolicyVerdict, *, read_only: bool) -> bool:
    """Whether a handler may run under ``verdict``.

    ``read_only`` must be declared at registration. An unmarked handler is
    treated as a mutator, because assuming otherwise would silently exempt every
    handler that predates this gate.
    """
    if verdict.decision is NormalizationDecision.RUN:
        return True
    if verdict.decision is NormalizationDecision.SUPPRESS_MUTATORS:
        return read_only
    return False
