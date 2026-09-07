"""Callback-local identity and scheduling for D-810-owned safe points.

The coordinator is deliberately smaller than the optblock adapter.  It does
not execute block rules, retain a live Hex-Rays object, or decide when a
pipeline is eligible.  The adapter remains responsible for those policies.
This module only gives one owned stage an exact native-epoch token and turns
the detached pipeline outcome into a disposition that the adapter can use to
install its stale-pointer fence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from d810.hexrays.ir.native_identity import NativeIdentity, native_object_identity


class SafePointDisposition(str, Enum):
    """Outcome of one owned stage at one current native safe point."""

    ABSTAINED = "abstained"
    ANALYSIS_ONLY = "analysis_only"
    MUTATED = "mutated"


class _ClaimState(str, Enum):
    CLAIMED = "claimed"
    COMPLETED = "completed"
    FAILED = "failed"


class FailedSafePointError(RuntimeError):
    """An owned stage failed against this native epoch; consumers must stop."""


@dataclass(frozen=True, slots=True)
class OwnedStageOutcome:
    """The only outcome a D-810-owned stage may report to the coordinator.

    The coordinator used to accept ``Any`` and guess at ``applied_count`` /
    ``mutations`` / ``total`` fields.  A producer that renamed a field, or
    returned an object carrying none of them, silently read as "no mutation"
    and the adapter skipped its stale-pointer fence.  The disposition is now
    stated by the committer, not inferred by the consumer.
    """

    disposition: SafePointDisposition
    mutation_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, SafePointDisposition):
            raise TypeError("owned stage outcome requires a SafePointDisposition")
        if isinstance(self.mutation_count, bool) or not isinstance(
            self.mutation_count, int
        ):
            raise TypeError("owned stage mutation_count must be an integer")
        if self.mutation_count < 0:
            raise ValueError("owned stage mutation_count must be non-negative")
        mutated = self.disposition is SafePointDisposition.MUTATED
        if mutated and self.mutation_count <= 0:
            raise ValueError("a mutated outcome requires a positive count")
        if not mutated and self.mutation_count:
            raise ValueError("a non-mutated outcome cannot carry mutations")

    @classmethod
    def abstained(cls) -> "OwnedStageOutcome":
        """The stage did not run, or ran and changed nothing observable."""
        return cls(disposition=SafePointDisposition.ABSTAINED)

    @classmethod
    def analysis_only(cls) -> "OwnedStageOutcome":
        """The stage published facts and left live microcode untouched."""
        return cls(disposition=SafePointDisposition.ANALYSIS_ONLY)

    @classmethod
    def mutated(cls, mutation_count: int) -> "OwnedStageOutcome":
        """The stage committed *mutation_count* live modifications."""
        return cls(
            disposition=SafePointDisposition.MUTATED,
            mutation_count=mutation_count,
        )

    @classmethod
    def from_applied_count(
        cls,
        applied_count: int,
        *,
        facts_published: bool = False,
    ) -> "OwnedStageOutcome":
        """Build the outcome a committer reports from its own applied count."""
        if isinstance(applied_count, bool) or not isinstance(applied_count, int):
            raise TypeError("owned stage applied_count must be an integer")
        if applied_count < 0:
            raise ValueError("owned stage applied_count must be non-negative")
        if applied_count > 0:
            return cls.mutated(applied_count)
        return cls.analysis_only() if facts_published else cls.abstained()


@dataclass(frozen=True, slots=True)
class SafePointKey:
    """Exact identity of one stage invocation against one live MBA epoch.

    ``mba_identity`` is the :class:`NativeIdentity` of the live ``mba_t``, not
    ``id(mba)``.  ``mblock_t.mba`` manufactures a new SWIG proxy per access,
    so two proxies for one MBA once produced two keys and let one native
    epoch be claimed twice; a dead proxy's recycled ``id`` could equally let a
    stale claim suppress a genuinely new epoch.  Both EAs and block serials
    survive a native replacement and cannot distinguish stale callback
    objects either.  The key stores only the primitive identity, never the
    live object.
    """

    session_id: object
    function_ea: int
    mba_identity: NativeIdentity
    maturity: int
    generation: int
    stage_id: str

    def __post_init__(self) -> None:
        if self.session_id is None:
            raise TypeError("safe-point session_id must not be None")
        try:
            hash(self.session_id)
        except TypeError as exc:
            raise TypeError("safe-point session_id must be hashable") from exc
        if not isinstance(self.mba_identity, NativeIdentity):
            raise TypeError("safe-point mba_identity must be a NativeIdentity")
        object.__setattr__(self, "function_ea", int(self.function_ea))
        object.__setattr__(self, "maturity", int(self.maturity))
        object.__setattr__(self, "generation", int(self.generation))
        if self.generation < 0:
            raise ValueError("safe-point generation must be non-negative")
        if not isinstance(self.stage_id, str) or not self.stage_id.strip():
            raise TypeError("safe-point stage_id must be a non-empty string")

    @classmethod
    def from_mba(
        cls,
        *,
        session_id: object,
        function_ea: int,
        mba: object,
        maturity: int,
        generation: int,
        stage_id: str,
    ) -> "SafePointKey":
        """Build a key while retaining no reference to the live MBA."""
        if mba is None:
            raise TypeError("safe-point key requires a live MBA object")
        return cls(
            session_id=session_id,
            function_ea=function_ea,
            mba_identity=native_object_identity(mba),
            maturity=maturity,
            generation=generation,
            stage_id=stage_id,
        )

    @property
    def mba_id(self) -> NativeIdentity:
        """Compatibility spelling for consumers that call the value an ID."""
        return self.mba_identity

    @property
    def native_generation(self) -> int:
        """Explicit spelling for the generation component of the key."""
        return self.generation


@dataclass(frozen=True, slots=True)
class SafePointResult:
    """Portable result of a coordinator claim and owned-stage execution."""

    key: SafePointKey
    disposition: SafePointDisposition
    claimed: bool
    mutation_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.key, SafePointKey):
            raise TypeError("safe-point result requires a SafePointKey")
        if not isinstance(self.disposition, SafePointDisposition):
            raise TypeError("safe-point result requires a SafePointDisposition")
        if not isinstance(self.claimed, bool):
            raise TypeError("safe-point result claimed must be boolean")
        mutation_count = int(self.mutation_count)
        if mutation_count < 0:
            raise ValueError("safe-point mutation_count must be non-negative")
        if self.disposition is SafePointDisposition.MUTATED and mutation_count <= 0:
            raise ValueError("mutated safe-point result requires a positive count")
        if self.disposition is not SafePointDisposition.MUTATED and mutation_count:
            raise ValueError("non-mutated safe-point result cannot have mutations")
        object.__setattr__(self, "mutation_count", mutation_count)

    @property
    def requires_stale_pointer_barrier(self) -> bool:
        """Whether the adapter must stop using callback-local block pointers."""
        return self.disposition is SafePointDisposition.MUTATED

    @property
    def allows_hosted_lane(self) -> bool:
        """Whether a callback may continue to hosted rules for this result."""
        return not self.requires_stale_pointer_barrier


class HexRaysSafePointCoordinator:
    """Claim exact safe points and classify detached pipeline outcomes.

    Claims retain their completion state under immutable native-epoch keys.
    They are reset by the owning adapter at decompilation start. There is no generation handshake or
    automatic unbarrier: when a pipeline mutates, the caller must install its
    existing maturity-wide ``_pipeline_just_fired`` fence.
    """

    def __init__(self) -> None:
        self._claimed: dict[SafePointKey, _ClaimState] = {}

    def reset(self) -> None:
        """Discard claims at a new top-level decompilation boundary."""
        self._claimed.clear()

    @property
    def has_failed_claims(self) -> bool:
        """Whether callback entry needs an epoch check, derived from its owner."""
        return _ClaimState.FAILED in self._claimed.values()

    def claim(self, key: SafePointKey) -> bool:
        """Claim *key* once, returning false for an already-seen epoch."""
        if not isinstance(key, SafePointKey):
            raise TypeError("safe-point claim requires a SafePointKey")
        if key in self._claimed:
            return False
        self._claimed[key] = _ClaimState.CLAIMED
        return True

    def require_usable(self, key: SafePointKey) -> None:
        """Reject a failed native epoch before any callback consumer runs.

        A claimed stage that failed is not an abstention. Maturity setup may
        itself have been interrupted, so adapter counters cannot own this
        decision. The claim survives until its owner resets the session; a
        different native identity, generation or maturity is a different key.
        """
        if not isinstance(key, SafePointKey):
            raise TypeError("safe-point usability requires a SafePointKey")
        if self._claimed.get(key) is _ClaimState.FAILED:
            raise FailedSafePointError(
                f"owned stage {key.stage_id!r} failed for this native epoch"
            )

    def run(
        self,
        key: SafePointKey,
        operation: Callable[[], OwnedStageOutcome],
    ) -> SafePointResult:
        """Claim *key* and record the operation's own stated outcome.

        A completed duplicate is an abstention and does not call ``operation``. An
        operation exception -- including the :class:`TypeError` raised for an
        outcome that is not an :class:`OwnedStageOutcome` -- is deliberately
        propagated to the adapter's existing exception boundary; the claim is
        retained as failed so later consumers cannot resume that native epoch.
        """
        if not callable(operation):
            raise TypeError("safe-point operation must be callable")
        self.require_usable(key)
        if not self.claim(key):
            return SafePointResult(
                key=key,
                disposition=SafePointDisposition.ABSTAINED,
                claimed=False,
            )
        try:
            result = self._result_for(key, operation())
        except BaseException:
            self._claimed[key] = _ClaimState.FAILED
            raise
        self._claimed[key] = _ClaimState.COMPLETED
        return result

    @staticmethod
    def _result_for(
        key: SafePointKey,
        outcome: object,
    ) -> SafePointResult:
        """Record *outcome*, refusing anything that is not the typed contract.

        Failing closed matters more than tolerance here: the disposition
        decides whether the adapter installs its stale-pointer fence, so an
        unrecognised value must never be silently read as "no mutation".
        """
        if not isinstance(outcome, OwnedStageOutcome):
            raise TypeError(
                "owned stage at safe point "
                f"{key.stage_id!r} must return an OwnedStageOutcome, not "
                f"{type(outcome).__name__}"
            )
        return SafePointResult(
            key=key,
            disposition=outcome.disposition,
            claimed=True,
            mutation_count=outcome.mutation_count,
        )


__all__ = [
    "FailedSafePointError",
    "HexRaysSafePointCoordinator",
    "OwnedStageOutcome",
    "SafePointDisposition",
    "SafePointKey",
    "SafePointResult",
]
