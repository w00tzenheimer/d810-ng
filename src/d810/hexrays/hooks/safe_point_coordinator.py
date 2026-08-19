"""Callback-local identity and scheduling for D-810-owned safe points.

The coordinator is deliberately smaller than the optblock adapter.  It does
not execute block rules, retain a live Hex-Rays object, or decide when a
pipeline is eligible.  The adapter remains responsible for those policies.
This module only gives one owned stage an exact native-epoch token and turns
the detached pipeline outcome into a disposition that the adapter can use to
install its stale-pointer fence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum

from d810.core import typing


class SafePointDisposition(str, Enum):
    """Outcome of one owned stage at one current native safe point."""

    ABSTAINED = "abstained"
    ANALYSIS_ONLY = "analysis_only"
    MUTATED = "mutated"


@dataclass(frozen=True, slots=True)
class SafePointKey:
    """Exact identity of one stage invocation against one live MBA epoch.

    ``mba_identity`` is intentionally the process-local ``id(mba)`` rather
    than an EA or block serial.  Both EAs and block serials can survive a
    native replacement and therefore cannot distinguish stale callback
    objects.  The key stores only that integer, never the live object.
    """

    session_id: object
    function_ea: int
    mba_identity: int
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
        object.__setattr__(self, "function_ea", int(self.function_ea))
        object.__setattr__(self, "mba_identity", int(self.mba_identity))
        object.__setattr__(self, "maturity", int(self.maturity))
        object.__setattr__(self, "generation", int(self.generation))
        if self.mba_identity <= 0:
            raise ValueError("safe-point mba_identity must be positive")
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
            mba_identity=id(mba),
            maturity=maturity,
            generation=generation,
            stage_id=stage_id,
        )

    @property
    def mba_id(self) -> int:
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

    The set contains immutable keys only.  It is reset by the owning adapter
    at decompilation start.  There is intentionally no generation handshake or
    automatic unbarrier: when a pipeline mutates, the caller must install its
    existing maturity-wide ``_pipeline_just_fired`` fence.
    """

    _MUTATION_FIELDS = ("applied_count", "mutation_count", "mutations", "total")
    _FACT_FIELDS = (
        "facts_published",
        "analysis_only",
        "facts",
        "analysis_outputs",
        "evidence_outputs",
    )

    def __init__(self) -> None:
        self._claimed: set[SafePointKey] = set()

    def reset(self) -> None:
        """Discard claims at a new top-level decompilation boundary."""
        self._claimed.clear()

    def claim(self, key: SafePointKey) -> bool:
        """Claim *key* once, returning false for an already-seen epoch."""
        if not isinstance(key, SafePointKey):
            raise TypeError("safe-point claim requires a SafePointKey")
        if key in self._claimed:
            return False
        self._claimed.add(key)
        return True

    def run(
        self,
        key: SafePointKey,
        operation: Callable[[], typing.Any],
    ) -> SafePointResult:
        """Claim *key* and classify the detached operation result.

        A duplicate is an abstention and does not call ``operation``.  An
        operation exception is deliberately propagated to the adapter's
        existing exception boundary; the claim is retained so a failing
        callback cannot retry the same native epoch indefinitely.
        """
        if not callable(operation):
            raise TypeError("safe-point operation must be callable")
        if not self.claim(key):
            return SafePointResult(
                key=key,
                disposition=SafePointDisposition.ABSTAINED,
                claimed=False,
            )
        return self._result_for(key, operation())

    @classmethod
    def _result_for(
        cls,
        key: SafePointKey,
        value: typing.Any,
    ) -> SafePointResult:
        if isinstance(value, SafePointDisposition):
            disposition = value
            mutation_count = 1 if disposition is SafePointDisposition.MUTATED else 0
            return SafePointResult(
                key=key,
                disposition=disposition,
                claimed=True,
                mutation_count=mutation_count,
            )

        mutation_count = cls._mutation_count(value)
        if mutation_count > 0:
            return SafePointResult(
                key=key,
                disposition=SafePointDisposition.MUTATED,
                claimed=True,
                mutation_count=mutation_count,
            )
        if cls._publishes_facts(value):
            disposition = SafePointDisposition.ANALYSIS_ONLY
        else:
            disposition = SafePointDisposition.ABSTAINED
        return SafePointResult(
            key=key,
            disposition=disposition,
            claimed=True,
        )

    @classmethod
    def _mutation_count(cls, value: typing.Any) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return max(0, int(value))
        for name in cls._MUTATION_FIELDS:
            candidate = cls._read(value, name)
            if candidate is None:
                continue
            try:
                return max(0, int(candidate))
            except (TypeError, ValueError, OverflowError):
                continue
        return 0

    @classmethod
    def _publishes_facts(cls, value: typing.Any) -> bool:
        for name in cls._FACT_FIELDS:
            candidate = cls._read(value, name)
            if candidate is None:
                continue
            if name in {"facts_published", "analysis_only"}:
                if bool(candidate):
                    return True
                continue
            if candidate:
                return True
        return False

    @staticmethod
    def _read(value: typing.Any, name: str) -> typing.Any:
        if isinstance(value, Mapping):
            return value.get(name)
        return getattr(value, name, None)


__all__ = [
    "HexRaysSafePointCoordinator",
    "SafePointDisposition",
    "SafePointKey",
    "SafePointResult",
]
