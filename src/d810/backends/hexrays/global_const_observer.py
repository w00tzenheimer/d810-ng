"""Observation-only bounded-table discovery at the post-D810 CALLS seam.

This module intentionally keeps the observer separate from the readonly-data
peephole rule.  The observer reads the live MBA, queues exact type proposals
through :mod:`global_const_annotation`, and never changes microcode or asks
Hex-Rays to restart a decompilation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.ir.maturity import IRMaturity

logger = getLogger("d810.backends.hexrays.global_const_observer")

PENDING_PREPARATION_REASON = "next preparation round"


def discover_dynamic_global_table_access(instruction: object) -> object | None:
    """Delegate bounded-table discovery without importing IDA at module load."""

    from d810.backends.hexrays.global_const_annotation import (
        discover_dynamic_global_table_access as discover,
    )

    return discover(instruction)


def annotate_global_table_access(
    access: object,
    *,
    function_ea: int,
    database_identity: str = "",
) -> object:
    """Delegate exact proposal queuing without importing IDA at module load."""

    from d810.backends.hexrays.global_const_annotation import (
        annotate_global_table_access as annotate,
    )

    return annotate(
        access,
        function_ea=function_ea,
        database_identity=database_identity,
    )


def pending_global_const_proposals(
    *, database_identity: str | None = None
) -> tuple[object, ...]:
    """Read the durable proposal queue without importing IDA at module load."""

    from d810.backends.hexrays.global_const_annotation import (
        pending_global_const_proposals as pending,
    )

    return pending(database_identity=database_identity)


@dataclass(frozen=True, slots=True)
class GlobalConstProposalIdentity:
    """Canonical proposal identity in one database/function generation."""

    database_identity: str
    function_ea: int
    generation: int | None
    proposal_identity: tuple[object, ...]

    @property
    def item_head(self) -> int:
        return int(self.proposal_identity[1])

    @property
    def item_end(self) -> int:
        return int(self.proposal_identity[2])

    @property
    def before(self) -> object:
        return self.proposal_identity[3]

    @property
    def after(self) -> object:
        return self.proposal_identity[4]

    @classmethod
    def from_proposal(
        cls,
        proposal: object,
        *,
        database_identity: str,
        generation: int | None,
    ) -> "GlobalConstProposalIdentity":
        raw_identity = getattr(proposal, "identity", None)
        if not isinstance(raw_identity, (tuple, list)) or len(raw_identity) != 5:
            raise ValueError("proposal must expose its exact five-field identity")
        try:
            identity = (
                int(raw_identity[0]),
                int(raw_identity[1]),
                int(raw_identity[2]),
                raw_identity[3],
                raw_identity[4],
            )
            hash(identity)
        except (TypeError, ValueError, IndexError) as error:
            raise ValueError("proposal identity is not hashable and exact") from error
        return cls(
            database_identity=str(database_identity),
            function_ea=int(identity[0]),
            generation=generation,
            proposal_identity=identity,
        )


@dataclass(frozen=True, slots=True)
class _DisabledPreparationOptions:
    """Backend-local fallback for callers that have no compiled schedule."""

    enabled: bool = False
    discover_bounded_tables: bool = True


@dataclass(frozen=True, slots=True)
class GlobalConstObserverRuntimeState:
    """Rollback snapshot for observer policy and callback dedupe state."""

    preparation_options: object
    seen: frozenset[GlobalConstProposalIdentity]
    current_generations: tuple[tuple[str, int, int], ...]
    pending_reason: str | None


class GlobalConstObserver:
    """Queue bounded-table const proposals without entering mutation paths."""

    def __init__(
        self,
        *,
        preparation_options: object | bool | None = None,
        database_identity: str = "",
        calls_maturity: int | None = None,
        discover: Callable[[object], object | None] | None = None,
        queue: Callable[..., object] | None = None,
        pending_proposals: Callable[[], tuple[object, ...]] | None = None,
    ) -> None:
        self.preparation_options = self._validate_options(preparation_options)
        self.database_identity = str(database_identity)
        self._calls_maturity = calls_maturity
        self._discover = discover or discover_dynamic_global_table_access
        self._queue = queue or (
            lambda access, *, function_ea: annotate_global_table_access(
                access,
                function_ea=function_ea,
                database_identity=self.database_identity,
            )
        )
        self._pending_proposals = pending_proposals or (
            lambda: pending_global_const_proposals(
                database_identity=self.database_identity,
            )
        )
        self._seen: set[GlobalConstProposalIdentity] = set()
        self._current_generation: dict[tuple[str, int], int] = {}
        self.pending_reason: str | None = None

    @property
    def restart_requested(self) -> bool:
        """The observer is passive and can never request a restart."""

        return False

    @property
    def pending_identities(self) -> tuple[GlobalConstProposalIdentity, ...]:
        """Return pending identities from the durable queue, not a shadow set."""

        try:
            proposals = tuple(self._pending_proposals())
        except Exception:
            logger.debug("durable global-const proposal lookup failed", exc_info=True)
            return ()
        identities: set[GlobalConstProposalIdentity] = set()
        for proposal in proposals:
            try:
                identities.add(
                    GlobalConstProposalIdentity.from_proposal(
                        proposal,
                        database_identity=self.database_identity,
                        generation=None,
                    )
                )
            except (AttributeError, TypeError, ValueError, IndexError):
                logger.debug("malformed durable global-const proposal", exc_info=True)
        return tuple(
            sorted(
                identities,
                key=lambda identity: (
                    identity.function_ea,
                    identity.item_head,
                    identity.item_end,
                    repr(identity.before),
                    repr(identity.after),
                ),
            )
        )

    def snapshot_runtime_state(self) -> GlobalConstObserverRuntimeState:
        """Capture live options and per-generation suppression for rollback."""

        return GlobalConstObserverRuntimeState(
            preparation_options=self.preparation_options,
            seen=frozenset(self._seen),
            current_generations=tuple(
                sorted(
                    (
                        database_identity,
                        function_ea,
                        generation,
                    )
                    for (
                        database_identity,
                        function_ea,
                    ), generation in self._current_generation.items()
                )
            ),
            pending_reason=self.pending_reason,
        )

    def restore_runtime_state(self, state: GlobalConstObserverRuntimeState) -> None:
        """Restore a live observer snapshot captured before project activation."""

        if not isinstance(state, GlobalConstObserverRuntimeState):
            raise TypeError("state must be GlobalConstObserverRuntimeState")
        self.preparation_options = self._validate_options(state.preparation_options)
        self._seen = set(state.seen)
        self._current_generation = {
            (database_identity, function_ea): generation
            for database_identity, function_ea, generation in state.current_generations
        }
        self.pending_reason = state.pending_reason

    # Keep the snapshot protocol discoverable to manager-owned rollback code.
    snapshot_state = snapshot_runtime_state
    restore_state = restore_runtime_state

    def _durable_pending_exists(self) -> bool:
        return bool(self.pending_identities)

    def configure(self, preparation_options: object | bool | None) -> None:
        """Replace the immutable preparation policy at a manager boundary."""

        self.preparation_options = self._validate_options(preparation_options)

    @staticmethod
    def _validate_options(
        preparation_options: object | bool | None,
    ) -> object:
        if preparation_options is None:
            return _DisabledPreparationOptions()
        if isinstance(preparation_options, bool):
            return _DisabledPreparationOptions(enabled=preparation_options)
        enabled = getattr(preparation_options, "enabled", None)
        discover = getattr(preparation_options, "discover_bounded_tables", None)
        if not isinstance(enabled, bool) or not isinstance(discover, bool):
            raise TypeError(
                "preparation_options must expose boolean enabled and "
                "discover_bounded_tables fields"
            )
        return preparation_options

    def _expected_calls_maturity(self) -> int | None:
        if self._calls_maturity is not None:
            return int(self._calls_maturity)
        try:
            import ida_hexrays

            return int(ida_hexrays.MMAT_CALLS)
        except Exception:
            return None

    def _is_calls_maturity(self, maturity: object) -> bool:
        if maturity is IRMaturity.CALL_MODELED:
            return True
        if isinstance(maturity, str):
            return maturity.strip().upper() in {"MMAT_CALLS", "CALL_MODELED"}
        if isinstance(maturity, bool):
            return False
        expected = self._expected_calls_maturity()
        if expected is None:
            return False
        try:
            return int(maturity) == expected
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _function_ea_for(mba: object) -> int:
        try:
            return int(getattr(mba, "entry_ea", 0) or 0)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _instructions(mba: object) -> Iterator[object]:
        """Yield instructions in deterministic MBA block/list order."""

        try:
            quantity = int(getattr(mba, "qty", 0) or 0)
        except (TypeError, ValueError):
            return
        for serial in range(quantity):
            try:
                block = mba.get_mblock(serial)
            except Exception:
                continue
            instruction = getattr(block, "head", None)
            while instruction is not None:
                yield instruction
                instruction = getattr(instruction, "next", None)

    def _rotate_generation(self, function_ea: int, generation: int) -> None:
        scope = (self.database_identity, function_ea)
        previous = self._current_generation.get(scope)
        if previous == generation:
            return
        self._current_generation[scope] = generation
        if previous is not None:
            self._seen = {
                identity
                for identity in self._seen
                if not (
                    identity.database_identity == self.database_identity
                    and identity.function_ea == function_ea
                    and identity.generation == previous
                )
            }

    @staticmethod
    def _is_new_queue(report: object) -> bool:
        queued_count = getattr(report, "queued_count", None)
        if queued_count is not None:
            try:
                return int(queued_count) > 0
            except (TypeError, ValueError):
                return False
        changed_count = getattr(report, "changed_count", 0)
        try:
            return int(changed_count) > 0
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _proposal_candidates(report: object) -> tuple[object, ...]:
        """Read canonical proposal objects emitted by the annotation report."""

        candidates: list[object] = []
        for attribute in ("proposal_candidates", "queued_proposals"):
            values = getattr(report, attribute, ())
            if values is None:
                continue
            try:
                candidates.extend(tuple(values))
            except TypeError:
                continue
        return tuple(candidates)

    def observe(
        self,
        mba: object,
        maturity: object,
        *,
        generation: int | None = None,
    ) -> None:
        """Observe one post-D810 MBA at exactly the CALLS maturity."""

        if generation is None:
            raise ValueError("generation must be supplied by the lifecycle owner")
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise TypeError("generation must be an int")
        if generation < 0:
            raise ValueError("generation must be non-negative")
        options = self.preparation_options
        if not options.enabled or not options.discover_bounded_tables:
            return None
        if not self._is_calls_maturity(maturity):
            return None

        function_ea = self._function_ea_for(mba)
        self._rotate_generation(function_ea, generation)
        for instruction in self._instructions(mba):
            try:
                access = self._discover(instruction)
            except Exception:
                logger.debug(
                    "bounded global-table discovery failed for func=0x%X",
                    function_ea,
                    exc_info=True,
                )
                continue
            if access is None:
                continue
            try:
                report = self._queue(access, function_ea=function_ea)
            except Exception:
                # Queueing is a best-effort observation.  Do not mark a failed
                # proposal as seen, and never let a type backend failure alter
                # the live microcode callback.
                logger.debug(
                    "bounded global-table proposal queue failed for func=0x%X",
                    function_ea,
                    exc_info=True,
                )
                continue
            for proposal in self._proposal_candidates(report):
                try:
                    self._seen.add(
                        GlobalConstProposalIdentity.from_proposal(
                            proposal,
                            database_identity=self.database_identity,
                            generation=generation,
                        )
                    )
                except (AttributeError, TypeError, ValueError, IndexError):
                    logger.debug(
                        "global-const report omitted a canonical proposal identity",
                        exc_info=True,
                    )
            if self._is_new_queue(report):
                self.pending_reason = PENDING_PREPARATION_REASON
        if self._durable_pending_exists():
            self.pending_reason = PENDING_PREPARATION_REASON
        return None


# The longer name is useful to manager wiring and keeps the backend seam
# discoverable without creating a second implementation.
GlobalConstObservationSubscriber = GlobalConstObserver


__all__ = [
    "GlobalConstObservationSubscriber",
    "GlobalConstObserver",
    "GlobalConstProposalIdentity",
    "GlobalConstObserverRuntimeState",
    "PENDING_PREPARATION_REASON",
    "annotate_global_table_access",
    "discover_dynamic_global_table_access",
    "pending_global_const_proposals",
]
