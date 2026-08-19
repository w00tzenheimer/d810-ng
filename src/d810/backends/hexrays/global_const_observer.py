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


def annotate_global_table_access(access: object, *, function_ea: int) -> object:
    """Delegate exact proposal queuing without importing IDA at module load."""

    from d810.backends.hexrays.global_const_annotation import (
        annotate_global_table_access as annotate,
    )

    return annotate(access, function_ea=function_ea)


@dataclass(frozen=True, slots=True)
class GlobalConstProposalIdentity:
    """Identity of one observation in one database/function generation."""

    database_identity: str
    function_ea: int
    generation: object
    item_head: int
    item_end: int
    element_size: int
    element_count: int


@dataclass(frozen=True, slots=True)
class _DisabledPreparationOptions:
    """Backend-local fallback for callers that have no compiled schedule."""

    enabled: bool = False
    discover_bounded_tables: bool = True


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
    ) -> None:
        self.preparation_options = self._validate_options(preparation_options)
        self.database_identity = str(database_identity)
        self._calls_maturity = calls_maturity
        self._discover = discover or discover_dynamic_global_table_access
        self._queue = queue or annotate_global_table_access
        self._seen: set[GlobalConstProposalIdentity] = set()
        self._current_generation: dict[tuple[str, int], object] = {}
        self._pending_identities: set[GlobalConstProposalIdentity] = set()
        self.pending_reason: str | None = None

    @property
    def restart_requested(self) -> bool:
        """The observer is passive and can never request a restart."""

        return False

    @property
    def pending_identities(self) -> tuple[GlobalConstProposalIdentity, ...]:
        return tuple(
            sorted(
                self._pending_identities,
                key=lambda identity: (
                    identity.function_ea,
                    identity.item_head,
                    identity.item_end,
                    identity.element_size,
                    identity.element_count,
                ),
            )
        )

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
    def _generation_for(mba: object) -> object:
        """Use the live MBA generation identity, never a process-global EA set."""

        for name in ("this", "generation", "_generation"):
            value = getattr(mba, name, None)
            if value is None or value == 0:
                continue
            try:
                hash(value)
            except TypeError:
                return repr(value)
            return value
        return id(mba)

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

    @staticmethod
    def _access_identity(
        access: object,
        *,
        database_identity: str,
        function_ea: int,
        generation: object,
    ) -> GlobalConstProposalIdentity:
        def _int(name: str) -> int:
            try:
                return int(getattr(access, name))
            except (AttributeError, TypeError, ValueError):
                return 0

        return GlobalConstProposalIdentity(
            database_identity=database_identity,
            function_ea=function_ea,
            generation=generation,
            item_head=_int("item_head"),
            item_end=_int("item_end"),
            element_size=_int("element_size"),
            element_count=_int("element_count"),
        )

    def _rotate_generation(self, function_ea: int, generation: object) -> None:
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
            self._pending_identities = {
                identity
                for identity in self._pending_identities
                if not (
                    identity.database_identity == self.database_identity
                    and identity.function_ea == function_ea
                    and identity.generation == previous
                )
            }
            if not self._pending_identities:
                self.pending_reason = None

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

    def observe(self, mba: object, maturity: object) -> None:
        """Observe one post-D810 MBA at exactly the CALLS maturity."""

        options = self.preparation_options
        if not options.enabled or not options.discover_bounded_tables:
            return None
        if not self._is_calls_maturity(maturity):
            return None

        function_ea = self._function_ea_for(mba)
        generation = self._generation_for(mba)
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
            identity = self._access_identity(
                access,
                database_identity=self.database_identity,
                function_ea=function_ea,
                generation=generation,
            )
            if identity in self._seen:
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
            self._seen.add(identity)
            if self._is_new_queue(report):
                self._pending_identities.add(identity)
                self.pending_reason = PENDING_PREPARATION_REASON
        return None


# The longer name is useful to manager wiring and keeps the backend seam
# discoverable without creating a second implementation.
GlobalConstObservationSubscriber = GlobalConstObserver


__all__ = [
    "GlobalConstObservationSubscriber",
    "GlobalConstObserver",
    "GlobalConstProposalIdentity",
    "PENDING_PREPARATION_REASON",
    "annotate_global_table_access",
    "discover_dynamic_global_table_access",
]
