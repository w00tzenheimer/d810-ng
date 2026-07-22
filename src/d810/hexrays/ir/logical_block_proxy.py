"""Versioned logical block authority for one live MBA session."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.ir.block_identity import (
    BlockHandleProvenance,
    MbaBlockHandle,
    StableBlockIdentity,
)


class LogicalBlockVersionState(Enum):
    STAGED = "staged"
    PUBLISHED = "published"
    RETIRED = "retired"
    ABORTED = "aborted"


class LogicalBlockStageConflict(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class LogicalBlockVersionId:
    proxy_token: str
    version: int

    def __post_init__(self) -> None:
        proxy_token = str(self.proxy_token)
        version = int(self.version)
        if not proxy_token:
            raise ValueError("logical block version requires a proxy token")
        if version < 0:
            raise ValueError("logical block version must be non-negative")
        object.__setattr__(self, "proxy_token", proxy_token)
        object.__setattr__(self, "version", version)


@dataclass(frozen=True, slots=True)
class LogicalBlockVersion:
    version_id: LogicalBlockVersionId
    handle: MbaBlockHandle
    generation: int
    predecessor_version_id: LogicalBlockVersionId | None

    def __post_init__(self) -> None:
        generation = int(self.generation)
        if generation < 0:
            raise ValueError("logical block generation must be non-negative")
        if self.handle.token == self.version_id.proxy_token:
            raise ValueError("logical and physical block tokens must be distinct")
        predecessor = self.predecessor_version_id
        if (
            predecessor is not None
            and predecessor.proxy_token != self.version_id.proxy_token
        ):
            raise ValueError("replacement lineage cannot cross logical proxies")
        object.__setattr__(self, "generation", generation)


@dataclass(frozen=True, slots=True)
class LogicalBlockVersionTransition:
    transaction_id: str
    retired_version_id: LogicalBlockVersionId | None
    promoted_version_id: LogicalBlockVersionId | None

    def __post_init__(self) -> None:
        transaction_id = str(self.transaction_id)
        if not transaction_id:
            raise ValueError("logical block transition requires a transaction id")
        if self.retired_version_id is None and self.promoted_version_id is None:
            raise ValueError("logical block transition requires a changed version")
        object.__setattr__(self, "transaction_id", transaction_id)


class LogicalBlockProxy:
    """One stable logical block with versioned physical realizations.

    A version deliberately contains no MBA serial.  The live identity index
    binds a resolved version to a serial only at the backend boundary.  This
    object owns publication authority: ordinary readers see ``_published``;
    only the transaction that staged a replacement may see that replacement.
    """

    __slots__ = (
        "_aborted",
        "_lineage",
        "_next_version",
        "_provenance",
        "_proxy_token",
        "_published",
        "_retired",
        "_session_id",
        "_stable_identity",
        "_staged",
        "_states",
    )

    def __init__(
        self,
        *,
        proxy_token: str,
        published: LogicalBlockVersion,
    ) -> None:
        proxy_token = str(proxy_token)
        if not proxy_token or published.version_id.proxy_token != proxy_token:
            raise ValueError("published version must belong to its logical proxy")
        self._proxy_token = proxy_token
        self._session_id = published.handle.session_id
        self._stable_identity = published.handle.stable_identity
        self._provenance = published.handle.provenance
        self._published = published
        self._staged: dict[str, LogicalBlockVersion] = {}
        self._retired: list[LogicalBlockVersion] = []
        self._aborted: list[LogicalBlockVersion] = []
        self._lineage: list[
            tuple[LogicalBlockVersionId, LogicalBlockVersionId]
        ] = []
        self._states: dict[LogicalBlockVersionId, LogicalBlockVersionState] = {
            published.version_id: LogicalBlockVersionState.PUBLISHED
        }
        self._next_version = published.version_id.version + 1

    @classmethod
    def with_published(
        cls,
        *,
        proxy_token: str,
        handle: MbaBlockHandle,
        generation: int,
    ) -> LogicalBlockProxy:
        proxy_token = str(proxy_token)
        generation = int(generation)
        if not proxy_token:
            raise ValueError("logical block proxy requires a token")
        return cls(
            proxy_token=proxy_token,
            published=LogicalBlockVersion(
                version_id=LogicalBlockVersionId(proxy_token, 0),
                handle=handle,
                generation=generation,
                predecessor_version_id=None,
            ),
        )

    @property
    def proxy_token(self) -> str:
        return self._proxy_token

    @property
    def stable_identity(self) -> StableBlockIdentity | None:
        return self._stable_identity

    @property
    def generation(self) -> int:
        return self._published.generation

    @property
    def provenance(self) -> BlockHandleProvenance:
        return self._provenance

    @property
    def retired_versions(self) -> tuple[LogicalBlockVersion, ...]:
        return tuple(self._retired)

    @property
    def aborted_versions(self) -> tuple[LogicalBlockVersion, ...]:
        return tuple(self._aborted)

    @property
    def replacement_lineage(
        self,
    ) -> tuple[tuple[LogicalBlockVersionId, LogicalBlockVersionId], ...]:
        return tuple(self._lineage)

    def resolve(self, *, transaction_id: str | None = None) -> LogicalBlockVersion:
        if transaction_id is not None:
            staged = self._staged.get(str(transaction_id))
            if staged is not None:
                return staged
        return self._published

    def stage(
        self,
        *,
        transaction_id: str,
        handle: MbaBlockHandle,
        generation: int,
    ) -> LogicalBlockVersion:
        transaction_id = str(transaction_id)
        generation = int(generation)
        if not transaction_id:
            raise ValueError("logical block stage requires a transaction id")
        if transaction_id in self._staged:
            raise LogicalBlockStageConflict(
                f"transaction {transaction_id!r} already staged this logical block"
            )
        if generation != self.generation + 1:
            raise ValueError(
                "staged logical block generation must follow published generation"
            )
        if handle.session_id != self._session_id:
            raise ValueError("logical block session cannot drift between versions")
        if handle.stable_identity != self._stable_identity:
            raise ValueError("logical block stable identity cannot drift between versions")
        if handle.provenance is not self._provenance:
            raise ValueError("logical block provenance cannot drift between versions")
        staged = LogicalBlockVersion(
            version_id=LogicalBlockVersionId(
                proxy_token=self._proxy_token,
                version=self._next_version,
            ),
            handle=handle,
            generation=generation,
            predecessor_version_id=self._published.version_id,
        )
        self._next_version += 1
        self._staged[transaction_id] = staged
        self._states[staged.version_id] = LogicalBlockVersionState.STAGED
        return staged

    def commit(self, transaction_id: str) -> LogicalBlockVersionTransition:
        transaction_id = str(transaction_id)
        try:
            staged = self._staged[transaction_id]
        except KeyError as exc:
            raise LogicalBlockStageConflict(
                f"transaction {transaction_id!r} has no staged logical block"
            ) from exc
        published = self._published
        if staged.predecessor_version_id != published.version_id:
            raise LogicalBlockStageConflict(
                "staged logical block no longer has the published predecessor"
            )
        self._staged.pop(transaction_id)
        self._states[published.version_id] = LogicalBlockVersionState.RETIRED
        self._retired.append(published)
        self._published = staged
        self._states[staged.version_id] = LogicalBlockVersionState.PUBLISHED
        self._lineage.append((published.version_id, staged.version_id))
        return LogicalBlockVersionTransition(
            transaction_id=transaction_id,
            retired_version_id=published.version_id,
            promoted_version_id=staged.version_id,
        )

    def abort(self, transaction_id: str) -> LogicalBlockVersion:
        transaction_id = str(transaction_id)
        try:
            staged = self._staged.pop(transaction_id)
        except KeyError as exc:
            raise LogicalBlockStageConflict(
                f"transaction {transaction_id!r} has no staged logical block"
            ) from exc
        self._states[staged.version_id] = LogicalBlockVersionState.ABORTED
        self._aborted.append(staged)
        return staged

    def state_of(self, version_id: LogicalBlockVersionId) -> LogicalBlockVersionState:
        return self._states[version_id]


__all__ = [
    "LogicalBlockProxy",
    "LogicalBlockStageConflict",
    "LogicalBlockVersion",
    "LogicalBlockVersionId",
    "LogicalBlockVersionState",
    "LogicalBlockVersionTransition",
]
