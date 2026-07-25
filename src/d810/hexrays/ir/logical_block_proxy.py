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
    retired_version: LogicalBlockVersion | None
    promoted_version: LogicalBlockVersion | None

    def __post_init__(self) -> None:
        transaction_id = str(self.transaction_id)
        if not transaction_id:
            raise ValueError("logical block transition requires a transaction id")
        retired = self.retired_version
        promoted = self.promoted_version
        if retired is None and promoted is None:
            raise ValueError("logical block transition requires a changed version")
        if retired is not None and promoted is not None:
            if retired.version_id.proxy_token != promoted.version_id.proxy_token:
                raise ValueError("logical block transition cannot cross proxies")
            if promoted.predecessor_version_id != retired.version_id:
                raise ValueError(
                    "promoted logical block must identify its retired predecessor"
                )
        elif promoted is not None and promoted.predecessor_version_id is not None:
            raise ValueError(
                "initial logical block publication cannot claim a predecessor"
            )
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
        "_generation",
        "_lineage",
        "_next_version",
        "_provenance",
        "_proxy_token",
        "_published",
        "_retired",
        "_retirements",
        "_session_id",
        "_stable_identity",
        "_staged",
        "_states",
    )

    def __init__(
        self,
        *,
        proxy_token: str,
        session_id: str,
        stable_identity: StableBlockIdentity | None,
        provenance: BlockHandleProvenance,
        generation: int,
        published: LogicalBlockVersion | None,
    ) -> None:
        proxy_token = str(proxy_token)
        session_id = str(session_id)
        generation = int(generation)
        if not proxy_token or not session_id:
            raise ValueError("logical block proxy requires tokens and a session")
        if generation < 0:
            raise ValueError("logical block generation must be non-negative")
        if published is not None:
            if published.version_id.proxy_token != proxy_token:
                raise ValueError("published version must belong to its logical proxy")
            if published.handle.session_id != session_id:
                raise ValueError("published version must belong to the proxy session")
            if published.handle.stable_identity != stable_identity:
                raise ValueError("published version must match the proxy identity")
            if published.handle.provenance is not provenance:
                raise ValueError("published version must match the proxy provenance")
            if published.generation != generation:
                raise ValueError("published version must match the proxy generation")
        self._proxy_token = proxy_token
        self._session_id = session_id
        self._stable_identity = stable_identity
        self._provenance = provenance
        self._generation = generation
        self._published = published
        self._staged: dict[str, LogicalBlockVersion] = {}
        self._retirements: dict[str, int] = {}
        self._retired: list[LogicalBlockVersion] = []
        self._aborted: list[LogicalBlockVersion] = []
        self._lineage: list[tuple[LogicalBlockVersionId, LogicalBlockVersionId]] = []
        self._states: dict[LogicalBlockVersionId, LogicalBlockVersionState] = {}
        if published is not None:
            self._states[published.version_id] = LogicalBlockVersionState.PUBLISHED
        self._next_version = (
            0 if published is None else published.version_id.version + 1
        )

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
            session_id=handle.session_id,
            stable_identity=handle.stable_identity,
            provenance=handle.provenance,
            generation=generation,
            published=LogicalBlockVersion(
                version_id=LogicalBlockVersionId(proxy_token, 0),
                handle=handle,
                generation=generation,
                predecessor_version_id=None,
            ),
        )

    @classmethod
    def without_published(
        cls,
        *,
        proxy_token: str,
        session_id: str,
        stable_identity: StableBlockIdentity | None,
        provenance: BlockHandleProvenance,
        generation: int,
    ) -> LogicalBlockProxy:
        synthetic_provenance = {
            BlockHandleProvenance.CREATED_SYNTHETIC,
            BlockHandleProvenance.OBSERVED_EPHEMERAL,
        }
        if provenance in synthetic_provenance and stable_identity is not None:
            raise ValueError("synthetic logical proxy cannot claim stable identity")
        if provenance not in synthetic_provenance and stable_identity is None:
            raise ValueError("native logical proxy requires stable identity")
        return cls(
            proxy_token=proxy_token,
            session_id=session_id,
            stable_identity=stable_identity,
            provenance=provenance,
            generation=generation,
            published=None,
        )

    @property
    def proxy_token(self) -> str:
        return self._proxy_token

    @property
    def stable_identity(self) -> StableBlockIdentity | None:
        return self._stable_identity

    @property
    def generation(self) -> int:
        return self._generation

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

    def resolve(
        self,
        *,
        transaction_id: str | None = None,
    ) -> LogicalBlockVersion | None:
        if transaction_id is not None:
            transaction_id = str(transaction_id)
            if transaction_id in self._retirements:
                return None
            staged = self._staged.get(transaction_id)
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
        if transaction_id in self._retirements:
            raise LogicalBlockStageConflict(
                f"transaction {transaction_id!r} already retired this logical block"
            )
        if generation <= self.generation:
            raise ValueError(
                "staged logical block generation must be newer than published generation"
            )
        if handle.session_id != self._session_id:
            raise ValueError("logical block session cannot drift between versions")
        if handle.stable_identity != self._stable_identity:
            raise ValueError(
                "logical block stable identity cannot drift between versions"
            )
        if handle.provenance is not self._provenance:
            raise ValueError("logical block provenance cannot drift between versions")
        staged = LogicalBlockVersion(
            version_id=LogicalBlockVersionId(
                proxy_token=self._proxy_token,
                version=self._next_version,
            ),
            handle=handle,
            generation=generation,
            predecessor_version_id=(
                None if self._published is None else self._published.version_id
            ),
        )
        self._next_version += 1
        self._staged[transaction_id] = staged
        self._states[staged.version_id] = LogicalBlockVersionState.STAGED
        return staged

    def stage_retirement(self, *, transaction_id: str, generation: int) -> None:
        transaction_id = str(transaction_id)
        generation = int(generation)
        if not transaction_id:
            raise ValueError("logical block retirement requires a transaction id")
        if self._published is None:
            raise LogicalBlockStageConflict(
                "cannot retire an unpublished logical block"
            )
        if transaction_id in self._staged or transaction_id in self._retirements:
            raise LogicalBlockStageConflict(
                f"transaction {transaction_id!r} already staged this logical block"
            )
        if generation <= self.generation:
            raise ValueError(
                "staged logical block generation must be newer than published generation"
            )
        self._retirements[transaction_id] = generation

    def commit(self, transaction_id: str) -> LogicalBlockVersionTransition:
        transaction_id = str(transaction_id)
        retirement_generation = self._retirements.get(transaction_id)
        if retirement_generation is not None:
            published = self._published
            if published is None:
                raise LogicalBlockStageConflict(
                    "retired logical block no longer has a published predecessor"
                )
            self._retirements.pop(transaction_id)
            self._states[published.version_id] = LogicalBlockVersionState.RETIRED
            self._retired.append(published)
            self._published = None
            self._generation = retirement_generation
            return LogicalBlockVersionTransition(
                transaction_id=transaction_id,
                retired_version=published,
                promoted_version=None,
            )
        try:
            staged = self._staged[transaction_id]
        except KeyError as exc:
            raise LogicalBlockStageConflict(
                f"transaction {transaction_id!r} has no staged logical block"
            ) from exc
        published = self._published
        published_version_id = None if published is None else published.version_id
        if staged.predecessor_version_id != published_version_id:
            raise LogicalBlockStageConflict(
                "staged logical block no longer has the published predecessor"
            )
        self._staged.pop(transaction_id)
        if published is not None:
            self._states[published.version_id] = LogicalBlockVersionState.RETIRED
            self._retired.append(published)
        self._published = staged
        self._generation = staged.generation
        self._states[staged.version_id] = LogicalBlockVersionState.PUBLISHED
        if published is not None:
            self._lineage.append((published.version_id, staged.version_id))
        return LogicalBlockVersionTransition(
            transaction_id=transaction_id,
            retired_version=published,
            promoted_version=staged,
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

    def abort_retirement(self, transaction_id: str) -> LogicalBlockVersion:
        transaction_id = str(transaction_id)
        if transaction_id not in self._retirements:
            raise LogicalBlockStageConflict(
                f"transaction {transaction_id!r} has no staged retirement"
            )
        self._retirements.pop(transaction_id)
        published = self._published
        if published is None:
            raise LogicalBlockStageConflict(
                "aborted retirement has no published logical block"
            )
        return published

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
