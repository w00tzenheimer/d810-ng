"""Versioned logical block authority contract."""

from __future__ import annotations

from dataclasses import fields

import pytest

from d810.hexrays.ir.logical_block_proxy import (
    LogicalBlockProxy,
    LogicalBlockStageConflict,
    LogicalBlockVersion,
    LogicalBlockVersionId,
    LogicalBlockVersionState,
)
from d810.ir.block_identity import (
    BlockHandleProvenance,
    MbaBlockHandle,
    NativeEaInterval,
    StableBlockIdentity,
)
from tests.native_preanalysis import make_native_key


NATIVE_KEY = make_native_key()


def _identity() -> StableBlockIdentity:
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D348, 0x40D349),),
        native_key=NATIVE_KEY,
    )


def _handle(token: str) -> MbaBlockHandle:
    return MbaBlockHandle.native(
        _identity(),
        session_id="proxy-session",
        token=token,
    )


def test_version_identity_contains_no_mba_serial_coordinate() -> None:
    assert [field.name for field in fields(LogicalBlockVersionId)] == [
        "proxy_token",
        "version",
    ]
    assert "serial" not in {field.name for field in fields(LogicalBlockVersion)}


def test_resolution_is_published_normally_and_staged_only_for_owner() -> None:
    proxy = LogicalBlockProxy.with_published(
        proxy_token="logical:bootstrap",
        handle=_handle("physical:v0"),
        generation=3,
    )
    published = proxy.resolve()

    staged = proxy.stage(
        transaction_id="tx-owner",
        handle=_handle("physical:v1"),
        generation=4,
    )

    assert proxy.resolve() is published
    assert proxy.resolve(transaction_id="tx-owner") is staged
    assert proxy.resolve(transaction_id="tx-observer") is published
    assert proxy.state_of(published.version_id) is LogicalBlockVersionState.PUBLISHED
    assert proxy.state_of(staged.version_id) is LogicalBlockVersionState.STAGED


def test_commit_promotes_stage_retires_published_and_records_lineage() -> None:
    proxy = LogicalBlockProxy.with_published(
        proxy_token="logical:bootstrap",
        handle=_handle("physical:v0"),
        generation=3,
    )
    original = proxy.resolve()
    staged = proxy.stage(
        transaction_id="tx-commit",
        handle=_handle("physical:v1"),
        generation=4,
    )

    transition = proxy.commit("tx-commit")

    assert transition.transaction_id == "tx-commit"
    assert transition.retired_version is original
    assert transition.promoted_version is staged
    assert proxy.resolve() is staged
    assert proxy.generation == 4
    assert proxy.retired_versions == (original,)
    assert proxy.state_of(original.version_id) is LogicalBlockVersionState.RETIRED
    assert proxy.state_of(staged.version_id) is LogicalBlockVersionState.PUBLISHED
    assert staged.predecessor_version_id == original.version_id
    assert proxy.replacement_lineage == ((original.version_id, staged.version_id),)


def test_abort_discards_stage_without_changing_published_authority() -> None:
    proxy = LogicalBlockProxy.with_published(
        proxy_token="logical:bootstrap",
        handle=_handle("physical:v0"),
        generation=3,
    )
    published = proxy.resolve()
    staged = proxy.stage(
        transaction_id="tx-abort",
        handle=_handle("physical:v1"),
        generation=4,
    )

    discarded = proxy.abort("tx-abort")

    assert discarded is staged
    assert proxy.resolve() is published
    assert proxy.generation == 3
    assert proxy.retired_versions == ()
    assert proxy.aborted_versions == (staged,)
    assert proxy.state_of(staged.version_id) is LogicalBlockVersionState.ABORTED


def test_aborted_version_number_is_not_reused() -> None:
    proxy = LogicalBlockProxy.with_published(
        proxy_token="logical:bootstrap",
        handle=_handle("physical:v0"),
        generation=3,
    )
    aborted = proxy.stage(
        transaction_id="tx-abort",
        handle=_handle("physical:v1"),
        generation=4,
    )
    proxy.abort("tx-abort")

    replacement = proxy.stage(
        transaction_id="tx-retry",
        handle=_handle("physical:v2"),
        generation=4,
    )

    assert replacement.version_id.version == aborted.version_id.version + 1


def test_commit_rejects_stage_based_on_a_retired_published_version() -> None:
    proxy = LogicalBlockProxy.with_published(
        proxy_token="logical:bootstrap",
        handle=_handle("physical:v0"),
        generation=3,
    )
    proxy.stage(
        transaction_id="tx-first",
        handle=_handle("physical:v1"),
        generation=4,
    )
    proxy.stage(
        transaction_id="tx-stale",
        handle=_handle("physical:v2"),
        generation=4,
    )
    proxy.commit("tx-first")

    with pytest.raises(LogicalBlockStageConflict, match="published predecessor"):
        proxy.commit("tx-stale")


def test_proxy_identity_and_provenance_cannot_drift_between_versions() -> None:
    proxy = LogicalBlockProxy.with_published(
        proxy_token="logical:bootstrap",
        handle=_handle("physical:v0"),
        generation=3,
    )
    foreign_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAA8),),
        native_key=NATIVE_KEY,
    )
    foreign = MbaBlockHandle.native(
        foreign_identity,
        session_id="proxy-session",
        token="physical:foreign",
    )
    imported = MbaBlockHandle.imported_native(
        _identity(),
        session_id="proxy-session",
        token="physical:imported",
    )

    with pytest.raises(ValueError, match="stable identity"):
        proxy.stage(
            transaction_id="tx-identity-drift",
            handle=foreign,
            generation=4,
        )
    with pytest.raises(ValueError, match="provenance"):
        proxy.stage(
            transaction_id="tx-provenance-drift",
            handle=imported,
            generation=4,
        )
    assert proxy.provenance is BlockHandleProvenance.NATIVE


def test_new_logical_block_is_unpublished_until_owning_transaction_commits() -> None:
    proxy = LogicalBlockProxy.without_published(
        proxy_token="logical:new-tail",
        session_id="proxy-session",
        stable_identity=None,
        provenance=BlockHandleProvenance.SYNTHETIC,
        generation=3,
    )
    staged = proxy.stage(
        transaction_id="tx-insert",
        handle=MbaBlockHandle.synthetic(
            session_id="proxy-session",
            token="physical:new-tail",
        ),
        generation=4,
    )

    assert proxy.resolve() is None
    assert proxy.resolve(transaction_id="tx-insert") is staged

    transition = proxy.commit("tx-insert")

    assert transition.retired_version is None
    assert transition.promoted_version is staged
    assert proxy.resolve() is staged
    assert proxy.generation == 4


def test_retirement_is_transaction_local_and_commit_has_no_promoted_version() -> None:
    proxy = LogicalBlockProxy.with_published(
        proxy_token="logical:dead-route",
        handle=_handle("physical:v0"),
        generation=3,
    )
    published = proxy.resolve()

    proxy.stage_retirement(transaction_id="tx-remove", generation=4)

    assert proxy.resolve() is published
    assert proxy.resolve(transaction_id="tx-remove") is None

    transition = proxy.commit("tx-remove")

    assert transition.retired_version is published
    assert transition.promoted_version is None
    assert proxy.resolve() is None
    assert proxy.generation == 4
    assert proxy.state_of(published.version_id) is LogicalBlockVersionState.RETIRED


def test_aborted_retirement_preserves_published_version() -> None:
    proxy = LogicalBlockProxy.with_published(
        proxy_token="logical:live-route",
        handle=_handle("physical:v0"),
        generation=3,
    )
    published = proxy.resolve()
    proxy.stage_retirement(transaction_id="tx-remove", generation=4)

    assert proxy.abort_retirement("tx-remove") is published
    assert proxy.resolve() is published
    assert proxy.generation == 3
