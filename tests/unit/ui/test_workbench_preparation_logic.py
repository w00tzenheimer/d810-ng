from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.manager.workbench_models import (
    PreparationScriptSummary,
    PreparationTransactionSummary,
    PreparationWorkbenchSummary,
    SnapshotFreshness,
)
from d810.ui.workbench_logic import preparation_action_states


pytestmark = pytest.mark.pure_python


def _summary(*, script_matches: bool = True, transaction=None):
    return PreparationWorkbenchSummary(
        database_identity="idb-a",
        scripts=(
            PreparationScriptSummary(
                script_id="normalize",
                display_name="Normalize",
                path="/tmp/normalize.py",
                configured_source_sha256="a" * 64,
                current_source_sha256=("a" * 64 if script_matches else "b" * 64),
                source_hash_matches=script_matches,
                enabled=True,
                portable=False,
            ),
        ),
        transactions=(() if transaction is None else (transaction,)),
    )


def _transaction(**changes):
    values = dict(
        transaction_id="tx-1",
        database_identity="idb-a",
        anchor_function_ea=0x401000,
        script_id="normalize",
        script_path="/tmp/normalize.py",
        script_source_sha256="a" * 64,
        state="idb_prepared",
        bytes_changed=1,
        byte_ranges=((0x401000, 0x401001),),
        type_annotations=0,
        affected_function_eas=(0x401000,),
        live_after_image=True,
        restore_allowed=True,
        restore_blocker="",
        recovery_required=False,
    )
    values.update(changes)
    return PreparationTransactionSummary(**values)


def _snapshot(summary):
    return SimpleNamespace(
        freshness=SnapshotFreshness.CURRENT,
        engine_started=True,
        preparation=summary,
    )


@pytest.mark.parametrize(
    ("transaction", "reason"),
    [
        (_transaction(database_identity="idb-b"), "database"),
        (_transaction(state="script_running", restore_allowed=False), "running"),
        (
            _transaction(live_after_image=False, restore_allowed=False),
            "after-image",
        ),
        (
            _transaction(restore_allowed=False, restore_blocker="interference"),
            "interference",
        ),
    ],
)
def test_restore_is_disabled_for_unsafe_transaction(transaction, reason) -> None:
    states = {
        item.action_id: item
        for item in preparation_action_states(
            _snapshot(_summary(transaction=transaction)),
            selected_transaction_id="tx-1",
        )
    }

    assert not states["restore_preparation"].enabled
    assert reason in states["restore_preparation"].reason.casefold()


def test_prepare_actions_are_disabled_when_script_changed_after_preview() -> None:
    states = {
        item.action_id: item
        for item in preparation_action_states(_snapshot(_summary(script_matches=False)))
    }

    assert states["preview_preparation"].enabled
    assert not states["prepare_only"].enabled
    assert not states["prepare_and_decompile"].enabled
    assert "source" in states["prepare_only"].reason.casefold()
