from tools.scripts.rhad_investigation.preopt_interior_entry import (
    PreoptImportedEntryOwner,
    PreoptInteriorEntryAbstentionReason,
    PreoptInteriorEntryCandidate,
    index_preopt_imported_entry_owners,
    plan_preopt_interior_entry_bridges,
)


def _candidate(
    *,
    instruction_count: int = 0,
    successor_count: int = 0,
    owners: tuple[PreoptImportedEntryOwner, ...] = (
        PreoptImportedEntryOwner(serial=500, predecessor_count=0),
    ),
) -> PreoptInteriorEntryCandidate:
    return PreoptInteriorEntryCandidate(
        native_entry_ea=0x40C6DA,
        placeholder_serial=523,
        placeholder_instruction_count=instruction_count,
        placeholder_successor_count=successor_count,
        imported_owners=owners,
    )


def test_plans_empty_placeholder_to_unique_orphaned_imported_owner() -> None:
    result = plan_preopt_interior_entry_bridges((_candidate(),))

    assert result.bridges == (
        result.bridges[0].__class__(
            native_entry_ea=0x40C6DA,
            placeholder_serial=523,
            imported_serial=500,
        ),
    )
    assert result.abstentions == ()


def test_abstains_when_imported_entry_has_multiple_owners() -> None:
    result = plan_preopt_interior_entry_bridges(
        (
            _candidate(
                owners=(
                    PreoptImportedEntryOwner(
                        serial=500,
                        predecessor_count=0,
                    ),
                    PreoptImportedEntryOwner(
                        serial=501,
                        predecessor_count=0,
                    ),
                )
            ),
        )
    )

    assert result.bridges == ()
    assert result.abstentions[0].reason is (
        PreoptInteriorEntryAbstentionReason.AMBIGUOUS_IMPORTED_OWNER
    )


def test_abstains_when_placeholder_contains_microcode() -> None:
    result = plan_preopt_interior_entry_bridges((_candidate(instruction_count=1),))

    assert result.bridges == ()
    assert result.abstentions[0].reason is (
        PreoptInteriorEntryAbstentionReason.NONEMPTY_PLACEHOLDER
    )


def test_abstains_when_placeholder_already_has_a_successor() -> None:
    result = plan_preopt_interior_entry_bridges((_candidate(successor_count=1),))

    assert result.bridges == ()
    assert result.abstentions[0].reason is (
        PreoptInteriorEntryAbstentionReason.NONTERMINAL_PLACEHOLDER
    )


def test_abstains_when_imported_entry_owner_is_missing() -> None:
    result = plan_preopt_interior_entry_bridges((_candidate(owners=()),))

    assert result.bridges == ()
    assert result.abstentions[0].reason is (
        PreoptInteriorEntryAbstentionReason.MISSING_IMPORTED_OWNER
    )


def test_abstains_when_imported_owner_is_already_connected() -> None:
    result = plan_preopt_interior_entry_bridges(
        (
            _candidate(
                owners=(
                    PreoptImportedEntryOwner(
                        serial=500,
                        predecessor_count=1,
                    ),
                )
            ),
        )
    )

    assert result.bridges == ()
    assert result.abstentions[0].reason is (
        PreoptInteriorEntryAbstentionReason.IMPORTED_OWNER_ALREADY_CONNECTED
    )


def test_indexes_imported_owner_when_native_entry_instruction_was_folded() -> None:
    result = index_preopt_imported_entry_owners(
        native_entry_by_instruction_ea={
            0x40C6DF: 0x40C6DA,
            0x40C6E5: 0x40C6DA,
        },
        native_origins_by_imported_serial={
            500: (0x40C6DF, 0x40C6E5),
        },
        predecessor_count_by_imported_serial={500: 0},
    )

    assert result.owners_by_native_entry == (
        (
            0x40C6DA,
            (
                PreoptImportedEntryOwner(
                    serial=500,
                    predecessor_count=0,
                ),
            ),
        ),
    )
    assert result.ambiguous_serials == ()


def test_imported_owner_index_reports_cross_entry_ambiguity() -> None:
    result = index_preopt_imported_entry_owners(
        native_entry_by_instruction_ea={
            0x401010: 0x401000,
            0x402010: 0x402000,
        },
        native_origins_by_imported_serial={
            17: (0x401010, 0x402010),
        },
        predecessor_count_by_imported_serial={17: 0},
    )

    assert result.owners_by_native_entry == ()
    assert result.ambiguous_serials == (17,)
