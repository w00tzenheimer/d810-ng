import pytest

from d810.hexrays.preanalysis.relative_dword_jump_tables import (
    NativeRegisterBlock,
    _record_r15_effect,
    _is_r15_destination,
    _validated_switch_table_count,
    prove_register_constants_at_sites,
    reaching_register_writes,
)


def _block(start, end, successors=(), writes=()):
    return NativeRegisterBlock(start, end, tuple(successors), tuple(writes))


def test_only_rendered_r15_family_operands_are_r15_destinations():
    assert _is_r15_destination("r15")
    assert _is_r15_destination("r15d")
    assert _is_r15_destination("r15w")
    assert _is_r15_destination("r15b")
    assert not _is_r15_destination("r10")
    assert not _is_r15_destination("rcx")


def test_switch_metadata_supplies_exact_zero_based_table_domain():
    assert (
        _validated_switch_table_count(
            expected_table_ea=0x5000,
            switch_table_ea=0x5000,
            table_count=9,
            element_size=4,
            lowcase=0,
            sparse=False,
            indirect=False,
        )
        == 9
    )


def test_switch_metadata_rejects_unproved_or_incompatible_domains():
    common = {
        "expected_table_ea": 0x5000,
        "switch_table_ea": 0x5000,
        "table_count": 9,
        "element_size": 4,
        "lowcase": 0,
        "sparse": False,
        "indirect": False,
    }
    for changed in (
        {"switch_table_ea": 0x6000},
        {"table_count": 1},
        {"table_count": 257},
        {"element_size": 8},
        {"lowcase": 1},
        {"sparse": True},
        {"indirect": True},
    ):
        assert _validated_switch_table_count(**(common | changed)) is None


def test_unclobbered_local_register_save_restore_preserves_r15_value():
    writes = [(0x1000, 0x5000)]
    saves = {}

    _record_r15_effect(
        writes,
        saves,
        ea=0x1004,
        mnemonic="mov",
        destination="rsi",
        source="r15",
        changed_operands=("rsi",),
        changed_r15=False,
        value=None,
    )
    _record_r15_effect(
        writes,
        saves,
        ea=0x1008,
        mnemonic="not",
        destination="r15",
        source="",
        changed_operands=("r15",),
        changed_r15=True,
        value=None,
    )
    _record_r15_effect(
        writes,
        saves,
        ea=0x100C,
        mnemonic="mov",
        destination="r15",
        source="rsi",
        changed_operands=("r15",),
        changed_r15=True,
        value=None,
    )

    assert writes == [(0x1000, 0x5000)]


def test_clobbered_save_register_does_not_preserve_r15_value():
    writes = [(0x1000, 0x5000)]
    saves = {}

    _record_r15_effect(
        writes,
        saves,
        ea=0x1004,
        mnemonic="mov",
        destination="rsi",
        source="r15",
        changed_operands=("rsi",),
        changed_r15=False,
        value=None,
    )
    _record_r15_effect(
        writes,
        saves,
        ea=0x1008,
        mnemonic="xor",
        destination="rsi",
        source="rax",
        changed_operands=("rsi",),
        changed_r15=False,
        value=None,
    )
    _record_r15_effect(
        writes,
        saves,
        ea=0x100C,
        mnemonic="mov",
        destination="r15",
        source="rsi",
        changed_operands=("r15",),
        changed_r15=True,
        value=None,
    )

    assert writes[-1] == (0x100C, None)


@pytest.mark.parametrize(
    ("save_register", "clobber_alias"),
    (
        ("rsi", "esi"),
        ("rsi", "si"),
        ("rsi", "sil"),
        ("r8", "r8d"),
        ("r8", "r8w"),
        ("r8", "r8b"),
    ),
)
def test_partial_register_clobber_invalidates_saved_r15(
    save_register, clobber_alias
):
    writes = [(0x1000, 0x5000)]
    saves = {}

    _record_r15_effect(
        writes,
        saves,
        ea=0x1004,
        mnemonic="mov",
        destination=save_register,
        source="r15",
        changed_operands=(save_register,),
        changed_r15=False,
        value=None,
    )
    _record_r15_effect(
        writes,
        saves,
        ea=0x1008,
        mnemonic="xor",
        destination=clobber_alias,
        source=clobber_alias,
        changed_operands=(clobber_alias,),
        changed_r15=False,
        value=None,
    )
    _record_r15_effect(
        writes,
        saves,
        ea=0x100C,
        mnemonic="mov",
        destination="r15",
        source=save_register,
        changed_operands=("r15",),
        changed_r15=True,
        value=None,
    )

    assert writes[-1] == (0x100C, None)


def test_disconnected_register_write_does_not_taint_reachable_site():
    blocks = (
        _block(0x1000, 0x1010, (0x1010,), ((0x1004, 0x5000),)),
        _block(0x1010, 0x1020),
        _block(0x2000, 0x2010, (0x1010,), ((0x2004, 0xDEAD),)),
    )

    assert prove_register_constants_at_sites(
        blocks, entry_ea=0x1000, site_eas=(0x1018,)
    ) == {0x1018: 0x5000}


def test_reachable_predecessor_disagreement_rejects_constant_proof():
    blocks = (
        _block(0x1000, 0x1010, (0x1010, 0x1020), ((0x1004, 0x5000),)),
        _block(0x1010, 0x1020, (0x1030,)),
        _block(0x1020, 0x1030, (0x1030,), ((0x1024, 0xDEAD),)),
        _block(0x1030, 0x1040),
    )

    assert prove_register_constants_at_sites(
        blocks, entry_ea=0x1000, site_eas=(0x1038,)
    ) == {0x1038: None}


def test_each_reachable_arm_may_restore_the_same_table_base():
    blocks = (
        _block(0x1000, 0x1010, (0x1010, 0x1020)),
        _block(0x1010, 0x1020, (0x1030,), ((0x1014, 0x5000),)),
        _block(0x1020, 0x1030, (0x1030,), ((0x1024, 0x5000),)),
        _block(0x1030, 0x1040),
    )

    assert prove_register_constants_at_sites(
        blocks, entry_ea=0x1000, site_eas=(0x1038,)
    ) == {0x1038: 0x5000}


def test_reaching_writes_report_each_predecessor_specific_definition():
    blocks = (
        _block(0x1000, 0x1010, (0x1010, 0x1020), ((0x1004, 0x5000),)),
        _block(0x1010, 0x1020, (0x1030,)),
        _block(0x1020, 0x1030, (0x1030,), ((0x1024, None),)),
        _block(0x1030, 0x1040),
    )

    assert reaching_register_writes(blocks, entry_ea=0x1000, site_ea=0x1038) == (
        (0x1004, 0x5000),
        (0x1024, None),
    )
