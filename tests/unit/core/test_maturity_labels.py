from __future__ import annotations

from d810.core.maturity_labels import (
    EARLY_FACT_COLLECTION_MATURITIES,
    IDA_MMAT_GLBOPT1,
    WITH_ZERO_MMAT_CALLS,
    WITH_ZERO_MMAT_GLBOPT1,
    WITH_ZERO_MMAT_GLBOPT2,
    LOCAL_FACT_COLLECTION_MATURITIES,
    MaturityNumbering,
    is_glbopt1_post_d810,
    maturity_phase_rank,
    mmat_label,
    mmat_name,
    mmat_rank,
    mmat_value,
)


def test_ida_and_with_zero_numbering_are_distinct() -> None:
    assert mmat_name(4, numbering=MaturityNumbering.IDA) == "MMAT_GLBOPT1"
    assert mmat_name(5, numbering=MaturityNumbering.WITH_ZERO) == "MMAT_GLBOPT1"
    assert mmat_label(0, numbering=MaturityNumbering.WITH_ZERO) == "maturity=MMAT_ZERO"


def test_symbolic_maturity_values_accept_short_and_full_names() -> None:
    assert mmat_value("GLBOPT1", numbering=MaturityNumbering.IDA) == 4
    assert mmat_value("MMAT_GLBOPT1", numbering=MaturityNumbering.WITH_ZERO) == 5
    assert mmat_value("MMAT_14", numbering=MaturityNumbering.IDA) == 14
    assert mmat_rank("unknown", numbering=MaturityNumbering.IDA, default=77) == 77


def test_fact_collection_sets_use_with_zero_values() -> None:
    assert EARLY_FACT_COLLECTION_MATURITIES == frozenset({2, 3, 4, 5})
    assert LOCAL_FACT_COLLECTION_MATURITIES == frozenset({2, 3})


def test_timeline_phase_rank_is_centralized() -> None:
    assert maturity_phase_rank("MMAT_LOCOPT", "pre_d810") == 0
    assert maturity_phase_rank("GLBOPT1", "post_d810") == 8
    assert is_glbopt1_post_d810("MMAT_GLBOPT1", "post_d810")
    assert not is_glbopt1_post_d810("MMAT_GLBOPT1", "pre_d810")


# ---------------------------------------------------------------------------
# Live snapshot maturity (ticket d81-4ulv)
# ---------------------------------------------------------------------------


def test_live_snapshot_maturity_uses_the_maturity_the_mba_is_at():
    from d810.core.maturity_labels import live_snapshot_maturity

    # The post_apply snapshot used to hard-code MMAT_GLBOPT1 while the
    # pipeline that writes it fires at a later boundary.  The default
    # numbering is WITH_ZERO because that is what ida_hexrays.MMAT_* uses.
    assert live_snapshot_maturity(WITH_ZERO_MMAT_GLBOPT2) == "MMAT_GLBOPT2"
    assert live_snapshot_maturity(WITH_ZERO_MMAT_GLBOPT1) == "MMAT_GLBOPT1"
    assert live_snapshot_maturity(WITH_ZERO_MMAT_CALLS) == "MMAT_CALLS"


def test_live_snapshot_maturity_ida_numbering_is_opt_in():
    from d810.core.maturity_labels import live_snapshot_maturity

    assert (
        live_snapshot_maturity(IDA_MMAT_GLBOPT1, numbering=MaturityNumbering.IDA)
        == "MMAT_GLBOPT1"
    )
    # Same integer, different numbering: this is exactly the off-by-one that
    # mislabelled a GLBOPT1 snapshot.
    assert live_snapshot_maturity(IDA_MMAT_GLBOPT1) == "MMAT_CALLS"


def test_live_snapshot_maturity_accepts_a_name():
    from d810.core.maturity_labels import live_snapshot_maturity

    assert live_snapshot_maturity("MMAT_GLBOPT2") == "MMAT_GLBOPT2"
    assert live_snapshot_maturity("glbopt2") == "MMAT_GLBOPT2"


def test_live_snapshot_maturity_falls_back_when_unreadable():
    from d810.core.maturity_labels import live_snapshot_maturity

    assert live_snapshot_maturity(None) == "MMAT_GLBOPT1"
    assert live_snapshot_maturity(object()) == "MMAT_GLBOPT1"
    assert live_snapshot_maturity(None, fallback="MMAT_CALLS") == "MMAT_CALLS"


def test_live_snapshot_maturity_keeps_an_out_of_range_value_visible():
    from d810.core.maturity_labels import live_snapshot_maturity

    assert live_snapshot_maturity(99) == "MMAT_99"
