from __future__ import annotations

from d810.core.maturity_labels import (
    EARLY_FACT_COLLECTION_MATURITIES,
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
