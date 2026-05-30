"""Unit cover for portable arithmetic/store instruction kinds."""

from __future__ import annotations

from d810.ir.flowgraph import InsnKind


class TestSubStoreKinds:
    def test_members_exist(self) -> None:
        assert hasattr(InsnKind, "SUB")
        assert hasattr(InsnKind, "STORE")

    def test_values_are_stable_strings(self) -> None:
        assert InsnKind.SUB.value == "sub"
        assert InsnKind.STORE.value == "store"

    def test_kinds_are_distinct_from_related_existing_kinds(self) -> None:
        distinct = {
            InsnKind.SUB,
            InsnKind.ADD,
            InsnKind.STORE,
            InsnKind.LOAD,
            InsnKind.MOV,
        }
        assert len(distinct) == 5

    def test_kinds_are_not_unknown(self) -> None:
        assert InsnKind.SUB is not InsnKind.UNKNOWN
        assert InsnKind.STORE is not InsnKind.UNKNOWN
