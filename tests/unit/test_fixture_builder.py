"""Unit tests for the pure-Python fixture-builder logic (ticket d81-rtfh).

No IDA imports — everything here is testable without an IDA runtime. The
IDA-bound extract/resolve worker is covered by
``tests/system/e2e/test_fixture_idb_worker.py``.
"""
from pathlib import Path

from d810.samples.fixture_builder import CallSiteFold, detect_indirect_call_folds

REPO = Path(__file__).resolve().parents[2]
SUB = (REPO / "samples/src/masm/sub_1815C8C30.asm").read_text()


def test_detects_slot_const_and_reg_from_committed_asm():
    folds = detect_indirect_call_folds(SUB)
    assert CallSiteFold(
        slot_symbol="off_18210A360",
        const=0x64E2C558D421136,
        call_reg="rax",
        materialized=None,  # committed slot is a reloc expr, not a raw dq
    ) in folds


def test_reads_materialized_value_on_fresh_extract():
    fresh = (
        "CONST SEGMENT\n"
        "off_ABC dq 0DEADBEEFCAFE0000h\n"
        "CONST ENDS\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "f:\n"
        "    mov rax, qword ptr [off_ABC]\n"
        "    mov rcx, 10h\n"
        "    add rax, rcx\n"
        "    call rax\n"
        "_TEXT ENDS\nEND\n"
    )
    (fold,) = detect_indirect_call_folds(fresh)
    assert fold.slot_symbol == "off_ABC"
    assert fold.const == 0x10
    assert fold.materialized == 0xDEADBEEFCAFE0000
