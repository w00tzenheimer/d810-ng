"""The witness must be able to fail, or asserting with it proves nothing.

Task 0.2's checklist: prove the harness detects a deliberate byte patch, a
deliberate comment, and a patch-then-revert inside one interval -- and prove that
the last case defeats digest-only detection and is caught only by the counters.
"""

from __future__ import annotations

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
idaapi = pytest.importorskip("idaapi")

from tests.system.runtime.support.mutation_witness import (  # noqa: E402
    MutationWitness,
    image_digest,
)


def _some_code_ea() -> int:
    for ea in __import__("idautils").Functions():
        return ea
    pytest.skip("no functions in fixture")


class TestMutationWitness:
    binary_name = "fake_jumps.dll"

    def test_quiet_interval_is_clean(self, ida_database):
        with MutationWitness() as witness:
            # Reading the database must not register as mutation.
            ida_bytes.get_bytes(_some_code_ea(), 16)
            reading = witness.reading("quiet")

        assert reading.clean, reading.describe()
        assert reading.digest_matches
        assert reading.event_total == 0

    def test_byte_patch_is_detected(self, ida_database):
        ea = _some_code_ea()
        original = ida_bytes.get_bytes(ea, 1)
        with MutationWitness() as witness:
            ida_bytes.patch_bytes(ea, bytes([original[0] ^ 0xFF]))
            reading = witness.reading("patched")
        ida_bytes.patch_bytes(ea, original)

        assert not reading.clean
        assert not reading.digest_matches
        assert reading.counts.get("byte_patched", 0) >= 1

    def test_comment_is_detected(self, ida_database):
        ea = _some_code_ea()
        with MutationWitness() as witness:
            idaapi.set_cmt(ea, "witness self-test", False)
            reading = witness.reading("commented")
        idaapi.set_cmt(ea, "", False)

        assert not reading.clean
        assert reading.counts.get("cmt_changed", 0) >= 1

    def test_patch_then_revert_defeats_the_digest_but_not_the_counters(
        self, ida_database
    ):
        """The case that justifies carrying both signals.

        Bytes end where they started, so the digest is identical and a
        digest-only harness would report the interval clean. The counters saw
        both writes.
        """
        ea = _some_code_ea()
        original = ida_bytes.get_bytes(ea, 1)
        baseline = image_digest()

        with MutationWitness() as witness:
            ida_bytes.patch_bytes(ea, bytes([original[0] ^ 0xFF]))
            ida_bytes.patch_bytes(ea, original)
            reading = witness.reading("patch-then-revert")

        assert image_digest() == baseline, "bytes should be back where they started"
        assert reading.digest_matches, "digest alone cannot see this"
        assert reading.counts.get("byte_patched", 0) >= 2, (
            "counters must see both writes"
        )
        assert not reading.clean, (
            "the witness must fail this interval even though the digest matches"
        )

    def test_assert_clean_raises_on_mutation(self, ida_database):
        ea = _some_code_ea()
        original = ida_bytes.get_bytes(ea, 1)
        try:
            with MutationWitness() as witness:
                ida_bytes.patch_bytes(ea, bytes([original[0] ^ 0xFF]))
                with pytest.raises(AssertionError):
                    witness.assert_clean("should raise")
        finally:
            ida_bytes.patch_bytes(ea, original)

    def test_rebaseline_accepts_an_intentional_mutation(self, ida_database):
        ea = _some_code_ea()
        original = ida_bytes.get_bytes(ea, 1)
        with MutationWitness() as witness:
            ida_bytes.patch_bytes(ea, bytes([original[0] ^ 0xFF]))
            witness.rebaseline()
            after = witness.reading("post-rebaseline")

        ida_bytes.patch_bytes(ea, original)

        assert after.clean, after.describe()

    def test_metadata_mutation_without_a_byte_write_is_detected(self, ida_database):
        """The miss a byte-only witness makes.

        Indirect-label materialization reshapes items, crefs, switch metadata and
        function boundaries without patching bytes. Renaming stands in for that
        class here: no byte changes, so the digest is clean, and only the event
        counters notice.
        """
        ea = _some_code_ea()
        old_name = ida_funcs.get_func_name(ea)
        with MutationWitness() as witness:
            idaapi.set_name(ea, "witness_selftest_renamed", idaapi.SN_NOCHECK)
            reading = witness.reading("renamed")
        idaapi.set_name(ea, old_name or "", idaapi.SN_NOCHECK)

        assert reading.digest_matches, "a rename changes no segment bytes"
        assert reading.counts.get("renamed", 0) >= 1
        assert not reading.clean
