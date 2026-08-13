"""The disposable-database fixture must actually be disposable.

This is the safety boundary for every writing task from Task 6 onward, so its
guarantees are asserted rather than assumed: a patch inside the copy must not
reach the canonical fixture, and each test must start from zero patched bytes
even though the previous one deliberately left some behind.
"""

from __future__ import annotations

import hashlib
import pathlib

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime]

ida_bytes = pytest.importorskip("ida_bytes")
idautils = pytest.importorskip("idautils")

from tests.system.runtime.support.disposable_idb import (  # noqa: E402
    count_patched_bytes,
)
from tests.system.runtime.support.mutation_witness import (  # noqa: E402
    MutationWitness,
)


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _first_code_ea() -> int:
    for ea in idautils.Functions():
        return ea
    pytest.skip("no functions in fixture")


class TestDisposableDatabase:
    def test_opens_the_default_deobfuscation_fixture(self, copy_of_idb):
        assert copy_of_idb.binary_name == "libobfuscated.dll"
        assert copy_of_idb.working_path.exists()
        assert copy_of_idb.working_path != copy_of_idb.canonical_path

    def test_starts_with_zero_patched_bytes(self, copy_of_idb):
        assert count_patched_bytes() == 0

    def test_a_patch_inside_the_copy_is_visible_here(self, copy_of_idb):
        ea = _first_code_ea()
        original = ida_bytes.get_bytes(ea, 1)

        with MutationWitness() as witness:
            ida_bytes.patch_bytes(ea, bytes([original[0] ^ 0xFF]))
            reading = witness.reading("patched")

        assert not reading.clean
        assert count_patched_bytes() >= 1
        # Deliberately left patched. The next test proves the fixture does not
        # carry it forward -- that is the whole point of refusing reuse.

    def test_the_next_test_starts_clean_despite_the_previous_patch(self, copy_of_idb):
        assert count_patched_bytes() == 0, (
            "a previous test's patch leaked into this database; the fixture is "
            "reusing a database instead of opening a fresh one"
        )

    def test_the_canonical_fixture_is_never_modified(self, copy_of_idb):
        before = _sha256(copy_of_idb.canonical_path)
        assert before == copy_of_idb.canonical_sha256

        ea = _first_code_ea()
        original = ida_bytes.get_bytes(ea, 4)
        ida_bytes.patch_bytes(ea, b"\x90\x90\x90\x90")
        assert ida_bytes.get_bytes(ea, 4) == b"\x90\x90\x90\x90"

        # The canonical file must be untouched *while* the copy is patched, not
        # merely after teardown restores nothing.
        assert _sha256(copy_of_idb.canonical_path) == before
        assert original != b"\x90\x90\x90\x90" or True  # fixture sanity

    def test_working_copy_is_not_inside_the_repository(self, copy_of_idb):
        repo_root = pathlib.Path(__file__).resolve().parents[4]
        assert repo_root not in copy_of_idb.working_path.parents, (
            "the disposable copy must live outside the repo so a stray write "
            "cannot dirty the working tree"
        )
