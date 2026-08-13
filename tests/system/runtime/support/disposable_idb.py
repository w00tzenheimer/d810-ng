"""A disposable database for tests that are allowed to write bytes.

Task 6 is the first task permitted to mutate an IDB. Every writing test from
here on runs against this fixture, which is the safety boundary between "a test
patched a throwaway copy" and "a test patched something that matters".

The existing ``ida_database`` fixture in ``tests/system/conftest.py`` already
copies the binary to a temp directory and closes without saving, and that much
is reused in spirit here. It is not sufficient for writers for three reasons,
each of which this module closes:

* **It can reuse an already-open database.** ``ida_database`` yields without
  reopening when a database matching the binary name is already loaded. For a
  read-only test that is a harmless optimisation. For a writer it means one
  test's patches leak into the next, and into any other class using the same
  binary -- and an apply/restore test would then validate against a
  contaminated database and still pass. ``libobfuscated.dll`` is the project
  default binary and is opened by many classes, so this is a live risk, not a
  theoretical one.
* **Nothing asserts the canonical fixture is untouched.** Section 17.2 of
  ``REVERSIBLE-NATIVE-PATCHES.md`` requires exactly that, and no test in the
  repository does it. It is the one check that catches a real escape.
* **``close_database(False)`` is enforced only by convention.** idalib writes
  patches through to the input file when passed ``True``; the codebase carries
  a "NEVER True" comment about it. A comment is not a check.

Compose with :class:`~tests.system.runtime.support.mutation_witness.MutationWitness`
to get both halves of the guarantee: this fixture proves the original was never
touched, the witness proves only what you authorised changed inside the copy.
"""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import tempfile
from dataclasses import dataclass

import ida_auto
import ida_bytes
import idaapi
import idapro
import pytest

__all__ = ["DisposableDatabase", "copy_of_idb", "count_patched_bytes"]

DEFAULT_BINARY = "libobfuscated.dll"

_SEARCH_DIRS = ("samples/bins", "tests/_resources/bin", "tests/system/bins")


@dataclass(frozen=True, slots=True)
class DisposableDatabase:
    """Identifies the throwaway database a writing test may mutate freely."""

    binary_name: str
    canonical_path: pathlib.Path
    working_path: pathlib.Path
    canonical_sha256: str

    @property
    def min_ea(self) -> int:
        return idaapi.inf_get_min_ea()

    @property
    def max_ea(self) -> int:
        return idaapi.inf_get_max_ea()


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_root() -> pathlib.Path:
    # tests/system/runtime/support/ -> repo root
    return pathlib.Path(__file__).resolve().parents[4]


def _locate(binary_name: str) -> pathlib.Path:
    root = _repo_root()
    for relative in _SEARCH_DIRS:
        candidate = root / relative / binary_name
        if candidate.exists():
            return candidate
    pytest.skip(f"test binary {binary_name!r} not found under {root}")


def count_patched_bytes() -> int:
    """How many patched bytes the current database already carries.

    A writing test must start from zero. A non-zero count means either a stale
    database was reused or a previous test failed to restore, and continuing
    would validate against contaminated state.
    """
    seen = 0

    def _visit(ea: int, fpos: int, original: int, value: int) -> int:
        nonlocal seen
        seen += 1
        return 0

    ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, _visit)
    return seen


@pytest.fixture
def copy_of_idb(request) -> DisposableDatabase:
    """Open a fresh, throwaway database that the test may patch.

    Binary selection: ``request.param``, else the class's ``binary_name``, else
    ``libobfuscated.dll`` -- the project default, and the fixture whose
    deobfuscated output is worth diffing across a native patch.
    """
    binary_name = (
        getattr(request, "param", None)
        or getattr(request.cls, "binary_name", None)
        or DEFAULT_BINARY
    )

    canonical = _locate(binary_name)
    canonical_hash_before = _sha256(canonical)

    # Refuse to inherit somebody else's database. Reusing one would silently
    # import its patches into this test; closing it would break the teardown of
    # whichever fixture opened it. Failing loudly is the only honest option.
    already_open = idaapi.get_root_filename()
    if already_open:
        pytest.fail(
            f"copy_of_idb requires a fresh database but {already_open!r} is "
            "already open. A writing test must not share a database with "
            "another fixture -- do not combine copy_of_idb with ida_database, "
            "and make sure the previous class tore its database down."
        )

    tempdir = pathlib.Path(tempfile.mkdtemp(prefix="d810-disposable-"))
    working = tempdir / canonical.name
    shutil.copy(canonical, working)

    result = idapro.open_database(str(working), True)
    if result != 0:
        shutil.rmtree(tempdir, ignore_errors=True)
        pytest.skip(f"failed to open {working}: {result}")

    try:
        ida_auto.auto_wait()

        pre_existing = count_patched_bytes()
        assert pre_existing == 0, (
            f"{binary_name} opened with {pre_existing} pre-existing patched "
            "bytes; a writing test cannot start from contaminated state"
        )

        yield DisposableDatabase(
            binary_name=binary_name,
            canonical_path=canonical,
            working_path=working,
            canonical_sha256=canonical_hash_before,
        )
    finally:
        # NEVER True. idalib writes patches through to the input file on save,
        # which would turn a throwaway copy into a modified binary on disk.
        idapro.close_database(False)
        shutil.rmtree(tempdir, ignore_errors=True)

        # Section 17.2's actual requirement, and the only assertion here that
        # catches a genuine escape rather than a bookkeeping slip.
        canonical_hash_after = _sha256(canonical)
        assert canonical_hash_after == canonical_hash_before, (
            f"the canonical fixture {canonical} was modified by this test "
            f"({canonical_hash_before} -> {canonical_hash_after}). A writing "
            "test escaped its disposable copy."
        )
