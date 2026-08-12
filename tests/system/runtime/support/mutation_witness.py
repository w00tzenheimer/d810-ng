"""Positive evidence that a code path did not mutate the database.

Task 0.2 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md``. Section 17.2 requires every
abstention path, preflight-only case and read-only capture to be *asserted*
non-mutating rather than assumed, and Task 6's "verify zero IDB changes" checkbox
is unenforceable without a standing mechanism.

Three signals, because no one of them is sufficient:

* **Image digest** -- SHA-256 over every segment's bounds and contents. Catches a
  byte that changed and stayed changed. Blind to a patch that is reverted inside
  one interval, and blind to everything that is not a byte.
* **IDB event counters** -- ``ida_idp.IDB_Hooks``. Catches patch-then-revert,
  which the digest cannot see, and catches the metadata mutations that never
  touch a byte at all. Blind to anything that happened before the hooks were
  installed.
* **Ctree comment counter** -- ``ida_hexrays.Hexrays_Hooks``. Decompiler-level
  comments never reach ``IDB_Hooks``.

The metadata half is not padding. At the pinned baseline both flowchart-seam
consumers mutate, but only one writes bytes: indirect-label materialization
undefines items, creates instructions, adds crefs, installs ``switch_info_t`` and
creates functions without patching a single byte. A byte-only witness would call
that handler perfectly clean while it rewrote the item map underneath a function
some certificate claims is frozen.

Usage::

    with MutationWitness() as witness:
        do_the_thing_that_should_not_mutate()
        witness.assert_clean("after the thing")
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field

import ida_bytes
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_segment

__all__ = ["MutationWitness", "WitnessReading", "image_digest"]


def image_digest() -> bytes:
    """SHA-256 over every segment's bounds and contents.

    Bounds are included so that creating or resizing a segment registers even
    when no byte inside an existing segment changed.
    """
    digest = hashlib.sha256()
    segment_ea = ida_segment.get_first_segment_ea()
    while segment_ea != ida_idaapi.BADADDR:
        # getseg() is deprecated in 9.4 in favour of get_segment_info(), which
        # takes a different signature and does not exist in 9.1/9.3. Section
        # 17.4 requires those versions, so the deprecation warning is the
        # cheaper cost than a version-conditional branch here.
        segment = ida_segment.getseg(segment_ea)
        if segment is None:
            break
        digest.update(int(segment.start_ea).to_bytes(8, "little"))
        digest.update(int(segment.end_ea).to_bytes(8, "little"))
        contents = ida_bytes.get_bytes(
            segment.start_ea, int(segment.end_ea - segment.start_ea)
        )
        if contents is not None:
            digest.update(contents)
        segment_ea = ida_segment.get_next_segment_ea(segment.start_ea)
    return digest.digest()


@dataclass(frozen=True, slots=True)
class WitnessReading:
    label: str
    digest_matches: bool
    counts: Mapping[str, int] = field(default_factory=dict)

    @property
    def event_total(self) -> int:
        return sum(self.counts.values())

    @property
    def clean(self) -> bool:
        return self.digest_matches and self.event_total == 0

    def describe(self) -> str:
        fired = {name: n for name, n in self.counts.items() if n}
        return (
            f"{self.label}: digest={'same' if self.digest_matches else 'CHANGED'} "
            f"events={fired or 'none'}"
        )


class _IdbCounter(ida_idp.IDB_Hooks):
    """Counts the database events a native normalization could plausibly cause.

    Byte writes are only one row here. The item and function rows are what catch
    a handler that reshapes the database without patching anything.
    """

    def __init__(self, counts: dict[str, int]):
        super().__init__()
        self._counts = counts

    def _bump(self, key: str) -> int:
        self._counts[key] = self._counts.get(key, 0) + 1
        return 0

    # bytes
    def byte_patched(self, ea, old_value):
        return self._bump("byte_patched")

    # comments
    def cmt_changed(self, ea, repeatable_cmt):
        return self._bump("cmt_changed")

    def range_cmt_changed(self, kind, a, cmt, repeatable):
        return self._bump("range_cmt_changed")

    # item map
    def make_code(self, insn):
        return self._bump("make_code")

    def make_data(self, ea, flags, tid, length):
        return self._bump("make_data")

    # function boundaries and ownership
    def func_added(self, pfn):
        return self._bump("func_added")

    def deleting_func(self, pfn):
        return self._bump("deleting_func")

    def set_func_start(self, pfn, new_start):
        return self._bump("set_func_start")

    def set_func_end(self, pfn, new_end):
        return self._bump("set_func_end")

    def func_tail_appended(self, pfn, tail):
        return self._bump("func_tail_appended")

    def func_tail_deleted(self, pfn, tail_ea):
        return self._bump("func_tail_deleted")

    # names
    def renamed(self, ea, new_name, local_name, old_name):
        return self._bump("renamed")


class _CtreeCounter(ida_hexrays.Hexrays_Hooks):
    """Decompiler-level comments never reach IDB_Hooks."""

    def __init__(self, counts: dict[str, int]):
        super().__init__()
        self._counts = counts

    def cmt_changed(self, cfunc, location, cmt):
        self._counts["ctree_cmt_changed"] = self._counts.get("ctree_cmt_changed", 0) + 1
        return 0


class MutationWitness:
    """Baseline the database, then assert nothing changed.

    Hooks are installed *before* the baseline digest is taken, so no mutation can
    slip between the two.
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._idb = _IdbCounter(self._counts)
        self._ctree = _CtreeCounter(self._counts)
        self._baseline: bytes | None = None
        self._active = False

    def start(self) -> MutationWitness:
        self._idb.hook()
        self._ctree.hook()
        self._active = True
        self._counts.clear()
        self._baseline = image_digest()
        return self

    def stop(self) -> None:
        if not self._active:
            return
        self._idb.unhook()
        self._ctree.unhook()
        self._active = False

    def __enter__(self) -> MutationWitness:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    def reading(self, label: str = "") -> WitnessReading:
        if self._baseline is None:
            raise RuntimeError("MutationWitness.start() was never called")
        return WitnessReading(
            label=label,
            digest_matches=image_digest() == self._baseline,
            counts=dict(self._counts),
        )

    def assert_clean(self, label: str = "") -> WitnessReading:
        result = self.reading(label)
        assert result.clean, f"expected no database mutation -- {result.describe()}"
        return result

    def rebaseline(self) -> None:
        """Accept the current state as the new baseline and reset counters.

        For a test with an intentional mutation in the middle: assert clean
        around the read-only phase, rebaseline, then assert clean again.
        """
        self._counts.clear()
        self._baseline = image_digest()
