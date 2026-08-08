"""Cache of solved-and-proved rewrites, so neither cost lands on a decompile.

Why this exists
---------------
Solving and proving are both expensive and both were on the critical path.
Measured on VM_DecryptPacket: solving cost 11.52s across 60 candidates, and
proving 189.9s across the 14 that produced a usable rewrite -- 98% of that in
just 4 proofs.  Neither number is acceptable inside a live decompilation.

The table turns both into a dict lookup on every pass after the first.

Why the key is the tree and not the signature
---------------------------------------------
Signature-keying would give more reuse and is tempting, because CoBRA's answer
is a function of the signature.  It is **not sound** as a cache key: two
expressions sharing a signature are only interchangeable under the linear-MBA
class assumption, which needs ``bitwidth >= 2**n_leaves``.  At 32 bits that
caps out at 5 leaves while ``DEFAULT_MAX_LEAVES`` is 8, so the assumption is
routinely violated.  Keying on the tree is unconditionally sound and costs
little: reuse here is dominated by re-decompiling the same function, which
reproduces identical trees.

Leaf *names* are abstracted away, though.  ``prove_equivalent`` builds free
bitvectors for the leaves, so every proof is already universally quantified
over them -- leaf identity was never part of what was proved.  Aliasing still
matters and is preserved: ``a + a`` and ``a + b`` key differently.

No IDA dependency: this module handles plain dicts, so the off-path prover can
touch it from a worker thread without going anywhere near the Hex-Rays API.
"""

from __future__ import annotations

import dataclasses
import enum
import threading

from d810.core.cache import CacheImpl
from d810.core.typing import Any, Callable, Mapping

#: Cap on live entries. CacheImpl defaults to 256, which is far too small here:
#: a SINGLE function (VM_DecryptPacket) banked 207 entries, so 256 would evict
#: continuously across a whole binary and turn hits back into 84ms solves.
DEFAULT_MAX_ENTRIES = 8192


class Outcome(enum.Enum):
    """What is known about a candidate expression."""

    #: A strictly smaller, Z3-proved equivalent is available.
    PROVED = "proved"
    #: Nothing better exists, or nothing better survived acceptance.  Caching
    #: this is not an optimisation detail -- 46 of 60 measured candidates land
    #: here, and without it every one is re-solved on every pass.
    NO_REWRITE = "no_rewrite"
    #: Escalated to the off-path prover; ask again later.  Deliberately
    #: distinct from NO_REWRITE: collapsing the two would either re-solve
    #: escalated work forever or permanently suppress a rewrite that is about
    #: to be found.
    PENDING = "pending"


@dataclasses.dataclass(frozen=True)
class Entry:
    outcome: Outcome
    rewrite: dict | None = None


@dataclasses.dataclass
class TableStats:
    """Lookup accounting.

    Every lookup increments exactly one of the four terms, so
    ``hits + negative_hits + pending_hits + misses == lookups`` always holds.
    An invariant that counts needs a term for every legitimate outcome; a
    hit/miss pair alone would silently fold negatives into one of them.
    """

    lookups: int = 0
    hits: int = 0
    negative_hits: int = 0
    pending_hits: int = 0
    misses: int = 0

    @property
    def balanced(self) -> bool:
        return (
            self.hits + self.negative_hits + self.pending_hits + self.misses
        ) == self.lookups


def _canon(tree: Mapping[str, Any], names: dict[str, int]) -> tuple:
    kind = tree["kind"]
    if kind == "const":
        return ("c", tree["value"])
    if kind == "var":
        name = tree["name"]
        if name not in names:
            names[name] = len(names)
        return ("v", names[name])
    if kind == "un":
        return ("u", tree["op"], _canon(tree["a"], names))
    return ("b", tree["op"], _canon(tree["a"], names), _canon(tree["b"], names))


def canonical_key(tree: Mapping[str, Any], bitwidth: int) -> tuple:
    """Key a tree for the table.

    Leaves are numbered by first occurrence, so renaming does not change the
    key while aliasing still does.  Constants and operator identity are kept
    verbatim -- they change the function.  Bitwidth is part of the key because
    a proof at one width says nothing about another.
    """
    return _keyed(tree, bitwidth)[0]


def _keyed(tree: Mapping[str, Any], bitwidth: int) -> tuple[tuple, list[str]]:
    """Return ``(key, leaf_order)`` where ``leaf_order[i]`` got index ``i``."""
    names: dict[str, int] = {}
    key = (bitwidth, _canon(tree, names))
    order = [""] * len(names)
    for name, index in names.items():
        order[index] = name
    return key, order


def _to_positional(tree: Mapping[str, Any], names: dict[str, int]) -> dict:
    """Rewrite leaf names to ``@i`` placeholders using an existing numbering."""
    kind = tree["kind"]
    if kind == "const":
        return dict(tree)
    if kind == "var":
        return {"kind": "var", "name": f"@{names[tree['name']]}"}
    if kind == "un":
        return {"kind": "un", "op": tree["op"], "a": _to_positional(tree["a"], names)}
    return {
        "kind": "bin",
        "op": tree["op"],
        "a": _to_positional(tree["a"], names),
        "b": _to_positional(tree["b"], names),
    }


def _instantiate(tree: Mapping[str, Any], order: list[str]) -> dict:
    """Bind ``@i`` placeholders back to the querying expression's leaves."""
    kind = tree["kind"]
    if kind == "const":
        return dict(tree)
    if kind == "var":
        name = tree["name"]
        if name.startswith("@"):
            return {"kind": "var", "name": order[int(name[1:])]}
        return dict(tree)
    if kind == "un":
        return {"kind": "un", "op": tree["op"], "a": _instantiate(tree["a"], order)}
    return {
        "kind": "bin",
        "op": tree["op"],
        "a": _instantiate(tree["a"], order),
        "b": _instantiate(tree["b"], order),
    }


class RewriteTable:
    """In-memory rewrite cache with explicit negative and pending states."""

    def __init__(
        self,
        *,
        max_size: int = DEFAULT_MAX_ENTRIES,
        on_evict: Callable[[tuple, Entry], None] | None = None,
    ) -> None:
        # Storage, locking and eviction come from d810's own CacheImpl rather
        # than a hand-rolled dict. Two things that buys, both of which were
        # real defects here: a BOUNDED size (this table previously grew without
        # limit) and a removal_listener so eviction cannot silently drop work.
        self._on_evict = on_evict
        self._entries: CacheImpl = CacheImpl(
            max_size=max_size,
            removal_listener=self._on_removal,
        )
        self._lock = threading.Lock()
        self.stats = TableStats()

    def _on_removal(self, key, value) -> None:
        """FLUSH-BEFORE-EVICT.

        Deliberately not load-on-miss: a miss is the very thing this table
        exists to prevent. An evicted NO_REWRITE would return None, the rule
        would re-solve it (~84ms measured) and only then discover the durable
        store already held the answer. Writing on the way out keeps disk
        authoritative without ever paying a solve to find out.
        """
        if self._on_evict is None or value is None:
            return
        try:
            self._on_evict(key, value)
        except Exception:  # noqa: BLE001 - eviction must never break a lookup
            pass

    def set_evict_sink(self, sink: Callable[[tuple, Entry], None] | None) -> None:
        """Attach the durable store AFTER construction.

        Not a constructor argument on purpose: the table is a candidate for
        ``survives_reload``, whose shared-instance wrapper silently ignores
        constructor args on every call after the first. A setter keeps the
        wiring explicit and re-attachable.
        """
        self._on_evict = sink

    @property
    def size(self) -> int:
        return len(self._entries)

    def lookup(self, tree: Mapping[str, Any], bitwidth: int) -> Entry | None:
        """Look a tree up, returning any rewrite bound to *this* tree's leaves.

        The stored rewrite is positional (``@0``, ``@1``, ...), because the
        entry is shared by every alpha-equivalent expression.  Handing it back
        verbatim would return an expression over some earlier caller's
        variables -- silently wrong output, which is worse than a miss.
        """
        key, order = _keyed(tree, bitwidth)
        with self._lock:
            self.stats.lookups += 1
            entry = self._entries.get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            if entry.outcome is Outcome.PROVED:
                self.stats.hits += 1
            elif entry.outcome is Outcome.NO_REWRITE:
                self.stats.negative_hits += 1
            else:
                self.stats.pending_hits += 1
        if entry.outcome is Outcome.PROVED and entry.rewrite is not None:
            return Entry(Outcome.PROVED, _instantiate(entry.rewrite, order))
        return entry

    def record_proved(
        self, tree: Mapping[str, Any], bitwidth: int, rewrite: dict
    ) -> None:
        names: dict[str, int] = {}
        key = (bitwidth, _canon(tree, names))
        positional = _to_positional(rewrite, names)
        with self._lock:
            self._entries[key] = Entry(Outcome.PROVED, positional)

    def record_no_rewrite(self, tree: Mapping[str, Any], bitwidth: int) -> None:
        key = canonical_key(tree, bitwidth)
        with self._lock:
            self._entries[key] = Entry(Outcome.NO_REWRITE)

    def record_pending(self, tree: Mapping[str, Any], bitwidth: int) -> None:
        """Mark as escalated, without clobbering a result already known.

        The off-path prover and the live rule can reach the same key
        concurrently; a late PENDING must not erase a proof that landed first.
        """
        key = canonical_key(tree, bitwidth)
        with self._lock:
            existing = self._entries.get(key)
            if existing is not None and existing.outcome is not Outcome.PENDING:
                return
            self._entries[key] = Entry(Outcome.PENDING)

    def to_dict(self) -> dict:
        """Serialise settled results only.

        PENDING is in-flight state, not a result.  Persisting it would make a
        killed session look like it still had escalated work outstanding,
        permanently suppressing those candidates on every future run.
        """
        return {
            "version": 1,
            "entries": [
                {
                    "key": _key_to_json(key),
                    "outcome": entry.outcome.value,
                    "rewrite": entry.rewrite,
                }
                for key, entry in self._entries.items()
                if entry.outcome is not Outcome.PENDING
            ],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RewriteTable:
        table = cls()
        for raw in payload.get("entries", ()):
            outcome = Outcome(raw["outcome"])
            if outcome is Outcome.PENDING:
                continue
            table._entries[_key_from_json(raw["key"])] = Entry(
                outcome, raw.get("rewrite")
            )
        return table


def _key_to_json(key: tuple) -> Any:
    """Tuples do not survive JSON; lists do."""
    if isinstance(key, tuple):
        return [_key_to_json(part) for part in key]
    return key


def _key_from_json(raw: Any) -> Any:
    if isinstance(raw, list):
        return tuple(_key_from_json(part) for part in raw)
    return raw


__all__ = [
    "Entry",
    "Outcome",
    "RewriteTable",
    "TableStats",
    "canonical_key",
]
