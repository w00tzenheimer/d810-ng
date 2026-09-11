"""Bounded reuse of immutable Python bytecode analysis, never binding values.

Opt in with D810_CODE_ANALYSIS_CACHE=1 in a fresh process. The default strict
path performs the identical immediate analysis on every request. Neither path
traverses nested code: that remains the consumer's semantic decision.
"""

from __future__ import annotations

import dis
import os
from collections import OrderedDict
from threading import RLock
from types import CodeType


CACHE_ENABLED = os.environ.get("D810_CODE_ANALYSIS_CACHE", "0") == "1"


class CodeAnalysisCache:
    """Identity-keyed LRU retaining code objects until eviction or clear.

    A single lock includes miss analysis, so concurrent calls cannot publish
    partial results or duplicate disassembly. Only successful results enter
    the cache. Counters include failed/strict instruction visits as well.
    """

    def __init__(self, capacity: int = 1024):
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self._entries: OrderedDict[int, tuple[CodeType, tuple[str, ...]]] = (
            OrderedDict()
        )
        self._lock = RLock()
        self.clear()

    def clear(self) -> None:
        """Release retained code and reset experiment counters atomically."""
        with self._lock:
            self._entries.clear()
            self.hits = self.misses = self.strict = 0
            self.instructions = self.failures = self.evictions = 0

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(
                hits=self.hits,
                misses=self.misses,
                strict=self.strict,
                instructions=self.instructions,
                failures=self.failures,
                evictions=self.evictions,
                entries=len(self._entries),
            )

    def loaded_names(self, code: object, *, reuse: bool = True) -> tuple[str, ...]:
        # dis also accepts mutable function objects and source strings. Preserve
        # that decoder compatibility, but retain only actual immutable code.
        reuse = reuse and type(code) is CodeType
        with self._lock:
            key = id(code)
            if reuse:
                entry = self._entries.get(key)
                if entry is not None and entry[0] is code:
                    self._entries.move_to_end(key)
                    self.hits += 1
                    return entry[1]
                self.misses += 1
            else:
                self.strict += 1
            names: set[str] = set()
            try:
                for instruction in dis.get_instructions(code):
                    self.instructions += 1
                    if instruction.opname in {
                        "LOAD_GLOBAL",
                        "LOAD_NAME",
                    } and isinstance(instruction.argval, str):
                        names.add(instruction.argval)
            except Exception:
                self.failures += 1
                raise
            result = tuple(sorted(names))
            if reuse:
                self._entries[key] = (code, result)
                if len(self._entries) > self.capacity:
                    self._entries.popitem(last=False)
                    self.evictions += 1
            return result


code_analysis_cache = CodeAnalysisCache()


def immediate_loaded_names(code: object) -> tuple[str, ...]:
    return code_analysis_cache.loaded_names(code, reuse=CACHE_ENABLED)
