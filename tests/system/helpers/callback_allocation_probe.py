"""Measure a bounded number of callback allocation windows."""

import gc
import tracemalloc
from dataclasses import dataclass


@dataclass(frozen=True)
class AllocationSample:
    before: int
    retained: int
    peak: int


class BoundedAllocationProbe:
    def __init__(self, limit: int):
        self.limit = limit
        self.samples: list[AllocationSample] = []

    def measure(self, callback, *args, **kwargs):
        if len(self.samples) >= self.limit:
            return callback(*args, **kwargs)
        gc.collect()
        tracemalloc.start()
        try:
            before = tracemalloc.get_traced_memory()[0]
            try:
                return callback(*args, **kwargs)
            finally:
                gc.collect()
                current, peak = tracemalloc.get_traced_memory()
                self.samples.append(AllocationSample(before, current - before, peak))
        finally:
            tracemalloc.stop()
