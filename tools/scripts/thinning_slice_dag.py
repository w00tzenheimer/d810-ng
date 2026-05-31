#!/usr/bin/env python3
"""Pure: classification rows -> phase-ordered, dependency-topo-sorted slice DAG.

Consumed by the ``thinning-backbone`` workflow (spec
``docs/plans/2026-05-31-optimizers-thinning-execution-workflow-spec.md`` §4) to turn per-file
role classifications into a deterministic, bisectable slice order. ``stays``-role files (the
InstCombine rule registry the shell keeps) are excluded from slices and reported under
``retained``.
"""
from __future__ import annotations

import argparse
import json

# Global migration order (spec §7 gate matrix). Phase A is authored, not classified.
PHASE_ORDER = {p: i for i, p in enumerate(["A", "C", "D", "E", "F", "G", "H"])}


class SliceCycleError(RuntimeError):
    """Raised when the dependency edges among movable files contain a cycle."""


def build_slice_dag(rows: list[dict], *, anchor: str) -> dict:
    """Topo-sort ``rows`` into phase-ordered slices.

    Each row: ``{path, role, destination_module, phase, dep_edges, gate_class, ...}``.
    Order key is (phase, path); dependencies (``dep_edges``) must come first within that order.
    """
    retained = [r["path"] for r in rows if r.get("role") == "stays"]
    movable = [r for r in rows if r.get("role") != "stays"]

    by_path = {r["path"]: r for r in movable}
    indeg = {r["path"]: 0 for r in movable}
    for r in movable:
        for d in r.get("dep_edges", ()):
            if d in by_path:
                indeg[r["path"]] += 1

    def ready_key(p: str) -> tuple[int, str]:
        return (PHASE_ORDER.get(by_path[p].get("phase", "H"), 99), p)

    ready = sorted([p for p, d in indeg.items() if d == 0], key=ready_key)
    order: list[str] = []
    while ready:
        p = ready.pop(0)
        order.append(p)
        for q in movable:
            if p in q.get("dep_edges", ()):
                indeg[q["path"]] -= 1
                if indeg[q["path"]] == 0:
                    ready.append(q["path"])
        ready.sort(key=ready_key)

    if len(order) != len(movable):
        raise SliceCycleError(f"cycle among {set(indeg) - set(order)}")

    return {
        "anchor": anchor,
        "retained": retained,
        "slices": [by_path[p] for p in order],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("classification_json", help="path to classification rows JSON (list)")
    ap.add_argument("--anchor", required=True)
    ap.add_argument("-o", "--out", required=True, help="path to write backbone.json")
    args = ap.parse_args()
    rows = json.loads(open(args.classification_json).read())
    dag = build_slice_dag(rows, anchor=args.anchor)
    with open(args.out, "w") as fh:
        json.dump(dag, fh, indent=2)
    print(f"slices={len(dag['slices'])} retained={len(dag['retained'])} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
