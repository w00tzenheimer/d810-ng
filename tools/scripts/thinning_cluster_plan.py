#!/usr/bin/env python3
"""File-level reducibility analysis for the optimizers-thinning campaign.

Byte-identical relocation into the fine LLVM/LiSA taxonomy is only possible where the file-level
import graph is topo-orderable AND every import points to a destination layer <= the importer's.
A multi-file import CYCLE whose files are classified to DIFFERENT target layers is IRREDUCIBLE by
relocation (after the move, some intra-cycle edge is upward) -- it needs a decoupling refactor.

Reads  .tmp/thinning/classification.json
Writes .tmp/thinning/clusters.json  (ordered atomic units: singletons in bottom-up topo order,
       plus multi-file SCCs flagged same-layer (movable atomically) vs cross-layer (irreducible)).

Prints the headline: how many files move cleanly vs how many are trapped in cross-layer cycles.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

WT = Path("/Users/mahmoud/src/idapro/d810/.worktrees/llvm-lisa-restructure")

# LLVM/LiSA layer order (high -> low). A legal import goes from higher to lower (or same).
LAYER_RANK = {  # higher number = higher layer
    "shell": 7, "families": 6, "passes": 5, "evidence": 4, "mutation": 4,
    "transforms": 3, "analyses": 2,
}


def old_module(path: str) -> str:
    return "d810." + path[: -len(".py")].replace("/", ".")


def main() -> int:
    RELOC = {"analyses", "transforms", "passes", "families", "evidence", "mutation"}
    rows = json.loads(Path(".tmp/thinning/classification.json").read_text())
    movable = [r for r in rows if r.get("role") in RELOC and (WT / "src/d810" / r["path"]).exists()]
    mod2file = {old_module(r["path"]): r["path"] for r in movable}
    by_path = {r["path"]: r for r in movable}

    # file-level import edges X -> Y (both movable)
    edges: dict[str, set[str]] = {r["path"]: set() for r in movable}
    for r in movable:
        src = (WT / "src/d810" / r["path"]).read_text(errors="ignore")
        mods = set(re.findall(r"^\s*from\s+(d810\.[\w.]+)\s+import\b", src, re.M))
        mods |= set(re.findall(r"^\s*import\s+(d810\.[\w.]+)", src, re.M))
        for m in mods:
            if m in mod2file and mod2file[m] != r["path"]:
                edges[r["path"]].add(mod2file[m])

    # Tarjan SCC (iterative-safe recursion via sys limit bump)
    sys.setrecursionlimit(10000)
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    onstack: dict[str, bool] = {}
    stack: list[str] = []
    sccs: list[list[str]] = []
    c = [0]

    def strong(v: str):
        index[v] = low[v] = c[0]; c[0] += 1
        stack.append(v); onstack[v] = True
        for w in edges[v]:
            if w not in index:
                strong(w); low[v] = min(low[v], low[w])
            elif onstack.get(w):
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop(); onstack[w] = False; comp.append(w)
                if w == v:
                    break
            sccs.append(comp)

    for v in edges:
        if v not in index:
            strong(v)

    # Tarjan yields SCCs in reverse-topo order (deps first) = bottom-up move order.
    singletons = [comp[0] for comp in sccs if len(comp) == 1]
    multi = [comp for comp in sccs if len(comp) > 1]

    def layers(paths):
        return sorted({by_path[p]["role"] for p in paths})

    same_layer_sccs, cross_layer_sccs = [], []
    for comp in multi:
        ranks = {LAYER_RANK.get(by_path[p]["role"], 0) for p in comp}
        (same_layer_sccs if len(ranks) == 1 else cross_layer_sccs).append(comp)

    trapped = sum(len(c) for c in cross_layer_sccs)
    print(f"movable files: {len(movable)}")
    print(f"  singleton (cleanly movable, bottom-up): {len(singletons)}")
    print(f"  same-layer SCCs (atomically movable): {len(same_layer_sccs)} ({sum(len(c) for c in same_layer_sccs)} files)")
    print(f"  CROSS-LAYER SCCs (IRREDUCIBLE w/o refactor): {len(cross_layer_sccs)} ({trapped} files)")
    for comp in sorted(cross_layer_sccs, key=len, reverse=True):
        print(f"    - {len(comp)}f spanning layers {layers(comp)}")
        for p in sorted(comp)[:6]:
            print(f"        [{by_path[p]['role']}] {p}")
        if len(comp) > 6:
            print(f"        ... +{len(comp)-6} more")

    # emit atomic units in order: each singleton + same-layer SCC as a movable cluster;
    # cross-layer SCCs flagged irreducible (need a common-layer or decouple decision).
    units = []
    for comp in sccs:
        ranks = {LAYER_RANK.get(by_path[p]["role"], 0) for p in comp}
        units.append({
            "files": [{"path": p, "old_module": old_module(p), "dest": by_path[p]["destination_module"],
                       "role": by_path[p]["role"], "seam": by_path[p].get("needs_seam", False)} for p in comp],
            "atomic": len(comp) > 1,
            "irreducible_cross_layer": len(comp) > 1 and len(ranks) > 1,
            "gate_class": "golden" if any(by_path[p]["role"] in ("evidence", "mutation") for p in comp) else "static",
        })
    Path(".tmp/thinning/clusters.json").write_text(json.dumps(units, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
