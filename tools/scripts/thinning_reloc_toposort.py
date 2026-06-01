#!/usr/bin/env python3
"""Regenerate phase_RELOC_FULL.json in strict movable-dependency topo order.

The previous plan sorted by ``(layer, #movable-deps)`` which is NOT a valid
relocation order: within a layer a file F that imports a sibling-layer file G
must be relocated AFTER G, else F's home (e.g. ``transforms``) ends up importing
the still-in-``optimizers`` G -> upward import -> lint break.

Rule: emit G before F whenever F imports G (G is a dependency of F). This is a
Kahn topo-sort with edges dependency -> dependent, tie-broken by
``(layer, original_index)`` so the order stays layer-ascending / stable.

Movable set = entries in phase_RELOC_FULL.json whose source file still exists
(already-relocated files are dropped).
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / ".tmp/thinning/phase_RELOC_FULL.json"
SRC = ROOT / "src"


def main() -> None:
    entries = json.loads(PLAN.read_text())
    movable = [e for e in entries if (SRC / "d810" / e["path"]).exists()]
    by_mod = {e["old_module"]: e for e in movable}

    deps: dict[str, set[str]] = {e["old_module"]: set() for e in movable}
    for e in movable:
        f_mod = e["old_module"]
        f_parent = f_mod.rpartition(".")[0]
        text = (SRC / "d810" / e["path"]).read_text()
        for g_mod in by_mod:
            if g_mod == f_mod:
                continue
            g_parent, _, g_stem = g_mod.rpartition(".")
            found = False
            if re.search(r"\b" + re.escape(g_mod) + r"\b", text):
                found = True
            if not found:
                for m in re.finditer(
                    r"from\s+" + re.escape(g_parent) + r"\s+import\s+(.+)", text
                ):
                    if re.search(r"\b" + re.escape(g_stem) + r"\b", m.group(1)):
                        found = True
                        break
            if not found and f_parent == g_parent:
                if re.search(r"from\s+\.\s*" + re.escape(g_stem) + r"\b", text):
                    found = True
                elif any(
                    re.search(r"\b" + re.escape(g_stem) + r"\b", m.group(1))
                    for m in re.finditer(r"from\s+\.\s+import\s+(.+)", text)
                ):
                    found = True
            if found:
                deps[g_mod].add(f_mod)  # G is a dep of F

    indeg: dict[str, int] = {m: 0 for m in by_mod}
    for dependents in deps.values():
        for f in dependents:
            indeg[f] += 1

    order_key = {e["old_module"]: (e["layer"], i) for i, e in enumerate(movable)}
    ready = sorted((m for m in by_mod if indeg[m] == 0), key=lambda m: order_key[m])
    out: list[dict] = []
    emitted: set[str] = set()
    while ready:
        m = ready.pop(0)
        emitted.add(m)
        out.append(by_mod[m])
        newly = []
        for f in deps[m]:
            indeg[f] -= 1
            if indeg[f] == 0:
                newly.append(f)
        if newly:
            ready.extend(newly)
            ready.sort(key=lambda x: order_key[x])

    if len(out) != len(movable):
        cyc = [m for m in by_mod if m not in emitted]
        raise SystemExit(
            f"CYCLE among movable files ({len(cyc)} unemitted): "
            + ", ".join(c.split('.')[-1] for c in cyc)
        )

    PLAN.write_text(json.dumps(out, indent=1) + "\n")

    pos = {e["old_module"]: i for i, e in enumerate(out)}
    bad = [
        (g.split(".")[-1], f.split(".")[-1])
        for g, dependents in deps.items()
        for f in dependents
        if pos[g] > pos[f]
    ]
    print(f"movable: {len(movable)}  emitted: {len(out)}  ordering-violations: {len(bad)}")
    for g, f in bad:
        print(f"  VIOLATION: {g} must precede {f}")
    print("layer dist:", dict(sorted(Counter(e["layer"] for e in out).items())))
    print("first 14 (next batch order):")
    for e in out[:14]:
        deps_of = sorted(
            g.split(".")[-1] for g in by_mod if e["old_module"] in deps[g]
        )
        print(
            f"  L{e['layer']} {e['old_module'].split('.')[-1]:42s} -> {e['dest']}"
            + (f"   (deps: {','.join(deps_of)})" if deps_of else "")
        )


if __name__ == "__main__":
    main()
