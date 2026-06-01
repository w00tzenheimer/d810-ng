#!/usr/bin/env python3
"""Drive the optimizers->taxonomy relocation sweep, one file per commit.

For each plan entry {path, old_module, dest, layer}:
  1. repoint EVERY importer across src/ tests/ tools/:
       - absolute  `from <old_module> import ...`            (libcst)
       - relative  `from .stem import ...` resolving to old   (libcst, dot-resolved)
       - by-name   `from <old_parent> import <stem>`          (libcst split -> FlattenSentinel)
       - literal   dotted path in strings/comments/plain imports (boundary regex)
  2. ensure dest package dirs have __init__.py (git add new ones)
  3. git mv src/d810/<path> -> <new_path from dest>
  4. FAST gate: lint-imports + sg + check-cycles + unit/system collect-only
  5. green -> commit `refactor(thinning): relocate <stem> -> <dest>`
     red   -> print failing check + reset --hard + clean, STOP (prior commits kept)

Unit-suite + golden run per BATCH by the caller, not here.

  thinning_reloc_apply.py --plan .tmp/thinning/phase_RELOC_FULL.json --count 6
  thinning_reloc_apply.py --plan ... --start 6 --count 6
  thinning_reloc_apply.py --only snapshot,planner_context   # by stem
  add --dry-run to preview repoint counts without git mv/commit
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import libcst as cst

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
TREES = ("src", "tests", "tools")
ENV = {**os.environ, "PYTHONPATH": "src:tests"}


def _dotted(node) -> str:
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        return _dotted(node.value) + "." + node.attr.value
    return ""


def _parse_dotted(dotted: str):
    parts = dotted.split(".")
    out: cst.BaseExpression = cst.Name(parts[0])
    for p in parts[1:]:
        out = cst.Attribute(value=out, attr=cst.Name(p))
    return out


def module_of(pyfile: Path) -> str:
    rel = pyfile.relative_to(SRC).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


class _Repointer(cst.CSTTransformer):
    def __init__(self, old: str, dest: str, f_pkg: str):
        self.old = old
        self.dest = dest
        self.old_parent, _, self.stem = old.rpartition(".")
        self.dest_parent = dest.rpartition(".")[0]
        self.f_pkg = f_pkg
        self.changed = False

    def _resolve_relative(self, ndots: int, modstr: str) -> str:
        base = self.f_pkg.split(".") if self.f_pkg else []
        up = ndots - 1
        if up:
            base = base[:-up] if up <= len(base) else []
        if modstr:
            base = base + modstr.split(".")
        return ".".join(base)

    def leave_ImportFrom(self, original, updated):
        ndots = len(updated.relative)
        modstr = _dotted(updated.module) if updated.module is not None else ""
        absmod = modstr if ndots == 0 else self._resolve_relative(ndots, modstr)

        if absmod == self.old or absmod.startswith(self.old + "."):
            tail = absmod[len(self.old):]
            self.changed = True
            return updated.with_changes(
                module=_parse_dotted(self.dest + tail), relative=[]
            )

        if absmod == self.old_parent and not isinstance(updated.names, cst.ImportStar):
            names = list(updated.names)
            moved = [a for a in names if a.name.value == self.stem]
            if moved:
                kept = [a for a in names if a.name.value != self.stem]
                self.changed = True
                moved_clean = moved[0].with_changes(comma=cst.MaybeSentinel.DEFAULT)
                new_import = cst.ImportFrom(
                    module=_parse_dotted(self.dest_parent), names=[moved_clean]
                )
                if not kept:
                    return new_import
                kept[-1] = kept[-1].with_changes(comma=cst.MaybeSentinel.DEFAULT)
                return cst.FlattenSentinel(
                    [updated.with_changes(names=kept), new_import]
                )
        return updated


def repoint_file(text: str, *, old: str, dest: str, f_pkg: str) -> tuple[str, bool]:
    try:
        tree = cst.parse_module(text)
        rp = _Repointer(old, dest, f_pkg)
        out = tree.visit(rp).code
        changed = rp.changed
    except cst.ParserSyntaxError:
        out, changed = text, False
    out2 = re.sub(re.escape(old) + r"(?![\w])", dest, out)
    if out2 != out:
        changed = True
    return out2, changed


def sh(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, **kw)


def ensure_init(dest_module: str) -> None:
    parts = dest_module.split(".")[:-1]
    p = SRC
    for part in parts:
        p = p / part
        init = p / "__init__.py"
        if not init.exists():
            p.mkdir(parents=True, exist_ok=True)
            init.write_text("")
            sh(["git", "add", str(init.relative_to(ROOT))])


def fast_gate() -> tuple[bool, str, str]:
    checks = [
        ("lint-imports", ["lint-imports", "--config", ".importlinter"]),
        ("sg", ["sg", "scan", "--config", "sgconfig.yml", "--report-style", "short"]),
        ("check-cycles", ["pyenv", "exec", "python", "tools/scripts/check-cycles.py"]),
        ("unit-collect", ["pyenv", "exec", "python", "-m", "pytest",
                          "tests/unit", "--collect-only", "-q"]),
        ("system-collect", ["pyenv", "exec", "python", "-m", "pytest",
                            "tests/system", "--collect-only", "-q"]),
    ]
    for name, cmd in checks:
        cp = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, env=ENV)
        broken = bool(re.search(r"[1-9]\d* broken", cp.stdout)) if name == "lint-imports" else False
        if cp.returncode != 0 or broken:
            return False, name, (cp.stdout + cp.stderr)[-3000:]
    return True, "", ""


def relocate_one(entry: dict, *, dry: bool) -> bool:
    old = entry["old_module"]
    dest = entry["dest"]
    stem = old.rsplit(".", 1)[-1]
    src_path = SRC / "d810" / entry["path"]
    new_rel = "src/" + dest.replace(".", "/") + ".py"
    new_path = ROOT / new_rel

    if not src_path.exists():
        print(f"  SKIP {stem}: source missing — already relocated?")
        return True

    cand = sh(["grep", "-rlE", "--include=*.py", re.escape(old), *TREES])
    files = {l for l in cand.stdout.splitlines() if l}
    old_parent_path = "src/" + old.rsplit(".", 1)[0].replace(".", "/")
    rel = sh(["grep", "-rlE", "--include=*.py",
              r"from \.+[a-zA-Z0-9_.]*" + re.escape(stem) + r" import|from \.+ import",
              old_parent_path])
    files |= {l for l in rel.stdout.splitlines() if l}
    files.discard(str(src_path.relative_to(ROOT)))

    changed_files = []
    for rel_f in sorted(files):
        f = ROOT / rel_f
        if not f.exists():
            continue
        if SRC in f.parents and f.name == "__init__.py":
            f_pkg = module_of(f)
        elif SRC in f.parents:
            f_pkg = module_of(f).rsplit(".", 1)[0]
        else:
            f_pkg = ""
        text = f.read_text()
        new_text, changed = repoint_file(text, old=old, dest=dest, f_pkg=f_pkg)
        if changed:
            changed_files.append(rel_f)
            if not dry:
                f.write_text(new_text)

    print(f"  {stem} -> {dest}: {len(changed_files)} importer files repointed")
    if dry:
        return True

    ensure_init(dest)
    new_path.parent.mkdir(parents=True, exist_ok=True)
    mv = sh(["git", "mv", str(src_path.relative_to(ROOT)), new_rel])
    if mv.returncode != 0:
        print(f"  ERROR git mv: {mv.stderr}")
        sh(["git", "reset", "--hard", "HEAD"])
        sh(["git", "clean", "-fd", "--", *TREES])
        return False
    sh(["git", "add", "-A", *TREES])

    ok, check, detail = fast_gate()
    if not ok:
        print(f"\n  GATE FAILED [{check}] on {stem}:\n{detail}\n")
        sh(["git", "reset", "--hard", "HEAD"])
        sh(["git", "clean", "-fd", "--", *TREES])
        return False

    c = sh(["git", "commit", "-m", f"refactor(thinning): relocate {stem} -> {dest}"])
    if c.returncode != 0:
        print(f"  ERROR commit: {c.stdout}{c.stderr}")
        return False
    print(f"  COMMITTED {stem}")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", default=".tmp/thinning/phase_RELOC_FULL.json")
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--count", type=int, default=6)
    ap.add_argument("--only", default="")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    plan = json.loads((ROOT / a.plan).read_text())
    if a.only:
        stems = set(a.only.split(","))
        batch = [e for e in plan if e["old_module"].rsplit(".", 1)[-1] in stems]
    else:
        batch = plan[a.start:a.start + a.count]

    print(f"Relocating {len(batch)} files (dry={a.dry_run}):")
    for e in batch:
        if not relocate_one(e, dry=a.dry_run):
            print(f"\nHALTED at {e['old_module'].rsplit('.',1)[-1]}. Prior commits kept.")
            return 1
    print(f"\nBatch done: {len(batch)} files relocated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
