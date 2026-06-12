#!/usr/bin/env python3
"""Detector codemod: portable-core IDA-shape abstraction leaks (epic llr-rv7p).

The ``portable-core-no-ida`` import-linter contract forbids ``import ida_*`` but
canNOT see SHAPE -- so portable-core (ir / analyses / transforms / passes /
capabilities / families) is full of pure-Python code that PASSES the import gate
while mirroring the Hex-Rays data model.  This script is the deterministic,
re-runnable replacement for the one-time agent sweep recorded at
``.tmp/abstraction-audit/INVENTORY.md``.

It does THREE jobs:
  1. AUDIT -- deterministic leak inventory (validate / re-measure the ~124 count)
  2. BURN-DOWN -- ``--json`` per-category counts to track slices S4/S5/S6/S9
  3. S8 SEED -- the detection core the shape-lint gate (ticket llr-f130) wraps

Categories (match the audit taxonomy):
  A  maturity -- MMAT_* name-tables, ``maturity:int`` fields/params, MMAT literals
  B  serial   -- ``*serial*`` dataclass FIELDS (persistent identity), serial as
                 a dict/set key (mblock_t mirror); within-fn index = ignored
  C  mop      -- the duck-typed dodge: ``getattr(x,"t"/"nnn"/"stkoff"...)`` and
                 ``"mop_n"``/``"mop_S"`` string compares on object-typed operands
  D  stale    -- comments/docstrings/loggers citing DELETED d810.cfg / d810.recon
  E  opcode   -- hardcoded ``"m_<op>"`` mnemonic string dispatch / raw opcode ints

This is a CONSERVATIVE structural detector (AST for A/B/C/E so comments never
false-positive; text scan for D since it lives in comments).  It is calibrated
against the agent audit, not identical to it: it trades a little recall for zero
comment-noise and full repeatability.  Read-only -- it never writes.
"""
from __future__ import annotations

import argparse
import ast
import json
import pathlib
import sys
from collections import Counter
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[2]
PORTABLE_CORE = (
    "ir",
    "analyses",
    "transforms",
    "passes",
    "capabilities",
    "families",
)

# C: operand sub-fields that only exist on a live Hex-Rays mop_t / minsn_t.
# Reading these off an ``object``/``Any``-typed param IS the gate-evading shape.
_MOP_FIELDS = {"t", "nnn", "stkoff", "lvar_idx", "lvar_off", "gaddr"}
# E / C string literals that are raw Hex-Rays enum spellings used for dispatch.
_VENDOR_ENUM_PREFIXES = ("mop_", "m_")
# A: the canonical maturity ladder (any literal of these = an MMAT table/compare)
_MMAT_TOKEN = "MMAT_"
# Accepted portable metadata boundary -- reading stage from a dict is NOT a leak.
_BOUNDARY_KEYS = {"producer_stage_id", "maturity", "snapshot_id", "phase"}


@dataclass(frozen=True)
class Finding:
    rel: str
    line: int
    category: str  # A B C D E
    token: str
    verdict: str  # REAL-LEAK | LIKELY | BOUNDARY-OK | STALE


@dataclass
class _Visitor(ast.NodeVisitor):
    rel: str
    docstrings: frozenset[int] = frozenset()  # id()s of docstring Constant nodes
    findings: list[Finding] = field(default_factory=list)
    _in_dataclass: int = 0

    # ---- A: maturity ------------------------------------------------------
    def _maturity_annotation(self, name: str, ann: ast.expr | None, line: int) -> None:
        if ann is None or "maturity" not in name.lower():
            return
        # ``maturity: int`` threaded as logic = leak; ``: str`` rehydrate = OK.
        ann_txt = ast.unparse(ann)
        verdict = "BOUNDARY-OK" if ann_txt.strip().lstrip('"').startswith("str") else "REAL-LEAK"
        self.findings.append(Finding(self.rel, line, "A", f"{name}: {ann_txt}", verdict))

    def visit_Constant(self, node: ast.Constant) -> None:
        if id(node) in self.docstrings:
            return  # a docstring describing MMAT_/m_ is documentation, not a leak
        if isinstance(node.value, str):
            s = node.value
            if _MMAT_TOKEN in s:
                self.findings.append(Finding(self.rel, node.lineno, "A", repr(s), "REAL-LEAK"))
            elif s.startswith(_VENDOR_ENUM_PREFIXES) and len(s) <= 12 and s.replace("_", "").isalnum():
                # "mop_n" / "m_goto" style raw-enum string dispatch (C if mop_, E if m_)
                cat = "C" if s.startswith("mop_") else "E"
                self.findings.append(Finding(self.rel, node.lineno, cat, repr(s), "REAL-LEAK"))
        self.generic_visit(node)

    # ---- B + A: dataclass fields -----------------------------------------
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        is_dc = any(
            (isinstance(d, ast.Name) and d.id == "dataclass")
            or (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id == "dataclass")
            or (isinstance(d, ast.Attribute) and d.attr == "dataclass")
            for d in node.decorator_list
        )
        if is_dc:
            self._in_dataclass += 1
        self.generic_visit(node)
        if is_dc:
            self._in_dataclass -= 1

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            name = node.target.id
            if self._in_dataclass:
                # B: a persistent *serial* identity field mirrors mblock_t numbering
                if "serial" in name.lower():
                    self.findings.append(
                        Finding(self.rel, node.lineno, "B", f"field {name}", "LIKELY")
                    )
                self._maturity_annotation(name, node.annotation, node.lineno)
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> None:
        if node.annotation is not None:
            self._maturity_annotation(node.arg, node.annotation, node.lineno)
        self.generic_visit(node)

    # ---- C: duck-typed mop_t via getattr ---------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
            and node.args[1].value in _MOP_FIELDS
        ):
            self.findings.append(
                Finding(self.rel, node.lineno, "C", f'getattr(_, "{node.args[1].value}")', "REAL-LEAK")
            )
        self.generic_visit(node)

    # ---- B: serial as a subscript key ------------------------------------
    def visit_Subscript(self, node: ast.Subscript) -> None:
        idx = node.slice
        if isinstance(idx, ast.Attribute) and idx.attr == "serial":
            self.findings.append(
                Finding(self.rel, node.lineno, "B", f"[_.serial] key", "LIKELY")
            )
        self.generic_visit(node)


def _scan_stale(rel: str, text: str) -> list[Finding]:
    """D: deleted-package refs live in comments/docstrings/logger strings."""
    out: list[Finding] = []
    needles = ("d810.cfg", "d810.recon", "recon.collectors", "D810.recon", "D810.cfg")
    for i, line in enumerate(text.splitlines(), 1):
        for n in needles:
            if n in line:
                out.append(Finding(rel, i, "D", n, "STALE"))
                break
    return out


def _audit_file(path: pathlib.Path, rel: str) -> list[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = _scan_stale(rel, text)
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError:
        return findings
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None)
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                docstrings.add(id(body[0].value))
    v = _Visitor(rel=rel, docstrings=frozenset(docstrings))
    v.visit(tree)
    return findings + v.findings


def _iter_targets(packages: tuple[str, ...]) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for pkg in packages:
        base = ROOT / "src" / "d810" / pkg
        if base.exists():
            out.extend(sorted(base.rglob("*.py")))
    return [p for p in out if "__pycache__" not in p.parts]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package", action="append", choices=PORTABLE_CORE,
                    help="restrict to one or more portable-core packages")
    ap.add_argument("--category", action="append", choices=list("ABCDE"),
                    help="restrict to one or more leak categories")
    ap.add_argument("--real-only", action="store_true",
                    help="show only REAL-LEAK (drop LIKELY/BOUNDARY-OK)")
    ap.add_argument("--sites", action="store_true",
                    help="count edit-SITES (dedup file+category+line) not raw tokens; "
                         "comparable to the agent audit's site-level count")
    ap.add_argument("--json", action="store_true", help="machine-readable counts (burn-down)")
    ap.add_argument("--list", action="store_true", help="print every finding as file:line")
    ap.add_argument("--fail-over", type=int, default=None,
                    help="exit 1 if REAL-LEAK count exceeds N (S8 gate mode)")
    args = ap.parse_args()

    packages = tuple(args.package) if args.package else PORTABLE_CORE
    cats = set(args.category) if args.category else set("ABCDE")

    findings: list[Finding] = []
    for path in _iter_targets(packages):
        rel = str(path.relative_to(ROOT))
        for f in _audit_file(path, rel):
            if f.category in cats and (not args.real_only or f.verdict == "REAL-LEAK"):
                findings.append(f)

    if args.sites:
        seen: set[tuple[str, str, int]] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = (f.rel, f.category, f.line)
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        findings = deduped

    real = [f for f in findings if f.verdict == "REAL-LEAK"]
    by_cat = Counter(f.category for f in findings)
    by_cat_real = Counter(f.category for f in real)
    by_file_real = Counter(f.rel for f in real)

    if args.json:
        print(json.dumps({
            "total": len(findings),
            "real_leak": len(real),
            "by_category": dict(sorted(by_cat.items())),
            "by_category_real": dict(sorted(by_cat_real.items())),
        }, indent=2))
    else:
        cat_name = {"A": "maturity", "B": "serial-identity", "C": "mop/duck-typed",
                    "D": "stale-refs", "E": "opcode-dispatch"}
        print(f"# Portable-IR leak audit (deterministic) -- packages={','.join(packages)}\n")
        print("|cat|name|REAL-LEAK|all findings|")
        print("|-|-|-|-|")
        for c in sorted(cats):
            print(f"|{c}|{cat_name[c]}|{by_cat_real.get(c,0)}|{by_cat.get(c,0)}|")
        print(f"\nTOTAL REAL-LEAK: {len(real)}   (all findings incl. LIKELY/BOUNDARY-OK: {len(findings)})\n")
        print("Top real-leak files:")
        for rel, n in by_file_real.most_common(10):
            print(f"  {n:>3}  {rel}")
        if args.list:
            print("\nAll findings:")
            for f in sorted(findings, key=lambda x: (x.category, x.rel, x.line)):
                print(f"  {f.category} {f.verdict:<11} {f.rel}:{f.line}  {f.token}")

    if args.fail_over is not None and len(real) > args.fail_over:
        print(f"\nFAIL: {len(real)} REAL-LEAK > threshold {args.fail_over}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
