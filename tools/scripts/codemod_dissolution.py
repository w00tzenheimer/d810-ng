#!/usr/bin/env python3
"""recon/cfg DISSOLUTION codemod (umbrella ticket llr-lyly).

Generalizes ``codemod_ls11_dispatcher_cluster.py`` from a single
``OLD_PKG -> NEW_PKG`` pair to an arbitrary many->many per-module
``old_dotted -> new_dotted`` map (recon -> analyses/pre_analysis/passes,
cfg -> ir/analyses/transforms/passes), and adds the high-value
``--stage preflight`` UPWARD-EDGE DETECTOR.

The map is DATA-DRIVEN by module role-suffix (playbook
``recon-cfg-dissolution-execution-playbook.md`` section 9): the codebase names
modules by role, so ``home_for()`` resolves each recon/cfg module to its
destination package deterministically.

Stages:
  --stage preflight   THE detector. For each module's POST-MOVE home + the
                      target layer order, statically (grimp) resolve every
                      import to its post-move layer and list every edge that
                      would point UPWARD (layer-fatal).  Converts Risk #1
                      (intra-cfg upward edges) from an unknown into a per-cluster
                      worklist: a cluster is either "clean, codemod-move it" or
                      "these N edges need manual P1-style severance first".
                      READ-ONLY.
  --stage move        Relocate modules (filtered by --only) + sys.modules-alias
                      shims + libcst+regex intra rewrites. (Per-cluster, golden-gated.)
  --stage cutover     Repoint consumers off the shims; --delete-shims removes them.
  --stage scaffold    Create passes/ support/ pre_analysis/ (docstring __init__).
  --stage selftest    Boundary-regex correctness (prefix-collision guard).

Default dry-run; --apply writes.  --only <substr> restricts move/cutover to a
cluster.  Run from the worktree root with ``PYTHONPATH=src``.

NB the move/cutover engine is the LS11 engine verbatim (hybrid libcst import-node
rewrite + boundary regex + alias shims + per-file regex fallback); only the
mapping is generalized.  preflight is net-new.
"""
from __future__ import annotations

import argparse
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import libcst as cst

SRC = Path("src")
DISSOLVING_ROOTS = ("src/d810/recon", "src/d810/cfg")

# --------------------------------------------------------------------------- #
# Target layer order (high -> low; index 0 = highest, imports everything below).
# An import A->B is UPWARD-FATAL iff layer_index(B) < layer_index(A) (B higher).
# Planned end-state spine: support < ir < capabilities < analyses < transforms
# < passes (per the design doc).  The three NEW packages (passes/pre_analysis/
# support) are placed at their planned positions; FINALIZED in Phase 0b -- adjust
# here if the .importlinter ordering lands differently.  recon/cfg are dissolving
# (kept here only so pre-move imports still resolve to a layer).
# --------------------------------------------------------------------------- #
TARGET_LAYER_ORDER: tuple[str, ...] = (
    "d810.ui",
    "d810.diagnostics",
    "d810.optimizers",
    "d810.families",
    "d810.passes",          # NEW: scheduler; above transforms, below families
    "d810.recon",           # dissolving
    "d810.backends",
    "d810.evaluator",
    "d810.hexrays",
    "d810.transforms",
    "d810.mba",
    "d810.cfg",             # dissolving
    "d810.analyses",
    "d810.pre_analysis",    # NEW: read-only collectors, just below analyses
    "d810.capabilities",
    "d810.ir",
    "d810.support",         # NEW: shared utils, below ir
    "d810.core",
    "d810.errors",
)


def layer_index(dotted: str) -> int | None:
    """Longest-prefix layer index for a dotted module (None if not under a layer)."""
    best: int | None = None
    best_len = -1
    for i, pkg in enumerate(TARGET_LAYER_ORDER):
        if (dotted == pkg or dotted.startswith(pkg + ".")) and len(pkg) > best_len:
            best, best_len = i, len(pkg)
    return best


# --------------------------------------------------------------------------- #
# Role-suffix -> destination package (playbook section 9).  Ordered: first match
# wins, so put the more specific patterns first.  Each rule maps a leaf-name
# predicate to a destination PACKAGE; home_for() keeps the leaf name.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RoleRule:
    dest: str  # destination package dotted prefix
    # leaf-name predicates (any-match): substrings / suffixes
    suffixes: tuple[str, ...] = ()
    contains: tuple[str, ...] = ()
    exact: tuple[str, ...] = ()


ROLE_RULES: tuple[RoleRule, ...] = (
    # ir: portable dataclasses / identities / graph snapshot
    RoleRule("d810.ir", exact=(
        "flowgraph", "lattice", "mop_identity", "block_identity", "state_dag_key",
        "state_edge_pair", "state_variable", "semantic_reference", "provenance", "plan",
    ), suffixes=("_identity",)),
    # transforms: planning / emission / lowering / modification building
    RoleRule("d810.transforms", suffixes=(
        "_planning", "_emission", "_lowering", "_recording", "_building",
    ), contains=("modification_builder", "mod_claims", "graph_modification",
                 "materialization", "reorder_blocks", "select_loop_planning"),
       exact=("dead_block_elimination", "fake_jump_fixer", "opaque_jump_fixer",
              "simplify_identical_branch", "loop_carrier_backedge_refresh")),
    # passes: scheduler / pipeline / transaction engine / recon orchestration root
    RoleRule("d810.passes", exact=(
        "pipeline", "transaction_engine", "transaction_policy", "invariants",
        "contract", "phase", "runtime", "store", "inferences", "persist_inference",
        "outcome", "flow_hints", "function_priors",
    )),
    # pre_analysis: recon collectors (read-only profiling)
    RoleRule("d810.pre_analysis", exact=(
        "cfg_shape", "dispatch_pattern", "profile_classifier", "ctree_structure",
        "opcode_distribution", "handler_transitions", "fixpred_signals",
        "return_frontier",
    )),
    # analyses/value_flow: value-flow fact ontology
    RoleRule("d810.analyses.value_flow", contains=("value_flow",),
             suffixes=("_value_fact",)),
    # analyses/control_flow: discovery / graph algorithms / classifiers (the bulk)
    RoleRule("d810.analyses.control_flow", suffixes=(
        "_discovery", "_analysis", "_facts", "_evidence", "_oracle", "_report",
        "_classifier", "_resolver", "_closure",
    ), contains=("transition_", "dominator", "postdominator", "scc", "dag_index",
                 "sese_hammock", "graph_checks", "compare_chain", "conditional_alias",
                 "state_var_alias", "terminal_frontier", "block_lineage",
                 "redirect_reconciliation", "backedge"),
       exact=("state_machine_analysis",)),
    # observability -> diagnostics
    RoleRule("d810.diagnostics", exact=("observability",)),
)


def home_for(old_dotted: str) -> str | None:
    """Resolve a recon/cfg module's destination dotted path by role-suffix.

    Returns the new dotted module path (dest package + original leaf), or None
    when no rule matches (those need a manual home decision -- preflight lists
    them as UNMAPPED)."""
    leaf = old_dotted.rsplit(".", 1)[-1]
    for rule in ROLE_RULES:
        if (
            leaf in rule.exact
            or any(leaf.endswith(s) for s in rule.suffixes)
            or any(c in leaf for c in rule.contains)
        ):
            return f"{rule.dest}.{leaf}"
    return None


def _module_dotted(path: Path) -> str:
    rel = path.relative_to(SRC).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def build_move_map() -> tuple[dict[str, str], list[str]]:
    """Scan the dissolving roots, apply role rules. Returns (mapped, unmapped)."""
    mapped: dict[str, str] = {}
    unmapped: list[str] = []
    for root in DISSOLVING_ROOTS:
        base = Path(root)
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            dotted = _module_dotted(path)
            if dotted.endswith("__init__") or "__pycache__" in dotted:
                continue
            home = home_for(dotted)
            if home is None:
                unmapped.append(dotted)
            else:
                mapped[dotted] = home
    return mapped, unmapped


# --------------------------------------------------------------------------- #
# preflight -- the upward-edge detector (READ-ONLY, the de-risking deliverable)
# --------------------------------------------------------------------------- #
def run_preflight(move_map: dict[str, str], unmapped: list[str]) -> int:
    try:
        import grimp
    except ImportError:
        print("FATAL: grimp not importable (needed for preflight).")
        return 2
    print(f"building d810 import graph (grimp)...")
    graph = grimp.build_graph("d810")
    modset = set(graph.modules)

    # destination -> list of upward edges (importer_leaf -> target, layers)
    by_dest: dict[str, list[str]] = defaultdict(list)
    clean_dest: dict[str, int] = defaultdict(int)
    total_up = 0

    for old, new in sorted(move_map.items()):
        if old not in modset:
            continue
        new_layer = layer_index(new)
        if new_layer is None:
            continue
        ups = []
        for imp in sorted(graph.find_modules_directly_imported_by(old)):
            if not imp.startswith("d810."):
                continue
            imp_post = move_map.get(imp, imp)  # resolve to post-move home
            imp_layer = layer_index(imp_post)
            if imp_layer is None:
                continue
            if imp_layer < new_layer:  # target sits HIGHER -> upward-fatal
                moved_note = " (moved)" if imp in move_map else ""
                ups.append(
                    f"      {old}  ->  {imp_post}{moved_note}  "
                    f"[{new.split('.')[1]} imports {imp_post.split('.')[1]} = UP]"
                )
        dest_pkg = ".".join(new.split(".")[:2])
        if ups:
            by_dest[dest_pkg].extend(ups)
            total_up += len(ups)
        else:
            clean_dest[dest_pkg] += 1

    print("\n========== DISSOLUTION PREFLIGHT (post-move upward-edge scan) ==========")
    print(f"mapped modules: {len(move_map)} | unmapped (need a home): {len(unmapped)}")
    print(f"\n--- CLEAN clusters (codemod-movable as-is; count = modules with 0 upward edges) ---")
    for dest in sorted(clean_dest):
        flagged = len({u.split('  ->')[0].strip() for u in by_dest.get(dest, [])})
        print(f"  {dest:32s} clean={clean_dest[dest]:3d}  needs-severance={flagged}")
    print(f"\n--- UPWARD EDGES (Risk #1 worklist: manual P1-style severance before move) ---")
    if not total_up:
        print("  NONE -- every mapped module is layer-clean post-move.")
    for dest in sorted(by_dest):
        print(f"  [{dest}] {len(by_dest[dest])} edge(s):")
        for line in by_dest[dest][:60]:
            print(line)
    if unmapped:
        print(f"\n--- UNMAPPED ({len(unmapped)}: no role rule matched -> decide a home) ---")
        for m in unmapped[:80]:
            print(f"      {m}")
    print(f"\nSUMMARY: {total_up} upward edge(s) across "
          f"{len(by_dest)} destination cluster(s); {len(unmapped)} unmapped module(s).")
    return 0


# --------------------------------------------------------------------------- #
# move / cutover engine (generalized from codemod_ls11_dispatcher_cluster.py)
# --------------------------------------------------------------------------- #
def _dotted_pattern(dotted: str) -> re.Pattern[str]:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(dotted) + r"(?![A-Za-z0-9_])")


def _rewrite_dotted(code: str, move_map: dict[str, str]) -> str | None:
    # longest-prefix-first so a module path is rewritten before any shorter
    # colliding prefix, and submodule/attribute access is preserved.
    for old in sorted(move_map, key=len, reverse=True):
        new = move_map[old]
        if code == old or code.startswith(old + "."):
            return new + code[len(old):]
    return None


class _RenameTransformer(cst.CSTTransformer):
    def __init__(self, move_map: dict[str, str]) -> None:
        self._map = move_map

    def leave_ImportFrom(self, original, updated):  # noqa: ANN001
        if updated.module is None:
            return updated
        code = cst.Module([]).code_for_node(updated.module)
        new = _rewrite_dotted(code, self._map)
        if new is not None:
            return updated.with_changes(module=cst.parse_expression(new))
        return updated

    def leave_ImportAlias(self, original, updated):  # noqa: ANN001
        code = cst.Module([]).code_for_node(updated.name)
        new = _rewrite_dotted(code, self._map)
        if new is not None:
            return updated.with_changes(name=cst.parse_expression(new))
        return updated


def rewrite_text(text: str, move_map: dict[str, str], patterns) -> str:
    try:
        text = cst.parse_module(text).visit(_RenameTransformer(move_map)).code
    except Exception as exc:  # non-parseable -> regex-only fallback
        print(f"    (libcst parse failed: {type(exc).__name__}; regex-only)")
    for pat, new in patterns:
        text = pat.sub(new, text)
    return text


def _alias_shim(old_dotted: str, new_dotted: str) -> str:
    new_pkg, new_leaf = new_dotted.rsplit(".", 1)
    return (
        f'"""Migration shim: ``{old_dotted}`` -> ``{new_dotted}`` (dissolution, llr-lyly).\n\n'
        "sys.modules alias preserving the old import path; re-exports public AND\n"
        'private symbols.  Deleted in Phase Z once consumers repoint.\n"""\n'
        "import sys\n\n"
        f"from {new_pkg} import {new_leaf} as _canonical\n\n"
        "sys.modules[__name__] = _canonical\n"
    )


def _iter_targets(move_map: dict[str, str], only: str | None):
    for old, new in sorted(move_map.items()):
        if only and only not in old and only not in new:
            continue
        yield old, new


def _path_of(dotted: str) -> Path:
    return SRC / Path(*dotted.split(".")).with_suffix(".py")


def run_move(move_map: dict[str, str], only: str | None, *, apply: bool) -> int:
    patterns = tuple((_dotted_pattern(o), n) for o, n in move_map.items())
    n = 0
    for old, new in _iter_targets(move_map, only):
        op, np_ = _path_of(old), _path_of(new)
        if not op.exists():
            continue
        if np_.exists():
            print(f"  FATAL: dest exists {np_}")
            return 2
        n += 1
        print(f"  {'move+shim' if apply else 'would move+shim'}: {op} -> {np_}")
        if apply:
            moved = rewrite_text(op.read_text(encoding="utf-8"), move_map, patterns)
            np_.parent.mkdir(parents=True, exist_ok=True)
            np_.write_text(moved, encoding="utf-8")
            op.write_text(_alias_shim(old, new), encoding="utf-8")
    print(f"\nmove: {'applied' if apply else 'dry-run'} ({n} module(s), only={only!r}).")
    return 0


def run_cutover(move_map: dict[str, str], roots, *, apply: bool) -> int:
    patterns = tuple((_dotted_pattern(o), n) for o, n in move_map.items())
    shim_paths = {_path_of(o).as_posix() for o in move_map}
    changed = 0
    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            if path.as_posix() in shim_paths or path.name.startswith("codemod_"):
                continue
            src = path.read_text(encoding="utf-8")
            out = rewrite_text(src, move_map, patterns)
            if out != src:
                changed += 1
                print(f"  {'rewrote' if apply else 'would rewrite'} {path}")
                if apply:
                    path.write_text(out, encoding="utf-8")
    print(f"\ncutover: {'applied' if apply else 'dry-run'} ({changed} file(s)).")
    return 0


SCAFFOLD = {
    "d810.passes": "Scheduled passes: wire analyses + transforms (dissolution, llr-lyly).",
    "d810.support": "Shared backend-neutral utilities (dissolution, llr-lyly).",
    "d810.pre_analysis": "Read-only pre-analysis collectors (dissolution, llr-lyly).",
}


def run_scaffold(*, apply: bool) -> int:
    for pkg, doc in SCAFFOLD.items():
        initp = SRC / Path(*pkg.split(".")) / "__init__.py"
        if initp.exists():
            print(f"  SKIP {initp} (exists)")
            continue
        print(f"  {'write' if apply else 'would write'} {initp}")
        if apply:
            initp.parent.mkdir(parents=True, exist_ok=True)
            initp.write_text(f'"""{doc}"""\n', encoding="utf-8")
    print("\nReminder: append each new package to the 3 portable-core .importlinter "
          "source_modules IN THE SAME COMMIT (never standalone).")
    return 0


def run_selftest() -> int:
    mm = {
        "d810.cfg.flowgraph": "d810.ir.flowgraph",
        "d810.recon.flow.x_discovery": "d810.analyses.control_flow.x_discovery",
    }
    patterns = tuple((_dotted_pattern(o), n) for o, n in mm.items())
    cases = [
        ("from d810.cfg.flowgraph import FlowGraph",
         "from d810.ir.flowgraph import FlowGraph"),
        # prefix-collision guard: flowgraph must not match flowgraph_utils
        ("from d810.cfg.flowgraph_utils import X", "from d810.cfg.flowgraph_utils import X"),
        ("import d810.recon.flow.x_discovery as d",
         "import d810.analyses.control_flow.x_discovery as d"),
        ("d810.cfg.flowgraph.FlowGraph", "d810.ir.flowgraph.FlowGraph"),
    ]
    ok = True
    for inp, exp in cases:
        got = rewrite_text(inp, mm, patterns)
        good = got == exp
        ok &= good
        print(f"  [{'OK ' if good else 'FAIL'}] {inp}  ->  {got}")
    print("\nALL PASS" if ok else "\nSELFTEST FAILED")
    return 0 if ok else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--stage", required=True,
                   choices=["preflight", "move", "cutover", "scaffold", "selftest"])
    p.add_argument("--apply", action="store_true")
    p.add_argument("--only", help="restrict move/cutover to modules matching this substring")
    p.add_argument("--roots", nargs="*", default=["src", "tests", "tools"])
    args = p.parse_args()

    if args.stage == "selftest":
        return run_selftest()
    if args.stage == "scaffold":
        return run_scaffold(apply=args.apply)

    move_map, unmapped = build_move_map()
    if args.stage == "preflight":
        return run_preflight(move_map, unmapped)
    if args.stage == "move":
        return run_move(move_map, args.only, apply=args.apply)
    if args.stage == "cutover":
        return run_cutover(move_map, tuple(args.roots), apply=args.apply)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
