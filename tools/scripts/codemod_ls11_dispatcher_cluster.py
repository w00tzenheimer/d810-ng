#!/usr/bin/env python3
"""LS11 codemod: relocate the recon/flow dispatcher cluster into
``d810.analyses.control_flow`` and scaffold the net-new dispatcher-resolution /
semantic-transition / automaton types (ticket d81-mt50, playbook SLICE 5).

This single tool drives **every mechanical stage** of LS11, one commit per stage
(the no-combine discipline is preserved by running stages separately and
committing in between):

    --stage c2     move {dispatcher_kind, dispatcher_map->dispatcher_resolution,
                   dispatcher_handler_map} + sys.modules-alias shims + intra rewrites
    --stage c3a    relocate the equality_chain observe hook to the optimizer
                   wrapper (BEHAVIOR edit -> requires --allow-behavior-edit;
                   GC-4 stash-redump golden afterwards)
    --stage c3b    move the remaining 7 cluster modules (state_transition_resolution
                   ->semantic_transition, branch_ownership, predecessor_dispatcher_target,
                   equality_chain_dispatcher, indirect_jump_table_analysis,
                   switch_case_transition_analysis, dispatcher_discovery_facts)
                   + alias shims + intra rewrites (+ FactObservation repoint)
    --stage c9     repoint all consumers off the recon shims onto the new homes;
                   with --delete-shims, remove the shim files after proving zero
                   importers remain
    --stage scaffold   write the net-new C5/C8 module skeletons and print the
                   in-file C4/C6/C7 insertion snippets (these are AUTHORED with
                   tests per the ticket; the codemod only scaffolds)

Design choices grounded against HEAD (see ticket d81-mt50):
  * **sys.modules-alias shims for ALL moved modules.** A plain ``import *`` shim
    would drop the PRIVATE symbol ``_unresolved_fact`` that
    ``switch_case_transitions.py:112`` imports from
    ``switch_case_transition_analysis`` -> ``ImportError`` (the risk-register
    trap).  The alias re-exports public AND private names with zero enumeration.
  * **Hybrid rewrite (project template): libcst FIRST, then a boundary-aware
    regex text pass** -- mirrors ``codemod_rename_mba_backends.py``.  libcst
    rewrites ``ImportFrom`` / ``ImportAlias`` nodes robustly (matching whole
    dotted MODULE nodes, so it is inherently free of the
    ``branch_ownership`` vs ``branch_ownership_oracle`` prefix-collision class);
    the regex pass then catches the references libcst preserves verbatim --
    docstrings, comments, ``importlib`` / RuntimeError string literals, and
    fully-qualified attribute access used in code (not in an import).  If a file
    fails to parse, the pass falls back to regex-only for that file.
  * The ONE form neither pass rewrites is a bare-leaf rename
    (``from d810.recon.flow import dispatcher_map`` where the leaf renames to a
    different parent).  Verified ABSENT in the tree; ``_bare_leaf_importers()``
    guards both the cutover and shim-deletion and fails loudly if one ever
    appears (it would also be a false-negative for the deletion scan otherwise).
  * The 4 ``to_dispatcher_handler_map`` METHOD-CALL sites are naturally skipped:
    a dotted MODULE path ``d810.recon.flow.dispatcher_handler_map`` never matches
    the attribute access ``x.to_dispatcher_handler_map()``.

Default is dry-run; pass --apply to write.  Run from the worktree root with
``pyenv exec``.  After every applied stage::

    PYTHONPATH=src lint-imports --config .importlinter      # 13 kept / 0 broken
    sg scan --config sgconfig.yml --report-style short      # clean
    PYTHONPATH=src:tests pyenv exec python -m pytest tests/unit/ -q   # no regress
"""
from __future__ import annotations

import argparse
import difflib
import re
from dataclasses import dataclass
from pathlib import Path

import libcst as cst

OLD_PKG = "d810.recon.flow"
NEW_PKG = "d810.analyses.control_flow"
RECON_FLOW_DIR = Path("src/d810/recon/flow")
ANALYSES_CF_DIR = Path("src/d810/analyses/control_flow")


@dataclass(frozen=True)
class ClusterModule:
    old_leaf: str
    new_leaf: str  # == old_leaf when there is no rename
    stage: str  # "c2" | "c3b"

    @property
    def old_dotted(self) -> str:
        return f"{OLD_PKG}.{self.old_leaf}"

    @property
    def new_dotted(self) -> str:
        return f"{NEW_PKG}.{self.new_leaf}"

    @property
    def old_path(self) -> Path:
        return RECON_FLOW_DIR / f"{self.old_leaf}.py"

    @property
    def new_path(self) -> Path:
        return ANALYSES_CF_DIR / f"{self.new_leaf}.py"


# Stage assignment + the two renames (dispatcher_map->dispatcher_resolution,
# state_transition_resolution->semantic_transition).  Verified intra-cluster
# graph: C2 modules never import a C3b module, so C2 is self-contained.
CLUSTER: tuple[ClusterModule, ...] = (
    ClusterModule("dispatcher_kind", "dispatcher_kind", "c2"),
    ClusterModule("dispatcher_map", "dispatcher_resolution", "c2"),
    ClusterModule("dispatcher_handler_map", "dispatcher_handler_map", "c2"),
    ClusterModule("state_transition_resolution", "semantic_transition", "c3b"),
    ClusterModule("branch_ownership", "branch_ownership", "c3b"),
    ClusterModule("predecessor_dispatcher_target", "predecessor_dispatcher_target", "c3b"),
    ClusterModule("equality_chain_dispatcher", "equality_chain_dispatcher", "c3b"),
    ClusterModule("indirect_jump_table_analysis", "indirect_jump_table_analysis", "c3b"),
    ClusterModule("switch_case_transition_analysis", "switch_case_transition_analysis", "c3b"),
    ClusterModule("dispatcher_discovery_facts", "dispatcher_discovery_facts", "c3b"),
)

# Longest-prefix-first so e.g. ".dispatcher_map" is rewritten before any shorter
# colliding prefix.  Applied to file CONTENT (covers from/import/as/string forms).
def _replacements() -> tuple[tuple[str, str], ...]:
    pairs = [(m.old_dotted, m.new_dotted) for m in CLUSTER]
    pairs.sort(key=lambda p: len(p[0]), reverse=True)
    return tuple(pairs)


REPLACEMENTS = _replacements()

# dispatcher_discovery_facts imports FactObservation from the retained recon
# model shim; once it lands in analyses/ that import is upward-fatal.  Repoint it
# to the canonical observation home -- ONLY inside that one moved file.
FACTOBS_OLD = "d810.recon.facts.model"
FACTOBS_NEW = "d810.analyses.value_flow.observation"

# Files whose path ends with one of these are migration shims / this tool / the
# template: never rewrite them during the consumer cutover.
def _shim_suffixes() -> tuple[str, ...]:
    return tuple(m.old_path.as_posix() for m in CLUSTER)


def iter_python_files(roots: tuple[str, ...]) -> list[Path]:
    """*.py under roots, excluding caches and (root-relative) .worktrees."""
    out: list[Path] = []
    root_cwd = Path.cwd()
    for root in roots:
        base = Path(root)
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.py")):
            rel = path.resolve().relative_to(root_cwd).as_posix()
            if rel.startswith(".worktrees/") or "__pycache__/" in rel:
                continue
            out.append(path)
    return out


def _dotted_pattern(dotted: str) -> re.Pattern[str]:
    """Match a dotted module path only at an identifier boundary, so e.g.
    ``d810.recon.flow.branch_ownership`` never matches inside the non-cluster
    ``d810.recon.flow.branch_ownership_oracle``.  A trailing ``.`` (submodule /
    attribute access) is allowed; a trailing ``[A-Za-z0-9_]`` is not."""
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(dotted) + r"(?![A-Za-z0-9_])")


_REPL_PATTERNS = tuple((_dotted_pattern(old), new) for old, new in REPLACEMENTS)
_FACTOBS_PATTERN = _dotted_pattern(FACTOBS_OLD)


def _rewrite_dotted(code: str, *, factobs: bool) -> str | None:
    """Longest-prefix dotted-module rewrite for a libcst module/name node string.
    Boundary-safe by construction: only an exact match or a ``<old>.`` submodule
    prefix rewrites (REPLACEMENTS is longest-first)."""
    for old, new in REPLACEMENTS:
        if code == old or code.startswith(old + "."):
            return new + code[len(old):]
    if factobs and (code == FACTOBS_OLD or code.startswith(FACTOBS_OLD + ".")):
        return FACTOBS_NEW + code[len(FACTOBS_OLD):]
    return None


class _ClusterRenameTransformer(cst.CSTTransformer):
    """Rewrites import-statement nodes (the structural, edge-case-prone part).
    Matches the ``codemod_rename_mba_backends`` idiom, generalized to the LS11
    rename map + the scoped FactObservation repoint."""

    def __init__(self, *, factobs: bool) -> None:
        self._factobs = factobs

    def leave_ImportFrom(
        self, original_node: cst.ImportFrom, updated_node: cst.ImportFrom
    ) -> cst.ImportFrom:
        module = updated_node.module
        if module is None:
            return updated_node
        code = cst.Module([]).code_for_node(module)
        new = _rewrite_dotted(code, factobs=self._factobs)
        if new is not None:
            return updated_node.with_changes(module=cst.parse_expression(new))
        return updated_node

    def leave_ImportAlias(
        self, original_node: cst.ImportAlias, updated_node: cst.ImportAlias
    ) -> cst.ImportAlias:
        code = cst.Module([]).code_for_node(updated_node.name)
        new = _rewrite_dotted(code, factobs=self._factobs)
        if new is not None:
            return updated_node.with_changes(name=cst.parse_expression(new))
        return updated_node


def _regex_pass(text: str, *, factobs: bool) -> str:
    out = text
    for pat, new in _REPL_PATTERNS:
        out = pat.sub(new, out)
    if factobs:
        out = _FACTOBS_PATTERN.sub(FACTOBS_NEW, out)
    return out


def rewrite_text(text: str, *, factobs: bool = False) -> str:
    """Hybrid: libcst rewrites import nodes, then the boundary-regex text pass
    catches strings/comments/docstrings/FQ-attribute refs libcst preserves
    verbatim.  Running regex AFTER libcst is idempotent (libcst already replaced
    the OLD path in import nodes, so the regex only hits residual OLD strings).
    Falls back to regex-only if a file does not parse."""
    try:
        module = cst.parse_module(text)
        text = module.visit(_ClusterRenameTransformer(factobs=factobs)).code
    except Exception as exc:  # non-parseable file -> regex-only, but say so
        print(f"    (libcst parse failed: {type(exc).__name__}; regex-only fallback)")
    return _regex_pass(text, factobs=factobs)


# Bare-leaf rename form ``from d810.recon.flow import {dispatcher_map|
# state_transition_resolution|...}`` is the one shape neither pass rewrites (and
# a false-negative for the deletion scan).  Verified absent; guard anyway.
_BARE_LEAF_RE = re.compile(
    r"from\s+d810\.recon\.flow\s+import\s+(?P<names>[^\n#]+)"
)
_CLUSTER_LEAVES = frozenset(m.old_leaf for m in CLUSTER)


def _bare_leaf_importers(roots: tuple[str, ...]) -> list[str]:
    shim_suffixes = _shim_suffixes()
    hits: list[str] = []
    for path in iter_python_files(roots):
        posix = path.as_posix()
        if any(posix.endswith(s) for s in shim_suffixes) or path.name.startswith("codemod_"):
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            mobj = _BARE_LEAF_RE.search(line)
            if not mobj:
                continue
            names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", mobj.group("names"))
            if _CLUSTER_LEAVES.intersection(names):
                hits.append(f"{path}:{i}: {line.strip()}")
    return hits


def _alias_shim(mod: ClusterModule) -> str:
    return (
        f'"""Migration shim: ``{mod.old_dotted}`` relocated to '
        f"``{mod.new_dotted}`` (LS11, ticket d81-mt50).\n\n"
        "sys.modules alias that preserves the old import path during the LS11\n"
        "dispatcher-cluster relocation.  Re-exports every public AND private\n"
        "symbol of the canonical module.  Deleted in LS11 C9 once all consumers\n"
        'repoint to the canonical home.\n"""\n'
        "import sys\n\n"
        f"from {NEW_PKG} import {mod.new_leaf} as _canonical\n\n"
        "sys.modules[__name__] = _canonical\n"
    )


def _preview(path: Path, before: str, after: str) -> None:
    for line in difflib.unified_diff(
        before.splitlines(), after.splitlines(),
        fromfile=str(path), tofile=str(path), lineterm="",
    ):
        print(line)


# --------------------------------------------------------------------------- #
# move stages (c2, c3b)
# --------------------------------------------------------------------------- #
def run_move_stage(stage: str, *, apply: bool) -> int:
    mods = [m for m in CLUSTER if m.stage == stage]
    if not ANALYSES_CF_DIR.exists():
        print(f"FATAL: {ANALYSES_CF_DIR} missing (LS6 should have created it).")
        return 2
    errors = 0
    for m in mods:
        if not m.old_path.exists():
            print(f"  SKIP {m.old_leaf}: {m.old_path} absent "
                  "(already moved? rerun is idempotent-ish but check git).")
            continue
        if m.new_path.exists():
            print(f"  FATAL {m.old_leaf}: destination {m.new_path} already exists.")
            errors += 1
            continue
        original = m.old_path.read_text(encoding="utf-8")
        moved = rewrite_text(
            original, factobs=(m.old_leaf == "dispatcher_discovery_facts")
        )
        shim = _alias_shim(m)
        verb = "move+shim" if apply else "would move+shim"
        print(f"  {verb}: {m.old_path}  ->  {m.new_path}")
        if not apply:
            if moved != original:
                print("    --- intra-cluster import rewrites in moved file ---")
                _preview(m.new_path, original, moved)
            print("    --- shim to be written at old path ---")
            for ln in shim.splitlines():
                print(f"    | {ln}")
            continue
        # content already captured in `moved`; write the canonical file, then
        # overwrite the old path in place with the alias shim.
        m.new_path.write_text(moved, encoding="utf-8")
        m.old_path.write_text(shim, encoding="utf-8")
    print(f"\n{stage}: {'applied' if apply else 'dry-run'} ({len(mods)} module(s)). "
          "Next: lint-imports 13/0, sg clean, pytest unit no-regress, then commit.")
    return 2 if errors else 0


# --------------------------------------------------------------------------- #
# c3a -- behavior edit (relocate the equality_chain observe hook)
# --------------------------------------------------------------------------- #
RECON_EQ = RECON_FLOW_DIR / "equality_chain_dispatcher.py"
WRAPPER_EQ = Path("src/d810/optimizers/microcode/flow/dispatcher/equality_chain.py")

# exact anchors captured from HEAD
C3A_RECON_CALL = (
    "    _observe_state_dispatcher_map(mba, dispatch_map)\n"
    "    return dispatch_map\n"
)
C3A_RECON_CALL_NEW = "    return dispatch_map\n"

C3A_HELPER_BLOCK = '''def _observe_state_dispatcher_map(
    mba: object,
    dispatch_map: StateDispatcherMap,
) -> None:
    """Publish equality-chain rows for the diag DB when observability is on."""
    try:
        from d810.recon.observability import observe_state_dispatcher_rows

        observe_state_dispatcher_rows(
            func_ea=int(getattr(mba, "entry_ea", 0) or 0),
            maturity=_maturity_name(int(getattr(mba, "maturity", -1) or -1)),
            dispatcher_entry_block=int(dispatch_map.dispatcher_entry_block),
            dispatcher_kind=dispatch_map.router_kind.name,
            rows=dispatch_map.rows,
        )
    except Exception:
        return


'''

C3A_MATURITY_BLOCK = '''def _maturity_name(maturity: int) -> str:
    names = {
        0: "MMAT_GENERATED",
        1: "MMAT_PREOPTIMIZED",
        2: "MMAT_LOCOPT",
        3: "MMAT_CALLS",
        4: "MMAT_GLBOPT1",
        5: "MMAT_GLBOPT2",
        6: "MMAT_GLBOPT3",
        7: "MMAT_LVARS",
    }
    return names.get(int(maturity), f"MMAT_{int(maturity)}")


'''

C3A_WRAPPER_RETURN = (
    "    return extract_state_dispatcher_map_from_mba(\n"
    "        view,\n"
    "        dispatcher_entry_block=dispatcher_entry_block,\n"
    "        max_depth=max_depth,\n"
    "    )\n"
)
C3A_WRAPPER_RETURN_NEW = (
    "    dispatch_map = extract_state_dispatcher_map_from_mba(\n"
    "        view,\n"
    "        dispatcher_entry_block=dispatcher_entry_block,\n"
    "        max_depth=max_depth,\n"
    "    )\n"
    "    if dispatch_map is not None:\n"
    "        _observe_state_dispatcher_map(mba, dispatch_map)\n"
    "    return dispatch_map\n"
)
# the observe helper + _maturity_name, relocated verbatim to the wrapper module.
# StateDispatcherMap is already imported at the wrapper top; the helper keeps its
# lazy ``from d810.recon.observability import ...`` (optimizers->recon is DOWN).
C3A_WRAPPER_APPEND = "\n\n" + C3A_HELPER_BLOCK.rstrip("\n") + "\n\n\n" + C3A_MATURITY_BLOCK.rstrip("\n") + "\n"


def run_c3a(*, apply: bool, allow_behavior: bool) -> int:
    if not RECON_EQ.exists() or not WRAPPER_EQ.exists():
        print("FATAL: c3a anchors missing (run c3a BEFORE c3b moves the module).")
        return 2
    recon = RECON_EQ.read_text(encoding="utf-8")
    wrapper = WRAPPER_EQ.read_text(encoding="utf-8")

    checks = {
        "recon observe-call anchor": C3A_RECON_CALL in recon,
        "recon helper block anchor": C3A_HELPER_BLOCK in recon,
        "recon _maturity_name anchor": C3A_MATURITY_BLOCK in recon,
        "wrapper return anchor": C3A_WRAPPER_RETURN in wrapper,
        "wrapper not already edited": "_observe_state_dispatcher_map" not in wrapper,
    }
    print("c3a precondition checks:")
    for name, ok in checks.items():
        print(f"  [{'OK ' if ok else 'XX '}] {name}")
    if not all(checks.values()):
        print("FATAL: anchors drifted -- refusing to edit. Re-ground against HEAD.")
        return 2

    new_recon = recon.replace(C3A_RECON_CALL, C3A_RECON_CALL_NEW, 1)
    new_recon = new_recon.replace(C3A_HELPER_BLOCK, "", 1)
    new_recon = new_recon.replace(C3A_MATURITY_BLOCK, "", 1)
    new_wrapper = wrapper.replace(C3A_WRAPPER_RETURN, C3A_WRAPPER_RETURN_NEW, 1)
    new_wrapper = new_wrapper.rstrip("\n") + "\n" + C3A_WRAPPER_APPEND

    print("\n*** c3a is a BEHAVIOR edit (diag side-effect relocation). ***")
    print("    GC-4: after applying, stash-redump sub_7FFD (268/8/1/10/10/19, "
          "gates 12/12) + _hodur_func (114/3/0/1/48/11, gates 4/4); counters MUST "
          "be unaffected (golden dumps run observability OFF).")
    if not apply or not allow_behavior:
        print("\n(dry-run / behavior edit not authorized -- pass "
              "--apply --allow-behavior-edit to write)")
        print("\n--- recon equality_chain_dispatcher.py ---")
        _preview(RECON_EQ, recon, new_recon)
        print("\n--- optimizer wrapper equality_chain.py ---")
        _preview(WRAPPER_EQ, wrapper, new_wrapper)
        return 0
    RECON_EQ.write_text(new_recon, encoding="utf-8")
    WRAPPER_EQ.write_text(new_wrapper, encoding="utf-8")
    print("\napplied c3a. RUN GC-4 NOW before committing.")
    return 0


# --------------------------------------------------------------------------- #
# c9 -- consumer cutover + shim deletion
# --------------------------------------------------------------------------- #
def run_cutover(roots: tuple[str, ...], *, apply: bool, delete_shims: bool) -> int:
    shim_suffixes = _shim_suffixes()
    changed = 0
    for path in iter_python_files(roots):
        posix = path.as_posix()
        if any(posix.endswith(s) for s in shim_suffixes):
            continue  # never rewrite the shims (deleted below)
        if path.name.startswith("codemod_"):
            continue  # mapping strings in codemods are intentional
        src = path.read_text(encoding="utf-8")
        out = rewrite_text(src)  # no factobs: only the moved module repoints that
        if out == src:
            continue
        changed += 1
        if apply:
            path.write_text(out, encoding="utf-8")
            print(f"  rewrote {path}")
        else:
            print(f"  would rewrite {path}")
    print(f"\ncutover: {'applied' if apply else 'dry-run'} ({changed} file(s)).")

    # bare-leaf rename form is unrewritable by BOTH passes -- flag loudly.
    bare = _bare_leaf_importers(roots)
    if bare:
        print("\nWARNING: bare-leaf `from d810.recon.flow import <cluster-leaf>` "
              "found -- neither libcst nor regex rewrites these; fix by hand:")
        for line in bare[:40]:
            print(f"  {line}")

    # shim deletion -- only after proving zero importers of the old dotted paths
    remaining = _scan_old_importers(roots)
    if remaining or bare:
        if remaining:
            print("\nshims NOT safe to delete -- old-path importers remain:")
            for line in remaining[:40]:
                print(f"  {line}")
        if delete_shims:
            print("FATAL: --delete-shims refused (unresolved importers / bare-leaf).")
            return 2
        return 0
    print("\nno old-path importers remain (lazy/in-function bodies scanned).")
    if not delete_shims:
        print("re-run with --delete-shims --apply to remove the shim files.")
        return 0
    for m in CLUSTER:
        if m.old_path.exists():
            print(f"  {'delete' if apply else 'would delete'} shim {m.old_path}")
            if apply:
                m.old_path.unlink()
    return 0


def _scan_old_importers(roots: tuple[str, ...]) -> list[str]:
    """Grep both import forms AND in-function bodies for any surviving old path,
    excluding the shims themselves and codemod scripts."""
    shim_suffixes = _shim_suffixes()
    # boundary-aware so the non-cluster ``branch_ownership_oracle`` import does
    # not false-positive against the ``branch_ownership`` needle.
    needles = tuple(_dotted_pattern(m.old_dotted) for m in CLUSTER)
    hits: list[str] = []
    for path in iter_python_files(roots):
        posix = path.as_posix()
        if any(posix.endswith(s) for s in shim_suffixes) or path.name.startswith("codemod_"):
            continue
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(pat.search(line) for pat in needles):
                hits.append(f"{path}:{i}: {line.strip()}")
    return hits


# --------------------------------------------------------------------------- #
# scaffold -- net-new C5/C8 files + printed C4/C6/C7 insertion snippets
# --------------------------------------------------------------------------- #
SCAFFOLD_C5 = Path("src/d810/capabilities/dispatcher.py")
SCAFFOLD_C8_RESOLVER = Path("src/d810/families/state_machine_cff/dispatcher_resolver.py")
SCAFFOLD_C8_AUTOMATON = ANALYSES_CF_DIR / "state_machine.py"

SCAFFOLD_FILES: dict[Path, str] = {
    SCAFFOLD_C5: '''"""LS11 C5: portable router-kind enum + state-machine seed (ticket d81-mt50).

Lives in ``d810.capabilities`` (layer below cfg/analyses).  ``FunctionId`` /
``BlockRef`` / ``collector_analysis`` are ``Any``-typed because
``capabilities -> cfg`` and ``capabilities -> analyses`` are UPWARD-FATAL;
``capabilities -> ir`` is the only legal structural dependency (precedent:
``capabilities/use_def_safety.py``).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from d810.core.typing import Any

__all__ = ["RouterKind", "StateMachineSeed"]


class RouterKind(str, enum.Enum):
    BST = "bst"
    SWITCH = "switch"
    EQUALITY_CHAIN = "equality_chain"
    CONDITION_CHAIN = "condition_chain"
    INDIRECT_TABLE = "indirect_table"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class StateMachineSeed:
    """Cheap pre-resolution inputs a DispatcherResolver consumes (design doc)."""

    function_id: Any  # FunctionId (cfg/ir) -- Any to stay below the layer line
    candidate_entries: tuple[Any, ...] = ()  # tuple[BlockRef, ...]
    collector_analysis: Any | None = None
    profile_name: str = ""
''',
    SCAFFOLD_C8_RESOLVER: '''"""LS11 C8: DispatcherResolver protocol (ticket d81-mt50).

First ``families -> capabilities`` edge in the tree (DOWN-legal).  Any-typing
precedent: ``families/state_machine_cff/protocols.py``.  ``accepts()`` returns
ranked evidence (``ResolverCandidate``), NEVER ``bool``; ``resolve()`` may fail
after ``accepts()`` succeeds.
"""
from __future__ import annotations

from d810.core.typing import Any, Protocol, runtime_checkable

from d810.capabilities.dispatcher import RouterKind, StateMachineSeed

__all__ = ["DispatcherResolver"]


@runtime_checkable
class DispatcherResolver(Protocol):
    name: str
    router_kind: RouterKind

    def accepts(self, seed: StateMachineSeed, entry: Any) -> Any | None:
        """Return a ResolverCandidate (ranked evidence) or None.  NOT a bool."""
        ...

    def resolve(self, seed: StateMachineSeed, candidate: Any) -> Any | None:
        """Return a DispatcherResolution or None (may fail after accepts())."""
        ...
''',
    SCAFFOLD_C8_AUTOMATON: '''"""LS11 C8: cyclic semantic automaton + acyclic DAG projection (ticket d81-mt50).

The recognition graph ("what did we prove") may be cyclic; ``StateDagView`` is the
optional acyclic projection used for linearization.  Distinct from the lowering
graph (LS12).  Net-new + unwired in LS11.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from d810.core.typing import Any

__all__ = ["SemanticGraph", "StateDagView"]


@dataclass(frozen=True)
class SemanticGraph:
    """Possibly-cyclic direct semantic CFG over recovered states."""

    states: tuple[Any, ...] = ()          # state ids / refs
    edges: tuple[tuple[Any, Any], ...] = ()  # (src_state, dst_state)
    has_cycles: bool = False


@dataclass(frozen=True)
class StateDagView:
    """Acyclic projection of a SemanticGraph for safe linearization."""

    ordered_states: tuple[Any, ...] = ()
    edges: tuple[tuple[Any, Any], ...] = ()
'''
}

SCAFFOLD_SNIPPETS = """
=== C4 (edit analyses/control_flow/semantic_transition.py) ===
Add value-identity fields using the REAL d810.ir.ValueRef (LS8 landed; no typed-hole):
    from d810.ir import ValueRef            # analyses -> ir is DOWN-legal
    # extend StateTransitionFact / SemanticTransition with: subject: ValueRef | None

=== C6 (edit analyses/control_flow/dispatcher_resolution.py) ===
Add, and append both names to __all__:
    @dataclass(frozen=True)
    class ResolverCandidate:
        resolver_name: str
        router_kind: "RouterKind"
        confidence: float
        specificity: int = 0
        reasons: tuple[str, ...] = ()

    @dataclass(frozen=True)
    class DispatcherResolution:
        dispatcher_map: StateDispatcherMap
        resolver_name: str
        router_kind: "RouterKind"
        confidence: float
        ranking_reason: tuple[str, ...] = ()
    # import RouterKind from d810.capabilities.dispatcher (analyses -> capabilities DOWN)

=== C7 (edit analyses/control_flow/semantic_transition.py) ===
Add SemanticTransition + a projection from the moved StateTransitionFact, and
append to __all__:
    class SemanticTransitionKind(str, enum.Enum):
        HANDLER_WRITE = "handler_write"; CASE_WRITE = "case_write"
        LOOP_UPDATE = "loop_update"; CARRIED_STATE = "carried_state"
        CONDITIONAL_RETURN = "conditional_return"; EXIT_ROUTINE = "exit_routine"
        UNKNOWN = "unknown"
    @dataclass(frozen=True)
    class SemanticTransition: ...   # + def semantic_transition_from_fact(f) -> SemanticTransition
"""


def run_scaffold(*, apply: bool) -> int:
    for path, body in SCAFFOLD_FILES.items():
        if path.exists():
            print(f"  SKIP {path} (already exists)")
            continue
        print(f"  {'write' if apply else 'would write'} {path}")
        if apply:
            path.write_text(body, encoding="utf-8")
    print("\nIn-file additions (authored WITH tests per ticket, not codemodded):")
    print(SCAFFOLD_SNIPPETS)
    print("Remember: create-package-then-add-to-.importlinter source_modules in "
          "the SAME commit; add structural tests under tests/unit/.")
    return 0


# --------------------------------------------------------------------------- #
# selftest -- guards the module-boundary replacement (prefix-collision class)
# --------------------------------------------------------------------------- #
def run_selftest() -> int:
    cases = [
        ("from d810.recon.flow.branch_ownership import X",
         "from d810.analyses.control_flow.branch_ownership import X"),
        # MUST NOT touch the non-cluster oracle (branch_ownership is a prefix):
        ("from d810.recon.flow.branch_ownership_oracle import X",
         "from d810.recon.flow.branch_ownership_oracle import X"),
        ("import d810.recon.flow.switch_case_transition_analysis as s",
         "import d810.analyses.control_flow.switch_case_transition_analysis as s"),
        ("d810.recon.flow.dispatcher_map.StateDispatcherMap",
         "d810.analyses.control_flow.dispatcher_resolution.StateDispatcherMap"),
        ("x.to_dispatcher_handler_map()", "x.to_dispatcher_handler_map()"),
        ("from d810.recon.flow.state_transition_resolution import R",
         "from d810.analyses.control_flow.semantic_transition import R"),
    ]
    ok = True
    for inp, exp in cases:
        got = rewrite_text(inp)
        good = got == exp
        ok &= good
        print(f"  [{'OK ' if good else 'FAIL'}] {inp}  ->  {got}")
    fo = rewrite_text("from d810.recon.facts.model import FactObservation", factobs=True)
    fo2 = rewrite_text("from d810.recon.facts.model import FactObservation", factobs=False)
    ok &= fo == "from d810.analyses.value_flow.observation import FactObservation"
    ok &= "recon.facts.model" in fo2
    print(f"  [{'OK ' if fo.endswith('observation import FactObservation') else 'FAIL'}] factobs repoint (scoped to dispatcher_discovery_facts)")
    print(f"  [{'OK ' if 'recon.facts.model' in fo2 else 'FAIL'}] no-factobs leaves the model shim alone")
    print("\nALL PASS" if ok else "\nSELFTEST FAILED")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--stage", required=True,
                   choices=["c2", "c3a", "c3b", "c9", "scaffold", "selftest"])
    p.add_argument("--apply", action="store_true", help="write changes (default dry-run)")
    p.add_argument("--allow-behavior-edit", action="store_true",
                   help="authorize the c3a behavior edit (GC-4 golden required after)")
    p.add_argument("--delete-shims", action="store_true",
                   help="c9 only: delete shim files after proving zero importers")
    p.add_argument("--roots", nargs="*", default=["src", "tests", "tools"],
                   help="roots scanned by c9 cutover (default: src tests tools)")
    args = p.parse_args()

    if args.stage in ("c2", "c3b"):
        return run_move_stage(args.stage, apply=args.apply)
    if args.stage == "c3a":
        return run_c3a(apply=args.apply, allow_behavior=args.allow_behavior_edit)
    if args.stage == "c9":
        return run_cutover(tuple(args.roots), apply=args.apply, delete_shims=args.delete_shims)
    if args.stage == "scaffold":
        return run_scaffold(apply=args.apply)
    if args.stage == "selftest":
        return run_selftest()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
