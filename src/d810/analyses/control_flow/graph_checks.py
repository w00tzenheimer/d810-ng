"""Semantic correctness checks for post-linearization CFG."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from d810.analyses.control_flow.edit_simulation import SimulatedEdit, simulate_edits
from d810.ir.flowgraph import BlockKind, FlowGraph, InsnKind


@dataclass(frozen=True)
class TerminalCycle:
    """A terminal block that unexpectedly re-enters the handler/dispatcher region."""

    terminal_block: int
    reentry_target: int
    path: list[int] = field(default_factory=list)


@dataclass
class SemanticCheckResult:
    """Result of a semantic verification check."""

    passed: bool
    cycles: list[TerminalCycle] = field(default_factory=list)
    diagnostics: dict[str, object] = field(default_factory=dict)


@dataclass
class StructuralCheckResult:
    """Result of structural legality checks before live apply."""

    passed: bool
    reason: str = ""
    diagnostics: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TerminalReachabilityResult:
    """Result of checking that a reachable terminal route stays reachable."""

    passed: bool
    pre_reachable_terminals: frozenset[int]
    post_reachable_terminals: frozenset[int]
    pre_reachable_count: int
    post_reachable_count: int
    reason: str = ""


@dataclass(frozen=True)
class EntryReachabilityResult:
    """Result of checking that a rewrite does not collapse entry reachability."""

    passed: bool
    pre_reachable_count: int
    post_reachable_count: int
    retained_ratio: float
    min_pre_reachable: int
    min_retained_ratio: float
    reason: str = ""


def reachable_from_adjacency(
    adj: dict[int, list[int]] | dict[int, tuple[int, ...]],
    entry_serial: int,
) -> frozenset[int]:
    """Return nodes reachable from *entry_serial* in an adjacency map."""
    if entry_serial not in adj:
        return frozenset()

    visited: set[int] = set()
    queue: deque[int] = deque([int(entry_serial)])
    while queue:
        serial = queue.popleft()
        if serial in visited or serial not in adj:
            continue
        visited.add(serial)
        queue.extend(int(succ) for succ in adj.get(serial, ()))
    return frozenset(visited)


_BADADDR_64 = 0xFFFFFFFFFFFFFFFF


def _is_explicit_terminal_block(block: object) -> bool:
    if getattr(block, "kind", None) is BlockKind.STOP:
        return True
    if getattr(block, "tail_kind", None) is InsnKind.RET:
        return True
    try:
        start_ea = int(getattr(block, "start_ea", -1) or -1)
    except (TypeError, ValueError):
        start_ea = -1
    succs = getattr(block, "succs", ()) or ()
    return start_ea == _BADADDR_64 and len(succs) == 0


def _terminal_block_serials(cfg: FlowGraph) -> frozenset[int]:
    return frozenset(
        int(serial)
        for serial, block in cfg.blocks.items()
        if _is_explicit_terminal_block(block)
    )


def reachable_terminal_blocks(cfg: FlowGraph) -> frozenset[int]:
    """Return explicit terminal blocks reachable from the CFG entry."""
    reachable = reachable_from_adjacency(cfg.as_adjacency_dict(), cfg.entry_serial)
    return frozenset(_terminal_block_serials(cfg) & reachable)


def reachable_terminal_blocks_from_adjacency(
    cfg: FlowGraph,
    adj: dict[int, list[int]] | dict[int, tuple[int, ...]],
) -> frozenset[int]:
    """Return CFG terminal blocks reachable in an alternate adjacency map."""
    reachable = reachable_from_adjacency(adj, cfg.entry_serial)
    return frozenset(_terminal_block_serials(cfg) & reachable)


def check_terminal_reachability_preserved(
    pre_cfg: FlowGraph,
    *,
    post_cfg: FlowGraph | None = None,
    post_adj: dict[int, list[int]] | dict[int, tuple[int, ...]] | None = None,
) -> TerminalReachabilityResult:
    """Require a reachable terminal route before a rewrite to remain reachable.

    General block reachability stays diagnostic-only for cleanup stages.  This
    check is narrower: if the pre-state has a reachable explicit terminal block,
    a simulated or live post-state may not make all terminal blocks unreachable.
    """
    if (post_cfg is None) == (post_adj is None):
        raise ValueError("provide exactly one of post_cfg or post_adj")

    pre_reachable = reachable_from_adjacency(
        pre_cfg.as_adjacency_dict(),
        pre_cfg.entry_serial,
    )
    pre_terminals = frozenset(_terminal_block_serials(pre_cfg) & pre_reachable)

    if post_cfg is not None:
        post_reachable = reachable_from_adjacency(
            post_cfg.as_adjacency_dict(),
            post_cfg.entry_serial,
        )
        post_terminals = frozenset(_terminal_block_serials(post_cfg) & post_reachable)
    else:
        post_reachable = reachable_from_adjacency(post_adj or {}, pre_cfg.entry_serial)
        post_terminals = frozenset(_terminal_block_serials(pre_cfg) & post_reachable)

    if pre_terminals and not post_terminals:
        return TerminalReachabilityResult(
            passed=False,
            pre_reachable_terminals=pre_terminals,
            post_reachable_terminals=post_terminals,
            pre_reachable_count=len(pre_reachable),
            post_reachable_count=len(post_reachable),
            reason="all reachable terminal routes became unreachable",
        )
    return TerminalReachabilityResult(
        passed=True,
        pre_reachable_terminals=pre_terminals,
        post_reachable_terminals=post_terminals,
        pre_reachable_count=len(pre_reachable),
        post_reachable_count=len(post_reachable),
    )


def check_entry_reachability_not_collapsed(
    pre_cfg: FlowGraph,
    *,
    post_cfg: FlowGraph | None = None,
    post_adj: dict[int, list[int]] | dict[int, tuple[int, ...]] | None = None,
    min_pre_reachable: int = 20,
    min_retained_ratio: float = 0.5,
) -> EntryReachabilityResult:
    """Reject rewrites that collapse a broad entry component into a tiny island."""
    if (post_cfg is None) == (post_adj is None):
        raise ValueError("provide exactly one of post_cfg or post_adj")

    pre_reachable = reachable_from_adjacency(
        pre_cfg.as_adjacency_dict(),
        pre_cfg.entry_serial,
    )
    if post_cfg is not None:
        post_reachable = reachable_from_adjacency(
            post_cfg.as_adjacency_dict(),
            post_cfg.entry_serial,
        )
    else:
        post_reachable = reachable_from_adjacency(post_adj or {}, pre_cfg.entry_serial)

    return check_entry_reachability_counts_not_collapsed(
        pre_reachable_count=len(pre_reachable),
        post_reachable_count=len(post_reachable),
        min_pre_reachable=min_pre_reachable,
        min_retained_ratio=min_retained_ratio,
    )


def check_entry_reachability_counts_not_collapsed(
    *,
    pre_reachable_count: int,
    post_reachable_count: int,
    min_pre_reachable: int = 20,
    min_retained_ratio: float = 0.5,
) -> EntryReachabilityResult:
    """Evaluate entry reachability preservation from already-computed counts."""
    pre_count = int(pre_reachable_count)
    post_count = int(post_reachable_count)
    retained_ratio = (post_count / pre_count) if pre_count else 1.0

    if pre_count >= min_pre_reachable and retained_ratio < min_retained_ratio:
        return EntryReachabilityResult(
            passed=False,
            pre_reachable_count=pre_count,
            post_reachable_count=post_count,
            retained_ratio=retained_ratio,
            min_pre_reachable=min_pre_reachable,
            min_retained_ratio=min_retained_ratio,
            reason="entry reachability collapsed",
        )
    return EntryReachabilityResult(
        passed=True,
        pre_reachable_count=pre_count,
        post_reachable_count=post_count,
        retained_ratio=retained_ratio,
        min_pre_reachable=min_pre_reachable,
        min_retained_ratio=min_retained_ratio,
    )


def check_edge_split_structural_legality(
    adj: dict[int, list[int]],
    edits: list[SimulatedEdit],
) -> StructuralCheckResult:
    """Validate edge-split edits against pre-apply graph invariants.

    Checks are evaluated incrementally against a simulated pre-state:
    1. ``src_block`` must be 1-way.
    2. ``via_pred`` must be 1-way.
    3. ``via_pred -> src_block`` must exist.
    4. ``src_block -> old_target`` must exist.
    """
    current_adj: dict[int, list[int]] = {k: list(v) for k, v in adj.items()}

    for idx, edit in enumerate(edits):
        if edit.kind == "edge_split_redirect" and edit.via_pred is not None:
            src_succs = current_adj.get(edit.source, [])
            pred_succs = current_adj.get(edit.via_pred, [])

            if len(src_succs) != 1:
                return StructuralCheckResult(
                    passed=False,
                    reason="edge-split source block must be 1-way (INTERR 50860 guard)",
                    diagnostics={"index": idx, "source": edit.source, "src_succs": src_succs},
                )
            if len(pred_succs) != 1:
                return StructuralCheckResult(
                    passed=False,
                    reason="edge-split predecessor must be 1-way (INTERR 50858 guard)",
                    diagnostics={"index": idx, "via_pred": edit.via_pred, "pred_succs": pred_succs},
                )
            if edit.source not in pred_succs:
                return StructuralCheckResult(
                    passed=False,
                    reason="edge-split predecessor edge to source is missing (INTERR 50858 guard)",
                    diagnostics={
                        "index": idx,
                        "via_pred": edit.via_pred,
                        "source": edit.source,
                        "pred_succs": pred_succs,
                    },
                )
            if edit.old_target not in src_succs:
                return StructuralCheckResult(
                    passed=False,
                    reason="edge-split source old_target mismatch (INTERR 50860 guard)",
                    diagnostics={
                        "index": idx,
                        "source": edit.source,
                        "old_target": edit.old_target,
                        "src_succs": src_succs,
                    },
                )

        current_adj = simulate_edits(current_adj, [edit]).adj

    return StructuralCheckResult(passed=True)


def detect_terminal_cycles(
    adj: dict[int, list[int]],
    terminal_exits: set[int],
    handler_entries: set[int],
    dispatcher: int,
) -> SemanticCheckResult:
    """Check that terminal exit blocks do not re-enter dispatcher or handler region.

    Args:
        adj: Adjacency list (block serial -> successor serials).
        terminal_exits: Blocks identified as terminal handler exits.
        handler_entries: All handler entry block serials.
        dispatcher: Dispatcher block serial.

    Returns:
        SemanticCheckResult with passed=True if no cycles found.
    """
    forbidden = handler_entries | {dispatcher}
    cycles: list[TerminalCycle] = []

    for term_blk in terminal_exits:
        succs = adj.get(term_blk, [])
        if not succs:
            continue  # true terminal (0 successors) — safe

        # BFS from terminal block; if we hit forbidden, it's a cycle
        visited: set[int] = set()
        queue: list[tuple[int, list[int]]] = [(term_blk, [term_blk])]
        found = False
        while queue and not found:
            node, path = queue.pop(0)
            for succ in adj.get(node, []):
                if succ in forbidden:
                    cycles.append(TerminalCycle(
                        terminal_block=term_blk,
                        reentry_target=succ,
                        path=path + [succ],
                    ))
                    found = True
                    break
                if succ not in visited:
                    visited.add(succ)
                    queue.append((succ, path + [succ]))

    return SemanticCheckResult(passed=len(cycles) == 0, cycles=cycles)


@dataclass
class TerminalSinkResult:
    """Result of proving whether a block is a valid terminal sink."""

    ok: bool
    reason: str = ""
    witness_path: list[int] = field(default_factory=list)
    reaches_forbidden: bool = False
    reaches_exit: bool = False
    has_nonexit_cycle: bool = False
    reachable_count: int = 0


def prove_terminal_sink(
    start: int,
    adj: dict[int, list[int]],
    exits: set[int],
    forbidden: set[int],
) -> TerminalSinkResult:
    """Prove that ``start`` is a valid terminal sink.

    BFS from start:
    - FAIL if any reachable node in forbidden (dispatcher, pre_header, handler entries)
    - FAIL if no reachable node in exits (must reach an exit block)
    - FAIL if reachable subgraph (excluding exit nodes) has a cycle (SCC size>1 or self-loop)
    - PASS otherwise

    Args:
        start: Block serial to check as a terminal sink.
        adj: Adjacency list (block serial -> successor serials).
        exits: Set of block serials that are true exits (0 successors).
        forbidden: Set of block serials that must not be reachable.

    Returns:
        TerminalSinkResult with ok=True if start is a valid terminal sink.
    """
    # Check start itself against forbidden set
    if start in forbidden:
        return TerminalSinkResult(
            ok=False,
            reason="start block is forbidden",
            witness_path=[start],
            reaches_forbidden=True,
            reachable_count=1,
        )

    # BFS to find all reachable nodes and check forbidden / exit reachability
    visited: set[int] = set()
    parent: dict[int, int | None] = {start: None}
    queue: deque[int] = deque([start])
    visited.add(start)
    reaches_exit = False
    reaches_forbidden = False
    forbidden_witness: list[int] = []

    while queue:
        node = queue.popleft()
        for succ in adj.get(node, []):
            if succ in forbidden:
                reaches_forbidden = True
                # Build witness path
                path = [succ]
                cur = node
                while cur is not None:
                    path.append(cur)
                    cur = parent.get(cur)
                forbidden_witness = list(reversed(path))
                # Don't break — continue to get full reachable set
            if succ in exits:
                reaches_exit = True
            if succ not in visited:
                visited.add(succ)
                parent[succ] = node
                # Don't expand past exit nodes (they are sinks)
                if succ not in exits:
                    queue.append(succ)

    reachable_count = len(visited)

    # Check 1: forbidden reachability (highest priority)
    if reaches_forbidden:
        return TerminalSinkResult(
            ok=False,
            reason="reaches forbidden block",
            witness_path=forbidden_witness,
            reaches_forbidden=True,
            reaches_exit=reaches_exit,
            reachable_count=reachable_count,
        )

    # Check 2: must reach at least one exit
    if not reaches_exit:
        # Build witness: longest path from start
        witness = [start]
        cur = start
        seen: set[int] = {start}
        while True:
            succs = adj.get(cur, [])
            advanced = False
            for s in succs:
                if s not in seen:
                    seen.add(s)
                    witness.append(s)
                    cur = s
                    advanced = True
                    break
            if not advanced:
                break
        return TerminalSinkResult(
            ok=False,
            reason="no exit reachable",
            witness_path=witness,
            reaches_forbidden=False,
            reaches_exit=False,
            reachable_count=reachable_count,
        )

    # Check 3: cycle detection in non-exit subgraph
    # Build subgraph excluding exit nodes
    non_exit_nodes = visited - exits
    # Check for cycles using DFS coloring (WHITE=0, GRAY=1, BLACK=2)
    color: dict[int, int] = {n: 0 for n in non_exit_nodes}

    def _has_cycle_from(node: int) -> list[int] | None:
        stack: list[tuple[int, int]] = [(node, 0)]  # (node, successor_index)
        path: list[int] = []
        while stack:
            n, idx = stack[-1]
            if color[n] == 0:
                color[n] = 1
                path.append(n)
            succs = [s for s in adj.get(n, []) if s in non_exit_nodes]
            if idx < len(succs):
                stack[-1] = (n, idx + 1)
                s = succs[idx]
                if color[s] == 1:
                    # Found cycle — build witness
                    cycle_start_idx = path.index(s)
                    return path[cycle_start_idx:] + [s]
                if color[s] == 0:
                    stack.append((s, 0))
            else:
                color[n] = 2
                if path and path[-1] == n:
                    path.pop()
                stack.pop()
        return None

    for node in non_exit_nodes:
        if color[node] == 0:
            cycle_witness = _has_cycle_from(node)
            if cycle_witness is not None:
                return TerminalSinkResult(
                    ok=False,
                    reason="cycle in non-exit subgraph",
                    witness_path=cycle_witness,
                    reaches_forbidden=False,
                    reaches_exit=reaches_exit,
                    has_nonexit_cycle=True,
                    reachable_count=reachable_count,
                )

    return TerminalSinkResult(
        ok=True,
        reaches_exit=True,
        reachable_count=reachable_count,
    )


@dataclass
class SemanticGate:
    """Semantic correctness gate -- replaces structural VerificationGate.

    Acceptance criteria:
    1. No terminal cycles (terminal handlers must not re-enter dispatcher/handlers)
    2. Conflict count below safety bound

    Block reachability and handler reachability are logged as diagnostics
    but do NOT cause gate failure.

    The ``result`` argument must expose ``terminal_cycles`` (list) and
    ``conflict_count_after`` (int) attributes.  This is deliberately
    duck-typed so the gate can be unit-tested without importing from the
    optimizers layer.

    Attributes:
        max_conflict_count: Upper bound on conflict count.
    """

    max_conflict_count: int = 10

    def check(self, result: object) -> bool:
        """Return True iff the result passes all semantic checks.

        Args:
            result: Object with ``terminal_cycles`` and
                ``conflict_count_after`` attributes (e.g. ``StageResult``).

        Returns:
            True when no terminal cycles exist and conflict count is
            at or below the maximum.
        """
        if getattr(result, "terminal_cycles", None):
            return False
        if getattr(result, "conflict_count_after", 0) > self.max_conflict_count:
            return False
        return True
