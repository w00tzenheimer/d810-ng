"""Read-only discovery for local selector/state-machine shells.

The facts in this module describe a proven artifact selector shell:
entering a header through a specific predecessor edge deterministically walks
only dispatch bookkeeping blocks before reaching a semantic continuation.
Planning and materialization live in cfg/hexrays layers.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnKind, OperandKind


SELECTOR_SHELL_FACTS_METADATA_KEY = "selector_shell_facts"

VarId = tuple[str, int]
Env = dict[VarId, int]

_CONDITIONAL_JUMP_OPCODES = frozenset({42, 43, 44, 45, 46, 48, 49, 52})
_GOTO_OPCODE = 55


@dataclass(frozen=True)
class SelectorShellEdgeProof:
    """A predecessor edge whose selector shell path is fully resolved."""

    from_serial: int
    old_target: int
    new_target: int
    ordered_path: tuple[int, ...]
    artifact_blocks: frozenset[int]
    proof_kind: str = "constant_selector_path"


@dataclass(frozen=True)
class SelectorShellFact:
    """Normalized selector-shell evidence consumed by CFG planning."""

    header_block: int
    semantic_target: int
    artifact_blocks: frozenset[int]
    edge_proofs: tuple[SelectorShellEdgeProof, ...]
    proof_sources: tuple[str, ...] = ("constant_path_simulation",)


def _operand(insn: object | None, slot: str) -> object | None:
    if insn is None:
        return None
    for slot_name, operand in getattr(insn, "operand_slots", ()) or ():
        if slot_name == slot:
            return operand
    return getattr(insn, slot, None)


def _const_value(mop: object | None) -> int | None:
    if mop is None:
        return None
    value = getattr(mop, "value", None)
    if value is None:
        nnn = getattr(mop, "nnn", None)
        value = getattr(nnn, "value", None)
    if value is None:
        return None
    try:
        return int(value) & 0xFFFFFFFFFFFFFFFF
    except (TypeError, ValueError):
        return None


def _block_ref(mop: object | None) -> int | None:
    if mop is None:
        return None
    value = getattr(mop, "block_ref", None)
    if value is None:
        value = getattr(mop, "block_num", None)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _var_id(mop: object | None) -> VarId | None:
    if mop is None:
        return None
    kind = getattr(mop, "kind", None)
    reg = getattr(mop, "reg", None)
    if reg is not None or kind is OperandKind.REGISTER:
        try:
            return ("reg", int(reg))
        except (TypeError, ValueError):
            return None
    stkoff = getattr(mop, "stkoff", None)
    if stkoff is not None or kind is OperandKind.STACK:
        try:
            return ("stack", int(stkoff))
        except (TypeError, ValueError):
            return None
    lvar_idx = getattr(mop, "lvar_idx", None)
    if lvar_idx is not None:
        try:
            return ("lvar", int(lvar_idx))
        except (TypeError, ValueError):
            return None
    return None


def _is_kind(insn: object | None, kind: InsnKind, *names: str) -> bool:
    if insn is None:
        return False
    actual = getattr(insn, "kind", None)
    if actual is kind:
        return True
    actual_name = actual.value if isinstance(actual, InsnKind) else str(actual)
    return actual_name in names or actual_name == f"InsnKind.{kind.name}"


def _raw_opcode(insn: object | None) -> int:
    try:
        return int(getattr(insn, "raw_opcode", getattr(insn, "opcode", -1)))
    except (TypeError, ValueError):
        return -1


def _is_simple_assign(insn: object | None) -> bool:
    if not (
        _is_kind(insn, InsnKind.MOV, "mov") or _is_kind(insn, InsnKind.XDU, "xdu")
    ):
        return False
    if _var_id(_operand(insn, "d")) is None:
        return False
    src = _operand(insn, "l")
    return _const_value(src) is not None or _var_id(src) is not None


def _is_branch(insn: object | None) -> bool:
    return (
        _raw_opcode(insn) in _CONDITIONAL_JUMP_OPCODES
        or _is_kind(insn, InsnKind.COND_JUMP, "cond_jump")
        or _is_kind(
            insn,
            InsnKind.EQUALITY_JUMP,
            "equality_jump",
        )
    )


def _is_goto(insn: object | None) -> bool:
    return _is_kind(insn, InsnKind.GOTO, "goto") or _raw_opcode(insn) == _GOTO_OPCODE


def _last_insn(block: BlockSnapshot) -> object | None:
    return block.insn_snapshots[-1] if block.insn_snapshots else None


def _is_pure_shell_block(block: BlockSnapshot) -> bool:
    if not block.insn_snapshots:
        return block.nsucc <= 1
    for insn in block.insn_snapshots:
        if _is_simple_assign(insn) or _is_branch(insn) or _is_goto(insn):
            continue
        return False
    return True


def _is_internal_shell_predecessor(cfg: FlowGraph, block: BlockSnapshot) -> bool:
    if not block.preds or not _is_pure_shell_block(block):
        return False
    pred_blocks = tuple(
        pred_block
        for pred in block.preds
        if (pred_block := cfg.get_block(int(pred))) is not None
    )
    return bool(pred_blocks) and all(
        _is_pure_shell_block(pred_block) for pred_block in pred_blocks
    )


def _exec_simple_assignments(block: BlockSnapshot, env: Env) -> Env:
    result = dict(env)
    for insn in block.insn_snapshots:
        if not _is_simple_assign(insn):
            continue
        dst = _var_id(_operand(insn, "d"))
        if dst is None:
            continue
        src = _operand(insn, "l")
        value = _const_value(src)
        if value is None:
            src_id = _var_id(src)
            value = result.get(src_id) if src_id is not None else None
        if value is None:
            result.pop(dst, None)
        else:
            result[dst] = int(value)
    return result


def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _eval_branch(block: BlockSnapshot, env: Env) -> bool | None:
    tail = _last_insn(block)
    if tail is None or not _is_branch(tail):
        return None
    left = _operand(tail, "l")
    right = _operand(tail, "r")
    left_value = _const_value(left)
    if left_value is None:
        left_id = _var_id(left)
        left_value = env.get(left_id) if left_id is not None else None
    right_value = _const_value(right)
    if right_value is None:
        right_id = _var_id(right)
        right_value = env.get(right_id) if right_id is not None else None
    opcode = int(getattr(tail, "opcode", -1) or -1)
    if opcode == 42:
        return bool(left_value)
    if left_value is None or right_value is None:
        return None
    if opcode == 43:
        return int(left_value) != int(right_value)
    if opcode == 44:
        return int(left_value) == int(right_value)
    if opcode == 45:
        return (int(left_value) & 0xFFFFFFFFFFFFFFFF) >= (
            int(right_value) & 0xFFFFFFFFFFFFFFFF
        )
    if opcode == 46:
        return (int(left_value) & 0xFFFFFFFFFFFFFFFF) < (
            int(right_value) & 0xFFFFFFFFFFFFFFFF
        )
    if opcode == 48:
        return (int(left_value) & 0xFFFFFFFFFFFFFFFF) <= (
            int(right_value) & 0xFFFFFFFFFFFFFFFF
        )
    if opcode == 49:
        return _signed32(int(left_value)) > _signed32(int(right_value))
    if opcode == 52:
        return _signed32(int(left_value)) <= _signed32(int(right_value))
    return None


def _branch_targets(block: BlockSnapshot) -> tuple[int, int] | None:
    tail = _last_insn(block)
    taken = _block_ref(_operand(tail, "d"))
    if taken is None or taken not in block.succs:
        return None
    fallthrough = tuple(int(succ) for succ in block.succs if int(succ) != int(taken))
    if len(fallthrough) != 1:
        return None
    return int(taken), fallthrough[0]


def _next_successors(block: BlockSnapshot, env: Env) -> tuple[int, ...] | None:
    if block.nsucc == 0:
        return ()
    if block.nsucc == 1:
        return (int(block.succs[0]),)
    if block.nsucc != 2:
        return None
    targets = _branch_targets(block)
    if targets is None:
        return None
    taken, fallthrough = targets
    decision = _eval_branch(block, env)
    if decision is None:
        return None
    return (taken if decision else fallthrough,)


def _simulate_selector_path(
    cfg: FlowGraph,
    *,
    start: int,
    semantic_target: int,
    env: Env,
    max_steps: int = 16,
) -> tuple[int, tuple[int, ...], frozenset[int]] | None:
    current = int(start)
    current_env = dict(env)
    path: list[int] = []
    artifact_blocks: set[int] = set()
    seen: set[tuple[int, tuple[tuple[VarId, int], ...]]] = set()
    for _ in range(max_steps):
        if current == int(semantic_target):
            return current, tuple(path + [current]), frozenset(artifact_blocks)
        block = cfg.get_block(current)
        if block is None or not _is_pure_shell_block(block):
            return None
        state_key = (current, tuple(sorted(current_env.items())))
        if state_key in seen:
            return None
        seen.add(state_key)
        path.append(current)
        artifact_blocks.add(current)
        current_env = _exec_simple_assignments(block, current_env)
        successors = _next_successors(block, current_env)
        if successors is None or len(successors) != 1:
            return None
        current = int(successors[0])
    return None


def _coerce_edge_proof(item: object) -> SelectorShellEdgeProof | None:
    if isinstance(item, SelectorShellEdgeProof):
        return item
    if not isinstance(item, Mapping):
        return None
    try:
        return SelectorShellEdgeProof(
            from_serial=int(item["from_serial"]),
            old_target=int(item["old_target"]),
            new_target=int(item["new_target"]),
            ordered_path=tuple(int(s) for s in item.get("ordered_path", ())),
            artifact_blocks=frozenset(
                int(s) for s in item.get("artifact_blocks", ())
            ),
            proof_kind=str(item.get("proof_kind", "constant_selector_path")),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _coerce_fact(item: object) -> SelectorShellFact | None:
    if isinstance(item, SelectorShellFact):
        return item
    if not isinstance(item, Mapping):
        return None
    edge_proofs = tuple(
        proof
        for raw in item.get("edge_proofs", ())
        if (proof := _coerce_edge_proof(raw)) is not None
    )
    if not edge_proofs:
        return None
    try:
        return SelectorShellFact(
            header_block=int(item["header_block"]),
            semantic_target=int(item["semantic_target"]),
            artifact_blocks=frozenset(
                int(s) for s in item.get("artifact_blocks", ())
            ),
            edge_proofs=edge_proofs,
            proof_sources=tuple(str(s) for s in item.get("proof_sources", ())),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _is_valid_fact(cfg: FlowGraph, fact: SelectorShellFact) -> bool:
    header = cfg.get_block(int(fact.header_block))
    semantic = cfg.get_block(int(fact.semantic_target))
    if header is None or semantic is None or _is_pure_shell_block(semantic):
        return False
    proven_artifacts: set[int] = set()
    for proof in fact.edge_proofs:
        pred = cfg.get_block(int(proof.from_serial))
        if pred is None:
            return False
        if int(proof.old_target) not in pred.succs:
            return False
        if int(proof.new_target) != int(fact.semantic_target):
            return False
        if int(proof.old_target) != int(fact.header_block):
            return False
        result = _simulate_selector_path(
            cfg,
            start=int(fact.header_block),
            semantic_target=int(fact.semantic_target),
            env=_exec_simple_assignments(pred, {}),
        )
        if result is None:
            return False
        target, ordered_path, artifact_blocks = result
        if int(target) != int(fact.semantic_target):
            return False
        if tuple(int(serial) for serial in proof.ordered_path) != ordered_path:
            return False
        if (
            frozenset(int(serial) for serial in proof.artifact_blocks)
            != artifact_blocks
        ):
            return False
        if not artifact_blocks:
            return False
        proven_artifacts.update(artifact_blocks)
    if frozenset(proven_artifacts) != frozenset(
        int(serial) for serial in fact.artifact_blocks
    ):
        return False
    return True


def discover_selector_shell_facts(
    cfg: FlowGraph | None,
) -> tuple[SelectorShellFact, ...]:
    """Discover selector shells with predecessor-specific continuation proof."""
    if cfg is None:
        return ()
    facts: list[SelectorShellFact] = []
    for header in cfg.blocks.values():
        if header.nsucc != 2 or not _is_pure_shell_block(header):
            continue
        for semantic_target in tuple(int(succ) for succ in header.succs):
            semantic = cfg.get_block(semantic_target)
            if semantic is None or _is_pure_shell_block(semantic):
                continue
            proofs: list[SelectorShellEdgeProof] = []
            fact_artifacts: set[int] = set()
            for pred_serial in header.preds:
                pred = cfg.get_block(int(pred_serial))
                if pred is None or pred.nsucc != 1:
                    continue
                if _is_internal_shell_predecessor(cfg, pred):
                    continue
                if int(pred.succs[0]) != int(header.serial):
                    continue
                env = _exec_simple_assignments(pred, {})
                result = _simulate_selector_path(
                    cfg,
                    start=int(header.serial),
                    semantic_target=int(semantic_target),
                    env=env,
                )
                if result is None:
                    continue
                target, path, artifact_blocks = result
                if target != int(semantic_target) or not artifact_blocks:
                    continue
                fact_artifacts.update(artifact_blocks)
                proofs.append(
                    SelectorShellEdgeProof(
                        from_serial=int(pred.serial),
                        old_target=int(header.serial),
                        new_target=int(semantic_target),
                        ordered_path=path,
                        artifact_blocks=artifact_blocks,
                    )
                )
            if proofs:
                facts.append(
                    SelectorShellFact(
                        header_block=int(header.serial),
                        semantic_target=int(semantic_target),
                        artifact_blocks=frozenset(fact_artifacts),
                        edge_proofs=tuple(proofs),
                    )
                )
    return tuple(fact for fact in facts if _is_valid_fact(cfg, fact))


def serialize_selector_shell_facts(
    facts: Sequence[SelectorShellFact],
) -> tuple[dict[str, object], ...]:
    """Serialize selector-shell facts into FlowGraph metadata."""
    serialized: list[dict[str, object]] = []
    for fact in sorted(
        facts,
        key=lambda item: (int(item.header_block), int(item.semantic_target)),
    ):
        serialized.append(
            {
                "header_block": int(fact.header_block),
                "semantic_target": int(fact.semantic_target),
                "artifact_blocks": tuple(sorted(int(s) for s in fact.artifact_blocks)),
                "proof_sources": tuple(fact.proof_sources),
                "edge_proofs": tuple(
                    {
                        "from_serial": int(proof.from_serial),
                        "old_target": int(proof.old_target),
                        "new_target": int(proof.new_target),
                        "ordered_path": tuple(int(s) for s in proof.ordered_path),
                        "artifact_blocks": tuple(
                            sorted(int(s) for s in proof.artifact_blocks)
                        ),
                        "proof_kind": proof.proof_kind,
                    }
                    for proof in fact.edge_proofs
                ),
            }
        )
    return tuple(serialized)


def extract_selector_shell_facts(
    flow_graph: FlowGraph | None,
) -> tuple[SelectorShellFact, ...]:
    """Read validated selector-shell facts from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    raw = flow_graph.metadata.get(SELECTOR_SHELL_FACTS_METADATA_KEY)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    facts = tuple(fact for item in raw if (fact := _coerce_fact(item)) is not None)
    return tuple(fact for fact in facts if _is_valid_fact(flow_graph, fact))


__all__ = [
    "SELECTOR_SHELL_FACTS_METADATA_KEY",
    "SelectorShellEdgeProof",
    "SelectorShellFact",
    "discover_selector_shell_facts",
    "extract_selector_shell_facts",
    "serialize_selector_shell_facts",
]
