"""Shared helpers and engine strategy wrapper for fake-jump cleanup."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.ir.flowgraph import FlowGraph, InsnKind, OperandKind
from d810.transforms.graph_modification import (
    CloneConditionalAsGoto,
    CloneConditionalAsGotoFromBranchArm,
    ConvertToGoto,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.core.typing import TYPE_CHECKING
from d810.transforms.plan_fragment import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.analyses.control_flow.conditional_jump_eval import (
    conditional_jump_outcome_for_values,
)
from d810.analyses.control_flow.graph_checks import reachable_from_adjacency

if TYPE_CHECKING:
    from d810.transforms.snapshot import (
        AnalysisSnapshot,
    )

FAKE_JUMP_FIXES_METADATA_KEY = "fake_jump_fixes"
PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY = "payload_fake_jump_fixes"

VarId = tuple[str, int]


@dataclass(frozen=True)
class FakeJumpResolution:
    """Decision for one fake-jump predecessor."""

    new_target: int | None
    always_taken: bool = False
    always_not_taken: bool = False


@dataclass(frozen=True)
class FakeJumpPredFix:
    """Validated per-predecessor redirect around a fake-jump block."""

    fake_block: int
    pred_block: int
    new_target: int


@dataclass(frozen=True)
class PayloadFakeJumpFix:
    """Payload-preserving predecessor split for a fake conditional block."""

    fake_block: int
    original_target: int
    clone_redirects: tuple[tuple[int, int], ...]


def should_skip_fake_jump_predecessor(
    resolved_count: int,
    unresolved_count: int,
) -> bool:
    """Return True when unresolved histories make the fix unsafe."""
    if resolved_count <= 0:
        return True
    return resolved_count < 3 and unresolved_count > 10 * resolved_count


def resolve_fake_jump_target(
    *,
    opcode: int,
    compared_value: int,
    pred_comparison_values: Sequence[int],
    taken_target: int,
    fallthrough_target: int,
    jz_opcode: int,
    jnz_opcode: int,
    jae_opcode: int | None = None,
    jb_opcode: int | None = None,
    ja_opcode: int | None = None,
    jbe_opcode: int | None = None,
    jg_opcode: int | None = None,
    jge_opcode: int | None = None,
    jl_opcode: int | None = None,
    jle_opcode: int | None = None,
    operand_size: int = 4,
) -> FakeJumpResolution:
    """Resolve the deterministic target for a fake conditional jump."""
    opcode_names = {
        jz_opcode: "m_jz",
        jnz_opcode: "m_jnz",
        jae_opcode: "m_jae",
        jb_opcode: "m_jb",
        ja_opcode: "m_ja",
        jbe_opcode: "m_jbe",
        jg_opcode: "m_jg",
        jge_opcode: "m_jge",
        jl_opcode: "m_jl",
        jle_opcode: "m_jle",
    }
    opcode_names = {
        key: value for key, value in opcode_names.items() if key is not None
    }
    outcome = conditional_jump_outcome_for_values(
        opcode,
        pred_comparison_values,
        compared_value,
        operand_size=operand_size,
        opcode_names=opcode_names,
    )
    if outcome is None:
        return FakeJumpResolution(new_target=None)

    if outcome.always_taken:
        return FakeJumpResolution(
            new_target=taken_target,
            always_taken=True,
            always_not_taken=False,
        )
    if outcome.always_not_taken:
        return FakeJumpResolution(
            new_target=fallthrough_target,
            always_taken=False,
            always_not_taken=True,
        )
    return FakeJumpResolution(new_target=None)


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


def _kind_name(insn: object | None) -> str:
    if insn is None:
        return ""
    kind = getattr(insn, "kind", None)
    if isinstance(kind, InsnKind):
        return kind.value
    return str(kind)


def _is_mov(insn: object | None) -> bool:
    return getattr(insn, "kind", None) is InsnKind.MOV or _kind_name(insn) in {
        "InsnKind.MOV",
        "mov",
    }


def _is_equality_branch(insn: object | None) -> bool:
    opcode = int(getattr(insn, "opcode", -1) or -1)
    if opcode in (43, 44):
        return True
    kind = getattr(insn, "kind", None)
    return kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}


def _last_insn(block: object | None) -> object | None:
    insns = getattr(block, "insn_snapshots", ()) or ()
    return insns[-1] if insns else None


def _compare_var_const(block: object | None) -> tuple[int, VarId, int] | None:
    tail = _last_insn(block)
    if tail is None or not _is_equality_branch(tail):
        return None
    opcode = int(getattr(tail, "opcode", -1) or -1)
    if opcode not in (43, 44):
        return None
    left = _operand(tail, "l")
    right = _operand(tail, "r")
    left_var = _var_id(left)
    right_var = _var_id(right)
    left_const = _const_value(left)
    right_const = _const_value(right)
    if left_var is not None and right_const is not None:
        return opcode, left_var, int(right_const)
    if right_var is not None and left_const is not None:
        return opcode, right_var, int(left_const)
    return None


def _branch_targets(block: object | None) -> tuple[int, int] | None:
    if block is None:
        return None
    tail = _last_insn(block)
    taken = _block_ref(_operand(tail, "d"))
    if taken is None or taken not in getattr(block, "succs", ()):
        return None
    fallthrough = tuple(
        int(succ) for succ in getattr(block, "succs", ()) if int(succ) != int(taken)
    )
    if len(fallthrough) != 1:
        return None
    return int(taken), int(fallthrough[0])


def _last_const_assignment(block: object | None, dest_id: VarId) -> int | None:
    result: int | None = None
    for insn in getattr(block, "insn_snapshots", ()) or ():
        if not _is_mov(insn):
            continue
        dst = _var_id(_operand(insn, "d"))
        value = _const_value(_operand(insn, "l"))
        if dst == dest_id and value is not None:
            result = int(value)
    return result


def _is_cloneable_predecessor(pred_block: object | None, fake_block: int) -> bool:
    if pred_block is None:
        return False
    if int(getattr(pred_block, "nsucc", 0) or 0) == 1:
        return tuple(int(succ) for succ in getattr(pred_block, "succs", ())) == (
            int(fake_block),
        )
    return (
        int(getattr(pred_block, "nsucc", 0) or 0) == 2
        and int(fake_block) in tuple(int(succ) for succ in getattr(pred_block, "succs", ()))
    )


def _clone_branch_arm(pred_block: object, fake_block: int) -> int | None:
    if int(getattr(pred_block, "nsucc", 0) or 0) != 2:
        return None
    tail_target = _block_ref(_operand(_last_insn(pred_block), "d"))
    if tail_target == int(fake_block):
        return 1
    succs = tuple(int(succ) for succ in getattr(pred_block, "succs", ()))
    if int(fake_block) in succs:
        return 0
    return None


def _successor_count(block: object | None) -> int:
    if block is None:
        return 0
    nsucc = getattr(block, "nsucc", None)
    if callable(nsucc):
        try:
            return int(nsucc())
        except (TypeError, ValueError):
            return 0
    if nsucc is not None:
        try:
            return int(nsucc)
        except (TypeError, ValueError):
            return 0
    return len(tuple(getattr(block, "succs", ()) or ()))


def _block_successors(block: object | None) -> tuple[int, ...]:
    if block is None:
        return ()
    succs = getattr(block, "succs", ()) or ()
    try:
        return tuple(int(succ) for succ in succs)
    except (TypeError, ValueError):
        return ()


def _lookup_block(cfg: object, serial: int) -> object | None:
    getter = getattr(cfg, "get_block", None)
    if callable(getter):
        return getter(int(serial))
    blocks = getattr(cfg, "blocks", None)
    if isinstance(blocks, Mapping):
        return blocks.get(int(serial))
    return None


def _has_terminal_successor(cfg: object, block: object) -> bool:
    for succ in _block_successors(block):
        succ_block = _lookup_block(cfg, int(succ))
        if succ_block is not None and _successor_count(succ_block) == 0:
            return True
    return False


def _coerce_fake_jump_fixes(raw: object) -> dict[int, dict[int, int]]:
    if not isinstance(raw, Mapping):
        return {}

    fixes: dict[int, dict[int, int]] = {}
    for fake_block, pred_map in raw.items():
        try:
            fake_block_int = int(fake_block)
        except (TypeError, ValueError):
            continue
        if not isinstance(pred_map, Mapping):
            continue

        coerced_pred_map: dict[int, int] = {}
        for pred_block, new_target in pred_map.items():
            try:
                coerced_pred_map[int(pred_block)] = int(new_target)
            except (TypeError, ValueError):
                continue
        if coerced_pred_map:
            fixes[fake_block_int] = coerced_pred_map
    return fixes


def collect_payload_fake_jump_fixes(
    cfg: FlowGraph | None,
) -> tuple[PayloadFakeJumpFix, ...]:
    """Collect fake jumps whose branch block has payload that must be preserved."""
    if cfg is None:
        return ()
    fixes: dict[int, PayloadFakeJumpFix] = {}
    for block in cfg.blocks.values():
        if int(block.nsucc) != 2 or len(block.preds) < 2:
            continue
        compare = _compare_var_const(block)
        targets = _branch_targets(block)
        if compare is None or targets is None:
            continue
        opcode, compared_id, compared_const = compare
        taken_target, fallthrough_target = targets

        resolved: list[tuple[int, int, bool, bool]] = []
        for pred_serial in block.preds:
            pred_block = cfg.get_block(int(pred_serial))
            pred_value = _last_const_assignment(pred_block, compared_id)
            if pred_block is None or pred_value is None:
                resolved = []
                break
            resolution = resolve_fake_jump_target(
                opcode=opcode,
                compared_value=compared_const,
                pred_comparison_values=(pred_value,),
                taken_target=taken_target,
                fallthrough_target=fallthrough_target,
                jz_opcode=44,
                jnz_opcode=43,
            )
            if resolution.new_target is None:
                resolved = []
                break
            if int(resolution.new_target) == int(block.serial):
                resolved = []
                break
            resolved.append(
                (
                    int(pred_serial),
                    int(resolution.new_target),
                    _is_cloneable_predecessor(pred_block, int(block.serial)),
                    int(getattr(pred_block, "nsucc", 0) or 0) == 1,
                )
            )
        if len(resolved) != len(block.preds):
            continue

        uncloneable_targets = {
            int(target) for _pred, target, cloneable, _one_way in resolved if not cloneable
        }
        if len(uncloneable_targets) > 1:
            continue
        if uncloneable_targets:
            original_target = next(iter(uncloneable_targets))
        elif (
            preferred_targets := {
                int(target)
                for _pred, target, _cloneable, one_way in resolved
                if not one_way
            }
        ):
            if len(preferred_targets) > 1:
                continue
            original_target = next(iter(preferred_targets))
        else:
            target_counts: dict[int, int] = {}
            for _pred, target, _cloneable, _one_way in resolved:
                target_counts[int(target)] = target_counts.get(int(target), 0) + 1
            original_target = sorted(
                target_counts,
                key=lambda target: (-target_counts[target], target),
            )[0]

        clone_redirects: list[tuple[int, int]] = []
        for pred, target, cloneable, _one_way in resolved:
            if int(target) == int(original_target):
                continue
            if not cloneable:
                clone_redirects = []
                break
            clone_redirects.append((int(pred), int(target)))
        else:
            fixes[int(block.serial)] = PayloadFakeJumpFix(
                fake_block=int(block.serial),
                original_target=int(original_target),
                clone_redirects=tuple(sorted(clone_redirects)),
            )
    return tuple(fixes[key] for key in sorted(fixes))


def _is_valid_fake_jump_fix(cfg: FlowGraph, fix: FakeJumpPredFix) -> bool:
    fake_block = cfg.blocks.get(fix.fake_block)
    pred_block = cfg.blocks.get(fix.pred_block)
    target_block = cfg.blocks.get(fix.new_target)

    if fake_block is None or pred_block is None or target_block is None:
        return False
    if _has_terminal_successor(cfg, fake_block):
        return False
    if fix.pred_block == cfg.entry_serial:
        return False
    if fix.new_target == fix.pred_block:
        return False
    if pred_block.nsucc == 1:
        if pred_block.succs[0] != fix.fake_block:
            return False
    elif pred_block.nsucc == 2:
        if fix.fake_block not in pred_block.succs:
            return False
    else:
        return False
    if fix.new_target not in fake_block.succs:
        return False
    return True


def _normalize_fake_jump_fixes(
    cfg: FlowGraph,
    raw: object,
) -> tuple[FakeJumpPredFix, ...]:
    fixes: list[FakeJumpPredFix] = []
    for fake_block, pred_map in _coerce_fake_jump_fixes(raw).items():
        for pred_block, new_target in pred_map.items():
            fix = FakeJumpPredFix(
                fake_block=fake_block,
                pred_block=pred_block,
                new_target=new_target,
            )
            if _is_valid_fake_jump_fix(cfg, fix):
                fixes.append(fix)
    return tuple(fixes)


def _coerce_payload_fake_jump_fixes(
    raw: object,
) -> tuple[PayloadFakeJumpFix, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    fixes: list[PayloadFakeJumpFix] = []
    for item in raw:
        if isinstance(item, PayloadFakeJumpFix):
            fixes.append(item)
            continue
        if not isinstance(item, Mapping):
            continue
        try:
            fixes.append(
                PayloadFakeJumpFix(
                    fake_block=int(item["fake_block"]),
                    original_target=int(item["original_target"]),
                    clone_redirects=tuple(
                        (int(pred), int(target))
                        for pred, target in item["clone_redirects"]
                    ),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return tuple(fixes)


def _is_valid_payload_fake_jump_fix(
    cfg: FlowGraph,
    fix: PayloadFakeJumpFix,
) -> bool:
    fake_block = cfg.get_block(fix.fake_block)
    if fake_block is None or fake_block.nsucc != 2:
        return False
    if _has_terminal_successor(cfg, fake_block):
        return False
    if int(fix.original_target) not in fake_block.succs:
        return False
    for pred, target in fix.clone_redirects:
        pred_block = cfg.get_block(int(pred))
        if pred_block is None or int(target) not in fake_block.succs:
            return False
        if not _is_cloneable_predecessor(pred_block, int(fix.fake_block)):
            return False
    return True


def _serialize_fake_jump_fixes(
    fixes: Sequence[FakeJumpPredFix],
) -> dict[int, dict[int, int]]:
    serialized: dict[int, dict[int, int]] = {}
    for fix in fixes:
        serialized.setdefault(fix.fake_block, {})[fix.pred_block] = fix.new_target
    return serialized


def serialize_fake_jump_fixes(
    fixes: Sequence[FakeJumpPredFix],
) -> dict[int, dict[int, int]]:
    """Serialize per-predecessor fixes into FlowGraph metadata payload."""
    return _serialize_fake_jump_fixes(fixes)


def serialize_payload_fake_jump_fixes(
    fixes: Sequence[PayloadFakeJumpFix],
) -> tuple[dict[str, object], ...]:
    """Serialize payload-preserving fake-jump fixes into FlowGraph metadata."""
    return tuple(
        {
            "fake_block": int(fix.fake_block),
            "original_target": int(fix.original_target),
            "clone_redirects": tuple(
                (int(pred), int(target)) for pred, target in fix.clone_redirects
            ),
        }
        for fix in sorted(fixes, key=lambda item: int(item.fake_block))
    )


def extract_fake_jump_fixes(
    flow_graph: FlowGraph | None,
) -> tuple[FakeJumpPredFix, ...]:
    """Read validated per-predecessor fake-jump fixes from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    return _normalize_fake_jump_fixes(
        flow_graph,
        flow_graph.metadata.get(FAKE_JUMP_FIXES_METADATA_KEY),
    )


def extract_payload_fake_jump_fixes(
    flow_graph: FlowGraph | None,
) -> tuple[PayloadFakeJumpFix, ...]:
    """Read or derive validated payload-preserving fake-jump fixes."""
    if flow_graph is None:
        return ()
    raw = flow_graph.metadata.get(PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY)
    fixes = _coerce_payload_fake_jump_fixes(raw)
    if not fixes:
        fixes = collect_payload_fake_jump_fixes(flow_graph)
    return tuple(
        fix for fix in fixes if _is_valid_payload_fake_jump_fix(flow_graph, fix)
    )


def build_fake_jump_modifications(
    fixes: Sequence[FakeJumpPredFix],
    flow_graph: FlowGraph | None = None,
) -> list[GraphModification]:
    """Translate validated per-predecessor fixes into graph edits."""
    modifications: list[GraphModification] = []
    for fix in fixes:
        pred_block = (
            flow_graph.blocks.get(fix.pred_block)
            if flow_graph is not None
            else None
        )
        if pred_block is not None and pred_block.nsucc == 2:
            modifications.append(
                RedirectBranch(
                    from_serial=fix.pred_block,
                    old_target=fix.fake_block,
                    new_target=fix.new_target,
                )
            )
            continue
        modifications.append(
            RedirectGoto(
                from_serial=fix.pred_block,
                old_target=fix.fake_block,
                new_target=fix.new_target,
            )
        )
    return modifications


def build_payload_fake_jump_modifications(
    fixes: Sequence[PayloadFakeJumpFix],
    flow_graph: FlowGraph | None = None,
) -> list[GraphModification]:
    """Translate payload-preserving fake-jump evidence into graph edits."""
    modifications: list[GraphModification] = []
    for fix in fixes:
        for pred, target in fix.clone_redirects:
            pred_block = (
                flow_graph.get_block(int(pred)) if flow_graph is not None else None
            )
            if pred_block is not None and pred_block.nsucc == 2:
                pred_arm = _clone_branch_arm(pred_block, int(fix.fake_block))
                if pred_arm is None:
                    continue
                modifications.append(
                    CloneConditionalAsGotoFromBranchArm(
                        source_block=int(fix.fake_block),
                        pred_serial=int(pred),
                        pred_arm=int(pred_arm),
                        goto_target=int(target),
                        reason="payload_fake_jump_clone_as_goto",
                    )
                )
                continue
            modifications.append(
                CloneConditionalAsGoto(
                    source_block=int(fix.fake_block),
                    pred_serial=int(pred),
                    goto_target=int(target),
                    reason="payload_fake_jump_clone_as_goto",
                )
            )
        modifications.append(
            ConvertToGoto(
                block_serial=int(fix.fake_block),
                goto_target=int(fix.original_target),
            )
        )
    return modifications


def _build_ownership(modifications: Sequence[GraphModification]) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()

    for mod in modifications:
        if isinstance(mod, (RedirectBranch, RedirectGoto)):
            blocks.add(mod.from_serial)
            edges.add((mod.from_serial, mod.old_target))
        elif isinstance(mod, ConvertToGoto):
            blocks.add(mod.block_serial)
        elif isinstance(mod, CloneConditionalAsGoto):
            blocks.add(mod.source_block)
            edges.add((mod.pred_serial, mod.source_block))
        elif isinstance(mod, CloneConditionalAsGotoFromBranchArm):
            blocks.add(mod.source_block)
            edges.add((mod.pred_serial, mod.source_block))

    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


def _entry_reachable_count(flow_graph: FlowGraph | None) -> int:
    if flow_graph is None:
        return 0
    return len(
        reachable_from_adjacency(
            flow_graph.as_adjacency_dict(),
            flow_graph.entry_serial,
        )
    )


class FakeJumpStrategy:
    """Engine strategy wrapper for validated per-predecessor fake-jump redirects."""

    name = "fake_jump"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return bool(
            extract_fake_jump_fixes(snapshot.flow_graph)
            or extract_payload_fake_jump_fixes(snapshot.flow_graph)
        )

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        fixes = extract_fake_jump_fixes(snapshot.flow_graph)
        payload_fixes = extract_payload_fake_jump_fixes(snapshot.flow_graph)
        if fixes and payload_fixes:
            plain_blocks = frozenset(int(fix.fake_block) for fix in fixes)
            payload_fixes = tuple(
                fix for fix in payload_fixes if int(fix.fake_block) not in plain_blocks
            )
        if not fixes and not payload_fixes:
            return None

        modifications = build_fake_jump_modifications(fixes, snapshot.flow_graph)
        modifications.extend(
            build_payload_fake_jump_modifications(
                payload_fixes,
                snapshot.flow_graph,
            )
        )
        if not modifications:
            return None

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=_build_ownership(modifications),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=len(modifications),
                conflict_density=0.0,
            ),
            risk_score=0.1,
            metadata={
                FAKE_JUMP_FIXES_METADATA_KEY: _serialize_fake_jump_fixes(fixes),
                PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY: (
                    serialize_payload_fake_jump_fixes(payload_fixes)
                ),
                "planner_entry_reachable_count": _entry_reachable_count(
                    snapshot.flow_graph
                ),
                "planner_entry_serial": (
                    int(snapshot.flow_graph.entry_serial)
                    if snapshot.flow_graph is not None
                    else 0
                ),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "FAKE_JUMP_FIXES_METADATA_KEY",
    "FakeJumpPredFix",
    "FakeJumpResolution",
    "FakeJumpStrategy",
    "PAYLOAD_FAKE_JUMP_FIXES_METADATA_KEY",
    "PayloadFakeJumpFix",
    "build_fake_jump_modifications",
    "build_payload_fake_jump_modifications",
    "collect_payload_fake_jump_fixes",
    "extract_fake_jump_fixes",
    "extract_payload_fake_jump_fixes",
    "resolve_fake_jump_target",
    "serialize_fake_jump_fixes",
    "serialize_payload_fake_jump_fixes",
    "should_skip_fake_jump_predecessor",
]
