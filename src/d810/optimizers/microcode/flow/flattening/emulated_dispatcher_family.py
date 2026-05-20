"""Family adapter for the extracted emulated-dispatcher detection path."""
from __future__ import annotations

import os
import json
import hashlib
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace
from types import SimpleNamespace

import ida_hexrays

from d810.core.typing import Protocol
from d810.cfg.dominator import compute_dom_tree
from d810.cfg.dispatcher_rewrite_planning import (
    DispatcherPredecessorRewriteInput,
    plan_dispatcher_predecessor_rewrite,
)
from d810.cfg.flowgraph import FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    CreateConditionalRedirect,
    ConvertToGoto,
    EdgeRedirectViaPredSplit,
    GraphModification,
    InsertBlock,
    PromoteOperandToScalar,
    ReorderBlocks,
    RedirectBranch,
    RedirectGoto,
    ZeroStateWrite,
)
from d810.cfg.modification_builder import ModificationBuilder
from d810.cfg.plan import (
    PatchEdgeSplitTrampoline,
    PatchInsertBlock,
    compile_patch_plan,
)
from d810.cfg.reconstruction_postprocess_emission import (
    execute_reconstruction_postprocess,
)
from d810.core import logging
from d810.evaluator.hexrays_microcode.dispatcher_state_evaluation import (
    all_history_values_found,
    collect_possible_history_values,
)
from d810.evaluator.hexrays_microcode.chains import find_reaching_defs_for_stkvar
from d810.evaluator.hexrays_microcode.use_def_dominance import (
    check_redirect_severs_use_def,
)
from d810.hexrays.mutation.cfg_mutations import mba_deep_cleaning
from d810.hexrays.mutation.cfg_verify import safe_verify
from d810.hexrays.mutation.ir_translator import (
    IDAIRTranslator,
    capture_insn_snapshot,
    classify_live_insn_kind,
    classify_live_operand_kind,
)
from d810.hexrays.utils.hexrays_helpers import CONTROL_FLOW_OPCODES
from d810.cfg.reconstruction_emission import (
    execute_primary_reconstruction_modifications,
)
from d810.optimizers.microcode.flow.flattening.engine.family import (
    CFFStrategyFamily,
)
from d810.optimizers.microcode.flow.flattening.ollvm_carrier_backend import (
    collect_ollvm_branch_ownership_refiners,
    collect_ollvm_post_execute_carrier_facts,
    collect_ollvm_profile_fact_observations,
)
from d810.optimizers.microcode.flow.flattening.ollvm_dispatcher_analysis import (
    OllvmDispatcherCollector,
    OllvmFatherHistoryResolver,
)
from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
    AnalysisSnapshot,
    ReachabilityInfo,
    StateModelSummary,
)
from d810.optimizers.microcode.flow.flattening.strategies.emulated_dispatcher_strategy import (
    EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY,
    EMULATED_DISPATCHER_FALLBACK_MODIFICATIONS_KEY,
    EMULATED_DISPATCHER_LOOP_RECOVERY_MODIFICATIONS_KEY,
    EMULATED_DISPATCHER_METADATA_KEY,
    EMULATED_DISPATCHER_MODIFICATIONS_KEY,
    EMULATED_DISPATCHER_PHASE_ARTIFACT_KEY,
    EMULATED_DISPATCHER_PHASE_CONTEXT_KEY,
    DispatcherLoopRecoveryStrategy,
    EmulatedDispatcherCandidateRecord,
    EmulatedDispatcherPhaseArtifact,
    EmulatedDispatcherPhaseContext,
    EmulatedDispatcherMetadata,
    EmulatedDispatcherStrategy,
)
from d810.recon.flow.bst_analysis import (
    _detect_state_var_stkoff,
    _extract_state_from_block,
    _find_pre_header_state,
    _walk_handler_chain,
    analyze_bst_dispatcher,
    resolve_via_bst_walk,
)
from d810.recon.flow.branch_ownership import (
    BranchOwnershipProof,
    branch_ownership_proof_from_any,
    collect_branch_ownership_proofs,
)
from d810.recon.flow.dispatcher_detection import DispatcherCache
from d810.recon.flow.dispatcher_map import StateDispatcherMap, StateDispatcherRow
from d810.recon.flow.dispatcher_discovery_facts import (
    collect_state_dispatcher_discovery_fact_observations,
)
from d810.recon.flow.dynamic_state_transition_recovery import (
    recover_dynamic_state_write_transitions,
)
from d810.recon.flow.equality_chain_dispatcher import (
    extract_state_dispatcher_map_from_mba,
)
from d810.recon.flow.entry_island_rescue_discovery import (
    collect_entry_island_rescue_seeds,
    collect_late_entry_island_diagnostics,
    collect_late_entry_island_rescue_seeds,
)
from d810.recon.flow.graph_reachability import (
    collect_residual_dispatcher_predecessors,
    compute_reachable_blocks,
)
from d810.recon.flow.linearized_state_dag import (
    BoundaryInlineMode,
    LabelRenderMode,
    ProgramCommentMode,
    ProgramRenderStrategy,
    RenderOrderStrategy,
    RedirectSourceKind,
    SemanticEdgeKind,
    build_live_linearized_state_dag_from_graph,
    build_linearized_state_program,
    render_linearized_state_program,
)
from d810.recon.flow.predecessor_dispatcher_target import (
    PredecessorDispatcherTargetFact,
    collect_predecessor_dispatcher_target_facts,
)
from d810.recon.flow.reconstruction_discovery import (
    classify_artifact_return_blocks,
)
from d810.recon.flow.reconstruction_candidate_builder import (
    build_reconstruction_candidate,
)
from d810.recon.flow.reconstruction_discovery_indexes import (
    build_reconstruction_discovery_indexes,
)
from d810.recon.facts.value_flow import (
    MUST_ALIAS_FACT_TYPE,
    OBSERVABLE_MEMORY_DEF_FACT_TYPE,
    SCALAR_PROMOTION_FACT_TYPE,
    SCALAR_REPLACEMENT_FACT_TYPE,
    production_value_flow_fact,
)
from d810.recon.flow.residual_alias_discovery import (
    discover_residual_alias_overrides,
)
from d810.recon.flow.residual_handoff_resolution import (
    resolve_effective_target_entry,
)
from d810.recon.flow.return_corridor_discovery import (
    collect_common_return_corridor,
)
from d810.recon.flow.state_machine_analysis import (
    build_mba_view_from_flow_graph,
    find_last_state_write_site_on_path_snapshot,
    run_snapshot_constant_fixpoint,
)
from d810.recon.flow.terminal_family_collection import (
    collect_terminal_family_report,
)
from d810.recon.flow.transition_builder import _convert_bst_to_result
from d810.recon.flow.transition_report import build_dispatcher_transition_report_from_graph

family_logger = logging.getLogger(
    "D810.unflat.emulated_dispatcher.family", logging.DEBUG
)

__all__ = [
    "EmulatedDispatcherDetection",
    "EmulatedDispatcherStrategyFamily",
    "GenericDispatcherCollectorProtocol",
    "GenericDispatcherEngineProfile",
    "GenericDispatcherResolverProtocol",
    "default_ollvm_dispatcher_profile",
    "ollvm_state_dispatcher_map_profile",
    "tigress_indirect_dispatcher_profile",
    "tigress_switch_dispatcher_profile",
]


@dataclass(frozen=True)
class _ReturnSlotUse:
    block_serial: int
    ins_ea: int
    stkoff: int
    size: int


@dataclass(frozen=True)
class _ReturnCarrierBypass:
    return_block: int
    return_slot_stkoff: int
    writer_block: int
    writer_ea: int


@dataclass(frozen=True)
class _ReturnSlotWriterCandidate:
    block_serial: int
    ins_ea: int
    dst_stkoff: int
    src_stkoff: int


@dataclass(frozen=True)
class _LoopReturnCarrierCandidate:
    stkoff: int
    size: int
    source_mop: object
    write_block: int
    read_blocks: tuple[int, ...]


@dataclass(frozen=True)
class TerminalSelectorPayloadIncomingEdge:
    """External payload incoming edge blocked by a side-effect veto.

    The branch-ownership diagnostic row tells us why the terminal selector
    backedge could not become trusted nonsemantic proof: another incoming edge
    reaches the same payload block, and that edge's discarded arm owns payload
    side effects.  This value records that exact external edge identity so any
    later CFG primitive can preserve the payload before redirecting the edge.
    """

    source_block: int
    branch_arm: int
    old_target: int
    source_state: int
    target_state: int
    target_entry: int
    veto_proof_id: str
    side_effect_guard_reason: str


@dataclass(frozen=True)
class TerminalSelectorPayloadMaterializationCandidate:
    """Proof-gated OLLVM terminal payload materialization plan.

    This is not itself permission to remove a branch.  It is the narrow bridge
    between branch ownership diagnostics and CFG planning: all edge identities
    are exact, all external incoming edges have sticky side-effect veto proof,
    and the payload store snapshots are carried explicitly for replay.
    """

    selector_source_block: int
    selector_branch_arm: int
    selector_old_target: int
    selector_state: int
    payload_state: int
    payload_block: int
    payload_backedge_target: int
    semantic_continuation: int
    side_effect_corridor_blocks: tuple[int, ...]
    side_effect_instructions: tuple[InsnSnapshot, ...]
    selector_blocked_proof_id: str
    selector_residue_proof_id: str
    external_incoming_edges: tuple[TerminalSelectorPayloadIncomingEdge, ...]

    @property
    def materialization_veto_proof_ids(self) -> tuple[str, ...]:
        return tuple(edge.veto_proof_id for edge in self.external_incoming_edges)

    @property
    def side_effect_guard_reasons(self) -> tuple[str, ...]:
        return tuple(
            edge.side_effect_guard_reason for edge in self.external_incoming_edges
        )

    @property
    def owned_redirect_edges(self) -> tuple[tuple[int, int], ...]:
        """Raw predecessor edges replaced by this materialization plan."""

        return (
            (int(self.selector_source_block), int(self.selector_old_target)),
            *(
                (int(edge.source_block), int(edge.old_target))
                for edge in self.external_incoming_edges
            ),
        )


def _iter_block_insns(block: object):
    insn = getattr(block, "head", None)
    while insn is not None:
        yield insn
        insn = getattr(insn, "next", None)


def _stack_slot_from_mop(mop: object | None) -> tuple[int, int] | None:
    if mop is None:
        return None
    if int(getattr(mop, "t", ida_hexrays.mop_z)) != int(ida_hexrays.mop_S):
        return None
    slot = getattr(mop, "s", None)
    if slot is None or getattr(slot, "off", None) is None:
        return None
    return int(slot.off), int(getattr(mop, "size", 0) or 0)


def _dstr(obj: object | None) -> str:
    if obj is None:
        return ""
    dstr = getattr(obj, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            return ""
    return str(dstr or "")


def _is_rax_mop(mop: object | None) -> bool:
    if mop is None:
        return False
    if int(getattr(mop, "t", ida_hexrays.mop_z)) != int(ida_hexrays.mop_r):
        return False
    if int(getattr(mop, "r", -1)) == 0:
        return True
    return "rax" in _dstr(mop).lower()


def _const_mop_value(mop: object | None) -> int | None:
    if mop is None:
        return None
    try:
        if int(getattr(mop, "t", -1)) != int(ida_hexrays.mop_n):
            return None
    except Exception:
        return None
    candidates = [getattr(mop, "value", None)]
    nnn = getattr(mop, "nnn", None)
    candidates.append(getattr(nnn, "value", None))
    for value in candidates:
        if value is None:
            continue
        try:
            return int(value)
        except Exception:
            continue
    return None


def _collect_return_slot_uses(mba: object) -> tuple[_ReturnSlotUse, ...]:
    """Find live reads from a stack return slot into the return register."""
    uses: list[_ReturnSlotUse] = []
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        try:
            block = mba.get_mblock(serial)  # type: ignore[attr-defined]
        except Exception:
            continue
        if block is None:
            continue
        for insn in _iter_block_insns(block):
            opcode = int(getattr(insn, "opcode", -1))
            slot = None
            if opcode == int(ida_hexrays.m_mov):
                maybe_slot = _stack_slot_from_mop(getattr(insn, "l", None))
                if maybe_slot is not None and _is_rax_mop(getattr(insn, "d", None)):
                    slot = maybe_slot
            elif opcode == int(getattr(ida_hexrays, "m_ret", -2)):
                for side in ("l", "r", "d"):
                    slot = _stack_slot_from_mop(getattr(insn, side, None))
                    if slot is not None:
                        break
            if slot is None:
                continue
            stkoff, size = slot
            if size <= 0:
                continue
            uses.append(
                _ReturnSlotUse(
                    block_serial=int(serial),
                    ins_ea=int(getattr(insn, "ea", 0) or 0),
                    stkoff=stkoff,
                    size=size,
                )
            )
    return tuple(uses)


def _scan_return_slot_defs(
    mba: object,
    *,
    stkoff: int,
    size: int,
) -> tuple[object, ...]:
    defs: list[object] = []
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        try:
            block = mba.get_mblock(serial)  # type: ignore[attr-defined]
        except Exception:
            continue
        if block is None:
            continue
        for insn in _iter_block_insns(block):
            dest = _stack_slot_from_mop(getattr(insn, "d", None))
            if dest is None:
                continue
            dest_stkoff, dest_size = dest
            if int(dest_stkoff) != int(stkoff) or int(dest_size) != int(size):
                continue
            defs.append(
                SimpleNamespace(
                    block_serial=int(serial),
                    ins_ea=int(getattr(insn, "ea", 0) or 0),
                    ins_opcode=int(getattr(insn, "opcode", -1)),
                )
            )
    return tuple(defs)


def _scan_stack_to_stack_return_slot_writers(
    mba: object,
    *,
    candidate_blocks: frozenset[int],
) -> tuple[_ReturnSlotWriterCandidate, ...]:
    writers: list[_ReturnSlotWriterCandidate] = []
    for serial in sorted(candidate_blocks):
        try:
            block = mba.get_mblock(serial)  # type: ignore[attr-defined]
        except Exception:
            continue
        if block is None:
            continue
        for insn in _iter_block_insns(block):
            if int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_mov):
                continue
            src = _stack_slot_from_mop(getattr(insn, "l", None))
            dst = _stack_slot_from_mop(getattr(insn, "d", None))
            if src is None or dst is None:
                continue
            src_stkoff, _src_size = src
            dst_stkoff, dst_size = dst
            if dst_size <= 0 or int(src_stkoff) == int(dst_stkoff):
                continue
            writers.append(
                _ReturnSlotWriterCandidate(
                    block_serial=int(serial),
                    ins_ea=int(getattr(insn, "ea", 0) or 0),
                    dst_stkoff=int(dst_stkoff),
                    src_stkoff=int(src_stkoff),
                )
            )
    return tuple(writers)


def _const_zero_return_writer(
    mba: object,
    block_serial: int,
) -> tuple[int, int] | None:
    insn = _const_zero_return_writer_insn(mba, block_serial)
    if insn is None:
        return None
    return 0, int(getattr(insn, "ea", 0) or 0)


def _const_zero_return_writer_insn(
    mba: object,
    block_serial: int,
) -> object | None:
    try:
        block = mba.get_mblock(block_serial)  # type: ignore[attr-defined]
    except Exception:
        return None
    if block is None:
        return None
    for insn in _iter_block_insns(block):
        if int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_mov):
            continue
        if not _is_rax_mop(getattr(insn, "d", None)) and "rax" not in _dstr(
            insn
        ).lower():
            continue
        if _const_mop_value(getattr(insn, "l", None)) != 0:
            continue
        return insn
    return None


def _semantic_return_handler_blocks(phase_context: object | None) -> frozenset[int]:
    program = getattr(phase_context, "semantic_reference_program", None)
    if program is None:
        return frozenset()
    return_node_indexes = {
        int(getattr(line, "node_index"))
        for line in getattr(program, "lines", ()) or ()
        if getattr(line, "node_index", None) is not None
        and (
            str(getattr(line, "line_kind", "")) == "return"
            or str(getattr(line, "text", "")).strip().startswith("return ")
        )
    }
    if not return_node_indexes:
        return frozenset()
    blocks: set[int] = set()
    for node in getattr(program, "nodes", ()) or ():
        if int(getattr(node, "node_index", -1)) not in return_node_indexes:
            continue
        block = getattr(node, "handler_serial", None)
        if block is None:
            block = getattr(node, "entry_anchor", None)
        if block is None:
            continue
        try:
            blocks.add(int(block))
        except (TypeError, ValueError):
            continue
    return frozenset(blocks)


def _post_redirect_adjacency(
    flow_graph: FlowGraph,
    modifications: tuple[GraphModification, ...],
) -> dict[int, list[int]]:
    adjacency = flow_graph.as_adjacency_dict()
    for mod in modifications:
        if not isinstance(mod, (RedirectGoto, RedirectBranch)):
            continue
        try:
            source = int(mod.from_serial)
            old_target = int(mod.old_target)
            new_target = int(mod.new_target)
        except Exception:
            continue
        succs = list(adjacency.get(source, ()))
        try:
            succs.remove(old_target)
        except ValueError:
            pass
        if new_target not in succs:
            succs.append(new_target)
        adjacency[source] = succs
    return adjacency


def _nearest_dominating_return_slot_writer(
    *,
    mba: object,
    flow_graph: FlowGraph,
    pre_dom: object,
    use: _ReturnSlotUse,
) -> object | None:
    try:
        defs = tuple(
            find_reaching_defs_for_stkvar(
                mba,
                int(use.block_serial),
                int(use.stkoff),
                int(use.size),
            )
        )
    except Exception:
        family_logger.debug(
            "Return-carrier preservation: reaching-def query failed for "
            "blk[%d] slot=0x%x",
            int(use.block_serial),
            int(use.stkoff),
            exc_info=True,
        )
        return None
    if not defs:
        defs = _scan_return_slot_defs(
            mba,
            stkoff=int(use.stkoff),
            size=int(use.size),
        )

    dominating_defs = tuple(
        site
        for site in defs
        if getattr(site, "block_serial", None) is not None
        and int(getattr(site, "block_serial")) in flow_graph.blocks
        and pre_dom.dominates(int(getattr(site, "block_serial")), int(use.block_serial))
    )
    if not dominating_defs:
        return None

    deepest = [
        site
        for site in dominating_defs
        if not any(
            int(getattr(site, "block_serial")) != int(getattr(other, "block_serial"))
            and pre_dom.dominates(
                int(getattr(site, "block_serial")),
                int(getattr(other, "block_serial")),
            )
            for other in dominating_defs
        )
    ]
    deepest_blocks = {int(getattr(site, "block_serial")) for site in deepest}
    if len(deepest_blocks) != 1:
        return None
    return deepest[-1]


def _return_carrier_preservation_bypasses(
    *,
    mba: object,
    flow_graph: FlowGraph,
    modifications: tuple[GraphModification, ...],
) -> tuple[_ReturnCarrierBypass, ...]:
    if not any(isinstance(mod, (RedirectGoto, RedirectBranch)) for mod in modifications):
        return ()

    return_uses = _collect_return_slot_uses(mba)
    if not return_uses:
        return ()

    pre_adj = flow_graph.as_adjacency_dict()
    pre_dom = compute_dom_tree(pre_adj, entry=int(flow_graph.entry_serial))
    post_dom = compute_dom_tree(
        _post_redirect_adjacency(flow_graph, modifications),
        entry=int(flow_graph.entry_serial),
    )

    bypasses: list[_ReturnCarrierBypass] = []
    for use in return_uses:
        writer = _nearest_dominating_return_slot_writer(
            mba=mba,
            flow_graph=flow_graph,
            pre_dom=pre_dom,
            use=use,
        )
        if writer is None:
            continue
        writer_block = int(getattr(writer, "block_serial"))
        if post_dom.dominates(writer_block, int(use.block_serial)):
            continue
        bypasses.append(
            _ReturnCarrierBypass(
                return_block=int(use.block_serial),
                return_slot_stkoff=int(use.stkoff),
                writer_block=writer_block,
                writer_ea=int(getattr(writer, "ins_ea", 0) or 0),
            )
        )
    return tuple(bypasses)


def _semantic_return_carrier_bypasses(
    *,
    mba: object,
    flow_graph: FlowGraph,
    modifications: tuple[GraphModification, ...],
    phase_context: object | None,
) -> tuple[_ReturnCarrierBypass, ...]:
    return_blocks = _semantic_return_handler_blocks(phase_context)
    if not return_blocks:
        return ()
    redirect_targets = {
        int(mod.new_target)
        for mod in modifications
        if isinstance(mod, (RedirectGoto, RedirectBranch))
    }
    direct_return_blocks = return_blocks & redirect_targets
    if not direct_return_blocks:
        return ()

    touched_blocks = frozenset(
        int(block)
        for mod in modifications
        if isinstance(mod, (RedirectGoto, RedirectBranch))
        for block in (mod.from_serial, mod.new_target)
    )
    writers = _scan_stack_to_stack_return_slot_writers(
        mba,
        candidate_blocks=touched_blocks,
    )

    post_dom = compute_dom_tree(
        _post_redirect_adjacency(flow_graph, modifications),
        entry=int(flow_graph.entry_serial),
    )
    bypasses: list[_ReturnCarrierBypass] = []
    for return_block in sorted(direct_return_blocks):
        if int(return_block) not in flow_graph.blocks:
            continue
        for writer in writers:
            if int(writer.block_serial) == int(return_block):
                continue
            if post_dom.dominates(int(writer.block_serial), int(return_block)):
                continue
            bypasses.append(
                _ReturnCarrierBypass(
                    return_block=int(return_block),
                    return_slot_stkoff=int(writer.dst_stkoff),
                    writer_block=int(writer.block_serial),
                    writer_ea=int(writer.ins_ea),
                )
            )
        if writers:
            continue
        const_zero_writer = _const_zero_return_writer(mba, int(return_block))
        if const_zero_writer is None:
            continue
        slot, ins_ea = const_zero_writer
        bypasses.append(
            _ReturnCarrierBypass(
                return_block=int(return_block),
                return_slot_stkoff=int(slot),
                writer_block=int(return_block),
                writer_ea=int(ins_ea),
            )
        )
    return tuple(bypasses)


def _direct_rewrite_blocks(
    modifications: tuple[GraphModification, ...],
) -> frozenset[int]:
    blocks: set[int] = set()
    for mod in modifications:
        if not isinstance(mod, (RedirectGoto, RedirectBranch)):
            continue
        for attr in ("from_serial", "old_target", "new_target"):
            value = getattr(mod, attr, None)
            if value is None:
                continue
            try:
                blocks.add(int(value))
            except (TypeError, ValueError):
                continue
    return frozenset(blocks)


def _mop_stack_key(mop: object | None) -> tuple[int, int] | None:
    slot = _stack_slot_from_mop(mop)
    if slot is None:
        return None
    stkoff, size = slot
    if size <= 0:
        return None
    return int(stkoff), int(size)


def _select_loop_return_carrier(
    *,
    mba: object,
    modifications: tuple[GraphModification, ...],
    state_var_stkoff: int | None,
) -> _LoopReturnCarrierCandidate | None:
    """Find the single non-state loop carrier preserved by direct recovery.

    The intended approov_simplified direct lowering has exactly one data
    carrier that is both tested by the phase header and self-updated by the
    phase body.  Refuse ambiguous or state-var-only shapes.
    """

    touched_blocks = _direct_rewrite_blocks(modifications)
    if not touched_blocks:
        return None

    state_slot = None if state_var_stkoff is None else int(state_var_stkoff)
    read_blocks: dict[tuple[int, int], set[int]] = {}
    self_updates: dict[tuple[int, int], tuple[object, int]] = {}
    update_opcodes = {
        int(ida_hexrays.m_add),
        int(ida_hexrays.m_sub),
        int(ida_hexrays.m_mul),
        int(ida_hexrays.m_xor),
        int(ida_hexrays.m_and),
        int(ida_hexrays.m_or),
    }

    for serial in sorted(touched_blocks):
        try:
            block = mba.get_mblock(serial)  # type: ignore[attr-defined]
        except Exception:
            continue
        if block is None:
            continue
        for insn in _iter_block_insns(block):
            opcode = int(getattr(insn, "opcode", -1))
            if opcode in CONTROL_FLOW_OPCODES:
                for side in ("l", "r"):
                    key = _mop_stack_key(getattr(insn, side, None))
                    if key is None or key[0] == state_slot:
                        continue
                    read_blocks.setdefault(key, set()).add(int(serial))
            if opcode not in update_opcodes:
                continue
            dest_key = _mop_stack_key(getattr(insn, "d", None))
            if dest_key is None or dest_key[0] == state_slot:
                continue
            for side in ("l", "r"):
                source_mop = getattr(insn, side, None)
                if _mop_stack_key(source_mop) == dest_key:
                    self_updates.setdefault(dest_key, (source_mop, int(serial)))
                    break

    candidates = tuple(
        (key, self_updates[key])
        for key in sorted(set(read_blocks) & set(self_updates))
    )
    if len(candidates) != 1:
        return None

    (stkoff, size), (source_mop, write_block) = candidates[0]
    return _LoopReturnCarrierCandidate(
        stkoff=int(stkoff),
        size=int(size),
        source_mop=source_mop,
        write_block=int(write_block),
        read_blocks=tuple(sorted(read_blocks[(stkoff, size)])),
    )


def _rewrite_return_const_zero_to_carrier(
    *,
    mba: object,
    return_block: int,
    writer_ea: int,
    carrier: _LoopReturnCarrierCandidate,
) -> bool:
    insn = _const_zero_return_writer_insn(mba, int(return_block))
    if insn is None:
        return False
    if writer_ea and int(getattr(insn, "ea", 0) or 0) != int(writer_ea):
        return False

    try:
        saved_dest = ida_hexrays.mop_t()
        saved_dest.assign(getattr(insn, "d", None))

        source = ida_hexrays.mop_t()
        source.assign(carrier.source_mop)

        src_size = int(getattr(source, "size", 0) or carrier.size)
        dst_size = int(getattr(saved_dest, "size", 0) or src_size)
        insn.opcode = (
            ida_hexrays.m_xds
            if dst_size > src_size
            else ida_hexrays.m_mov
        )
        insn.l.assign(source)
        try:
            insn.r.erase()
        except Exception:
            pass
        insn.d.assign(saved_dest)

        block = mba.get_mblock(int(return_block))  # type: ignore[attr-defined]
        if block is not None:
            try:
                block.mark_lists_dirty()
            except Exception:
                pass
        try:
            mba.mark_chains_dirty()  # type: ignore[attr-defined]
        except Exception:
            pass
        return True
    except Exception:
        family_logger.debug(
            "Return-carrier preservation: failed to rewrite const-zero return",
            exc_info=True,
        )
        return False


def _repair_semantic_const_zero_return_carrier(
    *,
    mba: object,
    modifications: tuple[GraphModification, ...],
    phase_artifact: object | None,
    bypasses: tuple[_ReturnCarrierBypass, ...],
) -> bool:
    const_zero_bypasses = tuple(
        bypass
        for bypass in bypasses
        if int(bypass.return_block) == int(bypass.writer_block)
        and int(bypass.return_slot_stkoff) == 0
    )
    if not const_zero_bypasses or len(const_zero_bypasses) != len(bypasses):
        return False

    carrier = _select_loop_return_carrier(
        mba=mba,
        modifications=modifications,
        state_var_stkoff=getattr(phase_artifact, "state_var_stkoff", None),
    )
    if carrier is None:
        return False

    for bypass in const_zero_bypasses:
        if not _rewrite_return_const_zero_to_carrier(
            mba=mba,
            return_block=int(bypass.return_block),
            writer_ea=int(bypass.writer_ea),
            carrier=carrier,
        ):
            return False

    family_logger.info(
        "DispatcherLoopRecovery preserved return carrier by rewriting "
        "const-zero return handler(s): carrier_slot=0x%x size=%d "
        "writer_blk=%d read_blks=%s returns=%s",
        int(carrier.stkoff),
        int(carrier.size),
        int(carrier.write_block),
        carrier.read_blocks,
        tuple(int(bypass.return_block) for bypass in const_zero_bypasses),
    )
    return True


def _return_carrier_preservation_blockers(
    *,
    mba: object,
    flow_graph: FlowGraph,
    modifications: tuple[GraphModification, ...],
    phase_context: object | None = None,
    phase_artifact: object | None = None,
    allow_live_repair: bool = False,
) -> tuple[str, ...]:
    bypasses = _return_carrier_preservation_bypasses(
        mba=mba,
        flow_graph=flow_graph,
        modifications=modifications,
    )
    if not bypasses:
        bypasses = _semantic_return_carrier_bypasses(
            mba=mba,
            flow_graph=flow_graph,
            modifications=modifications,
            phase_context=phase_context,
        )
    if not bypasses:
        return ()
    if allow_live_repair and _repair_semantic_const_zero_return_carrier(
        mba=mba,
        modifications=modifications,
        phase_artifact=phase_artifact,
        bypasses=bypasses,
    ):
        return ()
    details = "; ".join(
        (
            f"return_blk={item.return_block} slot=0x{item.return_slot_stkoff:x} "
            f"writer_blk={item.writer_block} writer_ea=0x{item.writer_ea:x}"
        )
        for item in bypasses
    )
    family_logger.info(
        "DispatcherLoopRecovery rejected direct rewrite batch because it would "
        "orphan return-carrier writer(s): %s",
        details,
    )
    return ("dispatcher_loop_recovery_return_carrier_bypass",)


class GenericDispatcherCollectorProtocol(Protocol):
    """Collector surface required by the dispatcher-engine profile.

    Live detector implementations are passed to ``mba.for_all_topinsns()`` and
    must be valid Hex-Rays instruction visitors for their detector profile.
    Map-driven profiles may use a no-op collector that only exposes this
    protocol surface.
    """

    def get_dispatcher_list(self) -> list[object]:
        """Return dispatcher candidates collected from the live MBA."""


class GenericDispatcherResolverProtocol(Protocol):
    """Resolver surface required by generic dispatcher lowering."""

    mba: object
    cur_maturity: int
    cur_maturity_pass: int
    dispatcher_list: list[object]

    def get_dispatcher_father_histories(
        self,
        dispatcher_father: object,
        dispatcher_entry_block: object,
        dispatcher_info: object,
    ) -> object:
        """Return state histories for one dispatcher predecessor."""

    def check_if_histories_are_resolved(self, histories: object) -> bool:
        """Return whether *histories* fully resolve a state value."""

    def _filter_dependency_safe_copies(
        self,
        father: object,
        insns: list[object],
    ) -> list[object]:
        """Return copied side effects that can safely be replayed."""

    def ensure_all_dispatcher_fathers_are_direct(self) -> int:
        """Normalize dispatcher predecessors before late-maturity lowering."""


class _NoopDispatcherCollector:
    """Collector used by profiles that are fully recon-map driven."""

    def __init__(self) -> None:
        pass

    def visit_minsn(self) -> int:
        return 0

    def get_dispatcher_list(self) -> list[object]:
        return []


class _NoopDispatcherResolver:
    """Resolver placeholder for profiles that never use father histories."""

    def __init__(self) -> None:
        self.mba = None
        self.cur_maturity = 0
        self.cur_maturity_pass = 0
        self.dispatcher_list: list[object] = []

    def get_dispatcher_father_histories(
        self,
        dispatcher_father: object,
        dispatcher_entry_block: object,
        dispatcher_info: object,
    ) -> object:
        return None

    def check_if_histories_are_resolved(self, histories: object) -> bool:
        return False

    def _filter_dependency_safe_copies(
        self,
        father: object,
        insns: list[object],
    ) -> list[object]:
        return []

    def ensure_all_dispatcher_fathers_are_direct(self) -> int:
        return 0


def _empty_state_dispatcher_maps(
    _mba: object,
    _analysis: object,
    _collector_dispatchers: tuple[object, ...],
) -> tuple[StateDispatcherMap, ...]:
    return ()


def _empty_switch_case_transition_facts(
    _mba: object,
    _dispatch_map: StateDispatcherMap,
    _profile_name: str,
) -> tuple[object, ...]:
    return ()


def _switch_fact_transition_kind_name(fact: object) -> str:
    name = getattr(fact, "transition_kind_name", None)
    if name is not None:
        return str(name)
    kind = getattr(fact, "transition_kind", "")
    value = getattr(kind, "value", None)
    if value is not None:
        return str(value)
    return str(kind)


def _switch_fact_exit_block(fact: object) -> int | None:
    exit_block = getattr(fact, "exit_block", None)
    if exit_block is None:
        payload = getattr(fact, "payload", {}) or {}
        if isinstance(payload, dict):
            exit_block = payload.get("exit_block")
    if exit_block is None:
        return None
    try:
        return int(exit_block)
    except Exception:
        return None


def _switch_fact_source_state(fact: object) -> int | None:
    source_state = getattr(fact, "source_state", None)
    if source_state is None:
        return None
    try:
        return int(source_state)
    except Exception:
        return None


def _switch_fact_next_states(fact: object) -> tuple[int, ...]:
    try:
        return tuple(int(value) for value in getattr(fact, "next_states", ()) or ())
    except Exception:
        return ()


def _switch_fact_arm_exit_blocks(fact: object) -> tuple[int | None, ...]:
    payload = getattr(fact, "payload", {}) or {}
    raw = payload.get("arm_exit_blocks") if isinstance(payload, dict) else None
    if raw is not None:
        try:
            return tuple(None if value is None else int(value) for value in raw)
        except Exception:
            return ()
    exit_block = _switch_fact_exit_block(fact)
    return () if exit_block is None else (exit_block,)


def _switch_fact_arm_ordered_paths(fact: object) -> tuple[tuple[int, ...], ...]:
    payload = getattr(fact, "payload", {}) or {}
    raw = payload.get("arm_ordered_paths") if isinstance(payload, dict) else None
    if raw is not None:
        try:
            return tuple(
                tuple(int(serial) for serial in (path or ()))
                for path in raw
            )
        except Exception:
            return ()
    ordered_path = tuple(int(serial) for serial in getattr(fact, "ordered_path", ()) or ())
    return () if not ordered_path else (ordered_path,)


def _switch_fact_trusted_proof_kind(fact: object, expected_kind: str) -> bool:
    proof = getattr(fact, "proof", None)
    if proof is None or not bool(getattr(proof, "trusted", False)):
        return False
    proof_kind = getattr(proof, "proof_kind_name", None)
    if proof_kind is None:
        raw_kind = getattr(proof, "proof_kind", "")
        proof_kind = getattr(raw_kind, "value", raw_kind)
    return str(proof_kind) == expected_kind


_SWITCH_TRANSITION_PARTIAL_BLOCKER_ALLOWLIST = frozenset({
    "tigress_switch_transition_fact_unresolved",
    "tigress_switch_transition_initial_redirect_unproven",
    "tigress_switch_transition_visible_state_not_lowered",
})


def _switch_transition_blockers_allow_partial_lowering(
    blockers: tuple[str, ...],
    *,
    facts: tuple[object, ...] = (),
) -> bool:
    """Return whether switch fact blockers are nonfatal for partial lowering."""

    if any(
        str(blocker) not in _SWITCH_TRANSITION_PARTIAL_BLOCKER_ALLOWLIST
        for blocker in blockers
    ):
        return False

    if "tigress_switch_transition_fact_unresolved" not in blockers:
        return True

    unresolved_facts = tuple(
        fact for fact in facts
        if _switch_fact_transition_kind_name(fact) == "UNRESOLVED"
    )
    return bool(unresolved_facts) and all(
        str(getattr(fact, "reason", ""))
        == "direct_target_not_in_switch_rows"
        for fact in unresolved_facts
    )



def _ordered_path_predecessor(
    ordered_path: tuple[int, ...],
    source: int,
) -> int | None:
    try:
        source_index = ordered_path.index(int(source))
    except ValueError:
        return None
    if source_index <= 0:
        return None
    return int(ordered_path[source_index - 1])


def _switch_dispatcher_reentry_targets(
    flow_graph: FlowGraph,
    *,
    dispatcher_entry: int,
    dispatcher_blocks: frozenset[int],
    facts: tuple[object, ...],
) -> frozenset[int]:
    """Return blocks that state exits may re-enter before the switch table.

    A C ``while (state != terminal) switch (state)`` lowers to a two-block
    dispatcher shape: handler state-write exits go back to the loop guard, and
    the guard jumps into the actual ``m_jtbl`` block.  The exact
    ``StateDispatcherMap`` correctly names the ``m_jtbl`` entry as the table,
    but transition rewrites must claim the state-write edge to the guard.
    """

    map_dispatcher_blocks = {int(block) for block in dispatcher_blocks}
    targets = {int(dispatcher_entry)}
    exit_blocks: set[int] = set()
    for fact in facts:
        exit_block = _switch_fact_exit_block(fact)
        if exit_block is not None:
            exit_blocks.add(int(exit_block))
        for arm_exit in _switch_fact_arm_exit_blocks(fact):
            if arm_exit is not None:
                exit_blocks.add(int(arm_exit))

    candidate_guards: set[int] = set()
    for source in exit_blocks:
        block = flow_graph.get_block(source)
        if block is None or block.nsucc != 1:
            continue
        target = int(block.succs[0])
        if target == int(dispatcher_entry):
            continue
        if target not in map_dispatcher_blocks:
            continue
        target_block = flow_graph.get_block(target)
        if (
            target_block is not None
            and target_block.nsucc == 2
            and int(dispatcher_entry) in tuple(int(succ) for succ in target_block.succs)
        ):
            candidate_guards.add(target)

    if len(candidate_guards) == 1:
        targets.update(candidate_guards)
    return frozenset(targets)


def _ollvm_state_dispatcher_maps(
    mba: object,
    analysis: object,
    collector_dispatchers: tuple[object, ...],
) -> tuple[StateDispatcherMap, ...]:
    maps: list[StateDispatcherMap] = []
    seen_entries: set[int] = set()

    for dispatcher_info in collector_dispatchers:
        entry_block = getattr(dispatcher_info, "entry_block", None)
        entry = getattr(entry_block, "serial", None)
        if entry is not None:
            seen_entries.add(int(entry))
    for entry in getattr(analysis, "dispatchers", ()) or ():
        seen_entries.add(int(entry))

    if seen_entries:
        for entry in sorted(seen_entries):
            dispatch_map = extract_state_dispatcher_map_from_mba(
                mba,
                dispatcher_entry_block=int(entry),
            )
            if dispatch_map is not None:
                maps.append(dispatch_map)
        if not maps:
            dispatch_map = extract_state_dispatcher_map_from_mba(mba)
            if dispatch_map is not None:
                maps.append(dispatch_map)
    else:
        dispatch_map = extract_state_dispatcher_map_from_mba(mba)
        if dispatch_map is not None:
            maps.append(dispatch_map)
    return tuple(maps)


def _ollvm_state_dispatcher_map_fallback(
    mba: object,
    analysis: object,
    collector_dispatchers: tuple[object, ...],
) -> tuple[StateDispatcherMap, ...]:
    """Recover exact dispatcher rows when the legacy OLLVM collector is empty."""

    if collector_dispatchers:
        return ()
    switch_maps = _tigress_switch_state_dispatcher_maps(
        mba,
        analysis,
        collector_dispatchers,
    )
    if switch_maps:
        return switch_maps
    return _ollvm_state_dispatcher_maps(mba, analysis, collector_dispatchers)


def _tigress_switch_state_dispatcher_maps(
    mba: object,
    _analysis: object,
    _collector_dispatchers: tuple[object, ...],
) -> tuple[StateDispatcherMap, ...]:
    try:
        from d810.recon.flow.switch_table_analysis import (
            analyze_switch_table_dispatcher,
        )

        result = analyze_switch_table_dispatcher(mba)
    except Exception:
        family_logger.debug(
            "switch-table state dispatcher profile collection failed",
            exc_info=True,
        )
        return ()
    if result is None:
        return ()
    return (result.state_dispatcher_map,)


def _tigress_switch_case_transition_facts(
    mba: object,
    dispatch_map: StateDispatcherMap,
    profile_name: str,
) -> tuple[object, ...]:
    try:
        from d810.recon.flow.switch_case_transition_analysis import (
            collect_switch_case_transition_facts_from_mba,
        )

        return tuple(
            collect_switch_case_transition_facts_from_mba(
                mba=mba,
                dispatch_map=dispatch_map,
                profile_name=profile_name,
            )
        )
    except Exception:
        family_logger.debug(
            "switch-table transition fact profile collection failed",
            exc_info=True,
        )
        return ()


def _make_tigress_indirect_state_dispatcher_maps(
    goto_table_info: object,
) -> Callable[[object, object, tuple[object, ...]], tuple[StateDispatcherMap, ...]]:
    def _collect(
        mba: object,
        _analysis: object,
        _collector_dispatchers: tuple[object, ...],
    ) -> tuple[StateDispatcherMap, ...]:
        if not isinstance(goto_table_info, dict):
            return ()
        try:
            from d810.recon.flow.indirect_jump_table_analysis import (
                analyze_tigress_indirect_dispatcher_from_config,
            )

            result = analyze_tigress_indirect_dispatcher_from_config(
                mba,
                goto_table_info,
            )
        except Exception:
            family_logger.debug(
                "indirect jump-table state dispatcher profile collection failed",
                exc_info=True,
            )
            return ()
        if result is None:
            return ()
        return (result.state_dispatcher_map,)

    return _collect


def _empty_post_execute_carrier_facts(_mba: object) -> tuple[object, ...]:
    return ()


def _empty_profile_fact_observations(_mba: object) -> tuple[object, ...]:
    return ()


def _empty_branch_ownership_refiners(
    _mba: object,
    _logger: object,
) -> tuple[object, ...]:
    return ()


def _entry_to_pre_header_corridor(
    flow_graph: FlowGraph,
    *,
    pre_header_serial: int,
    dispatcher_entry_serial: int,
    max_hops: int = 32,
) -> tuple[int, ...]:
    """Return the deterministic entry corridor ending at *pre_header_serial*.

    Late OLLVM equality-chain dispatchers can be discovered below an already
    collapsed entry trampoline.  The actual function entry still flows through
    a single-successor corridor that performs the initial state write, then
    lands on the immediate dispatcher preheader.  Lowering should preserve that
    corridor and redirect only the final preheader edge; treating this shape as
    a residual phase hides the real initial state and prevents the root rewrite.
    """

    entry_serial = int(flow_graph.entry_serial)
    pre_header = int(pre_header_serial)
    dispatcher_entry = int(dispatcher_entry_serial)
    path: list[int] = [entry_serial]
    current = entry_serial
    visited = {entry_serial}

    for _ in range(max_hops):
        if current == pre_header:
            return tuple(path)
        block = flow_graph.get_block(current)
        if block is None or block.nsucc != 1:
            return ()
        succ = int(block.succs[0])
        if succ == dispatcher_entry:
            return ()
        if succ in visited and succ != pre_header:
            return ()
        path.append(succ)
        visited.add(succ)
        current = succ

    return ()


def _guarded_entry_setup_pre_header_region(
    flow_graph: FlowGraph,
    *,
    pre_header_serial: int,
    dispatcher_entry_serial: int,
    forbidden_serials: set[int] | frozenset[int] = frozenset(),
    max_blocks: int = 128,
) -> tuple[int, ...]:
    """Prove a guarded setup region from function entry to dispatcher preheader.

    Some state-machine dispatchers start after ordinary function setup: input
    validation, allocation, logging, or other source-level guards may return
    before the dispatcher loop.  That shape is not the straight deterministic
    entry corridor handled by :func:`_entry_to_pre_header_corridor`, but it is
    still safe for phase reconstruction when the setup region is closed: every
    path from function entry either reaches the dispatcher preheader or exits,
    and no path enters the dispatcher/handler-owned region before the proven
    preheader.  Lowering then preserves the setup region and only rewires the
    preheader's dispatcher edge to the initial semantic handler.
    """

    entry_serial = int(flow_graph.entry_serial)
    pre_header = int(pre_header_serial)
    dispatcher_entry = int(dispatcher_entry_serial)
    forbidden = {int(serial) for serial in forbidden_serials}
    forbidden.add(dispatcher_entry)

    pre_header_block = flow_graph.get_block(pre_header)
    if (
        pre_header_block is None
        or pre_header_block.nsucc != 1
        or pre_header_block.succs != (dispatcher_entry,)
        or pre_header in forbidden
    ):
        return ()

    visited: set[int] = set()
    active: set[int] = set()
    reached_pre_header = False

    def _walk(serial: int) -> bool:
        nonlocal reached_pre_header
        serial = int(serial)
        if len(visited) > max_blocks:
            return False
        if serial in forbidden:
            return False
        if serial == pre_header:
            reached_pre_header = True
            return True
        if serial in active:
            return False
        if serial in visited:
            return True

        block = flow_graph.get_block(serial)
        if block is None:
            return False
        visited.add(serial)
        active.add(serial)
        try:
            for succ in tuple(int(succ) for succ in block.succs):
                if succ == dispatcher_entry:
                    return False
                if succ not in flow_graph.blocks:
                    return False
                if not _walk(succ):
                    return False
        finally:
            active.discard(serial)
        return True

    if not _walk(entry_serial) or not reached_pre_header:
        return ()
    return tuple(sorted((*visited, pre_header)))


def _recover_initial_state_from_entry_corridor(
    flow_graph: FlowGraph,
    *,
    pre_header_serial: int,
    dispatcher_entry_serial: int,
    state_var_stkoff: int,
) -> tuple[int, tuple[int, ...]] | None:
    """Recover the entry state written before a trampoline preheader."""

    path = _entry_to_pre_header_corridor(
        flow_graph,
        pre_header_serial=int(pre_header_serial),
        dispatcher_entry_serial=int(dispatcher_entry_serial),
    )
    if not path:
        return None
    resolved = find_last_state_write_site_on_path_snapshot(
        flow_graph,
        path,
        int(state_var_stkoff),
    )
    if resolved is None:
        return None
    _write_block, site = resolved
    return int(site.state_value) & 0xFFFFFFFF, path


def _merge_compatible_state_dispatcher_maps(
    *,
    dispatcher_entry_serial: int,
    maps: tuple[StateDispatcherMap, ...],
) -> StateDispatcherMap | None:
    """Return one phase map that includes compatible suffix-chain rows.

    OLLVM equality chains can be rediscovered from every compare block.  Each
    suffix map is a truthful exact relation, but consuming only the map whose
    entry is the first compare block can drop rows that live behind branch-local
    dispatcher islands.  The lowering phase needs the complete exact
    ``state -> handler`` relation, so merge maps that use the same state
    variable and source model into the primary map.
    """

    primary = next(
        (
            dispatch_map
            for dispatch_map in maps
            if int(dispatch_map.dispatcher_entry_block)
            == int(dispatcher_entry_serial)
        ),
        None,
    )
    if primary is None:
        if not maps:
            return None
        # Equality-chain extraction can produce one exact map per suffix
        # compare block.  The semantic dispatcher root may be a wider range
        # block from the generic dispatcher analysis, not one of those exact
        # suffix maps.  Keep the exact rows, but anchor the merged phase map
        # to the caller-proven root so pre-header and cleanup planning consume
        # the whole dispatcher, not just a suffix island.
        if any(
            str(getattr(dispatch_map.source, "name", ""))
            != "CONDITIONAL_CHAIN"
            for dispatch_map in maps
        ):
            return None
        primary = maps[0]

    rows_by_state: dict[int, StateDispatcherRow] = {
        int(row.state_const) & 0xFFFFFFFFFFFFFFFF: row
        for row in primary.rows
    }
    dispatcher_blocks = set(int(block) for block in primary.dispatcher_blocks)
    dispatcher_blocks.add(int(dispatcher_entry_serial))
    skipped_conflicts = 0
    skipped_incompatible = 0

    for dispatch_map in maps:
        if dispatch_map is primary:
            continue
        if dispatch_map.source != primary.source:
            skipped_incompatible += 1
            continue
        if dispatch_map.state_var_stkoff != primary.state_var_stkoff:
            skipped_incompatible += 1
            continue
        if dispatch_map.state_var_lvar_idx != primary.state_var_lvar_idx:
            skipped_incompatible += 1
            continue
        dispatcher_blocks.update(int(block) for block in dispatch_map.dispatcher_blocks)
        for row in dispatch_map.rows:
            state = int(row.state_const) & 0xFFFFFFFFFFFFFFFF
            existing = rows_by_state.get(state)
            if existing is None:
                rows_by_state[state] = row
                continue
            if (
                int(existing.target_block) == int(row.target_block)
                and existing.row_kind == row.row_kind
            ):
                continue
            skipped_conflicts += 1

    if (
        not skipped_conflicts
        and not skipped_incompatible
        and len(rows_by_state) == len(primary.rows)
        and dispatcher_blocks == set(int(block) for block in primary.dispatcher_blocks)
    ):
        return primary

    if skipped_conflicts or skipped_incompatible:
        family_logger.info(
            "Merged OLLVM state-dispatcher maps with exclusions: entry=blk[%d] "
            "rows=%d conflicts=%d incompatible=%d",
            int(dispatcher_entry_serial),
            len(rows_by_state),
            skipped_conflicts,
            skipped_incompatible,
        )
    elif len(rows_by_state) != len(primary.rows):
        family_logger.info(
            "Merged OLLVM state-dispatcher suffix maps: entry=blk[%d] "
            "rows=%d->%d maps=%d",
            int(dispatcher_entry_serial),
            len(primary.rows),
            len(rows_by_state),
            len(maps),
        )

    return StateDispatcherMap(
        rows=tuple(
            rows_by_state[state] for state in sorted(rows_by_state)
        ),
        dispatcher_entry_block=int(dispatcher_entry_serial),
        dispatcher_blocks=frozenset(dispatcher_blocks),
        state_var_stkoff=primary.state_var_stkoff,
        state_var_lvar_idx=primary.state_var_lvar_idx,
        source=primary.source,
        initial_state=primary.initial_state,
        default_target_block=primary.default_target_block,
        default_row_kind=primary.default_row_kind,
    )


def _coalesced_dispatcher_handler_states(
    dispatch_map: StateDispatcherMap | None,
) -> tuple[int, ...]:
    """Return handler states whose target is the dispatcher entry itself.

    For materialized Tigress computed-goto functions this means Hex-Rays has
    folded a label body into the dispatcher jump block.  The row is useful
    diagnostics, but it is not safe rewrite authority for phase reconstruction
    because a semantic handler and dispatcher loop share one block serial.
    """

    if dispatch_map is None:
        return ()
    dispatcher_entry = int(dispatch_map.dispatcher_entry_block)
    states = []
    for row in dispatch_map.rows:
        if not row.is_handler_row:
            continue
        if int(row.target_block) == dispatcher_entry:
            states.append(int(row.state_const) & 0xFFFFFFFFFFFFFFFF)
    return tuple(sorted(states))


def _collect_tigress_indirect_terminal_stub_modifications(
    *,
    dag: object,
    flow_graph: FlowGraph,
    dispatch_map: StateDispatcherMap | None,
    state_var_stkoff: int,
    constant_result: object,
    logger: object | None = None,
) -> tuple[GraphModification, ...]:
    """Repair computed-goto stubs that recon classified as terminal.

    Tigress indirect label tables can materialize as ``handler -> empty stub``
    in Hex-Rays even when the handler just wrote the next dispatcher state and
    loaded the computed target.  The native xref is enough for IDA to see the
    label targets, but the microcode snapshot can still end the state DAG at the
    empty stub.  Only repair that shape when the written state resolves through
    the exact indirect ``StateDispatcherMap``.
    """

    if dispatch_map is None:
        return ()

    dispatcher_entry = int(dispatch_map.dispatcher_entry_block)
    in_stk_maps = getattr(constant_result, "in_stk_maps", {}) or {}
    in_reg_maps = getattr(constant_result, "in_reg_maps", {}) or {}
    modifications: list[GraphModification] = []
    seen_sources: set[tuple[int, int]] = set()

    for edge in getattr(dag, "edges", ()) or ():
        kind = getattr(edge, "kind", None)
        edge_target_state = getattr(edge, "target_state", None)
        edge_kind_name = _semantic_edge_kind_name(kind)
        is_terminal_return_edge = (
            kind == SemanticEdgeKind.CONDITIONAL_RETURN
            or edge_kind_name == "CONDITIONAL_RETURN"
        )
        is_state_transition_edge = edge_target_state is not None and (
            kind
            in {
                SemanticEdgeKind.TRANSITION,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
            }
            or edge_kind_name
            in {
                "TRANSITION",
                "CONDITIONAL_TRANSITION",
            }
        )
        if not (is_terminal_return_edge or is_state_transition_edge):
            continue

        ordered_path = tuple(int(serial) for serial in getattr(edge, "ordered_path", ()) or ())
        if len(ordered_path) < 2:
            continue
        resolved = find_last_state_write_site_on_path_snapshot(
            flow_graph,
            ordered_path,
            int(state_var_stkoff),
            in_stk_maps=in_stk_maps,
            in_reg_maps=in_reg_maps,
        )
        if resolved is None:
            continue

        write_block_serial, site = resolved
        write_block = flow_graph.get_block(int(write_block_serial))
        if write_block is None or write_block.nsucc != 1:
            continue
        old_target = int(write_block.succs[0])
        if old_target == dispatcher_entry:
            continue

        try:
            write_index = ordered_path.index(int(write_block_serial))
            old_target_index = ordered_path.index(old_target)
        except ValueError:
            continue
        if old_target_index <= write_index:
            continue

        old_target_block = flow_graph.get_block(old_target)
        if (
            old_target_block is None
            or old_target_block.nsucc != 0
            or old_target_block.insn_snapshots
        ):
            continue

        next_state = int(site.state_value) & 0xFFFFFFFFFFFFFFFF
        if edge_target_state is not None and (
            int(edge_target_state) & 0xFFFFFFFFFFFFFFFF
        ) != next_state:
            continue
        target = dispatch_map.resolve_target(next_state)
        if target is None:
            continue
        target = int(target)
        if (
            target == dispatcher_entry
            or target == old_target
            or target not in flow_graph.blocks
        ):
            continue

        source_key = (int(write_block_serial), old_target)
        if source_key in seen_sources:
            continue
        seen_sources.add(source_key)
        modifications.append(
            RedirectGoto(
                from_serial=int(write_block_serial),
                old_target=old_target,
                new_target=target,
            )
        )
        if logger is not None:
            logger.info(
                "Tigress indirect terminal stub repaired: "
                "blk[%d] old=blk[%d] state=0x%X target=blk[%d] write_ea=0x%X",
                int(write_block_serial),
                old_target,
                next_state,
                target,
                int(site.insn_ea),
            )

    return tuple(modifications)


def _phase_mod_source_serial(modification: GraphModification) -> int:
    if isinstance(modification, (RedirectGoto, RedirectBranch)):
        return int(modification.from_serial)
    if isinstance(modification, (ConvertToGoto, ZeroStateWrite)):
        return int(modification.block_serial)
    return -1


def _order_phase_reconstruction_modifications(
    modifications: list[GraphModification],
    *,
    preserve_first: bool = True,
) -> list[GraphModification]:
    """Return a serial-stable order for one reconstruction batch.

    The reconstruction emitter plans edits against the same live snapshot. Some
    branch redirects lower by inserting a helper fallthrough block immediately
    after the source block, which shifts every later block serial. Applying
    lower-numbered structural edits before higher-numbered structural edits can
    therefore make a later source serial resolve to the wrong live block. Keep
    the entry redirect first, then apply structural rewrites from high serials to
    low serials so helper insertion only affects edits that have already run.
    State-write neutralizers do not create blocks, so they run after structural
    rewrites and use the deferred modifier's serial remap.
    """

    if len(modifications) <= 2:
        return list(modifications)

    entry_redirect = [modifications[0]] if preserve_first else []
    rest = list(modifications[1:] if preserve_first else modifications)

    def sort_key(modification: GraphModification) -> tuple[int, int]:
        if isinstance(modification, (RedirectGoto, RedirectBranch, ConvertToGoto)):
            return (0, -_phase_mod_source_serial(modification))
        if isinstance(modification, ZeroStateWrite):
            return (1, -_phase_mod_source_serial(modification))
        return (2, -_phase_mod_source_serial(modification))

    return entry_redirect + sorted(rest, key=sort_key)


def _dag_has_terminal_frontier_edges(dag: object) -> bool:
    """Return whether a state DAG still carries live terminal evidence."""

    terminal_kinds = {
        SemanticEdgeKind.CONDITIONAL_RETURN,
        SemanticEdgeKind.EXIT_ROUTINE,
    }
    return any(
        getattr(edge, "kind", None) in terminal_kinds
        for edge in getattr(dag, "edges", ()) or ()
    )


def _semantic_edge_kind_name(kind: object) -> str:
    """Return a stable edge-kind name across live enums and serialized values."""

    if kind is None:
        return "NONE"
    name = getattr(kind, "name", None)
    if name is not None:
        return str(name).upper()
    value = getattr(kind, "value", None)
    if value is not None:
        return str(value).upper()
    text = str(kind).upper()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text


def _dag_edge_kind_counts(dag: object) -> Counter[str]:
    return Counter(
        _semantic_edge_kind_name(getattr(edge, "kind", None))
        for edge in getattr(dag, "edges", ()) or ()
    )


def _state_const_from_key(key: object) -> int | None:
    state_const = getattr(key, "state_const", None)
    if state_const is None:
        return None
    try:
        return int(state_const) & 0xFFFFFFFFFFFFFFFF
    except (TypeError, ValueError):
        return None


def _edge_source_state(edge: object) -> int | None:
    return _state_const_from_key(getattr(edge, "source_key", None))


def _edge_target_state(edge: object) -> int | None:
    return _state_const_from_key(getattr(edge, "target_key", None))


def _edge_return_entry(edge: object) -> int | None:
    target_entry = getattr(edge, "target_entry_anchor", None)
    if target_entry is None:
        target_entry = getattr(edge, "target_entry", None)
    if target_entry is None:
        ordered_path = tuple(int(serial) for serial in getattr(edge, "ordered_path", ()) or ())
        if ordered_path:
            target_entry = ordered_path[-1]
    if target_entry is None:
        return None
    try:
        return int(target_entry)
    except (TypeError, ValueError):
        return None


def _block_snapshot_has_memory_store(flow_graph: FlowGraph, serial: int) -> bool:
    block = flow_graph.get_block(int(serial))
    if block is None:
        return False
    for insn in block.iter_insns():
        try:
            if int(getattr(insn, "opcode", -1)) == int(ida_hexrays.m_stx):
                return True
        except (TypeError, ValueError):
            continue
    return False


def _state_has_payload_store(
    *,
    dag: object,
    flow_graph: FlowGraph,
    state: int,
) -> bool:
    state_u = int(state) & 0xFFFFFFFFFFFFFFFF
    for node in getattr(dag, "nodes", ()) or ():
        if _state_const_from_key(getattr(node, "key", None)) != state_u:
            continue
        candidate_blocks: set[int] = set()
        entry_anchor = getattr(node, "entry_anchor", None)
        if entry_anchor is not None:
            candidate_blocks.add(int(entry_anchor))
        candidate_blocks.update(int(serial) for serial in getattr(node, "owned_blocks", ()) or ())
        candidate_blocks.update(int(serial) for serial in getattr(node, "exclusive_blocks", ()) or ())
        if any(
            _block_snapshot_has_memory_store(flow_graph, serial)
            for serial in candidate_blocks
        ):
            return True
    return False


def _collect_phase_branch_ownership_proofs(
    *,
    dag: object,
    dispatch_map: StateDispatcherMap | None,
    proof_refiners: tuple[object, ...] = (),
) -> tuple[BranchOwnershipProof, ...]:
    """Collect recon branch ownership proofs for planning/diagnostics."""

    return collect_branch_ownership_proofs(
        dag=dag,
        dispatch_map=dispatch_map,
        proof_refiner=_compose_branch_ownership_refiners(tuple(proof_refiners)),
    )


def _compose_branch_ownership_refiners(
    refiners: tuple[object, ...],
):
    if not refiners:
        return None

    def _refine(
        proof: BranchOwnershipProof,
        edge: object,
    ) -> BranchOwnershipProof | None:
        current = proof
        changed = False
        for refiner in refiners:
            try:
                refined = refiner(current, edge)
            except Exception:
                continue
            if refined is None:
                continue
            current = refined
            changed = True
            if current.vetoes_fallback_refinement:
                break
        return current if changed else None

    return _refine


def _edge_has_trusted_nonsemantic_branch_proof(
    edge: object,
    *,
    branch_ownership_proofs: tuple[BranchOwnershipProof, ...] = (),
) -> bool:
    """Return whether recon proved this branch arm is non-semantic."""

    matched_nonsemantic = False
    matched_semantic = False

    for proof in _iter_branch_ownership_proofs_for_edge(
        edge,
        branch_ownership_proofs=branch_ownership_proofs,
    ):
        if (
            not _branch_ownership_proof_has_rewrite_identity(proof)
            or not _branch_ownership_proof_matches_edge(proof, edge)
        ):
            continue
        if proof.authorizes_semantic_branch_bridge:
            matched_semantic = True
        if proof.authorizes_nonsemantic_branch_rewrite:
            matched_nonsemantic = True

    return matched_nonsemantic and not matched_semantic


def _trusted_nonsemantic_branch_proof_for_edge(
    edge: object,
    *,
    branch_ownership_proofs: tuple[BranchOwnershipProof, ...] = (),
) -> BranchOwnershipProof | None:
    """Return exact nonsemantic proof for ``edge`` unless semantic proof vetoes."""

    matched_nonsemantic: BranchOwnershipProof | None = None
    matched_semantic = False
    for proof in _iter_branch_ownership_proofs_for_edge(
        edge,
        branch_ownership_proofs=branch_ownership_proofs,
    ):
        if (
            not _branch_ownership_proof_has_rewrite_identity(proof)
            or not _branch_ownership_proof_matches_edge(proof, edge)
        ):
            continue
        if proof.authorizes_semantic_branch_bridge:
            matched_semantic = True
        if proof.authorizes_nonsemantic_branch_rewrite:
            matched_nonsemantic = proof
    if matched_semantic:
        return None
    return matched_nonsemantic


def _iter_branch_ownership_proofs_for_edge(
    edge: object,
    *,
    branch_ownership_proofs: tuple[BranchOwnershipProof, ...] = (),
):
    """Yield branch ownership proof rows attached to or supplied for ``edge``."""

    proof_candidates = [
        branch_ownership_proofs,
        getattr(edge, "branch_ownership_proof", None),
        getattr(edge, "branch_ownership_proofs", None),
    ]
    metadata = getattr(edge, "metadata", None)
    if isinstance(metadata, dict):
        proof_candidates.extend((
            metadata.get("branch_ownership_proof"),
            metadata.get("branch_ownership_proofs"),
        ))
    source_anchor = getattr(edge, "source_anchor", None)
    if source_anchor is not None:
        proof_candidates.extend((
            getattr(source_anchor, "branch_ownership_proof", None),
            getattr(source_anchor, "branch_ownership_proofs", None),
        ))

    for candidate in proof_candidates:
        if candidate is None:
            continue
        candidates = candidate if isinstance(candidate, (list, tuple)) else (candidate,)
        for proof_candidate in candidates:
            proof = branch_ownership_proof_from_any(proof_candidate)
            if proof is not None:
                yield proof


def _branch_ownership_proof_has_rewrite_identity(proof: object) -> bool:
    """Return whether a trusted proof identifies a concrete edge.

    Diagnostic proof rows may be partial.  Rewrite-authorizing proofs are
    stricter: they must name the state edge, plus either the concrete target
    entry or the branch arm.  Populated identity fields are still matched
    exactly by :func:`_branch_ownership_proof_matches_edge`.
    """

    return (
        getattr(proof, "source_state", None) is not None
        and getattr(proof, "target_state", None) is not None
        and (
            getattr(proof, "target_entry", None) is not None
            or getattr(proof, "branch_arm", None) is not None
        )
    )


def _branch_ownership_proof_matches_edge(proof: object, edge: object) -> bool:
    """Return whether ``proof`` describes this exact DAG edge.

    Proof rows can be attached directly to an edge, to shared edge metadata, or
    to a source anchor.  Once producers attach proof lists to shared anchors, a
    trusted proof for one branch arm must not authorize a sibling branch.
    """

    expected_source_state = _edge_source_state(edge)
    expected_target_state = _edge_target_state(edge)
    expected_target_entry = _edge_return_entry(edge)
    source_anchor = getattr(edge, "source_anchor", None)
    expected_source_block = (
        getattr(source_anchor, "block_serial", None)
        if source_anchor is not None else None
    )
    expected_branch_arm = (
        getattr(source_anchor, "branch_arm", None)
        if source_anchor is not None else None
    )

    return all((
        _proof_field_matches(
            getattr(proof, "source_block", None),
            expected_source_block,
        ),
        _proof_field_matches(
            getattr(proof, "source_state", None),
            expected_source_state,
        ),
        _proof_field_matches(
            getattr(proof, "target_state", None),
            expected_target_state,
        ),
        _proof_field_matches(
            getattr(proof, "target_entry", None),
            expected_target_entry,
        ),
        _proof_field_matches(
            getattr(proof, "branch_arm", None),
            expected_branch_arm,
        ),
    ))


def _proof_field_matches(proof_value: object | None, edge_value: object | None) -> bool:
    if proof_value is None:
        return True
    if edge_value is None:
        return False
    try:
        return int(proof_value) == int(edge_value)
    except (TypeError, ValueError):
        return str(proof_value) == str(edge_value)


def _branch_ownership_proof_has_materialization_identity(proof: object) -> bool:
    """Return whether a proof can identify a concrete materialization edge."""

    return all((
        getattr(proof, "source_block", None) is not None,
        getattr(proof, "branch_arm", None) is not None,
        getattr(proof, "source_state", None) is not None,
        getattr(proof, "target_state", None) is not None,
        getattr(proof, "target_entry", None) is not None,
    ))


def _branch_ownership_proof_matches_materialization_edge(
    proof: object,
    edge: object,
) -> bool:
    return (
        _branch_ownership_proof_has_materialization_identity(proof)
        and _branch_ownership_proof_matches_edge(proof, edge)
    )


def _payload_store_snapshots(
    flow_graph: FlowGraph,
    payload_block: int,
) -> tuple[InsnSnapshot, ...]:
    block = flow_graph.get_block(int(payload_block))
    if block is None:
        return ()
    stores: list[InsnSnapshot] = []
    for insn in block.iter_insns():
        try:
            if int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_stx):
                continue
        except (TypeError, ValueError):
            continue
        stores.append(insn)
    return tuple(stores)


def _return_entries_by_source_state(
    dag: object,
) -> tuple[dict[int, list[int]], dict[int, set[int]], dict[int, list[object]]]:
    outgoing_by_state: dict[int, list[object]] = {}
    return_entries_by_state: dict[int, list[int]] = {}
    targets_by_source_state: dict[int, set[int]] = {}
    for edge in tuple(getattr(dag, "edges", ()) or ()):
        source_state = _edge_source_state(edge)
        if source_state is None:
            continue
        outgoing_by_state.setdefault(source_state, []).append(edge)
        target_state = _edge_target_state(edge)
        if target_state is not None:
            targets_by_source_state.setdefault(source_state, set()).add(target_state)
        kind_name = _semantic_edge_kind_name(getattr(edge, "kind", None))
        if kind_name in {"CONDITIONAL_RETURN", "EXIT_ROUTINE"}:
            return_entry = _edge_return_entry(edge)
            if return_entry is not None:
                return_entries_by_state.setdefault(source_state, []).append(
                    return_entry
                )
    return return_entries_by_state, targets_by_source_state, outgoing_by_state


def _terminal_selector_semantic_continuation(
    *,
    selector_state: int,
    payload_state: int,
    dag: object,
) -> int | None:
    (
        return_entries_by_state,
        targets_by_source_state,
        _outgoing_by_state,
    ) = _return_entries_by_source_state(dag)
    selector_targets = targets_by_source_state.get(int(selector_state), set())
    selector_returns = list(return_entries_by_state.get(int(selector_state), ()))
    for selector_target in sorted(selector_targets):
        selector_returns.extend(return_entries_by_state.get(selector_target, ()))
    selector_returns = sorted(set(int(entry) for entry in selector_returns))
    if len(selector_returns) != 1 or int(payload_state) not in selector_targets:
        return None
    return int(selector_returns[0])


def _strict_matching_proofs_for_edge(
    proofs: tuple[BranchOwnershipProof, ...],
    edge: object,
) -> tuple[BranchOwnershipProof, ...]:
    return tuple(
        proof for proof in proofs
        if _branch_ownership_proof_matches_materialization_edge(proof, edge)
    )


def _branch_arm_old_target(
    flow_graph: FlowGraph,
    source_block: int,
    branch_arm: int,
) -> int | None:
    """Return the live CFG successor for a proof edge's branch arm."""

    block = flow_graph.blocks.get(int(source_block))
    if block is None:
        return None
    successors = tuple(getattr(block, "succs", ()) or ())
    arm = int(branch_arm)
    if arm < 0 or arm >= len(successors):
        return None
    return int(successors[arm])


def _ollvm_canonical_var_token(token: str | None) -> str | None:
    if token is None:
        return None
    token = str(token).strip()
    if token.startswith("%var_"):
        suffix = []
        for char in token[5:]:
            if char.isalnum():
                suffix.append(char.upper())
                continue
            break
        return f"%var_{''.join(suffix)}" if suffix else None
    if token.startswith("v"):
        suffix = []
        for char in token[1:]:
            if char.isdigit():
                suffix.append(char)
                continue
            break
        return f"v{''.join(suffix)}" if suffix else None
    return None


def _ollvm_var_tokens_from_text(text: str) -> tuple[str, ...]:
    tokens: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("%var_", index):
            end = index + 5
            while end < len(text) and text[end].isalnum():
                end += 1
            token = _ollvm_canonical_var_token(text[index:end])
            if token is not None:
                tokens.append(token)
            index = end
            continue
        if text[index] == "v" and index + 1 < len(text) and text[index + 1].isdigit():
            end = index + 1
            while end < len(text) and text[end].isdigit():
                end += 1
            token = _ollvm_canonical_var_token(text[index:end])
            if token is not None:
                tokens.append(token)
            index = end
            continue
        index += 1
    return tuple(tokens)


def _ollvm_mop_text(mop: object | None) -> str:
    if mop is None:
        return ""
    dstr = getattr(mop, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            pass
    return str(mop)


def _ollvm_mop_var_token(mop: object | None) -> str | None:
    tokens = _ollvm_var_tokens_from_text(_ollvm_mop_text(mop))
    return tokens[0] if tokens else None


def _ollvm_insn_text(insn: object | None) -> str:
    if insn is None:
        return ""
    dstr = getattr(insn, "dstr", None)
    if callable(dstr):
        try:
            return str(dstr())
        except Exception:
            pass
    return str(insn)


def _ollvm_instruction_text_digest(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _ollvm_live_instruction_at_locator(
    mba: object,
    locator: dict[str, object],
) -> object | None:
    try:
        block_serial = int(locator.get("source_block"))  # type: ignore[arg-type]
    except Exception:
        return None
    try:
        blk = mba.get_mblock(block_serial)
    except Exception:
        return None
    if blk is None:
        return None
    expected_ea = locator.get("instruction_ea")
    expected_index = locator.get("instruction_index")
    expected_hash = str(locator.get("instruction_text_sha1") or "")
    expected_token = _ollvm_canonical_var_token(str(locator.get("carrier_token") or ""))
    expected_opcode_name = str(locator.get("instruction_opcode_name") or "")
    insn = getattr(blk, "head", None)
    index = 0
    while insn is not None:
        ea_matches = True
        if expected_ea is not None:
            try:
                ea_matches = int(getattr(insn, "ea", 0) or 0) == int(expected_ea)
            except Exception:
                ea_matches = False
        index_matches = True
        if expected_index is not None:
            try:
                index_matches = int(index) == int(expected_index)
            except Exception:
                index_matches = False
        if ea_matches and index_matches:
            text = _ollvm_insn_text(insn)
            if expected_hash and _ollvm_instruction_text_digest(text) != expected_hash:
                return None
            if expected_token is not None and expected_token not in _ollvm_var_tokens_from_text(text):
                return None
            if expected_opcode_name and expected_opcode_name.startswith("m_"):
                # Keep this a text-level check because unit and IDA runtime
                # environments represent opcode names differently.
                if not text.lstrip().startswith(expected_opcode_name[2:]):
                    return None
            return insn
        insn = getattr(insn, "next", None)
        index += 1
    return None


def _ollvm_fact_anchor_is_live(
    mba: object,
    locator: dict[str, object],
) -> bool:
    if locator.get("requires_live_revalidation") is not True:
        return False
    return _ollvm_live_instruction_at_locator(mba, locator) is not None


def _ollvm_overlap_proof_authorizes_alias_scalarization(
    proof: dict[str, object],
) -> bool:
    if proof.get("fully_included") is not True:
        return False
    if proof.get("partial_overlap") is not False:
        return False
    base = _ollvm_canonical_var_token(str(proof.get("base_token") or ""))
    carrier = _ollvm_canonical_var_token(str(proof.get("carrier_token") or ""))
    if base is None or carrier is None or base == carrier:
        return False
    return True


def _ollvm_stx_target_token_from_text(text: str) -> str | None:
    if ", ds" not in text:
        return None
    tail = text.rsplit(", ds", 1)[-1]
    tokens = _ollvm_var_tokens_from_text(tail)
    return tokens[-1] if tokens else None


def _ollvm_collect_local_alias_tokens(
    carrier_facts: tuple[object, ...],
) -> frozenset[str]:
    """Return fact-backed OLLVM local aliases that can be scalarized."""

    aliases: set[str] = set()
    for fact in carrier_facts:
        payload = getattr(fact, "payload", None)
        if not isinstance(payload, dict):
            continue
        details = payload.get("details")
        if not isinstance(details, dict):
            details = {}
        if production_value_flow_fact(fact, SCALAR_REPLACEMENT_FACT_TYPE):
            token = _ollvm_canonical_var_token(str(payload.get("storage_identity") or ""))
            if token is not None:
                aliases.add(token)
            continue
        if production_value_flow_fact(fact, MUST_ALIAS_FACT_TYPE):
            carrier_token = _ollvm_canonical_var_token(
                str(details.get("carrier_token") or "")
            )
            if carrier_token is not None:
                aliases.add(carrier_token)
            aliases.update(
                alias for alias in (
                    _ollvm_canonical_var_token(str(raw_alias))
                    for raw_alias in (details.get("alias_tokens") or ())
                )
                if alias is not None
            )
    return frozenset(sorted(aliases))


@dataclass(frozen=True)
class _OllvmLocalAliasScalarizationSpec:
    alias_token: str
    base_token: str
    fact_id: str
    fact_kind: str
    anchor_locator: dict[str, object]
    overlap_proof: dict[str, object]


def _ollvm_local_alias_scalarization_specs(
    carrier_facts: tuple[object, ...],
    mba: object | None = None,
) -> dict[str, _OllvmLocalAliasScalarizationSpec]:
    specs: dict[str, _OllvmLocalAliasScalarizationSpec] = {}
    for fact in carrier_facts:
        if not production_value_flow_fact(fact, SCALAR_REPLACEMENT_FACT_TYPE):
            continue
        payload = getattr(fact, "payload", None)
        if not isinstance(payload, dict):
            continue
        details = payload.get("details")
        if not isinstance(details, dict):
            details = {}
        if details.get("proof_family") != "local_expression_storage_scalarization":
            continue
        anchor_locator = payload.get("anchor_locator")
        overlap_proof = payload.get("storage_overlap_proof")
        if not isinstance(anchor_locator, dict) or not isinstance(overlap_proof, dict):
            continue
        if not _ollvm_overlap_proof_authorizes_alias_scalarization(overlap_proof):
            continue
        if mba is not None and not _ollvm_fact_anchor_is_live(mba, anchor_locator):
            continue
        alias_token = _ollvm_canonical_var_token(
            str(payload.get("storage_identity") or "")
        )
        base_token = _ollvm_canonical_var_token(
            str(details.get("local_base_token") or "")
        )
        if base_token is None:
            base_token = _ollvm_canonical_var_token(
                str(details.get("multiply_add_base_token") or "")
            )
        if alias_token is None or base_token is None or alias_token == base_token:
            continue
        specs[alias_token] = _OllvmLocalAliasScalarizationSpec(
            alias_token=alias_token,
            base_token=base_token,
            fact_id=str(getattr(fact, "fact_id", "")),
            fact_kind=SCALAR_REPLACEMENT_FACT_TYPE,
            anchor_locator=dict(anchor_locator),
            overlap_proof=dict(overlap_proof),
        )
    return specs


def _ollvm_local_alias_fact_ids(
    carrier_facts: tuple[object, ...],
) -> set[str]:
    return {
        str(getattr(fact, "fact_id", ""))
        for fact in carrier_facts
        if (
            production_value_flow_fact(fact, MUST_ALIAS_FACT_TYPE)
            or production_value_flow_fact(fact, SCALAR_REPLACEMENT_FACT_TYPE)
        )
    }


def _ollvm_mop_size(mop: object | None) -> int:
    try:
        return int(getattr(mop, "size", 0) or 0)
    except Exception:
        return 0


def _ollvm_widths_compatible(left: object | None, right: object | None) -> bool:
    left_size = _ollvm_mop_size(left)
    right_size = _ollvm_mop_size(right)
    return left_size > 0 and right_size > 0 and left_size == right_size


def _ollvm_has_value_width(mop: object | None) -> bool:
    return _ollvm_mop_size(mop) > 0


def _ollvm_make_lists_ready(blk: object | None) -> None:
    make_lists_ready = getattr(blk, "make_lists_ready", None)
    if callable(make_lists_ready):
        make_lists_ready()


def _verify_ollvm_carrier_mutation(
    mba: object,
    logger: object,
    label: str,
    *,
    touched_blocks: set[int],
    fact_ids: set[str],
    fact_kinds: set[str],
) -> None:
    try:
        mba.mark_chains_dirty()
    except Exception:
        pass
    try:
        mba.optimize_local(0)
    except Exception:
        pass
    logger_func = getattr(logger, "error", None)
    if not callable(logger_func):
        logger_func = lambda *args, **kwargs: None
    safe_verify(
        mba,
        f"OLLVM {label} fact-backed mutation",
        logger_func=logger_func,
        capture_blocks=sorted(touched_blocks),
        capture_metadata={
            "mutation_family": label,
            "carrier_fact_ids": sorted(fact_ids),
            "carrier_fact_kinds": sorted(fact_kinds),
        },
    )


def _ollvm_rewrite_ldx_alias_to_scalar(insn: object, alias_tokens: frozenset[str]) -> bool:
    if int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_ldx):
        return False
    source = getattr(insn, "r", None)
    dest = getattr(insn, "d", None)
    token = _ollvm_mop_var_token(source)
    if token not in alias_tokens or source is None or dest is None:
        return False
    # The ldx source is an address carrier, so it is usually pointer-sized.
    # The destination is the loaded scalar value.  Do not compare those widths;
    # require a concrete value width and let safe_verify validate the rewrite.
    if not _ollvm_has_value_width(dest):
        return False
    try:
        saved_source = ida_hexrays.mop_t()
        saved_source.assign(source)
        saved_dest = ida_hexrays.mop_t()
        saved_dest.assign(dest)
        insn.opcode = ida_hexrays.m_mov
        insn.l.assign(saved_source)
        try:
            insn.r.erase()
        except Exception:
            pass
        insn.d.assign(saved_dest)
        return True
    except Exception:
        return False


def _ollvm_rewrite_stx_alias_to_scalar(insn: object, alias_tokens: frozenset[str]) -> bool:
    if int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_stx):
        return False
    target = getattr(insn, "d", None)
    source = getattr(insn, "l", None)
    token = _ollvm_mop_var_token(target)
    if token not in alias_tokens or source is None or target is None:
        return False
    # Do not scalarize the output-like double-indirect store target
    # ``[ds:alias].8``.  That path still needs real output-pointer proof.
    target_text = _ollvm_mop_text(target)
    if "[ds" in target_text:
        return False
    if not _ollvm_widths_compatible(source, target):
        return False
    try:
        saved_source = ida_hexrays.mop_t()
        saved_source.assign(source)
        saved_target = ida_hexrays.mop_t()
        saved_target.assign(target)
        insn.opcode = ida_hexrays.m_mov
        insn.l.assign(saved_source)
        try:
            insn.r.erase()
        except Exception:
            pass
        insn.d.assign(saved_target)
        return True
    except Exception:
        return False


def _ollvm_replace_alias_load_mop(
    mop: object | None,
    alias_tokens: frozenset[str],
) -> int:
    if mop is None:
        return 0
    nested = getattr(mop, "d", None)
    if nested is None:
        return 0

    changed = 0
    if int(getattr(nested, "opcode", -1)) == int(ida_hexrays.m_ldx):
        source = getattr(nested, "r", None)
        token = _ollvm_mop_var_token(source)
        if token in alias_tokens and source is not None:
            # Nested ldx has the same address-vs-value shape: source is the
            # address carrier, while the enclosing mop carries the value width.
            if not _ollvm_has_value_width(mop):
                return 0
            try:
                replacement = ida_hexrays.mop_t()
                replacement.assign(source)
                mop.assign(replacement)
                return 1
            except Exception:
                return 0

    for side in ("l", "r", "d"):
        changed += _ollvm_replace_alias_load_mop(
            getattr(nested, side, None),
            alias_tokens,
        )
    return changed


def _ollvm_alias_access_spec_for_insn(
    insn: object,
    alias_specs: dict[str, _OllvmLocalAliasScalarizationSpec],
) -> _OllvmLocalAliasScalarizationSpec | None:
    opcode = int(getattr(insn, "opcode", -1))
    if opcode == int(ida_hexrays.m_ldx):
        return alias_specs.get(_ollvm_mop_var_token(getattr(insn, "r", None)))
    if opcode == int(ida_hexrays.m_stx):
        target_text = _ollvm_mop_text(getattr(insn, "d", None))
        if "[ds" in target_text:
            token = _ollvm_mop_var_token(getattr(insn, "d", None))
            return alias_specs.get(token)
    for side in ("l", "r", "d"):
        nested_spec = _ollvm_nested_alias_load_spec(
            getattr(insn, side, None),
            alias_specs,
        )
        if nested_spec is not None:
            return nested_spec
    return None


def _ollvm_nested_alias_load_spec(
    mop: object | None,
    alias_specs: dict[str, _OllvmLocalAliasScalarizationSpec],
) -> _OllvmLocalAliasScalarizationSpec | None:
    if mop is None:
        return None
    nested = getattr(mop, "d", None)
    if nested is None:
        return None
    if int(getattr(nested, "opcode", -1)) == int(ida_hexrays.m_ldx):
        spec = alias_specs.get(_ollvm_mop_var_token(getattr(nested, "r", None)))
        if spec is not None:
            return spec
    for side in ("l", "r", "d"):
        spec = _ollvm_nested_alias_load_spec(getattr(nested, side, None), alias_specs)
        if spec is not None:
            return spec
    return None


def _ollvm_nested_alias_value_size(
    mop: object | None,
    alias_token: str,
) -> int:
    if mop is None:
        return 0
    nested = getattr(mop, "d", None)
    if nested is None:
        return 0
    if (
        int(getattr(nested, "opcode", -1)) == int(ida_hexrays.m_ldx)
        and _ollvm_mop_var_token(getattr(nested, "r", None)) == alias_token
    ):
        return _ollvm_mop_size(mop)
    for side in ("l", "r", "d"):
        size = _ollvm_nested_alias_value_size(getattr(nested, side, None), alias_token)
        if size > 0:
            return size
    return 0


def _ollvm_alias_access_value_size(
    insn: object,
    alias_token: str,
) -> int:
    opcode = int(getattr(insn, "opcode", -1))
    if opcode == int(ida_hexrays.m_ldx):
        if _ollvm_mop_var_token(getattr(insn, "r", None)) == alias_token:
            return _ollvm_mop_size(getattr(insn, "d", None))
    if opcode == int(ida_hexrays.m_stx):
        if _ollvm_mop_var_token(getattr(insn, "d", None)) == alias_token:
            return _ollvm_mop_size(getattr(insn, "l", None))
    for side in ("l", "r", "d"):
        size = _ollvm_nested_alias_value_size(getattr(insn, side, None), alias_token)
        if size > 0:
            return size
    return 0


def _ollvm_is_local_alias_setup_move(
    insn: object,
    alias_specs: dict[str, _OllvmLocalAliasScalarizationSpec],
) -> bool:
    if int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_mov):
        return False
    dest_token = _ollvm_mop_var_token(getattr(insn, "d", None))
    if dest_token not in alias_specs:
        return False
    base_token = alias_specs[dest_token].base_token
    left_text = _ollvm_mop_text(getattr(insn, "l", None))
    if base_token == dest_token:
        return "&(" in left_text
    if "&(" in left_text and base_token in _ollvm_var_tokens_from_text(left_text):
        return True
    text = _ollvm_insn_text(insn)
    if "," not in text:
        return False
    left_text = text.rsplit(",", 1)[0]
    return "&(" in left_text and base_token in _ollvm_var_tokens_from_text(left_text)


def _ollvm_nop_insn(insn: object) -> bool:
    try:
        insn.opcode = ida_hexrays.m_nop
        for side in ("l", "r", "d"):
            mop = getattr(insn, side, None)
            if mop is None:
                continue
            try:
                mop.erase()
            except Exception:
                pass
        return True
    except Exception:
        return False


def _ollvm_collect_rdx_output_alias_mop(mba: object) -> object | None:
    output_mop = None
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        insn = getattr(blk, "head", None) if blk is not None else None
        while insn is not None:
            if int(getattr(insn, "opcode", -1)) == int(ida_hexrays.m_mov):
                left_text = _ollvm_mop_text(getattr(insn, "l", None)).lower()
                if left_text.startswith("rdx.8"):
                    dest = getattr(insn, "d", None)
                    if dest is not None:
                        try:
                            saved = ida_hexrays.mop_t()
                            saved.assign(dest)
                            output_mop = saved
                        except Exception:
                            pass
            insn = getattr(insn, "next", None)
    return output_mop


@dataclass(frozen=True)
class _OllvmCarrierFactSpec:
    kind: str
    fact_id: str
    token: str
    source_block: int
    source_ea: int
    instruction_index: int | None
    instruction_dstr: str


def _ollvm_fact_specs_by_block_ea(
    carrier_facts: tuple[object, ...],
    *,
    kind: str,
) -> dict[tuple[int, int], _OllvmCarrierFactSpec]:
    specs: dict[tuple[int, int], _OllvmCarrierFactSpec] = {}
    for fact in carrier_facts:
        payload = getattr(fact, "payload", None)
        if not isinstance(payload, dict):
            continue
        if not production_value_flow_fact(fact, kind):
            continue
        token = _ollvm_canonical_var_token(str(payload.get("storage_identity") or ""))
        source_block = payload.get("source_block")
        instruction_ea = payload.get("source_ea")
        if token is None or source_block is None or instruction_ea is None:
            continue
        details = payload.get("details")
        if not isinstance(details, dict):
            details = {}
        instruction_index = payload.get("instruction_index")
        try:
            parsed_instruction_index = (
                int(instruction_index) if instruction_index is not None else None
            )
        except Exception:
            parsed_instruction_index = None
        source_block_int = int(source_block)
        instruction_ea_int = int(instruction_ea)
        specs[(source_block_int, instruction_ea_int)] = _OllvmCarrierFactSpec(
            kind=kind,
            fact_id=str(getattr(fact, "fact_id", "")),
            token=token,
            source_block=source_block_int,
            source_ea=instruction_ea_int,
            instruction_index=parsed_instruction_index,
            instruction_dstr=str(details.get("instruction_dstr") or ""),
        )
    return specs

def _apply_carrier_output_alias_repair(
    mba: object,
    logger: object,
    carrier_facts: tuple[object, ...],
) -> int:
    if mba is None:
        return 0
    output_mop = _ollvm_collect_rdx_output_alias_mop(mba)
    if output_mop is None:
        return 0
    output_store_specs = _ollvm_fact_specs_by_block_ea(
        carrier_facts,
        kind=OBSERVABLE_MEMORY_DEF_FACT_TYPE,
    )
    if not output_store_specs:
        return 0

    changed = 0
    touched_blocks: set[int] = set()
    fact_ids: set[str] = set()
    fact_kinds: set[str] = set()
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        if blk is None:
            continue
        _ollvm_make_lists_ready(blk)
        block_changed = 0
        block_serial = int(getattr(blk, "serial", serial))
        insn = getattr(blk, "head", None)
        while insn is not None:
            if int(getattr(insn, "opcode", -1)) == int(ida_hexrays.m_stx):
                spec = output_store_specs.get((
                    block_serial,
                    int(getattr(insn, "ea", 0) or 0),
                ))
                target = getattr(insn, "d", None)
                target_token = _ollvm_mop_var_token(target)
                target_text = _ollvm_mop_text(target)
                if (
                    spec is not None
                    and target_token == spec.token
                    and "[ds" in target_text
                ):
                    try:
                        nested = getattr(target, "d", None)
                        if (
                            nested is not None
                            and int(getattr(nested, "opcode", -1))
                            == int(ida_hexrays.m_ldx)
                        ):
                            nested_source = getattr(nested, "r", None)
                            if not _ollvm_widths_compatible(output_mop, nested_source):
                                insn = getattr(insn, "next", None)
                                continue
                            nested.r.assign(output_mop)
                            block_changed += 1
                            touched_blocks.add(block_serial)
                            fact_ids.add(spec.fact_id)
                            fact_kinds.add(spec.kind)
                    except Exception:
                        pass
            insn = getattr(insn, "next", None)
        if block_changed:
            changed += block_changed
            try:
                blk.mark_lists_dirty()
            except Exception:
                pass
    if changed:
        try:
            mba.mark_chains_dirty()
        except Exception:
            pass
        _verify_ollvm_carrier_mutation(
            mba,
            logger,
            "output_alias_repair",
            touched_blocks=touched_blocks,
            fact_ids=fact_ids,
            fact_kinds=fact_kinds,
        )
        log_info = getattr(logger, "info", None)
        if callable(log_info):
            log_info(
                "OLLVM output alias repair retargeted %d final store target(s) "
                "to rdx alias from fact-backed stores=%s",
                int(changed),
                ",".join(
                    f"blk[{block}]@0x{ea:x}"
                    for block, ea in sorted(output_store_specs)
                ),
            )
    return int(changed)


def _apply_local_alias_mem2reg(
    mba: object,
    logger: object,
    carrier_facts: tuple[object, ...],
) -> int:
    if mba is None:
        return 0
    alias_specs = _ollvm_local_alias_scalarization_specs(carrier_facts, mba=mba)
    if not alias_specs:
        return 0
    queued = 0
    qty = int(getattr(mba, "qty", 0) or 0)
    setup_moves_removed = 0
    fact_ids: set[str] = set()
    try:
        from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
    except Exception:
        return 0
    modifier = DeferredGraphModifier(mba)
    queued_keys: set[tuple[int, int, int, str, str]] = set()
    for serial in range(qty):
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        if blk is None:
            continue
        _ollvm_make_lists_ready(blk)
        block_serial = int(getattr(blk, "serial", serial))
        insn = getattr(blk, "head", None)
        while insn is not None:
            if _ollvm_is_local_alias_setup_move(insn, alias_specs):
                insn = getattr(insn, "next", None)
                continue
            alias_spec = _ollvm_alias_access_spec_for_insn(
                insn,
                alias_specs,
            )
            if alias_spec is not None:
                host_ea = int(getattr(insn, "ea", 0) or 0)
                host_opcode = int(getattr(insn, "opcode", 0) or 0)
                queue_key = (
                    block_serial,
                    host_ea,
                    host_opcode,
                    alias_spec.alias_token,
                    alias_spec.base_token,
                )
                if queue_key in queued_keys:
                    insn = getattr(insn, "next", None)
                    continue
                value_size = _ollvm_alias_access_value_size(
                    insn,
                    alias_spec.alias_token,
                )
                if value_size <= 0:
                    insn = getattr(insn, "next", None)
                    continue
                queued_keys.add(queue_key)
                modifier.queue_scalarize_local_alias_access(
                    block_serial,
                    host_ea,
                    host_opcode,
                    alias_spec.alias_token,
                    alias_spec.base_token,
                    host_text_sha1=_ollvm_instruction_text_digest(
                        _ollvm_insn_text(insn)
                    ),
                    value_size=value_size,
                    description=(
                        "ollvm fact-backed local alias scalarization "
                        f"{alias_spec.alias_token}->{alias_spec.base_token} "
                        f"blk[{block_serial}]@0x{int(getattr(insn, 'ea', 0) or 0):x}"
                    ),
                )
                queued += 1
                fact_ids.add(alias_spec.fact_id)
            insn = getattr(insn, "next", None)
    if not queued:
        return 0
    try:
        applied = int(modifier.apply(
            run_optimize_local=True,
            run_deep_cleaning=False,
            verify_each_mod=True,
            rollback_on_verify_failure=True,
            transactional=True,
        ))
    except Exception:
        log_exception = getattr(logger, "exception", None)
        if callable(log_exception):
            log_exception("OLLVM local alias queued scalarization failed")
        return 0
    if applied != queued or getattr(modifier, "verify_failed", False):
        log_warning = getattr(logger, "warning", None)
        if callable(log_warning):
            log_warning(
                "OLLVM local carrier alias mem2reg rejected transactional "
                "batch: applied=%d queued=%d verify_failed=%s",
                int(applied),
                int(queued),
                bool(getattr(modifier, "verify_failed", False)),
            )
        return 0
    if applied > 0:
        try:
            mba.mark_chains_dirty()
        except Exception:
            pass
        _verify_ollvm_carrier_mutation(
            mba,
            logger,
            "local_alias_mem2reg",
            touched_blocks=set(range(qty)),
            fact_ids=fact_ids or _ollvm_local_alias_fact_ids(carrier_facts),
            fact_kinds={
                SCALAR_REPLACEMENT_FACT_TYPE,
                MUST_ALIAS_FACT_TYPE,
            },
        )
        log_info = getattr(logger, "info", None)
        if callable(log_info):
            log_info(
                "OLLVM local carrier alias mem2reg applied %d queued edit(s) "
                "for aliases=%s removed_setup_moves=%d",
                int(applied),
                ",".join(sorted(alias_specs)),
                int(setup_moves_removed),
            )
    return int(applied)


def _copy_mop(mop: object | None) -> object | None:
    if mop is None:
        return None
    try:
        copied = ida_hexrays.mop_t()
        copied.assign(mop)
        return copied
    except Exception:
        return None


def _same_carrier_alias_repair_specs(
    carrier_facts: tuple[object, ...],
) -> dict[tuple[int, int], tuple[str, frozenset[str], str]]:
    specs: dict[tuple[int, int], tuple[str, frozenset[str], str]] = {}
    for fact in carrier_facts:
        payload = getattr(fact, "payload", None)
        if not isinstance(payload, dict):
            continue
        if not production_value_flow_fact(fact, MUST_ALIAS_FACT_TYPE):
            continue
        details = payload.get("details")
        if not isinstance(details, dict):
            continue
        carrier_token = _ollvm_canonical_var_token(
            str(details.get("carrier_token") or "")
        )
        source_block = payload.get("source_block")
        instruction_ea = payload.get("source_ea")
        alias_tokens = frozenset(
            token for token in (
                _ollvm_canonical_var_token(str(alias))
                for alias in (details.get("alias_tokens") or ())
            )
            if token is not None
        )
        if (
            carrier_token is None
            or not alias_tokens
            or source_block is None
            or instruction_ea is None
        ):
            continue
        specs[(int(source_block), int(instruction_ea))] = (
            carrier_token,
            alias_tokens,
            str(getattr(fact, "fact_id", "")),
        )
    return specs


def _apply_same_carrier_alias_repairs(
    mba: object,
    logger: object,
    carrier_facts: tuple[object, ...],
) -> int:
    """Repair multiply-add operands only when exact carrier facts prove aliasing."""

    if mba is None:
        return 0
    specs = _same_carrier_alias_repair_specs(carrier_facts)
    if not specs:
        return 0
    changed = 0
    touched_blocks: set[int] = set()
    fact_ids: set[str] = set()
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        if blk is None:
            continue
        _ollvm_make_lists_ready(blk)
        block_changed = 0
        block_serial = int(getattr(blk, "serial", serial))
        insn = getattr(blk, "head", None)
        while insn is not None:
            opcode = int(getattr(insn, "opcode", -1))
            if opcode == int(ida_hexrays.m_add):
                spec = specs.get((block_serial, int(getattr(insn, "ea", 0) or 0)))
                if spec is None:
                    insn = getattr(insn, "next", None)
                    continue
                carrier_token, same_base_alias_tokens, fact_id = spec
                text = _ollvm_insn_text(insn)
                right = getattr(insn, "r", None)
                dest = getattr(insn, "d", None)
                if (
                    "#5.4" in text
                    and carrier_token in _ollvm_var_tokens_from_text(text)
                    and _ollvm_mop_var_token(right) in same_base_alias_tokens
                    and _ollvm_mop_var_token(dest) == carrier_token
                    and _ollvm_widths_compatible(right, dest)
                ):
                    try:
                        replacement = _copy_mop(dest)
                        if replacement is not None:
                            right.assign(replacement)
                            block_changed += 1
                            touched_blocks.add(block_serial)
                            fact_ids.add(fact_id)
                    except Exception:
                        pass

            insn = getattr(insn, "next", None)
        if block_changed:
            changed += block_changed
            try:
                blk.mark_lists_dirty()
            except Exception:
                pass
    if changed:
        try:
            mba.mark_chains_dirty()
        except Exception:
            pass
        _verify_ollvm_carrier_mutation(
            mba,
            logger,
            "same_carrier_alias_repair",
            touched_blocks=touched_blocks,
            fact_ids=fact_ids,
            fact_kinds={MUST_ALIAS_FACT_TYPE},
        )
        log_info = getattr(logger, "info", None)
        if callable(log_info):
            log_info(
                "OLLVM same-carrier alias repair applied %d fact-backed change(s)",
                int(changed),
            )
    return int(changed)


def _ollvm_store_target_is_direct_local(insn: object) -> bool:
    """True when a late ``m_stx`` target has collapsed to a local operand.

    OLLVM SUB/BCF stores start as explicit indirect writes through local
    pointer carriers.  After the dispatcher rewrites and GLBOPT folding, Hex-
    Rays can collapse the address operand itself to a stack/local mop while
    leaving the opcode as ``m_stx``.  At that point preserving the store as an
    indirect write is actively harmful: LVARS renders it as a pointer cast of
    the carrier value instead of a scalar carrier update.
    """

    target = getattr(insn, "d", None)
    if target is None:
        return False
    target_type = int(getattr(target, "t", -1))
    if target_type not in {
        int(getattr(ida_hexrays, "mop_S", -1000)),
        int(getattr(ida_hexrays, "mop_l", -1001)),
    }:
        return False
    try:
        text = insn.dstr()
    except Exception:
        text = str(insn)
    tail = text.rsplit(", ds", 1)[-1] if ", ds" in text else text
    return "[ds" not in tail


def _carrier_store_promotion_specs(
    carrier_facts: tuple[object, ...],
) -> frozenset[tuple[int, int]]:
    specs = _ollvm_fact_specs_by_block_ea(
        carrier_facts,
        kind=SCALAR_PROMOTION_FACT_TYPE,
    )
    return frozenset(sorted(specs))


def _is_ollvm_semantic_carrier_store(
    insn: object,
    *,
    block_serial: int,
    semantic_store_specs: frozenset[tuple[int, int]],
) -> bool:
    """True for fused OLLVM semantic carrier stores worth scalar promotion.

    OLLVM's SUB/BCF lowering often leaves the real update as a single
    ``m_stx`` whose value operand is a large ``mop_d`` tree.  Early maturities
    usually render the target as a ``[ds:carrier]`` store, but after CALLS
    reconstruction the same carrier can be folded into a direct local target.
    If left fused, IDA's lvar pass can collapse distinct logical carriers into
    the same pointer-looking local and render broken self-feeding loops.
    Hoisting the value expression into a fresh kreg preserves semantics while
    giving later passes an explicit def-use chain.
    """

    if insn is None or int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_stx):
        return False
    if (
        int(block_serial),
        int(getattr(insn, "ea", 0) or 0),
    ) not in semantic_store_specs:
        return False
    value = getattr(insn, "l", None)
    if value is None or int(getattr(value, "t", -1)) != int(ida_hexrays.mop_d):
        return False
    if getattr(value, "d", None) is None:
        return False
    return True


def _is_ollvm_direct_local_carrier_store(
    insn: object,
    *,
    block_serial: int,
    semantic_store_specs: frozenset[tuple[int, int]],
) -> bool:
    if insn is None or int(getattr(insn, "opcode", -1)) != int(ida_hexrays.m_stx):
        return False
    if (
        int(block_serial),
        int(getattr(insn, "ea", 0) or 0),
    ) not in semantic_store_specs:
        return False
    if not _ollvm_store_target_is_direct_local(insn):
        return False
    return True


def _scalarize_ollvm_direct_local_carrier_store(
    insn: object,
    logger: object,
    *,
    block_serial: int,
    semantic_store_specs: frozenset[tuple[int, int]],
) -> bool:
    """Rewrite a late direct-local ``m_stx`` carrier update into ``m_mov``."""

    if not _is_ollvm_direct_local_carrier_store(
        insn,
        block_serial=block_serial,
        semantic_store_specs=semantic_store_specs,
    ):
        return False
    source = getattr(insn, "l", None)
    dest = getattr(insn, "d", None)
    if source is None or dest is None:
        return False
    try:
        source_size = int(getattr(source, "size", 0) or 0)
        dest_size = int(getattr(dest, "size", 0) or 0)
        if dest_size > 0 and source_size > 0 and dest_size != source_size:
            return False
        if source_size > 0:
            dest.size = source_size
        getattr(insn, "r").erase()
        insn.opcode = ida_hexrays.m_mov
    except Exception:
        log_exception = getattr(logger, "exception", None)
        if callable(log_exception):
            log_exception(
                "OLLVM semantic carrier scalarization failed at blk[%d]@0x%x",
                int(block_serial),
                int(getattr(insn, "ea", 0) or 0),
            )
        return False
    log_info = getattr(logger, "info", None)
    if callable(log_info):
        log_info(
            "OLLVM semantic carrier scalarized direct-local store "
            "blk[%d]@0x%x",
            int(block_serial),
            int(getattr(insn, "ea", 0) or 0),
        )
    return True


def _apply_semantic_carrier_promotions(
    mba: object,
    logger: object,
    carrier_facts: tuple[object, ...],
) -> int:
    """Hoist fused OLLVM carrier stores through the existing scalar primitive."""

    if mba is None:
        return 0
    semantic_store_fact_specs = _ollvm_fact_specs_by_block_ea(
        carrier_facts,
        kind=SCALAR_PROMOTION_FACT_TYPE,
    )
    semantic_store_specs = frozenset(sorted(semantic_store_fact_specs))
    if not semantic_store_specs:
        return 0
    queued: set[tuple[int, int, int]] = set()
    scalarized = 0
    touched_blocks: set[int] = set()
    fact_ids: set[str] = set()
    try:
        from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
    except Exception:
        return 0

    modifier = DeferredGraphModifier(mba)
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        if blk is None:
            continue
        _ollvm_make_lists_ready(blk)
        insn = getattr(blk, "head", None)
        while insn is not None:
            block_serial = int(getattr(blk, "serial", serial))
            if _scalarize_ollvm_direct_local_carrier_store(
                insn,
                logger,
                block_serial=block_serial,
                semantic_store_specs=semantic_store_specs,
            ):
                scalarized += 1
                touched_blocks.add(block_serial)
                spec = semantic_store_fact_specs.get((
                    block_serial,
                    int(getattr(insn, "ea", 0) or 0),
                ))
                if spec is not None:
                    fact_ids.add(spec.fact_id)
                insn = getattr(insn, "next", None)
                continue
            if _is_ollvm_semantic_carrier_store(
                insn,
                block_serial=block_serial,
                semantic_store_specs=semantic_store_specs,
            ):
                key = (block_serial, int(insn.ea), int(insn.opcode))
                if key not in queued:
                    queued.add(key)
                    modifier.queue_promote_operand_to_scalar(
                        block_serial,
                        int(insn.ea),
                        int(insn.opcode),
                        "l",
                        description=(
                            "ollvm semantic carrier store value promotion "
                            f"blk[{block_serial}]@0x{int(insn.ea):x}"
                        ),
                    )
            insn = getattr(insn, "next", None)

    if not queued:
        if scalarized > 0:
            try:
                mba.mark_chains_dirty()
            except Exception:
                pass
            _verify_ollvm_carrier_mutation(
                mba,
                logger,
                "semantic_carrier_direct_store_scalarization",
                touched_blocks=touched_blocks,
                fact_ids=fact_ids,
                fact_kinds={SCALAR_PROMOTION_FACT_TYPE},
            )
        return int(scalarized)

    log_info = getattr(logger, "info", None)
    if callable(log_info):
        log_info(
            "OLLVM semantic carrier promotion queued %d fused store value(s)",
            len(queued),
        )
    try:
        applied = int(modifier.apply())
    except Exception:
        log_exception = getattr(logger, "exception", None)
        if callable(log_exception):
            log_exception("OLLVM semantic carrier promotion failed")
        return 0
    if applied > 0:
        try:
            mba.mark_chains_dirty()
        except Exception:
            pass
        _verify_ollvm_carrier_mutation(
            mba,
            logger,
            "semantic_carrier_promotion",
            touched_blocks={
                block for block, _ea, _opcode in queued
            },
            fact_ids={
                spec.fact_id
                for key, spec in semantic_store_fact_specs.items()
                if any(block == key[0] and ea == key[1] for block, ea, _opcode in queued)
            },
            fact_kinds={SCALAR_PROMOTION_FACT_TYPE},
        )
    return int(applied) + int(scalarized)


def _collect_semantic_carrier_promotion_modifications(
    mba: object,
    carrier_facts: tuple[object, ...],
) -> tuple[GraphModification, ...]:
    """Return late scalar-promotion edits for fused OLLVM carrier stores."""

    if mba is None:
        return ()
    semantic_store_specs = _carrier_store_promotion_specs(carrier_facts)
    if not semantic_store_specs:
        return ()
    modifications: list[GraphModification] = []
    seen: set[tuple[int, int, int]] = set()
    qty = int(getattr(mba, "qty", 0) or 0)
    for serial in range(qty):
        try:
            blk = mba.get_mblock(serial)
        except Exception:
            continue
        if blk is None:
            continue
        block_serial = int(getattr(blk, "serial", serial))
        insn = getattr(blk, "head", None)
        while insn is not None:
            if _is_ollvm_semantic_carrier_store(
                insn,
                block_serial=block_serial,
                semantic_store_specs=semantic_store_specs,
            ):
                key = (block_serial, int(insn.ea), int(insn.opcode))
                if key not in seen:
                    seen.add(key)
                    modifications.append(PromoteOperandToScalar(
                        block_serial=block_serial,
                        host_ea=int(insn.ea),
                        host_opcode=int(insn.opcode),
                        operand_side="l",
                    ))
            insn = getattr(insn, "next", None)
    return tuple(modifications)


def _collect_terminal_selector_payload_materialization_candidates(
    *,
    dag: object,
    flow_graph: FlowGraph,
    branch_ownership_proofs: tuple[BranchOwnershipProof, ...],
) -> tuple[TerminalSelectorPayloadMaterializationCandidate, ...]:
    """Build materialization candidates from terminal-selector gap proofs."""

    edges = tuple(getattr(dag, "edges", ()) or ())
    incoming_by_target: dict[int, list[object]] = {}
    outgoing_by_source: dict[int, list[object]] = {}
    for edge in edges:
        source_state = _edge_source_state(edge)
        target_state = _edge_target_state(edge)
        if source_state is not None:
            outgoing_by_source.setdefault(source_state, []).append(edge)
        if target_state is not None:
            incoming_by_target.setdefault(target_state, []).append(edge)

    candidates: list[TerminalSelectorPayloadMaterializationCandidate] = []
    for proof in branch_ownership_proofs:
        if (
            str(getattr(proof, "reason", ""))
            != "terminal_selector_backedge_requires_side_effect_materialization"
        ):
            continue
        evidence = getattr(proof, "evidence", {}) or {}
        if evidence.get("requires_side_effect_materialization") is not True:
            continue
        if not _branch_ownership_proof_has_materialization_identity(proof):
            continue

        selector_state = int(proof.source_state)
        payload_state = int(proof.target_state)
        payload_block = int(proof.target_entry)
        selector_source_block = int(proof.source_block)
        selector_branch_arm = int(proof.branch_arm)
        selector_old_target = _branch_arm_old_target(
            flow_graph,
            selector_source_block,
            selector_branch_arm,
        )
        if selector_old_target is None:
            continue

        selector_edges = tuple(
            edge for edge in outgoing_by_source.get(selector_state, ())
            if _branch_ownership_proof_matches_materialization_edge(proof, edge)
        )
        if len(selector_edges) != 1:
            continue
        payload_backedges = tuple(
            edge for edge in outgoing_by_source.get(payload_state, ())
            if _edge_target_state(edge) == selector_state
        )
        if len(payload_backedges) != 1:
            continue
        payload_backedge_target = _edge_return_entry(payload_backedges[0])
        if payload_backedge_target is None:
            continue

        semantic_continuation = _terminal_selector_semantic_continuation(
            selector_state=selector_state,
            payload_state=payload_state,
            dag=dag,
        )
        if semantic_continuation is None:
            continue

        side_effect_instructions = _payload_store_snapshots(
            flow_graph,
            payload_block,
        )
        if not side_effect_instructions:
            continue

        external_edges = tuple(
            edge for edge in incoming_by_target.get(payload_state, ())
            if not _branch_ownership_proof_matches_materialization_edge(proof, edge)
        )
        if not external_edges:
            continue

        external_incoming: list[TerminalSelectorPayloadIncomingEdge] = []
        rejected = False
        for external_edge in external_edges:
            matching_proofs = _strict_matching_proofs_for_edge(
                branch_ownership_proofs,
                external_edge,
            )
            if any(
                matching.authorizes_semantic_branch_bridge
                for matching in matching_proofs
            ):
                rejected = True
                break
            veto_proofs = tuple(
                matching for matching in matching_proofs
                if matching.vetoes_fallback_refinement
            )
            if len(veto_proofs) != 1:
                rejected = True
                break
            veto = veto_proofs[0]
            reason = str(
                (getattr(veto, "evidence", {}) or {}).get(
                    "side_effect_guard_reason",
                    "",
                )
            )
            if not reason:
                rejected = True
                break
            old_target = _branch_arm_old_target(
                flow_graph,
                int(veto.source_block),
                int(veto.branch_arm),
            )
            if old_target is None:
                rejected = True
                break
            external_incoming.append(TerminalSelectorPayloadIncomingEdge(
                source_block=int(veto.source_block),
                branch_arm=int(veto.branch_arm),
                old_target=int(old_target),
                source_state=int(veto.source_state),
                target_state=int(veto.target_state),
                target_entry=int(veto.target_entry),
                veto_proof_id=str(veto.proof_id),
                side_effect_guard_reason=reason,
            ))
        if rejected or not external_incoming:
            continue

        candidates.append(TerminalSelectorPayloadMaterializationCandidate(
            selector_source_block=selector_source_block,
            selector_branch_arm=selector_branch_arm,
            selector_old_target=int(selector_old_target),
            selector_state=selector_state,
            payload_state=payload_state,
            payload_block=payload_block,
            payload_backedge_target=int(payload_backedge_target),
            semantic_continuation=int(semantic_continuation),
            side_effect_corridor_blocks=(payload_block,),
            side_effect_instructions=side_effect_instructions,
            selector_blocked_proof_id=str(proof.proof_id),
            selector_residue_proof_id=str(
                evidence.get("opaque_selected_proof_id") or ""
            ),
            external_incoming_edges=tuple(external_incoming),
        ))
    return tuple(candidates)


def _terminal_selector_payload_materialization_modifications(
    candidate: TerminalSelectorPayloadMaterializationCandidate,
) -> tuple[GraphModification, ...]:
    """Lower a materialization candidate to existing PatchPlan primitives."""

    modifications: list[GraphModification] = []
    modifications.append(InsertBlock(
        pred_serial=int(candidate.selector_source_block),
        succ_serial=int(candidate.semantic_continuation),
        instructions=candidate.side_effect_instructions,
        old_target_serial=int(candidate.selector_old_target),
    ))
    for incoming in candidate.external_incoming_edges:
        modifications.append(InsertBlock(
            pred_serial=int(incoming.source_block),
            succ_serial=int(candidate.semantic_continuation),
            instructions=candidate.side_effect_instructions,
            old_target_serial=int(incoming.old_target),
        ))
    return tuple(modifications)


def _compile_terminal_selector_payload_materialization_modifications(
    candidate: TerminalSelectorPayloadMaterializationCandidate,
    flow_graph: FlowGraph,
) -> tuple[tuple[GraphModification, ...], str | None]:
    """Return validated materialization edits or a blocker reason."""

    if int(candidate.selector_branch_arm) != 1:
        return (), "terminal_payload_materialization_selector_arm_not_supported"

    modifications = _terminal_selector_payload_materialization_modifications(
        candidate
    )
    try:
        patch_plan = compile_patch_plan(modifications, flow_graph)
    except Exception:
        return (), "terminal_payload_materialization_patch_plan_failed"

    expected_step_count = len(candidate.external_incoming_edges) + 1
    if len(patch_plan.steps) != expected_step_count:
        return (), "terminal_payload_materialization_unexpected_patch_plan"

    rewritten_continuation = patch_plan.relocation_map.rewrite_serial(
        int(candidate.semantic_continuation)
    )

    selector_step = patch_plan.steps[0]
    if not isinstance(selector_step, PatchInsertBlock):
        return (), "terminal_payload_materialization_missing_selector_insert"
    if (
        int(selector_step.pred_serial) != int(candidate.selector_source_block)
        or int(selector_step.succ_serial) != int(rewritten_continuation)
        or int(selector_step.old_target_serial or -1) != int(candidate.selector_old_target)
        or tuple(selector_step.instructions) != tuple(candidate.side_effect_instructions)
    ):
        return (), "terminal_payload_materialization_selector_identity_mismatch"

    for index, incoming in enumerate(candidate.external_incoming_edges, start=1):
        step = patch_plan.steps[index]
        if not isinstance(step, PatchInsertBlock):
            return (), "terminal_payload_materialization_missing_insert_block"
        if (
            int(step.pred_serial) != int(incoming.source_block)
            or int(step.succ_serial) != int(rewritten_continuation)
            or int(step.old_target_serial or -1) != int(incoming.old_target)
            or tuple(step.instructions) != tuple(candidate.side_effect_instructions)
        ):
            return (), "terminal_payload_materialization_insert_identity_mismatch"

    return modifications, None


def _candidate_has_owned_or_split_lowering(
    candidate: object,
    flow_graph: FlowGraph,
    *,
    split_via_pred: int | None = None,
) -> bool:
    """Return whether proof-gated retargeting has a safe CFG edit shape."""

    mode = str(getattr(candidate, "emission_mode", "") or "")
    horizon = getattr(candidate, "horizon_block", None)
    if horizon is None:
        return False
    try:
        horizon = int(horizon)
    except (TypeError, ValueError):
        return False

    if mode == "pred_split":
        shared = getattr(candidate, "first_shared_block", None)
        via_pred = getattr(candidate, "via_pred", None)
        if shared is None or via_pred is None:
            return False
        try:
            shared = int(shared)
            via_pred = int(via_pred)
        except (TypeError, ValueError):
            return False
        shared_block = flow_graph.get_block(shared)
        return (
            shared_block is not None
            and via_pred in tuple(int(pred) for pred in getattr(shared_block, "preds", ()) or ())
        )

    if (
        getattr(candidate, "first_shared_block", None) is not None
        or getattr(candidate, "via_pred", None) is not None
    ):
        return False

    horizon_block = flow_graph.get_block(horizon)
    if horizon_block is None or int(getattr(horizon_block, "npred", 0)) > 1:
        if split_via_pred is None:
            return False
        try:
            split_via_pred = int(split_via_pred)
        except (TypeError, ValueError):
            return False
        if horizon_block is None:
            return False
        if split_via_pred not in tuple(
            int(pred) for pred in getattr(horizon_block, "preds", ()) or ()
        ):
            return False
        pred_block = flow_graph.get_block(split_via_pred)
        if pred_block is None:
            return False
        return horizon in tuple(
            int(succ) for succ in getattr(pred_block, "succs", ()) or ()
        )
    if mode == "direct":
        return int(getattr(horizon_block, "nsucc", 0)) == 1
    if mode == "conditional_arm":
        return int(getattr(horizon_block, "nsucc", 0)) == 2
    return False


def _terminal_payload_split_via_pred_for_candidate(
    *,
    candidate: object,
    selector_edges: tuple[object, ...],
    flow_graph: FlowGraph,
    branch_ownership_proofs: tuple[BranchOwnershipProof, ...] = (),
) -> int | None:
    """Return the selector predecessor that can be split for shared payloads."""

    edge = getattr(candidate, "edge", None)
    if edge is None:
        return None
    source_state = _edge_source_state(edge)
    if source_state is None:
        return None
    try:
        horizon = int(getattr(candidate, "horizon_block"))
    except (TypeError, ValueError):
        return None
    source_block = flow_graph.get_block(horizon)
    if source_block is None or int(getattr(source_block, "npred", 0)) <= 1:
        return None
    for selector_edge in selector_edges:
        if _edge_target_state(selector_edge) != source_state:
            continue
        proof = _trusted_nonsemantic_branch_proof_for_edge(
            selector_edge,
            branch_ownership_proofs=branch_ownership_proofs,
        )
        if proof is None:
            continue
        via_pred = getattr(proof, "source_block", None)
        if via_pred is None:
            continue
        try:
            via_pred = int(via_pred)
        except (TypeError, ValueError):
            continue
        pred_block = flow_graph.get_block(via_pred)
        if pred_block is None:
            continue
        if horizon not in tuple(
            int(succ) for succ in getattr(pred_block, "succs", ()) or ()
        ):
            continue
        if via_pred not in tuple(
            int(pred) for pred in getattr(source_block, "preds", ()) or ()
        ):
            continue
        return via_pred
    return None


def _terminal_payload_edge_split_replacement(
    *,
    candidate: object,
    modification: object,
    dag: object,
    flow_graph: FlowGraph,
    branch_ownership_proofs: tuple[BranchOwnershipProof, ...],
) -> tuple[EdgeRedirectViaPredSplit, ...] | None:
    """Replace a shared payload direct retarget with a pred-scoped clone."""

    if not isinstance(modification, RedirectGoto):
        return None
    edge = getattr(candidate, "edge", None)
    if edge is None:
        return None
    source_state = _edge_source_state(edge)
    target_state = _edge_target_state(edge)
    if source_state is None or target_state is None:
        return None
    selector_edges = tuple(
        selector_edge
        for selector_edge in getattr(dag, "edges", ()) or ()
        if _edge_source_state(selector_edge) == target_state
    )
    via_pred = _terminal_payload_split_via_pred_for_candidate(
        candidate=candidate,
        selector_edges=selector_edges,
        flow_graph=flow_graph,
        branch_ownership_proofs=branch_ownership_proofs,
    )
    if via_pred is None:
        return None
    return (
        EdgeRedirectViaPredSplit(
            src_block=int(modification.from_serial),
            old_target=int(modification.old_target),
            new_target=int(modification.new_target),
            via_pred=int(via_pred),
        ),
    )


def _retarget_ollvm_terminal_payload_backedges(
    *,
    dag: object,
    flow_graph: FlowGraph,
    raw_candidates: list,
    branch_ownership_proofs: tuple[BranchOwnershipProof, ...] = (),
    logger: object,
) -> list:
    """Send proven opaque terminal payload states to the return frontier.

    The StateDispatcherMap OLLVM path can prove the exact row graph before
    lowering, but the raw graph may still contain an OLLVM BCF tail pattern:

    ``payload_state -> selector_state``
        The payload block performs a memory store, then writes a selector state.

    ``selector_state -> payload_state | return_state``
        The selector may be controlled by an opaque predicate, but topology is
        not proof.  A real data-dependent retry loop has the same outer shape.

    For this shape, retargeting is allowed only when recon has attached a
    trusted :class:`BranchOwnershipProof` to the selector-to-payload edge.
    Without that ownership proof the candidate is left unchanged, even if the
    graph shape would remove a residual ``while (1)`` in the sampled output.
    """

    edges = tuple(getattr(dag, "edges", ()) or ())
    outgoing_by_state: dict[int, list[object]] = {}
    return_entries_by_state: dict[int, list[int]] = {}
    targets_by_source_state: dict[int, set[int]] = {}

    for edge in edges:
        source_state = _edge_source_state(edge)
        if source_state is None:
            continue
        outgoing_by_state.setdefault(source_state, []).append(edge)
        target_state = _edge_target_state(edge)
        if target_state is not None:
            targets_by_source_state.setdefault(source_state, set()).add(target_state)
        kind_name = _semantic_edge_kind_name(getattr(edge, "kind", None))
        if kind_name in {"CONDITIONAL_RETURN", "EXIT_ROUTINE"}:
            return_entry = _edge_return_entry(edge)
            if return_entry is not None:
                return_entries_by_state.setdefault(source_state, []).append(return_entry)

    rewritten: list = []
    retargeted = 0
    for candidate in raw_candidates:
        edge = getattr(candidate, "edge", None)
        if edge is None:
            rewritten.append(candidate)
            continue
        kind_name = _semantic_edge_kind_name(getattr(edge, "kind", None))
        if kind_name != "TRANSITION":
            rewritten.append(candidate)
            continue
        source_state = _edge_source_state(edge)
        target_state = _edge_target_state(edge)
        if source_state is None or target_state is None:
            rewritten.append(candidate)
            continue
        source_edges = outgoing_by_state.get(source_state, ())
        if len(source_edges) != 1:
            rewritten.append(candidate)
            continue
        if not _state_has_payload_store(
            dag=dag,
            flow_graph=flow_graph,
            state=source_state,
        ):
            rewritten.append(candidate)
            continue

        selector_edges = outgoing_by_state.get(target_state, ())
        has_selector_payload_proof = any(
            _edge_target_state(selector_edge) == source_state
            and _trusted_nonsemantic_branch_proof_for_edge(
                selector_edge,
                branch_ownership_proofs=branch_ownership_proofs,
            ) is not None
            for selector_edge in selector_edges
        )
        if not has_selector_payload_proof:
            rewritten.append(candidate)
            continue

        split_via_pred = _terminal_payload_split_via_pred_for_candidate(
            candidate=candidate,
            selector_edges=tuple(selector_edges),
            flow_graph=flow_graph,
            branch_ownership_proofs=branch_ownership_proofs,
        )
        if not _candidate_has_owned_or_split_lowering(
            candidate,
            flow_graph,
            split_via_pred=split_via_pred,
        ):
            rewritten.append(candidate)
            continue

        selector_targets = targets_by_source_state.get(target_state, set())
        selector_returns = list(return_entries_by_state.get(target_state, ()))
        for selector_target in sorted(selector_targets):
            selector_returns.extend(return_entries_by_state.get(selector_target, ()))
        selector_returns = sorted(set(int(entry) for entry in selector_returns))
        if len(selector_returns) != 1 or source_state not in selector_targets:
            rewritten.append(candidate)
            continue
        return_entry = int(selector_returns[0])
        if int(getattr(candidate, "target_entry", -1)) == return_entry:
            rewritten.append(candidate)
            continue

        rewritten.append(replace(candidate, target_entry=return_entry))
        retargeted += 1
        logger.info(
            "OLLVM terminal payload backedge retargeted: state=0x%08X "
            "selector=0x%08X target_entry blk[%d]->blk[%d]",
            source_state & 0xFFFFFFFF,
            target_state & 0xFFFFFFFF,
            int(getattr(candidate, "target_entry", -1)),
            return_entry,
        )

    if retargeted:
        logger.info(
            "OLLVM terminal payload backedge rewrite retargeted %d candidate(s)",
            retargeted,
        )
    return rewritten


def _dag_has_unknown_state_exits(dag: object) -> bool:
    """Return whether the DAG still has unresolved state-machine exits.

    Reconstruction emits ``ZeroStateWrite`` neutralizers after redirecting a
    state edge so the dispatcher state variable no longer keeps an obsolete
    state live.  That is only safe when the current phase covers the state
    machine well enough that any remaining dispatcher re-entry is irrelevant.
    OLLVM equality-chain functions often become solvable in layers: the first
    phase redirects the proven exact rows, then a later residual pass consumes
    the handler corridors that were not yet resolved.  If we zero state writes
    while UNKNOWN exits remain, that later pass rediscovers a synthetic
    ``0`` state and can collapse unrelated semantic corridors together.
    """

    for edge in getattr(dag, "edges", ()) or ():
        kind = getattr(edge, "kind", None)
        if kind == SemanticEdgeKind.UNKNOWN:
            return True
        if _semantic_edge_kind_name(kind) == "UNKNOWN":
            return True
    return False


def _exact_dispatcher_entry_by_state(
    phase_context: EmulatedDispatcherPhaseContext | None,
) -> dict[int, int]:
    """Return exact state-map handler entries attached to a phase context."""

    dispatch_map = (
        getattr(phase_context, "state_dispatcher_map", None)
        if phase_context is not None
        else None
    )
    if dispatch_map is None:
        return {}
    entries: dict[int, int] = {}
    for row in getattr(dispatch_map, "rows", ()) or ():
        if not bool(getattr(row, "is_handler_row", False)):
            continue
        entries[int(row.state_const) & 0xFFFFFFFFFFFFFFFF] = int(row.target_block)
    return entries


def _phase_node_entry_by_state(
    *,
    dag: object,
    phase_context: EmulatedDispatcherPhaseContext | None,
    flow_graph: FlowGraph | None,
    logger: object | None = None,
) -> dict[int, int]:
    """Build the entry target map used by phase lowerers.

    The DAG may contain supplemental/local nodes that share a state constant
    with an exact equality-chain row.  Those nodes are useful for semantic
    path discovery, but they are not allowed to replace the dispatcher table's
    own ``state -> handler`` ownership when choosing the phase entry target.
    Prefer exact ``StateDispatcherMap`` rows whenever the target block is still
    present, then fall back to the first DAG node for the state.  Choosing the
    first DAG entry is deliberate: later supplemental aliases should enrich the
    state, not silently overwrite the canonical handler selected earlier.
    """

    node_entries: dict[int, list[int]] = {}
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        state_const = getattr(key, "state_const", None)
        entry_anchor = getattr(node, "entry_anchor", None)
        if state_const is None or entry_anchor is None:
            continue
        state = int(state_const) & 0xFFFFFFFFFFFFFFFF
        entry = int(entry_anchor)
        entries = node_entries.setdefault(state, [])
        if entry not in entries:
            entries.append(entry)

    exact_entries = _exact_dispatcher_entry_by_state(phase_context)
    resolved: dict[int, int] = {}
    for state in sorted(set(node_entries) | set(exact_entries)):
        entries = node_entries.get(state, [])
        exact_entry = exact_entries.get(state)
        exact_available = exact_entry is not None and (
            flow_graph is None or flow_graph.get_block(int(exact_entry)) is not None
        )
        if exact_available:
            chosen = int(exact_entry)
        elif entries:
            chosen = int(entries[0])
        else:
            continue
        resolved[state] = chosen
        if logger is not None and (
            len(entries) > 1
            or (
                exact_available
                and entries
                and int(entries[0]) != int(exact_entry)
            )
        ):
            logger.info(
                "Phase state entry map resolved duplicate state 0x%X: "
                "dag_entries=%s exact_entry=%s chosen=blk[%d]",
                state & 0xFFFFFFFF,
                tuple(entries),
                (
                    "None"
                    if exact_entry is None
                    else f"blk[{int(exact_entry)}]"
                ),
                chosen,
            )
    return resolved


def _phase_reconstruction_reorder_blocks_from_dag(
    *,
    dag: object,
    flow_graph: FlowGraph,
    initial_state: int | None,
    excluded_blocks: set[int] | frozenset[int] | tuple[int, ...] = (),
) -> ReorderBlocks | None:
    """Build a DFS block-ordering pass from a reconstructed state DAG.

    State-dispatcher-map reconstruction already redirects concrete CFG edges
    using DAG evidence.  For large OLLVM equality-chain functions that is not
    always enough: the live blocks remain physically interleaved with old
    dispatcher corridors, and Hex-Rays may structure the redirected graph by
    dropping semantically important late branches.  Reordering copies the
    semantic blocks in state-DFS order after the redirects, leaving dispatcher
    route blocks behind for DCE.

    This helper is intentionally conservative.  It only orders blocks that the
    DAG already owns or names in an edge path, skips dispatcher/BST blocks, and
    never asks the backend to copy the function stop block.
    """

    initial_state_u: int | None = (
        (int(initial_state) & 0xFFFFFFFFFFFFFFFF)
        if initial_state is not None
        else None
    )
    excluded = {int(serial) for serial in excluded_blocks}
    nodes_by_state: dict[int, list[object]] = {}
    for node in getattr(dag, "nodes", ()) or ():
        key = getattr(node, "key", None)
        state_const = getattr(key, "state_const", None)
        if state_const is None:
            continue
        nodes_by_state.setdefault(
            int(state_const) & 0xFFFFFFFFFFFFFFFF,
            [],
        ).append(node)

    if initial_state_u is None or initial_state_u not in nodes_by_state:
        return None

    edges_by_source: dict[int, list[object]] = {}
    terminal_edges: list[object] = []
    for edge in getattr(dag, "edges", ()) or ():
        source_key = getattr(edge, "source_key", None)
        source_state = getattr(source_key, "state_const", None)
        if source_state is None:
            continue
        source_state_u = int(source_state) & 0xFFFFFFFFFFFFFFFF
        edges_by_source.setdefault(source_state_u, []).append(edge)
        if getattr(edge, "target_key", None) is None:
            terminal_edges.append(edge)

    def _edge_sort_key(edge: object) -> tuple[int, int, tuple[int, ...]]:
        source_anchor = getattr(edge, "source_anchor", None)
        branch_arm = getattr(source_anchor, "branch_arm", None)
        arm_key = 99 if branch_arm is None else int(branch_arm)
        kind_name = _semantic_edge_kind_name(getattr(edge, "kind", None))
        terminal_key = 1 if kind_name in {"CONDITIONAL_RETURN", "EXIT_ROUTINE"} else 0
        return (
            terminal_key,
            arm_key,
            tuple(int(serial) for serial in getattr(edge, "ordered_path", ()) or ()),
        )

    for edge_list in edges_by_source.values():
        edge_list.sort(key=_edge_sort_key)

    seen_blocks: set[int] = set()
    ordered_blocks: list[int] = []

    def _append_block(serial: object) -> None:
        try:
            serial_i = int(serial)
        except (TypeError, ValueError):
            return
        if serial_i in seen_blocks or serial_i in excluded:
            return
        block = flow_graph.get_block(serial_i)
        if block is None:
            return
        if int(getattr(block, "block_type", -1)) == int(ida_hexrays.BLT_STOP):
            return
        seen_blocks.add(serial_i)
        ordered_blocks.append(serial_i)

    def _append_node(node: object) -> None:
        entry_anchor = getattr(node, "entry_anchor", None)
        if entry_anchor is not None:
            _append_block(entry_anchor)
        for serial in getattr(node, "owned_blocks", ()) or ():
            _append_block(serial)
        for serial in getattr(node, "exclusive_blocks", ()) or ():
            _append_block(serial)

    visited_states: set[int] = set()

    def _dfs_state(state: int) -> None:
        state_u = int(state) & 0xFFFFFFFFFFFFFFFF
        if state_u in visited_states:
            return
        visited_states.add(state_u)
        for node in nodes_by_state.get(state_u, ()):
            _append_node(node)
        for edge in edges_by_source.get(state_u, ()):
            for serial in getattr(edge, "ordered_path", ()) or ():
                _append_block(serial)
            target_entry = getattr(edge, "target_entry_anchor", None)
            if target_entry is not None:
                _append_block(target_entry)
            target_key = getattr(edge, "target_key", None)
            target_state = getattr(target_key, "state_const", None)
            if target_state is not None:
                _dfs_state(int(target_state))

    _dfs_state(initial_state_u)

    # Include unreachable/supplemental DAG nodes after the reachable walk so the
    # backend still has a stable order for residual rows that recon discovered
    # but the root pass cannot reach because of unresolved exits.
    for state in sorted(nodes_by_state):
        _dfs_state(state)

    # Terminal edges can have no target node.  They may still name concrete
    # return-frontier blocks, so append those paths after state-owned blocks.
    for edge in sorted(terminal_edges, key=_edge_sort_key):
        for serial in getattr(edge, "ordered_path", ()) or ():
            _append_block(serial)
        target_entry = getattr(edge, "target_entry_anchor", None)
        if target_entry is not None:
            _append_block(target_entry)

    if not ordered_blocks:
        return None

    non_2way: list[int] = []
    two_way: list[int] = []
    for serial in ordered_blocks:
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        if int(getattr(block, "block_type", -1)) == int(ida_hexrays.BLT_2WAY):
            two_way.append(serial)
        else:
            non_2way.append(serial)

    return ReorderBlocks(
        dfs_block_order=tuple(ordered_blocks),
        non_2way_serials=tuple(non_2way),
        two_way_serials=tuple(two_way),
    )


def _format_use_def_violations(
    violations: tuple[object, ...],
    *,
    limit: int = 8,
) -> str:
    details = "; ".join(
        f"var_stk[{int(getattr(violation, 'var_stkoff', 0)):#x}]"
        f"@blk[{int(getattr(violation, 'use_block', -1))}]"
        for violation in violations[:limit]
    )
    if len(violations) > limit:
        details = f"{details}; ..."
    return details


def _emit_use_def_veto_provenance(
    *,
    mba: object,
    modification: RedirectGoto | RedirectBranch,
    action: str,
    reason_prefix: str,
    target_state_text: str,
    violations: tuple[object, ...],
) -> None:
    """Persist phase-lowering use-def severance as CFG provenance.

    The state-dispatcher-map path can now recognize the OLLVM dispatcher and
    build a large semantic DAG, but direct CFG rewrites may still bypass payload
    definitions that later uses depend on.  In map-backed OLLVM phases this is
    advisory by default because the alternative is to block the exact
    dispatcher-map lowering and keep the legacy partially-flattened structure.
    Hard-veto mode is still available for residual terminal phases and explicit
    debugging.  Keep the payload compact and bounded: the row records the full
    count plus a short sample of orphaned uses, enough to identify the damaged
    variable/corridor in the diag DB.
    """

    try:
        from d810.cfg.observability import observe_cfg_provenance_latest

        sample_limit = 16
        func_ea = int(getattr(mba, "entry_ea", 0) or 0)
        observe_cfg_provenance_latest(
            func_ea=func_ea,
            pass_name="EmulatedDispatcherUnflattener",
            action=str(action),
            block_serial=int(modification.from_serial),
            target_serial=int(modification.new_target),
            reason=f"{reason_prefix}_use_def_severance",
            extra={
                "old_target": int(modification.old_target),
                "target_state": str(target_state_text),
                "orphaned_use_count": len(violations),
                "orphaned_uses_sample": [
                    {
                        "var_stkoff": int(getattr(violation, "var_stkoff", 0)),
                        "var_size": int(getattr(violation, "var_size", 0)),
                        "use_block": int(getattr(violation, "use_block", -1)),
                        "use_ea": (
                            "0x"
                            f"{int(getattr(violation, 'use_ea', 0)) & 0xFFFFFFFFFFFFFFFF:016x}"
                        ),
                    }
                    for violation in violations[:sample_limit]
                ],
            },
            mba=mba,
        )
    except Exception:
        family_logger.debug(
            "Phase reconstruction use-def veto provenance emission failed",
            exc_info=True,
        )


@dataclass(frozen=True)
class GenericDispatcherEngineProfile:
    """Detector/resolver profile for the shared dispatcher engine family."""

    name: str
    collector_factory: Callable[[], GenericDispatcherCollectorProtocol]
    resolver_factory: Callable[[], GenericDispatcherResolverProtocol]
    state_transport: str
    lowering_mode: str
    provenance_hints: tuple[str, ...] = ()
    prefer_switch_transition_facts: bool = False
    allow_incomplete_switch_transition_facts: bool = False
    enable_terminal_payload_materialization: bool = False
    enable_phase_reorder: bool = False
    enable_predecessor_dispatcher_target_lowering: bool = False
    state_dispatcher_map_factory: Callable[
        [object, object, tuple[object, ...]],
        tuple[StateDispatcherMap, ...],
    ] = _empty_state_dispatcher_maps
    switch_case_transition_fact_factory: Callable[
        [object, StateDispatcherMap, str],
        tuple[object, ...],
    ] = _empty_switch_case_transition_facts
    post_execute_carrier_fact_factory: Callable[
        [object],
        tuple[object, ...],
    ] = _empty_post_execute_carrier_facts
    fact_observation_factory: Callable[
        [object],
        tuple[object, ...],
    ] = _empty_profile_fact_observations
    branch_ownership_refiner_factory: Callable[
        [object, object],
        tuple[object, ...],
    ] = _empty_branch_ownership_refiners

    def configure_resolver(
        self,
        resolver: GenericDispatcherResolverProtocol,
        *,
        mba: ida_hexrays.mba_t,
        detection: "EmulatedDispatcherDetection",
    ) -> GenericDispatcherResolverProtocol:
        """Bind live MBA context to a resolver instance for this profile."""

        resolver.mba = mba
        resolver.cur_maturity = mba.maturity
        resolver.cur_maturity_pass = 0
        resolver.dispatcher_list = list(detection.collector_dispatchers)
        return resolver

    def dispatcher_entry_block(self, dispatcher_info: object) -> object | None:
        """Return the profile's dispatcher entry object, if one exists."""

        return getattr(dispatcher_info, "entry_block", None)

    def dispatcher_entry_serial(self, dispatcher_info: object) -> int | None:
        """Return the serial for one dispatcher candidate's entry block."""

        entry_block = self.dispatcher_entry_block(dispatcher_info)
        if entry_block is None:
            return None
        try:
            return int(entry_block.serial)
        except Exception:
            return None

    def dispatcher_predecessor_serials(
        self,
        dispatcher_info: object,
    ) -> tuple[int, ...] | None:
        """Return live predecessor serials for one dispatcher candidate.

        ``None`` means the profile could not expose the entry topology at all;
        an empty tuple means the entry topology exists but has no predecessors.
        """

        entry_block = self.dispatcher_entry_block(dispatcher_info)
        blk = getattr(entry_block, "blk", None) if entry_block is not None else None
        predset = getattr(blk, "predset", None)
        if predset is None:
            return None
        try:
            return tuple(int(serial) for serial in list(predset))
        except Exception:
            return None

    def collect_dispatcher_father_histories(
        self,
        resolver: GenericDispatcherResolverProtocol,
        dispatcher_father: object,
        dispatcher_info: object,
    ) -> object:
        """Return state histories for one dispatcher predecessor."""

        entry_block = self.dispatcher_entry_block(dispatcher_info)
        if entry_block is None:
            return None
        return resolver.get_dispatcher_father_histories(
            dispatcher_father,
            entry_block,
            dispatcher_info,
        )

    def histories_resolved(
        self,
        resolver: GenericDispatcherResolverProtocol,
        histories: object,
    ) -> bool:
        """Return whether predecessor histories are fully resolved."""

        return bool(resolver.check_if_histories_are_resolved(histories))

    def resolve_state_values(
        self,
        histories: object,
        dispatcher_info: object,
    ) -> object:
        """Return possible state values carried by resolved histories."""

        entry_block = self.dispatcher_entry_block(dispatcher_info)
        use_before_def_list = (
            getattr(entry_block, "use_before_def_list", ())
            if entry_block is not None
            else ()
        )
        return collect_possible_history_values(
            histories,
            use_before_def_list,
            verbose=False,
        )

    def state_values_complete(self, values: object) -> bool:
        """Return whether state-value recovery produced complete values."""

        return bool(all_history_values_found(values))

    def emulate_dispatcher_target(
        self,
        dispatcher_info: object,
        history: object,
    ) -> tuple[object | None, object]:
        """Emulate one dispatcher history to a concrete target block."""

        return dispatcher_info.emulate_dispatcher_with_father_history(
            history,
            resolve_conditional_exits=True,
        )

    def filter_dependency_safe_copies(
        self,
        resolver: GenericDispatcherResolverProtocol,
        dispatcher_father: object,
        raw_ins_to_copy: list[object],
    ) -> list[object]:
        """Filter copied dispatcher side effects for replay safety."""

        return resolver._filter_dependency_safe_copies(
            dispatcher_father,
            raw_ins_to_copy,
        )

    def prepare_dispatcher_fathers(
        self,
        resolver: GenericDispatcherResolverProtocol,
    ) -> int:
        """Normalize dispatcher predecessors before late-maturity lowering."""

        return int(resolver.ensure_all_dispatcher_fathers_are_direct())

    def collect_state_dispatcher_maps(
        self,
        mba: object,
        *,
        analysis: object,
        collector_dispatchers: tuple[object, ...],
    ) -> tuple[StateDispatcherMap, ...]:
        """Return exact state-dispatcher maps supplied by this profile."""
        return tuple(
            self.state_dispatcher_map_factory(
                mba,
                analysis,
                tuple(collector_dispatchers),
            )
        )

    def collect_switch_case_transition_facts(
        self,
        mba: object,
        *,
        state_dispatcher_map: StateDispatcherMap | None,
    ) -> tuple[object, ...]:
        """Return switch case transition facts supplied by this profile.

        These are read-only recon diagnostics.  The shared engine carries them
        with the phase context so Tigress lowering can later consume the same
        evidence that diagnostics persisted, instead of depending on the
        legacy switch rule as the live owner.
        """
        if state_dispatcher_map is None:
            return ()
        return tuple(
            self.switch_case_transition_fact_factory(
                mba,
                state_dispatcher_map,
                self.name,
            )
        )

    def collect_post_execute_carrier_facts(
        self,
        mba: object,
    ) -> tuple[object, ...]:
        """Return concrete carrier fact families supplied by this profile.

        The engine family consumes these only by generic fact kind/capability.
        Profile-specific oracle witnesses stay behind the factory boundary.
        """

        return tuple(self.post_execute_carrier_fact_factory(mba))

    def collect_fact_observations(
        self,
        mba: object,
    ) -> tuple[object, ...]:
        """Return profile-specific fact rows to mirror into diagnostics."""

        return tuple(self.fact_observation_factory(mba))

    def collect_branch_ownership_refiners(
        self,
        mba: object,
        logger: object,
    ) -> tuple[object, ...]:
        """Return profile-specific branch ownership proof refiners."""

        return tuple(self.branch_ownership_refiner_factory(mba, logger))

    def select_dynamic_transition(
        self,
        transition_result: object,
        *,
        father_serial: int,
    ) -> tuple[object | None, object | None]:
        """Select a dynamic transition fallback for one dispatcher predecessor."""

        for handler in getattr(transition_result, "handlers", {}).values():
            if int(getattr(handler, "check_block", -1)) != int(father_serial):
                continue
            for transition in getattr(handler, "transitions", ()):
                if getattr(transition, "provenance_kind", None) != "global_or_state_write":
                    continue
                if int(getattr(transition, "from_block", -1)) != int(father_serial):
                    continue
                return transition, handler
        return None, None

    def dynamic_transition_recovery_active(
        self,
        phase_context: object | None,
    ) -> bool:
        """Return whether the profile's dynamic-transition fallback is active."""

        transition_result = getattr(phase_context, "transition_result", None)
        if transition_result is None:
            return False
        for handler in getattr(transition_result, "handlers", {}).values():
            for transition in getattr(handler, "transitions", ()):
                if getattr(transition, "provenance_kind", None) == "global_or_state_write":
                    return True
        return False

    def dynamic_guard_fallthrough(
        self,
        transition_result: object,
        *,
        target_state: int,
        target_serial: int,
        father_serial: int,
    ) -> int | None:
        """Return the false-arm continuation for a dynamic guarded edge."""

        handlers = getattr(transition_result, "handlers", {}) or {}
        target_handler = handlers.get(int(target_state))
        if target_handler is None:
            return None
        followup_transitions = [
            transition
            for transition in getattr(target_handler, "transitions", ())
            if getattr(transition, "provenance_kind", None) != "global_or_state_write"
            and not bool(getattr(transition, "is_conditional", False))
        ]
        if len(followup_transitions) != 1:
            return None
        followup_state = int(followup_transitions[0].to_state)
        followup_handler = handlers.get(followup_state)
        if followup_handler is None:
            return None
        fallthrough_serial = int(getattr(followup_handler, "check_block", -1))
        if fallthrough_serial < 0:
            return None
        if fallthrough_serial in (int(target_serial), int(father_serial)):
            return None
        return fallthrough_serial


def default_ollvm_dispatcher_profile() -> GenericDispatcherEngineProfile:
    """Return the default OLLVM-backed dispatcher profile."""

    return GenericDispatcherEngineProfile(
        name="ollvm",
        collector_factory=OllvmDispatcherCollector,
        resolver_factory=OllvmFatherHistoryResolver,
        state_transport="father_history_emulation",
        lowering_mode="generic_graph_modifications",
        provenance_hints=(),
        allow_incomplete_switch_transition_facts=True,
        state_dispatcher_map_factory=_ollvm_state_dispatcher_map_fallback,
        switch_case_transition_fact_factory=_tigress_switch_case_transition_facts,
        post_execute_carrier_fact_factory=collect_ollvm_post_execute_carrier_facts,
        fact_observation_factory=collect_ollvm_profile_fact_observations,
        branch_ownership_refiner_factory=collect_ollvm_branch_ownership_refiners,
    )


def ollvm_state_dispatcher_map_profile(
    *,
    enable_terminal_payload_materialization: bool = False,
    enable_phase_reorder: bool = False,
) -> GenericDispatcherEngineProfile:
    """Return the recon-owned OLLVM equality-chain profile.

    OLLVM equality-chain dispatchers are now modelled through the neutral
    ``StateDispatcherMap`` recon surface.  Keeping the legacy OLLVM collector
    active here makes father-history emulation compete with the exact row map:
    the collector can still find a broad dispatcher, but it cannot explain all
    side effects and conditional states in large FLA+BCF samples.  That leaves
    the family in the old "some fathers unresolved" posture and prevents the
    phase-level recon paths from owning lowering.

    Use no-op collector/resolver objects so detection and lowering are driven
    by exact equality-chain rows plus transition facts.  If a future change
    needs father-history emulation, it should opt into the default profile
    explicitly instead of silently reintroducing legacy ownership here.
    """

    return GenericDispatcherEngineProfile(
        name="ollvm_state_map",
        collector_factory=_NoopDispatcherCollector,
        resolver_factory=_NoopDispatcherResolver,
        state_transport="state_dispatcher_map",
        lowering_mode="generic_graph_modifications",
        provenance_hints=("equality_chain",),
        enable_terminal_payload_materialization=enable_terminal_payload_materialization,
        enable_phase_reorder=enable_phase_reorder,
        state_dispatcher_map_factory=_ollvm_state_dispatcher_maps,
        post_execute_carrier_fact_factory=collect_ollvm_post_execute_carrier_facts,
        fact_observation_factory=collect_ollvm_profile_fact_observations,
        branch_ownership_refiner_factory=collect_ollvm_branch_ownership_refiners,
    )


def tigress_switch_dispatcher_profile(
    *,
    prefer_switch_transition_facts: bool = False,
    allow_incomplete_switch_transition_facts: bool = False,
) -> GenericDispatcherEngineProfile:
    """Return a switch-table state-machine profile for Tigress-style dispatchers."""

    return GenericDispatcherEngineProfile(
        name="tigress_switch",
        collector_factory=_NoopDispatcherCollector,
        resolver_factory=_NoopDispatcherResolver,
        state_transport="state_dispatcher_map",
        lowering_mode="generic_graph_modifications",
        provenance_hints=("switch_table",),
        prefer_switch_transition_facts=prefer_switch_transition_facts,
        allow_incomplete_switch_transition_facts=allow_incomplete_switch_transition_facts,
        state_dispatcher_map_factory=_tigress_switch_state_dispatcher_maps,
        switch_case_transition_fact_factory=_tigress_switch_case_transition_facts,
    )


def tigress_indirect_dispatcher_profile(
    *,
    goto_table_info: object | None = None,
    enable_phase_reorder: bool = False,
) -> GenericDispatcherEngineProfile:
    """Return a read-only profile for Tigress computed-goto dispatch tables."""

    return GenericDispatcherEngineProfile(
        name="tigress_indirect",
        collector_factory=_NoopDispatcherCollector,
        resolver_factory=_NoopDispatcherResolver,
        state_transport="state_dispatcher_map",
        lowering_mode="indirect_jump_table_diagnostics",
        provenance_hints=("indirect_jump_table",),
        enable_phase_reorder=enable_phase_reorder,
        state_dispatcher_map_factory=_make_tigress_indirect_state_dispatcher_maps(
            goto_table_info or {}
        ),
    )


@dataclass(frozen=True)
class EmulatedDispatcherDetection:
    """Concrete detection result for the phenotype-based dispatcher family."""

    dispatcher_analysis: object | None = None
    collector_dispatchers: tuple[object, ...] = ()
    collector_dispatcher_entries: tuple[int, ...] = ()
    analysis_dispatchers: tuple[int, ...] = ()
    state_dispatcher_maps: tuple[StateDispatcherMap, ...] = ()
    state_dispatcher_entries: tuple[int, ...] = ()
    dispatcher_shape: str = "none"
    state_transport: str = "none"
    lowering_mode: str = "none"
    provenance_hints: tuple[str, ...] = ()
    state_constants: tuple[int, ...] = ()
    planning_blocker: str | None = None

    @property
    def detected(self) -> bool:
        return bool(
            self.analysis_dispatchers
            or self.collector_dispatcher_entries
            or self.state_dispatcher_entries
        )

    @property
    def description(self) -> str:
        if not self.detected:
            return "no emulated dispatcher detected"
        if self.planning_blocker:
            return (
                f"emulated dispatcher detected via {self.dispatcher_shape}; "
                f"planning blocked: {self.planning_blocker}"
            )
        return f"emulated dispatcher detected via {self.dispatcher_shape}"


class EmulatedDispatcherStrategyFamily(CFFStrategyFamily):
    """Engine-family adapter over the legacy generic dispatcher collector."""

    def __init__(
        self,
        *,
        cfg_translator: IDAIRTranslator | None = None,
        logger=None,
        profile: GenericDispatcherEngineProfile | None = None,
    ) -> None:
        self._cfg_translator = cfg_translator or IDAIRTranslator()
        self._logger = logger or family_logger
        self._profile = profile or default_ollvm_dispatcher_profile()
        self._strategies = [
            DispatcherLoopRecoveryStrategy(),
            EmulatedDispatcherStrategy(),
        ]
        self._deferred_side_effects: dict[
            tuple[int, int, tuple[int, ...]],
            tuple[object, ...],
        ] = {}
        self._executed_phase_reconstruction_roots: set[
            tuple[int, int, int, int, int]
        ] = set()

    @property
    def name(self) -> str:
        return "emulated_dispatcher"

    @property
    def strategies(self) -> list:
        return list(self._strategies)

    def strategies_for_maturity(self, maturity: int | None = None) -> list:
        return list(self._strategies)

    def _phase_reconstruction_root_key(
        self,
        *,
        mba: ida_hexrays.mba_t,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
    ) -> tuple[int, int, int, int, int] | None:
        if phase_artifact.initial_state is None:
            return None
        return (
            int(getattr(mba, "entry_ea", 0) or 0),
            int(getattr(mba, "maturity", -1) or -1),
            int(phase_artifact.dispatcher_entry_serial),
            int(phase_artifact.pre_header_serial or -1),
            int(phase_artifact.initial_state) & 0xFFFFFFFFFFFFFFFF,
        )

    def record_executed_phase_reconstruction(
        self,
        *,
        mba: ida_hexrays.mba_t,
        snapshot: AnalysisSnapshot,
        total_changes: int,
    ) -> None:
        """Remember successfully consumed phase-reconstruction roots.

        Equality-chain OLLVM functions can expose smaller residual dispatcher
        views after a root phase is peeled.  Re-lowering the exact same
        dispatcher/pre-header/initial-state root can mechanically verify while
        bypassing semantic side effects that were still waiting to structure.
        Treat a successful lowering of that exact root as ownership evidence
        for the rest of the maturity, but keep distinct residual pre-headers
        eligible because they represent different live corridors.
        """

        if total_changes <= 0 or snapshot.flow_graph is None:
            return
        metadata = snapshot.flow_graph.metadata.get(
            EMULATED_DISPATCHER_METADATA_KEY,
        )
        if not isinstance(metadata, EmulatedDispatcherMetadata):
            return
        if metadata.selected_lowering_mode != "state_region_reconstruction":
            return
        phase_artifact = metadata.phase_artifact
        if phase_artifact is None:
            return
        key = self._phase_reconstruction_root_key(
            mba=mba,
            phase_artifact=phase_artifact,
        )
        if key is None:
            return
        self._executed_phase_reconstruction_roots.add(key)

    def _phase_reconstruction_allowed(
        self,
        mba: object,
        detection: EmulatedDispatcherDetection,
    ) -> bool:
        """Return whether the current maturity may lower a phase DAG.

        Equality-chain OLLVM functions expose their complete dispatcher table
        before global optimization. Waiting until GLBOPT can leave us with a
        compacted residual dispatcher whose rows are still true, but whose
        handler-side semantic structure has already been folded away. Allow the
        map-backed reconstruction path at MMAT_CALLS so it can consume the
        exact recon map while all original handler blocks are still present.
        Other dispatcher profiles keep the existing GLBOPT gate.
        """

        if detection.dispatcher_shape not in {
            "conditional_chain",
            "indirect_jump",
            "switch_table",
        }:
            return False
        maturity = int(getattr(mba, "maturity", -1))
        if maturity >= int(ida_hexrays.MMAT_GLBOPT1):
            return True
        if (
            self._profile.name == "tigress_indirect"
            and detection.dispatcher_shape == "indirect_jump"
            and maturity >= int(ida_hexrays.MMAT_LOCOPT)
        ):
            return True
        return (
            self._profile.state_transport == "state_dispatcher_map"
            and maturity >= int(ida_hexrays.MMAT_CALLS)
        )

    def _make_resolver(
        self,
        mba: ida_hexrays.mba_t,
        detection: EmulatedDispatcherDetection,
    ) -> GenericDispatcherResolverProtocol:
        resolver = self._profile.resolver_factory()
        return self._profile.configure_resolver(
            resolver,
            mba=mba,
            detection=detection,
        )

    def detect(self, mba: object) -> EmulatedDispatcherDetection:
        cache = DispatcherCache.get_or_create(mba)
        analysis = cache.analyze()

        collector = self._profile.collector_factory()
        if not isinstance(collector, _NoopDispatcherCollector):
            mba.for_all_topinsns(collector)
        collector_dispatchers = tuple(collector.get_dispatcher_list())
        collector_entries = tuple(
            serial
            for info in collector_dispatchers
            for serial in (self._profile.dispatcher_entry_serial(info),)
            if serial is not None
        )
        state_dispatcher_maps = self._profile.collect_state_dispatcher_maps(
            mba,
            analysis=analysis,
            collector_dispatchers=collector_dispatchers,
        )
        state_dispatcher_entries = tuple(
            int(dispatch_map.dispatcher_entry_block)
            for dispatch_map in state_dispatcher_maps
        )
        analysis_dispatchers = tuple(int(serial) for serial in analysis.dispatchers)
        state_constants = set(int(value) for value in analysis.state_constants)
        for dispatch_map in state_dispatcher_maps:
            state_constants.update(int(row.state_const) for row in dispatch_map.rows)
        analysis_type = getattr(getattr(analysis, "dispatcher_type", None), "name", "none")
        analysis_type = str(analysis_type).lower()
        if state_dispatcher_maps:
            analysis_type = str(state_dispatcher_maps[0].source.name).lower()
        detected = bool(analysis_dispatchers or collector_entries or state_dispatcher_entries)
        state_transport = self._profile.state_transport
        provenance_hints = self._profile.provenance_hints
        if state_dispatcher_entries and not collector_entries:
            state_transport = "state_dispatcher_map"
            first_source = str(getattr(state_dispatcher_maps[0].source, "name", ""))
            if first_source == "CONDITIONAL_CHAIN":
                provenance_hints = tuple(
                    dict.fromkeys((*provenance_hints, "equality_chain"))
                )

        planning_blocker = None
        if analysis_dispatchers and not collector_entries and not state_dispatcher_entries:
            planning_blocker = "dispatcher_cache_detected_but_collector_found_none"

        detection = EmulatedDispatcherDetection(
            dispatcher_analysis=analysis,
            collector_dispatchers=collector_dispatchers,
            collector_dispatcher_entries=collector_entries,
            state_dispatcher_maps=state_dispatcher_maps,
            state_dispatcher_entries=state_dispatcher_entries,
            analysis_dispatchers=analysis_dispatchers,
            dispatcher_shape=analysis_type if detected else "none",
            state_transport=state_transport if detected else "none",
            lowering_mode=self._profile.lowering_mode if detected else "none",
            provenance_hints=provenance_hints if detected else (),
            state_constants=tuple(sorted(state_constants)),
            planning_blocker=planning_blocker,
        )
        self._logger.info(
            "Emulated-dispatcher detect: shape=%s dispatchers=%s collector=%s blocker=%s",
            detection.dispatcher_shape,
            detection.analysis_dispatchers,
            detection.collector_dispatcher_entries,
            detection.planning_blocker,
        )
        return detection

    def _collect_lowering_candidates(
        self,
        mba: ida_hexrays.mba_t,
        detection: EmulatedDispatcherDetection,
        *,
        flow_graph: FlowGraph,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None = None,
        phase_context: EmulatedDispatcherPhaseContext | None = None,
    ) -> tuple[
        tuple[GraphModification, ...],
        tuple[str, ...],
        tuple[EmulatedDispatcherCandidateRecord, ...],
    ]:
        if not detection.collector_dispatchers:
            # PredecessorDispatcherTargetFact proves which handler a state
            # reaches, but not that the raw predecessor edge is safe to
            # rewrite.  Keep these facts diagnostic/recon evidence until a
            # planner-owned split/clone materialization primitive can consume
            # them without bypassing dispatcher-owned structure.
            return (), (), ()

        resolver = self._make_resolver(mba, detection)
        scc_memberships = self._compute_scc_memberships(flow_graph)

        modifications: list[GraphModification] = []
        blockers: list[str] = []
        candidate_records: list[EmulatedDispatcherCandidateRecord] = []
        seen_fathers: set[tuple[int, int]] = set()
        dynamic_candidate_selected = False
        deferred_dynamic_default_blockers: list[str] = []

        for dispatcher_info in detection.collector_dispatchers:
            entry_serial = self._profile.dispatcher_entry_serial(dispatcher_info)
            pred_serials = self._profile.dispatcher_predecessor_serials(
                dispatcher_info
            )
            if entry_serial is None or pred_serials is None:
                blockers.append("collector_dispatcher_missing_entry_block")
                continue

            for pred_serial in pred_serials:
                pred_blk = mba.get_mblock(pred_serial)
                if pred_blk is None:
                    blockers.append("dispatcher_predecessor_missing")
                    continue
                father_key = (int(entry_serial), int(pred_blk.serial))
                if father_key in seen_fathers:
                    continue
                seen_fathers.add(father_key)
                start_index = len(modifications)
                candidate, reason, record = self._build_lowering_candidate(
                    resolver,
                    pred_blk,
                    dispatcher_info,
                    scc_memberships=scc_memberships,
                )
                if candidate is None and reason in {
                    "dispatcher_history_missing_values",
                    "dispatcher_history_unresolved",
                    "dispatcher_history_missing",
                }:
                    dynamic_candidate = self._build_dynamic_transition_candidate(
                        mba=mba,
                        dispatcher_father=pred_blk,
                        dispatcher_info=dispatcher_info,
                        phase_artifact=phase_artifact,
                        phase_context=phase_context,
                        scc_memberships=scc_memberships,
                    )
                    if dynamic_candidate is not None:
                        candidate, record = dynamic_candidate
                        dynamic_candidate_selected = True
                        reason = None
                if candidate is not None:
                    modifications.extend(candidate)
                    record = EmulatedDispatcherCandidateRecord(
                        **{
                            **record.__dict__,
                            "selected_modification_indexes": tuple(
                                range(start_index, len(modifications))
                            ),
                        }
                    )
                candidate_records.append(record)
                if reason is not None:
                    if self._is_dynamic_default_blocker(
                        record=record,
                        reason=reason,
                        phase_artifact=phase_artifact,
                    ):
                        deferred_dynamic_default_blockers.append(reason)
                    else:
                        blockers.append(reason)

        if not dynamic_candidate_selected:
            blockers.extend(deferred_dynamic_default_blockers)

        return (
            tuple(modifications),
            tuple(blockers),
            self._annotate_cluster_candidates(tuple(candidate_records)),
        )

    def _dynamic_transition_recovery_active(
        self,
        phase_context: EmulatedDispatcherPhaseContext | None,
    ) -> bool:
        return self._profile.dynamic_transition_recovery_active(phase_context)

    def _is_dynamic_default_blocker(
        self,
        *,
        record: EmulatedDispatcherCandidateRecord,
        reason: str,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
    ) -> bool:
        if reason != "dispatcher_history_missing_values":
            return False
        if phase_artifact is None:
            return False
        point_handlers = {int(serial) for serial, _state in phase_artifact.handler_state_map}
        range_handlers = {int(serial) for serial, _lo, _hi in phase_artifact.handler_range_map}
        default_handlers = range_handlers - point_handlers
        return int(record.father_serial) in default_handlers

    def _collect_phase_linear_chain_modifications(
        self,
        *,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
        detection: EmulatedDispatcherDetection,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        """Lower a fully resolved conditional-chain dispatcher as one unit.

        This path covers table-backed conditional chains where recon proves the
        state chain from exact dispatcher rows rather than from per-predecessor
        father histories.  The predecessor-local FixPredecessor rewrite can
        remove the terminal return for this shape, so this method emits one
        whole-chain edit batch instead: redirect the proven payload corridor,
        neutralize dead BST nodes, and copy/reorder the live payload blocks away
        from stale dispatcher preds.
        """

        if detection.dispatcher_shape not in {"conditional_chain", "switch_table"}:
            return (), ("phase_linear_chain_not_supported_dispatcher",)
        if phase_artifact is None or phase_context is None:
            return (), ("phase_linear_chain_missing_artifact",)
        if phase_artifact.semantic_reference_variant != "semantic_reference_like":
            return (), ("phase_linear_chain_nonsemantic_reference",)
        if phase_artifact.pre_header_serial is None:
            return (), ("phase_linear_chain_missing_pre_header",)

        dispatcher_entry = int(phase_artifact.dispatcher_entry_serial)
        bst_nodes = {int(serial) for serial in phase_artifact.bst_node_blocks}
        for serial, _lo, _hi in phase_artifact.handler_range_map:
            blk = mba.get_mblock(int(serial))
            if (
                blk is not None
                and int(blk.nsucc()) == 2
                and blk.tail is not None
                and ida_hexrays.is_mcode_jcond(blk.tail.opcode)
            ):
                bst_nodes.add(int(serial))

        transition_result = getattr(phase_context, "transition_result", None)
        transitions_by_state: dict[int, int] = {}
        conditional_states: set[int] = set()
        for transition in getattr(transition_result, "transitions", ()) or ():
            from_state = getattr(transition, "from_state", None)
            to_state = getattr(transition, "to_state", None)
            if from_state is None or to_state is None:
                continue
            from_state = int(from_state)
            to_state = int(to_state)
            if bool(getattr(transition, "is_conditional", False)):
                conditional_states.add(from_state)
                continue
            if from_state in transitions_by_state and transitions_by_state[from_state] != to_state:
                return (), ("phase_linear_chain_ambiguous_transition",)
            transitions_by_state[from_state] = to_state

        known_handler_states = {
            int(state) for _serial, state in phase_artifact.handler_state_map
        } | set(transitions_by_state)
        if len(known_handler_states) < 2:
            return (), ("phase_linear_chain_too_few_handlers",)
        if conditional_states & known_handler_states:
            return (), ("phase_linear_chain_has_conditional_handler",)
        incoming_exact_states = {
            to_state
            for to_state in transitions_by_state.values()
            if to_state in known_handler_states
        }
        if phase_artifact.initial_state in known_handler_states:
            start_state = int(phase_artifact.initial_state)
        else:
            candidates = sorted(known_handler_states - incoming_exact_states)
            if len(candidates) != 1:
                return (), ("phase_linear_chain_start_state_ambiguous",)
            start_state = candidates[0]

        bst_result = getattr(phase_context, "bst_result", None)
        state_dispatcher_map = getattr(
            phase_context,
            "state_dispatcher_map",
            None,
        )
        state_var_stkoff = phase_artifact.state_var_stkoff
        if state_var_stkoff is None:
            return (), ("phase_linear_chain_missing_state_var",)

        def _resolve_state_target(state: int) -> int | None:
            target = (
                state_dispatcher_map.resolve_target(int(state))
                if state_dispatcher_map is not None else None
            )
            if target is not None and int(target) in bst_nodes:
                target = None
            if target is None:
                target = resolve_via_bst_walk(
                    mba,
                    dispatcher_entry,
                    int(state),
                    bst_nodes,
                )
            if target is None and bst_result is not None:
                dispatcher = getattr(bst_result, "dispatcher", None)
                if dispatcher is not None:
                    target = dispatcher.lookup(int(state))
            if target is None:
                return None
            return int(target)

        ordered_states: list[int] = []
        state_targets: dict[int, int] = {}
        redirect_sources: dict[int, int] = {}
        terminal_state: int | None = None
        terminal_target: int | None = None
        current_state = start_state
        seen_states: set[int] = set()
        while len(ordered_states) <= len(known_handler_states) + 2:
            if current_state in seen_states:
                return (), ("phase_linear_chain_cycle",)
            seen_states.add(current_state)
            current_target = _resolve_state_target(current_state)
            if current_target is None:
                return (), ("phase_linear_chain_state_target_unresolved",)
            if current_target == dispatcher_entry or current_target in bst_nodes:
                return (), ("phase_linear_chain_state_target_is_dispatcher",)
            if current_target not in flow_graph.blocks:
                return (), ("phase_linear_chain_state_target_missing",)

            walk = _walk_handler_chain(
                mba=mba,
                handler_start_serial=current_target,
                dispatcher_entry_serial=dispatcher_entry,
                state_var_stkoff=int(state_var_stkoff),
                chain_visited=set(),
                state_var_lvar_idx=None,
            )
            chain = tuple(int(serial) for serial in walk.get("chain", ()) or ())
            if not bool(walk.get("back_edge")):
                terminal_state = current_state
                terminal_target = current_target
                break

            next_state = walk.get("next_state")
            if next_state is None:
                return (), ("phase_linear_chain_missing_transition",)
            if not chain:
                return (), ("phase_linear_chain_empty_handler_chain",)
            redirect_source = int(chain[-1])
            if redirect_source not in flow_graph.blocks:
                return (), ("phase_linear_chain_redirect_source_missing",)

            ordered_states.append(current_state)
            state_targets[current_state] = current_target
            redirect_sources[current_state] = redirect_source
            current_state = int(next_state)
        else:
            return (), ("phase_linear_chain_too_deep",)

        if len(ordered_states) < 2:
            return (), ("phase_linear_chain_too_short",)
        if terminal_state is None or terminal_target is None:
            return (), ("phase_linear_chain_missing_terminal_state",)

        def _single_dispatcher_successor(serial: int) -> bool:
            block = flow_graph.get_block(serial)
            return block is not None and block.succs == (dispatcher_entry,)

        pre_header = int(phase_artifact.pre_header_serial)
        if not _single_dispatcher_successor(pre_header):
            return (), ("phase_linear_chain_pre_header_not_dispatcher_pred",)

        modifications: list[GraphModification] = [
            RedirectGoto(
                from_serial=pre_header,
                old_target=dispatcher_entry,
                new_target=state_targets[start_state],
            )
        ]
        dispatcher_cleanup_targets = set(bst_nodes)
        dispatcher_cleanup_targets.add(dispatcher_entry)
        exit_candidates = sorted(
            serial for serial, block in flow_graph.blocks.items() if block.nsucc == 0
        )
        if not exit_candidates:
            return (), ("phase_linear_chain_missing_exit_block",)
        terminal_exit_serial = exit_candidates[-1]
        for index, state in enumerate(ordered_states):
            handler = redirect_sources[state]
            if not _single_dispatcher_successor(handler):
                return (), ("phase_linear_chain_handler_not_dispatcher_pred",)
            if index + 1 < len(ordered_states):
                next_target = state_targets[ordered_states[index + 1]]
            else:
                next_target = terminal_target
            if handler == next_target:
                return (), ("phase_linear_chain_self_loop",)
            modifications.append(
                RedirectGoto(
                    from_serial=handler,
                    old_target=dispatcher_entry,
                    new_target=next_target,
                )
            )

        for serial in sorted(dispatcher_cleanup_targets):
            block = flow_graph.get_block(serial)
            if block is None or block.nsucc != 2:
                continue
            if serial == terminal_exit_serial:
                continue
            modifications.append(
                ConvertToGoto(
                    block_serial=serial,
                    goto_target=terminal_exit_serial,
                )
            )

        reorder_order: list[int] = []
        for state in ordered_states:
            target = state_targets[state]
            if target not in reorder_order:
                reorder_order.append(target)
        if terminal_target not in reorder_order:
            reorder_order.append(terminal_target)

        modifications.append(
            ReorderBlocks(
                dfs_block_order=tuple(reorder_order),
                non_2way_serials=tuple(reorder_order),
            )
        )

        self._logger.info(
            "Phase linear-chain lowering selected %d edit(s): states=%s terminal=0x%X->blk[%d] reorder=%s cleanup=%s",
            len(modifications),
            tuple(f"0x{state:08X}" for state in ordered_states),
            terminal_state & 0xFFFFFFFF,
            terminal_target,
            tuple(reorder_order),
            tuple(sorted(dispatcher_cleanup_targets)),
        )
        return tuple(modifications), ()

    def _collect_phase_state_dag_modifications(
        self,
        *,
        flow_graph: FlowGraph,
        detection: EmulatedDispatcherDetection,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        """Lower a resolved state DAG without replaying dispatcher emulation.

        OLLVM equality-chain dispatchers can produce a richer recon artifact
        than the father-history collector can safely lower.  In that shape the
        DAG already names the semantic state transitions and the exact local
        branch arm that reaches each state-write corridor.  Use that evidence
        directly:

        * redirect the preheader to the initial handler;
        * redirect one-way state exits to their resolved target handlers;
        * for conditional taken arms, retarget the explicit conditional branch;
        * for conditional fallthrough arms, retarget the branch-local
          one-way corridor just before the synthetic state-write block.

        The last point matters because the current live backend only rewrites
        the explicit conditional target.  Mutating a physical fallthrough edge
        in-place would either require a new backend primitive or invert/copy the
        condition.  Redirecting the fallthrough-only corridor preserves the
        condition while bypassing the dispatcher state write.
        """

        if detection.dispatcher_shape not in {"conditional_chain", "switch_table"}:
            return (), ("phase_state_dag_not_supported_dispatcher",)
        if phase_artifact is None or phase_context is None:
            return (), ("phase_state_dag_missing_artifact",)
        if phase_artifact.semantic_reference_variant != "semantic_reference_like":
            return (), ("phase_state_dag_nonsemantic_reference",)
        if phase_artifact.pre_header_serial is None:
            return (), ("phase_state_dag_missing_pre_header",)
        if phase_artifact.initial_state is None:
            return (), ("phase_state_dag_missing_initial_state",)
        dag = getattr(phase_context, "dag", None)
        if dag is None:
            return (), ("phase_state_dag_missing_dag",)

        dispatcher_entry = int(phase_artifact.dispatcher_entry_serial)
        node_entry_by_state = _phase_node_entry_by_state(
            dag=dag,
            phase_context=phase_context,
            flow_graph=flow_graph,
            logger=self._logger,
        )

        initial_entry = node_entry_by_state.get(
            int(phase_artifact.initial_state) & 0xFFFFFFFFFFFFFFFF
        )
        if initial_entry is None:
            return (), ("phase_state_dag_initial_target_missing",)

        pre_header = int(phase_artifact.pre_header_serial)
        pre_header_block = flow_graph.get_block(pre_header)
        if (
            pre_header_block is None
            or pre_header_block.nsucc != 1
            or pre_header_block.succs != (dispatcher_entry,)
        ):
            return (), ("phase_state_dag_pre_header_not_dispatcher_pred",)
        # State-DAG lowering is a whole-dispatcher rewrite.  After the root
        # rewrite runs, later optimizer passes may rediscover a smaller
        # dispatcher-shaped sub-phase inside the already-mutated graph.  Those
        # nested phases have a handler block or state-write corridor as their
        # "preheader"; broad state-DAG fallback lowering can hide the real entry
        # path and produce CFG shapes Hex-Rays cannot safely structure.  Keep
        # this fallback on the original function-entry preheader; residual
        # corridors are handled by the narrower reconstruction collector.
        entry_serial = int(flow_graph.entry_serial)
        handler_entries = {
            int(serial)
            for serial, _state in getattr(phase_artifact, "handler_state_map", ())
        }
        bst_node_blocks = {
            int(serial) for serial in getattr(phase_artifact, "bst_node_blocks", ())
        }
        is_entry_corridor_pre_header = bool(
            _entry_to_pre_header_corridor(
                flow_graph,
                pre_header_serial=pre_header,
                dispatcher_entry_serial=dispatcher_entry,
            )
        )
        is_guarded_entry_setup_pre_header = bool(
            _guarded_entry_setup_pre_header_region(
                flow_graph,
                pre_header_serial=pre_header,
                dispatcher_entry_serial=dispatcher_entry,
                forbidden_serials=handler_entries | bst_node_blocks,
            )
        )
        if (
            pre_header != entry_serial
            and entry_serial not in pre_header_block.preds
            and not is_entry_corridor_pre_header
            and not is_guarded_entry_setup_pre_header
        ):
            return (), ("phase_state_dag_pre_header_not_function_entry",)

        modifications: list[GraphModification] = [
            RedirectGoto(
                from_serial=pre_header,
                old_target=dispatcher_entry,
                new_target=initial_entry,
            )
        ]
        blockers: list[str] = []
        redirect_goto_targets: dict[int, int] = {pre_header: initial_entry}
        redirect_branch_targets: dict[tuple[int, int], int] = {}
        conditional_edge_count = 0
        transition_edge_count = 0
        skipped_backedge_fallthrough = 0

        state_adjacency: dict[int, set[int]] = {}
        for dag_edge in getattr(dag, "edges", ()) or ():
            if getattr(dag_edge, "kind", None) not in (
                SemanticEdgeKind.TRANSITION,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
            ):
                continue
            source_state = getattr(getattr(dag_edge, "source_key", None), "state_const", None)
            target_state = getattr(dag_edge, "target_state", None)
            if source_state is None or target_state is None:
                continue
            state_adjacency.setdefault(
                int(source_state) & 0xFFFFFFFFFFFFFFFF,
                set(),
            ).add(int(target_state) & 0xFFFFFFFFFFFFFFFF)

        def _state_reaches(start_state: int, goal_state: int) -> bool:
            start_state = int(start_state) & 0xFFFFFFFFFFFFFFFF
            goal_state = int(goal_state) & 0xFFFFFFFFFFFFFFFF
            queue = [start_state]
            seen: set[int] = set()
            while queue:
                current = queue.pop(0)
                if current in seen:
                    continue
                if current == goal_state:
                    return True
                seen.add(current)
                queue.extend(
                    state for state in state_adjacency.get(current, ()) if state not in seen
                )
            return False

        def _add_goto_redirect(source: int, target: int) -> bool:
            source = int(source)
            target = int(target)
            if source == target:
                return True
            block = flow_graph.get_block(source)
            if block is None:
                blockers.append("phase_state_dag_goto_source_missing")
                return False
            if block.nsucc != 1:
                blockers.append("phase_state_dag_goto_source_not_one_way")
                return False
            old_target = int(block.succs[0])
            existing = redirect_goto_targets.get(source)
            if existing is not None:
                if existing != target:
                    blockers.append("phase_state_dag_conflicting_goto_redirect")
                    return False
                return True
            redirect_goto_targets[source] = target
            modifications.append(
                RedirectGoto(
                    from_serial=source,
                    old_target=old_target,
                    new_target=target,
                )
            )
            return True

        def _add_branch_redirect(source: int, old_target: int, target: int) -> bool:
            source = int(source)
            old_target = int(old_target)
            target = int(target)
            if source == target or old_target == target:
                return True
            block = flow_graph.get_block(source)
            if block is None:
                blockers.append("phase_state_dag_branch_source_missing")
                return False
            if block.nsucc != 2 or old_target not in block.succs:
                blockers.append("phase_state_dag_branch_source_not_two_way")
                return False
            if block.succs[1] != old_target:
                blockers.append("phase_state_dag_branch_old_target_not_taken")
                return False
            key = (source, old_target)
            existing = redirect_branch_targets.get(key)
            if existing is not None:
                if existing != target:
                    blockers.append("phase_state_dag_conflicting_branch_redirect")
                    return False
                return True
            redirect_branch_targets[key] = target
            modifications.append(
                RedirectBranch(
                    from_serial=source,
                    old_target=old_target,
                    new_target=target,
                )
            )
            return True

        def _path_after_source(edge: object, source: int) -> tuple[int, ...]:
            ordered_path = tuple(int(serial) for serial in getattr(edge, "ordered_path", ()) or ())
            if not ordered_path:
                return ()
            try:
                source_index = ordered_path.index(int(source))
            except ValueError:
                return ()
            return ordered_path[source_index + 1 :]

        for edge in getattr(dag, "edges", ()) or ():
            kind = getattr(edge, "kind", None)
            if kind not in (
                SemanticEdgeKind.TRANSITION,
                SemanticEdgeKind.CONDITIONAL_TRANSITION,
            ):
                continue
            target_entry = getattr(edge, "target_entry_anchor", None)
            if target_entry is None:
                continue
            target_entry = int(target_entry)
            if target_entry == dispatcher_entry:
                continue
            source_anchor = getattr(edge, "source_anchor", None)
            if source_anchor is None:
                continue
            source = int(getattr(source_anchor, "block_serial", -1))
            if source < 0:
                continue

            if kind == SemanticEdgeKind.TRANSITION:
                transition_edge_count += 1
                if source == target_entry:
                    continue
                source_block = flow_graph.get_block(source)
                if source_block is None:
                    blockers.append("phase_state_dag_transition_source_missing")
                    break
                if source_block.nsucc != 1:
                    blockers.append("phase_state_dag_transition_source_not_one_way")
                    break
                if not _add_goto_redirect(source, target_entry):
                    break
                continue

            conditional_edge_count += 1
            if (
                getattr(source_anchor, "kind", None)
                != RedirectSourceKind.CONDITIONAL_BRANCH
            ):
                blockers.append("phase_state_dag_conditional_source_not_branch")
                break
            branch_arm = getattr(source_anchor, "branch_arm", None)
            if branch_arm is None:
                blockers.append("phase_state_dag_conditional_missing_arm")
                break
            branch_block = flow_graph.get_block(source)
            if branch_block is None or branch_block.nsucc != 2:
                blockers.append("phase_state_dag_conditional_source_not_two_way")
                break
            arm = int(branch_arm)
            if arm < 0 or arm >= len(branch_block.succs):
                blockers.append("phase_state_dag_conditional_arm_out_of_range")
                break

            path_after_source = _path_after_source(edge, source)
            if not path_after_source:
                blockers.append("phase_state_dag_conditional_path_missing")
                break

            if arm == 1 and len(path_after_source) == 1:
                if not _add_branch_redirect(
                    source,
                    int(branch_block.succs[arm]),
                    target_entry,
                ):
                    break
                continue

            if len(path_after_source) == 1:
                redirect_source = int(path_after_source[0])
            else:
                redirect_source = int(path_after_source[-2])
            source_state = getattr(getattr(edge, "source_key", None), "state_const", None)
            target_state = getattr(edge, "target_state", None)
            if (
                source_state is not None
                and target_state is not None
                and _state_reaches(target_state, source_state)
            ):
                # A fallthrough-corridor redirect is not a native branch-arm
                # mutation.  It works for acyclic local dispatcher exits, but
                # for semantic backedges it turns a loop-closing state edge into
                # a direct physical goto from the branch-local corridor.  On
                # OLLVM equality-chain functions this can produce a CFG shape
                # that verifies but crashes the final Hex-Rays structurer.  Keep
                # the backedge in recon for future loop-aware lowering and
                # lower only the acyclic corridor exits here.
                skipped_backedge_fallthrough += 1
                continue
            if not _add_goto_redirect(redirect_source, target_entry):
                break

        if blockers:
            return (), tuple(sorted(set(blockers)))
        if conditional_edge_count == 0:
            return (), ("phase_state_dag_no_conditional_edges",)
        if transition_edge_count == 0:
            return (), ("phase_state_dag_no_transition_edges",)
        if len(modifications) <= 1:
            return (), ("phase_state_dag_no_redirects",)

        self._logger.info(
            "Phase state-DAG lowering selected %d edit(s): transitions=%d conditional=%d "
            "skipped_backedge_fallthrough=%d initial=0x%X->blk[%d]",
            len(modifications),
            transition_edge_count,
            conditional_edge_count,
            skipped_backedge_fallthrough,
            int(phase_artifact.initial_state) & 0xFFFFFFFF,
            initial_entry,
        )
        limit_text = os.environ.get("D810_STATE_DAG_MAX_EDITS", "").strip()
        if limit_text:
            try:
                limit = int(limit_text, 0)
            except ValueError:
                limit = 0
            if limit > 0:
                self._logger.warning(
                    "D810_STATE_DAG_MAX_EDITS=%d limiting phase state-DAG batch from %d edit(s)",
                    limit,
                    len(modifications),
                )
                modifications = modifications[:limit]
        return tuple(modifications), ()

    def _is_residual_state_write_pre_header(
        self,
        *,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
        pre_header: int,
        dispatcher_entry: int,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        initial_state: int,
    ) -> bool:
        """Return True for a residual OLLVM state-write corridor preheader.

        Root equality-chain phases start at the function entry preheader.  After
        that root rewrite, IDA often exposes nested equality-chain dispatchers
        whose predecessor is not a semantic handler but a tiny corridor:

        ``state = CONST; goto dispatcher``

        That corridor is safe to consume only if it writes the phase's recovered
        initial state and that state has an exact handler in this phase.  The
        narrow instruction-count check keeps this from treating arbitrary
        semantic blocks as residual preheaders.
        """

        if phase_artifact.state_var_stkoff is None:
            return False
        if pre_header in {
            int(serial) for serial in getattr(phase_artifact, "bst_node_blocks", ())
        }:
            return False
        handler_states = {
            int(state) & 0xFFFFFFFFFFFFFFFF
            for _serial, state in getattr(phase_artifact, "handler_state_map", ())
        }
        initial_state_u = int(initial_state) & 0xFFFFFFFFFFFFFFFF
        if initial_state_u not in handler_states:
            return False

        pre_header_block = flow_graph.get_block(pre_header)
        if (
            pre_header_block is None
            or pre_header_block.nsucc != 1
            or pre_header_block.succs != (dispatcher_entry,)
            or len(tuple(getattr(pre_header_block, "insn_snapshots", ()) or ())) > 2
        ):
            return False

        live_block = mba.get_mblock(pre_header)
        if live_block is None:
            return False
        try:
            written_state = _extract_state_from_block(
                live_block,
                int(phase_artifact.state_var_stkoff),
                mba=mba,
            )
        except Exception:
            self._logger.debug(
                "Residual state-write preheader check failed for blk[%d]",
                pre_header,
                exc_info=True,
            )
            return False
        return (
            written_state is not None
            and (int(written_state) & 0xFFFFFFFFFFFFFFFF) == initial_state_u
        )

    def _collect_residual_terminal_postprocess_modifications(
        self,
        *,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
        detection: EmulatedDispatcherDetection,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        phase_context: EmulatedDispatcherPhaseContext,
        constant_result: object,
        indexes: object,
        pre_header: int,
        dispatcher_entry: int,
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        """Try terminal-aware residual cleanup without collapsing the entry edge.

        A residual OLLVM equality-chain phase can contain valid semantic
        terminal evidence even though its pre-header is a live handler, not the
        function entry.  The normal phase reconstruction path starts by
        redirecting ``pre_header -> dispatcher`` straight to the initial handler;
        that is correct for a root acyclic phase, but it can delete the only
        loop/return corridor that keeps terminal side effects reachable in a
        residual phase.  Reuse the Hodur postprocess machinery here, but start
        from an empty modification list so only explicitly-proven residual
        handoff/terminal-family edits are allowed.
        """

        block_nsucc_map = {
            int(serial): int(getattr(block, "nsucc", 0))
            for serial, block in getattr(flow_graph, "blocks", {}).items()
        }
        block_succ_map = {
            int(serial): tuple(int(succ) for succ in getattr(block, "succs", ()) or ())
            for serial, block in getattr(flow_graph, "blocks", {}).items()
        }
        builder = ModificationBuilder(
            block_nsucc_map=block_nsucc_map,
            block_succ_map=block_succ_map,
        )
        modifications: list[GraphModification] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        rejected_metadata: list[dict[str, int | str | None]] = []
        state_machine = SimpleNamespace(
            state_constants=set(int(value) for value in detection.state_constants),
        )
        dag = phase_context.dag

        try:
            postprocess = execute_reconstruction_postprocess(
                dag=dag,
                corrected_dag=dag,
                flow_graph=flow_graph,
                modifications=modifications,
                builder=builder,
                dispatcher_region=set(int(serial) for serial in indexes.dispatcher_region),
                dispatcher_serial=int(dispatcher_entry),
                bst_result=phase_context.bst_result,
                state_machine=state_machine,
                state_var_stkoff=int(phase_artifact.state_var_stkoff),
                constant_result=constant_result,
                node_by_key=indexes.node_by_key,
                rejected_metadata=rejected_metadata,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                collect_entry_island_rescue_seeds=collect_entry_island_rescue_seeds,
                collect_late_entry_island_diagnostics=collect_late_entry_island_diagnostics,
                collect_late_entry_island_rescue_seeds=collect_late_entry_island_rescue_seeds,
                collect_residual_dispatcher_predecessors=collect_residual_dispatcher_predecessors,
                compute_reachable_blocks=compute_reachable_blocks,
                classify_artifact_return_blocks=classify_artifact_return_blocks,
                collect_common_return_corridor=collect_common_return_corridor,
                collect_terminal_family_report=collect_terminal_family_report,
                resolve_effective_target_entry=resolve_effective_target_entry,
                build_reconstruction_candidate=build_reconstruction_candidate,
                build_projected_mba=build_mba_view_from_flow_graph,
                discover_residual_alias_overrides_fn=discover_residual_alias_overrides,
            )
        except Exception:
            self._logger.debug(
                "Residual terminal postprocess failed",
                exc_info=True,
            )
            return (), ("phase_reconstruction_terminal_postprocess_failed",)

        if not modifications:
            return (), (
                "phase_reconstruction_residual_terminal_frontier_not_loop_aware",
            )

        filtered_modifications: list[GraphModification] = []
        dropped_pre_header_collapses = 0
        for modification in modifications:
            if (
                isinstance(modification, RedirectGoto)
                and int(modification.from_serial) == int(pre_header)
                and int(modification.old_target) == int(dispatcher_entry)
            ):
                dropped_pre_header_collapses += 1
                continue
            filtered_modifications.append(modification)

        if dropped_pre_header_collapses:
            self._logger.info(
                "Residual terminal postprocess dropped %d pre-header collapse edit(s) "
                "from blk[%d] -> dispatcher blk[%d]",
                dropped_pre_header_collapses,
                int(pre_header),
                int(dispatcher_entry),
            )
        if not filtered_modifications:
            return (), (
                "phase_reconstruction_residual_terminal_frontier_not_loop_aware",
            )
        modifications = filtered_modifications

        mod_counts = Counter(type(mod).__name__ for mod in modifications)
        self._logger.info(
            "Residual terminal postprocess selected %d edit(s): mods=%s "
            "initial_residual_preds=%s residual_preds=%s",
            len(modifications),
            ", ".join(f"{name}={count}" for name, count in mod_counts.most_common()),
            tuple(
                int(serial)
                for serial in getattr(postprocess, "initial_residual_dispatcher_preds", ())
            ),
            tuple(
                int(serial)
                for serial in getattr(postprocess, "residual_dispatcher_preds", ())
            ),
        )
        self._logger.info(
            "Residual terminal postprocess edit details: %s",
            tuple(self._summarize_modification(mod) for mod in modifications),
        )
        return tuple(modifications), ()

    def _collect_phase_reconstruction_modifications(
        self,
        *,
        mba: ida_hexrays.mba_t,
        flow_graph: FlowGraph,
        detection: EmulatedDispatcherDetection,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        """Lower an emulated-dispatcher DAG through reconstruction candidates.

        The first state-DAG lowering slice only redirects already-visible CFG
        edges.  That is useful for reducing the dispatcher, but it cannot
        materialize OLLVM semantic regions whose side effects live behind
        shared corridors, duplicated state-write tails, or branch-local state
        writes.  Reuse the same neutral reconstruction pipeline Hodur uses:
        discover the state-write horizon for each DAG edge, choose the least
        invasive redirect/clone primitive for that horizon, and emit
        ZeroStateWrite neutralizers for consumed dispatcher writes.

        This is intentionally phase-artifact driven.  The diagnostic DB mirrors
        the DAG and rendered program, but behavior depends only on the live
        in-memory recon objects attached to ``phase_context``.
        """

        if detection.dispatcher_shape not in {
            "conditional_chain",
            "indirect_jump",
            "switch_table",
        }:
            return (), ("phase_reconstruction_not_supported_dispatcher",)
        if phase_artifact is None or phase_context is None:
            return (), ("phase_reconstruction_missing_artifact",)
        if phase_artifact.semantic_reference_variant != "semantic_reference_like":
            return (), ("phase_reconstruction_nonsemantic_reference",)
        if phase_artifact.pre_header_serial is None:
            return (), ("phase_reconstruction_missing_pre_header",)
        if phase_artifact.initial_state is None:
            return (), ("phase_reconstruction_missing_initial_state",)
        root_key = self._phase_reconstruction_root_key(
            mba=mba,
            phase_artifact=phase_artifact,
        )
        if (
            root_key is not None
            and root_key in self._executed_phase_reconstruction_roots
        ):
            return (), ("phase_reconstruction_root_already_consumed",)
        initial_state_u = int(phase_artifact.initial_state) & 0xFFFFFFFFFFFFFFFF
        known_state_constants = {
            int(value) & 0xFFFFFFFFFFFFFFFF
            for value in getattr(detection, "state_constants", ()) or ()
        }
        phase_handler_states = {
            int(state) & 0xFFFFFFFFFFFFFFFF
            for _serial, state in getattr(phase_artifact, "handler_state_map", ()) or ()
        }
        if (
            initial_state_u == 0
            and initial_state_u not in known_state_constants
            and initial_state_u not in phase_handler_states
        ):
            return (), ("phase_reconstruction_initial_state_is_neutralizer_zero",)
        if phase_artifact.state_var_stkoff is None:
            return (), ("phase_reconstruction_missing_state_var",)
        dag = getattr(phase_context, "dag", None)
        if dag is None:
            return (), ("phase_reconstruction_missing_dag",)
        if self._profile.name == "tigress_indirect":
            coalesced_states = _coalesced_dispatcher_handler_states(
                getattr(phase_context, "state_dispatcher_map", None),
            )
            if coalesced_states:
                self._logger.info(
                    "Tigress indirect phase reconstruction blocked: "
                    "dispatcher blk[%d] also owns handler state(s)=%s",
                    int(phase_artifact.dispatcher_entry_serial),
                    tuple(
                        f"0x{int(state) & 0xFFFFFFFFFFFFFFFF:016X}"
                        for state in coalesced_states
                    ),
                )
                return (), (
                    "phase_reconstruction_indirect_handler_coalesced_with_dispatcher",
                )

        dispatcher_entry = int(phase_artifact.dispatcher_entry_serial)
        pre_header = int(phase_artifact.pre_header_serial)
        pre_header_block = flow_graph.get_block(pre_header)
        if (
            pre_header_block is None
            or pre_header_block.nsucc != 1
            or pre_header_block.succs != (dispatcher_entry,)
        ):
            return (), ("phase_reconstruction_pre_header_not_dispatcher_pred",)

        entry_serial = int(flow_graph.entry_serial)
        handler_entries = {
            int(serial)
            for serial, _state in getattr(phase_artifact, "handler_state_map", ())
        }
        bst_node_blocks = {
            int(serial) for serial in getattr(phase_artifact, "bst_node_blocks", ())
        }
        is_residual_phase = False
        residual_has_terminal_frontier = False
        is_entry_corridor_pre_header = bool(
            _entry_to_pre_header_corridor(
                flow_graph,
                pre_header_serial=pre_header,
                dispatcher_entry_serial=dispatcher_entry,
            )
        )
        is_guarded_entry_setup_pre_header = bool(
            _guarded_entry_setup_pre_header_region(
                flow_graph,
                pre_header_serial=pre_header,
                dispatcher_entry_serial=dispatcher_entry,
                forbidden_serials=handler_entries | bst_node_blocks,
            )
        )
        if (
            pre_header != entry_serial
            and entry_serial not in pre_header_block.preds
            and not is_entry_corridor_pre_header
            and not is_guarded_entry_setup_pre_header
        ):
            is_handler_residual = (
                pre_header in handler_entries and pre_header not in bst_node_blocks
            )
            is_state_write_residual = self._is_residual_state_write_pre_header(
                mba=mba,
                flow_graph=flow_graph,
                pre_header=pre_header,
                dispatcher_entry=dispatcher_entry,
                phase_artifact=phase_artifact,
                initial_state=int(phase_artifact.initial_state),
            )
            if not is_handler_residual and not is_state_write_residual:
                return (), ("phase_reconstruction_pre_header_not_function_entry",)
            is_residual_phase = True
            residual_has_terminal_frontier = _dag_has_terminal_frontier_edges(dag)

        node_entry_by_state = _phase_node_entry_by_state(
            dag=dag,
            phase_context=phase_context,
            flow_graph=flow_graph,
            logger=self._logger,
        )

        initial_entry = node_entry_by_state.get(
            initial_state_u
        )
        if initial_entry is None and not (
            is_residual_phase and residual_has_terminal_frontier
        ):
            return (), ("phase_reconstruction_initial_target_missing",)

        try:
            constant_result = run_snapshot_constant_fixpoint(
                flow_graph,
                int(phase_artifact.state_var_stkoff),
            )
        except Exception:
            self._logger.debug(
                "Phase reconstruction constant fixpoint failed",
                exc_info=True,
            )
            return (), ("phase_reconstruction_constant_fixpoint_failed",)

        try:
            indexes = build_reconstruction_discovery_indexes(
                dag=dag,
                corrected_dag=dag,
                structured_regions=(),
            )
        except Exception:
            if is_residual_phase and residual_has_terminal_frontier:
                return (), (
                    "phase_reconstruction_residual_terminal_frontier_not_loop_aware",
                )
            self._logger.debug(
                "Phase reconstruction discovery-index build failed",
                exc_info=True,
            )
            return (), ("phase_reconstruction_discovery_indexes_failed",)
        residual_primary_enabled = (
            os.environ.get("D810_OLLVM_RESIDUAL_PRIMARY", "").strip() == "1"
        )
        if (
            is_residual_phase
            and residual_has_terminal_frontier
            and self._profile.name == "ollvm_state_map"
            and not residual_primary_enabled
        ):
            terminal_modifications, terminal_blockers = (
                self._collect_residual_terminal_postprocess_modifications(
                    mba=mba,
                    flow_graph=flow_graph,
                    detection=detection,
                    phase_artifact=phase_artifact,
                    phase_context=phase_context,
                    constant_result=constant_result,
                    indexes=indexes,
                    pre_header=pre_header,
                    dispatcher_entry=dispatcher_entry,
                )
            )
            if terminal_modifications:
                return terminal_modifications, ()
            return (), terminal_blockers

        raw_candidates = []
        rejected_reasons: Counter[str] = Counter()
        for edge in getattr(dag, "edges", ()) or ():
            source_key = getattr(edge, "source_key", None)
            target_key = getattr(edge, "target_key", None)
            if (
                source_key is not None
                and target_key is not None
                and getattr(source_key, "state_const", None) is not None
                and getattr(target_key, "state_const", None) is not None
                and (
                    int(source_key.state_const) & 0xFFFFFFFFFFFFFFFF
                    == int(target_key.state_const) & 0xFFFFFFFFFFFFFFFF
                )
            ):
                rejected_reasons["self_loop_edge"] += 1
                continue
            candidate, rejection = build_reconstruction_candidate(
                edge,
                flow_graph=flow_graph,
                node_by_key=indexes.node_by_key,
                state_var_stkoff=int(phase_artifact.state_var_stkoff),
                constant_result=constant_result,
                shared_suffix_blocks=indexes.shared_suffix_blocks,
                dispatcher_region=indexes.dispatcher_region,
            )
            if candidate is None:
                if rejection is not None:
                    rejected_reasons[str(rejection.get("rejection_reason") or "unknown")] += 1
                continue
            raw_candidates.append(candidate)

        if not raw_candidates:
            if rejected_reasons:
                self._logger.info(
                    "Phase reconstruction found no candidates; rejections=%s",
                    ", ".join(
                        f"{reason}={count}"
                        for reason, count in rejected_reasons.most_common()
                    ),
                )
            return (), ("phase_reconstruction_no_candidates",)

        branch_ownership_proofs = _collect_phase_branch_ownership_proofs(
            dag=dag,
            dispatch_map=phase_context.state_dispatcher_map,
            proof_refiners=self._profile.collect_branch_ownership_refiners(
                mba,
                self._logger,
            ),
        )

        terminal_payload_materialization_modifications: list[GraphModification] = []
        terminal_payload_materialization_owned_blocks: set[int] = set()
        terminal_payload_materialization_owned_edges: set[tuple[int, int]] = set()
        if self._profile.name == "ollvm_state_map":
            raw_candidates = _retarget_ollvm_terminal_payload_backedges(
                dag=dag,
                flow_graph=flow_graph,
                raw_candidates=raw_candidates,
                branch_ownership_proofs=branch_ownership_proofs,
                logger=self._logger,
            )
            materialization_candidates = (
                _collect_terminal_selector_payload_materialization_candidates(
                    dag=dag,
                    flow_graph=flow_graph,
                    branch_ownership_proofs=branch_ownership_proofs,
                )
            )
            if self._profile.enable_terminal_payload_materialization:
                self._logger.info(
                    "OLLVM terminal payload materialization scan: "
                    "maturity=%s candidates=%d",
                    getattr(mba, "maturity", None),
                    len(materialization_candidates),
                )
            for materialization_candidate in materialization_candidates:
                self._logger.info(
                    "OLLVM terminal payload materialization candidate: "
                    "selector=0x%08X arm=%d payload=0x%08X "
                    "payload_blk[%d] continuation=blk[%d] "
                    "external_preds=%s side_effect_eas=%s",
                    int(materialization_candidate.selector_state) & 0xFFFFFFFF,
                    int(materialization_candidate.selector_branch_arm),
                    int(materialization_candidate.payload_state) & 0xFFFFFFFF,
                    int(materialization_candidate.payload_block),
                    int(materialization_candidate.semantic_continuation),
                    ",".join(
                        f"blk[{edge.source_block}]/arm{edge.branch_arm}"
                        for edge in (
                            materialization_candidate.external_incoming_edges
                        )
                    ),
                    ",".join(
                        f"0x{int(insn.ea):X}"
                        for insn in (
                            materialization_candidate.side_effect_instructions
                        )
                    ),
                )
                if not self._profile.enable_terminal_payload_materialization:
                    continue
                materialization_modifications, materialization_blocker = (
                    _compile_terminal_selector_payload_materialization_modifications(
                        materialization_candidate,
                        flow_graph,
                    )
                )
                if materialization_blocker is not None:
                    self._logger.info(
                        "OLLVM terminal payload materialization blocked: "
                        "reason=%s selector=0x%08X payload=0x%08X",
                        materialization_blocker,
                        int(materialization_candidate.selector_state) & 0xFFFFFFFF,
                        int(materialization_candidate.payload_state) & 0xFFFFFFFF,
                    )
                    continue
                terminal_payload_materialization_modifications.extend(
                    materialization_modifications
                )
                terminal_payload_materialization_owned_blocks.update(
                    int(block)
                    for block in materialization_candidate.side_effect_corridor_blocks
                )
                terminal_payload_materialization_owned_edges.update(
                    materialization_candidate.owned_redirect_edges
                )
                terminal_payload_materialization_owned_edges.add((
                    int(materialization_candidate.payload_block),
                    int(materialization_candidate.semantic_continuation),
                ))
                self._logger.info(
                    "OLLVM terminal payload materialization owns raw edges: %s",
                    tuple(materialization_candidate.owned_redirect_edges),
                )
                self._logger.info(
                    "OLLVM terminal payload materialization enabled: "
                    "selector=0x%08X payload=0x%08X edits=%d",
                    int(materialization_candidate.selector_state) & 0xFFFFFFFF,
                    int(materialization_candidate.payload_state) & 0xFFFFFFFF,
                    len(materialization_modifications),
                )

        use_residual_terminal_postprocess = (
            is_residual_phase
            and residual_has_terminal_frontier
            and self._profile.name == "ollvm_state_map"
        )
        include_entry_redirect = not use_residual_terminal_postprocess
        modifications: list[GraphModification] = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        if include_entry_redirect:
            modifications.append(
                RedirectGoto(
                    from_serial=pre_header,
                    old_target=dispatcher_entry,
                    new_target=initial_entry,
                )
            )
            owned_blocks.add(pre_header)
            owned_edges.add((pre_header, initial_entry))
        else:
            self._logger.info(
                "Phase reconstruction residual-primary mode omits pre-header "
                "collapse blk[%d] -> blk[%d]; terminal frontier evidence must "
                "remain reachable through the live handler corridor",
                int(pre_header),
                int(dispatcher_entry),
            )
        initial_modification_count = len(modifications)
        if terminal_payload_materialization_modifications:
            modifications.extend(terminal_payload_materialization_modifications)
            owned_blocks.update(terminal_payload_materialization_owned_blocks)
            owned_edges.update(terminal_payload_materialization_owned_edges)
        direct_use_def_veto_sources: set[int] = set()
        use_def_policy_env = os.environ.get(
            "D810_OLLVM_PHASE_USE_DEF_VETO", ""
        ).strip()
        if use_def_policy_env == "0":
            use_def_policy = "off"
        elif use_def_policy_env == "1":
            use_def_policy = "veto"
        elif use_residual_terminal_postprocess:
            use_def_policy = "veto"
        elif self._profile.state_transport == "state_dispatcher_map":
            use_def_policy = "advisory"
        else:
            use_def_policy = "off"
        observed_use_def_severance_count = 0

        def _veto_use_def_severing_redirect(
            modification: GraphModification,
            candidate: object,
            *,
            reason_prefix: str,
        ) -> str | None:
            if not isinstance(modification, (RedirectGoto, RedirectBranch)):
                return None
            try:
                violations = check_redirect_severs_use_def(
                    modification,
                    mba,
                    flow_graph,
                )
            except Exception:
                self._logger.debug(
                    "Phase reconstruction use-def veto check failed for "
                    "blk[%d] -> blk[%d]",
                    int(modification.from_serial),
                    int(modification.new_target),
                    exc_info=True,
                )
                return None
            if not violations:
                return None
            state_var_stkoff = int(phase_artifact.state_var_stkoff)
            real_violations = tuple(
                violation
                for violation in violations
                if int(violation.var_stkoff) != state_var_stkoff
            )
            if not real_violations:
                self._logger.info(
                    "Phase reconstruction ignored use-def severance for "
                    "blk[%d] -> blk[%d] because only dispatcher state writes "
                    "would be orphaned",
                    int(modification.from_serial),
                    int(modification.new_target),
                )
                return None

            nonlocal observed_use_def_severance_count
            observed_use_def_severance_count += 1
            edge = getattr(candidate, "edge", None)
            target_state = getattr(edge, "target_state", None)
            target_state_text = (
                f"0x{int(target_state) & 0xFFFFFFFF:08X}"
                if target_state is not None
                else "unknown"
            )
            is_hard_veto = use_def_policy == "veto"
            if is_hard_veto:
                direct_use_def_veto_sources.add(int(modification.from_serial))
            action = "VETO_REDIRECT" if is_hard_veto else "WARN_REDIRECT"
            log_method = self._logger.warning if is_hard_veto else self._logger.info
            log_method(
                "Phase reconstruction %s %s redirect blk[%d] -> blk[%d] "
                "for non-state use-def severance target_state=%s "
                "orphaned_uses=%d details=%s",
                "vetoed" if is_hard_veto else "observed",
                reason_prefix,
                int(modification.from_serial),
                int(modification.new_target),
                target_state_text,
                len(real_violations),
                _format_use_def_violations(real_violations),
            )
            _emit_use_def_veto_provenance(
                mba=mba,
                modification=modification,
                action=action,
                reason_prefix=reason_prefix,
                target_state_text=target_state_text,
                violations=real_violations,
            )
            if not is_hard_veto:
                return None
            return f"use_def_severance:{len(real_violations)}"

        def _veto_conditional_redirect(**kwargs: object) -> str | None:
            modification = kwargs.get("modification")
            candidate = kwargs.get("candidate")
            if modification is None:
                return None
            if isinstance(modification, (RedirectGoto, RedirectBranch)):
                try:
                    raw_edge = (
                        int(modification.from_serial),
                        int(modification.old_target),
                    )
                except Exception:
                    raw_edge = None
                if raw_edge in terminal_payload_materialization_owned_edges:
                    self._logger.info(
                        "Phase reconstruction skipped materialized conditional "
                        "raw edge blk[%d] old=blk[%d] new=blk[%d]",
                        int(modification.from_serial),
                        int(modification.old_target),
                        int(modification.new_target),
                    )
                    return "terminal_payload_materialization_owns_raw_edge"
            source_block = kwargs.get("source_block")
            if source_block is not None:
                try:
                    if int(source_block) in direct_use_def_veto_sources:
                        return "direct_use_def_vetoed_source"
                except Exception:
                    pass
            return _veto_use_def_severing_redirect(
                modification,
                candidate,
                reason_prefix="conditional",
            )

        def _direct_redirect_veto(
            modification: GraphModification,
            candidate: object,
        ) -> str | tuple[GraphModification, ...] | None:
            if isinstance(modification, (RedirectGoto, RedirectBranch)):
                raw_edge = (int(modification.from_serial), int(modification.old_target))
                if raw_edge in terminal_payload_materialization_owned_edges:
                    self._logger.info(
                        "Phase reconstruction skipped materialized direct "
                        "raw edge blk[%d] old=blk[%d] new=blk[%d]",
                        int(modification.from_serial),
                        int(modification.old_target),
                        int(modification.new_target),
                    )
                    return "terminal_payload_materialization_owns_raw_edge"
            replacement = _terminal_payload_edge_split_replacement(
                candidate=candidate,
                modification=modification,
                dag=dag,
                flow_graph=flow_graph,
                branch_ownership_proofs=branch_ownership_proofs,
            )
            if replacement is not None:
                self._logger.info(
                    "Phase reconstruction replaced shared terminal payload "
                    "redirect with pred-split clone: src=blk[%d] old=blk[%d] "
                    "new=blk[%d] via_pred=blk[%d]",
                    int(replacement[0].src_block),
                    int(replacement[0].old_target),
                    int(replacement[0].new_target),
                    int(replacement[0].via_pred),
                )
                return replacement
            if use_def_policy == "off":
                return None
            return _veto_use_def_severing_redirect(
                modification,
                candidate,
                reason_prefix="direct",
            )

        try:
            run = execute_primary_reconstruction_modifications(
                raw_candidates=list(raw_candidates),
                flow_graph=flow_graph,
                node_by_key=indexes.node_by_key,
                dispatcher_serial=dispatcher_entry,
                modifications=modifications,
                owned_blocks=owned_blocks,
                owned_edges=owned_edges,
                direct_redirect_veto=(
                    _direct_redirect_veto
                    if (
                        use_def_policy != "off"
                        or self._profile.name == "ollvm_state_map"
                    )
                    else None
                ),
                conditional_redirect_veto=(
                    _veto_conditional_redirect
                    if (
                        use_def_policy != "off"
                        or terminal_payload_materialization_owned_edges
                    )
                    else None
                ),
                mba=mba,
                insn_kind_classifier=classify_live_insn_kind,
                operand_kind_classifier=classify_live_operand_kind,
            )
        except Exception:
            self._logger.debug(
                "Phase reconstruction emission failed",
                exc_info=True,
            )
            return (), ("phase_reconstruction_emission_failed",)

        if terminal_payload_materialization_owned_edges:
            retained_modifications: list[GraphModification] = []
            for modification in modifications:
                if isinstance(modification, (RedirectGoto, RedirectBranch)):
                    raw_edge = (
                        int(modification.from_serial),
                        int(modification.old_target),
                    )
                    if raw_edge in terminal_payload_materialization_owned_edges:
                        self._logger.info(
                            "Phase reconstruction removed materialization-owned "
                            "redirect blk[%d] old=blk[%d] new=blk[%d]",
                            int(modification.from_serial),
                            int(modification.old_target),
                            int(modification.new_target),
                        )
                        continue
                retained_modifications.append(modification)
            modifications[:] = retained_modifications

        accepted_count = (
            len(getattr(run, "conditional_results", ()) or ())
            + sum(
                1
                for result in getattr(run, "direct_results", ()) or ()
                if getattr(result, "accepted_candidate", None) is not None
            )
            + sum(
                len(getattr(result, "accepted_candidates", ()) or ())
                for result in getattr(run, "shared_group_results", ()) or ()
            )
        )

        if (
            is_residual_phase
            and residual_has_terminal_frontier
            and not include_entry_redirect
        ):
            zero_state_write_count = sum(
                1 for mod in modifications if isinstance(mod, ZeroStateWrite)
            )
            if zero_state_write_count:
                modifications = [
                    mod
                    for mod in modifications
                    if not isinstance(mod, ZeroStateWrite)
                ]
                self._logger.info(
                    "Phase reconstruction residual-primary kept dispatcher "
                    "corridor state writes live: removed %d ZeroStateWrite "
                    "edit(s) because the residual pre-header was not collapsed",
                    zero_state_write_count,
                )

        if terminal_payload_materialization_modifications:
            materialized_sources = {
                int(edge[0])
                for edge in terminal_payload_materialization_owned_edges
            }
            watched_modifications = []
            for modification in modifications:
                if isinstance(modification, (RedirectGoto, RedirectBranch)):
                    source_serial = int(modification.from_serial)
                    if source_serial in materialized_sources:
                        watched_modifications.append(
                            (
                                type(modification).__name__,
                                source_serial,
                                int(modification.old_target),
                                int(modification.new_target),
                            )
                        )
                elif isinstance(modification, InsertBlock):
                    source_serial = int(modification.pred_serial)
                    if source_serial in materialized_sources:
                        watched_modifications.append(
                            (
                                type(modification).__name__,
                                source_serial,
                                int(modification.old_target_serial or -1),
                                int(modification.succ_serial),
                            )
                        )
            if watched_modifications:
                self._logger.info(
                    "OLLVM terminal payload materialization source edits: %s",
                    tuple(watched_modifications),
                )

        if (
            self._profile.state_transport == "state_dispatcher_map"
            and (
                _dag_has_unknown_state_exits(dag)
                or bool(rejected_reasons.get("phase_linear_chain_state_target_unresolved"))
                or accepted_count < len(raw_candidates)
                or observed_use_def_severance_count > 0
            )
        ):
            zero_state_write_count = sum(
                1 for mod in modifications if isinstance(mod, ZeroStateWrite)
            )
            if zero_state_write_count:
                modifications = [
                    mod
                    for mod in modifications
                    if not isinstance(mod, ZeroStateWrite)
                ]
                self._logger.info(
                    "Phase reconstruction kept dispatcher state writes live: "
                    "removed %d ZeroStateWrite edit(s) because the "
                    "state-dispatcher-map phase still has unresolved exits; "
                    "later residual phases must see the original state "
                    "constants, not synthetic zero-state aliases; "
                    "accepted=%d/%d use_def_severance=%d edge_kinds=%s "
                    "rejections=%s",
                    zero_state_write_count,
                    accepted_count,
                    len(raw_candidates),
                    observed_use_def_severance_count,
                    ", ".join(
                        f"{kind}={count}"
                        for kind, count in _dag_edge_kind_counts(dag).most_common()
                    ),
                    ", ".join(
                        f"{reason}={count}"
                        for reason, count in rejected_reasons.most_common()
                    ),
                )

        if self._profile.name == "tigress_indirect":
            terminal_stub_modifications = (
                _collect_tigress_indirect_terminal_stub_modifications(
                    dag=dag,
                    flow_graph=flow_graph,
                    dispatch_map=getattr(phase_context, "state_dispatcher_map", None),
                    state_var_stkoff=int(phase_artifact.state_var_stkoff),
                    constant_result=constant_result,
                    logger=self._logger,
                )
            )
            if terminal_stub_modifications:
                existing_redirect_edges = {
                    (int(mod.from_serial), int(mod.old_target))
                    for mod in modifications
                    if isinstance(mod, (RedirectGoto, RedirectBranch))
                }
                appended_terminal_stub_modifications = tuple(
                    mod
                    for mod in terminal_stub_modifications
                    if not isinstance(mod, RedirectGoto)
                    or (int(mod.from_serial), int(mod.old_target))
                    not in existing_redirect_edges
                )
                if appended_terminal_stub_modifications:
                    modifications.extend(appended_terminal_stub_modifications)
                    owned_edges.update(
                        (
                            int(mod.from_serial),
                            int(mod.new_target),
                        )
                        for mod in appended_terminal_stub_modifications
                        if isinstance(mod, RedirectGoto)
                    )
                    self._logger.info(
                        "Tigress indirect terminal stub repair appended %d edit(s)",
                        len(appended_terminal_stub_modifications),
                    )

        reorder_enabled = not is_residual_phase and (
            bool(self._profile.enable_phase_reorder)
            or (
                self._profile.name == "ollvm_state_map"
                and os.environ.get("D810_OLLVM_PHASE_REORDER", "").strip() == "1"
            )
        )
        if reorder_enabled:
            reorder = _phase_reconstruction_reorder_blocks_from_dag(
                dag=dag,
                flow_graph=flow_graph,
                initial_state=phase_artifact.initial_state,
                excluded_blocks=indexes.dispatcher_region,
            )
            if reorder is not None and len(reorder.dfs_block_order) >= 2:
                modifications.append(reorder)
                self._logger.info(
                    "Phase reconstruction appended DAG block reorder: "
                    "blocks=%d non_2way=%d two_way=%d initial=0x%X",
                    len(reorder.dfs_block_order),
                    len(reorder.non_2way_serials),
                    len(reorder.two_way_serials),
                    int(phase_artifact.initial_state) & 0xFFFFFFFF,
                )
            else:
                self._logger.info(
                    "Phase reconstruction skipped DAG block reorder: no stable "
                    "semantic block order for initial=0x%X",
                    int(phase_artifact.initial_state) & 0xFFFFFFFF,
                )

        if len(modifications) <= initial_modification_count:
            if use_residual_terminal_postprocess:
                terminal_modifications, terminal_blockers = (
                    self._collect_residual_terminal_postprocess_modifications(
                        mba=mba,
                        flow_graph=flow_graph,
                        detection=detection,
                        phase_artifact=phase_artifact,
                        phase_context=phase_context,
                        constant_result=constant_result,
                        indexes=indexes,
                        pre_header=pre_header,
                        dispatcher_entry=dispatcher_entry,
                    )
                )
                if terminal_modifications:
                    return terminal_modifications, ()
                return (), terminal_blockers
            if rejected_reasons:
                self._logger.info(
                    "Phase reconstruction rejected all %d candidates after emission; "
                    "discovery_rejections=%s",
                    len(raw_candidates),
                    ", ".join(
                        f"{reason}={count}"
                        for reason, count in rejected_reasons.most_common()
                    ),
                )
            return (), ("phase_reconstruction_no_emitted_modifications",)

        modifications = _order_phase_reconstruction_modifications(
            modifications,
            preserve_first=include_entry_redirect,
        )
        mod_counts = Counter(type(mod).__name__ for mod in modifications)
        self._logger.info(
            "Phase reconstruction selected %d edit(s): candidates=%d accepted=%d "
            "mods=%s initial=0x%X->blk[%d]",
            len(modifications),
            len(raw_candidates),
            accepted_count,
            ", ".join(f"{name}={count}" for name, count in mod_counts.most_common()),
            int(phase_artifact.initial_state) & 0xFFFFFFFF,
            initial_entry,
        )
        return tuple(modifications), ()

    def _collect_derived_xor_dispatcher_modifications(
        self,
        *,
        flow_graph: FlowGraph,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        """Lower the ABC XOR dispatcher once recon proves derived-key edges.

        This is deliberately gated on ``derived_xor_dispatch_key`` transition
        provenance.  The dispatcher state labels are not raw state-variable
        values for this family; they are the low-byte key produced by
        ``key = low8(carrier) ^ K``.  Generic state-write lowering therefore
        cannot safely infer the edge from ``carrier ^= C`` unless recon has
        first converted those writes into explicit key transitions.
        """

        if phase_artifact is None or phase_context is None:
            return (), ("derived_xor_dispatcher_missing_artifact",)
        if phase_artifact.pre_header_serial is None:
            return (), ("derived_xor_dispatcher_missing_pre_header",)
        if phase_artifact.initial_state is None:
            return (), ("derived_xor_dispatcher_missing_initial_state",)

        transition_result = getattr(phase_context, "transition_result", None)
        transitions = tuple(getattr(transition_result, "transitions", ()) or ())
        derived_transitions = tuple(
            transition
            for transition in transitions
            if getattr(transition, "provenance_kind", None)
            == "derived_xor_dispatch_key"
        )
        if not derived_transitions:
            return (), ("derived_xor_dispatcher_missing_transitions",)

        state_to_handler = {
            int(state): int(serial)
            for serial, state in phase_artifact.handler_state_map
        }
        if int(phase_artifact.initial_state) not in state_to_handler:
            return (), ("derived_xor_dispatcher_initial_target_missing",)

        dispatcher_entry = int(phase_artifact.dispatcher_entry_serial)
        modifications: list[GraphModification] = [
            RedirectGoto(
                from_serial=int(phase_artifact.pre_header_serial),
                old_target=dispatcher_entry,
                new_target=state_to_handler[int(phase_artifact.initial_state)],
            )
        ]
        seen_redirects: set[tuple[int, int]] = {
            (
                int(phase_artifact.pre_header_serial),
                state_to_handler[int(phase_artifact.initial_state)],
            )
        }

        for transition in derived_transitions:
            target_state = getattr(transition, "to_state", None)
            if target_state is None or int(target_state) not in state_to_handler:
                return (), ("derived_xor_dispatcher_target_missing",)
            source = getattr(transition, "condition_block", None)
            if source is None:
                source = getattr(transition, "from_block", None)
            if source is None:
                return (), ("derived_xor_dispatcher_source_missing",)
            source = int(source)
            target = state_to_handler[int(target_state)]
            block = flow_graph.get_block(source)
            if block is None:
                return (), ("derived_xor_dispatcher_source_block_missing",)
            if block.succs != (dispatcher_entry,):
                return (), ("derived_xor_dispatcher_source_not_dispatcher_pred",)
            if source == target:
                return (), ("derived_xor_dispatcher_self_loop",)
            key = (source, target)
            if key in seen_redirects:
                continue
            seen_redirects.add(key)
            modifications.append(
                RedirectGoto(
                    from_serial=source,
                    old_target=dispatcher_entry,
                    new_target=target,
                )
            )

        self._logger.info(
            "Derived-XOR dispatcher lowering selected %d edit(s): initial=0x%X transitions=%d",
            len(modifications),
            int(phase_artifact.initial_state) & 0xFFFFFFFF,
            len(derived_transitions),
        )
        return tuple(modifications), ()

    def _compute_scc_memberships(
        self,
        flow_graph: FlowGraph,
    ) -> dict[int, tuple[int, ...]]:
        index = 0
        stack: list[int] = []
        on_stack: set[int] = set()
        indexes: dict[int, int] = {}
        lowlinks: dict[int, int] = {}
        memberships: dict[int, tuple[int, ...]] = {}

        def _strongconnect(serial: int) -> None:
            nonlocal index
            indexes[serial] = index
            lowlinks[serial] = index
            index += 1
            stack.append(serial)
            on_stack.add(serial)

            for succ in flow_graph.blocks[serial].succs:
                if succ not in flow_graph.blocks:
                    continue
                if succ not in indexes:
                    _strongconnect(succ)
                    lowlinks[serial] = min(lowlinks[serial], lowlinks[succ])
                elif succ in on_stack:
                    lowlinks[serial] = min(lowlinks[serial], indexes[succ])

            if lowlinks[serial] != indexes[serial]:
                return

            component: list[int] = []
            while stack:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == serial:
                    break
            normalized = tuple(sorted(component))
            for member in normalized:
                memberships[member] = normalized

        for serial in flow_graph.blocks:
            if serial not in indexes:
                _strongconnect(serial)

        return memberships

    def _resolve_state_var_stkoff(
        self,
        detection: EmulatedDispatcherDetection,
    ) -> int | None:
        candidate = getattr(detection.dispatcher_analysis, "state_variable", None)
        if candidate is None:
            return None
        try:
            if getattr(candidate, "mop_type", None) == ida_hexrays.mop_S:
                return int(getattr(candidate, "mop_offset", None))
        except Exception:
            return None
        return None

    def _primary_dispatcher_entry_serial(
        self,
        detection: EmulatedDispatcherDetection,
    ) -> int | None:
        if (
            detection.dispatcher_shape == "conditional_chain"
            and detection.state_dispatcher_entries
            and detection.analysis_dispatchers
        ):
            return int(detection.analysis_dispatchers[0])
        if detection.state_dispatcher_entries:
            return int(detection.state_dispatcher_entries[0])
        for dispatcher_info in detection.collector_dispatchers:
            entry_serial = self._profile.dispatcher_entry_serial(dispatcher_info)
            if entry_serial is not None:
                return int(entry_serial)
        if detection.analysis_dispatchers:
            return int(detection.analysis_dispatchers[0])
        return None

    def _build_phase_artifact(
        self,
        mba: ida_hexrays.mba_t,
        detection: EmulatedDispatcherDetection,
        *,
        flow_graph: FlowGraph,
    ) -> tuple[EmulatedDispatcherPhaseArtifact, EmulatedDispatcherPhaseContext] | tuple[None, None]:
        dispatcher_entry_serial = self._primary_dispatcher_entry_serial(detection)
        if dispatcher_entry_serial is None:
            return None, None

        state_var_stkoff = self._resolve_state_var_stkoff(detection)
        state_dispatcher_map = _merge_compatible_state_dispatcher_maps(
            dispatcher_entry_serial=int(dispatcher_entry_serial),
            maps=tuple(detection.state_dispatcher_maps),
        )
        if state_dispatcher_map is not None:
            handler_map = state_dispatcher_map.to_dispatcher_handler_map()
            bst_result = handler_map.to_bst_result()
            map_initial_state = getattr(state_dispatcher_map, "initial_state", None)
            if state_dispatcher_map.state_var_stkoff is not None:
                if (
                    state_var_stkoff is not None
                    and int(state_var_stkoff)
                    != int(state_dispatcher_map.state_var_stkoff)
                ):
                    self._logger.debug(
                        "State-dispatcher map overriding cache state var: "
                        "cache=0x%X map=0x%X dispatcher=blk[%d]",
                        int(state_var_stkoff),
                        int(state_dispatcher_map.state_var_stkoff),
                        int(dispatcher_entry_serial),
                    )
                state_var_stkoff = int(state_dispatcher_map.state_var_stkoff)
            try:
                pre_header_serial, initial_state = _find_pre_header_state(
                    mba,
                    dispatcher_entry_serial,
                    state_var_stkoff,
                )
                if pre_header_serial is not None:
                    bst_result.pre_header_serial = int(pre_header_serial)
                if initial_state is not None and map_initial_state is None:
                    bst_result.initial_state = int(initial_state) & 0xFFFFFFFF
            except Exception:
                self._logger.debug(
                    "Failed to recover preheader for state-dispatcher map",
                    exc_info=True,
                )
        else:
            try:
                bst_result = analyze_bst_dispatcher(
                    mba,
                    dispatcher_entry_serial,
                    state_var_stkoff=state_var_stkoff,
                )
            except Exception:
                self._logger.warning(
                    "Failed to build emulated-dispatcher BST artifact",
                    exc_info=True,
                )
                return None, None

        detected_state_var_stkoff = None
        try:
            detected_stkoff, _detected_lvar_idx = _detect_state_var_stkoff(
                mba,
                dispatcher_entry_serial,
                diag=False,
            )
            if detected_stkoff is not None:
                detected_state_var_stkoff = int(detected_stkoff)
        except Exception:
            pass

        transition_result = _convert_bst_to_result(bst_result)
        base_transition_result = transition_result
        known_states = set(int(value) for value in detection.state_constants)
        if state_dispatcher_map is not None:
            known_states.update(
                int(row.state_const) for row in state_dispatcher_map.rows
            )
        known_states.update(
            int(value)
            for value in getattr(bst_result, "handler_state_map", {}).values()
        )
        if getattr(bst_result, "initial_state", None) is not None:
            known_states.add(int(bst_result.initial_state))
        transition_result = recover_dynamic_state_write_transitions(
            mba=mba,
            flow_graph=flow_graph,
            transition_result=transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=(
                state_var_stkoff
                if state_var_stkoff is not None
                else detected_state_var_stkoff
            ),
            known_states=known_states,
        )
        if (
            transition_result is not base_transition_result
            and state_var_stkoff is None
            and detected_state_var_stkoff is not None
        ):
            state_var_stkoff = detected_state_var_stkoff
        recovered_initial_state = getattr(transition_result, "initial_state", None)
        if recovered_initial_state is None:
            recovered_initial_state = getattr(bst_result, "initial_state", None)
        if (
            recovered_initial_state is None
            and state_var_stkoff is not None
            and getattr(bst_result, "pre_header_serial", None) is not None
        ):
            try:
                fixpoint = run_snapshot_constant_fixpoint(
                    flow_graph,
                    int(state_var_stkoff),
                )
                pre_header_state = fixpoint.out_stk_maps.get(
                    int(bst_result.pre_header_serial),
                    {},
                ).get(int(state_var_stkoff))
                if pre_header_state is not None:
                    recovered_initial_state = int(pre_header_state) & 0xFFFFFFFF
                    self._logger.info(
                        "Recovered emulated-dispatcher initial state from preheader "
                        "blk[%d]: 0x%08X",
                        int(bst_result.pre_header_serial),
                        int(recovered_initial_state) & 0xFFFFFFFF,
                    )
            except Exception:
                self._logger.debug(
                    "Failed to recover emulated-dispatcher initial state from preheader",
                    exc_info=True,
                )
        if (
            recovered_initial_state is None
            and state_var_stkoff is not None
            and getattr(bst_result, "pre_header_serial", None) is not None
        ):
            corridor_recovery = _recover_initial_state_from_entry_corridor(
                flow_graph,
                pre_header_serial=int(bst_result.pre_header_serial),
                dispatcher_entry_serial=int(dispatcher_entry_serial),
                state_var_stkoff=int(state_var_stkoff),
            )
            if corridor_recovery is not None:
                recovered_initial_state, corridor_path = corridor_recovery
                self._logger.info(
                    "Recovered emulated-dispatcher initial state from entry "
                    "corridor %s -> preheader blk[%d]: 0x%08X",
                    corridor_path,
                    int(bst_result.pre_header_serial),
                    int(recovered_initial_state) & 0xFFFFFFFF,
                )
        bst_node_blocks = tuple(sorted(int(serial) for serial in bst_result.bst_node_blocks))
        transition_report = build_dispatcher_transition_report_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=recovered_initial_state,
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=bst_node_blocks,
            diagnostics=(),
        )
        dag = build_live_linearized_state_dag_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=recovered_initial_state,
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=bst_node_blocks,
            diagnostics=(),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=mba,
            prefer_local_corridors=True,
        )
        semantic_program = build_linearized_state_program(
            dag,
            order_strategy=RenderOrderStrategy.SEMANTIC,
            program_strategy=ProgramRenderStrategy.LOCAL_BOUNDARY_SELECTIVE,
            label_render_mode=LabelRenderMode.STATE_FAMILY,
            boundary_inline_mode=BoundaryInlineMode.INLINE_SINGLE_LEVEL,
            comment_mode=ProgramCommentMode.MINIMAL,
        )
        semantic_program_text = render_linearized_state_program(semantic_program)
        switch_case_transition_facts = self._profile.collect_switch_case_transition_facts(
            mba,
            state_dispatcher_map=state_dispatcher_map,
        )
        predecessor_dispatcher_target_facts = (
            collect_predecessor_dispatcher_target_facts(
                transition_result=transition_result,
                dispatcher_entry_serial=dispatcher_entry_serial,
                state_dispatcher_map=state_dispatcher_map,
                bst_result=bst_result,
                transition_report=transition_report,
                dag=dag,
                state_var_stkoff=state_var_stkoff,
            )
        )
        dispatcher_snapshot = flow_graph.get_block(dispatcher_entry_serial)
        dispatcher_predecessor_serials = (
            tuple(int(serial) for serial in getattr(dispatcher_snapshot, "preds", ()) or ())
            if dispatcher_snapshot is not None
            else ()
        )
        dispatcher_discovery_fact_observations = (
            collect_state_dispatcher_discovery_fact_observations(
                state_dispatcher_map=state_dispatcher_map,
                maturity=self._maturity_name(int(getattr(mba, "maturity", 0) or 0)),
                phase="pre_d810",
                profile_name=self._profile.name,
                predecessor_serials=dispatcher_predecessor_serials,
                initial_state=recovered_initial_state,
                pre_header_serial=getattr(bst_result, "pre_header_serial", None),
                predecessor_target_facts=predecessor_dispatcher_target_facts,
            )
        )
        artifact = EmulatedDispatcherPhaseArtifact(
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=recovered_initial_state,
            bst_node_blocks=bst_node_blocks,
            handler_state_map=tuple(
                sorted(
                    (int(serial), int(state))
                    for serial, state in getattr(bst_result, "handler_state_map", {}).items()
                )
            ),
            handler_range_map=tuple(
                sorted(
                    (
                        int(serial),
                        None if lo is None else int(lo),
                        None if hi is None else int(hi),
                    )
                    for serial, (lo, hi) in getattr(bst_result, "handler_range_map", {}).items()
                )
            ),
            transition_rows=len(getattr(transition_report, "rows", ()) or ()),
            dag_node_count=len(getattr(dag, "nodes", ()) or ()),
            dag_edge_count=len(getattr(dag, "edges", ()) or ()),
            semantic_state_labels=tuple(
                str(getattr(node, "state_label", ""))
                for node in getattr(dag, "nodes", ())
            ),
            semantic_reference_variant=str(getattr(semantic_program, "variant_name", None)),
            semantic_reference_line_count=len(getattr(semantic_program, "lines", ()) or ()),
            semantic_reference_node_count=len(getattr(semantic_program, "nodes", ()) or ()),
            semantic_reference_program=semantic_program_text,
        )
        context = EmulatedDispatcherPhaseContext(
            bst_result=bst_result,
            transition_result=transition_result,
            transition_report=transition_report,
            dag=dag,
            semantic_reference_program=semantic_program,
            state_dispatcher_map=state_dispatcher_map,
            switch_case_transition_facts=switch_case_transition_facts,
            predecessor_dispatcher_target_facts=predecessor_dispatcher_target_facts,
            dispatcher_discovery_fact_observations=(
                dispatcher_discovery_fact_observations
            ),
        )
        return artifact, context

    def _collect_loop_recovery_modifications(
        self,
        *,
        mba: ida_hexrays.mba_t,
        snapshot_flow_graph: FlowGraph,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
        candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        if phase_artifact is None or phase_context is None:
            return (), ()
        if phase_artifact.state_var_stkoff is None:
            return (), ("dispatcher_loop_recovery_missing_state_var",)
        artifact_blockers = self._dispatcher_loop_recovery_artifact_blockers(
            phase_artifact
        )
        if artifact_blockers:
            return (), artifact_blockers

        direct_batch, direct_blockers = self._collect_phase_redirect_loop_recovery(
            mba=mba,
            phase_artifact=phase_artifact,
            candidate_records=candidate_records,
        )
        if direct_batch:
            return_carrier_blockers = _return_carrier_preservation_blockers(
                mba=mba,
                flow_graph=snapshot_flow_graph,
                modifications=direct_batch,
                phase_context=phase_context,
                phase_artifact=phase_artifact,
                allow_live_repair=True,
            )
            if return_carrier_blockers:
                return (), return_carrier_blockers
            self._logger.info(
                "DispatcherLoopRecovery selected %d direct phase rewrite(s) from %d fallback candidates",
                len(direct_batch),
                len(candidate_records),
            )
            return direct_batch, ()
        # Keep loop recovery on the explicit phase-cycle contract only.
        # The broader DAG reconstruction fallback overfires on samples like
        # approov_vm_dispatcher, where recon sees a dispatcher but does not
        # yet prove a loop phase strong enough for structural recovery.
        return (), direct_blockers

    def _collect_tigress_switch_transition_modifications(
        self,
        *,
        flow_graph: FlowGraph,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        if phase_artifact is None or phase_context is None:
            return (), ("tigress_switch_transition_missing_artifact",)
        dispatch_map = getattr(phase_context, "state_dispatcher_map", None)
        if not isinstance(dispatch_map, StateDispatcherMap):
            return (), ("tigress_switch_transition_missing_dispatcher_map",)
        if (
            self._profile.name != "tigress_switch"
            and str(getattr(dispatch_map.source, "name", "")) != "SWITCH_TABLE"
        ):
            return (), ("tigress_switch_transition_not_profile",)
        facts = tuple(getattr(phase_context, "switch_case_transition_facts", ()) or ())
        if not facts:
            return (), ("tigress_switch_transition_missing_facts",)

        # Match the legacy switch rule's large-dispatcher caution. This first
        # behavior slice can still persist exact diagnostics for large switches,
        # but runtime planning abstains until repeated-pass/profile guards exist.
        if len(dispatch_map.rows) > 256:
            return (), ("tigress_switch_transition_large_dispatcher_abstained",)

        dispatcher_entry = int(dispatch_map.dispatcher_entry_block)
        modifications: list[GraphModification] = []
        blockers: Counter[str] = Counter()
        redirects_by_claim: dict[tuple[int, int | None], int] = {}
        lowered_states: set[int] = set()
        terminal_states: set[int] = set()
        visible_handler_states = {
            int(row.state_const)
            for row in dispatch_map.rows
            if getattr(row, "row_kind", "handler") == "handler"
        }
        reentry_targets = _switch_dispatcher_reentry_targets(
            flow_graph,
            dispatcher_entry=dispatcher_entry,
            dispatcher_blocks=frozenset(
                int(block) for block in dispatch_map.dispatcher_blocks
            ),
            facts=facts,
        )

        def _add_redirect(
            source: int,
            target: int,
            *,
            ordered_path: tuple[int, ...] = (),
        ) -> bool:
            source = int(source)
            target = int(target)
            source_block = flow_graph.get_block(source)
            if source_block is None:
                blockers["tigress_switch_transition_source_missing"] += 1
                return False
            if source_block.nsucc != 1:
                blockers["tigress_switch_transition_source_not_dispatcher_pred"] += 1
                return False
            old_target = int(source_block.succs[0])
            if old_target not in reentry_targets:
                blockers["tigress_switch_transition_source_not_dispatcher_pred"] += 1
                return False
            if target in reentry_targets or target not in flow_graph.blocks:
                blockers["tigress_switch_transition_target_not_handler"] += 1
                return False
            if source == target:
                blockers["tigress_switch_transition_self_loop"] += 1
                return False
            via_pred: int | None = None
            if int(source_block.npred) > 1:
                via_pred = _ordered_path_predecessor(ordered_path, source)
                if via_pred is None:
                    blockers["tigress_switch_transition_source_not_owned"] += 1
                    return False
                if via_pred not in tuple(int(pred) for pred in source_block.preds):
                    blockers["tigress_switch_transition_pred_split_unproven"] += 1
                    return False
            key = (source, via_pred)
            previous = redirects_by_claim.get(key)
            if previous is not None:
                if previous != target:
                    blockers["tigress_switch_transition_conflicting_source"] += 1
                    return False
                return True
            redirects_by_claim[key] = target
            if via_pred is None:
                modifications.append(
                    RedirectGoto(
                        from_serial=source,
                        old_target=old_target,
                        new_target=target,
                    )
                )
            else:
                modifications.append(
                    EdgeRedirectViaPredSplit(
                        src_block=source,
                        old_target=old_target,
                        new_target=target,
                        via_pred=via_pred,
                    )
                )
            return True

        def _target_for_state(state: int) -> int | None:
            target = dispatch_map.resolve_target(int(state))
            if target is None:
                blockers["tigress_switch_transition_target_unresolved"] += 1
                return None
            target = int(target)
            if target == dispatcher_entry or target not in flow_graph.blocks:
                blockers["tigress_switch_transition_target_not_handler"] += 1
                return None
            return target

        map_initial_state = dispatch_map.initial_state
        artifact_initial_state = phase_artifact.initial_state
        initial_state = map_initial_state
        if initial_state is None:
            initial_state = artifact_initial_state
        elif (
            artifact_initial_state is not None
            and (int(initial_state) & 0xFFFFFFFFFFFFFFFF)
            != (int(artifact_initial_state) & 0xFFFFFFFFFFFFFFFF)
        ):
            blockers["tigress_switch_transition_initial_state_conflict"] += 1
        initial_redirect_proven = False
        if initial_state is not None and phase_artifact.pre_header_serial is not None:
            initial_target = dispatch_map.resolve_target(int(initial_state))
            pre_header = int(phase_artifact.pre_header_serial)
            pre_header_block = flow_graph.get_block(pre_header)
            if (
                initial_target is not None
                and pre_header_block is not None
                and pre_header_block.nsucc == 1
                and int(pre_header_block.succs[0]) in reentry_targets
                and int(initial_target) in flow_graph.blocks
            ):
                initial_redirect_proven = _add_redirect(pre_header, int(initial_target))
            else:
                blockers["tigress_switch_transition_initial_redirect_unproven"] += 1
        else:
            blockers["tigress_switch_transition_initial_redirect_unproven"] += 1

        for fact in facts:
            fact_kind = _switch_fact_transition_kind_name(fact)
            source_state = _switch_fact_source_state(fact)
            if source_state is None:
                if fact_kind in {"DIAGNOSTIC", "UNRESOLVED"}:
                    blockers[f"tigress_switch_transition_fact_{fact_kind.lower()}"] += 1
                continue
            if fact_kind in {"DIAGNOSTIC", "UNRESOLVED"}:
                blockers[f"tigress_switch_transition_fact_{fact_kind.lower()}"] += 1
                continue
            if fact_kind == "RETURN_FRONTIER":
                if not _switch_fact_trusted_proof_kind(fact, "TERMINAL_RETURN_FRONTIER"):
                    blockers["tigress_switch_transition_return_frontier_unproven"] += 1
                    continue
                exit_block = _switch_fact_exit_block(fact)
                if exit_block is not None:
                    block = flow_graph.get_block(exit_block)
                    if block is not None and dispatcher_entry in tuple(block.succs):
                        blockers["tigress_switch_transition_return_frontier_still_dispatches"] += 1
                        continue
                terminal_states.add(source_state)
                continue

            next_states = _switch_fact_next_states(fact)
            arm_exit_blocks = _switch_fact_arm_exit_blocks(fact)
            arm_ordered_paths = _switch_fact_arm_ordered_paths(fact)
            if fact_kind == "DIRECT":
                if len(next_states) != 1:
                    blockers["tigress_switch_transition_direct_target_count"] += 1
                    continue
                target = _target_for_state(next_states[0])
                if target is None:
                    continue
                source = _switch_fact_exit_block(fact)
                if source is None:
                    blockers["tigress_switch_transition_missing_exit_block"] += 1
                    continue
                ordered_path = arm_ordered_paths[0] if arm_ordered_paths else ()
                if _add_redirect(source, target, ordered_path=ordered_path):
                    lowered_states.add(source_state)
                continue

            if fact_kind == "CONDITIONAL":
                if not _switch_fact_trusted_proof_kind(fact, "REAL_DATA_DEPENDENT"):
                    blockers["tigress_switch_transition_conditional_untrusted"] += 1
                    continue
                if len(next_states) != 2:
                    blockers["tigress_switch_transition_conditional_target_count"] += 1
                    continue
                if len(arm_exit_blocks) != 2 or any(
                    value is None for value in arm_exit_blocks
                ):
                    blockers["tigress_switch_transition_conditional_missing_arm_exit"] += 1
                    continue
                arm_targets = tuple(_target_for_state(state) for state in next_states)
                if any(target is None for target in arm_targets):
                    continue
                arm_ok = True
                for index, (source, target) in enumerate(zip(arm_exit_blocks, arm_targets)):
                    ordered_path = (
                        arm_ordered_paths[index]
                        if index < len(arm_ordered_paths)
                        else ()
                    )
                    arm_ok = (
                        _add_redirect(int(source), int(target), ordered_path=ordered_path)
                        and arm_ok
                    )
                if arm_ok:
                    lowered_states.add(source_state)
                continue

            blockers[f"tigress_switch_transition_fact_{fact_kind.lower()}"] += 1

        if not initial_redirect_proven:
            blockers["tigress_switch_transition_initial_redirect_unproven"] += 1
        for state in sorted(visible_handler_states - lowered_states - terminal_states):
            blockers["tigress_switch_transition_visible_state_not_lowered"] += 1

        if not modifications:
            self._logger.debug(
                "Tigress switch transition found no edits; reentry_targets=%s facts=%s blockers=%s",
                tuple(sorted(reentry_targets)),
                tuple(
                    (
                        _switch_fact_transition_kind_name(fact),
                        _switch_fact_source_state(fact),
                        _switch_fact_exit_block(fact),
                        _switch_fact_next_states(fact),
                        _switch_fact_arm_exit_blocks(fact),
                    )
                    for fact in facts
                ),
                ", ".join(f"{reason}={count}" for reason, count in blockers.most_common())
                or "none",
            )
            if blockers:
                return (), tuple(sorted(blockers))
            return (), ("tigress_switch_transition_no_direct_candidates",)
        if blockers and not self._profile.allow_incomplete_switch_transition_facts:
            return (), tuple(sorted(blockers))
        self._logger.info(
            "Tigress switch transition lowering selected %d edit(s); blockers=%s",
            len(modifications),
            ", ".join(f"{reason}={count}" for reason, count in blockers.most_common())
            or "none",
        )
        return tuple(modifications), tuple(sorted(blockers))

    def _collect_phase_redirect_loop_recovery(
        self,
        *,
        mba: ida_hexrays.mba_t,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[tuple[GraphModification, ...], tuple[str, ...]]:
        if not candidate_records:
            return (), ()

        phase_cycle = self._build_interval_phase_loop_recovery(
            mba=mba,
            phase_artifact=phase_artifact,
            candidate_records=candidate_records,
        )
        if phase_cycle is not None:
            return phase_cycle, ()

        loop_recovery: list[GraphModification] = []
        blockers: list[str] = []

        for record in candidate_records:
            if record.target_serial is None or record.source_nsucc != 1:
                blockers.append("dispatcher_loop_recovery_requires_one_way_father")
                break
            branch_rewrite = self._build_phase_cycle_branch_recovery(
                mba=mba,
                phase_artifact=phase_artifact,
                record=record,
                candidate_records=candidate_records,
            )
            if branch_rewrite is not None:
                loop_recovery.extend(branch_rewrite)
                continue
            if record.raw_side_effect_count == 0:
                loop_recovery.append(
                    RedirectGoto(
                        from_serial=int(record.father_serial),
                        old_target=int(record.dispatcher_entry_serial),
                        new_target=int(record.target_serial),
                    )
                )
                continue
            if record.raw_side_effect_count != 1 or len(record.state_signature) != 1:
                blockers.append("dispatcher_loop_recovery_requires_single_state_write")
                break

            rewrite = self._build_live_state_write_recovery(
                mba=mba,
                father_serial=int(record.father_serial),
                dispatcher_entry_serial=int(record.dispatcher_entry_serial),
                target_serial=int(record.target_serial),
                expected_state=int(record.state_signature[0]),
                state_var_stkoff=int(phase_artifact.state_var_stkoff),
            )
            if rewrite is None:
                blockers.append("dispatcher_loop_recovery_non_state_write_insert")
                break
            loop_recovery.extend(rewrite)

        if blockers:
            return (), tuple(sorted(set(blockers)))
        return tuple(loop_recovery), ()

    def _dispatcher_loop_recovery_artifact_blockers(
        self,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
    ) -> tuple[str, ...]:
        blockers: list[str] = []
        if phase_artifact.semantic_reference_variant != "semantic_reference_like":
            blockers.append("dispatcher_loop_recovery_nonsemantic_artifact")
        if any(
            "_fallback" in str(label)
            for label in phase_artifact.semantic_state_labels
        ):
            blockers.append("dispatcher_loop_recovery_fallback_phase")
        return tuple(blockers)

    def _build_interval_phase_loop_recovery(
        self,
        *,
        mba: ida_hexrays.mba_t,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[GraphModification, ...] | None:
        if phase_artifact.state_var_stkoff is None or phase_artifact.initial_state is None:
            return None

        state_to_handler = {
            int(state): int(serial)
            for serial, state in phase_artifact.handler_state_map
        }
        if not state_to_handler:
            return None

        header_state = int(phase_artifact.initial_state)
        header_target = state_to_handler.get(header_state)
        if header_target is None:
            return None

        terminal_records = tuple(
            record
            for record in candidate_records
            if record.target_serial is not None
            and tuple(int(value) for value in record.state_signature)
            and record.raw_side_effect_count == 0
            and tuple(int(target) for target in record.target_scc)
            == (int(record.target_serial),)
        )
        terminal_states = {
            int(record.state_signature[0])
            for record in terminal_records
        }
        body_states = tuple(
            sorted(
                state
                for state in state_to_handler
                if state not in {header_state, *terminal_states}
            )
        )
        if len(body_states) != 1:
            return None

        body_state = int(body_states[0])
        body_target = int(state_to_handler[body_state])

        point_handler_targets = set(state_to_handler.values())
        next_phase_targets = tuple(
            sorted(
                {
                    int(serial)
                    for serial, _lo, _hi in phase_artifact.handler_range_map
                    if int(serial) not in point_handler_targets
                }
            )
        )
        if len(next_phase_targets) != 1:
            return None
        next_phase_target = int(next_phase_targets[0])

        def _matching_records(expected_state: int, expected_target: int) -> tuple[EmulatedDispatcherCandidateRecord, ...]:
            return tuple(
                record
                for record in candidate_records
                if record.target_serial is not None
                and tuple(int(value) for value in record.state_signature) == (expected_state,)
                and int(record.target_serial) == expected_target
                and int(record.source_nsucc) == 1
                and int(record.raw_side_effect_count) == 1
            )

        header_records = _matching_records(header_state, header_target)
        body_records = _matching_records(body_state, body_target)
        next_phase_records = tuple(
            record
            for record in candidate_records
            if record.target_serial is not None
            and int(record.target_serial) == next_phase_target
            and int(record.source_nsucc) == 1
            and int(record.raw_side_effect_count) == 1
        )
        if not header_records or len(body_records) != 1 or len(next_phase_records) < 1:
            return None

        def _is_2way(serial: int) -> bool:
            blk = mba.get_mblock(serial)
            return blk is not None and int(blk.nsucc()) == 2

        if not all(
            _is_2way(serial)
            for serial in (header_target, body_target, next_phase_target)
        ):
            return None

        modifications: list[GraphModification] = []
        for record in (*header_records, *body_records):
            rewrite = self._build_live_state_write_recovery(
                mba=mba,
                father_serial=int(record.father_serial),
                dispatcher_entry_serial=int(record.dispatcher_entry_serial),
                target_serial=int(record.target_serial),
                expected_state=int(record.state_signature[0]),
                state_var_stkoff=int(phase_artifact.state_var_stkoff),
            )
            if rewrite is None:
                return None
            modifications.extend(rewrite)

        modifications.extend(
            (
                RedirectBranch(
                    from_serial=header_target,
                    old_target=int(phase_artifact.dispatcher_entry_serial),
                    new_target=next_phase_target,
                ),
                RedirectBranch(
                    from_serial=body_target,
                    old_target=int(phase_artifact.dispatcher_entry_serial),
                    new_target=next_phase_target,
                ),
            )
        )
        if terminal_records:
            # The next phase already has a concrete terminal arm.  Preserve it
            # by sending the terminal state-write block to the real exit rather
            # than folding that conditional arm into a self-loop.
            for record in terminal_records:
                modifications.append(
                    RedirectGoto(
                        from_serial=int(record.father_serial),
                        old_target=int(phase_artifact.dispatcher_entry_serial),
                        new_target=int(record.target_serial),
                    )
                )
        else:
            modifications.append(
                RedirectBranch(
                    from_serial=next_phase_target,
                    old_target=int(phase_artifact.dispatcher_entry_serial),
                    new_target=next_phase_target,
                )
            )
        self._logger.info(
            "DispatcherLoopRecovery phase-cycle lowering: header=%s body=%s next_phase=%s terminal=%s mods=%d",
            tuple(int(record.father_serial) for record in header_records),
            tuple(int(record.father_serial) for record in body_records),
            tuple(int(record.father_serial) for record in next_phase_records),
            tuple(int(record.father_serial) for record in terminal_records),
            len(modifications),
        )
        return tuple(modifications)

    def _build_phase_cycle_branch_recovery(
        self,
        *,
        mba: ida_hexrays.mba_t,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        record: EmulatedDispatcherCandidateRecord,
        candidate_records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[GraphModification, ...] | None:
        if phase_artifact.semantic_reference_variant != "semantic_reference_like":
            return None
        if record.target_serial is None or record.raw_side_effect_count != 0:
            return None

        father_blk = mba.get_mblock(int(record.father_serial))
        if father_blk is None or father_blk.nsucc() != 1:
            return None
        if int(father_blk.succ(0)) != int(record.target_serial):
            return None

        predecessors = [mba.get_mblock(int(pred)) for pred in list(father_blk.predset)]
        conditional_parents = [
            parent
            for parent in predecessors
            if parent is not None
            and int(parent.nsucc()) == 2
            and int(record.father_serial) in {int(parent.succ(0)), int(parent.succ(1))}
        ]
        if len(conditional_parents) != 1:
            return None

        parent_blk = conditional_parents[0]
        if tuple(int(target) for _, _, target in phase_artifact.handler_range_map) and int(
            parent_blk.serial
        ) not in {
            int(target) for _, _, target in phase_artifact.handler_range_map
        }:
            return None
        if tuple(int(target) for target in record.target_scc) != (
            int(record.target_serial),
        ):
            return None

        self._logger.info(
            "DispatcherLoopRecovery phase-cycle branch: parent=%d terminal_bridge=%d -> self-loop %d",
            int(parent_blk.serial),
            int(record.father_serial),
            int(parent_blk.serial),
        )
        return (
            RedirectBranch(
                from_serial=int(parent_blk.serial),
                old_target=int(record.father_serial),
                new_target=int(parent_blk.serial),
            ),
        )

    def _build_live_state_write_recovery(
        self,
        *,
        mba: ida_hexrays.mba_t,
        father_serial: int,
        dispatcher_entry_serial: int,
        target_serial: int,
        expected_state: int,
        state_var_stkoff: int,
    ) -> tuple[GraphModification, ...] | None:
        blk = mba.get_mblock(father_serial)
        if blk is None:
            return None

        matched_ea: int | None = None
        insn = blk.head
        while insn is not None:
            if (
                int(insn.opcode) == int(ida_hexrays.m_mov)
                and int(getattr(getattr(insn, "d", None), "t", ida_hexrays.mop_z))
                == int(ida_hexrays.mop_S)
                and int(getattr(getattr(insn, "d", None), "s", SimpleNamespace(off=-1)).off)
                == state_var_stkoff
                and int(getattr(getattr(insn, "l", None), "t", ida_hexrays.mop_z))
                == int(ida_hexrays.mop_n)
                and int(getattr(getattr(getattr(insn, "l", None), "nnn", None), "value", -1))
                == expected_state
            ):
                matched_ea = int(insn.ea)
                break
            insn = insn.next

        if matched_ea is None:
            return None

        return (
            ZeroStateWrite(block_serial=father_serial, insn_ea=matched_ea),
            RedirectGoto(
                from_serial=father_serial,
                old_target=dispatcher_entry_serial,
                new_target=target_serial,
            ),
        )

    def _format_snapshot_mop(self, mop: object | None) -> str:
        if mop is None:
            return "z"
        t = getattr(mop, "t", None)
        size = getattr(mop, "size", None)
        value = getattr(mop, "value", None)
        stkoff = getattr(mop, "stkoff", None)
        reg = getattr(mop, "reg", None)
        block_ref = getattr(mop, "block_ref", None)
        return (
            f"t={t},size={size},value={value},stkoff={stkoff},"
            f"reg={reg},block_ref={block_ref}"
        )

    def _payload_signature(
        self,
        instructions: tuple[object, ...],
    ) -> tuple[str, ...]:
        signature: list[str] = []
        for insn in instructions:
            signature.append(
                "|".join(
                    (
                        f"op={getattr(insn, 'opcode', None)}",
                        f"l={self._format_snapshot_mop(getattr(insn, 'l', None))}",
                        f"r={self._format_snapshot_mop(getattr(insn, 'r', None))}",
                        f"d={self._format_snapshot_mop(getattr(insn, 'd', None))}",
                    )
                )
            )
        return tuple(signature)

    def _annotate_cluster_candidates(
        self,
        records: tuple[EmulatedDispatcherCandidateRecord, ...],
    ) -> tuple[EmulatedDispatcherCandidateRecord, ...]:
        repeated_keys = {
            key
            for key, count in Counter(
                record.cluster_key for record in records if record.cluster_key
            ).items()
            if count > 1
        }
        return tuple(
            record
            if not record.cluster_key
            else EmulatedDispatcherCandidateRecord(
                **{
                    **record.__dict__,
                    "cluster_candidate": record.cluster_key in repeated_keys,
                }
            )
            for record in records
        )

    def _summarize_modification(self, mod: GraphModification) -> str:
        if isinstance(mod, RedirectGoto):
            return (
                f"RedirectGoto({mod.from_serial}:{mod.old_target}->{mod.new_target})"
            )
        if isinstance(mod, ConvertToGoto):
            return f"ConvertToGoto({mod.block_serial}->{mod.goto_target})"
        if isinstance(mod, CreateConditionalRedirect):
            return (
                "CreateConditionalRedirect("
                f"src={mod.source_block},ref={mod.ref_block},"
                f"jcc={mod.conditional_target},ft={mod.fallthrough_target},"
                f"insns={len(mod.instructions)})"
            )
        if isinstance(mod, InsertBlock):
            return (
                "InsertBlock("
                f"pred={mod.pred_serial},succ={mod.succ_serial},"
                f"old={mod.old_target_serial},insns={len(mod.instructions)})"
            )
        return type(mod).__name__

    def _legacy_analogue_for_candidate(
        self,
        *,
        modifications: tuple[GraphModification, ...],
        source_nsucc: int,
    ) -> tuple[str | None, bool | None]:
        if not modifications:
            return None, None
        mod = modifications[0]
        if isinstance(mod, RedirectGoto):
            return "redirect_goto", True
        if isinstance(mod, ConvertToGoto):
            return "convert_to_goto", True
        if isinstance(mod, InsertBlock):
            return "create_and_redirect", source_nsucc == 1
        if isinstance(mod, CreateConditionalRedirect):
            if len(mod.instructions) > 0:
                return "create_and_redirect", False
            return "create_conditional_redirect", True
        return None, None

    def _selection_reason_for_candidate(
        self,
        *,
        modifications: tuple[GraphModification, ...],
        raw_side_effect_count: int,
        deferred_side_effect_count: int,
    ) -> str | None:
        if not modifications:
            return None
        mod = modifications[0]
        if isinstance(mod, RedirectGoto):
            return "direct_redirect"
        if isinstance(mod, ConvertToGoto):
            return "convert_conditional_source_to_goto"
        if isinstance(mod, InsertBlock):
            if deferred_side_effect_count > 0:
                return "insert_deferred_side_effect_block"
            if raw_side_effect_count > 0:
                return "insert_side_effect_block"
            return "insert_block"
        if isinstance(mod, CreateConditionalRedirect):
            if mod.source_block == mod.ref_block:
                return "resolved_conditional_exit"
            if deferred_side_effect_count > 0:
                return "conditional_redirect_with_deferred_side_effects"
            if raw_side_effect_count > 0:
                return "conditional_redirect_with_side_effects"
            return "conditional_redirect_clone"
        return type(mod).__name__

    def _build_lowering_candidate(
        self,
        resolver: GenericDispatcherResolverProtocol,
        dispatcher_father: ida_hexrays.mblock_t,
        dispatcher_info: object,
        *,
        scc_memberships: dict[int, tuple[int, ...]],
    ) -> tuple[
        tuple[GraphModification, ...] | None,
        str | None,
        EmulatedDispatcherCandidateRecord,
    ]:
        entry_serial = self._profile.dispatcher_entry_serial(dispatcher_info)
        base_record = EmulatedDispatcherCandidateRecord(
            dispatcher_entry_serial=int(entry_serial if entry_serial is not None else -1),
            father_serial=int(dispatcher_father.serial),
            source_nsucc=int(dispatcher_father.nsucc()),
            source_scc=scc_memberships.get(int(dispatcher_father.serial), ()),
        )
        if entry_serial is None:
            reason = "collector_dispatcher_missing_entry_block"
            return None, reason, EmulatedDispatcherCandidateRecord(
                **{
                    **base_record.__dict__,
                    "blocker": reason,
                    "semantically_valid": False,
                    "structurally_legacy_equivalent": None,
                }
            )

        def _blocked_record(reason: str, **extra) -> EmulatedDispatcherCandidateRecord:
            return EmulatedDispatcherCandidateRecord(
                **{
                    **base_record.__dict__,
                    **extra,
                    "blocker": reason,
                    "semantically_valid": False,
                    "structurally_legacy_equivalent": None,
                }
            )

        histories = self._profile.collect_dispatcher_father_histories(
            resolver,
            dispatcher_father,
            dispatcher_info,
        )
        if not histories:
            reason = "dispatcher_history_missing"
            return None, reason, _blocked_record(reason)
        if not self._profile.histories_resolved(resolver, histories):
            reason = "dispatcher_history_unresolved"
            return None, reason, _blocked_record(reason)

        values = self._profile.resolve_state_values(
            histories,
            dispatcher_info,
        )
        if not self._profile.state_values_complete(values):
            reason = "dispatcher_history_missing_values"
            return None, reason, _blocked_record(reason)
        if any(candidate != values[0] for candidate in values[1:]):
            reason = "dispatcher_history_ambiguous"
            return None, reason, _blocked_record(reason)
        state_signature = tuple(int(value) for value in values[0])
        deferred_side_effects = self._deferred_side_effects.get(
            (
                int(resolver.mba.entry_ea),
                int(entry_serial),
                state_signature,
            )
        )

        target_blk, disp_ins = self._profile.emulate_dispatcher_target(
            dispatcher_info,
            histories[0],
        )
        if target_blk is None:
            reason = "dispatcher_emulation_returned_no_target"
            return None, reason, _blocked_record(
                reason,
                state_signature=state_signature,
            )
        if target_blk.serial == dispatcher_father.serial:
            reason = "dispatcher_target_self_loop"
            return None, reason, _blocked_record(
                reason,
                state_signature=state_signature,
                target_serial=int(target_blk.serial),
            )

        raw_ins_to_copy = [
            ins
            for ins in disp_ins
            if ins is not None and ins.opcode not in CONTROL_FLOW_OPCODES
        ]
        safe_copy_insns = self._profile.filter_dependency_safe_copies(
            resolver,
            dispatcher_father,
            raw_ins_to_copy,
        )
        base_record = EmulatedDispatcherCandidateRecord(
            **{
                **base_record.__dict__,
                "state_signature": state_signature,
                "target_serial": int(target_blk.serial),
                "raw_side_effect_count": len(raw_ins_to_copy),
                "safe_side_effect_count": len(safe_copy_insns),
                "target_scc": scc_memberships.get(int(target_blk.serial), ()),
            }
        )

        def _record_for_modifications(
            modifications: tuple[GraphModification, ...],
        ) -> EmulatedDispatcherCandidateRecord:
            analogue_kind, _legacy_equivalent = self._legacy_analogue_for_candidate(
                modifications=modifications,
                source_nsucc=base_record.source_nsucc,
            )
            payload_signature: tuple[str, ...] = ()
            if safe_copy_insns:
                payload_signature = self._payload_signature(
                    tuple(capture_insn_snapshot(insn) for insn in safe_copy_insns)
                )
            elif deferred_side_effects:
                payload_signature = self._payload_signature(deferred_side_effects)
            cluster_key = ()
            if base_record.target_serial is not None:
                cluster_key = (
                    f"state={','.join(str(value) for value in base_record.state_signature)}",
                    f"target={base_record.target_serial}",
                    f"payload={';'.join(payload_signature)}",
                    f"source_scc={','.join(str(value) for value in base_record.source_scc)}",
                    f"target_scc={','.join(str(value) for value in base_record.target_scc)}",
                    f"source_nsucc={base_record.source_nsucc}",
                )
            return EmulatedDispatcherCandidateRecord(
                **{
                    **base_record.__dict__,
                    "selection_reason": self._selection_reason_for_candidate(
                        modifications=modifications,
                        raw_side_effect_count=len(raw_ins_to_copy),
                        deferred_side_effect_count=len(deferred_side_effects or ()),
                    ),
                    "selected_modification_kinds": tuple(
                        type(mod).__name__ for mod in modifications
                    ),
                    "selected_modification_summaries": tuple(
                        self._summarize_modification(mod) for mod in modifications
                    ),
                    "legacy_analogue_kind": analogue_kind,
                    "semantically_valid": True,
                    "structurally_legacy_equivalent": None,
                    "payload_signature": payload_signature,
                    "cluster_key": cluster_key,
                }
            )

        safe_copy_snapshots = tuple(
            capture_insn_snapshot(insn) for insn in safe_copy_insns
        )
        source_old_target = (
            int(dispatcher_father.succ(0))
            if int(dispatcher_father.nsucc()) >= 1
            else None
        )
        source_tail = getattr(dispatcher_father, "tail", None)
        source_is_conditional = bool(
            source_tail is not None
            and ida_hexrays.is_mcode_jcond(source_tail.opcode)
        )
        target_tail = getattr(target_blk, "tail", None)
        target_is_conditional = bool(
            target_tail is not None and ida_hexrays.is_mcode_jcond(target_tail.opcode)
        )
        target_conditional_target = None
        target_fallthrough_target = None
        if target_is_conditional:
            target_dest = getattr(getattr(target_tail, "d", None), "b", None)
            if target_dest is not None:
                target_conditional_target = int(target_dest)
            if target_blk.nextb is not None:
                target_fallthrough_target = int(target_blk.nextb.serial)
        clone_conditional_targets = (
            os.environ.get("D810_UNFLAT_CLONE_COND_TARGET", "").strip().lower()
            in ("1", "true", "yes", "on")
        )
        decision = plan_dispatcher_predecessor_rewrite(
            DispatcherPredecessorRewriteInput(
                source_serial=int(dispatcher_father.serial),
                source_nsucc=int(dispatcher_father.nsucc()),
                source_old_target=source_old_target,
                source_is_conditional=source_is_conditional,
                target_serial=int(target_blk.serial),
                target_nsucc=int(target_blk.nsucc()),
                target_is_conditional=target_is_conditional,
                target_conditional_target=target_conditional_target,
                target_fallthrough_target=target_fallthrough_target,
                safe_copy_instructions=safe_copy_snapshots,
                deferred_side_effect_instructions=tuple(deferred_side_effects or ()),
                raw_side_effect_count=len(raw_ins_to_copy),
                safe_side_effect_count=len(safe_copy_insns),
                defer_side_effects=(
                    bool(safe_copy_snapshots)
                    and resolver.mba.maturity == ida_hexrays.MMAT_CALLS
                ),
                clone_conditional_targets=clone_conditional_targets,
            )
        )
        if decision.defer_side_effects and safe_copy_snapshots:
            self._deferred_side_effects[
                (
                    int(resolver.mba.entry_ea),
                    int(entry_serial),
                    state_signature,
                )
            ] = safe_copy_snapshots
        if decision.blocker is not None:
            return None, decision.blocker, _blocked_record(
                decision.blocker,
                state_signature=state_signature,
                target_serial=int(target_blk.serial),
                raw_side_effect_count=len(raw_ins_to_copy),
                safe_side_effect_count=len(safe_copy_insns),
            )
        modifications = decision.modifications
        return modifications, None, _record_for_modifications(modifications)

    def _mop_const_value(self, mop) -> int | None:
        if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_n:
            return None
        nnn = getattr(mop, "nnn", None)
        value = getattr(nnn, "value", None)
        if value is None:
            return None
        try:
            return int(value)
        except Exception:
            return None

    def _mop_stack_offset(self, mop) -> int | None:
        if mop is None or getattr(mop, "t", None) != ida_hexrays.mop_S:
            return None
        stkoff = getattr(mop, "stkoff", None)
        if stkoff is None:
            stack_ref = getattr(mop, "s", None)
            stkoff = getattr(stack_ref, "off", None) if stack_ref is not None else None
        if stkoff is None:
            return None
        try:
            return int(stkoff)
        except Exception:
            return None

    def _is_state_var_compare_to(
        self,
        tail,
        *,
        state_var_stkoff: int,
        target_state: int,
    ) -> bool:
        if tail is None:
            return False
        left_value = self._mop_const_value(getattr(tail, "l", None))
        right_value = self._mop_const_value(getattr(tail, "r", None))
        if left_value is not None and (left_value & 0xFFFFFFFF) == target_state:
            return self._mop_stack_offset(getattr(tail, "r", None)) == state_var_stkoff
        if right_value is not None and (right_value & 0xFFFFFFFF) == target_state:
            return self._mop_stack_offset(getattr(tail, "l", None)) == state_var_stkoff
        return False

    def _find_dispatcher_ref_block_for_state(
        self,
        mba: ida_hexrays.mba_t,
        *,
        phase_artifact: EmulatedDispatcherPhaseArtifact,
        target_state: int,
        target_serial: int,
    ) -> int | None:
        """Find the dispatcher comparison block that guards one recovered state."""

        state_var_stkoff = phase_artifact.state_var_stkoff
        if state_var_stkoff is None:
            return None
        for serial in phase_artifact.bst_node_blocks:
            blk = mba.get_mblock(int(serial))
            if blk is None or blk.tail is None:
                continue
            if not ida_hexrays.is_mcode_jcond(blk.tail.opcode):
                continue
            try:
                conditional_target = int(blk.tail.d.b)
            except Exception:
                continue
            if conditional_target != int(target_serial):
                continue
            if not self._is_state_var_compare_to(
                blk.tail,
                state_var_stkoff=int(state_var_stkoff),
                target_state=int(target_state) & 0xFFFFFFFF,
            ):
                continue
            return int(serial)
        return None

    def _build_dynamic_transition_candidate(
        self,
        *,
        mba: ida_hexrays.mba_t,
        dispatcher_father: ida_hexrays.mblock_t,
        dispatcher_info: object,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
        scc_memberships: dict[int, tuple[int, ...]],
    ) -> tuple[tuple[GraphModification, ...], EmulatedDispatcherCandidateRecord] | None:
        transition_result = getattr(phase_context, "transition_result", None)
        if transition_result is None or phase_artifact is None:
            return None
        if phase_artifact.state_var_stkoff is None:
            return None
        entry_serial = self._profile.dispatcher_entry_serial(dispatcher_info)
        if entry_serial is None:
            return None
        if dispatcher_father.nsucc() != 1:
            return None
        if int(dispatcher_father.succ(0)) != int(entry_serial):
            return None

        father_serial = int(dispatcher_father.serial)
        matched_transition, matched_handler = self._profile.select_dynamic_transition(
            transition_result,
            father_serial=father_serial,
        )
        if matched_transition is None or matched_handler is None:
            return None

        target_state = int(matched_transition.to_state)
        target_handler = getattr(transition_result, "handlers", {}).get(target_state)
        if target_handler is None:
            return None
        target_serial = int(getattr(target_handler, "check_block", -1))
        if target_serial < 0 or target_serial == father_serial:
            return None
        ref_serial = self._find_dispatcher_ref_block_for_state(
            mba,
            phase_artifact=phase_artifact,
            target_state=target_state,
            target_serial=target_serial,
        )
        if ref_serial is None:
            return None
        fallthrough_serial = self._profile.dynamic_guard_fallthrough(
            transition_result,
            target_state=target_state,
            target_serial=target_serial,
            father_serial=father_serial,
        )
        if fallthrough_serial is None:
            fallthrough_serial = self._dynamic_guard_fallthrough_from_predecessor_facts(
                phase_context,
                source_state=target_state,
                target_serial=target_serial,
                father_serial=father_serial,
            )
        if fallthrough_serial is None or fallthrough_serial == target_serial:
            return None

        source_scc = scc_memberships.get(father_serial, ())
        target_scc = scc_memberships.get(target_serial, ())
        modifications = (
            CreateConditionalRedirect(
                source_block=father_serial,
                ref_block=ref_serial,
                conditional_target=target_serial,
                fallthrough_target=fallthrough_serial,
            ),
        )
        record = EmulatedDispatcherCandidateRecord(
            dispatcher_entry_serial=int(entry_serial),
            father_serial=father_serial,
            state_signature=(target_state,),
            target_serial=target_serial,
            source_nsucc=int(dispatcher_father.nsucc()),
            raw_side_effect_count=0,
            safe_side_effect_count=0,
            selection_reason="dynamic_state_write_conditional_redirect",
            selected_modification_kinds=tuple(
                type(mod).__name__ for mod in modifications
            ),
            selected_modification_summaries=tuple(
                self._summarize_modification(mod) for mod in modifications
            ),
            legacy_analogue_kind="create_conditional_redirect",
            semantically_valid=True,
            structurally_legacy_equivalent=False,
            source_scc=source_scc,
            target_scc=target_scc,
            cluster_key=(
                f"state={target_state}",
                f"target={target_serial}",
                f"fallthrough={fallthrough_serial}",
                "dynamic_state_write",
                f"source_scc={','.join(str(value) for value in source_scc)}",
                f"target_scc={','.join(str(value) for value in target_scc)}",
                f"source_nsucc={int(dispatcher_father.nsucc())}",
            ),
        )
        self._logger.info(
            "Emulated-dispatcher dynamic state-write conditional redirect: "
            "father=%d ref=blk[%d] true=blk[%d] false=blk[%d] state=0x%X",
            father_serial,
            ref_serial,
            target_serial,
            fallthrough_serial,
            target_state & 0xFFFFFFFF,
        )
        return modifications, record

    def _build_dynamic_transition_candidate_from_predecessor_fact(
        self,
        *,
        mba: ida_hexrays.mba_t,
        fact: PredecessorDispatcherTargetFact,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
        scc_memberships: dict[int, tuple[int, ...]],
    ) -> tuple[tuple[GraphModification, ...], EmulatedDispatcherCandidateRecord] | None:
        """Build a dynamic guarded edge from recon predecessor-target proof."""

        transition_result = getattr(phase_context, "transition_result", None)
        if transition_result is None or phase_artifact is None:
            return None
        if phase_artifact.state_var_stkoff is None:
            return None
        if fact.transition_provenance_kind != "global_or_state_write":
            return None

        father_serial = int(fact.predecessor_block_serial)
        entry_serial = int(fact.dispatcher_entry_serial)
        target_state = int(fact.state_const)
        target_serial = int(fact.target_block_serial)
        if target_serial == father_serial:
            return None
        state_dispatcher_map = getattr(phase_context, "state_dispatcher_map", None)
        dispatcher_blocks = set(
            getattr(state_dispatcher_map, "dispatcher_blocks", ()) or ()
        )
        if target_serial in dispatcher_blocks:
            return None

        dispatcher_father = mba.get_mblock(father_serial)
        if dispatcher_father is None or dispatcher_father.nsucc() != 1:
            return None
        if int(dispatcher_father.succ(0)) != entry_serial:
            return None

        ref_serial = self._find_dispatcher_ref_block_for_state(
            mba,
            phase_artifact=phase_artifact,
            target_state=target_state,
            target_serial=target_serial,
        )
        if ref_serial is None and fact.compare_block_serial is not None:
            ref_serial = int(fact.compare_block_serial)
        if ref_serial is None:
            return None
        fallthrough_serial = self._profile.dynamic_guard_fallthrough(
            transition_result,
            target_state=target_state,
            target_serial=target_serial,
            father_serial=father_serial,
        )
        if fallthrough_serial is None:
            fallthrough_serial = self._dynamic_guard_fallthrough_from_predecessor_facts(
                phase_context,
                source_state=target_state,
                target_serial=target_serial,
                father_serial=father_serial,
            )
        if fallthrough_serial is None or fallthrough_serial == target_serial:
            return None

        source_scc = scc_memberships.get(father_serial, ())
        target_scc = scc_memberships.get(target_serial, ())
        modifications = (
            CreateConditionalRedirect(
                source_block=father_serial,
                ref_block=ref_serial,
                conditional_target=target_serial,
                fallthrough_target=fallthrough_serial,
            ),
        )
        record = EmulatedDispatcherCandidateRecord(
            dispatcher_entry_serial=entry_serial,
            father_serial=father_serial,
            state_signature=(target_state,),
            target_serial=target_serial,
            source_nsucc=int(dispatcher_father.nsucc()),
            raw_side_effect_count=0,
            safe_side_effect_count=0,
            selection_reason="dynamic_state_write_conditional_redirect",
            selected_modification_kinds=tuple(
                type(mod).__name__ for mod in modifications
            ),
            selected_modification_summaries=tuple(
                self._summarize_modification(mod) for mod in modifications
            ),
            legacy_analogue_kind="create_conditional_redirect",
            semantically_valid=True,
            structurally_legacy_equivalent=False,
            source_scc=source_scc,
            target_scc=target_scc,
            cluster_key=(
                f"state={target_state}",
                f"target={target_serial}",
                f"fallthrough={fallthrough_serial}",
                "predecessor_dispatcher_target",
                f"resolver={fact.resolver_kind}",
                f"source_scc={','.join(str(value) for value in source_scc)}",
                f"target_scc={','.join(str(value) for value in target_scc)}",
                f"source_nsucc={int(dispatcher_father.nsucc())}",
            ),
        )
        self._logger.info(
            "Emulated-dispatcher predecessor-target conditional redirect: "
            "father=%d ref=blk[%d] true=blk[%d] false=blk[%d] "
            "state=0x%X resolver=%s",
            father_serial,
            ref_serial,
            target_serial,
            fallthrough_serial,
            target_state & 0xFFFFFFFF,
            fact.resolver_kind,
        )
        return modifications, record

    def _dynamic_guard_fallthrough_from_predecessor_facts(
        self,
        phase_context: EmulatedDispatcherPhaseContext | None,
        *,
        source_state: int,
        target_serial: int,
        father_serial: int,
    ) -> int | None:
        """Resolve guarded-edge fallthrough from predecessor-target facts."""

        if phase_context is None:
            return None
        candidates: list[int] = []
        for fact in getattr(
            phase_context, "predecessor_dispatcher_target_facts", ()
        ) or ():
            if not isinstance(fact, PredecessorDispatcherTargetFact):
                continue
            if int(fact.predecessor_block_serial) != int(target_serial):
                continue
            if fact.source_state_const is None:
                continue
            if int(fact.source_state_const) != int(source_state):
                continue
            candidate = int(fact.target_block_serial)
            if candidate in (int(target_serial), int(father_serial)):
                continue
            candidates.append(candidate)
        unique_candidates = tuple(dict.fromkeys(candidates))
        if len(unique_candidates) != 1:
            return None
        return unique_candidates[0]

    def _collect_predecessor_dispatcher_target_candidates(
        self,
        *,
        mba: ida_hexrays.mba_t,
        phase_artifact: EmulatedDispatcherPhaseArtifact | None,
        phase_context: EmulatedDispatcherPhaseContext | None,
        flow_graph: FlowGraph,
    ) -> tuple[
        tuple[GraphModification, ...],
        tuple[str, ...],
        tuple[EmulatedDispatcherCandidateRecord, ...],
    ]:
        """Collect dynamic candidates from recon predecessor-target facts."""

        if phase_context is None:
            return (), (), ()
        facts = tuple(
            getattr(phase_context, "predecessor_dispatcher_target_facts", ()) or ()
        )
        scc_memberships = self._compute_scc_memberships(flow_graph)
        modifications: list[GraphModification] = []
        candidate_records: list[EmulatedDispatcherCandidateRecord] = []
        seen_fathers: set[tuple[int, int, int]] = set()
        for fact in facts:
            if not isinstance(fact, PredecessorDispatcherTargetFact):
                continue
            fact_key = (
                int(fact.dispatcher_entry_serial),
                int(fact.predecessor_block_serial),
                int(fact.state_const),
            )
            if fact_key in seen_fathers:
                continue
            seen_fathers.add(fact_key)
            start_index = len(modifications)
            candidate = self._build_dynamic_transition_candidate_from_predecessor_fact(
                mba=mba,
                fact=fact,
                phase_artifact=phase_artifact,
                phase_context=phase_context,
                scc_memberships=scc_memberships,
            )
            if candidate is None:
                continue
            candidate_modifications, record = candidate
            modifications.extend(candidate_modifications)
            candidate_records.append(
                EmulatedDispatcherCandidateRecord(
                    **{
                        **record.__dict__,
                        "selected_modification_indexes": tuple(
                            range(start_index, len(modifications))
                        ),
                    }
                )
            )

        return (
            tuple(modifications),
            (),
            self._annotate_cluster_candidates(tuple(candidate_records)),
        )

    def build_snapshot(
        self,
        mba: object,
        detection: EmulatedDispatcherDetection,
    ) -> AnalysisSnapshot:
        self._prepare_dispatcher_fathers(mba, detection)
        flow_graph = self._cfg_translator.lift(mba)
        phase_artifact, phase_context = self._build_phase_artifact(
            mba,
            detection,
            flow_graph=flow_graph,
        )
        fallback_modifications, fallback_blockers, candidate_records = self._collect_lowering_candidates(
            mba,
            detection,
            flow_graph=flow_graph,
            phase_artifact=phase_artifact,
            phase_context=phase_context,
        )
        phase_reconstruction_modifications: tuple[GraphModification, ...] = ()
        phase_reconstruction_blockers: tuple[str, ...] = ()
        if self._phase_reconstruction_allowed(mba, detection):
            phase_reconstruction_modifications, phase_reconstruction_blockers = (
                self._collect_phase_reconstruction_modifications(
                    mba=mba,
                    flow_graph=flow_graph,
                    detection=detection,
                    phase_artifact=phase_artifact,
                    phase_context=phase_context,
                )
            )
            if phase_reconstruction_blockers:
                self._logger.info(
                    "Phase reconstruction lowering blocked: %s",
                    phase_reconstruction_blockers,
                )
        state_dag_modifications: tuple[GraphModification, ...] = ()
        state_dag_blockers: tuple[str, ...] = ()
        if (
            mba.maturity >= ida_hexrays.MMAT_GLBOPT1
            and detection.dispatcher_shape in {"conditional_chain", "switch_table"}
        ):
            state_dag_modifications, state_dag_blockers = (
                self._collect_phase_state_dag_modifications(
                    flow_graph=flow_graph,
                    detection=detection,
                    phase_artifact=phase_artifact,
                    phase_context=phase_context,
                )
            )
            if state_dag_blockers:
                self._logger.info(
                    "Phase state-DAG lowering blocked: %s",
                    state_dag_blockers,
                )
        switch_transition_modifications: tuple[GraphModification, ...] = ()
        switch_transition_blockers: tuple[str, ...] = ()
        if (
            mba.maturity >= ida_hexrays.MMAT_GLBOPT1
            and detection.dispatcher_shape == "switch_table"
        ):
            switch_transition_modifications, switch_transition_blockers = (
                self._collect_tigress_switch_transition_modifications(
                    flow_graph=flow_graph,
                    phase_artifact=phase_artifact,
                    phase_context=phase_context,
                )
            )
            if switch_transition_blockers:
                self._logger.info(
                    "Tigress switch transition lowering blocked: %s",
                    switch_transition_blockers,
                )
        if (
            not fallback_modifications
            and not fallback_blockers
            and not detection.collector_dispatchers
            and mba.maturity >= ida_hexrays.MMAT_GLBOPT1
        ):
            phase_modifications, phase_blockers = (
                self._collect_phase_linear_chain_modifications(
                    mba=mba,
                    flow_graph=flow_graph,
                    detection=detection,
                    phase_artifact=phase_artifact,
                    phase_context=phase_context,
                )
            )
            if not phase_modifications:
                derived_modifications, derived_blockers = (
                    self._collect_derived_xor_dispatcher_modifications(
                        flow_graph=flow_graph,
                        phase_artifact=phase_artifact,
                        phase_context=phase_context,
                    )
                )
                if derived_modifications and not derived_blockers:
                    phase_modifications = derived_modifications
                    phase_blockers = ()
                elif derived_blockers and not phase_blockers:
                    phase_blockers = derived_blockers
            if phase_modifications and not phase_blockers:
                fallback_modifications = phase_modifications
                fallback_blockers = ()
            elif phase_blockers:
                fallback_blockers = phase_blockers
        loop_recovery_modifications: tuple[GraphModification, ...] = ()
        loop_recovery_blockers: tuple[str, ...] = ()
        if mba.maturity >= ida_hexrays.MMAT_GLBOPT1 and detection.collector_dispatchers:
            loop_recovery_modifications, loop_recovery_blockers = (
                self._collect_loop_recovery_modifications(
                    mba=mba,
                    snapshot_flow_graph=flow_graph,
                    phase_artifact=phase_artifact,
                    phase_context=phase_context,
                    candidate_records=candidate_records,
                )
            )
        semantic_carrier_modifications: tuple[GraphModification, ...] = ()
        if mba.maturity >= ida_hexrays.MMAT_GLBOPT1:
            carrier_facts = self._profile.collect_post_execute_carrier_facts(mba)
            semantic_carrier_modifications = (
                _collect_semantic_carrier_promotion_modifications(
                    mba,
                    carrier_facts,
                )
            )
            if semantic_carrier_modifications:
                self._logger.info(
                    "Semantic carrier GLBOPT1 lowering found %d fused store value(s)",
                    len(semantic_carrier_modifications),
                )
        selected_modifications = fallback_modifications
        selected_lowering_mode = detection.lowering_mode
        selected_blockers = fallback_blockers
        selected_partial_rewrite_reasons: tuple[str, ...] = ()
        switch_transition_partial_allowed = (
            self._profile.allow_incomplete_switch_transition_facts
            and _switch_transition_blockers_allow_partial_lowering(
                switch_transition_blockers,
                facts=tuple(
                    getattr(phase_context, "switch_case_transition_facts", ()) or ()
                ),
            )
        )
        switch_transition_selectable = bool(switch_transition_modifications) and (
            not switch_transition_blockers
            or switch_transition_partial_allowed
        )
        if self._profile.prefer_switch_transition_facts and switch_transition_selectable:
            selected_modifications = switch_transition_modifications
            selected_lowering_mode = "tigress_switch_transition_facts"
            selected_blockers = (
                () if switch_transition_partial_allowed else switch_transition_blockers
            )
            if switch_transition_partial_allowed:
                selected_partial_rewrite_reasons = tuple(
                    sorted(set(switch_transition_blockers))
                )
        elif phase_reconstruction_modifications and not phase_reconstruction_blockers:
            if (
                fallback_modifications
                and not fallback_blockers
                and self._profile.state_transport == "state_dispatcher_map"
            ):
                selected_modifications = (
                    tuple(fallback_modifications)
                    + tuple(phase_reconstruction_modifications)
                )
            else:
                selected_modifications = phase_reconstruction_modifications
            selected_lowering_mode = "state_region_reconstruction"
            selected_blockers = ()
        elif state_dag_modifications and not state_dag_blockers:
            selected_modifications = state_dag_modifications
            selected_lowering_mode = "state_dag_recovery"
            selected_blockers = ()
        elif switch_transition_selectable:
            selected_modifications = switch_transition_modifications
            selected_lowering_mode = "tigress_switch_transition_facts"
            selected_blockers = (
                () if switch_transition_partial_allowed else switch_transition_blockers
            )
            if switch_transition_partial_allowed:
                selected_partial_rewrite_reasons = tuple(
                    sorted(set(switch_transition_blockers))
                )
        elif not selected_modifications and phase_reconstruction_blockers:
            selected_blockers = phase_reconstruction_blockers
        elif not selected_modifications and state_dag_blockers:
            selected_blockers = state_dag_blockers
        elif not selected_modifications and switch_transition_blockers:
            selected_blockers = switch_transition_blockers
        if (
            loop_recovery_blockers
            and "dispatcher_loop_recovery_return_carrier_bypass"
            in loop_recovery_blockers
        ):
            selected_modifications = ()
            selected_lowering_mode = "dispatcher_loop_recovery"
            selected_blockers = loop_recovery_blockers
            selected_partial_rewrite_reasons = ()
        if loop_recovery_modifications and not loop_recovery_blockers:
            selected_modifications = loop_recovery_modifications
            selected_lowering_mode = "dispatcher_loop_recovery"
            selected_blockers = ()
            selected_partial_rewrite_reasons = ()
        if (
            semantic_carrier_modifications
            and not selected_modifications
        ):
            selected_modifications = semantic_carrier_modifications
            selected_lowering_mode = "semantic_carrier_hoist"
            selected_blockers = ()
        # Match the safer legacy posture for partially-resolved dispatcher
        # families: observe raw candidates for diagnostics, but do not lower
        # any dispatcher edits unless all predecessor histories needed for the
        # current collector view are resolvable.
        planning_ready = bool(selected_modifications) and not selected_blockers
        planning_blocker = None
        if not planning_ready:
            if selected_blockers:
                planning_blocker = selected_blockers[0]
            else:
                planning_blocker = detection.planning_blocker
        observation = EmulatedDispatcherMetadata(
            dispatcher_shape=detection.dispatcher_shape,
            state_transport=detection.state_transport,
            lowering_mode=selected_lowering_mode,
            provenance_hints=detection.provenance_hints,
            analysis_dispatchers=detection.analysis_dispatchers,
            state_dispatcher_entries=detection.state_dispatcher_entries,
            state_constants=detection.state_constants,
            collector_dispatchers=detection.collector_dispatcher_entries,
            planning_ready=planning_ready,
            planning_blocker=planning_blocker,
            candidate_count=len(fallback_modifications),
            rejected_fathers=len(fallback_blockers),
            candidate_kinds=tuple(type(mod).__name__ for mod in selected_modifications),
            rejection_reasons=tuple(sorted(set(selected_blockers))),
            partial_rewrite_reasons=selected_partial_rewrite_reasons,
            candidate_records=candidate_records,
            phase_artifact=phase_artifact,
            selected_lowering_mode=selected_lowering_mode,
            selected_modification_count=len(selected_modifications),
            loop_recovery_modification_count=len(loop_recovery_modifications),
        )
        flow_graph = FlowGraph(
            blocks=flow_graph.blocks,
            entry_serial=flow_graph.entry_serial,
            func_ea=flow_graph.func_ea,
            metadata={
                **dict(flow_graph.metadata),
                EMULATED_DISPATCHER_METADATA_KEY: observation,
                EMULATED_DISPATCHER_MODIFICATIONS_KEY: selected_modifications,
                EMULATED_DISPATCHER_FALLBACK_MODIFICATIONS_KEY: fallback_modifications,
                EMULATED_DISPATCHER_LOOP_RECOVERY_MODIFICATIONS_KEY: loop_recovery_modifications,
                EMULATED_DISPATCHER_CANDIDATE_RECORDS_KEY: candidate_records,
                EMULATED_DISPATCHER_PHASE_ARTIFACT_KEY: phase_artifact,
                EMULATED_DISPATCHER_PHASE_CONTEXT_KEY: phase_context,
            },
        )
        return AnalysisSnapshot(
            mba=mba,
            dispatcher_cache=DispatcherCache.get_or_create(mba),
            reachability=self.compute_reachability_info(mba),
            maturity=mba.maturity,
            flow_graph=flow_graph,
            state_summary=StateModelSummary(
                state_constants=frozenset(detection.state_constants),
                handler_count=len(detection.analysis_dispatchers),
                transition_count=0,
            ),
        )

    def observe_phase_diagnostics(
        self,
        mba: object,
        snapshot: AnalysisSnapshot,
        *,
        fact_view: object | None = None,
    ) -> None:
        """Persist read-only dispatcher phase evidence through observability.

        This is diagnostics-only. It captures the exact DAG produced from the
        current dispatcher evidence plus any in-memory fact-derived transition
        resolutions. Runtime behavior must not depend on the SQLite sink.
        """
        flow_graph = snapshot.flow_graph
        if flow_graph is None:
            return
        metadata = getattr(flow_graph, "metadata", {}) or {}
        phase_context = metadata.get(EMULATED_DISPATCHER_PHASE_CONTEXT_KEY)
        if not isinstance(phase_context, EmulatedDispatcherPhaseContext):
            return
        dag = getattr(phase_context, "dag", None)
        if dag is None:
            return
        dag_node_objects = tuple(getattr(dag, "nodes", ()) or ())
        dag_edge_objects = tuple(getattr(dag, "edges", ()) or ())

        try:
            from d810.hexrays.observability import request_capture_mba_snapshot
            from d810.recon.observability import (
                DagEdge,
                DagNode,
                dag_node_diagnostic_state,
                observe_dag,
                observe_branch_ownership_proofs,
                observe_dag_local_facts,
                observe_fact_observation,
                observe_rendered_program,
                observe_state_transition_dispatch_resolutions,
                observe_switch_case_transition_facts,
            )

            maturity_name = self._maturity_name(
                int(getattr(mba, "maturity", 0) or 0)
            )
            snap_ref = request_capture_mba_snapshot(
                blocks=[],
                label=f"{self._profile.name}_emulated_dispatcher_phase_dag",
                func_ea=int(getattr(mba, "entry_ea", 0) or 0),
                maturity=maturity_name,
                phase="pre_d810",
            )
            if snap_ref is None:
                return

            dag_nodes = []
            for node in dag_node_objects:
                diagnostic_state = dag_node_diagnostic_state(node)
                dag_nodes.append(DagNode(
                    state=diagnostic_state,
                    state_hex=(
                        f"0x{diagnostic_state & 0xFFFFFFFFFFFFFFFF:016x}"
                    ),
                    entry_block=int(getattr(node, "entry_anchor", -1)),
                    classification=self._enum_name(getattr(node, "kind", "")),
                    shared_suffix=(
                        json.dumps(
                            sorted(
                                int(block)
                                for block in getattr(
                                    node, "shared_suffix_blocks", ()
                                )
                            )
                        )
                        if getattr(node, "shared_suffix_blocks", ())
                        else None
                    ),
                ))

            dag_edges = []
            for edge_index, edge in enumerate(dag_edge_objects):
                source_anchor = getattr(edge, "source_anchor", None)
                target_key = getattr(edge, "target_key", None)
                dag_edges.append(DagEdge(
                    edge_id=int(edge_index),
                    source_state=self._state_const_from_key(
                        getattr(edge, "source_key", None)
                    ),
                    target_state=self._state_const_from_key(target_key),
                    edge_kind=self._enum_name(getattr(edge, "kind", "")),
                    source_block=(
                        int(getattr(source_anchor, "block_serial"))
                        if source_anchor is not None
                        and getattr(source_anchor, "block_serial", None) is not None
                        else None
                    ),
                    source_arm=(
                        int(getattr(source_anchor, "branch_arm"))
                        if source_anchor is not None
                        and getattr(source_anchor, "branch_arm", None) is not None
                        else None
                    ),
                    target_entry=(
                        int(getattr(edge, "target_entry_anchor"))
                        if getattr(edge, "target_entry_anchor", None) is not None
                        else None
                    ),
                    ordered_path=(
                        json.dumps(
                            [int(serial) for serial in getattr(edge, "ordered_path", ())]
                        )
                        if getattr(edge, "ordered_path", ())
                        else "[]"
                    ),
                ))

            observe_dag(snap_ref, dag_nodes, dag_edges)
            observe_dag_local_facts(snap_ref, dag)
            proofs = _collect_phase_branch_ownership_proofs(
                dag=SimpleNamespace(edges=dag_edge_objects),
                dispatch_map=phase_context.state_dispatcher_map,
                proof_refiners=self._profile.collect_branch_ownership_refiners(
                    mba,
                    self._logger,
                ),
            )
            if proofs:
                observe_branch_ownership_proofs(
                    snap_ref,
                    tuple(
                        proof.to_diag_row(
                            profile_name=self._profile.name,
                            maturity=maturity_name,
                        )
                        for proof in proofs
                    ),
                )
                proof_counts = Counter(
                    (proof.proof_kind_name, bool(proof.trusted))
                    for proof in proofs
                )
                self._logger.info(
                    "BRANCH_OWNERSHIP_PROOFS: emitted %d rows for profile=%s "
                    "groups=%s",
                    len(proofs),
                    self._profile.name,
                    dict(sorted(proof_counts.items())),
                )
            switch_case_transition_facts = tuple(
                getattr(phase_context, "switch_case_transition_facts", ()) or ()
            )
            if switch_case_transition_facts:
                observe_switch_case_transition_facts(
                    snap_ref,
                    switch_case_transition_facts,
                )
                self._logger.info(
                    "SWITCH_CASE_TRANSITION_FACTS: emitted %d rows "
                    "for profile=%s",
                    len(switch_case_transition_facts),
                    self._profile.name,
                )
            dispatcher_discovery_fact_observations = tuple(
                getattr(
                    phase_context,
                    "dispatcher_discovery_fact_observations",
                    (),
                )
                or ()
            )
            profile_fact_observations = self._profile.collect_fact_observations(mba)
            fact_observations = (
                *dispatcher_discovery_fact_observations,
                *profile_fact_observations,
            )
            if fact_observations:
                observe_fact_observation(
                    snap_ref,
                    int(getattr(mba, "entry_ea", 0) or 0),
                    fact_observations,
                )
                self._logger.info(
                    "PROFILE_FACT_OBSERVATIONS: emitted %d rows for profile=%s "
                    "(dispatcher_discovery=%d profile_specific=%d)",
                    len(fact_observations),
                    self._profile.name,
                    len(dispatcher_discovery_fact_observations),
                    len(profile_fact_observations),
                )
            observe_rendered_program(
                snap_ref,
                phase_context.semantic_reference_program,
            )
            self._observe_state_transition_dispatch_resolutions(
                snap_ref,
                phase_context=phase_context,
                fact_view=fact_view,
                maturity_name=maturity_name,
            )
        except Exception:
            self._logger.debug(
                "emulated-dispatcher phase diagnostics persistence failed",
                exc_info=True,
            )

    def _observe_state_transition_dispatch_resolutions(
        self,
        snap_ref: object,
        *,
        phase_context: EmulatedDispatcherPhaseContext,
        fact_view: object | None,
        maturity_name: str,
    ) -> None:
        state_dispatcher_map = getattr(
            phase_context,
            "state_dispatcher_map",
            None,
        )
        if state_dispatcher_map is None or fact_view is None:
            return
        try:
            from d810.recon.flow.state_transition_resolution import (
                facts_from_validated_view,
                resolve_state_transitions_with_dispatcher_map,
            )
            from d810.recon.observability import (
                observe_state_transition_dispatch_resolutions,
            )

            transition_facts, state_write_anchors = facts_from_validated_view(
                fact_view
            )
            if not transition_facts:
                return
            resolutions = resolve_state_transitions_with_dispatcher_map(
                transition_facts,
                dispatch_map=state_dispatcher_map,
                state_write_anchors=state_write_anchors,
                resolution_kind=(
                    f"{self._profile.name}_state_dispatcher_map"
                ),
            )
            observe_state_transition_dispatch_resolutions(
                snap_ref,
                tuple(
                    resolution.to_diag_row(
                        resolution_maturity=maturity_name
                    )
                    for resolution in resolutions
                ),
            )
            self._logger.info(
                "STATE_TRANSITION_DISPATCH_RESOLUTIONS: emitted %d rows "
                "for profile=%s",
                len(resolutions),
                self._profile.name,
            )
        except Exception:
            self._logger.debug(
                "state-transition dispatch resolution observation failed",
                exc_info=True,
            )

    @staticmethod
    def _state_const_from_key(key: object | None) -> int | None:
        if key is None:
            return None
        state_const = getattr(key, "state_const", None)
        if state_const is None:
            return None
        try:
            return int(state_const)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _enum_name(value: object) -> str:
        name = getattr(value, "name", None)
        if name is not None:
            return str(name)
        return str(value)

    @staticmethod
    def _maturity_name(maturity: int) -> str:
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

    def _prepare_dispatcher_fathers(
        self,
        mba: ida_hexrays.mba_t,
        detection: EmulatedDispatcherDetection,
    ) -> int:
        if mba.maturity != ida_hexrays.MMAT_CALLS:
            return 0
        if not detection.collector_dispatchers:
            return 0

        resolver = self._make_resolver(mba, detection)
        total_changes = self._profile.prepare_dispatcher_fathers(resolver)
        if total_changes > 0:
            mba.mark_chains_dirty()
            self._logger.info(
                "Prepared emulated-dispatcher direct fathers: %d change(s)",
                total_changes,
            )
        return int(total_changes)

    def compute_reachability_info(self, mba: ida_hexrays.mba_t) -> ReachabilityInfo:
        visited: set[int] = set()
        queue = [0]
        while queue:
            serial = queue.pop()
            if serial in visited or serial < 0 or serial >= mba.qty:
                continue
            visited.add(serial)
            blk = mba.get_mblock(serial)
            if blk is None:
                continue
            for i in range(blk.nsucc()):
                queue.append(int(blk.succ(i)))
        return ReachabilityInfo(
            entry_serial=0,
            reachable_blocks=frozenset(visited),
            total_blocks=int(mba.qty),
        )

    def post_execute_cleanup(
        self,
        mba: ida_hexrays.mba_t,
        *,
        snapshot: AnalysisSnapshot,
        total_changes: int,
    ) -> int:
        """Mirror the legacy generic post-apply cleanup tail.

        After successful redirect lowering, run deep cleaning and one local
        optimization round so Hex-Rays can collapse the rewritten dispatcher
        shape into cleaner pseudocode, matching the old generic path more
        closely.
        """
        if total_changes <= 0:
            return 0

        semantic_carrier_changes = 0
        carrier_facts = self._profile.collect_post_execute_carrier_facts(mba)
        if (
            int(getattr(mba, "maturity", -1) or -1) == int(ida_hexrays.MMAT_CALLS)
            and carrier_facts
        ):
            semantic_carrier_changes += _apply_carrier_output_alias_repair(
                mba,
                self._logger,
                carrier_facts,
            )
            semantic_carrier_changes += _apply_local_alias_mem2reg(
                mba,
                self._logger,
                carrier_facts,
            )
            semantic_carrier_changes += _apply_same_carrier_alias_repairs(
                mba,
                self._logger,
                carrier_facts,
            )
        if (
            int(getattr(mba, "maturity", -1) or -1) >= int(ida_hexrays.MMAT_GLBOPT1)
            and carrier_facts
        ):
            semantic_carrier_changes = _apply_semantic_carrier_promotions(
                mba,
                self._logger,
                carrier_facts,
            ) + semantic_carrier_changes

        lowered_modifications = ()
        if snapshot.flow_graph is not None:
            lowered_modifications = tuple(
                mod
                for mod in snapshot.flow_graph.metadata.get(
                    EMULATED_DISPATCHER_MODIFICATIONS_KEY, ()
                )
                if isinstance(mod, GraphModification)
            )
        if any(
            isinstance(mod, (InsertBlock, CreateConditionalRedirect))
            for mod in lowered_modifications
        ):
            self._logger.info(
                "Skipping post-execute deep cleaning for side-effect or conditional redirect rewrites"
            )
            mba.mark_chains_dirty()
            if semantic_carrier_changes > 0:
                mba.optimize_local(0)
                post_opt_carrier_changes = _apply_same_carrier_alias_repairs(
                    mba,
                    self._logger,
                    carrier_facts,
                )
                if post_opt_carrier_changes > 0:
                    semantic_carrier_changes += post_opt_carrier_changes
                    mba.optimize_local(0)
            safe_verify(
                mba,
                "verifying EmulatedDispatcherUnflattener.optimize after deferred edge-split apply",
                logger_func=self._logger.error,
            )
            return int(semantic_carrier_changes)

        nb_clean = mba_deep_cleaning(mba, False)
        if total_changes + nb_clean + semantic_carrier_changes > 0:
            mba.mark_chains_dirty()
            mba.optimize_local(0)
        safe_verify(
            mba,
            "optimizing EmulatedDispatcherUnflattener.optimize",
            logger_func=self._logger.error,
        )
        return int(nb_clean) + int(semantic_carrier_changes)
