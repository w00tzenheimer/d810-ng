"""Experimental DAG-driven reconstruction strategy.

This strategy intentionally does not try to be a smarter LFG. It starts from
instruction-level state-write horizons and only claims proven handoff sites:

- 1-way blocks
- block exits into the dispatcher/BST region
- last state write in the block resolves to a semantic state
- instructions after the state write are only goto/nop glue

That gives the pipeline a deterministic reconstruction foothold without
pretending we can already rebuild every shared suffix or merged conditional.
"""
from __future__ import annotations

import ida_hexrays

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur._helpers import blk_label
from d810.optimizers.microcode.flow.flattening.hodur._modification_bridge import (
    ModificationBuilder,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.linearized_state_dag import (
    LinearizedStateDag,
    RedirectSourceKind,
    StateNodeKind,
    build_live_linearized_state_dag_from_graph,
)
from d810.recon.flow.state_machine_analysis import (
    find_last_state_write_site_snapshot,
    run_snapshot_constant_fixpoint,
)
from d810.recon.flow.transition_builder import (
    TransitionResult,
    _get_state_var_stkoff,
)

logger = logging.getLogger(
    "D810.hodur.strategy.state_write_reconstruction",
    logging.DEBUG,
)

__all__ = ["StateWriteReconstructionStrategy"]


class StateWriteReconstructionStrategy:
    """Reconstruct state-write horizons into direct semantic gotos."""

    prerequisites: list[str] = []

    @property
    def name(self) -> str:
        return "state_write_reconstruction"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    @staticmethod
    def _resolve_state_var_stkoff(snapshot, state_machine) -> int | None:
        detector = getattr(snapshot, "detector", None)
        if detector is not None:
            stkoff = _get_state_var_stkoff(detector)
            if stkoff is not None:
                return int(stkoff)

        state_var = getattr(state_machine, "state_var", None)
        if state_var is None:
            return None
        if getattr(state_var, "t", None) == getattr(ida_hexrays, "mop_S", None):
            s = getattr(state_var, "s", None)
            off = getattr(s, "off", None) if s is not None else None
            if off is not None:
                return int(off)
        return None

    @staticmethod
    def _is_raw_state_label(label: str, state_value: int) -> bool:
        if label.endswith("_fallback"):
            return False
        try:
            return int(label, 16) == (state_value & 0xFFFFFFFF)
        except Exception:
            return False

    @classmethod
    def _resolve_semantic_entry_map(
        cls,
        dag: LinearizedStateDag,
    ) -> dict[int, int]:
        target_map: dict[int, tuple[tuple[int, int, int, int], int]] = {}
        bst_blocks = set(dag.bst_node_blocks)

        for node in dag.nodes:
            state_value = node.key.state_const
            if state_value is None or node.entry_anchor in bst_blocks:
                continue
            score = (
                1 if not cls._is_raw_state_label(node.state_label, state_value) else 0,
                1 if node.kind == StateNodeKind.EXACT else 0,
                1 if node.entry_anchor in node.exclusive_blocks else 0,
                -int(node.entry_anchor),
            )
            previous = target_map.get(state_value & 0xFFFFFFFF)
            if previous is None or score > previous[0]:
                target_map[state_value & 0xFFFFFFFF] = (score, int(node.entry_anchor))

        return {state: entry for state, (_score, entry) in target_map.items()}

    @staticmethod
    def _is_shared_suffix_conditional_tail(
        dag: LinearizedStateDag,
        *,
        source_block: int,
    ) -> bool:
        if not any(source_block in node.shared_suffix_blocks for node in dag.nodes):
            return False
        for edge in dag.edges:
            if edge.source_anchor.kind != RedirectSourceKind.CONDITIONAL_BRANCH:
                continue
            if source_block not in edge.ordered_path:
                continue
            if edge.ordered_path.index(source_block) > 0:
                return True
        return False

    @staticmethod
    def _is_trivial_handoff_glue(site) -> bool:
        if not site.trailing_opcodes:
            return True
        m_goto = getattr(ida_hexrays, "m_goto", None)
        m_nop = getattr(ida_hexrays, "m_nop", None)
        allowed = {
            opcode
            for opcode in (m_goto, m_nop)
            if opcode is not None
        }
        return all(opcode in allowed for opcode in site.trailing_opcodes)

    def is_applicable(self, snapshot) -> bool:
        sm = snapshot.state_machine
        flow_graph = snapshot.flow_graph
        bst_result = snapshot.bst_result
        if sm is None or flow_graph is None or bst_result is None:
            return False
        if not sm.handlers:
            return False
        return self._resolve_state_var_stkoff(snapshot, sm) is not None

    def plan(self, snapshot):
        if not self.is_applicable(snapshot):
            return None

        sm = snapshot.state_machine
        bst_result = snapshot.bst_result
        flow_graph = snapshot.flow_graph
        mba = snapshot.mba
        assert sm is not None
        assert bst_result is not None
        assert flow_graph is not None

        state_var_stkoff = self._resolve_state_var_stkoff(snapshot, sm)
        if state_var_stkoff is None:
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        transition_result = TransitionResult(
            transitions=list(sm.transitions),
            handlers=dict(sm.handlers),
            assignment_map=dict(sm.assignment_map),
            initial_state=sm.initial_state,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            strategy_name=self.name,
            resolved_count=len(sm.transitions),
        )
        dag = build_live_linearized_state_dag_from_graph(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=snapshot.bst_dispatcher_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=getattr(bst_result, "pre_header_serial", None),
            initial_state=sm.initial_state,
            handler_range_map=getattr(bst_result, "handler_range_map", {}) or {},
            bst_node_blocks=tuple(
                sorted(getattr(bst_result, "bst_node_blocks", set()) or set())
            ),
            diagnostics=tuple(getattr(bst_result, "diagnostics", ()) or ()),
            dispatcher=getattr(bst_result, "dispatcher", None),
            mba=mba,
            prefer_local_corridors=True,
        )
        semantic_entry_by_state = self._resolve_semantic_entry_map(dag)
        if not semantic_entry_by_state:
            return None

        constant_result = run_snapshot_constant_fixpoint(
            flow_graph,
            state_var_stkoff,
        )

        dispatcher_region = set(dag.bst_node_blocks)
        if dag.dispatcher_entry_serial >= 0:
            dispatcher_region.add(dag.dispatcher_entry_serial)

        modifications: list = []
        owned_blocks: set[int] = set()
        owned_edges: set[tuple[int, int]] = set()
        sites_metadata: list[dict[str, int]] = []
        candidate_blocks = 0
        no_site = 0
        non_trivial_glue = 0
        no_target = 0
        rejected_target = 0
        interesting_blocks = {10, 45, 69, 192}

        for block in flow_graph.blocks.values():
            if block.nsucc != 1:
                continue
            old_target = int(block.succs[0])
            if old_target not in dispatcher_region:
                continue
            candidate_blocks += 1
            initial_stk_map = constant_result.in_stk_maps.get(block.serial, {})
            initial_reg_map = constant_result.in_reg_maps.get(block.serial, {})
            if self._is_shared_suffix_conditional_tail(dag, source_block=block.serial):
                if block.serial in interesting_blocks:
                    logger.info(
                        "RECON DAG DEBUG: %s suppressed as shared-suffix conditional tail",
                        blk_label(mba, block.serial),
                    )
                continue
            if block.serial in interesting_blocks:
                logger.info(
                    "RECON DAG DEBUG: %s entry stk=%s reg=%s",
                    blk_label(mba, block.serial),
                    {hex(int(k)): hex(int(v) & 0xFFFFFFFF) for k, v in sorted(initial_stk_map.items())},
                    {int(k): hex(int(v) & 0xFFFFFFFF) for k, v in sorted(initial_reg_map.items())},
                )

            site = find_last_state_write_site_snapshot(
                flow_graph,
                block.serial,
                state_var_stkoff,
                initial_stk_map=initial_stk_map,
                initial_reg_map=initial_reg_map,
            )
            if site is None:
                no_site += 1
                if block.serial in interesting_blocks:
                    logger.info(
                        "RECON DAG DEBUG: %s no resolvable state-write horizon",
                        blk_label(mba, block.serial),
                    )
                continue
            if not self._is_trivial_handoff_glue(site):
                non_trivial_glue += 1
                if block.serial in interesting_blocks:
                    logger.info(
                        "RECON DAG DEBUG: %s state=0x%08X rejected for non-trivial glue (%s)",
                        blk_label(mba, block.serial),
                        site.state_value & 0xFFFFFFFF,
                        tuple(int(op) for op in site.trailing_opcodes),
                    )
                continue

            target_entry = semantic_entry_by_state.get(site.state_value & 0xFFFFFFFF)
            if target_entry is None:
                no_target += 1
                if block.serial in interesting_blocks:
                    logger.info(
                        "RECON DAG DEBUG: %s state=0x%08X missing semantic entry",
                        blk_label(mba, block.serial),
                        site.state_value & 0xFFFFFFFF,
                    )
                continue
            if (
                target_entry == block.serial
                or target_entry in dispatcher_region
                or target_entry == old_target
            ):
                rejected_target += 1
                if block.serial in interesting_blocks:
                    logger.info(
                        "RECON DAG DEBUG: %s state=0x%08X rejected target=%s old_target=%s dispatcher=%s",
                        blk_label(mba, block.serial),
                        site.state_value & 0xFFFFFFFF,
                        blk_label(mba, target_entry),
                        blk_label(mba, old_target),
                        target_entry in dispatcher_region,
                    )
                continue

            horizon_eas = (int(site.insn_ea),) + tuple(
                int(ea) for ea in site.trailing_insn_eas
            )
            modifications.append(
                builder.nop_instruction(block.serial, horizon_eas[0])
            )
            if len(horizon_eas) > 1:
                from d810.cfg.graph_modification import NopInstructions

                modifications[-1] = NopInstructions(
                    block_serial=block.serial,
                    insn_eas=tuple(horizon_eas),
                )
            modifications.append(
                builder.goto_redirect(
                    source_block=block.serial,
                    target_block=target_entry,
                    old_target=old_target,
                )
            )
            owned_blocks.add(block.serial)
            owned_edges.add((block.serial, target_entry))
            sites_metadata.append(
                {
                    "block_serial": int(block.serial),
                    "state_value": int(site.state_value & 0xFFFFFFFF),
                    "target_entry": int(target_entry),
                    "state_write_ea": int(site.insn_ea),
                    "truncated_count": len(horizon_eas),
                }
            )
            logger.info(
                "RECON DAG: horizon %s state=0x%08X -> %s (nopped=%d)",
                blk_label(mba, block.serial),
                site.state_value & 0xFFFFFFFF,
                blk_label(mba, target_entry),
                len(horizon_eas),
            )

        if not modifications:
            logger.info(
                "RECON DAG: no proven horizons across %d dispatcher handoff blocks "
                "(no_site=%d, non_trivial_glue=%d, no_target=%d, rejected_target=%d)",
                candidate_blocks,
                no_site,
                non_trivial_glue,
                no_target,
                rejected_target,
            )
            return None

        logger.info(
            "RECON DAG: claimed %d proven horizons across %d dispatcher handoff blocks "
            "(no_site=%d, non_trivial_glue=%d, no_target=%d, rejected_target=%d)",
            len(sites_metadata),
            candidate_blocks,
            no_site,
            non_trivial_glue,
            no_target,
            rejected_target,
        )

        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=OwnershipScope(
                blocks=frozenset(owned_blocks),
                edges=frozenset(owned_edges),
                transitions=frozenset(),
            ),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=len(owned_blocks),
                transitions_resolved=len(owned_edges),
                blocks_freed=len(owned_blocks),
                conflict_density=0.0,
            ),
            risk_score=0.15,
            metadata={
                "mode": "experimental_reconstruction",
                "reconstruction_sites": tuple(sites_metadata),
                "safeguard_min_required": 1,
            },
            modifications=modifications,
        )
