"""Hodur projected-topology backend boundary.

LFG planning sometimes needs an MBA-shaped view of a projected ``FlowGraph``
and a live-style DAG rebuild over that view.  Keep those live/projection
mechanics behind this adapter so strategy code wires policy callbacks without
importing the Hex-Rays-shaped helpers directly.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.typing import Protocol
from d810.transforms.edit_simulator import project_post_state
from d810.transforms.plan import compile_patch_plan
from d810.analyses.control_flow.linearized_state_dag import (
    build_live_linearized_state_dag_from_graph,
)
from d810.analyses.control_flow.state_machine_analysis import build_mba_view_from_flow_graph


@dataclass(frozen=True, slots=True)
class ProjectedStateDag:
    """A projected FlowGraph plus the semantic DAG materialized from it."""

    flow_graph: object
    mba: object | None
    dag: object
    corrected_dag: object | None = None


class ProjectedTopologyBackend(Protocol):
    """Backend boundary for projected LFG topology reconstruction."""

    def build_projected_mba(self, flow_graph: object) -> object:
        """Adapt a projected flow graph into the backend's live-topology view."""

    def project_flow_graph(
        self,
        base_flow_graph: object,
        modifications: object,
    ) -> object:
        """Project graph modifications over ``base_flow_graph``."""

    def build_live_dag(
        self,
        current_flow_graph: object,
        transition_result: object,
        *,
        dispatcher_entry_serial: int,
        state_var_stkoff: int | None,
        pre_header_serial: int | None,
        initial_state: int | None,
        handler_range_map: dict | None,
        bst_node_blocks: tuple[int, ...],
        diagnostics: tuple[object, ...],
        dispatcher: object | None,
        mba: object | None,
        prefer_local_corridors: bool = True,
        corrected_dag_out: list[object] | None = None,
    ) -> object:
        """Build a live-style semantic DAG from backend-owned topology inputs."""

    def materialize_state_dag(
        self,
        flow_graph: object,
        transition_result: object,
        *,
        dispatcher_entry_serial: int,
        state_var_stkoff: int | None,
        pre_header_serial: int | None,
        initial_state: int | None,
        handler_range_map: dict | None,
        bst_node_blocks: tuple[int, ...],
        diagnostics: tuple[object, ...],
        dispatcher: object | None,
        mba: object | None = None,
        prefer_local_corridors: bool = True,
        collect_corrected_dag: bool = False,
    ) -> ProjectedStateDag:
        """Materialize a semantic DAG from an already-projected flow graph."""

    def project_state_dag(
        self,
        base_flow_graph: object,
        modifications: object,
        transition_result: object,
        *,
        dispatcher_entry_serial: int,
        state_var_stkoff: int | None,
        pre_header_serial: int | None,
        initial_state: int | None,
        handler_range_map: dict | None,
        bst_node_blocks: tuple[int, ...],
        diagnostics: tuple[object, ...],
        dispatcher: object | None,
        prefer_local_corridors: bool = True,
        collect_corrected_dag: bool = False,
    ) -> ProjectedStateDag:
        """Project modifications onto a flow graph and materialize its DAG."""


class HodurProjectedTopologyBackend:
    """Default backend for Hodur LFG projected-topology evidence."""

    def build_projected_mba(self, flow_graph: object) -> object:
        return build_mba_view_from_flow_graph(flow_graph)

    def project_flow_graph(
        self,
        base_flow_graph: object,
        modifications: object,
    ) -> object:
        return project_post_state(
            base_flow_graph,
            compile_patch_plan(modifications, base_flow_graph),
        )

    def build_live_dag(
        self,
        current_flow_graph: object,
        transition_result: object,
        *,
        dispatcher_entry_serial: int,
        state_var_stkoff: int | None,
        pre_header_serial: int | None,
        initial_state: int | None,
        handler_range_map: dict | None,
        bst_node_blocks: tuple[int, ...],
        diagnostics: tuple[object, ...],
        dispatcher: object | None,
        mba: object | None,
        prefer_local_corridors: bool = True,
        corrected_dag_out: list[object] | None = None,
    ) -> object:
        return build_live_linearized_state_dag_from_graph(
            current_flow_graph,
            transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=pre_header_serial,
            initial_state=initial_state,
            handler_range_map=handler_range_map or {},
            bst_node_blocks=tuple(sorted(int(block) for block in bst_node_blocks)),
            diagnostics=tuple(diagnostics or ()),
            dispatcher=dispatcher,
            mba=mba,
            prefer_local_corridors=prefer_local_corridors,
            corrected_dag_out=corrected_dag_out,
        )

    def materialize_state_dag(
        self,
        flow_graph: object,
        transition_result: object,
        *,
        dispatcher_entry_serial: int,
        state_var_stkoff: int | None,
        pre_header_serial: int | None,
        initial_state: int | None,
        handler_range_map: dict | None,
        bst_node_blocks: tuple[int, ...],
        diagnostics: tuple[object, ...],
        dispatcher: object | None,
        mba: object | None = None,
        prefer_local_corridors: bool = True,
        collect_corrected_dag: bool = False,
    ) -> ProjectedStateDag:
        dag_mba = mba if mba is not None else self.build_projected_mba(flow_graph)
        corrected_dag_out: list[object] | None = [] if collect_corrected_dag else None
        dag = self.build_live_dag(
            flow_graph,
            transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=pre_header_serial,
            initial_state=initial_state,
            handler_range_map=handler_range_map,
            bst_node_blocks=bst_node_blocks,
            diagnostics=diagnostics,
            dispatcher=dispatcher,
            mba=dag_mba,
            prefer_local_corridors=prefer_local_corridors,
            corrected_dag_out=corrected_dag_out,
        )
        corrected_dag = corrected_dag_out[0] if corrected_dag_out else None
        return ProjectedStateDag(
            flow_graph=flow_graph,
            mba=dag_mba,
            dag=dag,
            corrected_dag=corrected_dag,
        )

    def project_state_dag(
        self,
        base_flow_graph: object,
        modifications: object,
        transition_result: object,
        *,
        dispatcher_entry_serial: int,
        state_var_stkoff: int | None,
        pre_header_serial: int | None,
        initial_state: int | None,
        handler_range_map: dict | None,
        bst_node_blocks: tuple[int, ...],
        diagnostics: tuple[object, ...],
        dispatcher: object | None,
        prefer_local_corridors: bool = True,
        collect_corrected_dag: bool = False,
    ) -> ProjectedStateDag:
        projected_flow_graph = self.project_flow_graph(base_flow_graph, modifications)
        return self.materialize_state_dag(
            projected_flow_graph,
            transition_result,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=state_var_stkoff,
            pre_header_serial=pre_header_serial,
            initial_state=initial_state,
            handler_range_map=handler_range_map,
            bst_node_blocks=bst_node_blocks,
            diagnostics=diagnostics,
            dispatcher=dispatcher,
            prefer_local_corridors=prefer_local_corridors,
            collect_corrected_dag=collect_corrected_dag,
        )


DEFAULT_HODUR_PROJECTED_TOPOLOGY_BACKEND: ProjectedTopologyBackend = (
    HodurProjectedTopologyBackend()
)


__all__ = [
    "DEFAULT_HODUR_PROJECTED_TOPOLOGY_BACKEND",
    "HodurProjectedTopologyBackend",
    "ProjectedStateDag",
    "ProjectedTopologyBackend",
]
