"""Bounded re-run gate for StateMachineCffUnflattener (ticket llr-3gn4).

A single spine-redirect pass can leave the dispatcher's comparison ENTRY block
reachable; the equality-chain / switch profile re-runs (bounded) so a later round
recovers + redirects that residual dispatcher and IDA's optimize_global converges
to the clean dispatcher-free graph (approov_real_pattern needs the 2nd round). The
TABLE/indirect_jump_table profile keeps the historical one-shot contract.

These exercise the pure gate (``_should_run_unflatten_round`` / ``_mark_ea_converged``)
— no live ``mba`` — but the rule's module imports ``ida_hexrays`` at top level, so the
test lives under ``tests/system`` where the conftest boots IDA headlessly (Test
Placement Rule: never mock IDA in unit tests).
"""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays
import pytest
import d810.optimizers.microcode.flow.flattening.state_machine_cff_unflattener as unflattener

from d810.optimizers.microcode.flow.flattening.state_machine_cff_unflattener import (
    StateMachineCffUnflattener,
    _bind_materialized_dispatcher_identity,
    _bind_materialized_handler_targets,
    _materialized_identity_evidence_ready,
    _portable_materialized_state_route_evidence,
    _rebind_portable_materialized_state_routes,
    _resolver_native_state_register,
    _should_defer_incomplete_materialized_identity,
    _should_defer_unbound_materialized_preopt,
    _unflatten_recovery_epoch_generation,
    _unique_materialized_handler_entry_route_source_eas,
    _unique_materialized_handler_region_identities,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.maturity import IRMaturity
from d810.analyses.control_flow.native_preanalysis_session import (
    NativePreanalysisSessionState,
)
from d810.optimizers.microcode.flow.jumps.resolver_session_state import (
    ResolverSessionState,
)
from d810.passes.unflatten.state_machine import LOWER_STATE_MACHINE_PLAN_METADATA
from d810.transforms.minimal_unflatten_emit import (
    TERMINAL_CARRIER_CONVERGENCE_METADATA,
)


_EA = 0x1800017F0
#: Two distinct recovery maturities -- the gate now budgets re-runs per-(ea,maturity)
#: (ticket llr-a93i), so a cap at one maturity must leave the other's budget intact.
_MAT = ida_hexrays.MMAT_GLBOPT1
_MAT2 = ida_hexrays.MMAT_CALLS


@pytest.mark.parametrize(
    ("seeds", "expected"),
    (
        (
            {
                "materialized_state_var_reg": 28,
                "materialized_dispatcher_entry_serial": 37,
                "materialized_handler_by_state": {0x699BC698: 40},
                "portable_materialized_handler_identity_misses": (),
                "unmapped_materialized_handler_targets": (),
            },
            True,
        ),
        (
            {
                "materialized_state_var_reg": None,
                "materialized_dispatcher_entry_serial": 37,
                "materialized_handler_by_state": {0x699BC698: 40},
                "portable_materialized_handler_identity_misses": (),
                "unmapped_materialized_handler_targets": (),
            },
            False,
        ),
        (
            {
                "materialized_state_var_reg": 28,
                "materialized_dispatcher_entry_serial": None,
                "materialized_handler_by_state": {0x699BC698: 40},
                "portable_materialized_handler_identity_misses": (),
                "unmapped_materialized_handler_targets": (),
            },
            False,
        ),
        (
            {
                "materialized_state_var_reg": 28,
                "materialized_dispatcher_entry_serial": 37,
                "materialized_handler_by_state": {},
                "portable_materialized_handler_identity_misses": (),
                "unmapped_materialized_handler_targets": (),
            },
            False,
        ),
        (
            {
                "materialized_state_var_reg": 28,
                "materialized_dispatcher_entry_serial": 37,
                "materialized_handler_by_state": {0x699BC698: 40},
                "portable_materialized_handler_identity_misses": (),
                "unmapped_materialized_handler_targets": (
                    (0x12345678, 0x40E242),
                ),
            },
            False,
        ),
        (
            {
                "materialized_state_var_reg": 28,
                "materialized_dispatcher_entry_serial": 37,
                "materialized_handler_by_state": {0x699BC698: 40},
                # The first native-EA binding pass may miss a target that the
                # later exact imported-root or terminal-route reconciliation
                # resolves.  Only the final inventory is mutation-time truth.
                "portable_materialized_handler_identity_misses": (
                    (0x12345678, 0x40E242),
                ),
                "unmapped_materialized_handler_targets": (),
            },
            True,
        ),
    ),
)
def test_materialized_identity_evidence_requires_a_complete_portable_binding(
    seeds,
    expected,
) -> None:
    assert _materialized_identity_evidence_ready(seeds) is expected


def test_incomplete_materialized_identity_defers_only_non_tigress_profiles() -> None:
    assert _should_defer_incomplete_materialized_identity(
        materialized_computed_goto_profile=True,
        materialized_evidence_ready=False,
        uses_tigress_indirect_materialization=False,
    )
    assert not _should_defer_incomplete_materialized_identity(
        materialized_computed_goto_profile=True,
        materialized_evidence_ready=True,
        uses_tigress_indirect_materialization=False,
    )
    assert not _should_defer_incomplete_materialized_identity(
        materialized_computed_goto_profile=False,
        materialized_evidence_ready=False,
        uses_tigress_indirect_materialization=False,
    )
    assert not _should_defer_incomplete_materialized_identity(
        materialized_computed_goto_profile=True,
        materialized_evidence_ready=False,
        uses_tigress_indirect_materialization=True,
    )


def test_materialized_mutation_waits_for_current_preopt_evidence_generation() -> None:
    native = NativePreanalysisSessionState(evidence_generation=1)
    state = ResolverSessionState(native_preanalysis=native, materialized=True)

    assert _should_defer_unbound_materialized_preopt(state)

    native.bound_preopt_generation = 1
    assert not _should_defer_unbound_materialized_preopt(state)

    native.bound_preopt_generation = None
    state.materialized = False
    assert not _should_defer_unbound_materialized_preopt(state)


def test_materialized_state_route_round_trips_through_portable_identity() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        MaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex

    state = 0x699BC698
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAC0, 0x40EAD0),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAB7),)
    )
    native_index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        bindings=((source_identity, 3), (target_identity, 7)),
    )
    evidence = _portable_materialized_state_route_evidence(
        (
            MaterializedStateRoute(
                source_block_serial=3,
                state_constant=state,
                target_handler_serial=7,
                handler_exit_proven=True,
                proof_kind="state_route",
            ),
        ),
        native_index,
    )

    assert len(evidence) == 1
    assert evidence[0].source_identity == source_identity
    assert evidence[0].target_identity == target_identity

    regenerated_index = MbaBlockIdentityIndex.from_bindings(
        generation=2,
        bindings=((source_identity, 41), (target_identity, 58)),
    )
    blocks = {
        41: SimpleNamespace(serial=41),
        58: SimpleNamespace(serial=58),
    }
    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        regenerated_index,
        handler_by_state={state: 58},
        flow_graph=SimpleNamespace(get_block=blocks.get),
    )

    assert len(rebound) == 1
    assert rebound[0].source_block_serial == 41
    assert rebound[0].target_handler_serial == 58
    assert rebound[0].state_constant == state
    assert rebound[0].handler_exit_proven


def test_portable_state_route_same_mba_round_trip_preserves_route_identity() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        MaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex

    state = 0x699BC698
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAC0, 0x40EAD0),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAB7),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        bindings=((source_identity, 3), (target_identity, 7)),
    )
    route = MaterializedStateRoute(
        source_block_serial=3,
        state_constant=state,
        target_handler_serial=7,
        handler_exit_proven=True,
    )
    evidence = _portable_materialized_state_route_evidence((route,), index)

    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        index,
        handler_by_state={state: 7},
        flow_graph=SimpleNamespace(
            get_block=lambda serial: SimpleNamespace(serial=serial)
        ),
    )

    assert rebound == (route,)


def test_portable_terminal_route_round_trip_preserves_native_source_anchor() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        MaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex

    state = 0x81F82C5E
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D350, 0x40D351),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40F821, 0x40F822),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        bindings=((source_identity, 369), (target_identity, 395)),
    )
    route = MaterializedStateRoute(
        source_block_serial=369,
        state_constant=state,
        target_handler_serial=395,
        proof_kind="terminal_state_route",
        source_native_ea=0x40D350,
        target_native_ea=0x40F821,
    )
    evidence = _portable_materialized_state_route_evidence((route,), index)

    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        index,
        # The equality-chain handler map names the terminal selector leaf, not
        # the exact native return endpoint carried by the portable route.
        handler_by_state={state: 369},
        flow_graph=SimpleNamespace(
            get_block=lambda serial: (
                SimpleNamespace(serial=serial)
                if serial in {369, 395}
                else None
            )
        ),
    )

    assert rebound == (route,)


def test_portable_state_route_rebind_uses_current_authoritative_handler_map() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        MaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex

    state = 0x699BC698
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAC0, 0x40EAD0),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAB7),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        bindings=((source_identity, 3), (target_identity, 7)),
    )
    evidence = _portable_materialized_state_route_evidence(
        (
            MaterializedStateRoute(
                source_block_serial=3,
                state_constant=state,
                target_handler_serial=7,
            ),
        ),
        index,
    )

    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        index,
        handler_by_state={state: 8},
        flow_graph=SimpleNamespace(
            get_block=lambda serial: SimpleNamespace(serial=serial)
        ),
    )

    assert len(rebound) == 1
    assert rebound[0].source_block_serial == 3
    assert rebound[0].target_handler_serial == 8


def test_portable_state_route_rebinds_missing_exit_through_handler_region() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        PortableMaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph

    state = 0x699BC698
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E27F, 0x40E280),)
    )
    source_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E242, 0x40E280),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAA7, 0x40EAB7),)
    )
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (41, 42, 43, 58)
    }
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=2,
        flow_graph=FlowGraph(
            blocks=blocks,
            entry_serial=41,
            func_ea=_EA,
        ),
        imported_native_eas_by_serial={
            41: (0x40E245,),
            42: (0x40E260,),
            43: (0x40E27A,),
            58: (0x40EAA7,),
        },
    )
    evidence = (
        PortableMaterializedStateRoute(
            source_identity=source_identity,
            source_handler_region_identity=source_region,
            state_constant=state,
            target_identity=target_identity,
            handler_exit_proven=True,
        ),
    )

    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        index,
        handler_by_state={state: 58},
        flow_graph=FlowGraph(
            blocks=blocks,
            entry_serial=41,
            func_ea=_EA,
        ),
        imported_direct_boundary_evidence=(
            SimpleNamespace(
                port=SimpleNamespace(
                    state_constant=state,
                    source_block_ea=0x40E242,
                    source_instruction_ea=0x40E27F,
                    endpoint_block_ea=0x40E260,
                ),
                endpoint_anchor_eas=(0x40E260,),
            ),
        ),
    )

    assert len(rebound) == 1
    assert rebound[0].source_block_serial == 42
    assert rebound[0].source_handler_serial == 41
    assert rebound[0].target_handler_serial == 58


def test_portable_handler_exit_prefers_region_boundaries_over_stale_splits() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        PortableMaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph

    state = 0x6EA4D36E
    source_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D524, 0x40D5F9),)
    )
    stale_source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D560, 0x40D561),)
    )
    stale_handler_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D550, 0x40D551),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40F4D4, 0x40F4D5),)
    )
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (41, 42, 43, 44, 58)
    }
    graph = FlowGraph(blocks=blocks, entry_serial=41, func_ea=_EA)
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=2,
        flow_graph=graph,
        imported_native_eas_by_serial={
            41: (0x40D524,),
            42: (0x40D560,),
            43: (0x40D5F7,),
            44: (0x40D550,),
            58: (0x40F4D4,),
        },
    )
    evidence = (
        PortableMaterializedStateRoute(
            source_identity=stale_source_identity,
            source_handler_identity=stale_handler_identity,
            source_handler_region_identity=source_region,
            state_constant=state,
            target_identity=target_identity,
            handler_exit_proven=True,
        ),
    )

    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        index,
        handler_by_state={state: 58},
        flow_graph=graph,
    )

    assert len(rebound) == 1
    assert rebound[0].source_block_serial == 43
    assert rebound[0].source_handler_serial == 41
    assert rebound[0].target_handler_serial == 58
    assert rebound[0].source_native_ea == 0x40D560


def test_portable_state_route_infers_unique_enclosing_handler_region() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        MaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex

    state = 0x4A67CB8A
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D72C, 0x40D72D),)
    )
    source_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D700, 0x40D74E),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E700, 0x40E701),)
    )
    native_index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        bindings=((source_identity, 17), (target_identity, 33)),
    )

    evidence = _portable_materialized_state_route_evidence(
        (
            MaterializedStateRoute(
                source_block_serial=17,
                state_constant=state,
                target_handler_serial=33,
            ),
        ),
        native_index,
        source_handler_regions_by_serial={12: source_region},
    )

    assert len(evidence) == 1
    assert evidence[0].source_handler_identity is None
    assert evidence[0].source_handler_region_identity == source_region


def test_portable_state_route_does_not_guess_between_enclosing_regions() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        MaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex

    state = 0x4A67CB8A
    source_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D72C, 0x40D72D),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E700, 0x40E701),)
    )
    native_index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        bindings=((source_identity, 17), (target_identity, 33)),
    )

    evidence = _portable_materialized_state_route_evidence(
        (
            MaterializedStateRoute(
                source_block_serial=17,
                state_constant=state,
                target_handler_serial=33,
            ),
        ),
        native_index,
        source_handler_regions_by_serial={
            12: StableBlockIdentity.from_intervals(
                (NativeEaInterval(0x40D700, 0x40D74E),)
            ),
            13: StableBlockIdentity.from_intervals(
                (NativeEaInterval(0x40D720, 0x40D760),)
            ),
        },
    )

    assert len(evidence) == 1
    assert evidence[0].source_handler_region_identity is None


def test_portable_state_route_uses_unique_region_exit_when_receipts_are_ambiguous() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        PortableMaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph

    state = 0x4A67CB8A
    missing_source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D72C, 0x40D72D),)
    )
    source_region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D700, 0x40D74E),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E700, 0x40E701),)
    )
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (41, 42, 58)
    }
    graph = FlowGraph(blocks=blocks, entry_serial=41, func_ea=_EA)
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=2,
        flow_graph=graph,
        imported_native_eas_by_serial={
            41: (0x40D701,),
            42: (0x40D740,),
            58: (0x40E700,),
        },
    )
    evidence = (
        PortableMaterializedStateRoute(
            source_identity=missing_source,
            source_handler_region_identity=source_region,
            state_constant=state,
            target_identity=target_identity,
        ),
    )
    receipts = tuple(
        SimpleNamespace(
            port=SimpleNamespace(
                state_constant=state,
                source_block_ea=source_ea,
                source_instruction_ea=source_ea,
                endpoint_block_ea=source_ea,
            ),
            endpoint_anchor_eas=(endpoint_ea,),
        )
        for source_ea, endpoint_ea in (
            (0x40D710, 0x40D701),
            (0x40D730, 0x40D740),
        )
    )

    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        index,
        handler_by_state={state: 58},
        flow_graph=graph,
        imported_direct_boundary_evidence=receipts,
    )

    assert len(rebound) == 1
    assert rebound[0].source_block_serial == 42
    assert rebound[0].target_handler_serial == 58


def test_handlerless_portable_route_rebinds_through_unique_state_target_receipt() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        PortableMaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph

    state = 0x244AC7CD
    missing_source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D482, 0x40D483),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D48E, 0x40D48F),)
    )
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (41, 58)
    }
    graph = FlowGraph(blocks=blocks, entry_serial=41, func_ea=_EA)
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=2,
        flow_graph=graph,
        imported_native_eas_by_serial={
            41: (0x40D4A2,),
            58: (0x40D48E,),
        },
    )
    evidence = (
        PortableMaterializedStateRoute(
            source_identity=missing_source,
            state_constant=state,
            target_identity=target_identity,
        ),
    )
    receipt = SimpleNamespace(
        port=SimpleNamespace(
            state_constant=state,
            source_block_ea=0x40D48E,
            source_instruction_ea=0x40D4A2,
            endpoint_block_ea=0x40D48E,
            target_ea=0x40D48E,
        ),
        endpoint_anchor_eas=(0x40D4A2,),
    )

    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        index,
        handler_by_state={state: 58},
        flow_graph=graph,
        imported_direct_boundary_evidence=(receipt,),
    )

    assert len(rebound) == 1
    assert rebound[0].source_block_serial == 41
    assert rebound[0].target_handler_serial == 58


def test_handlerless_portable_route_receipt_join_requires_exact_native_target() -> None:
    from d810.analyses.control_flow.materialized_indirect_transfer import (
        PortableMaterializedStateRoute,
    )
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph

    state = 0x244AC7CD
    missing_source = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D482, 0x40D483),)
    )
    target_identity = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40D48E, 0x40D48F),)
    )
    blocks = {
        serial: BlockSnapshot(
            serial=serial,
            block_type=0,
            succs=(),
            preds=(),
            flags=0,
            start_ea=0xFFFFFFFFFFFFFFFF,
            insn_snapshots=(),
        )
        for serial in (41, 42, 58)
    }
    graph = FlowGraph(blocks=blocks, entry_serial=41, func_ea=_EA)
    index = MbaBlockIdentityIndex.from_flow_graph(
        generation=2,
        flow_graph=graph,
        imported_native_eas_by_serial={
            41: (0x40D4A2,),
            42: (0x40F000,),
            58: (0x40D48E,),
        },
    )
    evidence = (
        PortableMaterializedStateRoute(
            source_identity=missing_source,
            state_constant=state,
            target_identity=target_identity,
        ),
    )
    receipts = (
        SimpleNamespace(
            port=SimpleNamespace(
                state_constant=state,
                source_block_ea=0x40D48E,
                source_instruction_ea=0x40D4A2,
                endpoint_block_ea=0x40D48E,
                target_ea=0x40D48E,
            ),
            endpoint_anchor_eas=(0x40D4A2,),
        ),
        SimpleNamespace(
            port=SimpleNamespace(
                state_constant=state,
                source_block_ea=0x40F000,
                source_instruction_ea=0x40F000,
                endpoint_block_ea=0x40F000,
                target_ea=0x40F100,
            ),
            endpoint_anchor_eas=(0x40F000,),
        ),
    )

    rebound = _rebind_portable_materialized_state_routes(
        evidence,
        index,
        handler_by_state={state: 58},
        flow_graph=graph,
        imported_direct_boundary_evidence=receipts,
    )

    assert len(rebound) == 1
    assert rebound[0].source_block_serial == 41


def test_portable_dispatcher_region_rebinds_every_split_imported_descendant() -> None:
    from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex

    first_router = StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x40EAA7, 0x40EAA8),
            NativeEaInterval(0x40EAB1, 0x40EAB2),
        )
    )
    second_router = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40EAB7, 0x40EAB8),)
    )
    index = MbaBlockIdentityIndex.from_bindings(
        generation=1,
        bindings=((first_router, 20), (second_router, 21)),
    )

    portable_region = unflattener._portable_materialized_dispatcher_region_identity(
        frozenset({20, 21}),
        index,
    )
    rebound = unflattener._rebind_portable_materialized_dispatcher_region(
        portable_region,
        imported_native_eas_by_serial={
            70: frozenset({0x40EAA7}),
            71: frozenset({0x40EAB1}),
            72: frozenset({0x40EAB7}),
            73: frozenset({0x40EAA7}),
            90: frozenset({0x40F000}),
        },
        excluded_serials=frozenset({73}),
    )

    assert portable_region == StableBlockIdentity.from_intervals(
        (
            NativeEaInterval(0x40EAA7, 0x40EAA8),
            NativeEaInterval(0x40EAB1, 0x40EAB2),
            NativeEaInterval(0x40EAB7, 0x40EAB8),
        )
    )
    assert rebound == frozenset({70, 71, 72})


def test_stack_homed_state_can_join_one_portable_native_selector() -> None:
    prelim = SimpleNamespace(state_var_stkoff=0x9C, state_var_reg=None)
    transfers = (
        SimpleNamespace(selector_state_var_reg=28),
        SimpleNamespace(selector_state_var_reg=28),
        SimpleNamespace(selector_state_var_reg=None),
    )

    assert _resolver_native_state_register(
        prelim,
        transfers,
        materialized_computed_goto_profile=True,
    ) == 28
    assert prelim.state_var_reg is None


def test_native_selector_join_abstains_outside_profile_or_on_conflict() -> None:
    prelim = SimpleNamespace(state_var_stkoff=0x9C, state_var_reg=None)

    assert _resolver_native_state_register(
        prelim,
        (SimpleNamespace(selector_state_var_reg=28),),
        materialized_computed_goto_profile=False,
    ) is None
    assert _resolver_native_state_register(
        prelim,
        (
            SimpleNamespace(selector_state_var_reg=28),
            SimpleNamespace(selector_state_var_reg=36),
        ),
        materialized_computed_goto_profile=True,
    ) is None


def test_exact_materialized_selector_survives_without_legacy_recovery() -> None:
    transfers = (
        SimpleNamespace(
            resolver_kind="residual_state_route",
            selector_state_var_reg=28,
            selector_state_constant=0x699BC698,
        ),
        SimpleNamespace(
            resolver_kind="static_handler_entry_route",
            selector_state_var_reg=28,
            selector_state_constant=0x12345678,
        ),
    )

    assert _resolver_native_state_register(
        None,
        transfers,
        materialized_computed_goto_profile=True,
    ) == 28
    assert _resolver_native_state_register(
        SimpleNamespace(
            dispatcher_block_serial=None,
            dispatch_map=None,
            state_var_reg=None,
            state_var_stkoff=None,
        ),
        transfers,
        materialized_computed_goto_profile=True,
    ) == 28
    assert _resolver_native_state_register(
        None,
        transfers,
        materialized_computed_goto_profile=False,
    ) is None


def test_materialized_handler_targets_rebind_to_current_mba_blocks() -> None:
    blocks = {
        40: SimpleNamespace(insn_snapshots=(object(),)),
        41: SimpleNamespace(insn_snapshots=(object(),)),
    }
    flow_graph = SimpleNamespace(get_block=blocks.get)
    live_by_ea = {
        0x40EAA7: SimpleNamespace(serial=40),
        0x40F12D: SimpleNamespace(serial=41),
        0x40DC04: SimpleNamespace(serial=41),
    }

    targets, entries, missing = _bind_materialized_handler_targets(
        flow_graph,
        {
            0x699BC698: 0x40EAA7,
            0x11111111: 0x40F12D,
            0x22222222: 0x40DC04,
            0x33333333: 0x40DEAD,
        },
        live_block_for_ea=live_by_ea.get,
    )

    assert targets == {
        0x699BC698: 40,
        0x11111111: 41,
        0x22222222: 41,
    }
    assert entries == {40: 0x40EAA7}
    assert missing == ((0x33333333, 0x40DEAD),)


def test_materialized_handler_target_rebinds_through_exact_entry_route_source() -> None:
    blocks = {44: SimpleNamespace(insn_snapshots=(object(),))}
    flow_graph = SimpleNamespace(get_block=blocks.get)
    live_by_ea = {0x40E228: SimpleNamespace(serial=44)}

    targets, entries, missing = _bind_materialized_handler_targets(
        flow_graph,
        {0x08DF7433: 0x40E242},
        live_block_for_ea=live_by_ea.get,
        entry_route_source_eas={0x08DF7433: 0x40E228},
    )

    assert targets == {0x08DF7433: 44}
    assert entries == {44: 0x40E242}
    assert missing == ()


def test_materialized_handler_entry_route_rejects_shared_bootstrap_source() -> None:
    state_a = 0x08DF7433
    state_b = 0x3AF41FBE
    transfers = (
        SimpleNamespace(
            resolver_kind="static_handler_entry_route",
            selector_state_constant=state_a,
            source_block_ea=0x40D348,
            target_eas=(0x40E242,),
        ),
        SimpleNamespace(
            resolver_kind="static_handler_entry_route",
            selector_state_constant=state_b,
            source_block_ea=0x40D348,
            target_eas=(0x40F12D,),
        ),
        SimpleNamespace(
            resolver_kind="static_handler_entry_route",
            selector_state_constant=state_a,
            source_block_ea=0x40E228,
            target_eas=(0x40E242,),
        ),
        SimpleNamespace(
            resolver_kind="static_handler_entry_route",
            selector_state_constant=state_b,
            source_block_ea=0x40F113,
            target_eas=(0x40F12D,),
        ),
    )

    assert _unique_materialized_handler_entry_route_source_eas(
        transfers,
        {state_a: 0x40E242, state_b: 0x40F12D},
    ) == {
        state_a: 0x40E228,
        state_b: 0x40F113,
    }


def test_materialized_handler_region_identity_survives_missing_entry_ea() -> None:
    state = 0x08DF7433
    transfers = (
        SimpleNamespace(
            resolver_kind="static_handler_entry_route",
            selector_state_constant=state,
            target_eas=(0x40E242,),
            owned_native_ranges=((0x40E242, 0x40E280), (0x40E290, 0x40E2A0)),
        ),
    )

    assert _unique_materialized_handler_region_identities(
        transfers,
        {state: 0x40E242},
    ) == {
        state: StableBlockIdentity.from_intervals(
            (
                NativeEaInterval(0x40E242, 0x40E280),
                NativeEaInterval(0x40E290, 0x40E2A0),
            )
        )
    }


def test_materialized_handler_region_identity_rejects_conflicting_ranges() -> None:
    state = 0x08DF7433
    transfers = (
        SimpleNamespace(
            resolver_kind="static_handler_entry_route",
            selector_state_constant=state,
            target_eas=(0x40E242,),
            owned_native_ranges=((0x40E242, 0x40E280),),
        ),
        SimpleNamespace(
            resolver_kind="static_handler_entry_route",
            selector_state_constant=state,
            target_eas=(0x40E242,),
            owned_native_ranges=((0x40E242, 0x40E290),),
        ),
    )

    assert _unique_materialized_handler_region_identities(
        transfers,
        {state: 0x40E242},
    ) == {}


def test_materialized_handler_target_rebinds_through_owned_native_region() -> None:
    state = 0x08DF7433
    region = StableBlockIdentity.from_intervals(
        (NativeEaInterval(0x40E242, 0x40E280),)
    )
    blocks = {44: SimpleNamespace(insn_snapshots=(object(),))}
    flow_graph = SimpleNamespace(get_block=blocks.get)

    targets, entries, missing = _bind_materialized_handler_targets(
        flow_graph,
        {state: 0x40E242},
        live_block_for_ea=lambda _ea: None,
        entry_route_region_identities={state: region},
        live_block_for_region_identity=lambda identity: (
            SimpleNamespace(serial=44) if identity == region else None
        ),
    )

    assert targets == {state: 44}
    assert entries == {44: 0x40E242}
    assert missing == ()


def test_complete_materialized_identity_evidence_reopens_the_family_gate(
    monkeypatch,
) -> None:
    from d810.optimizers.microcode.flow.flattening import (
        state_machine_cff_unflattener as unflat_mod,
    )

    monkeypatch.setattr(unflat_mod, "select_family", lambda *_args, **_kwargs: None)
    rule = StateMachineCffUnflattener.__new__(StateMachineCffUnflattener)
    backend = SimpleNamespace(capabilities=lambda: frozenset())
    mba = SimpleNamespace(entry_ea=_EA, maturity=ida_hexrays.MMAT_CALLS)
    source = SimpleNamespace(flow_graph=object())

    family = rule._select_family(
        mba,
        source,
        {},
        backend,
        materialized_evidence_ready=True,
    )

    assert family is not None
    assert family.name == "materialized_computed_goto_continuation"
    assert family.pipeline_for(family, {}) == tuple(
        unflat_mod.standard_state_machine_passes()
    )
    assert (
        rule._select_family(
            mba,
            source,
            {},
            backend,
            materialized_evidence_ready=False,
        )
        is None
    )
    assert (
        rule._select_family(
            mba,
            source,
            {"profile": "tigress_indirect"},
            backend,
            materialized_evidence_ready=True,
        )
        is None
    )


def test_materialized_dispatcher_identity_rebinds_without_serial_persistence() -> None:
    transfers = (
        SimpleNamespace(
            dispatcher_entry_ea=0x40D370,
            dispatcher_router_eas=(0x40D370, 0x40D381),
        ),
        SimpleNamespace(
            dispatcher_entry_ea=0x40D370,
            dispatcher_router_eas=(0x40D381, 0x40D391),
        ),
    )
    origins = {
        31: frozenset({0x40D370}),
        32: frozenset({0x40D381}),
        33: frozenset({0x40D391}),
        40: frozenset({0x40EAA7}),
    }

    assert _bind_materialized_dispatcher_identity(
        origins,
        transfers,
        handler_serials=frozenset({40}),
    ) == (31, frozenset({31, 32, 33}))
    assert _bind_materialized_dispatcher_identity(
        {**origins, 34: frozenset({0x40D370})},
        transfers,
        handler_serials=frozenset({40}),
    ) == (None, frozenset({31, 32, 33, 34}))


def _fresh_rule() -> StateMachineCffUnflattener:
    rule = StateMachineCffUnflattener.__new__(StateMachineCffUnflattener)
    # Initialise only the re-run bookkeeping (skip the heavy ComposedUnflatteningRule
    # __init__ / IDA lifecycle — the gate is pure and reads nothing else).
    rule._unflat_round_count = {}
    rule._unflat_done_eas = set()
    return rule


def test_regenerated_mba_resets_only_its_function_round_budget() -> None:
    class RecordingPassManager:
        def __init__(self) -> None:
            self.reset_eas: list[int] = []

        def reset_func(self, func_ea: int) -> None:
            self.reset_eas.append(int(func_ea))

    rule = _fresh_rule()
    other_ea = _EA + 0x1000
    rule._pass_manager = RecordingPassManager()
    rule._pass_manager_session_by_func = {}
    rule._unflat_round_count = {
        (_EA, _MAT): 1,
        (other_ea, _MAT): 2,
    }
    rule._unflat_done_eas = {_EA, other_ea}

    first_wrapper = SimpleNamespace(entry_ea=_EA, this=0x1111)
    same_mba_wrapper = SimpleNamespace(entry_ea=_EA, this=0x1111)
    regenerated_mba = SimpleNamespace(entry_ea=_EA, this=0x2222)

    rule._reset_pass_manager_if_new_session(first_wrapper)
    assert rule._pass_manager.reset_eas == [_EA]
    assert (_EA, _MAT) not in rule._unflat_round_count
    assert _EA not in rule._unflat_done_eas
    assert rule._unflat_round_count[(other_ea, _MAT)] == 2
    assert other_ea in rule._unflat_done_eas

    rule._unflat_round_count[(_EA, _MAT)] = 1
    rule._unflat_done_eas.add(_EA)
    rule._reset_pass_manager_if_new_session(same_mba_wrapper)
    assert rule._pass_manager.reset_eas == [_EA]
    assert rule._unflat_round_count[(_EA, _MAT)] == 1
    assert _EA in rule._unflat_done_eas

    rule._reset_pass_manager_if_new_session(regenerated_mba)
    assert rule._pass_manager.reset_eas == [_EA, _EA]
    assert (_EA, _MAT) not in rule._unflat_round_count
    assert _EA not in rule._unflat_done_eas


def test_import_epoch_resets_round_budget_when_mba_pointer_is_reused() -> None:
    class RecordingPassManager:
        def __init__(self) -> None:
            self.reset_eas: list[int] = []

        def reset_func(self, func_ea: int) -> None:
            self.reset_eas.append(int(func_ea))

    rule = _fresh_rule()
    rule._pass_manager = RecordingPassManager()
    rule._pass_manager_session_by_func = {}
    reused_mba = SimpleNamespace(entry_ea=_EA, this=0x1111)

    rule._reset_pass_manager_if_new_session(
        reused_mba,
        evidence_generation=7,
        stable_preopt_epoch=False,
    )
    rule._unflat_round_count[(_EA, _MAT)] = 1

    # Re-entering the same pre-import epoch must preserve the one-shot budget.
    rule._reset_pass_manager_if_new_session(
        reused_mba,
        evidence_generation=7,
        stable_preopt_epoch=False,
    )
    assert rule._pass_manager.reset_eas == [_EA]
    assert rule._unflat_round_count[(_EA, _MAT)] == 1

    # Hex-Rays may reuse the same mba_t address across PREOPT regeneration.  The
    # appearance of imported portable identities is nevertheless a new live epoch
    # and must grant the indirect profile its one recovery attempt.
    rule._reset_pass_manager_if_new_session(
        reused_mba,
        evidence_generation=7,
        stable_preopt_epoch=True,
    )
    assert rule._pass_manager.reset_eas == [_EA, _EA]
    assert (_EA, _MAT) not in rule._unflat_round_count

    rule._unflat_round_count[(_EA, _MAT)] = 1
    rule._reset_pass_manager_if_new_session(
        reused_mba,
        evidence_generation=8,
        stable_preopt_epoch=True,
    )
    assert rule._pass_manager.reset_eas == [_EA, _EA, _EA]
    assert (_EA, _MAT) not in rule._unflat_round_count


def test_preopt_bound_epoch_ignores_mba_address_churn_from_own_mutations() -> None:
    class RecordingPassManager:
        def __init__(self) -> None:
            self.reset_eas: list[int] = []

        def reset_func(self, func_ea: int) -> None:
            self.reset_eas.append(int(func_ea))

    rule = _fresh_rule()
    rule._pass_manager = RecordingPassManager()
    rule._pass_manager_session_by_func = {}
    first_wrapper = SimpleNamespace(entry_ea=_EA, this=0x1111)
    relocated_wrapper = SimpleNamespace(entry_ea=_EA, this=0x2222)

    rule._reset_pass_manager_if_new_session(
        first_wrapper,
        evidence_generation=7,
        stable_preopt_epoch=True,
    )
    rule._unflat_round_count[(_EA, _MAT)] = 1

    # Structural edits can relocate the live mba_t.  That is not a new
    # imported evidence epoch and must not reopen the one-shot recovery gate.
    rule._reset_pass_manager_if_new_session(
        relocated_wrapper,
        evidence_generation=7,
        stable_preopt_epoch=True,
    )
    assert rule._pass_manager.reset_eas == [_EA]
    assert rule._unflat_round_count[(_EA, _MAT)] == 1

    # A genuinely newer evidence generation still earns one new attempt.
    rule._reset_pass_manager_if_new_session(
        relocated_wrapper,
        evidence_generation=8,
        stable_preopt_epoch=True,
    )
    assert rule._pass_manager.reset_eas == [_EA, _EA]
    assert (_EA, _MAT) not in rule._unflat_round_count


def test_recovery_epoch_uses_generation_bound_into_preopt_without_import() -> None:
    assert _unflatten_recovery_epoch_generation(
        current_evidence_generation=7,
        bound_preopt_generation=3,
    ) == 3
    assert _unflatten_recovery_epoch_generation(
        current_evidence_generation=7,
        bound_preopt_generation=None,
    ) == 7


class TestUnflattenBoundedRerunGate:
    def test_non_indirect_reruns_until_converged(self) -> None:
        """The equality-chain profile re-runs across rounds until recovery converges."""
        rule = _fresh_rule()
        # First two rounds proceed (each emits the spine then the residual-dispatcher
        # redirect on the re-lifted graph).
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is True
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is True
        # Recovery finds no dispatcher -> converged -> terminal (every maturity).
        rule._mark_ea_converged(_EA)
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is False

    def test_indirect_is_one_shot(self) -> None:
        """The TABLE/indirect_jump_table profile runs exactly once (no re-run, no body drop)."""
        rule = _fresh_rule()
        assert rule._should_run_unflatten_round(_EA, is_indirect=True, maturity=_MAT) is True
        # Second invocation is refused even though the ea was never marked converged.
        assert rule._should_run_unflatten_round(_EA, is_indirect=True, maturity=_MAT) is False

    def test_non_indirect_round_cap_stops_only_that_maturity(self) -> None:
        """The hard round cap stops a single (ea, maturity) -- not the whole function.

        Per-(ea,maturity) budgeting (ticket llr-a93i): a maturity that loops to the cap
        without converging must NOT mark the ea globally done, or a later maturity would
        never get to recover a dispatcher this one could not (the folded equality-chain
        recovers early; a 36-back-edge machine recovers later).
        """
        rule = _fresh_rule()
        cap = StateMachineCffUnflattener._MAX_UNFLATTEN_ROUNDS
        for _ in range(cap):
            assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is True
        # Cap reached for _MAT -> refused there, but the ea is NOT globally terminal.
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is False
        assert _EA not in rule._unflat_done_eas
        # A DIFFERENT maturity still gets its own full budget.
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT2) is True

    def test_converged_ea_stays_terminal_across_maturities(self) -> None:
        """Once marked converged, an ea never runs again at ANY maturity (idempotent)."""
        rule = _fresh_rule()
        rule._mark_ea_converged(_EA)
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is False
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT2) is False
        assert rule._should_run_unflatten_round(_EA, is_indirect=True, maturity=_MAT) is False

    def test_distinct_eas_are_independent(self) -> None:
        """Re-run bookkeeping is per function ea, not global."""
        rule = _fresh_rule()
        other = _EA + 0x1000
        rule._mark_ea_converged(_EA)
        # The converged ea is terminal but a different function still runs.
        assert rule._should_run_unflatten_round(_EA, is_indirect=False, maturity=_MAT) is False
        assert rule._should_run_unflatten_round(other, is_indirect=False, maturity=_MAT) is True

    def test_terminal_carrier_plan_metadata_requests_convergence(self) -> None:
        """A terminal stack-alias guard split is a scoped early-convergence signal."""
        rule = _fresh_rule()
        facts = SimpleNamespace(
            get_analysis=lambda name, default=None: (
                {TERMINAL_CARRIER_CONVERGENCE_METADATA: True}
                if name == LOWER_STATE_MACHINE_PLAN_METADATA
                else default
            )
        )

        assert rule._lower_plan_requested_terminal_convergence(facts) is True

    def test_live_pipeline_receives_ir_maturity_and_input_facts(self, monkeypatch) -> None:
        """The live optimizer adapter must route through FunctionPassManager."""
        from d810.hexrays.preanalysis import indirect_jump_labels
        from d810.optimizers.microcode.flow.flattening import (
            state_machine_cff_unflattener as unflat_mod,
        )

        class _Family:
            name = "fake"
            recovery_maturities = (IRMaturity.GLOBAL_ANALYZED,)

        class _Backend:
            def capabilities(self):
                return frozenset()

        class _Facts:
            def __init__(self):
                self._values = {}

            def put_analysis(self, name, value):
                self._values[name] = value

            def get_analysis(self, name, default=None):
                return self._values.get(name, default)

        class _FunctionPassManager:
            def __init__(self):
                self.facts = _Facts()

            def reset_all(self):
                pass

            def reset_func(self, func_ea):
                captured["reset_func"] = int(func_ea)

            def facts_for(self, source, *, input_facts=None, analysis_seeds=None):
                captured["prepared_input_facts"] = input_facts
                captured["prepared_analysis_seeds"] = dict(analysis_seeds or {})
                for name, value in (analysis_seeds or {}).items():
                    self.facts.put_analysis(name, value)
                return self.facts

            def run(self, **kwargs):
                captured.update(kwargs)
                return kwargs["source"].flow_graph

            def analysis_manager_for(self, func_ea):
                captured["analysis_manager_for"] = int(func_ea)
                return self.facts

        captured: dict[str, object] = {}
        scheduler = object()
        family = _Family()
        fact_view = SimpleNamespace(active_observations=("state",))

        monkeypatch.setattr(
            indirect_jump_labels,
            "is_materialized_indirect_dispatcher",
            lambda _ea: False,
        )
        monkeypatch.setattr(
            StateMachineCffUnflattener,
            "_should_run_unflatten_round",
            lambda self, func_ea, *, is_indirect, maturity: True,
        )
        monkeypatch.setattr(
            StateMachineCffUnflattener,
            "_publish_unflat_diagnostics",
            lambda self, *args, **kwargs: None,
        )
        monkeypatch.setattr(
            unflat_mod,
            "FunctionPassManager",
            _FunctionPassManager,
        )
        monkeypatch.setattr(
            unflat_mod,
            "lift_function",
            lambda mba, maturity: SimpleNamespace(
                flow_graph=SimpleNamespace(blocks={}),
                func_ea=int(mba.entry_ea),
                live_source=mba,
            ),
        )
        monkeypatch.setattr(
            unflat_mod,
            "register_extra_dispatcher_resolver",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(
            unflat_mod,
            "recover_dispatcher",
            lambda *_args, **_kwargs: SimpleNamespace(
                dispatcher_block_serial=None,
                state_var_stkoff=None,
                state_var_reg=None,
                dispatch_map=None,
            ),
        )
        monkeypatch.setattr(unflat_mod, "select_family", lambda *_args, **_kwargs: family)
        monkeypatch.setattr(unflat_mod, "HexRaysMutationBackend", _Backend)
        monkeypatch.setattr(unflat_mod, "HexRaysValRangeCapability", lambda _mba: object())
        monkeypatch.setattr(unflat_mod, "HexRaysUseDefSafetyBackend", lambda: object())
        monkeypatch.setattr(
            unflat_mod,
            "HexRaysMachineRecoveryEnginesCapability",
            lambda **_kwargs: object(),
        )

        rule = StateMachineCffUnflattener()
        rule.config = {}
        rule.flow_context = SimpleNamespace(
            validated_fact_view=lambda _maturity: fact_view
        )
        rule.set_pass_scheduler(scheduler)
        rule._union_maturities_cache = frozenset({ida_hexrays.MMAT_GLBOPT1})

        mba = SimpleNamespace(
            entry_ea=_EA,
            maturity=ida_hexrays.MMAT_GLBOPT1,
        )
        assert rule.optimize(SimpleNamespace(mba=mba, serial=0)) == 0

        assert captured["maturity"] is IRMaturity.GLOBAL_ANALYZED
        assert captured["input_facts"] is fact_view
        assert captured["prepared_input_facts"] is fact_view
        from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex

        current_identity_index = captured["analysis_seeds"][
            "current_block_identity_index"
        ]
        assert isinstance(current_identity_index, MbaBlockIdentityIndex)
        assert current_identity_index.evidence_generation == 5
        expected_analysis_seeds = {
            "range_evidence": None,
            "current_block_identity_index": current_identity_index,
            "materialized_indirect_transfers": (),
            "imported_native_eas_by_serial": {},
            "native_carrier_consumer_serials_by_load_ea": {},
            "materialized_state_routes": (),
            "legacy_handler_by_state": {},
            "materialized_handler_by_state": {},
            "materialized_state_var_reg": None,
            "materialized_computed_goto_profile": False,
            "materialized_handler_entry_eas": {},
            "authoritative_handler_serials": frozenset(),
            "portable_materialized_handler_identity_misses": (),
            "unmapped_materialized_handler_targets": (),
            "materialized_dispatcher_entry_serial": None,
            "materialized_dispatcher_router_serials": frozenset(),
            "residual_entry_bridge_evidence": None,
            "imported_direct_boundary_evidence": (),
            "imported_conditional_boundary_evidence": (),
        }
        assert captured["analysis_seeds"] == expected_analysis_seeds
        assert captured["prepared_analysis_seeds"] == expected_analysis_seeds
        assert captured["reset_func"] == _EA

    def test_config_v2_mode_executes_configured_pass_specs(self, monkeypatch) -> None:
        """Config-v2 mode runs configured specs while preserving rule-local options."""
        from d810.hexrays.preanalysis import indirect_jump_labels
        from d810.optimizers.microcode.flow.flattening import (
            state_machine_cff_unflattener as unflat_mod,
        )

        class _Family:
            name = "fake"
            recovery_maturities = (IRMaturity.GLOBAL_ANALYZED,)

        class _Backend:
            def capabilities(self):
                return frozenset()

        class _Facts:
            def __init__(self):
                self._values = {}

            def put_analysis(self, name, value):
                self._values[name] = value

            def get_analysis(self, name, default=None):
                return self._values.get(name, default)

        class _FunctionPassManager:
            def __init__(self):
                self.facts = _Facts()

            def reset_all(self):
                pass

            def reset_func(self, func_ea):
                captured["reset_func"] = int(func_ea)

            def facts_for(self, source, *, input_facts=None, analysis_seeds=None):
                for name, value in (analysis_seeds or {}).items():
                    self.facts.put_analysis(name, value)
                return self.facts

            def run(self, **kwargs):
                captured.update(kwargs)
                return kwargs["source"].flow_graph

            def analysis_manager_for(self, func_ea):
                captured["analysis_manager_for"] = int(func_ea)
                return self.facts

        captured: dict[str, object] = {}
        family = _Family()
        rule_config = {
            "min_state_constant": 16777216,
            "enable_transition_validator": True,
        }
        project_config = {
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": [
                {"pass": "recover_dispatcher"},
                {"pass": "recover_state_transitions"},
                {"pass": "plan_semantic_regions"},
                {"pass": "lower_state_machine"},
                {"pass": "cleanup_residual_dispatcher"},
            ],
        }

        monkeypatch.setattr(
            indirect_jump_labels,
            "is_materialized_indirect_dispatcher",
            lambda _ea: False,
        )
        monkeypatch.setattr(
            StateMachineCffUnflattener,
            "_should_run_unflatten_round",
            lambda self, func_ea, *, is_indirect, maturity: True,
        )
        monkeypatch.setattr(
            StateMachineCffUnflattener,
            "_publish_unflat_diagnostics",
            lambda self, *args, **kwargs: None,
        )
        monkeypatch.setattr(
            StateMachineCffUnflattener,
            "_log_pipeline_v2_shadow",
            lambda self, *args, **kwargs: None,
        )
        monkeypatch.setattr(unflat_mod, "FunctionPassManager", _FunctionPassManager)
        monkeypatch.setattr(
        unflat_mod,
        "lift_function",
        lambda mba, maturity: SimpleNamespace(
            flow_graph=SimpleNamespace(blocks={}),
            func_ea=int(mba.entry_ea),
            live_source=mba,
        ),
        )
        monkeypatch.setattr(
            unflat_mod,
            "register_extra_dispatcher_resolver",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(
            unflat_mod,
            "recover_dispatcher",
            lambda *_args, **_kwargs: SimpleNamespace(
                dispatcher_block_serial=None,
                state_var_stkoff=None,
                state_var_reg=None,
                dispatch_map=None,
            ),
        )
        monkeypatch.setattr(unflat_mod, "select_family", lambda *_args, **_kwargs: family)
        monkeypatch.setattr(unflat_mod, "HexRaysMutationBackend", _Backend)
        monkeypatch.setattr(unflat_mod, "HexRaysValRangeCapability", lambda _mba: object())
        monkeypatch.setattr(unflat_mod, "HexRaysUseDefSafetyBackend", lambda: object())
        monkeypatch.setattr(
            unflat_mod,
            "HexRaysMachineRecoveryEnginesCapability",
            lambda **_kwargs: object(),
        )

        rule = StateMachineCffUnflattener()
        rule.config = rule_config
        rule.set_project_config(project_config)
        rule.flow_context = SimpleNamespace(
            validated_fact_view=lambda _maturity: SimpleNamespace(
                active_observations=()
            )
        )
        rule._union_maturities_cache = frozenset({ida_hexrays.MMAT_GLBOPT1})

        mba = SimpleNamespace(
            entry_ea=_EA,
            maturity=ida_hexrays.MMAT_GLBOPT1,
        )
        assert rule.optimize(SimpleNamespace(mba=mba, serial=0)) == 0

        pipeline_v2_specs = captured["pipeline_v2_specs"]
        assert tuple(spec.pass_id for spec in pipeline_v2_specs) == (
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        )
        assert captured["project_config"] is rule_config
        assert "pipeline_v2_shadow_registry" not in captured
        assert captured["reset_func"] == _EA
        assert rule._last_pipeline_v2_mode == "config-v2"
        assert rule._last_config_v2_pass_ids == (
            "recover_dispatcher",
            "recover_state_transitions",
            "plan_semantic_regions",
            "lower_state_machine",
            "cleanup_residual_dispatcher",
        )

    def test_block_optimizer_manager_forwards_project_config_to_rules(self, tmp_path):
        """Project additional config reaches rules after legacy rule configuration."""
        from d810.hexrays.hooks.optblock_adapter import BlockOptimizerManager

        class _Rule:
            def __init__(self):
                self.project_configs: list[dict[str, object]] = []
                self.scheduler = None

            def set_project_config(self, config):
                self.project_configs.append(dict(config))

            def set_pass_scheduler(self, scheduler):
                self.scheduler = scheduler

        rule = _Rule()
        manager = BlockOptimizerManager(
            stats=SimpleNamespace(),
            log_dir=tmp_path,
            ctx_cls=object,
        )
        manager.add_rule(rule)
        manager.configure(
            pipeline_v2_mode="config-v2",
            pipeline_v2=(
                {"pass": "recover_dispatcher"},
            ),
        )

        assert rule.project_configs[-1] == {
            "pipeline_v2_mode": "config-v2",
            "pipeline_v2": (
                {"pass": "recover_dispatcher"},
            ),
        }
        manager.configure(project_name="legacy.json")
        assert rule.project_configs[-1] == {}


class TestTigressIndirectMaterializationConfig:
    def test_non_tigress_profile_does_not_register_materialization(self, monkeypatch) -> None:
        """OLLVM/state-map configs must not arm Tigress indirect materialization."""
        calls: list[str] = []

        from d810.core import project as project_mod
        from d810.hexrays.preanalysis import indirect_jump_labels as label_mod

        monkeypatch.setattr(
            project_mod,
            "register_project_reload_cleanup",
            lambda *_args, **_kwargs: calls.append("cleanup"),
        )
        monkeypatch.setattr(
            label_mod,
            "register_indirect_materialization",
            lambda *_args, **_kwargs: calls.append("register"),
        )
        monkeypatch.setattr(
            label_mod,
            "materialize_discovered_indirect_label_targets",
            lambda *_args, **_kwargs: calls.append("idb_scan"),
        )

        rule = StateMachineCffUnflattener()
        rule.configure({"profile": "state_dispatcher_map"})

        assert calls == []

    def test_tigress_profile_registers_current_function_materialization_only(
        self,
        monkeypatch,
    ) -> None:
        """Tigress indirect arms flowchart events but never scans the whole IDB."""
        calls: list[tuple[str, object]] = []

        from d810.core import project as project_mod
        from d810.hexrays.preanalysis import indirect_jump_labels as label_mod

        monkeypatch.setattr(
            project_mod,
            "register_project_reload_cleanup",
            lambda name, _callback: calls.append(("cleanup", name)),
        )
        monkeypatch.setattr(
            label_mod,
            "reset_indirect_materialization",
            lambda: calls.append(("reset", None)),
        )
        monkeypatch.setattr(
            label_mod,
            "register_indirect_materialization",
            lambda info: calls.append(("register", dict(info))),
        )

        def _fail_idb_scan(*_args, **_kwargs):
            raise AssertionError("whole-IDB Tigress prepass must not run")

        monkeypatch.setattr(
            label_mod,
            "materialize_discovered_indirect_label_targets",
            _fail_idb_scan,
        )

        rule = StateMachineCffUnflattener()
        rule.configure({"profile": "tigress_indirect"})

        assert calls == [
            ("cleanup", "hexrays.indirect_jump_label_materialization"),
            ("reset", None),
            ("register", {}),
        ]

    def test_tigress_profile_preserves_configured_goto_table_info(self, monkeypatch) -> None:
        """Configured layout remains supported as the precise override path."""
        registered: list[dict] = []

        from d810.core import project as project_mod
        from d810.hexrays.preanalysis import indirect_jump_labels as label_mod

        monkeypatch.setattr(
            project_mod,
            "register_project_reload_cleanup",
            lambda *_args, **_kwargs: None,
        )
        monkeypatch.setattr(label_mod, "reset_indirect_materialization", lambda: None)
        monkeypatch.setattr(
            label_mod,
            "register_indirect_materialization",
            lambda info: registered.append(dict(info)),
        )

        goto_table_info = {
            "0x1800175c0": {
                "table_address": "0x180019f10",
                "table_nb_elt": 37,
            },
        }
        rule = StateMachineCffUnflattener()
        rule.configure(
            {
                "profile": "tigress_indirect",
                "goto_table_info": goto_table_info,
            }
        )

        assert registered == [goto_table_info]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
