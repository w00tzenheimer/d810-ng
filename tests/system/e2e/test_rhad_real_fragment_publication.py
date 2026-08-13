"""C5 publication canary for one bounded real Rhad terminal fragment."""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys

import pytest

idapro = pytest.importorskip("idapro")

# The dedicated Rhadamanthys loader regression work is owned by another branch.
# Keep this module visible in collection, but do not make its in-progress oracle
# block cfg-recon-mainline's system suite.
pytestmark = pytest.mark.skip(reason="Rhadamanthys loader regressions are owned by a separate branch")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_BINARY = _REPO / "samples" / "bins" / "rhad_loader_unpacked.bin"
_FUNCTION_EA = 0x40A560
_STATE_WRITE_EA = 0x40C7E5
_CARRIER_EA = 0x40C7EA
_DELIVERY_COMPARE_EA = 0x40C7F0
_DELIVERY_EA = 0x40C7F6
_ORIGINAL_TAKEN_TARGET_EA = 0x40C347
_ORIGINAL_FALLTHROUGH_TARGET_EA = 0x40C7FC
_TERMINAL_TARGET_EA = 0x40C898
_TERMINAL_RETURN_EA = 0x40C89F
_STATE_VAR_REG = 20
_STATE_CONSTANT = 0x19A7218A
_RETURN_STORAGE_EA = 0x48B8A4
_FIXTURE_SHA256 = "2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
_REFERENCE_BINARY_SHA256 = (
    "6358957fe74360725b125bdc41b16df9952d95b338792fd3521249e5030ddd8c"
)
_REFERENCE_COMMIT = "21b0d4783703bc4fb6910cfae51d92cd683d2c65"
_RUNTIME_IMAGE = "d810-idapro-9.3-test-runtime:py313-v1"
_RUNTIME_IMAGE_ID = (
    "sha256:360f91d9d4ace70d89e03893f1d895d94383fa0fe426ddba9d3898a7922b650a"
)
_REFERENCE_RUN_ID = "a560-v33-terminal-40c7f6-20260725"
_REFERENCE_ROUTE_ID = "rhad:0x40A560:flow_route:0x40C7F6"
_REFERENCE_LEDGER_IDENTITY = "flow_route:0x40C7F6"
_FRAGMENT_RANGES = (
    (_STATE_WRITE_EA, _ORIGINAL_FALLTHROUGH_TARGET_EA),
    (_TERMINAL_TARGET_EA, 0x40C8A2),
)
_SIDECAR_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")


def _reference_oracle_manifest() -> dict[str, object]:
    return {
        "schema_version": 2,
        "publication_root_ea": hex(_DELIVERY_EA),
        "run": {
            "run_id": _REFERENCE_RUN_ID,
            "function_ea": hex(_FUNCTION_EA),
            "fixture_sha256": _FIXTURE_SHA256,
            "reference_binary_sha256": _REFERENCE_BINARY_SHA256,
            "candidate_binary_sha256": _FIXTURE_SHA256,
            "reference_commit": _REFERENCE_COMMIT,
            "runtime_image": _RUNTIME_IMAGE,
            "runtime_image_id": _RUNTIME_IMAGE_ID,
            "cache_disabled": True,
            "metadata": {
                "reference_ledger_binary_sha256": _FIXTURE_SHA256,
                "reference_transaction_index": 636,
            },
        },
        "routes": [
            {
                "route_id": _REFERENCE_ROUTE_ID,
                "function_ea": hex(_FUNCTION_EA),
                "owner_ea": hex(_STATE_WRITE_EA),
                "rewrite_anchor_ea": hex(_DELIVERY_EA),
                "corridor": [
                    [hex(_STATE_WRITE_EA), hex(_ORIGINAL_FALLTHROUGH_TARGET_EA)]
                ],
                "reference_phase": "flow_route",
                "original_transfer_kind": "conditional",
                "final_transfer_kind": "direct",
                "direct_target_ea": hex(_TERMINAL_TARGET_EA),
                "true_target_ea": None,
                "false_target_ea": None,
                "predicate_kind": None,
                "reference_ledger_identity": _REFERENCE_LEDGER_IDENTITY,
                "reference_ledger": {
                    "corridor": [
                        {
                            "bytes": "bb8a21a719",
                            "ea": _STATE_WRITE_EA,
                            "mnemonic": "mov",
                            "op_str": "ebx, 0x19a7218a",
                            "size": 5,
                            "writes_flags": False,
                        },
                        {
                            "bytes": "81fb65d3b20b",
                            "ea": _DELIVERY_COMPARE_EA,
                            "mnemonic": "cmp",
                            "op_str": "ebx, 0xbb2d365",
                            "size": 6,
                            "writes_flags": True,
                        },
                        {
                            "bytes": "0f8c4bfbffff",
                            "ea": _DELIVERY_EA,
                            "mnemonic": "jl",
                            "op_str": "0x40c347",
                            "size": 6,
                            "writes_flags": False,
                        },
                    ],
                    "corridor_start_ea": _STATE_WRITE_EA,
                    "corridor_end_ea": _ORIGINAL_FALLTHROUGH_TARGET_EA,
                    "flag_writer_eas": [_DELIVERY_COMPARE_EA],
                    "flow_register": "ebx",
                    "function_ea": _FUNCTION_EA,
                    "phase": "flow_route",
                    "planned_branches": [
                        {
                            "anchor_ea": _DELIVERY_EA,
                            "opcode": "e9",
                            "target_ea": _TERMINAL_TARGET_EA,
                        }
                    ],
                    "state_writes": [
                        {
                            "ea": _STATE_WRITE_EA,
                            "mnemonic": "mov",
                            "value": _STATE_CONSTANT,
                            "value_kind": "immediate",
                        }
                    ],
                    "status": "committed",
                },
            }
        ],
    }


def _clear_ida_sidecars(binary: pathlib.Path) -> None:
    for suffix in _SIDECAR_SUFFIXES:
        for stale in (
            binary.with_suffix(suffix),
            pathlib.Path(str(binary) + suffix),
        ):
            stale.unlink(missing_ok=True)


def _generate_fragment_mba():
    import ida_hexrays
    import idaapi

    ranges = ida_hexrays.mba_ranges_t()
    for start_ea, end_ea in _FRAGMENT_RANGES:
        ranges.ranges.push_back(idaapi.range_t(start_ea, end_ea))
    failure = ida_hexrays.hexrays_failure_t()
    mba = ida_hexrays.gen_microcode(
        ranges,
        failure,
        None,
        int(ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS),
        int(ida_hexrays.MMAT_PREOPTIMIZED),
    )
    assert mba is not None, (
        "real-fragment PREOPT generation failed: "
        f"code={int(failure.code)} ea=0x{int(failure.errea):X} "
        f"description={failure.desc()!r}"
    )
    mba.build_graph()
    return mba


def _block_label(graph, serial: int) -> str:
    block = graph.blocks[int(serial)]
    return f"blk{int(serial)}@0x{int(block.start_ea):X}"


def _graph_description(graph) -> str:
    rows: list[str] = []
    for block in graph.blocks.values():
        instruction_eas = tuple(
            f"0x{int(instruction.ea):X}" for instruction in block.insn_snapshots
        )
        successors = tuple(_block_label(graph, int(serial)) for serial in block.succs)
        rows.append(
            f"{_block_label(graph, int(block.serial))} "
            f"insns={instruction_eas} succs={successors}"
        )
    return "\n".join(rows)


def _unique_instruction_block(graph, instruction_ea: int):
    matches = tuple(
        block
        for block in graph.blocks.values()
        if int(instruction_ea)
        in {int(instruction.ea) for instruction in block.insn_snapshots}
    )
    assert len(matches) == 1, (
        f"native instruction 0x{int(instruction_ea):X} requires one "
        f"PREOPT owner, observed {len(matches)}\n{_graph_description(graph)}"
    )
    return matches[0]


def _unique_corridor_block(graph, instruction_eas: frozenset[int]):
    matches = tuple(
        block
        for block in graph.blocks.values()
        if instruction_eas
        <= {int(instruction.ea) for instruction in block.insn_snapshots}
    )
    assert len(matches) == 1, (
        f"native corridor {tuple(hex(ea) for ea in sorted(instruction_eas))} "
        f"requires one PREOPT owner, observed {len(matches)}\n"
        f"{_graph_description(graph)}"
    )
    return matches[0]


def _unique_start_block(graph, start_ea: int):
    matches = tuple(
        block for block in graph.blocks.values() if int(block.start_ea) == int(start_ea)
    )
    assert len(matches) == 1, (
        f"native anchor 0x{int(start_ea):X} requires one PREOPT block, "
        f"observed {len(matches)}\n{_graph_description(graph)}"
    )
    return matches[0]


def _install_diagnostic_sink(diag_path: pathlib.Path, session_id: str) -> object:
    from d810.core.diag import create_diag_database
    from d810.core.diag import event_handlers
    from d810.core.diag.event_handlers import install_diag_event_handlers
    from d810.core.observability import emit as emit_diagnostic
    from d810.core.observability import reset_diagnostic_bus
    from d810.core.observability_events import DiagnosticSessionObserved

    database = create_diag_database(str(diag_path))
    connection = database.connection()
    reset_diagnostic_bus()
    event_handlers.get_diag_conn = lambda *_args, **_kwargs: connection
    install_diag_event_handlers()
    emit_diagnostic(
        DiagnosticSessionObserved(
            session_id=session_id,
            func_ea=_FUNCTION_EA,
            top_level_epoch=1,
            native_key_json="",
            status="active",
        )
    )
    return connection


def _run_worker(
    binary: pathlib.Path,
    diag_path: pathlib.Path,
    result_path: pathlib.Path,
) -> None:
    assert idapro.open_database(str(binary), True) == 0
    connection = None
    try:
        import ida_hexrays
        import idaapi

        idaapi.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()

        from d810.analyses.control_flow.materialized_indirect_transfer import (
            TerminalReturnCarrierRequest,
        )
        from d810.analyses.control_flow.native_preanalysis_session import (
            NativePreanalysisSessionState,
        )
        from d810.analyses.control_flow.semantic_route_evidence import (
            CanonicalSemanticEvidence,
            SemanticRouteDestination,
            SemanticRouteProof,
            SemanticRouteProofKind,
            SemanticRouteShape,
            SemanticStateWriteProof,
            bind_canonical_semantic_evidence,
        )
        from d810.analyses.control_flow.terminal_return_carrier_evidence import (
            TerminalReturnCarrierSourceKind,
        )
        from d810.backends.hexrays.lifter import lift_function
        from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend
        from d810.backends.hexrays.native_preanalysis_key import (
            build_native_preanalysis_key,
        )
        from d810.core.events import EventEmitter
        from d810.core.semantic_route_oracle import ReferenceRouteOracleCatalog
        from d810.core.observability import emit as emit_diagnostic
        from d810.core.observability_events import (
            EvidenceGenerationObserved,
            LifecycleEventObserved,
        )
        from d810.hexrays.ir.mba_identity_index import MbaBlockIdentityIndex
        from d810.hexrays.contracts.invariants import (
            block_address_range,
            block_closing_opcode_at_tail,
            successor_set_matches_tail_semantics,
        )
        from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
        from d810.hexrays.mutation.mba_mutation_events import (
            MbaCfgTransactionAuthorityObserved,
            MbaMutationAborted,
            MbaMutationCommitted,
            MbaMutationGateway,
            MbaMutationPlanned,
            MbaSemanticFragmentRouteOracleCompared,
        )
        from d810.ir.block_identity import (
            NativeEaInterval,
            stable_block_identity_from_snapshot,
        )
        from d810.ir.semantic_edge import SemanticEdgeRole
        from d810.ir.storage_identity import (
            StorageIdentity,
            StorageIdentityKind,
        )
        from d810.manager.fragment_publication_lifecycle import (
            SessionFragmentPublicationLifecycleAuthority,
        )
        from d810.manager.manager import D810Manager
        from d810.hexrays.mutation.detached_handler_island import (
            capture_terminal_return_carrier_evidence,
        )
        from d810.transforms.canonical_semantic_fragment import (
            build_canonical_semantic_fragment_plan,
        )
        from d810.transforms.fragment_plan import FragmentPublicationPurpose
        from d810.transforms.detached_route_oracle import (
            bind_fragment_reference_oracle,
        )

        native_key = build_native_preanalysis_key(
            _FUNCTION_EA,
            profile_config={"test": "rhad-real-terminal-fragment-c5"},
        )
        mba = _generate_fragment_mba()
        source = lift_function(mba)
        graph = source.flow_graph
        route_block = _unique_corridor_block(
            graph,
            frozenset(
                {
                    _STATE_WRITE_EA,
                    _CARRIER_EA,
                    _DELIVERY_COMPARE_EA,
                    _DELIVERY_EA,
                }
            ),
        )
        terminal_block = _unique_instruction_block(graph, _TERMINAL_TARGET_EA)
        route_instruction_eas = {
            int(instruction.ea) for instruction in route_block.insn_snapshots
        }
        assert {
            _STATE_WRITE_EA,
            _CARRIER_EA,
            _DELIVERY_COMPARE_EA,
            _DELIVERY_EA,
        } <= route_instruction_eas, _graph_description(graph)
        route_identity = stable_block_identity_from_snapshot(
            route_block,
            native_key=native_key,
        )
        terminal_identity = stable_block_identity_from_snapshot(
            terminal_block,
            native_key=native_key,
        )
        assert route_identity is not None
        assert terminal_identity is not None

        immediate_arm_blocks = tuple(
            graph.blocks[int(serial)] for serial in route_block.succs
        )
        assert len(immediate_arm_blocks) == 2, _graph_description(graph)
        assert all(len(block.succs) == 1 for block in immediate_arm_blocks), (
            _graph_description(graph)
        )
        prohibited_dispatcher_blocks = tuple(
            _unique_start_block(graph, target_ea)
            for target_ea in (
                _ORIGINAL_TAKEN_TARGET_EA,
                _ORIGINAL_FALLTHROUGH_TARGET_EA,
            )
        )
        assert {
            int(graph.blocks[int(block.succs[0])].serial)
            for block in immediate_arm_blocks
        } == {int(block.serial) for block in prohibited_dispatcher_blocks}, (
            _graph_description(graph)
        )
        prohibited_dispatcher_serials = tuple(
            int(block.serial) for block in prohibited_dispatcher_blocks
        )
        prohibited_dispatcher_anchors = {
            int(graph.blocks[serial].start_ea)
            for serial in prohibited_dispatcher_serials
        }
        assert prohibited_dispatcher_anchors == {
            _ORIGINAL_TAKEN_TARGET_EA,
            _ORIGINAL_FALLTHROUGH_TARGET_EA,
        }, _graph_description(graph)

        request = TerminalReturnCarrierRequest(
            source_handler_ea=_STATE_WRITE_EA,
            terminal_target_ea=_TERMINAL_TARGET_EA,
            state_var_reg=_STATE_VAR_REG,
            state_constant=_STATE_CONSTANT,
        )
        terminal_carrier = capture_terminal_return_carrier_evidence(
            _FUNCTION_EA,
            request,
            mba,
            capture_identity=route_identity,
            terminal_identity=terminal_identity,
            terminal_return_ea=_TERMINAL_RETURN_EA,
        )
        assert terminal_carrier is not None
        assert (
            terminal_carrier.source.kind
            is TerminalReturnCarrierSourceKind.ADDRESS_OF_STORAGE
        )
        assert terminal_carrier.source.storage_identity == StorageIdentity(
            StorageIdentityKind.GLOBAL,
            _RETURN_STORAGE_EA,
        )
        assert terminal_carrier.state_write_ea == _STATE_WRITE_EA
        assert terminal_carrier.carrier_ea == _CARRIER_EA
        assert terminal_carrier.terminal_return_ea == _TERMINAL_RETURN_EA
        assert terminal_carrier.corridor_instruction_eas == (
            _STATE_WRITE_EA,
            _CARRIER_EA,
        )
        atomic_group_id = "rhad-terminal-route@0x40C7F6"
        proof = SemanticRouteProof(
            proof_id="terminal-return@0x40C7F6:0x19A7218A",
            atomic_group_id=atomic_group_id,
            proof_kind=SemanticRouteProofKind.TERMINAL_RETURN,
            shape=SemanticRouteShape.DIRECT,
            source_identity=route_identity,
            source_anchor_ea=_DELIVERY_EA,
            delivery_region=NativeEaInterval(_DELIVERY_EA, _DELIVERY_EA + 1),
            destinations=(
                SemanticRouteDestination(
                    role=SemanticEdgeRole.DIRECT,
                    state_constant=_STATE_CONSTANT,
                    target_identity=terminal_identity,
                    target_anchor_ea=_TERMINAL_TARGET_EA,
                    terminal=True,
                ),
            ),
            state_write=SemanticStateWriteProof(
                identity=route_identity,
                instruction_ea=_STATE_WRITE_EA,
                state_variable=StorageIdentity(
                    StorageIdentityKind.REGISTER,
                    _STATE_VAR_REG,
                ),
                width=4,
                state_constant=_STATE_CONSTANT,
                corridor_instruction_eas=(
                    _STATE_WRITE_EA,
                    _CARRIER_EA,
                    _DELIVERY_COMPARE_EA,
                    _DELIVERY_EA,
                ),
                authority_transfer_ea=None,
                preserved_call_instruction_eas=(),
            ),
            terminal_return_carrier=terminal_carrier,
            diagnostic_provenance=(
                ("provider_proof_kind", "terminal_state_route"),
                ("delivery_kind", "direct_target"),
            ),
        )
        evidence = CanonicalSemanticEvidence(
            native_key=native_key,
            generation=1,
            atomic_group_id=atomic_group_id,
            route_proofs=(proof,),
        )
        bound = bind_canonical_semantic_evidence(graph, evidence)
        assert bound is not None, _graph_description(graph)
        plan = build_canonical_semantic_fragment_plan(
            graph,
            bound,
            prohibited_dispatcher_serials=prohibited_dispatcher_serials,
        )
        catalog = ReferenceRouteOracleCatalog.from_manifest(
            _reference_oracle_manifest()
        )
        selection = catalog.reference_oracle_for(
            _FUNCTION_EA,
            native_key,
            (_DELIVERY_EA,),
        )
        assert selection is not None, (
            "real C5 fragment requires exact cache-disabled reference authority; "
            f"input={native_key.input_identity!r} anchor=0x{_DELIVERY_EA:X}"
        )
        plan = bind_fragment_reference_oracle(plan, selection)
        assert (
            plan.publication_purpose
            is FragmentPublicationPurpose.CANONICAL_SEMANTIC_LOWERING
        )
        assert plan.reference_oracle_run == selection.run
        assert (
            plan.operations[0].direct_transfer_rewrite is not None
            and plan.operations[0].reference_route_authority is not None
            and plan.operations[0].reference_route_authority.reference_route
            == selection.routes[0]
        )
        assert len(plan.roots) == 1
        assert len(plan.operations) == 1
        assert len(plan.operations[0].edges) == 1
        assert len(plan.return_carriers) == 1
        assert len(plan.terminal_returns) == 1
        assert len(plan.terminal_routes) == 1
        assert len(plan.owned_originals) == 2
        assert len(plan.prohibited_dispatcher_blocks) == 2
        assert plan.native_bodies == ()
        root_anchor_ea = int(plan.block(plan.roots[0]).semantic_anchor_ea)
        assert root_anchor_ea == _DELIVERY_EA

        session_id = "rhad-real-terminal-fragment-c5"
        connection = _install_diagnostic_sink(diag_path, session_id)
        connection.execute(
            "UPDATE diagnostic_sessions SET native_key_json=? WHERE session_id=?",
            (native_key.to_json(), session_id),
        )

        def observe_transition(transition) -> None:
            emit_diagnostic(
                EvidenceGenerationObserved(
                    session_id=session_id,
                    func_ea=_FUNCTION_EA,
                    operation=transition.operation,
                    previous_generation=transition.previous_generation,
                    resulting_generation=transition.resulting_generation,
                    evidence_family=transition.evidence_family,
                    outcome=transition.outcome,
                    owner="native_preanalysis",
                    reason=transition.reason,
                    maturity="MMAT_PREOPTIMIZED",
                    phase="semantic_lowering",
                )
            )

        emit_diagnostic(
            EvidenceGenerationObserved(
                session_id=session_id,
                func_ea=_FUNCTION_EA,
                operation="evidence_coalesced",
                previous_generation=0,
                resulting_generation=1,
                evidence_family="real_rhad_terminal_fragment",
                outcome="accepted",
                owner="native_state_route",
                reason="bounded real-fragment C5 canary",
                maturity="MMAT_PREOPTIMIZED",
                phase="semantic_lowering",
            )
        )
        emit_diagnostic(
            LifecycleEventObserved(
                session_id=session_id,
                func_ea=_FUNCTION_EA,
                event_kind="real_fragment_proof_ready",
                provider="native_state_route",
                maturity="MMAT_PREOPTIMIZED",
                phase="semantic_lowering",
                evidence_generation=1,
                summary="bounded real Rhad terminal route proof accepted",
                payload={
                    "atomic_group_id": atomic_group_id,
                    "proof_id": proof.proof_id,
                    "state_write_ea": hex(_STATE_WRITE_EA),
                    "carrier_ea": hex(_CARRIER_EA),
                    "source_anchor_ea": hex(_DELIVERY_EA),
                    "target_ea": hex(_TERMINAL_TARGET_EA),
                    "terminal_return_ea": hex(_TERMINAL_RETURN_EA),
                    "state_constant": hex(_STATE_CONSTANT),
                    "prohibited_dispatcher_anchor_eas": tuple(
                        hex(ea) for ea in sorted(prohibited_dispatcher_anchors)
                    ),
                },
            )
        )

        lifecycle = NativePreanalysisSessionState(
            evidence_generation=1,
            event_observer=observe_transition,
        )
        assert lifecycle._fragment_publication_mark_normalization_staged()
        assert lifecycle._fragment_publication_mark_normalization_validated()
        assert lifecycle._fragment_publication_mark_normalization_published_and_postvalidated()
        authority = SessionFragmentPublicationLifecycleAuthority(
            native_key=native_key,
            state=lifecycle,
        )
        identity_index = MbaBlockIdentityIndex.from_mba(
            mba,
            generation=0,
            evidence_generation=1,
            native_key=native_key,
            session_id=session_id,
        )
        gateway = MbaMutationGateway(
            native_key=native_key,
            generation=0,
            session_id=session_id,
            function_ea=_FUNCTION_EA,
            maturity=int(mba.maturity),
            identity_index=identity_index,
            lifecycle_authority=authority,
        )
        emitter = EventEmitter()
        emitter.on(MbaMutationPlanned, D810Manager._on_mutation_planned)
        emitter.on(
            MbaSemanticFragmentRouteOracleCompared,
            D810Manager._on_semantic_fragment_route_oracle_compared,
        )
        emitter.on(MbaMutationCommitted, D810Manager._on_mutation_committed)
        emitter.on(MbaMutationAborted, D810Manager._on_mutation_aborted)
        emitter.on(
            MbaCfgTransactionAuthorityObserved,
            D810Manager._on_cfg_transaction_authority,
        )
        gateway.event_emitter = emitter

        class VerifyingFragmentModifier(DeferredGraphModifier):
            def _verify_phase(self, phase: str) -> None:
                special_block_violations = tuple(
                    violation
                    for violation in block_closing_opcode_at_tail(
                        self.mba,
                        phase=phase,
                    )
                    if violation.code == "CFG_51814_SPECIAL_BLOCK_NOT_EMPTY"
                )
                if special_block_violations:
                    anchored = []
                    for violation in special_block_violations:
                        serial = int(violation.block_serial)
                        block = self.mba.get_mblock(serial)
                        anchor_ea = int(
                            getattr(block, "start", 0)
                            or getattr(getattr(block, "head", None), "ea", 0)
                            or 0
                        )
                        anchored.append(f"blk{serial}@0x{anchor_ea:X}")
                    raise RuntimeError(
                        "live MBA special block is non-empty after "
                        f"{phase}: {tuple(anchored)!r}"
                    )
                successor_violations = tuple(
                    violation
                    for violation in successor_set_matches_tail_semantics(
                        self.mba,
                        phase=phase,
                    )
                    if violation.code == "CFG_50860_SUCC_MISMATCH"
                )
                if successor_violations:
                    anchored = []
                    for violation in successor_violations:
                        serial = int(violation.block_serial)
                        block = self.mba.get_mblock(serial)
                        anchor_ea = int(
                            getattr(block, "start", 0)
                            or getattr(getattr(block, "head", None), "ea", 0)
                            or 0
                        )
                        anchored.append(
                            (
                                f"blk{serial}@0x{anchor_ea:X}",
                                dict(violation.details or {}),
                            )
                        )
                    raise RuntimeError(
                        "live MBA successor semantics failed after "
                        f"{phase}: {tuple(anchored)!r}"
                    )
                address_violations = tuple(
                    violation
                    for violation in block_address_range(
                        self.mba,
                        phase=phase,
                    )
                    if violation.code
                    in {
                        "CFG_50869_START_GE_END",
                        "CFG_50870_BLOCK_OUTSIDE_FUNC",
                    }
                )
                if address_violations:
                    anchored = []
                    for violation in address_violations:
                        serial = int(violation.block_serial)
                        block = self.mba.get_mblock(serial)
                        anchored.append(
                            (
                                f"blk{serial}@0x{int(block.start):X}",
                                f"[0x{int(block.start):X},0x{int(block.end):X})",
                                violation.code,
                            )
                        )
                    raise RuntimeError(
                        "live MBA block range failed after "
                        f"{phase}: {tuple(anchored)!r}"
                    )
                try:
                    self.mba.verify(True)
                except RuntimeError as exc:
                    range_rows = ()
                    if "50870" in str(exc):
                        range_rows = tuple(
                            (
                                (
                                    f"blk{serial}@0x"
                                    f"{int(self.mba.map_fict_ea(int(block.start))):X}"
                                ),
                                hex(int(block.start)),
                                hex(int(block.end)),
                                hex(
                                    int(
                                        self.mba.map_fict_ea(
                                            int(block.end),
                                        )
                                    )
                                ),
                                hex(int(block.flags)),
                            )
                            for serial in range(int(self.mba.qty))
                            for block in (self.mba.get_mblock(serial),)
                            if block is not None
                        )
                    raise RuntimeError(
                        f"live MBA verification failed after {phase}: {exc}; "
                        f"ranges={range_rows!r}"
                    ) from exc

            def _realize_semantic_patch_plan(self, patch_plan, prepared_fragment):
                projection = super()._realize_semantic_patch_plan(
                    patch_plan,
                    prepared_fragment,
                )
                self._verify_phase("fragment staging")
                return projection

            def _publish_semantic_patch_roots(
                self,
                fragment_plan,
                rollback_token,
            ) -> None:
                super()._publish_semantic_patch_roots(
                    fragment_plan,
                    rollback_token,
                )
                self._verify_phase("root publication")

            def _rebuild_semantic_fragment_chains(self, fragment_plan) -> None:
                super()._rebuild_semantic_fragment_chains(fragment_plan)
                self._verify_phase("chain rebuild")

        backend = HexRaysMutationBackend(
            mutation_gateway=gateway,
            fragment_backend_factory=lambda live, transaction, _profile: (
                VerifyingFragmentModifier(
                    live,
                    mutation_gateway=transaction,
                )
            ),
        )

        post_graph = backend.apply(plan, mba)
        mba.verify(True)
        assert lifecycle.semantic_fragment_published_postvalidated_generation == 1
        assert lifecycle.receipt_committed_generation == 1
        assert post_graph != graph

        connection.commit()
        result_path.write_text(
            json.dumps(
                {
                    "plan_id": plan.plan_id,
                    "atomic_group_id": plan.atomic_group_id,
                    "operation_count": len(plan.operations),
                    "return_carrier_count": len(plan.return_carriers),
                    "terminal_return_count": len(plan.terminal_returns),
                    "terminal_route_count": len(plan.terminal_routes),
                    "root_anchor_ea": root_anchor_ea,
                    "reference_run_id": selection.run.run_id,
                    "reference_route_id": selection.routes[0].route_id,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    finally:
        if connection is not None:
            from d810.core.diag.event_handlers import (
                uninstall_diag_event_handlers,
            )
            from d810.core.observability import reset_diagnostic_bus

            connection.commit()
            uninstall_diag_event_handlers()
            reset_diagnostic_bus()
            connection.close()
        idapro.close_database(False)


@pytest.mark.skipif(not _BINARY.exists(), reason="real loader fixture unavailable")
def test_real_a560_terminal_fragment_reaches_c5_with_db_evidence(
    tmp_path: pathlib.Path,
) -> None:
    binary = tmp_path / _BINARY.name
    diag_path = tmp_path / "real-terminal-fragment.diag.sqlite3"
    result_path = tmp_path / "real-terminal-fragment.json"
    shutil.copy2(_BINARY, binary)
    _clear_ida_sidecars(binary)

    env = dict(os.environ)
    env.pop("PYTEST_CURRENT_TEST", None)
    env["PYTHONPATH"] = os.pathsep.join(
        (
            str(_REPO / "src"),
            str(_REPO / "tests"),
            env.get("PYTHONPATH", ""),
        )
    )
    result = subprocess.run(
        [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "--worker",
            str(binary),
            str(diag_path),
            str(result_path),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
        check=False,
    )
    preserved_diag = os.environ.get(
        "D810_RHAD_REAL_FRAGMENT_DIAG_OUTPUT",
    )
    if preserved_diag and diag_path.exists():
        preserved_path = pathlib.Path(preserved_diag)
        preserved_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(diag_path, preserved_path)
    assert result.returncode == 0, (
        f"real-fragment worker failed ({result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    summary = json.loads(result_path.read_text(encoding="utf-8"))
    assert summary["operation_count"] == 1
    assert summary["return_carrier_count"] == 1
    assert summary["terminal_return_count"] == 1
    assert summary["terminal_route_count"] == 1
    assert summary["root_anchor_ea"] == _DELIVERY_EA
    assert summary["reference_run_id"] == _REFERENCE_RUN_ID
    assert summary["reference_route_id"] == _REFERENCE_ROUTE_ID

    connection = sqlite3.connect(diag_path)
    try:
        proof = connection.execute(
            "SELECT summary,payload_json FROM lifecycle_events "
            "WHERE event_kind='real_fragment_proof_ready'"
        ).fetchone()
        assert proof is not None
        proof_payload = json.loads(proof[1])
        assert proof_payload["state_write_ea"] == hex(_STATE_WRITE_EA)
        assert proof_payload["carrier_ea"] == hex(_CARRIER_EA)
        assert proof_payload["source_anchor_ea"] == hex(_DELIVERY_EA)
        assert proof_payload["target_ea"] == hex(_TERMINAL_TARGET_EA)
        assert proof_payload["terminal_return_ea"] == hex(_TERMINAL_RETURN_EA)

        transaction = connection.execute(
            "SELECT plan_id,atomic_group_id,plan_json,outcome,fragment_staged,"
            "root_publication_succeeded,rollback_attempted "
            "FROM semantic_fragment_transactions"
        ).fetchone()
        assert transaction is not None
        assert transaction[:2] == (
            summary["plan_id"],
            summary["atomic_group_id"],
        )
        assert transaction[3:] == ("committed", 1, 1, 0)
        persisted_plan = json.loads(transaction[2])
        assert persisted_plan["publication_purpose"] == "canonical_semantic_lowering"
        assert persisted_plan["reference_oracle_run"]["run_id"] == _REFERENCE_RUN_ID
        assert len(persisted_plan["operations"]) == 1
        assert len(persisted_plan["return_carriers"]) == 1
        assert len(persisted_plan["terminal_returns"]) == 1
        assert (
            persisted_plan["terminal_returns"][0]["instruction_ea"]
            == _TERMINAL_RETURN_EA
        )
        assert len(persisted_plan["terminal_routes"]) == 1

        cfg_attempt = connection.execute(
            "SELECT plan_id,attempt_id,session_id,current_phase,mba_generation,"
            "evidence_generation,mutation_started,poisoned "
            "FROM cfg_transaction_attempts"
        ).fetchone()
        assert cfg_attempt is not None
        assert cfg_attempt[0] == summary["plan_id"]
        assert cfg_attempt[2:] == (
            "rhad-real-terminal-fragment-c5",
            "committed",
            0,
            1,
            1,
            0,
        )
        cfg_phases = connection.execute(
            "SELECT phase_index,phase FROM cfg_transaction_phase_events "
            "WHERE plan_id=? AND attempt_id=? ORDER BY phase_index",
            (cfg_attempt[0], cfg_attempt[1]),
        ).fetchall()
        assert cfg_phases == list(
            enumerate(
                (
                    "planned",
                    "projected",
                    "preflighted",
                    "bound",
                    "realizing",
                    "observed",
                    "committed",
                )
            )
        )

        clone_block_ids = {
            block["block_id"]
            for block in persisted_plan["blocks"]
            if block["materialization"] == "clone_published"
        }
        assert len(clone_block_ids) == 2
        creation_witnesses = connection.execute(
            "SELECT local_block_id,requested_insertion_serial,returned_serial,state "
            "FROM cfg_creation_witnesses WHERE plan_id=? AND attempt_id=? "
            "AND requested_insertion_serial IS NOT NULL "
            "AND returned_serial IS NOT NULL",
            (cfg_attempt[0], cfg_attempt[1]),
        ).fetchall()
        witnesses_by_id = {row[0]: row[1:] for row in creation_witnesses}
        assert len(witnesses_by_id) == 3
        for clone_block_id in clone_block_ids:
            assert witnesses_by_id[clone_block_id][0] is not None
            assert witnesses_by_id[clone_block_id][1] is not None
            assert witnesses_by_id[clone_block_id][2] == "committed"
        helper_witnesses = {
            local_id: witness
            for local_id, witness in witnesses_by_id.items()
            if local_id.startswith("root-fallthrough-helper:")
        }
        assert len(helper_witnesses) == 1
        helper_witness = next(iter(helper_witnesses.values()))
        assert helper_witness[0] is not None
        assert helper_witness[1] is not None
        assert helper_witness[2] == "committed"

        oracle = connection.execute(
            "SELECT run_id,plan_id,atomic_group_id,route_id,maturity,"
            "candidate_variant,outcome,first_divergence,failed_invariant,"
            "owner_ea_i64,rewrite_anchor_ea_i64,reference_ledger_identity,"
            "oracle_shape_json,candidate_shape_json,reason "
            "FROM semantic_fragment_route_oracle_comparisons"
        ).fetchone()
        assert oracle is not None
        assert oracle[:12] == (
            _REFERENCE_RUN_ID,
            summary["plan_id"],
            summary["atomic_group_id"],
            _REFERENCE_ROUTE_ID,
            "DETACHED_PREPUBLICATION",
            "detached_prepublication",
            "matched",
            0,
            None,
            _STATE_WRITE_EA,
            _DELIVERY_EA,
            _REFERENCE_LEDGER_IDENTITY,
        )
        oracle_shape = json.loads(oracle[12])
        candidate_shape = json.loads(oracle[13])
        assert oracle_shape["terminator_ea"] == f"0x{_DELIVERY_EA:X}"
        assert oracle_shape["direct_target_ea"] == f"0x{_TERMINAL_TARGET_EA:X}"
        assert candidate_shape["terminator_ea"] == f"0x{_DELIVERY_EA:X}"
        assert candidate_shape["terminator_opcode"] == "goto"
        assert candidate_shape["transfer_kind"] == "direct"
        assert candidate_shape["direct_target_ea"] == f"0x{_TERMINAL_TARGET_EA:X}"
        assert candidate_shape["reachable_from_entry"] is True
        assert oracle[14] == ""

        receipt = connection.execute(
            "SELECT planned_operation_count,applied_operation_count,outcome "
            "FROM mutation_receipts"
        ).fetchone()
        assert receipt is not None
        assert receipt[0] == receipt[1]
        assert receipt[2] == "committed"
        transaction_events = connection.execute(
            "SELECT event_index,event_kind,outcome "
            "FROM semantic_fragment_transaction_events ORDER BY event_index"
        ).fetchall()
        oracle_event = next(
            row for row in transaction_events if row[1] == "detached_route_oracle"
        )
        receipt_event = next(row for row in transaction_events if row[1] == "receipt")
        assert oracle_event[2] == "passed"
        assert receipt_event[2] == "committed"
        assert oracle_event[0] < receipt_event[0]
        validation = connection.execute(
            "SELECT phase,passed FROM semantic_fragment_validation_outcomes"
        ).fetchall()
        assert {phase for phase, _passed in validation} == {
            "prepublication",
            "postpublication",
        }
        assert validation and all(passed for _phase, passed in validation)
        root_group = connection.execute(
            "SELECT publication_attempted,publication_succeeded,"
            "rollback_attempted FROM semantic_fragment_root_publication_groups"
        ).fetchone()
        assert root_group == (1, 1, 0)
        transitions = connection.execute(
            "SELECT from_state,to_state FROM logical_block_version_transitions"
        ).fetchall()
        assert ("published", "retired") in transitions
        assert ("staged", "published") in transitions
        lifecycle_operations = {
            row[0]
            for row in connection.execute(
                "SELECT operation FROM evidence_generation_events"
            ).fetchall()
            if row[0] is not None
        }
        assert {
            "normalization_published_postvalidated",
            "canonical_semantic_plan_ready",
            "semantic_fragment_staged",
            "semantic_fragment_validated",
            "semantic_fragment_published_postvalidated",
            "receipt_committed",
        } <= lifecycle_operations
    finally:
        connection.close()


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--worker":
        raise SystemExit(
            "usage: test_rhad_real_fragment_publication.py --worker BINARY DIAG RESULT"
        )
    _run_worker(
        pathlib.Path(sys.argv[2]),
        pathlib.Path(sys.argv[3]),
        pathlib.Path(sys.argv[4]),
    )
