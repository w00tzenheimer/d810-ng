"""Manager-owned single-route Rhad GENERATED checksum producer.

This is intentionally not a general A560 restoration path. It compiles the
pinned ``cmovl`` checksum route and submits it to the shared fragment
transaction backend at the actual GENERATED callback boundary.
"""

from __future__ import annotations

from collections import deque

from d810.core.logging import getLogger
from d810.core.semantic_route_oracle import RouteOracleRun
from d810.hexrays.mutation.semantic_fragment_profile import (
    SemanticFragmentPublicationProfile,
)
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.transforms.fragment_plan import (
    FragmentBlock,
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentEdge,
    FragmentNativeBody,
    FragmentOperation,
    FragmentPlan,
    FragmentPublicationPurpose,
    FragmentWorkItemScope,
)
from d810.transforms.rhad_reference_compiler import (
    RhadConditionalRoute,
    RhadReferenceLedger,
    RhadReferencePhase,
    compile_rhad_reference_fragment,
)


logger = getLogger(__name__)

FUNCTION_EA = 0x40A560
SOURCE_EA = 0x40A5F0
TRANSFER_EA = 0x40A605
INPUT_SHA256 = "2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
IMPORTED_RANGES = (
    (0x40A607, 0x40A615),
    (0x40A615, 0x40A61B),
    (0x40A619, 0x40A61B),
    (0x40A680, 0x40A68C),
    (0x40A68A, 0x40A68C),
    (0x40B6C0, 0x40B6CA),
    (0x40B6CA, 0x40B6D0),
    (0x40B6D0, 0x40B6D6),
    (0x40B6D4, 0x40B6D6),
)
IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}" for start_ea, _end_ea in IMPORTED_RANGES
)
BOUNDARY_EXIT_EAS = (0x40A61B, 0x40A68C, 0x40B790)


def _emit_checksum_lifecycle(
    session: object,
    *,
    event_kind: str,
    maturity: str,
    phase: str,
    summary: str,
    payload: dict[str, object],
) -> None:
    from d810.core.observability import emit as emit_diagnostic
    from d810.core.observability_events import LifecycleEventObserved

    emit_diagnostic(
        LifecycleEventObserved(
            session_id=str(session.identity_key),
            func_ea=int(session.function_ea),
            event_kind=str(event_kind),
            provider="rhad_generated_checksum",
            maturity=str(maturity),
            phase=str(phase),
            evidence_generation=int(
                session.native_preanalysis.evidence_generation
            ),
            mba_generation_before=int(session.current_mba_generation),
            mba_generation_after=int(session.current_mba_generation),
            summary=str(summary),
            payload=dict(payload),
        )
    )


def observe_a560_generated_checksum_preparation(
    session: object,
    *,
    prepared: bool,
) -> None:
    """Record the immutable target-template authority before publication."""
    if int(session.function_ea) != FUNCTION_EA:
        return
    _emit_checksum_lifecycle(
        session,
        event_kind="rhad_generated_checksum_preparation",
        maturity="NATIVE_PREANALYSIS",
        phase="template_preparation",
        summary=(
            "A560 GENERATED checksum templates prepared"
            if prepared
            else "A560 GENERATED checksum templates unavailable"
        ),
        payload={
            "prepared": bool(prepared),
            "template_root_eas": [0x40A607, 0x40B6C0],
            "imported_ranges": [list(row) for row in IMPORTED_RANGES],
            "imported_block_count": len(IMPORTED_BLOCK_IDS),
            "boundary_exit_eas": list(BOUNDARY_EXIT_EAS),
        },
    )


def _instructions(block: object) -> tuple[object, ...]:
    rows = []
    instruction = block.head
    while instruction is not None:
        rows.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(rows)


def _native_anchor(block: object, origins: dict[int, int]) -> int:
    return min(
        (
            int(origins.get(int(row.ea), int(row.ea)))
            for row in _instructions(block)
            if int(origins.get(int(row.ea), int(row.ea))) > 0
        ),
        default=int(block.start),
    )


def _checksum_route_observation(mba: object) -> dict[str, object]:
    """Observe the committed route without building or changing a live graph."""
    import ida_hexrays

    from d810.hexrays.mutation.detached_handler_island import (
        imported_detached_snippet_instruction_origins,
    )

    origins = dict(imported_detached_snippet_instruction_origins(mba))
    blocks = {
        serial: mba.get_mblock(serial) for serial in range(int(mba.qty))
    }

    def reachable_anchors() -> tuple[int, ...]:
        reachable: set[int] = set()
        pending = [0]
        while pending:
            serial = pending.pop()
            if serial in reachable:
                continue
            reachable.add(serial)
            pending.extend(int(value) for value in blocks[serial].succset)
        return tuple(
            sorted({_native_anchor(blocks[serial], origins) for serial in reachable})
        )

    transfer_indirect = any(
        int(row.opcode) == int(ida_hexrays.m_ijmp)
        and int(origins.get(int(row.ea), int(row.ea))) == TRANSFER_EA
        for block in blocks.values()
        for row in _instructions(block)
    )
    source = next(
        (
            block
            for block in blocks.values()
            if any(
                int(origins.get(int(row.ea), int(row.ea))) == SOURCE_EA
                for row in _instructions(block)
            )
        ),
        None,
    )
    if source is None:
        reachable = reachable_anchors()
        return {
            "source_present": False,
            "indirect_transfer_present": transfer_indirect,
            "target_eas": [],
            "reachable_eas": list(reachable),
            "passed": not transfer_indirect and 0x40B6C0 in reachable,
        }

    target_eas: set[int] = set()
    source_successors = tuple(int(value) for value in source.succset)
    if source_successors:
        for successor_serial in source_successors:
            target = blocks[successor_serial]
            while (
                _native_anchor(target, origins) in {0x40A5FE, 0x40A601}
                and len(tuple(target.succset)) == 1
            ):
                successor_serial = int(tuple(target.succset)[0])
                target = blocks[successor_serial]
            target_eas.add(_native_anchor(target, origins))
    else:
        if source.nextb is None or source.nextb.nextb is None:
            return {
                "source_present": True,
                "indirect_transfer_present": transfer_indirect,
                "target_eas": [],
                "reachable_eas": [],
                "passed": False,
                "reason": "conditional-select physical corridor is absent",
            }
        route_rows = (
            *(_instructions(source)[-1:]),
            *(_instructions(source.nextb)[-1:]),
            *(_instructions(source.nextb.nextb)[-1:]),
        )
        for row in route_rows:
            opcode = int(row.opcode)
            operand = row.l if opcode == int(ida_hexrays.m_goto) else row.d
            if int(operand.t) != int(ida_hexrays.mop_b):
                continue
            target_eas.add(_native_anchor(blocks[int(operand.b)], origins))
    expected_targets = {0x40A607, 0x40B6C0}
    return {
        "source_present": True,
        "indirect_transfer_present": transfer_indirect,
        "target_eas": sorted(target_eas),
        "reachable_eas": list(reachable_anchors()),
        "passed": not transfer_indirect and target_eas == expected_targets,
    }


def observe_a560_generated_checksum_maturity(
    *,
    function_ea: int,
    mba: object,
    decision: dict[str, object],
    maturity_override: str | None = None,
) -> None:
    """Persist one deduplicated route-specific maturity observation."""
    if int(function_ea) != FUNCTION_EA or int(mba.entry_ea) != FUNCTION_EA:
        return
    session = decision.get("session")
    if (
        session is None
        or not session.rhad_generated_checksum_committed_for_current_mba
    ):
        return
    from d810.hexrays.ir_maturity import maturity_to_name

    maturity = (
        maturity_to_name(int(mba.maturity))
        if maturity_override is None
        else str(maturity_override)
    )
    if maturity in session.rhad_generated_checksum_observed_maturities:
        return
    session.rhad_generated_checksum_observed_maturities.add(maturity)
    observation = _checksum_route_observation(mba)
    _emit_checksum_lifecycle(
        session,
        event_kind="rhad_generated_checksum_maturity",
        maturity=maturity,
        phase="route_survival",
        summary=(
            f"A560 GENERATED checksum route {'passed' if observation['passed'] else 'failed'} "
            f"at {maturity}"
        ),
        payload={
            **observation,
            "comparison_constant": 0x0BB2D365,
            "true_target_ea": 0x40B6C0,
            "false_target_ea": 0x40A607,
            "transfer_ea": TRANSFER_EA,
        },
    )


def observe_a560_generated_checksum_preopt(**kwargs: object) -> None:
    observe_a560_generated_checksum_maturity(
        **kwargs,
        maturity_override="MMAT_PREOPTIMIZED",
    )


def observe_a560_generated_checksum_locopt(**kwargs: object) -> None:
    observe_a560_generated_checksum_maturity(
        **kwargs,
        maturity_override="MMAT_LOCOPT",
    )


def observe_a560_generated_checksum_calls(**kwargs: object) -> None:
    # Hex-Rays invokes hxe_calls_done after call analysis while the live MBA's
    # numeric maturity still reports LOCOPT.  The callback boundary, not that
    # lagging field, is the authoritative CALLS observation label.
    observe_a560_generated_checksum_maturity(
        **kwargs,
        maturity_override="MMAT_CALLS",
    )


def prepare_a560_generated_checksum_templates(
    state: object,
) -> bool:
    """Capture both target-rooted PREOPT bodies before the live MBA exists."""
    resolution = state.portable_evidence.computed_goto_resolution
    if resolution is None or int(resolution.function_ea) != FUNCTION_EA:
        return False

    import ida_hexrays
    import idaapi

    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg
    from d810.hexrays.mutation.detached_handler_island import (
        capture_generated_reference_snippet_template,
    )

    transfers = cg._static_prepatch_union_source_transfers(resolution)
    source_plan = cg._plan_frontend_normalization_union_source(
        resolution,
        transfers=transfers,
        contextual_patch_plans=(
            state.portable_evidence.promoted_contextual_patch_plans
        ),
    )
    if source_plan is None:
        return False
    seeds = frozenset(int(ea) for ea in source_plan.region.seed_eas)

    def native_fragment(
        root_ea: int,
    ) -> tuple[
        tuple[tuple[int, int], ...],
        tuple[int, ...],
        tuple[tuple[int, int], ...],
        tuple[int, ...],
    ]:
        native_blocks: dict[int, object] = {}
        boundary_eas: set[int] = set()
        pending = deque((int(root_ea),))
        while pending:
            entry_ea = pending.popleft()
            if entry_ea in native_blocks:
                continue
            block = source_plan.cfg.blocks_by_ea.get(entry_ea)
            if block is None:
                raise ValueError(
                    f"GENERATED checksum lost native block 0x{entry_ea:X}"
                )
            native_blocks[entry_ea] = block
            for edge in block.outgoing_edges:
                if edge.target_ea is None:
                    continue
                target_ea = int(edge.target_ea)
                if target_ea != int(root_ea) and target_ea in seeds:
                    boundary_eas.add(target_ea)
                    continue
                if target_ea in source_plan.cfg.blocks_by_ea:
                    pending.append(target_ea)
        owned_ranges = tuple(
            sorted(
                (int(block.start_ea), int(block.end_ea))
                for block in native_blocks.values()
            )
        )
        boundary_ranges = tuple(
            sorted(
                (
                    int(source_plan.cfg.blocks_by_ea[ea].start_ea),
                    int(source_plan.cfg.blocks_by_ea[ea].end_ea),
                )
                for ea in boundary_eas
                if ea in source_plan.cfg.blocks_by_ea
            )
        )
        return (
            owned_ranges,
            tuple(sorted(native_blocks)),
            boundary_ranges,
            tuple(sorted(boundary_eas)),
        )

    captured = 0
    for target_ea in (0x40A607, 0x40B6C0):
        (
            ranges,
            owned_entry_eas,
            boundary_ranges,
            boundary_eas,
        ) = native_fragment(target_ea)
        mba_ranges = ida_hexrays.mba_ranges_t()
        for start_ea, end_ea in (*ranges, *boundary_ranges):
            mba_ranges.ranges.push_back(idaapi.range_t(start_ea, end_ea))
        failure = ida_hexrays.hexrays_failure_t()
        if not state.begin_snippet_capture(int(target_ea)):
            return False
        try:
            target_mba = cg._generate_microcode_without_d810(
                ida_hexrays.gen_microcode,
                mba_ranges,
                failure,
                None,
                int(ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS),
                int(ida_hexrays.MMAT_PREOPTIMIZED),
            )
            if target_mba is None:
                logger.info(
                    "GENERATED checksum target capture failed: "
                    "target=0x%X reason=%s",
                    target_ea,
                    failure.desc(),
                )
                return False
            target_mba.build_graph()
            captured += int(
                capture_generated_reference_snippet_template(
                    FUNCTION_EA,
                    target_ea,
                    target_mba,
                    ranges,
                    boundary_ranges=boundary_ranges,
                    boundary_exit_eas=boundary_eas,
                    owned_block_entry_eas=owned_entry_eas,
                )
            )
        finally:
            state.finish_snippet_capture()
    logger.info(
        "prepared GENERATED checksum target templates: captured=%d",
        captured,
    )
    return captured == 2


def _identity(native_key, start_ea: int, end_ea: int, *eas: int):
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(int(start_ea), int(end_ea)),),
        native_key=native_key,
        exact_instruction_eas=tuple(eas or (int(start_ea),)),
    )


def build_a560_generated_checksum_plan(
    *,
    native_key: object,
    evidence_generation: int,
) -> FragmentPlan:
    """Compile the one admitted checksum route without live-MBA access."""
    generation = int(evidence_generation)
    function_identity = int(native_key.function_rva)
    input_identity = str(native_key.input_identity).lower()
    if not input_identity.startswith("sha256:") or len(input_identity) != 71:
        raise ValueError("A560 checksum requires a SHA-256 native input identity")
    candidate_sha256 = input_identity.removeprefix("sha256:")
    source_identity = _identity(
        native_key,
        SOURCE_EA,
        TRANSFER_EA + 2,
        0x40A5F0,
        0x40A5F6,
        0x40A5FE,
        0x40A601,
        0x40A605,
    )
    original_id = "native-original@0x40A5F0"
    source_id = "native@0x40A5F0"
    predecessor_id = "native@0x40A5AE"
    body_id = "rhad-a560-generated-native-body"
    blocks = (
        FragmentBlock(
            block_id=predecessor_id,
            role=FragmentBlockRole.EXTERNAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=0x40A5AE,
            stable_identity=_identity(
                native_key,
                0x40A5AE,
                SOURCE_EA,
                0x40A5AE,
                0x40A5C8,
            ),
        ),
        FragmentBlock(
            block_id=original_id,
            role=FragmentBlockRole.ORIGINAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=SOURCE_EA,
            stable_identity=source_identity,
        ),
        FragmentBlock(
            block_id=source_id,
            role=FragmentBlockRole.REPLACEMENT,
            materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
            semantic_anchor_ea=SOURCE_EA,
            stable_identity=source_identity,
            replaces_block_id=original_id,
        ),
        FragmentBlock(
            block_id="native@0x40A5FE",
            role=FragmentBlockRole.EXTERNAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=0x40A5FE,
            stable_identity=_identity(
                native_key,
                0x40A5FE,
                0x40A601,
                0x40A5FE,
            ),
        ),
        FragmentBlock(
            block_id="native@0x40A601",
            role=FragmentBlockRole.EXTERNAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=0x40A601,
            stable_identity=_identity(
                native_key,
                0x40A601,
                TRANSFER_EA + 2,
                0x40A601,
                TRANSFER_EA,
            ),
        ),
        *(
            FragmentBlock(
                block_id=block_id,
                role=FragmentBlockRole.IMPORTED,
                materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
                semantic_anchor_ea=start_ea,
                stable_identity=_identity(
                    native_key,
                    start_ea,
                    end_ea,
                    start_ea,
                ),
                native_body_id=body_id,
            )
            for block_id, (start_ea, end_ea) in zip(
                IMPORTED_BLOCK_IDS,
                IMPORTED_RANGES,
                strict=True,
            )
        ),
    )
    base_plan = FragmentPlan(
        plan_id="rhad-a560-generated-checksum-base",
        atomic_group_id=f"rhad-a560-generated-checksum:g{generation}",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=native_key,
        blocks=blocks,
        roots=(source_id,),
        owned_originals=(original_id,),
        prohibited_dispatcher_blocks=(),
        operations=(
            FragmentOperation(
                operation_id="placeholder@0x40A605",
                source_block_id=source_id,
                edges=(
                    FragmentEdge(
                        role=SemanticEdgeRole.DIRECT,
                        target_block_id="native@0x40A607",
                    ),
                ),
            ),
        ),
        work_item_scope=FragmentWorkItemScope(
            work_item_id=f"rhad-generated-checksum@0x40A605:g{generation}",
            selected_obligation_ids=("rhad:route@0x40A605",),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id=body_id,
                block_ids=IMPORTED_BLOCK_IDS,
                entry_block_ids=(
                    "native@0x40A607",
                    "native@0x40A619",
                    "native@0x40A68A",
                    "native@0x40B6C0",
                    "native@0x40B6D4",
                ),
                terminal_block_ids=(),
                native_ranges=(
                    NativeEaInterval(0x40A607, 0x40A61B),
                    NativeEaInterval(0x40A680, 0x40A68C),
                    NativeEaInterval(0x40B6C0, 0x40B6D6),
                ),
                proof_ids=("native-body@0x40A605",),
                preserved_native_transfer_block_ids=IMPORTED_BLOCK_IDS,
            ),
        ),
    )
    route = RhadConditionalRoute(
        operation_id="rhad:route@0x40A605",
        source_block_id=source_id,
        transfer_ea=TRANSFER_EA,
        predicate_anchor_ea=0x40A5F6,
        normalization_start_ea=0x40A5F6,
        condition_producer_ea=0x40A5F0,
        conditional_select_ea=0x40A5FE,
        selected_value_block_id="native@0x40A5FE",
        join_block_id="native@0x40A601",
        observed_predicate_kind=PredicateKind.SGE,
        predicate_kind=PredicateKind.SLT,
        true_target_block_id="native@0x40B6C0",
        false_target_block_id="native@0x40A607",
        comparison_constant=0x0BB2D365,
        owned_corridor_instruction_eas=(
            0x40A5F0,
            0x40A5F6,
            0x40A5FE,
            0x40A601,
            0x40A605,
        ),
        imported_closure_block_ids=IMPORTED_BLOCK_IDS,
        boundary_exit_eas=BOUNDARY_EXIT_EAS,
        flag_corridor_id="flags-intact@0x40A5F0",
        phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    )
    ledger = RhadReferenceLedger(
        ledger_id=f"rhad-generated-reference@0x40A560:g{generation}",
        function_ea=function_identity,
        evidence_generation=generation,
        base_plan=base_plan,
        reference_oracle_run=RouteOracleRun(
            run_id="rhad-a560-generated-checksum",
            function_ea=function_identity,
            fixture_sha256=INPUT_SHA256,
            reference_binary_sha256="1" * 64,
            candidate_binary_sha256=candidate_sha256,
            reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
            runtime_image_id="sha256:360f91d9d4ac",
            cache_disabled=True,
        ),
        operations=(route,),
        required_boundary_exit_eas=BOUNDARY_EXIT_EAS,
        reference_provenance={
            "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
            "operation_shape": "cmovl_selected_indirect_transfer",
        },
    )
    return compile_rhad_reference_fragment(
        ledger,
        expected_evidence_generation=generation,
    )


def publish_a560_generated_checksum(
    *,
    function_ea: int,
    mba: object,
    decision: dict[str, object],
) -> None:
    """Compile and submit the checksum through the sole live backend entry."""
    if int(function_ea) != FUNCTION_EA or int(mba.entry_ea) != FUNCTION_EA:
        return
    session = decision.get("session")
    gateway = decision.get("mutation_gateway")
    materializer = decision.get("semantic_native_body_materializer")
    logger.info(
        "GENERATED checksum boundary observed: session=%s gateway=%s "
        "materializer=%s",
        session is not None,
        gateway is not None,
        materializer is not None,
    )
    if session is None or gateway is None or materializer is None:
        return
    if session.rhad_generated_checksum_attempted_for_current_mba:
        logger.info("GENERATED checksum already attempted for current MBA")
        return
    # The optinsn adapter deliberately keeps the lifecycle event retryable when
    # a listener fails.  This producer is a fragment-atomic transaction,
    # however, so retrying it once per instruction would obscure the first
    # failed obligation and could attempt the same SDK writes repeatedly.
    session.rhad_generated_checksum_attempted_for_current_mba = True
    session.rhad_generated_checksum_committed_for_current_mba = False
    session.rhad_generated_checksum_observed_maturities.clear()
    plan = build_a560_generated_checksum_plan(
        native_key=session.native_key,
        evidence_generation=int(session.native_preanalysis.evidence_generation),
    )
    _emit_checksum_lifecycle(
        session,
        event_kind="rhad_generated_checksum_compiled",
        maturity="MMAT_GENERATED",
        phase="reference_compilation",
        summary="compiled one bounded A560 GENERATED reference route",
        payload={
            "plan_id": plan.plan_id,
            "atomic_group_id": plan.atomic_group_id,
            "operation_ids": [operation.operation_id for operation in plan.operations],
            "imported_block_ids": list(IMPORTED_BLOCK_IDS),
            "imported_block_count": len(IMPORTED_BLOCK_IDS),
            "boundary_exit_eas": list(BOUNDARY_EXIT_EAS),
            "comparison_constant": 0x0BB2D365,
            "true_target_ea": 0x40B6C0,
            "false_target_ea": 0x40A607,
            "transfer_ea": TRANSFER_EA,
        },
    )
    from d810.backends.hexrays.mutation.backend import HexRaysMutationBackend

    backend = HexRaysMutationBackend(
        mutation_gateway=gateway,
        semantic_native_body_materializer=materializer,
    )
    backend.apply(
        plan,
        mba,
        publication_profile=(
            SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE
        ),
    )
    receipt = backend._committed_fragment_receipt
    if receipt is None:
        raise RuntimeError("GENERATED checksum did not produce a receipt")
    session.rhad_generated_checksum_committed_for_current_mba = True
    decision["microcode_modified"] = True
    decision["rhad_generated_checksum_receipt"] = receipt
    decision["rhad_generated_checksum_plan"] = plan
    _emit_checksum_lifecycle(
        session,
        event_kind="rhad_generated_checksum_published",
        maturity="MMAT_GENERATED",
        phase="transaction_commit",
        summary="committed one bounded A560 GENERATED checksum transaction",
        payload={
            "plan_id": plan.plan_id,
            "mutation_batch_id": receipt.mutation_batch_id,
            "planned_operation_count": int(receipt.planned_operation_count),
            "applied_operation_count": int(receipt.operation_count),
            "root_publication_confirmed": bool(receipt.root_publication_confirmed),
            "prepublication_validation_passed": bool(
                receipt.prepublication_validation.passed
            ),
            "postpublication_validation_passed": bool(
                receipt.postpublication_validation.passed
            ),
        },
    )
    observe_a560_generated_checksum_maturity(
        function_ea=function_ea,
        mba=mba,
        decision=decision,
    )
    logger.info(
        "committed GENERATED checksum route: plan=%s batch=%s operations=%d",
        plan.plan_id,
        receipt.mutation_batch_id,
        int(receipt.operation_count),
    )


__all__ = [
    "BOUNDARY_EXIT_EAS",
    "FUNCTION_EA",
    "IMPORTED_BLOCK_IDS",
    "IMPORTED_RANGES",
    "INPUT_SHA256",
    "SOURCE_EA",
    "TRANSFER_EA",
    "build_a560_generated_checksum_plan",
    "prepare_a560_generated_checksum_templates",
    "publish_a560_generated_checksum",
]
