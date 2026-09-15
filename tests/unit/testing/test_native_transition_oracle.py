from __future__ import annotations

from tests.system.e2e.hash_bound.native_transition_oracle import (
    NativeCfgBlock,
    NativeImageSlice,
    NativeInstruction,
    NativeTransitionRequest,
    NativeTransitionStatus,
    enumerate_selector_routes,
    prove_linked_native_transition,
    prove_native_transition,
)
from tests.system.e2e.hash_bound.native_transition_references import (
    e086be0_gs_selector_slice,
    e086be0_missing_native_slices,
)


def _request(
    *instructions: tuple[int, bytes],
    targets: tuple[tuple[str, tuple[int, ...]], ...],
    registers: tuple[tuple[str, int], ...] = (),
    instruction_budget: int = 16,
) -> NativeTransitionRequest:
    return NativeTransitionRequest(
        instructions=tuple(
            NativeInstruction(ea=ea, data=data) for ea, data in instructions
        ),
        entry_ea=instructions[0][0],
        target_partitions=targets,
        register_assumptions=registers,
        memory_assumptions=(),
        instruction_budget=instruction_budget,
    )


def test_exact_encoded_selector_resolves_one_partition() -> None:
    # mov eax, ecx; xor eax, 0x11223344; cmp eax, 0x11223345;
    # je 0x1015; jmp 0x1016
    request = _request(
        (0x1000, bytes.fromhex("89 c8")),
        (0x1002, bytes.fromhex("35 44 33 22 11")),
        (0x1007, bytes.fromhex("3d 45 33 22 11")),
        (0x100C, bytes.fromhex("74 07")),
        (0x100E, bytes.fromhex("eb 06")),
        targets=(("equal", (0x1015,)), ("other", (0x1016,))),
        registers=(("ecx", 1),),
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.RESOLVED
    assert receipt.target == "equal"
    assert receipt.instruction_eas == (0x1000, 0x1002, 0x1007, 0x100C)
    assert receipt.request_fingerprint.startswith("sha256:")


def test_execution_outside_exact_instruction_slice_is_unresolved() -> None:
    request = _request(
        (0x2000, bytes.fromhex("eb 05")),
        targets=(("target", (0x2008,)),),
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.UNRESOLVED
    assert receipt.reason == "instruction_not_in_slice:0x2007"


def test_unmapped_native_read_records_exact_fault_address() -> None:
    request = _request(
        (0x2800, bytes.fromhex("8b 04 25 60 00 00 00")),
        targets=(("unreached", (0x2807,)),),
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.UNRESOLVED
    assert receipt.reason == "unmapped_memory_read:0x60"
    assert receipt.instruction_eas == (0x2800,)


def test_overlapping_target_partitions_are_rejected() -> None:
    request = _request(
        (0x3000, bytes.fromhex("90")),
        targets=(("left", (0x3001,)), ("right", (0x3001,))),
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.UNRESOLVED
    assert receipt.reason == "target_partitions_overlap"


def test_instruction_budget_exhaustion_is_unresolved() -> None:
    request = _request(
        (0x4000, bytes.fromhex("eb fe")),
        targets=(("target", (0x4010,)),),
        instruction_budget=3,
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.UNRESOLVED
    assert receipt.reason == "instruction_budget_exhausted"


def test_entry_that_is_another_partition_target_must_execute_first() -> None:
    request = _request(
        (0x5000, bytes.fromhex("90")),
        (0x5001, bytes.fromhex("eb 00")),
        targets=(("prior_route", (0x5000,)), ("next_route", (0x5003,))),
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.RESOLVED
    assert receipt.target == "next_route"
    assert receipt.instruction_eas == (0x5000, 0x5001)


def test_target_near_page_end_maps_only_bounded_decode_padding() -> None:
    request = _request(
        (0x7000, bytes.fromhex("e9 be 0f 00 00")),
        targets=(("page_end", (0x7FC3,)),),
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.RESOLVED
    assert receipt.target == "page_end"
    assert receipt.instruction_eas == (0x7000,)


def test_target_translation_prefetch_can_cross_the_next_page() -> None:
    request = NativeTransitionRequest(
        instructions=(
            NativeInstruction(0x1800A6F90, bytes.fromhex("31 c0")),
            NativeInstruction(0x1800A6F92, bytes.fromhex("75 57")),
        ),
        entry_ea=0x1800A6F90,
        target_partitions=(("page_end", (0x1800A6F94,)),),
        register_assumptions=(),
        # A mapped data page above the code extends emu_start's stop address.
        # Unicorn then translates past the named target before firing its hook.
        memory_assumptions=((0x1800D0000, b"\0"),),
        instruction_budget=16,
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.RESOLVED
    assert receipt.target == "page_end"
    assert receipt.instruction_eas == (0x1800A6F90, 0x1800A6F92)


def test_target_observation_can_be_armed_after_state_write() -> None:
    request = NativeTransitionRequest(
        instructions=(
            NativeInstruction(0x6000, bytes.fromhex("90")),
            NativeInstruction(0x6001, bytes.fromhex("90")),
            NativeInstruction(0x6002, bytes.fromhex("eb fc")),
        ),
        entry_ea=0x6000,
        target_partitions=(("redispatched", (0x6000,)),),
        register_assumptions=(),
        memory_assumptions=(),
        instruction_budget=8,
        target_observation_ea=0x6001,
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.RESOLVED
    assert receipt.target == "redispatched"
    assert receipt.instruction_eas == (0x6000, 0x6001, 0x6002)


def test_hash_bound_malformed_fixture_preserves_atomic_effect_boundary() -> None:
    # Exact linked bytes for the second selector producer in
    # sub_7FFB0E1E69E0. The hand-checked native arithmetic produces
    # 0x199A79B7 and dispatches to the malformed LOCK SETO effect at 0x180098E44.
    code = (
        (0x180098DA8, bytes.fromhex("448b0d81780300")),
        (0x180098DAF, bytes.fromhex("458d916b66793d")),
        (0x180098DB6, bytes.fromhex("458d99ac080407")),
        (0x180098DBD, bytes.fromhex("4533da")),
        (0x180098DC0, bytes.fromhex("4181c12f559128")),
        (0x180098DC7, bytes.fromhex("4533cb")),
        (0x180098DCA, bytes.fromhex("4181f1bffcdb63")),
        (0x180098DD1, bytes.fromhex("44894c2404")),
        (0x180098DD6, bytes.fromhex("448b4c2404")),
        (0x180098DDB, bytes.fromhex("4181f92a908e6e")),
        (0x180098DE2, bytes.fromhex("7557")),
        (0x180098E3B, bytes.fromhex("4181f9b7799a19")),
        (0x180098E42, bytes.fromhex("7508")),
    )
    request = NativeTransitionRequest(
        instructions=tuple(NativeInstruction(ea, data) for ea, data in code),
        entry_ea=0x180098DA8,
        target_partitions=(
            ("atomic_lock_seto", (0x180098E44,)),
            ("return", (0x180098E4C,)),
        ),
        register_assumptions=(("rsp", 0x70008000),),
        memory_assumptions=(
            (0x1800D0630, bytes.fromhex("20926508")),
            (0x70000000, bytes(0x10000)),
        ),
        instruction_budget=32,
    )

    receipt = prove_native_transition(request)

    assert receipt.status is NativeTransitionStatus.RESOLVED
    assert receipt.target == "atomic_lock_seto"
    assert receipt.instruction_eas[-3:] == (
        0x180098DE2,
        0x180098E3B,
        0x180098E42,
    )


def test_e086_routes_omitted_by_old_golden_resolve_from_exact_native_bytes() -> None:
    references = e086be0_missing_native_slices(0x180000000)
    expected_targets = (
        "handler_8A5BB",
        "handler_8AFD5",
        "handler_8A988",
        "handler_8AD56",
        "handler_8A8B0",
    )

    receipts = []
    for reference in references:
        exact_bytes = {
            **{
                instruction.ea: instruction.data
                for instruction in reference.request.instructions
            },
            **dict(reference.linked_memory),
        }
        receipts.append(
            prove_linked_native_transition(
                reference,
                read_linked_bytes=lambda ea, size, exact_bytes=exact_bytes: (
                    exact_bytes.get(ea, b"")[:size]
                ),
            )
        )

    assert tuple(receipt.status for receipt in receipts) == (
        NativeTransitionStatus.RESOLVED,
    ) * 5
    assert tuple(receipt.target for receipt in receipts) == expected_targets
    assert tuple(receipt.selector_value for receipt in receipts) == (
        0x7ACCC969,
        0x76711AAE,
        0x51FAE032,
        0x7C35A383,
        0x4C815853,
    )


def test_e086_gs_peb_arm_resolves_with_explicit_segment_base() -> None:
    reference = e086be0_gs_selector_slice(0x180000000)
    exact_bytes = {
        **{
            instruction.ea: instruction.data
            for instruction in reference.request.instructions
        },
        **dict(reference.linked_memory),
    }

    receipt = prove_linked_native_transition(
        reference,
        read_linked_bytes=lambda ea, size: exact_bytes.get(ea, b"")[:size],
    )

    assert receipt.status is NativeTransitionStatus.RESOLVED
    assert receipt.target == "selector_3076403d"
    assert receipt.selector_value == 0x3076403D


def test_linked_slice_rejects_instruction_byte_drift_before_execution() -> None:
    reference = NativeImageSlice(
        image_base=0x180000000,
        request=_request(
            (0x180001000, bytes.fromhex("90")),
            targets=(("done", (0x180001001,)),),
        ),
        linked_memory=((0x180002000, bytes.fromhex("78563412")),),
    )

    receipt = prove_linked_native_transition(
        reference,
        read_linked_bytes=lambda ea, size: (
            bytes.fromhex("cc")
            if (ea, size) == (0x180001000, 1)
            else bytes.fromhex("78563412")
        ),
    )

    assert receipt.status is NativeTransitionStatus.UNRESOLVED
    assert receipt.reason == "linked_instruction_bytes_mismatch:0x180001000"
    assert receipt.instruction_eas == ()


def test_linked_slice_rejects_constant_data_drift_before_execution() -> None:
    reference = NativeImageSlice(
        image_base=0x180000000,
        request=_request(
            (0x180001000, bytes.fromhex("90")),
            targets=(("done", (0x180001001,)),),
        ),
        linked_memory=((0x180002000, bytes.fromhex("78563412")),),
    )

    receipt = prove_linked_native_transition(
        reference,
        read_linked_bytes=lambda ea, size: (
            bytes.fromhex("90")
            if (ea, size) == (0x180001000, 1)
            else bytes.fromhex("00000000")
        ),
    )

    assert receipt.status is NativeTransitionStatus.UNRESOLVED
    assert receipt.reason == "linked_memory_bytes_mismatch:0x180002000"
    assert receipt.instruction_eas == ()


def test_shared_state_write_enumerates_each_native_predecessor_arm() -> None:
    blocks = (
        NativeCfgBlock(0x1000, (0x1000,), (0x1200,), (), ()),
        NativeCfgBlock(0x1100, (0x1100,), (0x1200,), (), ()),
        NativeCfgBlock(
            0x1200,
            (0x1200,),
            (0x1300,),
            (0x1200,),
            (),
            (0x1200,),
        ),
        NativeCfgBlock(0x1300, (0x1300,), (0x1400, 0x1500), (), ()),
    )

    routes = enumerate_selector_routes(blocks, dispatcher_entries=(0x1300,))

    assert tuple(
        (route.source_ea, route.state_write_ea, route.dispatcher_entry_ea)
        for route in routes
    ) == (
        (0x1000, 0x1200, 0x1300),
        (0x1100, 0x1200, 0x1300),
    )


def test_locally_computed_state_write_is_one_route_despite_many_predecessors() -> None:
    blocks = (
        NativeCfgBlock(0x3000, (0x3000,), (0x3200,), (), ()),
        NativeCfgBlock(0x3100, (0x3100,), (0x3200,), (), ()),
        NativeCfgBlock(0x3200, (0x3200, 0x3204), (0x3300,), (0x3204,), ()),
        NativeCfgBlock(0x3300, (0x3300,), (), (), ()),
    )

    routes = enumerate_selector_routes(blocks, dispatcher_entries=(0x3300,))

    assert tuple((route.source_ea, route.state_write_ea) for route in routes) == (
        (0x3200, 0x3204),
    )


def test_live_in_merge_before_write_preserves_each_predecessor_arm() -> None:
    blocks = (
        NativeCfgBlock(0x5000, (0x5000,), (0x5300,), (), ()),
        NativeCfgBlock(0x5100, (0x5100,), (0x5300,), (), ()),
        NativeCfgBlock(0x5200, (0x5200,), (0x5300,), (), ()),
        NativeCfgBlock(
            0x5300,
            (0x5300, 0x5302),
            (0x5400,),
            (0x5302,),
            (),
            (0x5302,),
        ),
        NativeCfgBlock(0x5400, (0x5400,), (), (), ()),
    )

    routes = enumerate_selector_routes(blocks, dispatcher_entries=(0x5400,))

    assert tuple((route.source_ea, route.state_write_ea) for route in routes) == (
        (0x5000, 0x5302),
        (0x5100, 0x5302),
        (0x5200, 0x5302),
    )


def test_effects_in_rewritten_source_block_are_preserved_not_skipped() -> None:
    blocks = (
        NativeCfgBlock(
            0x4000,
            (0x4000, 0x4004, 0x4008),
            (0x4100,),
            (0x4004,),
            (0x4008,),
        ),
        NativeCfgBlock(0x4100, (0x4100,), (), (), ()),
    )

    routes = enumerate_selector_routes(blocks, dispatcher_entries=(0x4100,))

    assert tuple((route.source_ea, route.state_write_ea) for route in routes) == (
        (0x4000, 0x4004),
    )

def test_effectful_corridor_is_not_certified_as_selector_plumbing() -> None:
    blocks = (
        NativeCfgBlock(0x2000, (0x2000,), (0x2100,), (0x2000,), ()),
        NativeCfgBlock(0x2100, (0x2100,), (0x2200,), (), (0x2100,)),
        NativeCfgBlock(0x2200, (0x2200,), (), (), ()),
    )

    routes = enumerate_selector_routes(blocks, dispatcher_entries=(0x2200,))

    assert routes == ()
