from d810.analyses.control_flow.call_abi import (
    StackCallAbiEvidence,
    project_detached_call_stack_point,
    prove_three_argument_callee_purged_call,
)


def _evidence(**overrides: object) -> StackCallAbiEvidence:
    values: dict[str, object] = {
        "word_size": 4,
        "outgoing_stack_offsets": (-12, -8, -4),
        "call_stack_deficit": 12,
        "argument_values_proven": True,
        "continuation_is_linear": True,
        "continuation_reaches_proven_reentry": True,
        "caller_stack_adjustment": 0,
        "has_authoritative_type": False,
    }
    values.update(overrides)
    return StackCallAbiEvidence(**values)


def test_proves_exact_three_argument_callee_purged_call() -> None:
    proof = prove_three_argument_callee_purged_call(_evidence())

    assert proof is not None
    assert proof.argument_count == 3
    assert proof.stack_argument_bytes == 12
    assert proof.callee_purges_stack


def test_rejects_nonmatching_argument_count_or_stack_topology() -> None:
    assert prove_three_argument_callee_purged_call(
        _evidence(outgoing_stack_offsets=(-8, -4), call_stack_deficit=8)
    ) is None
    assert prove_three_argument_callee_purged_call(
        _evidence(outgoing_stack_offsets=(-16, -8, -4))
    ) is None
    assert prove_three_argument_callee_purged_call(
        _evidence(outgoing_stack_offsets=(-12, -8, -4, -4))
    ) is None


def test_rejects_ambiguous_or_nonrejoining_continuation() -> None:
    assert prove_three_argument_callee_purged_call(
        _evidence(argument_values_proven=False)
    ) is None
    assert prove_three_argument_callee_purged_call(
        _evidence(continuation_is_linear=False)
    ) is None
    assert prove_three_argument_callee_purged_call(
        _evidence(continuation_reaches_proven_reentry=False)
    ) is None
    assert prove_three_argument_callee_purged_call(
        _evidence(caller_stack_adjustment=None)
    ) is None
    assert prove_three_argument_callee_purged_call(
        _evidence(caller_stack_adjustment=12)
    ) is None


def test_abstains_when_authoritative_type_exists() -> None:
    assert prove_three_argument_callee_purged_call(
        _evidence(has_authoritative_type=True)
    ) is None


def test_rejects_mismatched_call_stack_deficit() -> None:
    assert prove_three_argument_callee_purged_call(
        _evidence(call_stack_deficit=None)
    ) is None
    assert prove_three_argument_callee_purged_call(
        _evidence(call_stack_deficit=8)
    ) is None


def test_detached_call_stack_point_adds_missing_route_delta_once() -> None:
    assert (
        project_detached_call_stack_point(
            native_spd=-1168,
            canonical_spd=-1168,
            route_call_delta=-12,
        )
        == -1180
    )


def test_detached_call_stack_point_preserves_native_delta_already_present() -> None:
    assert (
        project_detached_call_stack_point(
            native_spd=-1180,
            canonical_spd=-1168,
            route_call_delta=-12,
        )
        == -1180
    )


def test_detached_call_stack_point_rejects_conflicting_or_positive_delta() -> None:
    assert (
        project_detached_call_stack_point(
            native_spd=-1176,
            canonical_spd=-1168,
            route_call_delta=-12,
        )
        is None
    )
    assert (
        project_detached_call_stack_point(
            native_spd=-1168,
            canonical_spd=-1168,
            route_call_delta=4,
        )
        is None
    )
