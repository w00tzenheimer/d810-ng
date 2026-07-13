"""Tests for conservative residual microcode indirect-transfer proof."""
from __future__ import annotations

from dataclasses import replace

from d810.analyses.control_flow.residual_indirect_transfer import (
    ResidualTransferCandidate,
    ResidualStackStateCandidate,
    validate_residual_transfer,
    validate_stack_state_transfer,
)


def _candidate(**overrides) -> ResidualTransferCandidate:
    values = {
        "fragment_start_ea": 0x4000,
        "fragment_end_ea": 0x4040,
        "selector_stack_offset": 0x80,
        "condition_code": 0xD,
        "true_pointer_value": 0x5000,
        "false_pointer_value": 0x6000,
        "additive_base": 0x1000,
        "envelope_start_ea": 0x4000,
        "envelope_end_ea": 0x8000,
    }
    values.update(overrides)
    return ResidualTransferCandidate(**values)


def test_validates_stack_selected_two_way_residual_targets():
    proof = validate_residual_transfer(_candidate())

    assert proof is not None
    assert proof.fragment_start_ea == 0x4000
    assert proof.selector_stack_offset == 0x80
    assert proof.condition_code == 0xD
    assert proof.true_target_ea == 0x6000
    assert proof.false_target_ea == 0x7000


def test_abstains_when_microcode_facts_are_not_a_complete_stack_two_way_proof():
    assert validate_residual_transfer(_candidate(selector_stack_offset=None)) is None
    assert validate_residual_transfer(_candidate(condition_code=None)) is None
    assert validate_residual_transfer(_candidate(true_pointer_value=None)) is None
    assert validate_residual_transfer(_candidate(false_pointer_value=None)) is None
    assert validate_residual_transfer(_candidate(additive_base=None)) is None
    assert validate_residual_transfer(_candidate(fragment_end_ea=0x4000)) is None
    assert validate_residual_transfer(_candidate(true_pointer_value=0x9000)) is None


def test_validates_register_selected_two_way_residual_targets():
    proof = validate_residual_transfer(
        _candidate(selector_stack_offset=None, selector_register=3)
    )

    assert proof is not None
    assert proof.selector_stack_offset is None
    assert proof.selector_register == 3


def test_abstains_without_exactly_one_selector_storage_identity():
    assert validate_residual_transfer(
        _candidate(selector_stack_offset=None, selector_register=None)
    ) is None


def test_uses_proven_x86_address_width_for_additive_target_wraparound():
    proof = validate_residual_transfer(
        _candidate(
            true_pointer_value=0x02529D25,
            false_pointer_value=0x0252896F,
            additive_base=0xFDEE1C81,
            address_bits=32,
            envelope_start_ea=0x400000,
            envelope_end_ea=0x410000,
        )
    )

    assert proof is not None
    assert proof.true_target_ea == 0x40B9A6
    assert proof.false_target_ea == 0x40A5F0
    assert validate_residual_transfer(
        _candidate(selector_register=3)
    ) is None


def test_stack_state_proof_routes_prologue_arms_through_recovered_dispatcher():
    proof = validate_stack_state_transfer(
        ResidualStackStateCandidate(
            fragment_start_ea=0x4000,
            fragment_end_ea=0x4040,
            selector_stack_offset=0x80,
            predicate_ea=0x3000,
            predicate_condition_code=5,
            true_state=0xA0716E5B,
            false_state=0xEC71CA67,
            state_targets=(
                (0xA0716E5B, 0x6000),
                (0xEC71CA67, 0x7000),
            ),
            envelope_start_ea=0x4000,
            envelope_end_ea=0x8000,
        )
    )

    assert proof is not None
    assert proof.predicate_ea == 0x3000
    assert proof.condition_code == 5
    assert proof.true_target_ea == 0x6000
    assert proof.false_target_ea == 0x7000


def test_stack_state_proof_abstains_on_missing_or_ambiguous_state_route():
    candidate = ResidualStackStateCandidate(
        fragment_start_ea=0x4000,
        fragment_end_ea=0x4040,
        selector_stack_offset=0x80,
        predicate_ea=0x3000,
        predicate_condition_code=5,
        true_state=1,
        false_state=2,
        state_targets=((1, 0x6000),),
        envelope_start_ea=0x4000,
        envelope_end_ea=0x8000,
    )

    assert validate_stack_state_transfer(candidate) is None
    assert validate_stack_state_transfer(
        replace(candidate, state_targets=((1, 0x6000), (1, 0x6004), (2, 0x7000)))
    ) is None
