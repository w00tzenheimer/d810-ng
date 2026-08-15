from __future__ import annotations

import pytest

from d810.ir.edge_state_contract import (
    EdgeStateContract,
    MachineStateLocation,
    MachineStateLocationKind,
)

pytestmark = pytest.mark.pure_python


def _location(
    kind: MachineStateLocationKind = MachineStateLocationKind.REGISTER,
    identity: str = "rax",
    bit_offset: int = 0,
    bit_width: int = 64,
) -> MachineStateLocation:
    return MachineStateLocation(kind, identity, bit_offset, bit_width)


def _permitting_contract(**overrides: object) -> EdgeStateContract:
    rax = _location()
    values: dict[str, object] = {
        "required_target_inputs": (rax,),
        "proven_equivalent_inputs": (rax,),
        "source_stack_delta": 0,
        "target_stack_delta": 0,
        "proof_ids": ("single-iteration:edge-7",),
    }
    values.update(overrides)
    return EdgeStateContract(**values)  # type: ignore[arg-type]


def test_location_rejects_invalid_identity_and_bit_range() -> None:
    with pytest.raises(ValueError, match="identity"):
        _location(identity="  ")
    with pytest.raises(ValueError, match="bit_offset"):
        _location(bit_offset=-1)
    with pytest.raises(ValueError, match="bit_width"):
        _location(bit_width=0)


def test_location_rejects_malformed_field_types() -> None:
    with pytest.raises(TypeError, match="kind"):
        MachineStateLocation("register", "rax", 0, 64)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="bit_offset"):
        _location(bit_offset=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="bit_width"):
        _location(bit_width=8.0)  # type: ignore[arg-type]


def test_contract_canonicalizes_location_sets_and_proof_ids() -> None:
    rax = _location()
    zf = _location(MachineStateLocationKind.FLAGS, "rflags.zf", 6, 1)

    contract = EdgeStateContract(
        required_target_inputs=(rax, zf, rax),
        proven_equivalent_inputs=(zf, rax, zf),
        source_stack_delta=0,
        target_stack_delta=0,
        proof_ids=("proof-b", "proof-a", "proof-b"),
    )

    assert contract.required_target_inputs == (zf, rax)
    assert contract.proven_equivalent_inputs == (zf, rax)
    assert contract.proof_ids == ("proof-a", "proof-b")


@pytest.mark.parametrize(
    "overrides",
    [
        {"proven_equivalent_inputs": ()},
        {
            "skipped_observable_effects": (
                _location(MachineStateLocationKind.FLAGS, "rflags.zf", 6, 1),
            )
        },
        {"unpersisted_body_effects": (_location(),)},
        {"source_stack_delta": None},
        {"target_stack_delta": None},
        {"source_stack_delta": 8},
        {"proof_ids": ()},
        {"unresolved_aliases": True},
        {"unresolved_call_effects": True},
    ],
)
def test_contract_abstains_without_complete_positive_evidence(
    overrides: dict[str, object],
) -> None:
    assert _permitting_contract(**overrides).permits_control_only_relink is False


def test_contract_accepts_equivalent_live_inputs_and_dead_retained_effects() -> None:
    state = _location(MachineStateLocationKind.STACK, "stack:-8", 0, 32)
    contract = _permitting_contract(
        unpersisted_body_effects=(state,),
        proven_dead_body_effects=(state,),
    )

    assert contract.permits_control_only_relink is True


def test_contract_rejects_blank_proof_ids_and_non_location_members() -> None:
    with pytest.raises(ValueError, match="proof_ids"):
        _permitting_contract(proof_ids=("",))
    with pytest.raises(TypeError, match="required_target_inputs"):
        _permitting_contract(required_target_inputs=(object(),))
