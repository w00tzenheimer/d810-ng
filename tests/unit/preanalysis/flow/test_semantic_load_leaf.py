"""A fresh carrier load needs exact local provenance, not memory non-aliasing."""

from d810.analyses.control_flow.semantic_load_leaf import (
    prove_fresh_full_width_load_leaf,
)
from d810.ir.flowgraph import InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.insn_projection import instruction_source_trees_supported_for_semantic_load
from d810.ir.expressions import ValueOpKind
from d810.ir.instructions import (
    Instruction,
    InstructionControl,
    InstructionMemoryAccess,
    InstructionMemoryAccessKind,
)
from d810.ir.semantics import PredicateKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.ir.varnode import Space, Varnode


RAX = Varnode(Space.REGISTER, 8, 8)
R12 = Varnode(Space.REGISTER, 96, 8)
R8 = Varnode(Space.REGISTER, 64, 8)
STATE = Varnode(Space.STACK, 56, 8)
SAVED_ARG = Varnode(Space.STACK, 1448, 8)
OTHER = Varnode(Space.STACK, 1360, 8)
DS = Varnode(Space.REGISTER, 256, 2)


def _proof(
    blocks: dict[int, tuple[Instruction, ...]],
    predecessors: dict[int, tuple[int, ...]],
) -> bool:
    return prove_fresh_full_width_load_leaf(
        block_serial=3,
        entry_serial=0,
        projected_block=blocks.__getitem__,
        predecessors_of=predecessors.__getitem__,
        expected_state_identities=frozenset(
            {StorageIdentity(StorageIdentityKind.REGISTER, RAX.offset)}
        ),
        expected_state_width=8,
        selector_source_identities=frozenset(
            {StorageIdentity(StorageIdentityKind.STACK, STATE.offset)}
        ),
    )


def _leaf(*, address=R12, result=RAX) -> tuple[Instruction, ...]:
    return (
        Instruction(
            operation=ValueOpKind.LOAD,
            inputs=(DS, address),
            result=result,
            memory=InstructionMemoryAccess(
                kind=InstructionMemoryAccessKind.INDIRECT,
                segment=DS,
                target=address,
                width=result.size,
            ),
        ),
        Instruction(
            operation=ValueOpKind.LOAD,
            inputs=(DS, address),
            result=OTHER,
            memory=InstructionMemoryAccess(
                kind=InstructionMemoryAccessKind.INDIRECT,
                segment=DS,
                target=address,
                width=OTHER.size,
            ),
        ),
        Instruction(
            operation=ValueOpKind.MOVE,
            inputs=(RAX, OTHER),
            control=InstructionControl(predicate=PredicateKind.EQ),
        ),
    )


def test_entry_argument_and_saved_copy_prove_load_address_independent() -> None:
    blocks = {
        0: (
            Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),
            Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=SAVED_ARG),
        ),
        1: (Instruction(operation=ValueOpKind.MOVE, inputs=(SAVED_ARG,), result=R12),),
        2: (),
        3: _leaf(),
    }
    predecessors = {0: (), 1: (0, 2), 2: (1,), 3: (1,)}
    assert _proof(blocks, predecessors)


def test_selector_derived_address_is_not_a_semantic_leaf() -> None:
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(STATE,), result=R12),),
        3: _leaf(),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_partial_address_register_write_is_not_proved() -> None:
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),),
        3: (
            Instruction(
                operation=ValueOpKind.MOVE,
                inputs=(Varnode(Space.CONST, 1, 4),),
                result=Varnode(Space.REGISTER, R12.offset, 4),
            ),
            *_leaf(),
        ),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_old_carrier_read_before_load_is_not_proved() -> None:
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),),
        3: (
            Instruction(operation=ValueOpKind.MOVE, inputs=(RAX,), result=OTHER),
            *_leaf(),
        ),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_load_must_replace_full_carrier_width() -> None:
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),),
        3: _leaf(result=Varnode(Space.REGISTER, RAX.offset, 4)),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_carrier_in_load_address_is_not_proved() -> None:
    blocks = {0: (), 3: _leaf(address=RAX)}
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_nested_expression_may_use_only_the_fresh_carrier_definition() -> None:
    intermediate = Varnode(Space.TEMP, 0, 8)
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),),
        3: (
            _leaf()[0],
            Instruction(
                operation=ValueOpKind.SUB,
                inputs=(RAX, Varnode(Space.CONST, 1, 8)),
                result=intermediate,
                attrs={"ea": 0x1234},
            ),
            Instruction(
                operation=ValueOpKind.SAR,
                inputs=(intermediate, Varnode(Space.CONST, 4, 1)),
                result=OTHER,
                attrs={"ea": 0x1234},
            ),
            Instruction(
                operation=ValueOpKind.MOVE,
                inputs=(RAX, OTHER),
                control=InstructionControl(predicate=PredicateKind.EQ),
            ),
        ),
    }
    assert _proof(blocks, {0: (), 3: (0,)})


def test_temporary_without_exact_instruction_anchor_is_not_proved() -> None:
    intermediate = Varnode(Space.TEMP, 0, 8)
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),),
        3: (
            _leaf()[0],
            Instruction(
                operation=ValueOpKind.SUB,
                inputs=(RAX, Varnode(Space.CONST, 1, 8)),
                result=intermediate,
            ),
            Instruction(
                operation=ValueOpKind.SAR,
                inputs=(intermediate, Varnode(Space.CONST, 4, 1)),
                result=OTHER,
            ),
            Instruction(
                operation=ValueOpKind.MOVE,
                inputs=(RAX, OTHER),
                control=InstructionControl(predicate=PredicateKind.EQ),
            ),
        ),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_load_with_no_projected_address_is_not_proved() -> None:
    blocks = {
        0: (),
        3: (
            Instruction(operation=ValueOpKind.LOAD, result=RAX),
            Instruction(
                operation=ValueOpKind.MOVE,
                inputs=(RAX, Varnode(Space.CONST, 0, 8)),
                control=InstructionControl(predicate=PredicateKind.EQ),
            ),
        ),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_load_without_typed_memory_is_not_proved() -> None:
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),),
        3: (
            Instruction(operation=ValueOpKind.LOAD, inputs=(DS, R12), result=RAX),
            _leaf()[1],
            _leaf()[2],
        ),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_only_literal_global_address_wrapper_is_admitted() -> None:
    address = MopSnapshot(
        kind=OperandKind.ADDRESS,
        size=8,
        sub_l=MopSnapshot(kind=OperandKind.GLOBAL, gaddr=8, size=8),
    )
    assert instruction_source_trees_supported_for_semantic_load(
        InsnSnapshot(opcode=0, ea=1, operands=(), l=address)
    )
    assert not instruction_source_trees_supported_for_semantic_load(
        InsnSnapshot(opcode=0, ea=1, operands=(), l=MopSnapshot(
            kind=OperandKind.ADDRESS,
            size=8,
            sub_l=MopSnapshot(kind=OperandKind.STACK, stkoff=56, size=8),
        ))
    )
    assert not instruction_source_trees_supported_for_semantic_load(
        InsnSnapshot(
            opcode=0,
            ea=1,
            operands=(),
            l=MopSnapshot(kind=OperandKind.UNKNOWN, size=8),
        )
    )


def test_narrow_copy_cannot_define_full_address_register() -> None:
    blocks = {
        0: (
            Instruction(
                operation=ValueOpKind.MOVE,
                inputs=(Varnode(Space.REGISTER, R8.offset, 4),),
                result=R12,
            ),
        ),
        3: _leaf(),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_unsized_alias_write_cannot_be_ignored() -> None:
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),),
        3: (
            Instruction(
                operation=ValueOpKind.MOVE,
                inputs=(Varnode(Space.CONST, 1, 8),),
                result=Varnode(Space.REGISTER, R12.offset, 0),
            ),
            *_leaf(),
        ),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_hidden_predecessor_write_cannot_be_skipped() -> None:
    blocks = {
        0: (Instruction(operation=ValueOpKind.MOVE, inputs=(R8,), result=R12),),
        1: (
            Instruction(
                operation=ValueOpKind.VENDOR,
                result=R12,
                attrs={"unprojected_write": True},
            ),
        ),
        3: _leaf(),
    }
    assert not _proof(blocks, {0: (), 1: (0,), 3: (1,)})


def test_hidden_predecessor_source_cannot_prove_address() -> None:
    blocks = {
        0: (
            Instruction(
                operation=ValueOpKind.MOVE,
                inputs=(R8,),
                result=R12,
                attrs={"unprojected_source": True},
            ),
        ),
        3: _leaf(),
    }
    assert not _proof(blocks, {0: (), 3: (0,)})


def test_missing_predecessor_block_abstains_instead_of_raising() -> None:
    blocks = {0: (), 3: _leaf()}
    assert not _proof(blocks, {0: (), 3: (99,)})
