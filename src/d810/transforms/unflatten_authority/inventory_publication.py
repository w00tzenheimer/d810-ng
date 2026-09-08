"""Owned inventory publication with separate occurrence-only export provenance.

The existing runtime arena retains origins. Internal readers use structural
values; an origin reference never proves that a mutable record is unchanged.
"""

from d810.core.runtime_identity import (
    RuntimeAuthorityArena, RuntimeAuthorityKind, RuntimeAuthorityRef,
)
from d810.core.structural_identity import StructuralNodeKind, StructuralRef, compare_values
from d810.core.typing import NamedTuple
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import NativeBlockRef, StableBlockIdentity
from d810.transforms.unflatten_authority import inventory_alias, inventory_inputs, inventory_values, model


class InventoryOrigin(NamedTuple):
    """Immutable coordinates for an occurrence in the existing runtime owner."""

    ordinal: int
    owner: object


class InventoryPublication(NamedTuple):
    root: StructuralRef
    origin: InventoryOrigin


def _require_arena(arena: RuntimeAuthorityArena) -> None:
    if type(arena) is not RuntimeAuthorityArena:
        raise TypeError("inventory publication requires the existing exact arena")


def _retain(arena: RuntimeAuthorityArena, value: object) -> InventoryOrigin:
    ref = arena.mint(RuntimeAuthorityKind.INVENTORY, value)
    # RuntimeAuthorityRef is a frozen dataclass, so retain immutable coordinates
    # rather than exposing a mutable-by-object.__setattr__ reference as a key.
    return InventoryOrigin(ref.ordinal, ref._owner)


def _origin(arena: RuntimeAuthorityArena, origin: InventoryOrigin) -> object:
    _require_arena(arena)
    if type(origin) is not InventoryOrigin:
        raise TypeError("inventory origin requires exact immutable coordinates")
    return arena.get(RuntimeAuthorityRef(
        RuntimeAuthorityKind.INVENTORY, origin.ordinal, origin.owner,
    ))


def publish_inventory(
    arena: RuntimeAuthorityArena, value: model.SemanticGraphInventory,
) -> InventoryPublication:
    """Validate ingress and captured content before retaining an origin."""
    _require_arena(arena)
    model.validate_semantic_graph_inventory(value)
    validated_digest = value.inventory_digest
    root = inventory_inputs.capture_inventory(arena.structural, value)
    # Replay the captured value itself. A public-before/public-after check can
    # miss a transient mutation that affected only the captured terms.
    detached = inventory_inputs.materialize_inventory(arena.structural, root)
    if detached.inventory_digest != validated_digest:
        raise ValueError("captured inventory differs from validated ingress")
    if inventory_inputs.capture_inventory(arena.structural, detached) is not root:
        raise ValueError("captured inventory constructor normalization differs")
    return InventoryPublication(root, _retain(arena, value))


def inventory_root(
    arena: RuntimeAuthorityArena, publication: InventoryPublication,
) -> StructuralRef:
    _require_arena(arena)
    if type(publication) is not InventoryPublication:
        raise TypeError("inventory publication requires its exact owned record")
    arena.structural.resolve(publication.root, StructuralNodeKind.SUBJECT)
    inventory_values.inventory_field(arena.structural, publication.root, "inventory_digest")
    return publication.root


def retain_inventory_row_origin(arena: RuntimeAuthorityArena, row: object) -> InventoryOrigin:
    """Retain a selected row only for later exact occurrence comparison."""
    _require_arena(arena)
    if type(row) not in (
        model.InventoryEffectSite, model.InventoryBlockObservation,
        model.InventoryInstructionObservation,
    ):
        raise TypeError("inventory origin requires an exact selected row")
    return _retain(arena, row)


def require_inventory_row_origin(
    arena: RuntimeAuthorityArena, origin: InventoryOrigin, row: object,
) -> None:
    if _origin(arena, origin) is not row:
        raise ValueError("inventory row occurrence changed before export")


def require_inventory_export(
    arena: RuntimeAuthorityArena, publication: InventoryPublication,
    value: model.SemanticGraphInventory,
) -> None:
    """Keep full public validation and exact origin checks at export."""
    root = inventory_root(arena, publication)
    if _origin(arena, publication.origin) is not value:
        raise ValueError("inventory occurrence changed before export")
    model.validate_semantic_graph_inventory(value)
    digest = inventory_values.scalar_value(
        arena.structural,
        inventory_values.inventory_field(arena.structural, root, "inventory_digest"),
    )
    if digest != value.inventory_digest:
        raise ValueError("inventory content changed before export")


class InventoryRowOccurrences(NamedTuple):
    """Temporary lexical export origins; never read their semantic fields."""

    inventory: object
    effects: tuple[object, ...]
    blocks: tuple[object, ...]
    instructions: tuple[tuple[object, ...], ...]


def snapshot_inventory_rows(value: model.SemanticGraphInventory) -> InventoryRowOccurrences:
    """Retain pre-capture row occurrences without granting validation."""
    if type(value) is not model.SemanticGraphInventory:
        raise TypeError("inventory occurrences require exact inventory")
    effects, blocks = value.effects, value.blocks
    if type(effects) is not tuple or type(blocks) is not tuple:
        raise TypeError("inventory occurrence collections require exact tuples")
    instructions = []
    for block in blocks:
        if type(block) is not model.InventoryBlockObservation:
            raise TypeError("inventory block occurrence has foreign type")
        rows = block.instruction_observations
        if type(rows) is not tuple:
            raise TypeError("inventory instruction occurrences require exact tuple")
        instructions.append(rows)
    return InventoryRowOccurrences(value, effects, blocks, tuple(instructions))


def retain_inventory_position_origin(
    arena: RuntimeAuthorityArena, publication: InventoryPublication,
    occurrences: InventoryRowOccurrences, family: str, position: tuple[int, ...],
) -> InventoryOrigin:
    """Retain a selected pre-capture occurrence by its original row path."""
    root = inventory_root(arena, publication)
    if type(occurrences) is not InventoryRowOccurrences:
        raise TypeError("inventory row path requires exact occurrence snapshot")
    if _origin(arena, publication.origin) is not occurrences.inventory:
        raise ValueError("inventory occurrence snapshot belongs to another root")
    if (type(family) is not str or type(position) is not tuple
            or any(type(index) is not int or index < 0 for index in position)):
        raise TypeError("inventory row path requires exact coordinates")
    table = arena.structural
    if family in ("effects", "blocks") and len(position) == 1:
        rows = inventory_values.sequence_children(table, inventory_values.inventory_field(table, root, family))
        original = occurrences.effects if family == "effects" else occurrences.blocks
        if len(rows) != len(original):
            raise ValueError("inventory occurrence path shape changed")
        if position[0] >= len(original):
            raise ValueError("inventory occurrence path is out of bounds")
        row = original[position[0]]
        expected_type = model.InventoryEffectSite if family == "effects" else model.InventoryBlockObservation
    elif family == "instructions" and len(position) == 2:
        blocks = inventory_values.sequence_children(table, inventory_values.inventory_field(table, root, "blocks"))
        if len(blocks) != len(occurrences.instructions):
            raise ValueError("inventory block occurrence path shape changed")
        block_index, instruction_index = position
        if block_index >= len(blocks):
            raise ValueError("inventory block occurrence path is out of bounds")
        rows = inventory_values.sequence_children(table, inventory_values.record_field(table, blocks[block_index], "instruction_observations"))
        original = occurrences.instructions[block_index]
        if len(rows) != len(original):
            raise ValueError("inventory instruction occurrence path shape changed")
        if instruction_index >= len(original):
            raise ValueError("inventory instruction occurrence path is out of bounds")
        row = original[instruction_index]
        expected_type = model.InventoryInstructionObservation
    else:
        raise ValueError("unsupported inventory occurrence path")
    if type(row) is not expected_type:
        raise TypeError("inventory occurrence path has a foreign row family")
    return retain_inventory_row_origin(arena, row)


class LocalAliasInputPublication(NamedTuple):
    """Copied grammar coordinates with occurrence-only public export origins."""

    inputs: inventory_alias.LocalAliasInputs
    scalar_state: tuple[object, ...]
    claim_origin: object
    fact_origin: object
    subject_origin: object
    owner_origin: object


def _local_alias_state(claim, fact):
    if type(claim) is not model.LocalAliasEffectScalarizationClaim:
        raise TypeError("claim must be LocalAliasEffectScalarizationClaim")
    if type(fact) is not model.PatchStepEvidencePayload:
        raise TypeError("patch_step_fact must be PatchStepEvidencePayload")
    subject = claim.owner_subject
    if type(subject) is not model.SemanticSubjectRef:
        raise TypeError("local alias requires exact owner subject")
    owner = subject.block_ref
    bitness = None
    if type(owner) is NativeBlockRef:
        identity = owner.identity
        if type(identity) is not StableBlockIdentity:
            raise TypeError("local alias requires exact native block identity")
        native_key = identity.native_key
        if type(native_key) is not NativePreanalysisKey:
            raise TypeError("local alias requires exact native key")
        bitness = native_key.bitness
    if bitness is not None and type(bitness) is not int:
        raise TypeError("local alias native width requires exact integer")
    state = (
        claim.step_index, claim.step_digest, subject.anchor_ea,
        claim.source_generation, claim.host_ea, claim.host_opcode,
        claim.value_size, None if bitness is None else bitness // 8,
        claim.alias_token, claim.base_token,
    )
    expected_types = (int, str, int, int, int, int, (int, type(None)),
                      (int, type(None)), str, str)
    if any(type(value) not in (expected if type(expected) is tuple else (expected,))
           for value, expected in zip(state, expected_types)):
        raise TypeError("local alias coordinates require exact scalar fields")
    fact_state = (fact.step_index, fact.step_digest, fact.host_ea, fact.host_opcode)
    if tuple(type(value) for value in fact_state) != (int, str, int, int):
        raise TypeError("local alias patch coordinates require exact scalars")
    if fact_state != (state[0], state[1], state[4], state[5]):
        raise ValueError("local-alias patch step does not match claim")
    return state, subject, owner


def publish_local_alias_inputs(
    source_arena: RuntimeAuthorityArena, projected_arena: RuntimeAuthorityArena,
    claim: model.LocalAliasEffectScalarizationClaim, fact: model.PatchStepEvidencePayload,
) -> LocalAliasInputPublication:
    _require_arena(source_arena)
    _require_arena(projected_arena)
    if source_arena is projected_arena:
        raise ValueError("local alias requires distinct source/projected owners")
    state, subject, owner = _local_alias_state(claim, fact)
    source_ref = inventory_inputs.capture_inventory_reference(source_arena.structural, owner)
    projected_ref = inventory_inputs.capture_inventory_reference(projected_arena.structural, owner)
    if not compare_values(source_arena.structural, source_ref, projected_arena.structural, projected_ref):
        raise ValueError("local alias source/projected owner captures differ")
    after, after_subject, after_owner = _local_alias_state(claim, fact)
    if state != after or subject is not after_subject or owner is not after_owner:
        raise ValueError("local alias claim changed during publication")
    inputs = inventory_alias.LocalAliasInputs(
        source_ref, projected_ref, state[2], state[3], state[4], state[5],
        state[6], state[7], state[8], state[9],
    )
    return LocalAliasInputPublication(inputs, state, claim, fact, subject, owner)


def require_local_alias_inputs_export(
    source_arena: RuntimeAuthorityArena, projected_arena: RuntimeAuthorityArena,
    publication: LocalAliasInputPublication,
    claim: model.LocalAliasEffectScalarizationClaim, fact: model.PatchStepEvidencePayload,
) -> None:
    _require_arena(source_arena)
    _require_arena(projected_arena)
    if type(publication) is not LocalAliasInputPublication:
        raise TypeError("local alias export requires exact publication")
    source_arena.structural.resolve(publication.inputs.source_owner, StructuralNodeKind.SUBJECT)
    projected_arena.structural.resolve(publication.inputs.projected_owner, StructuralNodeKind.SUBJECT)
    if publication.claim_origin is not claim or publication.fact_origin is not fact:
        raise ValueError("local alias claim/fact occurrence changed")
    state, subject, owner = _local_alias_state(claim, fact)
    if (state != publication.scalar_state or subject is not publication.subject_origin
            or owner is not publication.owner_origin):
        raise ValueError("local alias claim changed before export")
    # This fresh boundary check retains public descendant drift detection;
    # internal drafting/replay never recaptures the owner reference.
    if inventory_inputs.capture_inventory_reference(source_arena.structural, owner) is not publication.inputs.source_owner:
        raise ValueError("local alias owner changed before export")
    if inventory_inputs.capture_inventory_reference(projected_arena.structural, owner) is not publication.inputs.projected_owner:
        raise ValueError("local alias projected owner changed before export")
