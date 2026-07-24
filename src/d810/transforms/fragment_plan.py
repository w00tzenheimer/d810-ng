"""Portable plans for detached, fragment-atomic semantic publication.

Canonical passes describe the semantic fragment they require with stable native
identities and plan-local block ids.  This contract deliberately contains no
live MBA object, block serial, logical proxy, or physical version coordinate.
The mutation gateway owns binding these references to the current MBA and
realizing the whole plan in one unpublished transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import json

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.ir.expressions import ValueOpKind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind


_BADADDR = 0xFFFFFFFFFFFFFFFF


class FragmentPlanRejected(ValueError):
    """A fragment plan is incomplete or internally inconsistent."""


class FragmentBlockRole(str, Enum):
    """Publication role of one plan-local block representation."""

    ORIGINAL = "original"
    REPLACEMENT = "replacement"
    EXTERNAL = "external"
    SYNTHETIC = "synthetic"
    IMPORTED = "imported"


class FragmentBlockMaterialization(str, Enum):
    """Portable instruction for realizing one plan-local block."""

    REUSE_PUBLISHED = "reuse_published"
    CLONE_PUBLISHED = "clone_published"
    CREATE_EMPTY = "create_empty"
    IMPORT_NATIVE = "import_native"


class FragmentPublicationPurpose(str, Enum):
    """Authority track advanced by a validated fragment publication."""

    FRONTEND_NORMALIZATION = "frontend_normalization"
    CANONICAL_SEMANTIC_LOWERING = "canonical_semantic_lowering"


@dataclass(frozen=True, slots=True)
class FragmentWorkItemScope:
    """Generation-local obligations owned by one fragment transaction."""

    work_item_id: str
    selected_obligation_ids: tuple[str, ...]
    remaining_obligation_ids: tuple[str, ...]
    unreachable_obligation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        work_item_id = _require_identifier(
            self.work_item_id,
            "fragment work item id",
        )
        selected = tuple(
            _require_identifier(value, "selected fragment obligation")
            for value in self.selected_obligation_ids
        )
        remaining = tuple(
            _require_identifier(value, "remaining fragment obligation")
            for value in self.remaining_obligation_ids
        )
        unreachable = tuple(
            _require_identifier(value, "root-unreachable fragment obligation")
            for value in self.unreachable_obligation_ids
        )
        if not selected:
            raise FragmentPlanRejected(
                "fragment work item requires selected obligations"
            )
        if (
            len(set(selected)) != len(selected)
            or len(set(remaining)) != len(remaining)
            or len(set(unreachable)) != len(unreachable)
        ):
            raise FragmentPlanRejected(
                "fragment work item contains duplicate obligations"
            )
        obligation_sets = tuple(map(set, (selected, remaining, unreachable)))
        if any(
            left & right
            for index, left in enumerate(obligation_sets)
            for right in obligation_sets[index + 1 :]
        ):
            raise FragmentPlanRejected(
                "selected, remaining, and root-unreachable fragment "
                "obligations must be disjoint"
            )
        object.__setattr__(self, "work_item_id", work_item_id)
        object.__setattr__(self, "selected_obligation_ids", selected)
        object.__setattr__(self, "remaining_obligation_ids", remaining)
        object.__setattr__(self, "unreachable_obligation_ids", unreachable)


class FragmentDataFlowRole(str, Enum):
    """Observable semantic responsibility protected by a data-flow proof."""

    CONDITION = "condition"
    CARRIER = "carrier"
    STATE_VALUE = "state_value"
    CALL = "call"
    CLEANUP = "cleanup"
    RETURN = "return"


class FragmentRangeObservation(str, Enum):
    """Exact instruction-time coordinate for a portable value-range proof."""

    BEFORE_INSTRUCTION = "before_instruction"
    AFTER_INSTRUCTION = "after_instruction"


class FragmentReturnSourceKind(str, Enum):
    """Portable shape assigned to the ABI return result."""

    CONSTANT = "constant"
    STORAGE_VALUE = "storage_value"
    ADDRESS_OF_STORAGE = "address_of_storage"


def _require_identifier(value: str, description: str) -> str:
    value = str(value).strip()
    if not value:
        raise FragmentPlanRejected(f"{description} must not be empty")
    return value


def _require_native_ea(value: int, description: str) -> int:
    value = int(value)
    if not 0 <= value < _BADADDR:
        raise FragmentPlanRejected(f"{description} must be a native EA")
    return value


@dataclass(frozen=True, slots=True)
class FragmentBlock:
    """One plan-local block representation with portable identity."""

    block_id: str
    role: FragmentBlockRole
    materialization: FragmentBlockMaterialization
    semantic_anchor_ea: int
    stable_identity: StableBlockIdentity | None = None
    replaces_block_id: str | None = None
    native_body_id: str | None = None

    def __post_init__(self) -> None:
        block_id = _require_identifier(self.block_id, "fragment block id")
        semantic_anchor_ea = _require_native_ea(
            self.semantic_anchor_ea,
            "fragment block semantic anchor",
        )
        if not isinstance(self.role, FragmentBlockRole):
            raise TypeError("fragment block requires a FragmentBlockRole")
        if not isinstance(self.materialization, FragmentBlockMaterialization):
            raise TypeError("fragment block requires a FragmentBlockMaterialization")

        required_materialization = {
            FragmentBlockRole.ORIGINAL: FragmentBlockMaterialization.REUSE_PUBLISHED,
            FragmentBlockRole.REPLACEMENT: FragmentBlockMaterialization.CLONE_PUBLISHED,
            FragmentBlockRole.EXTERNAL: FragmentBlockMaterialization.REUSE_PUBLISHED,
            FragmentBlockRole.SYNTHETIC: FragmentBlockMaterialization.CREATE_EMPTY,
            FragmentBlockRole.IMPORTED: FragmentBlockMaterialization.IMPORT_NATIVE,
        }[self.role]
        if self.materialization is not required_materialization:
            requirement = {
                FragmentBlockRole.ORIGINAL: "original fragment block must reuse published authority",
                FragmentBlockRole.REPLACEMENT: "replacement fragment block must clone its published original",
                FragmentBlockRole.EXTERNAL: "external fragment block must reuse published authority",
                FragmentBlockRole.SYNTHETIC: "synthetic fragment block must create an empty staged block",
                FragmentBlockRole.IMPORTED: "imported fragment block must materialize native body",
            }[self.role]
            raise FragmentPlanRejected(requirement)

        if self.role is FragmentBlockRole.SYNTHETIC:
            if self.stable_identity is not None:
                raise FragmentPlanRejected(
                    "synthetic fragment block cannot claim stable native identity"
                )
        elif not isinstance(self.stable_identity, StableBlockIdentity):
            raise FragmentPlanRejected(
                "non-synthetic fragment block requires stable native identity"
            )
        elif not self.stable_identity.native_ranges.contains(semantic_anchor_ea):
            raise FragmentPlanRejected(
                "fragment block semantic anchor must belong to its stable identity"
            )

        replaces_block_id = self.replaces_block_id
        if self.role is FragmentBlockRole.REPLACEMENT:
            if replaces_block_id is None:
                raise FragmentPlanRejected(
                    "replacement fragment block requires a replaced block id"
                )
            replaces_block_id = _require_identifier(
                replaces_block_id,
                "replaced fragment block id",
            )
            if replaces_block_id == block_id:
                raise FragmentPlanRejected(
                    "replacement and original require distinct plan-local ids"
                )
        elif replaces_block_id is not None:
            raise FragmentPlanRejected(
                "only a replacement fragment block may name a replaced block"
            )

        native_body_id = self.native_body_id
        if self.role is FragmentBlockRole.IMPORTED:
            if native_body_id is None:
                raise FragmentPlanRejected(
                    "imported fragment block requires a native body id"
                )
            native_body_id = _require_identifier(
                native_body_id,
                "fragment native body id",
            )
        elif native_body_id is not None:
            raise FragmentPlanRejected(
                "only an imported fragment block may name a native body"
            )

        object.__setattr__(self, "block_id", block_id)
        object.__setattr__(self, "semantic_anchor_ea", semantic_anchor_ea)
        object.__setattr__(self, "replaces_block_id", replaces_block_id)
        object.__setattr__(self, "native_body_id", native_body_id)


@dataclass(frozen=True, slots=True)
class FragmentNativeBody:
    """One closed native body staged without publishing any live root."""

    body_id: str
    block_ids: tuple[str, ...]
    entry_block_ids: tuple[str, ...]
    terminal_block_ids: tuple[str, ...]
    native_ranges: tuple[NativeEaInterval, ...]
    proof_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        body_id = _require_identifier(self.body_id, "fragment native body id")

        def identifiers(values: tuple[str, ...], description: str) -> tuple[str, ...]:
            normalized = tuple(
                _require_identifier(value, description) for value in values
            )
            if len(set(normalized)) != len(normalized):
                raise FragmentPlanRejected(
                    f"fragment native body contains duplicate {description}s"
                )
            return normalized

        block_ids = identifiers(self.block_ids, "block id")
        entry_block_ids = identifiers(self.entry_block_ids, "entry block id")
        terminal_block_ids = identifiers(
            self.terminal_block_ids,
            "terminal block id",
        )
        proof_ids = identifiers(self.proof_ids, "proof id")
        if not block_ids or not entry_block_ids or not proof_ids:
            raise FragmentPlanRejected(
                "fragment native body requires blocks, entries, and proofs"
            )
        if not set(entry_block_ids).issubset(block_ids):
            raise FragmentPlanRejected(
                "fragment native body entries must belong to the body"
            )
        if not set(terminal_block_ids).issubset(block_ids):
            raise FragmentPlanRejected(
                "fragment native body terminals must belong to the body"
            )
        native_ranges = tuple(self.native_ranges)
        if not native_ranges or any(
            not isinstance(native_range, NativeEaInterval)
            for native_range in native_ranges
        ):
            raise FragmentPlanRejected(
                "fragment native body requires native EA ranges"
            )
        if tuple(
            sorted(
                native_ranges,
                key=lambda native_range: (
                    native_range.start_ea,
                    native_range.end_ea,
                ),
            )
        ) != native_ranges:
            raise FragmentPlanRejected(
                "fragment native body ranges must be ordered"
            )
        for previous, current in zip(native_ranges, native_ranges[1:]):
            if current.start_ea < previous.end_ea:
                raise FragmentPlanRejected(
                    "fragment native body ranges must not overlap"
                )

        object.__setattr__(self, "body_id", body_id)
        object.__setattr__(self, "block_ids", block_ids)
        object.__setattr__(self, "entry_block_ids", entry_block_ids)
        object.__setattr__(self, "terminal_block_ids", terminal_block_ids)
        object.__setattr__(self, "native_ranges", native_ranges)
        object.__setattr__(self, "proof_ids", proof_ids)


@dataclass(frozen=True, slots=True)
class FragmentEdge:
    """One semantic destination in a fragment operation."""

    role: SemanticEdgeRole
    target_block_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, SemanticEdgeRole):
            raise TypeError("fragment edge requires a SemanticEdgeRole")
        object.__setattr__(
            self,
            "target_block_id",
            _require_identifier(self.target_block_id, "fragment edge target"),
        )


@dataclass(frozen=True, slots=True)
class FragmentConditionalSelectEnvelope:
    """Portable ownership of one live conditional-select lowering envelope."""

    predicate_ea: int
    observed_predicate_kind: PredicateKind
    selected_value_block_id: str
    join_block_id: str

    def __post_init__(self) -> None:
        predicate_ea = _require_native_ea(
            self.predicate_ea,
            "conditional-select predicate",
        )
        if not isinstance(self.observed_predicate_kind, PredicateKind):
            raise TypeError(
                "conditional-select envelope requires a PredicateKind"
            )
        selected_value_block_id = _require_identifier(
            self.selected_value_block_id,
            "conditional-select selected-value block",
        )
        join_block_id = _require_identifier(
            self.join_block_id,
            "conditional-select join block",
        )
        if selected_value_block_id == join_block_id:
            raise FragmentPlanRejected(
                "conditional-select envelope requires distinct selected-value "
                "and join blocks"
            )
        object.__setattr__(self, "predicate_ea", predicate_ea)
        object.__setattr__(
            self,
            "selected_value_block_id",
            selected_value_block_id,
        )
        object.__setattr__(self, "join_block_id", join_block_id)


@dataclass(frozen=True, slots=True)
class FragmentComputedBranchNormalization:
    """Typed proof for replacing one unresolved imported computed branch."""

    predicate_kind: PredicateKind
    normalization_start_ea: int
    condition_producer_ea: int
    unresolved_transfer_ea: int
    conditional_select_envelope: FragmentConditionalSelectEnvelope | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.predicate_kind, PredicateKind):
            raise TypeError(
                "computed branch normalization requires a PredicateKind"
            )
        normalization_start_ea = _require_native_ea(
            self.normalization_start_ea,
            "computed branch normalization start",
        )
        condition_producer_ea = _require_native_ea(
            self.condition_producer_ea,
            "computed branch condition producer",
        )
        unresolved_transfer_ea = _require_native_ea(
            self.unresolved_transfer_ea,
            "unresolved computed transfer",
        )
        if (
            normalization_start_ea == condition_producer_ea
            or normalization_start_ea == unresolved_transfer_ea
            or condition_producer_ea == unresolved_transfer_ea
        ):
            raise FragmentPlanRejected(
                "computed branch start, producer, and transfer require distinct "
                "anchors"
            )
        conditional_select_envelope = self.conditional_select_envelope
        if conditional_select_envelope is not None and not isinstance(
            conditional_select_envelope,
            FragmentConditionalSelectEnvelope,
        ):
            raise TypeError(
                "computed branch conditional-select envelope is invalid"
            )
        object.__setattr__(
            self,
            "normalization_start_ea",
            normalization_start_ea,
        )
        object.__setattr__(
            self,
            "condition_producer_ea",
            condition_producer_ea,
        )
        object.__setattr__(
            self,
            "unresolved_transfer_ea",
            unresolved_transfer_ea,
        )


@dataclass(frozen=True, slots=True)
class FragmentOperation:
    """One complete semantic control-flow operation inside a fragment."""

    operation_id: str
    source_block_id: str
    edges: tuple[FragmentEdge, ...]
    predicate_anchor_ea: int | None = None
    computed_branch_normalization: FragmentComputedBranchNormalization | None = None

    def __post_init__(self) -> None:
        operation_id = _require_identifier(
            self.operation_id,
            "fragment operation id",
        )
        source_block_id = _require_identifier(
            self.source_block_id,
            "fragment operation source",
        )
        edges = tuple(self.edges)
        if len(edges) not in {1, 2}:
            raise FragmentPlanRejected(
                "fragment operation requires one direct edge or both conditional roles"
            )
        if any(not isinstance(edge, FragmentEdge) for edge in edges):
            raise TypeError("fragment operation contains an invalid edge")
        roles = tuple(edge.role for edge in edges)
        if len(set(roles)) != len(roles):
            raise FragmentPlanRejected(
                "fragment operation requires unique semantic edge roles"
            )

        conditional_roles = frozenset(
            {
                SemanticEdgeRole.CONDITIONAL_TAKEN,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        )
        predicate_anchor_ea = self.predicate_anchor_ea
        computed_branch_normalization = self.computed_branch_normalization
        if computed_branch_normalization is not None and not isinstance(
            computed_branch_normalization,
            FragmentComputedBranchNormalization,
        ):
            raise TypeError(
                "fragment operation computed branch normalization is invalid"
            )
        if len(edges) == 1:
            if edges[0].role not in {
                SemanticEdgeRole.DIRECT,
                SemanticEdgeRole.CALL_FALLTHROUGH,
            }:
                raise FragmentPlanRejected(
                    "fragment conditional requires both conditional roles"
                )
            if predicate_anchor_ea is not None:
                raise FragmentPlanRejected(
                    "fragment predicate belongs only to a complete conditional"
                )
            if computed_branch_normalization is not None:
                raise FragmentPlanRejected(
                    "computed branch normalization belongs only to a "
                    "complete conditional"
                )
        else:
            if frozenset(roles) != conditional_roles:
                raise FragmentPlanRejected(
                    "fragment conditional requires both conditional roles"
                )
            if predicate_anchor_ea is None:
                raise FragmentPlanRejected(
                    "fragment conditional requires a predicate anchor"
                )
            if edges[0].target_block_id == edges[1].target_block_id:
                raise FragmentPlanRejected(
                    "fragment conditional requires distinct destinations"
                )
            predicate_anchor_ea = _require_native_ea(
                predicate_anchor_ea,
                "fragment predicate anchor",
            )

        object.__setattr__(self, "operation_id", operation_id)
        object.__setattr__(self, "source_block_id", source_block_id)
        object.__setattr__(self, "edges", edges)
        object.__setattr__(self, "predicate_anchor_ea", predicate_anchor_ea)

    @property
    def roles(self) -> frozenset[SemanticEdgeRole]:
        return frozenset(edge.role for edge in self.edges)


@dataclass(frozen=True, slots=True)
class FragmentReturnSource:
    """Portable value materialized into the ABI return result."""

    kind: FragmentReturnSourceKind
    width: int
    storage_identity: StorageIdentity | None = None
    constant: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, FragmentReturnSourceKind):
            raise TypeError("fragment return source requires a typed source kind")
        width = int(self.width)
        if not 1 <= width <= 8:
            raise FragmentPlanRejected(
                "fragment return source width must be 1..8 bytes"
            )
        storage_identity = self.storage_identity
        constant = self.constant
        if self.kind is FragmentReturnSourceKind.CONSTANT:
            if storage_identity is not None:
                raise FragmentPlanRejected(
                    "constant fragment return source cannot name storage"
                )
            if constant is None or not 0 <= int(constant) < (1 << (width * 8)):
                raise FragmentPlanRejected(
                    "fragment return constant must fit its source width"
                )
            constant = int(constant)
        else:
            if not isinstance(storage_identity, StorageIdentity):
                raise FragmentPlanRejected(
                    "storage fragment return source requires stable storage identity"
                )
            if storage_identity.kind not in {
                StorageIdentityKind.STACK,
                StorageIdentityKind.GLOBAL,
            }:
                raise FragmentPlanRejected(
                    "fragment return source supports only stable stack or global storage"
                )
            if int(storage_identity.offset) < 0:
                raise FragmentPlanRejected(
                    "fragment return storage offset must be non-negative"
                )
            if constant is not None:
                raise FragmentPlanRejected(
                    "storage fragment return source cannot carry a constant"
                )
        object.__setattr__(self, "width", width)
        object.__setattr__(self, "constant", constant)


@dataclass(frozen=True, slots=True)
class FragmentReturnCarrier:
    """One staged assignment to the ABI return result."""

    carrier_id: str
    block_id: str
    state_write_ea: int
    carrier_ea: int
    operation: ValueOpKind
    source: FragmentReturnSource
    return_width: int
    corridor_instruction_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        carrier_id = _require_identifier(
            self.carrier_id,
            "fragment return carrier id",
        )
        block_id = _require_identifier(
            self.block_id,
            "fragment return carrier block",
        )
        state_write_ea = _require_native_ea(
            self.state_write_ea,
            "fragment return carrier state-write anchor",
        )
        carrier_ea = _require_native_ea(
            self.carrier_ea,
            "fragment return carrier anchor",
        )
        if state_write_ea == carrier_ea:
            raise FragmentPlanRejected(
                "fragment return state write and carrier require distinct anchors"
            )
        if self.operation not in {
            ValueOpKind.MOVE,
            ValueOpKind.ZEXT,
            ValueOpKind.SEXT,
        }:
            raise FragmentPlanRejected(
                "fragment return carrier operation must be move, "
                "zero-extension, or sign-extension"
            )
        if not isinstance(self.source, FragmentReturnSource):
            raise TypeError("fragment return carrier requires a portable source")
        return_width = int(self.return_width)
        if not 1 <= return_width <= 8:
            raise FragmentPlanRejected(
                "fragment return width must be 1..8 bytes"
            )
        if (
            self.operation is ValueOpKind.MOVE
            and self.source.width != return_width
        ):
            raise FragmentPlanRejected(
                "fragment return move source and result widths must match"
            )
        if self.operation in {ValueOpKind.ZEXT, ValueOpKind.SEXT} and not (
            self.source.width < return_width
        ):
            raise FragmentPlanRejected(
                "fragment return extension must widen its source"
            )
        corridor_instruction_eas = tuple(
            _require_native_ea(ea, "fragment return carrier corridor anchor")
            for ea in self.corridor_instruction_eas
        )
        if (
            len(corridor_instruction_eas) < 2
            or corridor_instruction_eas[0] != state_write_ea
            or corridor_instruction_eas[-1] != carrier_ea
            or len(set(corridor_instruction_eas))
            != len(corridor_instruction_eas)
        ):
            raise FragmentPlanRejected(
                "fragment return carrier corridor must run uniquely "
                "from state write to carrier"
            )
        object.__setattr__(self, "carrier_id", carrier_id)
        object.__setattr__(self, "block_id", block_id)
        object.__setattr__(self, "state_write_ea", state_write_ea)
        object.__setattr__(self, "carrier_ea", carrier_ea)
        object.__setattr__(self, "return_width", return_width)
        object.__setattr__(
            self,
            "corridor_instruction_eas",
            corridor_instruction_eas,
        )


@dataclass(frozen=True, slots=True)
class FragmentTerminalReturn:
    """One staged terminal return instruction."""

    return_id: str
    block_id: str
    instruction_ea: int
    return_width: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "return_id",
            _require_identifier(self.return_id, "fragment terminal return id"),
        )
        object.__setattr__(
            self,
            "block_id",
            _require_identifier(self.block_id, "fragment terminal return block"),
        )
        object.__setattr__(
            self,
            "instruction_ea",
            _require_native_ea(
                self.instruction_ea,
                "fragment terminal return anchor",
            ),
        )
        return_width = int(self.return_width)
        if not 1 <= return_width <= 8:
            raise FragmentPlanRejected(
                "fragment terminal return width must be 1..8 bytes"
            )
        object.__setattr__(self, "return_width", return_width)


@dataclass(frozen=True, slots=True)
class FragmentTerminalRoute:
    """Atomic link between one route, return carrier, and terminal return."""

    terminal_route_id: str
    operation_id: str
    carrier_id: str
    return_id: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "terminal_route_id",
            _require_identifier(
                self.terminal_route_id,
                "fragment terminal route id",
            ),
        )
        object.__setattr__(
            self,
            "operation_id",
            _require_identifier(
                self.operation_id,
                "fragment terminal route operation",
            ),
        )
        object.__setattr__(
            self,
            "carrier_id",
            _require_identifier(
                self.carrier_id,
                "fragment terminal route carrier",
            ),
        )
        object.__setattr__(
            self,
            "return_id",
            _require_identifier(
                self.return_id,
                "fragment terminal route return",
            ),
        )


@dataclass(frozen=True, slots=True)
class FragmentValueSite:
    """Plan-local value definition or use at one stable semantic anchor."""

    site_id: str
    block_id: str
    value_id: str
    instruction_ea: int
    storage_identity: StorageIdentity | None = None
    width: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "site_id",
            _require_identifier(self.site_id, "fragment value site id"),
        )
        object.__setattr__(
            self,
            "block_id",
            _require_identifier(self.block_id, "fragment value site block"),
        )
        object.__setattr__(
            self,
            "value_id",
            _require_identifier(self.value_id, "fragment value id"),
        )
        object.__setattr__(
            self,
            "instruction_ea",
            _require_native_ea(
                self.instruction_ea,
                "fragment value site instruction",
            ),
        )
        storage_identity = self.storage_identity
        width = int(self.width)
        if storage_identity is None:
            if width != 0:
                raise FragmentPlanRejected(
                    "fragment value site without storage identity must have zero width"
                )
        elif not isinstance(storage_identity, StorageIdentity):
            raise TypeError(
                "fragment value site storage identity requires a StorageIdentity"
            )
        elif width <= 0:
            raise FragmentPlanRejected(
                "fragment value site with storage identity requires positive width"
            )
        object.__setattr__(self, "width", width)


@dataclass(frozen=True, slots=True)
class FragmentDataFlowObligation:
    """One definition whose complete use-def and def-use relation must survive."""

    obligation_id: str
    role: FragmentDataFlowRole
    definition: FragmentValueSite
    uses: tuple[FragmentValueSite, ...]

    def __post_init__(self) -> None:
        obligation_id = _require_identifier(
            self.obligation_id,
            "fragment data-flow obligation id",
        )
        if not isinstance(self.role, FragmentDataFlowRole):
            raise TypeError("fragment data-flow obligation requires a semantic role")
        if not isinstance(self.definition, FragmentValueSite):
            raise TypeError("fragment data-flow definition requires a value site")
        if self.definition.storage_identity is None:
            raise FragmentPlanRejected(
                "fragment data-flow definition requires portable storage identity"
            )
        uses = tuple(self.uses)
        if not uses or any(not isinstance(use, FragmentValueSite) for use in uses):
            raise FragmentPlanRejected(
                "fragment data-flow obligation requires one or more value uses"
            )
        if len({use.site_id for use in uses}) != len(uses):
            raise FragmentPlanRejected(
                "fragment data-flow obligation contains duplicate use sites"
            )
        if any(use.value_id != self.definition.value_id for use in uses):
            raise FragmentPlanRejected(
                "fragment data-flow definition and uses must name one value"
            )
        if any(use.storage_identity is None for use in uses):
            raise FragmentPlanRejected(
                "fragment data-flow uses require portable storage identity"
            )
        if any(
            use.storage_identity != self.definition.storage_identity
            or use.width != self.definition.width
            for use in uses
        ):
            raise FragmentPlanRejected(
                "fragment data-flow definition and uses require one storage identity and width"
            )
        if any(use.site_id == self.definition.site_id for use in uses):
            raise FragmentPlanRejected(
                "fragment data-flow definition and uses require distinct sites"
            )
        object.__setattr__(self, "obligation_id", obligation_id)
        object.__setattr__(self, "uses", uses)


@dataclass(frozen=True, slots=True)
class FragmentFlagCorridor:
    """Ordered flag producer-to-consumer corridor with explicit writers."""

    corridor_id: str
    producer: FragmentValueSite
    consumer: FragmentValueSite
    block_path: tuple[str, ...]
    permitted_flag_write_eas: frozenset[int]

    def __post_init__(self) -> None:
        corridor_id = _require_identifier(
            self.corridor_id,
            "fragment flag corridor id",
        )
        if not isinstance(self.producer, FragmentValueSite) or not isinstance(
            self.consumer,
            FragmentValueSite,
        ):
            raise TypeError("fragment flag corridor requires value sites")
        if self.producer.value_id != self.consumer.value_id:
            raise FragmentPlanRejected(
                "fragment flag producer and consumer must name one value"
            )
        block_path = tuple(
            _require_identifier(block_id, "fragment flag corridor block")
            for block_id in self.block_path
        )
        if not block_path or block_path[0] != self.producer.block_id:
            raise FragmentPlanRejected(
                "fragment flag corridor must start at its producer block"
            )
        if block_path[-1] != self.consumer.block_id:
            raise FragmentPlanRejected(
                "fragment flag corridor must end at its consumer block"
            )
        permitted_flag_write_eas = frozenset(
            _require_native_ea(ea, "permitted fragment flag writer")
            for ea in self.permitted_flag_write_eas
        )
        if self.producer.instruction_ea not in permitted_flag_write_eas:
            raise FragmentPlanRejected(
                "fragment flag corridor must permit its producer write"
            )
        object.__setattr__(self, "corridor_id", corridor_id)
        object.__setattr__(self, "block_path", block_path)
        object.__setattr__(
            self,
            "permitted_flag_write_eas",
            permitted_flag_write_eas,
        )


@dataclass(frozen=True, slots=True)
class FragmentRangeAssumption:
    """Inclusive portable range required at one fragment value site."""

    assumption_id: str
    site: FragmentValueSite
    observation: FragmentRangeObservation
    lo: int | None = None
    hi: int | None = None

    def __post_init__(self) -> None:
        assumption_id = _require_identifier(
            self.assumption_id,
            "fragment range assumption id",
        )
        if not isinstance(self.site, FragmentValueSite):
            raise TypeError("fragment range assumption requires a value site")
        if self.site.storage_identity is None:
            raise FragmentPlanRejected(
                "fragment range assumption requires portable storage identity"
            )
        if not isinstance(self.observation, FragmentRangeObservation):
            raise TypeError(
                "fragment range assumption requires an instruction observation"
            )
        if not 1 <= self.site.width <= 8:
            raise FragmentPlanRejected(
                "fragment range assumption requires a 1..8 byte value site"
            )
        lo = None if self.lo is None else int(self.lo)
        hi = None if self.hi is None else int(self.hi)
        if lo is None and hi is None:
            raise FragmentPlanRejected(
                "fragment range assumption requires at least one bound"
            )
        if lo is not None and hi is not None and lo > hi:
            raise FragmentPlanRejected(
                "fragment range assumption lower bound exceeds upper bound"
            )
        max_unsigned = (1 << (self.site.width * 8)) - 1
        if any(
            bound is not None and not 0 <= bound <= max_unsigned
            for bound in (lo, hi)
        ):
            raise FragmentPlanRejected(
                "fragment range bounds must fit the unsigned site width"
            )
        object.__setattr__(self, "assumption_id", assumption_id)
        object.__setattr__(self, "lo", lo)
        object.__setattr__(self, "hi", hi)


@dataclass(frozen=True, slots=True)
class FragmentPlan:
    """Complete portable intent for one atomic semantic publication."""

    plan_id: str
    atomic_group_id: str
    publication_purpose: FragmentPublicationPurpose
    native_key: NativePreanalysisKey
    blocks: tuple[FragmentBlock, ...]
    roots: tuple[str, ...]
    owned_originals: tuple[str, ...]
    prohibited_dispatcher_blocks: tuple[str, ...]
    operations: tuple[FragmentOperation, ...]
    work_item_scope: FragmentWorkItemScope | None = None
    return_carriers: tuple[FragmentReturnCarrier, ...] = ()
    terminal_returns: tuple[FragmentTerminalReturn, ...] = ()
    terminal_routes: tuple[FragmentTerminalRoute, ...] = ()
    native_bodies: tuple[FragmentNativeBody, ...] = ()
    data_flow_obligations: tuple[FragmentDataFlowObligation, ...] = ()
    flag_corridors: tuple[FragmentFlagCorridor, ...] = ()
    value_range_assumptions: tuple[FragmentRangeAssumption, ...] = ()

    def __post_init__(self) -> None:
        plan_id = _require_identifier(self.plan_id, "fragment plan id")
        atomic_group_id = _require_identifier(
            self.atomic_group_id,
            "fragment atomic group id",
        )
        if not isinstance(self.publication_purpose, FragmentPublicationPurpose):
            raise TypeError(
                "fragment plan requires a FragmentPublicationPurpose"
            )
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("fragment plan requires a native preanalysis key")
        work_item_scope = self.work_item_scope
        if (
            self.publication_purpose
            is FragmentPublicationPurpose.FRONTEND_NORMALIZATION
        ):
            if not isinstance(work_item_scope, FragmentWorkItemScope):
                raise FragmentPlanRejected(
                    "frontend-normalization plan requires one work-item scope"
                )
        elif work_item_scope is not None:
            raise FragmentPlanRejected(
                "canonical semantic plan cannot claim frontend work-item scope"
            )

        blocks = tuple(self.blocks)
        if not blocks or any(not isinstance(block, FragmentBlock) for block in blocks):
            raise FragmentPlanRejected("fragment plan requires portable blocks")
        block_by_id = {block.block_id: block for block in blocks}
        if len(block_by_id) != len(blocks):
            raise FragmentPlanRejected("fragment plan contains duplicate block ids")
        for block in blocks:
            identity = block.stable_identity
            if identity is not None and identity.native_key != self.native_key:
                raise FragmentPlanRejected(
                    f"fragment block {block.block_id!r} native identity mismatch"
                )

        roots = self._normalize_block_ids(self.roots, "fragment root")
        if not roots:
            raise FragmentPlanRejected("fragment plan requires publication roots")
        for root in roots:
            block = block_by_id.get(root)
            if block is None:
                raise FragmentPlanRejected(f"fragment root {root!r} is unknown")
            if block.role is not FragmentBlockRole.REPLACEMENT:
                raise FragmentPlanRejected(
                    f"fragment root {root!r} must be a replacement block"
                )

        owned_originals = self._normalize_block_ids(
            self.owned_originals,
            "owned original",
        )
        for block_id in owned_originals:
            block = block_by_id.get(block_id)
            if block is None:
                raise FragmentPlanRejected(f"owned original {block_id!r} is unknown")
            if block.role is not FragmentBlockRole.ORIGINAL:
                raise FragmentPlanRejected(
                    f"owned original {block_id!r} has the wrong block role"
                )

        prohibited_dispatcher_blocks = self._normalize_block_ids(
            self.prohibited_dispatcher_blocks,
            "prohibited dispatcher block",
        )
        for block_id in prohibited_dispatcher_blocks:
            if block_id not in block_by_id:
                raise FragmentPlanRejected(
                    f"prohibited dispatcher block {block_id!r} is unknown"
                )
            if block_id in roots:
                raise FragmentPlanRejected(
                    "fragment root cannot also be a prohibited dispatcher block"
                )

        for block in blocks:
            if block.role is not FragmentBlockRole.REPLACEMENT:
                continue
            original = block_by_id.get(str(block.replaces_block_id))
            if original is None or original.role is not FragmentBlockRole.ORIGINAL:
                raise FragmentPlanRejected(
                    f"replacement {block.block_id!r} must name an original block"
                )
            if original.block_id not in owned_originals:
                raise FragmentPlanRejected(
                    f"replacement {block.block_id!r} must own its replaced original"
                )
            if block.stable_identity != original.stable_identity:
                raise FragmentPlanRejected(
                    f"replacement {block.block_id!r} stable identity must match "
                    f"original {original.block_id!r}"
                )

        native_bodies = tuple(self.native_bodies)
        if any(
            not isinstance(native_body, FragmentNativeBody)
            for native_body in native_bodies
        ):
            raise TypeError("fragment plan contains an invalid native body")
        self._require_unique_ids(
            (native_body.body_id for native_body in native_bodies),
            "fragment native body",
        )
        native_body_by_id = {
            native_body.body_id: native_body for native_body in native_bodies
        }
        imported_block_ids = {
            block.block_id
            for block in blocks
            if block.role is FragmentBlockRole.IMPORTED
        }
        claimed_imported_block_ids: set[str] = set()
        for native_body in native_bodies:
            for block_id in native_body.block_ids:
                block = block_by_id.get(block_id)
                if block is None or block.role is not FragmentBlockRole.IMPORTED:
                    raise FragmentPlanRejected(
                        f"native body {native_body.body_id!r} contains a "
                        "non-imported block"
                    )
                if block.native_body_id != native_body.body_id:
                    raise FragmentPlanRejected(
                        f"imported block {block_id!r} names a different native body"
                    )
                if block_id in claimed_imported_block_ids:
                    raise FragmentPlanRejected(
                        f"imported block {block_id!r} belongs to multiple native bodies"
                    )
                claimed_imported_block_ids.add(block_id)
                identity = block.stable_identity
                if identity is None or any(
                    not any(
                        body_range.start_ea <= interval.start_ea
                        and interval.end_ea <= body_range.end_ea
                        for body_range in native_body.native_ranges
                    )
                    for interval in identity.native_ranges.intervals
                ):
                    raise FragmentPlanRejected(
                        f"imported block {block_id!r} lies outside its native body"
                    )
        if claimed_imported_block_ids != imported_block_ids:
            raise FragmentPlanRejected(
                "every imported fragment block must belong to one native body"
            )
        for block in blocks:
            if (
                block.role is FragmentBlockRole.IMPORTED
                and block.native_body_id not in native_body_by_id
            ):
                raise FragmentPlanRejected(
                    f"imported block {block.block_id!r} has an unknown native body"
                )

        operations = tuple(self.operations)
        if not operations or any(
            not isinstance(operation, FragmentOperation) for operation in operations
        ):
            raise FragmentPlanRejected("fragment plan requires semantic operations")
        self._require_unique_ids(
            (operation.operation_id for operation in operations),
            "fragment operation",
        )
        self._require_unique_ids(
            (operation.source_block_id for operation in operations),
            "fragment operation source",
        )
        for operation in operations:
            source = block_by_id.get(operation.source_block_id)
            if source is None:
                raise FragmentPlanRejected(
                    f"fragment operation {operation.operation_id!r} has unknown source block"
                )
            if source.role not in {
                FragmentBlockRole.REPLACEMENT,
                FragmentBlockRole.SYNTHETIC,
                FragmentBlockRole.IMPORTED,
            }:
                raise FragmentPlanRejected(
                    f"fragment operation {operation.operation_id!r} must execute on "
                    "a staged replacement, synthetic, or imported block"
                )
            if operation.predicate_anchor_ea is not None:
                identity = source.stable_identity
                if identity is not None and not identity.native_ranges.contains(
                    operation.predicate_anchor_ea
                ):
                    raise FragmentPlanRejected(
                        f"fragment operation {operation.operation_id!r} predicate "
                        "anchor does not belong to its source identity"
                    )
            computed_normalization = (
                operation.computed_branch_normalization
            )
            if computed_normalization is not None:
                if self.publication_purpose is not (
                    FragmentPublicationPurpose.FRONTEND_NORMALIZATION
                ):
                    raise FragmentPlanRejected(
                        f"fragment operation {operation.operation_id!r} "
                        "computed branch normalization requires a "
                        "frontend-normalization plan"
                    )
                envelope = computed_normalization.conditional_select_envelope
                identity = source.stable_identity
                if identity is None:
                    raise FragmentPlanRejected(
                        f"fragment operation {operation.operation_id!r} "
                        "computed branch source lacks stable identity"
                    )
                if envelope is None:
                    if source.role is not FragmentBlockRole.IMPORTED:
                        raise FragmentPlanRejected(
                            f"fragment operation {operation.operation_id!r} "
                            "computed branch suffix normalization requires an "
                            "imported source"
                        )
                    if any(
                        not identity.native_ranges.contains(ea)
                        for ea in (
                            computed_normalization.normalization_start_ea,
                            computed_normalization.condition_producer_ea,
                            computed_normalization.unresolved_transfer_ea,
                        )
                    ):
                        raise FragmentPlanRejected(
                            f"fragment operation {operation.operation_id!r} "
                            "computed branch anchors do not belong to its source "
                            "identity"
                        )
                    native_body = native_body_by_id.get(
                        str(source.native_body_id)
                    )
                    if (
                        native_body is None
                        or operation.operation_id not in native_body.proof_ids
                    ):
                        raise FragmentPlanRejected(
                            f"fragment operation {operation.operation_id!r} "
                            "computed branch normalization lacks native-body "
                            "proof ownership"
                        )
                else:
                    if source.role is not FragmentBlockRole.REPLACEMENT:
                        raise FragmentPlanRejected(
                            f"fragment operation {operation.operation_id!r} "
                            "conditional-select normalization requires a "
                            "replacement source"
                        )
                    source_anchors = (
                        computed_normalization.normalization_start_ea,
                        computed_normalization.condition_producer_ea,
                        operation.predicate_anchor_ea,
                        envelope.predicate_ea,
                    )
                    if any(
                        ea is None or not identity.native_ranges.contains(ea)
                        for ea in source_anchors
                    ):
                        raise FragmentPlanRejected(
                            f"fragment operation {operation.operation_id!r} "
                            "conditional-select source anchors do not belong to "
                            "its replacement identity"
                        )
                    selected = block_by_id.get(
                        envelope.selected_value_block_id
                    )
                    join = block_by_id.get(envelope.join_block_id)
                    if (
                        selected is None
                        or join is None
                        or selected.role is not FragmentBlockRole.EXTERNAL
                        or join.role is not FragmentBlockRole.EXTERNAL
                        or selected.stable_identity is None
                        or join.stable_identity is None
                        or not selected.stable_identity.native_ranges.contains(
                            envelope.predicate_ea
                        )
                        or not join.stable_identity.native_ranges.contains(
                            computed_normalization.unresolved_transfer_ea
                        )
                    ):
                        raise FragmentPlanRejected(
                            f"fragment operation {operation.operation_id!r} "
                            "conditional-select envelope does not own its "
                            "published copy and join anchors"
                        )
            for edge in operation.edges:
                if edge.target_block_id not in block_by_id:
                    raise FragmentPlanRejected(
                        f"fragment operation {operation.operation_id!r} has unknown "
                        f"target block {edge.target_block_id!r}"
                    )
        operation_source_ids = {
            operation.source_block_id for operation in operations
        }
        for native_body in native_bodies:
            terminal_ids = set(native_body.terminal_block_ids)
            if terminal_ids & operation_source_ids:
                raise FragmentPlanRejected(
                    f"native body {native_body.body_id!r} terminal block "
                    "cannot also own an operation"
                )
            missing_topology = (
                set(native_body.block_ids)
                - terminal_ids
                - operation_source_ids
            )
            if missing_topology:
                raise FragmentPlanRejected(
                    f"native body {native_body.body_id!r} lacks topology for "
                    f"{sorted(missing_topology)}"
                )

        return_carriers = tuple(self.return_carriers)
        if any(
            not isinstance(carrier, FragmentReturnCarrier)
            for carrier in return_carriers
        ):
            raise TypeError("fragment plan contains an invalid return carrier")
        self._require_unique_ids(
            (carrier.carrier_id for carrier in return_carriers),
            "fragment return carrier",
        )
        carrier_by_id = {
            carrier.carrier_id: carrier for carrier in return_carriers
        }
        for carrier in return_carriers:
            block = block_by_id.get(carrier.block_id)
            if block is None:
                raise FragmentPlanRejected(
                    f"fragment return carrier {carrier.carrier_id!r} has "
                    "unknown block"
                )
            if block.role not in {
                FragmentBlockRole.REPLACEMENT,
                FragmentBlockRole.IMPORTED,
            }:
                raise FragmentPlanRejected(
                    f"fragment return carrier {carrier.carrier_id!r} must "
                    "execute on a staged replacement or imported block"
                )
            identity = block.stable_identity
            if identity is None or any(
                not identity.native_ranges.contains(ea)
                or ea not in identity.exact_instruction_eas
                for ea in carrier.corridor_instruction_eas
            ):
                raise FragmentPlanRejected(
                    f"fragment return carrier {carrier.carrier_id!r} requires "
                    "exact anchors owned by its block identity"
                )

        terminal_returns = tuple(self.terminal_returns)
        if any(
            not isinstance(terminal_return, FragmentTerminalReturn)
            for terminal_return in terminal_returns
        ):
            raise TypeError("fragment plan contains an invalid terminal return")
        self._require_unique_ids(
            (terminal_return.return_id for terminal_return in terminal_returns),
            "fragment terminal return",
        )
        self._require_unique_ids(
            (terminal_return.block_id for terminal_return in terminal_returns),
            "fragment terminal return block",
        )
        terminal_return_by_id = {
            terminal_return.return_id: terminal_return
            for terminal_return in terminal_returns
        }
        terminal_return_by_block = {
            terminal_return.block_id: terminal_return
            for terminal_return in terminal_returns
        }
        for terminal_return in terminal_returns:
            block = block_by_id.get(terminal_return.block_id)
            if block is None:
                raise FragmentPlanRejected(
                    f"fragment terminal return {terminal_return.return_id!r} "
                    "has unknown block"
                )
            if block.role not in {
                FragmentBlockRole.REPLACEMENT,
                FragmentBlockRole.IMPORTED,
            }:
                raise FragmentPlanRejected(
                    f"fragment terminal return {terminal_return.return_id!r} "
                    "must execute on a staged replacement or imported block"
                )
            identity = block.stable_identity
            if (
                identity is None
                or not identity.native_ranges.contains(
                    terminal_return.instruction_ea
                )
                or terminal_return.instruction_ea
                not in identity.exact_instruction_eas
            ):
                raise FragmentPlanRejected(
                    f"fragment terminal return {terminal_return.return_id!r} "
                    "requires an exact anchor owned by its block identity"
                )
            if terminal_return.block_id in operation_source_ids:
                raise FragmentPlanRejected(
                    f"fragment terminal return {terminal_return.return_id!r} "
                    "cannot also own an outgoing operation"
                )

        terminal_routes = tuple(self.terminal_routes)
        if any(
            not isinstance(terminal_route, FragmentTerminalRoute)
            for terminal_route in terminal_routes
        ):
            raise TypeError("fragment plan contains an invalid terminal route")
        self._require_unique_ids(
            (terminal_route.terminal_route_id for terminal_route in terminal_routes),
            "fragment terminal route",
        )
        self._require_unique_ids(
            (terminal_route.operation_id for terminal_route in terminal_routes),
            "fragment terminal route operation",
        )
        self._require_unique_ids(
            (terminal_route.carrier_id for terminal_route in terminal_routes),
            "fragment terminal route carrier",
        )
        operation_by_id = {
            operation.operation_id: operation for operation in operations
        }
        used_carrier_ids: set[str] = set()
        used_return_ids: set[str] = set()
        linked_terminal_edges: set[tuple[str, str]] = set()
        for terminal_route in terminal_routes:
            operation = operation_by_id.get(terminal_route.operation_id)
            carrier = carrier_by_id.get(terminal_route.carrier_id)
            terminal_return = terminal_return_by_id.get(terminal_route.return_id)
            if operation is None:
                raise FragmentPlanRejected(
                    f"fragment terminal route {terminal_route.terminal_route_id!r} "
                    "has unknown operation"
                )
            if carrier is None:
                raise FragmentPlanRejected(
                    f"fragment terminal route {terminal_route.terminal_route_id!r} "
                    "has unknown return carrier"
                )
            if terminal_return is None:
                raise FragmentPlanRejected(
                    f"fragment terminal route {terminal_route.terminal_route_id!r} "
                    "has unknown terminal return"
                )
            if (
                len(operation.edges) != 1
                or operation.edges[0].role is not SemanticEdgeRole.DIRECT
                or operation.edges[0].target_block_id
                != terminal_return.block_id
            ):
                raise FragmentPlanRejected(
                    f"fragment terminal route {terminal_route.terminal_route_id!r} "
                    "requires one direct edge to its terminal return block"
                )
            if carrier.return_width != terminal_return.return_width:
                raise FragmentPlanRejected(
                    f"fragment terminal route {terminal_route.terminal_route_id!r} "
                    "carrier and return widths must match"
                )
            used_carrier_ids.add(carrier.carrier_id)
            used_return_ids.add(terminal_return.return_id)
            linked_terminal_edges.add(
                (operation.operation_id, terminal_return.block_id)
            )
        if used_carrier_ids != set(carrier_by_id):
            raise FragmentPlanRejected(
                "every fragment return carrier must belong to one terminal route"
            )
        if used_return_ids != set(terminal_return_by_id):
            raise FragmentPlanRejected(
                "every fragment terminal return must belong to a terminal route"
            )
        planned_terminal_edges = {
            (operation.operation_id, edge.target_block_id)
            for operation in operations
            for edge in operation.edges
            if edge.target_block_id in terminal_return_by_block
        }
        if linked_terminal_edges != planned_terminal_edges:
            raise FragmentPlanRejected(
                "every edge to a fragment terminal return requires its atomic "
                "carrier and route"
            )

        data_flow_obligations = tuple(self.data_flow_obligations)
        if any(
            not isinstance(obligation, FragmentDataFlowObligation)
            for obligation in data_flow_obligations
        ):
            raise TypeError("fragment plan contains an invalid data-flow obligation")
        self._require_unique_ids(
            (obligation.obligation_id for obligation in data_flow_obligations),
            "fragment data-flow obligation",
        )
        data_flow_sites: set[FragmentValueSite] = set()
        site_by_id: dict[str, FragmentValueSite] = {}

        def register_sites(sites: tuple[FragmentValueSite, ...]) -> None:
            for site in sites:
                prior = site_by_id.get(site.site_id)
                if prior is not None and prior != site:
                    raise FragmentPlanRejected(
                        f"fragment value site id {site.site_id!r} is ambiguous"
                    )
                site_by_id[site.site_id] = site

        for obligation in data_flow_obligations:
            sites = (obligation.definition, *obligation.uses)
            self._require_sites_known(sites, block_by_id)
            register_sites(sites)
            data_flow_sites.update(sites)

        flag_corridors = tuple(self.flag_corridors)
        if any(
            not isinstance(corridor, FragmentFlagCorridor)
            for corridor in flag_corridors
        ):
            raise TypeError("fragment plan contains an invalid flag corridor")
        self._require_unique_ids(
            (corridor.corridor_id for corridor in flag_corridors),
            "fragment flag corridor",
        )
        for corridor in flag_corridors:
            sites = (corridor.producer, corridor.consumer)
            self._require_sites_known(sites, block_by_id)
            register_sites(sites)
            for block_id in corridor.block_path:
                if block_id not in block_by_id:
                    raise FragmentPlanRejected(
                        f"fragment flag corridor {corridor.corridor_id!r} has unknown "
                        f"block {block_id!r}"
                    )

        value_range_assumptions = tuple(self.value_range_assumptions)
        if any(
            not isinstance(assumption, FragmentRangeAssumption)
            for assumption in value_range_assumptions
        ):
            raise TypeError("fragment plan contains an invalid range assumption")
        self._require_unique_ids(
            (assumption.assumption_id for assumption in value_range_assumptions),
            "fragment range assumption",
        )
        for assumption in value_range_assumptions:
            self._require_sites_known((assumption.site,), block_by_id)
            register_sites((assumption.site,))
            if assumption.site not in data_flow_sites:
                raise FragmentPlanRejected(
                    f"fragment range assumption {assumption.assumption_id!r} must "
                    "describe a declared data-flow site"
                )

        object.__setattr__(self, "plan_id", plan_id)
        object.__setattr__(self, "atomic_group_id", atomic_group_id)
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(self, "roots", roots)
        object.__setattr__(self, "owned_originals", owned_originals)
        object.__setattr__(
            self,
            "prohibited_dispatcher_blocks",
            prohibited_dispatcher_blocks,
        )
        object.__setattr__(self, "operations", operations)
        object.__setattr__(self, "work_item_scope", work_item_scope)
        object.__setattr__(self, "return_carriers", return_carriers)
        object.__setattr__(self, "terminal_returns", terminal_returns)
        object.__setattr__(self, "terminal_routes", terminal_routes)
        object.__setattr__(self, "native_bodies", native_bodies)
        object.__setattr__(
            self,
            "data_flow_obligations",
            data_flow_obligations,
        )
        object.__setattr__(self, "flag_corridors", flag_corridors)
        object.__setattr__(
            self,
            "value_range_assumptions",
            value_range_assumptions,
        )

    @staticmethod
    def _normalize_block_ids(
        values: tuple[str, ...], description: str
    ) -> tuple[str, ...]:
        normalized = tuple(_require_identifier(value, description) for value in values)
        if len(set(normalized)) != len(normalized):
            raise FragmentPlanRejected(
                f"fragment plan contains duplicate {description}s"
            )
        return normalized

    @staticmethod
    def _require_unique_ids(values, description: str) -> None:
        values = tuple(values)
        if len(set(values)) != len(values):
            raise FragmentPlanRejected(
                f"fragment plan contains duplicate {description} ids"
            )

    @staticmethod
    def _require_sites_known(
        sites: tuple[FragmentValueSite, ...],
        block_by_id: dict[str, FragmentBlock],
    ) -> None:
        for site in sites:
            block = block_by_id.get(site.block_id)
            if block is None:
                raise FragmentPlanRejected(
                    f"fragment value site {site.site_id!r} has unknown block"
                )
            identity = block.stable_identity
            if identity is not None and not identity.native_ranges.contains(
                site.instruction_ea
            ):
                raise FragmentPlanRejected(
                    f"fragment value site {site.site_id!r} does not belong to "
                    "its block identity"
                )

    def block(self, block_id: str) -> FragmentBlock:
        """Return one plan block or fail without a backend-coordinate fallback."""
        block_id = str(block_id)
        for block in self.blocks:
            if block.block_id == block_id:
                return block
        raise KeyError(block_id)

    def operation(self, operation_id: str) -> FragmentOperation:
        """Return one complete operation by its portable id."""
        operation_id = str(operation_id)
        for operation in self.operations:
            if operation.operation_id == operation_id:
                return operation
        raise KeyError(operation_id)


def _portable_fragment_json_value(value):
    """Convert one portable plan value into deterministic JSON data."""
    if isinstance(value, NativePreanalysisKey):
        return value.to_dict()
    if isinstance(value, StableBlockIdentity):
        return value.to_dict()
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _portable_fragment_json_value(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, dict):
        return {
            str(key): _portable_fragment_json_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_portable_fragment_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        converted = [_portable_fragment_json_value(item) for item in value]
        return sorted(
            converted,
            key=lambda item: json.dumps(
                item,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(
        "fragment plan contains a non-portable JSON value: "
        f"{type(value).__name__}"
    )


def fragment_plan_to_dict(plan: FragmentPlan) -> dict[str, object]:
    """Return the complete serial-free diagnostic representation of a plan."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("fragment plan serialization requires a FragmentPlan")
    payload = _portable_fragment_json_value(plan)
    if not isinstance(payload, dict):
        raise TypeError("fragment plan serialization did not produce an object")
    return payload


def serialize_fragment_plan(plan: FragmentPlan) -> str:
    """Serialize every plan member deterministically for diagnostic replay."""
    return json.dumps(
        fragment_plan_to_dict(plan),
        sort_keys=True,
        separators=(",", ":"),
    )


__all__ = [
    "FragmentBlock",
    "FragmentBlockMaterialization",
    "FragmentBlockRole",
    "FragmentConditionalSelectEnvelope",
    "FragmentComputedBranchNormalization",
    "FragmentDataFlowObligation",
    "FragmentDataFlowRole",
    "FragmentEdge",
    "FragmentFlagCorridor",
    "FragmentNativeBody",
    "FragmentOperation",
    "FragmentPlan",
    "FragmentPlanRejected",
    "FragmentPublicationPurpose",
    "FragmentRangeAssumption",
    "FragmentRangeObservation",
    "FragmentReturnCarrier",
    "FragmentReturnSource",
    "FragmentReturnSourceKind",
    "FragmentTerminalReturn",
    "FragmentTerminalRoute",
    "FragmentValueSite",
    "FragmentWorkItemScope",
    "fragment_plan_to_dict",
    "serialize_fragment_plan",
]
