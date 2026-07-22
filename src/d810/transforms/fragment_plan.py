"""Portable plans for detached, fragment-atomic semantic publication.

Canonical passes describe the semantic fragment they require with stable native
identities and plan-local block ids.  This contract deliberately contains no
live MBA object, block serial, logical proxy, or physical version coordinate.
The mutation gateway owns binding these references to the current MBA and
realizing the whole plan in one unpublished transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import StableBlockIdentity
from d810.ir.semantic_edge import SemanticEdgeRole


_BADADDR = 0xFFFFFFFFFFFFFFFF


class FragmentPlanRejected(ValueError):
    """A fragment plan is incomplete or internally inconsistent."""


class FragmentBlockRole(str, Enum):
    """Publication role of one plan-local block representation."""

    ORIGINAL = "original"
    REPLACEMENT = "replacement"
    EXTERNAL = "external"
    SYNTHETIC = "synthetic"


class FragmentDataFlowRole(str, Enum):
    """Observable semantic responsibility protected by a data-flow proof."""

    CONDITION = "condition"
    CARRIER = "carrier"
    STATE_VALUE = "state_value"
    CALL = "call"
    CLEANUP = "cleanup"
    RETURN = "return"


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
    semantic_anchor_ea: int
    stable_identity: StableBlockIdentity | None = None
    replaces_block_id: str | None = None

    def __post_init__(self) -> None:
        block_id = _require_identifier(self.block_id, "fragment block id")
        semantic_anchor_ea = _require_native_ea(
            self.semantic_anchor_ea,
            "fragment block semantic anchor",
        )
        if not isinstance(self.role, FragmentBlockRole):
            raise TypeError("fragment block requires a FragmentBlockRole")

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

        object.__setattr__(self, "block_id", block_id)
        object.__setattr__(self, "semantic_anchor_ea", semantic_anchor_ea)
        object.__setattr__(self, "replaces_block_id", replaces_block_id)


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
class FragmentOperation:
    """One complete semantic control-flow operation inside a fragment."""

    operation_id: str
    source_block_id: str
    edges: tuple[FragmentEdge, ...]
    predicate_anchor_ea: int | None = None

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
        if len(edges) == 1:
            if edges[0].role is not SemanticEdgeRole.DIRECT:
                raise FragmentPlanRejected(
                    "fragment conditional requires both conditional roles"
                )
            if predicate_anchor_ea is not None:
                raise FragmentPlanRejected(
                    "fragment predicate belongs only to a complete conditional"
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
class FragmentValueSite:
    """Plan-local value definition or use at one stable semantic anchor."""

    site_id: str
    block_id: str
    value_id: str
    instruction_ea: int

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
    lo: int | None = None
    hi: int | None = None

    def __post_init__(self) -> None:
        assumption_id = _require_identifier(
            self.assumption_id,
            "fragment range assumption id",
        )
        if not isinstance(self.site, FragmentValueSite):
            raise TypeError("fragment range assumption requires a value site")
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
        object.__setattr__(self, "assumption_id", assumption_id)
        object.__setattr__(self, "lo", lo)
        object.__setattr__(self, "hi", hi)


@dataclass(frozen=True, slots=True)
class FragmentPlan:
    """Complete portable intent for one atomic semantic publication."""

    plan_id: str
    atomic_group_id: str
    native_key: NativePreanalysisKey
    blocks: tuple[FragmentBlock, ...]
    roots: tuple[str, ...]
    owned_originals: tuple[str, ...]
    prohibited_dispatcher_blocks: tuple[str, ...]
    operations: tuple[FragmentOperation, ...]
    data_flow_obligations: tuple[FragmentDataFlowObligation, ...] = ()
    flag_corridors: tuple[FragmentFlagCorridor, ...] = ()
    value_range_assumptions: tuple[FragmentRangeAssumption, ...] = ()

    def __post_init__(self) -> None:
        plan_id = _require_identifier(self.plan_id, "fragment plan id")
        atomic_group_id = _require_identifier(
            self.atomic_group_id,
            "fragment atomic group id",
        )
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("fragment plan requires a native preanalysis key")

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

        operations = tuple(self.operations)
        if not operations or any(
            not isinstance(operation, FragmentOperation) for operation in operations
        ):
            raise FragmentPlanRejected("fragment plan requires semantic operations")
        self._require_unique_ids(
            (operation.operation_id for operation in operations),
            "fragment operation",
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
            }:
                raise FragmentPlanRejected(
                    f"fragment operation {operation.operation_id!r} must execute on "
                    "a staged replacement or synthetic block"
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
            for edge in operation.edges:
                if edge.target_block_id not in block_by_id:
                    raise FragmentPlanRejected(
                        f"fragment operation {operation.operation_id!r} has unknown "
                        f"target block {edge.target_block_id!r}"
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
        known_sites: set[FragmentValueSite] = set()
        site_by_id: dict[str, FragmentValueSite] = {}
        for obligation in data_flow_obligations:
            sites = (obligation.definition, *obligation.uses)
            self._require_sites_known(sites, block_by_id)
            for site in sites:
                prior = site_by_id.get(site.site_id)
                if prior is not None and prior != site:
                    raise FragmentPlanRejected(
                        f"fragment value site id {site.site_id!r} is ambiguous"
                    )
                site_by_id[site.site_id] = site
            known_sites.update(sites)

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
            self._require_sites_known(
                (corridor.producer, corridor.consumer),
                block_by_id,
            )
            if (
                corridor.producer not in known_sites
                or corridor.consumer not in known_sites
            ):
                raise FragmentPlanRejected(
                    f"fragment flag corridor {corridor.corridor_id!r} must protect "
                    "declared data-flow sites"
                )
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
            if assumption.site not in known_sites:
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


__all__ = [
    "FragmentBlock",
    "FragmentBlockRole",
    "FragmentDataFlowObligation",
    "FragmentDataFlowRole",
    "FragmentEdge",
    "FragmentFlagCorridor",
    "FragmentOperation",
    "FragmentPlan",
    "FragmentPlanRejected",
    "FragmentRangeAssumption",
    "FragmentValueSite",
]
