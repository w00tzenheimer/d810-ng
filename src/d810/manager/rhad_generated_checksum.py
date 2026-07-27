"""Manager-owned typed Rhad GENERATED reference-batch producer.

This remains intentionally narrower than full A560 restoration. Exact-input
evidence selects an ordered operation batch, the portable compiler lowers it,
and the manager submits one plan to the shared transaction backend at the
actual GENERATED callback boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from d810.core.logging import getLogger
from d810.core.native_preanalysis_key import NativePreanalysisKey
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
    RhadCompilerRejection,
    RhadConditionalRoute,
    RhadDirectRoute,
    RhadExistingConditionalRoute,
    RhadOperationVariant,
    RhadReferenceOperation,
    RhadReferenceLedger,
    RhadReferencePhase,
    RhadSetccIndexedTableRoute,
    RhadSetccIndexedTableProofArtifact,
    compile_rhad_reference_fragment,
)


logger = getLogger(__name__)

INPUT_SHA256 = "2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
ROW16_TABLE_PROOF_PATH = (
    Path(__file__).resolve().parents[1]
    / "conf"
    / "semantic_route_oracles"
    / "rhad_a560_row16_setcc_table_proof.json"
)
ROW17_TABLE_PROOF_PATH = (
    Path(__file__).resolve().parents[1]
    / "conf"
    / "semantic_route_oracles"
    / "rhad_a560_row17_setcc_table_proof.json"
)


def load_row16_table_proof_artifact(
    path: Path = ROW16_TABLE_PROOF_PATH,
) -> RhadSetccIndexedTableProofArtifact:
    """Load the required canonical row-16 proof before any live mutation."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RhadCompilerRejection(
            f"Rhad row-16 table proof artifact is unavailable: {error}"
        ) from error
    return RhadSetccIndexedTableProofArtifact.from_mapping(payload)


def load_row17_table_proof_artifact(
    path: Path = ROW17_TABLE_PROOF_PATH,
) -> RhadSetccIndexedTableProofArtifact:
    """Load the required canonical row-17 proof before any live mutation."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RhadCompilerRejection(
            f"Rhad row-17 table proof artifact is unavailable: {error}"
        ) from error
    return RhadSetccIndexedTableProofArtifact.from_mapping(payload)


ACCEPTED_IMPORTED_RANGES = (
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
DIRECT_IMPORTED_RANGES = (
    (0x40A61B, 0x40A62D),
    (0x40A62D, 0x40A633),
    (0x40A631, 0x40A633),
    (0x40A740, 0x40A74C),
    (0x40A74A, 0x40A74C),
)
THIRD_SHAPE_IMPORTED_LAYOUT = (
    (0x40A68C, 0x40A69A, (0x40A68C, 0x40A692, 0x40A698)),
    (0x40A69A, 0x40A6A0, (0x40A69A,)),
    (0x40A6A0, 0x40A6A6, (0x40A6A0, 0x40A6A2, 0x40A6A4)),
    (0x40A6A4, 0x40A6A6, (0x40A6A4,)),
    (0x40A6A6, 0x40A6B4, (0x40A6A6, 0x40A6AC, 0x40A6B2)),
    (0x40A6B4, 0x40A6BA, (0x40A6B4,)),
    (0x40A6BA, 0x40A6C0, (0x40A6BA, 0x40A6BC, 0x40A6BE)),
    (0x40A800, 0x40A80E, (0x40A800, 0x40A806, 0x40A80C)),
    (0x40A80E, 0x40A814, (0x40A80E,)),
    (0x40A814, 0x40A81A, (0x40A814, 0x40A816, 0x40A818)),
    (0x40A818, 0x40A81A, (0x40A818,)),
)
ROW9_TARGET_IMPORTED_LAYOUT = (
    (0x40A6C0, 0x40A6CE, (0x40A6C0, 0x40A6C6, 0x40A6CC)),
    (0x40A6CE, 0x40A6D4, (0x40A6CE,)),
    (0x40A6D4, 0x40A6DA, (0x40A6D4, 0x40A6D6, 0x40A6D8)),
    (0x40A6D8, 0x40A6DA, (0x40A6D8,)),
    (0x40A960, 0x40A96E, (0x40A960, 0x40A966, 0x40A96C)),
    (0x40A96E, 0x40A974, (0x40A96E,)),
    (0x40A974, 0x40A97A, (0x40A974, 0x40A976, 0x40A978)),
    (0x40A978, 0x40A97A, (0x40A978,)),
)
ROW10_TARGET_IMPORTED_LAYOUT = (
    (0x40A6DA, 0x40A6E8, (0x40A6DA, 0x40A6E0, 0x40A6E6)),
    (0x40A6E8, 0x40A6EE, (0x40A6E8,)),
    (0x40A6EE, 0x40A6F4, (0x40A6EE, 0x40A6F0, 0x40A6F2)),
    (0x40A6F2, 0x40A6F4, (0x40A6F2,)),
    (0x40AB76, 0x40AB84, (0x40AB76, 0x40AB7C, 0x40AB82)),
    (0x40AB84, 0x40AB8A, (0x40AB84,)),
    (0x40AB8A, 0x40AB90, (0x40AB8A, 0x40AB8C, 0x40AB8E)),
    (0x40AB8E, 0x40AB90, (0x40AB8E,)),
)
ROW11_TARGET_IMPORTED_LAYOUT = (
    (0x40A6F4, 0x40A702, (0x40A6F4, 0x40A6FA, 0x40A700)),
    (0x40A702, 0x40A708, (0x40A702,)),
    (0x40A708, 0x40A70E, (0x40A708, 0x40A70A, 0x40A70C)),
    (0x40A70C, 0x40A70E, (0x40A70C,)),
    (0x40AE8B, 0x40AE99, (0x40AE8B, 0x40AE91, 0x40AE97)),
    (0x40AE99, 0x40AE9F, (0x40AE99,)),
    (0x40AE9F, 0x40AEA5, (0x40AE9F, 0x40AEA1, 0x40AEA3)),
    (0x40AEA3, 0x40AEA5, (0x40AEA3,)),
)
ROW12_TARGET_IMPORTED_LAYOUT = (
    (
        0x40A70E,
        0x40A739,
        (
            0x40A70E,
            0x40A710,
            0x40A716,
            0x40A71B,
            0x40A71D,
            0x40A721,
            0x40A723,
            0x40A728,
            0x40A72E,
            0x40A730,
            0x40A736,
        ),
    ),
    (0x40A736, 0x40A739, (0x40A736,)),
    (0x40A739, 0x40A73F, (0x40A739, 0x40A73B, 0x40A73D)),
    (0x40A73D, 0x40A73F, (0x40A73D,)),
)
FOURTH_SHAPE_IMPORTED_LAYOUT = (
    (0x40A74C, 0x40A75A, (0x40A74C, 0x40A752, 0x40A758)),
    (0x40A75A, 0x40A760, (0x40A75A,)),
    (0x40A760, 0x40A766, (0x40A760, 0x40A762, 0x40A764)),
    (0x40A764, 0x40A766, (0x40A764,)),
    (
        0x40A766,
        0x40A77E,
        (
            0x40A766,
            0x40A768,
            0x40A76E,
            0x40A771,
            0x40A774,
            0x40A77A,
            0x40A77C,
        ),
    ),
    (0x40ABC6, 0x40ABD4, (0x40ABC6, 0x40ABCC, 0x40ABD2)),
    (0x40ABD4, 0x40ABDA, (0x40ABD4,)),
    (0x40ABDA, 0x40ABE0, (0x40ABDA, 0x40ABDC, 0x40ABDE)),
    (0x40ABDE, 0x40ABE0, (0x40ABDE,)),
    (0x40A77C, 0x40A77E, (0x40A77C,)),
    (0x40A9DE, 0x40A9EC, (0x40A9DE, 0x40A9E4, 0x40A9EA)),
    (0x40A9EC, 0x40A9F2, (0x40A9EC,)),
    (0x40A9F2, 0x40A9F8, (0x40A9F2, 0x40A9F4, 0x40A9F6)),
    (0x40A9F6, 0x40A9F8, (0x40A9F6,)),
    (
        0x40A77E,
        0x40A794,
        (0x40A77E, 0x40A780, 0x40A786, 0x40A789, 0x40A790, 0x40A792),
    ),
    (0x40A792, 0x40A794, (0x40A792,)),
)
FIFTH_SHAPE_IMPORTED_LAYOUT = (
    (0x40A794, 0x40A7A2, (0x40A794, 0x40A79A, 0x40A7A0)),
    (0x40A7A2, 0x40A7A8, (0x40A7A2,)),
    (0x40A7A8, 0x40A7AE, (0x40A7A8, 0x40A7AA, 0x40A7AC)),
    (0x40A7AC, 0x40A7AE, (0x40A7AC,)),
    (0x40AEE6, 0x40AEF4, (0x40AEE6, 0x40AEEC, 0x40AEF2)),
    (0x40AEF4, 0x40AEFA, (0x40AEF4,)),
    (0x40AEFA, 0x40AF00, (0x40AEFA, 0x40AEFC, 0x40AEFE)),
    (0x40AEFE, 0x40AF00, (0x40AEFE,)),
)
SIXTH_SHAPE_IMPORTED_LAYOUT = (
    (0x40A7AE, 0x40A7BA, (0x40A7AE, 0x40A7B5)),
    (0x40A7BA, 0x40A7CD, (0x40A7BA, 0x40A7BD, 0x40A7C2, 0x40A7C7)),
    (0x40A7CD, 0x40A7E5, (0x40A7CD, 0x40A7D3, 0x40A7D9, 0x40A7DF)),
    (0x40A7E5, 0x40A7F1, (0x40A7E5, 0x40A7E7, 0x40A7E9, 0x40A7EF)),
    (0x40A7EF, 0x40A7F1, (0x40A7EF,)),
    (0x40B4C5, 0x40B4E2, (0x40B4C5, 0x40B4CA, 0x40B4D0, 0x40B4D6, 0x40B4DC)),
    (0x40B4E2, 0x40B4F0, (0x40B4E2, 0x40B4E4, 0x40B4E6, 0x40B4E8, 0x40B4EE)),
    (0x40B4EE, 0x40B4F0, (0x40B4EE,)),
)
ROW20_TARGET_IMPORTED_LAYOUT = (
    (0x40A81A, 0x40A828, (0x40A81A, 0x40A820, 0x40A826)),
    (0x40A828, 0x40A82E, (0x40A828,)),
    (0x40A82E, 0x40A834, (0x40A82E, 0x40A830, 0x40A832)),
    (0x40A832, 0x40A834, (0x40A832,)),
    (0x40AA60, 0x40AA6E, (0x40AA60, 0x40AA66, 0x40AA6C)),
    (0x40AA6E, 0x40AA74, (0x40AA6E,)),
    (0x40AA74, 0x40AA7A, (0x40AA74, 0x40AA76, 0x40AA78)),
    (0x40AA78, 0x40AA7A, (0x40AA78,)),
)
ROW21_TARGET_IMPORTED_LAYOUT = (
    (0x40A834, 0x40A842, (0x40A834, 0x40A83A, 0x40A840)),
    (0x40A842, 0x40A848, (0x40A842,)),
    (0x40A848, 0x40A84E, (0x40A848, 0x40A84A, 0x40A84C)),
    (0x40A84C, 0x40A84E, (0x40A84C,)),
    (0x40AC3D, 0x40AC4A, (0x40AC3D, 0x40AC42, 0x40AC48)),
    (0x40AC4A, 0x40AC50, (0x40AC4A,)),
    (0x40AC50, 0x40AC56, (0x40AC50, 0x40AC52, 0x40AC54)),
    (0x40AC54, 0x40AC56, (0x40AC54,)),
)
ROW22_TARGET_IMPORTED_LAYOUT = (
    (0x40A84E, 0x40A85C, (0x40A84E, 0x40A854, 0x40A85A)),
    (0x40A85C, 0x40A862, (0x40A85C,)),
    (0x40A862, 0x40A868, (0x40A862, 0x40A864, 0x40A866)),
    (0x40A866, 0x40A868, (0x40A866,)),
    (0x40AFDF, 0x40AFED, (0x40AFDF, 0x40AFE5, 0x40AFEB)),
    (0x40AFED, 0x40AFF3, (0x40AFED,)),
    (0x40AFF3, 0x40AFF9, (0x40AFF3, 0x40AFF5, 0x40AFF7)),
    (0x40AFF7, 0x40AFF9, (0x40AFF7,)),
)
ROW23_TARGET_IMPORTED_LAYOUT = (
    (
        0x40A868,
        0x40A8A3,
        (
            0x40A868,
            0x40A86D,
            0x40A874,
            0x40A877,
            0x40A87F,
            0x40A887,
            0x40A88D,
            0x40A892,
            0x40A898,
            0x40A89A,
            0x40A8A0,
        ),
    ),
    (0x40A8A0, 0x40A8A3, (0x40A8A0,)),
    (0x40A8A3, 0x40A8A9, (0x40A8A3, 0x40A8A5, 0x40A8A7)),
    (0x40A8A7, 0x40A8A9, (0x40A8A7,)),
)
ROW26_SOURCE_IMPORTED_LAYOUT = (
    (0x40A8B5, 0x40A8C3, (0x40A8B5, 0x40A8BB, 0x40A8C1)),
    (0x40A8C3, 0x40A8C9, (0x40A8C3,)),
    (0x40A8C9, 0x40A8CF, (0x40A8C9, 0x40A8CB, 0x40A8CD)),
    (0x40A8CD, 0x40A8CF, (0x40A8CD,)),
)
ROW26_TARGET_IMPORTED_LAYOUT = (
    (0x40A8CF, 0x40A8DD, (0x40A8CF, 0x40A8D5, 0x40A8DB)),
    (0x40A8DD, 0x40A8E3, (0x40A8DD,)),
    (0x40A8E3, 0x40A8E9, (0x40A8E3, 0x40A8E5, 0x40A8E7)),
    (0x40A8E7, 0x40A8E9, (0x40A8E7,)),
    (0x40ACBF, 0x40ACCD, (0x40ACBF, 0x40ACC5, 0x40ACCB)),
    (0x40ACCD, 0x40ACD3, (0x40ACCD,)),
    (0x40ACD3, 0x40ACD9, (0x40ACD3, 0x40ACD5, 0x40ACD7)),
    (0x40ACD7, 0x40ACD9, (0x40ACD7,)),
)
BASE_IMPORTED_LAYOUT = tuple(
    (start_ea, end_ea, (start_ea,))
    for start_ea, end_ea in ACCEPTED_IMPORTED_RANGES + DIRECT_IMPORTED_RANGES
)
IMPORTED_LAYOUT = (
    BASE_IMPORTED_LAYOUT
    + THIRD_SHAPE_IMPORTED_LAYOUT
    + ROW9_TARGET_IMPORTED_LAYOUT
    + ROW10_TARGET_IMPORTED_LAYOUT
    + ROW11_TARGET_IMPORTED_LAYOUT
    + ROW12_TARGET_IMPORTED_LAYOUT
    + FOURTH_SHAPE_IMPORTED_LAYOUT[:-1]
    + FIFTH_SHAPE_IMPORTED_LAYOUT
    + SIXTH_SHAPE_IMPORTED_LAYOUT
    + ROW20_TARGET_IMPORTED_LAYOUT
    + ROW21_TARGET_IMPORTED_LAYOUT
    + ROW22_TARGET_IMPORTED_LAYOUT
    + ROW23_TARGET_IMPORTED_LAYOUT
    + ROW26_SOURCE_IMPORTED_LAYOUT
    + ROW26_TARGET_IMPORTED_LAYOUT
    + FOURTH_SHAPE_IMPORTED_LAYOUT[-1:]
)
IMPORTED_RANGES = tuple(
    (start_ea, end_ea) for start_ea, end_ea, _exact_eas in IMPORTED_LAYOUT
)
IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}" for start_ea, _end_ea in IMPORTED_RANGES
)
ACCEPTED_IMPORTED_BLOCK_IDS = IMPORTED_BLOCK_IDS[: len(ACCEPTED_IMPORTED_RANGES)]
DIRECT_IMPORTED_BLOCK_IDS = IMPORTED_BLOCK_IDS[
    len(ACCEPTED_IMPORTED_RANGES) : len(BASE_IMPORTED_LAYOUT)
]
DEPENDENCY_IMPORTED_BLOCK_IDS = IMPORTED_BLOCK_IDS[
    len(BASE_IMPORTED_LAYOUT) : len(BASE_IMPORTED_LAYOUT) + 4
]
SELECTED_IMPORTED_BLOCK_IDS = IMPORTED_BLOCK_IDS[
    len(BASE_IMPORTED_LAYOUT) + 4 : len(BASE_IMPORTED_LAYOUT)
    + len(THIRD_SHAPE_IMPORTED_LAYOUT)
]
ROW9_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW9_TARGET_IMPORTED_LAYOUT
)
ROW10_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW10_TARGET_IMPORTED_LAYOUT
)
ROW11_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW11_TARGET_IMPORTED_LAYOUT
)
ROW12_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW12_TARGET_IMPORTED_LAYOUT
)
FOURTH_DIRECT_IMPORTED_BLOCK_IDS = (
    "native@0x40A74C",
    "native@0x40A75A",
    "native@0x40A760",
    "native@0x40A764",
)
FOURTH_EXISTING_IMPORTED_BLOCK_IDS = (
    "native@0x40A766",
    "native@0x40A77C",
    "native@0x40A9DE",
    "native@0x40A9EC",
    "native@0x40A9F2",
    "native@0x40A9F6",
)
SETCC_IMPORTED_BLOCK_IDS = (
    "native@0x40A77E",
    "native@0x40A792",
    "native@0x40ABC6",
    "native@0x40ABD4",
    "native@0x40ABDA",
    "native@0x40ABDE",
)
FIFTH_SETCC_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in FIFTH_SHAPE_IMPORTED_LAYOUT
)
SIXTH_EXISTING_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in SIXTH_SHAPE_IMPORTED_LAYOUT
)
ROW20_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW20_TARGET_IMPORTED_LAYOUT
)
ROW21_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW21_TARGET_IMPORTED_LAYOUT
)
ROW22_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW22_TARGET_IMPORTED_LAYOUT
)
ROW23_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW23_TARGET_IMPORTED_LAYOUT
)
ROW26_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in (
        ROW26_SOURCE_IMPORTED_LAYOUT + ROW26_TARGET_IMPORTED_LAYOUT
    )
)
BOUNDARY_EXIT_EAS = (
    0x40A5F0,
    0x40A633,
    0x40A8E9,
    0x40A9A0,
    0x40AD1E,
    0x40AD6E,
    0x40ADBE,
    0x40B024,
    0x40B17F,
    0x40B1D0,
    0x40B21C,
    0x40B26D,
    0x40B790,
)
TEMPLATE_ROOT_EAS = (
    0x40A607,
    0x40B6C0,
    0x40A61B,
    0x40A68C,
    0x40A6A6,
    0x40A6C0,
    0x40A960,
    0x40A6DA,
    0x40AB76,
    0x40A6F4,
    0x40AE8B,
    0x40A70E,
    0x40A800,
    0x40A81A,
    0x40A834,
    0x40A84E,
    0x40AFDF,
    0x40A868,
    0x40A8B5,
    0x40A8CF,
    0x40ACBF,
    0x40AC3D,
    0x40AA60,
    0x40A74C,
    0x40A766,
    0x40A9DE,
    0x40A77E,
    0x40ABC6,
    0x40A794,
    0x40A7AE,
    0x40AEE6,
)


@dataclass(frozen=True, slots=True)
class RhadGeneratedBlockEvidence:
    """One stable native block identity required by a GENERATED batch."""

    block_id: str
    start_ea: int
    end_ea: int
    exact_instruction_eas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class RhadGeneratedPreservedTransfer:
    """One unresolved native transfer and its exact semantic boundary exits."""

    transfer_ea: int
    boundary_exit_eas: tuple[int, ...]

    def __post_init__(self) -> None:
        transfer_ea = int(self.transfer_ea)
        boundary_exit_eas = tuple(int(ea) for ea in self.boundary_exit_eas)
        if transfer_ea <= 0:
            raise ValueError("Rhad preserved transfer requires a native EA")
        if (
            any(ea <= 0 for ea in boundary_exit_eas)
            or len(set(boundary_exit_eas)) != len(boundary_exit_eas)
            or boundary_exit_eas != tuple(sorted(boundary_exit_eas))
        ):
            raise ValueError(
                "Rhad preserved transfer boundary exits must be positive, unique, "
                "and ordered"
            )
        object.__setattr__(self, "transfer_ea", transfer_ea)
        object.__setattr__(self, "boundary_exit_eas", boundary_exit_eas)


@dataclass(frozen=True, slots=True)
class RhadGeneratedTemplateFragment:
    """Exact target-rooted native ranges translated for one batch body."""

    root_ea: int
    owned_ranges: tuple[tuple[int, int], ...]
    owned_block_entry_eas: tuple[int, ...]
    boundary_ranges: tuple[tuple[int, int], ...]
    boundary_exit_eas: tuple[int, ...]
    direct_boundary_routes: tuple[tuple[int, int, int], ...]
    preserved_unresolved_transfers: tuple[RhadGeneratedPreservedTransfer, ...]

    def __post_init__(self) -> None:
        root_ea = int(self.root_ea)
        owned_ranges = tuple(
            (int(start_ea), int(end_ea)) for start_ea, end_ea in self.owned_ranges
        )
        boundary_ranges = tuple(
            (int(start_ea), int(end_ea)) for start_ea, end_ea in self.boundary_ranges
        )
        owned_entries = tuple(int(ea) for ea in self.owned_block_entry_eas)
        boundary_exits = tuple(int(ea) for ea in self.boundary_exit_eas)
        direct_boundary_routes = tuple(
            (int(source_ea), int(instruction_ea), int(target_ea))
            for source_ea, instruction_ea, target_ea in self.direct_boundary_routes
        )
        preserved_unresolved_transfers = tuple(self.preserved_unresolved_transfers)
        if any(
            not isinstance(evidence, RhadGeneratedPreservedTransfer)
            for evidence in preserved_unresolved_transfers
        ):
            raise TypeError("Rhad preserved transfer evidence must be typed")
        preserved_unresolved_transfer_eas = tuple(
            evidence.transfer_ea for evidence in preserved_unresolved_transfers
        )
        preserved_boundary_exit_eas = {
            ea
            for evidence in preserved_unresolved_transfers
            for ea in evidence.boundary_exit_eas
        }
        unowned_boundary_exit_eas = set(boundary_exits) - preserved_boundary_exit_eas
        if (
            root_ea <= 0
            or not owned_ranges
            or any(start_ea >= end_ea for start_ea, end_ea in owned_ranges)
            or any(start_ea >= end_ea for start_ea, end_ea in boundary_ranges)
            or root_ea not in owned_entries
            or len(set(owned_entries)) != len(owned_entries)
            or not preserved_boundary_exit_eas.issubset(boundary_exits)
            or len(boundary_ranges) != len(unowned_boundary_exit_eas)
            or len(set(boundary_exits)) != len(boundary_exits)
            or any(
                source_ea <= 0 or instruction_ea <= 0 or target_ea <= 0
                for source_ea, instruction_ea, target_ea in direct_boundary_routes
            )
            or len({instruction_ea for _, instruction_ea, _ in direct_boundary_routes})
            != len(direct_boundary_routes)
            or len(set(preserved_unresolved_transfer_eas))
            != len(preserved_unresolved_transfer_eas)
            or any(
                not any(start_ea <= ea < end_ea for start_ea, end_ea in owned_ranges)
                for ea in preserved_unresolved_transfer_eas
            )
        ):
            if len(set(preserved_unresolved_transfer_eas)) != len(
                preserved_unresolved_transfer_eas
            ):
                raise ValueError(
                    "Rhad GENERATED template fragment has a duplicate preserved "
                    "transfer"
                )
            if any(
                not any(start_ea <= ea < end_ea for start_ea, end_ea in owned_ranges)
                for ea in preserved_unresolved_transfer_eas
            ):
                raise ValueError(
                    "Rhad preserved transfer is outside its owned native range"
                )
            if not preserved_boundary_exit_eas.issubset(boundary_exits) or len(
                boundary_ranges
            ) != len(unowned_boundary_exit_eas):
                raise ValueError(
                    "Rhad preserved transfer boundary ownership differs from the "
                    "fragment exits"
                )
            raise ValueError("Rhad GENERATED template fragment is incomplete")
        object.__setattr__(self, "root_ea", root_ea)
        object.__setattr__(self, "owned_ranges", owned_ranges)
        object.__setattr__(self, "owned_block_entry_eas", owned_entries)
        object.__setattr__(self, "boundary_ranges", boundary_ranges)
        object.__setattr__(self, "boundary_exit_eas", boundary_exits)
        object.__setattr__(self, "direct_boundary_routes", direct_boundary_routes)
        object.__setattr__(
            self,
            "preserved_unresolved_transfers",
            preserved_unresolved_transfers,
        )

    @property
    def preserved_unresolved_transfer_eas(self) -> tuple[int, ...]:
        return tuple(
            evidence.transfer_ea for evidence in self.preserved_unresolved_transfers
        )

    @property
    def preserved_transfer_exit_map(self) -> dict[int, tuple[int, ...]]:
        return {
            evidence.transfer_ea: evidence.boundary_exit_eas
            for evidence in self.preserved_unresolved_transfers
        }


@dataclass(frozen=True, slots=True)
class RhadGeneratedReferenceBatch:
    """Complete typed production evidence for one reference-operation batch."""

    batch_id: str
    input_sha256: str
    function_ea: int
    native_function_rva: int
    predecessor: RhadGeneratedBlockEvidence
    source_original_id: str
    source: RhadGeneratedBlockEvidence
    auxiliary_blocks: tuple[RhadGeneratedBlockEvidence, ...]
    native_body_id: str
    imported_blocks: tuple[RhadGeneratedBlockEvidence, ...]
    native_body_entry_block_ids: tuple[str, ...]
    native_body_ranges: tuple[tuple[int, int], ...]
    native_body_proof_ids: tuple[str, ...]
    template_fragments: tuple[RhadGeneratedTemplateFragment, ...]
    operations: tuple[RhadReferenceOperation, ...]
    required_boundary_exit_eas: tuple[int, ...]
    reference_commit: str
    reference_binary_sha256: str
    runtime_image: str
    runtime_image_id: str

    def __post_init__(self) -> None:
        if len(self.input_sha256) != 64 or any(
            character not in "0123456789abcdef"
            for character in self.input_sha256.lower()
        ):
            raise ValueError("Rhad GENERATED batch requires a SHA-256 input identity")
        if not self.operations or len(
            {operation.operation_id for operation in self.operations}
        ) != len(self.operations):
            raise ValueError("Rhad GENERATED batch requires unique operations")
        imported_ids = tuple(block.block_id for block in self.imported_blocks)
        if len(set(imported_ids)) != len(imported_ids):
            raise ValueError("Rhad GENERATED batch contains duplicate imported blocks")
        if not set(self.native_body_entry_block_ids).issubset(imported_ids):
            raise ValueError("Rhad GENERATED batch entries must be imported blocks")
        if not set(self.native_body_proof_ids).issuperset(
            operation.operation_id
            for operation in self.operations
            if isinstance(
                operation,
                (
                    RhadDirectRoute,
                    RhadExistingConditionalRoute,
                    RhadSetccIndexedTableRoute,
                ),
            )
        ):
            raise ValueError("Rhad GENERATED imported routes require native-body proof")
        if (
            not self.template_fragments
            or tuple(fragment.root_ea for fragment in self.template_fragments)
            != TEMPLATE_ROOT_EAS
        ):
            raise ValueError("Rhad GENERATED template roots require typed fragments")

    @property
    def template_root_eas(self) -> tuple[int, ...]:
        return tuple(fragment.root_ea for fragment in self.template_fragments)

    @property
    def proof_artifact_identities(self) -> tuple[str, ...]:
        return tuple(
            operation.table_proof_artifact.content_identity
            for operation in self.operations
            if isinstance(operation, RhadSetccIndexedTableRoute)
        )

    @property
    def aggregate_program_identity(self) -> str:
        payload = {
            "function_ea": int(self.function_ea),
            "input_sha256": self.input_sha256.lower(),
            "operation_ids": [operation.operation_id for operation in self.operations],
            "proof_artifact_identities": list(self.proof_artifact_identities),
            "reference_commit": self.reference_commit.lower(),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_ACCEPTED_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40A605",
    source_block_id="native@0x40A5F0",
    transfer_ea=0x40A605,
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
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40A5F0",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
)

_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A619",
    source_block_id="native@0x40A615",
    source_native_ea=0x40A607,
    transfer_ea=0x40A619,
    owner_anchor_ea=0x40A615,
    direct_target_block_id="native@0x40A61B",
    owned_corridor_instruction_eas=(0x40A607, 0x40A615, 0x40A617, 0x40A619),
    imported_closure_block_ids=DIRECT_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A633, 0x40A74C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ACCEPTED_ROUTE.operation_id,),
)

_DEPENDENCY_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A68A",
    source_block_id="native@0x40A680",
    source_native_ea=0x40A613,
    transfer_ea=0x40A68A,
    owner_anchor_ea=0x40A680,
    direct_target_block_id="native@0x40A68C",
    owned_corridor_instruction_eas=(
        0x40A613,
        0x40A680,
        0x40A686,
        0x40A688,
        0x40A68A,
    ),
    imported_closure_block_ids=DEPENDENCY_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A800,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ACCEPTED_ROUTE.operation_id,),
)

_SELECTED_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A6A4",
    reference_order=8,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A68C",
    selected_value_block_id="native@0x40A69A",
    join_block_id="native@0x40A6A0",
    source_native_ea=0x40A68C,
    source_block_anchor_ea=0x40A6A0,
    transfer_ea=0x40A6A4,
    condition_producer_ea=0x40A692,
    predicate_anchor_ea=0x40A698,
    normalization_start_ea=0x40A698,
    source_branch_ea=0x40A698,
    selected_value_ea=0x40A69A,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A6A6",
    false_target_block_id="native@0x40A800",
    true_target_ea=0x40A6A6,
    false_target_ea=0x40A800,
    comparison_constant=0x65203D55,
    owned_corridor_instruction_eas=(
        0x40A68C,
        0x40A692,
        0x40A698,
        0x40A69A,
        0x40A6A0,
        0x40A6A2,
        0x40A6A4,
    ),
    imported_closure_block_ids=SELECTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A9A0,),
    flag_corridor_id="flags-intact@0x40A692",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_DEPENDENCY_ROUTE.operation_id,),
)

_ROW9_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A6BE",
    reference_order=9,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A6A6",
    selected_value_block_id="native@0x40A6B4",
    join_block_id="native@0x40A6BA",
    source_native_ea=0x40A6A6,
    source_block_anchor_ea=0x40A6BA,
    transfer_ea=0x40A6BE,
    condition_producer_ea=0x40A6AC,
    predicate_anchor_ea=0x40A6B2,
    normalization_start_ea=0x40A6B2,
    source_branch_ea=0x40A6B2,
    selected_value_ea=0x40A6B4,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A6C0",
    false_target_block_id="native@0x40A960",
    true_target_ea=0x40A6C0,
    false_target_ea=0x40A960,
    comparison_constant=0x4DFFC906,
    owned_corridor_instruction_eas=(
        0x40A6A6,
        0x40A6AC,
        0x40A6B2,
        0x40A6B4,
        0x40A6BA,
        0x40A6BC,
        0x40A6BE,
    ),
    imported_closure_block_ids=ROW9_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A6DA, 0x40AB76, 0x40AD1E),
    flag_corridor_id="flags-intact@0x40A6AC",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_SELECTED_ROUTE.operation_id,),
)

_ROW10_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A6D8",
    reference_order=10,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A6C0",
    selected_value_block_id="native@0x40A6CE",
    join_block_id="native@0x40A6D4",
    source_native_ea=0x40A6C0,
    source_block_anchor_ea=0x40A6D4,
    transfer_ea=0x40A6D8,
    condition_producer_ea=0x40A6C6,
    predicate_anchor_ea=0x40A6CC,
    normalization_start_ea=0x40A6CC,
    source_branch_ea=0x40A6CC,
    selected_value_ea=0x40A6CE,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A6DA",
    false_target_block_id="native@0x40AB76",
    true_target_ea=0x40A6DA,
    false_target_ea=0x40AB76,
    comparison_constant=0x40D5B460,
    owned_corridor_instruction_eas=(
        0x40A6C0,
        0x40A6C6,
        0x40A6CC,
        0x40A6CE,
        0x40A6D4,
        0x40A6D6,
        0x40A6D8,
    ),
    imported_closure_block_ids=ROW10_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A6F4, 0x40AE8B, 0x40B17F),
    flag_corridor_id="flags-intact@0x40A6C6",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW9_EXISTING_ROUTE.operation_id,),
)

_ROW11_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A6F2",
    reference_order=11,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A6DA",
    selected_value_block_id="native@0x40A6E8",
    join_block_id="native@0x40A6EE",
    source_native_ea=0x40A6DA,
    source_block_anchor_ea=0x40A6EE,
    transfer_ea=0x40A6F2,
    condition_producer_ea=0x40A6E0,
    predicate_anchor_ea=0x40A6E6,
    normalization_start_ea=0x40A6E6,
    source_branch_ea=0x40A6E6,
    selected_value_ea=0x40A6E8,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A6F4",
    false_target_block_id="native@0x40AE8B",
    true_target_ea=0x40A6F4,
    false_target_ea=0x40AE8B,
    comparison_constant=0x40ABF871,
    owned_corridor_instruction_eas=(
        0x40A6DA,
        0x40A6E0,
        0x40A6E6,
        0x40A6E8,
        0x40A6EE,
        0x40A6F0,
        0x40A6F2,
    ),
    imported_closure_block_ids=ROW11_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40A70E),
    flag_corridor_id="flags-intact@0x40A6E0",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW10_EXISTING_ROUTE.operation_id,),
)

_ROW12_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A70C",
    reference_order=12,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A6F4",
    selected_value_block_id="native@0x40A702",
    join_block_id="native@0x40A708",
    source_native_ea=0x40A6F4,
    source_block_anchor_ea=0x40A708,
    transfer_ea=0x40A70C,
    condition_producer_ea=0x40A6FA,
    predicate_anchor_ea=0x40A700,
    normalization_start_ea=0x40A700,
    source_branch_ea=0x40A700,
    selected_value_ea=0x40A702,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40A70E",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40A70E,
    false_target_ea=0x40A5F0,
    comparison_constant=0x357A351E,
    owned_corridor_instruction_eas=(
        0x40A6F4,
        0x40A6FA,
        0x40A700,
        0x40A702,
        0x40A708,
        0x40A70A,
        0x40A70C,
    ),
    imported_closure_block_ids=ROW12_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40A6FA",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW11_EXISTING_ROUTE.operation_id,),
)

_FOURTH_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A74A",
    source_block_id="native@0x40A740",
    source_native_ea=0x40A607,
    transfer_ea=0x40A74A,
    owner_anchor_ea=0x40A740,
    direct_target_block_id="native@0x40A74C",
    owned_corridor_instruction_eas=(
        0x40A607,
        0x40A740,
        0x40A746,
        0x40A748,
        0x40A74A,
    ),
    imported_closure_block_ids=FOURTH_DIRECT_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A9DE,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_DIRECT_ROUTE.operation_id,),
)

_FOURTH_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A764",
    reference_order=15,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A74C",
    selected_value_block_id="native@0x40A75A",
    join_block_id="native@0x40A760",
    source_native_ea=0x40A74C,
    source_block_anchor_ea=0x40A760,
    transfer_ea=0x40A764,
    condition_producer_ea=0x40A752,
    predicate_anchor_ea=0x40A758,
    normalization_start_ea=0x40A758,
    source_branch_ea=0x40A758,
    selected_value_ea=0x40A75A,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A766",
    false_target_block_id="native@0x40A9DE",
    true_target_ea=0x40A766,
    false_target_ea=0x40A9DE,
    comparison_constant=0x23B8E806,
    owned_corridor_instruction_eas=(
        0x40A74C,
        0x40A752,
        0x40A758,
        0x40A75A,
        0x40A760,
        0x40A762,
        0x40A764,
    ),
    imported_closure_block_ids=FOURTH_EXISTING_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A77E, 0x40ABC6, 0x40AD6E),
    flag_corridor_id="flags-intact@0x40A752",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_FOURTH_DIRECT_ROUTE.operation_id,),
)

_SETCC_TABLE_PROOF_ARTIFACT = load_row16_table_proof_artifact()

_SETCC_ROUTE = RhadSetccIndexedTableRoute(
    operation_id="rhad:route@0x40A77C",
    reference_order=16,
    operation_variant=RhadOperationVariant.SETCC_INDEXED_TABLE,
    reference_symbol="JumpInliner._fixup_index_access",
    source_block_id="native@0x40A766",
    source_native_ea=0x40A766,
    source_block_anchor_ea=0x40A766,
    transfer_ea=0x40A77C,
    condition_producer_ea=0x40A768,
    predicate_anchor_ea=0x40A76E,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A77E",
    false_target_block_id="native@0x40ABC6",
    true_target_ea=0x40A77E,
    false_target_ea=0x40ABC6,
    table_proof_artifact=_SETCC_TABLE_PROOF_ARTIFACT,
    owned_corridor_instruction_eas=(
        0x40A766,
        0x40A768,
        0x40A76E,
        0x40A771,
        0x40A774,
        0x40A77A,
        0x40A77C,
    ),
    imported_closure_block_ids=SETCC_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A794, 0x40AEE6, 0x40B1D0),
    flag_corridor_id="flags-intact@0x40A768",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_FOURTH_EXISTING_ROUTE.operation_id,),
)

_FIFTH_SETCC_TABLE_PROOF_ARTIFACT = load_row17_table_proof_artifact()

_FIFTH_SETCC_ROUTE = RhadSetccIndexedTableRoute(
    operation_id="rhad:route@0x40A792",
    reference_order=17,
    operation_variant=RhadOperationVariant.SETCC_INDEXED_TABLE,
    reference_symbol="JumpInliner._fixup_index_access",
    source_block_id="native@0x40A77E",
    source_native_ea=0x40A77E,
    source_block_anchor_ea=0x40A77E,
    transfer_ea=0x40A792,
    condition_producer_ea=0x40A780,
    predicate_anchor_ea=0x40A786,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40AEE6",
    false_target_block_id="native@0x40A794",
    true_target_ea=0x40AEE6,
    false_target_ea=0x40A794,
    table_proof_artifact=_FIFTH_SETCC_TABLE_PROOF_ARTIFACT,
    owned_corridor_instruction_eas=(
        0x40A77E,
        0x40A780,
        0x40A786,
        0x40A789,
        0x40A790,
        0x40A792,
    ),
    imported_closure_block_ids=FIFTH_SETCC_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0,),
    flag_corridor_id="flags-intact@0x40A780",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_SETCC_ROUTE.operation_id,),
)

_SIXTH_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A7AC",
    reference_order=18,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A794",
    selected_value_block_id="native@0x40A7A2",
    join_block_id="native@0x40A7A8",
    source_native_ea=0x40A794,
    source_block_anchor_ea=0x40A7A8,
    transfer_ea=0x40A7AC,
    condition_producer_ea=0x40A79A,
    predicate_anchor_ea=0x40A7A0,
    normalization_start_ea=0x40A7A0,
    source_branch_ea=0x40A7A0,
    selected_value_ea=0x40A7A2,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40A7AE",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40A7AE,
    false_target_ea=0x40A5F0,
    comparison_constant=0x1F0B7687,
    owned_corridor_instruction_eas=(
        0x40A794,
        0x40A79A,
        0x40A7A0,
        0x40A7A2,
        0x40A7A8,
        0x40A7AA,
        0x40A7AC,
    ),
    imported_closure_block_ids=SIXTH_EXISTING_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40A79A",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_FIFTH_SETCC_ROUTE.operation_id,),
)

_ROW20_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A818",
    reference_order=20,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A800",
    selected_value_block_id="native@0x40A80E",
    join_block_id="native@0x40A814",
    source_native_ea=0x40A800,
    source_block_anchor_ea=0x40A814,
    transfer_ea=0x40A818,
    condition_producer_ea=0x40A806,
    predicate_anchor_ea=0x40A80C,
    normalization_start_ea=0x40A80C,
    source_branch_ea=0x40A80C,
    selected_value_ea=0x40A80E,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A81A",
    false_target_block_id="native@0x40AA60",
    true_target_ea=0x40A81A,
    false_target_ea=0x40AA60,
    comparison_constant=0x742F372A,
    owned_corridor_instruction_eas=(
        0x40A800,
        0x40A806,
        0x40A80C,
        0x40A80E,
        0x40A814,
        0x40A816,
        0x40A818,
    ),
    imported_closure_block_ids=ROW20_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A834, 0x40AC3D, 0x40ADBE),
    flag_corridor_id="flags-intact@0x40A806",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_SIXTH_EXISTING_ROUTE.operation_id,),
)

_ROW21_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A832",
    reference_order=21,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A81A",
    selected_value_block_id="native@0x40A828",
    join_block_id="native@0x40A82E",
    source_native_ea=0x40A81A,
    source_block_anchor_ea=0x40A82E,
    transfer_ea=0x40A832,
    condition_producer_ea=0x40A820,
    predicate_anchor_ea=0x40A826,
    normalization_start_ea=0x40A826,
    source_branch_ea=0x40A826,
    selected_value_ea=0x40A828,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A834",
    false_target_block_id="native@0x40AC3D",
    true_target_ea=0x40A834,
    false_target_ea=0x40AC3D,
    comparison_constant=0x6D56E4D2,
    owned_corridor_instruction_eas=(
        0x40A81A,
        0x40A820,
        0x40A826,
        0x40A828,
        0x40A82E,
        0x40A830,
        0x40A832,
    ),
    imported_closure_block_ids=ROW21_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A84E, 0x40AFDF, 0x40B21C),
    flag_corridor_id="flags-intact@0x40A820",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW20_EXISTING_ROUTE.operation_id,),
)

_ROW22_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A84C",
    reference_order=22,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A834",
    selected_value_block_id="native@0x40A842",
    join_block_id="native@0x40A848",
    source_native_ea=0x40A834,
    source_block_anchor_ea=0x40A848,
    transfer_ea=0x40A84C,
    condition_producer_ea=0x40A83A,
    predicate_anchor_ea=0x40A840,
    normalization_start_ea=0x40A840,
    source_branch_ea=0x40A840,
    selected_value_ea=0x40A842,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A84E",
    false_target_block_id="native@0x40AFDF",
    true_target_ea=0x40A84E,
    false_target_ea=0x40AFDF,
    comparison_constant=0x6859ABF3,
    owned_corridor_instruction_eas=(
        0x40A834,
        0x40A83A,
        0x40A840,
        0x40A842,
        0x40A848,
        0x40A84A,
        0x40A84C,
    ),
    imported_closure_block_ids=ROW22_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40A868),
    flag_corridor_id="flags-intact@0x40A83A",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW21_EXISTING_ROUTE.operation_id,),
)

_ROW23_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A866",
    reference_order=23,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A84E",
    selected_value_block_id="native@0x40A85C",
    join_block_id="native@0x40A862",
    source_native_ea=0x40A84E,
    source_block_anchor_ea=0x40A862,
    transfer_ea=0x40A866,
    condition_producer_ea=0x40A854,
    predicate_anchor_ea=0x40A85A,
    normalization_start_ea=0x40A85A,
    source_branch_ea=0x40A85A,
    selected_value_ea=0x40A85C,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40A868",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40A868,
    false_target_ea=0x40A5F0,
    comparison_constant=0x65203D55,
    owned_corridor_instruction_eas=(
        0x40A84E,
        0x40A854,
        0x40A85A,
        0x40A85C,
        0x40A862,
        0x40A864,
        0x40A866,
    ),
    imported_closure_block_ids=ROW23_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40A854",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW22_EXISTING_ROUTE.operation_id,),
)

_ROW26_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A8CD",
    reference_order=26,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A8B5",
    selected_value_block_id="native@0x40A8C3",
    join_block_id="native@0x40A8C9",
    source_native_ea=0x40A8B5,
    source_block_anchor_ea=0x40A8C9,
    transfer_ea=0x40A8CD,
    condition_producer_ea=0x40A8BB,
    predicate_anchor_ea=0x40A8C1,
    normalization_start_ea=0x40A8C1,
    source_branch_ea=0x40A8C1,
    selected_value_ea=0x40A8C3,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A8CF",
    false_target_block_id="native@0x40ACBF",
    true_target_ea=0x40A8CF,
    false_target_ea=0x40ACBF,
    comparison_constant=0x0E9795EF,
    owned_corridor_instruction_eas=(
        0x40A8B5, 0x40A8BB, 0x40A8C1, 0x40A8C3, 0x40A8C9, 0x40A8CB, 0x40A8CD,
    ),
    imported_closure_block_ids=ROW26_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A8E9, 0x40B024, 0x40B26D),
    flag_corridor_id="flags-intact@0x40A8BB",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW23_EXISTING_ROUTE.operation_id,),
)

_A560_GENERATED_REFERENCE_BATCH = RhadGeneratedReferenceBatch(
    batch_id="rhad-generated-reference@0x40A560",
    input_sha256=INPUT_SHA256,
    function_ea=0x40A560,
    native_function_rva=0xA560,
    predecessor=RhadGeneratedBlockEvidence(
        block_id="native@0x40A5AE",
        start_ea=0x40A5AE,
        end_ea=0x40A5F0,
        exact_instruction_eas=(0x40A5AE, 0x40A5C8),
    ),
    source_original_id="native-original@0x40A5F0",
    source=RhadGeneratedBlockEvidence(
        block_id="native@0x40A5F0",
        start_ea=0x40A5F0,
        end_ea=0x40A607,
        exact_instruction_eas=(0x40A5F0, 0x40A5F6, 0x40A5FE, 0x40A601, 0x40A605),
    ),
    auxiliary_blocks=(
        RhadGeneratedBlockEvidence(
            block_id="native@0x40A5FE",
            start_ea=0x40A5FE,
            end_ea=0x40A601,
            exact_instruction_eas=(0x40A5FE,),
        ),
        RhadGeneratedBlockEvidence(
            block_id="native@0x40A601",
            start_ea=0x40A601,
            end_ea=0x40A607,
            exact_instruction_eas=(0x40A601, 0x40A605),
        ),
    ),
    native_body_id="rhad-a560-generated-native-body",
    imported_blocks=tuple(
        RhadGeneratedBlockEvidence(
            block_id=block_id,
            start_ea=start_ea,
            end_ea=end_ea,
            exact_instruction_eas=exact_instruction_eas,
        )
        for block_id, (start_ea, end_ea, exact_instruction_eas) in zip(
            IMPORTED_BLOCK_IDS,
            IMPORTED_LAYOUT,
            strict=True,
        )
    ),
    native_body_entry_block_ids=(
        "native@0x40A607",
        "native@0x40A619",
        "native@0x40A68A",
        "native@0x40B6C0",
        "native@0x40B6D4",
        "native@0x40A61B",
        "native@0x40A631",
        "native@0x40A74A",
        "native@0x40A68C",
        "native@0x40A6A4",
        "native@0x40A6A6",
        "native@0x40A6B4",
        "native@0x40A6C0",
        "native@0x40A6D8",
        "native@0x40A6DA",
        "native@0x40A6F2",
        "native@0x40A6F4",
        "native@0x40A70C",
        "native@0x40A70E",
        "native@0x40A73D",
        "native@0x40A960",
        "native@0x40A978",
        "native@0x40AB76",
        "native@0x40AB8E",
        "native@0x40AE8B",
        "native@0x40AEA3",
        "native@0x40A800",
        "native@0x40A818",
        "native@0x40A81A",
        "native@0x40A832",
        "native@0x40A834",
        "native@0x40A84C",
        "native@0x40A84E",
        "native@0x40A866",
        "native@0x40AFDF",
        "native@0x40AFF7",
        "native@0x40A868",
        "native@0x40A8A0",
        "native@0x40A8A3",
        "native@0x40A8A7",
        "native@0x40A8B5",
        "native@0x40A8CD",
        "native@0x40A8CF",
        "native@0x40A8E7",
        "native@0x40ACBF",
        "native@0x40ACD7",
        "native@0x40AC3D",
        "native@0x40AC54",
        "native@0x40AA60",
        "native@0x40AA78",
        "native@0x40A74C",
        "native@0x40A764",
        "native@0x40A766",
        "native@0x40A77C",
        "native@0x40A9DE",
        "native@0x40A9F6",
        "native@0x40A77E",
        "native@0x40A792",
        "native@0x40ABC6",
        "native@0x40ABDE",
        "native@0x40A794",
        "native@0x40A7A2",
        "native@0x40A7A8",
        "native@0x40A7AC",
        "native@0x40A7AE",
        "native@0x40A7BA",
        "native@0x40A7CD",
        "native@0x40A7E5",
        "native@0x40A7EF",
        "native@0x40B4C5",
        "native@0x40B4E2",
        "native@0x40B4EE",
        "native@0x40AEE6",
        "native@0x40AEF4",
        "native@0x40AEFA",
        "native@0x40AEFE",
    ),
    native_body_ranges=(
        (0x40A607, 0x40A61B),
        (0x40A61B, 0x40A633),
        (0x40A680, 0x40A68C),
        (0x40A68C, 0x40A6A6),
        (0x40A6A6, 0x40A6DA),
        (0x40A6DA, 0x40A6F4),
        (0x40A6F4, 0x40A70E),
        (0x40A70E, 0x40A73F),
        (0x40A740, 0x40A74C),
        (0x40A74C, 0x40A794),
        (0x40A794, 0x40A7AE),
        (0x40A7AE, 0x40A7F1),
        (0x40A800, 0x40A81A),
        (0x40A81A, 0x40A834),
        (0x40A834, 0x40A84E),
        (0x40A84E, 0x40A868),
        (0x40A868, 0x40A8A9),
        (0x40A8B5, 0x40A8CF),
        (0x40A8CF, 0x40A8E9),
        (0x40A960, 0x40A97A),
        (0x40A9DE, 0x40A9F8),
        (0x40AA60, 0x40AA7A),
        (0x40AB76, 0x40AB90),
        (0x40ABC6, 0x40ABE0),
        (0x40AC3D, 0x40AC56),
        (0x40ACBF, 0x40ACD9),
        (0x40AE8B, 0x40AEA5),
        (0x40AEE6, 0x40AF00),
        (0x40AFDF, 0x40AFF9),
        (0x40B4C5, 0x40B4F0),
        (0x40B6C0, 0x40B6D6),
    ),
    native_body_proof_ids=(
        "native-body@0x40A605",
        _DIRECT_ROUTE.operation_id,
        _DEPENDENCY_ROUTE.operation_id,
        _SELECTED_ROUTE.operation_id,
        _ROW9_EXISTING_ROUTE.operation_id,
        _ROW10_EXISTING_ROUTE.operation_id,
        _ROW11_EXISTING_ROUTE.operation_id,
        _ROW12_EXISTING_ROUTE.operation_id,
        _FOURTH_DIRECT_ROUTE.operation_id,
        _FOURTH_EXISTING_ROUTE.operation_id,
        _SETCC_ROUTE.operation_id,
        _FIFTH_SETCC_ROUTE.operation_id,
        _SIXTH_EXISTING_ROUTE.operation_id,
        _ROW20_EXISTING_ROUTE.operation_id,
        _ROW21_EXISTING_ROUTE.operation_id,
        _ROW22_EXISTING_ROUTE.operation_id,
        _ROW23_EXISTING_ROUTE.operation_id,
        _ROW26_EXISTING_ROUTE.operation_id,
    ),
    template_fragments=(
        RhadGeneratedTemplateFragment(
            root_ea=0x40A607,
            owned_ranges=(
                (0x40A607, 0x40A615),
                (0x40A615, 0x40A61B),
                (0x40A680, 0x40A68C),
            ),
            owned_block_entry_eas=(0x40A607, 0x40A615, 0x40A680),
            boundary_ranges=(
                (0x40A61B, 0x40A62D),
                (0x40A68C, 0x40A69A),
            ),
            boundary_exit_eas=(0x40A61B, 0x40A68C),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B6C0,
            owned_ranges=(
                (0x40B6C0, 0x40B6CA),
                (0x40B6CA, 0x40B6D0),
                (0x40B6D0, 0x40B6D6),
            ),
            owned_block_entry_eas=(0x40B6C0, 0x40B6CA, 0x40B6D0),
            boundary_ranges=((0x40B790, 0x40B79E),),
            boundary_exit_eas=(0x40B790,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A61B,
            owned_ranges=(
                (0x40A61B, 0x40A62D),
                (0x40A62D, 0x40A633),
                (0x40A740, 0x40A74C),
            ),
            owned_block_entry_eas=(0x40A61B, 0x40A62D, 0x40A740),
            boundary_ranges=(
                (0x40A633, 0x40A645),
                (0x40A74C, 0x40A75A),
            ),
            boundary_exit_eas=(0x40A633, 0x40A74C),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A68C,
            owned_ranges=(
                (0x40A68C, 0x40A69A),
                (0x40A69A, 0x40A6A0),
                (0x40A6A0, 0x40A6A6),
            ),
            owned_block_entry_eas=(0x40A68C, 0x40A69A, 0x40A6A0),
            boundary_ranges=((0x40A800, 0x40A80E),),
            boundary_exit_eas=(0x40A800,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A6A6,
            owned_ranges=(
                (0x40A6A6, 0x40A6B4),
                (0x40A6B4, 0x40A6BA),
                (0x40A6BA, 0x40A6C0),
            ),
            owned_block_entry_eas=(0x40A6A6, 0x40A6B4, 0x40A6BA, 0x40A6BE),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A6C0, 0x40A960),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A6BE,
                    boundary_exit_eas=(0x40A6C0, 0x40A960),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A6C0,
            owned_ranges=(
                (0x40A6C0, 0x40A6CE),
                (0x40A6CE, 0x40A6D4),
                (0x40A6D4, 0x40A6DA),
            ),
            owned_block_entry_eas=(0x40A6C0, 0x40A6CE, 0x40A6D4, 0x40A6D8),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A6DA, 0x40AB76),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A6D8,
                    boundary_exit_eas=(0x40A6DA, 0x40AB76),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A960,
            owned_ranges=(
                (0x40A960, 0x40A96E),
                (0x40A96E, 0x40A974),
                (0x40A974, 0x40A97A),
            ),
            owned_block_entry_eas=(0x40A960, 0x40A96E, 0x40A974, 0x40A978),
            boundary_ranges=(),
            boundary_exit_eas=(0x40AD1E,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A978,
                    boundary_exit_eas=(0x40AD1E,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A6DA,
            owned_ranges=(
                (0x40A6DA, 0x40A6E8),
                (0x40A6E8, 0x40A6EE),
                (0x40A6EE, 0x40A6F4),
            ),
            owned_block_entry_eas=(0x40A6DA, 0x40A6E8, 0x40A6EE, 0x40A6F2),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A6F4, 0x40AE8B),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A6F2,
                    boundary_exit_eas=(0x40A6F4, 0x40AE8B),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AB76,
            owned_ranges=(
                (0x40AB76, 0x40AB84),
                (0x40AB84, 0x40AB8A),
                (0x40AB8A, 0x40AB90),
            ),
            owned_block_entry_eas=(0x40AB76, 0x40AB84, 0x40AB8A, 0x40AB8E),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B17F,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AB8E,
                    boundary_exit_eas=(0x40B17F,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A6F4,
            owned_ranges=(
                (0x40A6F4, 0x40A702),
                (0x40A702, 0x40A708),
                (0x40A708, 0x40A70E),
            ),
            owned_block_entry_eas=(0x40A6F4, 0x40A702, 0x40A708, 0x40A70C),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40A70E),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A70C,
                    boundary_exit_eas=(0x40A5F0, 0x40A70E),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AE8B,
            owned_ranges=(
                (0x40AE8B, 0x40AE99),
                (0x40AE99, 0x40AE9F),
                (0x40AE9F, 0x40AEA5),
            ),
            owned_block_entry_eas=(0x40AE8B, 0x40AE99, 0x40AE9F, 0x40AEA3),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AEA3,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A70E,
            owned_ranges=((0x40A70E, 0x40A73F),),
            owned_block_entry_eas=(0x40A70E, 0x40A736, 0x40A739, 0x40A73D),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A73D,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A800,
            owned_ranges=(
                (0x40A800, 0x40A80E),
                (0x40A80E, 0x40A814),
                (0x40A814, 0x40A81A),
            ),
            owned_block_entry_eas=(0x40A800, 0x40A80E, 0x40A814, 0x40A818),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A81A, 0x40AA60),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A818,
                    boundary_exit_eas=(0x40A81A, 0x40AA60),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A81A,
            owned_ranges=(
                (0x40A81A, 0x40A828),
                (0x40A828, 0x40A82E),
                (0x40A82E, 0x40A834),
            ),
            owned_block_entry_eas=(0x40A81A, 0x40A828, 0x40A82E, 0x40A832),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A834, 0x40AC3D),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A832,
                    boundary_exit_eas=(0x40A834, 0x40AC3D),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A834,
            owned_ranges=(
                (0x40A834, 0x40A842),
                (0x40A842, 0x40A848),
                (0x40A848, 0x40A84E),
            ),
            owned_block_entry_eas=(0x40A834, 0x40A842, 0x40A848, 0x40A84C),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A84E, 0x40AFDF),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A84C,
                    boundary_exit_eas=(0x40A84E, 0x40AFDF),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A84E,
            owned_ranges=(
                (0x40A84E, 0x40A85C),
                (0x40A85C, 0x40A862),
                (0x40A862, 0x40A868),
            ),
            owned_block_entry_eas=(0x40A84E, 0x40A85C, 0x40A862, 0x40A866),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40A868),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A866,
                    boundary_exit_eas=(0x40A5F0, 0x40A868),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AFDF,
            owned_ranges=(
                (0x40AFDF, 0x40AFED),
                (0x40AFED, 0x40AFF3),
                (0x40AFF3, 0x40AFF9),
            ),
            owned_block_entry_eas=(0x40AFDF, 0x40AFED, 0x40AFF3, 0x40AFF7),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AFF7,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A868,
            owned_ranges=((0x40A868, 0x40A8A9),),
            owned_block_entry_eas=(0x40A868, 0x40A8A0, 0x40A8A3, 0x40A8A7),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A8A7,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A8B5,
            owned_ranges=((0x40A8B5, 0x40A8CF),),
            owned_block_entry_eas=(0x40A8B5, 0x40A8C3, 0x40A8C9, 0x40A8CD),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A8CF, 0x40ACBF),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A8CD,
                    boundary_exit_eas=(0x40A8CF, 0x40ACBF),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A8CF,
            owned_ranges=((0x40A8CF, 0x40A8E9),),
            owned_block_entry_eas=(0x40A8CF, 0x40A8DD, 0x40A8E3, 0x40A8E7),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A8E9, 0x40B024),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A8E7,
                    boundary_exit_eas=(0x40A8E9, 0x40B024),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ACBF,
            owned_ranges=((0x40ACBF, 0x40ACD9),),
            owned_block_entry_eas=(0x40ACBF, 0x40ACCD, 0x40ACD3, 0x40ACD7),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B26D,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ACD7,
                    boundary_exit_eas=(0x40B26D,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AC3D,
            owned_ranges=(
                (0x40AC3D, 0x40AC4A),
                (0x40AC4A, 0x40AC50),
                (0x40AC50, 0x40AC56),
            ),
            owned_block_entry_eas=(0x40AC3D, 0x40AC4A, 0x40AC50, 0x40AC54),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B21C,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AC54,
                    boundary_exit_eas=(0x40B21C,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AA60,
            owned_ranges=(
                (0x40AA60, 0x40AA6E),
                (0x40AA6E, 0x40AA74),
                (0x40AA74, 0x40AA7A),
            ),
            owned_block_entry_eas=(0x40AA60, 0x40AA6E, 0x40AA74, 0x40AA78),
            boundary_ranges=(),
            boundary_exit_eas=(0x40ADBE,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AA78,
                    boundary_exit_eas=(0x40ADBE,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A74C,
            owned_ranges=(
                (0x40A74C, 0x40A75A),
                (0x40A75A, 0x40A760),
                (0x40A760, 0x40A766),
            ),
            owned_block_entry_eas=(0x40A74C, 0x40A75A, 0x40A760),
            boundary_ranges=(),
            boundary_exit_eas=(),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A764,
                    boundary_exit_eas=(),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A766,
            owned_ranges=((0x40A766, 0x40A77E),),
            owned_block_entry_eas=(0x40A766,),
            boundary_ranges=(),
            boundary_exit_eas=(),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A77C,
                    boundary_exit_eas=(),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A9DE,
            owned_ranges=(
                (0x40A9DE, 0x40A9EC),
                (0x40A9EC, 0x40A9F2),
                (0x40A9F2, 0x40A9F8),
            ),
            owned_block_entry_eas=(0x40A9DE, 0x40A9EC, 0x40A9F2),
            boundary_ranges=(),
            boundary_exit_eas=(0x40AD6E,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A9F6,
                    boundary_exit_eas=(0x40AD6E,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A77E,
            owned_ranges=((0x40A77E, 0x40A794),),
            owned_block_entry_eas=(0x40A77E,),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A794, 0x40AEE6),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A792,
                    boundary_exit_eas=(0x40A794, 0x40AEE6),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ABC6,
            owned_ranges=(
                (0x40ABC6, 0x40ABD4),
                (0x40ABD4, 0x40ABDA),
                (0x40ABDA, 0x40ABE0),
            ),
            owned_block_entry_eas=(0x40ABC6, 0x40ABD4, 0x40ABDA),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B1D0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ABDE,
                    boundary_exit_eas=(0x40B1D0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A794,
            owned_ranges=(
                (0x40A794, 0x40A7A2),
                (0x40A7A2, 0x40A7A8),
                (0x40A7A8, 0x40A7AE),
            ),
            owned_block_entry_eas=(0x40A794, 0x40A7A2, 0x40A7A8),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A7AC,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A7AE,
            owned_ranges=(
                (0x40A7AE, 0x40A7BA),
                (0x40A7BA, 0x40A7CD),
                (0x40A7CD, 0x40A7E5),
                (0x40A7E5, 0x40A7F1),
                (0x40B4C5, 0x40B4E2),
                (0x40B4E2, 0x40B4F0),
            ),
            owned_block_entry_eas=(
                0x40A7AE,
                0x40A7BA,
                0x40A7CD,
                0x40A7E5,
                0x40B4C5,
                0x40B4E2,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A7EF,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B4EE,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AEE6,
            owned_ranges=(
                (0x40AEE6, 0x40AEF4),
                (0x40AEF4, 0x40AEFA),
                (0x40AEFA, 0x40AF00),
            ),
            owned_block_entry_eas=(0x40AEE6, 0x40AEF4, 0x40AEFA),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AEFE,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
    ),
    operations=(
        _ACCEPTED_ROUTE,
        _DIRECT_ROUTE,
        _DEPENDENCY_ROUTE,
        _SELECTED_ROUTE,
        _ROW9_EXISTING_ROUTE,
        _ROW10_EXISTING_ROUTE,
        _ROW11_EXISTING_ROUTE,
        _ROW12_EXISTING_ROUTE,
        _FOURTH_DIRECT_ROUTE,
        _FOURTH_EXISTING_ROUTE,
        _SETCC_ROUTE,
        _FIFTH_SETCC_ROUTE,
        _SIXTH_EXISTING_ROUTE,
        _ROW20_EXISTING_ROUTE,
        _ROW21_EXISTING_ROUTE,
        _ROW22_EXISTING_ROUTE,
        _ROW23_EXISTING_ROUTE,
        _ROW26_EXISTING_ROUTE,
    ),
    required_boundary_exit_eas=BOUNDARY_EXIT_EAS,
    reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
    reference_binary_sha256="1" * 64,
    runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
    runtime_image_id="sha256:360f91d9d4ac",
)

_GENERATED_REFERENCE_BATCHES = (_A560_GENERATED_REFERENCE_BATCH,)


def reference_batch_for_native_key(
    native_key: NativePreanalysisKey,
) -> RhadGeneratedReferenceBatch | None:
    """Select exact-input production evidence without sample-specific dispatch."""
    if not isinstance(native_key, NativePreanalysisKey):
        raise TypeError("Rhad GENERATED registry requires a native preanalysis key")
    input_identity = str(native_key.input_identity).lower()
    return next(
        (
            batch
            for batch in _GENERATED_REFERENCE_BATCHES
            if input_identity == f"sha256:{batch.input_sha256.lower()}"
            and int(native_key.function_rva) == int(batch.native_function_rva)
        ),
        None,
    )


FUNCTION_EA = _A560_GENERATED_REFERENCE_BATCH.function_ea
SOURCE_EA = _A560_GENERATED_REFERENCE_BATCH.source.start_ea
TRANSFER_EA = _ACCEPTED_ROUTE.transfer_ea


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
            evidence_generation=int(session.native_preanalysis.evidence_generation),
            mba_generation_before=int(session.current_mba_generation),
            mba_generation_after=int(session.current_mba_generation),
            summary=str(summary),
            payload=dict(payload),
        )
    )


def observe_rhad_generated_reference_preparation(
    session: object,
    *,
    batch: RhadGeneratedReferenceBatch,
    prepared: bool,
) -> None:
    """Record the immutable target-template authority before publication."""
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
            "batch_id": batch.batch_id,
            "aggregate_program_identity": batch.aggregate_program_identity,
            "proof_artifact_identities": list(batch.proof_artifact_identities),
            "template_root_eas": list(batch.template_root_eas),
            "imported_ranges": [
                [block.start_ea, block.end_ea] for block in batch.imported_blocks
            ],
            "imported_block_count": len(batch.imported_blocks),
            "boundary_exit_eas": list(batch.required_boundary_exit_eas),
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


def _typed_delivery_block_closure(
    batch: RhadGeneratedReferenceBatch,
    root_block_id: str,
) -> tuple[str, ...]:
    """Expand one semantic target through typed downstream operations."""
    pending = [str(root_block_id)]
    closure: list[str] = []
    seen: set[str] = set()
    while pending:
        block_id = pending.pop(0)
        if block_id in seen:
            continue
        seen.add(block_id)
        closure.append(block_id)
        for operation in batch.operations:
            if operation.source_block_id != block_id:
                continue
            if isinstance(operation, RhadDirectRoute):
                targets = (operation.direct_target_block_id,)
            elif isinstance(
                operation,
                (
                    RhadConditionalRoute,
                    RhadExistingConditionalRoute,
                    RhadSetccIndexedTableRoute,
                ),
            ):
                targets = (
                    operation.true_target_block_id,
                    operation.false_target_block_id,
                )
            else:
                continue
            pending.extend(str(target) for target in targets if str(target) not in seen)
    return tuple(closure)


def _reference_batch_observation(
    mba: object,
    batch: RhadGeneratedReferenceBatch,
) -> dict[str, object]:
    """Observe every committed route without building or changing a live graph."""
    import ida_hexrays

    from d810.hexrays.mutation.detached_handler_island import (
        imported_detached_snippet_instruction_origins,
    )

    origins = dict(imported_detached_snippet_instruction_origins(mba))
    blocks = {serial: mba.get_mblock(serial) for serial in range(int(mba.qty))}
    block_anchor_by_id = {
        evidence.block_id: int(evidence.start_ea)
        for evidence in (
            batch.predecessor,
            batch.source,
            *batch.auxiliary_blocks,
            *batch.imported_blocks,
        )
    }
    block_evidence_by_id = {
        evidence.block_id: evidence
        for evidence in (
            batch.predecessor,
            batch.source,
            *batch.auxiliary_blocks,
            *batch.imported_blocks,
        )
    }

    def delivery_anchor(
        block: object,
        target_block_ids: tuple[str, ...],
    ) -> int:
        """Canonicalize an optimized live anchor through typed target ownership."""
        live_anchor = _native_anchor(block, origins)
        rooted_targets = tuple(
            dict.fromkeys(
                block_anchor_by_id[block_id]
                for block_id in target_block_ids
                for owned_block_id in _typed_delivery_block_closure(batch, block_id)
                for root_ea in (block_anchor_by_id[owned_block_id],)
                for fragment in batch.template_fragments
                if int(fragment.root_ea) == int(root_ea)
                and any(
                    int(start_ea) <= live_anchor < int(end_ea)
                    for start_ea, end_ea in fragment.owned_ranges
                )
            )
        )
        if not rooted_targets:
            rooted_targets = tuple(
                dict.fromkeys(
                    block_anchor_by_id[block_id]
                    for block_id in target_block_ids
                    for owned_block_id in _typed_delivery_block_closure(batch, block_id)
                    for evidence in (block_evidence_by_id[owned_block_id],)
                    if int(evidence.start_ea) <= live_anchor < int(evidence.end_ea)
                )
            )
        return int(rooted_targets[0]) if len(rooted_targets) == 1 else live_anchor

    def delivery_targets_reachable(target_block_ids: tuple[str, ...]) -> bool:
        expected = {block_anchor_by_id[block_id] for block_id in target_block_ids}
        observed = {
            delivery_anchor(blocks[serial], target_block_ids)
            for serial in reachable_block_serials
        }
        return expected.issubset(observed)

    def reachable_serials() -> set[int]:
        reachable: set[int] = set()
        pending = [0]
        while pending:
            serial = pending.pop()
            if serial in reachable:
                continue
            reachable.add(serial)
            pending.extend(int(value) for value in blocks[serial].succset)
        return reachable

    reachable_block_serials = reachable_serials()

    accepted_route = next(
        operation
        for operation in batch.operations
        if isinstance(operation, RhadConditionalRoute)
    )
    accepted_indirect = any(
        int(row.opcode) == int(ida_hexrays.m_ijmp)
        and int(origins.get(int(row.ea), int(row.ea))) == accepted_route.transfer_ea
        for block in blocks.values()
        for row in _instructions(block)
    )
    accepted_source = next(
        (
            block
            for block in blocks.values()
            if any(
                int(origins.get(int(row.ea), int(row.ea)))
                == accepted_route.condition_producer_ea
                for row in _instructions(block)
            )
        ),
        None,
    )
    reachable = tuple(
        sorted(
            {
                _native_anchor(blocks[serial], origins)
                for serial in reachable_block_serials
            }
        )
    )
    if accepted_source is None:
        accepted_targets: set[int] = set()
        accepted_passed = (
            not accepted_indirect
            and block_anchor_by_id[accepted_route.true_target_block_id] in reachable
        )
    else:
        accepted_targets = set()
        source_successors = tuple(int(value) for value in accepted_source.succset)
        if source_successors:
            for successor_serial in source_successors:
                target = blocks[successor_serial]
                while (
                    _native_anchor(target, origins)
                    in {
                        accepted_route.conditional_select_ea,
                        block_anchor_by_id[accepted_route.join_block_id],
                    }
                    and len(tuple(target.succset)) == 1
                ):
                    successor_serial = int(tuple(target.succset)[0])
                    target = blocks[successor_serial]
                accepted_targets.add(_native_anchor(target, origins))
        else:
            if (
                accepted_source.nextb is not None
                and accepted_source.nextb.nextb is not None
            ):
                route_rows = (
                    *(_instructions(accepted_source)[-1:]),
                    *(_instructions(accepted_source.nextb)[-1:]),
                    *(_instructions(accepted_source.nextb.nextb)[-1:]),
                )
                for row in route_rows:
                    opcode = int(row.opcode)
                    operand = row.l if opcode == int(ida_hexrays.m_goto) else row.d
                    if int(operand.t) != int(ida_hexrays.mop_b):
                        continue
                    accepted_targets.add(
                        _native_anchor(blocks[int(operand.b)], origins)
                    )
        expected_accepted_targets = {
            block_anchor_by_id[accepted_route.true_target_block_id],
            block_anchor_by_id[accepted_route.false_target_block_id],
        }
        accepted_passed = (
            not accepted_indirect and accepted_targets == expected_accepted_targets
        )

    operation_observations: list[dict[str, object]] = [
        {
            "operation_id": accepted_route.operation_id,
            "operation_category": accepted_route.category.value,
            "source_present": accepted_source is not None,
            "indirect_transfer_present": accepted_indirect,
            "target_eas": sorted(accepted_targets),
            "passed": accepted_passed,
        }
    ]
    for direct_route in (
        operation
        for operation in batch.operations
        if isinstance(operation, RhadDirectRoute)
    ):
        direct_target_ea = block_anchor_by_id[direct_route.direct_target_block_id]
        direct_indirect = any(
            int(row.opcode)
            in {
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_icall),
            }
            and int(origins.get(int(row.ea), int(row.ea)))
            == int(direct_route.transfer_ea)
            for block in blocks.values()
            for row in _instructions(block)
        )

        def direct_targets_for(block: object) -> set[int]:
            target_eas: set[int] = set()
            for successor_serial in tuple(int(value) for value in block.succset):
                target_eas.add(_native_anchor(blocks[successor_serial], origins))
            if not target_eas and block.tail is not None:
                tail = block.tail
                operand = (
                    tail.l if int(tail.opcode) == int(ida_hexrays.m_goto) else tail.d
                )
                if int(operand.t) == int(ida_hexrays.mop_b):
                    target_eas.add(_native_anchor(blocks[int(operand.b)], origins))
            return target_eas

        direct_source = next(
            (
                block
                for block in blocks.values()
                if block.tail is not None
                and int(origins.get(int(block.tail.ea), int(block.tail.ea)))
                == int(direct_route.transfer_ea)
                and direct_targets_for(block) == {direct_target_ea}
            ),
            None,
        )
        direct_targets = (
            set() if direct_source is None else direct_targets_for(direct_source)
        )
        source_topology_reachable = bool(
            direct_source is not None
            and (
                int(mba.maturity) == int(ida_hexrays.MMAT_GENERATED)
                or int(direct_source.serial) in reachable_block_serials
            )
        )
        direct_passed = not direct_indirect and (
            direct_targets == {direct_target_ea} if source_topology_reachable else True
        )
        operation_observations.append(
            {
                "operation_id": direct_route.operation_id,
                "operation_category": direct_route.category.value,
                "source_present": direct_source is not None,
                "source_topology_reachable": source_topology_reachable,
                "source_topology_retired": not source_topology_reachable,
                "indirect_transfer_present": direct_indirect,
                "target_eas": sorted(direct_targets),
                "boundary_exit_eas": sorted(direct_route.boundary_exit_eas),
                "passed": direct_passed,
            }
        )

    for conditional_route in (
        operation
        for operation in batch.operations
        if isinstance(operation, RhadExistingConditionalRoute)
    ):
        conditional_target_block_ids = (
            conditional_route.true_target_block_id,
            conditional_route.false_target_block_id,
        )
        delivery_target_eas = {
            block_anchor_by_id[block_id] for block_id in conditional_target_block_ids
        }
        conditional_indirect = any(
            int(row.opcode) == int(ida_hexrays.m_ijmp)
            and int(origins.get(int(row.ea), int(row.ea)))
            == int(conditional_route.transfer_ea)
            for block in blocks.values()
            for row in _instructions(block)
        )
        conditional_source = next(
            (
                block
                for block in blocks.values()
                if any(
                    int(origins.get(int(row.ea), int(row.ea)))
                    == int(conditional_route.condition_producer_ea)
                    for row in _instructions(block)
                )
            ),
            None,
        )
        conditional_targets: set[int] = set()
        if conditional_source is not None:
            source_successors = tuple(
                int(value) for value in conditional_source.succset
            )
            if source_successors:
                for successor_serial in source_successors:
                    target = blocks[successor_serial]
                    while (
                        _native_anchor(target, origins)
                        in {
                            int(conditional_route.selected_value_ea),
                            block_anchor_by_id[conditional_route.join_block_id],
                        }
                        and len(tuple(target.succset)) == 1
                    ):
                        successor_serial = int(tuple(target.succset)[0])
                        target = blocks[successor_serial]
                    conditional_targets.add(
                        delivery_anchor(target, conditional_target_block_ids)
                    )
            else:
                corridor_blocks = [conditional_source]
                if conditional_source.nextb is not None:
                    corridor_blocks.append(conditional_source.nextb)
                    if conditional_source.nextb.nextb is not None:
                        corridor_blocks.append(conditional_source.nextb.nextb)
                for block in corridor_blocks:
                    if block.tail is None:
                        continue
                    opcode = int(block.tail.opcode)
                    operand = (
                        block.tail.l
                        if opcode == int(ida_hexrays.m_goto)
                        else block.tail.d
                    )
                    if int(operand.t) == int(ida_hexrays.mop_b):
                        conditional_targets.add(
                            delivery_anchor(
                                blocks[int(operand.b)],
                                conditional_target_block_ids,
                            )
                        )
        source_topology_reachable = bool(
            conditional_source is not None
            and (
                int(mba.maturity) == int(ida_hexrays.MMAT_GENERATED)
                or int(conditional_source.serial) in reachable_block_serials
            )
        )
        semantic_targets_survive = bool(
            not source_topology_reachable
            or (
                conditional_targets == delivery_target_eas
                and (
                    int(mba.maturity) == int(ida_hexrays.MMAT_GENERATED)
                    or delivery_targets_reachable(conditional_target_block_ids)
                )
            )
        )
        operation_observations.append(
            {
                "operation_id": conditional_route.operation_id,
                "operation_category": conditional_route.category.value,
                "operation_variant": conditional_route.operation_variant.value,
                "source_present": conditional_source is not None,
                "source_topology_reachable": source_topology_reachable,
                "source_topology_retired": not source_topology_reachable,
                "indirect_transfer_present": conditional_indirect,
                "target_eas": sorted(conditional_targets),
                "semantic_target_eas": sorted(
                    {
                        int(conditional_route.true_target_ea),
                        int(conditional_route.false_target_ea),
                    }
                ),
                "delivery_target_eas": sorted(delivery_target_eas),
                "semantic_targets_survive": semantic_targets_survive,
                "boundary_exit_eas": sorted(conditional_route.boundary_exit_eas),
                "passed": not conditional_indirect and semantic_targets_survive,
            }
        )

    for setcc_route in (
        operation
        for operation in batch.operations
        if isinstance(operation, RhadSetccIndexedTableRoute)
    ):
        setcc_target_block_ids = (
            setcc_route.true_target_block_id,
            setcc_route.false_target_block_id,
        )
        delivery_target_eas = {
            block_anchor_by_id[block_id] for block_id in setcc_target_block_ids
        }
        setcc_indirect = any(
            int(row.opcode)
            in {
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_icall),
            }
            and int(origins.get(int(row.ea), int(row.ea)))
            == int(setcc_route.transfer_ea)
            for block in blocks.values()
            for row in _instructions(block)
        )
        setcc_source = next(
            (
                block
                for block in blocks.values()
                if any(
                    int(origins.get(int(row.ea), int(row.ea)))
                    == int(setcc_route.predicate_anchor_ea)
                    for row in _instructions(block)
                )
            ),
            None,
        )
        setcc_targets: set[int] = set()
        if setcc_source is not None:
            source_successors = tuple(int(value) for value in setcc_source.succset)
            if source_successors:
                for successor_serial in source_successors:
                    setcc_targets.add(
                        delivery_anchor(
                            blocks[successor_serial],
                            setcc_target_block_ids,
                        )
                    )
            else:
                corridor_blocks = [setcc_source]
                if setcc_source.nextb is not None:
                    corridor_blocks.append(setcc_source.nextb)
                    if setcc_source.nextb.nextb is not None:
                        corridor_blocks.append(setcc_source.nextb.nextb)
                for block in corridor_blocks:
                    if block.tail is None:
                        continue
                    opcode = int(block.tail.opcode)
                    operand = (
                        block.tail.l
                        if opcode == int(ida_hexrays.m_goto)
                        else block.tail.d
                    )
                    if int(operand.t) == int(ida_hexrays.mop_b):
                        setcc_targets.add(
                            delivery_anchor(
                                blocks[int(operand.b)],
                                setcc_target_block_ids,
                            )
                        )
        source_topology_reachable = bool(
            setcc_source is not None
            and (
                int(mba.maturity) == int(ida_hexrays.MMAT_GENERATED)
                or int(setcc_source.serial) in reachable_block_serials
            )
        )
        semantic_targets_survive = bool(
            not source_topology_reachable
            or (
                setcc_targets == delivery_target_eas
                and (
                    int(mba.maturity) == int(ida_hexrays.MMAT_GENERATED)
                    or delivery_targets_reachable(setcc_target_block_ids)
                )
            )
        )
        operation_observations.append(
            {
                "operation_id": setcc_route.operation_id,
                "operation_category": setcc_route.category.value,
                "operation_variant": setcc_route.operation_variant.value,
                "source_present": setcc_source is not None,
                "source_topology_reachable": source_topology_reachable,
                "source_topology_retired": not source_topology_reachable,
                "indirect_transfer_present": setcc_indirect,
                "target_eas": sorted(setcc_targets),
                "semantic_target_eas": sorted(
                    {
                        int(setcc_route.true_target_ea),
                        int(setcc_route.false_target_ea),
                    }
                ),
                "delivery_target_eas": sorted(delivery_target_eas),
                "semantic_targets_survive": semantic_targets_survive,
                "boundary_exit_eas": sorted(setcc_route.boundary_exit_eas),
                "passed": not setcc_indirect and semantic_targets_survive,
            }
        )

    return {
        "batch_id": batch.batch_id,
        "operation_observations": operation_observations,
        "reachable_eas": list(reachable),
        "passed": all(bool(row["passed"]) for row in operation_observations),
    }


def observe_rhad_generated_reference_maturity(
    *,
    function_ea: int,
    mba: object,
    decision: dict[str, object],
    maturity_override: str | None = None,
) -> None:
    """Persist one deduplicated batch-specific maturity observation."""
    session = decision.get("session")
    if session is None:
        return
    batch = reference_batch_for_native_key(session.native_key)
    if (
        batch is None
        or int(function_ea) != int(batch.function_ea)
        or int(mba.entry_ea) != int(batch.function_ea)
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
    observation = _reference_batch_observation(mba, batch)
    _emit_checksum_lifecycle(
        session,
        event_kind="rhad_generated_checksum_maturity",
        maturity=maturity,
        phase="route_survival",
        summary=(
            f"Rhad GENERATED reference batch "
            f"{'passed' if observation['passed'] else 'failed'} at {maturity}"
        ),
        payload=observation,
    )


def observe_rhad_generated_reference_preopt(**kwargs: object) -> None:
    observe_rhad_generated_reference_maturity(
        **kwargs,
        maturity_override="MMAT_PREOPTIMIZED",
    )


def observe_rhad_generated_reference_locopt(**kwargs: object) -> None:
    observe_rhad_generated_reference_maturity(
        **kwargs,
        maturity_override="MMAT_LOCOPT",
    )


def observe_rhad_generated_reference_calls(**kwargs: object) -> None:
    # Hex-Rays invokes hxe_calls_done after call analysis while the live MBA's
    # numeric maturity still reports LOCOPT.  The callback boundary, not that
    # lagging field, is the authoritative CALLS observation label.
    observe_rhad_generated_reference_maturity(
        **kwargs,
        maturity_override="MMAT_CALLS",
    )


def prepare_rhad_generated_reference_templates(
    state: object,
    batch: RhadGeneratedReferenceBatch,
) -> bool:
    """Capture every typed target-rooted PREOPT body before the live MBA exists."""
    resolution = state.portable_evidence.computed_goto_resolution
    if resolution is None or int(resolution.function_ea) != int(batch.function_ea):
        return False

    import ida_hexrays
    import idaapi

    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg
    from d810.hexrays.mutation.detached_handler_island import (
        capture_generated_reference_snippet_template,
    )

    captured = 0
    for fragment in batch.template_fragments:
        target_ea = int(fragment.root_ea)
        mba_ranges = ida_hexrays.mba_ranges_t()
        for start_ea, end_ea in (
            *fragment.owned_ranges,
            *fragment.boundary_ranges,
        ):
            mba_ranges.ranges.push_back(idaapi.range_t(start_ea, end_ea))
        failure = ida_hexrays.hexrays_failure_t()
        if not state.begin_snippet_capture(target_ea):
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
                    "GENERATED checksum target capture failed: target=0x%X reason=%s",
                    target_ea,
                    failure.desc(),
                )
                return False
            target_mba.build_graph()
            fragment_captured = capture_generated_reference_snippet_template(
                batch.function_ea,
                target_ea,
                target_mba,
                fragment.owned_ranges,
                boundary_ranges=fragment.boundary_ranges,
                boundary_exit_eas=fragment.boundary_exit_eas,
                owned_block_entry_eas=fragment.owned_block_entry_eas,
                direct_boundary_routes=fragment.direct_boundary_routes,
                preserved_unresolved_transfer_exits=(
                    fragment.preserved_transfer_exit_map
                ),
            )
            logger.info(
                "GENERATED checksum template result: target=0x%X captured=%s",
                target_ea,
                fragment_captured,
            )
            captured += int(fragment_captured)
        finally:
            state.finish_snippet_capture()
    logger.info(
        "prepared GENERATED checksum target templates: captured=%d",
        captured,
    )
    return captured == len(batch.template_fragments)


def _identity(native_key, start_ea: int, end_ea: int, *eas: int):
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(int(start_ea), int(end_ea)),),
        native_key=native_key,
        exact_instruction_eas=tuple(eas or (int(start_ea),)),
    )


def build_rhad_generated_reference_plan(
    *,
    native_key: NativePreanalysisKey,
    evidence_generation: int,
) -> FragmentPlan:
    """Compile the exact-input typed batch without live-MBA access."""
    generation = int(evidence_generation)
    batch = reference_batch_for_native_key(native_key)
    if batch is None:
        raise ValueError("no Rhad GENERATED reference batch matches the native input")
    candidate_sha256 = str(native_key.input_identity).lower().removeprefix("sha256:")
    source_identity = _identity(
        native_key,
        batch.source.start_ea,
        batch.source.end_ea,
        *batch.source.exact_instruction_eas,
    )
    imported_operation_source_ids = frozenset(
        operation.source_block_id
        for operation in batch.operations
        if operation.source_block_id
        in {evidence.block_id for evidence in batch.imported_blocks}
    )
    blocks = (
        FragmentBlock(
            block_id=batch.predecessor.block_id,
            role=FragmentBlockRole.EXTERNAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=batch.predecessor.start_ea,
            stable_identity=_identity(
                native_key,
                batch.predecessor.start_ea,
                batch.predecessor.end_ea,
                *batch.predecessor.exact_instruction_eas,
            ),
        ),
        FragmentBlock(
            block_id=batch.source_original_id,
            role=FragmentBlockRole.ORIGINAL,
            materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
            semantic_anchor_ea=batch.source.start_ea,
            stable_identity=source_identity,
        ),
        FragmentBlock(
            block_id=batch.source.block_id,
            role=FragmentBlockRole.REPLACEMENT,
            materialization=FragmentBlockMaterialization.CLONE_PUBLISHED,
            semantic_anchor_ea=batch.source.start_ea,
            stable_identity=source_identity,
            replaces_block_id=batch.source_original_id,
        ),
        *(
            FragmentBlock(
                block_id=evidence.block_id,
                role=FragmentBlockRole.EXTERNAL,
                materialization=FragmentBlockMaterialization.REUSE_PUBLISHED,
                semantic_anchor_ea=evidence.start_ea,
                stable_identity=_identity(
                    native_key,
                    evidence.start_ea,
                    evidence.end_ea,
                    *evidence.exact_instruction_eas,
                ),
            )
            for evidence in batch.auxiliary_blocks
        ),
        *(
            FragmentBlock(
                block_id=evidence.block_id,
                role=FragmentBlockRole.IMPORTED,
                materialization=FragmentBlockMaterialization.IMPORT_NATIVE,
                semantic_anchor_ea=evidence.start_ea,
                stable_identity=_identity(
                    native_key,
                    evidence.start_ea,
                    evidence.end_ea,
                    *evidence.exact_instruction_eas,
                ),
                native_body_id=batch.native_body_id,
            )
            for evidence in batch.imported_blocks
        ),
    )
    placeholder_operations = tuple(
        FragmentOperation(
            operation_id=f"placeholder:{operation.operation_id}",
            source_block_id=operation.source_block_id,
            edges=(
                FragmentEdge(
                    role=SemanticEdgeRole.DIRECT,
                    target_block_id=(
                        operation.false_target_block_id
                        if isinstance(
                            operation,
                            (
                                RhadConditionalRoute,
                                RhadExistingConditionalRoute,
                                RhadSetccIndexedTableRoute,
                            ),
                        )
                        else operation.direct_target_block_id
                    ),
                ),
            ),
        )
        for operation in batch.operations
    )
    base_plan = FragmentPlan(
        plan_id=f"{batch.batch_id}-base",
        atomic_group_id=f"{batch.batch_id}:g{generation}",
        publication_purpose=FragmentPublicationPurpose.FRONTEND_NORMALIZATION,
        native_key=native_key,
        blocks=blocks,
        roots=(batch.source.block_id,),
        owned_originals=(batch.source_original_id,),
        prohibited_dispatcher_blocks=(),
        operations=placeholder_operations,
        work_item_scope=FragmentWorkItemScope(
            work_item_id=f"{batch.batch_id}:g{generation}",
            selected_obligation_ids=tuple(
                operation.operation_id for operation in batch.operations
            ),
            remaining_obligation_ids=(),
            unreachable_obligation_ids=(),
        ),
        native_bodies=(
            FragmentNativeBody(
                body_id=batch.native_body_id,
                block_ids=tuple(
                    evidence.block_id for evidence in batch.imported_blocks
                ),
                entry_block_ids=batch.native_body_entry_block_ids,
                terminal_block_ids=(),
                native_ranges=tuple(
                    NativeEaInterval(start_ea, end_ea)
                    for start_ea, end_ea in batch.native_body_ranges
                ),
                proof_ids=batch.native_body_proof_ids,
                preserved_native_transfer_block_ids=tuple(
                    evidence.block_id
                    for evidence in batch.imported_blocks
                    if evidence.block_id not in imported_operation_source_ids
                ),
            ),
        ),
    )
    ledger = RhadReferenceLedger(
        ledger_id=f"{batch.batch_id}:g{generation}",
        function_ea=batch.native_function_rva,
        native_function_ea=batch.function_ea,
        evidence_generation=generation,
        base_plan=base_plan,
        reference_oracle_run=RouteOracleRun(
            run_id=batch.batch_id,
            function_ea=batch.native_function_rva,
            fixture_sha256=batch.input_sha256,
            reference_binary_sha256=batch.reference_binary_sha256,
            candidate_binary_sha256=candidate_sha256,
            reference_commit=batch.reference_commit,
            runtime_image=batch.runtime_image,
            runtime_image_id=batch.runtime_image_id,
            cache_disabled=True,
        ),
        operations=batch.operations,
        required_boundary_exit_eas=batch.required_boundary_exit_eas,
        reference_provenance={
            "reference_commit": batch.reference_commit,
            "operation_shapes": tuple(
                operation.category.value for operation in batch.operations
            ),
        },
    )
    if ledger.aggregate_program_identity != batch.aggregate_program_identity:
        raise RhadCompilerRejection(
            "Rhad aggregate program identity differs from its proof artifacts"
        )
    plan = compile_rhad_reference_fragment(
        ledger,
        expected_evidence_generation=generation,
    )
    if not plan.plan_id.endswith(batch.aggregate_program_identity):
        raise RhadCompilerRejection(
            "Rhad compiled plan identity omits aggregate proof authority"
        )
    return plan


def publish_rhad_generated_reference_batch(
    *,
    function_ea: int,
    mba: object,
    decision: dict[str, object],
) -> None:
    """Compile and submit a selected batch through the sole live backend entry."""
    session = decision.get("session")
    gateway = decision.get("mutation_gateway")
    materializer = decision.get("semantic_native_body_materializer")
    logger.info(
        "GENERATED checksum boundary observed: session=%s gateway=%s materializer=%s",
        session is not None,
        gateway is not None,
        materializer is not None,
    )
    if session is None or gateway is None or materializer is None:
        return
    batch = reference_batch_for_native_key(session.native_key)
    if (
        batch is None
        or int(function_ea) != int(batch.function_ea)
        or int(mba.entry_ea) != int(batch.function_ea)
    ):
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
    plan = build_rhad_generated_reference_plan(
        native_key=session.native_key,
        evidence_generation=int(session.native_preanalysis.evidence_generation),
    )
    _emit_checksum_lifecycle(
        session,
        event_kind="rhad_generated_checksum_compiled",
        maturity="MMAT_GENERATED",
        phase="reference_compilation",
        summary="compiled one bounded Rhad GENERATED reference batch",
        payload={
            "batch_id": batch.batch_id,
            "plan_id": plan.plan_id,
            "atomic_group_id": plan.atomic_group_id,
            "aggregate_program_identity": batch.aggregate_program_identity,
            "proof_artifacts": [
                {
                    "content_identity": operation.table_proof_artifact.content_identity,
                    "proof": operation.table_proof_artifact.proof_payload,
                }
                for operation in batch.operations
                if isinstance(operation, RhadSetccIndexedTableRoute)
            ],
            "operation_ids": [operation.operation_id for operation in plan.operations],
            "reference_operations": [
                {
                    "operation_id": operation.operation_id,
                    "reference_ledger_identity": (
                        operation.reference_route_authority.reference_route.reference_ledger_identity
                    ),
                    "reference_ledger_json": (
                        operation.reference_route_authority.reference_route.reference_ledger_json
                    ),
                }
                for operation in plan.operations
            ],
            "imported_block_ids": [
                evidence.block_id for evidence in batch.imported_blocks
            ],
            "imported_block_count": len(batch.imported_blocks),
            "boundary_exit_eas": list(batch.required_boundary_exit_eas),
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
        publication_profile=(SemanticFragmentPublicationProfile.GENERATED_GRAPH_FREE),
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
            "aggregate_program_identity": batch.aggregate_program_identity,
            "proof_artifact_identities": list(batch.proof_artifact_identities),
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
    observe_rhad_generated_reference_maturity(
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
    "ACCEPTED_IMPORTED_BLOCK_IDS",
    "BOUNDARY_EXIT_EAS",
    "DIRECT_IMPORTED_BLOCK_IDS",
    "FUNCTION_EA",
    "IMPORTED_BLOCK_IDS",
    "IMPORTED_RANGES",
    "INPUT_SHA256",
    "ROW16_TABLE_PROOF_PATH",
    "ROW17_TABLE_PROOF_PATH",
    "SOURCE_EA",
    "TEMPLATE_ROOT_EAS",
    "TRANSFER_EA",
    "RhadGeneratedReferenceBatch",
    "build_rhad_generated_reference_plan",
    "prepare_rhad_generated_reference_templates",
    "load_row16_table_proof_artifact",
    "load_row17_table_proof_artifact",
    "publish_rhad_generated_reference_batch",
    "reference_batch_for_native_key",
]
