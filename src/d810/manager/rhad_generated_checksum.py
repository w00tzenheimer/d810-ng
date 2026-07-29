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
    FragmentSetccFallthroughDelivery,
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
    rhad_reference_operation_identity_payload,
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
ROW68_TABLE_PROOF_PATH = (
    Path(__file__).resolve().parents[1]
    / "conf"
    / "semantic_route_oracles"
    / "rhad_a560_row68_setcc_table_proof.json"
)
ROW96_TABLE_PROOF_PATH = (
    Path(__file__).resolve().parents[1]
    / "conf"
    / "semantic_route_oracles"
    / "rhad_a560_row96_setcc_table_proof.json"
)
ROW126_TABLE_PROOF_PATH = (
    Path(__file__).resolve().parents[1]
    / "conf"
    / "semantic_route_oracles"
    / "rhad_a560_row126_setcc_table_proof.json"
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


def load_row68_table_proof_artifact(
    path: Path = ROW68_TABLE_PROOF_PATH,
) -> RhadSetccIndexedTableProofArtifact:
    """Load the required canonical row-68 proof before any live mutation."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RhadCompilerRejection(
            f"Rhad row-68 table proof artifact is unavailable: {error}"
        ) from error
    return RhadSetccIndexedTableProofArtifact.from_mapping(payload)


def load_row96_table_proof_artifact(
    path: Path = ROW96_TABLE_PROOF_PATH,
) -> RhadSetccIndexedTableProofArtifact:
    """Load the required canonical row-96 proof before any live mutation."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RhadCompilerRejection(
            f"Rhad row-96 table proof artifact is unavailable: {error}"
        ) from error
    return RhadSetccIndexedTableProofArtifact.from_mapping(payload)


def load_row126_table_proof_artifact(
    path: Path = ROW126_TABLE_PROOF_PATH,
) -> RhadSetccIndexedTableProofArtifact:
    """Load the required canonical row-126 proof before any live mutation."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RhadCompilerRejection(
            f"Rhad row-126 table proof artifact is unavailable: {error}"
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
ROW3_TARGET_IMPORTED_LAYOUT = (
    (0x40A633, 0x40A645, (0x40A633,)),
    (0x40A645, 0x40A64B, (0x40A645, 0x40A647, 0x40A649)),
    (0x40A649, 0x40A64B, (0x40A649,)),
    (0x40A8A9, 0x40A8B5, (0x40A8A9, 0x40A8AF, 0x40A8B1, 0x40A8B3)),
    (0x40A8B3, 0x40A8B5, (0x40A8B3,)),
)
ROW5_SOURCE_IMPORTED_LAYOUT = (
    (0x40A64B, 0x40A65D, (0x40A64B, 0x40A651, 0x40A657)),
    (0x40A65D, 0x40A663, (0x40A65D, 0x40A65F, 0x40A661)),
    (0x40A661, 0x40A663, (0x40A661,)),
    (0x40AAF1, 0x40AAFD, (0x40AAF1, 0x40AAF7, 0x40AAF9, 0x40AAFB)),
    (0x40AAFB, 0x40AAFD, (0x40AAFB,)),
)
ROW5_TARGET_IMPORTED_LAYOUT = (
    (0x40A663, 0x40A675, (0x40A663, 0x40A669, 0x40A66F)),
    (0x40A675, 0x40A67B, (0x40A675, 0x40A677, 0x40A679)),
    (0x40A679, 0x40A67B, (0x40A679,)),
    (0x40AE1A, 0x40AE26, (0x40AE1A, 0x40AE20, 0x40AE22, 0x40AE24)),
    (0x40AE24, 0x40AE26, (0x40AE24,)),
)
ROW6_TARGET_IMPORTED_LAYOUT = (
    (
        0x40AE26,
        0x40AE3E,
        (0x40AE26, 0x40AE28, 0x40AE2E, 0x40AE31, 0x40AE34, 0x40AE3A, 0x40AE3C),
    ),
    (0x40AE3C, 0x40AE3E, (0x40AE3C,)),
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
ROW27_TARGET_IMPORTED_LAYOUT = (
    (0x40A8E9, 0x40A8F7, (0x40A8E9, 0x40A8EF, 0x40A8F5)),
    (0x40A8F7, 0x40A8FD, (0x40A8F7,)),
    (0x40A8FD, 0x40A903, (0x40A8FD, 0x40A8FF, 0x40A901)),
    (0x40A901, 0x40A903, (0x40A901,)),
    (0x40B024, 0x40B032, (0x40B024, 0x40B02A, 0x40B030)),
    (0x40B032, 0x40B038, (0x40B032,)),
    (0x40B038, 0x40B03E, (0x40B038, 0x40B03A, 0x40B03C)),
    (0x40B03C, 0x40B03E, (0x40B03C,)),
)
ROW28_TARGET_IMPORTED_LAYOUT = (
    (
        0x40A903,
        0x40A922,
        (
            0x40A903,
            0x40A908,
            0x40A90D,
            0x40A90F,
            0x40A910,
            0x40A915,
            0x40A91A,
            0x40A91C,
        ),
    ),
    (0x40A922, 0x40A93C, (0x40A922, 0x40A928, 0x40A92D, 0x40A92F, 0x40A934, 0x40A936)),
    (0x40A93C, 0x40A954, (0x40A93C, 0x40A942, 0x40A948, 0x40A94E)),
    (0x40A954, 0x40A960, (0x40A954, 0x40A956, 0x40A958, 0x40A95E)),
    (0x40A95E, 0x40A960, (0x40A95E,)),
    (0x40B4F0, 0x40B50D, (0x40B4F0, 0x40B4F5, 0x40B4FB, 0x40B501, 0x40B507)),
    (0x40B50D, 0x40B51B, (0x40B50D, 0x40B50F, 0x40B511, 0x40B513, 0x40B519)),
    (0x40B519, 0x40B51B, (0x40B519,)),
)
ROW30_TARGET_IMPORTED_LAYOUT = (
    (0x40A97A, 0x40A988, (0x40A97A, 0x40A980, 0x40A986)),
    (0x40A988, 0x40A98E, (0x40A988,)),
    (0x40A98E, 0x40A994, (0x40A98E, 0x40A990, 0x40A992)),
    (0x40A992, 0x40A994, (0x40A992,)),
    (0x40AD1E, 0x40AD2C, (0x40AD1E, 0x40AD24, 0x40AD2A)),
    (0x40AD2C, 0x40AD32, (0x40AD2C,)),
    (0x40AD32, 0x40AD38, (0x40AD32, 0x40AD34, 0x40AD36)),
    (0x40AD36, 0x40AD38, (0x40AD36,)),
)
ROW31_TARGET_IMPORTED_LAYOUT = (
    (0x40A994, 0x40A9A2, (0x40A994, 0x40A99A, 0x40A9A0)),
    (0x40A9A2, 0x40A9A8, (0x40A9A2,)),
    (0x40A9A8, 0x40A9AE, (0x40A9A8, 0x40A9AA, 0x40A9AC)),
    (0x40A9AC, 0x40A9AE, (0x40A9AC,)),
    (0x40B071, 0x40B07F, (0x40B071, 0x40B077, 0x40B07D)),
    (0x40B07F, 0x40B085, (0x40B07F,)),
    (0x40B085, 0x40B08B, (0x40B085, 0x40B087, 0x40B089)),
    (0x40B089, 0x40B08B, (0x40B089,)),
)
ROW32_TARGET_IMPORTED_LAYOUT = (
    (
        0x40A9AE,
        0x40A9D8,
        (
            0x40A9AE,
            0x40A9B3,
            0x40A9B5,
            0x40A9BA,
            0x40A9BC,
            0x40A9BE,
            0x40A9C2,
            0x40A9C7,
            0x40A9CD,
            0x40A9CF,
            0x40A9D5,
        ),
    ),
    (0x40A9D5, 0x40A9D8, (0x40A9D5,)),
    (0x40A9D8, 0x40A9DE, (0x40A9D8, 0x40A9DA, 0x40A9DC)),
    (0x40A9DC, 0x40A9DE, (0x40A9DC,)),
)
ROW34_TARGET_IMPORTED_LAYOUT = (
    (0x40A9F8, 0x40AA06, (0x40A9F8, 0x40A9FE, 0x40AA04)),
    (0x40AA06, 0x40AA0C, (0x40AA06,)),
    (0x40AA0C, 0x40AA12, (0x40AA0C, 0x40AA0E, 0x40AA10)),
    (0x40AA10, 0x40AA12, (0x40AA10,)),
    (0x40AD6E, 0x40AD7C, (0x40AD6E, 0x40AD74, 0x40AD7A)),
    (0x40AD7C, 0x40AD82, (0x40AD7C,)),
    (0x40AD82, 0x40AD88, (0x40AD82, 0x40AD84, 0x40AD86)),
    (0x40AD86, 0x40AD88, (0x40AD86,)),
)
ROW35_TARGET_IMPORTED_LAYOUT = (
    (0x40AA12, 0x40AA20, (0x40AA12, 0x40AA18, 0x40AA1E)),
    (0x40AA20, 0x40AA26, (0x40AA20,)),
    (0x40AA26, 0x40AA2C, (0x40AA26, 0x40AA28, 0x40AA2A)),
    (0x40AA2A, 0x40AA2C, (0x40AA2A,)),
    (0x40B0BC, 0x40B0CA, (0x40B0BC, 0x40B0C2, 0x40B0C8)),
    (0x40B0CA, 0x40B0D0, (0x40B0CA,)),
    (0x40B0D0, 0x40B0D6, (0x40B0D0, 0x40B0D2, 0x40B0D4)),
    (0x40B0D4, 0x40B0D6, (0x40B0D4,)),
)
ROW36_TARGET_IMPORTED_LAYOUT = (
    (0x40AA2C, 0x40AA35, (0x40AA2C, 0x40AA30)),
    (
        0x40AA35,
        0x40AA5A,
        (
            0x40AA35,
            0x40AA3B,
            0x40AA44,
            0x40AA49,
            0x40AA4F,
            0x40AA51,
            0x40AA57,
        ),
    ),
    (0x40AA57, 0x40AA5A, (0x40AA57,)),
    (0x40AA5A, 0x40AA60, (0x40AA5A, 0x40AA5C, 0x40AA5E)),
    (0x40AA5E, 0x40AA60, (0x40AA5E,)),
)
ROW39_SOURCE_IMPORTED_LAYOUT = ((0x40AA7A, 0x40AA88, (0x40AA7A, 0x40AA80, 0x40AA86)),)
ROW38_TARGET_IMPORTED_LAYOUT = (
    (0x40AA88, 0x40AA8E, (0x40AA88,)),
    (0x40AA8E, 0x40AA94, (0x40AA8E, 0x40AA90, 0x40AA92)),
    (0x40AA92, 0x40AA94, (0x40AA92,)),
    (0x40ADBE, 0x40ADCC, (0x40ADBE, 0x40ADC4, 0x40ADCA)),
    (0x40ADCC, 0x40ADD2, (0x40ADCC,)),
    (0x40ADD2, 0x40ADD8, (0x40ADD2, 0x40ADD4, 0x40ADD6)),
    (0x40ADD6, 0x40ADD8, (0x40ADD6,)),
)
ROW40_SOURCE_IMPORTED_LAYOUT = ((0x40AA94, 0x40AAA2, (0x40AA94, 0x40AA9A, 0x40AAA0)),)
ROW39_TARGET_IMPORTED_LAYOUT = (
    (0x40AAA2, 0x40AAA8, (0x40AAA2,)),
    (0x40AAA8, 0x40AAAE, (0x40AAA8, 0x40AAAA, 0x40AAAC)),
    (0x40AAAC, 0x40AAAE, (0x40AAAC,)),
    (0x40B0F2, 0x40B100, (0x40B0F2, 0x40B0F8, 0x40B0FE)),
    (0x40B100, 0x40B106, (0x40B100,)),
    (0x40B106, 0x40B10C, (0x40B106, 0x40B108, 0x40B10A)),
    (0x40B10A, 0x40B10C, (0x40B10A,)),
)
ROW40_TARGET_IMPORTED_LAYOUT = (
    (
        0x40AAAE,
        0x40AAEB,
        (
            0x40AAAE,
            0x40AAB2,
            0x40AAB4,
            0x40AAB8,
            0x40AABB,
            0x40AABE,
            0x40AAC2,
            0x40AAC8,
            0x40AACD,
            0x40AACF,
            0x40AAD3,
            0x40AAD5,
            0x40AADA,
            0x40AAE0,
            0x40AAE2,
            0x40AAE8,
        ),
    ),
    (0x40AAE8, 0x40AAEB, (0x40AAE8,)),
    (0x40AAEB, 0x40AAF1, (0x40AAEB, 0x40AAED, 0x40AAEF)),
    (0x40AAEF, 0x40AAF1, (0x40AAEF,)),
)
ROW42_TARGET_IMPORTED_LAYOUT = (
    (0x40AAFD, 0x40AB0B, (0x40AAFD, 0x40AB03, 0x40AB09)),
    (0x40AB0B, 0x40AB11, (0x40AB0B,)),
    (0x40AB11, 0x40AB17, (0x40AB11, 0x40AB13, 0x40AB15)),
    (0x40AB15, 0x40AB17, (0x40AB15,)),
)
ROW43_TARGET_IMPORTED_LAYOUT = (
    (0x40AB17, 0x40AB25, (0x40AB17, 0x40AB1D, 0x40AB23)),
    (0x40AB25, 0x40AB2B, (0x40AB25,)),
    (0x40AB2B, 0x40AB31, (0x40AB2B, 0x40AB2D, 0x40AB2F)),
    (0x40AB2F, 0x40AB31, (0x40AB2F,)),
    (0x40B149, 0x40B157, (0x40B149, 0x40B14F, 0x40B155)),
    (0x40B157, 0x40B15D, (0x40B157,)),
    (0x40B15D, 0x40B163, (0x40B15D, 0x40B15F, 0x40B161)),
    (0x40B161, 0x40B163, (0x40B161,)),
)
ROW44_TARGET_IMPORTED_LAYOUT = (
    (0x40AB31, 0x40AB56, (0x40AB31, 0x40AB47, 0x40AB50)),
    (0x40AB56, 0x40AB6A, (0x40AB56, 0x40AB5C, 0x40AB64)),
    (0x40AB6A, 0x40AB76, (0x40AB6A, 0x40AB6C, 0x40AB6E, 0x40AB74)),
    (0x40AB74, 0x40AB76, (0x40AB74,)),
    (0x40B51B, 0x40B534, (0x40B51B, 0x40B520, 0x40B526, 0x40B52C, 0x40B52E)),
    (0x40B534, 0x40B542, (0x40B534, 0x40B536, 0x40B538, 0x40B53A, 0x40B540)),
    (0x40B540, 0x40B542, (0x40B540,)),
)
ROW46_TARGET_IMPORTED_LAYOUT = (
    (0x40AB90, 0x40AB9E, (0x40AB90, 0x40AB96, 0x40AB9C)),
    (0x40AB9E, 0x40ABA4, (0x40AB9E,)),
    (0x40ABA4, 0x40ABAA, (0x40ABA4, 0x40ABA6, 0x40ABA8)),
    (0x40ABA8, 0x40ABAA, (0x40ABA8,)),
    (0x40B17F, 0x40B18D, (0x40B17F, 0x40B185, 0x40B18B)),
    (0x40B18D, 0x40B193, (0x40B18D,)),
    (0x40B193, 0x40B199, (0x40B193, 0x40B195, 0x40B197)),
    (0x40B197, 0x40B199, (0x40B197,)),
)
ROW47_TARGET_IMPORTED_LAYOUT = (
    (
        0x40ABAA,
        0x40ABC0,
        (0x40ABAA, 0x40ABAF, 0x40ABB5, 0x40ABB7, 0x40ABBD),
    ),
    (0x40ABBD, 0x40ABC0, (0x40ABBD,)),
    (0x40ABC0, 0x40ABC6, (0x40ABC0, 0x40ABC2, 0x40ABC4)),
    (0x40ABC4, 0x40ABC6, (0x40ABC4,)),
)
ROW49_TARGET_IMPORTED_LAYOUT = (
    (0x40ABE0, 0x40ABEE, (0x40ABE0, 0x40ABE6, 0x40ABEC)),
    (0x40ABEE, 0x40ABF4, (0x40ABEE,)),
    (0x40ABF4, 0x40ABFA, (0x40ABF4, 0x40ABF6, 0x40ABF8)),
    (0x40ABF8, 0x40ABFA, (0x40ABF8,)),
    (0x40B1D0, 0x40B1DE, (0x40B1D0, 0x40B1D6, 0x40B1DC)),
    (0x40B1DE, 0x40B1E4, (0x40B1DE,)),
    (0x40B1E4, 0x40B1EA, (0x40B1E4, 0x40B1E6, 0x40B1E8)),
    (0x40B1E8, 0x40B1EA, (0x40B1E8,)),
)
ROW50_TARGET_IMPORTED_LAYOUT = (
    (0x40ABFA, 0x40ABFF, (0x40ABFA,)),
    (
        0x40ABFF,
        0x40AC19,
        (0x40ABFF, 0x40AC05, 0x40AC0A, 0x40AC0C, 0x40AC11, 0x40AC13),
    ),
    (0x40AC19, 0x40AC31, (0x40AC19, 0x40AC1F, 0x40AC25, 0x40AC2B)),
    (0x40AC31, 0x40AC3D, (0x40AC31, 0x40AC33, 0x40AC35, 0x40AC3B)),
    (0x40AC3B, 0x40AC3D, (0x40AC3B,)),
    (
        0x40B542,
        0x40B55F,
        (0x40B542, 0x40B547, 0x40B54D, 0x40B553, 0x40B559),
    ),
    (0x40B55F, 0x40B56D, (0x40B55F, 0x40B561, 0x40B563, 0x40B565, 0x40B56B)),
    (0x40B56B, 0x40B56D, (0x40B56B,)),
)
ROW52_TARGET_IMPORTED_LAYOUT = (
    (0x40AC56, 0x40AC64, (0x40AC56, 0x40AC5C, 0x40AC62)),
    (0x40AC64, 0x40AC6A, (0x40AC64,)),
    (0x40AC6A, 0x40AC70, (0x40AC6A, 0x40AC6C, 0x40AC6E)),
    (0x40AC6E, 0x40AC70, (0x40AC6E,)),
    (0x40B21C, 0x40B22A, (0x40B21C, 0x40B222, 0x40B228)),
    (0x40B22A, 0x40B230, (0x40B22A,)),
    (0x40B230, 0x40B236, (0x40B230, 0x40B232, 0x40B234)),
    (0x40B234, 0x40B236, (0x40B234,)),
)
ROW53_TARGET_IMPORTED_LAYOUT = (
    (0x40AC70, 0x40AC81, (0x40AC70, 0x40AC74, 0x40AC78, 0x40AC7B)),
    (
        0x40AC81,
        0x40AC9B,
        (0x40AC81, 0x40AC87, 0x40AC8C, 0x40AC8E, 0x40AC93, 0x40AC95),
    ),
    (0x40AC9B, 0x40ACB3, (0x40AC9B, 0x40ACA1, 0x40ACA7, 0x40ACAD)),
    (0x40ACB3, 0x40ACBF, (0x40ACB3, 0x40ACB5, 0x40ACB7, 0x40ACBD)),
    (0x40ACBD, 0x40ACBF, (0x40ACBD,)),
    (
        0x40B56D,
        0x40B58A,
        (0x40B56D, 0x40B572, 0x40B578, 0x40B57E, 0x40B584),
    ),
    (0x40B58A, 0x40B598, (0x40B58A, 0x40B58C, 0x40B58E, 0x40B590, 0x40B596)),
    (0x40B596, 0x40B598, (0x40B596,)),
)
ROW55_TARGET_IMPORTED_LAYOUT = (
    (0x40ACD9, 0x40ACE7, (0x40ACD9, 0x40ACDF, 0x40ACE5)),
    (0x40ACE7, 0x40ACED, (0x40ACE7,)),
    (0x40ACED, 0x40ACF3, (0x40ACED, 0x40ACEF, 0x40ACF1)),
    (0x40ACF1, 0x40ACF3, (0x40ACF1,)),
    (0x40B26D, 0x40B27B, (0x40B26D, 0x40B273, 0x40B279)),
    (0x40B27B, 0x40B281, (0x40B27B,)),
    (0x40B281, 0x40B287, (0x40B281, 0x40B283, 0x40B285)),
    (0x40B285, 0x40B287, (0x40B285,)),
)
ROW56_TARGET_IMPORTED_LAYOUT = (
    (0x40ACF3, 0x40AD06, (0x40ACF3, 0x40ACFB, 0x40AD00)),
    (0x40AD06, 0x40AD18, (0x40AD06, 0x40AD0C, 0x40AD12)),
    (0x40AD18, 0x40AD1E, (0x40AD18, 0x40AD1A, 0x40AD1C)),
    (0x40AD1C, 0x40AD1E, (0x40AD1C,)),
    (0x40B598, 0x40B5AF, (0x40B598, 0x40B59D, 0x40B5A3, 0x40B5A9)),
    (0x40B5AF, 0x40B5B7, (0x40B5AF, 0x40B5B1, 0x40B5B3, 0x40B5B5)),
    (0x40B5B5, 0x40B5B7, (0x40B5B5,)),
)
ROW58_TARGET_IMPORTED_LAYOUT = (
    (0x40AD38, 0x40AD46, (0x40AD38, 0x40AD3E, 0x40AD44)),
    (0x40AD46, 0x40AD4C, (0x40AD46,)),
    (0x40AD4C, 0x40AD52, (0x40AD4C, 0x40AD4E, 0x40AD50)),
    (0x40AD50, 0x40AD52, (0x40AD50,)),
    (0x40B2DB, 0x40B2E9, (0x40B2DB, 0x40B2E1, 0x40B2E7)),
    (0x40B2E9, 0x40B2EF, (0x40B2E9,)),
    (0x40B2EF, 0x40B2F5, (0x40B2EF, 0x40B2F1, 0x40B2F3)),
    (0x40B2F3, 0x40B2F5, (0x40B2F3,)),
)
ROW59_TARGET_IMPORTED_LAYOUT = (
    (
        0x40AD52,
        0x40AD68,
        (
            0x40AD52,
            0x40AD57,
            0x40AD5D,
            0x40AD5F,
            0x40AD65,
        ),
    ),
    (0x40AD65, 0x40AD68, (0x40AD65,)),
    (0x40AD68, 0x40AD6E, (0x40AD68, 0x40AD6A, 0x40AD6C)),
    (0x40AD6C, 0x40AD6E, (0x40AD6C,)),
)
ROW61_TARGET_IMPORTED_LAYOUT = (
    (0x40AD88, 0x40AD96, (0x40AD88, 0x40AD8E, 0x40AD94)),
    (0x40AD96, 0x40AD9C, (0x40AD96,)),
    (0x40AD9C, 0x40ADA2, (0x40AD9C, 0x40AD9E, 0x40ADA0)),
    (0x40ADA0, 0x40ADA2, (0x40ADA0,)),
    (
        0x40B32C,
        0x40B342,
        (0x40B32C, 0x40B32E, 0x40B334, 0x40B337, 0x40B33E, 0x40B340),
    ),
    (0x40B340, 0x40B342, (0x40B340,)),
)
ROW62_TARGET_IMPORTED_LAYOUT = (
    (
        0x40ADA2,
        0x40ADB8,
        (0x40ADA2, 0x40ADA7, 0x40ADAD, 0x40ADAF, 0x40ADB5),
    ),
    (0x40ADB5, 0x40ADB8, (0x40ADB5,)),
    (0x40ADB8, 0x40ADBE, (0x40ADB8, 0x40ADBA, 0x40ADBC)),
    (0x40ADBC, 0x40ADBE, (0x40ADBC,)),
)
ROW64_TARGET_IMPORTED_LAYOUT = (
    (0x40ADD8, 0x40ADE6, (0x40ADD8, 0x40ADDE, 0x40ADE4)),
    (0x40ADE6, 0x40ADEC, (0x40ADE6,)),
    (0x40ADEC, 0x40ADF2, (0x40ADEC, 0x40ADEE, 0x40ADF0)),
    (0x40ADF0, 0x40ADF2, (0x40ADF0,)),
    (0x40B37C, 0x40B38A, (0x40B37C, 0x40B382, 0x40B388)),
    (0x40B38A, 0x40B390, (0x40B38A,)),
    (0x40B390, 0x40B396, (0x40B390, 0x40B392, 0x40B394)),
    (0x40B394, 0x40B396, (0x40B394,)),
)
ROW65_TARGET_IMPORTED_LAYOUT = (
    (
        0x40ADF2,
        0x40AE08,
        (
            0x40ADF2,
            0x40ADF7,
            0x40ADFD,
            0x40ADFF,
            0x40AE05,
        ),
    ),
    (0x40AE05, 0x40AE08, (0x40AE05,)),
    (
        0x40AE08,
        0x40AE1A,
        (
            0x40AE08,
            0x40AE0A,
            0x40AE0C,
            0x40AE0E,
            0x40AE12,
            0x40AE16,
            0x40AE18,
        ),
    ),
    (0x40AE18, 0x40AE1A, (0x40AE18,)),
)
ROW67_TARGET_IMPORTED_LAYOUT = (
    (0x40A5CA, 0x40A5DF, (0x40A5CA, 0x40A5D0, 0x40A5D6, 0x40A5DC)),
    (0x40A5DC, 0x40A5DF, (0x40A5DC,)),
    (0x40A5DF, 0x40A5E5, (0x40A5DF, 0x40A5E1, 0x40A5E3)),
    (0x40A5E3, 0x40A5E5, (0x40A5E3,)),
)
ROW68_TARGET_IMPORTED_LAYOUT = (
    (
        0x40AE3E,
        0x40AE63,
        (
            0x40AE3E,
            0x40AE43,
            0x40AE48,
            0x40AE4A,
            0x40AE50,
            0x40AE55,
            0x40AE57,
            0x40AE58,
            0x40AE59,
            0x40AE5D,
            0x40AE60,
        ),
    ),
    (
        0x40AE63,
        0x40AE85,
        (
            0x40AE63,
            0x40AE69,
            0x40AE6F,
            0x40AE74,
            0x40AE7A,
            0x40AE7C,
            0x40AE82,
        ),
    ),
    (0x40AE82, 0x40AE85, (0x40AE82,)),
    (0x40AE85, 0x40AE8B, (0x40AE85, 0x40AE87, 0x40AE89)),
    (0x40AE89, 0x40AE8B, (0x40AE89,)),
)
ROW70_TARGET_IMPORTED_LAYOUT = (
    (
        0x40AEA5,
        0x40AEC6,
        (
            0x40AEA5,
            0x40AEA7,
            0x40AEAC,
            0x40AEB2,
            0x40AEB7,
            0x40AEB9,
            0x40AEBE,
            0x40AEC0,
        ),
    ),
    (0x40AEC6, 0x40AEDA, (0x40AEC6, 0x40AECC, 0x40AED2, 0x40AED4)),
    (0x40AEDA, 0x40AEE6, (0x40AEDA, 0x40AEDC, 0x40AEDE, 0x40AEE4)),
    (0x40AEE4, 0x40AEE6, (0x40AEE4,)),
    (
        0x40B5B7,
        0x40B5D0,
        (0x40B5B7, 0x40B5BC, 0x40B5C2, 0x40B5C8, 0x40B5CA),
    ),
    (0x40B5D0, 0x40B5DE, (0x40B5D0, 0x40B5D2, 0x40B5D4, 0x40B5D6, 0x40B5DC)),
    (0x40B5DC, 0x40B5DE, (0x40B5DC,)),
)
ROW72_TARGET_IMPORTED_LAYOUT = (
    (
        0x40AF00,
        0x40AF1C,
        (0x40AF00, 0x40AF06, 0x40AF0B, 0x40AF0D, 0x40AF11, 0x40AF15, 0x40AF16),
    ),
    (0x40AF1C, 0x40AF2F, (0x40AF1C, 0x40AF21, 0x40AF23, 0x40AF2A)),
    (
        0x40AF2F,
        0x40AF9D,
        (
            0x40AF2F,
            0x40AF32,
            0x40AF37,
            0x40AF3C,
            0x40AF3E,
            0x40AF45,
            0x40AF4A,
            0x40AF4F,
            0x40AF51,
            0x40AF58,
            0x40AF5C,
            0x40AF63,
            0x40AF6A,
            0x40AF71,
            0x40AF76,
            0x40AF7D,
            0x40AF7F,
            0x40AF84,
            0x40AF8A,
            0x40AF8F,
            0x40AF91,
            0x40AF92,
            0x40AF93,
            0x40AF98,
        ),
    ),
    (
        0x40AF9D,
        0x40AFBB,
        (0x40AF9D, 0x40AFA0, 0x40AFA5, 0x40AFAA, 0x40AFAC, 0x40AFB1, 0x40AFB5),
    ),
    (0x40AFBB, 0x40AFD3, (0x40AFBB, 0x40AFC1, 0x40AFC7, 0x40AFCD)),
    (0x40AFD3, 0x40AFDF, (0x40AFD3, 0x40AFD5, 0x40AFD7, 0x40AFDD)),
    (0x40AFDD, 0x40AFDF, (0x40AFDD,)),
    (0x40B5DE, 0x40B5FB, (0x40B5DE, 0x40B5E3, 0x40B5E9, 0x40B5EF, 0x40B5F5)),
    (0x40B5FB, 0x40B609, (0x40B5FB, 0x40B5FD, 0x40B5FF, 0x40B601, 0x40B607)),
    (0x40B607, 0x40B609, (0x40B607,)),
)
ROW74_TARGET_IMPORTED_LAYOUT = (
    (0x40AFF9, 0x40B00C, (0x40AFF9, 0x40B001, 0x40B006)),
    (0x40B00C, 0x40B01E, (0x40B00C, 0x40B012, 0x40B018)),
    (0x40B01E, 0x40B024, (0x40B01E, 0x40B020, 0x40B022)),
    (0x40B022, 0x40B024, (0x40B022,)),
    (0x40B609, 0x40B620, (0x40B609, 0x40B60E, 0x40B614, 0x40B61A)),
    (0x40B620, 0x40B628, (0x40B620, 0x40B622, 0x40B624, 0x40B626)),
    (0x40B626, 0x40B628, (0x40B626,)),
)
ROW76_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B03E,
        0x40B059,
        (0x40B03E, 0x40B043, 0x40B048, 0x40B04A, 0x40B04F, 0x40B053),
    ),
    (0x40B059, 0x40B06B, (0x40B059, 0x40B05F, 0x40B065)),
    (0x40B06B, 0x40B071, (0x40B06B, 0x40B06D, 0x40B06F)),
    (0x40B06F, 0x40B071, (0x40B06F,)),
    (0x40B628, 0x40B63F, (0x40B628, 0x40B62D, 0x40B633, 0x40B639)),
    (0x40B63F, 0x40B647, (0x40B63F, 0x40B641, 0x40B643, 0x40B645)),
    (0x40B645, 0x40B647, (0x40B645,)),
)
ROW78_TARGET_IMPORTED_LAYOUT = (
    (0x40B08B, 0x40B094, (0x40B08B, 0x40B08F, 0x40B090)),
    (
        0x40B094,
        0x40B0B6,
        (
            0x40B094,
            0x40B09A,
            0x40B0A0,
            0x40B0A5,
            0x40B0AB,
            0x40B0AD,
            0x40B0B3,
        ),
    ),
    (0x40B0B3, 0x40B0B6, (0x40B0B3,)),
    (0x40B0B6, 0x40B0BC, (0x40B0B6, 0x40B0B8, 0x40B0BA)),
    (0x40B0BA, 0x40B0BC, (0x40B0BA,)),
)
ROW80_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B0D6,
        0x40B0EC,
        (0x40B0D6, 0x40B0DB, 0x40B0E1, 0x40B0E3, 0x40B0E9),
    ),
    (0x40B0E9, 0x40B0EC, (0x40B0E9,)),
    (0x40B0EC, 0x40B0F2, (0x40B0EC, 0x40B0EE, 0x40B0F0)),
    (0x40B0F0, 0x40B0F2, (0x40B0F0,)),
)
ROW82_TARGET_IMPORTED_LAYOUT = (
    (0x40B10C, 0x40B11A, (0x40B10C, 0x40B113, 0x40B114)),
    (0x40B11A, 0x40B121, (0x40B11A, 0x40B11B)),
    (
        0x40B121,
        0x40B143,
        (0x40B121, 0x40B127, 0x40B12D, 0x40B132, 0x40B138, 0x40B13A, 0x40B140),
    ),
    (0x40B140, 0x40B143, (0x40B140,)),
    (0x40B143, 0x40B149, (0x40B143, 0x40B145, 0x40B147)),
    (0x40B147, 0x40B149, (0x40B147,)),
)
ROW84_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B163,
        0x40B179,
        (0x40B163, 0x40B168, 0x40B16E, 0x40B170, 0x40B176),
    ),
    (0x40B176, 0x40B179, (0x40B176,)),
    (0x40B179, 0x40B17F, (0x40B179, 0x40B17B, 0x40B17D)),
    (0x40B17D, 0x40B17F, (0x40B17D,)),
)
ROW86_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B199,
        0x40B1B6,
        (0x40B199, 0x40B19B, 0x40B1A0, 0x40B1A5, 0x40B1A7, 0x40B1AC, 0x40B1B0),
    ),
    (0x40B1B6, 0x40B1CA, (0x40B1B6, 0x40B1BC, 0x40B1C2, 0x40B1C4)),
    (0x40B1CA, 0x40B1D0, (0x40B1CA, 0x40B1CC, 0x40B1CE)),
    (0x40B1CE, 0x40B1D0, (0x40B1CE,)),
    (0x40B647, 0x40B660, (0x40B647, 0x40B64C, 0x40B652, 0x40B658, 0x40B65A)),
    (0x40B660, 0x40B668, (0x40B660, 0x40B662, 0x40B664, 0x40B666)),
    (0x40B666, 0x40B668, (0x40B666,)),
)
ROW88_TARGET_IMPORTED_LAYOUT = (
    (0x40B1EA, 0x40B1F4, (0x40B1EA, 0x40B1EE)),
    (
        0x40B1F4,
        0x40B216,
        (
            0x40B1F4,
            0x40B1FA,
            0x40B200,
            0x40B205,
            0x40B20B,
            0x40B20D,
            0x40B213,
        ),
    ),
    (0x40B213, 0x40B216, (0x40B213,)),
    (
        0x40B216,
        0x40B21C,
        (
            0x40B216,
            0x40B218,
            0x40B21A,
        ),
    ),
    (0x40B21A, 0x40B21C, (0x40B21A,)),
)
ROW90_TARGET_IMPORTED_LAYOUT = (
    (0x40B236, 0x40B242, (0x40B236, 0x40B23D)),
    (
        0x40B242,
        0x40B267,
        (
            0x40B242,
            0x40B248,
            0x40B251,
            0x40B256,
            0x40B25C,
            0x40B25E,
            0x40B264,
        ),
    ),
    (0x40B264, 0x40B267, (0x40B264,)),
    (0x40B267, 0x40B26D, (0x40B267, 0x40B269, 0x40B26B)),
)
ROW92_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B287,
        0x40B2A6,
        (
            0x40B287,
            0x40B28C,
            0x40B291,
            0x40B293,
            0x40B297,
            0x40B29B,
            0x40B29C,
            0x40B2A0,
        ),
    ),
    (0x40B2A6, 0x40B2B7, (0x40B2A6, 0x40B2AB, 0x40B2AF, 0x40B2B1)),
    (0x40B2B7, 0x40B2CF, (0x40B2B7, 0x40B2BD, 0x40B2C3, 0x40B2C9)),
    (0x40B2CF, 0x40B2DB, (0x40B2CF, 0x40B2D1, 0x40B2D3, 0x40B2D9)),
    (0x40B2D9, 0x40B2DB, (0x40B2D9,)),
    (
        0x40B668,
        0x40B685,
        (0x40B668, 0x40B66D, 0x40B673, 0x40B679, 0x40B67F),
    ),
    (0x40B685, 0x40B693, (0x40B685, 0x40B687, 0x40B689, 0x40B68B, 0x40B691)),
    (0x40B691, 0x40B693, (0x40B691,)),
)
ROW94_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B2F5,
        0x40B312,
        (0x40B2F5, 0x40B2F7, 0x40B2FC, 0x40B301, 0x40B303, 0x40B308, 0x40B30C),
    ),
    (0x40B312, 0x40B326, (0x40B312, 0x40B318, 0x40B31E, 0x40B320)),
    (0x40B326, 0x40B32C, (0x40B326, 0x40B328, 0x40B32A)),
    (0x40B32A, 0x40B32C, (0x40B32A,)),
    (0x40B693, 0x40B6AC, (0x40B693, 0x40B698, 0x40B69E, 0x40B6A4, 0x40B6A6)),
    (0x40B6AC, 0x40B6B4, (0x40B6AC, 0x40B6AE, 0x40B6B0, 0x40B6B2)),
    (0x40B6B2, 0x40B6B4, (0x40B6B2,)),
)
ROW96_TARGET_IMPORTED_LAYOUT = (
    (0x40B342, 0x40B354, (0x40B342, 0x40B349, 0x40B34A, 0x40B34E)),
    (
        0x40B354,
        0x40B376,
        (
            0x40B354,
            0x40B35A,
            0x40B360,
            0x40B365,
            0x40B36B,
            0x40B36D,
            0x40B373,
        ),
    ),
    (0x40B373, 0x40B376, (0x40B373,)),
    (0x40B376, 0x40B37C, (0x40B376, 0x40B378, 0x40B37A)),
    (0x40B37A, 0x40B37C, (0x40B37A,)),
)
ROW98_TARGET_IMPORTED_LAYOUT = (
    (0x40B396, 0x40B3A4, (0x40B396, 0x40B39C, 0x40B3A2)),
    (0x40B3A4, 0x40B3AA, (0x40B3A4,)),
    (0x40B3AA, 0x40B3B0, (0x40B3AA, 0x40B3AC, 0x40B3AE)),
    (0x40B3AE, 0x40B3B0, (0x40B3AE,)),
    (0x40B3E5, 0x40B3F3, (0x40B3E5, 0x40B3EB, 0x40B3F1)),
    (0x40B3F3, 0x40B3F9, (0x40B3F3,)),
    (0x40B3F9, 0x40B3FF, (0x40B3F9, 0x40B3FB, 0x40B3FD)),
    (0x40B3FD, 0x40B3FF, (0x40B3FD,)),
)
ROW99_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B3B0,
        0x40B3DF,
        (
            0x40B3B0,
            0x40B3B5,
            0x40B3B7,
            0x40B3BB,
            0x40B3BD,
            0x40B3C3,
            0x40B3C7,
            0x40B3C9,
            0x40B3CE,
            0x40B3D4,
            0x40B3D6,
            0x40B3DC,
        ),
    ),
    (0x40B3DC, 0x40B3DF, (0x40B3DC,)),
    (0x40B3DF, 0x40B3E5, (0x40B3DF, 0x40B3E1, 0x40B3E3)),
    (0x40B3E3, 0x40B3E5, (0x40B3E3,)),
)
ROW101_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B3FF,
        0x40B4A4,
        (
            0x40B3FF,
            0x40B405,
            0x40B40A,
            0x40B40C,
            0x40B410,
            0x40B416,
            0x40B41B,
            0x40B41D,
            0x40B421,
            0x40B427,
            0x40B42C,
            0x40B42E,
            0x40B432,
            0x40B438,
            0x40B43D,
            0x40B43F,
            0x40B443,
            0x40B449,
            0x40B44E,
            0x40B450,
            0x40B456,
            0x40B45B,
            0x40B45D,
            0x40B462,
            0x40B467,
            0x40B469,
            0x40B46E,
            0x40B475,
            0x40B476,
            0x40B47C,
            0x40B47F,
            0x40B481,
            0x40B485,
            0x40B486,
            0x40B487,
            0x40B488,
            0x40B48C,
            0x40B490,
            0x40B495,
            0x40B49A,
            0x40B49E,
        ),
    ),
    (
        0x40B4A4,
        0x40B4BF,
        (
            0x40B4A4,
            0x40B4AA,
            0x40B4B0,
            0x40B4B4,
            0x40B4BA,
            0x40B4BC,
        ),
    ),
    (0x40B4BC, 0x40B4BF, (0x40B4BC,)),
    (0x40B4BF, 0x40B4C5, (0x40B4BF, 0x40B4C1, 0x40B4C3)),
    (0x40B4C3, 0x40B4C5, (0x40B4C3,)),
)
ROW116_TARGET_IMPORTED_LAYOUT = (
    (0x40B6D6, 0x40B6E4, (0x40B6D6, 0x40B6DC, 0x40B6E2)),
    (0x40B6E4, 0x40B6EA, (0x40B6E4,)),
    (0x40B6EA, 0x40B6F0, (0x40B6EA, 0x40B6EC, 0x40B6EE)),
    (0x40B6EE, 0x40B6F0, (0x40B6EE,)),
    (0x40B790, 0x40B79E, (0x40B790, 0x40B796, 0x40B79C)),
    (0x40B79E, 0x40B7A4, (0x40B79E,)),
    (0x40B7A4, 0x40B7AA, (0x40B7A4, 0x40B7A6, 0x40B7A8)),
    (0x40B7A8, 0x40B7AA, (0x40B7A8,)),
)
ROW117_TARGET_IMPORTED_LAYOUT = (
    (0x40B6F0, 0x40B6FE, (0x40B6F0, 0x40B6F6, 0x40B6FC)),
    (0x40B6FE, 0x40B704, (0x40B6FE,)),
    (0x40B704, 0x40B70A, (0x40B704, 0x40B706, 0x40B708)),
    (0x40B708, 0x40B70A, (0x40B708,)),
    (
        0x40B880,
        0x40B898,
        (0x40B880, 0x40B882, 0x40B888, 0x40B88B, 0x40B88E, 0x40B894, 0x40B896),
    ),
    (0x40B896, 0x40B898, (0x40B896,)),
)
ROW118_TARGET_IMPORTED_LAYOUT = (
    (0x40B70A, 0x40B718, (0x40B70A, 0x40B710, 0x40B716)),
    (0x40B718, 0x40B71E, (0x40B718,)),
    (0x40B71E, 0x40B724, (0x40B71E, 0x40B720, 0x40B722)),
    (0x40B722, 0x40B724, (0x40B722,)),
    (0x40BB75, 0x40BB83, (0x40BB75, 0x40BB7B, 0x40BB81)),
    (0x40BB83, 0x40BB89, (0x40BB83,)),
    (0x40BB89, 0x40BB8F, (0x40BB89, 0x40BB8B, 0x40BB8D)),
    (0x40BB8D, 0x40BB8F, (0x40BB8D,)),
)
ROW119_TARGET_IMPORTED_LAYOUT = (
    (0x40B724, 0x40B732, (0x40B724, 0x40B72A, 0x40B730)),
    (0x40B732, 0x40B738, (0x40B732,)),
    (0x40B738, 0x40B73E, (0x40B738, 0x40B73A, 0x40B73C)),
    (0x40B73C, 0x40B73E, (0x40B73C,)),
    (0x40BD50, 0x40BD5E, (0x40BD50, 0x40BD56, 0x40BD5C)),
    (0x40BD5E, 0x40BD64, (0x40BD5E,)),
    (0x40BD64, 0x40BD6A, (0x40BD64, 0x40BD66, 0x40BD68)),
    (0x40BD68, 0x40BD6A, (0x40BD68,)),
)
ROW120_TARGET_IMPORTED_LAYOUT = (
    (0x40B73E, 0x40B74C, (0x40B73E, 0x40B744, 0x40B74A)),
    (0x40B74C, 0x40B752, (0x40B74C,)),
    (0x40B752, 0x40B758, (0x40B752, 0x40B754, 0x40B756)),
    (0x40B756, 0x40B758, (0x40B756,)),
    (0x40C0F0, 0x40C0FE, (0x40C0F0, 0x40C0F6, 0x40C0FC)),
    (0x40C0FE, 0x40C104, (0x40C0FE,)),
    (0x40C104, 0x40C10A, (0x40C104, 0x40C106, 0x40C108)),
    (0x40C108, 0x40C10A, (0x40C108,)),
)
ROW121_TARGET_IMPORTED_LAYOUT = (
    (0x40B758, 0x40B76B, (0x40B758, 0x40B760, 0x40B765)),
    (0x40B76B, 0x40B77D, (0x40B76B, 0x40B771, 0x40B777)),
    (0x40B77D, 0x40B783, (0x40B77D, 0x40B77F, 0x40B781)),
    (0x40B781, 0x40B783, (0x40B781,)),
    (0x40C696, 0x40C6AD, (0x40C696, 0x40C69B, 0x40C6A1, 0x40C6A7)),
    (0x40C6AD, 0x40C6B5, (0x40C6AD, 0x40C6AF, 0x40C6B1, 0x40C6B3)),
    (0x40C6B3, 0x40C6B5, (0x40C6B3,)),
)
ROW123_TARGET_IMPORTED_LAYOUT = (
    (0x40B7AA, 0x40B7B8, (0x40B7AA, 0x40B7B0, 0x40B7B6)),
    (0x40B7B8, 0x40B7BE, (0x40B7B8,)),
    (0x40B7BE, 0x40B7C4, (0x40B7BE, 0x40B7C0, 0x40B7C2)),
    (0x40B7C2, 0x40B7C4, (0x40B7C2,)),
    (
        0x40B940,
        0x40B958,
        (0x40B940, 0x40B942, 0x40B948, 0x40B94B, 0x40B94E, 0x40B954, 0x40B956),
    ),
    (0x40B956, 0x40B958, (0x40B956,)),
)
ROW124_TARGET_IMPORTED_LAYOUT = (
    (0x40B7C4, 0x40B7D2, (0x40B7C4, 0x40B7CA, 0x40B7D0)),
    (0x40B7D2, 0x40B7D8, (0x40B7D2,)),
    (0x40B7D8, 0x40B7DE, (0x40B7D8, 0x40B7DA, 0x40B7DC)),
    (0x40B7DC, 0x40B7DE, (0x40B7DC,)),
    (0x40BBDF, 0x40BBED, (0x40BBDF, 0x40BBE5, 0x40BBEB)),
    (0x40BBED, 0x40BBF3, (0x40BBED,)),
    (0x40BBF3, 0x40BBF9, (0x40BBF3, 0x40BBF5, 0x40BBF7)),
    (0x40BBF7, 0x40BBF9, (0x40BBF7,)),
)
ROW125_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B7DE,
        0x40B7F6,
        (0x40B7DE, 0x40B7E0, 0x40B7E6, 0x40B7E9, 0x40B7EC, 0x40B7F2, 0x40B7F4),
    ),
    (0x40B7F4, 0x40B7F6, (0x40B7F4,)),
    (0x40BE2F, 0x40BE3D, (0x40BE2F, 0x40BE35, 0x40BE3B)),
    (0x40BE3D, 0x40BE43, (0x40BE3D,)),
    (0x40BE43, 0x40BE49, (0x40BE43, 0x40BE45, 0x40BE47)),
    (0x40BE47, 0x40BE49, (0x40BE47,)),
)
ROW126_TARGET_IMPORTED_LAYOUT = (
    (0x40B7F6, 0x40B804, (0x40B7F6, 0x40B7FC, 0x40B802)),
    (0x40B804, 0x40B80A, (0x40B804,)),
    (0x40B80A, 0x40B810, (0x40B80A, 0x40B80C, 0x40B80E)),
    (0x40B80E, 0x40B810, (0x40B80E,)),
    (0x40C150, 0x40C15E, (0x40C150, 0x40C156, 0x40C15C)),
    (0x40C15E, 0x40C164, (0x40C15E,)),
    (0x40C164, 0x40C16A, (0x40C164, 0x40C166, 0x40C168)),
    (0x40C168, 0x40C16A, (0x40C168,)),
)
ROW127_TARGET_IMPORTED_LAYOUT = (
    (
        0x40B810,
        0x40B87B,
        (
            0x40B810,
            0x40B815,
            0x40B81C,
            0x40B81F,
            0x40B821,
            0x40B825,
            0x40B82B,
            0x40B830,
            0x40B832,
            0x40B836,
            0x40B837,
            0x40B839,
            0x40B83F,
            0x40B845,
            0x40B84C,
            0x40B852,
            0x40B857,
            0x40B859,
            0x40B85D,
            0x40B85F,
            0x40B864,
            0x40B86A,
            0x40B86C,
            0x40B872,
        ),
    ),
    (0x40B872, 0x40B875, (0x40B872,)),
    (0x40B875, 0x40B87B, (0x40B875, 0x40B877, 0x40B879)),
    (0x40B879, 0x40B87B, (0x40B879,)),
)
BASE_IMPORTED_LAYOUT = (
    (0x40A607, 0x40A615, (0x40A607,)),
    (0x40A615, 0x40A61B, (0x40A615,)),
    (0x40A619, 0x40A61B, (0x40A619,)),
    (0x40A680, 0x40A68C, (0x40A680,)),
    (0x40A68A, 0x40A68C, (0x40A68A,)),
    (0x40B6C0, 0x40B6CA, (0x40B6C0, 0x40B6C2, 0x40B6C8)),
    (0x40B6CA, 0x40B6D0, (0x40B6CA,)),
    (0x40B6D0, 0x40B6D6, (0x40B6D0, 0x40B6D2, 0x40B6D4)),
    (0x40B6D4, 0x40B6D6, (0x40B6D4,)),
    *((start_ea, end_ea, (start_ea,)) for start_ea, end_ea in DIRECT_IMPORTED_RANGES),
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
    + ROW3_TARGET_IMPORTED_LAYOUT
    + ROW5_SOURCE_IMPORTED_LAYOUT
    + ROW5_TARGET_IMPORTED_LAYOUT
    + ROW6_TARGET_IMPORTED_LAYOUT
    + ROW26_SOURCE_IMPORTED_LAYOUT
    + ROW26_TARGET_IMPORTED_LAYOUT
    + ROW27_TARGET_IMPORTED_LAYOUT
    + ROW28_TARGET_IMPORTED_LAYOUT
    + ROW30_TARGET_IMPORTED_LAYOUT
    + ROW31_TARGET_IMPORTED_LAYOUT
    + ROW32_TARGET_IMPORTED_LAYOUT
    + ROW34_TARGET_IMPORTED_LAYOUT
    + ROW35_TARGET_IMPORTED_LAYOUT
    + ROW36_TARGET_IMPORTED_LAYOUT
    + ROW39_SOURCE_IMPORTED_LAYOUT
    + ROW38_TARGET_IMPORTED_LAYOUT
    + ROW40_SOURCE_IMPORTED_LAYOUT
    + ROW39_TARGET_IMPORTED_LAYOUT
    + ROW40_TARGET_IMPORTED_LAYOUT
    + ROW42_TARGET_IMPORTED_LAYOUT
    + ROW43_TARGET_IMPORTED_LAYOUT
    + ROW44_TARGET_IMPORTED_LAYOUT
    + ROW46_TARGET_IMPORTED_LAYOUT
    + ROW47_TARGET_IMPORTED_LAYOUT
    + ROW49_TARGET_IMPORTED_LAYOUT
    + ROW50_TARGET_IMPORTED_LAYOUT
    + ROW52_TARGET_IMPORTED_LAYOUT
    + ROW53_TARGET_IMPORTED_LAYOUT
    + ROW55_TARGET_IMPORTED_LAYOUT
    + ROW56_TARGET_IMPORTED_LAYOUT
    + ROW58_TARGET_IMPORTED_LAYOUT
    + ROW59_TARGET_IMPORTED_LAYOUT
    + ROW61_TARGET_IMPORTED_LAYOUT
    + ROW62_TARGET_IMPORTED_LAYOUT
    + ROW64_TARGET_IMPORTED_LAYOUT
    + ROW65_TARGET_IMPORTED_LAYOUT
    + ROW67_TARGET_IMPORTED_LAYOUT
    + ROW68_TARGET_IMPORTED_LAYOUT
    + ROW70_TARGET_IMPORTED_LAYOUT
    + ROW72_TARGET_IMPORTED_LAYOUT
    + ROW74_TARGET_IMPORTED_LAYOUT
    + ROW76_TARGET_IMPORTED_LAYOUT
    + ROW78_TARGET_IMPORTED_LAYOUT
    + ROW80_TARGET_IMPORTED_LAYOUT
    + ROW82_TARGET_IMPORTED_LAYOUT
    + ROW84_TARGET_IMPORTED_LAYOUT
    + ROW86_TARGET_IMPORTED_LAYOUT
    + ROW88_TARGET_IMPORTED_LAYOUT
    + ROW90_TARGET_IMPORTED_LAYOUT
    + ROW92_TARGET_IMPORTED_LAYOUT
    + ROW94_TARGET_IMPORTED_LAYOUT
    + ROW96_TARGET_IMPORTED_LAYOUT
    + ROW98_TARGET_IMPORTED_LAYOUT
    + ROW99_TARGET_IMPORTED_LAYOUT
    + ROW101_TARGET_IMPORTED_LAYOUT
    + ROW116_TARGET_IMPORTED_LAYOUT
    + ROW117_TARGET_IMPORTED_LAYOUT
    + ROW118_TARGET_IMPORTED_LAYOUT
    + ROW119_TARGET_IMPORTED_LAYOUT
    + ROW120_TARGET_IMPORTED_LAYOUT
    + ROW121_TARGET_IMPORTED_LAYOUT
    + ROW123_TARGET_IMPORTED_LAYOUT
    + ROW124_TARGET_IMPORTED_LAYOUT
    + ROW125_TARGET_IMPORTED_LAYOUT
    + ROW126_TARGET_IMPORTED_LAYOUT
    + ROW127_TARGET_IMPORTED_LAYOUT
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
ROW3_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW3_TARGET_IMPORTED_LAYOUT
)
ROW5_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in (
        ROW5_SOURCE_IMPORTED_LAYOUT + ROW5_TARGET_IMPORTED_LAYOUT
    )
)
ROW6_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW6_TARGET_IMPORTED_LAYOUT
)
ROW19_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40B6C0",
    "native@0x40B6CA",
    "native@0x40B6D0",
    "native@0x40B6D4",
)
ROW25_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A64B",
    "native@0x40A65D",
    "native@0x40A661",
    "native@0x40AAF1",
    "native@0x40AAFB",
)
ROW26_SOURCE_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW26_SOURCE_IMPORTED_LAYOUT
)
ROW26_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in (
        ROW26_SOURCE_IMPORTED_LAYOUT + ROW26_TARGET_IMPORTED_LAYOUT
    )
)
ROW27_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW27_TARGET_IMPORTED_LAYOUT
)
ROW28_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW28_TARGET_IMPORTED_LAYOUT
)
ROW30_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW30_TARGET_IMPORTED_LAYOUT
)
ROW31_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW31_TARGET_IMPORTED_LAYOUT
)
ROW32_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW32_TARGET_IMPORTED_LAYOUT
)
ROW34_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW34_TARGET_IMPORTED_LAYOUT
)
ROW35_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW35_TARGET_IMPORTED_LAYOUT
)
ROW36_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW36_TARGET_IMPORTED_LAYOUT
)
ROW39_SOURCE_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW39_SOURCE_IMPORTED_LAYOUT
)
ROW38_TARGET_IMPORTED_BLOCK_IDS = ROW39_SOURCE_IMPORTED_BLOCK_IDS + tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW38_TARGET_IMPORTED_LAYOUT
)
ROW40_SOURCE_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW40_SOURCE_IMPORTED_LAYOUT
)
ROW39_TARGET_IMPORTED_BLOCK_IDS = ROW40_SOURCE_IMPORTED_BLOCK_IDS + tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW39_TARGET_IMPORTED_LAYOUT
)
ROW40_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW40_TARGET_IMPORTED_LAYOUT
)
ROW42_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW42_TARGET_IMPORTED_LAYOUT
)
ROW43_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW43_TARGET_IMPORTED_LAYOUT
)
ROW44_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW44_TARGET_IMPORTED_LAYOUT
)
ROW46_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW46_TARGET_IMPORTED_LAYOUT
)
ROW47_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW47_TARGET_IMPORTED_LAYOUT
)
ROW49_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW49_TARGET_IMPORTED_LAYOUT
)
ROW50_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW50_TARGET_IMPORTED_LAYOUT
)
ROW52_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW52_TARGET_IMPORTED_LAYOUT
)
ROW53_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW53_TARGET_IMPORTED_LAYOUT
)
ROW55_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW55_TARGET_IMPORTED_LAYOUT
)
ROW56_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW56_TARGET_IMPORTED_LAYOUT
)
ROW58_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW58_TARGET_IMPORTED_LAYOUT
)
ROW59_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW59_TARGET_IMPORTED_LAYOUT
)
ROW61_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW61_TARGET_IMPORTED_LAYOUT
)
ROW62_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW62_TARGET_IMPORTED_LAYOUT
)
ROW64_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW64_TARGET_IMPORTED_LAYOUT
)
ROW65_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW65_TARGET_IMPORTED_LAYOUT
)
ROW67_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW67_TARGET_IMPORTED_LAYOUT
)
ROW68_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW68_TARGET_IMPORTED_LAYOUT
)
ROW70_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW70_TARGET_IMPORTED_LAYOUT
)
ROW72_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW72_TARGET_IMPORTED_LAYOUT
)
ROW74_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW74_TARGET_IMPORTED_LAYOUT
)
ROW76_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW76_TARGET_IMPORTED_LAYOUT
)
ROW78_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW78_TARGET_IMPORTED_LAYOUT
)
ROW80_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW80_TARGET_IMPORTED_LAYOUT
)
ROW82_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW82_TARGET_IMPORTED_LAYOUT
)
ROW84_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW84_TARGET_IMPORTED_LAYOUT
)
ROW86_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW86_TARGET_IMPORTED_LAYOUT
)
ROW88_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW88_TARGET_IMPORTED_LAYOUT
)
ROW90_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW90_TARGET_IMPORTED_LAYOUT
)
ROW92_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW92_TARGET_IMPORTED_LAYOUT
)
ROW94_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW94_TARGET_IMPORTED_LAYOUT
)
ROW96_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW96_TARGET_IMPORTED_LAYOUT
)
ROW98_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW98_TARGET_IMPORTED_LAYOUT
)
ROW99_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW99_TARGET_IMPORTED_LAYOUT
)
ROW101_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW101_TARGET_IMPORTED_LAYOUT
)
ROW103_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW104_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW105_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW106_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW107_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW108_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW109_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW110_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW111_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW112_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW113_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW114_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW115_TARGET_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
)
ROW116_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW116_TARGET_IMPORTED_LAYOUT
)
ROW117_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW117_TARGET_IMPORTED_LAYOUT
)
ROW118_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW118_TARGET_IMPORTED_LAYOUT
)
ROW119_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW119_TARGET_IMPORTED_LAYOUT
)
ROW120_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW120_TARGET_IMPORTED_LAYOUT
)
ROW121_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW121_TARGET_IMPORTED_LAYOUT
)
ROW123_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW123_TARGET_IMPORTED_LAYOUT
)
ROW124_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW124_TARGET_IMPORTED_LAYOUT
)
ROW125_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW125_TARGET_IMPORTED_LAYOUT
)
ROW126_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW126_TARGET_IMPORTED_LAYOUT
)
ROW127_TARGET_IMPORTED_BLOCK_IDS = tuple(
    f"native@0x{start_ea:X}"
    for start_ea, _end_ea, _exact_eas in ROW127_TARGET_IMPORTED_LAYOUT
)
BOUNDARY_EXIT_EAS = (
    0x40A5F0,
    0x40A9A0,
    0x40B55B,
    0x40B898,
    0x40B958,
    0x40BB8F,
    0x40BBF9,
    0x40BC61,
    0x40BCCB,
    0x40BD6A,
    0x40BF8C,
    0x40BFDA,
    0x40C10A,
    0x40C16A,
    0x40C3D9,
    0x40C42E,
    0x40C898,
)
TEMPLATE_ROOT_EAS = (
    0x40A607,
    0x40B6C0,
    0x40A61B,
    0x40A633,
    0x40A64B,
    0x40A663,
    0x40A5CA,
    0x40AE26,
    0x40AE3E,
    0x40A68C,
    0x40A6A6,
    0x40A6C0,
    0x40A960,
    0x40A6DA,
    0x40AB76,
    0x40A6F4,
    0x40AE8B,
    0x40AEA5,
    0x40AF00,
    0x40A70E,
    0x40A800,
    0x40A81A,
    0x40A834,
    0x40A84E,
    0x40AFDF,
    0x40AFF9,
    0x40A868,
    0x40A8B5,
    0x40A8CF,
    0x40ACBF,
    0x40ACD9,
    0x40B26D,
    0x40B287,
    0x40ACF3,
    0x40A8E9,
    0x40B024,
    0x40A903,
    0x40A97A,
    0x40AD1E,
    0x40AD38,
    0x40AD52,
    0x40B2DB,
    0x40B2F5,
    0x40A994,
    0x40B071,
    0x40A9AE,
    0x40AC3D,
    0x40AC56,
    0x40AC70,
    0x40B21C,
    0x40B236,
    0x40AA60,
    0x40A74C,
    0x40A766,
    0x40A9DE,
    0x40A9F8,
    0x40AD6E,
    0x40AD88,
    0x40ADA2,
    0x40B32C,
    0x40B342,
    0x40AA12,
    0x40B0BC,
    0x40B0D6,
    0x40AA2C,
    0x40AA7A,
    0x40AA88,
    0x40AA94,
    0x40AAA2,
    0x40AAFD,
    0x40AB31,
    0x40AB90,
    0x40B17F,
    0x40B0F2,
    0x40B10C,
    0x40B163,
    0x40B199,
    0x40ADBE,
    0x40ADD8,
    0x40B37C,
    0x40B396,
    0x40B3E5,
    0x40B3B0,
    0x40B3FF,
    0x40ADF2,
    0x40A77E,
    0x40ABC6,
    0x40ABE0,
    0x40B1D0,
    0x40B1EA,
    0x40ABFA,
    0x40A794,
    0x40A7AE,
    0x40AEE6,
    0x40B03E,
    0x40B08B,
    0x40B6D6,
    0x40B790,
    0x40B6F0,
    0x40B880,
    0x40B70A,
    0x40BB75,
    0x40B724,
    0x40BD50,
    0x40B73E,
    0x40C0F0,
    0x40B758,
    0x40B7AA,
    0x40B940,
    0x40B7C4,
    0x40BBDF,
    0x40B7DE,
    0x40BE2F,
    0x40B7F6,
    0x40C150,
    0x40B810,
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
                not any(
                    start_ea <= ea < end_ea
                    for start_ea, end_ea in (*owned_ranges, *boundary_ranges)
                )
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
                not any(
                    start_ea <= ea < end_ea
                    for start_ea, end_ea in (*owned_ranges, *boundary_ranges)
                )
                for ea in preserved_unresolved_transfer_eas
            ):
                raise ValueError(
                    "Rhad preserved transfer is outside its captured native range"
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
            if (
                isinstance(
                    operation,
                    (
                        RhadDirectRoute,
                        RhadExistingConditionalRoute,
                        RhadSetccIndexedTableRoute,
                    ),
                )
                or (
                    isinstance(operation, RhadConditionalRoute)
                    and operation.source_block_id in imported_ids
                )
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
            "operation_reference_identities": [
                rhad_reference_operation_identity_payload(operation)
                for operation in self.operations
            ],
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
    reference_order=1,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40A5F0",
    source_value_block_id="native@0x40A5F0",
    source_native_ea=0x40A5BD,
    source_block_anchor_ea=0x40A5F0,
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
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
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
    reference_operation_id="rhad:route@0x40A619",
    reference_order=2,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
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

_ROW3_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A631",
    reference_operation_id="rhad:route@0x40A631",
    reference_order=3,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A62D",
    source_native_ea=0x40A61B,
    transfer_ea=0x40A631,
    owner_anchor_ea=0x40A62D,
    direct_target_block_id="native@0x40A633",
    owned_corridor_instruction_eas=(0x40A61B, 0x40A62D, 0x40A62F, 0x40A631),
    imported_closure_block_ids=ROW3_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A64B, 0x40A8B5),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_DIRECT_ROUTE.operation_id,),
)

_ROW4_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A649",
    reference_operation_id="rhad:route@0x40A649",
    reference_order=4,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A645",
    source_native_ea=0x40A633,
    transfer_ea=0x40A649,
    owner_anchor_ea=0x40A645,
    direct_target_block_id="native@0x40A8B5",
    owned_corridor_instruction_eas=(0x40A633, 0x40A645, 0x40A647, 0x40A649),
    imported_closure_block_ids=ROW26_SOURCE_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40ACBF,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW3_DIRECT_ROUTE.operation_id,),
)

_ROW5_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A661",
    reference_operation_id="rhad:route@0x40A661",
    reference_order=5,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A65D",
    source_native_ea=0x40A64B,
    transfer_ea=0x40A661,
    owner_anchor_ea=0x40A65D,
    direct_target_block_id="native@0x40A663",
    owned_corridor_instruction_eas=(0x40A64B, 0x40A65D, 0x40A65F, 0x40A661),
    imported_closure_block_ids=ROW5_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5CA, 0x40AAFD, 0x40AE26),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW3_DIRECT_ROUTE.operation_id,),
)

_ROW6_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A679",
    reference_operation_id="rhad:route@0x40A679",
    reference_order=6,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A675",
    source_native_ea=0x40A663,
    transfer_ea=0x40A679,
    owner_anchor_ea=0x40A675,
    direct_target_block_id="native@0x40AE26",
    owned_corridor_instruction_eas=(0x40A663, 0x40A675, 0x40A677, 0x40A679),
    imported_closure_block_ids=ROW6_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40AE3E),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW5_DIRECT_ROUTE.operation_id,),
)

_DEPENDENCY_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A68A",
    reference_operation_id="rhad:route@0x40A68A",
    reference_order=7,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
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
    join_ea=0x40A6A0,
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
    join_ea=0x40A6BA,
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
    join_ea=0x40A6D4,
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
    join_ea=0x40A6EE,
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
    join_ea=0x40A708,
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
    reference_operation_id="rhad:route@0x40A74A",
    reference_order=14,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
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
    join_ea=0x40A760,
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
    fallthrough_delivery=FragmentSetccFallthroughDelivery.PHYSICAL_ADJACENCY,
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
    fallthrough_delivery=FragmentSetccFallthroughDelivery.PHYSICAL_ADJACENCY,
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
    join_ea=0x40A7A8,
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

_ROW19_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A7EF",
    reference_operation_id="rhad:route@0x40A7EF",
    reference_order=19,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A7E5",
    source_native_ea=0x40A7CD,
    transfer_ea=0x40A7EF,
    owner_anchor_ea=0x40A7E5,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40A7CD,
        0x40A7E5,
        0x40A7E7,
        0x40A7E9,
        0x40A7EF,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_SIXTH_EXISTING_ROUTE.operation_id,),
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
    join_ea=0x40A814,
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
    join_ea=0x40A82E,
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
    join_ea=0x40A848,
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
    join_ea=0x40A862,
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

_ROW25_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A8B3",
    reference_operation_id="rhad:route@0x40A8B3",
    reference_order=25,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A8A9",
    source_native_ea=0x40A63F,
    transfer_ea=0x40A8B3,
    owner_anchor_ea=0x40A8A9,
    direct_target_block_id="native@0x40A64B",
    owned_corridor_instruction_eas=(
        0x40A63F,
        0x40A8A9,
        0x40A8AF,
        0x40A8B1,
        0x40A8B3,
    ),
    imported_closure_block_ids=ROW25_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A663, 0x40AAFD),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW3_DIRECT_ROUTE.operation_id,),
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
    join_ea=0x40A8C9,
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
        0x40A8B5,
        0x40A8BB,
        0x40A8C1,
        0x40A8C3,
        0x40A8C9,
        0x40A8CB,
        0x40A8CD,
    ),
    imported_closure_block_ids=ROW26_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A8E9, 0x40B024, 0x40B26D),
    flag_corridor_id="flags-intact@0x40A8BB",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW4_DIRECT_ROUTE.operation_id,),
)

_ROW27_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A8E7",
    reference_order=27,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A8CF",
    selected_value_block_id="native@0x40A8DD",
    join_block_id="native@0x40A8E3",
    source_native_ea=0x40A8CF,
    source_block_anchor_ea=0x40A8E3,
    join_ea=0x40A8E3,
    transfer_ea=0x40A8E7,
    condition_producer_ea=0x40A8D5,
    predicate_anchor_ea=0x40A8DB,
    normalization_start_ea=0x40A8DB,
    source_branch_ea=0x40A8DB,
    selected_value_ea=0x40A8DD,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A8E9",
    false_target_block_id="native@0x40B024",
    true_target_ea=0x40A8E9,
    false_target_ea=0x40B024,
    comparison_constant=0x0CDF90C9,
    owned_corridor_instruction_eas=(
        0x40A8CF,
        0x40A8D5,
        0x40A8DB,
        0x40A8DD,
        0x40A8E3,
        0x40A8E5,
        0x40A8E7,
    ),
    imported_closure_block_ids=ROW27_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40A903),
    flag_corridor_id="flags-intact@0x40A8D5",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW26_EXISTING_ROUTE.operation_id,),
)

_ROW28_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A901",
    reference_order=28,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A8E9",
    selected_value_block_id="native@0x40A8F7",
    join_block_id="native@0x40A8FD",
    source_native_ea=0x40A8E9,
    source_block_anchor_ea=0x40A8FD,
    join_ea=0x40A8FD,
    transfer_ea=0x40A901,
    condition_producer_ea=0x40A8EF,
    predicate_anchor_ea=0x40A8F5,
    normalization_start_ea=0x40A8F5,
    source_branch_ea=0x40A8F5,
    selected_value_ea=0x40A8F7,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40A903",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40A903,
    false_target_ea=0x40A5F0,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40A8E9,
        0x40A8EF,
        0x40A8F5,
        0x40A8F7,
        0x40A8FD,
        0x40A8FF,
        0x40A901,
    ),
    imported_closure_block_ids=ROW28_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40A8EF",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW27_EXISTING_ROUTE.operation_id,),
)

_ROW29_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40A95E",
    reference_operation_id="rhad:route@0x40A95E",
    reference_order=29,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A954",
    source_native_ea=0x40A93C,
    transfer_ea=0x40A95E,
    owner_anchor_ea=0x40A954,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40A93C,
        0x40A954,
        0x40A956,
        0x40A958,
        0x40A95E,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW28_EXISTING_ROUTE.operation_id,),
)

_ROW30_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A978",
    reference_order=30,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A960",
    selected_value_block_id="native@0x40A96E",
    join_block_id="native@0x40A974",
    source_native_ea=0x40A960,
    source_block_anchor_ea=0x40A974,
    join_ea=0x40A974,
    transfer_ea=0x40A978,
    condition_producer_ea=0x40A966,
    predicate_anchor_ea=0x40A96C,
    normalization_start_ea=0x40A96C,
    source_branch_ea=0x40A96C,
    selected_value_ea=0x40A96E,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A97A",
    false_target_block_id="native@0x40AD1E",
    true_target_ea=0x40A97A,
    false_target_ea=0x40AD1E,
    comparison_constant=0x636961E8,
    owned_corridor_instruction_eas=(
        0x40A960,
        0x40A966,
        0x40A96C,
        0x40A96E,
        0x40A974,
        0x40A976,
        0x40A978,
    ),
    imported_closure_block_ids=ROW30_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A994, 0x40B071, 0x40B55B),
    flag_corridor_id="flags-intact@0x40A966",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW9_EXISTING_ROUTE.operation_id,),
)

_ROW31_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A992",
    reference_order=31,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A97A",
    selected_value_block_id="native@0x40A988",
    join_block_id="native@0x40A98E",
    source_native_ea=0x40A97A,
    source_block_anchor_ea=0x40A98E,
    join_ea=0x40A98E,
    transfer_ea=0x40A992,
    condition_producer_ea=0x40A980,
    predicate_anchor_ea=0x40A986,
    normalization_start_ea=0x40A986,
    source_branch_ea=0x40A986,
    selected_value_ea=0x40A988,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A994",
    false_target_block_id="native@0x40B071",
    true_target_ea=0x40A994,
    false_target_ea=0x40B071,
    comparison_constant=0x5E07BA29,
    owned_corridor_instruction_eas=(
        0x40A97A,
        0x40A980,
        0x40A986,
        0x40A988,
        0x40A98E,
        0x40A990,
        0x40A992,
    ),
    imported_closure_block_ids=ROW31_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40A9AE),
    flag_corridor_id="flags-intact@0x40A980",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW30_EXISTING_ROUTE.operation_id,),
)

_ROW32_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A9AC",
    reference_order=32,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A994",
    selected_value_block_id="native@0x40A9A2",
    join_block_id="native@0x40A9A8",
    source_native_ea=0x40A994,
    source_block_anchor_ea=0x40A9A8,
    join_ea=0x40A9A8,
    transfer_ea=0x40A9AC,
    condition_producer_ea=0x40A99A,
    predicate_anchor_ea=0x40A9A0,
    normalization_start_ea=0x40A9A0,
    source_branch_ea=0x40A9A0,
    selected_value_ea=0x40A9A2,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40A9AE",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40A9AE,
    false_target_ea=0x40A5F0,
    comparison_constant=0x4DFFC906,
    owned_corridor_instruction_eas=(
        0x40A994,
        0x40A99A,
        0x40A9A0,
        0x40A9A2,
        0x40A9A8,
        0x40A9AA,
        0x40A9AC,
    ),
    imported_closure_block_ids=ROW32_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40A99A",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW31_EXISTING_ROUTE.operation_id,),
)

_ROW33_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40A9DC",
    reference_order=33,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40A9AE",
    source_value_block_id="native@0x40A9AE",
    source_native_ea=0x40A9B3,
    source_block_anchor_ea=0x40A9AE,
    transfer_ea=0x40A9DC,
    predicate_anchor_ea=0x40A9D5,
    normalization_start_ea=0x40A9D5,
    condition_producer_ea=0x40A9C7,
    conditional_select_ea=0x40A9D5,
    selected_value_block_id="native@0x40A9D5",
    join_block_id="native@0x40A9D8",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40A9B3,
        0x40A9C7,
        0x40A9CD,
        0x40A9CF,
        0x40A9D5,
        0x40A9D8,
        0x40A9DA,
        0x40A9DC,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40A9C7",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW32_EXISTING_ROUTE.operation_id,),
)

_ROW34_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40A9F6",
    reference_order=34,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A9DE",
    selected_value_block_id="native@0x40A9EC",
    join_block_id="native@0x40A9F2",
    source_native_ea=0x40A9DE,
    source_block_anchor_ea=0x40A9F2,
    join_ea=0x40A9F2,
    transfer_ea=0x40A9F6,
    condition_producer_ea=0x40A9E4,
    predicate_anchor_ea=0x40A9EA,
    normalization_start_ea=0x40A9EA,
    source_branch_ea=0x40A9EA,
    selected_value_ea=0x40A9EC,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40A9F8",
    false_target_block_id="native@0x40AD6E",
    true_target_ea=0x40A9F8,
    false_target_ea=0x40AD6E,
    comparison_constant=0x2B8162DC,
    owned_corridor_instruction_eas=(
        0x40A9DE,
        0x40A9E4,
        0x40A9EA,
        0x40A9EC,
        0x40A9F2,
        0x40A9F4,
        0x40A9F6,
    ),
    imported_closure_block_ids=ROW34_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40AA12, 0x40AD88, 0x40B0BC, 0x40B32C),
    flag_corridor_id="flags-intact@0x40A9E4",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_SETCC_ROUTE.operation_id,),
)

_ROW35_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AA10",
    reference_order=35,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40A9F8",
    selected_value_block_id="native@0x40AA06",
    join_block_id="native@0x40AA0C",
    source_native_ea=0x40A9F8,
    source_block_anchor_ea=0x40AA0C,
    join_ea=0x40AA0C,
    transfer_ea=0x40AA10,
    condition_producer_ea=0x40A9FE,
    predicate_anchor_ea=0x40AA04,
    normalization_start_ea=0x40AA04,
    source_branch_ea=0x40AA04,
    selected_value_ea=0x40AA06,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40AA12",
    false_target_block_id="native@0x40B0BC",
    true_target_ea=0x40AA12,
    false_target_ea=0x40B0BC,
    comparison_constant=0x29947C85,
    owned_corridor_instruction_eas=(
        0x40A9F8,
        0x40A9FE,
        0x40AA04,
        0x40AA06,
        0x40AA0C,
        0x40AA0E,
        0x40AA10,
    ),
    imported_closure_block_ids=ROW35_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0,),
    flag_corridor_id="flags-intact@0x40A9FE",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW34_EXISTING_ROUTE.operation_id,),
)

_ROW36_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AA2A",
    reference_order=36,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AA12",
    selected_value_block_id="native@0x40AA20",
    join_block_id="native@0x40AA26",
    source_native_ea=0x40AA12,
    source_block_anchor_ea=0x40AA26,
    join_ea=0x40AA26,
    transfer_ea=0x40AA2A,
    condition_producer_ea=0x40AA18,
    predicate_anchor_ea=0x40AA1E,
    normalization_start_ea=0x40AA1E,
    source_branch_ea=0x40AA1E,
    selected_value_ea=0x40AA20,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40AA2C",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AA2C,
    false_target_ea=0x40A5F0,
    comparison_constant=0x23B8E806,
    owned_corridor_instruction_eas=(
        0x40AA12,
        0x40AA18,
        0x40AA1E,
        0x40AA20,
        0x40AA26,
        0x40AA28,
        0x40AA2A,
    ),
    imported_closure_block_ids=ROW36_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AA18",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW35_EXISTING_ROUTE.operation_id,),
)

_ROW37_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40AA5E",
    reference_order=37,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40AA35",
    source_value_block_id="native@0x40AA35",
    source_native_ea=0x40AA3B,
    source_block_anchor_ea=0x40AA35,
    transfer_ea=0x40AA5E,
    predicate_anchor_ea=0x40AA57,
    normalization_start_ea=0x40AA57,
    condition_producer_ea=0x40AA49,
    conditional_select_ea=0x40AA57,
    selected_value_block_id="native@0x40AA57",
    join_block_id="native@0x40AA5A",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40AA3B,
        0x40AA49,
        0x40AA4F,
        0x40AA51,
        0x40AA57,
        0x40AA5A,
        0x40AA5C,
        0x40AA5E,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40AA49",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW36_EXISTING_ROUTE.operation_id,),
)

_ROW38_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AA78",
    reference_order=38,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AA60",
    selected_value_block_id="native@0x40AA6E",
    join_block_id="native@0x40AA74",
    source_native_ea=0x40AA60,
    source_block_anchor_ea=0x40AA74,
    join_ea=0x40AA74,
    transfer_ea=0x40AA78,
    condition_producer_ea=0x40AA66,
    predicate_anchor_ea=0x40AA6C,
    normalization_start_ea=0x40AA6C,
    source_branch_ea=0x40AA6C,
    selected_value_ea=0x40AA6E,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40AA7A",
    false_target_block_id="native@0x40ADBE",
    true_target_ea=0x40AA7A,
    false_target_ea=0x40ADBE,
    comparison_constant=0x7C4FB03D,
    owned_corridor_instruction_eas=(
        0x40AA60,
        0x40AA66,
        0x40AA6C,
        0x40AA6E,
        0x40AA74,
        0x40AA76,
        0x40AA78,
    ),
    imported_closure_block_ids=ROW38_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40AA94, 0x40ADD8, 0x40B0F2, 0x40B37C),
    flag_corridor_id="flags-intact@0x40AA66",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW20_EXISTING_ROUTE.operation_id,),
)

_ROW39_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AA92",
    reference_order=39,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AA7A",
    selected_value_block_id="native@0x40AA88",
    join_block_id="native@0x40AA8E",
    source_native_ea=0x40AA7A,
    source_block_anchor_ea=0x40AA88,
    join_ea=0x40AA8E,
    transfer_ea=0x40AA92,
    condition_producer_ea=0x40AA80,
    predicate_anchor_ea=0x40AA86,
    normalization_start_ea=0x40AA86,
    source_branch_ea=0x40AA86,
    selected_value_ea=0x40AA88,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40AA94",
    false_target_block_id="native@0x40B0F2",
    true_target_ea=0x40AA94,
    false_target_ea=0x40B0F2,
    comparison_constant=0x78BAC34B,
    owned_corridor_instruction_eas=(
        0x40AA7A,
        0x40AA80,
        0x40AA86,
        0x40AA88,
        0x40AA8E,
        0x40AA90,
        0x40AA92,
    ),
    imported_closure_block_ids=ROW39_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40AAAE),
    flag_corridor_id="flags-intact@0x40AA80",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW38_EXISTING_ROUTE.operation_id,),
)

_ROW40_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AAAC",
    reference_order=40,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AA94",
    selected_value_block_id="native@0x40AAA2",
    join_block_id="native@0x40AAA8",
    source_native_ea=0x40AA94,
    source_block_anchor_ea=0x40AAA2,
    join_ea=0x40AAA8,
    transfer_ea=0x40AAAC,
    condition_producer_ea=0x40AA9A,
    predicate_anchor_ea=0x40AAA0,
    normalization_start_ea=0x40AAA0,
    source_branch_ea=0x40AAA0,
    selected_value_ea=0x40AAA2,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40AAAE",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AAAE,
    false_target_ea=0x40A5F0,
    comparison_constant=0x742F372A,
    owned_corridor_instruction_eas=(
        0x40AA94,
        0x40AA9A,
        0x40AAA0,
        0x40AAA2,
        0x40AAA8,
        0x40AAAA,
        0x40AAAC,
    ),
    imported_closure_block_ids=ROW40_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AA9A",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW39_EXISTING_ROUTE.operation_id,),
)

_ROW42_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40AAFB",
    reference_operation_id="rhad:route@0x40AAFB",
    reference_order=42,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AAF1",
    source_native_ea=0x40A657,
    transfer_ea=0x40AAFB,
    owner_anchor_ea=0x40AAF1,
    direct_target_block_id="native@0x40AAFD",
    owned_corridor_instruction_eas=(
        0x40A657,
        0x40AAF1,
        0x40AAF7,
        0x40AAF9,
        0x40AAFB,
    ),
    imported_closure_block_ids=ROW42_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40AB17, 0x40B149),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW5_DIRECT_ROUTE.operation_id,),
)

_ROW43_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AB15",
    reference_order=43,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AAFD",
    selected_value_block_id="native@0x40AB0B",
    join_block_id="native@0x40AB11",
    source_native_ea=0x40AAFD,
    source_block_anchor_ea=0x40AB0B,
    join_ea=0x40AB11,
    transfer_ea=0x40AB15,
    condition_producer_ea=0x40AB03,
    predicate_anchor_ea=0x40AB09,
    normalization_start_ea=0x40AB09,
    source_branch_ea=0x40AB09,
    selected_value_ea=0x40AB0B,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40AB17",
    false_target_block_id="native@0x40B149",
    true_target_ea=0x40AB17,
    false_target_ea=0x40B149,
    comparison_constant=0x1EBFFA3C,
    owned_corridor_instruction_eas=(
        0x40AAFD,
        0x40AB03,
        0x40AB09,
        0x40AB0B,
        0x40AB11,
        0x40AB13,
        0x40AB15,
    ),
    imported_closure_block_ids=ROW43_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40AB31),
    flag_corridor_id="flags-intact@0x40AB03",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW42_DIRECT_ROUTE.operation_id,),
)

_ROW44_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AB2F",
    reference_order=44,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AB17",
    selected_value_block_id="native@0x40AB25",
    join_block_id="native@0x40AB2B",
    source_native_ea=0x40AB17,
    source_block_anchor_ea=0x40AB25,
    join_ea=0x40AB2B,
    transfer_ea=0x40AB2F,
    condition_producer_ea=0x40AB1D,
    predicate_anchor_ea=0x40AB23,
    normalization_start_ea=0x40AB23,
    source_branch_ea=0x40AB23,
    selected_value_ea=0x40AB25,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40AB31",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AB31,
    false_target_ea=0x40A5F0,
    comparison_constant=0x1BAABD04,
    owned_corridor_instruction_eas=(
        0x40AB17,
        0x40AB1D,
        0x40AB23,
        0x40AB25,
        0x40AB2B,
        0x40AB2D,
        0x40AB2F,
    ),
    imported_closure_block_ids=ROW44_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AB1D",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW43_EXISTING_ROUTE.operation_id,),
)

_ROW45_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40AB74",
    reference_operation_id="rhad:route@0x40AB74",
    reference_order=45,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AB6A",
    source_native_ea=0x40AB56,
    transfer_ea=0x40AB74,
    owner_anchor_ea=0x40AB6A,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40AB56,
        0x40AB6A,
        0x40AB6C,
        0x40AB6E,
        0x40AB74,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW44_EXISTING_ROUTE.operation_id,),
)

_ROW46_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AB8E",
    reference_order=46,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AB76",
    selected_value_block_id="native@0x40AB84",
    join_block_id="native@0x40AB8A",
    source_native_ea=0x40AB76,
    source_block_anchor_ea=0x40AB84,
    join_ea=0x40AB8A,
    transfer_ea=0x40AB8E,
    condition_producer_ea=0x40AB7C,
    predicate_anchor_ea=0x40AB82,
    normalization_start_ea=0x40AB82,
    source_branch_ea=0x40AB82,
    selected_value_ea=0x40AB84,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40AB90",
    false_target_block_id="native@0x40B17F",
    true_target_ea=0x40AB90,
    false_target_ea=0x40B17F,
    comparison_constant=0x456A4274,
    owned_corridor_instruction_eas=(
        0x40AB76,
        0x40AB7C,
        0x40AB82,
        0x40AB84,
        0x40AB8A,
        0x40AB8C,
        0x40AB8E,
    ),
    imported_closure_block_ids=ROW46_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40ABAA, 0x40B199),
    flag_corridor_id="flags-intact@0x40AB7C",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW10_EXISTING_ROUTE.operation_id,),
)

_ROW47_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40ABA8",
    reference_order=47,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AB90",
    selected_value_block_id="native@0x40AB9E",
    join_block_id="native@0x40ABA4",
    source_native_ea=0x40AB90,
    source_block_anchor_ea=0x40AB9E,
    join_ea=0x40ABA4,
    transfer_ea=0x40ABA8,
    condition_producer_ea=0x40AB96,
    predicate_anchor_ea=0x40AB9C,
    normalization_start_ea=0x40AB9C,
    source_branch_ea=0x40AB9C,
    selected_value_ea=0x40AB9E,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40ABAA",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40ABAA,
    false_target_ea=0x40A5F0,
    comparison_constant=0x40D5B460,
    owned_corridor_instruction_eas=(
        0x40AB90,
        0x40AB96,
        0x40AB9C,
        0x40AB9E,
        0x40ABA4,
        0x40ABA6,
        0x40ABA8,
    ),
    imported_closure_block_ids=ROW47_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AB96",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW46_EXISTING_ROUTE.operation_id,),
)

_ROW49_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40ABDE",
    reference_order=49,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40ABC6",
    selected_value_block_id="native@0x40ABD4",
    join_block_id="native@0x40ABDA",
    source_native_ea=0x40ABC6,
    source_block_anchor_ea=0x40ABD4,
    join_ea=0x40ABDA,
    transfer_ea=0x40ABDE,
    condition_producer_ea=0x40ABCC,
    predicate_anchor_ea=0x40ABD2,
    normalization_start_ea=0x40ABD2,
    source_branch_ea=0x40ABD2,
    selected_value_ea=0x40ABD4,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40ABE0",
    false_target_block_id="native@0x40B1D0",
    true_target_ea=0x40ABE0,
    false_target_ea=0x40B1D0,
    comparison_constant=0x22C02855,
    owned_corridor_instruction_eas=(
        0x40ABC6,
        0x40ABCC,
        0x40ABD2,
        0x40ABD4,
        0x40ABDA,
        0x40ABDC,
        0x40ABDE,
    ),
    imported_closure_block_ids=ROW49_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40ABFA, 0x40B1EA),
    flag_corridor_id="flags-intact@0x40ABCC",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_SETCC_ROUTE.operation_id,),
)

_ROW50_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40ABF8",
    reference_order=50,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40ABE0",
    selected_value_block_id="native@0x40ABEE",
    join_block_id="native@0x40ABF4",
    source_native_ea=0x40ABE0,
    source_block_anchor_ea=0x40ABEE,
    join_ea=0x40ABF4,
    transfer_ea=0x40ABF8,
    condition_producer_ea=0x40ABE6,
    predicate_anchor_ea=0x40ABEC,
    normalization_start_ea=0x40ABEC,
    source_branch_ea=0x40ABEC,
    selected_value_ea=0x40ABEE,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40ABFA",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40ABFA,
    false_target_ea=0x40A5F0,
    comparison_constant=0x22642D96,
    owned_corridor_instruction_eas=(
        0x40ABE0,
        0x40ABE6,
        0x40ABEC,
        0x40ABEE,
        0x40ABF4,
        0x40ABF6,
        0x40ABF8,
    ),
    imported_closure_block_ids=ROW50_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40ABE6",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW49_EXISTING_ROUTE.operation_id,),
)

_ROW51_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40AC3B",
    reference_operation_id="rhad:route@0x40AC3B",
    reference_order=51,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AC31",
    source_native_ea=0x40AC19,
    transfer_ea=0x40AC3B,
    owner_anchor_ea=0x40AC31,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40AC19,
        0x40AC31,
        0x40AC33,
        0x40AC35,
        0x40AC3B,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW50_EXISTING_ROUTE.operation_id,),
)

_ROW52_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AC54",
    reference_order=52,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AC3D",
    selected_value_block_id="native@0x40AC4A",
    join_block_id="native@0x40AC50",
    source_native_ea=0x40AC3D,
    source_block_anchor_ea=0x40AC4A,
    join_ea=0x40AC50,
    transfer_ea=0x40AC54,
    condition_producer_ea=0x40AC42,
    predicate_anchor_ea=0x40AC48,
    normalization_start_ea=0x40AC48,
    source_branch_ea=0x40AC48,
    selected_value_ea=0x40AC4A,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40AC56",
    false_target_block_id="native@0x40B21C",
    true_target_ea=0x40AC56,
    false_target_ea=0x40B21C,
    comparison_constant=0x7278AB7F,
    owned_corridor_instruction_eas=(
        0x40AC3D,
        0x40AC42,
        0x40AC48,
        0x40AC4A,
        0x40AC50,
        0x40AC52,
        0x40AC54,
    ),
    imported_closure_block_ids=ROW52_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40AC70),
    flag_corridor_id="flags-intact@0x40AC42",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW21_EXISTING_ROUTE.operation_id,),
)

_ROW53_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AC6E",
    reference_order=53,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AC56",
    selected_value_block_id="native@0x40AC64",
    join_block_id="native@0x40AC6A",
    source_native_ea=0x40AC56,
    source_block_anchor_ea=0x40AC64,
    join_ea=0x40AC6A,
    transfer_ea=0x40AC6E,
    condition_producer_ea=0x40AC5C,
    predicate_anchor_ea=0x40AC62,
    normalization_start_ea=0x40AC62,
    source_branch_ea=0x40AC62,
    selected_value_ea=0x40AC64,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40AC70",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AC70,
    false_target_ea=0x40A5F0,
    comparison_constant=0x6D56E4D2,
    owned_corridor_instruction_eas=(
        0x40AC56,
        0x40AC5C,
        0x40AC62,
        0x40AC64,
        0x40AC6A,
        0x40AC6C,
        0x40AC6E,
    ),
    imported_closure_block_ids=ROW53_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AC5C",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW52_EXISTING_ROUTE.operation_id,),
)

_ROW54_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40ACBD",
    reference_operation_id="rhad:route@0x40ACBD",
    reference_order=54,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40ACB3",
    source_native_ea=0x40AC9B,
    transfer_ea=0x40ACBD,
    owner_anchor_ea=0x40ACB3,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40AC9B,
        0x40ACB3,
        0x40ACB5,
        0x40ACB7,
        0x40ACBD,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW53_EXISTING_ROUTE.operation_id,),
)

_ROW55_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40ACD7",
    reference_order=55,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40ACBF",
    selected_value_block_id="native@0x40ACCD",
    join_block_id="native@0x40ACD3",
    source_native_ea=0x40ACBF,
    source_block_anchor_ea=0x40ACD3,
    join_ea=0x40ACD3,
    transfer_ea=0x40ACD7,
    condition_producer_ea=0x40ACC5,
    predicate_anchor_ea=0x40ACCB,
    normalization_start_ea=0x40ACCB,
    source_branch_ea=0x40ACCB,
    selected_value_ea=0x40ACCD,
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40ACD9",
    false_target_block_id="native@0x40B26D",
    true_target_ea=0x40ACD9,
    false_target_ea=0x40B26D,
    comparison_constant=0x13921E0E,
    owned_corridor_instruction_eas=(
        0x40ACBF,
        0x40ACC5,
        0x40ACCB,
        0x40ACCD,
        0x40ACD3,
        0x40ACD5,
        0x40ACD7,
    ),
    imported_closure_block_ids=ROW55_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40ACF3),
    flag_corridor_id="flags-intact@0x40ACC5",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW54_DIRECT_ROUTE.operation_id,),
)

_ROW56_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40ACF1",
    reference_order=56,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40ACD9",
    selected_value_block_id="native@0x40ACE7",
    join_block_id="native@0x40ACED",
    source_native_ea=0x40ACD9,
    source_block_anchor_ea=0x40ACE7,
    join_ea=0x40ACED,
    transfer_ea=0x40ACF1,
    condition_producer_ea=0x40ACDF,
    predicate_anchor_ea=0x40ACE5,
    normalization_start_ea=0x40ACE5,
    source_branch_ea=0x40ACE5,
    selected_value_ea=0x40ACE7,
    observed_predicate_kind=PredicateKind.NE,
    predicate_kind=PredicateKind.EQ,
    true_target_block_id="native@0x40ACF3",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40ACF3,
    false_target_ea=0x40A5F0,
    comparison_constant=0x0E9795EF,
    owned_corridor_instruction_eas=(
        0x40ACD9,
        0x40ACDF,
        0x40ACE5,
        0x40ACE7,
        0x40ACED,
        0x40ACEF,
        0x40ACF1,
    ),
    imported_closure_block_ids=ROW56_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40ACDF",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW55_EXISTING_ROUTE.operation_id,),
)

_ROW57_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40AD1C",
    reference_operation_id="rhad:route@0x40AD1C",
    reference_order=57,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AD18",
    source_native_ea=0x40AD06,
    transfer_ea=0x40AD1C,
    owner_anchor_ea=0x40AD18,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(0x40AD06, 0x40AD18, 0x40AD1A, 0x40AD1C),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW56_EXISTING_ROUTE.operation_id,),
)

_ROW58_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AD36",
    reference_order=58,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AD1E",
    selected_value_block_id="native@0x40AD2C",
    join_block_id="native@0x40AD32",
    source_native_ea=0x40AD1E,
    source_block_anchor_ea=0x40AD32,
    join_ea=0x40AD32,
    transfer_ea=0x40AD36,
    condition_producer_ea=0x40AD24,
    predicate_anchor_ea=0x40AD2A,
    normalization_start_ea=0x40AD2A,
    source_branch_ea=0x40AD2A,
    selected_value_ea=0x40AD2C,
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40AD38",
    false_target_block_id="native@0x40B2DB",
    true_target_ea=0x40AD38,
    false_target_ea=0x40B2DB,
    comparison_constant=0x6487820D,
    owned_corridor_instruction_eas=(
        0x40AD1E,
        0x40AD24,
        0x40AD2A,
        0x40AD2C,
        0x40AD32,
        0x40AD34,
        0x40AD36,
    ),
    imported_closure_block_ids=ROW58_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40AD52),
    flag_corridor_id="flags-intact@0x40AD24",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW57_DIRECT_ROUTE.operation_id,),
)

_ROW59_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AD50",
    reference_order=59,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AD38",
    selected_value_block_id="native@0x40AD46",
    join_block_id="native@0x40AD4C",
    source_native_ea=0x40AD38,
    source_block_anchor_ea=0x40AD4C,
    join_ea=0x40AD4C,
    transfer_ea=0x40AD50,
    condition_producer_ea=0x40AD3E,
    predicate_anchor_ea=0x40AD44,
    normalization_start_ea=0x40AD44,
    source_branch_ea=0x40AD44,
    selected_value_ea=0x40AD46,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40AD52",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AD52,
    false_target_ea=0x40A5F0,
    comparison_constant=0x636961E8,
    owned_corridor_instruction_eas=(
        0x40AD38,
        0x40AD3E,
        0x40AD44,
        0x40AD46,
        0x40AD4C,
        0x40AD4E,
        0x40AD50,
    ),
    imported_closure_block_ids=ROW59_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AD3E",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW58_EXISTING_ROUTE.operation_id,),
)

_ROW60_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40AD6C",
    reference_order=60,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40AD52",
    source_value_block_id="native@0x40AD52",
    source_native_ea=0x40AD5D,
    source_block_anchor_ea=0x40AD52,
    transfer_ea=0x40AD6C,
    predicate_anchor_ea=0x40AD65,
    normalization_start_ea=0x40AD65,
    condition_producer_ea=0x40AD57,
    conditional_select_ea=0x40AD65,
    selected_value_block_id="native@0x40AD65",
    join_block_id="native@0x40AD68",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40AD5D,
        0x40AD5F,
        0x40AD65,
        0x40AD68,
        0x40AD6A,
        0x40AD6C,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40AD57",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW59_EXISTING_ROUTE.operation_id,),
)

_ROW61_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AD86",
    reference_order=61,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AD6E",
    selected_value_block_id="native@0x40AD7C",
    join_block_id="native@0x40AD82",
    source_native_ea=0x40AD6E,
    source_block_anchor_ea=0x40AD82,
    join_ea=0x40AD82,
    transfer_ea=0x40AD86,
    condition_producer_ea=0x40AD74,
    predicate_anchor_ea=0x40AD7A,
    normalization_start_ea=0x40AD7A,
    source_branch_ea=0x40AD7A,
    selected_value_ea=0x40AD7C,
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40AD88",
    false_target_block_id="native@0x40B32C",
    true_target_ea=0x40AD88,
    false_target_ea=0x40B32C,
    comparison_constant=0x304E8694,
    owned_corridor_instruction_eas=(
        0x40AD6E,
        0x40AD74,
        0x40AD7A,
        0x40AD7C,
        0x40AD82,
        0x40AD84,
        0x40AD86,
    ),
    imported_closure_block_ids=ROW61_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40ADA2, 0x40B342),
    flag_corridor_id="flags-intact@0x40AD74",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW60_CMOV_ROUTE.operation_id,),
)

_ROW62_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40ADA0",
    reference_order=62,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AD88",
    selected_value_block_id="native@0x40AD96",
    join_block_id="native@0x40AD9C",
    source_native_ea=0x40AD88,
    source_block_anchor_ea=0x40AD9C,
    join_ea=0x40AD9C,
    transfer_ea=0x40ADA0,
    condition_producer_ea=0x40AD8E,
    predicate_anchor_ea=0x40AD94,
    normalization_start_ea=0x40AD94,
    source_branch_ea=0x40AD94,
    selected_value_ea=0x40AD96,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40ADA2",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40ADA2,
    false_target_ea=0x40A5F0,
    comparison_constant=0x2B8162DC,
    owned_corridor_instruction_eas=(
        0x40AD88,
        0x40AD8E,
        0x40AD94,
        0x40AD96,
        0x40AD9C,
        0x40AD9E,
        0x40ADA0,
    ),
    imported_closure_block_ids=ROW62_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AD8E",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW61_EXISTING_ROUTE.operation_id,),
)

_ROW63_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40ADBC",
    reference_order=63,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40ADA2",
    source_value_block_id="native@0x40ADA2",
    source_native_ea=0x40ADAD,
    source_block_anchor_ea=0x40ADA2,
    transfer_ea=0x40ADBC,
    predicate_anchor_ea=0x40ADB5,
    normalization_start_ea=0x40ADB5,
    condition_producer_ea=0x40ADA7,
    conditional_select_ea=0x40ADB5,
    selected_value_block_id="native@0x40ADB5",
    join_block_id="native@0x40ADB8",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40ADAD,
        0x40ADAF,
        0x40ADB5,
        0x40ADB8,
        0x40ADBA,
        0x40ADBC,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40ADA7",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW62_EXISTING_ROUTE.operation_id,),
)

_ROW64_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40ADD6",
    reference_order=64,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40ADBE",
    selected_value_block_id="native@0x40ADCC",
    join_block_id="native@0x40ADD2",
    source_native_ea=0x40ADBE,
    source_block_anchor_ea=0x40ADD2,
    join_ea=0x40ADD2,
    transfer_ea=0x40ADD6,
    condition_producer_ea=0x40ADC4,
    predicate_anchor_ea=0x40ADCA,
    normalization_start_ea=0x40ADCA,
    source_branch_ea=0x40ADCA,
    selected_value_ea=0x40ADCC,
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40ADD8",
    false_target_block_id="native@0x40B37C",
    true_target_ea=0x40ADD8,
    false_target_ea=0x40B37C,
    comparison_constant=0x7E46FA09,
    owned_corridor_instruction_eas=(
        0x40ADBE,
        0x40ADC4,
        0x40ADCA,
        0x40ADCC,
        0x40ADD2,
        0x40ADD4,
        0x40ADD6,
    ),
    imported_closure_block_ids=ROW64_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40ADF2, 0x40B396, 0x40B3E5),
    flag_corridor_id="flags-intact@0x40ADC4",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW63_CMOV_ROUTE.operation_id,),
)

_ROW65_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40ADF0",
    reference_order=65,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40ADD8",
    selected_value_block_id="native@0x40ADE6",
    join_block_id="native@0x40ADEC",
    source_native_ea=0x40ADD8,
    source_block_anchor_ea=0x40ADEC,
    join_ea=0x40ADEC,
    transfer_ea=0x40ADF0,
    condition_producer_ea=0x40ADDE,
    predicate_anchor_ea=0x40ADE4,
    normalization_start_ea=0x40ADE4,
    source_branch_ea=0x40ADE4,
    selected_value_ea=0x40ADE6,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40ADF2",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40ADF2,
    false_target_ea=0x40A5F0,
    comparison_constant=0x7C4FB03D,
    owned_corridor_instruction_eas=(
        0x40ADD8,
        0x40ADDE,
        0x40ADE4,
        0x40ADE6,
        0x40ADEC,
        0x40ADEE,
        0x40ADF0,
    ),
    imported_closure_block_ids=ROW65_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40ADDE",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW64_EXISTING_ROUTE.operation_id,),
)

_ROW66_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40AE18",
    reference_order=66,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40ADF2",
    source_value_block_id="native@0x40ADF2",
    source_native_ea=0x40ADFD,
    source_block_anchor_ea=0x40ADF2,
    transfer_ea=0x40AE18,
    predicate_anchor_ea=0x40AE05,
    normalization_start_ea=0x40AE05,
    condition_producer_ea=0x40ADF7,
    conditional_select_ea=0x40AE05,
    selected_value_block_id="native@0x40AE05",
    join_block_id="native@0x40AE08",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40ADFD,
        0x40ADFF,
        0x40AE05,
        0x40AE08,
        0x40AE0A,
        0x40AE18,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40ADF7",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW65_EXISTING_ROUTE.operation_id,),
)

_ROW67_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40AE24",
    reference_operation_id="rhad:route@0x40AE24",
    reference_order=67,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AE1A",
    source_native_ea=0x40A66F,
    transfer_ea=0x40AE24,
    owner_anchor_ea=0x40AE1A,
    direct_target_block_id="native@0x40A5CA",
    owned_corridor_instruction_eas=(
        0x40A66F,
        0x40AE1A,
        0x40AE20,
        0x40AE22,
        0x40AE24,
    ),
    imported_closure_block_ids=ROW67_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40C898),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW66_CMOV_ROUTE.operation_id,),
)

_ROW68_SETCC_TABLE_PROOF_ARTIFACT = load_row68_table_proof_artifact()

_ROW68_SETCC_ROUTE = RhadSetccIndexedTableRoute(
    operation_id="rhad:route@0x40AE3C",
    reference_order=68,
    operation_variant=RhadOperationVariant.SETCC_INDEXED_TABLE,
    reference_symbol="JumpInliner._fixup_index_access",
    source_block_id="native@0x40AE26",
    source_native_ea=0x40AE26,
    source_block_anchor_ea=0x40AE26,
    transfer_ea=0x40AE3C,
    condition_producer_ea=0x40AE28,
    predicate_anchor_ea=0x40AE2E,
    predicate_kind=PredicateKind.EQ,
    fallthrough_delivery=FragmentSetccFallthroughDelivery.PLANNED_HELPER,
    true_target_block_id="native@0x40AE3E",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AE3E,
    false_target_ea=0x40A5F0,
    table_proof_artifact=_ROW68_SETCC_TABLE_PROOF_ARTIFACT,
    owned_corridor_instruction_eas=(
        0x40AE26,
        0x40AE28,
        0x40AE2E,
        0x40AE31,
        0x40AE34,
        0x40AE3A,
        0x40AE3C,
    ),
    imported_closure_block_ids=(*ROW68_TARGET_IMPORTED_BLOCK_IDS,),
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AE28",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW67_DIRECT_ROUTE.operation_id,),
)

_ROW69_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40AE89",
    reference_order=69,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40AE63",
    source_value_block_id="native@0x40AE63",
    source_native_ea=0x40AE69,
    source_block_anchor_ea=0x40AE63,
    transfer_ea=0x40AE89,
    predicate_anchor_ea=0x40AE82,
    normalization_start_ea=0x40AE82,
    condition_producer_ea=0x40AE74,
    conditional_select_ea=0x40AE82,
    selected_value_block_id="native@0x40AE82",
    join_block_id="native@0x40AE85",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40AE69,
        0x40AE7A,
        0x40AE7C,
        0x40AE82,
        0x40AE85,
        0x40AE87,
        0x40AE89,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40AE74",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW68_SETCC_ROUTE.operation_id,),
)

_ROW70_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AEA3",
    reference_order=70,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AE8B",
    selected_value_block_id="native@0x40AE99",
    join_block_id="native@0x40AE9F",
    source_native_ea=0x40AE8B,
    source_block_anchor_ea=0x40AE9F,
    join_ea=0x40AE9F,
    transfer_ea=0x40AEA3,
    condition_producer_ea=0x40AE91,
    predicate_anchor_ea=0x40AE97,
    normalization_start_ea=0x40AE97,
    source_branch_ea=0x40AE97,
    selected_value_ea=0x40AE99,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40AEA5",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AEA5,
    false_target_ea=0x40A5F0,
    comparison_constant=0x40ABF871,
    owned_corridor_instruction_eas=(
        0x40AE8B,
        0x40AE91,
        0x40AE97,
        0x40AE99,
        0x40AE9F,
        0x40AEA1,
        0x40AEA3,
    ),
    imported_closure_block_ids=ROW70_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AE91",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW69_CMOV_ROUTE.operation_id,),
)

_ROW71_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40AEE4",
    reference_operation_id="rhad:route@0x40AEE4",
    reference_order=71,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AEDA",
    source_native_ea=0x40AEC6,
    transfer_ea=0x40AEE4,
    owner_anchor_ea=0x40AEDA,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40AEC6,
        0x40AEDA,
        0x40AEDC,
        0x40AEDE,
        0x40AEE4,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW70_EXISTING_ROUTE.operation_id,),
)

_ROW72_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AEFE",
    reference_order=72,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AEE6",
    selected_value_block_id="native@0x40AEF4",
    join_block_id="native@0x40AEFA",
    source_native_ea=0x40AEE6,
    source_block_anchor_ea=0x40AEFA,
    join_ea=0x40AEFA,
    transfer_ea=0x40AEFE,
    condition_producer_ea=0x40AEEC,
    predicate_anchor_ea=0x40AEF2,
    normalization_start_ea=0x40AEF2,
    source_branch_ea=0x40AEF2,
    selected_value_ea=0x40AEF4,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40AF00",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AF00,
    false_target_ea=0x40A5F0,
    comparison_constant=0x2100AFDD,
    owned_corridor_instruction_eas=(
        0x40AEE6,
        0x40AEEC,
        0x40AEF2,
        0x40AEF4,
        0x40AEFA,
        0x40AEFC,
        0x40AEFE,
    ),
    imported_closure_block_ids=ROW72_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AEEC",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW71_DIRECT_ROUTE.operation_id,),
)

_ROW73_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40AFDD",
    reference_operation_id="rhad:route@0x40AFDD",
    reference_order=73,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AFD3",
    source_native_ea=0x40AFBB,
    transfer_ea=0x40AFDD,
    owner_anchor_ea=0x40AFD3,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40AFBB,
        0x40AFD3,
        0x40AFD5,
        0x40AFD7,
        0x40AFDD,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW72_EXISTING_ROUTE.operation_id,),
)

_ROW74_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40AFF7",
    reference_order=74,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40AFDF",
    selected_value_block_id="native@0x40AFED",
    join_block_id="native@0x40AFF3",
    source_native_ea=0x40AFDF,
    source_block_anchor_ea=0x40AFF3,
    join_ea=0x40AFF3,
    transfer_ea=0x40AFF7,
    condition_producer_ea=0x40AFE5,
    predicate_anchor_ea=0x40AFEB,
    normalization_start_ea=0x40AFEB,
    source_branch_ea=0x40AFEB,
    selected_value_ea=0x40AFED,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40AFF9",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40AFF9,
    false_target_ea=0x40A5F0,
    comparison_constant=0x6859ABF3,
    owned_corridor_instruction_eas=(
        0x40AFDF,
        0x40AFE5,
        0x40AFEB,
        0x40AFED,
        0x40AFF3,
        0x40AFF5,
        0x40AFF7,
    ),
    imported_closure_block_ids=ROW74_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40AFE5",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW73_DIRECT_ROUTE.operation_id,),
)

_ROW75_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B022",
    reference_operation_id="rhad:route@0x40B022",
    reference_order=75,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B01E",
    source_native_ea=0x40B00C,
    transfer_ea=0x40B022,
    owner_anchor_ea=0x40B01E,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(0x40B00C, 0x40B01E, 0x40B020, 0x40B022),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW74_EXISTING_ROUTE.operation_id,),
)

_ROW76_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B03C",
    reference_order=76,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B024",
    selected_value_block_id="native@0x40B032",
    join_block_id="native@0x40B038",
    source_native_ea=0x40B024,
    source_block_anchor_ea=0x40B038,
    join_ea=0x40B038,
    transfer_ea=0x40B03C,
    condition_producer_ea=0x40B02A,
    predicate_anchor_ea=0x40B030,
    normalization_start_ea=0x40B030,
    source_branch_ea=0x40B030,
    selected_value_ea=0x40B032,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B03E",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B03E,
    false_target_ea=0x40A5F0,
    comparison_constant=0x0CDF90C9,
    owned_corridor_instruction_eas=(
        0x40B024,
        0x40B02A,
        0x40B030,
        0x40B032,
        0x40B038,
        0x40B03A,
        0x40B03C,
    ),
    imported_closure_block_ids=ROW76_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B02A",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW75_DIRECT_ROUTE.operation_id,),
)

_ROW77_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B06F",
    reference_operation_id="rhad:route@0x40B06F",
    reference_order=77,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B06B",
    source_native_ea=0x40B059,
    transfer_ea=0x40B06F,
    owner_anchor_ea=0x40B06B,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(0x40B059, 0x40B06B, 0x40B06D, 0x40B06F),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW76_EXISTING_ROUTE.operation_id,),
)

_ROW78_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B089",
    reference_order=78,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B071",
    selected_value_block_id="native@0x40B07F",
    join_block_id="native@0x40B085",
    source_native_ea=0x40B071,
    source_block_anchor_ea=0x40B085,
    join_ea=0x40B085,
    transfer_ea=0x40B089,
    condition_producer_ea=0x40B077,
    predicate_anchor_ea=0x40B07D,
    normalization_start_ea=0x40B07D,
    source_branch_ea=0x40B07D,
    selected_value_ea=0x40B07F,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B08B",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B08B,
    false_target_ea=0x40A5F0,
    comparison_constant=0x5E07BA29,
    owned_corridor_instruction_eas=(
        0x40B071,
        0x40B077,
        0x40B07D,
        0x40B07F,
        0x40B085,
        0x40B087,
        0x40B089,
    ),
    imported_closure_block_ids=ROW78_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B077",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW77_DIRECT_ROUTE.operation_id,),
)

_ROW79_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B0BA",
    reference_order=79,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B094",
    source_value_block_id="native@0x40B094",
    source_native_ea=0x40B09A,
    source_block_anchor_ea=0x40B094,
    transfer_ea=0x40B0BA,
    predicate_anchor_ea=0x40B0B3,
    normalization_start_ea=0x40B0B3,
    condition_producer_ea=0x40B0A5,
    conditional_select_ea=0x40B0B3,
    selected_value_block_id="native@0x40B0B3",
    join_block_id="native@0x40B0B6",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B09A,
        0x40B0AB,
        0x40B0AD,
        0x40B0B3,
        0x40B0B6,
        0x40B0B8,
        0x40B0BA,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B0A5",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW78_EXISTING_ROUTE.operation_id,),
)

_ROW80_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B0D4",
    reference_order=80,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B0BC",
    selected_value_block_id="native@0x40B0CA",
    join_block_id="native@0x40B0D0",
    source_native_ea=0x40B0BC,
    source_block_anchor_ea=0x40B0D0,
    join_ea=0x40B0D0,
    transfer_ea=0x40B0D4,
    condition_producer_ea=0x40B0C2,
    predicate_anchor_ea=0x40B0C8,
    normalization_start_ea=0x40B0C8,
    source_branch_ea=0x40B0C8,
    selected_value_ea=0x40B0CA,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B0D6",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B0D6,
    false_target_ea=0x40A5F0,
    comparison_constant=0x29947C85,
    owned_corridor_instruction_eas=(
        0x40B0BC,
        0x40B0C2,
        0x40B0C8,
        0x40B0CA,
        0x40B0D0,
        0x40B0D2,
        0x40B0D4,
    ),
    imported_closure_block_ids=ROW80_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B0C2",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW79_CMOV_ROUTE.operation_id,),
)

_ROW81_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B0F0",
    reference_order=81,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B0D6",
    source_value_block_id="native@0x40B0D6",
    source_native_ea=0x40B0E1,
    source_block_anchor_ea=0x40B0D6,
    transfer_ea=0x40B0F0,
    predicate_anchor_ea=0x40B0E9,
    normalization_start_ea=0x40B0E9,
    condition_producer_ea=0x40B0DB,
    conditional_select_ea=0x40B0E9,
    selected_value_block_id="native@0x40B0E9",
    join_block_id="native@0x40B0EC",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B0DB,
        0x40B0E1,
        0x40B0E3,
        0x40B0E9,
        0x40B0EC,
        0x40B0EE,
        0x40B0F0,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B0DB",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW80_EXISTING_ROUTE.operation_id,),
)

_ROW82_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B10A",
    reference_order=82,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B0F2",
    selected_value_block_id="native@0x40B100",
    join_block_id="native@0x40B106",
    source_native_ea=0x40B0F2,
    source_block_anchor_ea=0x40B106,
    join_ea=0x40B106,
    transfer_ea=0x40B10A,
    condition_producer_ea=0x40B0F8,
    predicate_anchor_ea=0x40B0FE,
    normalization_start_ea=0x40B0FE,
    source_branch_ea=0x40B0FE,
    selected_value_ea=0x40B100,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B10C",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B10C,
    false_target_ea=0x40A5F0,
    comparison_constant=0x78BAC34B,
    owned_corridor_instruction_eas=(
        0x40B0F2,
        0x40B0F8,
        0x40B0FE,
        0x40B100,
        0x40B106,
        0x40B108,
        0x40B10A,
    ),
    imported_closure_block_ids=ROW82_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B0F8",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW81_CMOV_ROUTE.operation_id,),
)

_ROW83_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B147",
    reference_order=83,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B121",
    source_value_block_id="native@0x40B121",
    source_native_ea=0x40B127,
    source_block_anchor_ea=0x40B121,
    transfer_ea=0x40B147,
    predicate_anchor_ea=0x40B140,
    normalization_start_ea=0x40B140,
    condition_producer_ea=0x40B132,
    conditional_select_ea=0x40B140,
    selected_value_block_id="native@0x40B140",
    join_block_id="native@0x40B143",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B127,
        0x40B132,
        0x40B138,
        0x40B13A,
        0x40B140,
        0x40B143,
        0x40B145,
        0x40B147,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B132",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW82_EXISTING_ROUTE.operation_id,),
)

_ROW84_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B161",
    reference_order=84,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B149",
    selected_value_block_id="native@0x40B157",
    join_block_id="native@0x40B15D",
    source_native_ea=0x40B149,
    source_block_anchor_ea=0x40B15D,
    join_ea=0x40B15D,
    transfer_ea=0x40B161,
    condition_producer_ea=0x40B14F,
    predicate_anchor_ea=0x40B155,
    normalization_start_ea=0x40B155,
    source_branch_ea=0x40B155,
    selected_value_ea=0x40B157,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B163",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B163,
    false_target_ea=0x40A5F0,
    comparison_constant=0x1EBFFA3C,
    owned_corridor_instruction_eas=(
        0x40B149,
        0x40B14F,
        0x40B155,
        0x40B157,
        0x40B15D,
        0x40B15F,
        0x40B161,
    ),
    imported_closure_block_ids=ROW84_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B14F",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW83_CMOV_ROUTE.operation_id,),
)

_ROW85_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B17D",
    reference_order=85,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B163",
    source_value_block_id="native@0x40B163",
    source_native_ea=0x40B16E,
    source_block_anchor_ea=0x40B163,
    transfer_ea=0x40B17D,
    predicate_anchor_ea=0x40B176,
    normalization_start_ea=0x40B176,
    condition_producer_ea=0x40B168,
    conditional_select_ea=0x40B176,
    selected_value_block_id="native@0x40B176",
    join_block_id="native@0x40B179",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B168,
        0x40B16E,
        0x40B170,
        0x40B176,
        0x40B179,
        0x40B17B,
        0x40B17D,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B168",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW84_EXISTING_ROUTE.operation_id,),
)

_ROW86_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B197",
    reference_order=86,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B17F",
    selected_value_block_id="native@0x40B18D",
    join_block_id="native@0x40B193",
    source_native_ea=0x40B17F,
    source_block_anchor_ea=0x40B193,
    join_ea=0x40B193,
    transfer_ea=0x40B197,
    condition_producer_ea=0x40B185,
    predicate_anchor_ea=0x40B18B,
    normalization_start_ea=0x40B18B,
    source_branch_ea=0x40B18B,
    selected_value_ea=0x40B18D,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B199",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B199,
    false_target_ea=0x40A5F0,
    comparison_constant=0x456A4274,
    owned_corridor_instruction_eas=(
        0x40B17F,
        0x40B185,
        0x40B18B,
        0x40B18D,
        0x40B193,
        0x40B195,
        0x40B197,
    ),
    imported_closure_block_ids=ROW86_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B185",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW85_CMOV_ROUTE.operation_id,),
)

_ROW87_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B1CE",
    reference_operation_id="rhad:route@0x40B1CE",
    reference_order=87,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B1CA",
    source_native_ea=0x40B1B6,
    transfer_ea=0x40B1CE,
    owner_anchor_ea=0x40B1CA,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40B1B6,
        0x40B1CA,
        0x40B1CC,
        0x40B1CE,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW86_EXISTING_ROUTE.operation_id,),
)

_ROW88_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B1E8",
    reference_order=88,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B1D0",
    selected_value_block_id="native@0x40B1DE",
    join_block_id="native@0x40B1E4",
    source_native_ea=0x40B1D0,
    source_block_anchor_ea=0x40B1E4,
    join_ea=0x40B1E4,
    transfer_ea=0x40B1E8,
    condition_producer_ea=0x40B1D6,
    predicate_anchor_ea=0x40B1DC,
    normalization_start_ea=0x40B1DC,
    source_branch_ea=0x40B1DC,
    selected_value_ea=0x40B1DE,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B1EA",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B1EA,
    false_target_ea=0x40A5F0,
    comparison_constant=0x22C02855,
    owned_corridor_instruction_eas=(
        0x40B1D0,
        0x40B1D6,
        0x40B1DC,
        0x40B1DE,
        0x40B1E4,
        0x40B1E6,
        0x40B1E8,
    ),
    imported_closure_block_ids=ROW88_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B1D6",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW87_DIRECT_ROUTE.operation_id,),
)

_ROW89_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B21A",
    reference_order=89,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B1F4",
    source_value_block_id="native@0x40B1F4",
    source_native_ea=0x40B1FA,
    source_block_anchor_ea=0x40B1F4,
    transfer_ea=0x40B21A,
    predicate_anchor_ea=0x40B213,
    normalization_start_ea=0x40B213,
    condition_producer_ea=0x40B205,
    conditional_select_ea=0x40B213,
    selected_value_block_id="native@0x40B213",
    join_block_id="native@0x40B216",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B1FA,
        0x40B205,
        0x40B20B,
        0x40B20D,
        0x40B213,
        0x40B216,
        0x40B218,
        0x40B21A,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B205",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW88_EXISTING_ROUTE.operation_id,),
)

_ROW90_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B234",
    reference_order=90,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B21C",
    selected_value_block_id="native@0x40B22A",
    join_block_id="native@0x40B230",
    source_native_ea=0x40B21C,
    source_block_anchor_ea=0x40B230,
    join_ea=0x40B230,
    transfer_ea=0x40B234,
    condition_producer_ea=0x40B222,
    predicate_anchor_ea=0x40B228,
    normalization_start_ea=0x40B228,
    source_branch_ea=0x40B228,
    selected_value_ea=0x40B22A,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B236",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B236,
    false_target_ea=0x40A5F0,
    comparison_constant=0x7278AB7F,
    owned_corridor_instruction_eas=(
        0x40B21C,
        0x40B222,
        0x40B228,
        0x40B22A,
        0x40B230,
        0x40B232,
        0x40B234,
    ),
    imported_closure_block_ids=ROW90_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B222",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW89_CMOV_ROUTE.operation_id,),
)

_ROW91_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B26B",
    reference_order=91,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B242",
    source_value_block_id="native@0x40B242",
    source_native_ea=0x40B248,
    source_block_anchor_ea=0x40B242,
    transfer_ea=0x40B26B,
    predicate_anchor_ea=0x40B264,
    normalization_start_ea=0x40B264,
    condition_producer_ea=0x40B256,
    conditional_select_ea=0x40B264,
    selected_value_block_id="native@0x40B264",
    join_block_id="native@0x40B267",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B248,
        0x40B256,
        0x40B25C,
        0x40B25E,
        0x40B264,
        0x40B267,
        0x40B269,
        0x40B26B,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B256",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW90_EXISTING_ROUTE.operation_id,),
)

_ROW92_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B285",
    reference_order=92,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B26D",
    selected_value_block_id="native@0x40B27B",
    join_block_id="native@0x40B281",
    source_native_ea=0x40B26D,
    source_block_anchor_ea=0x40B281,
    join_ea=0x40B281,
    transfer_ea=0x40B285,
    condition_producer_ea=0x40B273,
    predicate_anchor_ea=0x40B279,
    normalization_start_ea=0x40B279,
    source_branch_ea=0x40B279,
    selected_value_ea=0x40B27B,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B287",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B287,
    false_target_ea=0x40A5F0,
    comparison_constant=0x13921E0E,
    owned_corridor_instruction_eas=(
        0x40B26D,
        0x40B273,
        0x40B279,
        0x40B27B,
        0x40B281,
        0x40B283,
        0x40B285,
    ),
    imported_closure_block_ids=ROW92_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B273",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW91_CMOV_ROUTE.operation_id,),
)

_ROW93_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B2D9",
    reference_operation_id="rhad:route@0x40B2D9",
    reference_order=93,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B2CF",
    source_native_ea=0x40B2B7,
    transfer_ea=0x40B2D9,
    owner_anchor_ea=0x40B2CF,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40B2B7,
        0x40B2CF,
        0x40B2D1,
        0x40B2D3,
        0x40B2D9,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW92_EXISTING_ROUTE.operation_id,),
)

_ROW94_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B2F3",
    reference_order=94,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B2DB",
    selected_value_block_id="native@0x40B2E9",
    join_block_id="native@0x40B2EF",
    source_native_ea=0x40B2DB,
    source_block_anchor_ea=0x40B2EF,
    join_ea=0x40B2EF,
    transfer_ea=0x40B2F3,
    condition_producer_ea=0x40B2E1,
    predicate_anchor_ea=0x40B2E7,
    normalization_start_ea=0x40B2E7,
    source_branch_ea=0x40B2E7,
    selected_value_ea=0x40B2E9,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B2F5",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B2F5,
    false_target_ea=0x40A5F0,
    comparison_constant=0x6487820D,
    owned_corridor_instruction_eas=(
        0x40B2DB,
        0x40B2E1,
        0x40B2E7,
        0x40B2E9,
        0x40B2EF,
        0x40B2F1,
        0x40B2F3,
    ),
    imported_closure_block_ids=ROW94_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B2E1",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW93_DIRECT_ROUTE.operation_id,),
)

_ROW95_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B32A",
    reference_operation_id="rhad:route@0x40B32A",
    reference_order=95,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B326",
    source_native_ea=0x40B312,
    transfer_ea=0x40B32A,
    owner_anchor_ea=0x40B326,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40B312,
        0x40B326,
        0x40B328,
        0x40B32A,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW94_EXISTING_ROUTE.operation_id,),
)

_ROW96_SETCC_TABLE_PROOF_ARTIFACT = load_row96_table_proof_artifact()

_ROW96_SETCC_ROUTE = RhadSetccIndexedTableRoute(
    operation_id="rhad:route@0x40B340",
    reference_order=96,
    operation_variant=RhadOperationVariant.SETCC_INDEXED_TABLE,
    reference_symbol="JumpInliner._fixup_index_access",
    source_block_id="native@0x40B32C",
    source_native_ea=0x40B32C,
    source_block_anchor_ea=0x40B32C,
    transfer_ea=0x40B340,
    condition_producer_ea=0x40B32E,
    predicate_anchor_ea=0x40B334,
    predicate_kind=PredicateKind.NE,
    fallthrough_delivery=FragmentSetccFallthroughDelivery.PLANNED_HELPER,
    true_target_block_id="native@0x40A5F0",
    false_target_block_id="native@0x40B342",
    true_target_ea=0x40A5F0,
    false_target_ea=0x40B342,
    table_proof_artifact=_ROW96_SETCC_TABLE_PROOF_ARTIFACT,
    owned_corridor_instruction_eas=(
        0x40B32C,
        0x40B32E,
        0x40B334,
        0x40B337,
        0x40B33E,
        0x40B340,
    ),
    imported_closure_block_ids=ROW96_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B32E",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW95_DIRECT_ROUTE.operation_id,),
)

_ROW97_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B37A",
    reference_order=97,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B354",
    source_value_block_id="native@0x40B354",
    source_native_ea=0x40B35A,
    source_block_anchor_ea=0x40B354,
    transfer_ea=0x40B37A,
    predicate_anchor_ea=0x40B373,
    normalization_start_ea=0x40B373,
    condition_producer_ea=0x40B365,
    conditional_select_ea=0x40B373,
    selected_value_block_id="native@0x40B373",
    join_block_id="native@0x40B376",
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B35A,
        0x40B365,
        0x40B36B,
        0x40B36D,
        0x40B373,
        0x40B376,
        0x40B378,
        0x40B37A,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B365",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW96_SETCC_ROUTE.operation_id,),
)

_ROW98_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B394",
    reference_order=98,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B37C",
    selected_value_block_id="native@0x40B38A",
    join_block_id="native@0x40B390",
    source_native_ea=0x40B37C,
    source_block_anchor_ea=0x40B390,
    join_ea=0x40B390,
    transfer_ea=0x40B394,
    condition_producer_ea=0x40B382,
    predicate_anchor_ea=0x40B388,
    normalization_start_ea=0x40B388,
    source_branch_ea=0x40B388,
    selected_value_ea=0x40B38A,
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40B396",
    false_target_block_id="native@0x40B3E5",
    true_target_ea=0x40B396,
    false_target_ea=0x40B3E5,
    comparison_constant=0x7F9D6412,
    owned_corridor_instruction_eas=(
        0x40B37C,
        0x40B382,
        0x40B388,
        0x40B38A,
        0x40B390,
        0x40B392,
        0x40B394,
    ),
    imported_closure_block_ids=ROW98_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40B3B0, 0x40B3FF),
    flag_corridor_id="flags-intact@0x40B382",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW97_CMOV_ROUTE.operation_id,),
)

_ROW99_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B3AE",
    reference_order=99,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B396",
    selected_value_block_id="native@0x40B3A4",
    join_block_id="native@0x40B3AA",
    source_native_ea=0x40B396,
    source_block_anchor_ea=0x40B3AA,
    join_ea=0x40B3AA,
    transfer_ea=0x40B3AE,
    condition_producer_ea=0x40B39C,
    predicate_anchor_ea=0x40B3A2,
    normalization_start_ea=0x40B3A2,
    source_branch_ea=0x40B3A2,
    selected_value_ea=0x40B3A4,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B3B0",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B3B0,
    false_target_ea=0x40A5F0,
    comparison_constant=0x7E46FA09,
    owned_corridor_instruction_eas=(
        0x40B396,
        0x40B39C,
        0x40B3A2,
        0x40B3A4,
        0x40B3AA,
        0x40B3AC,
        0x40B3AE,
    ),
    imported_closure_block_ids=ROW99_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B39C",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW98_EXISTING_ROUTE.operation_id,),
)

_ROW100_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B3E3",
    reference_order=100,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B3B0",
    source_value_block_id="native@0x40B3B0",
    source_native_ea=0x40B3B5,
    source_block_anchor_ea=0x40B3B0,
    transfer_ea=0x40B3E3,
    predicate_anchor_ea=0x40B3DC,
    normalization_start_ea=0x40B3DC,
    condition_producer_ea=0x40B3CE,
    conditional_select_ea=0x40B3DC,
    selected_value_block_id="native@0x40B3DC",
    join_block_id="native@0x40B3DF",
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B3B5,
        0x40B3CE,
        0x40B3D4,
        0x40B3D6,
        0x40B3DC,
        0x40B3DF,
        0x40B3E1,
        0x40B3E3,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B3CE",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW99_EXISTING_ROUTE.operation_id,),
)

_ROW101_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B3FD",
    reference_order=101,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B3E5",
    selected_value_block_id="native@0x40B3F3",
    join_block_id="native@0x40B3F9",
    source_native_ea=0x40B3E5,
    source_block_anchor_ea=0x40B3F9,
    join_ea=0x40B3F9,
    transfer_ea=0x40B3FD,
    condition_producer_ea=0x40B3EB,
    predicate_anchor_ea=0x40B3F1,
    normalization_start_ea=0x40B3F1,
    source_branch_ea=0x40B3F1,
    selected_value_ea=0x40B3F3,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B3FF",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B3FF,
    false_target_ea=0x40A5F0,
    comparison_constant=0x7F9D6412,
    owned_corridor_instruction_eas=(
        0x40B3E5,
        0x40B3EB,
        0x40B3F1,
        0x40B3F3,
        0x40B3F9,
        0x40B3FB,
        0x40B3FD,
    ),
    imported_closure_block_ids=ROW101_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B3EB",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW100_CMOV_ROUTE.operation_id,),
)

_ROW102_CMOV_ROUTE = RhadConditionalRoute(
    operation_id="rhad:route@0x40B4C3",
    reference_order=102,
    operation_variant=RhadOperationVariant.CMOV_SELECTED_INDIRECT,
    reference_symbol="JumpInliner._fixup_cmov",
    source_block_id="native@0x40B4A4",
    source_value_block_id="native@0x40B3FF",
    source_native_ea=0x40B476,
    source_block_anchor_ea=0x40B4A4,
    transfer_ea=0x40B4C3,
    predicate_anchor_ea=0x40B4BC,
    normalization_start_ea=0x40B4BC,
    condition_producer_ea=0x40B4B4,
    conditional_select_ea=0x40B4BC,
    selected_value_block_id="native@0x40B4BC",
    join_block_id="native@0x40B4BF",
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40B6C0",
    false_target_block_id="native@0x40A607",
    true_target_ea=0x40B6C0,
    false_target_ea=0x40A607,
    comparison_constant=0x0BB2D365,
    owned_corridor_instruction_eas=(
        0x40B476,
        0x40B4AA,
        0x40B4B4,
        0x40B4BA,
        0x40B4BC,
        0x40B4BF,
        0x40B4C1,
        0x40B4C3,
    ),
    imported_closure_block_ids=ACCEPTED_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C, 0x40B790),
    flag_corridor_id="flags-intact@0x40B4B4",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW101_EXISTING_ROUTE.operation_id,),
)

_ROW103_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B4EE",
    reference_operation_id="rhad:route@0x40B4EE",
    reference_order=103,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B4E2",
    source_native_ea=0x40A7C7,
    transfer_ea=0x40B4EE,
    owner_anchor_ea=0x40B4E2,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40A7C7,
        0x40A7D9,
        0x40A7DF,
        0x40B4D6,
        0x40B4E2,
        0x40B4E4,
        0x40B4E6,
        0x40B4E8,
        0x40B4EE,
    ),
    imported_closure_block_ids=ROW103_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW102_CMOV_ROUTE.operation_id,),
)

_ROW104_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B519",
    reference_operation_id="rhad:route@0x40B519",
    reference_order=104,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B50D",
    source_native_ea=0x40A936,
    transfer_ea=0x40B519,
    owner_anchor_ea=0x40B50D,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40A936,
        0x40A948,
        0x40A94E,
        0x40B501,
        0x40B50D,
        0x40B50F,
        0x40B511,
        0x40B513,
        0x40B519,
    ),
    imported_closure_block_ids=ROW104_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW103_DIRECT_ROUTE.operation_id,),
)

_ROW105_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B540",
    reference_operation_id="rhad:route@0x40B540",
    reference_order=105,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B534",
    source_native_ea=0x40AB31,
    transfer_ea=0x40B540,
    owner_anchor_ea=0x40B534,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40AB31,
        0x40AB50,
        0x40AB62,
        0x40AB64,
        0x40B52C,
        0x40B534,
        0x40B536,
        0x40B538,
        0x40B53A,
        0x40B540,
    ),
    imported_closure_block_ids=ROW105_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW104_DIRECT_ROUTE.operation_id,),
)

_ROW106_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B56B",
    reference_operation_id="rhad:route@0x40B56B",
    reference_order=106,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B55F",
    source_native_ea=0x40AC13,
    transfer_ea=0x40B56B,
    owner_anchor_ea=0x40B55F,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40AC13,
        0x40AC25,
        0x40AC2B,
        0x40B553,
        0x40B55F,
        0x40B561,
        0x40B563,
        0x40B565,
        0x40B56B,
    ),
    imported_closure_block_ids=ROW106_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW105_DIRECT_ROUTE.operation_id,),
)

_ROW107_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B596",
    reference_operation_id="rhad:route@0x40B596",
    reference_order=107,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B58A",
    source_native_ea=0x40AC95,
    transfer_ea=0x40B596,
    owner_anchor_ea=0x40B58A,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40AC95,
        0x40ACA7,
        0x40ACAD,
        0x40B57E,
        0x40B58A,
        0x40B58C,
        0x40B58E,
        0x40B590,
        0x40B596,
    ),
    imported_closure_block_ids=ROW107_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW106_DIRECT_ROUTE.operation_id,),
)

_ROW108_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B5B5",
    reference_operation_id="rhad:route@0x40B5B5",
    reference_order=108,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B5AF",
    source_native_ea=0x40AD00,
    transfer_ea=0x40B5B5,
    owner_anchor_ea=0x40B5AF,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40AD00,
        0x40AD12,
        0x40B5AF,
        0x40B5B1,
        0x40B5B3,
        0x40B5B5,
    ),
    imported_closure_block_ids=ROW108_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW107_DIRECT_ROUTE.operation_id,),
)

_ROW109_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B5DC",
    reference_operation_id="rhad:route@0x40B5DC",
    reference_order=109,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B5D0",
    source_native_ea=0x40AEA5,
    transfer_ea=0x40B5DC,
    owner_anchor_ea=0x40B5D0,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40AEA5,
        0x40AEC0,
        0x40AED2,
        0x40AED4,
        0x40B5C8,
        0x40B5D0,
        0x40B5D2,
        0x40B5D4,
        0x40B5D6,
        0x40B5DC,
    ),
    imported_closure_block_ids=ROW109_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW108_DIRECT_ROUTE.operation_id,),
)

_ROW110_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B607",
    reference_operation_id="rhad:route@0x40B607",
    reference_order=110,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B5FB",
    source_native_ea=0x40AFB5,
    transfer_ea=0x40B607,
    owner_anchor_ea=0x40B5FB,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40AFB5,
        0x40AFC7,
        0x40AFCD,
        0x40B5EF,
        0x40B5FB,
        0x40B5FD,
        0x40B5FF,
        0x40B601,
        0x40B607,
    ),
    imported_closure_block_ids=ROW110_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW109_DIRECT_ROUTE.operation_id,),
)

_ROW111_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B626",
    reference_operation_id="rhad:route@0x40B626",
    reference_order=111,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B620",
    source_native_ea=0x40B006,
    transfer_ea=0x40B626,
    owner_anchor_ea=0x40B620,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40B006,
        0x40B018,
        0x40B620,
        0x40B622,
        0x40B624,
        0x40B626,
    ),
    imported_closure_block_ids=ROW111_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW110_DIRECT_ROUTE.operation_id,),
)

_ROW112_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B645",
    reference_operation_id="rhad:route@0x40B645",
    reference_order=112,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B63F",
    source_native_ea=0x40B053,
    transfer_ea=0x40B645,
    owner_anchor_ea=0x40B63F,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40B053,
        0x40B065,
        0x40B63F,
        0x40B641,
        0x40B643,
        0x40B645,
    ),
    imported_closure_block_ids=ROW112_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW111_DIRECT_ROUTE.operation_id,),
)

_ROW113_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B666",
    reference_operation_id="rhad:route@0x40B666",
    reference_order=113,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B660",
    source_native_ea=0x40B199,
    transfer_ea=0x40B666,
    owner_anchor_ea=0x40B660,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40B199,
        0x40B1B0,
        0x40B1C2,
        0x40B1C4,
        0x40B658,
        0x40B660,
        0x40B662,
        0x40B664,
        0x40B666,
    ),
    imported_closure_block_ids=ROW113_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW112_DIRECT_ROUTE.operation_id,),
)

_ROW114_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B691",
    reference_operation_id="rhad:route@0x40B691",
    reference_order=114,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B685",
    source_native_ea=0x40B2B1,
    transfer_ea=0x40B691,
    owner_anchor_ea=0x40B685,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40B2B1,
        0x40B2C3,
        0x40B2C9,
        0x40B679,
        0x40B685,
        0x40B687,
        0x40B689,
        0x40B68B,
        0x40B691,
    ),
    imported_closure_block_ids=ROW114_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW113_DIRECT_ROUTE.operation_id,),
)

_ROW115_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B6B2",
    reference_operation_id="rhad:route@0x40B6B2",
    reference_order=115,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B6AC",
    source_native_ea=0x40B2F5,
    transfer_ea=0x40B6B2,
    owner_anchor_ea=0x40B6AC,
    direct_target_block_id="native@0x40A607",
    owned_corridor_instruction_eas=(
        0x40B2F5,
        0x40B30C,
        0x40B31E,
        0x40B320,
        0x40B6A4,
        0x40B6AC,
        0x40B6AE,
        0x40B6B0,
        0x40B6B2,
    ),
    imported_closure_block_ids=ROW115_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A61B, 0x40A68C),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW114_DIRECT_ROUTE.operation_id,),
)

_ROW116_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B6D4",
    reference_order=116,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B6C0",
    selected_value_block_id="native@0x40B6CA",
    join_block_id="native@0x40B6D0",
    source_native_ea=0x40B6C0,
    source_block_anchor_ea=0x40B6D0,
    join_ea=0x40B6D0,
    transfer_ea=0x40B6D4,
    condition_producer_ea=0x40B6C2,
    predicate_anchor_ea=0x40B6C8,
    normalization_start_ea=0x40B6C8,
    source_branch_ea=0x40B6C8,
    selected_value_ea=0x40B6CA,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6D6",
    false_target_block_id="native@0x40B790",
    true_target_ea=0x40B6D6,
    false_target_ea=0x40B790,
    comparison_constant=0xCB1F8618,
    owned_corridor_instruction_eas=(
        0x40B6C0,
        0x40B6C2,
        0x40B6C8,
        0x40B6CA,
        0x40B6D0,
        0x40B6D2,
        0x40B6D4,
    ),
    imported_closure_block_ids=ROW116_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B940,),
    flag_corridor_id="flags-intact@0x40B6C2",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW115_DIRECT_ROUTE.operation_id,),
)

_ROW117_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B6EE",
    reference_order=117,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B6D6",
    selected_value_block_id="native@0x40B6E4",
    join_block_id="native@0x40B6EA",
    source_native_ea=0x40B6D6,
    source_block_anchor_ea=0x40B6E4,
    join_ea=0x40B6EA,
    transfer_ea=0x40B6EE,
    condition_producer_ea=0x40B6DC,
    predicate_anchor_ea=0x40B6E2,
    normalization_start_ea=0x40B6E2,
    source_branch_ea=0x40B6E2,
    selected_value_ea=0x40B6E4,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B6F0",
    false_target_block_id="native@0x40B880",
    true_target_ea=0x40B6F0,
    false_target_ea=0x40B880,
    comparison_constant=0xA5A94B86,
    owned_corridor_instruction_eas=(
        0x40B6D6,
        0x40B6DC,
        0x40B6E2,
        0x40B6E4,
        0x40B6EA,
        0x40B6EC,
        0x40B6EE,
    ),
    imported_closure_block_ids=ROW117_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B70A, 0x40B898, 0x40BB75, 0x40BC61),
    flag_corridor_id="flags-intact@0x40B6DC",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW116_EXISTING_ROUTE.operation_id,),
)

_ROW118_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B708",
    reference_order=118,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B6F0",
    selected_value_block_id="native@0x40B6FE",
    join_block_id="native@0x40B704",
    source_native_ea=0x40B6F0,
    source_block_anchor_ea=0x40B6FE,
    join_ea=0x40B704,
    transfer_ea=0x40B708,
    condition_producer_ea=0x40B6F6,
    predicate_anchor_ea=0x40B6FC,
    normalization_start_ea=0x40B6FC,
    source_branch_ea=0x40B6FC,
    selected_value_ea=0x40B6FE,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B70A",
    false_target_block_id="native@0x40BB75",
    true_target_ea=0x40B70A,
    false_target_ea=0x40BB75,
    comparison_constant=0x9A607E2A,
    owned_corridor_instruction_eas=(
        0x40B6F0,
        0x40B6F6,
        0x40B6FC,
        0x40B6FE,
        0x40B704,
        0x40B706,
        0x40B708,
    ),
    imported_closure_block_ids=ROW118_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B724, 0x40BB8F, 0x40BD50, 0x40BF8C),
    flag_corridor_id="flags-intact@0x40B6F6",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW117_EXISTING_ROUTE.operation_id,),
)

_ROW119_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B722",
    reference_order=119,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B70A",
    selected_value_block_id="native@0x40B718",
    join_block_id="native@0x40B71E",
    source_native_ea=0x40B70A,
    source_block_anchor_ea=0x40B718,
    join_ea=0x40B71E,
    transfer_ea=0x40B722,
    condition_producer_ea=0x40B710,
    predicate_anchor_ea=0x40B716,
    normalization_start_ea=0x40B716,
    source_branch_ea=0x40B716,
    selected_value_ea=0x40B718,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B724",
    false_target_block_id="native@0x40BD50",
    true_target_ea=0x40B724,
    false_target_ea=0x40BD50,
    comparison_constant=0x921C6083,
    owned_corridor_instruction_eas=(
        0x40B70A,
        0x40B710,
        0x40B716,
        0x40B718,
        0x40B71E,
        0x40B720,
        0x40B722,
    ),
    imported_closure_block_ids=ROW119_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B73E, 0x40BD6A, 0x40C0F0, 0x40C3D9),
    flag_corridor_id="flags-intact@0x40B710",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW118_EXISTING_ROUTE.operation_id,),
)

_ROW120_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B73C",
    reference_order=120,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B724",
    selected_value_block_id="native@0x40B732",
    join_block_id="native@0x40B738",
    source_native_ea=0x40B724,
    source_block_anchor_ea=0x40B732,
    join_ea=0x40B738,
    transfer_ea=0x40B73C,
    condition_producer_ea=0x40B72A,
    predicate_anchor_ea=0x40B730,
    normalization_start_ea=0x40B730,
    source_branch_ea=0x40B730,
    selected_value_ea=0x40B732,
    observed_predicate_kind=PredicateKind.SGE,
    predicate_kind=PredicateKind.SLT,
    true_target_block_id="native@0x40B73E",
    false_target_block_id="native@0x40C0F0",
    true_target_ea=0x40B73E,
    false_target_ea=0x40C0F0,
    comparison_constant=0x886CCA9F,
    owned_corridor_instruction_eas=(
        0x40B724,
        0x40B72A,
        0x40B730,
        0x40B732,
        0x40B738,
        0x40B73A,
        0x40B73C,
    ),
    imported_closure_block_ids=ROW120_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40B758, 0x40C10A),
    flag_corridor_id="flags-intact@0x40B72A",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW119_EXISTING_ROUTE.operation_id,),
)

_ROW121_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B756",
    reference_order=121,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B73E",
    selected_value_block_id="native@0x40B74C",
    join_block_id="native@0x40B752",
    source_native_ea=0x40B73E,
    source_block_anchor_ea=0x40B74C,
    join_ea=0x40B752,
    transfer_ea=0x40B756,
    condition_producer_ea=0x40B744,
    predicate_anchor_ea=0x40B74A,
    normalization_start_ea=0x40B74A,
    source_branch_ea=0x40B74A,
    selected_value_ea=0x40B74C,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B758",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B758,
    false_target_ea=0x40A5F0,
    comparison_constant=0x82F1899D,
    owned_corridor_instruction_eas=(
        0x40B73E,
        0x40B744,
        0x40B74A,
        0x40B74C,
        0x40B752,
        0x40B754,
        0x40B756,
    ),
    imported_closure_block_ids=ROW121_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B744",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW120_EXISTING_ROUTE.operation_id,),
)

_ROW122_DIRECT_ROUTE = RhadDirectRoute(
    operation_id="route:rhad-direct@0x40B781",
    reference_operation_id="rhad:route@0x40B781",
    reference_order=122,
    operation_variant=RhadOperationVariant.SIMPLE_INDIRECT_JUMP,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B77D",
    source_native_ea=0x40B76B,
    transfer_ea=0x40B781,
    owner_anchor_ea=0x40B77D,
    direct_target_block_id="native@0x40B6C0",
    owned_corridor_instruction_eas=(
        0x40B76B,
        0x40B77D,
        0x40B77F,
        0x40B781,
    ),
    imported_closure_block_ids=ROW19_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B790,),
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW121_EXISTING_ROUTE.operation_id,),
)

_ROW123_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B7A8",
    reference_order=123,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B790",
    selected_value_block_id="native@0x40B79E",
    join_block_id="native@0x40B7A4",
    source_native_ea=0x40B790,
    source_block_anchor_ea=0x40B7A4,
    join_ea=0x40B7A4,
    transfer_ea=0x40B7A8,
    condition_producer_ea=0x40B796,
    predicate_anchor_ea=0x40B79C,
    normalization_start_ea=0x40B79C,
    source_branch_ea=0x40B79C,
    selected_value_ea=0x40B79E,
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40B7AA",
    false_target_block_id="native@0x40B940",
    true_target_ea=0x40B7AA,
    false_target_ea=0x40B940,
    comparison_constant=0xEC71CA67,
    owned_corridor_instruction_eas=(
        0x40B790,
        0x40B796,
        0x40B79C,
        0x40B79E,
        0x40B7A4,
        0x40B7A6,
        0x40B7A8,
    ),
    imported_closure_block_ids=ROW123_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B7C4, 0x40B958, 0x40BBDF, 0x40BCCB),
    flag_corridor_id="flags-intact@0x40B796",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW122_DIRECT_ROUTE.operation_id,),
)

_ROW124_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B7C2",
    reference_order=124,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B7AA",
    selected_value_block_id="native@0x40B7B8",
    join_block_id="native@0x40B7BE",
    source_native_ea=0x40B7AA,
    source_block_anchor_ea=0x40B7B8,
    join_ea=0x40B7BE,
    transfer_ea=0x40B7C2,
    condition_producer_ea=0x40B7B0,
    predicate_anchor_ea=0x40B7B6,
    normalization_start_ea=0x40B7B6,
    source_branch_ea=0x40B7B6,
    selected_value_ea=0x40B7B8,
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40B7C4",
    false_target_block_id="native@0x40BBDF",
    true_target_ea=0x40B7C4,
    false_target_ea=0x40BBDF,
    comparison_constant=0xDEF4B7E6,
    owned_corridor_instruction_eas=(
        0x40B7AA,
        0x40B7B0,
        0x40B7B6,
        0x40B7B8,
        0x40B7BE,
        0x40B7C0,
        0x40B7C2,
    ),
    imported_closure_block_ids=ROW124_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B7DE, 0x40BBF9, 0x40BE2F, 0x40BFDA),
    flag_corridor_id="flags-intact@0x40B7B0",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW123_EXISTING_ROUTE.operation_id,),
)

_ROW125_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B7DC",
    reference_order=125,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B7C4",
    selected_value_block_id="native@0x40B7D2",
    join_block_id="native@0x40B7D8",
    source_native_ea=0x40B7C4,
    source_block_anchor_ea=0x40B7D2,
    join_ea=0x40B7D8,
    transfer_ea=0x40B7DC,
    condition_producer_ea=0x40B7CA,
    predicate_anchor_ea=0x40B7D0,
    normalization_start_ea=0x40B7D0,
    source_branch_ea=0x40B7D0,
    selected_value_ea=0x40B7D2,
    observed_predicate_kind=PredicateKind.SLT,
    predicate_kind=PredicateKind.SGE,
    true_target_block_id="native@0x40B7DE",
    false_target_block_id="native@0x40BE2F",
    true_target_ea=0x40B7DE,
    false_target_ea=0x40BE2F,
    comparison_constant=0xCEA36423,
    owned_corridor_instruction_eas=(
        0x40B7C4,
        0x40B7CA,
        0x40B7D0,
        0x40B7D2,
        0x40B7D8,
        0x40B7DA,
        0x40B7DC,
    ),
    imported_closure_block_ids=ROW125_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40B7F6, 0x40C150, 0x40C42E),
    flag_corridor_id="flags-intact@0x40B7CA",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW124_EXISTING_ROUTE.operation_id,),
)

_ROW126_SETCC_TABLE_PROOF_ARTIFACT = load_row126_table_proof_artifact()

_ROW126_SETCC_ROUTE = RhadSetccIndexedTableRoute(
    operation_id="rhad:route@0x40B7F4",
    reference_order=126,
    operation_variant=RhadOperationVariant.SETCC_INDEXED_TABLE,
    reference_symbol="JumpInliner._fixup_index_access",
    source_block_id="native@0x40B7DE",
    source_native_ea=0x40B7DE,
    source_block_anchor_ea=0x40B7DE,
    transfer_ea=0x40B7F4,
    condition_producer_ea=0x40B7E0,
    predicate_anchor_ea=0x40B7E6,
    predicate_kind=PredicateKind.SGE,
    fallthrough_delivery=FragmentSetccFallthroughDelivery.PLANNED_HELPER,
    true_target_block_id="native@0x40C150",
    false_target_block_id="native@0x40B7F6",
    true_target_ea=0x40C150,
    false_target_ea=0x40B7F6,
    table_proof_artifact=_ROW126_SETCC_TABLE_PROOF_ARTIFACT,
    owned_corridor_instruction_eas=(
        0x40B7DE,
        0x40B7E0,
        0x40B7E6,
        0x40B7E9,
        0x40B7EC,
        0x40B7F2,
        0x40B7F4,
    ),
    imported_closure_block_ids=ROW126_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A5F0, 0x40B810, 0x40C16A),
    flag_corridor_id="flags-intact@0x40B7E0",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW125_EXISTING_ROUTE.operation_id,),
)

_ROW127_EXISTING_ROUTE = RhadExistingConditionalRoute(
    operation_id="rhad:route@0x40B80E",
    reference_order=127,
    operation_variant=RhadOperationVariant.EXISTING_CONDITIONAL_PLUS_INDIRECT,
    reference_symbol="JumpInliner._fixup_jmp_and_possible_jcc",
    source_block_id="native@0x40B7F6",
    selected_value_block_id="native@0x40B804",
    join_block_id="native@0x40B80A",
    source_native_ea=0x40B7F6,
    source_block_anchor_ea=0x40B804,
    join_ea=0x40B80A,
    transfer_ea=0x40B80E,
    condition_producer_ea=0x40B7FC,
    predicate_anchor_ea=0x40B802,
    normalization_start_ea=0x40B802,
    source_branch_ea=0x40B802,
    selected_value_ea=0x40B804,
    observed_predicate_kind=PredicateKind.EQ,
    predicate_kind=PredicateKind.NE,
    true_target_block_id="native@0x40B810",
    false_target_block_id="native@0x40A5F0",
    true_target_ea=0x40B810,
    false_target_ea=0x40A5F0,
    comparison_constant=0xCB1F8618,
    owned_corridor_instruction_eas=(
        0x40B7F6,
        0x40B7FC,
        0x40B802,
        0x40B804,
        0x40B80A,
        0x40B80C,
        0x40B80E,
    ),
    imported_closure_block_ids=ROW127_TARGET_IMPORTED_BLOCK_IDS,
    boundary_exit_eas=(0x40A607, 0x40B6C0),
    flag_corridor_id="flags-intact@0x40B7FC",
    phase=RhadReferencePhase.INDIRECT_JUMP_RECONSTRUCTION,
    depends_on=(_ROW126_SETCC_ROUTE.operation_id,),
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
        "native@0x40A5CA",
        "native@0x40A607",
        "native@0x40A619",
        "native@0x40A68A",
        "native@0x40B6C0",
        "native@0x40B6D4",
        "native@0x40A61B",
        "native@0x40A631",
        "native@0x40A633",
        "native@0x40A649",
        "native@0x40A8A9",
        "native@0x40A8B3",
        "native@0x40A64B",
        "native@0x40A65D",
        "native@0x40A661",
        "native@0x40A663",
        "native@0x40A675",
        "native@0x40A679",
        "native@0x40AAF1",
        "native@0x40AAFB",
        "native@0x40AE1A",
        "native@0x40AE24",
        "native@0x40AE26",
        "native@0x40AE3C",
        "native@0x40AE3E",
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
        "native@0x40AEA5",
        "native@0x40AEC6",
        "native@0x40AEDA",
        "native@0x40AEE4",
        "native@0x40B5B7",
        "native@0x40B5D0",
        "native@0x40B5DC",
        "native@0x40AF00",
        "native@0x40AF1C",
        "native@0x40AF2F",
        "native@0x40AF9D",
        "native@0x40AFBB",
        "native@0x40AFD3",
        "native@0x40AFDD",
        "native@0x40B5DE",
        "native@0x40B5FB",
        "native@0x40B607",
        "native@0x40AFF9",
        "native@0x40B00C",
        "native@0x40B01E",
        "native@0x40B022",
        "native@0x40B609",
        "native@0x40B620",
        "native@0x40B626",
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
        "native@0x40A8E9",
        "native@0x40A8F7",
        "native@0x40A8FD",
        "native@0x40A901",
        "native@0x40B024",
        "native@0x40B032",
        "native@0x40B038",
        "native@0x40B03C",
        "native@0x40A903",
        "native@0x40A922",
        "native@0x40A93C",
        "native@0x40A954",
        "native@0x40A95E",
        "native@0x40B4F0",
        "native@0x40B50D",
        "native@0x40B519",
        "native@0x40A97A",
        "native@0x40A988",
        "native@0x40A98E",
        "native@0x40A992",
        "native@0x40AD1E",
        "native@0x40AD2C",
        "native@0x40AD32",
        "native@0x40AD36",
        "native@0x40AD38",
        "native@0x40AD52",
        "native@0x40B2DB",
        "native@0x40B2E9",
        "native@0x40B2EF",
        "native@0x40B2F3",
        "native@0x40B2F5",
        "native@0x40B312",
        "native@0x40B326",
        "native@0x40B32A",
        "native@0x40B693",
        "native@0x40B6AC",
        "native@0x40B6B2",
        "native@0x40A994",
        "native@0x40A9A2",
        "native@0x40A9A8",
        "native@0x40A9AC",
        "native@0x40B071",
        "native@0x40B07F",
        "native@0x40B085",
        "native@0x40B089",
        "native@0x40A9AE",
        "native@0x40A9D5",
        "native@0x40A9D8",
        "native@0x40A9DC",
        "native@0x40A9F8",
        "native@0x40AA06",
        "native@0x40AA0C",
        "native@0x40AA10",
        "native@0x40AD6E",
        "native@0x40AD7C",
        "native@0x40AD82",
        "native@0x40AD86",
        "native@0x40AD88",
        "native@0x40ADA2",
        "native@0x40B32C",
        "native@0x40B342",
        "native@0x40B354",
        "native@0x40B373",
        "native@0x40B376",
        "native@0x40B37A",
        "native@0x40AA12",
        "native@0x40AA20",
        "native@0x40AA26",
        "native@0x40AA2A",
        "native@0x40B0BC",
        "native@0x40B0CA",
        "native@0x40B0D0",
        "native@0x40B0D4",
        "native@0x40B0D6",
        "native@0x40B0E9",
        "native@0x40B0EC",
        "native@0x40B0F0",
        "native@0x40B10C",
        "native@0x40B11A",
        "native@0x40B121",
        "native@0x40B140",
        "native@0x40B143",
        "native@0x40B147",
        "native@0x40B163",
        "native@0x40B176",
        "native@0x40B179",
        "native@0x40B17D",
        "native@0x40AA2C",
        "native@0x40AA35",
        "native@0x40AA57",
        "native@0x40AA5A",
        "native@0x40AA5E",
        "native@0x40AC3D",
        "native@0x40AC54",
        "native@0x40AA60",
        "native@0x40AA78",
        "native@0x40AA7A",
        "native@0x40AA88",
        "native@0x40AA94",
        "native@0x40AAA2",
        "native@0x40AAA8",
        "native@0x40AAAC",
        "native@0x40AAAE",
        "native@0x40AAEF",
        "native@0x40AAFD",
        "native@0x40AB15",
        "native@0x40AB17",
        "native@0x40AB2F",
        "native@0x40B149",
        "native@0x40B161",
        "native@0x40AB31",
        "native@0x40AB56",
        "native@0x40AB6A",
        "native@0x40AB74",
        "native@0x40B51B",
        "native@0x40B534",
        "native@0x40B540",
        "native@0x40AB90",
        "native@0x40AB9E",
        "native@0x40ABA4",
        "native@0x40ABA8",
        "native@0x40ABAA",
        "native@0x40ABBD",
        "native@0x40ABC0",
        "native@0x40ABC4",
        "native@0x40B17F",
        "native@0x40B18D",
        "native@0x40B193",
        "native@0x40B197",
        "native@0x40B199",
        "native@0x40B1B6",
        "native@0x40B1CA",
        "native@0x40B1CE",
        "native@0x40B647",
        "native@0x40B660",
        "native@0x40B666",
        "native@0x40B0F2",
        "native@0x40B100",
        "native@0x40B106",
        "native@0x40B10A",
        "native@0x40ADBE",
        "native@0x40ADD8",
        "native@0x40B37C",
        "native@0x40B396",
        "native@0x40B3E5",
        "native@0x40B3B0",
        "native@0x40B3FF",
        "native@0x40ADF2",
        "native@0x40A74C",
        "native@0x40A764",
        "native@0x40A766",
        "native@0x40A77C",
        "native@0x40A9DE",
        "native@0x40A9F6",
        "native@0x40A77E",
        "native@0x40A792",
        "native@0x40ABC6",
        "native@0x40ABD4",
        "native@0x40ABDA",
        "native@0x40ABDE",
        "native@0x40ABE0",
        "native@0x40ABEE",
        "native@0x40ABF4",
        "native@0x40ABF8",
        "native@0x40B1D0",
        "native@0x40B1DE",
        "native@0x40B1E4",
        "native@0x40B1E8",
        "native@0x40B1EA",
        "native@0x40B1F4",
        "native@0x40B213",
        "native@0x40B216",
        "native@0x40B21A",
        "native@0x40ABFA",
        "native@0x40ABFF",
        "native@0x40AC19",
        "native@0x40AC31",
        "native@0x40AC3B",
        "native@0x40B542",
        "native@0x40B55F",
        "native@0x40B56B",
        "native@0x40AC56",
        "native@0x40AC64",
        "native@0x40AC6A",
        "native@0x40AC6E",
        "native@0x40B21C",
        "native@0x40B22A",
        "native@0x40B230",
        "native@0x40B234",
        "native@0x40B236",
        "native@0x40B242",
        "native@0x40B264",
        "native@0x40B267",
        "native@0x40AC70",
        "native@0x40AC81",
        "native@0x40AC9B",
        "native@0x40ACB3",
        "native@0x40ACBD",
        "native@0x40B56D",
        "native@0x40B58A",
        "native@0x40B596",
        "native@0x40ACD9",
        "native@0x40ACE7",
        "native@0x40ACED",
        "native@0x40ACF1",
        "native@0x40B26D",
        "native@0x40B27B",
        "native@0x40B281",
        "native@0x40B285",
        "native@0x40B287",
        "native@0x40B2A6",
        "native@0x40B2B7",
        "native@0x40B2CF",
        "native@0x40B2D9",
        "native@0x40B668",
        "native@0x40B685",
        "native@0x40B691",
        "native@0x40ACF3",
        "native@0x40AD06",
        "native@0x40AD18",
        "native@0x40AD1C",
        "native@0x40B598",
        "native@0x40B5AF",
        "native@0x40B5B5",
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
        "native@0x40B03E",
        "native@0x40B059",
        "native@0x40B06B",
        "native@0x40B06F",
        "native@0x40B628",
        "native@0x40B63F",
        "native@0x40B645",
        "native@0x40B08B",
        "native@0x40B094",
        "native@0x40B0B3",
        "native@0x40B0B6",
        "native@0x40B0BA",
        "native@0x40B6D6",
        "native@0x40B790",
        "native@0x40B6F0",
        "native@0x40B880",
        "native@0x40B70A",
        "native@0x40BB75",
        "native@0x40B724",
        "native@0x40BD50",
        "native@0x40B73E",
        "native@0x40C0F0",
        "native@0x40B758",
        "native@0x40B7AA",
        "native@0x40B940",
        "native@0x40B7C4",
        "native@0x40BBDF",
        "native@0x40B7DE",
        "native@0x40BE2F",
        "native@0x40B7F6",
        "native@0x40C150",
        "native@0x40B810",
    ),
    native_body_ranges=(
        (0x40A5CA, 0x40A5E5),
        (0x40A607, 0x40A61B),
        (0x40A61B, 0x40A633),
        (0x40A633, 0x40A64B),
        (0x40A64B, 0x40A67B),
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
        (0x40A8A9, 0x40A8B5),
        (0x40A8B5, 0x40A8CF),
        (0x40A8CF, 0x40A8E9),
        (0x40A8E9, 0x40A903),
        (0x40A903, 0x40A960),
        (0x40A960, 0x40A97A),
        (0x40A97A, 0x40A994),
        (0x40A994, 0x40A9AE),
        (0x40A9AE, 0x40A9DE),
        (0x40A9DE, 0x40A9F8),
        (0x40A9F8, 0x40AA12),
        (0x40AA12, 0x40AA2C),
        (0x40AA2C, 0x40AA60),
        (0x40AA60, 0x40AA7A),
        (0x40AA7A, 0x40AA94),
        (0x40AA94, 0x40AAA2),
        (0x40AAA2, 0x40AAAE),
        (0x40AAAE, 0x40AAF1),
        (0x40AAF1, 0x40AAFD),
        (0x40AAFD, 0x40AB31),
        (0x40AB31, 0x40AB76),
        (0x40AB76, 0x40AB90),
        (0x40AB90, 0x40ABAA),
        (0x40ABAA, 0x40ABC6),
        (0x40ABC6, 0x40ABE0),
        (0x40ABE0, 0x40ABFA),
        (0x40ABFA, 0x40AC3D),
        (0x40AC3D, 0x40AC56),
        (0x40AC56, 0x40AC70),
        (0x40AC70, 0x40ACBF),
        (0x40ACBF, 0x40ACD9),
        (0x40ACD9, 0x40ACF3),
        (0x40ACF3, 0x40AD1E),
        (0x40AD1E, 0x40AD38),
        (0x40AD38, 0x40AD52),
        (0x40AD52, 0x40AD6E),
        (0x40AD6E, 0x40AD88),
        (0x40AD88, 0x40ADA2),
        (0x40ADA2, 0x40ADBE),
        (0x40ADBE, 0x40ADD8),
        (0x40ADD8, 0x40ADF2),
        (0x40ADF2, 0x40AE1A),
        (0x40AE1A, 0x40AE26),
        (0x40AE26, 0x40AE3E),
        (0x40AE3E, 0x40AE8B),
        (0x40AE8B, 0x40AEA5),
        (0x40AEA5, 0x40AEE6),
        (0x40AEE6, 0x40AF00),
        (0x40AF00, 0x40AFDF),
        (0x40AFDF, 0x40AFF9),
        (0x40AFF9, 0x40B024),
        (0x40B024, 0x40B03E),
        (0x40B03E, 0x40B071),
        (0x40B071, 0x40B08B),
        (0x40B08B, 0x40B0BC),
        (0x40B0BC, 0x40B0D6),
        (0x40B0D6, 0x40B0F2),
        (0x40B0F2, 0x40B10C),
        (0x40B10C, 0x40B149),
        (0x40B149, 0x40B163),
        (0x40B163, 0x40B17F),
        (0x40B17F, 0x40B199),
        (0x40B199, 0x40B1D0),
        (0x40B1D0, 0x40B1EA),
        (0x40B1EA, 0x40B21C),
        (0x40B21C, 0x40B236),
        (0x40B236, 0x40B26D),
        (0x40B26D, 0x40B287),
        (0x40B287, 0x40B2DB),
        (0x40B2DB, 0x40B2F5),
        (0x40B2F5, 0x40B32C),
        (0x40B32C, 0x40B342),
        (0x40B342, 0x40B37C),
        (0x40B37C, 0x40B396),
        (0x40B396, 0x40B3B0),
        (0x40B3B0, 0x40B3E5),
        (0x40B3E5, 0x40B3FF),
        (0x40B3FF, 0x40B4C5),
        (0x40B4C5, 0x40B4F0),
        (0x40B4F0, 0x40B51B),
        (0x40B51B, 0x40B542),
        (0x40B542, 0x40B56D),
        (0x40B56D, 0x40B598),
        (0x40B598, 0x40B5B7),
        (0x40B5B7, 0x40B5DE),
        (0x40B5DE, 0x40B609),
        (0x40B609, 0x40B628),
        (0x40B628, 0x40B647),
        (0x40B647, 0x40B668),
        (0x40B668, 0x40B693),
        (0x40B693, 0x40B6B4),
        (0x40B6C0, 0x40B6D6),
        (0x40B6D6, 0x40B6F0),
        (0x40B6F0, 0x40B70A),
        (0x40B70A, 0x40B724),
        (0x40B724, 0x40B73E),
        (0x40B73E, 0x40B758),
        (0x40B758, 0x40B783),
        (0x40B790, 0x40B7AA),
        (0x40B7AA, 0x40B7C4),
        (0x40B7C4, 0x40B7DE),
        (0x40B7DE, 0x40B7F6),
        (0x40B7F6, 0x40B810),
        (0x40B810, 0x40B87B),
        (0x40B880, 0x40B898),
        (0x40B940, 0x40B958),
        (0x40BB75, 0x40BB8F),
        (0x40BBDF, 0x40BBF9),
        (0x40BD50, 0x40BD6A),
        (0x40BE2F, 0x40BE49),
        (0x40C0F0, 0x40C10A),
        (0x40C150, 0x40C16A),
        (0x40C696, 0x40C6B5),
    ),
    native_body_proof_ids=(
        "native-body@0x40A605",
        _DIRECT_ROUTE.operation_id,
        _ROW3_DIRECT_ROUTE.operation_id,
        _ROW4_DIRECT_ROUTE.operation_id,
        _ROW5_DIRECT_ROUTE.operation_id,
        _ROW6_DIRECT_ROUTE.operation_id,
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
        _ROW19_DIRECT_ROUTE.operation_id,
        _ROW20_EXISTING_ROUTE.operation_id,
        _ROW21_EXISTING_ROUTE.operation_id,
        _ROW22_EXISTING_ROUTE.operation_id,
        _ROW23_EXISTING_ROUTE.operation_id,
        _ROW25_DIRECT_ROUTE.operation_id,
        _ROW26_EXISTING_ROUTE.operation_id,
        _ROW27_EXISTING_ROUTE.operation_id,
        _ROW28_EXISTING_ROUTE.operation_id,
        _ROW29_DIRECT_ROUTE.operation_id,
        _ROW30_EXISTING_ROUTE.operation_id,
        _ROW31_EXISTING_ROUTE.operation_id,
        _ROW32_EXISTING_ROUTE.operation_id,
        _ROW33_CMOV_ROUTE.operation_id,
        _ROW34_EXISTING_ROUTE.operation_id,
        _ROW35_EXISTING_ROUTE.operation_id,
        _ROW36_EXISTING_ROUTE.operation_id,
        _ROW37_CMOV_ROUTE.operation_id,
        _ROW38_EXISTING_ROUTE.operation_id,
        _ROW39_EXISTING_ROUTE.operation_id,
        _ROW40_EXISTING_ROUTE.operation_id,
        _ROW42_DIRECT_ROUTE.operation_id,
        _ROW43_EXISTING_ROUTE.operation_id,
        _ROW44_EXISTING_ROUTE.operation_id,
        _ROW45_DIRECT_ROUTE.operation_id,
        _ROW46_EXISTING_ROUTE.operation_id,
        _ROW47_EXISTING_ROUTE.operation_id,
        _ROW49_EXISTING_ROUTE.operation_id,
        _ROW50_EXISTING_ROUTE.operation_id,
        _ROW51_DIRECT_ROUTE.operation_id,
        _ROW52_EXISTING_ROUTE.operation_id,
        _ROW53_EXISTING_ROUTE.operation_id,
        _ROW54_DIRECT_ROUTE.operation_id,
        _ROW55_EXISTING_ROUTE.operation_id,
        _ROW56_EXISTING_ROUTE.operation_id,
        _ROW57_DIRECT_ROUTE.operation_id,
        _ROW58_EXISTING_ROUTE.operation_id,
        _ROW59_EXISTING_ROUTE.operation_id,
        _ROW60_CMOV_ROUTE.operation_id,
        _ROW61_EXISTING_ROUTE.operation_id,
        _ROW62_EXISTING_ROUTE.operation_id,
        _ROW63_CMOV_ROUTE.operation_id,
        _ROW64_EXISTING_ROUTE.operation_id,
        _ROW65_EXISTING_ROUTE.operation_id,
        _ROW66_CMOV_ROUTE.operation_id,
        _ROW67_DIRECT_ROUTE.operation_id,
        _ROW68_SETCC_ROUTE.operation_id,
        _ROW69_CMOV_ROUTE.operation_id,
        _ROW70_EXISTING_ROUTE.operation_id,
        _ROW71_DIRECT_ROUTE.operation_id,
        _ROW72_EXISTING_ROUTE.operation_id,
        _ROW73_DIRECT_ROUTE.operation_id,
        _ROW74_EXISTING_ROUTE.operation_id,
        _ROW75_DIRECT_ROUTE.operation_id,
        _ROW76_EXISTING_ROUTE.operation_id,
        _ROW77_DIRECT_ROUTE.operation_id,
        _ROW78_EXISTING_ROUTE.operation_id,
        _ROW79_CMOV_ROUTE.operation_id,
        _ROW80_EXISTING_ROUTE.operation_id,
        _ROW81_CMOV_ROUTE.operation_id,
        _ROW82_EXISTING_ROUTE.operation_id,
        _ROW83_CMOV_ROUTE.operation_id,
        _ROW84_EXISTING_ROUTE.operation_id,
        _ROW85_CMOV_ROUTE.operation_id,
        _ROW86_EXISTING_ROUTE.operation_id,
        _ROW87_DIRECT_ROUTE.operation_id,
        _ROW88_EXISTING_ROUTE.operation_id,
        _ROW89_CMOV_ROUTE.operation_id,
        _ROW90_EXISTING_ROUTE.operation_id,
        _ROW91_CMOV_ROUTE.operation_id,
        _ROW92_EXISTING_ROUTE.operation_id,
        _ROW93_DIRECT_ROUTE.operation_id,
        _ROW94_EXISTING_ROUTE.operation_id,
        _ROW95_DIRECT_ROUTE.operation_id,
        _ROW96_SETCC_ROUTE.operation_id,
        _ROW97_CMOV_ROUTE.operation_id,
        _ROW98_EXISTING_ROUTE.operation_id,
        _ROW99_EXISTING_ROUTE.operation_id,
        _ROW100_CMOV_ROUTE.operation_id,
        _ROW101_EXISTING_ROUTE.operation_id,
        _ROW102_CMOV_ROUTE.operation_id,
        _ROW103_DIRECT_ROUTE.operation_id,
        _ROW104_DIRECT_ROUTE.operation_id,
        _ROW105_DIRECT_ROUTE.operation_id,
        _ROW106_DIRECT_ROUTE.operation_id,
        _ROW107_DIRECT_ROUTE.operation_id,
        _ROW108_DIRECT_ROUTE.operation_id,
        _ROW109_DIRECT_ROUTE.operation_id,
        _ROW110_DIRECT_ROUTE.operation_id,
        _ROW111_DIRECT_ROUTE.operation_id,
        _ROW112_DIRECT_ROUTE.operation_id,
        _ROW113_DIRECT_ROUTE.operation_id,
        _ROW114_DIRECT_ROUTE.operation_id,
        _ROW115_DIRECT_ROUTE.operation_id,
        _ROW116_EXISTING_ROUTE.operation_id,
        _ROW117_EXISTING_ROUTE.operation_id,
        _ROW118_EXISTING_ROUTE.operation_id,
        _ROW119_EXISTING_ROUTE.operation_id,
        _ROW120_EXISTING_ROUTE.operation_id,
        _ROW121_EXISTING_ROUTE.operation_id,
        _ROW122_DIRECT_ROUTE.operation_id,
        _ROW123_EXISTING_ROUTE.operation_id,
        _ROW124_EXISTING_ROUTE.operation_id,
        _ROW125_EXISTING_ROUTE.operation_id,
        _ROW126_SETCC_ROUTE.operation_id,
        _ROW127_EXISTING_ROUTE.operation_id,
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
            root_ea=0x40A633,
            owned_ranges=((0x40A633, 0x40A64B), (0x40A8A9, 0x40A8B5)),
            owned_block_entry_eas=(
                0x40A633,
                0x40A645,
                0x40A649,
                0x40A8A9,
                0x40A8B3,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A64B, 0x40A8B5),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A649,
                    boundary_exit_eas=(0x40A8B5,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A8B3,
                    boundary_exit_eas=(0x40A64B,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A64B,
            owned_ranges=((0x40A64B, 0x40A663), (0x40AAF1, 0x40AAFD)),
            owned_block_entry_eas=(
                0x40A64B,
                0x40A65D,
                0x40A661,
                0x40AAF1,
                0x40AAFB,
            ),
            boundary_ranges=((0x40A663, 0x40A675),),
            boundary_exit_eas=(0x40A663, 0x40AAFD),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AAFB,
                    boundary_exit_eas=(0x40AAFD,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A663,
            owned_ranges=((0x40A663, 0x40A67B), (0x40AE1A, 0x40AE26)),
            owned_block_entry_eas=(
                0x40A663,
                0x40A675,
                0x40A679,
                0x40AE1A,
                0x40AE24,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5CA, 0x40AE26),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A679,
                    boundary_exit_eas=(0x40AE26,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AE24,
                    boundary_exit_eas=(0x40A5CA,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A5CA,
            owned_ranges=((0x40A5CA, 0x40A5E5),),
            owned_block_entry_eas=(0x40A5CA, 0x40A5DC, 0x40A5DF, 0x40A5E3),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40C898),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A5E3,
                    boundary_exit_eas=(0x40A5F0, 0x40C898),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AE26,
            owned_ranges=((0x40AE26, 0x40AE3E),),
            owned_block_entry_eas=(0x40AE26, 0x40AE3C),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40AE3E),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AE3C,
                    boundary_exit_eas=(0x40A5F0, 0x40AE3E),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AE3E,
            owned_ranges=((0x40AE3E, 0x40AE8B),),
            owned_block_entry_eas=(
                0x40AE3E,
                0x40AE63,
                0x40AE82,
                0x40AE85,
                0x40AE89,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AE89,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
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
            root_ea=0x40AEA5,
            owned_ranges=((0x40AEA5, 0x40AEE6), (0x40B5B7, 0x40B5DE)),
            owned_block_entry_eas=(
                0x40AEA5,
                0x40AEC6,
                0x40AEDA,
                0x40AEE4,
                0x40B5B7,
                0x40B5D0,
                0x40B5DC,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AEE4,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B5DC,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AF00,
            owned_ranges=((0x40AF00, 0x40AFDF), (0x40B5DE, 0x40B609)),
            owned_block_entry_eas=(
                0x40AF00,
                0x40AF1C,
                0x40AF2F,
                0x40AF9D,
                0x40AFBB,
                0x40AFD3,
                0x40AFDD,
                0x40B5DE,
                0x40B5FB,
                0x40B607,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AFDD,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B607,
                    boundary_exit_eas=(0x40A607,),
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
            root_ea=0x40AFF9,
            owned_ranges=((0x40AFF9, 0x40B024), (0x40B609, 0x40B628)),
            owned_block_entry_eas=(
                0x40AFF9,
                0x40B00C,
                0x40B01E,
                0x40B022,
                0x40B609,
                0x40B620,
                0x40B626,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B022,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B626,
                    boundary_exit_eas=(0x40A607,),
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
            root_ea=0x40ACD9,
            owned_ranges=((0x40ACD9, 0x40ACF3),),
            owned_block_entry_eas=(0x40ACD9, 0x40ACE7, 0x40ACED, 0x40ACF1),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40ACF3),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ACF1,
                    boundary_exit_eas=(0x40A5F0, 0x40ACF3),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B26D,
            owned_ranges=((0x40B26D, 0x40B287),),
            owned_block_entry_eas=(0x40B26D, 0x40B27B, 0x40B281, 0x40B285),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B285,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B287,
            owned_ranges=((0x40B287, 0x40B2DB), (0x40B668, 0x40B693)),
            owned_block_entry_eas=(
                0x40B287,
                0x40B2A6,
                0x40B2B7,
                0x40B2CF,
                0x40B2D9,
                0x40B668,
                0x40B685,
                0x40B691,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B2D9,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B691,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ACF3,
            owned_ranges=((0x40ACF3, 0x40AD1E), (0x40B598, 0x40B5B7)),
            owned_block_entry_eas=(
                0x40ACF3,
                0x40AD06,
                0x40AD18,
                0x40AD1C,
                0x40B598,
                0x40B5AF,
                0x40B5B5,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AD1C,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B5B5,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A8E9,
            owned_ranges=((0x40A8E9, 0x40A903),),
            owned_block_entry_eas=(0x40A8E9, 0x40A8F7, 0x40A8FD, 0x40A901),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40A903),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A901,
                    boundary_exit_eas=(0x40A5F0, 0x40A903),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B024,
            owned_ranges=((0x40B024, 0x40B03E),),
            owned_block_entry_eas=(0x40B024, 0x40B032, 0x40B038, 0x40B03C),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B03C,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A903,
            owned_ranges=((0x40A903, 0x40A960), (0x40B4F0, 0x40B51B)),
            owned_block_entry_eas=(
                0x40A903,
                0x40A922,
                0x40A93C,
                0x40A954,
                0x40A95E,
                0x40B4F0,
                0x40B50D,
                0x40B519,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A95E,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B519,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A97A,
            owned_ranges=((0x40A97A, 0x40A994),),
            owned_block_entry_eas=(0x40A97A, 0x40A988, 0x40A98E, 0x40A992),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A994, 0x40B071),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A992,
                    boundary_exit_eas=(0x40A994, 0x40B071),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AD1E,
            owned_ranges=((0x40AD1E, 0x40AD38),),
            owned_block_entry_eas=(0x40AD1E, 0x40AD2C, 0x40AD32, 0x40AD36),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B2DB,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AD36,
                    boundary_exit_eas=(0x40B2DB,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AD38,
            owned_ranges=((0x40AD38, 0x40AD52),),
            owned_block_entry_eas=(0x40AD38, 0x40AD46, 0x40AD4C, 0x40AD50),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40AD52),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AD50,
                    boundary_exit_eas=(0x40A5F0, 0x40AD52),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AD52,
            owned_ranges=((0x40AD52, 0x40AD6E),),
            owned_block_entry_eas=(0x40AD52, 0x40AD65, 0x40AD68, 0x40AD6C),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AD6C,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B2DB,
            owned_ranges=((0x40B2DB, 0x40B2F5),),
            owned_block_entry_eas=(0x40B2DB, 0x40B2E9, 0x40B2EF, 0x40B2F3),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B2F3,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B2F5,
            owned_ranges=((0x40B2F5, 0x40B32C), (0x40B693, 0x40B6B4)),
            owned_block_entry_eas=(
                0x40B2F5,
                0x40B312,
                0x40B326,
                0x40B32A,
                0x40B693,
                0x40B6AC,
                0x40B6B2,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B32A,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B6B2,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A994,
            owned_ranges=((0x40A994, 0x40A9AE),),
            owned_block_entry_eas=(0x40A994, 0x40A9A2, 0x40A9A8, 0x40A9AC),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40A9AE),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A9AC,
                    boundary_exit_eas=(0x40A5F0, 0x40A9AE),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B071,
            owned_ranges=((0x40B071, 0x40B08B),),
            owned_block_entry_eas=(0x40B071, 0x40B07F, 0x40B085, 0x40B089),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B089,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40A9AE,
            owned_ranges=((0x40A9AE, 0x40A9DE),),
            owned_block_entry_eas=(0x40A9AE, 0x40A9D5, 0x40A9D8, 0x40A9DC),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40A9DC,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
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
            boundary_exit_eas=(0x40AC56, 0x40B21C),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AC54,
                    boundary_exit_eas=(0x40AC56, 0x40B21C),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AC56,
            owned_ranges=((0x40AC56, 0x40AC70),),
            owned_block_entry_eas=(0x40AC56, 0x40AC64, 0x40AC6A, 0x40AC6E),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40AC70),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AC6E,
                    boundary_exit_eas=(0x40A5F0, 0x40AC70),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AC70,
            owned_ranges=(
                (0x40AC70, 0x40AC81),
                (0x40AC81, 0x40AC9B),
                (0x40AC9B, 0x40ACB3),
                (0x40ACB3, 0x40ACBF),
                (0x40B56D, 0x40B58A),
                (0x40B58A, 0x40B598),
            ),
            owned_block_entry_eas=(
                0x40AC70,
                0x40AC81,
                0x40AC9B,
                0x40ACB3,
                0x40B56D,
                0x40B58A,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ACBD,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B596,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B21C,
            owned_ranges=((0x40B21C, 0x40B236),),
            owned_block_entry_eas=(0x40B21C, 0x40B22A, 0x40B230, 0x40B234),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B234,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B236,
            owned_ranges=((0x40B236, 0x40B26D),),
            owned_block_entry_eas=(0x40B236, 0x40B242, 0x40B264, 0x40B267),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B26B,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
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
            boundary_exit_eas=(0x40AA7A, 0x40ADBE),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AA78,
                    boundary_exit_eas=(0x40AA7A, 0x40ADBE),
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
            root_ea=0x40A9F8,
            owned_ranges=((0x40A9F8, 0x40AA12),),
            owned_block_entry_eas=(0x40A9F8, 0x40AA06, 0x40AA0C, 0x40AA10),
            boundary_ranges=(),
            boundary_exit_eas=(0x40AA12, 0x40B0BC),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AA10,
                    boundary_exit_eas=(0x40AA12, 0x40B0BC),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AD6E,
            owned_ranges=((0x40AD6E, 0x40AD88),),
            owned_block_entry_eas=(0x40AD6E, 0x40AD7C, 0x40AD82, 0x40AD86),
            boundary_ranges=(),
            boundary_exit_eas=(0x40AD88, 0x40B32C),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AD86,
                    boundary_exit_eas=(0x40AD88, 0x40B32C),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AD88,
            owned_ranges=((0x40AD88, 0x40ADA2),),
            owned_block_entry_eas=(0x40AD88, 0x40AD96, 0x40AD9C, 0x40ADA0),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40ADA2),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ADA0,
                    boundary_exit_eas=(0x40A5F0, 0x40ADA2),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ADA2,
            owned_ranges=((0x40ADA2, 0x40ADBE),),
            owned_block_entry_eas=(0x40ADA2, 0x40ADB5, 0x40ADB8, 0x40ADBC),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ADBC,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B32C,
            owned_ranges=((0x40B32C, 0x40B342),),
            owned_block_entry_eas=(0x40B32C, 0x40B340),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40B342),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B340,
                    boundary_exit_eas=(0x40A5F0, 0x40B342),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B342,
            owned_ranges=((0x40B342, 0x40B37C),),
            owned_block_entry_eas=(
                0x40B342,
                0x40B354,
                0x40B373,
                0x40B376,
                0x40B37A,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B37A,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AA12,
            owned_ranges=((0x40AA12, 0x40AA2C),),
            owned_block_entry_eas=(0x40AA12, 0x40AA20, 0x40AA26, 0x40AA2A),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AA2A,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B0BC,
            owned_ranges=((0x40B0BC, 0x40B0D6),),
            owned_block_entry_eas=(0x40B0BC, 0x40B0CA, 0x40B0D0, 0x40B0D4),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B0D4,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B0D6,
            owned_ranges=((0x40B0D6, 0x40B0F2),),
            owned_block_entry_eas=(0x40B0D6, 0x40B0E9, 0x40B0EC, 0x40B0F0),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B0F0,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AA2C,
            owned_ranges=((0x40AA2C, 0x40AA35), (0x40AA35, 0x40AA60)),
            owned_block_entry_eas=(
                0x40AA2C,
                0x40AA35,
                0x40AA57,
                0x40AA5A,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AA5E,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AA7A,
            owned_ranges=((0x40AA7A, 0x40AA88),),
            owned_block_entry_eas=(0x40AA7A,),
            boundary_ranges=(
                (0x40AA88, 0x40AA8E),
                (0x40AA8E, 0x40AA94),
            ),
            boundary_exit_eas=(0x40AA88, 0x40AA8E, 0x40AA94, 0x40B0F2),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AA92,
                    boundary_exit_eas=(0x40AA94, 0x40B0F2),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AA88,
            owned_ranges=(
                (0x40AA88, 0x40AA8E),
                (0x40AA8E, 0x40AA94),
            ),
            owned_block_entry_eas=(0x40AA88, 0x40AA8E, 0x40AA92),
            boundary_ranges=(),
            boundary_exit_eas=(0x40AA94, 0x40B0F2),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AA92,
                    boundary_exit_eas=(0x40AA94, 0x40B0F2),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AA94,
            owned_ranges=((0x40AA94, 0x40AAA2),),
            owned_block_entry_eas=(0x40AA94,),
            boundary_ranges=(
                (0x40AAA2, 0x40AAA8),
                (0x40AAA8, 0x40AAAE),
            ),
            boundary_exit_eas=(0x40AAA2, 0x40AAA8, 0x40A5F0, 0x40AAAE),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AAAC,
                    boundary_exit_eas=(0x40A5F0, 0x40AAAE),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AAA2,
            owned_ranges=(
                (0x40AAA2, 0x40AAAE),
                (0x40AAAE, 0x40AAF1),
            ),
            owned_block_entry_eas=(
                0x40AAA2,
                0x40AAA8,
                0x40AAAC,
                0x40AAAE,
                0x40AAE8,
                0x40AAEB,
                0x40AAEF,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40A607, 0x40AAAE, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AAAC,
                    boundary_exit_eas=(0x40A5F0, 0x40AAAE),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AAEF,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AAFD,
            owned_ranges=(
                (0x40AAFD, 0x40AB31),
                (0x40B149, 0x40B163),
            ),
            owned_block_entry_eas=(
                0x40AAFD,
                0x40AB0B,
                0x40AB11,
                0x40AB15,
                0x40AB17,
                0x40AB25,
                0x40AB2B,
                0x40AB2F,
                0x40B149,
                0x40B157,
                0x40B15D,
                0x40B161,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40AB17, 0x40AB31, 0x40B149),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AB15,
                    boundary_exit_eas=(0x40AB17, 0x40B149),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AB2F,
                    boundary_exit_eas=(0x40A5F0, 0x40AB31),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B161,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AB31,
            owned_ranges=(
                (0x40AB31, 0x40AB76),
                (0x40B51B, 0x40B542),
            ),
            owned_block_entry_eas=(
                0x40AB31,
                0x40AB56,
                0x40AB6A,
                0x40AB74,
                0x40B51B,
                0x40B534,
                0x40B540,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AB74,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B540,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40AB90,
            owned_ranges=((0x40AB90, 0x40ABC6),),
            owned_block_entry_eas=(
                0x40AB90,
                0x40AB9E,
                0x40ABA4,
                0x40ABA8,
                0x40ABAA,
                0x40ABBD,
                0x40ABC0,
                0x40ABC4,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40A607, 0x40ABAA, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ABA8,
                    boundary_exit_eas=(0x40A5F0, 0x40ABAA),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ABC4,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B17F,
            owned_ranges=(
                (0x40B17F, 0x40B18D),
                (0x40B18D, 0x40B193),
                (0x40B193, 0x40B199),
            ),
            owned_block_entry_eas=(0x40B17F, 0x40B18D, 0x40B193, 0x40B197),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40B199),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B197,
                    boundary_exit_eas=(0x40A5F0, 0x40B199),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B0F2,
            owned_ranges=((0x40B0F2, 0x40B10C),),
            owned_block_entry_eas=(0x40B0F2, 0x40B100, 0x40B106, 0x40B10A),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B10A,
                    boundary_exit_eas=(0x40A5F0,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B10C,
            owned_ranges=((0x40B10C, 0x40B149),),
            owned_block_entry_eas=(
                0x40B10C,
                0x40B11A,
                0x40B121,
                0x40B140,
                0x40B143,
                0x40B147,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B147,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B163,
            owned_ranges=((0x40B163, 0x40B17F),),
            owned_block_entry_eas=(0x40B163, 0x40B176, 0x40B179, 0x40B17D),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B17D,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B199,
            owned_ranges=((0x40B199, 0x40B1D0), (0x40B647, 0x40B668)),
            owned_block_entry_eas=(
                0x40B199,
                0x40B1B6,
                0x40B1CA,
                0x40B1CE,
                0x40B647,
                0x40B660,
                0x40B666,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B1CE,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B666,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ADBE,
            owned_ranges=(
                (0x40ADBE, 0x40ADCC),
                (0x40ADCC, 0x40ADD2),
                (0x40ADD2, 0x40ADD8),
            ),
            owned_block_entry_eas=(0x40ADBE, 0x40ADCC, 0x40ADD2, 0x40ADD6),
            boundary_ranges=(),
            boundary_exit_eas=(0x40ADD8, 0x40B37C),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ADD6,
                    boundary_exit_eas=(0x40ADD8, 0x40B37C),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ADD8,
            owned_ranges=(
                (0x40ADD8, 0x40ADE6),
                (0x40ADE6, 0x40ADEC),
                (0x40ADEC, 0x40ADF2),
            ),
            owned_block_entry_eas=(0x40ADD8, 0x40ADE6, 0x40ADEC, 0x40ADF0),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40ADF2),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ADF0,
                    boundary_exit_eas=(0x40A5F0, 0x40ADF2),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B37C,
            owned_ranges=(
                (0x40B37C, 0x40B38A),
                (0x40B38A, 0x40B390),
                (0x40B390, 0x40B396),
            ),
            owned_block_entry_eas=(0x40B37C, 0x40B38A, 0x40B390, 0x40B394),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B396, 0x40B3E5),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B394,
                    boundary_exit_eas=(0x40B396, 0x40B3E5),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B396,
            owned_ranges=(
                (0x40B396, 0x40B3A4),
                (0x40B3A4, 0x40B3AA),
                (0x40B3AA, 0x40B3B0),
            ),
            owned_block_entry_eas=(0x40B396, 0x40B3A4, 0x40B3AA, 0x40B3AE),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40B3B0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B3AE,
                    boundary_exit_eas=(0x40A5F0, 0x40B3B0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B3E5,
            owned_ranges=(
                (0x40B3E5, 0x40B3F3),
                (0x40B3F3, 0x40B3F9),
                (0x40B3F9, 0x40B3FF),
            ),
            owned_block_entry_eas=(0x40B3E5, 0x40B3F3, 0x40B3F9, 0x40B3FD),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40B3FF),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B3FD,
                    boundary_exit_eas=(0x40A5F0, 0x40B3FF),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B3B0,
            owned_ranges=((0x40B3B0, 0x40B3E3), (0x40B3E3, 0x40B3E5)),
            owned_block_entry_eas=(
                0x40B3B0,
                0x40B3DC,
                0x40B3DF,
                0x40B3E3,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B3E3,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B3FF,
            owned_ranges=(
                (0x40B3FF, 0x40B4A4),
                (0x40B4A4, 0x40B4C3),
                (0x40B4C3, 0x40B4C5),
            ),
            owned_block_entry_eas=(
                0x40B3FF,
                0x40B4A4,
                0x40B4BC,
                0x40B4BF,
                0x40B4C3,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B4C3,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ADF2,
            owned_ranges=((0x40ADF2, 0x40AE1A),),
            owned_block_entry_eas=(0x40ADF2, 0x40AE05, 0x40AE08, 0x40AE18),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AE18,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
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
            boundary_exit_eas=(0x40ABE0, 0x40B1D0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ABDE,
                    boundary_exit_eas=(0x40ABE0, 0x40B1D0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ABE0,
            owned_ranges=((0x40ABE0, 0x40ABFA),),
            owned_block_entry_eas=(0x40ABE0, 0x40ABEE, 0x40ABF4, 0x40ABF8),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40ABFA),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40ABF8,
                    boundary_exit_eas=(0x40A5F0, 0x40ABFA),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B1D0,
            owned_ranges=((0x40B1D0, 0x40B1EA),),
            owned_block_entry_eas=(0x40B1D0, 0x40B1DE, 0x40B1E4, 0x40B1E8),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40B1EA),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B1E8,
                    boundary_exit_eas=(0x40A5F0, 0x40B1EA),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B1EA,
            owned_ranges=((0x40B1EA, 0x40B21C),),
            owned_block_entry_eas=(
                0x40B1EA,
                0x40B1F4,
                0x40B213,
                0x40B216,
                0x40B21A,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B21A,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40ABFA,
            owned_ranges=(
                (0x40ABFA, 0x40AC3D),
                (0x40B542, 0x40B56D),
            ),
            owned_block_entry_eas=(
                0x40ABFA,
                0x40ABFF,
                0x40AC19,
                0x40AC31,
                0x40AC3B,
                0x40B542,
                0x40B55F,
                0x40B56B,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40AC3B,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B56B,
                    boundary_exit_eas=(0x40A607,),
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
        RhadGeneratedTemplateFragment(
            root_ea=0x40B03E,
            owned_ranges=((0x40B03E, 0x40B071), (0x40B628, 0x40B647)),
            owned_block_entry_eas=(
                0x40B03E,
                0x40B059,
                0x40B06B,
                0x40B06F,
                0x40B628,
                0x40B63F,
                0x40B645,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B06F,
                    boundary_exit_eas=(0x40B6C0,),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B645,
                    boundary_exit_eas=(0x40A607,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B08B,
            owned_ranges=((0x40B08B, 0x40B0BC),),
            owned_block_entry_eas=(
                0x40B08B,
                0x40B094,
                0x40B0B3,
                0x40B0B6,
                0x40B0BA,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B0BA,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B6D6,
            owned_ranges=(
                (0x40B6D6, 0x40B6E4),
                (0x40B6E4, 0x40B6EA),
                (0x40B6EA, 0x40B6F0),
            ),
            owned_block_entry_eas=(0x40B6D6, 0x40B6E4, 0x40B6EA),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B6F0, 0x40B880),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B6EE,
                    boundary_exit_eas=(0x40B6F0, 0x40B880),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B790,
            owned_ranges=(
                (0x40B790, 0x40B79E),
                (0x40B79E, 0x40B7A4),
                (0x40B7A4, 0x40B7AA),
            ),
            owned_block_entry_eas=(0x40B790, 0x40B79E, 0x40B7A4),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B7AA, 0x40B940),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B7A8,
                    boundary_exit_eas=(0x40B7AA, 0x40B940),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B6F0,
            owned_ranges=(
                (0x40B6F0, 0x40B6FE),
                (0x40B6FE, 0x40B704),
                (0x40B704, 0x40B70A),
            ),
            owned_block_entry_eas=(0x40B6F0, 0x40B6FE, 0x40B704),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B70A, 0x40BB75),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B708,
                    boundary_exit_eas=(0x40B70A, 0x40BB75),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B880,
            owned_ranges=((0x40B880, 0x40B898),),
            owned_block_entry_eas=(0x40B880,),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B898, 0x40BC61),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B896,
                    boundary_exit_eas=(0x40B898, 0x40BC61),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B70A,
            owned_ranges=(
                (0x40B70A, 0x40B718),
                (0x40B718, 0x40B71E),
                (0x40B71E, 0x40B724),
            ),
            owned_block_entry_eas=(0x40B70A, 0x40B718, 0x40B71E),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B724, 0x40BD50),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B722,
                    boundary_exit_eas=(0x40B724, 0x40BD50),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40BB75,
            owned_ranges=(
                (0x40BB75, 0x40BB83),
                (0x40BB83, 0x40BB89),
                (0x40BB89, 0x40BB8F),
            ),
            owned_block_entry_eas=(0x40BB75, 0x40BB83, 0x40BB89),
            boundary_ranges=(),
            boundary_exit_eas=(0x40BB8F, 0x40BF8C),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40BB8D,
                    boundary_exit_eas=(0x40BB8F, 0x40BF8C),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B724,
            owned_ranges=(
                (0x40B724, 0x40B732),
                (0x40B732, 0x40B738),
                (0x40B738, 0x40B73E),
            ),
            owned_block_entry_eas=(0x40B724, 0x40B732, 0x40B738),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B73E, 0x40C0F0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B73C,
                    boundary_exit_eas=(0x40B73E, 0x40C0F0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40BD50,
            owned_ranges=(
                (0x40BD50, 0x40BD5E),
                (0x40BD5E, 0x40BD64),
                (0x40BD64, 0x40BD6A),
            ),
            owned_block_entry_eas=(0x40BD50, 0x40BD5E, 0x40BD64),
            boundary_ranges=(),
            boundary_exit_eas=(0x40BD6A, 0x40C3D9),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40BD68,
                    boundary_exit_eas=(0x40BD6A, 0x40C3D9),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B73E,
            owned_ranges=(
                (0x40B73E, 0x40B74C),
                (0x40B74C, 0x40B752),
                (0x40B752, 0x40B758),
            ),
            owned_block_entry_eas=(0x40B73E, 0x40B74C, 0x40B752),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40B758),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B756,
                    boundary_exit_eas=(0x40A5F0, 0x40B758),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40C0F0,
            owned_ranges=(
                (0x40C0F0, 0x40C0FE),
                (0x40C0FE, 0x40C104),
                (0x40C104, 0x40C10A),
            ),
            owned_block_entry_eas=(0x40C0F0, 0x40C0FE, 0x40C104),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40C10A),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40C108,
                    boundary_exit_eas=(0x40A5F0, 0x40C10A),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B758,
            owned_ranges=(
                (0x40B758, 0x40B76B),
                (0x40B76B, 0x40B77D),
                (0x40B77D, 0x40B783),
                (0x40C696, 0x40C6AD),
                (0x40C6AD, 0x40C6B5),
            ),
            owned_block_entry_eas=(
                0x40B758,
                0x40B76B,
                0x40B77D,
                0x40C696,
                0x40C6AD,
            ),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B781,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40C6B3,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B7AA,
            owned_ranges=(
                (0x40B7AA, 0x40B7B8),
                (0x40B7B8, 0x40B7BE),
                (0x40B7BE, 0x40B7C4),
            ),
            owned_block_entry_eas=(0x40B7AA, 0x40B7B8, 0x40B7BE),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B7C4, 0x40BBDF),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B7C2,
                    boundary_exit_eas=(0x40B7C4, 0x40BBDF),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B940,
            owned_ranges=((0x40B940, 0x40B958),),
            owned_block_entry_eas=(0x40B940,),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B958, 0x40BCCB),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B956,
                    boundary_exit_eas=(0x40B958, 0x40BCCB),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B7C4,
            owned_ranges=(
                (0x40B7C4, 0x40B7D2),
                (0x40B7D2, 0x40B7D8),
                (0x40B7D8, 0x40B7DE),
            ),
            owned_block_entry_eas=(0x40B7C4, 0x40B7D2, 0x40B7D8),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B7DE, 0x40BE2F),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B7DC,
                    boundary_exit_eas=(0x40B7DE, 0x40BE2F),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40BBDF,
            owned_ranges=(
                (0x40BBDF, 0x40BBED),
                (0x40BBED, 0x40BBF3),
                (0x40BBF3, 0x40BBF9),
            ),
            owned_block_entry_eas=(0x40BBDF, 0x40BBED, 0x40BBF3),
            boundary_ranges=(),
            boundary_exit_eas=(0x40BBF9, 0x40BFDA),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40BBF7,
                    boundary_exit_eas=(0x40BBF9, 0x40BFDA),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B7DE,
            owned_ranges=((0x40B7DE, 0x40B7F6),),
            owned_block_entry_eas=(0x40B7DE,),
            boundary_ranges=(),
            boundary_exit_eas=(0x40B7F6, 0x40C150),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B7F4,
                    boundary_exit_eas=(0x40B7F6, 0x40C150),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40BE2F,
            owned_ranges=(
                (0x40BE2F, 0x40BE3D),
                (0x40BE3D, 0x40BE43),
                (0x40BE43, 0x40BE49),
            ),
            owned_block_entry_eas=(0x40BE2F, 0x40BE3D, 0x40BE43),
            boundary_ranges=(),
            boundary_exit_eas=(0x40C42E,),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40BE47,
                    boundary_exit_eas=(0x40C42E,),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B7F6,
            owned_ranges=(
                (0x40B7F6, 0x40B804),
                (0x40B804, 0x40B80A),
                (0x40B80A, 0x40B810),
            ),
            owned_block_entry_eas=(0x40B7F6, 0x40B804, 0x40B80A),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40B810),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B80E,
                    boundary_exit_eas=(0x40A5F0, 0x40B810),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40C150,
            owned_ranges=(
                (0x40C150, 0x40C15E),
                (0x40C15E, 0x40C164),
                (0x40C164, 0x40C16A),
            ),
            owned_block_entry_eas=(0x40C150, 0x40C15E, 0x40C164),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A5F0, 0x40C16A),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40C168,
                    boundary_exit_eas=(0x40A5F0, 0x40C16A),
                ),
            ),
        ),
        RhadGeneratedTemplateFragment(
            root_ea=0x40B810,
            owned_ranges=((0x40B810, 0x40B87B),),
            owned_block_entry_eas=(0x40B810,),
            boundary_ranges=(),
            boundary_exit_eas=(0x40A607, 0x40B6C0),
            direct_boundary_routes=(),
            preserved_unresolved_transfers=(
                RhadGeneratedPreservedTransfer(
                    transfer_ea=0x40B879,
                    boundary_exit_eas=(0x40A607, 0x40B6C0),
                ),
            ),
        ),
    ),
    operations=(
        _ACCEPTED_ROUTE,
        _DIRECT_ROUTE,
        _ROW3_DIRECT_ROUTE,
        _ROW4_DIRECT_ROUTE,
        _ROW5_DIRECT_ROUTE,
        _ROW6_DIRECT_ROUTE,
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
        _ROW19_DIRECT_ROUTE,
        _ROW20_EXISTING_ROUTE,
        _ROW21_EXISTING_ROUTE,
        _ROW22_EXISTING_ROUTE,
        _ROW23_EXISTING_ROUTE,
        _ROW25_DIRECT_ROUTE,
        _ROW26_EXISTING_ROUTE,
        _ROW27_EXISTING_ROUTE,
        _ROW28_EXISTING_ROUTE,
        _ROW29_DIRECT_ROUTE,
        _ROW30_EXISTING_ROUTE,
        _ROW31_EXISTING_ROUTE,
        _ROW32_EXISTING_ROUTE,
        _ROW33_CMOV_ROUTE,
        _ROW34_EXISTING_ROUTE,
        _ROW35_EXISTING_ROUTE,
        _ROW36_EXISTING_ROUTE,
        _ROW37_CMOV_ROUTE,
        _ROW38_EXISTING_ROUTE,
        _ROW39_EXISTING_ROUTE,
        _ROW40_EXISTING_ROUTE,
        _ROW42_DIRECT_ROUTE,
        _ROW43_EXISTING_ROUTE,
        _ROW44_EXISTING_ROUTE,
        _ROW45_DIRECT_ROUTE,
        _ROW46_EXISTING_ROUTE,
        _ROW47_EXISTING_ROUTE,
        _ROW49_EXISTING_ROUTE,
        _ROW50_EXISTING_ROUTE,
        _ROW51_DIRECT_ROUTE,
        _ROW52_EXISTING_ROUTE,
        _ROW53_EXISTING_ROUTE,
        _ROW54_DIRECT_ROUTE,
        _ROW55_EXISTING_ROUTE,
        _ROW56_EXISTING_ROUTE,
        _ROW57_DIRECT_ROUTE,
        _ROW58_EXISTING_ROUTE,
        _ROW59_EXISTING_ROUTE,
        _ROW60_CMOV_ROUTE,
        _ROW61_EXISTING_ROUTE,
        _ROW62_EXISTING_ROUTE,
        _ROW63_CMOV_ROUTE,
        _ROW64_EXISTING_ROUTE,
        _ROW65_EXISTING_ROUTE,
        _ROW66_CMOV_ROUTE,
        _ROW67_DIRECT_ROUTE,
        _ROW68_SETCC_ROUTE,
        _ROW69_CMOV_ROUTE,
        _ROW70_EXISTING_ROUTE,
        _ROW71_DIRECT_ROUTE,
        _ROW72_EXISTING_ROUTE,
        _ROW73_DIRECT_ROUTE,
        _ROW74_EXISTING_ROUTE,
        _ROW75_DIRECT_ROUTE,
        _ROW76_EXISTING_ROUTE,
        _ROW77_DIRECT_ROUTE,
        _ROW78_EXISTING_ROUTE,
        _ROW79_CMOV_ROUTE,
        _ROW80_EXISTING_ROUTE,
        _ROW81_CMOV_ROUTE,
        _ROW82_EXISTING_ROUTE,
        _ROW83_CMOV_ROUTE,
        _ROW84_EXISTING_ROUTE,
        _ROW85_CMOV_ROUTE,
        _ROW86_EXISTING_ROUTE,
        _ROW87_DIRECT_ROUTE,
        _ROW88_EXISTING_ROUTE,
        _ROW89_CMOV_ROUTE,
        _ROW90_EXISTING_ROUTE,
        _ROW91_CMOV_ROUTE,
        _ROW92_EXISTING_ROUTE,
        _ROW93_DIRECT_ROUTE,
        _ROW94_EXISTING_ROUTE,
        _ROW95_DIRECT_ROUTE,
        _ROW96_SETCC_ROUTE,
        _ROW97_CMOV_ROUTE,
        _ROW98_EXISTING_ROUTE,
        _ROW99_EXISTING_ROUTE,
        _ROW100_CMOV_ROUTE,
        _ROW101_EXISTING_ROUTE,
        _ROW102_CMOV_ROUTE,
        _ROW103_DIRECT_ROUTE,
        _ROW104_DIRECT_ROUTE,
        _ROW105_DIRECT_ROUTE,
        _ROW106_DIRECT_ROUTE,
        _ROW107_DIRECT_ROUTE,
        _ROW108_DIRECT_ROUTE,
        _ROW109_DIRECT_ROUTE,
        _ROW110_DIRECT_ROUTE,
        _ROW111_DIRECT_ROUTE,
        _ROW112_DIRECT_ROUTE,
        _ROW113_DIRECT_ROUTE,
        _ROW114_DIRECT_ROUTE,
        _ROW115_DIRECT_ROUTE,
        _ROW116_EXISTING_ROUTE,
        _ROW117_EXISTING_ROUTE,
        _ROW118_EXISTING_ROUTE,
        _ROW119_EXISTING_ROUTE,
        _ROW120_EXISTING_ROUTE,
        _ROW121_EXISTING_ROUTE,
        _ROW122_DIRECT_ROUTE,
        _ROW123_EXISTING_ROUTE,
        _ROW124_EXISTING_ROUTE,
        _ROW125_EXISTING_ROUTE,
        _ROW126_SETCC_ROUTE,
        _ROW127_EXISTING_ROUTE,
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


def _direct_route_maturity_payload(
    *,
    route: RhadDirectRoute,
    direct_target_ea: int,
    direct_indirect: bool,
    direct_source_present: bool,
    source_topology_reachable: bool,
    direct_targets: set[int],
) -> dict[str, object]:
    """Persist the complete typed semantic contract for one direct route."""
    expected_targets = {int(direct_target_ea)}
    semantic_targets_survive = bool(
        not source_topology_reachable or direct_targets == expected_targets
    )
    return {
        "operation_id": route.operation_id,
        "operation_category": route.category.value,
        "operation_variant": route.operation_variant.value,
        "source_present": bool(direct_source_present),
        "source_topology_reachable": bool(source_topology_reachable),
        "source_topology_retired": not source_topology_reachable,
        "indirect_transfer_present": bool(direct_indirect),
        "target_eas": sorted(direct_targets),
        "semantic_target_eas": sorted(expected_targets),
        "delivery_target_eas": sorted(expected_targets),
        "semantic_targets_survive": semantic_targets_survive,
        "boundary_exit_eas": sorted(route.boundary_exit_eas),
        "passed": not direct_indirect and semantic_targets_survive,
    }


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
    accepted_target_block_ids = (
        accepted_route.true_target_block_id,
        accepted_route.false_target_block_id,
    )
    expected_accepted_targets = {
        block_anchor_by_id[block_id] for block_id in accepted_target_block_ids
    }
    accepted_source_topology_reachable = bool(
        accepted_source is not None
        and accepted_targets == expected_accepted_targets
        and (
            int(mba.maturity) == int(ida_hexrays.MMAT_GENERATED)
            or int(accepted_source.serial) in reachable_block_serials
        )
    )
    accepted_semantic_targets_survive = bool(
        (
            accepted_source_topology_reachable
            and (
                int(mba.maturity) == int(ida_hexrays.MMAT_GENERATED)
                or delivery_targets_reachable(accepted_target_block_ids)
            )
        )
        or (
            not accepted_source_topology_reachable
            and delivery_targets_reachable((accepted_route.true_target_block_id,))
        )
    )
    accepted_passed = bool(not accepted_indirect and accepted_semantic_targets_survive)

    operation_observations: list[dict[str, object]] = [
        {
            "operation_id": accepted_route.operation_id,
            "operation_category": accepted_route.category.value,
            "operation_variant": accepted_route.operation_variant.value,
            "source_present": accepted_source is not None,
            "source_topology_reachable": accepted_source_topology_reachable,
            "source_topology_retired": not accepted_source_topology_reachable,
            "indirect_transfer_present": accepted_indirect,
            "target_eas": sorted(accepted_targets),
            "semantic_target_eas": sorted(expected_accepted_targets),
            "delivery_target_eas": sorted(expected_accepted_targets),
            "semantic_targets_survive": accepted_semantic_targets_survive,
            "boundary_exit_eas": sorted(accepted_route.boundary_exit_eas),
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
        operation_observations.append(
            _direct_route_maturity_payload(
                route=direct_route,
                direct_target_ea=direct_target_ea,
                direct_indirect=direct_indirect,
                direct_source_present=direct_source is not None,
                source_topology_reachable=source_topology_reachable,
                direct_targets=direct_targets,
            )
        )

    for conditional_route in (
        operation
        for operation in batch.operations
        if isinstance(
            operation,
            (RhadConditionalRoute, RhadExistingConditionalRoute),
        )
        and operation is not accepted_route
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
                            int(
                                conditional_route.conditional_select_ea
                                if isinstance(
                                    conditional_route,
                                    RhadConditionalRoute,
                                )
                                else conditional_route.selected_value_ea
                            ),
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
            and conditional_targets == delivery_target_eas
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
                    target = blocks[successor_serial]
                    while (
                        setcc_route.fallthrough_delivery
                        is FragmentSetccFallthroughDelivery.PLANNED_HELPER
                        and delivery_anchor(target, setcc_target_block_ids)
                        not in delivery_target_eas
                        and len(tuple(target.succset)) == 1
                    ):
                        successor_serial = int(tuple(target.succset)[0])
                        target = blocks[successor_serial]
                    setcc_targets.add(
                        delivery_anchor(
                            target,
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
            and setcc_targets == delivery_target_eas
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
    "ROW126_TABLE_PROOF_PATH",
    "SOURCE_EA",
    "TEMPLATE_ROOT_EAS",
    "TRANSFER_EA",
    "RhadGeneratedReferenceBatch",
    "build_rhad_generated_reference_plan",
    "prepare_rhad_generated_reference_templates",
    "load_row16_table_proof_artifact",
    "load_row17_table_proof_artifact",
    "load_row68_table_proof_artifact",
    "load_row96_table_proof_artifact",
    "load_row126_table_proof_artifact",
    "publish_rhad_generated_reference_batch",
    "reference_batch_for_native_key",
]
