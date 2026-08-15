"""Named issuer contracts for native patch authorization.

The gateway owns mechanics, not semantic target selection. A plan therefore
has to match a registered issuer contract before the recovery journal or IDB
is touched. Merely populating ``issuer_id`` and ``proof_id`` is not authority.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.transforms.native_patch_plan import NativePatchPlan


@dataclass(frozen=True, slots=True)
class NativePatchIssuerValidation:
    authorized: bool
    reason: str


@dataclass(frozen=True, slots=True)
class NativePatchIssuerContract:
    """Exact proof/provenance surface one named issuer may submit."""

    issuer_id: str
    patch_class: str
    proof_ids: frozenset[str] = frozenset()
    proof_id_prefixes: tuple[str, ...] = ()
    provenance: tuple[str, ...] | None = None
    provenance_prefix: tuple[str, ...] = ()
    proof_hash_matches: tuple[str, ...] = ()
    metadata_only: bool = False
    byte_writes_required: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.issuer_id, str) or not self.issuer_id.strip():
            raise ValueError("issuer_id must be a non-empty string")
        if self.patch_class not in {
            "lifting_normalization",
            "semantic_deobfuscation",
        }:
            raise ValueError("issuer patch_class is invalid")
        if any(
            not isinstance(item, str) or not item.strip() for item in self.proof_ids
        ):
            raise ValueError("proof_ids must contain non-empty strings")
        if any(
            not isinstance(item, str) or not item for item in self.proof_id_prefixes
        ):
            raise ValueError("proof_id_prefixes must contain non-empty strings")
        if not self.proof_ids and not self.proof_id_prefixes:
            raise ValueError("an issuer must constrain proof ids")
        if self.provenance is not None and (
            not self.provenance
            or any(
                not isinstance(item, str) or not item.strip()
                for item in self.provenance
            )
        ):
            raise ValueError("provenance must contain non-empty strings")
        if any(
            not isinstance(item, str) or not item.strip()
            for item in self.provenance_prefix
        ):
            raise ValueError("provenance_prefix must contain non-empty strings")
        if self.provenance is None and not self.provenance_prefix:
            raise ValueError("an issuer must constrain provenance")
        allowed_hash_fields = {
            "target_cfg_fingerprint",
            "native_origin_map_fingerprint",
            "inherited_function_fingerprint",
        }
        if any(field not in allowed_hash_fields for field in self.proof_hash_matches):
            raise ValueError("proof_hash_matches contains an unsupported plan field")
        if self.metadata_only and self.byte_writes_required:
            raise ValueError(
                "an issuer cannot require both metadata-only and byte-writing plans"
            )

    def validate(self, plan: NativePatchPlan) -> NativePatchIssuerValidation:
        if plan.patch_class != self.patch_class:
            return NativePatchIssuerValidation(False, "issuer_patch_class_mismatch")
        if plan.proof_id not in self.proof_ids and not any(
            plan.proof_id.startswith(prefix) for prefix in self.proof_id_prefixes
        ):
            return NativePatchIssuerValidation(False, "issuer_proof_id_mismatch")
        if self.provenance is not None and plan.provenance != self.provenance:
            return NativePatchIssuerValidation(False, "issuer_provenance_mismatch")
        if self.provenance_prefix and plan.provenance[
            : len(self.provenance_prefix)
        ] != (self.provenance_prefix):
            return NativePatchIssuerValidation(False, "issuer_provenance_mismatch")
        if any(
            plan.proof_hash != getattr(plan, field) for field in self.proof_hash_matches
        ):
            return NativePatchIssuerValidation(False, "issuer_proof_hash_mismatch")
        if self.metadata_only and any(op.writes_bytes for op in plan.operations):
            return NativePatchIssuerValidation(False, "issuer_requires_metadata_only")
        if self.byte_writes_required and not any(
            op.writes_bytes for op in plan.operations
        ):
            return NativePatchIssuerValidation(False, "issuer_requires_byte_writes")
        return NativePatchIssuerValidation(True, "issuer_contract_matched")


class NativePatchIssuerRegistry:
    """Immutable lookup of named issuer contracts used by one gateway."""

    def __init__(self, contracts: tuple[NativePatchIssuerContract, ...]) -> None:
        by_id: dict[str, NativePatchIssuerContract] = {}
        for contract in contracts:
            if not isinstance(contract, NativePatchIssuerContract):
                raise TypeError("issuer contracts must be NativePatchIssuerContract")
            if contract.issuer_id in by_id:
                raise ValueError(
                    f"duplicate native patch issuer {contract.issuer_id!r}"
                )
            by_id[contract.issuer_id] = contract
        self._by_id = by_id

    def validate(self, plan: NativePatchPlan) -> NativePatchIssuerValidation:
        if not isinstance(plan, NativePatchPlan):
            raise TypeError("plan must be a NativePatchPlan")
        contract = self._by_id.get(plan.issuer_id)
        if contract is None:
            return NativePatchIssuerValidation(
                False, f"unregistered native patch issuer {plan.issuer_id!r}"
            )
        return contract.validate(plan)


def indirect_label_materializer_issuer() -> NativePatchIssuerContract:
    """Production contract for the manager-owned indirect-label writer."""

    return NativePatchIssuerContract(
        issuer_id="indirect-label-materializer",
        patch_class="lifting_normalization",
        proof_ids=frozenset({"indirect-label-discovery"}),
        provenance=("indirect_jump_labels",),
        proof_hash_matches=(
            "target_cfg_fingerprint",
            "native_origin_map_fingerprint",
        ),
        metadata_only=True,
    )


def dead_edge_semantic_issuers() -> tuple[NativePatchIssuerContract, ...]:
    """Production contracts for the two proven dead-edge recognizers.

    The proof kind is part of both the issuer identity and provenance.  The
    proof digest must also be the plan's target-CFG fingerprint, preventing a
    caller from pairing an unrelated proof token with a byte-writing plan.
    """

    return tuple(
        NativePatchIssuerContract(
            issuer_id=f"dead-edge-normalizer:{proof_kind}",
            patch_class="semantic_deobfuscation",
            proof_id_prefixes=(f"{proof_kind}:",),
            provenance_prefix=(proof_kind,),
            proof_hash_matches=("target_cfg_fingerprint",),
            byte_writes_required=True,
        )
        for proof_kind in (
            "single_trip_loop_peel",
            "z3_opaque_predicate",
        )
    )


def stage_c_native_cfg_issuer() -> NativePatchIssuerContract:
    """Production contract for pass-owned Stage C CFG normalization."""

    return NativePatchIssuerContract(
        issuer_id="stage-c-native-cfg-normalizer",
        patch_class="semantic_deobfuscation",
        proof_id_prefixes=("native-cfg-intent-v1:",),
        provenance_prefix=("stage-c-native-cfg",),
        proof_hash_matches=("target_cfg_fingerprint",),
        byte_writes_required=True,
    )


__all__ = [
    "NativePatchIssuerContract",
    "NativePatchIssuerRegistry",
    "NativePatchIssuerValidation",
    "dead_edge_semantic_issuers",
    "indirect_label_materializer_issuer",
    "stage_c_native_cfg_issuer",
]
