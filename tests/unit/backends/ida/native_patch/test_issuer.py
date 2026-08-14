from __future__ import annotations

import dataclasses

from d810.backends.ida.native_patch.issuer import (
    NativePatchIssuerContract,
    NativePatchIssuerRegistry,
    dead_edge_semantic_issuers,
    indirect_label_materializer_issuer,
)
from d810.transforms.native_patch_plan import (
    NativeMetadataAction,
    NativeMetadataActionKind,
)

from . import _plan_fixtures as fixtures


def test_registry_requires_an_exact_named_issuer_proof_and_provenance() -> None:
    contract = NativePatchIssuerContract(
        issuer_id="issuer-1",
        patch_class="lifting_normalization",
        proof_ids=frozenset({"proof-1"}),
        provenance=("source-pass",),
    )
    registry = NativePatchIssuerRegistry((contract,))
    valid = dataclasses.replace(fixtures.plan(), provenance=("source-pass",))

    assert registry.validate(valid).authorized
    assert not registry.validate(
        dataclasses.replace(valid, issuer_id="unregistered")
    ).authorized
    assert not registry.validate(
        dataclasses.replace(valid, proof_id="unregistered-proof")
    ).authorized
    assert not registry.validate(
        dataclasses.replace(valid, provenance=("different-source",))
    ).authorized


def test_indirect_label_issuer_accepts_only_its_metadata_only_contract() -> None:
    registry = NativePatchIssuerRegistry((indirect_label_materializer_issuer(),))
    metadata_operation = dataclasses.replace(
        fixtures.operation(),
        replacement_bytes=fixtures.operation().expected_current_bytes,
        expected_after_shape=fixtures.operation().expected_before_shape,
        expected_after_successors=(),
        metadata_actions=(
            NativeMetadataAction(
                kind=NativeMetadataActionKind.UPDATE_XREF,
                ea=0x1000,
                expected_before="cref3:",
                expected_after="cref3:0x1002:1:0",
            ),
        ),
        writes_bytes=False,
    )
    valid = dataclasses.replace(
        fixtures.plan(operations=(metadata_operation,)),
        issuer_id="indirect-label-materializer",
        proof_id="indirect-label-discovery",
        proof_hash="request-fingerprint",
        target_cfg_fingerprint="request-fingerprint",
        native_origin_map_fingerprint="request-fingerprint",
        provenance=("indirect_jump_labels",),
    )

    assert registry.validate(valid).authorized
    assert not registry.validate(
        dataclasses.replace(valid, proof_hash="different-proof")
    ).authorized
    assert not registry.validate(
        dataclasses.replace(valid, operations=(fixtures.operation(),))
    ).authorized
    assert not registry.validate(
        dataclasses.replace(valid, patch_class="semantic_deobfuscation")
    ).authorized


def test_dead_edge_issuers_bind_named_proofs_to_cfg_and_byte_writes() -> None:
    contracts = dead_edge_semantic_issuers()
    assert {contract.issuer_id for contract in contracts} == {
        "dead-edge-normalizer:single_trip_loop_peel",
        "dead-edge-normalizer:z3_opaque_predicate",
    }
    registry = NativePatchIssuerRegistry(contracts)

    for proof_kind in ("single_trip_loop_peel", "z3_opaque_predicate"):
        valid = dataclasses.replace(
            fixtures.plan(),
            patch_class="semantic_deobfuscation",
            issuer_id=f"dead-edge-normalizer:{proof_kind}",
            proof_id=f"{proof_kind}:site=0x1000:action=RETARGET",
            proof_hash="cfg-proof",
            target_cfg_fingerprint="cfg-proof",
            provenance=(proof_kind, "proved by production oracle"),
        )

        assert registry.validate(valid).authorized
        assert not registry.validate(
            dataclasses.replace(valid, proof_hash="unbound-proof")
        ).authorized
        assert not registry.validate(
            dataclasses.replace(valid, provenance=("test-owned-proof",))
        ).authorized

        metadata_only_operation = dataclasses.replace(
            fixtures.operation(),
            replacement_bytes=fixtures.operation().expected_current_bytes,
            expected_after_shape=fixtures.operation().expected_before_shape,
            expected_after_successors=(),
            metadata_actions=(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.UPDATE_XREF,
                    ea=0x1000,
                    expected_before="cref3:",
                    expected_after="cref3:0x1002:1:0",
                ),
            ),
            writes_bytes=False,
        )
        assert not registry.validate(
            dataclasses.replace(valid, operations=(metadata_only_operation,))
        ).authorized
