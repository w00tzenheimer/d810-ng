"""Small test-only helpers shared by the authority migration checkpoints."""

from __future__ import annotations

import importlib
import hashlib

from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.unflatten_authority.ids import _subject_factory


def import_authority_model():
    """Import the future model at the package boundary under test."""

    return importlib.import_module("d810.transforms.unflatten_authority.model")


def authority_id(seed: str = "a") -> str:
    """Return a structurally valid supplied authority ID."""

    return "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


def block_ref(token: str = "b", version: int = 1) -> LogicalBlockRef:
    return LogicalBlockRef("authority-test", token, version)


def state_identity() -> StorageIdentity:
    return StorageIdentity(StorageIdentityKind.STACK, 0x40)


def edge_role() -> SemanticEdgeRole:
    return SemanticEdgeRole.DIRECT


def subject_kwargs(model, *, kind, role, locator, subject_id=None):
    """Build the common subject fields without hiding model validation."""

    owner = getattr(locator, "block_ref", None)
    if owner is None:
        owner = getattr(locator, "source_ref", None)
    anchor = getattr(locator, "anchor_ea", None)
    if anchor is None:
        anchor = getattr(locator, "source_anchor_ea", None)
    return dict(
        kind=kind,
        role=role,
        subject_id=subject_id or authority_id("s"),
        block_ref=owner,
        anchor_ea=anchor,
        locator=locator,
    )


def block_subject(model, *, role, token="subject", anchor_ea=0x1000):
    """Build a canonical block-backed subject for evaluator fixtures."""

    ref = block_ref(token)
    locator = model.BlockSubjectLocator(ref, anchor_ea)
    return _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=role,
        block_ref=ref,
        anchor_ea=anchor_ea,
        locator=locator,
    )
